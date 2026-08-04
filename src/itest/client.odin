package itest

import "core:encoding/base64"
import "core:mem"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
Client side of the integration tests.

These deliberately do not go through elodin's own upstream package: the point is
to speak to the server the way an outside client would, from raw bytes upwards.
*/

CLIENT_TIMEOUT :: 8 * time.Second

Query_Result :: struct {
	wire: []u8,
	ok:   bool,
}

query_udp :: proc(
	port: int,
	query: []u8,
	allocator := context.allocator,
	timeout := CLIENT_TIMEOUT,
) -> Query_Result {
	socket, err := net.make_unbound_udp_socket(.IP4)
	if err != nil {
		return {}
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, timeout)
	_ = net.set_option(socket, .Send_Timeout, timeout)

	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = port,
	}
	if _, serr := net.send_udp(socket, query, endpoint); serr != nil {
		return {}
	}

	buf := make([]u8, 65535, context.temp_allocator)
	n, _, rerr := net.recv_udp(socket, buf)
	if rerr != nil || n < dns.HEADER_SIZE {
		return {}
	}
	out := make([]u8, n, allocator)
	copy(out, buf[:n])
	return Query_Result{wire = out, ok = true}
}

// Confirms the server sends nothing at all, which is the correct answer to some
// malformed input. Returns true when the wait times out.
expect_no_udp_reply :: proc(port: int, query: []u8, wait := 400 * time.Millisecond) -> bool {
	socket, err := net.make_unbound_udp_socket(.IP4)
	if err != nil {
		return false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, wait)

	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = port,
	}
	if _, serr := net.send_udp(socket, query, endpoint); serr != nil {
		return false
	}
	buf := make([]u8, 4096, context.temp_allocator)
	_, _, rerr := net.recv_udp(socket, buf)
	return rerr != nil
}

query_tcp :: proc(port: int, query: []u8, allocator := context.allocator) -> Query_Result {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil {
		return {}
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	conn := Test_Conn {
		socket = socket,
	}
	return stream_query(&conn, query, allocator)
}

// Sends several queries on one connection, which is what a real TCP or DoT
// client does and what the server's per-connection loop has to handle.
query_tcp_multi :: proc(port: int, queries: [][]u8, allocator := context.allocator) -> []Query_Result {
	results := make([]Query_Result, len(queries), allocator)
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil {
		return results
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)

	conn := Test_Conn {
		socket = socket,
	}
	for q, i in queries {
		results[i] = stream_query(&conn, q, allocator)
		if !results[i].ok {
			break
		}
	}
	return results
}

query_dot :: proc(port: int, query: []u8, allocator := context.allocator) -> Query_Result {
	conn, ok := dial_tls(port)
	if !ok {
		return {}
	}
	defer close_tls(&conn)
	return stream_query(&conn, query, allocator)
}

Test_Conn :: struct {
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
}

@(private)
dial_tls :: proc(port: int, alpn: []string = nil) -> (conn: Test_Conn, ok: bool) {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil {
		return {}, false
	}
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	// The test certificate is self-signed, so verification is off here; the
	// point of these cases is the protocol, not the PKI.
	ctx, cerr := tlsx.client_context(false, "", alpn, context.temp_allocator)
	if cerr != .None {
		net.close(socket)
		return {}, false
	}
	defer tlsx.context_destroy(ctx)

	tls_conn, terr := tlsx.client_connect(ctx, socket, "elodin.local")
	if terr != .None {
		net.close(socket)
		return {}, false
	}
	return Test_Conn{socket = socket, tls = tls_conn}, true
}

@(private)
close_tls :: proc(conn: ^Test_Conn) {
	if conn.tls != nil {
		tlsx.close(conn.tls)
		conn.tls = nil
	}
}

@(private)
conn_write :: proc(c: ^Test_Conn, buf: []u8) -> bool {
	if c.tls != nil {
		_, err := tlsx.write(c.tls, buf)
		return err == .None
	}
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(c.socket, buf[sent:])
		if err != nil || n <= 0 {
			return false
		}
		sent += n
	}
	return true
}

@(private)
conn_read :: proc(c: ^Test_Conn, buf: []u8) -> (n: int, ok: bool) {
	if c.tls != nil {
		v, err := tlsx.read(c.tls, buf)
		return v, err == .None && v > 0
	}
	v, err := net.recv_tcp(c.socket, buf)
	return v, err == nil && v > 0
}

@(private)
conn_read_full :: proc(c: ^Test_Conn, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, ok := conn_read(c, buf[got:])
		if !ok {
			return false
		}
		got += n
	}
	return true
}

@(private)
stream_query :: proc(c: ^Test_Conn, query: []u8, allocator: mem.Allocator) -> Query_Result {
	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)
	if !conn_write(c, framed) {
		return {}
	}

	length_buf: [2]u8
	if !conn_read_full(c, length_buf[:]) {
		return {}
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
		return {}
	}
	out := make([]u8, length, allocator)
	if !conn_read_full(c, out) {
		return {}
	}
	return Query_Result{wire = out, ok = true}
}

// --- DoH ------------------------------------------------------------------

Http_Result :: struct {
	status:  int,
	body:    []u8,
	headers: string,
	ok:      bool,
}

doh_post :: proc(port: int, path: string, query: []u8, allocator := context.allocator) -> Http_Result {
	req := build_http_request("POST", path, "application/dns-message", query)
	return http_roundtrip(port, req, allocator)
}

doh_get :: proc(port: int, path: string, query: []u8, allocator := context.allocator) -> Http_Result {
	// RFC 8484 wants base64url with the padding stripped.
	encoded, err := base64.encode(query, base64.ENC_URL_TABLE, context.temp_allocator)
	if err != nil {
		return {}
	}
	trimmed := strings.trim_right(encoded, "=")
	target := strings.concatenate({path, "?dns=", trimmed}, context.temp_allocator)
	req := build_http_request("GET", target, "", nil)
	return http_roundtrip(port, req, allocator)
}

// Sends a request built by the caller, for the malformed and unsupported cases.
doh_raw :: proc(port: int, request: string, allocator := context.allocator) -> Http_Result {
	return http_roundtrip(port, transmute([]u8)request, allocator)
}

/*
One raw request, then everything the server says until it hangs up.

For the framing cases, where the question is not what any one reply says but how
many of them there are: a body framed differently from the way it was written
leaves bytes in the connection, and those bytes being read as a request and
answered is the thing to catch. Read reply by reply this is invisible - two
answers usually arrive in one record, and a reader that takes them one at a time
throws away whatever it over-read.
*/
doh_raw_until_close :: proc(port: int, request: string, allocator := context.allocator) -> (data: string, ok: bool) {
	conn, dialled := dial_tls(port, []string{"http/1.1"})
	if !dialled {
		return "", false
	}
	defer close_tls(&conn)

	if !conn_write(&conn, transmute([]u8)request) {
		return "", false
	}

	buf := make([dynamic]u8, 0, 8192, allocator)
	for len(buf) < 64 * 1024 {
		chunk: [4096]u8
		n, read_ok := conn_read(&conn, chunk[:])
		if !read_ok {
			break
		}
		append(&buf, ..chunk[:n])
	}
	return string(buf[:]), true
}

// Two POSTs down one connection, to prove keep-alive works.
doh_post_twice :: proc(port: int, path: string, query: []u8, allocator := context.allocator) -> (a, b: Http_Result) {
	conn, ok := dial_tls(port, []string{"http/1.1"})
	if !ok {
		return {}, {}
	}
	defer close_tls(&conn)

	req := build_http_request("POST", path, "application/dns-message", query)
	if !conn_write(&conn, req) {
		return {}, {}
	}
	a = read_http_response(&conn, allocator)
	if !a.ok {
		return a, {}
	}
	if !conn_write(&conn, req) {
		return a, {}
	}
	b = read_http_response(&conn, allocator)
	return a, b
}

@(private)
build_http_request :: proc(method, target, content_type: string, body: []u8) -> []u8 {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, method)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, target)
	strings.write_string(&b, " HTTP/1.1\r\nHost: elodin.local\r\nConnection: keep-alive\r\n")
	strings.write_string(&b, "Accept: application/dns-message\r\n")
	if content_type != "" {
		strings.write_string(&b, "Content-Type: ")
		strings.write_string(&b, content_type)
		strings.write_string(&b, "\r\n")
	}
	if len(body) > 0 {
		strings.write_string(&b, "Content-Length: ")
		strings.write_int(&b, len(body))
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "\r\n")
	head := strings.to_string(b)

	out := make([]u8, len(head) + len(body), context.temp_allocator)
	copy(out, transmute([]u8)head)
	copy(out[len(head):], body)
	return out
}

@(private)
http_roundtrip :: proc(port: int, request: []u8, allocator: mem.Allocator) -> Http_Result {
	conn, ok := dial_tls(port, []string{"http/1.1"})
	if !ok {
		return {}
	}
	defer close_tls(&conn)

	if !conn_write(&conn, request) {
		return {}
	}
	return read_http_response(&conn, allocator)
}

@(private)
read_http_response :: proc(conn: ^Test_Conn, allocator: mem.Allocator) -> Http_Result {
	buf := make([dynamic]u8, 0, 8192, context.temp_allocator)
	header_end := -1

	for header_end < 0 {
		chunk: [4096]u8
		n, ok := conn_read(conn, chunk[:])
		if !ok {
			return {}
		}
		append(&buf, ..chunk[:n])
		header_end = find_header_end(buf[:])
		if len(buf) > 64 * 1024 {
			return {}
		}
	}

	head := string(buf[:header_end])
	status := parse_status_line(head) or_else 0
	if status == 0 {
		return {}
	}
	content_length := header_int(head, "content-length")

	body_start := header_end + 4
	for len(buf) - body_start < content_length {
		chunk: [4096]u8
		n, ok := conn_read(conn, chunk[:])
		if !ok {
			break
		}
		append(&buf, ..chunk[:n])
	}

	available := min(content_length, len(buf) - body_start)
	body := make([]u8, max(0, available), allocator)
	if available > 0 {
		copy(body, buf[body_start:body_start + available])
	}
	return Http_Result{status = status, body = body, headers = strings.clone(head, allocator), ok = true}
}

@(private)
find_header_end :: proc(b: []u8) -> int {
	for i in 0 ..< max(0, len(b) - 3) {
		if b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n' {
			return i
		}
	}
	return -1
}

@(private)
parse_status_line :: proc(head: string) -> (status: int, ok: bool) {
	line_end := strings.index(head, "\r\n")
	line := head if line_end < 0 else head[:line_end]
	space := strings.index_byte(line, ' ')
	if space < 0 || space + 4 > len(line) {
		return 0, false
	}
	return strconv.parse_int(line[space + 1:space + 4])
}

@(private)
header_int :: proc(head: string, name: string) -> int {
	rest := head
	for {
		idx := strings.index(rest, "\r\n")
		if idx < 0 {
			return 0
		}
		rest = rest[idx + 2:]
		colon := strings.index_byte(rest, ':')
		if colon < 0 {
			return 0
		}
		if strings.equal_fold(rest[:colon], name) {
			line_end := strings.index(rest, "\r\n")
			value := rest[colon + 1:] if line_end < 0 else rest[colon + 1:line_end]
			v, ok := strconv.parse_int(strings.trim_space(value))
			return v if ok else 0
		}
	}
}

header_contains :: proc(head: string, needle: string) -> bool {
	return strings.contains(strings.to_lower(head, context.temp_allocator), strings.to_lower(needle, context.temp_allocator))
}
