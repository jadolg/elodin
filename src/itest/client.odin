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
	udp_port: int,
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
		port    = udp_port,
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
expect_no_udp_reply :: proc(udp_port: int, query: []u8, wait := 400 * time.Millisecond) -> bool {
	socket, err := net.make_unbound_udp_socket(.IP4)
	if err != nil {
		return false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, wait)

	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = udp_port,
	}
	if _, serr := net.send_udp(socket, query, endpoint); serr != nil {
		return false
	}
	buf := make([]u8, 4096, context.temp_allocator)
	_, _, rerr := net.recv_udp(socket, buf)
	return rerr != nil
}

query_tcp :: proc(tcp_port: int, query: []u8, allocator := context.allocator, timeout := CLIENT_TIMEOUT) -> Query_Result {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
	if err != nil {
		return {}
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, timeout)
	_ = net.set_option(socket, .Send_Timeout, timeout)

	conn := Test_Conn {
		socket = socket,
	}
	return stream_query(&conn, query, allocator)
}

// Sends several queries on one connection, which is what a real TCP or DoT
// client does and what the server's per-connection loop has to handle.
query_tcp_multi :: proc(tcp_port: int, queries: [][]u8, allocator := context.allocator) -> []Query_Result {
	results := make([]Query_Result, len(queries), allocator)
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
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

query_dot :: proc(dot_port: int, query: []u8, allocator := context.allocator) -> Query_Result {
	conn, ok := dial_tls(dot_port)
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

/*
Send `count` queries from one socket as fast as they go out, then read whatever
comes back until the wire goes quiet.

One socket and one draining pass, because the point is what the server sends in
answer to a burst: asking query by query and waiting for each would let the
budget refill between them, and waiting out a timeout for the ones that are
never answered would take the rest of the afternoon.
*/
Flood_Result :: struct {
	answered:  int,
	truncated: int,
	bytes:     int,
	// Set when the server's close arrived as a reset rather than as the end of the
	// stream, which is what a close over unread bytes sends. Only
	// `tcp_pipeline_flood` fills it in; a datagram has nothing to reset.
	reset:     bool,
}

udp_flood :: proc(udp_port: int, query: []u8, count: int, drain := 700 * time.Millisecond) -> Flood_Result {
	socket, err := net.make_unbound_udp_socket(.IP4)
	if err != nil {
		return {}
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond)
	_ = net.set_option(socket, .Send_Timeout, time.Second)
	_ = net.set_option(socket, .Receive_Buffer_Size, 4 << 20)

	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = udp_port,
	}

	out := make([]u8, len(query), context.temp_allocator)
	copy(out, query)
	for i in 0 ..< count {
		// A transaction ID of its own per query, as a real client would.
		out[0], out[1] = u8(i >> 8), u8(i)
		if _, serr := net.send_udp(socket, out, endpoint); serr != nil {
			break
		}
	}

	res: Flood_Result
	buf := make([]u8, 65535, context.temp_allocator)
	deadline := time.time_add(time.now(), drain)
	for time.diff(deadline, time.now()) < 0 {
		n, _, rerr := net.recv_udp(socket, buf)
		if rerr != nil {
			// The receive timeout expiring is how this notices the quiet.
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		res.answered += 1
		res.bytes += n
		if buf[2] & 0x02 != 0 {
			res.truncated += 1
		}
	}
	return res
}

/*
Send `count` queries down one TCP connection back to back, then read the answers
until the server has no more to give.

The flood a datagram limiter never sees. Nothing here waits for an answer before
sending the next query - which RFC 7766 6.2.1.1 explicitly allows a client to do -
so one connection out of `max_connections` carries as fast a query rate as the
socket does. All of it goes out before anything is read: a few dozen bytes per
query is far short of what a send buffer holds, so the server needs not have read a
byte for the write to finish.

The reading ends on the server closing the connection, which is what being over
the budget looks like on a stream: there is nothing to truncate, so an answer that
does not arrive arrives as the end of the connection. A run that is never cut off
ends on the receive timeout instead.
*/
tcp_pipeline_flood :: proc(tcp_port: int, query: []u8, count: int, drain := 700 * time.Millisecond) -> Flood_Result {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
	if err != nil {
		return {}
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, drain)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	stride := 2 + len(query)
	framed := make([]u8, count * stride, context.temp_allocator)
	for i in 0 ..< count {
		message := framed[i * stride:][:stride]
		message[0] = u8(len(query) >> 8)
		message[1] = u8(len(query))
		copy(message[2:], query)
		// A transaction ID of its own per query, as a real client would.
		message[2], message[3] = u8(i >> 8), u8(i)
	}
	sent := 0
	for sent < len(framed) {
		n, serr := net.send_tcp(socket, framed[sent:])
		if serr != nil || n <= 0 {
			break
		}
		sent += n
	}

	res: Flood_Result
	buf := make([]u8, dns.MAX_MESSAGE, context.temp_allocator)
	for {
		length_buf: [2]u8
		ok, reset := flood_read_full(socket, length_buf[:])
		if !ok {
			res.reset = reset
			break
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			break
		}
		ok, reset = flood_read_full(socket, buf[:length])
		if !ok {
			res.reset = reset
			break
		}
		res.answered += 1
		res.bytes += 2 + length
		if buf[2] & 0x02 != 0 {
			res.truncated += 1
		}
	}
	return res
}

/*
`conn_read_full` for a plain socket, and also how the read ended.

The end of the stream and a reset are the same "no more answers" to the loop
above, and a world apart to the client: a server that closes with queries still
unread in its receive queue sends an RST rather than a FIN (RFC 1122 4.2.2.13),
and the RST has this kernel throw away answers it had already been handed. That
difference is the whole of what the server's drain before the close is for, so it
is worth carrying back rather than flattening into `break`. `core:net` spells a
graceful end as no bytes and no error, and names the other thing
`Connection_Closed`.
*/
@(private)
flood_read_full :: proc(socket: net.TCP_Socket, buf: []u8) -> (ok: bool, reset: bool) {
	got := 0
	for got < len(buf) {
		n, err := net.recv_tcp(socket, buf[got:])
		if err != nil {
			return false, err == net.TCP_Recv_Error.Connection_Closed
		}
		if n == 0 {
			return false, false
		}
		got += n
	}
	return true, false
}

// --- DoH ------------------------------------------------------------------

Http_Result :: struct {
	status:  int,
	body:    []u8,
	headers: string,
	ok:      bool,
}

doh_post :: proc(doh_port: int, path: string, query: []u8, allocator := context.allocator) -> Http_Result {
	req := build_http_request("POST", path, "application/dns-message", query)
	return http_roundtrip(doh_port, req, allocator)
}

doh_get :: proc(doh_port: int, path: string, query: []u8, allocator := context.allocator) -> Http_Result {
	// RFC 8484 wants base64url with the padding stripped.
	encoded, err := base64.encode(query, base64.ENC_URL_TABLE, context.temp_allocator)
	if err != nil {
		return {}
	}
	trimmed := strings.trim_right(encoded, "=")
	target := strings.concatenate({path, "?dns=", trimmed}, context.temp_allocator)
	req := build_http_request("GET", target, "", nil)
	return http_roundtrip(doh_port, req, allocator)
}

// Sends a request built by the caller, for the malformed and unsupported cases.
doh_raw :: proc(doh_port: int, request: string, allocator := context.allocator) -> Http_Result {
	return http_roundtrip(doh_port, transmute([]u8)request, allocator)
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
doh_raw_until_close :: proc(doh_port: int, request: string, allocator := context.allocator) -> (data: string, ok: bool) {
	conn, dialled := dial_tls(doh_port, []string{"http/1.1"})
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
doh_post_twice :: proc(doh_port: int, path: string, query: []u8, allocator := context.allocator) -> (a, b: Http_Result) {
	conn, ok := dial_tls(doh_port, []string{"http/1.1"})
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
http_roundtrip :: proc(doh_port: int, request: []u8, allocator: mem.Allocator) -> Http_Result {
	conn, ok := dial_tls(doh_port, []string{"http/1.1"})
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

// --- plain HTTP -----------------------------------------------------------

/*
One HTTP/1.1 request over plain TCP.

The metrics endpoint is the only thing this server speaks HTTP to without TLS in
front of it, so this is `http_roundtrip` without the handshake. It answers one
request per connection and closes, which is why nothing here tries to reuse the
socket.
*/
http_request :: proc(port: int, method: string, target: string, allocator := context.allocator) -> Http_Result {
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
	if !conn_write(&conn, build_http_request(method, target, "", nil)) {
		return {}
	}
	return read_http_response(&conn, allocator)
}

// Whether anything is listening at all, which is what the "off by default" case
// is asking.
tcp_port_open :: proc(port: int) -> bool {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil {
		return false
	}
	net.close(socket)
	return true
}
