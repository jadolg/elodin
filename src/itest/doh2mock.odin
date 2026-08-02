package itest

import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:thread"
import "elodin:h2"
import "elodin:tlsx"

/*
A DoH upstream, for testing elodin's HTTP/2 upstream client
(src/upstream/h2client.odin) against a real server rather than only against
elodin's own listener — cases_h2.odin and cases_transport.odin exercise that
side, with elodin as the server.

Answers over whichever protocol ALPN selects: HTTP/2 reuses the h2 package's
own server-side Conn (the same code the doh2 listener runs), and HTTP/1.1 is a
small POST-only responder, since httpmock.odin's is GET-only and unencrypted.
Both paths always reply 200 with `payload`, transaction ID patched to match
the query — elodin's own request encoding is already covered elsewhere, so
this only needs to look like a real DoH resolver from the outside.
*/

Doh2_Mock :: struct {
	port:      int,
	path:      string,
	payload:   []u8,
	tls_ctx:   ^tlsx.Context,
	listener:  net.TCP_Socket,
	threads:   [dynamic]^thread.Thread,
	stop:      bool,

	mu:        sync.Mutex,
	h2_hits:   int,
	h1_hits:   int,
}

doh2_mock_make :: proc(port: int, path: string, payload: []u8) -> ^Doh2_Mock {
	m := new(Doh2_Mock)
	m.port = port
	m.path = path
	m.payload = payload
	m.threads = make([dynamic]^thread.Thread, 0, 4)
	return m
}

// `alpn` lists what the mock offers, most preferred first. Pass {"http/1.1"}
// to test elodin falling back cleanly when a resolver has no h2 support.
doh2_mock_start :: proc(m: ^Doh2_Mock, cert_file, key_file: string, alpn: []string = {"h2", "http/1.1"}) -> bool {
	ctx, terr := tlsx.server_context(cert_file, key_file, alpn)
	if terr != .None {
		return false
	}
	m.tls_ctx = ctx

	sock, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = m.port})
	if lerr != nil {
		tlsx.context_destroy(ctx)
		return false
	}
	m.listener = sock
	_ = net.set_option(sock, .Receive_Timeout, POLL_INTERVAL)
	append(&m.threads, thread.create_and_start_with_poly_data(m, doh2_mock_loop))
	return true
}

doh2_mock_stop :: proc(m: ^Doh2_Mock) {
	sync.atomic_store(&m.stop, true)
	if m.listener != 0 {
		net.close(m.listener)
	}
	for {
		sync.mutex_lock(&m.mu)
		pending := m.threads
		m.threads = make([dynamic]^thread.Thread, 0, 4)
		sync.mutex_unlock(&m.mu)
		if len(pending) == 0 {
			delete(pending)
			break
		}
		for t in pending {
			thread.join(t)
			thread.destroy(t)
		}
		delete(pending)
	}
	delete(m.threads)
	tlsx.context_destroy(m.tls_ctx)
	free(m)
}

// Connections handled over h2 and over HTTP/1.1, so a test can tell which
// protocol ALPN actually picked rather than only that a query was answered.
doh2_mock_counts :: proc(m: ^Doh2_Mock) -> (h2_hits, h1_hits: int) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	return m.h2_hits, m.h1_hits
}

@(private = "file")
doh2_mock_loop :: proc(m: ^Doh2_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, err := net.accept_tcp(m.listener)
		if err != nil {
			continue
		}
		_ = net.set_option(client, .Receive_Timeout, POLL_INTERVAL)
		conn := new(Doh2_Conn)
		conn.mock = m
		conn.socket = client
		t := thread.create_and_start_with_poly_data(conn, doh2_mock_conn)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
Doh2_Conn :: struct {
	mock:   ^Doh2_Mock,
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
}

@(private = "file")
doh2_mock_conn :: proc(conn: ^Doh2_Conn) {
	m := conn.mock
	defer free(conn)

	tls_conn, terr := tlsx.server_accept(m.tls_ctx, conn.socket)
	if terr != .None {
		net.close(conn.socket)
		return
	}
	conn.tls = tls_conn
	defer tlsx.close(tls_conn)

	if tlsx.alpn_protocol(tls_conn) == "h2" {
		doh2_serve_h2(conn)
		return
	}
	doh2_serve_http1(conn)
}

// --- HTTP/2 ------------------------------------------------------------

@(private = "file")
doh2_io_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	conn := cast(^Doh2_Conn)user
	for {
		if sync.atomic_load(&conn.mock.stop) {
			return 0, false
		}
		got, err := tlsx.read(conn.tls, buf)
		#partial switch err {
		case .None:
			return got, true
		case .Timeout:
			continue
		case:
			return 0, false
		}
	}
}

@(private = "file")
doh2_io_write :: proc(user: rawptr, buf: []u8) -> bool {
	conn := cast(^Doh2_Conn)user
	_, err := tlsx.write(conn.tls, buf)
	return err == .None
}

@(private = "file")
doh2_serve_h2 :: proc(conn: ^Doh2_Conn) {
	io := h2.IO{user = conn, read = doh2_io_read, write = doh2_io_write}
	hc := h2.make_conn(io, doh2_handler, conn)
	h2.serve(hc)
	h2.conn_wait_idle(hc)
	h2.conn_unref(hc)
}

@(private = "file")
doh2_handler :: proc(hc: ^h2.Conn, req: ^h2.Request) {
	conn := cast(^Doh2_Conn)hc.user
	m := conn.mock
	defer h2.request_destroy(hc, req)

	path := req.path
	if idx := strings.index_byte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path != m.path || req.method != "POST" || len(req.body) < 2 {
		h2.respond(hc, req.stream_id, h2.Response{status = 404})
		return
	}

	sync.mutex_lock(&m.mu)
	m.h2_hits += 1
	sync.mutex_unlock(&m.mu)

	body := doh2_reply_body(m, req.body[0], req.body[1], context.temp_allocator)
	h2.respond(hc, req.stream_id, h2.Response{status = 200, content_type = "application/dns-message", body = body})
}

// --- HTTP/1.1 ------------------------------------------------------------

@(private = "file")
doh2_serve_http1 :: proc(conn: ^Doh2_Conn) {
	m := conn.mock

	req := make([dynamic]u8, 0, 2048, context.temp_allocator)
	for {
		if sync.atomic_load(&m.stop) {
			return
		}
		chunk: [1024]u8
		n, err := tlsx.read(conn.tls, chunk[:])
		if err == .Timeout {
			continue
		}
		if err != .None || n <= 0 {
			return
		}
		append(&req, ..chunk[:n])
		if strings.contains(string(req[:]), "\r\n\r\n") {
			break
		}
		if len(req) > 16 * 1024 {
			return
		}
	}

	text := string(req[:])
	header_end := strings.index(text, "\r\n\r\n")
	if header_end < 0 {
		return
	}
	head := text[:header_end]
	body := req[header_end + 4:]

	line_end := strings.index(head, "\r\n")
	if line_end < 0 {
		return
	}
	parts := strings.split(head[:line_end], " ", context.temp_allocator)
	if len(parts) < 2 || parts[0] != "POST" {
		return
	}
	path := parts[1]

	content_length := 0
	for line in strings.split_lines_iterator(&head) {
		if idx := strings.index_byte(line, ':'); idx >= 0 && strings.equal_fold(strings.trim_space(line[:idx]), "content-length") {
			content_length, _ = strconv.parse_int(strings.trim_space(line[idx + 1:]))
		}
	}

	for len(body) < content_length {
		if sync.atomic_load(&m.stop) {
			return
		}
		chunk: [1024]u8
		n, err := tlsx.read(conn.tls, chunk[:])
		if err == .Timeout {
			continue
		}
		if err != .None || n <= 0 {
			return
		}
		append(&req, ..chunk[:n])
		body = req[header_end + 4:]
	}

	if path != m.path || content_length < 2 {
		_, _ = tlsx.write(conn.tls, transmute([]u8)string("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	sync.mutex_lock(&m.mu)
	m.h1_hits += 1
	sync.mutex_unlock(&m.mu)

	reply := doh2_reply_body(m, body[0], body[1], context.temp_allocator)
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ")
	strings.write_int(&b, len(reply))
	strings.write_string(&b, "\r\nConnection: close\r\n\r\n")
	out := transmute([]u8)strings.to_string(b)

	sent := 0
	for sent < len(out) {
		n, err := tlsx.write(conn.tls, out[sent:])
		if err != .None || n <= 0 {
			return
		}
		sent += n
	}
	sent = 0
	for sent < len(reply) {
		n, err := tlsx.write(conn.tls, reply[sent:])
		if err != .None || n <= 0 {
			return
		}
		sent += n
	}
}

// A copy of the mock's canned payload with the transaction ID patched to
// match the query that asked for it.
@(private = "file")
doh2_reply_body :: proc(m: ^Doh2_Mock, id_hi, id_lo: u8, allocator := context.allocator) -> []u8 {
	out := make([]u8, len(m.payload), allocator)
	copy(out, m.payload)
	if len(out) >= 2 {
		out[0], out[1] = id_hi, id_lo
	}
	return out
}
