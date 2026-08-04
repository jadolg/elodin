package itest

import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"

/*
A tiny HTTP/1.1 file server, so the blocklist download path can be tested
without reaching the internet.

Plain HTTP on purpose: it exercises elodin's fetcher and its on-disk cache,
which is where a list actually comes from, while leaving TLS to the cases that
are about TLS.
*/

// Routes are held in an array whose strings the mock owns. A map keyed by the
// request path would mean storing a key that borrows the connection's scratch
// buffer, and the entry would turn to garbage the moment that was reused.
Http_Route :: struct {
	path: string,
	body: string,
	hits: int,
}

Http_Mock :: struct {
	port:    int,
	socket:  net.TCP_Socket,
	threads: [dynamic]^thread.Thread,
	stop:    bool,

	mu:      sync.Mutex,
	routes:  [dynamic]Http_Route,
}

http_mock_make :: proc(port: int) -> ^Http_Mock {
	m := new(Http_Mock)
	m.port = port
	m.threads = make([dynamic]^thread.Thread, 0, 4)
	m.routes = make([dynamic]Http_Route, 0, 8)
	return m
}

http_mock_serve :: proc(m: ^Http_Mock, path: string, body: string) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	append(&m.routes, Http_Route{path = strings.clone(path), body = strings.clone(body)})
}

http_mock_hits :: proc(m: ^Http_Mock, path: string) -> int {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	for route in m.routes {
		if route.path == path {
			return route.hits
		}
	}
	return 0
}

http_mock_start :: proc(m: ^Http_Mock) -> bool {
	sock, err := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = m.port})
	if err != nil {
		return false
	}
	m.socket = sock
	_ = net.set_option(sock, .Receive_Timeout, POLL_INTERVAL)
	append(&m.threads, thread.create_and_start_with_poly_data(m, http_mock_loop))
	return true
}

http_mock_stop :: proc(m: ^Http_Mock) {
	sync.atomic_store(&m.stop, true)
	if m.socket != 0 {
		net.close(m.socket)
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
	for route in m.routes {
		delete(route.path)
		delete(route.body)
	}
	delete(m.routes)
	free(m)
}

@(private = "file")
Http_Mock_Conn :: struct {
	mock:   ^Http_Mock,
	socket: net.TCP_Socket,
}

@(private = "file")
http_mock_loop :: proc(m: ^Http_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, err := net.accept_tcp(m.socket)
		if err != nil {
			continue
		}
		_ = net.set_option(client, .Receive_Timeout, POLL_INTERVAL)
		conn := new(Http_Mock_Conn)
		conn.mock = m
		conn.socket = client
		t := thread.create_and_start_with_poly_data(conn, http_mock_conn)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
http_mock_conn :: proc(conn: ^Http_Mock_Conn) {
	m := conn.mock
	defer {
		net.close(conn.socket)
		free(conn)
		free_all(context.temp_allocator)
	}

	// Read until the end of the request headers; these requests have no body.
	request := make([dynamic]u8, 0, 2048, context.temp_allocator)
	for {
		if sync.atomic_load(&m.stop) {
			return
		}
		chunk: [1024]u8
		n, err := net.recv_tcp(conn.socket, chunk[:])
		// SO_RCVTIMEO expiring on a blocking recv() is EAGAIN on Linux,
		// which core:net reports as .Would_Block, not .Timeout - see
		// h2client.odin's h2_io_read.
		if err == .Timeout || err == .Would_Block {
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		append(&request, ..chunk[:n])
		if strings.contains(string(request[:]), "\r\n\r\n") {
			break
		}
		if len(request) > 16 * 1024 {
			return
		}
	}

	text := string(request[:])
	line_end := strings.index(text, "\r\n")
	if line_end < 0 {
		return
	}
	parts := strings.split(text[:line_end], " ", context.temp_allocator)
	if len(parts) < 2 {
		return
	}
	path := parts[1]

	body := ""
	found := false
	sync.mutex_lock(&m.mu)
	for &route in m.routes {
		if route.path == path {
			route.hits += 1
			body = route.body
			found = true
			break
		}
	}
	sync.mutex_unlock(&m.mu)

	b := strings.builder_make(context.temp_allocator)
	if !found {
		strings.write_string(&b, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	} else {
		strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ")
		strings.write_int(&b, len(body))
		strings.write_string(&b, "\r\nConnection: close\r\n\r\n")
		strings.write_string(&b, body)
	}

	out := transmute([]u8)strings.to_string(b)
	sent := 0
	for sent < len(out) {
		n, err := net.send_tcp(conn.socket, out[sent:])
		if err != nil || n <= 0 {
			return
		}
		sent += n
	}
}
