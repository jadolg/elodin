package upstream

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

/*
A list host that answers one connection per reply, in order, and keeps each
request line, so a test sees the target every hop asked for. `fetch_url` dials
afresh per hop, so a hop is a connection.
*/
@(private = "file")
Hop_Mock :: struct {
	listener: net.TCP_Socket,
	replies:  []string,
	// Copied out of the connection's buffer: the mock thread's scratch arena
	// does not outlive it.
	line_buf: [8][256]u8,
	lines:    [8]string,
	served:   int,
	// Connections that sent a request; a test's dial-out to end the run does not.
	requests: int,
}

@(private = "file")
hop_mock_run :: proc(m: ^Hop_Mock) {
	for reply in m.replies {
		client, _, err := net.accept_tcp(m.listener)
		if err != nil {
			return
		}
		_ = net.set_option(client, .Receive_Timeout, 2 * time.Second)
		request: [dynamic]u8
		buf: [1024]u8
		for !strings.contains(string(request[:]), "\r\n\r\n") {
			n, rerr := net.recv_tcp(client, buf[:])
			if rerr != nil || n <= 0 {
				break
			}
			append(&request, ..buf[:n])
		}
		text := string(request[:])
		if end := strings.index(text, "\r\n"); end >= 0 {
			n := copy(m.line_buf[m.served][:], text[:end])
			m.lines[m.served] = string(m.line_buf[m.served][:n])
			m.requests += 1
		}
		delete(request)
		sync.atomic_add(&m.served, 1)
		_, _ = net.send_tcp(client, transmute([]u8)reply)
		net.close(client)
	}
}

// Fetch `path` from a mock that sends `replies` in turn, and the requests it saw.
@(private = "file")
fetch_through :: proc(t: ^testing.T, path: string, replies: []string) -> (body: string, err: Error, lines: []string, ok: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return
	}
	m := new(Hop_Mock, context.temp_allocator)
	m.listener = listener
	m.replies = replies
	server := thread.create_and_start_with_poly_data(m, hop_mock_run)
	b, ferr := fetch_url(fmt.tprintf("http://127.0.0.1:%d%s", bound.port, path), nil, 2 * time.Second, 5 * time.Second, context.temp_allocator)
	// A fetch that stopped early leaves the mock in accept: dial it out.
	for i := sync.atomic_load(&m.served); i < len(replies); i += 1 {
		if s, derr := net.dial_tcp(bound); derr == nil {
			net.close(s)
		}
	}
	thread.join(server)
	thread.destroy(server)
	return string(b), ferr, m.lines[:m.requests], true
}

@(private = "file")
found :: proc(location: string) -> string {
	return fmt.tprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location)
}

@(private = "file")
OK_REPLY :: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

/*
RFC 9110 10.2.2: a Location is a URI-reference, resolved against the target it
answered (RFC 3986 5.2), so a list host that moves its list with a relative
one is followed (#460). And the query is part of the target at every hop:
`/list?format=hosts` is asked for as `/list?format=hosts`.
*/
@(test)
test_fetch_url_follows_a_relative_location :: proc(t: ^testing.T) {
	Case :: struct {
		start, location, want: string,
	}
	cases := []Case {
		{"/hosts.txt", "/v2/hosts.txt", "GET /v2/hosts.txt HTTP/1.1"},
		{"/lists/a.txt?v=1", "b.txt?v=2", "GET /lists/b.txt?v=2 HTTP/1.1"},
		{"/lists/a.txt?v=1", "?v=2", "GET /lists/a.txt?v=2 HTTP/1.1"},
		{"/lists/a.txt", "../c.txt#part", "GET /c.txt HTTP/1.1"},
		{"/a?format=hosts", "#top", "GET /a?format=hosts HTTP/1.1"},
	}
	for c in cases {
		body, err, lines, ok := fetch_through(t, c.start, {found(c.location), OK_REPLY})
		if !ok {
			return
		}
		testing.expectf(t, err == .None, "%q from %q: %v", c.location, c.start, err)
		testing.expectf(t, body == "ok", "%q from %q: body %q", c.location, c.start, body)
		if testing.expectf(t, len(lines) == 2, "%q from %q: %d requests", c.location, c.start, len(lines)) {
			testing.expect_value(t, lines[0], fmt.tprintf("GET %s HTTP/1.1", c.start))
			testing.expect_value(t, lines[1], c.want)
		}
	}
	free_all(context.temp_allocator)
}

// A network-path reference keeps the scheme and names its own host and port.
@(test)
test_fetch_url_follows_a_network_path_location :: proc(t: ^testing.T) {
	dest, derr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, derr == nil, "cannot listen on loopback: %v", derr) {
		return
	}
	defer net.close(dest)
	dest_bound, _ := net.bound_endpoint(dest)
	m := new(Hop_Mock, context.temp_allocator)
	m.listener = dest
	m.replies = {OK_REPLY}
	server := thread.create_and_start_with_poly_data(m, hop_mock_run)
	body, err, lines, ok := fetch_through(t, "/a", {found(fmt.tprintf("//127.0.0.1:%d/b?x", dest_bound.port))})
	if sync.atomic_load(&m.served) == 0 {
		if s, e := net.dial_tcp(dest_bound); e == nil {
			net.close(s)
		}
	}
	thread.join(server)
	thread.destroy(server)
	if ok {
		testing.expectf(t, err == .None && body == "ok", "a network-path redirect gave %v, %q", err, body)
		testing.expect_value(t, len(lines), 1)
		testing.expect_value(t, m.lines[0], "GET /b?x HTTP/1.1")
	}
	free_all(context.temp_allocator)
}

/*
A resolved Location is held to every rule an absolute one is: one that resolves
to a target a request line cannot carry is refused (#438), a scheme other than
http or https is refused, and a relative hop counts against the limit of five.
*/
@(test)
test_a_relative_location_is_held_to_the_redirect_rules :: proc(t: ^testing.T) {
	for location in ([]string{"/a b", "ftp://127.0.0.1/x", "http:list"}) {
		_, err, lines, ok := fetch_through(t, "/a", {found(location), OK_REPLY})
		if ok {
			testing.expectf(t, err == .HTTP_Error, "%q was followed: %v", location, err)
			testing.expectf(t, len(lines) == 1, "%q was dialled: %d requests", location, len(lines))
		}
	}
	loop := found("again")
	_, err, lines, ok := fetch_through(t, "/again", {loop, loop, loop, loop, loop, OK_REPLY})
	if ok {
		testing.expectf(t, err == .HTTP_Error, "a relative redirect loop ended in %v", err)
		testing.expectf(t, len(lines) == 5, "a relative redirect loop made %d requests", len(lines))
	}
	free_all(context.temp_allocator)
}

// A scheme is a scheme in any case (RFC 3986 3.1), and is sent as given.
@(test)
test_split_http_url_folds_the_scheme_and_keeps_the_query :: proc(t: ^testing.T) {
	scheme, host, path, port, _, ok := split_http_url("HTTPS://a.example/l?f=hosts#x")
	testing.expect(t, ok, "an uppercase scheme was refused")
	testing.expect_value(t, scheme, "https")
	testing.expect_value(t, host, "a.example")
	testing.expect_value(t, path, "/l?f=hosts")
	testing.expect_value(t, port, 443)
	_, _, path, _, _, ok = split_http_url("http://a.example?f=hosts")
	testing.expect(t, ok && path == "/?f=hosts", "a query with no path is rooted")
	_, _, _, _, _, ok = split_http_url("httpx://a.example/")
	testing.expect(t, !ok, "another scheme split")
	free_all(context.temp_allocator)
}
