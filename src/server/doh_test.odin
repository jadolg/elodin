package server

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"

/*
The DoH reader hands back views into a buffer it goes on appending to.

`http_line` returns a slice of `Http_Reader.buf`, and `read_http_request` keeps
several of those - the method, the path, the query string, the content type -
while it reads the headers and then the body. Every one of those reads can grow
the buffer past its capacity, and a grown buffer is a different block.

That the fields still read correctly today is a property of the arena behind
`context.temp_allocator`, which copies the old contents forward and does not
reclaim the block until `free_all`. Nothing in the reader depends on that, or
says so, and any other allocator invalidates the lot.
*/

// Delegates everything, and scribbles over a block before letting go of it.
// A correct reader never notices; one holding a view into a released block
// reads 0xDD.
@(private = "file")
Poisoning_Allocator :: struct {
	backing: mem.Allocator,
}

@(private = "file")
poisoning_proc :: proc(
	allocator_data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	p := cast(^Poisoning_Allocator)allocator_data
	b := p.backing

	#partial switch mode {
	case .Resize, .Resize_Non_Zeroed:
		// Done by hand rather than passed through, so the old block can be
		// scribbled on after its contents have been carried over.
		fresh, err := b.procedure(b.data, .Alloc, size, alignment, nil, 0, location)
		if err != nil {
			return nil, err
		}
		if old_memory != nil && old_size > 0 {
			copy(fresh, (cast([^]u8)old_memory)[:min(old_size, size)])
			mem.set(old_memory, 0xDD, old_size)
			_, _ = b.procedure(b.data, .Free, 0, 0, old_memory, old_size, location)
		}
		return fresh, nil

	case .Free:
		if old_memory != nil && old_size > 0 {
			mem.set(old_memory, 0xDD, old_size)
		}
	}
	return b.procedure(b.data, mode, size, alignment, old_memory, old_size, location)
}

@(private = "file")
poisoning_allocator :: proc(p: ^Poisoning_Allocator) -> mem.Allocator {
	return mem.Allocator{procedure = poisoning_proc, data = p}
}

@(private = "file")
Sender :: struct {
	endpoint: net.Endpoint,
	request:  string,
}

@(private = "file")
send_request :: proc(s: ^Sender) {
	socket, err := net.dial_tcp_from_endpoint(s.endpoint)
	if err != nil {
		return
	}
	defer net.close(socket)
	sent := 0
	raw := transmute([]u8)s.request
	for sent < len(raw) {
		n, serr := net.send_tcp(socket, raw[sent:])
		if serr != nil || n <= 0 {
			return
		}
		sent += n
	}
	// Held open until the reader has had its turn; closing here would race the
	// body read.
	time.sleep(250 * time.Millisecond)
}

/*
A request whose headers outgrow the reader's buffer must still parse.

The buffer starts at 4096 bytes, and MAX_HEADER_BYTES allows four times that,
so a request with a few kilobytes of headers - which any client is free to send
- grows it after the request line has already been sliced up.
*/
@(test)
test_doh_request_survives_a_buffer_that_grows :: proc(t: ^testing.T) {
	// Not from the temp allocator: it is about to be replaced, and this is
	// scaffolding rather than anything under test.
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(&b, "Content-Type: application/dns-message\r\n")
	// Enough padding to take the buffer past its initial capacity, well inside
	// what MAX_HEADER_BYTES permits.
	for i in 0 ..< 60 {
		strings.write_string(&b, "X-Padding-")
		strings.write_int(&b, i)
		strings.write_string(&b, ": ")
		for _ in 0 ..< 100 {
			strings.write_byte(&b, 'p')
		}
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "Content-Length: 4\r\n\r\nabcd")
	request := strings.to_string(b)

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	sender := Sender {
		endpoint = bound,
		request  = request,
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	defer {
		thread.join(client)
		thread.destroy(client)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	// Backed by an arena of its own, so the copies the reader is about to make
	// go away with it rather than showing up as leaks in the memory report.
	arena: virtual.Arena
	if aerr2 := virtual.arena_init_growing(&arena); aerr2 != nil {
		testing.expectf(t, false, "cannot create an arena: %v", aerr2)
		return
	}
	defer virtual.arena_destroy(&arena)
	poison := Poisoning_Allocator {
		backing = virtual.arena_allocator(&arena),
	}
	// The reader's buffer comes from `context.temp_allocator`; swapped for one
	// that will not quietly keep a released block readable.
	saved := context.temp_allocator
	context.temp_allocator = poisoning_allocator(&poison)
	defer context.temp_allocator = saved

	r := Http_Reader {
		conn = Conn{socket = accepted},
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	defer delete(r.buf)

	req, _, ok := read_http_request(&r)
	testing.expect(t, ok, "the request did not parse")
	if !ok {
		return
	}
	testing.expect_value(t, req.method, "POST")
	testing.expect_value(t, req.path, "/dns-query")
	testing.expect_value(t, req.content_type, "application/dns-message")
	testing.expect_value(t, string(req.body), "abcd")
}

/*
Two requests in one segment are two requests.

A client may send the next request without waiting for the answer to this one
(RFC 9112 9.3), and `Connection: keep-alive` is what this endpoint advertises.
Those bytes are read off the socket along with the request being parsed and sit
in the reader's buffer past its end, so a reader that does not outlive the
request takes them with it: the second request is dropped whole - the client
waits for an answer until `client_timeout` closes the connection - or, when only
part of it had arrived, the next `http_line` resumes in the middle of it and
reads a garbage request line.

Both go to a path this server does not serve, so both answers come from
`send_http_error` and no resolver, cache or upstream has to exist for it. The
first carries a body, which puts the leftover past what `http_exact` consumed
rather than only past a header line.
*/
@(test)
test_doh_answers_a_pipelined_pair :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return
	}
	defer net.close(client)

	// A few hundred bytes, so both requests are in flight before the server
	// reads anything and the second arrives in the same read as the first.
	pipelined :=
		"POST /not-served HTTP/1.1\r\nHost: dns.example\r\nContent-Length: 4\r\n\r\nabcd" +
		"GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\n"
	sent := 0
	raw := transmute([]u8)pipelined
	for sent < len(raw) {
		n, serr := net.send_tcp(client, raw[sent:])
		if serr != nil || n <= 0 {
			testing.expectf(t, false, "cannot send the requests: %v", serr)
			return
		}
		sent += n
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	// Nothing follows the pair, so the handler ends on this rather than on a
	// close: it stands in for `client_timeout` on a connection kept open.
	_ = net.set_option(accepted, .Receive_Timeout, 500 * time.Millisecond)

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	serve_doh(&s, Conn{socket = accepted}, "test")

	_ = net.set_option(client, .Receive_Timeout, 500 * time.Millisecond)
	answers := strings.builder_make(context.temp_allocator)
	for {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answers, chunk[:n])
	}

	testing.expect_value(t, strings.count(strings.to_string(answers), "HTTP/1.1 404"), 2)
	free_all(context.temp_allocator)
}

/*
One large request does not leave the connection holding a large buffer.

The reader outlives the request now, so its buffer is no longer handed back by
the `free_all` between requests: it holds whatever the largest request on the
connection made it grow to. A body at `MAX_DOH_BODY` doubles it to 128 KiB, and
a client that sends one and then goes back to 200-byte queries would keep that
for as long as it holds the connection open - no malformed input needed, and
multiplied by `server.max_connections`.

Checked either side of `http_compact`, so this fails if the growth stops
happening as well as if the buffer stops being given back.
*/
@(test)
test_doh_reader_gives_back_an_oversized_buffer :: proc(t: ^testing.T) {
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(&b, "Content-Type: application/dns-message\r\nContent-Length: ")
	strings.write_int(&b, MAX_DOH_BODY)
	strings.write_string(&b, "\r\n\r\n")
	for _ in 0 ..< MAX_DOH_BODY {
		strings.write_byte(&b, 'q')
	}

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	// On its own thread: 64 KiB is more than the socket buffers hold, so the
	// send only finishes as the read below drains it.
	sender := Sender {
		endpoint = bound,
		request  = strings.to_string(b),
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	defer {
		thread.join(client)
		thread.destroy(client)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	r := Http_Reader {
		conn = Conn{socket = accepted},
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE),
	}
	defer delete(r.buf)

	req, _, ok := read_http_request(&r)
	testing.expect(t, ok, "the request did not parse")
	if !ok {
		return
	}
	testing.expect_value(t, len(req.body), MAX_DOH_BODY)
	testing.expect(t, cap(r.buf) > HTTP_BUF_SIZE, "the body did not grow the buffer, so there is nothing to give back")

	http_compact(&r)
	testing.expect_value(t, len(r.buf), 0)
	testing.expect_value(t, cap(r.buf), HTTP_BUF_SIZE)
}

@(private = "file")
Doh_Session :: struct {
	server: ^Server,
	conn:   Conn,
}

@(private = "file")
run_serve_doh :: proc(d: ^Doh_Session) {
	serve_doh(d.server, d.conn, "test")
}

/*
The half of the next request that has already arrived is still the front of it.

This is the worse of the two ways the per-request reader lost pipelined bytes.
The dropped-whole case costs an answer; here the leftover is a fragment, and the
next `http_line` starts wherever the socket resumes - the middle of the request
line - so what the server reads is not the request the client sent. It parses as
garbage and the connection is closed under a client that did nothing wrong.

The pause between the two writes is what puts the split there: the first read
takes the whole of one request and the beginning of the next.
*/
@(test)
test_doh_answers_a_request_that_arrives_split :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return
	}
	defer net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	// Longer than the pause below, so the handler waits for the rest of the
	// second request rather than timing out on it.
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	session := Doh_Session {
		server = &s,
		conn   = Conn{socket = accepted},
	}
	handler := thread.create_and_start_with_poly_data(&session, run_serve_doh)
	defer {
		thread.join(handler)
		thread.destroy(handler)
	}

	// The first request and the request line of the second, cut mid-target.
	if !send_all(t, client, "GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\nGET /not-se") {
		net.shutdown(client, .Send)
		return
	}
	time.sleep(200 * time.Millisecond)
	if !send_all(t, client, "rved HTTP/1.1\r\nHost: dns.example\r\n\r\n") {
		net.shutdown(client, .Send)
		return
	}

	_ = net.set_option(client, .Receive_Timeout, 2 * time.Second)
	answers := strings.builder_make(context.temp_allocator)
	for strings.count(strings.to_string(answers), "HTTP/1.1 404") < 2 {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answers, chunk[:n])
	}

	testing.expect_value(t, strings.count(strings.to_string(answers), "HTTP/1.1 404"), 2)
	// Ends the handler: with nothing more to read it returns instead of sitting
	// out its receive timeout.
	net.shutdown(client, .Send)
	free_all(context.temp_allocator)
}

@(private = "file")
send_all :: proc(t: ^testing.T, socket: net.TCP_Socket, raw: string) -> bool {
	sent := 0
	bytes := transmute([]u8)raw
	for sent < len(bytes) {
		n, err := net.send_tcp(socket, bytes[sent:])
		if err != nil || n <= 0 {
			testing.expectf(t, false, "cannot send: %v", err)
			return false
		}
		sent += n
	}
	return true
}

/*
Hand `raw` to `read_http_request` over a loopback socket.

The sender closes as soon as its bytes are away. A reader that asks for more
than what was sent therefore reaches the end of the connection instead of
blocking, which is what a body shorter than its declared length has to look
like here.

`status` is what the reader asks the caller to answer a refused request with,
and `ok` is whether the loopback pair itself came up - not whether the request
parsed, which is `parsed`.
*/
@(private = "file")
read_request_over_loopback :: proc(
	t: ^testing.T,
	raw: string,
	what: string,
) -> (
	req: Http_Request_In,
	status: int,
	parsed, ok: bool,
) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "%s: cannot listen on loopback: %v", what, lerr)
		return {}, 0, false, false
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "%s: cannot read the bound port: %v", what, berr)
		return {}, 0, false, false
	}

	// A few hundred bytes, so the whole request fits in the socket buffer and
	// this side never has to interleave sending with the reading below.
	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "%s: cannot dial the listener: %v", what, derr)
		return {}, 0, false, false
	}
	sent := 0
	bytes := transmute([]u8)raw
	for sent < len(bytes) {
		n, serr := net.send_tcp(client, bytes[sent:])
		if serr != nil || n <= 0 {
			net.close(client)
			testing.expectf(t, false, "%s: cannot send the request: %v", what, serr)
			return {}, 0, false, false
		}
		sent += n
	}
	net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "%s: nothing connected: %v", what, aerr)
		return {}, 0, false, false
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	r := Http_Reader {
		conn = Conn{socket = accepted},
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	req, status, parsed = read_http_request(&r)
	return req, status, parsed, true
}

/*
A request line is three tokens, and the third of them is a version this server
speaks.

RFC 9112 3 writes it as `method SP request-target SP HTTP-version` with nothing
around it, and 2.3 writes the version as `HTTP/1.<DIGIT>` here. Split on its
first two spaces and never looked at, the third token took anything: `JUNK` was
read as a version, and so was `HTTP/1.1 trailing-garbage`, because everything
after the target - further spaces included - landed in it.

Both are the disagreement the `Content-Length` cases below are about, on the
other half of the request line. A front end sharing :443 with elodin, or
terminating TLS in front of it, reads the version as the grammar writes it: it
refuses the message, or - for `HTTP/1.1 x` - takes the target to be `/` on a
request this hop was willing to answer. `Host` is the same argument again: RFC
9112 3.2 makes it mandatory on HTTP/1.1 and a repeat invalid, for the reason a
repeated `Content-Length` is.

Which refusal each one gets is checked too, because the two are not
interchangeable: 505 says the *major version* is unsupported (RFC 9110 15.6.6),
which a client acts on by asking again in another version, and every other failure
here is a malformed request line, which RFC 9112 3 answers with a 400. A `JUNK`
answered 505 sends a client off to change something that was never wrong.

`status` is what the caller answers with, and 0 is "answer nothing, close" - the
framing cases keep that, an answer on a connection whose next byte this server
cannot place being worse than a close.
*/
@(test)
test_request_line_is_three_tokens_with_a_known_version :: proc(t: ^testing.T) {
	Case :: struct {
		line:       string, // the request line, without its CRLF
		host:       string, // the Host field lines, if any, each with its CRLF
		status:     int, // 0 for a request that parses
		keep_alive: bool, // what the version asks for, when it parses
		what:       string,
	}

	HOST :: "Host: dns.example\r\n"
	TWO_HOSTS :: "Host: a.example\r\nHost: b.example\r\n"

	CASES := []Case {
		{"GET /dns-query HTTP/1.1", HOST, 0, true, "an ordinary 1.1 request line"},
		{"GET /dns-query HTTP/1.0", HOST, 0, false, "1.0, which keep-alive is not assumed for"},
		// RFC 9112 3.2 asks for Host on HTTP/1.1; 1.0 predates the field.
		{"GET /dns-query HTTP/1.0", "", 0, false, "1.0 without a Host, which is allowed"},
		{"GET /dns-query HTTP/1.9", HOST, 0, true, "a minor version this major version allows"},
		// 505 is for a major version this server does not speak; a token that is
		// not a version at all is a malformed request line, which is a 400.
		{"GET /dns-query HTTP/2.0", HOST, 505, false, "a major version this endpoint does not speak"},
		{"GET /dns-query HTTP/0.9", HOST, 505, false, "a major version below this one"},
		{"GET /dns-query JUNK", HOST, 400, false, "a version that is not one"},
		{"GET /dns-query HTTP/1.10", HOST, 400, false, "a two-digit minor version, which is not the grammar"},
		{"GET /dns-query http/1.1", HOST, 400, false, "a lowercase version name"},
		{"GET /dns-query HTTP/1.1\t", HOST, 400, false, "a tab on the end of an otherwise good version"},
		{"GET /dns-query HTTP/11", HOST, 400, false, "a version with no dot in it"},
		{"GET /dns-query HTTP/1.x", HOST, 400, false, "a minor version that is not a digit"},
		{"GET /dns-query HTTP/x.1", HOST, 400, false, "a major version that is not a digit"},
		{"GET /dns-query HTTP/1.1 x", HOST, 400, false, "a fourth token"},
		{"GET /dns-query HTTP/1.1 ", HOST, 400, false, "a trailing space"},
		{"GET /dns-query ", HOST, 400, false, "no version at all"},
		{"GET  HTTP/1.1", HOST, 400, false, "an empty target"},
		{" /dns-query HTTP/1.1", HOST, 400, false, "an empty method"},
		{"GET /dns-query", HOST, 400, false, "two tokens"},
		{"GET /dns-query HTTP/1.1", "", 400, false, "1.1 with no Host"},
		{"GET /dns-query HTTP/1.1", HOST + HOST, 400, false, "identical repeats of Host"},
		{"GET /dns-query HTTP/1.1", TWO_HOSTS, 400, false, "conflicting repeats of Host"},
		{"GET /dns-query HTTP/1.0", TWO_HOSTS, 400, false, "repeats of Host on 1.0 as well"},
	}

	for c in CASES {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, c.line)
		strings.write_string(&b, "\r\n")
		strings.write_string(&b, c.host)
		strings.write_string(&b, "\r\n")

		req, status, parsed, ok := read_request_over_loopback(t, strings.to_string(b), c.what)
		if !ok {
			return
		}
		if c.status == 0 {
			testing.expectf(t, parsed, "%s was refused with a %d", c.what, status)
			if parsed {
				testing.expectf(
					t,
					req.keep_alive == c.keep_alive,
					"%s: keep_alive came back as %v, expected %v",
					c.what,
					req.keep_alive,
					c.keep_alive,
				)
			}
		} else {
			testing.expectf(t, !parsed, "%s was accepted, as %q", c.what, req.path)
			testing.expectf(t, status == c.status, "%s: answered %d, expected %d", c.what, status, c.status)
		}
		free_all(context.temp_allocator)
	}
}

/*
`Content-Length` is `1*DIGIT` (RFC 9110 8.6) and nothing else.

Read with `strconv.parse_int` and its default base, it is a good deal more than
that: the base is taken from a prefix, so `0x10` is 16 and `0b1010` is 10; `_`
between digits is skipped, so `1_0` is 10; a leading sign is allowed; and the
accumulator wraps without reporting it, so `18446744073709551620` is 4 and the
range check that follows sees nothing wrong with it.

Every one of those is a length elodin would act on and a front end would not.
Sharing :443 with a web server, or terminating TLS at nginx, haproxy or Envoy,
is an ordinary way to run DoH, and those parse the field as the RFC writes it -
so they reject the message or take a different length from it. Two hops that
disagree about where one request ends is the whole of CL.CL request smuggling:
what elodin reads as the tail of a body, the front end reads as the start of
the next request, and attributes to whoever's connection it is pipelining onto.

Repeats are refused for the same reason (RFC 9112 6.3). The loop kept the last
one it saw, and nothing says a proxy in front resolves the same way.
*/
@(test)
test_content_length_is_strict_decimal :: proc(t: ^testing.T) {
	Case :: struct {
		headers:  string, // between the request line and the blank line
		body:     string,
		accepted: bool,
		what:     string,
	}

	CASES := []Case {
		{"Content-Length: 4\r\n", "abcd", true, "a plain decimal length"},
		{"Content-Length: 004\r\n", "abcd", true, "leading zeroes, still 1*DIGIT"},
		{"Content-Length: 0x4\r\n", "abcd", false, "hexadecimal"},
		{"Content-Length: 0b100\r\n", "abcd", false, "binary"},
		{"Content-Length: 0o4\r\n", "abcd", false, "octal"},
		{"Content-Length: 0z4\r\n", "abcd", false, "base twelve, which the prefix table also has"},
		{"Content-Length: 1_0\r\n", "abcdefghij", false, "a digit separator"},
		{"Content-Length: +4\r\n", "abcd", false, "a signed length"},
		{"Content-Length: -4\r\n", "abcd", false, "a negative length"},
		{"Content-Length: \r\n", "", false, "an empty length"},
		{"Content-Length: 4 5\r\n", "abcd", false, "two lengths in one field"},
		// 2^64 + 4: the accumulator wraps to 4 and the range check is happy.
		{"Content-Length: 18446744073709551620\r\n", "abcd", false, "a length past 64 bits"},
		{"Content-Length: 4\r\nContent-Length: 0\r\n", "abcd", false, "conflicting repeats"},
		{"Content-Length: 4\r\nContent-Length: 4\r\n", "abcd", false, "identical repeats"},
		{"Content-Length:\t4\t\r\n", "abcd", true, "tabs around the digits, which is OWS"},
		/*
		Three ways to write a length this reader does not recognise as one while
		a hop in front may: a non-breaking space is not OWS but is whitespace to
		`strings.trim_space`; a folded line is a continuation of the one above it
		(RFC 9112 5.2); and space before the colon is not a field name (RFC 9112
		5.1). Skipped rather than refused, each leaves the body unread and the
		next request starting in the middle of it.
		*/
		{"Content-Length: 4 \r\n", "abcd", false, "a non-breaking space after the digits"},
		{"X-Fold: one\r\n Content-Length: 4\r\n", "abcd", false, "a folded continuation line"},
		{"Content-Length : 4\r\n", "abcd", false, "space before the colon"},
		{"Content-Length\t: 4\r\n", "abcd", false, "a tab before the colon"},
		{"just-some-garbage\r\n", "", false, "a field line with no colon at all"},
	}

	for c in CASES {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
		strings.write_string(&b, "Content-Type: application/dns-message\r\n")
		strings.write_string(&b, c.headers)
		strings.write_string(&b, "\r\n")
		strings.write_string(&b, c.body)

		req, _, parsed, ok := read_request_over_loopback(t, strings.to_string(b), c.what)
		if !ok {
			return
		}
		if c.accepted {
			testing.expectf(t, parsed, "%s was rejected", c.what)
			if parsed {
				testing.expectf(
					t,
					string(req.body) == c.body,
					"%s: body came back as %q, expected %q",
					c.what,
					string(req.body),
					c.body,
				)
			}
		} else {
			testing.expectf(
				t,
				!parsed,
				"%s was accepted, with a %d byte body; a front end would frame this request differently",
				c.what,
				len(req.body),
			)
		}
		free_all(context.temp_allocator)
	}
}

/*
A refusal reaches the client even when the request that earned it went on past
what the reader read.

`read_http_request` turns down a bad request line before it looks at the headers
that would say how long the body is, so the bytes of that body are still sitting
in this server's receive queue when the answer is written - and closing a socket
in that state does not send a FIN but an RST (RFC 1122 4.2.2.13). The RST reaches
a client that has not read yet, its kernel drops what is already in its receive
buffer, and the 400 written a moment earlier is gone: the client is left with a
connection reset, which is exactly the bare closed connection the status was
added to replace.

So the drain has to happen before the close. The body here is larger than one
`http_fill` chunk, which is what leaves bytes behind for the close to trip over -
a request that fits in the first read is drained by having been read. The client
shuts down its sending half rather than closing outright, so the drain ends on the
end of the data instead of on its timeout, and can still read afterwards.
*/
@(test)
test_a_refusal_outlives_the_close_that_follows_it :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 3 * time.Second)

	UNREAD :: 16 * 1024
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "POST /dns-query JUNK\r\nHost: dns.example\r\nContent-Length: ")
	strings.write_int(&b, UNREAD)
	strings.write_string(&b, "\r\n\r\n")
	for _ in 0 ..< UNREAD {
		strings.write_byte(&b, 'x')
	}
	request := transmute([]u8)strings.to_string(b)

	sent := 0
	for sent < len(request) {
		n, serr := net.send_tcp(client, request[sent:])
		if serr != nil || n <= 0 {
			testing.expectf(t, false, "cannot send the request: %v", serr)
			return
		}
		sent += n
	}
	_ = net.shutdown(client, .Send)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)
	conn := Conn {
		socket = accepted,
	}

	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	_, status, parsed := read_http_request(&r)
	testing.expect(t, !parsed, "a JUNK version was accepted")
	testing.expectf(t, status == 400, "answered %d, expected 400", status)
	testing.expect(t, len(r.buf) - r.pos < UNREAD, "the whole body was read, so nothing is left for the close")

	// What `serve_doh` does with a refused request, in the order it does it: the
	// answer, the drain, the close. Its return value is `keep_alive`, which is
	// false here; whether the write landed is what the read below is about.
	_ = send_http_error(conn, "doh", status, http_refusal_message(status), false)
	http_linger(conn)
	net.close(accepted)

	reply := make([dynamic]u8, 0, 4096, context.temp_allocator)
	for len(reply) < 4096 {
		chunk: [512]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil {
			testing.expectf(t, false, "the answer did not survive the close: %v", rerr)
			return
		}
		if n == 0 {
			break
		}
		append(&reply, ..chunk[:n])
	}
	testing.expectf(
		t,
		strings.has_prefix(string(reply[:]), "HTTP/1.1 400 "),
		"the client read %q, expected the 400 that was written",
		string(reply[:min(len(reply), 40)]),
	)
}
