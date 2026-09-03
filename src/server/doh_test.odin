package server

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

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

/*
A query over the budget is answered 429 and the connection survives it.

DoH pipelines - `Connection: keep-alive` is what this endpoint advertises - so a
client sitting on one connection can put queries through it as fast as the socket
carries them, and until the limiter was charged here that rate was bounded by
nothing at all: `max_connections` counts connections, and this is one.

429 rather than the bare close TCP and DoT get, because over HTTP there is a
status to say it with; and the connection is kept, because ending it charges this
server a TLS handshake per refusal and the client nothing - see
`serve_doh_request`.

Nothing behind `handle_query` is wired up in this server - no cache, no filters,
no upstream group - which is the other half of what this checks: the charge lands
before the work, so a refused query reaches none of it. A regression that charged
afterwards would not answer 429 here at all.
*/
@(test)
test_doh_refuses_a_query_over_the_rate_limit :: proc(t: ^testing.T) {
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

	// A bare 12-byte DNS header, which is the shortest thing the endpoint takes
	// for a query and enough to get past the length check ahead of the charge.
	body := strings.builder_make(context.temp_allocator)
	strings.write_string(&body, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(&body, "Content-Type: application/dns-message\r\nContent-Length: ")
	strings.write_int(&body, dns.HEADER_SIZE)
	strings.write_string(&body, "\r\n\r\n")
	for _ in 0 ..< dns.HEADER_SIZE {
		strings.write_byte(&body, 0)
	}
	if !send_all(t, client, strings.to_string(body)) {
		return
	}
	// The refusal keeps the connection, so what ends `serve_doh` is the end of the
	// stream rather than the refusal: without this the handler waits for a second
	// request until the receive timeout below.
	net.shutdown(client, .Send)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 500 * time.Millisecond)

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	s := Server {
		cfg = &cfg,
	}
	// One response a second, so the pool holds two and both are spent below.
	// Spent through `stream_rate_check`, because the stream pool is the one a DoH
	// request is charged to and datagrams cannot empty it - see `Rate_Class`. The
	// slip is on, which a connection must not use either way.
	s.limiter = make_rate_limiter(1, 2)
	defer destroy_rate_limiter(s.limiter)

	peer := net.Endpoint {
		address = net.IP4_Loopback,
		port    = 40000,
	}
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect(
			t,
			stream_rate_check(s.limiter, peer, time.tick_now()),
			"the stream budget refused a query it had room for",
		)
	}

	serve_doh(&s, Conn{socket = accepted, peer = peer}, "test")

	_ = net.set_option(client, .Receive_Timeout, 500 * time.Millisecond)
	answer := strings.builder_make(context.temp_allocator)
	for {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answer, chunk[:n])
	}

	head := strings.to_string(answer)
	testing.expect(t, strings.contains(head, "HTTP/1.1 429"), "an over-budget query was not answered 429")
	testing.expect(
		t,
		strings.contains(head, "Connection: keep-alive"),
		"the refusal ended the connection, which makes the next refusal cost a handshake",
	)
	testing.expect(
		t,
		!strings.contains(head, "Connection: close"),
		"the refusal ended the connection, which makes the next refusal cost a handshake",
	)

	limited, slipped := rate_limit_stats(s.limiter)
	testing.expect_value(t, limited, u64(1))
	// A truncated DNS answer is a UDP answer; nothing here may be counted as one.
	testing.expect_value(t, slipped, u64(0))
	free_all(context.temp_allocator)
}

/*
A connection over its budget is refused a query at a time rather than refused
once and closed.

The refusal is the cheapest thing this endpoint does and the close beside it was
the dearest: `Connection: close` sent the client back through the accept path and
a TLS handshake for every question it asked, so a client offering six thousand
queries a second had this server signing about that many key exchanges. More CPU
went on refusing than the flood cost the client, which never has to spoof an
address to provoke it - 236 us per refusal against the HTTP/2 path's 10.5 us on
the same flood, measured in `bench/results/2026-09-03-rate-limit-bystander.md`.

So the two queries here go out pipelined, on one connection, both over the
budget, and both come back 429 on a connection that is still open. What the close
did to the second one is why they are pipelined: it was written before its client
could have read the first refusal, so it arrived either way, and `http_linger`
read it and threw it away.

The client shuts its send side down after writing, which is what ends `serve_doh`
now that a refusal does not: in the server proper that is `client_timeout`.
*/
@(test)
test_doh_keeps_the_connection_after_a_429 :: proc(t: ^testing.T) {
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

	body := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< 2 {
		strings.write_string(&body, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
		strings.write_string(&body, "Content-Type: application/dns-message\r\nContent-Length: ")
		strings.write_int(&body, dns.HEADER_SIZE)
		strings.write_string(&body, "\r\n\r\n")
		for _ in 0 ..< dns.HEADER_SIZE {
			strings.write_byte(&body, 0)
		}
	}
	if !send_all(t, client, strings.to_string(body)) {
		return
	}
	net.shutdown(client, .Send)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	// Longer than the handler should need for either request, so that a
	// regression that goes back to closing shows up as a missing second refusal
	// rather than as a read this test gave up on.
	_ = net.set_option(accepted, .Receive_Timeout, 2 * time.Second)

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	s := Server {
		cfg = &cfg,
	}
	s.limiter = make_rate_limiter(1, 2)
	defer destroy_rate_limiter(s.limiter)

	peer := net.Endpoint {
		address = net.IP4_Loopback,
		port    = 40002,
	}
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect(
			t,
			stream_rate_check(s.limiter, peer, time.tick_now()),
			"the stream budget refused a query it had room for",
		)
	}

	serve_doh(&s, Conn{socket = accepted, peer = peer}, "test")

	_ = net.set_option(client, .Receive_Timeout, 500 * time.Millisecond)
	answer := strings.builder_make(context.temp_allocator)
	for {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answer, chunk[:n])
	}

	head := strings.to_string(answer)
	testing.expectf(
		t,
		strings.count(head, "HTTP/1.1 429") == 2,
		"the second over-budget query cost a connection instead of a 429: %q",
		head,
	)
	testing.expect(
		t,
		!strings.contains(head, "Connection: close"),
		"a refusal ended the connection, which charges the next one a TLS handshake",
	)

	// Both refusals are the budget's, and neither is a truncated UDP answer.
	limited, slipped := rate_limit_stats(s.limiter)
	testing.expect_value(t, limited, u64(2))
	testing.expect_value(t, slipped, u64(0))
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
	http_linger(conn, HTTP_LINGER_BODY_IDLE)
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

@(private = "file")
Late_Body :: struct {
	socket: net.TCP_Socket,
	body:   string,
	delay:  time.Duration,
	ready:  sync.Sema,
	go:     sync.Sema,
}

/*
Writes the body its request already declared, when told to, on a connection it
leaves open - which is what a client on a link with any latency looks like from
this end, and what `test_a_refusal_outlives_the_close_that_follows_it` cannot
show, its body being on the wire before the reader is.

Two semaphores and one sleep, and which is which is the point. The sleep used to
be the whole of it, timed from whenever this thread happened to start, and it had
to be long enough that the reader always won the race to it and short enough that
the drain was always still waiting when it ended. On a loaded runner it was
neither: thread start is unbounded, `time.sleep` may overshoot by as much as it
was asked for, and between them the body could arrive after the drain and the
check behind it had both finished - which is the flakiness this test had, on both
architectures, with the suite at its normal speed.

Both unbounded terms are taken out rather than one. `ready` is posted from inside
the thread, and the caller waits for it before it starts reading, so thread start
is absorbed where nothing is timing it; `go` is posted once the refusal has been
written, so the body cannot reach the wire before then however this thread is
scheduled. What is left to time is the sleep below - 50 ms against the 250 the
drain waits out - and it now runs on a thread known to be alive and sitting on
this line, rather than standing in for one that may not have started.
*/
@(private = "file")
send_late_body :: proc(lb: ^Late_Body) {
	sync.sema_post(&lb.ready)
	sync.sema_wait(&lb.go)
	time.sleep(lb.delay)
	sent := 0
	raw := transmute([]u8)lb.body
	for sent < len(raw) {
		n, err := net.send_tcp(lb.socket, raw[sent:])
		if err != nil || n <= 0 {
			return
		}
		sent += n
	}
}

/*
A refusal reaches the client when the body that earned it had not finished
arriving.

The other direction of `test_a_refusal_outlives_the_close_that_follows_it`. There
the body was on the wire before the reader ran, so a drain of any length at all
found it in the receive queue and read it. Here the request line is refused while
the declared body is still a round trip away, which is what every DoH client on a
real link looks like: `read_http_request` turns a request down on its version
before it has read a header, and the body the client is still sending arrives
after the answer has been written.

A drain that stops waiting while that body is still on its way is the same loss as
not draining at all, reached the other way round. What decides which close happens
is whether the receive queue is empty when it does: empty sends a FIN, and unread
bytes send an RST (RFC 1122 4.2.2.13), whose arrival has the client's kernel
discard the status already sitting in its receive buffer and hand its next read a
connection reset instead - so waiting 50 ms for a body that is 100 ms away costs
the client its 400 exactly as closing straight over it would.

Both halves of that are checked, in the order they happen: what the drain left
behind for the close to trip over, and then whether the status survived the close.
The first is the mechanism and the second is the consequence, and shortening the
wait fails on both.

The sequence is waited for rather than timed, which it did not used to be. A
100 ms sleep in the sender stood in for a round trip against the 250 ms of
`HTTP_LINGER_BODY_IDLE`, and the margin between the two was supposed to keep the
result off the scheduler. It did not: on a loaded CI runner the sender's thread
start plus a sleep that may overshoot by its own length put the body on the wire
after the drain and after the 500 ms check behind it, so the close met bytes
nobody had drained and the RST took the 400 with it - the test reporting the real
consequence of a body it had itself sent too late. It failed on both
architectures with the suite at its normal speed.

`Late_Body` is now handed its turn instead of guessing at it: it reports itself
alive before the reader runs, waits to be told the refusal has been written, and
only then sleeps the round trip - 50 ms against the drain's 250. Thread start and
sleep overshoot were the two unbounded terms sitting inside that margin, and both
are now outside it.

The sender is reaped between the drain and the check rather than after both, so
an empty queue at the check can only mean the drain emptied it. That is what a
late body used to be able to counterfeit, and the exact shape of the old failure:
16 KiB turning up after the drain and the check had finished, and the close
sending an RST over it.

What is deliberately *not* done is waiting for the body before the drain, which
would be more deterministic still. `http_linger` has to be what meets a body on
its way: with the whole 16 KiB already in the receive queue before the drain
began, a drain of any length would read it, and shortening
`HTTP_LINGER_BODY_IDLE` would stop failing this test - which is most of what it
is for. Nothing about the property changed either way: the body still cannot
exist on the wire until after the refusal was read and written, which is what
makes this the opposite case to the test named above.

The client never shuts its sending half down, so nothing but that wait ends the
drain.
*/
@(test)
test_a_refusal_outlives_a_body_that_is_still_arriving :: proc(t: ^testing.T) {
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
	// So that the body's blocking write cannot outlive the test. `thread.join`
	// below waits for that write, and without this a peer window that never opens
	// - a drain that stopped reading on a host with small socket buffers - would
	// hang the join rather than fail an assertion. See the note on the join.
	_ = net.set_option(client, .Send_Timeout, 3 * time.Second)

	// The head alone. A `JUNK` version is refused on the request line, which is
	// before `read_http_request` has looked at the Content-Length that says the
	// rest is coming.
	LATE :: 16 * 1024
	head := strings.builder_make(context.temp_allocator)
	strings.write_string(&head, "POST /dns-query JUNK\r\nHost: dns.example\r\nContent-Length: ")
	strings.write_int(&head, LATE)
	strings.write_string(&head, "\r\n\r\n")
	if !send_all(t, client, strings.to_string(head)) {
		return
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)
	conn := Conn {
		socket = accepted,
	}

	body := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< LATE {
		strings.write_byte(&body, 'x')
	}
	/*
	A fifth of the drain's wait, so the margin is plainly a margin. It stands in
	for the round trip the body is away, and it is deliberately an absolute figure
	rather than a fraction of `HTTP_LINGER_BODY_IDLE`: derived from the constant it
	would shrink with it, and shortening the drain is the thing this test exists to
	fail on.
	*/
	late := Late_Body {
		socket = client,
		body   = strings.to_string(body),
		delay  = 50 * time.Millisecond,
	}
	sender := thread.create_and_start_with_poly_data(&late, send_late_body)
	defer thread.destroy(sender)

	// Wait for it to be alive and waiting before anything below is timed against
	// it. Thread start is the other unbounded term this test used to have inside
	// its margin; absorbed here, it is outside it.
	sync.sema_wait(&late.ready)

	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	_, status, parsed := read_http_request(&r)
	testing.expect(t, !parsed, "a JUNK version was accepted")
	testing.expectf(t, status == 400, "answered %d, expected 400", status)
	/*
	The point of the arrangement: the reader is done before the body exists on the
	wire, so the drain is the only thing that can take it off. What is left in the
	buffer here is the rest of the head - the two headers the refused request line
	was followed by, which the first fill read along with it - and nothing of the
	body still to come.
	*/
	testing.expectf(
		t,
		len(r.buf) - r.pos < len(strings.to_string(head)),
		"%d bytes were left over, which is more than the head: the body arrived before the refusal, and this is the other test",
		len(r.buf) - r.pos,
	)

	// `serve_doh`'s refusal path, in its order: the answer, then the drain.
	_ = send_http_error(conn, "doh", status, http_refusal_message(status), false)

	/*
	And now the body is allowed onto the wire - after the refusal was read and
	written, which is the property separating this test from
	`test_a_refusal_outlives_the_close_that_follows_it`, and which the post turns
	from a race into an ordering.

	It must not be waited for here. The drain has to be what meets a body still on
	its way, so the sender runs against `http_linger` and is reaped after the check
	below. Were the 16 KiB already in the receive queue when the drain started, any
	wait at all would read it and a shortened `HTTP_LINGER_BODY_IDLE` would pass.
	*/
	sync.sema_post(&late.go)
	http_linger(conn, HTTP_LINGER_BODY_IDLE)

	/*
	Reaped here, between the drain and the check, so that what the check sees can
	only be the drain's doing. The body is fully written by the time this returns,
	so an empty queue below means the drain read it rather than that it had yet to
	be sent - which is the reading a late sender used to be able to fake, and the
	shape the old failure took: bytes arriving after both the drain and the check
	had finished, and the close sending an RST over them.

	A join can block, which is why the sender's socket carries a send timeout. In
	the ordinary case it cannot: 16 KiB goes into a loopback receive buffer two
	orders of magnitude larger whether or not anything is draining, and a drain
	that gave up early leaves it all sitting there for the check to find. But that
	is a fact about this machine's `net.core.rmem_default`, not about the test, and
	on a host that sized its buffers smaller a half-written body with no reader
	would hang here rather than fail - a suite that stops saying anything instead
	of one that says what went wrong. The timeout keeps the bad case loud.
	*/
	thread.join(sender)

	/*
	And then the sending half goes down, which is what makes the check below an
	answer rather than a guess.

	`send_tcp` returning means the bytes reached the kernel's send buffer, not that
	they reached the server - so a joined sender can still have a body in flight,
	and the check reading nothing could mean either that the drain took it all or
	that it has yet to land. That ambiguity is the last of this test's flakiness:
	when the body landed after the check, the close met unread bytes and sent an
	RST, the client lost its 400, and the failure named the close while saying
	nothing about the body being late.

	A FIN is queued behind everything already written, so once this is sent the
	read below can only return the leftover the drain failed to take, or the clean
	EOF that says there was none - `conn_read` reports both as `ok = false` only in
	the second case, since it requires `got > 0`. Nothing can arrive afterwards
	either, which is what leaves the close with one possible outcome.

	It does not weaken what the drain was measured against. `http_linger` had
	already returned before this line, ended by its own idle timeout with the
	sending half still open, which is what the docstring above means by nothing
	but that wait ending the drain.
	*/
	// Kept rather than discarded. This is the first operation on `client` after
	// whatever the teardown does to the connection, so on a failing run it is where
	// a pending `ECONNRESET` is consumed - which is why the read below then saw the
	// socket's *second* reading, `Not_Connected`, rather than the first. Naming it
	// lets the final check report whether the reset had already arrived by here.
	shutdown_err := net.shutdown(client, .Send)

	/*
	The assertion, taken before the close it is about: read to the end of what the
	client sent, and require it to have been nothing. A drain that covered the body
	leaves only the FIN queued behind it; a drain that gave up before the body
	arrived left it to turn up here, which is the close finding it there and
	sending an RST instead of a FIN.

	Read to a clean EOF rather than to one read returning nothing, which is what
	this used to do and is where an earlier round of flakiness lived. `conn_read`
	reports a receive timeout and an orderly shutdown the same way - `ok = false`,
	because it asks only for `got > 0` - so a body that had not yet landed within
	the wait was read as a queue that was empty, and the close then met the bytes
	and took the 400 with it in an RST. A `recv` returning zero with no error
	cannot be faked by a slow sender: the FIN is queued behind everything the
	client wrote, so reaching it means every byte before it has already been read
	here.

	`Not_Connected` and the `Connection_Closed` that precedes it name a socket the
	peer reset, not bytes still on their way, and they are the end of the read, not
	a failure of it. The verdict is `behind`, which counts bytes, and a client that
	gave up mid-body reaches this loop as data followed by the FIN of its
	`shutdown(.Send)` - counted and caught below - never as an RST, because this
	test's client only ever shuts its sending half down. An RST here is the
	teardown's own doing rather than the drain's, it flushes the receive queue as it
	lands so there is nothing left to measure, and taking it as the errno-shaped
	verdict is what let the suite stop on a socket state while saying nothing about
	the body. See the note on `Not_Connected` in issue #197: it is `recv` on a
	socket already torn down, distinct from the receive timeout, which surfaces as
	`Would_Block` on Linux and is a body that never arrived at all - a real hang,
	and still a failure that says so.

	The timeout is that guard against a hang rather than the mechanism, which is why
	it is generous and why it is written out rather than derived from
	`HTTP_LINGER_BODY_IDLE`: read for as long as the drain waits and a shortened
	drain would be measured with the same short ruler that shortened it, which is a
	check that agrees with whatever the constant says.
	*/
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)
	behind := 0
	for {
		leftover: [4096]u8
		n, rerr := net.recv_tcp(accepted, leftover[:])
		if rerr == .Not_Connected || rerr == .Connection_Closed {
			break
		}
		if rerr != nil {
			testing.expectf(t, false, "the client's bytes never finished arriving: %v", rerr)
			return
		}
		if n == 0 {
			break
		}
		behind += n
	}
	testing.expectf(
		t,
		behind == 0,
		"%d bytes were still on their way when the drain gave up, and the close will send an RST over them",
		behind,
	)

	net.close(accepted)

	/*
	And the consequence: the status the drain protected has to be the thing the
	client reads back. The verdict is the bytes, not the socket's state - so a reset
	ends this read the same way an EOF does and lets the prefix check below speak. A
	400 the client had already taken off the wire before the connection went down
	survives in `reply` and passes; a 400 an RST discarded before it was read leaves
	`reply` empty and fails, naming what was read and whether `shutdown` had already
	seen the reset. Only a receive timeout - `Would_Block`, a 400 that never came at
	all - is the hard failure here.
	*/
	reply := make([dynamic]u8, 0, 4096, context.temp_allocator)
	for len(reply) < 4096 {
		chunk: [512]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr == .Not_Connected || rerr == .Connection_Closed {
			break
		}
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
		"the client read %q (shutdown reported %v), expected the 400 that was written",
		string(reply[:min(len(reply), 40)]),
		shutdown_err,
	)
	free_all(context.temp_allocator)
}
