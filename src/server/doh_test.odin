package server

import "core:fmt"
import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:testkit"

/*
The DoH reader hands back views into a buffer it goes on appending to.

`http_line` returns a slice of `Http_Reader.buf`, and `read_http_request` takes
the method, the path, the query string and the content type from those views
while it goes on reading the headers and then the body. Every one of those reads
can grow the buffer past its capacity, and a grown buffer is a different block.

So every field it keeps but the body is copied out (`http_hold`), and this pins that
the copies survive a buffer that moves. The arena behind `context.temp_allocator`
would hide a view into a released block - it copies the old contents forward and
does not reclaim the block until `free_all` - so the test swaps in an allocator
that does not.
*/

// Delegates everything, and scribbles over a block before letting go of it.
// A correct reader never notices; one holding a view into a released block
// reads 0xDD.
@(private)
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

@(private)
poisoning_allocator :: proc(p: ^Poisoning_Allocator) -> mem.Allocator {
	return mem.Allocator{procedure = poisoning_proc, data = p}
}

@(private = "file")
Sender :: struct {
	endpoint: net.Endpoint,
	request:  string,
	// What the dial or the send failed with, read once the thread is joined.
	err:      net.Network_Error,
}

@(private = "file")
send_request :: proc(s: ^Sender) {
	socket, err := net.dial_tcp_from_endpoint(s.endpoint)
	if err != nil {
		s.err = err
		return
	}
	defer net.close(socket)
	// The close behind the send is a FIN after the bytes, which the reader takes
	// in order.
	_, s.err = net.send_tcp(socket, transmute([]u8)s.request)
}

/*
A request whose headers outgrow the reader's buffer must still parse.

The buffer starts at `HTTP_BUF_SIZE`, and MAX_HEADER_BYTES allows four times that,
so a request with a few kilobytes of headers - which any client is free to send
- grows it after the request line has already been sliced up.
*/
@(test)
test_doh_request_survives_a_buffer_that_grows :: proc(t: ^testing.T) {
	// Not from the temp allocator: it is about to be replaced, and this is
	// scaffolding rather than anything under test.
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	request := padded_request(&b)

	listener, bound, lok := loopback_listener(t)
	if !lok {
		return
	}
	defer net.close(listener)
	if !set_wait(t, listener, .Receive_Timeout, 3 * time.Second) {
		return
	}

	sender := Sender {
		endpoint = bound,
		request  = request,
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	defer {
		thread.join(client)
		thread.destroy(client)
		testing.expectf(t, sender.err == nil, "the request was not sent: %v", sender.err)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}

	expect_request_survives(t, accepted)
}

// A POST to `/dns-query` with a four-byte body, its headers padded past the
// reader's initial buffer, written into `b`.
@(private = "file")
padded_request :: proc(b: ^strings.Builder) -> string {
	strings.write_string(b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(b, "Content-Type: application/dns-message\r\n")
	// Enough padding to take the buffer past its initial capacity, well inside
	// what MAX_HEADER_BYTES permits.
	for i in 0 ..< 60 {
		strings.write_string(b, "X-Padding-")
		strings.write_int(b, i)
		strings.write_string(b, ": ")
		for _ in 0 ..< 100 {
			strings.write_byte(b, 'p')
		}
		strings.write_string(b, "\r\n")
	}
	strings.write_string(b, "Content-Length: 4\r\n\r\nabcd")
	return strings.to_string(b^)
}

// Read the padded request off `accepted` through a reader whose released blocks
// are scribbled over, and expect every field of it intact.
@(private = "file")
expect_request_survives :: proc(t: ^testing.T, accepted: net.TCP_Socket) {
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
	// This test's reader takes its buffer from `context.temp_allocator` (the
	// server's is on the heap); swapped for one that will not quietly keep a
	// released block readable.
	saved := context.temp_allocator
	context.temp_allocator = poisoning_allocator(&poison)
	defer context.temp_allocator = saved

	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE, context.temp_allocator),
	}
	defer delete(r.buf)

	req, _, ok := read_http_request(&r)
	if !testing.expect(t, ok, "the request did not parse") {
		return
	}
	testing.expect_value(t, req.method, "POST")
	testing.expect_value(t, req.path, "/dns-query")
	testing.expect_value(t, req.content_type, "application/dns-message")
	testing.expect_value(t, string(req.body), "abcd")
	// A view into the reader's buffer rather than a copy of up to MAX_DOH_BODY
	// (#533), which is what has the callers compact only after serving.
	start := uintptr(raw_data(r.buf))
	testing.expect(t, uintptr(raw_data(req.body)) >= start && uintptr(raw_data(req.body)) < start + uintptr(len(r.buf)), "the body was copied out of the reader's buffer")
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
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)

	// A few hundred bytes, so both requests are in flight before the server
	// reads anything and the second arrives in the same read as the first.
	pipelined :=
		"POST /not-served HTTP/1.1\r\nHost: dns.example\r\nContent-Length: 4\r\n\r\nabcd" +
		"GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\n"
	if _, serr := net.send_tcp(client, transmute([]u8)pipelined); !testing.expectf(t, serr == nil, "cannot send the requests: %v", serr) {
		return
	}
	// Nothing follows the pair, so the end of the stream ends the handler: it
	// stands in for `client_timeout` on a connection kept open.
	net.shutdown(client, .Send)

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	serve_doh(&s, Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}}, "test")
	// The listener's close, so the read below ends at the FIN.
	net.shutdown(accepted, .Send)

	answers, rerr := read_until_close(client, 500 * time.Millisecond)
	testing.expectf(t, rerr == nil, "the read did not end at the FIN: %v", rerr)
	testing.expect_value(t, strings.count(answers, "HTTP/1.1 404"), 2)
	free_all(context.temp_allocator)
}

/*
One large request does not leave the connection holding a large buffer.

The reader lives as long as the connection, so its buffer is not reclaimed
between requests: it holds whatever the largest request on the connection made
it grow to. A body at `MAX_DOH_BODY` doubles it to 128 KiB, and a client that
sends one and then goes back to 200-byte queries would keep that for as long as
it holds the connection open - no malformed input needed, and multiplied by
`server.max_connections`.

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

	listener, bound, lok := loopback_listener(t)
	if !lok {
		return
	}
	defer net.close(listener)

	// On its own thread, so the test does not depend on the socket buffers
	// holding all 64 KiB: the send may only finish as the read below drains it.
	sender := Sender {
		endpoint = bound,
		request  = strings.to_string(b),
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	defer {
		thread.join(client)
		thread.destroy(client)
		testing.expectf(t, sender.err == nil, "the request was not sent: %v", sender.err)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}

	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
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

/*
The half of the next request that has already arrived is still the front of it.

This is the worse of the two ways a reader that did not outlive the request
would lose pipelined bytes. The dropped-whole case costs an answer; here the
leftover would be a fragment, and the next `http_line` would start wherever the
socket resumes - the middle of the request line - so what the server read would
not be the request the client sent. It would parse as garbage and the connection
would be closed under a client that did nothing wrong.

Each write waits for the handler to have read the one before it, which is what
puts the split there: the first read takes the whole of one request and the
beginning of the next.
*/
@(test)
test_doh_answers_a_request_that_arrives_split :: proc(t: ^testing.T) {
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	session := Doh_Session {
		server = &s,
		conn   = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
	}
	handler := thread.create_and_start_with_poly_data(&session, run_serve_doh)
	defer {
		thread.join(handler)
		thread.destroy(handler)
	}
	pair := Split_Pair{client, accepted}
	// The first request and the request line of the second, cut mid-target.
	if !send_and_wait_read(t, &pair, "GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\nGET /not-se", "first") {
		net.shutdown(client, .Send)
		return
	}
	// And cut again between a CR and its LF: `http_line` refuses a bare CR, and
	// a CR that is only the last byte read so far is not one (#432).
	if !send_and_wait_read(t, &pair, "rved HTTP/1.1\r\nHost: dns.example\r", "second") {
		net.shutdown(client, .Send)
		return
	}
	if _, serr := net.send_tcp(client, transmute([]u8)string("\n\r\n")); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		net.shutdown(client, .Send)
		return
	}

	if !set_wait(t, client, .Receive_Timeout, 2 * time.Second) {
		net.shutdown(client, .Send)
		return
	}
	answers := read_until_count(client, "HTTP/1.1 404", 2)
	testing.expect_value(t, strings.count(answers, "HTTP/1.1 404"), 2)
	// Ends the handler: with nothing more to read it returns instead of sitting
	// out its receive timeout.
	net.shutdown(client, .Send)
	free_all(context.temp_allocator)
}

// Both ends of a loopback connection, for `send_and_wait_read`.
@(private = "file")
Split_Pair :: struct {
	client, accepted: net.TCP_Socket,
}

// Everything the client wrote has reached the handler's socket and been read
// off it.
@(private = "file")
all_read :: proc(data: rawptr) -> bool {
	p := (^Split_Pair)(data)
	return testkit.unacked_bytes(linux.Fd(p.client)) == 0 && unread_bytes(linux.Fd(p.accepted)) == 0
}

// Send `part` from the client and wait until the handler has read it off its
// socket; false, with the failure reported, when either does not happen.
@(private = "file")
send_and_wait_read :: proc(t: ^testing.T, p: ^Split_Pair, part: string, which: string, loc := #caller_location) -> bool {
	if _, serr := net.send_tcp(p.client, transmute([]u8)part); !testing.expectf(t, serr == nil, "cannot send: %v", serr, loc = loc) {
		return false
	}
	return testing.expectf(t, wait_until(all_read, p, 2 * time.Second), "the handler never read the %s write", which, loc = loc)
}

// What `client` reads until `needle` has come `count` times, an error, or the
// end of the stream.
@(private = "file")
read_until_count :: proc(client: net.TCP_Socket, needle: string, count: int) -> string {
	answers := strings.builder_make(context.temp_allocator)
	for strings.count(strings.to_string(answers), needle) < count {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answers, chunk[:n])
	}
	return strings.to_string(answers)
}

/*
A query over the budget is answered 429 and the connection survives it.

DoH pipelines - `Connection: keep-alive` is what this endpoint advertises - so a
client sitting on one connection can put queries through it as fast as the
socket carries them, and `max_connections` does not bound that rate: it counts
connections, and this is one.

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
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)

	// A bare 12-byte DNS header, which is the shortest thing the endpoint takes
	// for a query and enough to get past the length check ahead of the charge.
	body := strings.builder_make(context.temp_allocator)
	write_doh_post(&body, make([]u8, dns.HEADER_SIZE, context.temp_allocator))
	if _, serr := net.send_tcp(client, body.buf[:]); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		return
	}
	// The refusal keeps the connection, so what ends `serve_doh` is the end of the
	// stream rather than the refusal: without this the handler waits for a second
	// request until `client_timeout`.
	net.shutdown(client, .Send)

	cfg: config.Config
	s, peer := spent_limiter_server(t, &cfg)
	defer destroy_rate_limiter(s.limiter)

	serve_doh(&s, Conn{socket = accepted, peer = peer}, "test")
	// The listener's close, so the read below ends at the FIN.
	net.shutdown(accepted, .Send)

	head, rerr := read_until_close(client, 500 * time.Millisecond)
	testing.expectf(t, rerr == nil, "the read did not end at the FIN: %v", rerr)
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

	limited, slipped, _ := rate_limit_stats(s.limiter)
	testing.expect_value(t, limited, u64(1))
	// A truncated DNS answer is a UDP answer; nothing here may be counted as one.
	testing.expect_value(t, slipped, u64(0))
	free_all(context.temp_allocator)
}

/*
A connection over its budget is refused a query at a time rather than refused
once and closed.

The refusal is the cheapest thing this endpoint does and a close beside it would
be the dearest: `Connection: close` would send the client back through the
accept path and a TLS handshake for every question it asked, so a client
offering six thousand queries a second would have this server signing about that
many key exchanges. More CPU would go on refusing than the flood cost the
client, which never has to spoof an address to provoke it - 236 us per refusal
against the HTTP/2 path's 10.5 us on the same flood, measured in
`bench/results/2026-09-03-rate-limit-bystander.md`.

So the two queries here go out pipelined, on one connection, both over the
budget, and both come back 429 on a connection that is still open. They are
pipelined because of what a close would do to the second one: it is written
before its client could have read the first refusal, so it arrives either way,
and `http_linger` would read it and throw it away.

The client shuts its send side down after writing, which is what ends
`serve_doh`, since a refusal does not: in the server proper that is
`client_timeout`.
*/
@(test)
test_doh_keeps_the_connection_after_a_429 :: proc(t: ^testing.T) {
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)

	body := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< 2 {
		write_doh_post(&body, make([]u8, dns.HEADER_SIZE, context.temp_allocator))
	}
	if _, serr := net.send_tcp(client, body.buf[:]); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		return
	}
	net.shutdown(client, .Send)

	cfg: config.Config
	s, peer := spent_limiter_server(t, &cfg)
	defer destroy_rate_limiter(s.limiter)

	serve_doh(&s, Conn{socket = accepted, peer = peer}, "test")
	// The listener's close, so the read below ends at the FIN.
	net.shutdown(accepted, .Send)

	head, rerr := read_until_close(client, 500 * time.Millisecond)
	testing.expectf(t, rerr == nil, "the read did not end at the FIN: %v", rerr)
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
	limited, slipped, _ := rate_limit_stats(s.limiter)
	testing.expect_value(t, limited, u64(2))
	testing.expect_value(t, slipped, u64(0))
	free_all(context.temp_allocator)
}

/*
A refusal keeps the connection, but not one the client asked to have closed.

`Connection: close` is the client saying it wants no second request on this
socket, and the 429 carries the client's own `keep_alive` rather than an opinion
of its own - so the one refusal that still ends a connection is the one whose
client asked for it. RFC 9112 9.6: a recipient that reads the field sends no
further requests on that connection, and answering it `keep-alive` would leave
this end waiting out `client_timeout` for a request that is never coming.

A second request, pipelined behind the first, is the probe: a handler that
ignored the field and went back to reading would answer it too, so the count of
refusals is what tells the two apart. The client shuts its send side down after
both, which ends either handler at once. Nothing is drained on the way out: the
two requests arrived in one read, so nothing is left in the receive queue for the
close to turn into an RST.
*/
@(test)
test_doh_429_honours_connection_close :: proc(t: ^testing.T) {
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)

	body := strings.builder_make(context.temp_allocator)
	write_doh_post(&body, make([]u8, dns.HEADER_SIZE, context.temp_allocator), "Connection: close\r\n")
	write_doh_post(&body, make([]u8, dns.HEADER_SIZE, context.temp_allocator))
	if _, serr := net.send_tcp(client, body.buf[:]); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		return
	}
	net.shutdown(client, .Send)

	cfg: config.Config
	s, peer := spent_limiter_server(t, &cfg)
	defer destroy_rate_limiter(s.limiter)

	serve_doh(&s, Conn{socket = accepted, peer = peer}, "test")
	// The listener's close, so the read below ends at the FIN.
	net.shutdown(accepted, .Send)

	head, rerr := read_until_close(client, 500 * time.Millisecond)
	testing.expectf(t, rerr == nil, "the read did not end at the FIN: %v", rerr)
	testing.expectf(
		t,
		strings.count(head, "HTTP/1.1 429") == 1,
		"the handler read on past a `Connection: close` and answered what followed it: %q",
		head,
	)
	testing.expect(
		t,
		strings.contains(head, "Connection: close"),
		"the refusal answered keep-alive to a client that asked for a close",
	)
	free_all(context.temp_allocator)
}

// A DoH POST of `body` to /dns-query, with `extra` header lines after Host.
@(private = "file")
write_doh_post :: proc(b: ^strings.Builder, body: []u8, extra := "") {
	strings.write_string(b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(b, extra)
	strings.write_string(b, "Content-Type: application/dns-message\r\nContent-Length: ")
	strings.write_int(b, len(body))
	strings.write_string(b, "\r\n\r\n")
	strings.write_bytes(b, body)
}

/*
A DoH server on `cfg` whose one client, `peer`, has already spent its stream
budget: one response a second, so the pool holds two and both are spent here.
The slip is on, which a connection must not use either way. The limiter is the
caller's to destroy.
*/
@(private = "file")
spent_limiter_server :: proc(t: ^testing.T, cfg: ^config.Config, loc := #caller_location) -> (s: Server, peer: net.Endpoint) {
	cfg^ = config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	s = Server {
		cfg     = cfg,
		limiter = make_rate_limiter(1, 2),
	}
	peer = net.Endpoint {
		address = net.IP4_Loopback,
		port    = 40000,
	}
	spend_stream_budget(t, s.limiter, peer, loc)
	return s, peer
}

// The size of the body `junk_head` declares.
@(private = "file")
JUNK_BODY :: 16 * 1024

// A POST whose request line is refused on its `JUNK` version, before the reader
// has looked at the `Content-Length` that says `JUNK_BODY` bytes follow.
@(private = "file")
junk_head :: proc() -> string {
	return fmt.tprintf("POST /dns-query JUNK\r\nHost: dns.example\r\nContent-Length: %d\r\n\r\n", JUNK_BODY)
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
`http_fill` read, which is what leaves bytes behind for the close to trip over -
a request that fits in the first read is drained by having been read. The client
shuts down its sending half rather than closing outright, so the drain ends on the
end of the data instead of on its timeout, and can still read afterwards.
*/
@(test)
test_a_refusal_outlives_the_close_that_follows_it :: proc(t: ^testing.T) {
	// `accepted` is closed by hand, ahead of the client's read.
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	if !set_wait(t, client, .Receive_Timeout, 3 * time.Second) {
		net.close(accepted)
		return
	}

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, junk_head())
	for _ in 0 ..< JUNK_BODY {
		strings.write_byte(&b, 'x')
	}
	if _, serr := net.send_tcp(client, b.buf[:]); !testing.expectf(t, serr == nil, "cannot send the request: %v", serr) {
		net.close(accepted)
		return
	}
	_ = net.shutdown(client, .Send)

	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		net.close(accepted)
		return
	}
	conn := Conn {
		socket = accepted,
	}

	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE, context.temp_allocator),
	}
	_, status, parsed := read_http_request(&r)
	testing.expect(t, !parsed, "a JUNK version was accepted")
	testing.expectf(t, status == 400, "answered %d, expected 400", status)
	testing.expect(t, len(r.buf) - r.pos < JUNK_BODY, "the whole body was read, so nothing is left for the close")

	// What `serve_doh` does with a refused request, in the order it does it: the
	// answer, the drain, the close. Its return value is `keep_alive`, which is
	// false here; whether the write landed is what the read below is about.
	_ = send_http_error(conn, "doh", status, http_refusal_message(status), false)
	http_linger(conn, HTTP_LINGER_BODY_IDLE)
	net.close(accepted)

	reply, rerr := read_until_close(client, 3 * time.Second)
	if !testing.expectf(t, rerr == nil, "the answer did not survive the close: %v", rerr) {
		return
	}
	testing.expectf(
		t,
		strings.has_prefix(reply, "HTTP/1.1 400 "),
		"the client read %q, expected the 400 that was written",
		reply[:min(len(reply), 40)],
	)
}

@(private = "file")
Late_Body :: struct {
	socket: net.TCP_Socket,
	body:   string,
	delay:  time.Duration,
	ready:  sync.Sema,
	go:     sync.Sema,
	// What the send failed with, read once the thread is joined.
	err:    net.Network_Error,
}

/*
Writes the body its request already declared, when told to, on a connection it
leaves open - which is what a client on a link with any latency looks like from
this end, and what `test_a_refusal_outlives_the_close_that_follows_it` cannot
show, its body being on the wire before the reader is.

Two semaphores and one sleep, and which is which is the point. Thread start is
unbounded and `time.sleep` may overshoot by as much as it was asked for, so a
sleep timed from whenever this thread happened to start could put the body on
the wire after the drain and the check behind it had both finished, on a loaded
runner. Both unbounded terms are taken out. `ready` is posted from inside the
thread, and the caller waits for it before it starts reading, so thread start is
absorbed where nothing is timing it; `go` is posted once the refusal has been
written, so the body cannot reach the wire before then however this thread is
scheduled. What is left to time is the sleep below - 50 ms against the 250 the
drain waits out - and it runs on a thread known to be alive and sitting on this
line.
*/
@(private = "file")
send_late_body :: proc(lb: ^Late_Body) {
	sync.sema_post(&lb.ready)
	sync.sema_wait(&lb.go)
	time.sleep(lb.delay)
	_, lb.err = net.send_tcp(lb.socket, transmute([]u8)lb.body)
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

The sequence is waited for rather than timed. `Late_Body` is handed its turn:
it reports itself alive before the reader runs, waits to be told the refusal has
been written, and only then sleeps the round trip - 50 ms against the 250 ms of
`HTTP_LINGER_BODY_IDLE`. Thread start and sleep overshoot, the two unbounded
terms, are outside that margin (see `send_late_body`).

The sender is reaped between the drain and the check rather than after both, so
an empty queue at the check can only mean the drain emptied it.

What is deliberately *not* done is waiting for the body before the drain, which
would be more deterministic still. `http_linger` has to be what meets a body on
its way: with the whole 16 KiB already in the receive queue before the drain
began, a drain of any length would read it, and shortening
`HTTP_LINGER_BODY_IDLE` would stop failing this test - which is most of what it
is for. Nothing about the property changes either way: the body still cannot
exist on the wire until after the refusal was read and written, which is what
makes this the opposite case to the test named above.

The client never shuts its sending half down, so nothing but that wait ends the
drain.
*/
@(test)
test_a_refusal_outlives_a_body_that_is_still_arriving :: proc(t: ^testing.T) {
	// `accepted` is closed by hand, ahead of the client's read.
	client, accepted, head, paired := junk_head_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	conn := Conn {
		socket = accepted,
	}
	body, berr := strings.repeat("x", JUNK_BODY, context.temp_allocator)
	if !testing.expectf(t, berr == nil, "cannot build the body: %v", berr) {
		net.close(accepted)
		return
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
		body   = body,
		delay  = 50 * time.Millisecond,
	}
	sender := thread.create_and_start_with_poly_data(&late, send_late_body)
	defer thread.destroy(sender)

	// Wait for it to be alive and waiting before anything below is timed against
	// it, so thread start is absorbed here and is outside the margin.
	sync.sema_wait(&late.ready)

	status := expect_junk_refused_alone(t, conn, len(head))

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
	be sent.

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
	testing.expectf(t, late.err == nil, "the body was not sent: %v", late.err)

	/*
	And then the sending half goes down, which is what makes the check below an
	answer rather than a guess.

	`send_tcp` returning means the bytes reached the kernel's send buffer, not
	that they reached the server - so a joined sender can still have a body in
	flight, and the check reading nothing could mean either that the drain took
	it all or that it has yet to land. Left open, that ambiguity would make the
	test flaky: a body landing after the check would meet the close as unread
	bytes, the RST would cost the client its 400, and the failure would name the
	close while saying nothing about the body being late.

	A FIN is queued behind everything already written, so once this is sent the
	read below can only return the leftover the drain failed to take, or the
	clean EOF that says there was none - `net.recv_tcp` returns the first as
	bytes and the second as zero with no error. Nothing can arrive afterwards
	either, which is what leaves the close with one possible outcome.

	It does not weaken what the drain was measured against. `http_linger` had
	already returned before this line, ended by its own idle timeout with the
	sending half still open, which is what the docstring above means by nothing
	but that wait ending the drain.
	*/
	// Kept rather than discarded. This is the first operation on `client` after
	// whatever the teardown does to the connection, so on a failing run it is where
	// a pending `ECONNRESET` is consumed - which is why the read below then sees the
	// socket's *second* reading, `Not_Connected`, rather than the first. Naming it
	// lets the final check report whether the reset had already arrived by here.
	shutdown_err := net.shutdown(client, .Send)

	/*
	The assertion, taken before the close it is about: read to the end of what the
	client sent, and require it to have been nothing. A drain that covered the body
	leaves only the FIN queued behind it; a drain that gave up before the body
	arrived left it to turn up here, which is the close finding it there and
	sending an RST instead of a FIN.

	Read to a clean EOF rather than to one read returning nothing: a read that
	reports a receive timeout and an orderly shutdown the same way would take a
	body that had not yet landed within the wait for a queue that was empty, and
	the close would then meet the bytes and take the 400 with it in an RST. A
	`recv` returning zero with no error cannot be faked by a slow sender: the
	FIN is queued behind everything the client wrote, so reaching it means every
	byte before it has already been read here.

	`Not_Connected` and the `Connection_Closed` that precedes it name a socket
	the peer reset, not bytes still on their way, and they are the end of the
	read, not a failure of it. The verdict is `behind`, which counts bytes, and
	a client that gave up mid-body reaches this loop as data followed by the FIN
	of its `shutdown(.Send)` - counted and caught below - never as an RST,
	because this test's client only ever shuts its sending half down. An RST
	here is the teardown's own doing rather than the drain's, it flushes the
	receive queue as it lands so there is nothing left to measure, and taking it
	as the errno-shaped verdict would stop the suite on a socket state while
	saying nothing about the body. See the note on `Not_Connected` in issue
	#197: it is `recv` on a socket already torn down, distinct from the receive
	timeout, which surfaces as `Would_Block` on Linux and is a body that never
	arrived at all - a real hang, and still a failure that says so.

	The timeout is that guard against a hang rather than the mechanism, which is why
	it is generous and why it is written out rather than derived from
	`HTTP_LINGER_BODY_IDLE`: read for as long as the drain waits and a shortened
	drain would be measured with the same short ruler that shortened it, which is a
	check that agrees with whatever the constant says.
	*/
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		net.close(accepted)
		return
	}
	if !expect_nothing_left_behind(t, accepted) {
		net.close(accepted)
		return
	}
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
	expect_400_through_a_reset(t, client, shutdown_err)
	free_all(context.temp_allocator)
}

/*
A loopback pair whose client has sent `junk_head` alone, both ends' waits bounded.
On false both sockets are closed and the failure reported.
*/
@(private = "file")
junk_head_pair :: proc(t: ^testing.T) -> (client, accepted: net.TCP_Socket, head: string, ok: bool) {
	paired: bool
	client, accepted, paired = loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer if !ok {
		net.close(client)
		net.close(accepted)
	}
	if !set_wait(t, client, .Receive_Timeout, 3 * time.Second) {
		return
	}
	// So that the body's blocking write cannot outlive the test. `thread.join`
	// in the caller waits for that write, and without this a peer window that
	// never opens - a drain that stopped reading on a host with small socket
	// buffers - would hang the join rather than fail an assertion. See the note
	// on the join.
	if !set_wait(t, client, .Send_Timeout, 3 * time.Second) {
		return
	}

	// The head alone. A `JUNK` version is refused on the request line, which is
	// before `read_http_request` has looked at the Content-Length that says the
	// rest is coming.
	head = junk_head()
	if _, serr := net.send_tcp(client, transmute([]u8)head); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		return
	}

	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}
	return client, accepted, head, true
}

// Read the request off `conn` and expect it refused 400 with no more than the
// rest of its head, `head_len` bytes, read along with it. Returns the status.
@(private = "file")
expect_junk_refused_alone :: proc(t: ^testing.T, conn: Conn, head_len: int) -> int {
	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE, context.temp_allocator),
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
		len(r.buf) - r.pos < head_len,
		"%d bytes were left over, which is more than the head: the body arrived before the refusal, and this is the other test",
		len(r.buf) - r.pos,
	)
	return status
}

// Read `accepted` to a clean EOF or a reset and expect nothing on it; false,
// with the failure reported, when the read ends any other way.
@(private = "file")
expect_nothing_left_behind :: proc(t: ^testing.T, accepted: net.TCP_Socket) -> bool {
	behind := 0
	for {
		leftover: [4096]u8
		n, rerr := net.recv_tcp(accepted, leftover[:])
		if rerr == .Not_Connected || rerr == .Connection_Closed {
			break
		}
		if rerr != nil {
			testing.expectf(t, false, "the client's bytes never finished arriving: %v", rerr)
			return false
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
	return true
}

// Read `client` to an EOF or a reset and expect the 400 at the front of what
// came; `shutdown_err` is reported beside a miss.
@(private = "file")
expect_400_through_a_reset :: proc(t: ^testing.T, client: net.TCP_Socket, shutdown_err: net.Shutdown_Error) {
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
}
@(private = "file")
Dripper :: struct {
	endpoint: net.Endpoint,
	request:  string,
	stop:     bool,
}

// A byte every `DOH_DRIP_INTERVAL` until the request runs out or the test says to
// stop. The stop flag is what keeps the case that passes from waiting out a
// trickle written to be longer than any per-read wait.
@(private = "file")
DOH_DRIP_INTERVAL :: 150 * time.Millisecond

@(private = "file")
drip_request :: proc(d: ^Dripper) {
	socket, err := net.dial_tcp_from_endpoint(d.endpoint)
	if err != nil {
		return
	}
	defer net.close(socket)
	raw := transmute([]u8)d.request
	for i in 0 ..< len(raw) {
		if sync.atomic_load(&d.stop) {
			return
		}
		n, serr := net.send_tcp(socket, raw[i:][:1])
		if serr != nil || n != 1 {
			return
		}
		time.sleep(DOH_DRIP_INTERVAL)
	}
}

/*
A request trickled a byte at a time is given up on at the deadline the request
began with, not held for as long as the client keeps trickling.

The socket's receive timeout bounds one read and is restarted by every byte that
arrives, so a request line, its headers and its body - as many reads as the
client cares to split them into - would have no bound between them on that
timeout alone: a client sending a byte inside every wait would hold the
connection, and one of `max_connections`, for as long as it likes while no
request ever completes and nothing charges it for one. See `Http_Reader.budget`,
and `Read_Budget` where the DNS stream has the same shape and RFC 7766 6.2.3
says what a server should do about it.

The receive timeout here is five seconds, far longer than the deadline, so the
reader giving up inside two is the deadline doing it and not the socket: a reader
bounded only per read would still be collecting bytes when this case ends.
*/
@(test)
test_doh_reader_gives_up_on_a_drip_fed_request :: proc(t: ^testing.T) {
	listener, bound, lok := loopback_listener(t)
	if !lok {
		return
	}
	defer net.close(listener)

	// A request that would be read and answered if the whole of it ever arrived,
	// so what ends the read is how it was sent and not what it says.
	dripper := Dripper {
		endpoint = bound,
		request  = "GET /dns-query?dns=AAABAAABAAAAAAAA HTTP/1.1\r\nHost: dns.example\r\n\r\n",
	}
	client := thread.create_and_start_with_poly_data(&dripper, drip_request)
	defer {
		sync.atomic_store(&dripper.stop, true)
		thread.join(client)
		thread.destroy(client)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if !testing.expectf(t, aerr == nil, "nothing connected: %v", aerr) {
		return
	}
	defer net.close(accepted)
	if !set_wait(t, accepted, .Receive_Timeout, 5 * time.Second) {
		return
	}

	r := Http_Reader {
		conn   = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf    = make([dynamic]u8, 0, HTTP_BUF_SIZE),
		budget = Read_Budget{idle = 400 * time.Millisecond},
	}
	defer delete(r.buf)

	start := time.tick_now()
	_, _, ok := read_http_request(&r)
	elapsed := time.tick_since(start)

	testing.expect(t, !ok, "a request trickled a byte at a time was read to the end")
	testing.expectf(
		t,
		elapsed < 2 * time.Second,
		"the reader was held for %v by a byte every %v, against a 400ms budget",
		elapsed,
		DOH_DRIP_INTERVAL,
	)
}

@(private = "file")
Wrong_Path_Peer :: struct {
	socket:   net.TCP_Socket,
	stop:     bool,
	// Posted once `serve_doh` has returned.
	returned: sync.Sema,
	// Set when the server had not hung up by the stopper's bound, which then
	// ended the connection itself.
	forced:   bool,
}

// Asks for a path this server does not serve every 40ms - well inside the idle
// wait the case below sets - until told to stop or the server hangs up.
@(private = "file")
ask_the_wrong_path :: proc(p: ^Wrong_Path_Peer) {
	request := transmute([]u8)string("GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\n")
	for !sync.atomic_load(&p.stop) {
		n, err := net.send_tcp(p.socket, request)
		if err != nil || n <= 0 {
			return
		}
		time.sleep(40 * time.Millisecond)
	}
}

/*
A connection that never asks a question is not kept for as long as it likes (#344).

A 404 honours the client's keep-alive and is charged to nothing, since the
budget is denominated in questions. So a peer asking for the wrong path once
inside every idle wait could hold a connection and one of `max_connections`
forever, and the rate limiter would never see it. It is let go once twice
`client_timeout` passes with no question asked - see `doh_question_overdue`.

The peer here keeps asking until the server hangs up, or for a second, which is
over three times what `doh_question_overdue` allows at this `client_timeout`;
the server must hang up before that, rather than when the peer stops.
*/
@(test)
test_doh_lets_go_of_a_connection_that_asks_nothing :: proc(t: ^testing.T) {
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)

	peer := Wrong_Path_Peer {
		socket = client,
	}
	asker := thread.create_and_start_with_poly_data(&peer, ask_the_wrong_path)
	// Only there to end the case when the server never hangs up, which is the bug.
	stopper := thread.create_and_start_with_poly_data(&peer, proc(p: ^Wrong_Path_Peer) {
		if !sync.sema_wait_with_timeout(&p.returned, time.Second) {
			sync.atomic_store(&p.forced, true)
		}
		sync.atomic_store(&p.stop, true)
		net.shutdown(p.socket, .Both)
	})

	cfg := config.default_config()
	cfg.server.client_timeout = 150 * time.Millisecond
	s := Server {
		cfg = &cfg,
	}
	serve_doh(&s, Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}}, "test")
	sync.sema_post(&peer.returned)

	sync.atomic_store(&peer.stop, true)
	thread.join(asker)
	thread.destroy(asker)
	thread.join(stopper)
	thread.destroy(stopper)

	testing.expect(t, !sync.atomic_load(&peer.forced), "a connection that asked nothing was held until the peer gave up")
	free_all(context.temp_allocator)
}

/*
The time a question takes to answer is not time the connection asked nothing (#344).

A TCP client's idle wait starts once its answer is written, and so does the
window `doh_question_overdue` gives an HTTP/1.1 connection. Stamped where the
question was charged instead, an upstream slower than twice `client_timeout` -
two unreachable servers at the defaults - would end the connection as soon as
the answer went out, under the `Connection: keep-alive` that answer had just
promised, and a request the client had already sent would be lost with it.

The upstream here never answers, and gives up after 400ms against a 100ms
`client_timeout`. The 404 pipelined behind the query must still be answered.
*/
@(test)
test_doh_a_slow_answer_does_not_count_against_the_connection :: proc(t: ^testing.T) {
	h: Harness
	if !harness_bind(t, &h) {
		return
	}
	h.cfg.listeners.doh.path = "/dns-query"
	h.cfg.server.client_timeout = 100 * time.Millisecond
	h.cfg.upstream.timeout = 400 * time.Millisecond
	if !harness_build(t, &h) {
		return
	}
	defer harness_stop(&h)

	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	// Closed by hand below, ahead of the read; every return before that closes it
	// too.
	accepted_open := true
	defer if accepted_open {
		net.close(accepted)
	}

	req := strings.builder_make(context.temp_allocator)
	write_doh_post(&req, test_query("slow.example.", id = 0x5150))
	strings.write_string(&req, "GET /not-served HTTP/1.1\r\nHost: dns.example\r\n\r\n")
	if _, serr := net.send_tcp(client, req.buf[:]); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		return
	}
	// What ends `serve_doh` once both are answered.
	net.shutdown(client, .Send)

	// From loopback, which `server.allow_from` is read against per request.
	serve_doh(&h.srv, Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}}, "test")
	// Closed now so the read below ends at EOF, not at its timeout.
	net.close(accepted)
	accepted_open = false

	got, rerr := read_until_close(client, 500 * time.Millisecond)
	testing.expectf(t, rerr == nil, "the read did not end at the close: %v", rerr)
	testing.expectf(t, strings.contains(got, "HTTP/1.1 200"), "the query went unanswered: %q", got)
	testing.expectf(
		t,
		strings.contains(got, "HTTP/1.1 404"),
		"the request behind a slow answer was dropped with its connection: %q",
		got,
	)
	free_all(context.temp_allocator)
}

// A `client_timeout` meant as "forever" is not one doubled past the end of the
// range into a bound every connection is already over.
@(test)
test_doh_a_timeout_near_the_range_limit_keeps_connections :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.server.client_timeout = 10000 * 7 * 24 * time.Hour
	s := Server {
		cfg = &cfg,
	}
	now := time.tick_now()
	testing.expect(
		t,
		!doh_question_overdue(&s, time.tick_add(now, -time.Second), now),
		"a connection one second old was overdue",
	)
}

@(test)
test_doh_a_held_connection_outside_the_allow_list_gets_nothing_but_403 :: proc(t: ^testing.T) {
	/*
	A reload can take a held connection's network out of `server.allow_from`.
	The accept loop gives such a source nothing at all, so neither does the
	connection: a request for a path that is not the endpoint is refused 403,
	not answered 404 - and the profile is not handed out either.
	*/
	// `accepted` is closed by hand, as the listener's connection job closes it.
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	// Two requests, kept alive: the refusal closes the connection, so the second
	// is never answered. Padded past what one read takes, so that the close finds
	// bytes unread - which without a drain first is an RST, and the 403 lost.
	pipelined := strings.concatenate(
		{
			"GET /not-the-endpoint HTTP/1.1\r\nHost: dns.example\r\n\r\n",
			"GET /not-the-endpoint HTTP/1.1\r\nHost: dns.example\r\nX-Pad: ",
			strings.repeat("p", 4 * HTTP_BUF_SIZE, context.temp_allocator),
			"\r\n\r\n",
		},
		context.temp_allocator,
	)
	if _, serr := net.send_tcp(client, transmute([]u8)pipelined); !testing.expectf(t, serr == nil, "cannot send: %v", serr) {
		net.close(accepted)
		return
	}
	net.shutdown(client, .Send)
	if !set_wait(t, accepted, .Receive_Timeout, 500 * time.Millisecond) {
		net.close(accepted)
		return
	}

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	s := Server {
		cfg = &cfg,
	}
	// TEST-NET-3: in no range the default allow list names.
	serve_doh(&s, Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Address{203, 0, 113, 9}, port = 1}}, "test")
	// What the listener's connection job does once `serve_doh` returns.
	net.close(accepted)

	head, last := read_until_close(client, 500 * time.Millisecond)
	// No bytes and no error is the FIN; an RST is an error, the 403 gone with it.
	testing.expectf(t, last == nil, "the close was not graceful: %v", last)
	testing.expect(t, strings.contains(head, "HTTP/1.1 403"), "a source outside the allow list was answered on another path")
	testing.expect(t, !strings.contains(head, "HTTP/1.1 404"), "a source outside the allow list was told what is not there")
	testing.expect_value(t, strings.count(head, "HTTP/1.1 403"), 1)
	testing.expect_value(t, sync.atomic_load(&s.stats.refused), u64(1))
}

/*
A header that never ends is refused within one read of `HTTP_BUF_SIZE` past
`MAX_HEADER_BYTES` (#596).

`http_fill` reads into the buffer's free capacity, and the buffer doubles when
full, so a read that took all of it could carry the buffer to twice the limit
before `http_line` looks again. The whole of it is queued before the first read,
so every read finds as much as it asks for - which is why it is twice the limit
and no more: the sender is joined before anything is read and has no send
timeout, so all of it has to fit in loopback's socket buffers.
*/
@(test)
test_doh_reader_stops_a_header_that_never_ends_within_one_read :: proc(t: ^testing.T) {
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	strings.write_string(&b, "GET /dns-query HTTP/1.1\r\nX-Long: ")
	for _ in 0 ..< 2 * MAX_HEADER_BYTES {
		strings.write_byte(&b, 'a')
	}

	listener, bound, lok := loopback_listener(t)
	if !lok {
		return
	}
	defer net.close(listener)
	sender := Sender {
		endpoint = bound,
		request  = strings.to_string(b),
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	accepted, _, aerr := net.accept_tcp(listener)
	// Sent whole before anything is read: the sender returns once it has.
	thread.join(client)
	thread.destroy(client)
	testing.expectf(t, sender.err == nil, "the request was not sent: %v", sender.err)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}

	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE),
	}
	defer delete(r.buf)
	_, _, ok := read_http_request(&r)
	testing.expect(t, !ok, "a header with no end was read as a request")
	// The premise: the limit was reached, not the end of what was sent.
	testing.expectf(t, len(r.buf) > MAX_HEADER_BYTES, "only %d bytes were read", len(r.buf))
	testing.expectf(t, len(r.buf) <= MAX_HEADER_BYTES + HTTP_BUF_SIZE, "%d bytes read for a %d-byte header limit", len(r.buf), MAX_HEADER_BYTES)
}
