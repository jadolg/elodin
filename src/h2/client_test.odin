package h2

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:loop"

/*
Client tests run over a plain loopback TCP socket, no TLS: ALPN selection
happens one layer up (upstream/h2client.odin), and framing does not care what
carried the bytes. Most of these drive a real `Conn` (server.odin) as the
peer, so client and server are checked against each other rather than each
against its own assumptions; a few construct raw frames by hand where the
`respond` API cannot produce the shape under test (a mid-stream reset, a
GOAWAY, silence).
*/

// `stopping` exists because closing a socket does not reliably wake a thread
// already blocked reading it from another thread on Linux (see
// upstream/h2client.odin, which carries the production version of this same
// fix): the client socket below carries a short receive timeout so its
// reader polls for this flag instead of depending on close() to cut a read
// short.
@(private = "file")
Test_Conn :: struct {
	socket:   net.TCP_Socket,
	stopping: bool,
}

@(private = "file")
test_io_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	tc := cast(^Test_Conn)user
	for {
		if sync.atomic_load(&tc.stopping) {
			return 0, false
		}
		got, err := net.recv_tcp(tc.socket, buf)
		if err == nil {
			return got, true
		}
		// See upstream's `timed_out` (http.odin): on Linux, SO_RCVTIMEO expiring on a
		// blocking recv() is EAGAIN, which core:net reports as .Would_Block,
		// not .Timeout. Only continuing on .Timeout made every poll tick race
		// with client_request's own deadline as a spurious connection close.
		if err == .Timeout || err == .Would_Block {
			continue
		}
		return 0, false
	}
}

@(private = "file")
test_io_write :: proc(user: rawptr, buf: []u8) -> bool {
	return test_send((^Test_Conn)(user).socket, buf)
}

@(private = "file")
test_listen :: proc(t: ^testing.T) -> (listener: net.TCP_Socket, bound: net.Endpoint, ok: bool) {
	l, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return {}, {}, false
	}
	b, berr := net.bound_endpoint(l)
	if berr != nil {
		net.close(l)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return {}, {}, false
	}
	return l, b, true
}

@(private = "file")
test_dial_client :: proc(t: ^testing.T, bound: net.Endpoint) -> (c: ^Client, ct: ^thread.Thread, tc: ^Test_Conn, ok: bool) {
	sock, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the mock: %v", derr)
		return nil, nil, nil, false
	}
	_ = net.set_option(sock, .Receive_Timeout, 200 * time.Millisecond)
	tc = new(Test_Conn)
	tc.socket = sock
	io := IO{user = tc, read = test_io_read, write = test_io_write}
	c = client_make(io)
	ct = thread.create_and_start_with_poly_data(c, client_serve)
	return c, ct, tc, true
}

// Stops the reader thread, joins it, and releases the socket and Test_Conn.
// Must run after every test_dial_client, in this order: signalling stopping
// before the join is what bounds it (see Test_Conn's doc comment), and the
// socket must outlive the reader thread that is still using it.
@(private = "file")
test_close_client :: proc(ct: ^thread.Thread, tc: ^Test_Conn) {
	sync.atomic_store(&tc.stopping, true)
	thread.join(ct)
	thread.destroy(ct)
	net.close(tc.socket)
	free(tc)
}

// Runs a real server-side Conn over an accepted connection, using `handler`
// to answer every request.
@(private = "file")
serve_socket :: proc(socket: net.TCP_Socket, handler: Handler) {
	tc := new(Test_Conn)
	tc.socket = socket
	defer free(tc)
	hc := make_conn(IO{user = tc, read = test_io_read, write = test_io_write}, handler, nil)
	serve(hc)
	conn_wait_idle(hc)
	conn_unref(hc)
}

@(private = "file")
Test_Server :: struct {
	listener: net.TCP_Socket,
	handler:  Handler,
}

@(private = "file")
test_server_once :: proc(s: ^Test_Server) {
	client, _, err := net.accept_tcp(s.listener)
	if err != nil {
		return
	}
	defer net.close(client)
	serve_socket(client, s.handler)
}

/*
The peer a client test dials, on a thread of its own. It accepts one
connection and either serves it with a real `Conn` on `handler`, or takes the
client preface and hands the socket to `script` with `data`.
*/
@(private = "file")
Peer :: struct {
	handler:  Handler,
	script:   proc(peer: net.TCP_Socket, data: rawptr),
	data:     rawptr,
	listener: net.TCP_Socket,
	server:   ^thread.Thread,
	c:        ^Client,
	ct:       ^thread.Thread,
	tc:       ^Test_Conn,
}

@(private = "file")
run_peer :: proc(p: ^Peer) {
	socket, _, err := net.accept_tcp(p.listener)
	if err != nil {
		return
	}
	defer net.close(socket)
	if p.handler != nil {
		serve_socket(socket, p.handler)
		return
	}
	preface: [len(PREFACE)]u8
	if test_recv_full(socket, preface[:]) {
		p.script(socket, p.data)
	}
}

// Listens, starts the peer, and dials a client to it. `end_peer` undoes it all.
@(private = "file")
start_peer :: proc(t: ^testing.T, p: ^Peer) -> bool {
	bound: net.Endpoint
	ok: bool
	p.listener, bound, ok = test_listen(t)
	if !ok {
		return false
	}
	p.server = thread.create_and_start_with_poly_data(p, run_peer)
	if !testing.expect(t, p.server != nil, "cannot start the peer") {
		net.close(p.listener)
		return false
	}
	p.c, p.ct, p.tc, ok = test_dial_client(t, bound)
	if !ok {
		// Wakes the peer from an accept no client reached.
		net.shutdown(p.listener, .Both)
		thread.join(p.server)
		thread.destroy(p.server)
		net.close(p.listener)
	}
	return ok
}

// The client first, so the peer sees it go, then the peer.
@(private = "file")
end_peer :: proc(p: ^Peer) {
	test_close_client(p.ct, p.tc)
	client_unref(p.c)
	thread.join(p.server)
	thread.destroy(p.server)
	net.close(p.listener)
}

@(private = "file")
echo_handler :: proc(conn: ^Conn, req: ^Request) {
	defer request_destroy(conn, req)
	body := make([]u8, len(req.body), context.temp_allocator)
	copy(body, req.body)
	respond(conn, req.stream_id, Response{status = 200, content_type = "application/dns-message", body = body})
}

@(test)
test_client_request_round_trip :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	p := Peer{handler = echo_handler}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	want := []u8{0xde, 0xad, 0xbe, 0xef}
	resp, err := client_request(
		c,
		Client_Request {
			method = "POST",
			scheme = "https",
			authority = "mock.invalid",
			path = "/dns-query",
			content_type = "application/dns-message",
			accept = "application/dns-message",
			body = want,
		},
		2 * time.Second,
		allocator,
	)
	testing.expectf(t, err == .None, "request failed: %v", err)
	testing.expect_value(t, resp.status, 200)
	testing.expect_value(t, len(resp.body), len(want))
	if len(resp.body) == len(want) {
		testing.expect(t, string(resp.body) == string(want), "body was not echoed back unchanged")
	}
	delete(resp.body, allocator)

	expect_no_leaks(t, &track, "round trip")
	free_all(context.temp_allocator)
}

@(test)
test_client_multiplexes_concurrent_streams :: proc(t: ^testing.T) {
	p := Peer{handler = echo_handler}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	N :: 8
	Leg :: struct {
		c:  ^Client,
		id: u8,
		ok: bool,
		wg: ^sync.Wait_Group,
	}
	legs := make([]Leg, N, context.temp_allocator)
	wg: sync.Wait_Group
	sync.wait_group_add(&wg, N)

	worker :: proc(leg: ^Leg) {
		defer sync.wait_group_done(leg.wg)
		body := []u8{leg.id, leg.id, leg.id}
		resp, err := client_request(
			leg.c,
			Client_Request {
				method = "POST",
				scheme = "https",
				authority = "mock.invalid",
				path = "/dns-query",
				content_type = "application/dns-message",
				body = body,
			},
			5 * time.Second,
		)
		leg.ok = err == .None && resp.status == 200 && len(resp.body) == 3 &&
			resp.body[0] == leg.id && resp.body[1] == leg.id && resp.body[2] == leg.id
		if resp.body != nil {
			delete(resp.body)
		}
	}

	threads := make([]^thread.Thread, N, context.temp_allocator)
	for i in 0 ..< N {
		legs[i] = Leg{c = c, id = u8(i + 1), wg = &wg}
		threads[i] = thread.create_and_start_with_poly_data(&legs[i], worker)
	}
	sync.wait_group_wait(&wg)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	for leg in legs {
		testing.expectf(t, leg.ok, "leg %d did not get its own answer back", leg.id)
	}
	free_all(context.temp_allocator)
}

// --- hand-scripted server, for shapes `respond` cannot produce ------------

@(private = "file")
test_recv_full :: proc(socket: net.TCP_Socket, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, err := net.recv_tcp(socket, buf[got:])
		if err != nil || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

@(private = "file")
test_send :: proc(socket: net.TCP_Socket, buf: []u8) -> bool {
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(socket, buf[sent:])
		if err != nil || n <= 0 {
			return false
		}
		sent += n
	}
	return true
}

// Reads and discards frames until one of type `want` arrives on any stream,
// or the connection goes away.
@(private = "file")
test_wait_for_frame_type :: proc(socket: net.TCP_Socket, want: Frame_Type) -> (h: Frame_Header, ok: bool) {
	for {
		hdr: [FRAME_HEADER_SIZE]u8
		if !test_recv_full(socket, hdr[:]) {
			return {}, false
		}
		fh, fok := parse_frame_header(hdr[:])
		if !fok {
			return {}, false
		}
		if fh.length > 0 {
			payload := make([]u8, fh.length, context.temp_allocator)
			if !test_recv_full(socket, payload) {
				return {}, false
			}
		}
		if fh.type == want {
			return fh, true
		}
	}
}

// Answers with `MAX_BODY - 1` bytes more than the request carried, so a
// one-byte request is answered at the bound and a two-byte one just past it.
@(private = "file")
sized_handler :: proc(conn: ^Conn, req: ^Request) {
	defer request_destroy(conn, req)
	body := make([]u8, MAX_BODY - 1 + len(req.body), context.temp_allocator)
	respond(conn, req.stream_id, Response{status = 200, content_type = "application/dns-message", body = body})
}

/*
A response is a DNS message, at most MAX_BODY bytes (RFC 8484 6). One of
exactly that is kept; one byte more is this end's reset, reported as
`Too_Large` and not as the peer's `Reset`, so the caller can tell the two apart
as the HTTP/1.1 client does (#525).
*/
@(test)
test_client_response_past_max_body_is_too_large :: proc(t: ^testing.T) {
	for extra in 0 ..< 2 {
		listener, bound, lok := test_listen(t)
		if !lok {
			return
		}
		srv := Test_Server{listener = listener, handler = sized_handler}
		server_thread := thread.create_and_start_with_poly_data(&srv, test_server_once)
		// The client's own memory, the stream's body among it, is tracked; the
		// response handed back is not.
		heap := context.allocator
		held: mem.Tracking_Allocator
		mem.tracking_allocator_init(&held, heap)
		defer mem.tracking_allocator_destroy(&held)
		c: ^Client
		ct: ^thread.Thread
		tc: ^Test_Conn
		cok: bool
		{
			context.allocator = mem.tracking_allocator(&held)
			c, ct, tc, cok = test_dial_client(t, bound)
		}
		if cok {
			request := []u8{1, 2}
			resp, err := client_request(
				c,
				Client_Request{method = "POST", scheme = "https", authority = "mock.invalid", path = "/dns-query", body = request[:1 + extra]},
				2 * time.Second,
				heap,
			)
			if extra == 0 {
				testing.expectf(t, err == .None, "a %d-byte response was refused: %v", MAX_BODY, err)
				testing.expect_value(t, len(resp.body), MAX_BODY)
				// The stream's body grows by doubling but never past the bound,
				// where `append` alone takes it to 116 KiB.
				testing.expectf(t, held.peak_memory_allocated < MAX_BODY + 8192, "the client peaked at %d bytes", held.peak_memory_allocated)
			} else {
				testing.expectf(t, err == .Too_Large, "a %d-byte response came back as %v", MAX_BODY + 1, err)
				// With its status, so the caller can tell an oversized answer from
				// an error page it would not have read anyway.
				testing.expect_value(t, resp.status, 200)
			}
			delete(resp.body)
			test_close_client(ct, tc)
			client_unref(c)
		}
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}
	free_all(context.temp_allocator)
}

/*
A response can run past MAX_BODY while the request is still going up,
held back by flow control (RFC 9113 8.1 lets a server answer early). That is
the same `Too_Large` as a response that overran after the upload, not a reset
the peer chose (#525).
*/
@(test)
test_client_oversized_response_during_upload_is_too_large :: proc(t: ^testing.T) {
	run_script :: proc(client: net.TCP_Socket, _: rawptr) {
		if _, ok := test_wait_for_frame_type(client, .Headers); !ok {
			return
		}
		// :status 500 (static table index 14), then more DATA than a DNS message
		// and no END_STREAM. The upload stays stuck behind the initial window.
		out := make([dynamic]u8, 0, 5 * (FRAME_HEADER_SIZE + 16384) + 32, context.temp_allocator)
		write_frame_header(&out, 0, .Settings, 0, 0)
		write_frame_header(&out, 1, .Headers, FLAG_END_HEADERS, 1)
		append(&out, 0x8e)
		for _ in 0 ..< 5 {
			write_frame_header(&out, 16384, .Data, 0, 1)
			resize(&out, len(out) + 16384)
		}
		if !test_send(client, out[:]) {
			return
		}
		_, _ = test_wait_for_frame_type(client, .Rst_Stream)
	}
	p := Peer{script = run_script}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	// Past the peer's initial window, so the upload waits for credit that never comes.
	body := make([]u8, 2 * 65535, context.temp_allocator)
	resp, err := client_request(
		c,
		Client_Request{method = "POST", scheme = "https", authority = "mock.invalid", path = "/dns-query", body = body},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Too_Large)
	testing.expect_value(t, resp.status, 500)
	testing.expect_value(t, len(resp.body), 0)
	free_all(context.temp_allocator)
}

@(test)
test_client_request_reset_by_peer :: proc(t: ^testing.T) {
	// REFUSED_STREAM says the request was never processed, so it has its own
	// error the caller may retry on; any other code is a plain reset.
	expect_client_reset_as(t, .Refused_Stream, .Refused)
	expect_client_reset_as(t, .Cancel, .Reset)
}

@(private = "file")
expect_client_reset_as :: proc(t: ^testing.T, code: Error_Code, want: Client_Error) {
	run_script :: proc(client: net.TCP_Socket, data: rawptr) {
		code := (^Error_Code)(data)^
		// Whatever the client sends after its preface, until its request HEADERS.
		_, ok := test_wait_for_frame_type(client, .Headers)
		if !ok {
			return
		}
		out := make([dynamic]u8, 0, 13, context.temp_allocator)
		write_frame_header(&out, 4, .Rst_Stream, 0, 1)
		append_u32(&out, u32(code))
		_ = test_send(client, out[:])
	}
	reset_code := code
	p := Peer{script = run_script, data = &reset_code}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, want)
	free_all(context.temp_allocator)
}

@(test)
test_client_goaway_closes_the_connection :: proc(t: ^testing.T) {
	run_script :: proc(client: net.TCP_Socket, _: rawptr) {
		_, ok := test_wait_for_frame_type(client, .Headers)
		if !ok {
			return
		}
		out := make([dynamic]u8, 0, 17, context.temp_allocator)
		write_frame_header(&out, 8, .Goaway, 0, 0)
		append_u32(&out, 0)
		append_u32(&out, u32(Error_Code.No_Error))
		_ = test_send(client, out[:])
	}
	p := Peer{script = run_script}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Closed)

	// The reader loop has already returned by the time client_request's own
	// wait unblocks on `c.closed`, so this should not need to wait further.
	testing.expect(t, client_closed(c), "the connection was not marked closed after GOAWAY")
	free_all(context.temp_allocator)
}

@(test)
test_client_closes_connection_once_stream_ids_are_exhausted :: proc(t: ^testing.T) {
	// RFC 9113 5.1.1: an endpoint that has used up the 31-bit stream id space
	// must not open another stream on the connection. Rather than run 2^30
	// real requests, this drives the counter to the boundary directly and
	// checks client_request refuses to allocate past it instead of wrapping
	// the id and reusing one still live in c.streams.
	// The peer takes the preface and nothing else.
	p := Peer{script = proc(client: net.TCP_Socket, _: rawptr) {}}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	loop.lock(&c.mu)
	c.next_stream_id = 0x8000_0001
	loop.unlock(&c.mu)

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Closed)
	testing.expect(t, client_closed(c), "the connection was not marked closed once stream ids were exhausted")
	free_all(context.temp_allocator)
}

@(test)
test_client_wakes_a_pending_request_when_stream_ids_are_exhausted :: proc(t: ^testing.T) {
	// A request already blocked waiting for its response is exactly the state
	// a connection busy enough to exhaust its stream ids will be in: another
	// caller trips the RFC 9113 5.1.1 close while this one sits in
	// client_request's wait loop. That waiter must be woken by the close, not
	// left to fall through on its own deadline and come back as a
	// misclassified Timeout.

	// The mock holds the accepted socket open until the test explicitly
	// releases it, rather than closing it after a fixed sleep: closing it
	// early would let client_serve's own read-error path close and broadcast
	// the connection, waking stream A for a reason unrelated to the one this
	// test checks and masking a missing broadcast in the exhaustion branch.
	Script :: struct {
		headers_seen: bool,
		stop:         bool,
	}
	run_script :: proc(client: net.TCP_Socket, data: rawptr) {
		s := (^Script)(data)
		// This is stream A's HEADERS; never respond to it.
		if _, ok := test_wait_for_frame_type(client, .Headers); ok {
			sync.atomic_store(&s.headers_seen, true)
		}
		for !sync.atomic_load(&s.stop) {
			time.sleep(10 * time.Millisecond)
		}
	}
	srv: Script
	p := Peer{script = run_script, data = &srv}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c
	// Set before `end_peer` joins the peer, not just at the end of the happy
	// path: an early return between here and there would otherwise leave
	// run_script spinning on `stop` forever and that join hanging with it.
	defer sync.atomic_store(&srv.stop, true)

	// One id short of exhaustion: stream A's request takes the last valid id,
	// so a second request right behind it is the one that trips the close.
	loop.lock(&c.mu)
	c.next_stream_id = 0x7fff_ffff
	loop.unlock(&c.mu)

	Waiter :: struct {
		c:       ^Client,
		err:     Client_Error,
		elapsed: time.Duration,
	}
	wait_for_a :: proc(w: ^Waiter) {
		started := time.tick_now()
		_, w.err = client_request(
			w.c,
			Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
			4 * time.Second,
		)
		w.elapsed = time.tick_since(started)
	}
	w := Waiter{c = c}
	a := thread.create_and_start_with_poly_data(&w, wait_for_a)
	defer {
		// join is idempotent (checked below too, to read w's fields at a known
		// point); destroy is not, so it only happens here. Deferred rather
		// than left to the explicit call below so an early return before that
		// point can't let the `end_peer` defer above free
		// `c` while `a` is still inside client_request using it.
		thread.join(a)
		thread.destroy(a)
	}

	// Wait for stream A's HEADERS to land, then give it a little longer to
	// re-acquire the lock and settle into its cond_wait - both comfortably
	// short next to the 4s timeout that would mask a missing broadcast.
	for i := 0; i < 200 && !sync.atomic_load(&srv.headers_seen); i += 1 {
		time.sleep(5 * time.Millisecond)
	}
	testing.expect(t, sync.atomic_load(&srv.headers_seen), "stream A's HEADERS frame was never observed")
	time.sleep(100 * time.Millisecond)

	_, berr := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		time.Second,
	)
	testing.expect_value(t, berr, Client_Error.Closed)

	thread.join(a)
	testing.expect_value(t, w.err, Client_Error.Closed)
	testing.expect(
		t,
		w.elapsed < 2 * time.Second,
		"the pending request was not woken by the close and instead rode out its own deadline",
	)
	free_all(context.temp_allocator)
}

@(test)
test_client_refuses_frame_larger_than_advertised_max :: proc(t: ^testing.T) {
	/*
	The client advertises the RFC 9113 6.5.2 default MAX_FRAME_SIZE (16384) by
	sending none, yet the reader loop bounded an incoming frame at the receive
	window, 64x that. An upstream told one size and allowed another could send a
	frame in between; the client should refuse it as a FRAME_SIZE_ERROR.
	*/
	Script :: struct {
		saw:  bool,
		code: Error_Code,
	}
	run_script :: proc(client: net.TCP_Socket, data: rawptr) {
		s := (^Script)(data)
		if _, ok := test_wait_for_frame_type(client, .Headers); !ok {
			return
		}
		// A DATA frame one byte past the advertised maximum frame size.
		out := make([dynamic]u8, 0, FRAME_HEADER_SIZE, context.temp_allocator)
		write_frame_header(&out, DEFAULT_MAX_FRAME + 1, .Data, 0, 1)
		if !test_send(client, out[:]) {
			return
		}
		// The client should answer with a GOAWAY of FRAME_SIZE_ERROR and close.
		for {
			hdr: [FRAME_HEADER_SIZE]u8
			if !test_recv_full(client, hdr[:]) {
				return
			}
			fh, fok := parse_frame_header(hdr[:])
			if !fok {
				return
			}
			body: []u8
			if fh.length > 0 {
				body = make([]u8, fh.length, context.temp_allocator)
				if !test_recv_full(client, body) {
					return
				}
			}
			if fh.type == .Goaway && len(body) >= 8 {
				s.saw = true
				s.code = Error_Code(read_u32(body[4:]))
				return
			}
		}
	}
	srv: Script
	p := Peer{script = run_script, data = &srv}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Closed)

	// The peer is done once it has read the GOAWAY or lost the connection.
	thread.join(p.server)
	testing.expect(t, srv.saw, "the client did not GOAWAY an oversized frame")
	testing.expect_value(t, srv.code, Error_Code.Frame_Size_Error)
	free_all(context.temp_allocator)
}

@(test)
test_client_request_times_out_on_silence :: proc(t: ^testing.T) {
	run_script :: proc(client: net.TCP_Socket, _: rawptr) {
		_, _ = test_wait_for_frame_type(client, .Headers)
		// And then say nothing at all.
		time.sleep(2 * time.Second)
	}
	p := Peer{script = run_script}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	started := time.tick_now()
	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		200 * time.Millisecond,
	)
	elapsed := time.tick_since(started)
	testing.expect_value(t, err, Client_Error.Timeout)
	testing.expect(t, elapsed < time.Second, "the request took far longer than its own timeout")
	free_all(context.temp_allocator)
}

@(test)
test_client_reuses_connection_across_requests :: proc(t: ^testing.T) {
	/*
	Answers each request with the stream ID it arrived on. A connection numbers
	the client's streams 1, 3, 5, ... (RFC 9113 section 5.1.1), so five requests
	answered 1 through 9 went out on one connection, and a client that dialled
	again for any of them would read a 1 a second time.
	*/
	stream_id_handler :: proc(conn: ^Conn, req: ^Request) {
		defer request_destroy(conn, req)
		body := make([]u8, 1, context.temp_allocator)
		body[0] = u8(req.stream_id)
		respond(conn, req.stream_id, Response{status = 200, content_type = "application/dns-message", body = body})
	}
	p := Peer{handler = stream_id_handler}
	if !start_peer(t, &p) {
		return
	}
	defer end_peer(&p)
	c := p.c

	for i in 0 ..< 5 {
		resp, err := client_request(
			c,
			Client_Request{method = "POST", scheme = "https", authority = "mock.invalid", path = "/dns-query", body = {u8(i)}},
			2 * time.Second,
		)
		testing.expectf(t, err == .None, "request %d failed: %v", i, err)
		if err == .None {
			want := u8(2 * i + 1)
			testing.expectf(
				t,
				len(resp.body) == 1 && resp.body[0] == want,
				"request %d was answered on stream %v, want %d",
				i,
				resp.body,
				want,
			)
			delete(resp.body)
		}
	}
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// A stream freed while the reader thread is between locks
// ---------------------------------------------------------------------------

@(private = "file")
Client_Close_Hook :: struct {
	client:    ^Client,
	stream_id: u32,
	armed:     bool,
	fired:     bool,
	retired:   ^Client_Stream,
}

/*
Stands in for `client_request` giving up on a stream - a timeout, or the peer
resetting it - inside the window `client_handle_data` leaves open between
releasing `c.mu` after appending the body and re-acquiring it to mark the
response complete.

`client_handle_data` reaches here through the WINDOW_UPDATE it writes for the
bytes it just consumed. `client_write_all` holds `c.mu` for the length of this
call, so a request thread running its deferred cleanup would be parked on that
mutex right here and would take it the moment this returns.

The deferred cleanup in `client_request` frees the stream, so a write through
the reader thread's stale pointer is a use-after-free. The stream is only
unhooked from the map rather than released, so the write has somewhere defined
to land and the test can assert on it.
*/
@(private = "file")
retire_on_write :: proc(user: rawptr, buf: []u8) -> bool {
	h := cast(^Client_Close_Hook)user
	if h == nil || !h.armed || h.fired {
		return true
	}
	h.fired = true

	s, found := h.client.streams[h.stream_id]
	if !found {
		return true
	}
	delete_key(&h.client.streams, h.stream_id)
	h.retired = s
	return true
}

/*
An upstream that always has the next frame does not hold the reader's loop: a
fiber started beside the reader runs once `loop.TURN_BATCH` frames have been
read, not once the upstream stops sending. The reader is a fiber of the loop
that dialled the connection, and the queries waiting on its answers may be on
the same loop.
*/
@(test)
test_client_serve_takes_turns :: proc(t: ^testing.T) {
	FRAMES :: 4 * loop.TURN_BATCH
	Feed :: struct {
		frames:  int,
		sent:    int,
		ran_at:  int,
		started: bool,
	}
	feed := Feed {
		ran_at = -1,
	}
	feed_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
		f := (^Feed)(user)
		if !f.started {
			f.started = true
			// Behind the reader on the ready list, so it runs only once the reader
			// parks or yields.
			_, _ = loop.spawn(loop.current_loop(), proc(data: rawptr) {
				f := (^Feed)(data)
				f.ran_at = f.frames
			}, f)
		}
		if f.frames >= FRAMES {
			return 0, false
		}
		// A connection WINDOW_UPDATE of one, which nothing is waiting on. Not
		// one on a stream: no stream is open, so that is an idle-stream error.
		frame := [FRAME_HEADER_SIZE + 4]u8{0, 0, 4, u8(Frame_Type.Window_Update), 0, 0, 0, 0, 0, 0, 0, 0, 1}
		n = copy(buf, frame[f.sent:])
		f.sent += n
		if f.sent == len(frame) {
			f.sent = 0
			f.frames += 1
		}
		return n, true
	}

	l, made := loop.make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	th := loop.spawn_thread(l, loop.run, context)
	c := client_make(IO{user = &feed, read = feed_read, write = proc(user: rawptr, buf: []u8) -> bool {return true}})
	Job :: struct {
		c:    ^Client,
		done: sync.Sema,
	}
	job := Job {
		c = c,
	}
	_, _ = loop.spawn(l, proc(data: rawptr) {
		j := (^Job)(data)
		client_serve(j.c)
		sync.sema_post(&j.done)
	}, &job)
	finished := sync.sema_wait_with_timeout(&job.done, 5 * time.Second)
	loop.stop(l)
	thread.join(th)
	thread.destroy(th)
	loop.destroy(l)
	client_unref(c)

	testing.expect(t, finished, "the reader did not finish")
	// The premise: the reader never had to wait for a frame.
	testing.expect_value(t, feed.frames, FRAMES)
	testing.expectf(
		t,
		feed.ran_at >= 0 && feed.ran_at <= loop.TURN_BATCH,
		"the fiber beside the reader ran after %d of %d frames",
		feed.ran_at,
		FRAMES,
	)
}

@(test)
test_data_frame_cannot_touch_an_abandoned_stream :: proc(t: ^testing.T) {
	/*
	A response arriving for a stream whose caller has just given up on it must
	not write through a pointer the reader thread picked up before it released
	the lock.
	*/
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	hook := Client_Close_Hook{}
	c := client_make(IO{user = &hook, read = no_read, write = retire_on_write}, allocator)
	hook.client = c
	hook.stream_id = 1

	// The stream `client_request` would have opened, without the blocking wait.
	open_test_stream(c, 1, allocator)

	// One byte short of a batch, so this DATA's credit is written: the write
	// the hook rides in on.
	c.credit_owed = CREDIT_BATCH - 1
	hook.armed = true
	payload := []u8{'o', 'k'}
	client_handle_data(c, Frame_Header{length = len(payload), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, payload)

	testing.expect(t, hook.fired, "the retire hook never ran, so nothing was reproduced")
	testing.expect(t, hook.retired != nil, "the stream was not retired")
	testing.expect(t, !hook.retired.done, "a retired stream was marked done after it was abandoned")

	_, back_in_map := c.streams[1]
	testing.expect(t, !back_in_map, "the retired stream was put back in the table")

	client_stream_destroy(c, hook.retired)
	client_done(t, c, &track, "data after abandon")
}

@(test)
test_oversized_response_returns_connection_credit :: proc(t: ^testing.T) {
	/*
	The client side of the same accounting. An upstream response past the body
	limit has its stream reset, but the bytes still came off the connection and
	still count against a receive window every stream on it shares - and this
	connection is shared by design, so leaking that room stalls every query
	using it, not just the one that overran.
	*/
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)

	clear(&log.frames)
	payload := make([]u8, MAX_BODY + 1, context.temp_allocator)
	client_handle_data(c, Frame_Header{length = len(payload), type = .Data, stream_id = 1}, payload)

	testing.expect(t, saw_frame(&log, .Window_Update, 0), "the connection window was not replenished for a response that was refused")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "oversized response credit", &log)
}

/*
The client half of the same rule.

`client_handle_window_update` refuses a window pushed past 2^31-1;
`client_handle_settings` applied its retroactive delta to every open stream and
checked nothing, so an upstream could take the shared multiplexed connection's
streams past the maximum a byte at a time.
*/
@(test)
test_client_settings_window_change_is_bounded :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)

	grant := []u8{0x7f, 0xff, 0x00, 0x00} // MAX_WINDOW - DEFAULT_WINDOW
	granted := client_handle_window_update(
		c,
		Frame_Header{length = len(grant), type = .Window_Update, stream_id = 1},
		grant,
	)
	testing.expect(t, granted, "a window update to exactly the maximum was refused")
	testing.expect_value(t, s.send_window, MAX_WINDOW)

	clear(&log.frames)
	settings := []u8{0, u8(Setting.Initial_Window_Size), 0, 1, 0, 0} // 65536
	accepted := client_handle_settings(
		c,
		Frame_Header{length = len(settings), type = .Settings, stream_id = 0},
		settings,
	)
	testing.expect(t, !accepted, "a settings change past the maximum window was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for a flow-control violation")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "settings window overflow", &log)
}

/*
The client half of the same rule: RFC 9113 6.1 makes DATA on stream 0 a
connection error of type PROTOCOL_ERROR. `client_handle_data` looked it up in
the stream table and fell through same as any other miss, instead of
recognizing the connection control stream can never hold one.
*/
@(test)
test_client_data_on_stream_zero_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	body := []u8{'x'}
	ok := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 0}, body)
	testing.expect(t, !ok, "DATA on stream 0 was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for DATA on stream 0")

	client_done(t, c, &track, "client data on stream zero", &log)
}

/*
The client's bound is `next_stream_id`, not a server's `last_stream_id`, but
the rule is the same: RFC 9113 5.1 makes any frame on a stream id past what
this end has ever allocated a connection error of type PROTOCOL_ERROR. Left
unchecked, an upstream drives one connection WINDOW_UPDATE write per DATA
frame on ids this client never opened - the same amplification the server's
`h.stream_id > c.last_stream_id` guard exists to stop.
*/
@(test)
test_client_data_on_an_idle_stream_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	body := []u8{'x'}
	ok := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 3}, body)
	testing.expect(t, !ok, "DATA on an idle stream was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for DATA on an idle stream")

	client_done(t, c, &track, "client data on an idle stream", &log)
}

/*
This client allocates odd stream ids exclusively, and push is refused - so an
even id can never be legitimate here, whatever `next_stream_id` currently is.
The `>= next_stream_id` check alone misses this: after a single request,
`next_stream_id == 3`, and stream 2 - never allocated, never legitimate -
slips under that bound and reaches the ordinary not-found path.
*/
@(test)
test_client_data_on_an_even_stream_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)
	c.next_stream_id = 3

	body := []u8{'x'}
	ok := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 2}, body)
	testing.expect(t, !ok, "DATA on an even (server-initiated) stream was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for DATA on an even stream")

	client_done(t, c, &track, "client data on an even stream", &log)
}

/*
The client half of the same half-closed rule: RFC 9113 5.1 allows a stream
that already said END_STREAM only WINDOW_UPDATE, PRIORITY, or RST_STREAM
after that. `client_handle_data` did not check `s.done` and appended straight
to `s.body`, silently accepting more of a response the caller may already be
reading as complete.
*/
@(test)
test_client_data_after_end_stream_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.done = true

	clear(&log.frames)
	// One byte short of a batch, so the refused frame's credit is due on the wire.
	c.credit_owed = CREDIT_BATCH - 1
	body := []u8{'x'}
	ok := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, ok, "DATA after END_STREAM should be a stream error, not a connection error")
	testing.expect_value(t, len(s.body), 0)

	testing.expect(t, saw_frame(&log, .Rst_Stream, 1), "no RST_STREAM was sent for DATA after END_STREAM")
	testing.expect(t, saw_frame(&log, .Window_Update, 0), "the connection window was not replenished for a frame that was refused")

	/*
	A peer that keeps sending after the first violation must not draw a fresh
	RST_STREAM every time. `rst_sent`, set on the first violation above, is
	what keeps the second one quiet - kept separate from `s.done`/`s.reset` so
	it cannot itself turn a finished response into a reported failure.
	*/
	clear(&log.frames)
	ok2 := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, ok2, "a repeat violation should still be a stream error, not a connection error")
	testing.expect(t, !saw_frame(&log, .Rst_Stream), "a second RST_STREAM was sent for a stream already answered once")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client data after end stream", &log)
}

/*
The client half of the same peer-reset case: RFC 9113 5.4.2 forbids answering
an RST_STREAM with one of ours - that loops - so a stream the peer has
already reset must draw no RST_STREAM back, only its connection credit.
*/
@(test)
test_client_data_on_a_peer_reset_stream_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.reset = true

	clear(&log.frames)
	// One byte short of a batch, so the refused frame's credit is due on the wire.
	c.credit_owed = CREDIT_BATCH - 1
	body := []u8{'x'}
	ok := client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, ok, "DATA on a peer-reset stream should be a stream error, not a connection error")
	testing.expect_value(t, len(s.body), 0)

	testing.expect(t, !saw_frame(&log, .Rst_Stream), "an RST_STREAM was sent answering a stream the peer had already reset")
	testing.expect(t, saw_frame(&log, .Window_Update, 0), "the connection window was not replenished for a frame that was refused")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client data on a peer-reset stream", &log)
}

/*
RFC 9113 6.2: HEADERS is only ever sent on a stream, never on the connection
control stream - a connection error of type PROTOCOL_ERROR, the same as DATA
on stream 0. `client_handle_headers` went straight to padding/priority
stripping and HPACK decode with no such check, unlike the server's
`handle_headers`.
*/
@(test)
test_client_headers_on_stream_zero_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	block := make([dynamic]u8, 0, 64, context.temp_allocator)
	encode_header(&block, ":status", "200")
	ok := client_handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 0},
		block[:],
	)
	testing.expect(t, !ok, "HEADERS on stream 0 was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for HEADERS on stream 0")

	client_done(t, c, &track, "client headers on stream zero", &log)
}

/*
The HEADERS half of the same idle-stream rule `client_handle_data` got:
an id this client never allocated - past `next_stream_id`, or even, since
this client opens only odd ids and push is refused - is idle, and RFC 9113
5.1 makes DATA or HEADERS on one a connection error of type PROTOCOL_ERROR.
`client_handle_headers` had the stream-0 guard above but nothing past it, so
a HEADERS block on an id that could never belong to a request still ran the
full HPACK decode and was silently dropped by `client_finish_headers`'s
not-found path.
*/
@(test)
test_client_headers_on_an_idle_stream_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	block := make([dynamic]u8, 0, 64, context.temp_allocator)
	encode_header(&block, ":status", "200")
	// Even, and never allocated by this client either way.
	ok := client_handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 2},
		block[:],
	)
	testing.expect(t, !ok, "HEADERS on an idle stream was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for HEADERS on an idle stream")

	client_done(t, c, &track, "client headers on an idle stream", &log)
}

/*
The HEADERS half of the already-ended rule `client_handle_data` keeps for DATA.

`client_finish_headers` writes `:status` into `s.status` and sets `s.done`, so
without that rule an upstream sending a second HEADERS block after END_STREAM
would overwrite the status of a response the waiter in `client_request` might
be reading at that exact moment - broadcast already fired, lock not yet
re-acquired.
*/
@(test)
test_client_headers_after_end_stream_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.status = 200
	s.done = true

	clear(&log.frames)
	block := make([dynamic]u8, 0, 64, context.temp_allocator)
	encode_header(&block, ":status", "500")
	clear(&c.header_scratch)
	append(&c.header_scratch, ..block[:])
	ok := client_finish_headers(c, 1)
	testing.expect(t, ok, "HEADERS after END_STREAM should be a stream error, not a connection error")
	testing.expect_value(t, s.status, 200)

	testing.expect(t, saw_frame(&log, .Rst_Stream, 1), "no RST_STREAM was sent for HEADERS after END_STREAM")

	// A repeat violation must not draw a second RST_STREAM.
	clear(&log.frames)
	clear(&c.header_scratch)
	append(&c.header_scratch, ..block[:])
	ok2 := client_finish_headers(c, 1)
	testing.expect(t, ok2, "a repeat violation should still be a stream error, not a connection error")
	testing.expect_value(t, s.status, 200)
	testing.expect(t, !saw_frame(&log, .Rst_Stream), "a second RST_STREAM was sent for a stream already answered once")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client headers after end stream", &log)
}

/*
`client_send_body` is the one place the client itself writes DATA on a stream
mid-request. It checked `c.closed` and `s.reset` but not `s.done` or
`s.rst_sent` - so an upstream answering early (HEADERS+END_STREAM while the
request body is still uploading) and then drawing our own RST_STREAM with a
stray DATA frame left the body-sending thread writing further DATA frames
on a stream this connection had itself just reset.
*/
@(test)
test_client_send_body_stops_once_the_stream_is_reset_by_us :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.rst_sent = true

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), time.Second))
	testing.expect(t, !sent, "client_send_body wrote a body on a stream this connection had already reset")
	testing.expect(t, !saw_frame(&log, .Data), "a DATA frame was written on a stream this connection had already reset")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body after reset", &log)
}

/*
RFC 9113 8.1 explicitly allows a server to answer before it has read the
whole request, if the answer does not depend on the rest - a 413 on an
upload too large, a 401, a redirect. `client_send_body` returns success on
`s.done`, unlike `s.reset`, so `client_request` goes on to its wait loop and
returns the complete, valid response sitting in `s.status`/`s.body` rather than
reading a failure as `.Timeout`. Stopping the upload once the answer is in is
correct; reporting that as a failure is not.
*/
@(test)
test_client_send_body_stops_successfully_on_an_early_response :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.status = 413
	s.done = true

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), time.Second))
	testing.expect(t, sent, "an early response should stop the upload successfully, not report it as a failure")
	testing.expect(t, !saw_frame(&log, .Data), "a DATA frame was written after the response had already arrived complete")
	testing.expect(
		t,
		saw_frame(&log, .Rst_Stream, 1),
		"no RST_STREAM(NO_ERROR) was sent for the abandoned upload - RFC 9113 8.1 asks for one so the peer does not hold the stream open forever",
	)
	testing.expect_value(t, s.status, 413)

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body on early response", &log)
}

/*
RFC 9113 5.1 forbids sending frames other than PRIORITY on a stream already
closed with RST_STREAM - which is exactly what `rst_sent` records. The
`s.done` branch above sent RST_STREAM(NO_ERROR) unconditionally, so a stream
already answered with RST_STREAM(STREAM_CLOSED) (`rst_sent` true, reached via
`client_handle_data`'s or `client_finish_headers`'s own already_ended path)
drew a second RST_STREAM from the very code meant to avoid exactly that.
*/
@(test)
test_client_send_body_does_not_double_rst_a_stream_already_reset_by_us :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.status = 413
	s.done = true
	s.rst_sent = true

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), time.Second))
	testing.expect(t, sent, "an early response should stop the upload successfully")
	testing.expect(t, !saw_frame(&log, .Rst_Stream), "a second RST_STREAM was sent on a stream already reset by this connection")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body double rst", &log)
}

/*
The response-wait timeout in `client_request` sends RST_STREAM(.Cancel) when
it gives up, and so does the upload-side flow-control deadline in
`client_send_body`, which gives up the same way for the same reason - a peer
that stops granting window and says nothing else. Without it, a request
abandoned to a timeout mid-upload would leave the peer holding the stream (and
one of its MAX_CONCURRENT_STREAMS slots) open for the rest of the connection's
life.
*/
@(test)
test_client_send_body_resets_the_stream_on_a_flow_control_timeout :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	// No credit at all, so the wait loop has nothing to do but hit the deadline.
	s.send_window = 0
	c.send_window = 0

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), -time.Second))
	testing.expect(t, !sent, "client_send_body should give up once the deadline has passed")

	testing.expect(t, saw_frame(&log, .Rst_Stream, 1), "no RST_STREAM was sent for an upload abandoned to a flow-control timeout")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body flow control timeout", &log)
}

/*
RFC 9113 6.4: RST_STREAM always names a stream; stream 0 is a connection
error of type PROTOCOL_ERROR, the same check the server's Rst_Stream arm
makes. Checking the frame size alone would let RST_STREAM on stream 0 look up
c.streams[0] - always a miss - and return true.
*/
@(test)
test_client_rst_stream_on_stream_zero_is_a_connection_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	rst := []u8{0, 0, 0, 8} // CANCEL
	ok := client_handle_frame(c, Frame_Header{length = len(rst), type = .Rst_Stream, stream_id = 0}, rst)
	testing.expect(t, !ok, "RST_STREAM on stream 0 was accepted")

	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY was sent for RST_STREAM on stream 0")

	client_done(t, c, &track, "client rst_stream on stream zero", &log)
}

/*
`client_send_body`'s `s.done` branch read `rst_sent` to decide whether to
send RST(NO_ERROR), but never set it - so the RST it just sent did not
suppress the next one. `client_handle_data`'s `already_ended` is still true
here via `s.done` alone, and its own `need_rst` needed `rst_sent` to stay
false to fire again: a DATA frame the peer already had in flight then drew a
second RST_STREAM(STREAM_CLOSED) on a stream this end had just closed with
RST_STREAM(NO_ERROR) - which RFC 9113 5.1 forbids.
*/
@(test)
test_client_send_body_early_response_rst_suppresses_a_later_one :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.status = 413
	s.done = true

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), time.Second))
	testing.expect(t, sent, "an early response should stop the upload successfully")
	testing.expect(t, s.rst_sent, "client_send_body's own RST(NO_ERROR) did not mark the stream rst_sent")

	// The DATA frame the peer already had in flight when it answered early.
	clear(&log.frames)
	extra := []u8{'x'}
	dok := client_handle_data(c, Frame_Header{length = len(extra), type = .Data, stream_id = 1}, extra)
	testing.expect(t, dok, "DATA in flight when the response arrived should still be a stream error, not a connection error")
	testing.expect(t, !saw_frame(&log, .Rst_Stream), "a second RST_STREAM was sent on a stream already closed with RST(NO_ERROR)")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body early response rst", &log)
}

/*
The flow-control deadline path in `client_send_body` sends RST(.Cancel) and
sets `s.rst_sent` before it does - so a DATA frame the peer already had in
flight takes the `already_ended` path in `client_handle_data` rather than the
ordinary append path, which would append bytes to `s.body` and write a
stream-level WINDOW_UPDATE, both on a stream this end has already reset. RFC 9113
5.1 forbids sending or, implicitly, accepting anything but PRIORITY on a
stream closed with RST_STREAM.
*/
@(test)
test_client_send_body_flow_control_timeout_rst_is_not_forgotten :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)

	s := open_test_stream(c, 1, allocator)
	s.send_window = 0
	c.send_window = 0

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	sent := client_send_body(c, s, body, time.tick_add(time.tick_now(), -time.Second))
	testing.expect(t, !sent, "client_send_body should give up once the deadline has passed")
	testing.expect(t, s.rst_sent, "the flow-control timeout's own RST(.Cancel) did not mark the stream rst_sent")

	// The DATA frame the peer already had in flight when the timeout fired.
	clear(&log.frames)
	extra := []u8{'x'}
	dok := client_handle_data(c, Frame_Header{length = len(extra), type = .Data, stream_id = 1}, extra)
	testing.expect(t, dok, "DATA in flight when the timeout fired should still be a stream error, not a connection error")
	testing.expect_value(t, len(s.body), 0)
	testing.expect(t, !saw_frame(&log, .Rst_Stream), "a second RST_STREAM was sent on a stream already reset by the flow-control timeout")
	testing.expect(t, !saw_frame(&log, .Window_Update, 1), "a stream-level WINDOW_UPDATE was written on a stream this end had reset")

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client send body flow control timeout rst", &log)
}

/*
`:status` is exactly three digits (RFC 9113 8.3.2), and this is where an
upstream's word for how its answer went is taken.

`strconv.parse_int` with its default base reads more than that: `0x1` is a 1,
`1_0` is a 10, a sign is allowed, and a fourth digit is quietly dropped because
the field is not measured. A response that says `0x2c8` where a conforming peer
would say nothing intelligible then reads as 712 here - and further along, as
whatever the number happens to fall on either side of a `== 200`.

Anything that is not three digits is no status at all, and 0 is how that is
already reported for a `:status` the peer left out.
*/
@(test)
test_h2_status_is_three_digits :: proc(t: ^testing.T) {
	Case :: struct {
		value:  string,
		status: int,
		what:   string,
	}

	CASES := []Case {
		{"200", 200, "three digits"},
		{"404", 404, "three digits again, not from the static table"},
		{"0x1", 0, "hexadecimal"},
		{"0b11001000", 0, "binary"},
		{"1_0", 0, "a digit separator"},
		{"+200", 0, "a sign"},
		{"20", 0, "two digits"},
		{"2000", 0, "four digits"},
		{"", 0, "nothing at all"},
	}

	for c in CASES {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)

		client := client_make(IO{read = no_read, write = discard_write}, allocator)

		s := open_test_stream(client, 1, allocator)

		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", c.value)
		clear(&client.header_scratch)
		append(&client.header_scratch, ..block[:])

		testing.expectf(t, client_finish_headers(client, 1), "%s: the header block did not decode", c.what)
		testing.expectf(t, s.status == c.status, "%s: %q came back as status %d, expected %d", c.what, c.value, s.status, c.status)

		client_done(t, client, &track, c.what)
	}
}

/*
The client side of the empty-CONTINUATION flood.

The byte cap in `client_handle_continuation` measures what arrives, and an empty
CONTINUATION brings nothing - so the header block it is waiting on stays open
and the frames keep coming. The peer here is an upstream DoH server rather than
anyone who can reach a listener, which is why this is smaller than the server
side, but a reader thread that never gets to the end of a block is a reader
thread that never serves the responses behind it.
*/
@(test)
test_client_empty_continuation_flood_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	c := client_make(IO{read = no_read, write = discard_write}, allocator)
	c.continuation_on = 1

	sent := 0
	refused := false
	for _ in 0 ..< 10000 {
		sent += 1
		if !client_handle_continuation(c, Frame_Header{length = 0, type = .Continuation, stream_id = 1}, nil) {
			refused = true
			break
		}
	}
	testing.expectf(t, refused, "%d empty CONTINUATION frames were all accepted", sent)

	client_done(t, c, &track, "empty continuation flood")
}

@(private = "file")
Client_Header_Log :: struct {
	block: [dynamic]u8,
}

// Keeps the header block of the first HEADERS frame the client writes.
@(private = "file")
client_log_headers :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Client_Header_Log)user
	pos := 0
	if len(buf) >= len(PREFACE) && string(buf[:len(PREFACE)]) == PREFACE {
		pos = len(PREFACE)
	}
	for pos + FRAME_HEADER_SIZE <= len(buf) {
		h, ok := parse_frame_header(buf[pos:])
		if !ok || pos + FRAME_HEADER_SIZE + h.length > len(buf) {
			break
		}
		if h.type == .Headers && len(log.block) == 0 {
			append(&log.block, ..buf[pos + FRAME_HEADER_SIZE:pos + FRAME_HEADER_SIZE + h.length])
		}
		pos += FRAME_HEADER_SIZE + h.length
	}
	return true
}

/*
A request with a body says how long the body is.

RFC 9113 section 8.1.1 does not require `content-length` on HTTP/2, and most DoH
servers take a POST without it - but Cloudflare's does not: `cloudflare-dns.com`
and `1.1.1.1` answer HTTP 400 to every one, so an upstream configured there
failed every query with `HTTP_Error`. RFC 8484 section 4.1's own example POST
carries the header. Found by the live parity run with a DoH upstream.
*/
@(test)
test_client_request_sends_content_length :: proc(t: ^testing.T) {
	log := Client_Header_Log {
		block = make([dynamic]u8, 0, 128, context.temp_allocator),
	}
	c := client_make(IO{user = &log, read = no_read, write = client_log_headers})
	defer client_unref(c)

	body := []u8{0xde, 0xad, 0xbe, 0xef, 0x00}
	_, _ = client_request(
		c,
		Client_Request {
			method = "POST",
			scheme = "https",
			authority = "mock.invalid",
			path = "/dns-query",
			content_type = "application/dns-message",
			body = body,
		},
		10 * time.Millisecond,
	)

	table: Dynamic_Table
	dynamic_table_init(&table, DEFAULT_HEADER_TABLE_SIZE, context.temp_allocator)
	headers, err := decode(&table, log.block[:], context.temp_allocator)
	testing.expectf(t, err == .None, "the request's header block does not decode: %v", err)
	length := ""
	for f in headers {
		if f.name == "content-length" {
			length = f.value
		}
	}
	testing.expectf(t, length == "5", "content-length is %q, not the body's 5 bytes", length)
	free_all(context.temp_allocator)
}

/*
A stream this end opened as `id`, with its body and window as client_request
would leave them.
*/
@(private = "file")
open_test_stream :: proc(c: ^Client, id: u32, allocator: mem.Allocator) -> ^Client_Stream {
	s := new(Client_Stream, allocator)
	s.id = id
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 8, allocator)
	c.streams[id] = s
	c.next_stream_id = id + 2
	return s
}

/*
The client side of #308: each PING and non-ACK SETTINGS from an upstream draws
a frame back, so one that sends nothing else keeps a pooled connection's
reader echoing for as long as it likes. Past the per-second budget the
connection is told ENHANCE_YOUR_CALM and dropped.
*/
@(private = "file")
expect_client_control_flood_refused :: proc(t: ^testing.T, h: Frame_Header, payload: []u8, what: string) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)
	// A window that opens in the future cannot roll over mid-burst.
	c.control.window = time.tick_add(time.tick_now(), time.Hour)

	sent := 0
	refused := false
	for sent < 1000 {
		sent += 1
		if !client_handle_frame(c, h, payload) {
			refused = true
			break
		}
	}
	testing.expectf(t, refused, "%s: %d frames in a burst were all answered", what, sent)
	testing.expectf(t, sent == MAX_CONTROL_FRAMES_PER_SECOND + 1, "%s: refused at frame %d, not the first one over the budget", what, sent)
	testing.expectf(t, saw_frame(&log, .Goaway), "%s: the flood was dropped without a GOAWAY", what)
	testing.expectf(t, log.goaway_code == .Enhance_Your_Calm, "%s: GOAWAY said %v, not ENHANCE_YOUR_CALM", what, log.goaway_code)

	delete(log.frames)
	client_done(t, c, &track, what)
}

@(test)
test_client_ping_flood_is_refused :: proc(t: ^testing.T) {
	expect_client_control_flood_refused(t, Frame_Header{length = 8, type = .Ping}, make([]u8, 8, context.temp_allocator), "client ping flood")
}

@(test)
test_client_settings_flood_is_refused :: proc(t: ^testing.T) {
	expect_client_control_flood_refused(t, Frame_Header{type = .Settings}, nil, "client settings flood")
}

// The server's test_control_frame_budget_refills_each_second, for the client:
// ACKs draw nothing back so are not charged, and a spent budget comes back.
@(test)
test_client_control_budget_refills_each_second :: proc(t: ^testing.T) {
	c := client_make(IO{read = no_read, write = log_write})
	defer client_unref(c)
	ping := Frame_Header{length = 8, type = .Ping}
	payload := make([]u8, 8, context.temp_allocator)

	for _ in 0 ..< MAX_CONTROL_FRAMES_PER_SECOND {
		testing.expect(t, client_handle_frame(c, ping, payload), "a PING within the budget was refused")
	}
	ack := Frame_Header{length = 8, type = .Ping, flags = FLAG_ACK}
	testing.expect(t, client_handle_frame(c, ack, payload), "a PING ACK was charged against the budget")
	settings_ack := Frame_Header{type = .Settings, flags = FLAG_ACK}
	testing.expect(t, client_handle_frame(c, settings_ack, nil), "a SETTINGS ACK was charged against the budget")

	c.control.window = time.tick_add(c.control.window, -time.Second)
	testing.expect(t, client_handle_frame(c, ping, payload), "the budget did not refill after a second")
	testing.expect_value(t, c.control.frames, 1)
	free_all(context.temp_allocator)
}

/*
The client side of #393: a WINDOW_UPDATE pair for each 1-byte DATA frame on
an open stream would be 26 bytes out for 10 in. Credit is owed until a batch of
it is due, and every byte of it is still returned or owed.
*/
@(test)
test_client_tiny_data_frames_are_not_reflected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	log: Frame_Log
	c := logged_client(&log, allocator)
	open_test_stream(c, 1, allocator)

	clear(&log.frames)
	// The preface's own window grant is not this test's credit.
	log.credit = 0
	body := []u8{'x'}
	sent := 0
	frames := 0
	for frames < CREDIT_BATCH + 1000 {
		if !client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body) {
			break
		}
		frames += 1
		sent += FRAME_HEADER_SIZE + len(body)
	}
	written := 0
	for f in log.frames {
		written += FRAME_HEADER_SIZE + f.length
	}
	testing.expectf(t, written * 10 < sent, "%d bytes of 1-byte DATA frames drew %d bytes back", sent, written)
	testing.expectf(t, log.credit >= CREDIT_BATCH, "%d bytes read, only %d of credit returned", frames, log.credit)
	testing.expectf(t, log.credit + c.credit_owed == frames, "%d bytes read, %d returned and %d owed", frames, log.credit, c.credit_owed)

	client_done(t, c, &track, "client tiny data frames", &log)
}

/*
With no stream-level WINDOW_UPDATE, a stream's window is only ever spent, and
padding spends it without growing the body. A padded response under
MAX_BODY is kept; a stream that has spent half its window is reset
rather than left to run it dry and stall its caller until the timeout.
*/
@(test)
test_client_padding_cannot_stall_a_stream :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	c := client_make(IO{read = no_read, write = log_write}, allocator)
	s := open_test_stream(c, 1, allocator)
	// Its response headers are in, so DATA is its body.
	s.final = true

	// One byte of body in 257 bytes of window, each.
	frame := make([]u8, 257, context.temp_allocator)
	frame[0] = 255
	spent := 0
	send :: proc(c: ^Client, frame: []u8, spent: ^int) -> bool {
		spent^ += len(frame)
		return client_handle_data(c, Frame_Header{length = len(frame), type = .Data, flags = FLAG_PADDED, stream_id = 1}, frame)
	}
	for spent <= MAX_BODY {
		testing.expect(t, send(c, frame, &spent), "a padded DATA frame was a connection error")
	}
	testing.expectf(t, !s.reset, "a %d-byte response padded past MAX_BODY was refused", len(s.body))
	for spent <= RECV_WINDOW / 2 {
		testing.expect(t, send(c, frame, &spent), "a padded DATA frame was a connection error")
	}
	testing.expectf(t, s.reset, "a stream that spent %d bytes of its window was left open", spent)

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client padded stream")
}

/*
An upstream that PINGs once per answer is held to our own query rate, not to
MAX_CONTROL_FRAMES_PER_SECOND: a busy pooled connection answers far more than
that many queries a second, and dropping it would fail every one in flight.
*/
@(test)
test_client_answers_earn_back_the_control_budget :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	c := client_make(IO{read = no_read, write = log_write}, allocator)
	c.control.window = time.tick_add(time.tick_now(), time.Hour)
	block := make([dynamic]u8, 0, 16, context.temp_allocator)
	encode_header(&block, ":status", "200")
	ping := make([]u8, 8, context.temp_allocator)

	answered := 0
	for id := u32(1); answered < 4 * MAX_CONTROL_FRAMES_PER_SECOND; id += 2 {
		s := open_test_stream(c, id, allocator)

		h := Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = id}
		ok := client_handle_frame(c, h, block[:])
		// A second HEADERS on the same stream earns nothing more.
		ok = ok && client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = id}, block[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = 8, type = .Ping}, ping)
		client_stream_destroy(c, s)
		delete_key(&c.streams, id)
		if !ok {
			break
		}
		answered += 1
	}
	testing.expect_value(t, answered, 4 * MAX_CONTROL_FRAMES_PER_SECOND)

	// Two PINGs an answer is still one more than it earns, however many HEADERS
	// the upstream sends: capped.
	id := u32(2 * answered + 1)
	doubled := 0
	for doubled < 4 * MAX_CONTROL_FRAMES_PER_SECOND {
		s := open_test_stream(c, id, allocator)
		ok := client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = id}, block[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = id}, block[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = 8, type = .Ping}, ping)
		ok = ok && client_handle_frame(c, Frame_Header{length = 8, type = .Ping}, ping)
		client_stream_destroy(c, s)
		delete_key(&c.streams, id)
		id += 2
		if !ok {
			break
		}
		doubled += 1
	}
	testing.expectf(t, doubled < 4 * MAX_CONTROL_FRAMES_PER_SECOND, "two PINGs per answer were never capped")
	client_done(t, c, &track, "client earned budget")
}

/*
One stream earns one frame back, however its status comes and goes: a :status
that is not three digits reads as 0, and must not make a later valid one look
like the stream's first answer.
*/
@(test)
test_client_one_stream_earns_one_frame :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	c := client_make(IO{read = no_read, write = log_write}, allocator)
	c.control.window = time.tick_add(time.tick_now(), time.Hour)
	c.control.frames = MAX_CONTROL_FRAMES_PER_SECOND
	s := open_test_stream(c, 1, allocator)

	good := make([dynamic]u8, 0, 16, context.temp_allocator)
	encode_header(&good, ":status", "200")
	bad := make([dynamic]u8, 0, 16, context.temp_allocator)
	encode_header(&bad, ":status", "x")
	ping := make([]u8, 8, context.temp_allocator)

	answered := 0
	for answered < 1000 {
		ok := client_handle_frame(c, Frame_Header{length = len(good), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, good[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = len(bad), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, bad[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = 8, type = .Ping}, ping)
		if !ok {
			break
		}
		answered += 1
	}
	testing.expectf(t, answered == 1, "one stream earned %d PINGs back, not 1", answered)

	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_done(t, c, &track, "client one stream")
}

// The order answers and PINGs arrive in does not matter: answers that come
// first still earn their frames for the PINGs after them.
@(test)
test_client_answers_before_pings_still_earn :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	c := client_make(IO{read = no_read, write = log_write}, allocator)
	c.control.window = time.tick_add(time.tick_now(), time.Hour)
	block := make([dynamic]u8, 0, 16, context.temp_allocator)
	encode_header(&block, ":status", "200")
	ping := make([]u8, 8, context.temp_allocator)

	ANSWERS :: 2 * MAX_CONTROL_FRAMES_PER_SECOND
	for id := u32(1); id < 2 * ANSWERS; id += 2 {
		s := open_test_stream(c, id, allocator)
		h := Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = id}
		testing.expect(t, client_handle_frame(c, h, block[:]), "an answer was refused")
		client_stream_destroy(c, s)
		delete_key(&c.streams, id)
	}
	// The PINGs trail their answers into the next second: what was earned must
	// not expire with the window it was earned in.
	c.control.window = time.tick_add(time.tick_now(), -2 * time.Second)
	pinged := 0
	for pinged < 1000 && client_handle_frame(c, Frame_Header{length = 8, type = .Ping}, ping) {
		pinged += 1
	}
	testing.expect_value(t, pinged, ANSWERS + MAX_CONTROL_FRAMES_PER_SECOND)

	client_done(t, c, &track, "client answers first")
}

@(private = "file")
Limit_Request :: struct {
	c:   ^Client,
	err: Client_Error,
}

@(private = "file")
limit_request_run :: proc(r: ^Limit_Request) {
	req := Client_Request {
		method    = "GET",
		scheme    = "https",
		authority = "mock.invalid",
		path      = "/dns-query",
	}
	_, r.err = client_request(r.c, req, 5 * time.Second)
}

// How many HEADERS the client has written, and the stream id of the last.
@(private = "file")
limit_opened :: proc(c: ^Client, log: ^Frame_Log) -> (n: int, last: u32) {
	loop.lock(&c.mu)
	defer loop.unlock(&c.mu)
	for f in log.frames {
		if f.type == .Headers {
			n += 1
			last = f.stream_id
		}
	}
	return
}

// Waits for the client to have written `want` HEADERS, for up to two seconds.
@(private = "file")
limit_wait_opened :: proc(c: ^Client, log: ^Frame_Log, want: int) -> (last: u32, ok: bool) {
	for _ in 0 ..< 400 {
		n, id := limit_opened(c, log)
		if n >= want {
			return id, true
		}
		time.sleep(5 * time.Millisecond)
	}
	return 0, false
}

// Finishes a stream as a response with END_STREAM would.
@(private = "file")
limit_answer :: proc(c: ^Client, id: u32) {
	loop.lock(&c.mu)
	defer loop.unlock(&c.mu)
	if s, found := c.streams[id]; found {
		s.status = 200
		s.done = true
		loop.cond_broadcast(&c.cond)
	}
}

/*
RFC 9113 5.1.2: a client must not open more streams than the peer's
SETTINGS_MAX_CONCURRENT_STREAMS. Every worker shares one connection to a DoH
upstream, and a peer holding its limit refuses the stream over it with
RST_STREAM(REFUSED_STREAM) - a failed query, charged to an upstream that is
working fine (#326). The request past the limit has to wait for a slot.
*/
@(test)
test_client_waits_for_a_stream_slot_under_the_peers_limit :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	one := []u8{0, u8(Setting.Max_Concurrent_Streams), 0, 0, 0, 1}
	testing.expect(t, client_handle_settings(c, Frame_Header{length = len(one), type = .Settings}, one))

	reqs := [2]Limit_Request{{c = c}, {c = c}}
	threads: [2]^thread.Thread
	for &r, i in reqs {
		threads[i] = thread.create_and_start_with_poly_data(&r, limit_request_run)
	}

	first, ok := limit_wait_opened(c, &log, 1)
	testing.expect(t, ok, "no request opened a stream")
	// Long enough for the second request to have opened one too, had it not waited.
	time.sleep(200 * time.Millisecond)
	opened, _ := limit_opened(c, &log)
	testing.expect_value(t, opened, 1)

	limit_answer(c, first)
	second, ok2 := limit_wait_opened(c, &log, 2)
	testing.expect(t, ok2, "the waiting request never opened its stream once a slot freed")
	testing.expect(t, second != first, "the second request reused the first one's stream")
	limit_answer(c, second)

	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	for r in reqs {
		testing.expect_value(t, r.err, Client_Error.None)
	}
	free_all(context.temp_allocator)
}

/*
The wait for a slot has two ways out besides a slot freeing: the request's own
deadline, and the connection dying. Neither may open a stream.
*/
@(test)
test_client_wait_for_a_stream_slot_ends_on_deadline_or_close :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	// One slot, held by a stream that is never answered.
	one := []u8{0, u8(Setting.Max_Concurrent_Streams), 0, 0, 0, 1}
	testing.expect(t, client_handle_settings(c, Frame_Header{length = len(one), type = .Settings}, one))
	held := open_test_stream(c, 1, context.allocator)
	defer {
		delete_key(&c.streams, u32(1))
		client_stream_destroy(c, held)
	}

	req := Client_Request {
		method    = "GET",
		scheme    = "https",
		authority = "mock.invalid",
		path      = "/dns-query",
	}
	start := time.tick_now()
	_, err := client_request(c, req, 100 * time.Millisecond)
	testing.expect_value(t, err, Client_Error.Timeout)
	testing.expect(t, time.tick_since(start) < 2 * time.Second, "the wait outlived the request's deadline")

	r := Limit_Request {
		c = c,
	}
	th := thread.create_and_start_with_poly_data(&r, limit_request_run)
	time.sleep(100 * time.Millisecond)
	start = time.tick_now()
	// What client_serve does on its way out.
	loop.lock(&c.mu)
	c.closed = true
	loop.cond_broadcast(&c.cond)
	loop.cond_broadcast(&c.slot_cond)
	loop.unlock(&c.mu)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, r.err, Client_Error.Closed)
	testing.expect(t, time.tick_since(start) < 2 * time.Second, "a closed connection did not end the wait")

	opened, _ := limit_opened(c, &log)
	testing.expect_value(t, opened, 0)
	free_all(context.temp_allocator)
}

/*
A limit of zero with nothing open is a connection that will take no request
until the peer sends another SETTINGS, and nothing says it will. Waiting on it
costs every query its whole timeout - charged to the upstream as silence - and
`get_h2_conn` hands the same connection out again after the cooldown. It is
given up on at once instead, so the next query dials a fresh one.
*/
@(test)
test_client_a_zero_stream_limit_with_nothing_open_closes_the_connection :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	zero := []u8{0, u8(Setting.Max_Concurrent_Streams), 0, 0, 0, 0}
	testing.expect(t, client_handle_settings(c, Frame_Header{length = len(zero), type = .Settings}, zero))

	start := time.tick_now()
	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Closed)
	testing.expect(t, time.tick_since(start) < 500 * time.Millisecond, "the request waited on a connection that takes none")
	testing.expect(t, client_closed(c), "the connection was left open for the next request to wait on")
	opened, _ := limit_opened(c, &log)
	testing.expect_value(t, opened, 0)
	free_all(context.temp_allocator)
}

/*
RFC 9113 8.1: a server may answer in full and then RST_STREAM(NO_ERROR) the
upload, and the client MUST NOT discard that response. When the reset lands
before the waiter looks, the complete response still wins.
*/
@(test)
test_client_keeps_a_complete_response_reset_after_it_finished :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	r := Limit_Request {
		c = c,
	}
	th := thread.create_and_start_with_poly_data(&r, limit_request_run)
	id, ok := limit_wait_opened(c, &log, 1)
	testing.expect(t, ok, "the request never opened a stream")
	loop.lock(&c.mu)
	if s, found := c.streams[id]; found {
		s.status = 200
		s.done = true
		s.reset = true
		loop.cond_broadcast(&c.cond)
	}
	loop.unlock(&c.mu)
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, r.err, Client_Error.None)
	free_all(context.temp_allocator)
}

/*
A SETTINGS that raises the limit frees a slot as surely as a stream leaving,
and the request waiting on it must be let in then - not left until the held
stream is answered, or until its own deadline.
*/
@(test)
test_client_a_raised_stream_limit_lets_a_waiting_request_in :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	// One slot, held by a stream that is never answered.
	one := []u8{0, u8(Setting.Max_Concurrent_Streams), 0, 0, 0, 1}
	testing.expect(t, client_handle_settings(c, Frame_Header{length = len(one), type = .Settings}, one))
	held := open_test_stream(c, 1, context.allocator)
	defer {
		delete_key(&c.streams, u32(1))
		client_stream_destroy(c, held)
	}

	r := Limit_Request {
		c = c,
	}
	th := thread.create_and_start_with_poly_data(&r, limit_request_run)
	time.sleep(100 * time.Millisecond)
	opened, _ := limit_opened(c, &log)
	testing.expect_value(t, opened, 0)

	two := []u8{0, u8(Setting.Max_Concurrent_Streams), 0, 0, 0, 2}
	testing.expect(t, client_handle_settings(c, Frame_Header{length = len(two), type = .Settings}, two))
	id, ok := limit_wait_opened(c, &log, 1)
	testing.expect(t, ok, "the raised limit did not let the waiting request in")
	limit_answer(c, id)

	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, r.err, Client_Error.None)
	free_all(context.temp_allocator)
}

@(private = "file")
State_Probe :: struct {
	c:        ^Client,
	finished: sync.Sema,
	closed:   bool,
	busy:     bool,
}

@(private = "file")
state_probe_run :: proc(p: ^State_Probe) {
	p.closed = client_closed(p.c)
	client_ref(p.c)
	_, p.busy = client_idle_for(p.c)
	client_unref(p.c)
	sync.sema_post(&p.finished)
}

/*
What the upstream asks of a connection under a lock of its own - closed, idle,
another reference - must not wait for `mu`. `mu` is held across a socket write,
which parks; a fiber that parked on it while holding the upstream's plain lock
would block every fiber of its loop that reached for that lock next, the writer
among them when it shares the loop, and none of them would run again.
*/
@(test)
test_client_state_is_read_without_the_connection_lock :: proc(t: ^testing.T) {
	log: Frame_Log
	c := logged_client(&log)
	defer delete(log.frames)
	defer client_unref(c)

	// A writer parked mid-frame, as far as anybody else can tell.
	loop.lock(&c.mu)
	p := State_Probe {
		c = c,
	}
	th := thread.create_and_start_with_poly_data(&p, state_probe_run)
	answered := sync.sema_wait_with_timeout(&p.finished, 2 * time.Second)
	loop.unlock(&c.mu)
	thread.join(th)
	thread.destroy(th)

	testing.expect(t, answered, "reading the connection's state waited for the lock a writer holds")
	testing.expect(t, !p.closed, "a fresh connection read as closed")
	testing.expect(t, p.busy, "a second reference did not make the connection busy")
	free_all(context.temp_allocator)
}

/*
The client's side of the server's idle-stream and ENABLE_PUSH rules. RFC 9113
6.5.2 holds a server to ENABLE_PUSH 0 and has a client treat 1 as a
PROTOCOL_ERROR, so anything but 0 is refused here. Idle is an id this client
never allocated: at or past `next_stream_id`, or even.
*/
@(test)
test_client_idle_stream_and_enable_push_protocol_errors :: proc(t: ^testing.T) {
	cases := []struct {
		what:     string,
		h:        Frame_Header,
		payload:  []u8,
		accepted: bool,
	} {
		{"ENABLE_PUSH=1", {length = 6, type = .Settings}, {0, u8(Setting.Enable_Push), 0, 0, 0, 1}, false},
		{"ENABLE_PUSH=2", {length = 6, type = .Settings}, {0, u8(Setting.Enable_Push), 0, 0, 0, 2}, false},
		{"WINDOW_UPDATE on idle stream 5", {length = 4, type = .Window_Update, stream_id = 5}, {0, 0, 0x10, 0}, false},
		{"WINDOW_UPDATE on even stream 2", {length = 4, type = .Window_Update, stream_id = 2}, {0, 0, 0x10, 0}, false},
		{"RST_STREAM on idle stream 5", {length = 4, type = .Rst_Stream, stream_id = 5}, {0, 0, 0, 8}, false},
		{"RST_STREAM on even stream 2", {length = 4, type = .Rst_Stream, stream_id = 2}, {0, 0, 0, 8}, false},
		{"ENABLE_PUSH=0", {length = 6, type = .Settings}, {0, u8(Setting.Enable_Push), 0, 0, 0, 0}, true},
		{"WINDOW_UPDATE on closed stream 3", {length = 4, type = .Window_Update, stream_id = 3}, {0, 0, 0x10, 0}, true},
		{"RST_STREAM on closed stream 3", {length = 4, type = .Rst_Stream, stream_id = 3}, {0, 0, 0, 8}, true},
		{"WINDOW_UPDATE on the connection", {length = 4, type = .Window_Update}, {0, 0, 0x10, 0}, true},
	}
	for tc in cases {
		log: Frame_Log
		c := logged_client(&log)
		// Stream 3 was allocated and has finished.
		c.next_stream_id = 5
		ok := client_handle_frame(c, tc.h, tc.payload)
		saw_goaway := saw_frame(&log, .Goaway)
		if tc.accepted {
			testing.expectf(t, ok && !saw_goaway, "%s: accepted=%v goaway=%v, want accepted", tc.what, ok, saw_goaway)
		} else {
			testing.expectf(
				t,
				!ok && saw_goaway && log.goaway_code == .Protocol_Error,
				"%s: accepted=%v goaway=%v (%v), want PROTOCOL_ERROR",
				tc.what,
				ok,
				saw_goaway,
				log.goaway_code,
			)
		}
		delete(log.frames)
		client_unref(c)
		free_all(context.temp_allocator)
	}
}

/*
RFC 9113 8.1: a response is any number of interim (1xx) header sections, one
final one, the body, and optionally trailers, which end the stream and carry no
pseudo-header field. A response that breaks that is malformed, a stream error
of type PROTOCOL_ERROR (8.1.1) that a client MUST NOT accept: the request fails
as reset, so neither a trailer's `:status` nor DATA ahead of the final
section is taken for the answer's (#457).
*/
@(test)
test_client_response_framing_follows_rfc_9113_8_1 :: proc(t: ^testing.T) {
	Block :: struct {
		status:     string,
		end_stream: bool,
	}
	Case :: struct {
		what:      string,
		blocks:    []Block,
		// The block DATA goes after.
		data_at:   int,
		malformed: bool,
		status:    int,
	}
	// A block with no status is a trailer section, of `x-t`, or of the field
	// named in place of one.
	cases := []Case {
		{"trailers end the response", {{"200", false}, {"", true}}, 0, false, 200},
		{"interim responses come first", {{"103", false}, {"200", false}, {"", true}}, 1, false, 200},
		{"a trailer with :status", {{"200", false}, {"500", true}}, 0, true, 200},
		{"trailers without END_STREAM", {{"200", false}, {"", false}}, 0, true, 200},
		{"an interim response with END_STREAM", {{"100", true}}, 0, true, 100},
		{"DATA behind an interim response", {{"103", false}, {"200", true}}, 0, true, 103},
		{"a trailer field 8.2 refuses", {{"200", false}, {"connection", true}}, 0, true, 200},
		// No `:status` is no response; the interim one's is not carried over.
		{"a section without :status after an interim one", {{"103", false}, {"", true}}, 3, true, 0},
		{"a later :status behind a section without one", {{"103", false}, {"", false}, {"200", true}}, 3, true, 0},
		{"a response without :status", {{"", true}}, 3, true, 0},
		{"a malformed :status", {{"0x1", true}}, 3, true, 0},
		{"a 101, which HTTP/2 has no use for", {{"101", false}, {"200", true}}, 2, true, 101},
	}
	for tc in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)

		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)

		ok := true
		for b, i in tc.blocks {
			block := make([dynamic]u8, 0, 64, context.temp_allocator)
			switch {
			case b.status == "":
				encode_header(&block, "x-t", "1")
			case b.status[0] >= '0' && b.status[0] <= '9':
				encode_header(&block, ":status", b.status)
			case:
				encode_header(&block, b.status, "1")
			}
			flags := u8(FLAG_END_HEADERS) | (u8(FLAG_END_STREAM) if b.end_stream else 0)
			ok = ok && client_handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = flags, stream_id = 1}, block[:])
			if i == tc.data_at && !b.end_stream && !s.reset {
				body := []u8{'x'}
				ok = ok && client_handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
			}
		}
		testing.expectf(t, ok, "%s: the connection was dropped", tc.what)
		testing.expectf(t, s.status == tc.status, "%s: status %d, want %d", tc.what, s.status, tc.status)
		testing.expectf(t, s.reset == tc.malformed, "%s: reset %v, want %v", tc.what, s.reset, tc.malformed)
		testing.expectf(t, s.done == !tc.malformed, "%s: done %v, want %v", tc.what, s.done, !tc.malformed)
		rsts := count_frames(&log, .Rst_Stream)
		if tc.malformed {
			testing.expectf(t, rsts == 1 && log.rst_code == .Protocol_Error, "%s: %d RST_STREAM, last %v; want one PROTOCOL_ERROR", tc.what, rsts, log.rst_code)
			// A REFUSED_STREAM in flight behind this end's reset does not make the
			// request one to retry.
			code := []u8{0, 0, 0, u8(Error_Code.Refused_Stream)}
			ok = client_handle_frame(c, Frame_Header{length = 4, type = .Rst_Stream, stream_id = 1}, code)
			testing.expectf(t, ok && !s.refused, "%s: a later REFUSED_STREAM made the reset retryable", tc.what)
		} else {
			testing.expectf(t, rsts == 0, "%s: %d RST_STREAM", tc.what, rsts)
		}

		delete(log.frames)
		client_stream_destroy(c, s)
		delete_key(&c.streams, u32(1))
		client_done(t, c, &track, tc.what)
	}
}

/*
RFC 9113 8.3: a response's header section carries one `:status`, ahead of its
ordinary fields, and no other pseudo-header; 8.2 holds its ordinary fields as
it holds any. A response that breaks either is malformed and is not accepted
(8.1.1) - a second `:status` in particular would be read as the answer's.
*/
@(test)
test_client_response_head_is_held_to_8_2_and_8_3 :: proc(t: ^testing.T) {
	Case :: struct {
		what:   string,
		fields: []Header_Field,
	}
	cases := []Case {
		{"a second :status", {{":status", "500"}, {":status", "200"}}},
		{"a request pseudo-header", {{":status", "200"}, {":path", "/"}}},
		{"a pseudo-header after an ordinary field", {{"content-type", "application/dns-message"}, {":status", "200"}}},
		{"a connection-specific field", {{":status", "200"}, {"connection", "close"}}},
		{"an uppercase name", {{":status", "200"}, {"Content-Type", "application/dns-message"}}},
	}
	for tc in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)

		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)

		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		for f in tc.fields {
			encode_header(&block, f.name, f.value)
		}
		ok := client_handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, block[:])
		testing.expectf(t, ok, "%s: the connection was dropped", tc.what)
		testing.expectf(t, s.reset && !s.done, "%s: a malformed response was accepted (status %d)", tc.what, s.status)
		testing.expectf(t, log.rst_code == .Protocol_Error, "%s: RST code %v, want PROTOCOL_ERROR", tc.what, log.rst_code)

		delete(log.frames)
		client_done(t, c, &track, tc.what)
	}
}

// The server's rule on the client's side: a CONTINUATION with no block open is
// a connection error, stream 0 included, and never reaches the HPACK decoder.
@(test)
test_client_continuation_on_stream_zero_with_no_block_open_is_refused :: proc(t: ^testing.T) {
	c := client_make(IO{read = no_read, write = discard_write})
	// x-t: 1, with incremental indexing: a decoder that took it has an entry.
	block := []u8{0x40, 0x03, 'x', '-', 't', 0x01, '1'}
	ok := client_handle_continuation(c, Frame_Header{length = len(block), type = .Continuation, flags = FLAG_END_HEADERS, stream_id = 0}, block)
	testing.expect(t, !ok, "a CONTINUATION on stream 0 with no block open was accepted")
	testing.expect_value(t, len(c.decoder.entries), 0)
	client_unref(c)
	free_all(context.temp_allocator)
}
