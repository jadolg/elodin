package h2

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

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
		// See h2client.odin's h2_io_read: on Linux, SO_RCVTIMEO expiring on a
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
	tc := cast(^Test_Conn)user
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(tc.socket, buf[sent:])
		if err != nil || n <= 0 {
			return false
		}
		sent += n
	}
	return true
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

// Runs a real server-side Conn over one accepted connection, using `handler`
// to answer every request.
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
	tc := new(Test_Conn)
	tc.socket = client
	defer {
		net.close(client)
		free(tc)
	}
	io := IO{user = tc, read = test_io_read, write = test_io_write}
	hc := make_conn(io, s.handler, nil)
	serve(hc)
	conn_wait_idle(hc)
	conn_unref(hc)
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
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}
	srv := Test_Server{listener = listener, handler = echo_handler}
	server_thread := thread.create_and_start_with_poly_data(&srv, test_server_once)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

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
		mem.tracking_allocator(&track),
	)
	testing.expectf(t, err == .None, "request failed: %v", err)
	testing.expect_value(t, resp.status, 200)
	testing.expect_value(t, len(resp.body), len(want))
	if len(resp.body) == len(want) {
		testing.expect(t, string(resp.body) == string(want), "body was not echoed back unchanged")
	}
	delete(resp.body, mem.tracking_allocator(&track))

	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes still held, allocated at %v", entry.size, entry.location)
	}
	free_all(context.temp_allocator)
}

@(test)
test_client_multiplexes_concurrent_streams :: proc(t: ^testing.T) {
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}
	srv := Test_Server{listener = listener, handler = echo_handler}
	server_thread := thread.create_and_start_with_poly_data(&srv, test_server_once)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

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

@(test)
test_client_request_reset_by_peer :: proc(t: ^testing.T) {
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	Script :: struct {
		listener: net.TCP_Socket,
	}
	run_script :: proc(s: ^Script) {
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		defer net.close(client)
		// Client preface, then whatever it sends, until its request HEADERS.
		preface: [len(PREFACE)]u8
		if !test_recv_full(client, preface[:]) {
			return
		}
		_, ok := test_wait_for_frame_type(client, .Headers)
		if !ok {
			return
		}
		out := make([dynamic]u8, 0, 13, context.temp_allocator)
		write_frame_header(&out, 4, .Rst_Stream, 0, 1)
		append_u32(&out, u32(Error_Code.Refused_Stream))
		_ = test_send(client, out[:])
	}
	srv := Script{listener = listener}
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Reset)
	free_all(context.temp_allocator)
}

@(test)
test_client_goaway_closes_the_connection :: proc(t: ^testing.T) {
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	Script :: struct {
		listener: net.TCP_Socket,
	}
	run_script :: proc(s: ^Script) {
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		defer net.close(client)
		preface: [len(PREFACE)]u8
		if !test_recv_full(client, preface[:]) {
			return
		}
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
	srv := Script{listener = listener}
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

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
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	Script :: struct {
		listener: net.TCP_Socket,
	}
	run_script :: proc(s: ^Script) {
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		defer net.close(client)
		preface: [len(PREFACE)]u8
		_ = test_recv_full(client, preface[:])
	}
	srv := Script{listener = listener}
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	sync.mutex_lock(&c.mu)
	c.next_stream_id = 0x8000_0001
	sync.mutex_unlock(&c.mu)

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
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	// The mock holds the accepted socket open until the test explicitly
	// releases it, rather than closing it after a fixed sleep: closing it
	// early would let client_serve's own read-error path close and broadcast
	// the connection, waking stream A for a reason unrelated to the one this
	// test checks and masking a missing broadcast in the exhaustion branch.
	Script :: struct {
		listener:     net.TCP_Socket,
		headers_seen: bool,
		stop:         bool,
	}
	run_script :: proc(s: ^Script) {
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		defer net.close(client)
		preface: [len(PREFACE)]u8
		if !test_recv_full(client, preface[:]) {
			return
		}
		// This is stream A's HEADERS; never respond to it.
		if _, ok := test_wait_for_frame_type(client, .Headers); ok {
			sync.atomic_store(&s.headers_seen, true)
		}
		for !sync.atomic_load(&s.stop) {
			time.sleep(10 * time.Millisecond)
		}
	}
	srv := Script{listener = listener}
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	// One id short of exhaustion: stream A's request takes the last valid id,
	// so a second request right behind it is the one that trips the close.
	sync.mutex_lock(&c.mu)
	c.next_stream_id = 0x7fff_ffff
	sync.mutex_unlock(&c.mu)

	Waiter :: struct {
		c:       ^Client,
		err:     Client_Error,
		elapsed: time.Duration,
	}
	wait_for_a :: proc(w: ^Waiter) {
		started := time.now()
		_, w.err = client_request(
			w.c,
			Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
			4 * time.Second,
		)
		w.elapsed = time.diff(started, time.now())
	}
	w := Waiter{c = c}
	a := thread.create_and_start_with_poly_data(&w, wait_for_a)

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
	thread.destroy(a)
	testing.expect_value(t, w.err, Client_Error.Closed)
	testing.expect(
		t,
		w.elapsed < 2 * time.Second,
		"the pending request was not woken by the close and instead rode out its own deadline",
	)
	sync.atomic_store(&srv.stop, true)
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
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	Script :: struct {
		listener: net.TCP_Socket,
		done:     sync.Wait_Group,
		saw:      bool,
		code:     Error_Code,
	}
	run_script :: proc(s: ^Script) {
		defer sync.wait_group_done(&s.done)
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		defer net.close(client)
		preface: [len(PREFACE)]u8
		if !test_recv_full(client, preface[:]) {
			return
		}
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
	srv := Script{listener = listener}
	sync.wait_group_add(&srv.done, 1)
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		2 * time.Second,
	)
	testing.expect_value(t, err, Client_Error.Closed)

	sync.wait_group_wait(&srv.done)
	testing.expect(t, srv.saw, "the client did not GOAWAY an oversized frame")
	testing.expect_value(t, srv.code, Error_Code.Frame_Size_Error)
	free_all(context.temp_allocator)
}

@(test)
test_client_request_times_out_on_silence :: proc(t: ^testing.T) {
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	Script :: struct {
		listener: net.TCP_Socket,
		done:     sync.Wait_Group,
	}
	run_script :: proc(s: ^Script) {
		client, _, err := net.accept_tcp(s.listener)
		defer sync.wait_group_done(&s.done)
		if err != nil {
			return
		}
		defer net.close(client)
		preface: [len(PREFACE)]u8
		if !test_recv_full(client, preface[:]) {
			return
		}
		_, _ = test_wait_for_frame_type(client, .Headers)
		// And then say nothing at all.
		time.sleep(2 * time.Second)
	}
	srv := Script{listener = listener}
	sync.wait_group_add(&srv.done, 1)
	server_thread := thread.create_and_start_with_poly_data(&srv, run_script)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	started := time.now()
	_, err := client_request(
		c,
		Client_Request{method = "GET", scheme = "https", authority = "mock.invalid", path = "/dns-query"},
		200 * time.Millisecond,
	)
	elapsed := time.diff(started, time.now())
	testing.expect_value(t, err, Client_Error.Timeout)
	testing.expect(t, elapsed < time.Second, "the request took far longer than its own timeout")
	free_all(context.temp_allocator)
}

@(test)
test_client_reuses_connection_across_requests :: proc(t: ^testing.T) {
	listener, bound, lok := test_listen(t)
	if !lok {
		return
	}

	// Serves every connection the test dials, not just one: this checks that a
	// single Client issuing several sequential requests keeps reusing the same
	// stream-multiplexed connection rather than reconnecting.
	Counting_Server :: struct {
		listener: net.TCP_Socket,
		accepts:  int,
	}
	loop :: proc(s: ^Counting_Server) {
		client, _, err := net.accept_tcp(s.listener)
		if err != nil {
			return
		}
		s.accepts += 1
		tc := new(Test_Conn)
		tc.socket = client
		defer {
			net.close(client)
			free(tc)
		}
		io := IO{user = tc, read = test_io_read, write = test_io_write}
		hc := make_conn(io, echo_handler, nil)
		serve(hc)
		conn_wait_idle(hc)
		conn_unref(hc)
	}
	srv := Counting_Server{listener = listener}
	server_thread := thread.create_and_start_with_poly_data(&srv, loop)
	defer {
		thread.join(server_thread)
		thread.destroy(server_thread)
		net.close(listener)
	}

	c, ct, tc, cok := test_dial_client(t, bound)
	if !cok {
		return
	}
	defer {
		test_close_client(ct, tc)
		client_unref(c)
	}

	for i in 0 ..< 5 {
		body := []u8{u8(i)}
		resp, err := client_request(
			c,
			Client_Request{method = "POST", scheme = "https", authority = "mock.invalid", path = "/dns-query", body = body},
			2 * time.Second,
		)
		testing.expectf(t, err == .None, "request %d failed: %v", i, err)
		if err == .None {
			testing.expect_value(t, len(resp.body), 1)
			if len(resp.body) == 1 {
				testing.expect_value(t, resp.body[0], u8(i))
			}
			delete(resp.body)
		}
	}
	testing.expect_value(t, srv.accepts, 1)
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

@(private = "file")
hook_read_nothing :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	return 0, false
}

@(test)
test_data_frame_cannot_touch_an_abandoned_stream :: proc(t: ^testing.T) {
	/*
	A response arriving for a stream whose caller has just given up on it must
	not write through a pointer the reader thread picked up before it released
	the lock.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	hook := Client_Close_Hook{}
	c := client_make(IO{user = &hook, read = hook_read_nothing, write = retire_on_write}, allocator)
	hook.client = c
	hook.stream_id = 1

	// The stream `client_request` would have opened, without the blocking wait.
	s := new(Client_Stream, allocator)
	s.id = 1
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 8, allocator)
	c.streams[1] = s

	hook.armed = true
	payload := []u8{'o', 'k'}
	client_handle_data(c, Frame_Header{length = len(payload), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, payload)

	testing.expect(t, hook.fired, "the retire hook never ran, so nothing was reproduced")
	testing.expect(t, hook.retired != nil, "the stream was not retired")
	testing.expect(t, !hook.retired.done, "a retired stream was marked done after it was abandoned")

	_, back_in_map := c.streams[1]
	testing.expect(t, !back_in_map, "the retired stream was put back in the table")

	client_stream_destroy(c, hook.retired)
	client_unref(c)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "data after abandon: %d bytes leaked, allocated at %v", entry.size, entry.location)
	}
}

@(private = "file")
Client_Frame_Log :: struct {
	frames: [dynamic]Frame_Header,
}

@(private = "file")
client_log_write :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Client_Frame_Log)user
	if log == nil {
		return true
	}
	pos := 0
	// The preface is not a frame; skip it when it leads the buffer.
	if len(buf) >= len(PREFACE) && string(buf[:len(PREFACE)]) == PREFACE {
		pos = len(PREFACE)
	}
	for pos + FRAME_HEADER_SIZE <= len(buf) {
		h, ok := parse_frame_header(buf[pos:])
		if !ok {
			break
		}
		append(&log.frames, h)
		pos += FRAME_HEADER_SIZE + h.length
	}
	return true
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
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Client_Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := client_make(IO{user = &log, read = hook_read_nothing, write = client_log_write}, allocator)

	s := new(Client_Stream, allocator)
	s.id = 1
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 8, allocator)
	c.streams[1] = s

	clear(&log.frames)
	payload := make([]u8, CLIENT_MAX_BODY + 1, context.temp_allocator)
	client_handle_data(c, Frame_Header{length = len(payload), type = .Data, stream_id = 1}, payload)

	credited := false
	for f in log.frames {
		if f.type == .Window_Update && f.stream_id == 0 {
			credited = true
		}
	}
	testing.expect(t, credited, "the connection window was not replenished for a response that was refused")

	delete(log.frames)
	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_unref(c)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "oversized response credit: %d bytes leaked at %v", entry.size, entry.location)
	}
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
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Client_Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := client_make(IO{user = &log, read = hook_read_nothing, write = client_log_write}, allocator)

	s := new(Client_Stream, allocator)
	s.id = 1
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 8, allocator)
	c.streams[1] = s

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

	saw_goaway := false
	for f in log.frames {
		if f.type == .Goaway {
			saw_goaway = true
		}
	}
	testing.expect(t, saw_goaway, "no GOAWAY was sent for a flow-control violation")

	delete(log.frames)
	client_stream_destroy(c, s)
	delete_key(&c.streams, u32(1))
	client_unref(c)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "settings window overflow: %d bytes leaked at %v", entry.size, entry.location)
	}
}

@(private = "file")
write_nothing :: proc(user: rawptr, buf: []u8) -> bool {
	return true
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
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)
		allocator := mem.tracking_allocator(&track)

		client := client_make(IO{user = nil, read = hook_read_nothing, write = write_nothing}, allocator)

		s := new(Client_Stream, allocator)
		s.id = 1
		s.send_window = client.peer_initial_window
		s.body = make([dynamic]u8, 0, 8, allocator)
		client.streams[1] = s

		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", c.value)
		clear(&client.header_scratch)
		append(&client.header_scratch, ..block[:])

		testing.expectf(t, client_finish_headers(client, 1), "%s: the header block did not decode", c.what)
		testing.expectf(t, s.status == c.status, "%s: %q came back as status %d, expected %d", c.what, c.value, s.status, c.status)

		client_unref(client)
		free_all(context.temp_allocator)
		for _, entry in track.allocation_map {
			testing.expectf(t, false, "%s: %d bytes leaked at %v", c.what, entry.size, entry.location)
		}
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
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := client_make(IO{user = nil, read = hook_read_nothing, write = write_nothing}, allocator)
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

	client_unref(c)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes leaked at %v", entry.size, entry.location)
	}
}
