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
		if err == .Timeout {
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
