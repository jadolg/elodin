package upstream

import "base:runtime"
import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A race leg runs on a pool worker that lives as long as the process does, and
nothing outside `race_worker` resets that thread's scratch arena. The arena
chains a fresh block when the current one fills rather than reusing it, so a leg
that leaves its scratch behind costs the server a few kilobytes per query
forever. The test below drives real legs against a loopback responder and checks
the arena is back to empty after each one.
*/

@(private = "file")
Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
}

/*
Answer every query by echoing it back with the QR bit set.

That is all `response_matches` asks for — the ID, the QR bit and a question that
matches — and it keeps the responder free of an encoder of its own.
*/
@(private = "file")
mock_loop :: proc(m: ^Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil {
			// The receive timeout firing is how this loop notices `stop`.
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		buf[2] |= 0x80
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

// The arena behind `context.temp_allocator`, or nil if this thread was given
// something else and the measurement would be meaningless.
@(private = "file")
temp_arena :: proc() -> ^runtime.Arena {
	if context.temp_allocator.procedure != runtime.default_temp_allocator_proc {
		return nil
	}
	data := cast(^runtime.Default_Temp_Allocator)context.temp_allocator.data
	if data == nil {
		return nil
	}
	return &data.arena
}

@(test)
test_race_worker_releases_its_scratch :: proc(t: ^testing.T) {
	arena := temp_arena()
	if arena == nil {
		testing.expect(t, false, "this thread has no default temp allocator to measure")
		return
	}

	m := Mock{}
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return
	}
	m.socket = socket
	// Without this the responder would sit in recv_udp and never see `stop`.
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return
	}

	responder := thread.create_and_start_with_poly_data(&m, mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(socket)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr)
	if uerr != .None {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x2A2A,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc_err := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc_err == .None, "cannot encode the query: %v", enc_err)
	if enc_err != .None {
		return
	}

	LEGS :: 64

	// Laid out the way `resolve_race` lays it out, since `race_worker` releases
	// the state itself and expects to own all of this.
	st := new(Race_State)
	st.refs = 1
	st.last_err = .Timeout
	st.timeout = 2 * time.Second
	st.query = make([]u8, len(wire))
	copy(st.query, wire)
	st.jobs = make([]Race_Job, LEGS)

	// `wire` lives in the arena the legs are about to reset, and it has been
	// copied into `st.query` by now.
	free_all(context.temp_allocator)

	answered := 0
	for i in 0 ..< LEGS {
		st.jobs[i] = Race_Job {
			upstream = u,
			state    = st,
		}
		sync.mutex_lock(&st.mu)
		st.refs += 1
		st.outstanding += 1
		sync.mutex_unlock(&st.mu)

		race_worker(&st.jobs[i])

		// Both readings are taken before anything else runs: formatting a failure
		// message would itself allocate from the arena being measured.
		used := arena.total_used
		if st.response != nil {
			answered += 1
		}
		if used != 0 {
			testing.expectf(
				t,
				false,
				"leg %d left %d bytes in the temp arena; race_worker did not reset it",
				i,
				used,
			)
			break
		}
	}

	// Legs that allocate nothing would satisfy the check above without proving
	// anything, so confirm the responder was actually reached.
	testing.expect(t, answered > 0, "no leg ever got an answer, so nothing was measured")
	race_state_release(st)
}

/*
An HTTP responder that serves exactly one connection and then returns.

One connection is all any test here needs, and it keeps the mock free of the
accept timeouts and stop flags a long-running loop would want.
*/
@(private = "file")
Http_Mock :: struct {
	listener: net.TCP_Socket,
	reply:    string,
}

@(private = "file")
http_mock_once :: proc(m: ^Http_Mock) {
	client, _, err := net.accept_tcp(m.listener)
	if err != nil {
		return
	}
	defer net.close(client)
	// The requests under test are a few hundred bytes, so one read has all of it.
	buf: [4096]u8
	_, _ = net.recv_tcp(client, buf[:])
	_, _ = net.send_tcp(client, transmute([]u8)m.reply)
	// Closing here is what ends a reply with no length information, which is how
	// the truncated-body case below reaches its error path.
}

/*
Run one exchange against `reply` and hand back what the caller's allocator was
left holding.

`http_exchange` documents the body as the only thing the caller owns, so once
that is released a correct exchange has nothing outstanding.
*/
@(private = "file")
exchange_against :: proc(
	t: ^testing.T,
	reply: string,
	track: ^mem.Tracking_Allocator,
) -> (
	resp: Http_Response,
	err: Error,
	ok: bool,
) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return {}, .None, false
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return {}, .None, false
	}

	m := Http_Mock {
		listener = listener,
		reply    = reply,
	}
	server := thread.create_and_start_with_poly_data(&m, http_mock_once)
	defer {
		thread.join(server)
		thread.destroy(server)
		net.close(listener)
	}

	socket, derr := dial_tcp_timeout(bound, 2 * time.Second)
	if derr != .None {
		testing.expectf(t, false, "cannot dial the mock: %v", derr)
		return {}, .None, false
	}
	stream := Stream {
		socket = socket,
	}
	defer stream_close(&stream)

	resp, err = http_exchange(
		&stream,
		Http_Request{method = "GET", path = "/list.txt", host = "mock.invalid", accept = "text/plain"},
		mem.tracking_allocator(track),
	)
	return resp, err, true
}

@(private = "file")
expect_caller_holds_nothing :: proc(t: ^testing.T, track: ^mem.Tracking_Allocator, what: string) {
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%s: %d bytes still held, allocated at %v", what, entry.size, entry.location)
	}
}

@(test)
test_redirect_location_is_not_the_callers_to_free :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	// Two Location headers: a server repeating the field must not cost a string
	// per copy, and the first one is the one that counts.
	resp, err, ok := exchange_against(
		t,
		"HTTP/1.1 302 Found\r\nLocation: http://example.org/first\r\nLocation: http://example.org/second\r\nContent-Length: 0\r\n\r\n",
		&track,
	)
	if !ok {
		return
	}
	testing.expectf(t, err == .None, "exchange failed: %v", err)
	testing.expect_value(t, resp.status, 302)
	testing.expect_value(t, resp.location, "http://example.org/first")
	testing.expect(t, resp.body == nil, "a zero-length body should be nil")

	expect_caller_holds_nothing(t, &track, "redirect")
	free_all(context.temp_allocator)
}

@(test)
test_truncated_chunked_body_is_released :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	// One chunk, then the connection drops before the terminating zero chunk.
	resp, err, ok := exchange_against(
		t,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
		&track,
	)
	if !ok {
		return
	}
	testing.expect(t, err != .None, "a truncated chunked body was accepted")
	testing.expect(t, resp.body == nil, "a failed exchange returned a body")

	// The half-assembled body is the reader's to drop, not the caller's.
	expect_caller_holds_nothing(t, &track, "truncated chunked")
	free_all(context.temp_allocator)
}

/*
A responder that answers every query with one A record, so a bootstrap lookup
gets far enough to be cached.
*/
@(private = "file")
a_record_loop :: proc(m: ^Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		out := make([dynamic]u8, 0, n + 16, context.temp_allocator)
		append(&out, ..buf[:n])
		out[2] |= 0x80
		out[6], out[7] = 0, 1 // one answer
		// Owner name as a pointer back to the question at offset 12, then A/IN,
		// a TTL, and a four-byte address from TEST-NET-3.
		append(&out, 0xc0, 0x0c)
		append(&out, 0, 1, 0, 1)
		append(&out, 0, 0, 0, 60)
		append(&out, 0, 4)
		append(&out, 203, 0, 113, 7)
		_, _ = net.send_udp(m.socket, out[:], client)
		free_all(context.temp_allocator)
	}
}

/*
Refreshing an expired entry must not clone the hostname again.

A map assignment keeps the key the map already holds, so the second clone would
be orphaned the moment it was handed over — once per hostname per refresh, for
as long as the process runs.
*/
@(test)
test_bootstrap_refresh_does_not_orphan_its_key :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	// The cache clones its keys and builds its map from the ambient allocator.
	context.allocator = mem.tracking_allocator(&track)

	m := Mock{}
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return
	}

	responder := thread.create_and_start_with_poly_data(&m, a_record_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(socket)
	}

	HOST :: "mock.invalid"
	servers := []string{net.endpoint_to_string(bound, context.temp_allocator)}

	addr, ok := bootstrap_resolve(servers, HOST)
	testing.expect(t, ok, "the first lookup failed")
	testing.expect(t, addr != nil, "the first lookup returned no address")
	settled := len(track.allocation_map)

	// Expire the entry so the next call takes the refresh path rather than
	// returning the cached address.
	sync.mutex_lock(&bootstrap_cache.mu)
	entry := bootstrap_cache.entries[HOST]
	entry.expires = time.time_add(time.now(), -time.Minute)
	bootstrap_cache.entries[HOST] = entry
	sync.mutex_unlock(&bootstrap_cache.mu)

	addr2, ok2 := bootstrap_resolve(servers, HOST)
	testing.expect(t, ok2, "the refresh failed")
	testing.expect(t, addr2 != nil, "the refresh returned no address")

	testing.expectf(
		t,
		len(track.allocation_map) == settled,
		"the refresh added %d allocation(s); the hostname was cloned over a key the map already had",
		len(track.allocation_map) - settled,
	)
	testing.expect_value(t, len(bootstrap_cache.entries), 1)

	// The cache is a package global that outlives this test, and its keys point
	// into the tracking allocator that is about to go away.
	sync.mutex_lock(&bootstrap_cache.mu)
	for k in bootstrap_cache.entries {
		delete(k, context.allocator)
	}
	delete(bootstrap_cache.entries)
	bootstrap_cache.entries = nil
	sync.mutex_unlock(&bootstrap_cache.mu)

	free_all(context.temp_allocator)
}

/*
A chunk size too large to be an int must be refused, not narrowed.

`strconv.parse_u64_of_base` has no overflow check: it wraps and still reports
success, so a header of sixteen `F`s parses cleanly and turns negative on the
way into `int`. A negative count slips past the body-size guard, walks the
reader's position backwards and asks for a slice whose end precedes its start —
which a release build, compiled with bounds checks off, hands out.
*/
@(test)
test_chunk_size_too_large_is_refused :: proc(t: ^testing.T) {
	CASES :: []string {
		"FFFFFFFFFFFFFFFF\r\nxxxx\r\n0\r\n\r\n",
		"8000000000000000\r\nxxxx\r\n0\r\n\r\n",
		// Longer than 16 digits: the parser wraps round to a small value that
		// would otherwise be read as a plausible size.
		"10000000000000001\r\nxxxx\r\n0\r\n\r\n",
	}
	for body in CASES {
		r := Buf_Reader {
			buf = make([dynamic]u8, 0, 128, context.temp_allocator),
		}
		append(&r.buf, ..transmute([]u8)body)

		_, err := read_chunked(&r, context.temp_allocator)
		testing.expectf(t, err != .None, "%q was accepted as a chunk size", body)
		testing.expectf(t, r.pos >= 0, "%q left the reader at position %d", body, r.pos)
	}
	free_all(context.temp_allocator)
}

// A count that cannot be read cannot be satisfied, and must not be answered
// with a slice running backwards from the cursor.
@(test)
test_reader_exact_refuses_a_negative_count :: proc(t: ^testing.T) {
	r := Buf_Reader {
		buf = make([dynamic]u8, 0, 32, context.temp_allocator),
	}
	append(&r.buf, "abcdefgh")
	r.pos = 4

	_, err := reader_exact(&r, -1)
	testing.expect(t, err != .None, "a negative count was accepted")
	testing.expect_value(t, r.pos, 4)
	free_all(context.temp_allocator)
}
