package upstream

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:tlsx"

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

// The query echoed back with the QR bit set and one A record from TEST-NET-3.
@(private = "file")
a_record_reply :: proc(query: []u8) -> []u8 {
	out := make([dynamic]u8, 0, len(query) + 16, context.temp_allocator)
	append(&out, ..query)
	out[2] |= 0x80
	out[6], out[7] = 0, 1 // one answer
	// Owner name as a pointer back to the question at offset 12, then A/IN,
	// a TTL, and a four-byte address from TEST-NET-3.
	append(&out, 0xc0, 0x0c)
	append(&out, 0, 1, 0, 1)
	append(&out, 0, 0, 0, 60)
	append(&out, 0, 4)
	append(&out, 203, 0, 113, 7)
	return out[:]
}

/*
A header field costs a line, and a line is all the header scan used to count.
The 64 KB cap in `reader_line` bounds one line, not how many of them arrive, so
a list host answering with field after short field kept the parser reading for
as long as it cared to send. Nothing here is the caller's memory, but the work
is ours, and a response that needs more than a hundred fields to be understood
is not one worth waiting for.

Trailers are the same loop by another name, so the chunked reader is held to the
same count.
*/
@(private = "file")
many_field_reply :: proc(count: int, trailers: bool) -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\n")
	if trailers {
		strings.write_string(&b, "Transfer-Encoding: chunked\r\n")
	} else {
		strings.write_string(&b, "Content-Length: 0\r\n")
	}
	if !trailers {
		for i in 0 ..< count {
			fmt.sbprintf(&b, "X-Pad-%d: v\r\n", i)
		}
	}
	strings.write_string(&b, "\r\n")
	if trailers {
		strings.write_string(&b, "0\r\n")
		for i in 0 ..< count {
			fmt.sbprintf(&b, "X-Trailer-%d: v\r\n", i)
		}
		strings.write_string(&b, "\r\n")
	}
	return strings.to_string(b)
}

@(test)
test_header_count_is_capped :: proc(t: ^testing.T) {
	Case :: struct {
		count:    int,
		trailers: bool,
		refused:  bool,
		what:     string,
	}
	CASES := []Case {
		{MAX_HTTP_HEADERS - 1, false, false, "headers under the cap"},
		{MAX_HTTP_HEADERS + 1, false, true, "headers over the cap"},
		{MAX_HTTP_HEADERS - 1, true, false, "trailers under the cap"},
		{MAX_HTTP_HEADERS + 1, true, true, "trailers over the cap"},
	}

	for c in CASES {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)

		resp, err, ok := exchange_against(t, many_field_reply(c.count, c.trailers), &track)
		if !ok {
			return
		}
		if c.refused {
			testing.expectf(t, err == .HTTP_Error, "%s: accepted with %v", c.what, err)
			testing.expectf(t, resp.body == nil, "%s: a refused exchange returned a body", c.what)
		} else {
			testing.expectf(t, err == .None, "%s: refused with %v", c.what, err)
		}

		if resp.body != nil {
			delete(resp.body, mem.tracking_allocator(&track))
		}
		expect_caller_holds_nothing(t, &track, c.what)
		free_all(context.temp_allocator)
	}
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
		_, _ = net.send_udp(m.socket, a_record_reply(buf[:n]), client)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
Spoof_Mock :: struct {
	socket:  net.UDP_Socket, // the address the query is sent to
	spoofer: net.UDP_Socket, // an unrelated port the answer arrives from
	stop:    bool,
}

// Answer from a port the resolver never asked, as an off-path forgery would.
@(private = "file")
spoof_loop :: proc(m: ^Spoof_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		_, _ = net.send_udp(m.spoofer, a_record_reply(buf[:n]), client)
		free_all(context.temp_allocator)
	}
}

// Answer with the right ID over a question that was never asked.
@(private = "file")
wrong_question_loop :: proc(m: ^Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n <= dns.HEADER_SIZE + 1 {
			continue
		}
		reply := a_record_reply(buf[:n])
		// First byte of the first label of the question, so the name differs
		// while the ID and the QR bit stay agreeable.
		reply[dns.HEADER_SIZE + 1] = 'x'
		_, _ = net.send_udp(m.socket, reply, client)
		free_all(context.temp_allocator)
	}
}

/*
Bind a loopback UDP socket and report the endpoint it landed on.
*/
@(private = "file")
bind_loopback_udp :: proc(t: ^testing.T) -> (socket: net.UDP_Socket, endpoint: net.Endpoint, ok: bool) {
	sock, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return {}, {}, false
	}
	bound, berr := net.bound_endpoint(sock)
	if berr != nil {
		net.close(sock)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return {}, {}, false
	}
	return sock, bound, true
}

/*
A bootstrap answer has to come from the server that was asked.

The 16-bit ID is all an off-path attacker has to guess, and the entry it lands in
is cached for an hour and used to resolve blocklist hosts as well as upstreams.
*/
@(test)
test_bootstrap_ignores_a_reply_from_another_port :: proc(t: ^testing.T) {
	m := Spoof_Mock{}
	server, bound, ok := bind_loopback_udp(t)
	if !ok {
		return
	}
	spoofer, _, spoof_ok := bind_loopback_udp(t)
	if !spoof_ok {
		net.close(server)
		return
	}
	m.socket, m.spoofer = server, spoofer
	set_socket_timeouts(server, 50 * time.Millisecond)

	responder := thread.create_and_start_with_poly_data(&m, spoof_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(server)
		net.close(spoofer)
	}

	addr, found := bootstrap_query(
		net.endpoint_to_string(bound, context.temp_allocator),
		"mock.invalid",
		.A,
		200 * time.Millisecond,
	)
	testing.expect(t, !found, "an answer from a port we never asked was accepted")
	testing.expect(t, addr == nil, "a rejected answer still produced an address")
	free_all(context.temp_allocator)
}

// The question has to be echoed back too, as it is on the main exchange path.
@(test)
test_bootstrap_ignores_a_reply_to_another_question :: proc(t: ^testing.T) {
	m := Mock{}
	server, bound, ok := bind_loopback_udp(t)
	if !ok {
		return
	}
	m.socket = server
	set_socket_timeouts(server, 50 * time.Millisecond)

	responder := thread.create_and_start_with_poly_data(&m, wrong_question_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(server)
	}

	addr, found := bootstrap_query(
		net.endpoint_to_string(bound, context.temp_allocator),
		"mock.invalid",
		.A,
		200 * time.Millisecond,
	)
	testing.expect(t, !found, "an answer to a question we never asked was accepted")
	testing.expect(t, addr == nil, "a rejected answer still produced an address")
	free_all(context.temp_allocator)
}

// The honest responder is still accepted, so the checks above are not simply
// refusing everything.
@(test)
test_bootstrap_accepts_the_server_it_asked :: proc(t: ^testing.T) {
	m := Mock{}
	server, bound, ok := bind_loopback_udp(t)
	if !ok {
		return
	}
	m.socket = server
	set_socket_timeouts(server, 50 * time.Millisecond)

	responder := thread.create_and_start_with_poly_data(&m, a_record_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(server)
	}

	addr, found := bootstrap_query(
		net.endpoint_to_string(bound, context.temp_allocator),
		"mock.invalid",
		.A,
		200 * time.Millisecond,
	)
	testing.expect(t, found, "the honest responder's answer was refused")
	testing.expect_value(t, addr, net.Address(net.IP4_Address{203, 0, 113, 7}))
	free_all(context.temp_allocator)
}

@(private = "file")
ID_TRIALS :: 32

@(private = "file")
Id_Mock :: struct {
	socket: net.UDP_Socket,
	// Written by the responder thread, read by the test once every query it
	// makes has been answered.
	ids:    [ID_TRIALS]u16,
	count:  int,
	stop:   bool,
}

// Record the transaction ID of every query, then answer it as an honest server
// would so the caller moves on to the next one.
@(private = "file")
id_recording_loop :: proc(m: ^Id_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		if seen := sync.atomic_load(&m.count); seen < len(m.ids) {
			m.ids[seen] = u16(buf[0]) << 8 | u16(buf[1])
			sync.atomic_store(&m.count, seen + 1)
		}
		_, _ = net.send_udp(m.socket, a_record_reply(buf[:n]), client)
		free_all(context.temp_allocator)
	}
}

/*
The transaction ID on a bootstrap query has to be drawn, not read off the clock.

The two tests above are the rest of what guards this path: the reply has to come
from the server that was asked and answer the question that was sent. That
leaves elodin's ephemeral source port and these sixteen bits as the whole of
what an off-path attacker has to guess, and a forged reply that gets past them
sets the address of the upstream itself — cached for BOOTSTRAP_TTL, consulted
for blocklist hosts as well, so one landed guess redirects every later query
rather than poisoning a single name.

An ID taken from the low bits of a nanosecond timestamp is not sixteen bits of
anything. It is a function of when the query went out, and bootstrap queries go
out at moments an attacker can watch for or cause: process start, a reload, an
upstream that just stopped answering.

So the check is against the clock rather than against randomness in the
abstract, which a test cannot establish anyway. Note the time immediately before
each query and see where the ID the responder receives sits relative to it.
Derived from the clock it lands a microsecond or two past that reading every
time; drawn, it lands in a window that size only as often as chance puts it
there.
*/
@(test)
test_bootstrap_query_id_does_not_follow_the_clock :: proc(t: ^testing.T) {
	TRIALS :: ID_TRIALS
	/*
	Nanoseconds between the reading below and the point the ID is chosen inside
	`bootstrap_query` — a port split, an address parse and a name
	canonicalisation, on the order of a microsecond. Wide enough that a thread
	descheduled in the middle still counts, narrow enough that a drawn ID misses
	it most of the time.
	*/
	WINDOW :: 20_000
	/*
	Chance puts a drawn ID inside that window WINDOW/65536 of the time, so about
	ten of the thirty-two land there with a spread under three; twenty-four is
	five deviations out. A clock-derived one lands there in every trial it is
	not descheduled out of.
	*/
	MAX_IN_WINDOW :: 24

	m := Id_Mock{}
	server, bound, ok := bind_loopback_udp(t)
	if !ok {
		return
	}
	m.socket = server
	set_socket_timeouts(server, 50 * time.Millisecond)

	responder := thread.create_and_start_with_poly_data(&m, id_recording_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(server)
	}

	// Not from the temp allocator, which the loop below resets between trials so
	// that 32 receive buffers are not held at once.
	address := net.endpoint_to_string(bound, context.allocator)
	defer delete(address)

	sent_at: [TRIALS]i64
	for i in 0 ..< TRIALS {
		sent_at[i] = time.now()._nsec
		addr, found := bootstrap_query(address, "mock.invalid", .A, 200 * time.Millisecond)
		free_all(context.temp_allocator)
		if !found || addr == nil {
			testing.expectf(t, false, "trial %d: the honest responder's answer was refused", i)
			return
		}
	}

	seen := sync.atomic_load(&m.count)
	if seen != TRIALS {
		testing.expectf(t, false, "the responder saw %d queries, expected %d", seen, TRIALS)
		return
	}

	in_window := 0
	ids_seen: map[u16]bool
	defer delete(ids_seen)
	for i in 0 ..< TRIALS {
		id := m.ids[i]
		ids_seen[id] = true
		// Where the ID sits after the low sixteen bits of the send time, going
		// forwards and wrapping, which is what the elapsed nanoseconds would be
		// if the clock were where it came from.
		if (u32(id) + 65536 - u32(u16(sent_at[i]))) % 65536 < WINDOW {
			in_window += 1
		}
	}

	testing.expectf(
		t,
		in_window <= MAX_IN_WINDOW,
		"%d of %d bootstrap ids landed within %d ns after the send time; the id is coming from the clock",
		in_window,
		TRIALS,
		WINDOW,
	)
	// A constant ID, or one that only moves every few milliseconds, would also
	// sit inside that window - but so does a chance handful, so distinctness is
	// what tells the two apart.
	testing.expectf(
		t,
		len(ids_seen) >= TRIALS - 1,
		"only %d distinct ids in %d bootstrap queries",
		len(ids_seen),
		TRIALS,
	)
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
reader's position backwards and asks for a slice whose end precedes its start.
The release build's bounds checks would now stop that, by killing the process a
peer can reach; refusing the size is how it stays an error instead.
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

/*
`reader_line`'s 64 KB guard must measure the unconsumed remainder, not the
whole buffer. `Buf_Reader` never compacts, so once a body has pushed `r.buf`
past 64 KB, every consumed byte stays counted against the guard forever - the
next line that needs a fresh socket read would be refused even with nothing
outstanding to read.

`r.buf` is primed here to simulate exactly that: a chunk body already consumed
past 64 KB, with the cursor at the end of it, as `read_chunked` leaves things
right after a chunk's trailing CRLF. The terminal "0\r\n\r\n" line is still on
the wire, so answering it requires `reader_fill` to run - which the old guard
never gave a chance to.
*/
@(test)
test_reader_line_guard_measures_the_remainder :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return
	}

	m := Http_Mock {
		listener = listener,
		reply    = "0\r\n\r\n",
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
		return
	}
	set_socket_timeouts(socket, 2 * time.Second)
	stream := Stream {
		socket = socket,
	}
	defer stream_close(&stream)
	// The mock reads a request before it answers.
	stream_write(&stream, []u8{'\n'})

	r := Buf_Reader {
		stream = &stream,
		buf    = make([dynamic]u8, 0, 70_000, context.temp_allocator),
	}
	// Stand in for a chunk body already consumed past the 64 KB mark, cursor
	// at the end of it - nothing unconsumed, everything still counted by a
	// guard that looks at len(r.buf) alone.
	append(&r.buf, ..make([]u8, 70_000, context.temp_allocator))
	r.pos = len(r.buf)

	line, err := reader_line(&r)
	testing.expectf(t, err == .None, "the terminal chunk line was refused: %v", err)
	testing.expect_value(t, line, "0")
	free_all(context.temp_allocator)
}

/*
A response with no framing information ends when the connection does, and that
reader was the one path of four with no size limit on it: the header scan stops
at 64 KB, and chunked and Content-Length both check MAX_HTTP_BODY. This one read
until the peer stopped sending, so a list host that never sent a length decided
for itself how much memory to take.

Driven with a small limit rather than through `http_exchange`, so the bound is
exercised without moving 64 MB across the loopback on every run.
*/
@(test)
test_unframed_body_stops_at_the_limit :: proc(t: ^testing.T) {
	LIMIT :: 4096

	Case :: struct {
		body_len: int,
		refused:  bool,
		what:     string,
	}
	CASES := []Case{{LIMIT / 2, false, "under the limit"}, {LIMIT * 8, true, "over the limit"}}

	for c in CASES {
		listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
		if lerr != nil {
			testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
			return
		}
		bound, berr := net.bound_endpoint(listener)
		if berr != nil {
			net.close(listener)
			testing.expectf(t, false, "cannot read the mock's port: %v", berr)
			return
		}

		payload := make([]u8, c.body_len, context.temp_allocator)
		for i in 0 ..< len(payload) {
			payload[i] = 'x'
		}
		m := Http_Mock {
			listener = listener,
			reply    = string(payload),
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
			return
		}
		set_socket_timeouts(socket, 2 * time.Second)
		stream := Stream {
			socket = socket,
		}
		defer stream_close(&stream)
		// The mock reads a request before it answers.
		stream_write(&stream, []u8{'\n'})

		r := Buf_Reader {
			stream = &stream,
			buf    = make([dynamic]u8, 0, 256, context.temp_allocator),
		}
		data, err := reader_to_end(&r, LIMIT)
		if c.refused {
			testing.expectf(t, err != .None, "a body %s was read to the end anyway", c.what)
			testing.expectf(t, len(data) == 0, "a refused body still handed back %d bytes", len(data))
		} else {
			testing.expectf(t, err == .None, "a body %s failed: %v", c.what, err)
			testing.expectf(t, len(data) == c.body_len, "a body %s came back as %d bytes", c.what, len(data))
		}
	}
	free_all(context.temp_allocator)
}

/*
A Content-Length that is not a length must not fall through to the one reader
with no length to work with.

`-1` parses, so it slipped past both the `== 0` and the `> 0` case and landed on
the read-to-end path - the single framing path where a body was never bounded.
The `> MAX_HTTP_BODY` check that guards the ordinary case sits inside the branch
it never reached.
*/
@(test)
test_content_length_out_of_range_is_refused :: proc(t: ^testing.T) {
	CASES :: []string {
		"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nhello",
		"HTTP/1.1 200 OK\r\nContent-Length: -9999999\r\n\r\nhello",
	}
	for reply in CASES {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)

		resp, err, ok := exchange_against(t, reply, &track)
		if !ok {
			return
		}
		testing.expectf(t, err != .None, "%q was accepted, with a %d byte body", reply, len(resp.body))
		if resp.body != nil {
			delete(resp.body, mem.tracking_allocator(&track))
		}
		expect_caller_holds_nothing(t, &track, "negative content-length")
		free_all(context.temp_allocator)
	}
}

/*
The response side of the same field, held to the same grammar.

`Content-Length` is `1*DIGIT` (RFC 9110 8.6) and the status code is exactly
three of them (RFC 9112 4). `strconv.parse_int` with its default base reads a
good deal more: a prefix picks the base, so `0x10` is 16; `_` between digits is
skipped; a sign is allowed; and the accumulator wraps in silence, so a value
past 64 bits comes back as something small enough to pass the range check that
follows it.

What reaches this parser is a blocklist server's reply or a DoH upstream's, over
a connection this client keeps alive and reuses. A length it reads differently
from the peer that sent it leaves the reader standing in the middle of a body,
and the next response read off that connection starts from wherever that landed.
The server-side half of this is in `server/doh.odin`, where it is a smuggling
primitive rather than a desync with oneself.
*/
@(test)
test_response_framing_fields_are_strict_decimal :: proc(t: ^testing.T) {
	Case :: struct {
		reply:    string,
		accepted: bool,
		what:     string,
	}

	CASES := []Case {
		{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", true, "a plain decimal length"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\nhello", false, "a hexadecimal length"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 0b101\r\n\r\nhello", false, "a binary length"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\nhelloworld", false, "a digit separator in the length"},
		{"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello", false, "a signed length"},
		// 2^64 + 5: the accumulator wraps to 5, and 5 is a fine length.
		{"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551621\r\n\r\nhello", false, "a length past 64 bits"},
		{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello", false, "conflicting lengths"},
		{"HTTP/1.1 0x1 OK\r\nContent-Length: 0\r\n\r\n", false, "a hexadecimal status"},
		{"HTTP/1.1 1_0 OK\r\nContent-Length: 0\r\n\r\n", false, "a digit separator in the status"},
		{"HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n", false, "a four-digit status"},
	}

	for c in CASES {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)

		resp, err, ok := exchange_against(t, c.reply, &track)
		if !ok {
			return
		}
		if c.accepted {
			testing.expectf(t, err == .None, "%s was refused: %v", c.what, err)
			testing.expectf(t, string(resp.body) == "hello", "%s: body came back as %q", c.what, string(resp.body))
		} else {
			testing.expectf(t, err != .None, "%s was accepted, with a %d byte body", c.what, len(resp.body))
		}
		if resp.body != nil {
			delete(resp.body, mem.tracking_allocator(&track))
		}
		expect_caller_holds_nothing(t, &track, c.what)
		free_all(context.temp_allocator)
	}
}

/*
An answer as large as the query said it could be must arrive whole.

`recv_udp` fills the buffer it is given and drops the rest of the datagram
without saying so, so a buffer smaller than what the query advertised turns a
perfectly good answer into a prefix of one — with the header and question still
intact, so nothing downstream notices.
*/

@(private = "file")
Big_Mock :: struct {
	socket: net.UDP_Socket,
	size:   int,
	stop:   bool,
}

// Echoes the query with QR set, padded out to `size` bytes.
//
// The padding is not a well-formed record section, which does not matter here:
// what is under test is how many of the bytes on the wire survive the receive,
// and `response_matches` only reads the header and the question.
@(private = "file")
big_reply_loop :: proc(m: ^Big_Mock) {
	buf: [4096]u8
	out := make([]u8, m.size)
	defer delete(out)
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil {
			continue
		}
		if n < dns.HEADER_SIZE || n > m.size {
			continue
		}
		copy(out, buf[:n])
		for i in n ..< m.size {
			out[i] = 0xAA
		}
		out[2] |= 0x80
		_, _ = net.send_udp(m.socket, out, client)
	}
}

@(test)
test_udp_answer_up_to_the_advertised_size_is_not_truncated :: proc(t: ^testing.T) {
	ADVERTISED :: 8192
	REPLY :: 6000

	m := Big_Mock {
		size = REPLY,
	}
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

	responder := thread.create_and_start_with_poly_data(&m, big_reply_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(socket)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		2 * time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr)
	if uerr != .None {
		return
	}
	defer destroy(u)

	// The OPT record is the whole point: it is what tells the upstream how much
	// room there is, and therefore how much has to be read back.
	query := dns.Message {
		id         = 0x2A2A,
		question   = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(ADVERTISED, false)},
	}
	query.flags.rd = true
	wire, _, enc_err := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc_err == .None, "cannot encode the query: %v", enc_err)
	if enc_err != .None {
		return
	}

	resp, xerr := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, xerr == .None, "the exchange failed: %v", xerr)
	testing.expectf(
		t,
		len(resp) == REPLY,
		"the answer came back %d bytes of %d; the rest of the datagram was dropped",
		len(resp),
		REPLY,
	)
	free_all(context.temp_allocator)
}

/*
An upstream that ignores the advertised size is retried over TCP.

Sizing the buffer correctly only settles what a well-behaved responder sends.
One that overruns the room it was given leaves a prefix of an answer in the
buffer with its header and question intact, which is the shape most likely to
be mistaken for a whole one — so it has to be recognised and asked again on a
transport with no such limit, the same way the TC bit is handled.
*/

@(private = "file")
Overrun_Mock :: struct {
	udp:      net.UDP_Socket,
	listener: net.TCP_Socket,
	size:     int,
	stop:     bool,
}

@(private = "file")
overrun_udp_loop :: proc(m: ^Overrun_Mock) {
	buf: [4096]u8
	out := make([]u8, m.size)
	defer delete(out)
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.udp, buf[:])
		if err != nil {
			continue
		}
		if n < dns.HEADER_SIZE || n > m.size {
			continue
		}
		copy(out, buf[:n])
		for i in n ..< m.size {
			out[i] = 0xAA
		}
		out[2] |= 0x80
		_, _ = net.send_udp(m.udp, out, client)
	}
}

// Serves one framed answer and returns; one retry is all this needs.
@(private = "file")
overrun_tcp_once :: proc(m: ^Overrun_Mock) {
	client, _, err := net.accept_tcp(m.listener)
	if err != nil {
		return
	}
	defer net.close(client)

	length: [2]u8
	if read_full_tcp(client, length[:]) != .None {
		return
	}
	n := int(length[0]) << 8 | int(length[1])
	if n < dns.HEADER_SIZE || n > m.size {
		return
	}
	query := make([]u8, n, context.temp_allocator)
	if read_full_tcp(client, query) != .None {
		return
	}

	out := make([]u8, 2 + m.size, context.temp_allocator)
	out[0] = u8(m.size >> 8)
	out[1] = u8(m.size)
	copy(out[2:], query)
	for i in 2 + n ..< len(out) {
		out[i] = 0xAA
	}
	out[4] |= 0x80
	_ = write_all_tcp(client, out)
}

@(test)
test_udp_answer_over_the_advertised_size_falls_back_to_tcp :: proc(t: ^testing.T) {
	ADVERTISED :: 1232
	REPLY :: 3000

	// The TCP listener binds first so the UDP socket can take the same port
	// number; the two live in separate namespaces.
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	// So the accept below gives up on its own if the retry never comes, rather
	// than turning a regression into a hung test.
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)
	udp, uerr2 := net.make_bound_udp_socket(net.IP4_Loopback, bound.port)
	if uerr2 != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot bind udp/%d: %v", bound.port, uerr2)
		return
	}
	set_socket_timeouts(udp, 50 * time.Millisecond)

	m := Overrun_Mock {
		udp      = udp,
		listener = listener,
		size     = REPLY,
	}
	udp_thread := thread.create_and_start_with_poly_data(&m, overrun_udp_loop)
	tcp_thread := thread.create_and_start_with_poly_data(&m, overrun_tcp_once)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(udp_thread)
		thread.destroy(udp_thread)
		thread.join(tcp_thread)
		thread.destroy(tcp_thread)
		net.close(udp)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		2 * time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr)
	if uerr != .None {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id         = 0x2A2A,
		question   = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(ADVERTISED, false)},
	}
	query.flags.rd = true
	wire, _, enc_err := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc_err == .None, "cannot encode the query: %v", enc_err)
	if enc_err != .None {
		return
	}

	resp, xerr := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, xerr == .None, "the exchange failed: %v", xerr)
	testing.expectf(
		t,
		len(resp) == REPLY,
		"got %d bytes of %d; the overrun was not retried on a transport that could carry it",
		len(resp),
		REPLY,
	)
	free_all(context.temp_allocator)
}

/*
A DoT upstream whose handshake is killed by the peer gets one more try.

Some resolvers - Quad9, from some networks - reset a noticeable share of
connections partway through the TLS handshake while the very next attempt
succeeds. That is indistinguishable from a healthy server as far as the answers
go, but three of those in a row park the upstream for the failure cooldown and
push every query onto the fallback. So a handshake that died at the transport
level is retried once on a fresh connection, the same way a pooled connection
found dead is not counted against the server.

The mock resets its first connection and serves the second, so the query only
comes back if the retry happened.
*/

/*
Package-private rather than file-private: `padding_test.odin` stands up a DoT
mock of its own and there is one key generation to share between them.
*/
@(private)
DOT_CERT_DIR :: "/tmp/elodin-upstream-test"

@(private)
dot_cert_once: sync.Once
@(private)
dot_cert_path: string
@(private)
dot_key_path: string
@(private)
dot_cert_ok: bool

// Generated into the system temp directory and left there, so only the first
// run of the suite pays for key generation. `certs/` is used when a developer
// already has one; CI never does.
@(private)
generate_dot_certs :: proc() {
	if os.exists("certs/cert.pem") && os.exists("certs/key.pem") {
		dot_cert_path, dot_key_path, dot_cert_ok = "certs/cert.pem", "certs/key.pem", true
		return
	}

	dot_cert_path = DOT_CERT_DIR + "/cert.pem"
	dot_key_path = DOT_CERT_DIR + "/key.pem"
	if os.exists(dot_cert_path) && os.exists(dot_key_path) {
		dot_cert_ok = true
		return
	}
	if !os.exists(DOT_CERT_DIR) {
		if err := os.make_directory(DOT_CERT_DIR); err != nil {
			return
		}
	}

	process, perr := os.process_start(
		os.Process_Desc {
			command = []string {
				"openssl",
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				dot_key_path,
				"-out",
				dot_cert_path,
				"-days",
				"2",
				"-subj",
				"/CN=elodin.local",
				"-addext",
				"subjectAltName=DNS:elodin.local,DNS:localhost,IP:127.0.0.1",
			},
		},
	)
	if perr != nil {
		return
	}
	state, werr := os.process_wait(process)
	if werr != nil || state.exit_code != 0 {
		return
	}
	dot_cert_ok = true
}

@(private = "file")
Dot_Reset_Mock :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	resets:   int,
	served:   int,
}

@(private = "file")
dot_reset_once :: proc(m: ^Dot_Reset_Mock) {
	/*
	Hang up on the first caller hard.

	SO_LINGER with a zero timeout makes close() send a RST instead of a FIN,
	which is what the handshake being cut off looks like on the wire. A FIN
	would not do: OpenSSL has a protocol error of its own for that.
	*/
	first, _, ferr := net.accept_tcp(m.listener)
	if ferr != nil {
		return
	}
	lg := posix.linger {
		l_onoff  = 1,
		l_linger = 0,
	}
	posix.setsockopt(posix.FD(first), posix.SOL_SOCKET, .LINGER, &lg, posix.socklen_t(size_of(lg)))
	net.close(first)
	sync.atomic_add(&m.resets, 1)

	// The retry, answered properly.
	second, _, serr := net.accept_tcp(m.listener)
	if serr != nil {
		return
	}
	_ = net.set_option(second, .Receive_Timeout, 3 * time.Second)
	_ = net.set_option(second, .Send_Timeout, 3 * time.Second)
	conn, terr := tlsx.server_accept(m.ctx, second)
	if terr != .None {
		net.close(second)
		return
	}
	defer tlsx.close(conn)

	length: [2]u8
	if tlsx.read_full(conn, length[:]) != .None {
		return
	}
	n := int(length[0]) << 8 | int(length[1])
	if n < dns.HEADER_SIZE || n > 1024 {
		return
	}
	// Echoed back with the QR bit set, which is all `response_matches` asks for.
	buf: [2 + 1024]u8
	if tlsx.read_full(conn, buf[2:][:n]) != .None {
		return
	}
	buf[0], buf[1] = length[0], length[1]
	buf[4] |= 0x80
	if _, werr := tlsx.write(conn, buf[:2 + n]); werr != .None {
		return
	}
	sync.atomic_add(&m.served, 1)
}

@(test)
test_dot_handshake_reset_by_the_peer_is_retried :: proc(t: ^testing.T) {
	// The reset arrives while OpenSSL still has handshake bytes to push, so the
	// write that follows raises SIGPIPE. The server ignores it (see main.odin);
	// the test runner does not.
	posix.sigignore(.SIGPIPE)

	sync.once_do(&dot_cert_once, generate_dot_certs)
	if !dot_cert_ok {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	// So a missing retry ends the accept below rather than hanging the suite.
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	sctx, serr := tlsx.server_context(dot_cert_path, dot_key_path)
	if serr != .None {
		testing.expectf(t, false, "server_context: %v", serr)
		return
	}
	defer tlsx.context_destroy(sctx)

	m := Dot_Reset_Mock {
		listener = listener,
		ctx      = sctx,
	}
	mock_thread := thread.create_and_start_with_poly_data(&m, dot_reset_once)
	defer {
		thread.join(mock_thread)
		thread.destroy(mock_thread)
	}

	u, uerr := make_upstream(
		// Unverified: the mock's certificate is self-signed, and what is under
		// test is the retry rather than the trust decision.
		config.Upstream_Spec{name = "mock", kind = .TLS, address = "127.0.0.1", port = bound.port},
		0,
		2 * time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr)
	if uerr != .None {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x5151,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc_err := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc_err == .None, "cannot encode the query: %v", enc_err)
	if enc_err != .None {
		return
	}

	resp, xerr := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, xerr == .None, "the exchange failed: %v", xerr)
	testing.expect_value(t, sync.atomic_load(&m.resets), 1)
	testing.expectf(t, len(resp) == len(wire), "got %d bytes back, expected %d", len(resp), len(wire))
	free_all(context.temp_allocator)
}

@(private = "file")
Tls_Reset_Mock :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	resets:   int,
	accepted: int,
}

// The same hard hang-up as `dot_reset_once`, but the second connection is only
// handshaken: `open_stream` hands back a stream and leaves the protocol on it to
// its caller, so there is nothing else to answer here.
@(private = "file")
tls_reset_once :: proc(m: ^Tls_Reset_Mock) {
	first, _, ferr := net.accept_tcp(m.listener)
	if ferr != nil {
		return
	}
	lg := posix.linger {
		l_onoff  = 1,
		l_linger = 0,
	}
	posix.setsockopt(posix.FD(first), posix.SOL_SOCKET, .LINGER, &lg, posix.socklen_t(size_of(lg)))
	net.close(first)
	sync.atomic_add(&m.resets, 1)

	second, _, serr := net.accept_tcp(m.listener)
	if serr != nil {
		return
	}
	_ = net.set_option(second, .Receive_Timeout, 3 * time.Second)
	_ = net.set_option(second, .Send_Timeout, 3 * time.Second)
	conn, terr := tlsx.server_accept(m.ctx, second)
	if terr != .None {
		net.close(second)
		return
	}
	sync.atomic_add(&m.accepted, 1)
	tlsx.close(conn)
}

/*
The DoH side of the same reset.

`open_stream` carries every HTTPS upstream - HTTP/1.1, HTTP/2 and the bootstrap
resolver - and reaches the same resolvers over the same networks, so a handshake
the peer killed is worth exactly the retry the DoT path gets.
*/
@(test)
test_https_handshake_reset_by_the_peer_is_retried :: proc(t: ^testing.T) {
	posix.sigignore(.SIGPIPE)

	sync.once_do(&dot_cert_once, generate_dot_certs)
	if !dot_cert_ok {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	sctx, serr := tlsx.server_context(dot_cert_path, dot_key_path)
	if serr != .None {
		testing.expectf(t, false, "server_context: %v", serr)
		return
	}
	defer tlsx.context_destroy(sctx)

	cctx, cerr := tlsx.client_context(false)
	if cerr != .None {
		testing.expectf(t, false, "client_context: %v", cerr)
		return
	}
	defer tlsx.context_destroy(cctx)

	m := Tls_Reset_Mock {
		listener = listener,
		ctx      = sctx,
	}
	mock_thread := thread.create_and_start_with_poly_data(&m, tls_reset_once)
	defer thread.destroy(mock_thread)

	stream, oerr := open_stream(bound, cctx, "", 2 * time.Second)
	testing.expectf(t, oerr == .None, "open_stream failed: %v", oerr)
	if oerr == .None {
		testing.expect(t, stream.tls != nil, "the stream came back without a TLS session")
		stream_close(&stream)
	}

	// Under TLS 1.3 the client is done once it has sent its Finished, so the
	// mock may still be inside `server_accept` at this point. What it counted is
	// only worth reading once it has stopped counting.
	thread.join(mock_thread)
	testing.expect_value(t, sync.atomic_load(&m.resets), 1)
	testing.expect_value(t, sync.atomic_load(&m.accepted), 1)
	free_all(context.temp_allocator)
}

/*
A redirect may not drop the TLS the operator asked for, nor move a fetch that
started on the public internet onto an address only this machine can reach.

`split_http_url` restricting the scheme to http or https was the only filter on
a redirect target, so `Location: http://…` silently undid the transport the
operator configured - and blocklists decide what gets *blocked*, so the
interesting tampering is removal, which produces no visible failure.
*/
@(test)
test_address_is_public_classifies_reserved_ranges :: proc(t: ^testing.T) {
	Case :: struct {
		text:   string,
		public: bool,
	}
	CASES := []Case {
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"0.0.0.0", false},
		{"10.1.2.3", false},
		{"127.0.0.1", false},
		{"100.64.0.1", false},
		// The address a cloud metadata service answers on.
		{"169.254.169.254", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		// Just outside the private range, and ordinary public space.
		{"172.32.0.1", true},
		{"192.168.1.1", false},
		{"224.0.0.1", false},
		{"2606:4700:4700::1111", true},
		{"::1", false},
		{"fe80::1", false},
		{"fd00::1", false},
		{"ff02::1", false},
		// Reserved ranges spelled as IPv4-mapped IPv6 are still reserved.
		{"::ffff:127.0.0.1", false},
		{"::ffff:8.8.8.8", true},
	}
	for c in CASES {
		addr := net.parse_address(c.text)
		if addr == nil {
			testing.expectf(t, false, "%q did not parse as an address", c.text)
			continue
		}
		testing.expectf(t, address_is_public(addr) == c.public, "%q: expected public=%v", c.text, c.public)
	}
	// Nothing at all is not somewhere a redirect may name.
	testing.expect(t, !address_is_public(nil), "a nil address was treated as public")
}

@(test)
test_redirect_allowed_refuses_downgrade_and_retarget :: proc(t: ^testing.T) {
	Case :: struct {
		origin_scheme: string,
		origin_public: bool,
		scheme:        string,
		addr:          string,
		allowed:       bool,
		what:          string,
	}
	CASES := []Case {
		{"https", true, "https", "8.8.8.8", true, "https staying https"},
		{"https", true, "http", "8.8.8.8", false, "https downgraded to http"},
		{"http", true, "https", "8.8.8.8", true, "http upgraded to https"},
		{"http", true, "http", "8.8.8.8", true, "http staying http"},
		{"https", true, "https", "127.0.0.1", false, "a public origin retargeted at loopback"},
		{"https", true, "https", "169.254.169.254", false, "a public origin retargeted at link-local"},
		// An operator who configured a local mirror meant it.
		{"http", false, "http", "127.0.0.1", true, "a local mirror redirecting locally"},
		{"https", false, "https", "10.0.0.1", true, "a private origin staying private"},
	}
	for c in CASES {
		addr := net.parse_address(c.addr)
		if addr == nil {
			testing.expectf(t, false, "%q did not parse as an address", c.addr)
			continue
		}
		got := redirect_allowed(c.origin_scheme, c.origin_public, c.scheme, addr)
		testing.expectf(t, got == c.allowed, "%s: expected allowed=%v, got %v", c.what, c.allowed, got)
	}
}

// And the ordinary case still works: a redirect that keeps the operator's
// scheme and stays where it was pointed is followed to the end.
@(test)
test_redirect_within_the_configured_scheme_is_followed :: proc(t: ^testing.T) {
	dest, derr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if derr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", derr)
		return
	}
	dest_bound, dberr := net.bound_endpoint(dest)
	if dberr != nil {
		net.close(dest)
		testing.expectf(t, false, "cannot read the destination's port: %v", dberr)
		return
	}
	origin, oerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if oerr != nil {
		net.close(dest)
		testing.expectf(t, false, "cannot listen on loopback: %v", oerr)
		return
	}
	origin_bound, oberr := net.bound_endpoint(origin)
	if oberr != nil {
		net.close(dest)
		net.close(origin)
		testing.expectf(t, false, "cannot read the origin's port: %v", oberr)
		return
	}

	dest_mock := Http_Mock {
		listener = dest,
		reply    = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nrules",
	}
	origin_mock := Http_Mock {
		listener = origin,
		reply    = fmt.tprintf(
			"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/list.txt\r\nContent-Length: 0\r\n\r\n",
			dest_bound.port,
		),
	}
	dest_server := thread.create_and_start_with_poly_data(&dest_mock, http_mock_once)
	origin_server := thread.create_and_start_with_poly_data(&origin_mock, http_mock_once)

	url := fmt.tprintf("http://127.0.0.1:%d/list.txt", origin_bound.port)
	body, ferr := fetch_url(url, nil, 5 * time.Second, context.temp_allocator)

	// Joined before the arena the replies live in is reset.
	thread.join(origin_server)
	thread.destroy(origin_server)
	thread.join(dest_server)
	thread.destroy(dest_server)
	net.close(origin)
	net.close(dest)

	testing.expectf(t, ferr == .None, "an in-scheme redirect was refused: %v", ferr)
	testing.expect_value(t, string(body), "rules")
	free_all(context.temp_allocator)
}

/*
A lookup the server makes on its own account has to outlive one upstream
declining to answer it.

`exchange` reads the rcode only for BADCOOKIE, so a SERVFAIL is a successful
exchange and `resolve_sequential` returns it from the first server to reply -
the failover loop never runs, because nothing failed in the sense it measures.
That is right for a client's question, whose answer is the rcode. It is wrong
for a DS or DNSKEY lookup, where SERVFAIL says nothing about the delegation and
leaves the chain unestablished, refusing a name that another upstream in the
group could have settled.

Two responders, in configured order: the first answers SERVFAIL to everything,
the second answers NOERROR. `resolve` is expected to take the first at its word;
`resolve_answerable` is expected to go on and find the second.
*/
@(private = "file")
Rcode_Mock :: struct {
	socket: net.UDP_Socket,
	rcode:  u8,
	stop:   bool,
	hits:   int,
}

@(private = "file")
rcode_mock_loop :: proc(m: ^Rcode_Mock) {
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
		sync.atomic_add(&m.hits, 1)
		buf[2] |= 0x80
		buf[3] = (buf[3] & 0xf0) | m.rcode
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

// Binds a responder that answers every query with `rcode`, and hands back the
// upstream pointing at it.
@(private = "file")
start_rcode_mock :: proc(
	t: ^testing.T,
	m: ^Rcode_Mock,
	name: string,
	rcode: dns.Rcode,
) -> (
	u: ^Upstream,
	responder: ^thread.Thread,
	ok: bool,
) {
	m.rcode = u8(rcode) & 0xf
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return nil, nil, false
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return nil, nil, false
	}

	built, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
	)
	if uerr != .None {
		net.close(socket)
		testing.expectf(t, false, "cannot build the upstream: %v", uerr)
		return nil, nil, false
	}

	return built, thread.create_and_start_with_poly_data(m, rcode_mock_loop), true
}

@(test)
test_a_chain_lookup_is_asked_elsewhere_when_one_upstream_declines :: proc(t: ^testing.T) {
	refuser := Rcode_Mock{}
	answerer := Rcode_Mock{}

	bad, bad_thread, bad_ok := start_rcode_mock(t, &refuser, "refuser", .Serv_Fail)
	if !bad_ok {
		return
	}
	defer {
		sync.atomic_store(&refuser.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(refuser.socket)
		destroy(bad)
	}

	good, good_thread, good_ok := start_rcode_mock(t, &answerer, "answerer", .No_Error)
	if !good_ok {
		return
	}
	defer {
		sync.atomic_store(&answerer.stop, true)
		thread.join(good_thread)
		thread.destroy(good_thread)
		net.close(answerer.socket)
		destroy(good)
	}

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = bad
	servers[1] = good

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

	query := dns.Message {
		id       = 0x2A2A,
		question = []dns.Question{{name = "bahn.de.", type = .DS, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc == dns.Encode_Error.None, "cannot encode the query: %v", enc)
	if enc != .None {
		return
	}

	// What a client's own question gets, and should go on getting: the rcode is
	// the answer, and the first server to reply gave one.
	plain, plain_winner, plain_err := resolve(&g, wire, context.allocator)
	testing.expect_value(t, plain_err, Error.None)
	testing.expect_value(t, dns.peek_rcode(plain), dns.Rcode.Serv_Fail)
	testing.expect_value(t, plain_winner, bad)
	delete(plain, context.allocator)

	// What the chain walk gets: the declining server is skipped over rather
	// than believed.
	resp, winner, err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.No_Error)
	testing.expect_value(t, winner, good)
	testing.expect(t, sync.atomic_load(&answerer.hits) > 0, "the second upstream was never asked")
	delete(resp, context.allocator)

	free_all(context.temp_allocator)
}

// The other half: when nobody can answer, the first reply still comes back with
// its rcode intact, so `zone_step` reads it and calls the chain unavailable
// rather than the caller getting a transport error it would report differently.
@(test)
test_a_chain_lookup_keeps_the_reply_when_no_upstream_can_answer :: proc(t: ^testing.T) {
	first := Rcode_Mock{}
	second := Rcode_Mock{}

	a, a_thread, a_ok := start_rcode_mock(t, &first, "first", .Serv_Fail)
	if !a_ok {
		return
	}
	defer {
		sync.atomic_store(&first.stop, true)
		thread.join(a_thread)
		thread.destroy(a_thread)
		net.close(first.socket)
		destroy(a)
	}

	b, b_thread, b_ok := start_rcode_mock(t, &second, "second", .Refused)
	if !b_ok {
		return
	}
	defer {
		sync.atomic_store(&second.stop, true)
		thread.join(b_thread)
		thread.destroy(b_thread)
		net.close(second.socket)
		destroy(b)
	}

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = a
	servers[1] = b

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

	query := dns.Message {
		id       = 0x2A2A,
		question = []dns.Question{{name = "bahn.de.", type = .DS, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expectf(t, enc == dns.Encode_Error.None, "cannot encode the query: %v", enc)
	if enc != .None {
		return
	}

	resp, winner, err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.Serv_Fail)
	testing.expect_value(t, winner, a)
	testing.expect(t, sync.atomic_load(&second.hits) > 0, "the second upstream was never asked")
	delete(resp, context.allocator)

	free_all(context.temp_allocator)
}
