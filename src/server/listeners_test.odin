package server

import "core:net"
import "core:strconv"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:pool"
import "elodin:tlsx"

/*
Shutdown has to release the loops' contexts after the work that holds them, not
when the loops themselves stop.

A read loop hands its context to every job it queues, and `pool.destroy` runs
what is queued before it joins its workers - so a job submitted a moment before
the socket closed still reads that context well after the loop has gone.
*/

@(private = "file")
Barrier :: struct {
	go:      bool,
	started: bool,
}

// Occupies the pool's only worker until released, so a job queued behind it
// stays queued and the test can look at the world in between.
@(private = "file")
barrier_job :: proc(data: rawptr) {
	b := cast(^Barrier)data
	sync.atomic_store(&b.started, true)
	for !sync.atomic_load(&b.go) {
		time.sleep(time.Millisecond)
	}
}

@(private = "file")
wait_until :: proc(predicate: proc(data: rawptr) -> bool, data: rawptr, within: time.Duration) -> bool {
	deadline := time.time_add(time.now(), within)
	for time.diff(time.now(), deadline) > 0 {
		if predicate(data) {
			return true
		}
		time.sleep(time.Millisecond)
	}
	return false
}

@(private = "file")
Pending_Probe :: struct {
	handler_pool: ^pool.Pool,
	want:         int,
}

@(private = "file")
pending_reached :: proc(data: rawptr) -> bool {
	p := cast(^Pending_Probe)data
	return pool.pending(p.handler_pool) >= p.want
}

@(private = "file")
barrier_started :: proc(data: rawptr) -> bool {
	return sync.atomic_load(&(cast(^Barrier)data).started)
}

/*
The read loop must not release the context its queued jobs are still holding.

Detected by identity: `stop_listeners` has joined the loop by the time this
looks, so whatever the loop was going to release, it has. Asking the same
allocator for another context of the same size then either hands back an
address it cannot possibly hand back - because the context is still owned - or
hands back the very block a queued job is about to read through, which is the
defect.
*/
@(test)
test_read_loop_does_not_release_a_context_its_jobs_hold :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.listeners.udp = config.Listener {
		enabled = true,
		address = "127.0.0.1",
		port    = 0, // ephemeral, so the test never collides with a real server
	}
	cfg.listeners.tcp.enabled = false
	cfg.listeners.dot.enabled = false
	cfg.listeners.doh.enabled = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.log.queries = false
	cfg.server.max_connections = 8
	cfg.server.max_pending = 0

	// One worker, so a single occupied job is the whole pool.
	handler_pool := pool.make_pool(1)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		pool.destroy(handler_pool)
		testing.expect(t, false, "could not start the UDP listener")
		return
	}

	barrier := Barrier{}
	testing.expect(t, pool.submit(handler_pool, barrier_job, &barrier), "could not occupy the worker")
	if !wait_until(barrier_started, &barrier, time.Second) {
		sync.atomic_store(&barrier.go, true)
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
		testing.expect(t, false, "the worker never picked up the barrier job")
		return
	}

	bound, berr := net.bound_endpoint(l.udp_socket)
	if berr != nil {
		sync.atomic_store(&barrier.go, true)
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}

	/*
	A bare header with no question. It reaches the read loop, is queued, and is
	answered with FORMERR — which is all this needs, and it keeps the job off
	the cache, the filters and the upstream group, none of which are wired up
	here.
	*/
	client, cerr := net.make_unbound_udp_socket(net.family_from_endpoint(bound))
	testing.expectf(t, cerr == nil, "cannot open a client socket: %v", cerr)
	query: [dns.HEADER_SIZE]u8
	_, _ = net.send_udp(client, query[:], bound)

	probe := Pending_Probe {
		handler_pool = handler_pool,
		want         = 2, // the barrier, plus the query behind it
	}
	queued := wait_until(pending_reached, &probe, 2 * time.Second)
	net.close(client)

	// Sockets closed, read loop joined. Anything it releases, it has released.
	stop_listeners(&l)

	held := l.udp_loop_ctx
	testing.expect(t, held != nil, "the listener kept no handle on its read loop's context")
	if queued && held != nil {
		fresh := new(Udp_Context)
		defer free(fresh)
		testing.expect(
			t,
			fresh != held,
			"the read loop released a context a queued job still holds: the allocator handed it straight back",
		)
	}
	testing.expect(t, queued, "the query never reached the pool, so nothing was held across the shutdown")

	// Draining runs the queued job, which reads through that context.
	sync.atomic_store(&barrier.go, true)
	pool.destroy(handler_pool)

	destroy_listeners(&l)
	testing.expect(t, l.udp_loop_ctx == nil, "destroy_listeners left the context behind")
}

/*
A connection refused for want of a slot is counted, not only logged.

The line for it is a `warn` once and `debug` after that, on the reasoning that a
peer opening connections decides how many lines this server writes. That trade is
only sound because something else goes on counting: without `conn_refused`, a
server sitting at `max_connections` for a week shows one `warn` from its first
minute and nothing since - which is the silence the demotion was supposed to
avoid, not cause.

Driven through the accept loop against a real listener rather than through
`conn_spawn`, because the increment is in the loop and `conn_spawn` knows nothing
about the counter. `max_connections` of 1, one connection to occupy it and a
second to be refused.
*/
@(private = "file")
Refused_Probe :: struct {
	server: ^Server,
	want:   u64,
}

@(private = "file")
conn_refused_reached :: proc(data: rawptr) -> bool {
	p := cast(^Refused_Probe)data
	return sync.atomic_load(&p.server.stats.conn_refused) >= p.want
}

@(private = "file")
slot_taken :: proc(data: rawptr) -> bool {
	return active_connections(&(cast(^Listeners)data).conns) >= 1
}

@(test)
test_a_connection_past_the_limit_is_counted :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.listeners.udp.enabled = false
	cfg.listeners.tcp = config.Listener {
		enabled = true,
		address = "127.0.0.1",
		port    = 0,
	}
	cfg.listeners.dot.enabled = false
	cfg.listeners.doh.enabled = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.log.queries = false
	cfg.server.max_connections = 1
	// Long enough that the first connection is still holding its slot when the
	// second arrives, without leaving a stuck thread behind if it is not.
	cfg.server.client_timeout = 5 * time.Second

	handler_pool := pool.make_pool(1)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		pool.destroy(handler_pool)
		testing.expect(t, false, "could not start the TCP listener")
		return
	}
	defer {
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
	}

	bound, berr := net.bound_endpoint(l.tcp_socket)
	if !testing.expectf(t, berr == nil, "cannot read the listener's port: %v", berr) {
		return
	}

	// Opened and left open with nothing written on it, so the connection thread
	// sits in its read and the slot stays taken.
	first, ferr := net.dial_tcp(bound)
	if !testing.expectf(t, ferr == nil, "cannot open the first connection: %v", ferr) {
		return
	}
	defer net.close(first)

	// The accept loop has to have taken the first one before the second arrives,
	// or the limit is not what refuses it.
	taken := wait_until(slot_taken, &l, 2 * time.Second)
	if !testing.expect(t, taken, "the first connection never occupied the only slot") {
		return
	}

	second, serr := net.dial_tcp(bound)
	if !testing.expectf(t, serr == nil, "cannot open the second connection: %v", serr) {
		return
	}
	defer net.close(second)

	probe := Refused_Probe {
		server = &s,
		want   = 1,
	}
	counted := wait_until(conn_refused_reached, &probe, 2 * time.Second)
	testing.expectf(
		t,
		counted,
		"a connection refused past max_connections was not counted: conn_refused=%d",
		sync.atomic_load(&s.stats.conn_refused),
	)
	// And it is the limit that was blamed, not the OS refusing a thread.
	testing.expect_value(t, sync.atomic_load(&s.stats.conn_failed), u64(0))
}

@(private = "file")
month_number :: proc(name: string) -> int {
	names := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	for n, i in names {
		if n == name {
			return i + 1
		}
	}
	return 0
}

/*
The Date header's day-name has to agree with the date next to it, or a strict
cache rejects the whole header - and with it the `max-age` that told it when
to expire the answer.

The expected weekday is derived from the date `now_http_date` itself printed,
not from a separate `time.now()` call in the test: the two calls straddling
midnight would make the test flake on a day-name mismatch that was never a
bug.
*/
@(test)
test_now_http_date_weekday_matches_the_date :: proc(t: ^testing.T) {
	got := now_http_date()
	defer delete(got)

	// "Fri, 07 Aug 2026 18:56:41 GMT" - fixed width throughout, since the
	// format string uses %02d/%04d for every numeric field.
	if !testing.expectf(t, len(got) == 29, "Date header is not in the expected form: %q", got) {
		return
	}

	day, day_ok := strconv.parse_int(got[5:7])
	month := month_number(got[8:11])
	year, year_ok := strconv.parse_int(got[12:16])
	hour, hour_ok := strconv.parse_int(got[17:19])
	minute, minute_ok := strconv.parse_int(got[20:22])
	second, second_ok := strconv.parse_int(got[23:25])
	if !testing.expectf(
		t,
		day_ok && month != 0 && year_ok && hour_ok && minute_ok && second_ok,
		"could not parse the Date header: %q",
		got,
	) {
		return
	}

	parsed, ok := time.components_to_time(year, month, day, hour, minute, second)
	if !testing.expectf(t, ok, "the Date header's own date does not parse as a valid time: %q", got) {
		return
	}

	// Shared with production rather than a second copy of the table: a table
	// reordered the same way in both places would otherwise still agree with
	// itself. test_now_http_date_epoch_is_a_known_thursday below is what
	// actually catches that.
	expected := WEEKDAY_NAMES[int(time.weekday(parsed))]

	testing.expectf(
		t,
		got[:3] == expected,
		"Date header weekday does not match its date: got %q, expected %q",
		got[:3],
		expected,
	)
}

/*
An oracle independent of `weekday_name`'s own table: the Unix epoch is a well
known Thursday, so the expected string here is a literal, not anything
derived from the table under test. A table that agrees with itself while
being wrong - every name shifted one place, say - would pass the test above
but not this one.
*/
@(test)
test_now_http_date_epoch_is_a_known_thursday :: proc(t: ^testing.T) {
	epoch, ok := time.components_to_time(1970, 1, 1, 0, 0, 0)
	if !testing.expect(t, ok, "could not construct the Unix epoch as a time.Time") {
		return
	}

	got := http_date(epoch)
	defer delete(got)

	testing.expect_value(t, got, "Thu, 01 Jan 1970 00:00:00 GMT")
}

/*
The answers a refused connection has already written survive the close that
refuses the rest of it.

A client that pipelines - which RFC 7766 6.2.1.1 allows - has queries in this
server's receive queue that were never read, because the budget ran out before
they were reached. Closing a socket in that state sends an RST rather than a FIN
(RFC 1122 4.2.2.13), and the RST has the client's kernel discard its receive
buffer: without a drain first, the answers the client was already sent go with the
queries it was refused, and its `recv` fails where it should have handed over
those answers and then the end of the stream.

Served by hand rather than through `serve_dns_stream`, which wants a whole server
behind it. What is under test is the three things the refusal path does and the
order it does them in - the answer, the drain, the close - and the drain is the
only one of the three that is new. The client shuts down its sending half so the
drain ends on the end of the data rather than on `STREAM_LINGER_TIMEOUT`, and can
still read afterwards.
*/
@(test)
test_a_refused_pipeline_keeps_the_answers_already_written :: proc(t: ^testing.T) {
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

	// Bare DNS headers behind the two-byte length prefix, all of them sent before
	// any is answered, each with a transaction ID of its own as a real client's
	// would have.
	STRIDE :: 2 + dns.HEADER_SIZE
	PIPELINE :: 64
	pipeline: [PIPELINE * STRIDE]u8
	for i in 0 ..< PIPELINE {
		message := pipeline[i * STRIDE:][:STRIDE]
		message[1] = u8(dns.HEADER_SIZE)
		message[2], message[3] = u8(i >> 8), u8(i)
	}
	sent := 0
	for sent < len(pipeline) {
		n, serr := net.send_tcp(client, pipeline[sent:])
		if serr != nil || n <= 0 {
			testing.expectf(t, false, "cannot send the pipeline: %v", serr)
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

	// One query read and answered, which is the connection doing its job, and then
	// a budget with nothing left in it: what `serve_dns_stream` does from there,
	// in the order it does it.
	first: [STRIDE]u8
	if !conn_read_full(conn, first[:]) {
		testing.expect(t, false, "the first query never arrived")
		return
	}
	answer := first
	// QR, so what goes back is an answer and not the question echoed.
	answer[4] = 0x80
	if !conn_write_all(conn, answer[:]) {
		testing.expect(t, false, "the answer was not written")
		return
	}
	stream_linger(conn)
	net.close(accepted)

	reply: [STRIDE]u8
	got := 0
	for got < len(reply) {
		n, rerr := net.recv_tcp(client, reply[got:])
		if rerr != nil {
			testing.expectf(t, false, "the answer did not survive the close: %v", rerr)
			return
		}
		if n == 0 {
			testing.expect(t, false, "the connection ended before the answer arrived")
			return
		}
		got += n
	}
	testing.expectf(t, reply == answer, "the client read % x, expected the answer that was written", reply)

	/*
	And the connection ended rather than resetting. `core:net` spells a graceful
	close as no bytes and no error, where it documents `Connection_Closed` as the
	other thing - so this is the assertion that fails on an RST even if the answer
	above happened to be read before one arrived.
	*/
	n, rerr := net.recv_tcp(client, reply[:])
	testing.expectf(t, n == 0 && rerr == nil, "the close was not graceful: %d bytes, %v", n, rerr)
}

/*
The drains' short read wait reaches a TLS connection, which the socket option it
used to be written as did not.

`tlsx` reads SO_RCVTIMEO once, at the handshake, and then puts the socket into
non-blocking mode and waits on the deadline the connection carries instead. So a
`net.set_option` afterwards changes nothing a TLS read looks at, and the drains -
which are reached over DoT and DoH as often as over TCP - were left waiting out
`client_timeout` on a client that had stopped sending, holding one of
`max_connections` for the whole of it. That is what the short wait exists to
avoid, so it has to be the wait that a TLS read actually uses.

Nothing is handshaked here: what is under test is which field the wait lands in,
and a bare `tlsx.Conn` carries both of them. The write deadline is asserted too -
a drain shortens its reads and has no business saying what a write should wait
for.
*/
@(test)
test_a_drain_shortens_a_tls_read_as_well :: proc(t: ^testing.T) {
	tls := tlsx.Conn{}
	tlsx.set_timeouts(&tls, 10 * time.Second, 10 * time.Second)

	conn_set_read_timeout(Conn{tls = &tls}, STREAM_LINGER_IDLE)

	testing.expect_value(t, time.Duration(tls.read_timeout_ns), STREAM_LINGER_IDLE)
	testing.expect_value(t, time.Duration(tls.write_timeout_ns), 10 * time.Second)
}

/*
Loopback, in every spelling one can arrive in.

Two callers, and both of them read the answer as a statement about who is at the
other end. `plausible_source` refuses a datagram from a loopback address on our
own listening port, because under a wildcard bind that is this server talking to
itself - and on a `::` bind our own datagrams to an IPv4 destination carry
`::ffff:127.0.0.1`, not `::1`. `start_metrics` warns when the endpoint it just
bound is not loopback, so an operator who bound `::ffff:127.0.0.1` was told the
unauthenticated endpoint was reachable from the network when it was not.

The mapping and nothing else is undone, which is `config.address_bytes`'s rule:
`::7f00:1` and `::ffff:0:7f00:1` are IPv6 addresses that happen to carry the
octets of 127.0.0.1, no stack sources a datagram from them, and reading them as
IPv4 here would be reading an address the ACL compares as IPv6.

127/8 whole, both mapped and not, because that is what loopback is for IPv4 -
`::1/128` is the whole of it for IPv6, and the compat and translated forms of
`::1` are not it.
*/
@(test)
test_loopback_is_recognised_through_the_v4_mapping :: proc(t: ^testing.T) {
	Case :: struct {
		address:  net.Address,
		loopback: bool,
		what:     string,
	}

	CASES := []Case {
		{net.IP4_Loopback, true, "127.0.0.1"},
		{net.IP4_Address{127, 0, 0, 0}, true, "the bottom of 127/8"},
		{net.IP4_Address{127, 255, 255, 255}, true, "the top of it"},
		{net.IP6_Loopback, true, "`::1`"},
		{mapped_address(127, 0, 0, 1), true, "`::ffff:127.0.0.1`, our own datagram under a `::` bind"},
		{mapped_address(127, 1, 2, 3), true, "the rest of 127/8, mapped"},
		{mapped_address(127, 255, 255, 255), true, "the top of it, mapped"},

		{net.IP4_Address{126, 255, 255, 255}, false, "just below 127/8"},
		{net.IP4_Address{128, 0, 0, 1}, false, "just above it"},
		{mapped_address(126, 255, 255, 255), false, "just below 127/8, mapped"},
		{mapped_address(128, 0, 0, 1), false, "just above it, mapped"},
		{mapped_address(0, 0, 0, 0), false, "`::ffff:0.0.0.0`"},
		{mapped_address(0, 0, 0, 1), false, "0.0.0.0/8 is not loopback"},
		{mapped_address(192, 0, 2, 1), false, "an ordinary mapped address"},
		{net.IP6_Any, false, "`::`"},
		{net.IP6_Address{0x2001, 0x0db8, 0, 0, 0, 0, 0, 1}, false, "an ordinary IPv6 address"},
		// Not the mapping, so not unmapped.
		{groups_address({0, 0, 0, 0, 0, 0, 0x7f00, 0x0001}), false, "the compat form of 127.0.0.1"},
		{groups_address({0, 0, 0, 0, 0xffff, 0, 0x7f00, 0x0001}), false, "the translated form of 127.0.0.1"},
		{groups_address({0, 0, 0, 0, 0, 0xfffe, 0x7f00, 0x0001}), false, "one bit off the mapped prefix"},
		{groups_address({0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001}), true, "and the mapped prefix itself, written out"},
		// The mapped forms of `::1`, which are not addresses at all - the mapping
		// carries an IPv4 address, and `::1` is not one.
		{groups_address({0, 0, 0, 0, 0, 0xffff, 0, 1}), false, "`::ffff:0.0.0.1`, not `::1`"},

		// Neither family: not an address, so not loopback.
		{nil, false, "no address"},
	}

	for c in CASES {
		got := is_loopback(c.address)
		testing.expectf(t, got == c.loopback, "%s: is_loopback said %v", c.what, got)
	}
}

// `::ffff:a.b.c.d`, the form an IPv4 peer arrives in on a socket bound to `::`.
@(private = "file")
mapped_address :: proc(a, b, c, d: u8) -> net.Address {
	return groups_address({0, 0, 0, 0, 0, 0xffff, u16(a) << 8 | u16(b), u16(c) << 8 | u16(d)})
}

// An IPv6 address written as its eight groups, for the forms that only resemble
// the mapped one.
@(private = "file")
groups_address :: proc(groups: [8]u16) -> net.Address {
	addr: net.IP6_Address
	for g, i in groups {
		addr[i] = u16be(g)
	}
	return addr
}

/*
Loopback is 127/8 and `::1`, swept over every octet that decides it.

The table above names the interesting addresses; this says there are no others.
127/8 whole in both forms, nothing outside it in either, and the sweep is over
the octet the check actually reads - a check that looked at the wrong byte, or
compared a range rather than the octet, passes a hand-written table and fails
here.
*/
@(test)
test_loopback_is_127_over_8_in_both_forms :: proc(t: ^testing.T) {
	for first in 0 ..< 256 {
		want := first == 127
		unmapped := net.IP4_Address{u8(first), 0, 0, 1}
		testing.expectf(
			t,
			is_loopback(unmapped) == want,
			"%d.0.0.1: is_loopback said %v",
			first,
			is_loopback(unmapped),
		)
		testing.expectf(
			t,
			is_loopback(mapped_address(u8(first), 0, 0, 1)) == want,
			"`::ffff:%d.0.0.1`: is_loopback said %v",
			first,
			is_loopback(mapped_address(u8(first), 0, 0, 1)),
		)
	}
	// Everything below the /8 is inside it, whichever form it arrived in.
	for byte_value in 0 ..< 256 {
		b := u8(byte_value)
		testing.expectf(t, is_loopback(net.IP4_Address{127, b, b, b}), "127.%d.%d.%d is inside 127/8", b, b, b)
		testing.expectf(t, is_loopback(mapped_address(127, b, b, b)), "`::ffff:127.%d.%d.%d` is inside 127/8", b, b, b)
	}
	// `::1` and nothing near it.
	testing.expect(t, is_loopback(net.IP6_Loopback), "`::1` is loopback")
	for group in 0 ..< 8 {
		groups := [8]u16{0, 0, 0, 0, 0, 0, 0, 1}
		groups[group] |= 0x0100
		testing.expectf(t, !is_loopback(groups_address(groups)), "a bit set in group %d of `::1` is not `::1`", group)
	}
}
