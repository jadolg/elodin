package server

import "core:net"
import "core:strconv"
import "core:sync"
import "core:testing"
import "core:thread"
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

	bound, berr := net.bound_endpoint(l.udp[0].socket)
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

	held := l.udp[0].ctx
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
	testing.expect(t, l.udp == nil, "destroy_listeners left the readers behind")
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

/*
A client that has filled its share of the table is refused with the table not
full.

The accept loop is where this has to be shown. `conn_spawn` refusing over the
share is one thing; the loop reading the client's prefix off the address the
accept returned, charging the connection to it, and turning the refusal into
`conn_refused=` is the other, and a share checked against a prefix nobody filled
in would pass every unit test in `conns_test.odin` while bounding nothing.

`max_connections` of 4 with a share of 1, so the refusal cannot be the table
running out: three slots are free when the second connection from loopback is
turned away, and the case says so afterwards rather than leaving it to be
inferred from the counter. Both connections come from 127.0.0.1, which is one
/24 and therefore one client.
*/
@(test)
test_a_connection_over_its_prefix_share_is_refused :: proc(t: ^testing.T) {
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
	cfg.server.max_connections = 4
	// Set rather than left at the default, which is zero: the derivation from
	// `max_connections` happens at load, and this configuration never went
	// through it.
	cfg.server.max_connections_per_prefix = 1
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

	// Held open with nothing written on it, which is the shape of the problem:
	// the connection asks no questions, so nothing charges it to a budget, and
	// it occupies its slot until `client_timeout` gives up on it.
	first, ferr := net.dial_tcp(bound)
	if !testing.expectf(t, ferr == nil, "cannot open the first connection: %v", ferr) {
		return
	}
	defer net.close(first)

	if !testing.expect(t, wait_until(slot_taken, &l, 2 * time.Second), "the first connection never landed") {
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
		"a second connection from one prefix was served or lost rather than refused: conn_refused=%d",
		sync.atomic_load(&s.stats.conn_refused),
	)
	// The premise the refusal rests on: the table had room, so what refused the
	// connection was the client's share of it and not `max_connections`.
	testing.expect_value(t, active_connections(&l.conns), 1)
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
	first_budget := Read_Budget {
		idle = 3 * time.Second,
	}
	if !conn_read_full(conn, first[:], &first_budget) {
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

/*
A message trickled a byte at a time is given up on at `client_timeout`, not held
for as long as the client keeps trickling.

`client_timeout` reaches the socket as SO_RCVTIMEO, which bounds one read: every
byte that arrives restarts it, so before `Read_Budget` the only thing that ever
reclaimed an accepted connection could not fire at all against a client sending a
byte inside every wait. Nothing else caught it either - the connection and
connection-rate limits bound how many are opened and how fast, and the query
budgets are charged per message, so a connection on which no message ever
completes is charged nothing and counted against nothing while it holds one of
`max_connections`. RFC 7766 6.2.3 names the attack and says the idle timeout is
reset "on the receipt of a full DNS message, rather than on receipt of any part of
a DNS message".

The drip is shorter than `client_timeout`, which is what makes it a drip: every
byte lands inside the window the byte before it opened. Against a server holding
one deadline across the message, the connection ends after roughly
`client_timeout` regardless - about three bytes in here - so what is asserted is
that it ended before the message it was feeding could have finished arriving.

The bytes are a bare DNS header behind its length prefix, as the pipeline case
above uses: what is under test is a message that never finishes arriving, and
nothing ever parses one of those.
*/
@(test)
test_a_drip_fed_message_is_reclaimed_at_the_deadline :: proc(t: ^testing.T) {
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
	// Short, because the case spends it: the drip below is paced off it, and the
	// whole test takes a couple of multiples of it.
	cfg.server.client_timeout = 400 * time.Millisecond
	DRIP :: 150 * time.Millisecond

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

	client, derr := net.dial_tcp(bound)
	if !testing.expectf(t, derr == nil, "cannot open the connection: %v", derr) {
		return
	}
	defer net.close(client)
	// The read below is both how the close is noticed and what paces the drip: it
	// waits a drip's worth for something the server has no reason to send, so the
	// loop turns over at the drip interval whether or not the connection is still
	// there.
	_ = net.set_option(client, .Receive_Timeout, DRIP)

	message: [2 + dns.HEADER_SIZE]u8
	message[1] = u8(dns.HEADER_SIZE)

	sent := 0
	closed := false
	for sent < len(message) && !closed {
		n, serr := net.send_tcp(client, message[sent:][:1])
		if serr != nil || n != 1 {
			// The server closed and the RST came back before this byte went out,
			// which is the same outcome noticed one byte later.
			closed = true
			break
		}
		sent += 1

		reply: [1]u8
		rn, rerr := net.recv_tcp(client, reply[:])
		// A graceful close is no bytes and no error; a reset is
		// `Connection_Closed`. `Would_Block` is the drip's own wait expiring with
		// the connection still up, which is the loop doing its job.
		if (rn == 0 && rerr == nil) || (rerr != nil && rerr != net.TCP_Recv_Error.Would_Block) {
			closed = true
		}
	}

	testing.expectf(
		t,
		closed,
		"a client trickling a byte every %v held the connection through the whole message",
		DRIP,
	)
	testing.expectf(
		t,
		sent < len(message),
		"the connection survived all %d bytes of a message trickled a byte every %v, which is %v of it",
		len(message),
		DRIP,
		time.Duration(len(message)) * DRIP,
	)
}

@(private = "file")
Late_Sender :: struct {
	endpoint: net.Endpoint,
	message:  []u8,
	split:    int,
	wait:     time.Duration,
}

// Connect, wait, send the front of the message, wait again, send the rest. Both
// waits are shorter than the budget and longer than what is left of it once the
// first one has been spent out of the same figure.
@(private = "file")
send_late_and_split :: proc(s: ^Late_Sender) {
	socket, err := net.dial_tcp_from_endpoint(s.endpoint)
	if err != nil {
		return
	}
	defer net.close(socket)
	time.sleep(s.wait)
	if _, serr := net.send_tcp(socket, s.message[:s.split]); serr != nil {
		return
	}
	time.sleep(s.wait)
	_, _ = net.send_tcp(socket, s.message[s.split:])
	// Held open until the reader has had its turn; closing here would race the
	// second half off the wire.
	time.sleep(500 * time.Millisecond)
}

/*
Waiting for a message to start does not spend the budget for reading one.

The deadline covers the message, and it begins at the message's first byte rather
than where the connection started waiting for one - see `Read_Budget`. Sharing one
figure between the two instead would close on a keep-alive client that asked late
in its idle window and had its message split across segments, which is a client
this server has no complaint about: the rule is one budget per message, not one
per connection, and RFC 7828 tells a client the connection is held for the whole
of `client_timeout` whenever it next has something to ask.

Both waits here are 700ms against a one-second budget, which leaves either
reading of it 300ms of margin: measured from the connection the two of them are
1.4s and the message could never arrive, and measured from its first byte the
second half has 700ms of a second to make. The margin matters more than the
speed here - this is the one case in the change that a slow box could fail with
correct code, so it is the one that gets the room.
*/
@(test)
test_the_wait_for_a_message_is_not_spent_on_reading_it :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the bound port: %v", berr) {
		return
	}

	message: [2 + dns.HEADER_SIZE]u8
	message[1] = u8(dns.HEADER_SIZE)
	sender := Late_Sender {
		endpoint = bound,
		message  = message[:],
		// The length prefix in one segment and the body in the next, which is the
		// split the budget has to survive because it is the one a client is free
		// to make.
		split    = 2,
		wait     = 700 * time.Millisecond,
	}
	client := thread.create_and_start_with_poly_data(&sender, send_late_and_split)
	defer {
		thread.join(client)
		thread.destroy(client)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if !testing.expectf(t, aerr == nil, "nothing connected: %v", aerr) {
		return
	}
	defer net.close(accepted)
	// Long, so that what ends a read here is the budget and never the socket.
	_ = net.set_option(accepted, .Receive_Timeout, 5 * time.Second)
	conn := Conn {
		socket = accepted,
	}

	budget := Read_Budget {
		idle = 1 * time.Second,
	}
	length_buf: [2]u8
	if !testing.expect(t, conn_read_full(conn, length_buf[:], &budget), "the length prefix never arrived") {
		return
	}
	body: [dns.HEADER_SIZE]u8
	testing.expect(
		t,
		conn_read_full(conn, body[:], &budget),
		"a message split after its length prefix was given up on, though neither half was late",
	)
}

/*
A deadline with less than a microsecond left still arms a read that expires.

`net.set_option` carries the wait to the kernel as a `timeval`, so anything under
a microsecond truncates to a zero one - and SO_RCVTIMEO of zero is no timeout at
all rather than one that has already expired. A read armed with the raw remainder
in that window waits forever, which is the hold the budget exists to end, reached
by landing a read inside the last microsecond of it.

Asserted on a TLS connection because that is where the figure that was set can be
read back; `conn_arm_read` is the one that computes it either way.
*/
@(test)
test_a_nearly_spent_deadline_does_not_arm_an_endless_read :: proc(t: ^testing.T) {
	tls := tlsx.Conn{}
	tlsx.set_timeouts(&tls, 10 * time.Second, 10 * time.Second)

	// Exactly 500ns left, read from the same instant the deadline was built on, so
	// the window under test is the one this case gets rather than whatever the
	// clock happens to leave.
	now := time.tick_now()
	budget := Read_Budget {
		idle     = 10 * time.Second,
		deadline = time.tick_add(now, 500),
	}

	if testing.expect(t, conn_arm_read(Conn{tls = &tls}, &budget, now), "500ns left read as none") {
		testing.expectf(
			t,
			time.Duration(tls.read_timeout_ns) >= time.Microsecond,
			"a read was armed with %v, which reaches the kernel as no timeout at all",
			time.Duration(tls.read_timeout_ns),
		)
	}
	// And the write deadline is still the connection's: what is nearly spent is
	// the budget for reading a message.
	testing.expect_value(t, time.Duration(tls.write_timeout_ns), 10 * time.Second)
}

/*
Shortening how long an idle connection is held does not shorten the handshake in
front of it.

`server_handshake` bounds a handshake as a whole now, and the figure it uses is
the socket's receive timeout - which `stream_job` sets from `client_timeout`, the
same value RFC 7828 advertises as how long an idle connection is kept. An
operator shortens that to reclaim slots sooner, which says nothing about how long
a client may take to shake hands: a handshake is several round trips and whatever
a lossy path makes of them, so the two sharing one figure would have a
high-latency client failing to connect at all. Hence the floor, and hence this,
because a floor that quietly stopped applying would look exactly like it working.
*/
@(test)
test_the_handshake_keeps_its_floor_under_a_short_client_timeout :: proc(t: ^testing.T) {
	Want :: struct {
		client_timeout: time.Duration,
		handshake:      time.Duration,
	}
	cases := []Want {
		// Above the floor, so the connection's own figure stands: an operator who
		// raised it meant the handshake too.
		{30 * time.Second, 30 * time.Second},
		// The shipped default, comfortably above.
		{10 * time.Second, 10 * time.Second},
		// Below it, and the handshake keeps the floor.
		{1 * time.Second, HANDSHAKE_FLOOR},
		{50 * time.Millisecond, HANDSHAKE_FLOOR},
		// Exactly the floor is not below it.
		{HANDSHAKE_FLOOR, HANDSHAKE_FLOOR},
		// No receive timeout at all is what a non-positive value means, and a
		// floor is not a bound the operator asked to add - see
		// `test_a_timeout_that_cannot_be_stated_is_left_off`.
		{0, 0},
		{-1 * time.Second, -1 * time.Second},
	}
	for c in cases {
		testing.expectf(
			t,
			handshake_timeout(c.client_timeout) == c.handshake,
			"a %v client timeout gives the handshake %v, expected %v",
			c.client_timeout,
			handshake_timeout(c.client_timeout),
			c.handshake,
		)
	}
}
