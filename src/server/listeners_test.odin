package server

import "core:net"
import "core:strconv"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:pool"

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

	names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	expected := names[int(time.weekday(parsed))]

	testing.expectf(
		t,
		got[:3] == expected,
		"Date header weekday does not match its date: got %q, expected %q",
		got[:3],
		expected,
	)
}
