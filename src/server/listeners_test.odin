package server

import "core:net"
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
