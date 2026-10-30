package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:h2"
import "elodin:loop"

/*
The dial queues in `get_h2_conn` and `get_pipe` are bounded by each caller's
own deadline, counted in dials rather than in time (#378).

Against a peer that accepts and never speaks, the wall time of a queue is the
same whether the bound is there or not: the caller that comes out of the queue
past its deadline still dials, on the one millisecond floor, and that dial ends
at once. What it does leave behind is a connection. The listener here never
accepts, so the kernel finishes each TCP handshake into its backlog, the
ClientHello gets no answer, and the backlog drained afterwards is the number of
dials made.

Both queues are held to it: DoH through `get_h2_conn`, DoT through `get_pipe`.
*/
@(private = "file")
QUEUED_KINDS :: [?]config.Upstream_Kind{.HTTPS, .TLS}

@(private = "file")
mute_listener :: proc(t: ^testing.T, kind: config.Upstream_Kind) -> (listener: net.TCP_Socket, u: ^Upstream, ok: bool) {
	lerr: net.Network_Error
	listener, lerr = net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		net.close(listener)
		return
	}
	serr := net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)
	if !testing.expectf(t, serr == nil, "cannot bound the accept: %v", serr) {
		net.close(listener)
		return
	}
	uerr: Error
	u, uerr = make_upstream(
		config.Upstream_Spec {
			name = "mute",
			kind = kind,
			address = "127.0.0.1",
			port = bound.port,
			hostname = "mute.invalid",
			path = "/dns-query",
		},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		net.close(listener)
		return
	}
	return listener, u, true
}

/*
Every connection the kernel completed, all of them in the backlog by the time
the callers that made them returned. One closed while it sat there was a dial
all the same, and a signal is not the end of the backlog; anything else that
ends the drain early would undercount, so it fails the test instead, and the
count so far is what the caller reports.
*/
@(private = "file")
drain_dials :: proc(t: ^testing.T, listener: net.TCP_Socket) -> (dials: int) {
	for {
		c, _, err := net.accept_tcp(listener)
		#partial switch err {
		case .None:
			net.close(c)
			dials += 1
		case .Aborted:
			dials += 1
		case .Interrupted:
		case .Timeout, .Would_Block:
			return
		case:
			testing.expectf(t, false, "cannot drain the backlog: %v", err)
			return
		}
	}
}

// One go at the queue `u` dials through, with `budget` to spend.
@(private = "file")
queue_once :: proc(u: ^Upstream, budget: time.Duration) -> Error {
	if u.spec.kind == .HTTPS {
		conn, ok, err := get_h2_conn(u, 30 * time.Second, budget)
		if ok {
			h2.client_unref(conn)
		}
		return err
	}
	c, err := get_pipe(u, 30 * time.Second, time.tick_add(time.tick_now(), budget))
	pipe_unref(c)
	return err
}

@(private = "file")
Dial_Caller :: struct {
	u:       ^Upstream,
	budget:  time.Duration,
	took:    time.Duration,
	err:     Error,
	started: bool,
	done:    ^sync.Wait_Group,
}

@(private = "file")
dial_caller :: proc(c: ^Dial_Caller) {
	start := time.tick_now()
	sync.atomic_store(&c.started, true)
	c.err = queue_once(c.u, c.budget)
	c.took = time.tick_since(start)
	sync.wait_group_done(c.done)
}

/*
Callers queued behind a dial that outlasts them give up at their own deadline
and dial nothing. Unbounded, each of them waits the dial out and then makes one
of its own.

The dial in front of them is `u.connecting` set by hand rather than a real one,
and it ends only once every caller has returned: whenever each of them started,
a bounded caller has nothing left to dial with by then. The cap is what ends it
for callers that are not bounded, so that they fail rather than hang. It counts
from the moment the last caller started, so a caller the scheduler started late
still finds the dial in flight.
*/
@(test)
test_callers_queued_behind_a_dial_keep_their_own_budget :: proc(t: ^testing.T) {
	for kind in QUEUED_KINDS {
		callers_queued_behind_a_dial_keep_their_own_budget(t, kind)
	}
}

@(private = "file")
callers_queued_behind_a_dial_keep_their_own_budget :: proc(t: ^testing.T, kind: config.Upstream_Kind) {
	DIAL :: time.Second
	WAIT :: 200 * time.Millisecond
	WAITERS :: 3

	listener, u, ok := mute_listener(t, kind)
	if !ok {
		return
	}
	defer net.close(listener)
	defer destroy(u)

	sync.mutex_lock(&u.mu)
	u.connecting = true
	sync.mutex_unlock(&u.mu)

	done: sync.Wait_Group
	sync.wait_group_add(&done, WAITERS)
	waiters: [WAITERS]Dial_Caller
	threads: [WAITERS]^thread.Thread
	for i in 0 ..< WAITERS {
		waiters[i] = Dial_Caller {
			u      = u,
			budget = WAIT,
			done   = &done,
		}
		threads[i] = thread.create_and_start_with_poly_data(&waiters[i], dial_caller)
	}
	for &w in waiters {
		for !sync.atomic_load(&w.started) {
			time.sleep(time.Millisecond)
		}
	}
	_ = sync.wait_group_wait_with_timeout(&done, DIAL)
	sync.mutex_lock(&u.mu)
	u.connecting = false
	loop.cond_broadcast(&u.conn_cond)
	sync.mutex_unlock(&u.mu)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	for w, i in waiters {
		testing.expectf(t, w.err == .Timeout, "%v: waiter %d ended as %v, expected a timeout", kind, i, w.err)
		testing.expectf(t, w.took >= WAIT, "%v: waiter %d with a budget of %v gave up after %v; it never waited", kind, i, WAIT, w.took)
		testing.expectf(t, w.took < DIAL, "%v: waiter %d with a budget of %v took %v; it waited the dial out", kind, i, WAIT, w.took)
	}
	dials := drain_dials(t, listener)
	testing.expectf(t, dials == 0, "%v: %d callers queued behind a dial made %d of their own", kind, WAITERS, dials)
}

/*
A caller that wakes to a finished dial with its deadline already behind it
returns rather than starting a dial of its own: the bound sits above the
`connecting` check, not only on the wait below it. A spent budget puts the
caller in that state without a race.

A caller with budget left then dials once, so a counter that sees nothing
cannot pass either test.
*/
@(test)
test_a_caller_past_its_deadline_starts_no_dial :: proc(t: ^testing.T) {
	for kind in QUEUED_KINDS {
		a_caller_past_its_deadline_starts_no_dial(t, kind)
	}
}

@(private = "file")
a_caller_past_its_deadline_starts_no_dial :: proc(t: ^testing.T, kind: config.Upstream_Kind) {
	listener, u, ok := mute_listener(t, kind)
	if !ok {
		return
	}
	defer net.close(listener)
	defer destroy(u)

	err := queue_once(u, 0)
	testing.expectf(t, err == .Timeout, "%v: a spent budget ended as %v", kind, err)
	dials := drain_dials(t, listener)
	testing.expectf(t, dials == 0, "%v: a caller past its deadline made %d dials", kind, dials)

	err = queue_once(u, 100 * time.Millisecond)
	testing.expectf(t, err == .Timeout, "%v: a mute peer ended as %v", kind, err)
	dials = drain_dials(t, listener)
	testing.expectf(t, dials == 1, "%v: a caller with budget left made %d dials, expected 1", kind, dials)
}
