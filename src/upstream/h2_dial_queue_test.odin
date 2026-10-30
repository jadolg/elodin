package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:h2"

/*
The DoH dial queue in `get_h2_conn` is bounded by each caller's own deadline,
counted in dials rather than in time (#378).

Against a peer that accepts and never speaks, the wall time of the queue is
the same whether the bound is there or not: the caller that comes out of the
queue past its deadline still dials, on the one millisecond floor, and that
dial ends at once. What it does leave behind is a connection. The listener here
never accepts, so the kernel finishes each TCP handshake into its backlog, the
ClientHello gets no answer, and the backlog drained afterwards is the number
of dials made.
*/
@(private = "file")
mute_listener :: proc(t: ^testing.T) -> (listener: net.TCP_Socket, u: ^Upstream, ok: bool) {
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
	uerr: Error
	u, uerr = make_upstream(
		config.Upstream_Spec {
			name = "mute",
			kind = .HTTPS,
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

// Every connection the kernel completed, all of them in the backlog by the
// time the callers that made them returned.
@(private = "file")
drain_dials :: proc(listener: net.TCP_Socket) -> (dials: int) {
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)
	for {
		c, _, err := net.accept_tcp(listener)
		if err != nil {
			return
		}
		net.close(c)
		dials += 1
	}
}

@(private = "file")
Dial_Caller :: struct {
	u:      ^Upstream,
	budget: time.Duration,
	took:   time.Duration,
	err:    Error,
}

@(private = "file")
dial_caller :: proc(c: ^Dial_Caller) {
	start := time.tick_now()
	conn, ok, err := get_h2_conn(c.u, 30 * time.Second, c.budget)
	c.took = time.tick_since(start)
	c.err = err
	if ok {
		h2.client_unref(conn)
	}
}

/*
Callers queued behind a dial that outlasts them give up at their own deadline
and dial nothing: one connection for the dialler, none for the three behind it.
Unbounded, each of them waits the dial out and then makes one of its own.
*/
@(test)
test_callers_queued_behind_a_doh_dial_keep_their_own_budget :: proc(t: ^testing.T) {
	DIAL :: time.Second
	WAIT :: 200 * time.Millisecond
	WAITERS :: 3

	listener, u, ok := mute_listener(t)
	if !ok {
		return
	}
	defer net.close(listener)
	defer destroy(u)

	dialler := Dial_Caller {
		u      = u,
		budget = DIAL,
	}
	dt := thread.create_and_start_with_poly_data(&dialler, dial_caller)
	// Queued only once the dial is under way, so each waiter's deadline falls
	// inside it.
	for {
		sync.mutex_lock(&u.mu)
		connecting := u.connecting
		sync.mutex_unlock(&u.mu)
		if connecting {
			break
		}
		thread.yield()
	}
	waiters: [WAITERS]Dial_Caller
	threads: [WAITERS]^thread.Thread
	for i in 0 ..< WAITERS {
		waiters[i] = Dial_Caller {
			u      = u,
			budget = WAIT,
		}
		threads[i] = thread.create_and_start_with_poly_data(&waiters[i], dial_caller)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	thread.join(dt)
	thread.destroy(dt)

	testing.expectf(t, dialler.err != .None, "the dial to a peer that never speaks ended as %v", dialler.err)
	for w, i in waiters {
		testing.expectf(t, w.err == .Timeout, "waiter %d ended as %v, expected a timeout", i, w.err)
		testing.expectf(t, w.took < DIAL, "waiter %d with a budget of %v took %v; it waited the dial out", i, WAIT, w.took)
	}
	dials := drain_dials(listener)
	testing.expectf(t, dials == 1, "%d dials for one dialler and %d callers queued behind it", dials, WAITERS)
}

/*
A caller that wakes to a finished dial with its deadline already behind it
returns rather than starting a dial of its own: the bound sits above the
`connecting` check, not only on the wait below it. A spent budget puts the
caller in that state without a race.
*/
@(test)
test_a_caller_past_its_deadline_starts_no_doh_dial :: proc(t: ^testing.T) {
	listener, u, ok := mute_listener(t)
	if !ok {
		return
	}
	defer net.close(listener)
	defer destroy(u)

	_, got, err := get_h2_conn(u, 30 * time.Second, 0)
	testing.expectf(t, !got && err == .Timeout, "a spent budget got a connection (%v) or ended as %v", got, err)
	dials := drain_dials(listener)
	testing.expectf(t, dials == 0, "a caller past its deadline made %d dials", dials)
}
