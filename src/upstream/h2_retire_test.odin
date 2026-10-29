package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:loop"
import "elodin:tlsx"

/*
Replacing a dead shared HTTP/2 connection must not wait for its reader on the
caller's time (#454). The reader only notices `stopping` once its poll
ticks, so the query that found the connection dead waited up to
H2_POLL_INTERVAL before it could dial, outside the deadline `exchange` is
held to.

The connection here is handed to the upstream the way `get_h2_conn` would,
over plain TCP to a listener that never accepts: the kernel completes the
handshake, so the reader sits in its poll with nothing to read. The upstream
itself points at a port nobody listens on, so the redial ends at once and
the time `get_h2_conn` takes is the time it spent on the old connection.
*/
@(private = "file")
dead_port :: proc(t: ^testing.T) -> (port: int, ok: bool) {
	l, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return 0, false
	}
	bound, _ := net.bound_endpoint(l)
	net.close(l)
	return bound.port, true
}

@(private = "file")
replace_dead_h2 :: proc(t: ^testing.T, reader_gone: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)
	port, pok := dead_port(t)
	if !pok {
		return
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "retire", kind = .TCP, address = "127.0.0.1", port = port, hostname = "doh.invalid", path = "/dns-query"},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial the listener: %v", derr) {
		return
	}
	// What `get_h2_conn` builds once ALPN says h2, minus the TLS.
	_ = net.set_option(socket, .Receive_Timeout, H2_POLL_INTERVAL)
	sync.mutex_lock(&u.mu)
	u.proto = .H2
	hc := start_h2_conn(u, Stream{socket = socket})
	u.h2 = hc
	sync.mutex_unlock(&u.mu)

	if reader_gone {
		// The reader's own way out, as when the peer hangs up: the connection
		// is then closed before anyone retires it, and the last reference is
		// the caller's rather than the reader's.
		_ = net.shutdown(socket, .Receive)
		for h2_readers_running(u) > 0 {
			time.sleep(time.Millisecond)
		}
	} else {
		// A writer finding the connection dead, which is what leaves the
		// reader still in its poll when the next caller comes to replace it.
		// Given time to get there first: a reader not yet in its read sees
		// `stopping` straight away, and the join cost nothing.
		time.sleep(50 * time.Millisecond)
		loop.lock(&hc.client.mu)
		hc.client.closed = true
		loop.unlock(&hc.client.mu)
		testing.expect(t, h2_readers_running(u) > 0, "the premise: the reader is still polling")
	}

	start := time.tick_now()
	// What the redial comes to is beside the point, and not asserted: tests
	// run in parallel, and another may have bound the freed port since. The
	// budget is short so a redial that does not fail at once cannot eat the
	// margin below.
	conn, _, _ := get_h2_conn(u, 200 * time.Millisecond, 20 * time.Millisecond)
	took := time.tick_since(start)
	testing.expect(t, conn == nil)
	testing.expectf(t, took < H2_POLL_INTERVAL / 4, "replacing the connection took %v", took)
	sync.mutex_lock(&u.mu)
	testing.expect(t, u.h2 == nil)
	sync.mutex_unlock(&u.mu)

	// Nor does the retired reader sit out its poll: with no join to throttle
	// replacements, each reader left polling would hold a fiber and a socket
	// for up to H2_POLL_INTERVAL, as many as the upstream can be dialled in
	// that time.
	for h2_readers_running(u) > 0 && time.tick_since(start) < H2_POLL_INTERVAL / 2 {
		time.sleep(time.Millisecond)
	}
	testing.expectf(t, h2_readers_running(u) == 0, "the retired reader was still polling after %v", time.tick_since(start))
}

@(test)
test_replacing_a_dead_h2_conn_does_not_wait_for_its_reader :: proc(t: ^testing.T) {
	replace_dead_h2(t, reader_gone = false)
}

@(test)
test_replacing_an_h2_conn_whose_reader_has_gone_frees_it :: proc(t: ^testing.T) {
	replace_dead_h2(t, reader_gone = true)
}

/*
A reader that has left is not counted any more, whichever way it left: retired
by the next connection, or ending on its own when the peer hangs up. A count
that only grew would hold `teardown_h2` - and with it a reload's release of the
group - for good.
*/
@(test)
test_finished_h2_readers_leave_no_count_behind :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "reap", kind = .TCP, address = "127.0.0.1", port = bound.port, hostname = "doh.invalid", path = "/dns-query"},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	for _ in 0 ..< 4 {
		socket, derr := dial_tcp_timeout(bound, time.Second)
		if !testing.expectf(t, derr == .None, "cannot dial the listener: %v", derr) {
			return
		}
		sync.mutex_lock(&u.mu)
		old := u.h2
		u.h2 = start_h2_conn(u, Stream{socket = socket})
		sync.mutex_unlock(&u.mu)
		if old != nil {
			retire_h2_conn(old)
		}
		_ = net.shutdown(socket, .Receive)
		start := time.tick_now()
		for h2_readers_running(u) > 0 && time.tick_since(start) < 3 * time.Second {
			time.sleep(time.Millisecond)
		}
	}
	testing.expect_value(t, h2_readers_running(u), 0)
}

// Readers counted against `u` and not yet gone.
h2_readers_running :: proc(u: ^Upstream) -> int {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	return u.h2_readers
}

@(private = "file")
Close_Notify_Peer :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	// How the peer's reading ended: `.Closed` for a close_notify, an error
	// for a bare EOF.
	ended:    tlsx.Error,
}

@(private = "file")
read_until_closed :: proc(p: ^Close_Notify_Peer) {
	p.ended = .IO_Error
	socket, _, aerr := net.accept_tcp(p.listener)
	if aerr != nil {
		return
	}
	_ = net.set_option(socket, .Receive_Timeout, 3 * time.Second)
	conn, terr := tlsx.server_accept(p.ctx, socket)
	if terr != .None {
		net.close(socket)
		return
	}
	defer tlsx.close(conn)
	buf: [1024]u8
	for {
		if _, err := tlsx.read(conn, buf[:]); err != .None {
			p.ended = err
			return
		}
	}
}

/*
Every h2 upstream is TLS, and retiring one shuts its socket down to wake the
reader. With nothing sent first, the reader's EOF is a fatal error that stops
`tlsx.close` sending close_notify (RFC 8446 6.1), and the alert that error
writes onto the shut side raised SIGPIPE, which kills a process that has not
ignored it.
*/
@(test)
test_retiring_a_tls_h2_conn_sends_close_notify :: proc(t: ^testing.T) {
	sync.once_do(&dot_cert_once, generate_dot_certs)
	if !testing.expect(t, dot_cert_ok, "no certificate available and openssl could not make one") {
		return
	}
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)
	sctx, serr := tlsx.server_context(dot_cert_path, dot_key_path)
	if !testing.expectf(t, serr == .None, "server_context: %v", serr) {
		return
	}
	defer tlsx.context_destroy(sctx)
	cctx, cerr := tlsx.client_context(false)
	if !testing.expectf(t, cerr == .None, "client_context: %v", cerr) {
		return
	}
	defer tlsx.context_destroy(cctx)

	peer := Close_Notify_Peer {
		listener = listener,
		ctx      = sctx,
	}
	peer_thread := thread.create_and_start_with_poly_data(&peer, read_until_closed)
	defer {
		// A return before `open_stream` connected leaves the peer in `accept`,
		// and the join would hang the run instead of failing it.
		if !thread.is_done(peer_thread) {
			if s, err := net.dial_tcp(bound); err == nil {
				net.close(s)
			}
		}
		thread.destroy(peer_thread)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "notify", kind = .TCP, address = "127.0.0.1", port = bound.port, hostname = "doh.invalid", path = "/dns-query"},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	stream, oerr := open_stream(bound, cctx, "", 2 * time.Second)
	if !testing.expectf(t, oerr == .None, "open_stream: %v", oerr) {
		return
	}
	// What `get_h2_conn` sets once ALPN says h2.
	_ = net.set_option(stream.socket, .Receive_Timeout, H2_POLL_INTERVAL)
	tlsx.set_timeouts(stream.tls, H2_POLL_INTERVAL, time.Second)
	sync.mutex_lock(&u.mu)
	hc := start_h2_conn(u, stream)
	sync.mutex_unlock(&u.mu)

	// In its poll, as in `replace_dead_h2`.
	time.sleep(50 * time.Millisecond)
	retire_h2_conn(hc)
	thread.join(peer_thread)
	testing.expect_value(t, peer.ended, tlsx.Error.Closed)
	for h2_readers_running(u) > 0 {
		time.sleep(time.Millisecond)
	}
}

/*
A reader on a loop that is told to stop leaves, rather than spinning.

Its read waits `H2_POLL_INTERVAL` and goes round again on a timeout, which is how
a long-lived connection sits through quiet. A cancelled fiber's every wait
returns at once, as a timeout does, so a reader that went round on that too
would spin on its loop for ever and the loop - waiting for its last fiber - would
never stop. The loop is stopped the way the server stops it, with
`loop.cancel_all`; the wait for it to finish is bounded only so a failing run
reports rather than hangs.
*/
@(test)
test_a_cancelled_h2_reader_leaves_its_loop :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "cancelled", kind = .TCP, address = "127.0.0.1", port = bound.port, hostname = "doh.invalid", path = "/dns-query"},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	l, made := loop.make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	th := loop.spawn_thread(l, loop.run, context)
	Start :: struct {
		u:       ^Upstream,
		port:    int,
		started: sync.Sema,
		ok:      bool,
	}
	st := Start {
		u    = u,
		port = bound.port,
	}
	// Started from a fiber of the loop, so the reader is one of its fibers.
	_, _ = loop.spawn(l, proc(data: rawptr) {
		st := (^Start)(data)
		defer sync.sema_post(&st.started)
		socket, derr := dial_tcp_timeout(net.Endpoint{address = net.IP4_Loopback, port = st.port}, time.Second)
		if derr != .None {
			return
		}
		_ = net.set_option(socket, .Receive_Timeout, H2_POLL_INTERVAL)
		sync.mutex_lock(&st.u.mu)
		st.u.proto = .H2
		st.u.h2 = start_h2_conn(st.u, Stream{socket = socket})
		sync.mutex_unlock(&st.u.mu)
		st.ok = true
	}, &st)
	testing.expect(t, sync.sema_wait_with_timeout(&st.started, 5 * time.Second), "the dial never ran")
	if !testing.expect(t, st.ok, "could not start the connection") {
		loop.stop(l)
		thread.join(th)
		thread.destroy(th)
		loop.destroy(l)
		return
	}
	// The premise: a reader on the loop, waiting in its read.
	testing.expect(t, h2_readers_running(u) == 1, "no reader is running on the loop")

	Stopper :: struct {
		l:    ^loop.Loop,
		th:   ^thread.Thread,
		done: sync.Sema,
	}
	stopper := Stopper {
		l  = l,
		th = th,
	}
	waiter := thread.create_and_start_with_poly_data(&stopper, proc(s: ^Stopper) {
		loop.cancel_all(s.l)
		loop.stop(s.l)
		thread.join(s.th)
		sync.sema_post(&s.done)
	})
	if !testing.expect(t, sync.sema_wait_with_timeout(&stopper.done, 5 * time.Second), "the loop never stopped: its reader is still running") {
		return
	}
	thread.join(waiter)
	thread.destroy(waiter)
	thread.destroy(th)
	loop.destroy(l)
	testing.expect_value(t, h2_readers_running(u), 0)
}
