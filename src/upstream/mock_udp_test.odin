package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"

/*
Bind a loopback UDP socket and report the endpoint it landed on.
*/
@(private)
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
Bind `m.socket` on loopback and start `serve` on a thread of its own. `M` is any
mock with a `socket` and a `stop` flag: the socket's receive gives up every 50ms,
which is how `serve` sees `stop`. The caller ends it with `stop_udp_mock`. On a
failed start nothing is left to stop, and `m.socket` is not set: a zero socket
is fd 0, another test's under `odin test`.
*/
@(private)
serve_udp_mock :: proc(t: ^testing.T, m: ^$M, serve: proc(_: ^M)) -> (bound: net.Endpoint, worker: ^thread.Thread, ok: bool) {
	socket: net.UDP_Socket
	socket, bound = bind_loopback_udp(t) or_return
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)
	return bound, thread.create_and_start_with_poly_data(m, serve), true
}

// `serve_udp_mock`, and a UDP upstream named `name` pointing at it.
@(private)
start_udp_mock :: proc(
	t: ^testing.T,
	m: ^$M,
	serve: proc(_: ^M),
	name := "mock",
	timeout := time.Second,
	cookies := false,
) -> (
	u: ^Upstream,
	worker: ^thread.Thread,
	ok: bool,
) {
	bound: net.Endpoint
	bound, worker = serve_udp_mock(t, m, serve) or_return
	err: Error
	u, err = make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		timeout,
		context.allocator,
		cookies = cookies,
	)
	if !testing.expectf(t, err == .None, "cannot build the upstream %s: %v", name, err) {
		stop_udp_mock(m, worker)
		return nil, nil, false
	}
	return u, worker, true
}

// Ends what `serve_udp_mock` or `start_udp_mock` started, and destroys `u` if
// one is given.
@(private)
stop_udp_mock :: proc(m: ^$M, worker: ^thread.Thread, u: ^Upstream = nil) {
	sync.atomic_store(&m.stop, true)
	thread.join(worker)
	thread.destroy(worker)
	net.close(m.socket)
	if u != nil {
		destroy(u)
	}
}

/*
A UDP upstream named `name` in front of a socket bound and never read: a member
that does not answer, which is a timeout. Closed, the port would refuse (issue
#622), so the caller holds `socket` open until it is done and then closes it.
*/
@(private)
silent_upstream :: proc(
	t: ^testing.T,
	name: string,
	timeout := time.Second,
) -> (
	u: ^Upstream,
	socket: net.UDP_Socket,
	ok: bool,
) {
	bound: net.Endpoint
	socket, bound = bind_loopback_udp(t) or_return
	err: Error
	u, err = make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		timeout,
		context.allocator,
	)
	if !testing.expectf(t, err == .None, "cannot build the upstream %s: %v", name, err) {
		net.close(socket)
		return nil, {}, false
	}
	return u, socket, true
}

// Returns once `stop` is set: a mock holding its connection open until the test
// is done with it.
@(private)
hold_until_stop :: proc(stop: ^bool) {
	for !sync.atomic_load(stop) {
		time.sleep(10 * time.Millisecond)
	}
}

// A failover group over `servers`, which the caller owns.
@(private)
failover_group :: proc(servers: []^Upstream, timeout := time.Second, attempts := 1) -> Group {
	return Group{servers = servers, strategy = .Failover, timeout = timeout, attempts = attempts, allocator = context.allocator}
}
