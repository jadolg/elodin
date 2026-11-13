package upstream

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

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
	worker = thread.create_and_start_with_poly_data(m, serve)
	if !testing.expect(t, worker != nil, "cannot start the responder") {
		net.close(socket)
		m.socket = {}
		return {}, nil, false
	}
	return bound, worker, true
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

// Answers every query by echoing it back as a response after `delay`, or reads
// it and says nothing when `mute` is set. Counts what it was asked either way.
@(private)
Echo_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	mute:   bool,
	delay:  time.Duration,
	// The header rcode of the echo, NOERROR unless set.
	rcode:  u8,
	hits:   int,
}

@(private)
echo_mock_loop :: proc(m: ^Echo_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		if m.mute {
			continue
		}
		if m.delay > 0 {
			time.sleep(m.delay)
		}
		buf[2] |= 0x80
		buf[3] = 0x80 | (buf[3] & 0x70) | (m.rcode & 0xf)
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

/*
UDP `port` on loopback held, but refusing: bound, so no other socket can be
handed it while a test runs, and connected to a peer that never sends, so a
datagram from anyone else matches no socket and draws ICMP port unreachable -
the closed port, without releasing it for a parallel test to take.
*/
@(private)
refusing_udp :: proc(t: ^testing.T, port: int) -> (linux.Fd, bool) {
	fd, err := linux.socket(.INET, .DGRAM, {.CLOEXEC}, .UDP)
	if !testing.expectf(t, err == .NONE, "cannot open a udp socket: %v", err) {
		return -1, false
	}
	at := linux.Sock_Addr_In{sin_family = .INET, sin_port = u16be(u16(port)), sin_addr = {127, 0, 0, 1}}
	peer := linux.Sock_Addr_In{sin_family = .INET, sin_port = 9, sin_addr = {127, 0, 0, 1}}
	if berr := linux.bind(fd, &at); berr != .NONE {
		linux.close(fd)
		return -1, false
	}
	if cerr := linux.connect(fd, &peer); !testing.expectf(t, cerr == .NONE, "cannot connect the refusing socket: %v", cerr) {
		linux.close(fd)
		return -1, false
	}
	return fd, true
}

// A loopback port closed on UDP and on TCP, held for the test: a TCP socket
// bound and never listening answers a SYN with a RST. The caller closes both.
@(private)
Closed_Port :: struct {
	port: int,
	tcp:  linux.Fd,
	udp:  linux.Fd,
}

@(private)
closed_port :: proc(t: ^testing.T) -> (c: Closed_Port, ok: bool) {
	// The TCP port is the kernel's pick; its UDP twin is usually free too, and
	// a few picks find one that is.
	for _ in 0 ..< 16 {
		fd, err := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
		if !testing.expectf(t, err == .NONE, "cannot open a tcp socket: %v", err) {
			return
		}
		any := linux.Sock_Addr_In{sin_family = .INET, sin_addr = {127, 0, 0, 1}}
		bound: linux.Sock_Addr_Any
		if linux.bind(fd, &any) != .NONE || linux.getsockname(fd, &bound) != .NONE {
			linux.close(fd)
			continue
		}
		port := int(bound.sin_port)
		if udp, held := refusing_udp(t, port); held {
			return Closed_Port{port = port, tcp = fd, udp = udp}, true
		}
		linux.close(fd)
	}
	testing.expect(t, false, "no loopback port is free on both TCP and UDP")
	return
}

@(private)
release_port :: proc(c: Closed_Port) {
	linux.close(c.tcp)
	linux.close(c.udp)
}
