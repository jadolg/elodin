package upstream

import "core:fmt"
import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A UDP upstream whose port is closed fails in a syscall, not at the timeout
(issue #622).

The kernel answers a datagram to a closed port with ICMP port unreachable, and
Linux hands that to a UDP socket only if it is connected. The ICMP itself is
forgeable by anyone who can guess the exchange's source port, so it is not the
verdict: the same server is asked over TCP, where a closed port answers the SYN
with a RST an off-path sender cannot forge, and a live one answers the query.
*/

@(private = "file")
R_TIMEOUT :: 2 * time.Second

/*
UDP `port` on loopback held, but refusing: bound, so no other socket can be
handed it while a test runs, and connected to a peer that never sends, so a
datagram from anyone else matches no socket and draws ICMP port unreachable -
the closed port, without releasing it for a parallel test to take.
*/
@(private = "file")
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
@(private = "file")
Closed_Port :: struct {
	port: int,
	tcp:  linux.Fd,
	udp:  linux.Fd,
}

@(private = "file")
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

@(private = "file")
release_port :: proc(c: Closed_Port) {
	linux.close(c.tcp)
	linux.close(c.udp)
}

@(private = "file")
refused_query :: proc() -> []u8 {
	query := dns.Message {
		id       = 0x6220,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, _ := dns.encode_message(query, context.temp_allocator)
	return wire
}

@(private = "file")
udp_upstream :: proc(t: ^testing.T, port: int) -> (^Upstream, bool) {
	u, err := make_upstream(
		config.Upstream_Spec{name = "refused", kind = .UDP, address = "127.0.0.1", port = port},
		0,
		R_TIMEOUT,
		context.allocator,
	)
	return u, testing.expectf(t, err == .None, "cannot build the upstream: %v", err)
}

@(test)
test_a_refused_udp_upstream_fails_at_once :: proc(t: ^testing.T) {
	closed, ok := closed_port(t)
	if !ok {
		return
	}
	defer release_port(closed)
	port := closed.port

	// The premise: the platform reports the refusal to a connected socket.
	fd, serr := linux.socket(.INET, .DGRAM, {.CLOEXEC}, .UDP)
	if !testing.expectf(t, serr == .NONE, "cannot open a probe socket: %v", serr) {
		return
	}
	defer linux.close(fd)
	to := linux.Sock_Addr_In {
		sin_family = .INET,
		sin_port   = u16be(u16(port)),
		sin_addr   = {127, 0, 0, 1},
	}
	testing.expect_value(t, linux.connect(fd, &to), linux.Errno.NONE)
	probe: [4]u8
	_, _ = linux.send(fd, probe[:], {})
	tv := linux.Time_Val{seconds = 1}
	_ = linux.setsockopt(fd, linux.SOL_SOCKET, linux.Socket_Option.RCVTIMEO, &tv)
	_, rerr := linux.recv(fd, probe[:], {})
	if !testing.expectf(t, rerr == .ECONNREFUSED, "a connected probe to the closed port read %v, not a refusal", rerr) {
		return
	}

	u, built := udp_upstream(t, port)
	if !built {
		return
	}
	defer destroy(u)
	started := time.tick_now()
	resp, err := exchange(u, refused_query(), R_TIMEOUT, context.temp_allocator)
	spent := time.tick_since(started)
	// Refused over TCP as well, which is the verdict, and long before the timeout.
	testing.expectf(t, err == .Dial_Failed, "the exchange ended %v (%d bytes), not as a refused dial", err, len(resp))
	testing.expectf(t, spent < R_TIMEOUT / 2, "the exchange took %v, where a refusal is a syscall", spent)
	free_all(context.temp_allocator)
}

/*
Takes one connection and answers every query on it with the query itself, QR
set, until it is closed. Anything dialled after it waits in the backlog,
unanswered.
*/
@(private = "file")
echo_tcp_serve :: proc(listener: net.TCP_Socket) {
	client, _, err := net.accept_tcp(listener)
	if err != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 5 * R_TIMEOUT)
	for {
		frame: [2 + 512]u8
		if read_full_tcp(client, frame[:2]) != .None {
			return
		}
		n := int(frame[0]) << 8 | int(frame[1])
		if n < dns.HEADER_SIZE || n > len(frame) - 2 || read_full_tcp(client, frame[2:][:n]) != .None {
			return
		}
		frame[2 + 2] |= 0x80 // QR
		if _, serr := net.send_tcp(client, frame[:2 + n]); serr != nil {
			return
		}
	}
}

// A UDP upstream on a port refusing on UDP and open on TCP, with
// `echo_tcp_serve` behind it. The caller calls `stop_echo`.
@(private = "file")
Echo_Fixture :: struct {
	listener: net.TCP_Socket,
	udp:      linux.Fd,
	u:        ^Upstream,
	answerer: ^thread.Thread,
}

@(private = "file")
start_echo :: proc(t: ^testing.T) -> (f: Echo_Fixture, ok: bool) {
	for _ in 0 ..< 16 {
		listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
		if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
			return
		}
		bound, _ := net.bound_endpoint(listener)
		udp, held := refusing_udp(t, bound.port)
		if !held {
			net.close(listener)
			continue
		}
		_ = net.set_option(listener, .Receive_Timeout, R_TIMEOUT)
		u, built := udp_upstream(t, bound.port)
		if !built {
			net.close(listener)
			linux.close(udp)
			return
		}
		answerer := thread.create_and_start_with_poly_data(listener, echo_tcp_serve)
		return Echo_Fixture{listener = listener, udp = udp, u = u, answerer = answerer}, true
	}
	testing.expect(t, false, "no loopback port is free on both TCP and UDP")
	return
}

// The upstream first: closing its connection is what ends the answerer's read.
@(private = "file")
stop_echo :: proc(f: ^Echo_Fixture) {
	destroy(f.u)
	thread.join(f.answerer)
	thread.destroy(f.answerer)
	net.close(f.listener)
	linux.close(f.udp)
}

/*
The refusal is not taken on its word. What a forged ICMP looks like from this
side - a refusal from a server that is in fact answering - is a closed UDP port
in front of an open TCP one: the query is answered over TCP, and nothing is
charged against the upstream's health.
*/
@(test)
test_a_udp_refusal_is_checked_over_tcp :: proc(t: ^testing.T) {
	f, ok := start_echo(t)
	if !ok {
		return
	}
	defer stop_echo(&f)

	query := refused_query()
	started := time.tick_now()
	resp, err := exchange(f.u, query, R_TIMEOUT, context.temp_allocator)
	spent := time.tick_since(started)
	testing.expectf(t, err == .None, "the exchange ended %v, where the server answers over TCP", err)
	testing.expectf(t, len(resp) == len(query), "the answer is %d bytes, not the %d echoed", len(resp), len(query))
	testing.expectf(t, spent < R_TIMEOUT / 2, "the exchange took %v, where a refusal is a syscall", spent)
	// Not `healthy`, which holds until `FAILURE_THRESHOLD` failures and could not see one.
	failures := stats_of(f.u).failures
	testing.expectf(t, failures == 0, "a refusal the server contradicted was charged against it: %d failures", failures)
	free_all(context.temp_allocator)
}

/*
And past a full shared connection the check neither dials a connection of its
own nor gives up: a spray of forged ICMP reaches every exchange in flight at
once, and a connection each would turn them into a TCP handshake apiece against
the upstream, where a full connection already says the server's TCP is there.
So the exchange goes back to waiting for its UDP answer, which here never comes
- the port refuses - and it ends at its deadline. The shared connection is made
full by lowering its limit to zero once it is open.
*/
@(test)
test_a_udp_refusal_waits_on_udp_past_a_full_connection :: proc(t: ^testing.T) {
	f, ok := start_echo(t)
	if !ok {
		return
	}
	defer stop_echo(&f)

	_, first := exchange(f.u, refused_query(), R_TIMEOUT, context.temp_allocator)
	if !testing.expectf(t, first == .None, "the first exchange ended %v, so there is no shared connection", first) {
		return
	}
	sync.atomic_store(&f.u.max_outstanding, 0)
	WAIT :: 300 * time.Millisecond
	started := time.tick_now()
	_, err := exchange(f.u, refused_query(), WAIT, context.temp_allocator)
	spent := time.tick_since(started)
	testing.expectf(t, err == .Timeout, "the exchange ended %v, not waiting out its UDP answer", err)
	testing.expectf(t, spent >= WAIT, "the exchange ended after %v, before its %v", spent, WAIT)

	// A connection of its own would be waiting in the backlog by now, since the
	// answerer is busy with the shared one.
	_ = net.set_option(f.listener, .Receive_Timeout, 10 * time.Millisecond)
	if extra, _, aerr := net.accept_tcp(f.listener); aerr == nil {
		net.close(extra)
		testing.expect(t, false, "the check dialled a connection of its own past the full one")
	}
	free_all(context.temp_allocator)
}

/*
The bootstrap query waits past the refusal: it has no TCP path to check one on,
and a forged ICMP that ended it would decide where the upstream's queries go.
The assertion is a lower bound on the wait, which a slow machine only lengthens.
*/
@(test)
test_a_bootstrap_query_waits_past_a_refusal :: proc(t: ^testing.T) {
	closed, ok := closed_port(t)
	if !ok {
		return
	}
	defer release_port(closed)
	port := closed.port
	WAIT :: 200 * time.Millisecond
	server := fmt.tprintf("127.0.0.1:%d", port)
	started := time.tick_now()
	_, found := bootstrap_query(server, "example.com.", .A, WAIT)
	spent := time.tick_since(started)
	testing.expect(t, !found, "a closed bootstrap port produced an address")
	testing.expectf(t, spent >= WAIT, "the bootstrap query ended after %v, on a refusal, before its %v", spent, WAIT)
	free_all(context.temp_allocator)
}
