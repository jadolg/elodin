package upstream

import "core:fmt"
import "core:net"
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

// A loopback port closed on both UDP and TCP: bound on each, then released.
@(private = "file")
closed_port :: proc(t: ^testing.T) -> (port: int, ok: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return 0, false
	}
	bound, _ := net.bound_endpoint(listener)
	udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, bound.port)
	net.close(listener)
	if !testing.expectf(t, uerr == nil, "cannot bind udp/%d: %v", bound.port, uerr) {
		return 0, false
	}
	net.close(udp)
	return bound.port, true
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
	port, ok := closed_port(t)
	if !ok {
		return
	}

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

// Answers one query over TCP with the query itself, QR set.
@(private = "file")
echo_tcp_once :: proc(listener: net.TCP_Socket) {
	client, _, err := net.accept_tcp(listener)
	if err != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, R_TIMEOUT)
	frame: [2 + 512]u8
	if read_full_tcp(client, frame[:2]) != .None {
		return
	}
	n := int(frame[0]) << 8 | int(frame[1])
	if n < dns.HEADER_SIZE || n > len(frame) - 2 || read_full_tcp(client, frame[2:][:n]) != .None {
		return
	}
	frame[2 + 2] |= 0x80 // QR
	_, _ = net.send_tcp(client, frame[:2 + n])
}

/*
The refusal is not taken on its word. What a forged ICMP looks like from this
side - a refusal from a server that is in fact answering - is a closed UDP port
in front of an open TCP one: the query is answered over TCP, and nothing is
charged against the upstream's health.
*/
@(test)
test_a_udp_refusal_is_checked_over_tcp :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	bound, _ := net.bound_endpoint(listener)
	_ = net.set_option(listener, .Receive_Timeout, R_TIMEOUT)
	// Bound and released, so nothing holds udp/<port> as the query is sent.
	udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, bound.port)
	if !testing.expectf(t, uerr == nil, "cannot bind udp/%d: %v", bound.port, uerr) {
		net.close(listener)
		return
	}
	net.close(udp)

	u, built := udp_upstream(t, bound.port)
	if !built {
		net.close(listener)
		return
	}
	answerer := thread.create_and_start_with_poly_data(listener, echo_tcp_once)
	defer {
		net.close(listener)
		thread.join(answerer)
		thread.destroy(answerer)
		destroy(u)
	}

	query := refused_query()
	started := time.tick_now()
	resp, err := exchange(u, query, R_TIMEOUT, context.temp_allocator)
	spent := time.tick_since(started)
	testing.expectf(t, err == .None, "the exchange ended %v, where the server answers over TCP", err)
	testing.expectf(t, len(resp) == len(query), "the answer is %d bytes, not the %d echoed", len(resp), len(query))
	testing.expectf(t, spent < R_TIMEOUT / 2, "the exchange took %v, where a refusal is a syscall", spent)
	testing.expect(t, healthy(u), "a refusal the server contradicted was charged against it")
	free_all(context.temp_allocator)
}

/*
The bootstrap query waits past the refusal: it has no TCP path to check one on,
and a forged ICMP that ended it would decide where the upstream's queries go.
The assertion is a lower bound on the wait, which a slow machine only lengthens.
*/
@(test)
test_a_bootstrap_query_waits_past_a_refusal :: proc(t: ^testing.T) {
	port, ok := closed_port(t)
	if !ok {
		return
	}
	WAIT :: 200 * time.Millisecond
	server := fmt.tprintf("127.0.0.1:%d", port)
	started := time.tick_now()
	_, found := bootstrap_query(server, "example.com.", .A, WAIT)
	spent := time.tick_since(started)
	testing.expect(t, !found, "a closed bootstrap port produced an address")
	testing.expectf(t, spent >= WAIT, "the bootstrap query ended after %v, on a refusal, before its %v", spent, WAIT)
	free_all(context.temp_allocator)
}
