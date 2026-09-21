package upstream

import "core:mem"
import "core:net"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
Plain DNS over UDP.

A truncated reply is retried over TCP to the same server, which is what a
forwarder is expected to do rather than passing TC=1 back to the client and
making it discover the problem itself.
*/
@(private)
exchange_udp :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	family := net.family_from_endpoint(u.endpoint)
	socket, serr := net.make_unbound_udp_socket(family)
	if serr != nil {
		return nil, .Dial_Failed
	}
	defer net.close(socket)
	set_socket_timeouts(socket, timeout)

	if _, send_err := net.send_udp(socket, query, u.endpoint); send_err != nil {
		return nil, .IO_Error
	}

	/*
	Sized from what the query itself advertised, not from a fixed number.

	A responder may fill whatever room the OPT record offered it, so the buffer
	has to hold whatever this query asked for. A buffer smaller than that figure
	turns a perfectly good answer into a failure: Linux reports the shortfall
	rather than hiding it, which lands in the error path below, and three of
	those in a row park a healthy upstream for the cooldown.

	Read off the query rather than assumed, and the callers are what keep it
	small: every query the server forwards has had this field clamped into
	[512, `UPSTREAM_UDP_SIZE`] on the way out, so the *ceiling* is ours even
	where the number itself is still the client's smaller one. A client can
	therefore lower this buffer and nothing else about it. The clamp below is
	the floor and the wire's own ceiling rather than a policy - `bootstrap_query`
	builds a query with no OPT record at all and lands on the floor, and a query
	built by hand asking for more would be honoured and would cost this one
	buffer.

	One byte over, so a datagram that ignores the advertised size is
	recognisable rather than merely truncated.
	*/
	limit := clamp(int(dns.peek_udp_size(query)), dns.MAX_UDP_SIZE, dns.MAX_MESSAGE)
	buf := make([]u8, limit + 1, context.temp_allocator)
	deadline := time.time_add(time.now(), timeout)

	/*
	Whether anything arrived from the server and was thrown away.

	The loop below passes over a datagram it will not accept and waits for the
	genuine reply, so a server whose every reply is being discarded - one that
	stopped echoing our cookie, or a middlebox rewriting the question - leaves
	exactly the same trace as one that never answered at all. That is the one
	failure an operator cannot tell apart from the outside, and it is the one
	where the fault is on this side of the wire. Reported as `Bad_Response`,
	which is what the TCP path already calls a reply it rejects.
	*/
	rejected := false

	for time.diff(deadline, time.now()) < 0 {
		n, remote, recv_err := net.recv_udp(socket, buf)
		if recv_err != nil {
			// The datagram was larger than the room the query offered, so what
			// arrived is a prefix of an answer. TCP is where the whole one is.
			if recv_err == .Excess_Truncated {
				return exchange_pipelined(u, query, timeout, allocator)
			}
			return nil, .Bad_Response if rejected else .Timeout
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		// Ignore anything that did not come from the server we asked.
		if remote.port != u.endpoint.port || !addresses_equal(remote.address, u.endpoint.address) {
			continue
		}
		// A forged datagram is passed over rather than reported: the genuine
		// reply may still be on its way, and the loop has until the deadline.
		if !response_accepted(u, query, buf[:n]) {
			rejected = true
			continue
		}

		flags := transmute(dns.Flags)(u16(buf[2]) << 8 | u16(buf[3]))
		if flags.tc {
			return exchange_pipelined(u, query, timeout, allocator)
		}
		out := make([]u8, n, allocator)
		copy(out, buf[:n])
		return out, .None
	}
	return nil, .Bad_Response if rejected else .Timeout
}

@(private)
addresses_equal :: proc(a, b: net.Address) -> bool {
	switch x in a {
	case net.IP4_Address:
		y, ok := b.(net.IP4_Address)
		return ok && x == y
	case net.IP6_Address:
		y, ok := b.(net.IP6_Address)
		return ok && x == y
	}
	return false
}

@(private)
write_all_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> Error {
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(socket, buf[sent:])
		if err != nil || n <= 0 {
			return .IO_Error
		}
		sent += n
	}
	return .None
}

@(private)
read_full_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> Error {
	got := 0
	for got < len(buf) {
		n, err := net.recv_tcp(socket, buf[got:])
		if err != nil || n <= 0 {
			return .IO_Error
		}
		got += n
	}
	return .None
}

/*
What a failed read or write on an established TLS session means above.

Three different things about the peer, and the caller acts on each of them
differently. A server that accepted the query and then said nothing until the
timeout is answering too slowly, or not answering this question at all. One
that closed or reset is recycling a connection, which every DNS-over-TCP server
does and which `record_failure` refuses to read as an outage. Anything else is
the transport itself. `exchange_pipelined` retries a shared connection found
dead, so what reaches the counters is a fresh connection failing - where the
distinction is the diagnosis.
*/
@(private)
roundtrip_failure :: proc(terr: tlsx.Error) -> Error {
	#partial switch terr {
	case .Timeout:
		return .Timeout
	case .Closed:
		return .Peer_Closed
	}
	return .IO_Error
}
