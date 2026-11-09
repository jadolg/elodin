package upstream

import "core:mem"
import "core:net"
import "core:sys/linux"
import "core:sys/posix"
import "core:time"
import "elodin:dns"
import "elodin:loop"
import "elodin:netx"
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
	deadline: time.Tick,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	endpoint := endpoint_of(u) or_return
	socket, opened := open_udp(endpoint)
	if !opened {
		return nil, .Dial_Failed
	}
	defer net.close(socket)

	if _, send_err := loop.send_udp_until(socket, query, deadline); send_err != nil {
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

	// Datagrams passed over arriving back to back - a spoofed flood at this port -
	// never let this query park; `loop.recv_udp_until` yields between them (see
	// `loop.take_turn`).
	for time.tick_diff(loop.tick_now(), deadline) > 0 {
		n, remote, recv_err := loop.recv_udp_until(socket, buf, deadline)
		if recv_err != nil {
			/*
			Anything but the deadline is TCP's to settle. `.Excess_Truncated`:
			the datagram was larger than the room the query offered, so what
			arrived is a prefix of an answer, and TCP is where the whole one is.

			Anything else is, in practice, an ICMP error the kernel matched to
			this connected socket (issue #622): a hard one in `__udp4_lib_err`'s
			terms - a destination unreachable `icmp_err_convert` marks fatal
			(port or protocol unreachable, an unknown or prohibited host or
			network), fragmentation needed, a parameter problem - since it keeps
			the soft ones, host and network unreachable among them, from a
			socket without IP_RECVERR. It is not the verdict: an off-path sender
			who guesses the source port can forge one, and acted on it would end
			the exchange and, three in a row, park the upstream for `COOLDOWN`.
			The same server asked over TCP gives one that cannot be forged that
			way: a closed port answers the SYN with a RST acknowledging our
			initial sequence number, which fails the dial at once as
			`Dial_Failed`, and a live one answers the query.

			A local failure of the read takes the same road, and costs a TCP
			exchange rather than a wrong verdict.

			So a forged ICMP buys its sender one query moved to the pipelined
			connection - never a connection of its own, and with that one full
			the query goes back to waiting on UDP - and,
			against a server whose TCP is refused or dropped, that query's
			failure, charged as its TCP's. RFC 7766 section 5 has every DNS
			server support TCP, and a TC answer from such a server fails the
			same way. RFCs are silent on what a forwarder does with the ICMP
			itself; PowerDNS Recursor fails the query and throttles the server
			on it, Unbound connects but ignores it and waits out the timeout.
			*/
			if recv_err != .Would_Block {
				icmp := recv_err != .Excess_Truncated
				tcp_response, tcp_err := exchange_pipelined(u, query, timeout, deadline, allocator, private = !icmp)
				/*
				Turned away from a full shared connection (see `get_pipe`): the
				server's TCP is up, so the ICMP was most likely not the
				server's, and the UDP answer may still be on its way. The
				error is reported once, so the read waits again, to the same
				deadline.
				*/
				if icmp && tcp_err == .Backlogged {
					continue
				}
				return tcp_response, tcp_err
			}
			return nil, .Bad_Response if rejected else .Timeout
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		// Ignore anything that did not come from the server we asked. The
		// connected socket has the kernel drop those already; this stays as
		// the check that does not depend on it.
		if remote.port != endpoint.port || !netx.addresses_equal(remote.address, endpoint.address) {
			continue
		}
		// A forged datagram is passed over rather than reported: the genuine
		// reply may still be on its way, and the loop has until the deadline.
		if !response_accepted(u, query, buf[:n]) {
			rejected = true
			continue
		}

		flags := transmute(dns.Flags)(u16(buf[2]) << 8 | u16(buf[3]))
		/*
		On what is left of the exchange, not a timeout of its own (issues #376,
		#449): a TC that arrives late leaves the retry little, and it fails as
		the timeout it is, rather than one exchange costing two.
		*/
		if flags.tc {
			return exchange_pipelined(u, query, timeout, deadline, allocator)
		}
		out := make([]u8, n, allocator)
		copy(out, buf[:n])
		return out, .None
	}
	return nil, .Bad_Response if rejected else .Timeout
}

/*
A socket of its own for one exchange with `endpoint`, bound by the kernel to a
random port at the connect: RFC 5452 section 9.2 asks for an unpredictable source
port, and a socket shared between queries would hold one port for all of them.
Non-blocking from its creation, so a wait for the answer parks a fiber rather
than a loop; its reads and writes wait to the exchange's deadline with
`loop.recv_udp_until` and `loop.send_udp_until` rather than a timeout option,
so what an exchange costs above the send and the answer is this, one epoll
registration and the close (#612).

Connected to `endpoint` (issue #622), for two things an unconnected socket
does not get. Without IP_RECVERR, Linux reports an ICMP hard error - port
unreachable, say, or administratively prohibited - only to a UDP socket that is
connected (`__udp4_lib_err`), so a closed port fails in a syscall rather than
at the deadline; what `exchange_udp` makes of that is there.
And the kernel delivers only datagrams from `endpoint`, so a spoofed answer from
any other address never reaches the read, and a probe of this port from one is
answered as a closed port would be - the ICMP side channel Unbound's
`udp-connect` (on by default) closes. PowerDNS Recursor connects its sockets too.

Every wait runs to the one deadline, not a timeout restarted per read: a datagram
passed over - a stray, a forgery - landing just before a fresh timeout ran out
would buy another whole one, and an off-path sender could double any exchange
(issue #446). On the tick clock, which an NTP step cannot move.
*/
@(private)
open_udp :: proc(endpoint: net.Endpoint) -> (net.UDP_Socket, bool) {
	domain := linux.Address_Family.INET if net.family_from_endpoint(endpoint) == .IP4 else .INET6
	fd, err := linux.socket(domain, .DGRAM, {.CLOEXEC, .NONBLOCK}, .UDP)
	if err != .NONE {
		return {}, false
	}
	// A UDP connect sends nothing: it fixes the peer, and binds the random port.
	storage: posix.sockaddr_in6
	addr_len: posix.socklen_t
	fill_sockaddr(endpoint, &storage, &addr_len)
	if posix.connect(posix.FD(fd), cast(^posix.sockaddr)&storage, addr_len) != .OK {
		linux.close(fd)
		return {}, false
	}
	return net.UDP_Socket(fd), true
}

@(private)
write_all_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> Error {
	// One call: `loop.send_tcp` writes the whole buffer or says why not.
	if _, err := loop.send_tcp(socket, buf); err != nil {
		return .IO_Error
	}
	return .None
}

@(private)
read_full_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> Error {
	got := 0
	for got < len(buf) {
		n, err := loop.recv_tcp(socket, buf[got:])
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
