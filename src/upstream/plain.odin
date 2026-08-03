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

	A responder may fill whatever room the OPT record offered it, and this query
	is the client's own message forwarded verbatim — so the figure is the
	client's, and it goes as high as 65535. A buffer smaller than that figure
	turns a perfectly good answer into a failure: Linux reports the shortfall
	rather than hiding it, which lands in the error path below, and three of
	those in a row park a healthy upstream for the cooldown.

	One byte over, so a datagram that ignores the advertised size is
	recognisable rather than merely truncated.
	*/
	limit := clamp(int(dns.peek_udp_size(query)), dns.MAX_UDP_SIZE, dns.MAX_MESSAGE)
	buf := make([]u8, limit + 1, context.temp_allocator)
	deadline := time.time_add(time.now(), timeout)

	for time.diff(deadline, time.now()) < 0 {
		n, remote, recv_err := net.recv_udp(socket, buf)
		if recv_err != nil {
			// The datagram was larger than the room the query offered, so what
			// arrived is a prefix of an answer. TCP is where the whole one is.
			if recv_err == .Excess_Truncated {
				return exchange_tcp(u, query, timeout, allocator)
			}
			return nil, .Timeout
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
			continue
		}

		flags := transmute(dns.Flags)(u16(buf[2]) << 8 | u16(buf[3]))
		if flags.tc {
			return exchange_tcp(u, query, timeout, allocator)
		}
		out := make([]u8, n, allocator)
		copy(out, buf[:n])
		return out, .None
	}
	return nil, .Timeout
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

// Plain DNS over TCP, with the two-byte length prefix of RFC 1035 section 4.2.2.
@(private)
exchange_tcp :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	/*
	Try a pooled connection, then a fresh one.

	A resolver closes connections its client has left idle, so a pooled one is
	quite normally dead by the time it is picked up. That is not an upstream
	failure and must not be reported as one: a handful of them would trip the
	health cooldown and bench a server that is working.
	*/
	for attempt in 0 ..< 2 {
		conn: Idle_Conn
		reused := false
		if attempt == 0 {
			conn, reused = take_idle(u)
		}
		if !reused {
			socket, derr := dial_tcp_timeout(u.endpoint, timeout)
			if derr != .None {
				return nil, derr
			}
			set_socket_timeouts(socket, timeout)
			_ = net.set_option(socket, .TCP_Nodelay, true)
			conn = Idle_Conn {
				socket = socket,
			}
		}

		response, err = tcp_roundtrip(u, conn.socket, query, allocator)
		if err == .None {
			put_idle(u, conn)
			return response, .None
		}
		net.close(conn.socket)
		if !reused {
			return nil, err
		}
	}
	return nil, .IO_Error
}

@(private)
tcp_roundtrip :: proc(
	u: ^Upstream,
	socket: net.TCP_Socket,
	query: []u8,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	if len(query) > 0xffff {
		return nil, .Too_Large
	}
	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)

	if write_all_tcp(socket, framed) != .None {
		return nil, .IO_Error
	}

	length_buf: [2]u8
	if read_full_tcp(socket, length_buf[:]) != .None {
		return nil, .IO_Error
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE {
		return nil, .Bad_Response
	}

	out := make([]u8, length, allocator)
	if read_full_tcp(socket, out) != .None {
		delete(out, allocator)
		return nil, .IO_Error
	}
	if !response_accepted(u, query, out) {
		delete(out, allocator)
		return nil, .Bad_Response
	}
	return out, .None
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

// Open a fresh DoT connection. Dialling, the handshake and the retry that
// handshake gets are the HTTPS path's exactly, so they are shared with it.
@(private)
dial_dot :: proc(u: ^Upstream, timeout: time.Duration) -> (conn: Idle_Conn, err: Error) {
	stream := open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, timeout, u.spec.name) or_return
	return Idle_Conn{socket = stream.socket, tls = stream.tls}, .None
}

// DNS over TLS: the TCP framing above, carried inside a TLS session (RFC 7858).
@(private)
exchange_dot :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	// Pooled connection first, then a fresh one; see exchange_tcp for why a
	// dead pooled connection must not count as an upstream failure.
	for attempt in 0 ..< 2 {
		conn: Idle_Conn
		reused := false
		if attempt == 0 {
			conn, reused = take_idle(u)
		}
		if !reused {
			conn, err = dial_dot(u, timeout)
			if err != .None {
				return nil, err
			}
		}

		response, err = tls_roundtrip(conn.tls, query, allocator)
		if err == .None {
			put_idle(u, conn)
			return response, .None
		}
		tlsx.close(conn.tls)
		if !reused {
			return nil, err
		}
	}
	return nil, .IO_Error
}

@(private)
tls_roundtrip :: proc(conn: ^tlsx.Conn, query: []u8, allocator: mem.Allocator) -> (response: []u8, err: Error) {
	if len(query) > 0xffff {
		return nil, .Too_Large
	}
	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)

	if _, werr := tlsx.write(conn, framed); werr != .None {
		return nil, .IO_Error
	}

	length_buf: [2]u8
	if tlsx.read_full(conn, length_buf[:]) != .None {
		return nil, .IO_Error
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE {
		return nil, .Bad_Response
	}

	out := make([]u8, length, allocator)
	if tlsx.read_full(conn, out) != .None {
		delete(out, allocator)
		return nil, .IO_Error
	}
	if !response_matches(query, out) {
		delete(out, allocator)
		return nil, .Bad_Response
	}
	return out, .None
}
