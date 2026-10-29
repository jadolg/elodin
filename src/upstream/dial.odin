package upstream

import "core:c"
import "core:net"
import "core:sys/linux"
import "core:sys/posix"
import "core:time"
import "elodin:loop"
import "elodin:tlsx"

/*
Connect with a deadline.

core:net's dial has no timeout, and SO_SNDTIMEO does not apply to connect(), so
a black-holed upstream would tie up the query for the kernel's full SYN retry
budget (over two minutes on Linux). That defeats the point of having fallback
upstreams, so the connect is done by hand: non-blocking connect, then a wait for
the socket to become writable - a park on a loop, `poll` anywhere else.

The socket stays non-blocking for the rest of the session. Every read and write
on it goes through `loop`'s socket calls or `tlsx`, both of which wait where a
blocking socket would have, for as long as its SO_RCVTIMEO or SO_SNDTIMEO says.
*/
dial_tcp_timeout :: proc(endpoint: net.Endpoint, timeout: time.Duration) -> (socket: net.TCP_Socket, err: Error) {
	family: posix.AF
	switch _ in endpoint.address {
	case net.IP4_Address:
		family = .INET
	case net.IP6_Address:
		family = .INET6
	case:
		return 0, .Dial_Failed
	}

	fd := posix.socket(family, .STREAM)
	if c.int(fd) < 0 {
		return 0, .Dial_Failed
	}
	ok := false
	defer if !ok {
		posix.close(fd)
	}

	flags := posix.fcntl(fd, .GETFL)
	if flags < 0 {
		return 0, .Dial_Failed
	}
	if posix.fcntl(fd, .SETFL, flags | c.int(posix.O_NONBLOCK)) < 0 {
		return 0, .Dial_Failed
	}

	storage: posix.sockaddr_in6
	addr_len: posix.socklen_t
	fill_sockaddr(endpoint, &storage, &addr_len)

	res := posix.connect(fd, cast(^posix.sockaddr)&storage, addr_len)
	if res != .OK {
		if posix.errno() != .EINPROGRESS {
			return 0, .Dial_Failed
		}
		deadline := time.tick_add(time.tick_now(), max(timeout, time.Millisecond))
		switch loop.wait_fd(linux.Fd(fd), {.Out}, deadline) {
		case .Ready:
		case .Timeout, .Cancelled:
			return 0, .Timeout
		case .Failed:
			return 0, .Dial_Failed
		}
		so_err: c.int
		so_len := posix.socklen_t(size_of(so_err))
		if posix.getsockopt(fd, posix.SOL_SOCKET, .ERROR, &so_err, &so_len) != .OK {
			return 0, .Dial_Failed
		}
		if so_err != 0 {
			// A RST can land here instead of during the handshake purely on
			// scheduling luck - the peer had already reset by the time this
			// side got around to reading SO_ERROR. Reported the same as a
			// mid-handshake reset so the caller retries it the same way.
			if posix.Errno(so_err) == .ECONNRESET {
				return 0, .Dial_Reset
			}
			return 0, .Dial_Failed
		}
	}

	ok = true
	return net.TCP_Socket(fd), .None
}

@(private)
fill_sockaddr :: proc(endpoint: net.Endpoint, storage: ^posix.sockaddr_in6, out_len: ^posix.socklen_t) {
	switch a in endpoint.address {
	case net.IP4_Address:
		v4 := cast(^posix.sockaddr_in)storage
		v4^ = {}
		v4.sin_family = .INET
		v4.sin_port = posix.in_port_t(u16be(u16(endpoint.port)))
		bytes := a
		v4.sin_addr = transmute(posix.in_addr)bytes
		out_len^ = posix.socklen_t(size_of(posix.sockaddr_in))
	case net.IP6_Address:
		storage^ = {}
		storage.sin6_family = .INET6
		storage.sin6_port = posix.in_port_t(u16be(u16(endpoint.port)))
		groups := a
		bytes: [16]u8
		for g, i in groups {
			v := u16(g)
			bytes[i * 2] = u8(v >> 8)
			bytes[i * 2 + 1] = u8(v)
		}
		storage.sin6_addr = transmute(posix.in6_addr)bytes
		out_len^ = posix.socklen_t(size_of(posix.sockaddr_in6))
	}
}

/*
What a failed TLS handshake means to the group above.

A certificate that did not check out is a trust problem and stays distinct. A
handshake that ran out of time is a slow server, not a broken one, and reporting
it as `Timeout` keeps it alongside every other kind of upstream that was too
slow. Everything else - including a peer that reset the connection partway
through - is a TLS failure.
*/
@(private)
handshake_failure :: proc(terr: tlsx.Error) -> Error {
	#partial switch terr {
	case .Verify_Failed:
		return .Verify_Failed
	case .Timeout:
		return .Timeout
	}
	return .TLS_Failed
}

// Apply read and write deadlines to a connected socket. A non-zero timeout is
// never under a millisecond - a sliver of a deadline rounds to a zero
// `timeval`, and a negative one, a deadline already gone, reads back as zero,
// both of which the socket and `tlsx` take as no timeout at all - while zero
// stays zero, which is no timeout - a figure no configuration reaches, since the
// loader refuses an `upstream.timeout` under a millisecond (#499).
set_socket_timeouts :: proc(socket: net.Any_Socket, timeout: time.Duration) {
	bounded := max(timeout, time.Millisecond) if timeout != 0 else 0
	_ = net.set_option(socket, .Receive_Timeout, bounded)
	_ = net.set_option(socket, .Send_Timeout, bounded)
}
