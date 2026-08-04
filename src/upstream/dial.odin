package upstream

import "core:c"
import "core:net"
import "core:sys/posix"
import "core:time"
import "elodin:tlsx"

/*
Connect with a deadline.

core:net's dial has no timeout, and SO_SNDTIMEO does not apply to connect(), so
a black-holed upstream would tie up a worker for the kernel's full SYN retry
budget (over two minutes on Linux). That defeats the point of having fallback
upstreams, so the connect is done by hand: non-blocking connect, poll, then back
to blocking mode for the rest of the session.
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
		fds := [1]posix.pollfd{{fd = fd, events = {.OUT}}}
		ms := c.int(timeout / time.Millisecond)
		if ms <= 0 {
			ms = 1
		}
		n := posix.poll(raw_data(fds[:]), 1, ms)
		if n == 0 {
			return 0, .Timeout
		}
		if n < 0 {
			return 0, .Dial_Failed
		}

		// poll() reporting writability does not mean the connect succeeded;
		// SO_ERROR carries the verdict.
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

	if posix.fcntl(fd, .SETFL, flags) < 0 {
		return 0, .Dial_Failed
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

// Apply read and write deadlines to a connected socket.
set_socket_timeouts :: proc(socket: net.Any_Socket, timeout: time.Duration) {
	_ = net.set_option(socket, .Receive_Timeout, timeout)
	_ = net.set_option(socket, .Send_Timeout, timeout)
}
