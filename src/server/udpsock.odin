package server

import "core:net"
import "core:sys/posix"
import "elodin:logx"

/*
The two socket options the UDP listener needs and `core:net` will not set.

`net.set_option` knows the name `Reuse_Port` and refuses it - the option is in
its enum and not in the switch that implements one - and it sets
`Receive_Buffer_Size` without saying what the kernel granted, which is the half
of that setting worth reporting. Both go through `setsockopt` directly, which is
what `core:net` does underneath in any case.

`SO_REUSEPORT` is not in `core:sys/posix` either, since POSIX does not define
it. The numbers are the platform's own and are stable ABI: changing one would
break every compiled program on the system.
*/
when ODIN_OS == .Linux {
	@(private)
	SO_REUSEPORT :: 15
} else when ODIN_OS == .Darwin || ODIN_OS == .FreeBSD || ODIN_OS == .NetBSD || ODIN_OS == .OpenBSD {
	@(private)
	SO_REUSEPORT :: 0x0200
}

/*
Let this socket share its port with the other readers'.

Set before the bind, which is where it has to be: the kernel decides whether a
port may be shared when it is asked for, so a socket that binds without this
holds the port alone whatever is set afterwards.

Every socket sharing a port must have been bound by the same effective uid, so
what this opens is available to whoever can already run as this server's user.
*/
@(private)
set_reuse_port :: proc(socket: net.UDP_Socket) -> bool {
	on: b32 = true
	res := posix.setsockopt(
		posix.FD(socket),
		i32(posix.SOL_SOCKET),
		posix.Sock_Option(SO_REUSEPORT),
		&on,
		posix.socklen_t(size_of(on)),
	)
	if res != .OK {
		logx.errorf(
			"listeners.udp: the kernel refused SO_REUSEPORT (%v), so the readers cannot share a port",
			posix.errno(),
		)
		return false
	}
	return true
}

/*
Ask for a receive buffer, and report what the kernel granted.

Reported rather than assumed because the request is a request: Linux clamps it
to `net.core.rmem_max`, which is 208 KiB on a machine nobody has tuned, so a
server that printed what it asked for would be claiming a burst tolerance an
order of magnitude past what it has.

Linux reports back twice what it set aside, the second half being its own
per-datagram bookkeeping rather than room for data, so the figure is halved to
get back to something comparable with what was asked for. Elsewhere the value
is returned as it was set.

0 means the kernel would not say, which the caller reports as nothing rather
than as a size.
*/
@(private)
set_receive_buffer :: proc(socket: net.UDP_Socket, bytes: int) -> (granted: int) {
	want := i32(bytes)
	if posix.setsockopt(
		   posix.FD(socket),
		   i32(posix.SOL_SOCKET),
		   .RCVBUF,
		   &want,
		   posix.socklen_t(size_of(want)),
	   ) != .OK {
		return 0
	}
	got: i32
	size := posix.socklen_t(size_of(got))
	if posix.getsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), .RCVBUF, &got, &size) != .OK {
		return 0
	}
	if got <= 0 {
		return 0
	}
	when ODIN_OS == .Linux {
		return int(got / 2)
	} else {
		return int(got)
	}
}
