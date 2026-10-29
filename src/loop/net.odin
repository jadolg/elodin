package loop

import "base:intrinsics"
import "core:net"
import "core:sys/linux"
import "core:time"

/*
`core:net`'s socket calls, for sockets in non-blocking mode.

Every socket the server reads or writes on a loop is non-blocking, because a
blocking one would put the whole loop to sleep in the kernel. These take the same
arguments and return the same values as the calls they wrap, and wait where those
would have blocked: the call is made, and when it says `Would_Block` the fiber
waits for the descriptor and makes it again.

How long they wait is the socket's own `SO_RCVTIMEO` or `SO_SNDTIMEO`, read when
the first attempt would block, so everything that sets those today - a
connection's `client_timeout`, an upstream exchange's deadline, a listener's poll
interval - goes on meaning what it meant, and a wait that runs out returns
`Would_Block` exactly as a timed-out blocking call does on Linux. The deadline is
taken from the moment the call began, so a socket that was left in blocking mode
after all - the kernel having already waited the whole timeout - is not waited on
a second time.

A cancelled fiber's call returns as a timeout does.
*/

/*
The deadline a socket timeout option gives a call that began at `start`, or the
zero tick for none.

Read with the system call itself: `core:sys/linux`'s `getsockopt` passes the size
of the pointer it is given as the option's length, which for a `timeval` is half
of it, and the kernel refuses the read - every socket would have looked as if it
had no timeout, and a wait meant to end would have lasted for ever.
*/
/*
A socket read or written from a fiber must be non-blocking, or the call sleeps
in the kernel with the whole loop under it - every other fiber on the thread
waiting out this one's timeout. Nothing at the call says which a socket is, so
in a debug build - the integration suite's - every call made on a fiber checks,
and a socket created or adopted without `set_blocking(false)` stops the process
where it is used rather than showing up as a loop that answers one query at a
time. A system call per socket call, which is why it is debug only.
*/
@(private)
assert_nonblocking :: proc(fd: linux.Fd, loc := #caller_location) {
	when ODIN_DEBUG {
		if current() == nil {
			return
		}
		flags, err := linux.fcntl(fd, linux.F_GETFL)
		assert(err != .NONE || .NONBLOCK in flags, "a blocking socket was used on a loop", loc)
	}
}

@(private)
socket_deadline :: proc(fd: linux.Fd, option: linux.Socket_Option, start: Tick) -> Tick {
	tv: linux.Time_Val
	size := u32(size_of(tv))
	ret := intrinsics.syscall(
		linux.SYS_getsockopt,
		uintptr(fd),
		uintptr(linux.SOL_SOCKET),
		uintptr(option),
		uintptr(&tv),
		uintptr(&size),
	)
	if int(ret) < 0 || (tv.seconds == 0 && tv.microseconds == 0) {
		return {}
	}
	d := time.Duration(tv.seconds) * time.Second + time.Duration(tv.microseconds) * time.Microsecond
	return time.tick_add(start, d)
}

/*
Wait for `fd` until the deadline the socket option gives, computed once. False
when the wait ended without the descriptor becoming ready: a timeout, a
cancellation, or a descriptor epoll will not take.

A wait that ends without parking - the deadline already spent, the fiber
cancelled, epoll refusing the descriptor - counts as a turn, as a completed call
does: the read and accept loops retry on `Would_Block`, and a retry that never
parks would otherwise hold the loop for as long as the cause lasts.
*/
@(private)
socket_wait :: proc(
	fd: linux.Fd,
	events: Events,
	option: linux.Socket_Option,
	start: Tick,
	deadline: ^Tick,
	armed: ^bool,
) -> bool {
	if !armed^ {
		deadline^ = socket_deadline(fd, option, start)
		armed^ = true
	}
	if deadline^ != (Tick{}) && time.tick_diff(time.tick_now(), deadline^) <= 0 {
		take_turn()
		return false
	}
	switch wait_fd(fd, events, deadline^) {
	case .Ready:
		return true
	case .Cancelled, .Failed:
		// Either may return without parking; one that parked has its count reset.
		take_turn()
	case .Timeout:
	}
	return false
}

recv_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> (int, net.TCP_Recv_Error) {
	assert_nonblocking(linux.Fd(socket))
	start := time.tick_now()
	deadline: Tick
	armed: bool
	for {
		n, err := net.recv_tcp(socket, buf)
		if err != .Would_Block {
			take_turn()
			return n, err
		}
		if !socket_wait(linux.Fd(socket), {.In}, .RCVTIMEO, start, &deadline, &armed) {
			return 0, .Would_Block
		}
	}
}

/*
Write all of `buf`, as `net.send_tcp` does, or say why not. What was written
before a failure is counted in `n`.
*/
send_tcp :: proc(socket: net.TCP_Socket, buf: []u8) -> (n: int, err: net.TCP_Send_Error) {
	assert_nonblocking(linux.Fd(socket))
	start := time.tick_now()
	deadline: Tick
	armed: bool
	for {
		wrote, serr := net.send_tcp(socket, buf[n:])
		n += wrote
		if serr != .Would_Block {
			take_turn()
			return n, serr
		}
		if !socket_wait(linux.Fd(socket), {.Out}, .SNDTIMEO, start, &deadline, &armed) {
			return n, .Would_Block
		}
	}
}

recv_udp :: proc(socket: net.UDP_Socket, buf: []u8) -> (int, net.Endpoint, net.UDP_Recv_Error) {
	assert_nonblocking(linux.Fd(socket))
	start := time.tick_now()
	deadline: Tick
	armed: bool
	for {
		n, from, err := net.recv_udp(socket, buf)
		if err != .Would_Block {
			take_turn()
			return n, from, err
		}
		if !socket_wait(linux.Fd(socket), {.In}, .RCVTIMEO, start, &deadline, &armed) {
			return 0, {}, .Would_Block
		}
	}
}

send_udp :: proc(socket: net.UDP_Socket, buf: []u8, to: net.Endpoint) -> (int, net.UDP_Send_Error) {
	assert_nonblocking(linux.Fd(socket))
	start := time.tick_now()
	deadline: Tick
	armed: bool
	for {
		n, err := net.send_udp(socket, buf, to)
		if err != .Would_Block {
			take_turn()
			return n, err
		}
		if !socket_wait(linux.Fd(socket), {.Out}, .SNDTIMEO, start, &deadline, &armed) {
			return 0, .Would_Block
		}
	}
}

/*
`net.accept_tcp`, for a listening socket in non-blocking mode. The connection it
returns is non-blocking as well, ready for this package's reads and writes.
*/
accept_tcp :: proc(listener: net.TCP_Socket) -> (net.TCP_Socket, net.Endpoint, net.Accept_Error) {
	assert_nonblocking(linux.Fd(listener))
	start := time.tick_now()
	deadline: Tick
	armed: bool
	for {
		client, from, err := net.accept_tcp(listener)
		if err == nil {
			if net.set_blocking(client, false) != nil {
				net.close(client)
				// Retried as a connection that went away between the SYN and the
				// accept would be: the queue has moved on either way.
				take_turn()
				return {}, {}, .Aborted
			}
			take_turn()
			return client, from, nil
		}
		if err != .Would_Block {
			// Counted as the other wrappers count their errors: an accept loop
			// retries an aborted connection at once, and a queue of them would
			// otherwise hold the loop.
			take_turn()
			return {}, {}, err
		}
		if !socket_wait(linux.Fd(listener), {.In}, .RCVTIMEO, start, &deadline, &armed) {
			return {}, {}, .Would_Block
		}
	}
}
