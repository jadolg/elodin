/*
Fixtures the unit tests of more than one package share. A package's tests cannot
reach another package's `_test.odin` files, so a helper two packages' tests need
lives here, and only test files import it. It imports `dns`, so `dns`'s own tests
cannot import it and keep their own copies.
*/
package testkit

import "core:mem"
import "core:net"
import "core:sys/linux"
import "core:sys/posix"
import "core:time"
import "elodin:dns"

/*
A window-0 type bit map (RFC 4034 section 4.1.2) holding `types`, every one
below 256; nil for none, since a window with no type set is never written.
*/
type_bitmap :: proc(types: ..dns.Type) -> []u8 {
	if len(types) == 0 {
		return nil
	}
	high := 0
	for type in types {
		assert(int(type) < 256, "type_bitmap writes window 0 only")
		high = max(high, int(type))
	}
	length := high / 8 + 1
	out := make([]u8, 2 + length, context.temp_allocator)
	out[1] = u8(length)
	for type in types {
		out[2 + int(type) / 8] |= 0x80 >> u8(int(type) % 8)
	}
	return out
}

// Bytes `fd` sent that its peer has not acknowledged: `SIOCOUTQ`. -1 when the
// kernel will not say.
unacked_bytes :: proc(fd: linux.Fd) -> int {
	SIOCOUTQ :: 0x5411
	n: i32
	if i32(linux.ioctl(fd, SIOCOUTQ, uintptr(&n))) < 0 {
		return -1
	}
	return int(n)
}

/*
An allocator that refuses `fail_for` requests from its `fail_at`th on, counting
every allocation and resize in `seen`, and hands every other to `backing`: the
temp arena when that is left zero.

An arena that runs dry refuses everything after the first refusal too, so a
check missing at one allocation is covered by whichever check comes next. This
refuses a short run and then lets the next succeed, which is what finds it.
*/
Fail_Nth :: struct {
	backing:  mem.Allocator,
	seen:     int,
	fail_at:  int,
	fail_for: int,
}

// `f` as an allocator.
fail_nth :: proc(f: ^Fail_Nth) -> mem.Allocator {
	return {procedure = fail_nth_proc, data = f}
}

fail_nth_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	f := cast(^Fail_Nth)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		f.seen += 1
		if f.seen >= f.fail_at && f.seen < f.fail_at + f.fail_for {
			return nil, .Out_Of_Memory
		}
	}
	backing := f.backing if f.backing.procedure != nil else context.temp_allocator
	return backing.procedure(backing.data, mode, size, alignment, old_memory, old_size, loc)
}

/*
Shrink `socket`'s `option` buffer (`.RCVBUF` or `.SNDBUF`) to the kernel's
floor, and say whether it took: read back, since a setting that did not take
leaves a test that stalls nothing passing with nothing blocked.

Through `setsockopt` rather than `net.set_option`, whose buffer-size option
binds the value in a `case` listing several types, where it stays an `any`,
and hands the kernel the `any`'s data pointer as the size - megabytes, with
which no `send` ever waits.
*/
shrink_buffer :: proc(socket: net.TCP_Socket, option: posix.Sock_Option) -> bool {
	want: i32 = 2048
	if posix.setsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &want, posix.socklen_t(size_of(want))) != .OK {
		return false
	}
	got: i32
	size := posix.socklen_t(size_of(got))
	if posix.getsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &got, &size) != .OK {
		return false
	}
	// Linux doubles what it is given and holds it at a floor of a few KB.
	return got <= 16 * 1024
}

/*
A loopback listener whose connections advertise a window of a few KB, its
`accept` bounded by `wait`. Closed again on every failure, so a caller that gets
`ok` false has nothing to clean up.
*/
stall_listener :: proc(wait: time.Duration, backlog := 4) -> (listener: net.TCP_Socket, bound: net.Endpoint, ok: bool) {
	fd, serr := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
	if serr != .NONE {
		return
	}
	listener = net.TCP_Socket(fd)
	// Set before `listen`, so the handshake advertises it.
	if !shrink_buffer(listener, .RCVBUF) ||
	   net.bind(listener, net.Endpoint{address = net.IP4_Loopback, port = 0}) != nil ||
	   net.set_option(listener, .Receive_Timeout, wait) != nil ||
	   linux.listen(fd, i32(backlog)) != .NONE {
		net.close(listener)
		return
	}
	berr: net.Network_Error
	bound, berr = net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		return
	}
	return listener, bound, true
}
