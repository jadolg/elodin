/*
Fixtures the unit tests of more than one package share. A package's tests cannot
reach another package's `_test.odin` files, so a helper two packages' tests need
lives here, and only test files import it. It imports `dns`, `loop` and `netx`,
so their own tests cannot import it: they keep their own copies, each saying so.
*/
package testkit

import "base:runtime"
import "core:encoding/hex"
import "core:fmt"
import "core:math/rand"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:time"
import "elodin:dns"
import "elodin:loop"
import "elodin:netx"

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
every allocation and resize in `seen`, and hands every other to `backing`. Left
zero, `backing` is the temp allocator in force when `fail_nth` makes the
allocator, so installing it as `context.temp_allocator` does not hand requests
back to itself.

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
	if f.backing.procedure == nil {
		f.backing = context.temp_allocator
	}
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
	assert(backing.data != data, "a Fail_Nth is its own backing; build it with `fail_nth` or give it one")
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

// The bytes `text` spells in hex. A literal that does not decode is a broken
// fixture, so it panics rather than hand back nothing for a case to run on.
unhex :: proc(text: string, allocator := context.temp_allocator) -> []u8 {
	out, ok := hex.decode(transmute([]u8)text, allocator)
	if !ok {
		panic("a test's hex literal does not decode")
	}
	return out
}

/*
A directory of this run's own: `prefix` (an absolute path's leading part) with
the pid and a random suffix appended, made by this call at mode 0700, so nothing
can already be there and nobody else can plant anything in it, and the keys a
test writes into it are this user's to read. Held for the run, on the heap; ""
and false when none could be made.
*/
private_dir :: proc(prefix: string) -> (dir: string, ok: bool) {
	for _ in 0 ..< 8 {
		dir = fmt.aprintf("%s%d-%x", prefix, os.get_pid(), rand.uint64(), allocator = runtime.heap_allocator())
		#partial switch linux.mkdir(strings.clone_to_cstring(dir, context.temp_allocator), {.IRUSR, .IWUSR, .IXUSR}) {
		case .NONE:
			return dir, true
		case .EEXIST:
			delete(dir, runtime.heap_allocator())
		case:
			delete(dir, runtime.heap_allocator())
			return "", false
		}
	}
	return "", false
}

// How long an ended run's private directory is left before a sweep takes it.
PRIVATE_DIR_STALE :: time.Hour

/*
Remove the `private_dir`s under `prefix` of runs that have ended. The test runner
leaves through `exit`, which runs neither `@(fini)` nor `atexit` handlers, so a
run cannot remove its own; the next one removes each that is a real directory of
this user's, named by a pid that is gone, and untouched for `PRIVATE_DIR_STALE`.

Read with `lstat`, which does not follow a link: `os.remove_all` would, and a
link planted under the prefix would have it empty whatever it points at. The age
is what keeps a run in another pid namespace sharing the directory, whose pid
this /proc cannot see, from losing its directory mid-run.
*/
sweep_private_dirs :: proc(prefix: string) {
	slash := strings.last_index_byte(prefix, '/')
	if slash <= 0 || !os.exists("/proc/self") {
		return
	}
	entries, err := os.read_all_directory_by_path(prefix[:slash], context.temp_allocator)
	if err != nil {
		return
	}
	for e in entries {
		if !strings.has_prefix(e.fullpath, prefix) {
			continue
		}
		st: linux.Stat
		if linux.lstat(strings.clone_to_cstring(e.fullpath, context.temp_allocator), &st) != .NONE ||
		   !linux.S_ISDIR(st.mode) ||
		   st.uid != linux.getuid() {
			continue
		}
		name := e.fullpath[len(prefix):]
		pid := name[:strings.index_byte(name, '-')] if strings.contains_rune(name, '-') else name
		if _, numeric := netx.parse_decimal(pid, u64(max(i32))); !numeric || os.exists(fmt.tprintf("/proc/%s", pid)) {
			continue
		}
		age := time.diff(time.unix(i64(st.mtime.time_sec), 0), loop.now())
		if age < PRIVATE_DIR_STALE {
			continue
		}
		_ = os.remove_all(e.fullpath) // lint:allow a directory left behind is only the next sweep's
	}
}

// Fails `t` for every allocation `track` still holds and for any bad free,
// each message led by `what`. `dns`'s tests keep their own copy (see the
// package doc).
expect_no_leaks :: proc(t: ^testing.T, track: ^mem.Tracking_Allocator, what := "", loc := #caller_location) {
	sep := ": " if what != "" else ""
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%s%s%d bytes leaked, allocated at %v", what, sep, entry.size, entry.location, loc = loc)
	}
	testing.expectf(t, len(track.bad_free_array) == 0, "%s%s%d bad frees", what, sep, len(track.bad_free_array), loc = loc)
}
