package sandbox

import "base:runtime"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:thread"

/*
Each test sandboxes a forked child, since neither layer can be taken off the
process that has it. The child reports through its exit status: the bits of the
checks that failed, bits 0 to 6 only, or `SKIP_STATUS` when the kernel lacks
what is tested, which no set of failed checks can equal. It
allocates only from an arena over its own stack, as the parent's other threads
may hold the heap's lock at the fork.
*/
@(private = "file")
SKIP_STATUS :: 1 << 7

// A child's body. `dirs` is what its test passed to `run_child`: tests run in
// parallel, so a package variable would hand it another test's paths.
@(private = "file")
Child :: #type proc(dirs: []string) -> u8

@(private = "file")
Outcome :: struct {
	status: int,
	signal: posix.Signal,
	exited: bool,
}

@(private = "file")
run_child :: proc(t: ^testing.T, body: Child, dirs: []string = nil, loc := #caller_location) -> (out: Outcome, ok: bool) {
	pid := posix.fork()
	if pid < 0 {
		testing.expectf(t, false, "fork: %v", posix.errno(), loc = loc)
		return {}, false
	}
	if pid == 0 {
		buf: [64 * 1024]u8
		arena: mem.Arena
		mem.arena_init(&arena, buf[:])
		context = runtime.default_context()
		context.allocator = mem.arena_allocator(&arena)
		context.temp_allocator = context.allocator
		linux.exit_group(i32(body(dirs)))
	}
	status: i32
	if posix.waitpid(pid, &status, {}) != pid {
		testing.expectf(t, false, "waitpid: %v", posix.errno(), loc = loc)
		return {}, false
	}
	if posix.WIFEXITED(status) {
		return {status = int(posix.WEXITSTATUS(status)), exited = true}, true
	}
	if posix.WIFSIGNALED(status) {
		return {signal = posix.WTERMSIG(status)}, true
	}
	testing.expectf(t, false, "the child neither exited nor was killed: %x", status, loc = loc)
	return {}, false
}

// The child's checks all passed: it exited, with no bit set.
@(private = "file")
expect_passed :: proc(t: ^testing.T, out: Outcome, loc := #caller_location) {
	testing.expectf(t, out.exited, "the child was killed by %v", out.signal, loc = loc)
	testing.expectf(t, out.status == 0, "the child's failed checks: %b", out.status, loc = loc)
}

@(private = "file")
PR_GET_NO_NEW_PRIVS :: 39

@(private = "file")
no_new_privs :: proc() -> bool {
	return linux.syscall(linux.SYS_prctl, uintptr(PR_GET_NO_NEW_PRIVS), uintptr(0), uintptr(0), uintptr(0), uintptr(0)) == 1
}

// No new privileges under basic and strict; off leaves it as it was, which a
// run under a sandbox of its own may already have set.
@(test)
test_confine_sets_no_new_privs_unless_off :: proc(t: ^testing.T) {
	off :: proc(_: []string) -> u8 {
		before := no_new_privs()
		_, ok := confine({mode = .Off})
		return u8(!ok) << 1 | u8(no_new_privs() != before) << 2
	}
	basic :: proc(_: []string) -> u8 {
		_, ok := confine({mode = .Basic})
		return u8(!ok) << 1 | u8(!no_new_privs()) << 2
	}
	strict :: proc(_: []string) -> u8 {
		_, ok := confine({mode = .Strict})
		return u8(!ok) << 1 | u8(!no_new_privs()) << 2
	}
	bodies := [Mode]Child {
		.Off    = off,
		.Basic  = basic,
		.Strict = strict,
	}
	for body, mode in bodies {
		if out, ok := run_child(t, body); ok {
			testing.expectf(t, out.exited && out.status == 0, "%v: killed by %v, failed checks %b", mode, out.signal, out.status)
		}
	}
}

@(private = "file")
install_filter :: proc() -> bool {
	if linux.syscall(linux.SYS_prctl, uintptr(PR_SET_NO_NEW_PRIVS), uintptr(1), uintptr(0), uintptr(0), uintptr(0)) != 0 {
		return false
	}
	return filter_syscalls() == .NONE
}

@(private = "file")
errno_of :: proc(ret: int) -> linux.Errno {
	return linux.Errno(-ret) if ret < 0 else .NONE
}

@(private = "file")
CLONE_NEWUSER :: 0x10000000
@(private = "file")
SIGCHLD :: 17
@(private = "file")
AF_UNIX :: 1
@(private = "file")
SOCK_RAW :: 3
@(private = "file")
IPPROTO_ICMP :: 1
@(private = "file")
IPPROTO_SCTP :: 132
@(private = "file")
IPPROTO_UDPLITE :: 136
@(private = "file")
SCHED_IDLE :: 5
@(private = "file")
SCHED_BATCH :: 3
@(private = "file")
SOCK_NONBLOCK :: 0o4000
@(private = "file")
SOCK_CLOEXEC :: 0o2000000
// An option off the list at both levels: SO_KEEPALIVE under SOL_SOCKET, and
// TCP_DEFER_ACCEPT, the same number, under IPPROTO_TCP. TCP_NODELAY's
// number under SOL_SOCKET is SO_DEBUG: an option on the list, at the wrong level.
@(private = "file")
SO_KEEPALIVE :: 9
@(private = "file")
RLIMIT_NOFILE :: 7

// What the filter lets through, and how it refuses what it refuses with an
// error rather than the kill.
@(test)
test_the_filter_answers_by_the_call_and_its_arguments :: proc(t: ^testing.T) {
	body :: proc(_: []string) -> u8 {
		if !install_filter() {
			return 1
		}
		failed: u8
		self := uintptr(linux.getpid())
		if fd := linux.syscall(linux.SYS_socket, uintptr(AF_INET), uintptr(SOCK_STREAM), uintptr(0)); fd < 0 {
			failed |= 1 << 1
		} else {
			defer linux.close(linux.Fd(fd))
			tv: [2]i64
			one: i32 = 1
			set :: proc(fd: int, level, name: u32, value: rawptr, size: int) -> linux.Errno {
				return errno_of(linux.syscall(linux.SYS_setsockopt, uintptr(fd), uintptr(level), uintptr(name), value, uintptr(size)))
			}
			if set(fd, SOL_SOCKET, SO_RCVTIMEO_OLD, &tv, size_of(tv)) != .NONE ||
			   set(fd, IPPROTO_TCP, TCP_NODELAY, &one, size_of(one)) != .NONE ||
			   set(fd, SOL_SOCKET, SO_KEEPALIVE, &one, size_of(one)) != .EPERM ||
			   set(fd, IPPROTO_TCP, SO_KEEPALIVE, &one, size_of(one)) != .EPERM ||
			   set(fd, SOL_SOCKET, TCP_NODELAY, &one, size_of(one)) != .EPERM {
				failed |= 1 << 1
			}
		}
		if errno_of(linux.syscall(linux.SYS_socket, uintptr(AF_UNIX), uintptr(SOCK_DGRAM), uintptr(0))) != .EAFNOSUPPORT {
			failed |= 1 << 2
		}
		// A protocol of its own module refused; TCP named outright allowed.
		if errno_of(linux.syscall(linux.SYS_socket, uintptr(AF_INET), uintptr(SOCK_STREAM), uintptr(IPPROTO_SCTP))) != .EPERM ||
		   errno_of(linux.syscall(linux.SYS_socket, uintptr(AF_INET6), uintptr(SOCK_DGRAM), uintptr(IPPROTO_UDPLITE))) != .EPERM {
			failed |= 1 << 2
		}
		if fd := linux.syscall(linux.SYS_socket, uintptr(AF_INET), uintptr(SOCK_STREAM), uintptr(IPPROTO_TCP)); fd < 0 {
			failed |= 1 << 2
		} else {
			linux.close(linux.Fd(fd))
		}
		// Raw refused whoever asks; a datagram socket with its flags allowed.
		if errno_of(linux.syscall(linux.SYS_socket, uintptr(AF_INET), uintptr(SOCK_RAW), uintptr(IPPROTO_ICMP))) != .EPERM {
			failed |= 1 << 2
		}
		if fd := linux.syscall(linux.SYS_socket, uintptr(AF_INET6), uintptr(SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC), uintptr(0)); fd < 0 {
			failed |= 1 << 2
		} else {
			linux.close(linux.Fd(fd))
		}
		if errno_of(linux.syscall(linux.SYS_clone3, uintptr(0), uintptr(0))) != .ENOSYS {
			failed |= 1 << 3
		}
		// SIGCHLD as the exit signal; a filter that let it through would have
		// made a child, which leaves at once.
		ret := linux.syscall(linux.SYS_clone, uintptr(CLONE_NEWUSER | SIGCHLD), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
		if ret == 0 {
			linux.exit_group(0)
		}
		if errno_of(ret) != .EPERM {
			failed |= 1 << 4
		}
		if linux.syscall(linux.SYS_kill, self, uintptr(0)) != 0 || errno_of(linux.syscall(linux.SYS_kill, uintptr(1), uintptr(0))) != .EPERM {
			failed |= 1 << 5
		}
		tid := uintptr(linux.gettid())
		if linux.syscall(linux.SYS_tgkill, self, tid, uintptr(0)) != 0 || errno_of(linux.syscall(linux.SYS_tgkill, uintptr(1), uintptr(1), uintptr(0))) != .EPERM {
			failed |= 1 << 5
		}
		limit: [2]u64
		if linux.syscall(linux.SYS_prlimit64, uintptr(0), uintptr(RLIMIT_NOFILE), uintptr(0), &limit) != 0 ||
		   errno_of(linux.syscall(linux.SYS_prlimit64, uintptr(1), uintptr(RLIMIT_NOFILE), uintptr(0), &limit)) != .EPERM ||
		   errno_of(linux.syscall(linux.SYS_prlimit64, self, uintptr(RLIMIT_NOFILE), uintptr(0), &limit)) != .EPERM {
			failed |= 1 << 6
		}
		return failed
	}
	if out, ok := run_child(t, body); ok {
		expect_passed(t, out)
	}
}

// A loop thread pins itself with `sched_setaffinity(0, ...)` when
// `server.pin_loops` is on, and may not have run yet when the filter goes on;
// another process is not its to move.
@(test)
test_the_filter_lets_a_thread_pin_itself_and_no_other :: proc(t: ^testing.T) {
	body :: proc(_: []string) -> u8 {
		mask: [16]u64
		if linux.syscall(linux.SYS_sched_getaffinity, uintptr(0), uintptr(size_of(mask)), &mask) < 0 {
			return 4
		}
		if !install_filter() {
			return 1
		}
		failed: u8
		if linux.syscall(linux.SYS_sched_setaffinity, uintptr(0), uintptr(size_of(mask)), &mask) != 0 {
			failed |= 1 << 1
		}
		// Its own pid is the main thread's tid, which another thread is not to move.
		self := uintptr(linux.getpid())
		if errno_of(linux.syscall(linux.SYS_sched_setaffinity, uintptr(1), uintptr(size_of(mask)), &mask)) != .EPERM ||
		   errno_of(linux.syscall(linux.SYS_sched_setaffinity, self, uintptr(size_of(mask)), &mask)) != .EPERM {
			failed |= 1 << 2
		}
		return failed
	}
	if out, ok := run_child(t, body); ok {
		expect_passed(t, out)
	}
}

/*
What a serving process makes threads with is allowed - `pthread_create`, through
`clone` with CLONE_THREAD - and a process is not: `clone(SIGCHLD)` is fork. And
`sysinfo`, which sizing falls back to where `/proc/meminfo` cannot be read.
*/
@(test)
test_the_filter_lets_threads_start_and_refuses_a_fork :: proc(t: ^testing.T) {
	body :: proc(_: []string) -> u8 {
		if !install_filter() {
			return 1
		}
		failed: u8
		ret := linux.syscall(linux.SYS_clone, uintptr(SIGCHLD), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
		if ret == 0 {
			linux.exit_group(0)
		}
		if errno_of(ret) != .EPERM {
			failed |= 1 << 1
		}
		started := thread.create_and_start(proc() {})
		if started == nil {
			failed |= 1 << 2
		} else {
			thread.join(started)
			thread.destroy(started)
		}
		info: linux.Sys_Info
		if linux.sysinfo(&info) != .NONE {
			failed |= 1 << 3
		}
		// A thread's policy may be set as glibc sets it, and only to that.
		param: [1]i32
		if linux.syscall(linux.SYS_sched_setscheduler, uintptr(0), uintptr(SCHED_OTHER), &param) != 0 ||
		   errno_of(linux.syscall(linux.SYS_sched_setscheduler, uintptr(0), uintptr(SCHED_IDLE), &param)) != .EPERM {
			failed |= 1 << 4
		}
		return failed
	}
	if out, ok := run_child(t, body); ok {
		expect_passed(t, out)
	}
}

// A call off the list ends the process, and the kill reaches it as SIGSYS.
@(test)
test_a_call_off_the_list_kills_the_process :: proc(t: ^testing.T) {
	body :: proc(_: []string) -> u8 {
		if !install_filter() {
			return 1
		}
		linux.syscall(linux.SYS_getppid)
		return 2
	}
	if out, ok := run_child(t, body); ok {
		testing.expectf(t, !out.exited && out.signal == .SIGSYS, "exited %v with %d, signal %v", out.exited, out.status, out.signal)
	}
}

// An x86_64 process can still make i386 calls through `int 0x80`, by numbers
// that mean other calls: i386's 20, getpid, is x86_64's writev, on the list.
// Where the i386 entry is off (`ia32_emulation=0`) the call faults with or
// without a filter, so that is checked first.
@(test)
test_a_foreign_architecture_kills_the_process :: proc(t: ^testing.T) {
	when ODIN_ARCH != .amd64 {
		return
	} else {
		unfiltered :: proc(_: []string) -> u8 {
			page, ok := i386_getpid_page()
			if !ok {
				return 4
			}
			page()
			return 0
		}
		filtered :: proc(_: []string) -> u8 {
			page, ok := i386_getpid_page()
			if !ok {
				return 4
			}
			if !install_filter() {
				return 1
			}
			page()
			return 2
		}
		premise, premise_ok := run_child(t, unfiltered)
		if !premise_ok {
			return
		}
		if !premise.exited {
			fmt.eprintfln("sandbox: the i386 entry is off here (an unfiltered int 0x80 ends in %v), so it is not tested", premise.signal)
			return
		}
		if !testing.expectf(t, premise.status == 0, "the unfiltered child's failed checks: %b", premise.status) {
			return
		}
		if out, ok := run_child(t, filtered); ok {
			testing.expectf(t, !out.exited && out.signal == .SIGSYS, "exited %v with %d, signal %v", out.exited, out.status, out.signal)
		}
	}
}

// mov eax, 20; int 0x80; ret - on a page of its own, as Odin has no inline way
// to reach the i386 entry.
@(private = "file")
i386_getpid_page :: proc() -> (call: proc "c" (), ok: bool) {
	code := [?]u8{0xB8, I386_GETPID, 0, 0, 0, 0xCD, 0x80, 0xC3}
	page, err := linux.mmap(0, 4096, {.READ, .WRITE, .EXEC}, {.PRIVATE, .ANONYMOUS})
	if err != .NONE {
		return nil, false
	}
	mem.copy(page, &code, len(code))
	return cast(proc "c" ())page, true
}

@(private = "file")
I386_GETPID :: 20

// A scratch directory with a file in it, for the Landlock tests.
@(private = "file")
scratch_dir :: proc(t: ^testing.T, name: string, loc := #caller_location) -> (dir: string, ok: bool) {
	dir = fmt.aprintf("/tmp/elodin-sandbox-test-%d-%s", posix.getpid(), name, allocator = context.temp_allocator)
	if err := os.make_directory(dir); err != nil {
		testing.expectf(t, false, "cannot make %s: %v", dir, err, loc = loc)
		return "", false
	}
	path := strings.concatenate({dir, "/existing"}, context.temp_allocator)
	if err := os.write_entire_file(path, transmute([]u8)string("x")); err != nil {
		testing.expectf(t, false, "cannot write %s: %v", path, err, loc = loc)
		return dir, false
	}
	return dir, true
}

@(private = "file")
remove_scratch :: proc(t: ^testing.T, dir: string) {
	if dir == "" {
		return
	}
	entries, err := os.read_directory_by_path(dir, -1, context.temp_allocator)
	testing.expectf(t, err == nil, "cannot list %s: %v", dir, err)
	for e in entries {
		rerr := os.remove(e.fullpath)
		testing.expectf(t, rerr == nil, "cannot remove %s: %v", e.fullpath, rerr)
	}
	derr := os.remove(dir)
	testing.expectf(t, derr == nil, "cannot remove %s: %v", dir, derr)
}

@(private = "file")
can_create :: proc(dir: string) -> bool {
	path := strings.clone_to_cstring(strings.concatenate({dir, "/new"}, context.temp_allocator), context.temp_allocator)
	fd, err := linux.open(path, {.WRONLY, .CREAT, .CLOEXEC}, {.IRUSR, .IWUSR})
	if err != .NONE {
		return false
	}
	linux.close(fd)
	return true
}

@(private = "file")
can_read :: proc(dir: string) -> bool {
	path := strings.clone_to_cstring(strings.concatenate({dir, "/existing"}, context.temp_allocator), context.temp_allocator)
	fd, err := linux.open(path, {.CLOEXEC})
	if err != .NONE {
		return false
	}
	linux.close(fd)
	return true
}

/*
Basic confines writing to the cache and log directories and leaves reading
alone; strict confines reading to its readable paths too. A readable path that
is a file - `/proc/meminfo` in the plan - takes a file rule rather than failing
the ruleset, and one that does not exist is reported rather than failing it.
Once it is in force, `refusal_hint` names it for what it confines: a write under
either, a read only under strict.
*/
@(test)
test_landlock_confines_writes_and_under_strict_reads :: proc(t: ^testing.T) {
	inside, in_ok := scratch_dir(t, "inside")
	defer remove_scratch(t, inside)
	outside, out_ok := scratch_dir(t, "outside")
	defer remove_scratch(t, outside)
	if !in_ok || !out_ok {
		return
	}
	// The children's `dirs`: inside, then outside.
	dirs := []string{inside, outside}

	basic :: proc(dirs: []string) -> u8 {
		inside, outside := dirs[0], dirs[1]
		report, ok := confine({mode = .Basic, cache_dir = inside})
		if report.landlock == .Unavailable {
			return SKIP_STATUS
		}
		failed: u8
		failed |= u8(!ok || report.landlock != .Applied)
		failed |= u8(!can_create(inside)) << 1
		failed |= u8(can_create(outside)) << 2
		failed |= u8(!can_read(outside)) << 3
		eacces := os.Platform_Error(linux.Errno.EACCES)
		failed |= u8(refusal_hint(eacces, write = true) != REFUSAL_HINT) << 4
		failed |= u8(refusal_hint(eacces, write = false) != "") << 5
		failed |= u8(refusal_hint(os.Platform_Error(linux.Errno.ENOENT), write = true) != "") << 6
		return failed
	}
	strict :: proc(dirs: []string) -> u8 {
		inside, outside := dirs[0], dirs[1]
		missing := strings.concatenate({outside, "/missing"}, context.temp_allocator)
		report, ok := confine({mode = .Strict, log_dir = outside, readable = {inside, "/proc/meminfo", missing}})
		if report.landlock == .Unavailable {
			return SKIP_STATUS
		}
		failed: u8
		failed |= u8(!ok || report.landlock != .Applied)
		failed |= u8(!can_read(inside)) << 1
		failed |= u8(can_read(outside)) << 2
		// The log directory is written to, never read.
		failed |= u8(!can_create(outside)) << 3
		failed |= u8(can_create(inside)) << 4
		meminfo, err := linux.open("/proc/meminfo", {.CLOEXEC})
		failed |= u8(err != .NONE) << 5
		linux.close(meminfo)
		failed |= u8(len(report.unreachable) != 1 || report.unreachable[0] != {missing, i32(linux.Errno.ENOENT)}) << 6
		return failed
	}
	strict_hints :: proc(dirs: []string) -> u8 {
		report, ok := confine({mode = .Strict, readable = {dirs[0]}})
		if report.landlock == .Unavailable {
			return SKIP_STATUS
		}
		eacces := os.Platform_Error(linux.Errno.EACCES)
		failed: u8
		failed |= u8(!ok || report.landlock != .Applied)
		failed |= u8(refusal_hint(eacces, write = false) != REFUSAL_HINT) << 1
		failed |= u8(refusal_hint(eacces, write = true) != REFUSAL_HINT) << 2
		failed |= u8(refusal_hint(os.Platform_Error(linux.Errno.ENOENT), write = false) != "") << 3
		return failed
	}
	names := [3]string{"basic", "strict", "strict's hints"}
	for body, i in ([3]Child{basic, strict, strict_hints}) {
		out, ok := run_child(t, body, dirs)
		if !ok {
			continue
		}
		if out.exited && out.status == SKIP_STATUS {
			// Only where this process sees no Landlock either.
			abi := linux.syscall(linux.SYS_landlock_create_ruleset, uintptr(0), uintptr(0), uintptr(CREATE_RULESET_VERSION))
			if !testing.expectf(t, abi <= 0, "the child found no Landlock where this process finds ABI %d", abi) {
				continue
			}
			fmt.eprintfln("sandbox: Landlock is not available here, so %s is not tested", names[i])
			continue
		}
		testing.expectf(t, out.exited && out.status == 0, "%s: the child's failed checks: %b, killed by %v", names[i], out.status, out.signal)
	}
}

// A kernel's ABI decides which rights a ruleset may handle; one it does not
// know is EINVAL, and the ruleset would fail.
@(test)
test_landlock_handles_only_what_the_abi_knows :: proc(t: ^testing.T) {
	testing.expect_value(t, supported_access(1), ABI1_ACCESS)
	testing.expect(t, .Refer in supported_access(2) && .Truncate not_in supported_access(2), "ABI 2 is Refer and not Truncate")
	testing.expect(t, .Truncate in supported_access(3) && .Ioctl_Dev not_in supported_access(4), "ABI 3 and 4 have Truncate and not Ioctl_Dev")
	testing.expect(t, .Ioctl_Dev in supported_access(5), "ABI 5 has Ioctl_Dev")
	testing.expect_value(t, supported_scopes(5), Scope_Set{})
	testing.expect_value(t, supported_scopes(6), Scope_Set{.Abstract_Unix_Socket, .Signal})
}

// The hint is for a refusal Landlock may have made: EACCES, with it in force,
// on writing, or on reading where it confines reads too. `refusal_hint` asks
// `hint_for` with the flags `confine` sets: checked here in a child, which may
// set them without another test seeing it, and under a real ruleset by the
// Landlock test.
@(test)
test_the_refusal_hint_names_the_sandbox_only_when_it_may_be_why :: proc(t: ^testing.T) {
	eacces, enoent := os.Platform_Error(linux.Errno.EACCES), os.Platform_Error(linux.Errno.ENOENT)
	Case :: struct {
		in_force, reads, write: bool,
		err:                    os.Error,
		hinted:                 bool,
	}
	cases := []Case {
		{in_force = false, reads = true, write = true, err = eacces, hinted = false},
		{in_force = true, reads = false, write = true, err = eacces, hinted = true},
		{in_force = true, reads = false, write = false, err = eacces, hinted = false},
		{in_force = true, reads = true, write = false, err = eacces, hinted = true},
		{in_force = true, reads = true, write = true, err = enoent, hinted = false},
		// As `core:os` reports EACCES.
		{in_force = true, reads = false, write = true, err = io.Error.Permission_Denied, hinted = true},
	}
	for c in cases {
		hint := hint_for(c.err, write = c.write, in_force = c.in_force, reads = c.reads)
		testing.expectf(t, (hint == REFUSAL_HINT) == c.hinted, "%v", c)
	}

	wiring :: proc(_: []string) -> u8 {
		failed: u8
		for bits in 0 ..< 16 {
			in_force, reads, write := bits & 1 != 0, bits & 2 != 0, bits & 4 != 0
			err := os.Platform_Error(linux.Errno.EACCES if bits & 8 != 0 else linux.Errno.ENOENT)
			sync.atomic_store(&landlock_in_force, in_force)
			sync.atomic_store(&landlock_reads, reads)
			if refusal_hint(err, write = write) != hint_for(err, write = write, in_force = in_force, reads = reads) {
				failed |= 1 << uint(bits & 3)
			}
		}
		return failed
	}
	if out, ok := run_child(t, wiring); ok {
		expect_passed(t, out)
	}
}

// The program fits the buffer it is built in, with room: one that outgrew it
// would refuse every strict start.
@(test)
test_the_program_fits_its_buffer :: proc(t: ^testing.T) {
	when AUDIT_ARCH != 0 {
		program: [PROGRAM_MAX]Sock_Filter
		n := build_program(program[:], 1, SCHED_OTHER)
		testing.expectf(t, n > 0 && n <= len(program), "%d instructions for a buffer of %d", n, len(program))
	}
}

/*
A process started under another policy - `chrt --batch` - gives it to every
thread glibc starts, by `sched_setscheduler` on the new tid, so that policy is
allowed too; another still is not.
*/
@(test)
test_the_filter_lets_threads_start_under_the_processs_policy :: proc(t: ^testing.T) {
	body :: proc(_: []string) -> u8 {
		param: [1]i32
		if linux.syscall(linux.SYS_sched_setscheduler, uintptr(0), uintptr(SCHED_BATCH), &param) != 0 {
			return 4
		}
		if !install_filter() {
			return 1
		}
		failed: u8
		started := thread.create_and_start(proc() {})
		if started == nil {
			failed |= 1 << 1
		} else {
			thread.join(started)
			thread.destroy(started)
		}
		if linux.syscall(linux.SYS_sched_setscheduler, uintptr(0), uintptr(SCHED_BATCH), &param) != 0 ||
		   errno_of(linux.syscall(linux.SYS_sched_setscheduler, uintptr(0), uintptr(SCHED_IDLE), &param)) != .EPERM {
			failed |= 1 << 2
		}
		return failed
	}
	if out, ok := run_child(t, body); ok {
		expect_passed(t, out)
	}
}

// `os.remove` on a directory is rmdir, on x86_64 a call of its own.
@(test)
test_the_filter_lets_a_directory_be_removed :: proc(t: ^testing.T) {
	dir := fmt.tprintf("/tmp/elodin-sandbox-rmdir-%d", posix.getpid())
	if !testing.expect(t, os.make_directory(dir) == nil, "cannot make the directory") {
		return
	}
	defer if os.exists(dir) {
		err := os.remove(dir)
		testing.expectf(t, err == nil, "cannot remove %s: %v", dir, err)
	}
	body :: proc(dirs: []string) -> u8 {
		if !install_filter() {
			return 1
		}
		return u8(os.remove(dirs[0]) != nil) << 1
	}
	if out, ok := run_child(t, body, {dir}); ok {
		expect_passed(t, out)
	}
	testing.expect(t, !os.exists(dir), "the directory is still there")
}

// What the raw-socket check is about: without a filter, this run can open one.
@(test)
test_a_raw_socket_opens_without_the_filter :: proc(t: ^testing.T) {
	fd := linux.syscall(linux.SYS_socket, uintptr(AF_INET), uintptr(SOCK_RAW), uintptr(IPPROTO_ICMP))
	if fd < 0 {
		fmt.eprintfln("sandbox: this run cannot open a raw socket (%v), so refusing one proves less here", linux.Errno(-fd))
		return
	}
	linux.close(linux.Fd(fd))
}
