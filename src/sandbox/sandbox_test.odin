package sandbox

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"

/*
Each test sandboxes a forked child, since neither layer can be taken off the
process that has it. The child reports through its exit status: the bits of the
checks that failed, or `SKIP_STATUS` when the kernel lacks what is tested. It
allocates only from an arena over its own stack, as the parent's other threads
may hold the heap's lock at the fork.
*/
@(private = "file")
SKIP_STATUS :: 77

@(private = "file")
Child :: #type proc() -> u8

@(private = "file")
Outcome :: struct {
	status: int,
	signal: posix.Signal,
	exited: bool,
}

@(private = "file")
run_child :: proc(t: ^testing.T, body: Child, loc := #caller_location) -> (out: Outcome, ok: bool) {
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
		linux.exit_group(i32(body()))
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
	off :: proc() -> u8 {
		before := no_new_privs()
		_, ok := confine({mode = .Off})
		return u8(!ok) << 1 | u8(no_new_privs() != before) << 2
	}
	basic :: proc() -> u8 {
		_, ok := confine({mode = .Basic})
		return u8(!ok) << 1 | u8(!no_new_privs()) << 2
	}
	strict :: proc() -> u8 {
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
AF_UNIX :: 1
@(private = "file")
SOCK_RAW :: 3
@(private = "file")
IPPROTO_ICMP :: 1
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
	body :: proc() -> u8 {
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
				failed |= 1 << 7
			}
		}
		if errno_of(linux.syscall(linux.SYS_socket, uintptr(AF_UNIX), uintptr(SOCK_DGRAM), uintptr(0))) != .EAFNOSUPPORT {
			failed |= 1 << 2
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
		ret := linux.syscall(linux.SYS_clone, uintptr(CLONE_NEWUSER | 17), uintptr(0), uintptr(0), uintptr(0), uintptr(0))
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
	body :: proc() -> u8 {
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

// A call off the list ends the process, and the kill reaches it as SIGSYS.
@(test)
test_a_call_off_the_list_kills_the_process :: proc(t: ^testing.T) {
	body :: proc() -> u8 {
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
		unfiltered :: proc() -> u8 {
			page, ok := i386_getpid_page()
			if !ok {
				return 4
			}
			page()
			return 0
		}
		filtered :: proc() -> u8 {
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

// The paths the child reads, set by the parent before the fork.
@(private = "file")
landlock_inside, landlock_outside: string

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
	landlock_inside, landlock_outside = inside, outside

	basic :: proc() -> u8 {
		report, ok := confine({mode = .Basic, cache_dir = landlock_inside})
		if report.landlock == .Unavailable {
			return SKIP_STATUS
		}
		failed: u8
		failed |= u8(!ok || report.landlock != .Applied)
		failed |= u8(!can_create(landlock_inside)) << 1
		failed |= u8(can_create(landlock_outside)) << 2
		failed |= u8(!can_read(landlock_outside)) << 3
		return failed
	}
	strict :: proc() -> u8 {
		missing := strings.concatenate({landlock_outside, "/missing"}, context.temp_allocator)
		report, ok := confine({mode = .Strict, log_dirs = {landlock_outside}, readable = {landlock_inside, "/proc/meminfo", missing}})
		if report.landlock == .Unavailable {
			return SKIP_STATUS
		}
		failed: u8
		failed |= u8(!ok || report.landlock != .Applied)
		failed |= u8(!can_read(landlock_inside)) << 1
		failed |= u8(can_read(landlock_outside)) << 2
		// The log directory is written to, never read.
		failed |= u8(!can_create(landlock_outside)) << 3
		failed |= u8(can_create(landlock_inside)) << 4
		meminfo, err := linux.open("/proc/meminfo", {.CLOEXEC})
		failed |= u8(err != .NONE) << 5
		linux.close(meminfo)
		failed |= u8(len(report.unreachable) != 1 || report.unreachable[0] != {missing, i32(linux.Errno.ENOENT)}) << 6
		return failed
	}
	for body, i in ([2]Child{basic, strict}) {
		out, ok := run_child(t, body)
		if !ok {
			continue
		}
		if out.exited && out.status == SKIP_STATUS {
			// Only where this process sees no Landlock either.
			abi := linux.syscall(linux.SYS_landlock_create_ruleset, uintptr(0), uintptr(0), uintptr(CREATE_RULESET_VERSION))
			if !testing.expectf(t, abi <= 0, "the child found no Landlock where this process finds ABI %d", abi) {
				continue
			}
			fmt.eprintfln("sandbox: Landlock is not available here, so %s is not tested", "basic" if i == 0 else "strict")
			continue
		}
		expect_passed(t, out)
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

// The hint is for a refusal Landlock may have made: EACCES, with it in force.
@(test)
test_the_refusal_hint_names_the_sandbox_only_when_it_may_be_why :: proc(t: ^testing.T) {
	eacces, enoent := os.Platform_Error(linux.Errno.EACCES), os.Platform_Error(linux.Errno.ENOENT)
	was := sync.atomic_load(&landlock_in_force)
	defer sync.atomic_store(&landlock_in_force, was)

	sync.atomic_store(&landlock_in_force, false)
	testing.expect_value(t, refusal_hint(eacces), "")
	sync.atomic_store(&landlock_in_force, true)
	testing.expect_value(t, refusal_hint(eacces), REFUSAL_HINT)
	testing.expect_value(t, refusal_hint(enoent), "")
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
