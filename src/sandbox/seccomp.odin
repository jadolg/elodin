package sandbox

import "core:sys/linux"

/*
Install the syscall allowlist on every thread of the process, for good.

For after the privilege drop: nothing the startup does - binding, changing
identity, handing over the cache - is on the list. Needs
`PR_SET_NO_NEW_PRIVS`, which `confine` set on every thread there is.

What is not on the list kills the process (`SECCOMP_RET_KILL_PROCESS`), as
chrony's and OpenSSH's filters do: a forbidden call is either a bug that wants
a core dump or an attacker, and in neither case is carrying on the right end.
The exceptions return an error instead, where the caller has a fallback or the
call is fine with other arguments:

- `clone3` returns ENOSYS, because its flags are in memory a filter cannot read,
  and glibc then makes the same thread with `clone`.
- `clone` with a namespace flag, or without CLONE_THREAD, returns EPERM: a new
  user namespace is how an unprivileged process reaches kernel code otherwise
  reserved for root, and a new process is nothing the server makes.
- `socket` outside AF_INET and AF_INET6 returns EAFNOSUPPORT, and one that is
  neither a stream nor a datagram socket - raw - or names a protocol other than
  TCP or UDP, EPERM.
- `sched_setscheduler` to any policy but SCHED_OTHER and the one the process
  runs under returns EPERM: glibc sets a new thread's on its tid, which a
  filter cannot tell from another process's pid, so the policy is what is held
  - SCHED_IDLE would starve one.
- `kill` and `tgkill` aimed at any process but this one, and `prlimit64` and
  `sched_setaffinity` aimed at anything but the caller, return EPERM.
- `setsockopt` returns EPERM for any option but those in `SOCKET_OPTIONS`.

Returns the errno of the `seccomp` call, or ENOSYS on an architecture the
list is not written for.
*/
filter_syscalls :: proc() -> linux.Errno {
	when AUDIT_ARCH == 0 {
		return .ENOSYS
	} else {
		program: [PROGRAM_MAX]Sock_Filter
		policy := linux.syscall(linux.SYS_sched_getscheduler, uintptr(0))
		if policy < 0 {
			return linux.Errno(-policy)
		}
		n := build_program(program[:], u32(linux.getpid()), u32(policy))
		if n > len(program) {
			return .E2BIG
		}
		prog := Sock_Fprog {
			len    = u16(n),
			filter = &program[0],
		}
		ret := linux.syscall(
			linux.SYS_seccomp,
			uintptr(SECCOMP_SET_MODE_FILTER),
			uintptr(SECCOMP_FILTER_FLAG_TSYNC),
			&prog,
		)
		if ret < 0 {
			return linux.Errno(-ret)
		}
		// TSYNC returns the id of a thread it could not move onto the filter.
		if ret > 0 {
			return .ESRCH
		}
		return .NONE
	}
}

@(private)
Sock_Filter :: struct {
	code: u16,
	jt:   u8,
	jf:   u8,
	k:    u32,
}

@(private)
Sock_Fprog :: struct {
	len:    u16,
	filter: ^Sock_Filter,
}

// <linux/filter.h>, <linux/seccomp.h>.
@(private)
BPF_LD_W_ABS :: 0x20
@(private)
BPF_JEQ_K :: 0x15
@(private)
BPF_JSET_K :: 0x45
@(private)
BPF_AND_K :: 0x54
@(private)
BPF_RET_K :: 0x06

@(private)
SECCOMP_SET_MODE_FILTER :: 1
@(private)
SECCOMP_FILTER_FLAG_TSYNC :: 1
@(private)
RET_KILL_PROCESS :: 0x80000000
@(private)
RET_ERRNO :: 0x00050000
@(private)
RET_ALLOW :: 0x7fff0000

// `struct seccomp_data`: the call number, the architecture, then six 64-bit
// arguments. A 32-bit argument is the low word, which comes first on both
// little-endian targets here.
@(private)
DATA_NR :: 0
@(private)
DATA_ARCH :: 4
@(private)
DATA_ARG0_LOW :: 16
@(private)
DATA_ARG1_LOW :: 24
@(private)
DATA_ARG2_LOW :: 32

when ODIN_ARCH == .amd64 {
	@(private)
	AUDIT_ARCH :: 0xC000003E
} else when ODIN_ARCH == .arm64 {
	@(private)
	AUDIT_ARCH :: 0xC00000B7
} else {
	@(private)
	AUDIT_ARCH :: 0
}

@(private)
CLONE_THREAD :: 0x00010000
@(private)
CLONE_NAMESPACES :: 0x00000080 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000

// The type's bits in `socket`'s second argument; the flags are above them.
@(private)
SOCK_TYPE_MASK :: 0xf

/*
The socket options a serving process sets: the read and write timeouts in both
of their encodings, and TCP_NODELAY. Any other is EPERM - among them the ones
that hand the kernel code to run (`SO_ATTACH_FILTER`, `SO_ATTACH_BPF`) or load a
protocol module (`TCP_ULP`).
*/
@(private)
Socket_Option :: struct {
	level, name: u32,
}
@(private)
SOCKET_OPTIONS :: [?]Socket_Option {
	{u32(linux.Socket_API_Level.SOCKET), u32(linux.Socket_Option.RCVTIMEO_OLD)},
	{u32(linux.Socket_API_Level.SOCKET), u32(linux.Socket_Option.SNDTIMEO_OLD)},
	{u32(linux.Socket_API_Level.SOCKET), u32(linux.Socket_Option.RCVTIMEO_NEW)},
	{u32(linux.Socket_API_Level.SOCKET), u32(linux.Socket_Option.SNDTIMEO_NEW)},
	{u32(linux.Socket_API_Level.TCP), u32(linux.Socket_TCP_Option.NODELAY)},
}

// Two instructions per allowed call, five per socket option, and the fixed
// head, tail and argument checks, which come to fewer than `PROGRAM_HEAD`; a
// program that outgrows it is refused (`filter_syscalls`), which a test sees.
@(private)
PROGRAM_HEAD :: 80
@(private)
PROGRAM_MAX :: 2 * (len(ALLOWED) + len(ALLOWED_ARCH)) + 5 * len(SOCKET_OPTIONS) + PROGRAM_HEAD

/*
Write the filter into `out` and return its length, which is more than
`len(out)` when it did not fit and nothing past that was written. `pid` is the one process
`kill` and `tgkill` may name, and `policy` the scheduling policy the process
runs under, which glibc gives every thread it starts.

The head refuses a foreign architecture before any number is read: an x86_64
process can enter the kernel by the i386 table, where 11 is `execve` and not
`munmap`. x32 shares x86_64's audit arch and sets bit 30 in its numbers, so no
number on the list is one of its calls.
*/
@(private)
build_program :: proc(out: []Sock_Filter, pid: u32, policy: u32) -> int {
	n := 0
	// Past the end, counted and not written: the caller refuses a program
	// longer than `out`.
	emit :: proc(out: []Sock_Filter, n: ^int, code: u16, k: u32, jt: u8 = 0, jf: u8 = 0) {
		if n^ < len(out) {
			out[n^] = Sock_Filter{code, jt, jf, k}
		}
		n^ += 1
	}
	ret :: proc(out: []Sock_Filter, n: ^int, action: u32) {
		emit(out, n, BPF_RET_K, action)
	}
	errno :: proc(e: linux.Errno) -> u32 {
		return RET_ERRNO | u32(e)
	}

	emit(out, &n, BPF_LD_W_ABS, DATA_ARCH)
	emit(out, &n, BPF_JEQ_K, AUDIT_ARCH, jt = 1)
	ret(out, &n, RET_KILL_PROCESS)
	emit(out, &n, BPF_LD_W_ABS, DATA_NR)

	// Each checks one argument, so leaves the number behind: it returns on
	// every path rather than falling through to the list.
	emit(out, &n, BPF_JEQ_K, u32(linux.SYS_clone3), jf = 1)
	ret(out, &n, errno(.ENOSYS))

	// A thread, as pthread_create makes one, and nothing else: no namespace,
	// and no process - the server never forks.
	emit(out, &n, BPF_JEQ_K, u32(linux.SYS_clone), jf = 5)
	emit(out, &n, BPF_LD_W_ABS, DATA_ARG0_LOW)
	emit(out, &n, BPF_JSET_K, CLONE_NAMESPACES, jt = 1)
	emit(out, &n, BPF_JSET_K, CLONE_THREAD, jt = 1)
	ret(out, &n, errno(.EPERM))
	ret(out, &n, RET_ALLOW)

	// The family, then the type less SOCK_NONBLOCK and SOCK_CLOEXEC: a raw
	// socket is the kernel's packet code to a root process with no user.
	// And the protocol: 0, TCP or UDP - another, SCTP or UDP-Lite, is a kernel
	// module of its own, loaded on demand.
	emit(out, &n, BPF_JEQ_K, u32(linux.SYS_socket), jf = 14)
	emit(out, &n, BPF_LD_W_ABS, DATA_ARG0_LOW)
	emit(out, &n, BPF_JEQ_K, u32(linux.Address_Family.INET), jt = 1)
	emit(out, &n, BPF_JEQ_K, u32(linux.Address_Family.INET6), jf = 9)
	emit(out, &n, BPF_LD_W_ABS, DATA_ARG1_LOW)
	emit(out, &n, BPF_AND_K, SOCK_TYPE_MASK)
	emit(out, &n, BPF_JEQ_K, u32(linux.Socket_Type.STREAM), jt = 1)
	emit(out, &n, BPF_JEQ_K, u32(linux.Socket_Type.DGRAM), jf = 4)
	emit(out, &n, BPF_LD_W_ABS, DATA_ARG2_LOW)
	emit(out, &n, BPF_JEQ_K, 0, jt = 4)
	emit(out, &n, BPF_JEQ_K, u32(linux.Protocol.TCP), jt = 3)
	emit(out, &n, BPF_JEQ_K, u32(linux.Protocol.UDP), jt = 2)
	ret(out, &n, errno(.EPERM))
	ret(out, &n, errno(.EAFNOSUPPORT))
	ret(out, &n, RET_ALLOW)

	// kill and tgkill name this process; prlimit64 and sched_setaffinity, the
	// caller by 0, which is all glibc, musl and `loop.pin_current_thread` pass -
	// a pid there would be the main thread's, another thread's to move.
	Target :: struct {
		nr:    uintptr,
		value: u32,
	}
	targets := [4]Target {
		{linux.SYS_kill, pid},
		{linux.SYS_tgkill, pid},
		{linux.SYS_prlimit64, 0},
		{linux.SYS_sched_setaffinity, 0},
	}
	for target in targets {
		emit(out, &n, BPF_JEQ_K, u32(target.nr), jf = 4)
		emit(out, &n, BPF_LD_W_ABS, DATA_ARG0_LOW)
		emit(out, &n, BPF_JEQ_K, target.value, jt = 1)
		ret(out, &n, errno(.EPERM))
		ret(out, &n, RET_ALLOW)
	}

	emit(out, &n, BPF_JEQ_K, u32(linux.SYS_sched_setscheduler), jf = 5)
	emit(out, &n, BPF_LD_W_ABS, DATA_ARG1_LOW)
	emit(out, &n, BPF_JEQ_K, u32(linux.Sched_Policy.OTHER), jt = 2)
	emit(out, &n, BPF_JEQ_K, policy, jt = 1)
	ret(out, &n, errno(.EPERM))
	ret(out, &n, RET_ALLOW)

	// Each pair: a level that is not this one skips the three after it, an
	// option that is not this one the return.
	emit(out, &n, BPF_JEQ_K, u32(linux.SYS_setsockopt), jf = u8(5 * len(SOCKET_OPTIONS) + 1))
	for opt in SOCKET_OPTIONS {
		emit(out, &n, BPF_LD_W_ABS, DATA_ARG1_LOW)
		emit(out, &n, BPF_JEQ_K, opt.level, jf = 3)
		emit(out, &n, BPF_LD_W_ABS, DATA_ARG2_LOW)
		emit(out, &n, BPF_JEQ_K, opt.name, jf = 1)
		ret(out, &n, RET_ALLOW)
	}
	ret(out, &n, errno(.EPERM))

	for nr in ALLOWED {
		emit(out, &n, BPF_JEQ_K, u32(nr), jf = 1)
		ret(out, &n, RET_ALLOW)
	}
	for nr in ALLOWED_ARCH {
		emit(out, &n, BPF_JEQ_K, u32(nr), jf = 1)
		ret(out, &n, RET_ALLOW)
	}
	ret(out, &n, RET_KILL_PROCESS)
	return n
}

/*
What the process calls once it is serving, on glibc and musl: measured by
running the integration suite under strace and keeping the calls made after
the `ready` line, plus the calls the code makes on paths the suite does not
reach - a list refresh writing its cache, a second stop signal.

Not here, and so fatal: `execve`, `ptrace`, `bind`, `listen`, `ioctl`,
`prctl`, the identity calls, `mount`, `unshare`, `setns`, `bpf`, `keyctl`,
`io_uring_*`, `perf_event_open`, `userfaultfd` and every module and kexec call.
*/
@(private)
ALLOWED :: [?]uintptr {
	// Descriptors and files.
	linux.SYS_read,
	linux.SYS_write,
	linux.SYS_readv,
	linux.SYS_writev,
	linux.SYS_pread64,
	linux.SYS_close,
	linux.SYS_lseek,
	linux.SYS_fcntl,
	linux.SYS_openat,
	linux.SYS_faccessat,
	linux.SYS_faccessat2,
	linux.SYS_readlinkat,
	linux.SYS_fstat,
	linux.SYS_statx,
	linux.SYS_getdents64,
	linux.SYS_fsync,
	linux.SYS_fdatasync,
	linux.SYS_renameat,
	linux.SYS_renameat2,
	linux.SYS_mkdirat,
	linux.SYS_unlinkat,
	// openat2 for the log (`logx.open_log`).
	linux.SYS_openat2,
	// Memory.
	linux.SYS_brk,
	linux.SYS_mmap,
	linux.SYS_munmap,
	linux.SYS_mremap,
	linux.SYS_mprotect,
	linux.SYS_madvise,
	// Threads, signals and time.
	linux.SYS_futex,
	linux.SYS_set_robust_list,
	linux.SYS_rseq,
	linux.SYS_gettid,
	linux.SYS_getpid,
	linux.SYS_exit,
	linux.SYS_exit_group,
	linux.SYS_rt_sigaction,
	linux.SYS_rt_sigprocmask,
	linux.SYS_rt_sigreturn,
	linux.SYS_sigaltstack,
	linux.SYS_restart_syscall,
	linux.SYS_clock_gettime,
	linux.SYS_clock_getres,
	linux.SYS_clock_nanosleep,
	linux.SYS_gettimeofday,
	linux.SYS_nanosleep,
	linux.SYS_sched_yield,
	linux.SYS_sched_getaffinity,
	linux.SYS_sched_getscheduler,
	linux.SYS_sched_get_priority_min,
	linux.SYS_sched_get_priority_max,
	linux.SYS_getrandom,
	// What `config.probe_machine` falls back to where /proc/meminfo is not there.
	linux.SYS_sysinfo,
	linux.SYS_getuid,
	linux.SYS_geteuid,
	linux.SYS_getgid,
	linux.SYS_getegid,
	// The event loops and the network.
	linux.SYS_epoll_ctl,
	linux.SYS_epoll_pwait,
	linux.SYS_epoll_pwait2,
	linux.SYS_ppoll,
	linux.SYS_connect,
	linux.SYS_accept4,
	linux.SYS_sendto,
	linux.SYS_recvfrom,
	linux.SYS_sendmsg,
	linux.SYS_recvmsg,
	linux.SYS_getsockopt,
	linux.SYS_getsockname,
	linux.SYS_getpeername,
	linux.SYS_shutdown,
}

// The calls whose number, or whose name, is one architecture's own.
when ODIN_ARCH == .amd64 {
	@(private)
	ALLOWED_ARCH :: [?]uintptr {
		linux.SYS_newfstatat,
		// The older forms, which glibc and musl on x86_64 still call.
		linux.SYS_open,
		linux.SYS_access,
		linux.SYS_readlink,
		linux.SYS_stat,
		linux.SYS_lstat,
		linux.SYS_poll,
		linux.SYS_epoll_wait,
		linux.SYS_rename,
		linux.SYS_mkdir,
		linux.SYS_unlink,
		// `os.remove` of a directory, a stray one in the cache.
		linux.SYS_rmdir,
	}
} else when ODIN_ARCH == .arm64 {
	@(private)
	ALLOWED_ARCH :: [?]uintptr{linux.SYS_fstatat}
} else {
	@(private)
	ALLOWED_ARCH :: [0]uintptr{}
}
