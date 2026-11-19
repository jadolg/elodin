package main

import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "elodin:config"
import "elodin:logx"
import "elodin:sandbox"
import "elodin:server"
import "elodin:tlsx"

/*
Put `server.sandbox`'s first two layers on the process (#417), and return the
Landlock ABI in force, 0 for none, for the line `filter_process` writes.

Called before the first thread starts: `PR_SET_NO_NEW_PRIVS` and Landlock hold
for the calling thread and the threads it starts, and an event loop started
before this would parse every query outside them. Still root here when started
as root, which Landlock does not exempt: the startup work left - building the
first generation, the first list rebuild, the drop - is within the plan.

The cache directory is made here when blocking is on and it is missing, so it
has a rule: the rebuild would otherwise make it after Landlock, inside a parent
nothing may write to.

A process that cannot set `PR_SET_NO_NEW_PRIVS` ends: the operator asked for a
sandbox, and the layers after it depend on it. A missing Landlock is a warning.
*/
@(private)
confine_process :: proc(cfg: ^config.Config, config_path: string) -> (landlock_abi: int) {
	if cfg.server.sandbox == .Off {
		return 0
	}
	if cfg.blocking.enabled && cfg.blocking.cache_dir != "" {
		server.make_directories(cfg.blocking.cache_dir)
	}
	log_file := cfg.log.file if logx.writing_to_file() else ""
	plan := sandbox_plan(cfg, config_path, log_file, context.temp_allocator)
	report, ok := sandbox.confine(plan, context.temp_allocator)
	if !ok {
		logx.errorf("server.sandbox: cannot set no_new_privs; not starting without it")
		os.exit(1)
	}
	unconfined := "reading and writing files are" if cfg.server.sandbox == .Strict else "writing files is"
	switch report.landlock {
	case .Off:
	case .Applied:
		landlock_abi = report.abi
	case .Unavailable:
		logx.warnf(
			"server.sandbox: Landlock is unavailable (%s), so %s not confined; it needs Linux 5.13 with landlock among the lsm= modules, and a container runtime that allows its system calls",
			posix.strerror(posix.Errno(report.errno)),
			unconfined,
		)
	case .Failed:
		logx.warnf("server.sandbox: Landlock failed (%s), so %s not confined", posix.strerror(posix.Errno(report.errno)), unconfined)
	}
	for u in report.unreachable {
		logx.warnf("server.sandbox: cannot open %q (%s), so it stays out of reach until a restart", u.path, posix.strerror(posix.Errno(u.errno)))
	}
	return landlock_abi
}

/*
Install `server.sandbox: strict`'s syscall allowlist, after the drop, and say
what the process now runs under, with the Landlock ABI `confine_process` put in
force. A strict sandbox that cannot be had ends the process, as a failed drop
does.
*/
@(private)
filter_process :: proc(cfg: ^config.Config, landlock_abi: int) {
	if cfg.server.sandbox == .Off {
		return
	}
	seccomp := false
	if cfg.server.sandbox == .Strict {
		if err := sandbox.filter_syscalls(); err != .NONE {
			logx.errorf("server.sandbox: cannot install the syscall filter (%s); not starting without it", posix.strerror(posix.Errno(err)))
			os.exit(1)
		}
		seccomp = true
	}
	names := sandbox.MODE_NAMES
	logx.eventf(
		.Info,
		"sandbox",
		"mode=%s no_new_privs=true landlock_abi=%d seccomp=%v",
		names[cfg.server.sandbox],
		landlock_abi,
		seccomp,
	)
}

/*
What the configuration in `cfg` needs from the filesystem once it is serving;
`log_file` is the log file in use, "" for stderr.

Writes: the blocklist cache, when blocking is on or the directory is there for
a reload that turns it on, and the directory of the log file in use, which a
SIGHUP reopens by name. Reads, which only `.Strict` confines: the directory of
every file in `reread_files` and of OpenSSL's default trust store. Where a path
is a symlink, the directory of what it points to as well, because Landlock
judges the file reached, not the name. A directory rather than the file:
certbot renews by pointing the symlink at a new file beside the old one. Then
`/proc` and `/sys/fs/cgroup`, which the metrics and the sizing read, whole:
procfs makes a new inode at every lookup of an entry the kernel has let go of,
which a rule on `/proc/<pid>` would no longer match, and only a mount's root
stays.
*/
@(private)
sandbox_plan :: proc(cfg: ^config.Config, config_path, log_file: string, allocator := context.allocator) -> sandbox.Plan {
	plan := sandbox.Plan {
		mode = cfg.server.sandbox,
	}
	if cache := cfg.blocking.cache_dir; cache != "" && (cfg.blocking.enabled || os.exists(cache)) {
		plan.cache_dir = cache
	}
	if log_file != "" {
		log_dirs := make([dynamic]string, allocator)
		add_with_target(&log_dirs, filepath.dir(log_file), allocator)
		if target, ok := resolve(log_file, allocator); ok && filepath.dir(target) != filepath.dir(log_file) {
			append(&log_dirs, filepath.dir(target))
		}
		plan.log_dirs = log_dirs[:]
	}
	if plan.mode != .Strict {
		return plan
	}

	readable := make([dynamic]string, allocator)
	files := make([dynamic]string, context.temp_allocator)
	for f in reread_files(cfg, config_path, context.temp_allocator) {
		append(&files, f.path)
	}
	ca := tlsx.default_ca_locations(context.temp_allocator)
	// The bundle is a file; the rest are directories of certificates.
	append(&files, ca[0])
	for path in files {
		add_with_target(&readable, filepath.dir(path), allocator)
		if target, ok := resolve(path, allocator); ok {
			append(&readable, filepath.dir(target))
		}
	}
	for dir in ca[1:] {
		add_with_target(&readable, strings.clone(dir, allocator), allocator)
	}
	for path in MOUNT_READS {
		append(&readable, path)
	}
	plan.readable = readable[:]
	return plan
}

// What the metrics and `config.probe_machine` read, granted at the mount.
@(private)
MOUNT_READS :: [?]string{"/proc", "/sys/fs/cgroup"}

// Append `path`, and where it resolves elsewhere, what it resolves to.
@(private)
add_with_target :: proc(out: ^[dynamic]string, path: string, allocator := context.allocator) {
	append(out, path)
	if target, ok := resolve(path, allocator); ok && target != path {
		append(out, target)
	}
}

// `path` with every symlink in it followed, or false when it does not resolve.
@(private)
resolve :: proc(path: string, allocator := context.allocator) -> (string, bool) {
	buf: [posix.PATH_MAX]u8
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	if posix.realpath(cpath, raw_data(buf[:])) == nil {
		return "", false
	}
	return strings.clone_from_cstring(cstring(raw_data(buf[:])), allocator), true
}
