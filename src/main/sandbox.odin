package main

import "core:fmt"
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
Put `server.sandbox`'s first two layers on the process (#417).

Called before the first thread starts: `PR_SET_NO_NEW_PRIVS` and Landlock hold
for the calling thread and the threads it starts, and an event loop started
before this would parse every query outside them. Still root here when started
as root, which Landlock does not exempt: the startup work left - building the
first generation, the first list rebuild, the drop - is within the plan.

The cache directory is made here when it is missing, so it has a rule: the
rebuild would otherwise make it after Landlock, inside a parent nothing may
write to.

A process that cannot set `PR_SET_NO_NEW_PRIVS` ends: the operator asked for a
sandbox, and the layers after it depend on it. A missing Landlock is a warning.
*/
@(private)
confine_process :: proc(cfg: ^config.Config, config_path: string) {
	if cfg.server.sandbox == .Off {
		return
	}
	if cfg.blocking.enabled && cfg.blocking.cache_dir != "" {
		server.make_directories(cfg.blocking.cache_dir)
	}
	plan := sandbox_plan(cfg, config_path, context.temp_allocator)
	report, ok := sandbox.confine(plan, context.temp_allocator)
	if !ok {
		logx.errorf("server.sandbox: cannot set no_new_privs; not starting without it")
		os.exit(1)
	}
	switch report.landlock {
	case .Off, .Applied:
	case .Unavailable:
		logx.warnf(
			"server.sandbox: Landlock is unavailable (%s), so writes are not confined; it needs Linux 5.13 with landlock among the lsm= modules",
			posix.strerror(posix.Errno(report.errno)),
		)
	case .Failed:
		logx.warnf("server.sandbox: Landlock failed (%s), so writes are not confined", posix.strerror(posix.Errno(report.errno)))
	}
	for path in report.missing {
		logx.warnf("server.sandbox: %q does not exist, so it stays out of reach until a restart", path)
	}
	sandbox_landlock_abi = report.abi
}

// The Landlock ABI `confine_process` put in force, 0 for none, for the line
// `filter_process` writes.
@(private)
sandbox_landlock_abi: int

/*
Install `server.sandbox: strict`'s syscall allowlist, after the drop, and say
what the process now runs under. A strict sandbox that cannot be had ends the
process, as a failed drop does.
*/
@(private)
filter_process :: proc(cfg: ^config.Config) {
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
	logx.eventf(
		.Info,
		"sandbox",
		"mode=%s no_new_privs=true landlock_abi=%d seccomp=%v",
		sandbox_mode_name(cfg.server.sandbox),
		sandbox_landlock_abi,
		seccomp,
	)
}

@(private)
sandbox_mode_name :: proc(m: sandbox.Mode) -> string {
	switch m {
	case .Off:
		return "off"
	case .Basic:
		return "basic"
	case .Strict:
		return "strict"
	}
	return "unknown"
}

/*
What the configuration in `cfg` needs from the filesystem once it is serving.

Writes: the blocklist cache, with blocking on, and the directory of the log file
in use, which a SIGHUP reopens by name. Reads, which only `.Strict` confines:
the directory of every file a reload or a rebuild reads again - the
configuration, the DoT and DoH certificates and keys, `file:` lists, OpenSSL's
default trust store - and, for each that is a symlink, the directory of what it
points to, because Landlock judges the file reached, not the name. A directory
rather than the file: certbot renews by pointing the symlink at a new file
beside the old one. Then the `/proc` and `/sys` files the metrics and the
sizing read.
*/
@(private)
sandbox_plan :: proc(cfg: ^config.Config, config_path: string, allocator := context.allocator) -> sandbox.Plan {
	plan := sandbox.Plan {
		mode = cfg.server.sandbox,
	}
	if cfg.blocking.enabled {
		plan.cache_dir = cfg.blocking.cache_dir
	}
	if logx.writing_to_file() {
		plan.log_dir = filepath.dir(cfg.log.file)
	}
	if plan.mode != .Strict {
		return plan
	}

	readable := make([dynamic]string, allocator)
	files := make([dynamic]string, context.temp_allocator)
	append(&files, config_path)
	for ln in ([2]config.Listener{cfg.listeners.dot, cfg.listeners.doh}) {
		if ln.enabled {
			append(&files, ln.cert_file, ln.key_file)
		}
	}
	if cfg.blocking.enabled {
		for set in ([2][]config.Block_List{cfg.blocking.lists, cfg.blocking.allow_lists}) {
			for list in set {
				if list.enabled && list.file != "" {
					append(&files, list.file)
				}
			}
		}
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
	append(&readable, fmt.aprintf("/proc/%d", posix.getpid(), allocator = allocator))
	for path in PROC_READS {
		append(&readable, path)
	}
	plan.readable = readable[:]
	return plan
}

// What the metrics and `config.probe_machine` read outside `/proc/<pid>`.
@(private)
PROC_READS :: [?]string{"/proc/meminfo", "/proc/sys/vm/max_map_count", "/sys/fs/cgroup"}

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
