package main

import "core:os"
import "core:path/filepath"
import "core:slice"
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
		cfg.server.landlock = true
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
a reload that turns it on, and where the log file is, which a SIGHUP reopens by
name - nothing for a character device such as `/dev/stdout`, which is written
through the descriptor already open and would otherwise grant all of `/dev`.
Reads, which only `.Strict` confines: where every file in `reread_files` is,
listed or not and with blocking on or not, as a reload may turn either on; the
system resolver's `/etc/resolv.conf` and `/etc/hosts`, which a list download
falls back to; OpenSSL's default trust store, with the directories its hashed
entries point into; `/proc` and `/sys/fs/cgroup`, which the metrics and the
sizing read. See `add_dirs_of` for what "where a file is" grants.

`/proc` and `/sys/fs/cgroup` are granted whole: procfs makes a new inode at
every lookup of an entry the kernel has let go of, which a rule on
`/proc/<pid>` would no longer match, and only a mount's root stays.
*/
@(private)
sandbox_plan :: proc(cfg: ^config.Config, config_path, log_file: string, allocator := context.allocator) -> sandbox.Plan {
	plan := sandbox.Plan {
		mode = cfg.server.sandbox,
	}
	if cache := cfg.blocking.cache_dir; cache != "" && (cfg.blocking.enabled || os.exists(cache)) {
		plan.cache_dir = cache
	}
	if log_file != "" && !is_character_device(log_file) {
		log_dirs := make([dynamic]string, allocator)
		add_dirs_of(&log_dirs, log_file, allocator)
		plan.log_dirs = log_dirs[:]
	}
	if plan.mode != .Strict {
		return plan
	}

	readable := make([dynamic]string, allocator)
	for f in reread_files(cfg, config_path, context.temp_allocator, in_use_only = false) {
		add_dirs_of(&readable, f.path, allocator)
	}
	for path in RESOLVER_FILES {
		add_dirs_of(&readable, path, allocator)
	}
	ca := tlsx.default_ca_locations(context.temp_allocator)
	// The bundle is a file; the rest are directories of certificates.
	add_dirs_of(&readable, ca[0], allocator)
	for dir in ca[1:] {
		add_cert_dir(&readable, dir, allocator)
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

// What `netx.resolve` reads, for a list download nothing bootstraps.
@(private)
RESOLVER_FILES :: [?]string{"/etc/resolv.conf", "/etc/hosts"}

/*
Append where `file` is: its directory, and, where that or the file is reached
through a symlink, the directory it resolves to - Landlock judges the file
reached, not the name, and a directory rather than the file outlives a
renewal that re-points the link, as certbot's does. A file directly in `/` is
granted alone, since its directory would be everything.
*/
@(private)
add_dirs_of :: proc(out: ^[dynamic]string, file: string, allocator := context.allocator) {
	add :: proc(out: ^[dynamic]string, dir, file: string) {
		path := file if dir == "/" else dir
		if !slice.contains(out[:], path) {
			append(out, path)
		}
	}
	add(out, filepath.dir(file), file)
	if dir, ok := resolve(filepath.dir(file), allocator); ok {
		add(out, dir, file)
	}
	if target, ok := resolve(file, allocator); ok {
		add(out, filepath.dir(target), target)
	}
}

/*
Append a directory of hashed certificates and every directory its entries
resolve into. On Debian and Ubuntu each `/etc/ssl/certs/<hash>.0` leads to
`/usr/share/ca-certificates/mozilla`, and a build whose bundle file is absent -
the static one on those systems - verifies through those links alone.
*/
@(private)
add_cert_dir :: proc(out: ^[dynamic]string, dir: string, allocator := context.allocator) {
	for d in ([2]string{dir, resolve(dir, allocator) or_else dir}) {
		if !slice.contains(out[:], d) {
			append(out, d)
		}
	}
	entries, err := os.read_directory_by_path(dir, -1, context.temp_allocator)
	if err != nil {
		return
	}
	for e in entries {
		if target, ok := resolve(e.fullpath, allocator); ok {
			if d := filepath.dir(target); !slice.contains(out[:], d) {
				append(out, d)
			}
		}
	}
}

// Whether `path` is, or leads to, a character device.
@(private)
is_character_device :: proc(path: string) -> bool {
	st: posix.stat_t
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	return posix.stat(cpath, &st) == .OK && posix.S_ISCHR(st.st_mode)
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
