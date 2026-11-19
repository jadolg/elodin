package main

import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:sys/posix"
import "elodin:config"
import "elodin:logx"
import "elodin:netx"
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
		return
	}
	if cfg.blocking.enabled && cfg.blocking.cache_dir != "" {
		server.make_directories(cfg.blocking.cache_dir)
	}
	log_file := cfg.log.file if logx.writing_to_file() else ""
	plan, pinned := sandbox_plan(cfg, config_path, log_file, context.temp_allocator)
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
		warn_unreachable_later(cfg)
		for file in pinned {
			logx.warnf(
				"server.sandbox: %q is directly in %s, so the sandbox reaches only that file and not the directory; one that replaces it - an editor, a renewal, a log rotation - is not seen until a restart: give it a directory of its own",
				file,
				filepath.dir(file),
			)
		}
		if plan.mode == .Strict {
			logx.infof("server.sandbox: strict reads %s", strings.join(plan.readable, ", ", context.temp_allocator))
		}
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
	return
}

/*
Say, once Landlock is in force, what it will refuse a reload that the operator
could otherwise expect to work: a cache directory blocking may be turned on
for that is not there to grant, and, under strict, list hosts resolved through
`/etc/resolv.conf`, whose rule a resolver that replaces the file would leave on
the old one.
*/
@(private)
warn_unreachable_later :: proc(cfg: ^config.Config) {
	if cache := cfg.blocking.cache_dir; !cfg.blocking.enabled && cache != "" && !os.exists(cache) {
		logx.warnf(
			"server.sandbox: blocking.cache_dir %q does not exist, so a reload that turns blocking on cannot keep copies of the lists until a restart",
			cache,
		)
	}
	if cfg.server.sandbox == .Strict && len(cfg.upstream.bootstrap) == 0 {
		if host, found := system_resolved_list_host(cfg); found {
			logx.warnf(
				"server.sandbox: list host %q is resolved through /etc/resolv.conf, which strict reads only as it is now; set upstream.bootstrap so a resolver that rewrites it later does not stop the downloads",
				host,
			)
		}
	}
}

// The first host of a list URL that is a name rather than an address: what
// `upstream.resolve_address` resolves through the system when nothing bootstraps.
@(private)
system_resolved_list_host :: proc(cfg: ^config.Config) -> (host: string, found: bool) {
	if !cfg.blocking.enabled {
		return
	}
	for set in ([2][]config.Block_List{cfg.blocking.lists, cfg.blocking.allow_lists}) {
		for list in set {
			if !list.enabled || list.url == "" {
				continue
			}
			_, authority, _, ok := netx.split_url(list.url)
			if !ok {
				continue
			}
			name, _, split := netx.split_port(authority)
			if split && netx.parse_address(name) == nil {
				return name, true
			}
		}
	}
	return
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
a reload that turns it on, and the directory of the file the log leads to,
which a SIGHUP makes again after a rotation (`log_dir_of`) - only for a regular
file or one not made yet: a device, FIFO or socket, such as `/dev/stdout`, is
written through the descriptor already open.
Reads, which only `.Strict` confines: where every file in `reread_files` is,
listed or not and with blocking on or not, as a reload may turn either on; the
system resolver's `/etc/resolv.conf` and `/etc/hosts`, which a list download
falls back to, by the files themselves (`add_file_rule`); OpenSSL's default trust store, with the directories its hashed
entries point into; `/proc` and `/sys/fs/cgroup`, which the metrics and the
sizing read. See `add_dirs_of` for what "where a file is" grants; `pinned` lists
the files - a log among them - granted alone, being directly in a directory in
`PINNED_DIRS`.

`/proc` and `/sys/fs/cgroup` are granted whole: procfs makes a new inode at
every lookup of an entry the kernel has let go of, which a rule on
`/proc/<pid>` would no longer match, and only a mount's root stays.
*/
@(private)
sandbox_plan :: proc(
	cfg: ^config.Config,
	config_path, log_file: string,
	allocator := context.allocator,
) -> (
	plan: sandbox.Plan,
	pinned: []string,
) {
	plan.mode = cfg.server.sandbox
	if cache := cfg.blocking.cache_dir; cache != "" && (cfg.blocking.enabled) {
		plan.cache_dir = cache
	}
	pins := make([dynamic]string, allocator)
	if log_file != "" && regular_or_missing(log_file) {
		if dir, ok := log_dir_of(log_file, allocator); ok {
			grant := dir
			if is_pinned(dir) {
				// Written as it is; a rotation cannot make it again there.
				grant = resolve(log_file, allocator) or_else ""
				append(&pins, log_file)
			}
			// MUTATION: no log grant.
		}
	}
	if plan.mode != .Strict {
		return plan, pins[:]
	}

	readable := make([dynamic]string, allocator)
	for f in reread_files(cfg, config_path, context.temp_allocator, in_use_only = false) {
		add_dirs_of(&readable, &pins, f.path, allocator)
	}
	// MUTATION: no resolver files.
	ca := tlsx.default_ca_locations(context.temp_allocator)
	// The bundle is a file; the rest are directories of certificates.
	add_dirs_of(&readable, &pins, ca[0], allocator)
	for dir in ca[1:] {
		add_cert_dir(&readable, dir, allocator)
	}
	for path in MOUNT_READS {
		append(&readable, path)
	}
	plan.readable = readable[:]
	return plan, pins[:]
}

/*
The directory a log at `file` is made in: that of the file it resolves to, or,
not made yet, of the directory it would be made in, resolved. Never the name's
own directory, which for `/dev/stdout` led to a regular file is all of `/dev`:
Landlock judges the file reached, not the name.
*/
@(private)
log_dir_of :: proc(file: string, allocator := context.allocator) -> (string, bool) {
	if target, ok := resolve(file, allocator); ok {
		return filepath.dir(target), true
	}
	return resolve(filepath.dir(file), allocator)
}

/*
Directories whose every file a strict read grant would expose: a re-read file
directly in one is granted alone (`add_dirs_of`), and named at startup.
*/
@(private)
PINNED_DIRS :: [?]string{"/", "/etc"}

@(private)
is_pinned :: proc(dir: string) -> bool {
	for pinned in PINNED_DIRS {
		if dir == pinned {
			return true
		}
	}
	return false
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
renewal that re-points the link, as certbot's does. A directory in
`PINNED_DIRS` is never granted: the file itself is, and goes on `pinned`.
*/
@(private)
add_dirs_of :: proc(out, pinned: ^[dynamic]string, file: string, allocator := context.allocator) {
	add :: proc(out, pinned: ^[dynamic]string, dir, file: string) {
		path := dir
		if is_pinned(dir) {
			path = file
			if !slice.contains(pinned[:], file) {
				append(pinned, file)
			}
		}
		if !slice.contains(out[:], path) {
			append(out, path)
		}
	}
	add(out, pinned, filepath.dir(file), file)
	if dir, ok := resolve(filepath.dir(file), allocator); ok {
		add(out, pinned, dir, file)
	}
	// MUTATION: no symlink targets.
}

/*
Append `file` itself, which Landlock opens to the file it leads to, and, where
it is a symlink, the directory of that file: the system resolver's files are
in `/etc`, whose directory would be every secret there, and systemd-resolved
replaces its `resolv.conf` beside the old one.
*/
@(private)
add_file_rule :: proc(out: ^[dynamic]string, file: string, allocator := context.allocator) {
	if !slice.contains(out[:], file) {
		append(out, file)
	}
	if target, ok := resolve(file, allocator); ok && target != file {
		if d := filepath.dir(target); !slice.contains(out[:], d) {
			append(out, d)
		}
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
			if d := filepath.dir(target); false && !slice.contains(out[:], d) {
				append(out, d)
			}
		}
	}
}

// Whether `path` leads to a regular file, or to nothing yet: what a log the
// process creates and rotates is. A device, FIFO or socket is written through
// the descriptor already open (`logx.reopen` keeps it).
@(private)
regular_or_missing :: proc(path: string) -> bool {
	st: posix.stat_t
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	if posix.stat(cpath, &st) != .OK {
		return posix.errno() == .ENOENT
	}
	return posix.S_ISREG(st.st_mode)
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
