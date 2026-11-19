/*
Narrowing what the process may do once it is serving (#417).

`privdrop` changes who the process is. This package narrows what that account
may then do, for the same reason: everything after startup parses bytes an
attacker chose, and a memory bug in that code runs with whatever the process
still holds. `packaging/elodin.service` gets the same from systemd; this is for
a bare `sudo elodin`, a container, and every other start.

Three layers, each set once and kept for the life of the process:

- `PR_SET_NO_NEW_PRIVS`: no `execve` can raise privilege again.
- Landlock (Linux 5.13 and later): writing, creating, removing and executing are
  confined to the paths the plan names, and under `.Strict` reading is too.
- A seccomp allowlist, under `.Strict` only (`filter_syscalls`).

The first two apply to the calling thread and to threads it starts afterwards,
and to no other thread, so `confine` runs before the process starts any. The
filter is installed with `TSYNC`, which puts it on every thread at once.
*/
package sandbox

Mode :: enum u8 {
	// Nothing here is applied.
	Off,
	// No new privileges, and Landlock on writes and execution.
	Basic,
	// `.Basic`, Landlock on reads as well, and the syscall allowlist.
	Strict,
}

// What `confine` grants. Paths that do not exist when it runs are skipped and
// listed in `Report.missing`.
Plan :: struct {
	mode:      Mode,
	// Read, write, create and replace files beneath; the blocklist cache.
	cache_dir: string,
	// Write and create files beneath; the directory the log file is in.
	log_dir:   string,
	// Read beneath, under `.Strict`: a file or a directory.
	readable:  []string,
}

Landlock_Status :: enum u8 {
	// The plan's mode is `.Off`.
	Off,
	Applied,
	// The kernel has no Landlock, or it is disabled, or a container's own
	// filter refuses its calls. `Report.errno` says which.
	Unavailable,
	// Landlock is there and a call into it failed; nothing was restricted.
	Failed,
}

Report :: struct {
	landlock: Landlock_Status,
	// The Landlock ABI version the kernel reports, 0 when it has none.
	abi:      int,
	errno:    i32,
	// The plan's paths that could not be opened, so carry no rule.
	missing:  [dynamic]string,
}
