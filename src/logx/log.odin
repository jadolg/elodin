package logx

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:sys/posix"
import "core:time"
import "elodin:loop"

/*
Not `core:log`: its file logger writes `[LEVEL] --- [date]` lines, where these are
logfmt (`ts= level= msg=` with quoted values) for log shippers to parse, and a
`log.Logger` that wrote them would be this package behind one more indirection.
*/
Level :: enum u8 {
	Debug,
	Info,
	Warn,
	Error,
}

@(private)
State :: struct {
	mu:      sync.Mutex,
	level:   Level,
	file:    ^os.File,
	to_file: bool,
	// See `init`.
	guarded: bool,
}

@(private)
state := State {
	level = .Info,
}

/*
Point logging at a file, or at stderr when `path` is empty.

`owner`: the process is root and will drop to this account, which may own the
log's directory (the docs allow it). A file `init` creates is given to it at
once, by descriptor: it is the process's own output, like the blocklist cache,
and the dropped process has to open its name again after a rotation. At once,
not at the drop, so a start that fails in between (port 53 taken) leaves a file
the next start can still use, not a root-owned one it did not create and so
leaves alone. A file already there is the operator's - possibly a shared system
log - and keeps its owner (Unbound declines to chown its log file for the same
reason); `warn_out_of_reach` in main names one the account cannot open.

With an owner, the start is guarded. A process taken over under that account
could leave a symlink on the path for the next root start to append to - or
create - whatever file it names, a hard link to append to one of root's, or a
FIFO to hang it - with no reader, or a reader that stops reading. So a symlink
on the path is refused, and so is anything at the name but a regular file with
one link, then and on every reopen. Without a drop there is no such account,
and a root-owned symlink such as /var/run is followed as before.

Returns the error if the file cannot be opened, in which case logging stays on
stderr rather than being silently lost.
*/
Owner :: struct {
	uid: posix.uid_t,
	gid: posix.gid_t,
}

init :: proc(level: Level, path: string = "", owner: Maybe(Owner) = nil) -> os.Error {
	guarded := owner != nil
	sync.mutex_lock(&state.mu)
	state.level = level
	sync.atomic_store(&state.guarded, guarded)
	err: os.Error
	if path != "" {
		f: ^os.File
		created: bool
		f, created, err = open_log(path, guarded)
		if err == nil {
			state.file = f
			state.to_file = true
			if o, has := owner.?; has && created {
				// A failure leaves it root's; see `owner` above.
				posix.fchown(posix.FD(os.fd(f)), o.uid, o.gid)
			}
		}
	}
	sync.mutex_unlock(&state.mu)

	if err != nil {
		return err
	}
	warn_if_readable(path)
	return nil
}

/*
Open `path` afresh and write to it from here on, or to stderr when `path` is
empty; what a SIGHUP does to the log.

Opened by name every time, even when the name is the one already in use: that is
what logrotate's default `create` arrangement relies on - it renames the file and
sends the signal, and the process goes on appending to the renamed one until it
opens the name again.

Returns the error, leaving the log where it was, when the file cannot be opened -
most likely because privileges were dropped after the old one was opened as
root, or a `guarded` refusal (see `init`). Nothing is lost that way, and the
caller says so through the log that is still working.
*/
reopen :: proc(path: string) -> os.Error {
	f: ^os.File
	if path != "" {
		err: os.Error
		f, _, err = open_log(path, sync.atomic_load(&state.guarded))
		if err != nil {
			return err
		}
	}

	sync.mutex_lock(&state.mu)
	old := state.file if state.to_file else nil
	state.file = f
	state.to_file = f != nil
	sync.mutex_unlock(&state.mu)

	if old != nil {
		os.close(old)
	}
	warn_if_readable(path)
	return nil
}

/*
Created readable and writable by its owner only. With `log.queries` on, the file
names every client and every name it looked up, which is nobody else's business
on the host; a group that ships the log is given it by the operator (logrotate's
`create 0640 <user> <group>`), not by default. A file that already exists keeps
the mode it has; `readable_by_others` says when that mode is too wide.

`created` says the open made the file, which O_EXCL decides in the kernel: a
file or symlink already at the name fails it and is appended to as it is.
*/
@(private)
open_log :: proc(path: string, guarded: bool) -> (f: ^os.File, created: bool, err: os.Error) {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	// NOCTTY as `os.open` sets it: a tty named here would otherwise become the
	// controlling terminal of a session leader such as a systemd service, and
	// its ^C or hangup would reach the process.
	base: linux.Open_Flags = {.WRONLY, .APPEND, .CREAT, .CLOEXEC, .NOCTTY}
	if guarded {
		// Not to wait at a FIFO for a reader that never comes; cleared below.
		base += {.NONBLOCK}
	}
	owner_only: linux.Mode = {.IRUSR, .IWUSR}
	fd, errno := open_resolved(cpath, base + {.EXCL}, owner_only, guarded)
	created = errno == .NONE
	if !created {
		if errno != .EEXIST {
			return nil, false, os.Platform_Error(errno)
		}
		// Guarded, not created here: a file removed since the O_EXCL open would
		// otherwise be made now, as root, by an open that does not hand it over.
		fd, errno = open_resolved(cpath, base - {.CREAT} if guarded else base, owner_only, guarded)
		if errno != .NONE {
			return nil, false, os.Platform_Error(errno)
		}
		if guarded {
			if errno = refused_at_name(fd); errno != .NONE {
				linux.close(fd)
				return nil, false, os.Platform_Error(errno)
			}
		}
	}
	if guarded {
		if errno = linux.fcntl(fd, linux.F_SETFL, linux.Open_Flags{.APPEND}); errno != .NONE {
			linux.close(fd)
			return nil, false, os.Platform_Error(errno)
		}
	}
	// `os.new_file` panics where it cannot name the descriptor through
	// /proc/self/fd (no /proc in a chroot), which `os.open` returns as an error.
	first: [1]u8
	if _, rerr := linux.readlink(fmt.ctprintf("/proc/self/fd/%d", fd), first[:]); rerr != .NONE {
		linux.close(fd)
		return nil, false, os.Platform_Error(rerr)
	}
	return os.new_file(uintptr(fd), path), created, nil
}

/*
`open`, or with `no_symlinks` an `openat2` that refuses a symlink anywhere on
the path (RESOLVE_NO_SYMLINKS): O_NOFOLLOW alone covers the last component, and
the account that may own the file's directory may own one above it too. Where
the kernel predates openat2 (5.6), or a seccomp filter that does not know it
answers EPERM (older container runtimes' default profiles), it falls back to
O_NOFOLLOW.

`core:sys/linux`, not `core:sys/posix`: the latter's O_NOFOLLOW is the x86 value
on every Linux, which on arm64 is O_LARGEFILE - the flag would be silently
dropped there. It has no openat2 wrapper, hence the system call by hand.
*/
@(private)
open_resolved :: proc(cpath: cstring, flags: linux.Open_Flags, mode: linux.Mode, no_symlinks: bool) -> (linux.Fd, linux.Errno) {
	if !no_symlinks {
		return linux.open(cpath, flags, mode)
	}
	RESOLVE_NO_SYMLINKS :: 0x04
	ret := openat2(cpath, flags, mode, RESOLVE_NO_SYMLINKS)
	if ret == -int(linux.Errno.ENOSYS) || (ret == -int(linux.Errno.EPERM) && !openat2_allowed()) {
		return linux.open(cpath, flags + {.NOFOLLOW}, mode)
	}
	if ret < 0 {
		return -1, linux.Errno(-ret)
	}
	return linux.Fd(ret), .NONE
}

// The raw system call, which `core:sys/linux` does not wrap: a descriptor, or a
// negated errno.
@(private)
openat2 :: proc(cpath: cstring, flags: linux.Open_Flags, mode: linux.Mode, resolve: u64) -> int {
	how := struct {
		flags, mode, resolve: u64,
	} {
		flags   = u64(transmute(u32)flags),
		// openat2 refuses a mode without O_CREAT.
		mode    = u64(transmute(u32)mode) if .CREAT in flags else 0,
		resolve = resolve,
	}
	return linux.syscall(linux.SYS_openat2, linux.AT_FDCWD, transmute(uintptr)cpath, &how, size_of(how))
}

/*
Whether openat2 runs at all here. A seccomp filter written before it refuses it
with EPERM for every path, "/" included; an EPERM for one path while "/" opens
is that path's own (a FUSE mount, say) and is not taken as a reason to walk the
path again with only O_NOFOLLOW, where a directory on it could be swapped for a
symlink in between.
*/
@(private)
openat2_allowed :: proc() -> bool {
	ret := openat2("/", {.PATH, .CLOEXEC}, {}, 0)
	if ret >= 0 {
		linux.close(linux.Fd(ret))
		return true
	}
	return ret != -int(linux.Errno.EPERM) && ret != -int(linux.Errno.ENOSYS)
}

/*
What a guarded open (see `init`) refuses at the name. A hard link is a
symlink's twin: where fs.protected_hardlinks is off, the account that may own
the directory can link the name to a file of root's for the start to append to
(EMLINK). Anything but a regular file or a character device is refused too
(ENXIO): a FIFO whose reader stops reading would block every line, under the
log's lock, once its buffer fills.
*/
@(private)
refused_at_name :: proc(fd: linux.Fd) -> linux.Errno {
	st: linux.Stat
	if errno := linux.fstat(fd, &st); errno != .NONE {
		return errno
	}
	// A character device (/dev/null, a console) is let through: making one
	// takes CAP_MKNOD, which the account does not have, and a symlink to one
	// is refused on the path already.
	if linux.S_ISCHR(st.mode) {
		return .NONE
	}
	if !linux.S_ISREG(st.mode) {
		return .ENXIO
	}
	if st.nlink > 1 {
		return .EMLINK
	}
	return .NONE
}

/*
For `--check`, which creates nothing: whether a `guarded` start (see `init`)
would refuse `path` - a symlink on the way to it, or at the name what
`refused_at_name` refuses; when there is no file yet, a symlink on the way to
its directory.
*/
guard_refuses :: proc(path: string) -> bool {
	probe :: proc(p: string, file: bool) -> linux.Errno {
		fd, errno := open_resolved(strings.clone_to_cstring(p, context.temp_allocator), {.PATH, .CLOEXEC}, {}, true)
		if errno != .NONE {
			return errno
		}
		defer linux.close(fd)
		// The O_NOFOLLOW fallback opens a symlink itself under O_PATH rather
		// than failing; it is not a regular file, so it is refused here as the
		// start's open refuses it - at the file only: that start follows a
		// symlinked directory.
		return refused_at_name(fd) if file else .NONE
	}
	errno := probe(path, true)
	if errno == .ENOENT {
		errno = probe(os.dir(path), false)
	}
	return is_guard_refusal(os.Platform_Error(errno))
}

// Said after a log file the guard refused (see `init`), so the errno is not left to explain it.
GUARD_HINT :: "; started as root with server.user set, a symlink anywhere on its path, a hard-linked file, a FIFO or a socket is refused, see docs/logging.md"

/*
`GUARD_HINT` when `err`, from `init` or `reopen`, is the guard's refusal: ELOOP
a symlink, EMLINK a hard link, ENXIO not a regular file. Empty otherwise.
*/
guard_hint :: proc(err: os.Error) -> string {
	return GUARD_HINT if sync.atomic_load(&state.guarded) && is_guard_refusal(err) else ""
}

@(private)
is_guard_refusal :: proc(err: os.Error) -> bool {
	return(
		err == os.Platform_Error(linux.Errno.ELOOP) ||
		err == os.Platform_Error(linux.Errno.EMLINK) ||
		err == os.Platform_Error(linux.Errno.ENXIO) \
	)
}

// Whether lines go to a file rather than stderr.
writing_to_file :: proc() -> bool {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)
	return state.to_file
}

/*
Whether the log file in use can be read by every account on the host: a file
an older elodin, or someone else, created with a wider mode than `open_log`
does. False when logging to stderr or when it cannot tell.
*/
@(private)
readable_by_others :: proc() -> bool {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)
	if !state.to_file {
		return false
	}
	st: posix.stat_t
	if posix.fstat(posix.FD(os.fd(state.file)), &st) != .OK {
		return false
	}
	// A device such as /dev/null is 0666 by design and holds nothing.
	return posix.S_ISREG(st.st_mode) && .IROTH in st.st_mode
}

/*
A log file `open_log` creates is owner-only, but one already there keeps its
mode - an upgrade from a release that created it 0644, or logrotate's
`create 0644`. With `log.queries` on it names every client, so a mode that lets
every account read it is said at each open rather than changed: the file is the
operator's. `init` and `reopen` call it once the lock is released.
*/
@(private)
warn_if_readable :: proc(path: string) {
	if readable_by_others() {
		warnf("log.file: %q can be read by any account that can reach its directory; 'chmod o-r' it, or set logrotate's create mode", path)
	}
}

shutdown :: proc() {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)
	if state.to_file && state.file != nil {
		os.close(state.file)
		state.file = nil
		state.to_file = false
	}
}

// Atomic, because `enabled` reads it without the lock from every thread.
set_level :: proc(level: Level) {
	sync.atomic_store(&state.level, level)
}

enabled :: proc(level: Level) -> bool {
	return level >= sync.atomic_load(&state.level)
}

@(private)
level_tag :: proc(level: Level) -> string {
	switch level {
	case .Debug:
		return "debug"
	case .Info:
		return "info"
	case .Warn:
		return "warn"
	case .Error:
		return "error"
	}
	return "unknown"
}

/*
Write one logfmt record: `ts=... level=... msg=...`, then whatever the caller
brought.

Every line is a sequence of key=value pairs, so a collector - Loki with
`| logfmt`, but anything else reading the format too - gets the time, the
severity and the message as fields without a pattern to maintain per line. The
timestamp is RFC 3339 in UTC rather than a date and a clock separated by a
space, because the space would end the value and the parser would take half of
it as a key.
*/
@(private)
write_line :: proc(level: Level, msg: string, fields: string) {
	now := loop.now()
	stamp_buf: [64]u8
	stamp := time.to_string_hms(now, stamp_buf[:])

	// On the stack first, so a line goes out when there is no memory to render
	// it in - which is when the lines about memory are written. See `render`.
	buf: [LINE_BUFFER]u8
	b := strings.builder_from_bytes(buf[:])
	write_record(&b, now, stamp, level, msg, fields)
	line := strings.to_string(b)
	if len(line) == LINE_BUFFER {
		long := strings.builder_make(context.temp_allocator)
		write_record(&long, now, stamp, level, msg, fields)
		// At least, not past: a record that exactly fills the buffer is whole.
		if s := strings.to_string(long); len(s) >= LINE_BUFFER && s[len(s) - 1] == '\n' {
			line = s
		} else {
			/*
			Cut short, but still one record: the message cut to what fits even
			quoted at its widest, and the fields left off. Cutting the rendered
			line instead can end it inside a quoted value, which no logfmt reader
			takes as a record. On a rune boundary, for the reason `cut_runes` gives.
			*/
			b = strings.builder_from_bytes(buf[:])
			write_record(&b, now, stamp, level, cut_runes(msg, CUT_MESSAGE), "")
			line = strings.to_string(b)
		}
	}

	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)

	// One write(2) per line, and no flush after it. An `os.File` is unbuffered,
	// so the write is already what `tail` and a shipper read, and survives the
	// process being killed; `os.flush` on one is fsync(2), a disk sync per
	// answered query under this lock.
	target := state.file if state.to_file && state.file != nil else os.stderr
	os.write_string(target, line)
}

@(private)
write_record :: proc(b: ^strings.Builder, now: time.Time, stamp: string, level: Level, msg: string, fields: string) {
	y, m, d := time.date(now)
	fmt.sbprintf(b, "ts=%04d-%02d-%02dT%sZ level=%s msg=", y, int(m), d, stamp, level_tag(level))
	write_quoted(b, msg)
	if fields != "" {
		strings.write_byte(b, ' ')
		strings.write_string(b, fields)
	}
	strings.write_byte(b, '\n')
}

/*
The longest record, and the longest message or field list, rendered without
allocating. Every line this server writes fits: a query line naming a
full-length name is a few hundred bytes.
*/
@(private)
LINE_BUFFER :: 2048
@(private)
PART_BUFFER :: 1024
/*
The message bytes a cut-short record keeps: four rendered bytes each at most
(`\x7f`), and the timestamp, level and quotes beside them, inside `LINE_BUFFER`.
*/
@(private)
CUT_MESSAGE :: LINE_BUFFER / 4 - 64

/*
`format` rendered into `buf`, or, when it does not fit, on the temp allocator -
and cut to `buf` when that has nothing to give either.

On a fiber the temp allocator is the fiber's scratch, whose blocks are mapped
as it grows. The lines that matter most are written at the moment the OS stops
mapping memory - a connection refused because no stack could be mapped - and
most of those are said once (`report_once`), so a line rendered on the scratch
there would come out empty and be gone for good.

`whole` is false for the cut: a field list cut there can end inside a quoted
value, which the caller leaves off rather than write, as `write_line` does.
*/
@(private)
render :: proc(buf: []u8, format: string, args: ..any) -> (s: string, whole: bool) {
	s = fmt.bprintf(buf, format, ..args)
	if len(s) < len(buf) {
		return s, true
	}
	// At least as long: a rendering that exactly fills `buf` is whole too.
	if long := fmt.tprintf(format, ..args); len(long) >= len(s) {
		return long, true
	}
	return cut_runes(s, len(s)), false
}

/*
`s` cut to at most `n` bytes, backed off to the start of a rune: a record cut
inside one is no longer UTF-8, which a shipper may refuse or mangle.
*/
@(private)
cut_runes :: proc(s: string, n: int) -> string {
	cut := min(len(s), max(n, 0))
	// The lead byte of the last rune before the cut, at most three back.
	lead := cut - 1
	for lead > 0 && lead > cut - 4 && s[lead] & 0xc0 == 0x80 {
		lead -= 1
	}
	if lead < 0 {
		return s[:cut]
	}
	width := 1
	switch {
	case s[lead] & 0xe0 == 0xc0:
		width = 2
	case s[lead] & 0xf0 == 0xe0:
		width = 3
	case s[lead] & 0xf8 == 0xf0:
		width = 4
	}
	if lead + width > cut {
		cut = lead
	}
	return s[:cut]
}

@(private)
emit :: proc(level: Level, format: string, args: ..any) {
	// Before the formatting, not after: at debug level off and `log.queries`
	// on, this is the only thing standing between the hot path and a rendered
	// string per query that nothing would read.
	if !enabled(level) {
		return
	}
	msg: [PART_BUFFER]u8
	m, _ := render(msg[:], format, ..args)
	write_line(level, m, "")
}

/*
Log a named event with fields of its own.

`msg` names the event and stays the same from one line to the next, which is
what makes it a thing to select on; `format` renders the key=value pairs that
differ. Values that can contain a space, a quote or an `=` have to go through
`quote` on the way in - the ones this server passes are numbers, enum names and
addresses, and the two that are neither say so at the call site.
*/
eventf :: proc(level: Level, msg: string, format: string, args: ..any) {
	if !enabled(level) {
		return
	}
	fields: [PART_BUFFER]u8
	f, whole := render(fields[:], format, ..args)
	write_line(level, msg, f if whole else "")
}

/*
Lets one event in a window through at `warn`, and counts the others in it.

For a condition a peer can provoke as often as it likes, where a `warn` per
occurrence would let it write to this server's disk. Once a window rather than
once per process: a fault that begins hours after the first one, or a second,
different one, still reaches `warn`.

The first event opens it at once, so there is a line to find; after that it
opens once per `GATE_WINDOW`, and the line says how many it passed over since
the one before it - which, after a quiet spell, can be hours back.
Lock-free, because the callers are accept loops and send loops.
*/
Gate :: struct {
	next: i64,
	held: u64,
}

GATE_WINDOW :: 60 * time.Second

// `now` is a monotonic clock reading in nanoseconds, a parameter so a test can
// cross the window without waiting for it.
gate_pass :: proc(g: ^Gate, now: i64) -> (loud: bool, held: u64) {
	for {
		next := sync.atomic_load(&g.next)
		if next != 0 && now < next {
			sync.atomic_add(&g.held, 1)
			return false, 0
		}
		if _, swapped := sync.atomic_compare_exchange_strong(&g.next, next, now + i64(GATE_WINDOW)); swapped {
			return true, sync.atomic_exchange(&g.held, 0)
		}
	}
}

gate_pass_now :: proc(g: ^Gate) -> (loud: bool, held: u64) {
	return gate_pass(g, loop.tick_now()._nsec)
}

// Whether a gate is inside its window, without spending it: for a caller that
// leaves the line to another one on the same event and only needs to know that
// one has just been said.
gate_shut :: proc(g: ^Gate, now: i64) -> bool {
	next := sync.atomic_load(&g.next)
	return next != 0 && now < next
}

/*
`warnf`, saying how many like it a `Gate` passed over since the last one.
*/
warnf_held :: proc(held: u64, format: string, args: ..any) {
	if held == 0 {
		emit(.Warn, format, ..args)
		return
	}
	if !enabled(.Warn) {
		return
	}
	msg: [PART_BUFFER]u8
	count: [32]u8
	m, _ := render(msg[:], format, ..args)
	write_line(.Warn, m, fmt.bprintf(count[:], "held=%d", held))
}

/*
`warnf` through a `Gate`, with the number it held back, and `debugf` while the
gate is shut.
*/
gated_warnf :: proc(g: ^Gate, format: string, args: ..any) {
	gated_warnf_from(g, "", format, ..args)
}

/*
`gated_warnf` for a line about a client's query: the `debug` line carries the
client as a field and the `warn` does not, since a `warn` a minute naming it
would keep a record of who asked whatever `log.queries` says, while `debug` is
switched on to find out.
*/
gated_warnf_from :: proc(g: ^Gate, client: string, format: string, args: ..any) {
	if loud, held := gate_pass_now(g); loud {
		warnf_held(held, format, ..args)
		return
	}
	if client == "" {
		debugf(format, ..args)
		return
	}
	if !enabled(.Debug) {
		return
	}
	msg, from: [PART_BUFFER]u8
	f := strings.builder_from_bytes(from[:])
	strings.write_string(&f, "client=")
	write_quoted(&f, client)
	m, _ := render(msg[:], format, ..args)
	write_line(.Debug, m, strings.to_string(f))
}

debugf :: proc(format: string, args: ..any) {
	emit(.Debug, format, ..args)
}

infof :: proc(format: string, args: ..any) {
	emit(.Info, format, ..args)
}

warnf :: proc(format: string, args: ..any) {
	emit(.Warn, format, ..args)
}

errorf :: proc(format: string, args: ..any) {
	emit(.Error, format, ..args)
}

/*
Turn a string into a logfmt value.

Quoted only when it has to be: a bare token reads the same to a parser and is
what an operator expects to see. Inside quotes the escaping is the one Go's
`strconv.Unquote` undoes, which is what the logfmt decoders behind Loki use, so
a message with a quote in it survives the round trip instead of ending the
value early. A newline is the case that matters most - unescaped it would make
one event arrive as two records, the second of them unparseable.
*/
quote :: proc(s: string) -> string {
	if !needs_quoting(s) {
		return s
	}
	b := strings.builder_make(context.temp_allocator)
	write_quoted(&b, s)
	return strings.to_string(b)
}

// `quote`, into a builder the caller holds.
@(private)
write_quoted :: proc(b: ^strings.Builder, s: string) {
	if !needs_quoting(s) {
		strings.write_string(b, s)
		return
	}
	strings.write_byte(b, '"')
	for i in 0 ..< len(s) {
		switch c := s[i]; c {
		case '"', '\\':
			strings.write_byte(b, '\\')
			strings.write_byte(b, c)
		case '\n':
			strings.write_string(b, "\\n")
		case '\r':
			strings.write_string(b, "\\r")
		case '\t':
			strings.write_string(b, "\\t")
		case:
			// Bytes above 0x7f are the continuation of a UTF-8 rune and go
			// through as they are; the rest of the control range does not.
			if c < 0x20 || c == 0x7f {
				fmt.sbprintf(b, "\\x%02x", c)
			} else {
				strings.write_byte(b, c)
			}
		}
	}
	strings.write_byte(b, '"')
}

@(private)
needs_quoting :: proc(s: string) -> bool {
	// An empty value has to be written as "" - `key=` on its own is a key with
	// no value to some parsers and a syntax error to others.
	if s == "" {
		return true
	}
	for i in 0 ..< len(s) {
		switch c := s[i]; c {
		case ' ', '"', '=', '\\', 0x7f:
			return true
		case:
			if c < 0x20 {
				return true
			}
		}
	}
	return false
}

parse_level :: proc(s: string) -> (Level, bool) {
	switch strings.to_lower(s, context.temp_allocator) {
	case "debug":
		return .Debug, true
	case "info":
		return .Info, true
	case "warn", "warning":
		return .Warn, true
	case "error":
		return .Error, true
	}
	return .Info, false
}
