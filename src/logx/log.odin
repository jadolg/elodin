package logx

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"

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
}

@(private)
state := State {
	level = .Info,
}

/*
Point logging at a file, or at stderr when `path` is empty.

Returns false if the file cannot be opened, in which case logging stays on
stderr rather than being silently lost.
*/
init :: proc(level: Level, path: string = "") -> bool {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)

	state.level = level
	if path == "" {
		return true
	}
	f, err := os.open(path, {.Write, .Create, .Append}, os.Permissions_Read_All + {.Write_User})
	if err != nil {
		return false
	}
	state.file = f
	state.to_file = true
	return true
}

/*
Open `path` afresh and write to it from here on, or to stderr when `path` is
empty; what a SIGHUP does to the log.

Opened by name every time, even when the name is the one already in use: that is
what logrotate's default `create` arrangement relies on - it renames the file and
sends the signal, and the process goes on appending to the renamed one until it
opens the name again.

Returns false, leaving the log where it was, when the file cannot be opened -
most likely because privileges were dropped after the old one was opened as
root. Nothing is lost that way, and the caller says so through the log that is
still working.
*/
reopen :: proc(path: string) -> bool {
	f: ^os.File
	if path != "" {
		err: os.Error
		f, err = os.open(path, {.Write, .Create, .Append}, os.Permissions_Read_All + {.Write_User})
		if err != nil {
			return false
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
	return true
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
	now := time.now()
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
		if s := strings.to_string(long); len(s) > LINE_BUFFER && s[len(s) - 1] == '\n' {
			line = s
		} else {
			// Cut short, but still one record.
			buf[LINE_BUFFER - 1] = '\n'
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
`format` rendered into `buf`, or, when it does not fit, on the temp allocator -
and cut to `buf` when that has nothing to give either.

On a fiber the temp allocator is the fiber's scratch, whose blocks are mapped
as it grows. The lines that matter most are written at the moment the OS stops
mapping memory - a connection refused because no stack could be mapped - and
most of those are said once (`report_once`), so a line rendered on the scratch
there would come out empty and be gone for good.
*/
@(private)
render :: proc(buf: []u8, format: string, args: ..any) -> string {
	s := fmt.bprintf(buf, format, ..args)
	if len(s) < len(buf) {
		return s
	}
	if long := fmt.tprintf(format, ..args); len(long) > len(s) {
		return long
	}
	return s
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
	write_line(level, render(msg[:], format, ..args), "")
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
	write_line(level, msg, render(fields[:], format, ..args))
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
	return gate_pass(g, time.tick_now()._nsec)
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
	write_line(.Warn, render(msg[:], format, ..args), fmt.bprintf(count[:], "held=%d", held))
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
	write_line(.Debug, render(msg[:], format, ..args), strings.to_string(f))
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
