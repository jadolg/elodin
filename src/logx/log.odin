package logx

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"

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

shutdown :: proc() {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)
	if state.to_file && state.file != nil {
		os.close(state.file)
		state.file = nil
		state.to_file = false
	}
}

set_level :: proc(level: Level) {
	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)
	state.level = level
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
	buf: [64]u8
	stamp := time.to_string_hms(now, buf[:])
	y, m, d := time.date(now)

	line: string
	if fields == "" {
		line = fmt.tprintf(
			"ts=%04d-%02d-%02dT%sZ level=%s msg=%s\n",
			y,
			int(m),
			d,
			stamp,
			level_tag(level),
			quote(msg),
		)
	} else {
		line = fmt.tprintf(
			"ts=%04d-%02d-%02dT%sZ level=%s msg=%s %s\n",
			y,
			int(m),
			d,
			stamp,
			level_tag(level),
			quote(msg),
			fields,
		)
	}

	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)

	// Flush every line. Buffered output would mean an operator tailing the log,
	// or anything watching it, sees events long after they happened - and loses
	// them entirely if the process is killed.
	target := state.file if state.to_file && state.file != nil else os.stderr
	os.write_string(target, line)
	os.flush(target)
}

@(private)
emit :: proc(level: Level, format: string, args: ..any) {
	// Before the formatting, not after: at debug level off and `log.queries`
	// on, this is the only thing standing between the hot path and a rendered
	// string per query that nothing would read.
	if !enabled(level) {
		return
	}
	write_line(level, fmt.tprintf(format, ..args), "")
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
	write_line(level, msg, fmt.tprintf(format, ..args))
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
	strings.write_byte(&b, '"')
	for i in 0 ..< len(s) {
		switch c := s[i]; c {
		case '"', '\\':
			strings.write_byte(&b, '\\')
			strings.write_byte(&b, c)
		case '\n':
			strings.write_string(&b, "\\n")
		case '\r':
			strings.write_string(&b, "\\r")
		case '\t':
			strings.write_string(&b, "\\t")
		case:
			// Bytes above 0x7f are the continuation of a UTF-8 rune and go
			// through as they are; the rest of the control range does not.
			if c < 0x20 || c == 0x7f {
				fmt.sbprintf(&b, "\\x%02x", c)
			} else {
				strings.write_byte(&b, c)
			}
		}
	}
	strings.write_byte(&b, '"')
	return strings.to_string(b)
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
