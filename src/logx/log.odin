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
		return "DEBUG"
	case .Info:
		return "INFO "
	case .Warn:
		return "WARN "
	case .Error:
		return "ERROR"
	}
	return "?????"
}

@(private)
emit :: proc(level: Level, format: string, args: ..any) {
	if !enabled(level) {
		return
	}
	now := time.now()
	buf: [64]u8
	stamp := time.to_string_hms(now, buf[:])
	y, m, d := time.date(now)

	body := fmt.tprintf(format, ..args)
	line := fmt.tprintf("%04d-%02d-%02d %s %s %s\n", y, int(m), d, stamp, level_tag(level), body)

	sync.mutex_lock(&state.mu)
	defer sync.mutex_unlock(&state.mu)

	// Flush every line. Buffered output would mean an operator tailing the log,
	// or anything watching it, sees events long after they happened - and loses
	// them entirely if the process is killed.
	target := state.file if state.to_file && state.file != nil else os.stderr
	os.write_string(target, line)
	os.flush(target)
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
