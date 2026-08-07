package logx

import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:testing"

/*
One test proc, on purpose.

The logger is process-wide state - a level, a mutex, one file handle - and the
test runner gives each `@(test)` proc a thread of its own. Two of them here
would interleave their lines in the same file and race the level, so everything
this package has to say is said in sequence below.
*/
@(test)
test_every_line_is_logfmt :: proc(t: ^testing.T) {
	dir, path, ok := open_scratch_log(t)
	if !ok {
		return
	}
	defer os.remove_all(dir)
	defer shutdown()

	infof("elodin %s starting", "1.2.3")
	debugf("this one is below the level")
	infof(`he said "hi" and left C:\tmp`)
	infof("first\nsecond")
	infof("ready")
	set_level(.Debug)
	debugf("now this one is not")
	warnf("careful")
	errorf("broken")
	eventf(.Info, "stats", "queries=%d blocked=%d", 12, 3)
	eventf(.Info, "query", "name=%s", quote("a name with spaces"))

	lines := log_lines(t, path)
	if !testing.expectf(t, len(lines) == 9, "%d lines written, want 9:\n%v", len(lines), lines) {
		return
	}

	// A record Loki can parse starts with the two fields every record has, in
	// the same order, before anything specific to the event.
	testing.expect_value(t, after_stamp(t, lines[0]), `level=info msg="elodin 1.2.3 starting"`)

	for line, i in lines {
		expect_rfc3339_stamp(t, line, i)
	}

	// A quote inside the message would otherwise close the value early, and a
	// newline would split one event into two records.
	testing.expect_value(t, after_stamp(t, lines[1]), `level=info msg="he said \"hi\" and left C:\\tmp"`)
	testing.expect_value(t, after_stamp(t, lines[2]), `level=info msg="first\nsecond"`)

	// Nothing to escape and nothing to separate: quoting it would only be noise.
	testing.expect_value(t, after_stamp(t, lines[3]), "level=info msg=ready")

	testing.expect_value(t, after_stamp(t, lines[4]), "level=debug msg=\"now this one is not\"")
	testing.expect_value(t, after_stamp(t, lines[5]), "level=warn msg=careful")
	testing.expect_value(t, after_stamp(t, lines[6]), "level=error msg=broken")

	// The fields a caller passes are its own, and land beside msg rather than
	// inside it, which is the whole point of the format.
	testing.expect_value(t, after_stamp(t, lines[7]), "level=info msg=stats queries=12 blocked=3")
	testing.expect_value(t, after_stamp(t, lines[8]), `level=info msg=query name="a name with spaces"`)
}

@(private = "file")
open_scratch_log :: proc(t: ^testing.T) -> (dir: string, path: string, ok: bool) {
	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		testing.expectf(t, false, "no temporary directory: %v", terr)
		return
	}
	dir, _ = filepath.join({tmp, "elodin-logx-test"}, context.temp_allocator)
	os.remove_all(dir)
	if err := os.make_directory(dir); err != nil {
		testing.expectf(t, false, "cannot create %s: %v", dir, err)
		return
	}
	path, _ = filepath.join({dir, "elodin.log"}, context.temp_allocator)
	if !init(.Info, path) {
		testing.expectf(t, false, "cannot open %s for logging", path)
		os.remove_all(dir)
		return
	}
	return dir, path, true
}

@(private = "file")
log_lines :: proc(t: ^testing.T, path: string) -> []string {
	data, err := os.read_entire_file(path, context.temp_allocator)
	if err != nil {
		testing.expectf(t, false, "cannot read %s back: %v", path, err)
		return {}
	}
	text := strings.trim_right(string(data), "\n")
	if text == "" {
		return {}
	}
	return strings.split(text, "\n", context.temp_allocator)
}

// Everything after the timestamp, which is the part a test can pin exactly.
@(private = "file")
after_stamp :: proc(t: ^testing.T, line: string) -> string {
	space := strings.index_byte(line, ' ')
	if space < 0 {
		testing.expectf(t, false, "no fields after the timestamp in %q", line)
		return line
	}
	return line[space + 1:]
}

// ts=2026-08-07T09:12:33Z - the shape Loki reads as a time without being told
// how, which a space between the date and the clock would cost.
@(private = "file")
expect_rfc3339_stamp :: proc(t: ^testing.T, line: string, i: int) {
	STAMP :: len("ts=2026-08-07T09:12:33Z")
	if !testing.expectf(t, len(line) > STAMP, "line %d is too short for a timestamp: %q", i, line) {
		return
	}
	stamp := line[:STAMP]
	testing.expectf(t, strings.has_prefix(stamp, "ts="), "line %d does not start with ts=: %q", i, stamp)
	testing.expectf(t, stamp[13] == 'T', "line %d has no T between date and clock: %q", i, stamp)
	testing.expectf(t, stamp[STAMP - 1] == 'Z', "line %d is not marked UTC: %q", i, stamp)
	rest := stamp[3:]
	for at in 0 ..< len(rest) {
		switch at {
		case 4, 7, 10, 13, 16, 19:
			continue
		}
		c := rest[at]
		testing.expectf(t, c >= '0' && c <= '9', "line %d: %q is not a digit at %d", i, rune(c), at)
	}
}
