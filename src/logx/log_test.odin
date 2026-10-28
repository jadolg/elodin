package logx

import "base:runtime"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:testing"
import "core:unicode/utf8"

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
	g: Gate
	gated_warnf_from(&g, "192.0.2.1:53000", "query %s failed", "a.example")
	gated_warnf_from(&g, "192.0.2.1:53000", "query %s failed", "b.example")

	lines := log_lines(t, path)
	if !testing.expectf(t, len(lines) == 11, "%d lines written, want 11:\n%v", len(lines), lines) {
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

	// A gated line about a client's query names the client at debug, where it
	// is asked for, and not on the warn a window, which is written regardless.
	testing.expect_value(t, after_stamp(t, lines[9]), `level=warn msg="query a.example failed"`)
	testing.expect_value(t, after_stamp(t, lines[10]), `level=debug msg="query b.example failed" client=192.0.2.1:53000`)

	/*
	A line still goes out when there is no memory to render it in. That is the
	moment the lines about memory are written - the OS refusing a fiber's stack
	is also the OS refusing the scratch the line would be formatted out of - and
	most of them are said once (`report_once`), so one lost is lost for good.
	*/
	{
		context.temp_allocator = refusing_allocator()
		warnf("refusing a connection, the OS would not map a stack for it - %s", "check RLIMIT_AS")
	}
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 12, "%d lines written once memory ran out, want 12", len(lines)) {
		return
	}
	testing.expect_value(
		t,
		after_stamp(t, lines[11]),
		`level=warn msg="refusing a connection, the OS would not map a stack for it - check RLIMIT_AS"`,
	)

	// Past the stack buffers a line is rendered whole on the temp allocator, and
	// with nothing to allocate it is cut short but still one record.
	long := strings.repeat("x", 2 * LINE_BUFFER, context.temp_allocator)
	warnf("%s", long)
	{
		context.temp_allocator = refusing_allocator()
		warnf("%s", long)
	}
	warnf("after")
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 15, "%d lines after the long ones, want 15", len(lines)) {
		return
	}
	testing.expect_value(t, after_stamp(t, lines[12]), strings.concatenate({"level=warn msg=", long}, context.temp_allocator))
	testing.expect(t, strings.has_prefix(after_stamp(t, lines[13]), "level=warn msg=xxxx"), "the cut-short line lost its record")
	testing.expectf(t, len(lines[13]) < LINE_BUFFER, "the cut-short line is %d bytes, past the stack buffer", len(lines[13]))
	testing.expect_value(t, after_stamp(t, lines[14]), "level=warn msg=after")

	// A quoted message cut short keeps its closing quote: a line that ends inside
	// a quoted value is no record to a logfmt reader. Control bytes render four
	// bytes each, so even the message `render` cut to its buffer is past the line's.
	{
		escaped := strings.repeat("\x01", LINE_BUFFER, context.temp_allocator)
		context.temp_allocator = refusing_allocator()
		warnf("%s", escaped)
	}
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 16, "%d lines after the quoted one, want 16", len(lines)) {
		return
	}
	cut := after_stamp(t, lines[15])
	testing.expect(t, strings.has_prefix(cut, `level=warn msg="\x01\x01`), "the cut-short quoted line lost its record")
	testing.expect(t, strings.has_suffix(cut, `\x01"`), "the cut-short line ends inside its quoted message")

	// Both cuts land on a rune boundary. Five bytes a unit, so neither the
	// message buffer (1024) nor the cut-short record (`CUT_MESSAGE`) ends on one
	// by accident, and the escapes push the record past the line buffer.
	{
		runes := strings.repeat("\x01\x01€", 400, context.temp_allocator)
		context.temp_allocator = refusing_allocator()
		warnf("%s", runes)
	}
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 17, "%d lines after the multibyte one, want 17", len(lines)) {
		return
	}
	testing.expect(t, utf8.valid_string(lines[16]), "a cut-short line split a rune")
	testing.expect(t, strings.has_suffix(lines[16], `"`), "the cut-short multibyte line ends inside its quoted message")

	// A record that exactly fills the line buffer is whole, and keeps its fields.
	eventf(.Info, "exact", "pad=%s", "x")
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 18, "%d lines after the probe, want 18", len(lines)) {
		return
	}
	// The probe's length less its one-byte pad, and one for the newline.
	pad := strings.repeat("x", LINE_BUFFER - (len(lines[17]) - 1) - 1, context.temp_allocator)
	eventf(.Info, "exact", "pad=%s", pad)
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 19, "%d lines after the exact one, want 19", len(lines)) {
		return
	}
	testing.expect_value(t, len(lines[18]) + 1, LINE_BUFFER)
	testing.expect_value(t, after_stamp(t, lines[18]), strings.concatenate({"level=info msg=exact pad=", pad}, context.temp_allocator))

	// Fields cut short for want of memory are left off, as on the cut-short
	// record: cut, they would end inside their quoted value.
	{
		quoted := strings.concatenate({`"`, strings.repeat("y", 2 * PART_BUFFER, context.temp_allocator), `"`}, context.temp_allocator)
		context.temp_allocator = refusing_allocator()
		eventf(.Info, "cut", "name=%s", quoted)
	}
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 20, "%d lines after the cut fields, want 20", len(lines)) {
		return
	}
	testing.expect_value(t, after_stamp(t, lines[19]), "level=info msg=cut")
}

// An allocator with nothing to give, as a fiber's scratch is once the OS will
// map no more blocks for it.
@(private = "file")
refusing_allocator :: proc() -> runtime.Allocator {
	return runtime.Allocator {
		procedure = proc(
			_: rawptr,
			mode: runtime.Allocator_Mode,
			_, _: int,
			_: rawptr,
			_: int,
			_ := #caller_location,
		) -> (
			[]byte,
			runtime.Allocator_Error,
		) {
			#partial switch mode {
			case .Free, .Free_All:
				return nil, nil
			}
			return nil, .Out_Of_Memory
		},
	}
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

/*
A warning that fires once per process says nothing about the second time it
happens: the first Bogus verdict since start spends the only `warn`, and an
hours-long fault after it is `debug` and unlogged.

A gate lets one event through per window instead - the first immediately, so an
operator has a line to grep for, then one a window - and counts what it held
back so that the line says there was more. The clock is a parameter so the
window can be crossed without waiting for it.
*/
@(test)
test_a_gate_opens_once_a_window_and_counts_what_it_held :: proc(t: ^testing.T) {
	g: Gate
	window := i64(GATE_WINDOW)
	start := i64(1_000_000)

	loud, held := gate_pass(&g, start)
	testing.expect(t, loud, "the first event did not open the gate")
	testing.expect_value(t, held, 0)

	for i in 1 ..= 3 {
		loud, held = gate_pass(&g, start + i64(i))
		testing.expectf(t, !loud, "event %d inside the window was loud", i + 1)
	}

	loud, held = gate_pass(&g, start + window - 1)
	testing.expect(t, !loud, "the gate opened a nanosecond early")

	loud, held = gate_pass(&g, start + window)
	testing.expect(t, loud, "the gate stayed shut after its window")
	testing.expect_value(t, held, 4)

	loud, held = gate_pass(&g, start + window + 1)
	testing.expect(t, !loud, "the window did not restart when the gate opened")

	// Looking is not spending: it neither opens the gate nor counts an event.
	testing.expect(t, gate_shut(&g, start + window + 2), "a gate inside its window was not shut")
	testing.expect(t, !gate_shut(&g, start + 2 * window + 1), "a gate past its window was shut")
	testing.expect(t, !gate_shut(&Gate{}, start), "a gate nothing has passed was shut")
	loud, held = gate_pass(&g, start + 2 * window + 1)
	testing.expect(t, loud, "looking at a gate spent its window")
	testing.expect_value(t, held, 1)
}
