package logx

import "base:runtime"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:unicode/utf8"

/*
One test proc for the logger's state, on purpose.

The logger is process-wide state - a level, a mutex, one file handle - and the
test runner gives each `@(test)` proc a thread of its own. Two of them here
would interleave their lines in the same file and race the level, so everything
that goes through `init`, `reopen` or the lines is said in sequence below. The
other tests call `open_log` and the probes alone, which touch no state.
*/
@(test)
test_every_line_is_logfmt :: proc(t: ^testing.T) {
	dir, path, ok := open_scratch_log(t)
	if !ok {
		return
	}
	defer os.remove_all(dir)
	defer shutdown()

	// Created owner-only, so nobody else reads it; widened by hand, it is said.
	testing.expect(t, !readable_by_others(), "a log this process created is readable by others")
	testing.expect(t, os.chmod(path, os.Permissions_Read_All + {.Write_User}) == nil, "cannot widen the log's mode")
	testing.expect(t, readable_by_others(), "a 0644 log is not reported as readable by others")

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

	// Every reopen says so too - a SIGHUP and a reload that moves `log.file`
	// alike - since the file opened may not be the one that was checked.
	testing.expect(t, reopen(path) == nil, "cannot reopen the log")
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 21, "%d lines after the reopen, want 21", len(lines)) {
		return
	}
	testing.expect(t, strings.contains(lines[20], `level=warn msg="log.file:`), "a reopen of a 0644 log did not warn")

	// And so does a start on one, without its caller having to ask.
	shutdown()
	testing.expect(t, init(.Info, path) == nil, "cannot open the log again")
	lines = log_lines(t, path)
	if !testing.expectf(t, len(lines) == 22, "%d lines after the second start, want 22", len(lines)) {
		return
	}
	testing.expect(t, strings.contains(lines[21], `level=warn msg="log.file:`), "a start on a 0644 log did not warn")

	// A refusal is explained only where the guard is on, and only a refusal.
	symlinked := os.Platform_Error(linux.Errno.ELOOP)
	testing.expect_value(t, guard_hint(symlinked), "")
	shutdown()
	testing.expect(t, init(.Info, path, Owner{posix.getuid(), posix.getgid()}) == nil, "cannot open the log guarded")
	testing.expect_value(t, guard_hint(symlinked), GUARD_HINT)
	testing.expect_value(t, guard_hint(os.Platform_Error(linux.Errno.EACCES)), "")
}

/*
The log is created owner-only, whatever the umask lets through: with query
logging on it names every client. Read back from the kernel, not from what was
asked for. Uses `open_log` alone, so it shares no state with the test above.
*/
@(test)
test_log_file_is_created_owner_only :: proc(t: ^testing.T) {
	dir, ok := scratch_dir(t, "elodin-logx-mode-test")
	if !ok {
		return
	}
	defer os.remove_all(dir)
	path, _ := filepath.join({dir, "elodin.log"}, context.temp_allocator)

	f, created, err := open_log(path, false)
	if !testing.expectf(t, err == nil, "cannot open %s: %v", path, err) {
		return
	}
	os.close(f)
	testing.expect(t, created, "a new log file was not reported as created")

	// Opened again, it is appended to, and not this open's to hand over.
	again, created_again, err_again := open_log(path, false)
	if testing.expectf(t, err_again == nil, "cannot open %s again: %v", path, err_again) {
		os.close(again)
		testing.expect(t, !created_again, "an existing log file was reported as created")
	}

	// A symlink at the name is refused when asked to be - what a root start
	// asks - and the file it names is neither created nor appended to.
	target, _ := filepath.join({dir, "target"}, context.temp_allocator)
	link, _ := filepath.join({dir, "link.log"}, context.temp_allocator)
	if testing.expect(t, os.symlink(target, link) == nil, "cannot make the symlink") {
		_, _, lerr := open_log(link, true)
		testing.expect(t, lerr != nil, "a symlinked log was opened with symlinks refused")
		testing.expect(t, !os.exists(target), "refusing a symlinked log created its target")
		// `--check` says what the start refuses, and passes what it opens.
		testing.expect(t, guard_refuses(link), "--check passes a symlinked log")
		testing.expect(t, !guard_refuses(path), "--check refuses a plain log")
		missing, _ := filepath.join({dir, "missing.log"}, context.temp_allocator)
		testing.expect(t, !guard_refuses(missing), "--check refuses a log still to be created")
		// Nor through a symlinked directory above it, which O_NOFOLLOW alone
		// would follow.
		real_dir, _ := filepath.join({dir, "real"}, context.temp_allocator)
		dir_link, _ := filepath.join({dir, "dirlink"}, context.temp_allocator)
		through, _ := filepath.join({dir_link, "elodin.log"}, context.temp_allocator)
		if testing.expect(t, os.make_directory(real_dir) == nil && os.symlink(real_dir, dir_link) == nil, "cannot make the directory symlink") {
			_, _, derr := open_log(through, true)
			testing.expect(t, derr != nil, "a log under a symlinked directory was opened with symlinks refused")
			inside, _ := filepath.join({real_dir, "elodin.log"}, context.temp_allocator)
			testing.expect(t, !os.exists(inside), "refusing a symlinked directory created the log in its target")
			testing.expect(t, guard_refuses(through), "--check passes a log to be created under a symlinked directory")
		}

		// The descriptor a refusing open hands back blocks again: a full pipe
		// to a shipper would otherwise drop lines.
		if nf, _, nerr := open_log(path, true); testing.expectf(t, nerr == nil, "cannot open %s refusing symlinks: %v", path, nerr) {
			fl, _ := linux.fcntl(linux.Fd(os.fd(nf)), linux.F_GETFL)
			testing.expect(t, .NONBLOCK not_in fl, "the log was left non-blocking")
			os.close(nf)
		}

		// openat2 runs here, so a path's own EPERM would not be taken for a
		// seccomp filter and walked again with only O_NOFOLLOW.
		testing.expect(t, openat2_allowed(), "openat2 is reported unavailable on a kernel and sandbox that allow it")

		// A character device is let through: the account cannot make one.
		if nf, _, nerr := open_log("/dev/null", true); testing.expectf(t, nerr == nil, "/dev/null was refused under the guard: %v", nerr) {
			os.close(nf)
		}
		testing.expect(t, !guard_refuses("/dev/null"), "--check refuses /dev/null under the guard")

		// A FIFO with no reader is refused at once rather than waited on.
		fifo, _ := filepath.join({dir, "fifo.log"}, context.temp_allocator)
		if testing.expect(t, posix.mkfifo(strings.clone_to_cstring(fifo, context.temp_allocator), {.IRUSR, .IWUSR}) == .OK, "cannot make the FIFO") {
			_, _, ferr := open_log(fifo, true)
			testing.expect(t, ferr != nil, "a FIFO with no reader was opened")
			testing.expect(t, guard_refuses(fifo), "--check passes a FIFO")

			// Nor with one: a reader that stops reading would block every line.
			rd := posix.open(strings.clone_to_cstring(fifo, context.temp_allocator), {.NONBLOCK})
			if testing.expect(t, rd >= 0, "cannot open the FIFO's read end") {
				_, _, rerr := open_log(fifo, true)
				testing.expect(t, rerr != nil, "a FIFO with a reader was opened with the guard on")
				posix.close(rd)
			}
		}

		// Nor a file with a second hard link, the symlink's twin; followed, it
		// is appended to as before.
		linked, _ := filepath.join({dir, "linked.log"}, context.temp_allocator)
		twin, _ := filepath.join({dir, "twin"}, context.temp_allocator)
		if testing.expect(t, os.write_entire_file(linked, []byte{}) == nil && posix.link(strings.clone_to_cstring(linked, context.temp_allocator), strings.clone_to_cstring(twin, context.temp_allocator)) == .OK, "cannot make the hard link") {
			_, _, herr := open_log(linked, true)
			testing.expectf(t, herr == os.Platform_Error(linux.Errno.EMLINK), "a hard-linked log was not refused with symlinks refused: %v", herr)
			testing.expect(t, guard_refuses(linked), "--check passes a hard-linked log")
			if hf, _, hferr := open_log(linked, false); testing.expectf(t, hferr == nil, "a hard-linked log was refused when links are followed: %v", hferr) {
				os.close(hf)
			}
		}

		lf, _, ferr := open_log(link, false)
		if testing.expectf(t, ferr == nil, "a symlinked log was refused when symlinks are followed: %v", ferr) {
			os.close(lf)
		}
	}
	st: posix.stat_t
	if !testing.expect(t, posix.stat(strings.clone_to_cstring(path, context.temp_allocator), &st) == .OK, "cannot stat the log") {
		return
	}
	testing.expectf(t, transmute(u32)st.st_mode & 0o777 == 0o600, "the log was created %o, want 600", transmute(u32)st.st_mode & 0o777)
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
	dir = scratch_dir(t, "elodin-logx-test") or_return
	path, _ = filepath.join({dir, "elodin.log"}, context.temp_allocator)
	if init(.Info, path) != nil {
		testing.expectf(t, false, "cannot open %s for logging", path)
		os.remove_all(dir)
		return
	}
	return dir, path, true
}

// The pid keeps a run in another checkout from removing this one's files.
@(private = "file")
scratch_dir :: proc(t: ^testing.T, name: string) -> (dir: string, ok: bool) {
	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		testing.expectf(t, false, "no temporary directory: %v", terr)
		return
	}
	// Resolved: the guarded opens refuse a symlink anywhere on the path, and
	// $TMPDIR may hold one.
	if real, rerr := os.get_absolute_path(tmp, context.temp_allocator); rerr == nil {
		tmp = real
	}
	dir, _ = filepath.join({tmp, fmt.tprintf("%s-%d", name, posix.getpid())}, context.temp_allocator)
	os.remove_all(dir)
	if err := os.make_directory(dir); err != nil {
		testing.expectf(t, false, "cannot create %s: %v", dir, err)
		return
	}
	return dir, true
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
