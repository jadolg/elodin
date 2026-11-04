package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"

/*
The clock check that gates a live parity run (#361, parity_clock.odin).

In the ordinary suite rather than behind `--parity`: the live mode is the one
nothing gates, and the check is only worth anything if it is still there the
day a live run is started on a box whose clock has drifted.
*/
run_parity_clock_cases :: proc(r: ^Runner) {
	parity_clock_judge_case(r)
	parity_clock_refuses_live_run_case(r)
	parity_clock_slips_mid_run_case(r)
}

// What chronyc tracking prints, cut to the lines the judgement reads, on a
// host whose chronyd is synchronised and whose clock is `offset` away.
@(private = "file")
chronyc_tracking :: proc(offset: string, leap := "Normal") -> string {
	return fmt.tprintf(
		"Reference ID    : A9FEA97B (169.254.169.123)\n" +
		"Stratum         : 4\n" +
		"System time     : %s of NTP time\n" +
		"Last offset     : -0.000012030 seconds\n" +
		"Leap status     : %s\n",
		offset,
		leap,
	)
}

@(private = "file")
parity_clock_judge_case :: proc(r: ^Runner) {
	start_case(r, "parity: the clock judgement refuses a clock off by more than a minute, and only that")
	defer end_case(r)

	Row :: struct {
		what:           string,
		chronyc:        string,
		chronyc_ok:     bool,
		timedatectl:    string,
		timedatectl_ok: bool,
		refuse:         bool,
		note:           string,
	}
	rows := []Row {
		// The box the issue was found on.
		{"2h24m slow", chronyc_tracking("8640.000000000 seconds slow"), true, "", false, true, "8640.0s slow"},
		{"2h24m fast", chronyc_tracking("8640.000000000 seconds fast"), true, "", false, true, "8640.0s fast"},
		{"just past the limit", chronyc_tracking("60.500000000 seconds slow"), true, "", false, true, "60.5s slow"},
		{"just inside the limit", chronyc_tracking("59.900000000 seconds fast"), true, "", false, false, "59.900s fast"},
		{"in sync", chronyc_tracking("0.001557089 seconds slow"), true, "", false, false, "0.002s slow"},
		// An offset chronyd has nothing to base on is not a measurement.
		{
			"chronyd unsynchronised",
			chronyc_tracking("8640.000000000 seconds slow", "Not synchronised"),
			true,
			"",
			false,
			false,
			"unchecked",
		},
		{
			"chronyd leap status invalid",
			chronyc_tracking("8640.000000000 seconds slow", "Invalid"),
			true,
			"",
			false,
			false,
			"unchecked",
		},
		{"chronyc unparseable", chronyc_tracking("lots of seconds slow"), true, "", false, false, "unchecked"},
		{"chronyc absent, timesyncd in sync", "", false, "yes\n", true, false, "synchronised to NTP (timedatectl)"},
		{"chronyc absent, timesyncd not", "", false, "no\n", true, false, "NOT synchronised"},
		{"neither tool", "", false, "", false, false, "unchecked"},
	}
	for row in rows {
		got := parity_clock_judge(row.chronyc, row.chronyc_ok, row.timedatectl, row.timedatectl_ok)
		check(r, got.refuse == row.refuse, "%s: refuse is %v, want %v (%s)", row.what, got.refuse, row.refuse, got.note)
		check(r, strings.contains(got.note, row.note), "%s: note %q does not say %q", row.what, got.note, row.note)
	}
}

/*
Run a live parity run as a child, with a chronyc of the case's own first on the
PATH, so the run reads the clock the case chose rather than this host's.

The fake chronyc prints `first` the first time it is asked and `after` every
time after. The upstream is a port nothing listens on: a run that went past a
check fails too, but on queries rather than on the clock, which the output
tells apart.
*/
@(private = "file")
parity_clock_child :: proc(r: ^Runner, tag, first, after: string, args: []string) -> (output: string, exit_code: int, ok: bool) {
	bin_dir := filepath.join({r.work_dir, tag}, context.temp_allocator) or_else ""
	if !check(r, os.make_directory(bin_dir) == nil || os.exists(bin_dir), "cannot make %s", bin_dir) {
		return
	}
	chronyc := filepath.join({bin_dir, "chronyc"}, context.temp_allocator) or_else ""
	count := fmt.tprintf("%s.count", chronyc)
	script := fmt.tprintf(
		"#!/bin/sh\n" +
		"if [ -e '%s' ]; then cat <<'EOF'\n%sEOF\n" +
		"else : > '%s'; cat <<'EOF'\n%sEOF\nfi\n",
		count,
		after,
		count,
		first,
	)
	werr := os.write_entire_file(chronyc, script, os.Permissions_Read_All + os.Permissions_Execute_All + {.Write_User})
	if !check(r, werr == nil, "cannot write %s: %v", chronyc, werr) {
		return
	}

	// The script must run as itself: on a work dir mounted noexec the child would
	// fall through to this host's clock and start a live run.
	_, _, _, xerr := os.process_exec(os.Process_Desc{command = {chronyc}}, context.temp_allocator)
	if !check(r, xerr == nil, "cannot run %s (is %s mounted noexec?): %v", chronyc, r.work_dir, xerr) {
		return
	}
	// That run was the script's first; the child's is to be.
	_ = os.remove(count)

	inherited, eerr := os.environ(context.temp_allocator)
	if !check(r, eerr == nil, "cannot read the environment: %v", eerr) {
		return
	}
	env := make([dynamic]string, 0, len(inherited) + 1, context.temp_allocator)
	for kv in inherited {
		if !strings.has_prefix(kv, "PATH=") {
			append(&env, kv)
		}
	}
	path := os.get_env("PATH", context.temp_allocator)
	append(&env, fmt.tprintf("PATH=%s:%s", bin_dir, path))

	command := make([dynamic]string, context.temp_allocator)
	upstream := fmt.tprintf("127.0.0.1:%d", next_port(r))
	append(&command, os.args[0], "--binary", r.binary, "--parity", "--parity-runs", "1", "--parity-upstream", upstream)
	append(&command, ..args)
	state, stdout, stderr, err := os.process_exec(
		os.Process_Desc{command = command[:], env = env[:]},
		context.temp_allocator,
	)
	if !check(r, err == nil, "cannot run %s: %v", os.args[0], err) {
		return
	}
	return fmt.tprintf("%s%s", stdout, stderr), state.exit_code, true
}

// End to end: a live run on a clock 2h24m slow stops before it sends anything,
// and says the clock is why.
@(private = "file")
parity_clock_refuses_live_run_case :: proc(r: ^Runner) {
	start_case(r, "parity: a live run on a clock 2h24m slow is refused before the first query")
	defer end_case(r)

	slow := chronyc_tracking("8640.000000000 seconds slow")
	output, exit_code, ok := parity_clock_child(r, "parity-clock-slow", slow, slow, nil)
	if !ok {
		return
	}
	check(r, exit_code != 0, "the run exited 0:\n%s", output)
	// The premise: the run read the case's chronyc, not this host's.
	check(r, strings.contains(output, "8640.0s slow"), "the run did not read the clock the case set:\n%s", output)
	check(r, strings.contains(output, "the host clock"), "the refusal does not name the clock:\n%s", output)
	// Refused before it claimed a port slot, let alone sent a query.
	check(r, !strings.contains(output, "ports:"), "the run started on a refused clock:\n%s", output)
}

/*
End to end: a clock that slips during a run is caught after the scenario it
slipped in, which is named, so its divergences are read as the clock's.

The clock is right when the run starts and 2h24m slow every time it is read
after that.
*/
@(private = "file")
parity_clock_slips_mid_run_case :: proc(r: ^Runner) {
	start_case(r, "parity: a clock that slips during a live run stops it after that scenario")
	defer end_case(r)

	output, _, ok := parity_clock_child(
		r,
		"parity-clock-slips",
		chronyc_tracking("0.001000000 seconds slow"),
		chronyc_tracking("8640.000000000 seconds slow"),
		[]string{"--parity-scenario", "live"},
	)
	if !ok {
		return
	}
	// The premise: the run started on the clock the case set as right.
	check(r, strings.contains(output, "clock:     0.001s slow"), "the run did not start on the clock the case set:\n%s", output)
	check(
		r,
		strings.contains(output, "the host clock moved during live:") && strings.contains(output, "8640.0s slow"),
		"the slip was not reported against the scenario it happened in:\n%s",
		output,
	)
}
