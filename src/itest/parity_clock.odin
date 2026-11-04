package itest

import "core:fmt"
import "core:math"
import "core:os"
import "core:strconv"
import "core:strings"

/*
A live run trusts the host clock, and cannot see it (#361).

With validation on, a signature's validity period is held against this host's
clock (RFC 4034 section 3.1.5), and the reference resolver holds it against its
own. A host far enough off rejects signatures the reference accepts, and the run
reports every name under a zone that re-signs often as a divergence, identical
on every build, so it reads as a long-standing validator gap rather than as the
clock. The mock mode is immune: its answers carry no signatures.

So the clock is read before the first query, and a run on a clock visibly wrong
is refused rather than reported. A minute is generous: the tightest signing
window in use is measured in minutes, and a live-signing resolver's RRSIGs are
valid for hours either side of now. A host that cannot say how far off it is
gets a note and carries on: no chronyc is not a reason to refuse to run, and the
note is there for whoever reads the result afterwards.
*/
PARITY_CLOCK_LIMIT_SECONDS :: 60.0

Parity_Clock :: struct {
	// Refuse the run: the clock is measured, and off by more than the limit.
	refuse: bool,
	// What was learned about the clock, or that nothing was. Never empty.
	note:   string,
}

/*
Read the clock's offset from NTP time, as far as this host can say.

chronyc first, since it measures the offset; then timedatectl, which says only
whether systemd believes the clock is synchronised. A tool that is missing or
fails to answer is passed on as `ok = false`, which the judgement reads as
saying nothing.
*/
parity_clock_check :: proc() -> Parity_Clock {
	chronyc, chronyc_ok := parity_clock_run({"chronyc", "tracking"})
	timedatectl, timedatectl_ok := parity_clock_run({"timedatectl", "show", "-p", "NTPSynchronized", "--value"})
	return parity_clock_judge(chronyc, chronyc_ok, timedatectl, timedatectl_ok)
}

@(private = "file")
parity_clock_run :: proc(command: []string) -> (output: string, ok: bool) {
	state, stdout, _, err := os.process_exec(os.Process_Desc{command = command}, context.temp_allocator)
	if err != nil || !state.exited || state.exit_code != 0 {
		return "", false
	}
	return string(stdout), true
}

/*
The judgement, apart from running anything, so a case can hand it any output.

chronyc's offset counts only while chronyd itself is synchronised: a daemon with
no source reports a small offset from an estimate it has nothing to base on.
`Leap status : Not synchronised` is what it prints then, and that is read as
"unmeasured", not as "fine".
*/
parity_clock_judge :: proc(
	chronyc: string,
	chronyc_ok: bool,
	timedatectl: string,
	timedatectl_ok: bool,
) -> Parity_Clock {
	if chronyc_ok {
		offset, measured := parity_clock_chronyc_offset(chronyc)
		if measured {
			if abs(offset) > PARITY_CLOCK_LIMIT_SECONDS {
				return {
					refuse = true,
					note = fmt.tprintf(
						"the clock is %.1fs %s of NTP time (chronyc tracking); signatures would be judged against the wrong time, so a live run would measure the clock rather than elodin. Fix the clock (e.g. `sudo chronyc makestep`) and run again",
						abs(offset),
						offset > 0 ? "slow" : "fast",
					),
				}
			}
			return {note = fmt.tprintf("%.3fs %s of NTP time (chronyc)", abs(offset), offset > 0 ? "slow" : "fast")}
		}
	}
	if timedatectl_ok {
		switch strings.trim_space(timedatectl) {
		case "yes":
			return {note = "synchronised to NTP (timedatectl); offset not measured"}
		case "no":
			return {
				note = "NOT synchronised to NTP (timedatectl); a divergence in signature validity may be the clock",
			}
		}
	}
	return {note = "unchecked: neither chronyc nor timedatectl could say; a divergence in signature validity may be the clock"}
}

/*
The signed offset, in seconds, positive when the clock is slow.

From the line chronyc prints as `System time : 0.001557089 seconds slow of NTP
time`, and only when the leap status says chronyd is synchronised.
*/
@(private = "file")
parity_clock_chronyc_offset :: proc(output: string) -> (offset: f64, ok: bool) {
	synced := false
	text := output
	for line in strings.split_lines_iterator(&text) {
		key, _, value := strings.partition(line, ":")
		key = strings.trim_space(key)
		value = strings.trim_space(value)
		switch key {
		case "Leap status":
			synced = value != "Not synchronised"
		case "System time":
			fields := strings.fields(value, context.temp_allocator)
			if len(fields) < 3 || fields[1] != "seconds" {
				return 0, false
			}
			n, parsed := strconv.parse_f64(fields[0])
			if !parsed || math.is_nan(n) || math.is_inf(n) {
				return 0, false
			}
			switch fields[2] {
			case "slow":
				offset = n
			case "fast":
				offset = -n
			case:
				return 0, false
			}
			ok = true
		}
	}
	return offset, ok && synced
}
