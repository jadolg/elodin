package upstream

import "core:testing"
import "core:time"

/*
Whether a stage shares its exchange's deadline, read off the deadlines this
thread's UDP waits were handed (see `note_udp_wait`) rather than judged by how
long the exchange took (issue #556).

Call `udp_waits_reset` first, then this once the exchange has returned. Every
wait since must have run to one deadline, and to one the exchange can have set:
no earlier than `started + timeout`, and no later than the first wait's start
plus `timeout`, since the exchange takes its deadline before that wait begins.
A stage that starts a timeout of its own - the cookie retry, a bootstrap query,
a read after a stray - hands its waits a later deadline than the waits before
it had, by however long those took.
*/
@(private)
expect_udp_waits_share :: proc(t: ^testing.T, started: time.Tick, timeout: time.Duration, at_least: int, loc := #caller_location) {
	n := udp_wait_count
	if !testing.expectf(t, at_least <= n && n <= len(udp_waits), "%d UDP waits, where %d to %d were expected", n, at_least, len(udp_waits), loc = loc) {
		return
	}
	first := udp_waits[0].deadline
	for w, i in udp_waits[:n] {
		testing.expectf(t, w.deadline == first, "wait %d of %d ran %v past the first's deadline", i + 1, n, time.tick_diff(first, w.deadline), loc = loc)
	}
	earliest := time.tick_add(started, timeout)
	latest := time.tick_add(udp_waits[0].at, timeout)
	testing.expectf(
		t,
		time.tick_diff(earliest, first) >= 0 && time.tick_diff(first, latest) >= 0,
		"the waits ran to %v after the exchange began, where its deadline is %v after it",
		time.tick_diff(started, first),
		timeout,
		loc = loc,
	)
}

@(private)
udp_waits_reset :: proc() {
	udp_wait_count = 0
}
