package loop

import "core:sys/linux"
import "core:testing"
import "core:time"

// `moment_now` reads CLOCK_BOOTTIME: the clock that neither steps nor stops
// while the machine sleeps, which is the whole of why `Moment` exists. Off
// the tick clock it is out by every suspend and NTP correction since boot,
// off the wall clock by decades.
@(test)
test_a_moment_is_read_off_clock_boottime :: proc(t: ^testing.T) {
	boottime :: proc() -> Moment {
		ts, _ := linux.clock_gettime(.BOOTTIME)
		return Moment(i64(ts.time_sec) * i64(time.Second) + i64(ts.time_nsec))
	}
	before := boottime()
	now := moment_now()
	after := boottime()
	testing.expectf(t, before <= now && now <= after, "moment_now read %d, outside CLOCK_BOOTTIME's [%d, %d]", now, before, after)
}

/*
`tick_now` and `now` stand in for `core:time`'s readings everywhere in the
server, and deadlines from one are compared with the other's (a test, a
library), so each has to read the clock its `core:time` counterpart reads:
CLOCK_MONOTONIC_RAW and CLOCK_REALTIME. Bracketed by the system call itself,
so a different clock is out by its whole offset rather than by a race.
*/
@(test)
test_the_vdso_clocks_read_core_times_clocks :: proc(t: ^testing.T) {
	before := time.tick_now()
	tick := tick_now()
	after := time.tick_now()
	testing.expectf(t, before._nsec <= tick._nsec && tick._nsec <= after._nsec, "tick_now read %d, outside CLOCK_MONOTONIC_RAW's [%d, %d]", tick._nsec, before._nsec, after._nsec)

	// The wall clock can be stepped between the reads, so it is held to a band
	// rather than an order: any other clock is out by years, not a second.
	wall_core := time.now()
	wall := now()
	off := time.diff(wall_core, wall)
	testing.expectf(t, abs(off) < time.Second, "now read %d, %v off CLOCK_REALTIME's %d", wall._nsec, off, wall_core._nsec)
}
