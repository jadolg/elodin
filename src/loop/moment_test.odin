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
