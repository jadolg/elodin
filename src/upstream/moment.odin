package upstream

import "core:sys/posix"
import "core:time"

/*
A moment this package stores and later ages: when a connection went idle, when
a cooldown ends, when an idle timeout was learned, when a bootstrap address
expires.

On CLOCK_BOOTTIME rather than either of the clocks `core:time` reads. Not the
wall clock (`time.now`), which NTP or `chronyc makestep` steps, so a step would
park a member for its length or reap every pooled connection at once (issue
#548). Not the tick clock (`time.tick_now`, CLOCK_MONOTONIC_RAW) either, which
stops while the machine is suspended: a connection idle three seconds before an
eight-hour sleep would read as three seconds old on resume. It would be handed
out although the peer and any NAT on the way dropped it hours ago, and the
hang-up it meets would teach `note_idle_death` a three-second timeout the peer
never had. CLOCK_BOOTTIME neither steps nor stops.

A type of its own so it is never compared with a `time.Tick`: the deadlines
that bound a wait stay on the tick clock, which is what the event loop and
`tlsx` measure against, and the two clocks drift apart by every suspend.
The zero value is boot, which is in the past, as the wall clock's zero was.
*/
@(private)
Moment :: distinct i64

// Not in `posix.Clock`, which names only what POSIX does; Linux's value.
@(private = "file")
CLOCK_BOOTTIME :: posix.Clock(7)

@(private)
moment_now :: proc "contextless" () -> Moment {
	ts: posix.timespec
	posix.clock_gettime(CLOCK_BOOTTIME, &ts)
	return Moment(i64(ts.tv_sec) * i64(time.Second) + i64(ts.tv_nsec))
}

@(private)
moment_since :: proc "contextless" (m: Moment) -> time.Duration {
	return time.Duration(moment_now() - m)
}

@(private)
moment_add :: proc "contextless" (m: Moment, d: time.Duration) -> Moment {
	return m + Moment(d)
}
