package loop

import "core:sys/linux"
import "core:sys/posix"
import "core:time"

/*
A moment stored and aged later: when a connection went idle, when a cooldown
ends, when an idle timeout was learned, when a cached address expires.

On CLOCK_BOOTTIME rather than either of the clocks `core:time` reads. Not the
wall clock (`time.now`), which NTP or `chronyc makestep` steps, so a step would
park an upstream for its length or reap every pooled connection at once (issue
#548). Not the tick clock (`time.tick_now`, CLOCK_MONOTONIC_RAW) either, which
stops while the machine is suspended: a connection idle three seconds before an
eight-hour sleep would read as three seconds old on resume. It would be handed
out although the peer and any NAT on the way dropped it hours ago, and the
hang-up it meets would teach the pipeline a three-second idle timeout the peer
never had. CLOCK_BOOTTIME neither steps nor stops.

A type of its own so it is never compared with a `time.Tick`: the deadlines
that bound a wait stay on the tick clock, which is what this loop and `tlsx`
measure against, and the two clocks drift apart by every suspend.
The zero value is boot, so a zero `Moment` is always in the past.
*/
Moment :: distinct i64

moment_now :: proc "contextless" () -> Moment {
	ts: posix.timespec
	// `posix.Clock` names only what POSIX does; CLOCK_BOOTTIME is Linux's.
	posix.clock_gettime(posix.Clock(linux.Clock_Id.BOOTTIME), &ts)
	return Moment(i64(ts.tv_sec) * i64(time.Second) + i64(ts.tv_nsec))
}

moment_since :: proc "contextless" (m: Moment) -> time.Duration {
	return time.Duration(moment_now() - m)
}

moment_add :: proc "contextless" (m: Moment, d: time.Duration) -> Moment {
	return m + Moment(d)
}

/*
The clocks `core:time` reads, read through libc so the vDSO answers them.

`core:time` on Linux calls `clock_gettime` as a raw system call, which bypasses
the vDSO: every `time.now` and `time.tick_now` entered the kernel, six times
per UDP cache hit and nine per TCP one, about a tenth of the CPU a hit costs
(#594). These read the same clocks - CLOCK_REALTIME and CLOCK_MONOTONIC_RAW -
so a `Tick` or `Time` from either agrees with one from the other.

`mise run check` keeps `time.now`, `time.since`, `time.tick_now` and
`time.tick_since` out of the server.
*/
now :: proc "contextless" () -> time.Time {
	ts: posix.timespec
	posix.clock_gettime(.REALTIME, &ts)
	return time.Time{_nsec = i64(ts.tv_sec) * i64(time.Second) + i64(ts.tv_nsec)}
}

since :: proc "contextless" (t: time.Time) -> time.Duration {
	return time.diff(t, now())
}

tick_now :: proc "contextless" () -> Tick {
	ts: posix.timespec
	posix.clock_gettime(posix.Clock(linux.Clock_Id.MONOTONIC_RAW), &ts)
	return Tick{_nsec = i64(ts.tv_sec) * i64(time.Second) + i64(ts.tv_nsec)}
}

tick_since :: proc "contextless" (t: Tick) -> time.Duration {
	return time.tick_diff(t, tick_now())
}
