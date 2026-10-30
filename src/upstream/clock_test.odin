package upstream

import "core:net"
import "core:testing"
import "core:time"
import "elodin:config"

/*
Every moment this package measures a duration from is read off the tick clock
(issue #548).

`time.now` is `CLOCK_REALTIME`, which NTP or `chronyc makestep` can step. A
cooldown, an idle connection's age or a learned idle timeout timed on it would
end early or run for the length of the step. A step cannot be made from a test,
so this asserts what rules it out: each stamp lies between two readings of the
tick clock. Compared as `_nsec`, the one field the two clocks' types share, so a
stamp taken off the wall clock is caught rather than just failing to compile.
`mise run check` holds the rest of the package to the tick clock by grep.
*/
@(private = "file")
on_tick_clock :: proc(t: ^testing.T, what: string, stamp: i64, before, after: time.Tick) {
	testing.expectf(
		t,
		before._nsec <= stamp && stamp <= after._nsec,
		"%s was stamped at %d, outside the tick clock's [%d, %d]",
		what,
		stamp,
		before._nsec,
		after._nsec,
	)
}

@(test)
test_upstream_durations_are_measured_on_the_tick_clock :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "stepped", kind = .TCP, address = "127.0.0.1", port = 5353},
		1,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	before := time.tick_now()
	// No descriptor at all, so nothing closes another test's socket.
	put_idle(u, Idle_Conn{socket = net.TCP_Socket(-1)})
	for _ in 0 ..< FAILURE_THRESHOLD {
		record_failure(u, .Dial_Failed)
	}
	note_idle_death(u, PIPE_IDLE_FLOOR + time.Second)

	c := new(Pipe_Conn)
	defer free(c)
	c.stream.socket = net.TCP_Socket(-1)
	// Taken as the reader's, so the waiter leaving hands the reading to nobody.
	c.reading = true
	w := Pipe_Waiter {
		done     = true,
		deadline = time.tick_now(),
	}
	_ = pipe_wait(c, &w, 1)
	after := time.tick_now()

	if testing.expect_value(t, len(u.idle), 1) {
		on_tick_clock(t, "a pooled connection", u.idle[0].since._nsec, before, after)
	}
	clear(&u.idle)
	on_tick_clock(t, "a cooldown", u.down_until._nsec - i64(COOLDOWN), before, after)
	on_tick_clock(t, "a learned idle timeout", u.idle_learned._nsec, before, after)
	on_tick_clock(t, "a pipelined connection's last query", c.last._nsec, before, after)
	free_all(context.temp_allocator)
}
