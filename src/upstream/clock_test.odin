package upstream

import "core:net"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:h2"
import "elodin:loop"

/*
Every moment this package stores and later ages is a `loop.Moment`, read off
CLOCK_BOOTTIME (issue #548).

`time.now` is `CLOCK_REALTIME`, which NTP or `chronyc makestep` can step, and
`time.tick_now` is CLOCK_MONOTONIC_RAW, which stops while the machine sleeps. A
cooldown, an idle connection's age or a learned idle timeout timed on either
would be wrong by the length of a step or of a suspend. Neither can be made from
a test, so this asserts what rules them out: each stamp lies between two
readings of `loop.moment_now`, which `loop` tests against CLOCK_BOOTTIME. A stamp off either other clock is seconds or
more away from that window. `mise run check` holds the rest of the package off
the wall clock by grep.
*/
@(private = "file")
on_moment_clock :: proc(t: ^testing.T, what: string, stamp, before, after: loop.Moment) {
	testing.expectf(
		t,
		before <= stamp && stamp <= after,
		"%s was stamped at %d, outside the moment clock's [%d, %d]",
		what,
		stamp,
		before,
		after,
	)
}

@(test)
test_upstream_stamps_its_moments_on_the_moment_clock :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "stepped", kind = .TCP, address = "127.0.0.1", port = 5353},
		1,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	before := loop.moment_now()
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

	// Writes its preface on the way out, into nothing.
	cl := h2.client_make(h2.IO{write = proc(_: rawptr, _: []u8) -> bool {return true}})
	defer h2.client_unref(cl)
	h2.client_ref(cl)
	h2.client_unref(cl)
	after := loop.moment_now()

	if testing.expect_value(t, len(u.idle), 1) {
		on_moment_clock(t, "a pooled connection", u.idle[0].since, before, after)
	}
	clear(&u.idle)
	on_moment_clock(t, "a cooldown", u.down_until - loop.Moment(COOLDOWN), before, after)
	on_moment_clock(t, "a learned idle timeout", u.idle_learned, before, after)
	on_moment_clock(t, "a pipelined connection's last query", c.last, before, after)
	on_moment_clock(t, "an h2 connection's last request", cl.released, before, after)
	free_all(context.temp_allocator)
}
