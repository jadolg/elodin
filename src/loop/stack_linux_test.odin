#+build linux
package loop

import "base:intrinsics"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

// How deep the probe goes before it parks: half a release stack, far more than
// the frames it parks under.
@(private = "file")
DEPTH :: 128 * 1024

// The loop's clock in this file's test, moved by hand on the loop's own thread.
@(private = "file")
stack_now: Tick

@(private = "file")
stack_clock :: proc "contextless" () -> Tick {
	return stack_now
}

@(private = "file")
Stack_Probe :: struct {
	done:    sync.Sema,
	idle:    bool,
	// Woken before its trim comes due, as a query arriving in the same round is.
	woken:   bool,
	parked:  ^Fiber,
	token:   u64,
	// Pages of the parked fiber's stack resident at once, and once its park has
	// lasted `IDLE_TRIM_AFTER`.
	early:   int,
	late:    int,
	// Whether the late reading found it still parked, on its own deadline.
	waiting: bool,
	// The parked fiber's own local, read back once it runs again.
	canary:  u64,
	reason:  Wake_Reason,
}

/*
An idle fiber's stack is handed back once its park has lasted `IDLE_TRIM_AFTER`,
and only an idle one's (#596). One that went `DEPTH` deep and came back up keeps
those pages resident while it is parked, and after `set_idle(true)` it keeps no
more than the few its parked frames are on - but not before the park has lasted:
a connection asking back to back would pay the faults on every query. The trim
does not wake the fiber, which stays parked on its own deadline and then runs
on, its frames intact. A fiber woken in the round its trim comes due keeps its
pages: it runs next, and would only fault them back.

Residency is read by a second fiber on the same loop, which runs once the first
has switched out and moves the loop's clock itself.
*/
@(test)
test_an_idle_fiber_gives_its_stack_back_once_its_park_lasts :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	defer destroy(l)
	stack_now = time.tick_now()
	l.clock = stack_clock
	th := spawn_thread(l, run, context)
	if !testing.expect(t, th != nil, "no loop thread") {
		return
	}
	defer {
		stop(l)
		thread.join(th)
		thread.destroy(th)
	}
	page := int(page_size())
	for c in ([][2]bool{{false, false}, {true, false}, {true, true}}) {
		idle, woken := c[0], c[1]
		p := Stack_Probe {
			idle  = idle,
			woken = woken,
		}
		_, ok := spawn(l, deep_then_park, &p)
		if !testing.expect(t, ok) || !testing.expect(t, sync.sema_wait_with_timeout(&p.done, 5 * time.Second)) {
			return
		}
		testing.expectf(t, p.reason == .Ready && p.canary == 0x5eed, "idle %v: woke %v with canary %x", idle, p.reason, p.canary)
		testing.expectf(t, p.waiting != woken, "idle %v, woken %v: still parked on its deadline is %v", idle, woken, p.waiting)
		// The premise: what went deep is resident until it is given back.
		testing.expectf(t, p.early * page >= DEPTH, "idle %v: only %d pages resident at once", idle, p.early)
		if idle && !woken {
			testing.expectf(t, p.late * page <= max(16 * 1024, 2 * page), "an idle park kept %d pages resident", p.late)
		} else {
			testing.expectf(t, p.late * page >= DEPTH, "idle %v, woken %v: only %d pages kept resident", idle, woken, p.late)
		}
	}
}

@(private = "file")
deep_then_park :: proc(data: rawptr) {
	p := (^Stack_Probe)(data)
	canary: u64 = 0x5eed
	touch_deep()
	set_idle(p.idle)
	defer set_idle(false)
	p.parked = current()
	p.token = p.parked.token
	_, _ = spawn(current_loop(), measure_then_wake, p)
	// A deadline well past the trim, which the trim must leave in place.
	p.reason = park(time.tick_add(stack_now, 10 * IDLE_TRIM_AFTER))
	p.canary = intrinsics.volatile_load(&canary)
	sync.sema_post(&p.done)
}

@(private = "file")
measure_then_wake :: proc(data: rawptr) {
	p := (^Stack_Probe)(data)
	f := p.parked
	s := f.stack
	p.early, _ = residency(([^]u8)(s.base)[:s.size])
	if p.woken {
		wake(f, p.token)
	}
	stack_now = time.tick_add(stack_now, IDLE_TRIM_AFTER)
	expire_timers(f.loop, stack_now)
	p.late, _ = residency(([^]u8)(s.base)[:s.size])
	p.waiting = f.state == .Parked && f.heap_index >= 0 && timer_due(f) == f.deadline
	if !p.woken {
		wake(f, p.token)
	}
}

@(private = "file")
touch_deep :: proc() {
	buf: [DEPTH]u8
	for i := 0; i < DEPTH; i += 512 {
		intrinsics.volatile_store(&buf[i], 1)
	}
}

/*
The timer of an idle park fires at whichever comes first of its trim and its
deadline. A deadline before the trim wakes the fiber as any deadline does, and a
trim before the deadline leaves the fiber parked and back in the heap on that
deadline. Driven by hand on fibers with no stack, as
`test_timers_fire_in_deadline_order_and_an_ended_park_takes_its_timer` is.
*/
@(test)
test_an_idle_parks_timer_fires_at_its_trim_or_its_deadline :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made) {
		return
	}
	defer destroy(l)
	tl_loop = l
	defer tl_loop = nil

	base := time.tick_now()
	// Due first by its deadline, then by its trim; the trim never fires.
	early := Fiber {
		loop       = l,
		heap_index = -1,
		state      = .Parked,
		deadline   = time.tick_add(base, 10 * time.Millisecond),
		trim_at    = time.tick_add(base, IDLE_TRIM_AFTER),
	}
	// Trimmed first, then woken on its deadline.
	late := Fiber {
		loop       = l,
		heap_index = -1,
		state      = .Parked,
		token      = 1,
		deadline   = time.tick_add(base, 3 * IDLE_TRIM_AFTER),
		trim_at    = time.tick_add(base, IDLE_TRIM_AFTER),
	}
	timer_push(l, &late)
	timer_push(l, &early)

	expire_timers(l, time.tick_add(base, 20 * time.Millisecond))
	testing.expect(t, len(l.ready) == 1 && l.ready[0] == &early, "the deadline before the trim did not wake its fiber")
	testing.expect_value(t, early.wake_reason, Wake_Reason.Timeout)

	expire_timers(l, time.tick_add(base, 2 * IDLE_TRIM_AFTER))
	testing.expect_value(t, len(l.ready), 1)
	testing.expect(t, late.state == .Parked && late.heap_index == 0, "the trim did not leave its fiber parked in the heap")
	testing.expect(t, late.trim_at == (Tick{}) && timer_due(&late) == late.deadline, "the trimmed park is not due on its deadline")

	expire_timers(l, time.tick_add(base, 3 * IDLE_TRIM_AFTER))
	testing.expect(t, len(l.ready) == 2 && l.ready[1] == &late, "the trimmed park was not woken on its deadline")
	testing.expect_value(t, len(l.timers), 0)
}
