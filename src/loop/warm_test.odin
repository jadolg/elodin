package loop

import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

// The loop's clock in this file's test, moved by the test thread.
@(private = "file")
warm_now: i64

@(private = "file")
warm_clock :: proc "contextless" () -> Tick {
	return Tick{sync.atomic_load(&warm_now)}
}

@(private = "file")
Burst :: struct {
	started: sync.Sema,
	done:    sync.Sema,
	// Opened once every fiber of the burst is running, so they hold their stacks at once.
	gate:    Sema,
}

@(private = "file")
burst_job :: proc(data: rawptr) {
	b := (^Burst)(data)
	sync.sema_post(&b.started)
	sema_wait(&b.gate)
	sync.sema_post(&b.done)
}

// Run `n` fibers at once on `l` and wait for all of them to finish.
@(private = "file")
burst :: proc(t: ^testing.T, l: ^Loop, n: int) -> bool {
	b: Burst
	for _ in 0 ..< n {
		if _, ok := spawn(l, burst_job, &b); !testing.expect(t, ok) {
			return false
		}
	}
	for _ in 0 ..< n {
		if !testing.expect(t, sync.sema_wait_with_timeout(&b.started, 5 * time.Second)) {
			return false
		}
	}
	sema_post(&b.gate, n)
	for _ in 0 ..< n {
		if !testing.expect(t, sync.sema_wait_with_timeout(&b.done, 5 * time.Second)) {
			return false
		}
	}
	for fibers_alive(l) != 0 {
		time.sleep(time.Millisecond)
	}
	return true
}

@(private = "file")
warm_count :: proc(l: ^Loop) -> int {
	sync.mutex_lock(&l.mu)
	defer sync.mutex_unlock(&l.mu)
	return l.warm
}

@(private = "file")
noop :: proc(_: rawptr) {}

/*
A loaded loop keeps every stack its fibers finish with, and gives back only the
ones a whole `TRIM_AFTER` went by without (#612).

A burst of `N` holds `N` stacks at once; all `N` stay warm, so the next burst
maps none. A second, smaller burst in the next window takes `M` of them; at
that window's end the `N - M` nobody touched are unmapped and the `M` it used
are kept, with the loop busy the whole time. On a clock this test moves, so a
window ends where the test says and not when the machine gets round to it.
*/
@(test)
test_a_busy_loop_keeps_the_stacks_it_uses :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	defer destroy(l)
	sync.atomic_store(&warm_now, time.tick_now()._nsec)
	l.clock = warm_clock
	th := spawn_thread(l, run, context)
	if !testing.expect(t, th != nil, "no loop thread") {
		return
	}
	defer {
		stop(l)
		thread.join(th)
		thread.destroy(th)
	}
	N :: 200
	M :: 50
	advance :: proc() {
		sync.atomic_add(&warm_now, i64(TRIM_AFTER))
	}

	if !burst(t, l, N) {
		return
	}
	testing.expectf(t, warm_count(l) == N, "%d of a burst's %d stacks kept", warm_count(l), N)

	advance()
	if !burst(t, l, M) {
		return
	}
	testing.expectf(t, warm_count(l) == N, "%d of %d stacks kept after a smaller burst", warm_count(l), N)

	// The window the smaller burst ran in is over; a fiber started wakes the loop to see it.
	advance()
	if _, ok := spawn(l, noop, nil); !testing.expect(t, ok) {
		return
	}
	start := time.tick_now()
	for warm_count(l) != M && time.tick_since(start) < 5 * time.Second {
		time.sleep(time.Millisecond)
	}
	testing.expectf(t, warm_count(l) == M, "%d stacks warm, want the %d the last window used", warm_count(l), M)
}
