package loop

import "core:sync"
import "core:testing"
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
	return testing.expect(t, fibers_gone(l), "finished fibers were never put back")
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
that window's end the loop is left with `M`, what the window used, the other
`N - M` unmapped. On a clock this test moves, so a window ends where the test
says and not when the machine gets round to it.
*/
@(test)
test_a_busy_loop_keeps_the_stacks_it_uses :: proc(t: ^testing.T) {
	sync.atomic_store(&warm_now, time.tick_now()._nsec)
	r, started := start(t, warm_clock)
	if !started {
		return
	}
	defer finish(r)
	l := r.l
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

// The loop's clock in the idle test below, moved by its test thread.
@(private = "file")
idle_now: i64

@(private = "file")
idle_clock :: proc "contextless" () -> Tick {
	return Tick{sync.atomic_load(&idle_now)}
}

/*
A burst's warm stacks are given back once the loop has had nothing to do, down
to `WARM_IDLE_KEEP`: a whole window with none of them used. On a clock this
test moves, as above.
*/
@(test)
test_an_idle_loop_gives_back_its_warm_stacks :: proc(t: ^testing.T) {
	sync.atomic_store(&idle_now, time.tick_now()._nsec)
	r, started := start(t, idle_clock)
	if !started {
		return
	}
	defer finish(r)
	l := r.l
	N :: 40
	if !burst(t, l, N) {
		return
	}
	// The premise: the burst left more than a quiet loop keeps.
	testing.expectf(t, warm_count(l) > WARM_IDLE_KEEP, "only %d stacks were kept after a burst of %d", warm_count(l), N)

	// The burst's window ends, then a window the loop spends idle; a fiber
	// started wakes the loop to see each end.
	for _ in 0 ..< 2 {
		sync.atomic_add(&idle_now, i64(TRIM_AFTER))
		if _, ok := spawn(l, noop, nil); !testing.expect(t, ok) {
			return
		}
		if !testing.expect(t, fibers_gone(l), "the waking fiber never finished") {
			return
		}
	}
	start := time.tick_now()
	for warm_count(l) > WARM_IDLE_KEEP && time.tick_since(start) < 5 * time.Second {
		time.sleep(time.Millisecond)
	}
	testing.expectf(t, warm_count(l) <= WARM_IDLE_KEEP, "%d stacks still warm after an idle window", warm_count(l))
}

/*
A window's unused stacks are unmapped `TRIM_BATCH` a round, not all in one, so a
loop that falls from thousands in flight stalls its live queries behind no more
than a batch of `munmap` calls; the rounds after carry on until the debt is paid,
down to `WARM_IDLE_KEEP`. Driven without a loop thread, by calling the steps.
*/
@(test)
test_a_window_is_trimmed_a_batch_a_round :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	defer destroy(l)
	N :: 4 * TRIM_BATCH
	for _ in 0 ..< N {
		f := new(Fiber, l.allocator)
		f.loop = l
		f.heap_index = -1
		stack, mapped := stack_map()
		if !testing.expect(t, mapped, "no stack") {
			free(f, l.allocator)
			return
		}
		f.stack = stack
		f.next = l.free_warm
		l.free_warm = f
		l.warm += 1
	}
	// A window in which none of them was taken.
	l.warm_low = N
	trim_window(l)
	testing.expect_value(t, l.trim_owed, N)
	trim_some(l)
	testing.expect_value(t, l.warm, N - TRIM_BATCH)
	for rounds := 0; l.trim_owed > 0 && rounds < N; rounds += 1 {
		trim_some(l)
	}
	testing.expect_value(t, l.warm, WARM_IDLE_KEEP)
	testing.expect_value(t, l.trim_owed, 0)
}
