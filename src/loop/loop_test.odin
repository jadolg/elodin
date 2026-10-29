package loop

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"

/*
Every test runs its own loop on its own thread and touches nothing but what it
made, since tests run in parallel. The waits that decide an outcome are on
events; the timeouts on them only bound a run that has already failed.
*/

@(private = "file")
WAIT :: 5 * time.Second

@(private = "file")
Running :: struct {
	l:  ^Loop,
	th: ^thread.Thread,
}

@(private = "file")
start :: proc(t: ^testing.T) -> (r: Running, ok: bool) {
	l, made := make_loop()
	if !testing.expect(t, made, "no loop") {
		return {}, false
	}
	r.l = l
	r.th = spawn_thread(l, run, context)
	return r, testing.expect(t, r.th != nil, "no loop thread")
}

@(private = "file")
finish :: proc(r: Running) {
	stop(r.l)
	thread.join(r.th)
	thread.destroy(r.th)
	destroy(r.l)
}

@(private = "file")
Probe :: struct {
	done:    sync.Sema,
	ran:     int,
	on_loop: bool,
	fiber:   bool,
	handle:  Handle,
	result:  Wait_Result,
	reason:  Wake_Reason,
	elapsed: time.Duration,
	value:   int,
	order:   [dynamic]int,
}

@(test)
test_a_fiber_spawned_from_another_thread_runs_on_the_loop :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	p: Probe
	_, ok := spawn(r.l, proc(data: rawptr) {
		p := (^Probe)(data)
		p.ran += 1
		p.on_loop = current_loop() != nil
		p.fiber = current() != nil
		sync.sema_post(&p.done)
	}, &p)
	testing.expect(t, ok)
	testing.expect(t, sync.sema_wait_with_timeout(&p.done, WAIT))
	testing.expect_value(t, p.ran, 1)
	testing.expect(t, p.on_loop && p.fiber)
}

/*
The scratch is the fiber's own and lives exactly as long as its job: allocations
through `context.temp_allocator` come from a block that a second fiber running
at the same time does not share, so one fiber resetting its scratch cannot free
the other's.
*/
@(test)
test_each_fiber_has_its_own_scratch :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		probe:  Probe,
		first:  []u8,
		second: []u8,
		gate:   Sema,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.first = make([]u8, 32, context.temp_allocator)
		s.first[0] = 0xAA
		// Held until the second has allocated and reset its own scratch.
		sema_wait(&s.gate)
		s.probe.value = int(s.first[0])
		sync.sema_post(&s.probe.done)
	}, &s)
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.second = make([]u8, 32, context.temp_allocator)
		s.second[0] = 0x55
		free_all(context.temp_allocator)
		sema_post(&s.gate)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.probe.done, WAIT))
	testing.expect(t, raw_data(s.first) != raw_data(s.second))
	testing.expect_value(t, s.probe.value, 0xAA)
}

// --- Timers, on the loop's clock, driven by hand ----------------------------

@(private = "file")
fake_now: Tick

@(private = "file")
fake_clock :: proc "contextless" () -> Tick {
	return fake_now
}

/*
Deadlines fire in deadline order, and a park that ends before its deadline takes
its timer with it: nothing fires later for a wait that is already over. Driven
without a loop thread, by calling the scheduler's own steps, so what fires is
decided by the clock this test moves and not by the machine's speed.
*/
@(test)
test_timers_fire_in_deadline_order_and_an_ended_park_takes_its_timer :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made) {
		return
	}
	defer destroy(l)
	l.clock = fake_clock
	tl_loop = l
	defer tl_loop = nil

	base := time.tick_now()
	// 30, 10, 40, 20 ms out.
	after := [4]time.Duration{30, 10, 40, 20}
	fibers: [4]^Fiber
	for &f, i in fibers {
		f = new(Fiber)
		f.loop = l
		f.heap_index = -1
		f.state = .Parked
		f.token = u64(i)
		f.deadline = time.tick_add(base, after[i] * time.Millisecond)
		timer_push(l, f)
	}
	defer for f in fibers {
		free(f)
	}

	// The 20 ms one ends early, as a wait that was answered would.
	timer_remove(l, fibers[3])
	testing.expect_value(t, fibers[3].heap_index, -1)

	expire_timers(l, time.tick_add(base, 25 * time.Millisecond))
	testing.expect_value(t, len(l.ready), 1)
	testing.expect(t, l.ready[0] == fibers[1])
	testing.expect_value(t, fibers[1].wake_reason, Wake_Reason.Timeout)

	expire_timers(l, time.tick_add(base, 100 * time.Millisecond))
	testing.expect_value(t, len(l.ready), 3)
	testing.expect(t, l.ready[1] == fibers[0] && l.ready[2] == fibers[2])
	testing.expect_value(t, len(l.timers), 0)
	testing.expect(t, fibers[3].state == .Parked, "the removed timer fired")
}

/*
A wake that names a park which has already ended does nothing. The token moves on
with every park, so a timer that lost its race to a wake, or a wake posted from
another thread for a wait the fiber has since left, lands on a different number.
*/
@(test)
test_a_stale_wake_is_dropped :: proc(t: ^testing.T) {
	l, made := make_loop()
	if !testing.expect(t, made) {
		return
	}
	defer destroy(l)
	f := new(Fiber)
	defer free(f)
	f.loop = l
	f.heap_index = -1
	f.state = .Parked
	f.token = 7

	wake_local(f, 6, .Ready)
	testing.expect_value(t, len(l.ready), 0)
	wake_local(f, 7, .Ready)
	testing.expect_value(t, len(l.ready), 1)
	// Already woken: a second wake for the same park does not queue it twice.
	wake_local(f, 7, .Ready)
	testing.expect_value(t, len(l.ready), 1)
}

@(test)
test_sleep_parks_for_the_duration :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	p: Probe
	_, _ = spawn(r.l, proc(data: rawptr) {
		p := (^Probe)(data)
		began := time.tick_now()
		p.value = int(sleep(20 * time.Millisecond))
		p.elapsed = time.tick_since(began)
		sync.sema_post(&p.done)
	}, &p)
	testing.expect(t, sync.sema_wait_with_timeout(&p.done, WAIT))
	testing.expect_value(t, p.value, 1)
	testing.expectf(t, p.elapsed >= 20 * time.Millisecond, "woke after %v", p.elapsed)
}

// --- Cancellation ---------------------------------------------------------------

@(test)
test_cancel_ends_a_wait_and_every_later_one :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	p: Probe
	parked: Sema
	Shared :: struct {
		p:      ^Probe,
		parked: ^Sema,
	}
	s := Shared{&p, &parked}
	h, ok := spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(s.parked)
		// Would be an hour; the cancel ends it.
		s.p.value = int(sleep(time.Hour))
		// Already cancelled: this does not park at all.
		s.p.reason = park(time.tick_add(time.tick_now(), time.Hour))
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, ok)
	testing.expect(t, sema_wait_with_timeout(&parked, WAIT))
	cancel(h)
	testing.expect(t, sync.sema_wait_with_timeout(&p.done, WAIT))
	testing.expect_value(t, p.value, 0)
	testing.expect_value(t, p.reason, Wake_Reason.Cancelled)
}

/*
A handle to a fiber that has finished cancels nothing, even once the struct is
handed to another fiber: the incarnation it names is over.
*/
@(test)
test_a_handle_outlived_by_its_fiber_cancels_nothing :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	p: Probe
	old, _ := spawn(r.l, proc(data: rawptr) {
		sync.sema_post(&(^Probe)(data).done)
	}, &p)
	testing.expect(t, sync.sema_wait_with_timeout(&p.done, WAIT))
	// Let the scheduler put the struct back on its free list first.
	for fibers_alive(r.l) != 0 {
		time.sleep(time.Millisecond)
	}
	second: Probe
	h, _ := spawn(r.l, proc(data: rawptr) {
		p := (^Probe)(data)
		p.value = int(sleep(30 * time.Millisecond))
		sync.sema_post(&p.done)
	}, &second)
	testing.expect(t, h.fiber == old.fiber, "the free list did not hand the struct out again")
	cancel(old)
	testing.expect(t, sync.sema_wait_with_timeout(&second.done, WAIT))
	testing.expect_value(t, second.value, 1)
}

// --- Descriptors ----------------------------------------------------------------

@(private = "file")
socket_pair :: proc(t: ^testing.T) -> (a, b: linux.Fd, ok: bool) {
	fds: [2]linux.Fd
	if linux.socketpair(.UNIX, .STREAM, .HOPOPT, &fds) != .NONE {
		testing.fail_now(t, "no socket pair")
	}
	for fd in fds {
		flags, _ := linux.fcntl(fd, linux.F_GETFL)
		_ = linux.fcntl(fd, linux.F_SETFL, flags + {.NONBLOCK})
	}
	return fds[0], fds[1], true
}

@(test)
test_a_wait_on_a_descriptor_ends_when_it_is_readable :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:      Probe,
		fd:     linux.Fd,
		parked: Sema,
	}
	s := Shared {
		fd = a,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.parked)
		s.p.result = wait_fd(s.fd, {.In}, time.tick_add(time.tick_now(), WAIT))
		buf: [8]u8
		n, _ := linux.read(s.fd, buf[:])
		s.p.value = n
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	_, _ = linux.write(b, transmute([]u8)string("ping"))
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect_value(t, s.p.result, Wait_Result.Ready)
	testing.expect_value(t, s.p.value, 4)
}

@(test)
test_a_wait_on_a_quiet_descriptor_times_out :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:  Probe,
		fd: linux.Fd,
	}
	s := Shared {
		fd = a,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.p.result = wait_fd(s.fd, {.In}, time.tick_add(time.tick_now(), 20 * time.Millisecond))
		// Nothing is registered once the wait is over.
		s.p.value = len(current_loop().fds)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect_value(t, s.p.result, Wait_Result.Timeout)
	testing.expect_value(t, s.p.value, 0)
}

/*
Two fibers waiting on one descriptor, one to read and one to write - the shape of
a shared upstream connection - are each woken for their own event, and the
writer is not held up by the reader's wait.
*/
@(test)
test_two_fibers_wait_on_one_descriptor :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		reader, writer: Probe,
		fd:             linux.Fd,
		parked:         Sema,
	}
	s := Shared {
		fd = a,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.parked)
		s.reader.result = wait_fd(s.fd, {.In}, time.tick_add(time.tick_now(), WAIT))
		sync.sema_post(&s.reader.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.writer.result = wait_fd(s.fd, {.Out}, time.tick_add(time.tick_now(), WAIT))
		sync.sema_post(&s.writer.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.writer.done, WAIT))
	testing.expect_value(t, s.writer.result, Wait_Result.Ready)
	_, _ = linux.write(b, transmute([]u8)string("x"))
	testing.expect(t, sync.sema_wait_with_timeout(&s.reader.done, WAIT))
	testing.expect_value(t, s.reader.result, Wait_Result.Ready)
}

// Off a loop, the same call is `poll(2)`: what a test thread or the rebuild does.
@(test)
test_a_wait_off_a_loop_polls :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	testing.expect_value(t, wait_fd(a, {.In}, time.tick_add(time.tick_now(), 10 * time.Millisecond)), Wait_Result.Timeout)
	_, _ = linux.write(b, transmute([]u8)string("x"))
	testing.expect_value(t, wait_fd(a, {.In}, time.tick_add(time.tick_now(), WAIT)), Wait_Result.Ready)
}

/*
The socket calls wait for as long as the socket's own receive timeout says, and
then fail as a blocking read that timed out does.
*/
@(test)
test_a_socket_read_on_a_fiber_honours_the_receive_timeout :: proc(t: ^testing.T) {
	sock, err := net.make_unbound_udp_socket(.IP4)
	if !testing.expect(t, err == nil) {
		return
	}
	defer net.close(sock)
	_ = net.bind(sock, {net.IP4_Loopback, 0})
	_ = net.set_blocking(sock, false)
	_ = net.set_option(sock, .Receive_Timeout, 30 * time.Millisecond)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:    Probe,
		sock: net.UDP_Socket,
		err:  net.UDP_Recv_Error,
	}
	s := Shared {
		sock = sock,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		began := time.tick_now()
		buf: [64]u8
		_, _, s.err = recv_udp(s.sock, buf[:])
		s.p.elapsed = time.tick_since(began)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect_value(t, s.err, net.UDP_Recv_Error.Would_Block)
	testing.expectf(t, s.p.elapsed >= 30 * time.Millisecond, "gave up after %v", s.p.elapsed)
}

// --- Locks and waits shared with other fibers and threads ------------------------

/*
A `Mutex` held across a park does not stop the loop: the second fiber to ask for
it parks, and runs once the first lets it go. A `sync.Mutex` in its place would
have put the loop thread to sleep with the holder on it.
*/
@(test)
test_a_mutex_held_across_a_park_does_not_stall_the_loop :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		m:      Mutex,
		holder: Probe,
		waiter: Probe,
		held:   Sema,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		lock(&s.m)
		append(&s.holder.order, 1)
		sema_post(&s.held)
		_ = sleep(20 * time.Millisecond)
		append(&s.holder.order, 2)
		unlock(&s.m)
		sync.sema_post(&s.holder.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.held, WAIT))
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		lock(&s.m)
		append(&s.holder.order, 3)
		unlock(&s.m)
		sync.sema_post(&s.waiter.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.holder.done, WAIT))
	testing.expect(t, sync.sema_wait_with_timeout(&s.waiter.done, WAIT))
	testing.expect_value(t, len(s.holder.order), 3)
	if len(s.holder.order) == 3 {
		testing.expect_value(t, s.holder.order[2], 3)
	}
	delete(s.holder.order)
}

/*
An unlock frees a `Mutex` even when the waiter it wakes cannot run yet: here the
waiter is a fiber on a loop another fiber is keeping busy, and the lock is free
for anybody else the moment it is let go of, rather than owned by a waiter that
is not running. Handed over instead, every fiber after it - on any loop - would
queue behind that loop's round.
*/
@(test)
test_an_unlocked_mutex_is_free_while_its_waiter_waits_to_run :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		m:        Mutex,
		release:  bool,
		spinning: Sema,
		took:     Probe,
	}
	s: Shared
	lock(&s.m)
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		lock(&s.m)
		unlock(&s.m)
		sync.sema_post(&s.took.done)
	}, &s)
	// The waiter is queued once the list has it.
	for deadline := time.tick_now(); time.tick_since(deadline) < WAIT; {
		sync.mutex_lock(&s.m.mu)
		queued := s.m.waiters.head != nil
		sync.mutex_unlock(&s.m.mu)
		if queued {
			break
		}
		time.sleep(time.Millisecond)
	}
	// Keeps the waiter's loop from running it until told to stop.
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.spinning)
		for !sync.atomic_load(&s.release) {
		}
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.spinning, WAIT))
	unlock(&s.m)
	sync.mutex_lock(&s.m.mu)
	free := !s.m.locked
	sync.mutex_unlock(&s.m.mu)
	sync.atomic_store(&s.release, true)
	testing.expect(t, free, "the lock stayed owned by a waiter that could not run")
	testing.expect(t, sync.sema_wait_with_timeout(&s.took.done, WAIT), "the woken waiter never took the lock")
}

/*
Waiters are still served in the order they queued: a woken waiter that finds the
lock taken goes back to the head, so three fibers waiting on a held lock take it
first, second and third.
*/
@(test)
test_mutex_waiters_take_the_lock_in_turn :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		m:     Mutex,
		order: [dynamic]int,
		done:  Sema,
	}
	s: Shared
	Arg :: struct {
		s:  ^Shared,
		id: int,
	}
	args := [3]Arg{{&s, 1}, {&s, 2}, {&s, 3}}
	lock(&s.m)
	for &a in args {
		_, _ = spawn(r.l, proc(data: rawptr) {
			a := (^Arg)(data)
			lock(&a.s.m)
			append(&a.s.order, a.id)
			unlock(&a.s.m)
			sema_post(&a.s.done)
		}, &a)
		// Queued before the next is started, so the order is theirs.
		for deadline := time.tick_now(); time.tick_since(deadline) < WAIT; {
			sync.mutex_lock(&s.m.mu)
			n := 0
			for w := s.m.waiters.head; w != nil; w = w.next {
				n += 1
			}
			sync.mutex_unlock(&s.m.mu)
			if n == a.id {
				break
			}
			time.sleep(time.Millisecond)
		}
	}
	unlock(&s.m)
	for _ in 0 ..< 3 {
		testing.expect(t, sema_wait_with_timeout(&s.done, WAIT))
	}
	testing.expect_value(t, len(s.order), 3)
	if len(s.order) == 3 {
		testing.expect(t, s.order[0] == 1 && s.order[1] == 2 && s.order[2] == 3, "waiters took the lock out of turn")
	}
	delete(s.order)
}

// A fiber waiting on a `Cond` is woken by a plain thread signalling it.
@(test)
test_a_cond_wakes_a_fiber_from_another_thread :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		mu:     sync.Mutex,
		c:      Cond,
		ready:  bool,
		p:      Probe,
		parked: Sema,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sync.mutex_lock(&s.mu)
		sema_post(&s.parked)
		for !s.ready {
			if !cond_wait_with_timeout(&s.c, &s.mu, WAIT) {
				break
			}
		}
		s.p.value = int(s.ready)
		sync.mutex_unlock(&s.mu)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	sync.mutex_lock(&s.mu)
	s.ready = true
	cond_signal(&s.c)
	sync.mutex_unlock(&s.mu)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect_value(t, s.p.value, 1)
}

@(test)
test_a_sema_wait_times_out_and_then_takes_a_post :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		s:      Sema,
		p:      Probe,
		first:  bool,
		second: bool,
		parked: Sema,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.first = sema_wait_with_timeout(&s.s, 10 * time.Millisecond)
		sema_post(&s.parked)
		s.second = sema_wait_with_timeout(&s.s, WAIT)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	sema_post(&s.s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect(t, !s.first)
	testing.expect(t, s.second)
}

// --- Thread-locals carried by the fiber --------------------------------------

@(private = "file", thread_local)
test_local: int

@(private = "file", init)
register_test_local :: proc "contextless" () {
	context = {}
	register_local(proc "contextless" () -> rawptr {return &test_local}, size_of(test_local))
}

/*
A registered thread-local is the fiber's own: one fiber's value survives another
fiber setting its own on the same thread in between, and the loop thread itself
sees zero.
*/
@(test)
test_a_registered_thread_local_follows_its_fiber :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		a, b:  Probe,
		gate:  Sema,
		other: Sema,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		test_local = 11
		sema_post(&s.other)
		sema_wait(&s.gate)
		s.a.value = test_local
		sync.sema_post(&s.a.done)
	}, &s)
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_wait(&s.other)
		s.b.value = test_local
		test_local = 22
		sema_post(&s.gate)
		sync.sema_post(&s.b.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.a.done, WAIT))
	testing.expect(t, sync.sema_wait_with_timeout(&s.b.done, WAIT))
	testing.expect_value(t, s.a.value, 11)
	testing.expect_value(t, s.b.value, 0)
}

/*
A job starts with its registered thread-locals at zero, whatever the last job on
the same fiber left in them: the fiber struct and its stack are reused, and a
value carried over - a pinned generation, say - would belong to somebody else's
query.
*/
@(test)
test_a_reused_fiber_starts_with_its_thread_locals_at_zero :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	first, second: Probe
	_, _ = spawn(r.l, proc(data: rawptr) {
		p := (^Probe)(data)
		test_local = 33
		// Parked once, so the value is saved with the fiber, as a real job's is.
		_ = sleep(time.Millisecond)
		p.value = test_local
		sync.sema_post(&p.done)
	}, &first)
	testing.expect(t, sync.sema_wait_with_timeout(&first.done, WAIT))
	testing.expect_value(t, first.value, 33)
	// The finished fiber is the warm one the next spawn takes.
	_, _ = spawn(r.l, proc(data: rawptr) {
		p := (^Probe)(data)
		p.value = test_local
		sync.sema_post(&p.done)
	}, &second)
	testing.expect(t, sync.sema_wait_with_timeout(&second.done, WAIT))
	testing.expect_value(t, second.value, 0)
}

// --- Scale ---------------------------------------------------------------------

/*
Thousands of fibers parked at once, all on one loop thread, all finish - and a
burst leaves no more than the stack cache behind once it is over.
*/
@(test)
test_thousands_of_parked_fibers_on_one_thread :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	N :: 5000
	Shared :: struct {
		done:  sync.Sema,
		count: int,
	}
	s: Shared
	for _ in 0 ..< N {
		_, ok := spawn(r.l, proc(data: rawptr) {
			s := (^Shared)(data)
			_ = sleep(20 * time.Millisecond)
			if sync.atomic_add(&s.count, 1) == N - 1 {
				sync.sema_post(&s.done)
			}
		}, &s)
		if !testing.expect(t, ok) {
			return
		}
	}
	testing.expect(t, sync.sema_wait_with_timeout(&s.done, 4 * WAIT))
	for fibers_alive(r.l) != 0 {
		time.sleep(time.Millisecond)
	}
	sync.mutex_lock(&r.l.mu)
	warm := r.l.warm
	sync.mutex_unlock(&r.l.mu)
	testing.expectf(t, warm <= STACK_CACHE, "%d stacks kept", warm)
}

/*
A burst's warm stacks are kept while the loop is busy and given back once it has
had nothing to do for `TRIM_AFTER`, down to `WARM_IDLE_KEEP`. Waited for on the
count itself; the deadline only ends a failing run.
*/
@(test)
test_an_idle_loop_gives_back_its_warm_stacks :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	N :: 40
	Shared :: struct {
		done:  sync.Sema,
		count: int,
	}
	s: Shared
	for _ in 0 ..< N {
		_, _ = spawn(r.l, proc(data: rawptr) {
			s := (^Shared)(data)
			// Parked together, so the burst needs N stacks at once.
			_ = sleep(10 * time.Millisecond)
			if sync.atomic_add(&s.count, 1) == N - 1 {
				sync.sema_post(&s.done)
			}
		}, &s)
	}
	testing.expect(t, sync.sema_wait_with_timeout(&s.done, WAIT))
	warm :: proc(l: ^Loop) -> int {
		sync.mutex_lock(&l.mu)
		defer sync.mutex_unlock(&l.mu)
		return l.warm
	}
	for fibers_alive(r.l) != 0 {
		time.sleep(time.Millisecond)
	}
	// The premise: the burst left more than a quiet loop keeps.
	testing.expectf(t, warm(r.l) > WARM_IDLE_KEEP, "only %d stacks were kept after a burst of %d", warm(r.l), N)
	start := time.tick_now()
	for warm(r.l) > WARM_IDLE_KEEP && time.tick_since(start) < 4 * TRIM_AFTER {
		time.sleep(10 * time.Millisecond)
	}
	testing.expectf(t, warm(r.l) <= WARM_IDLE_KEEP, "%d stacks still warm after %v idle", warm(r.l), time.tick_since(start))
}

/*
`cancel_all` reaches every fiber on the loop, a fiber started by another fiber
and parked on a descriptor included - the shape of an upstream connection's
reader at shutdown.
*/
@(test)
test_cancel_all_reaches_a_fiber_waiting_on_a_descriptor :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	l, made := make_loop()
	if !testing.expect(t, made) {
		return
	}
	th := spawn_thread(l, run, context)
	Shared :: struct {
		fd:      linux.Fd,
		parked:  Sema,
		waiter:  ^Fiber,
		result:  Wait_Result,
		done:    sync.Sema,
	}
	s := Shared {
		fd = a,
	}
	_, _ = spawn(l, proc(data: rawptr) {
		// Started from a fiber, as an upstream reader is.
		_ = go(proc(data: rawptr) {
			s := (^Shared)(data)
			sync.atomic_store(&s.waiter, current())
			sema_post(&s.parked)
			s.result = wait_fd(s.fd, {.In}, time.tick_add(time.tick_now(), time.Hour))
			sync.sema_post(&s.done)
		}, data)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	/*
	The premise: the fiber is parked in the wait when the cancel lands. Cancelled
	before it got there, `wait_fd` returns `.Cancelled` without ever parking, and
	this would pass without a parked waiter having been woken at all.
	*/
	waiter := sync.atomic_load(&s.waiter)
	start := time.tick_now()
	for sync.atomic_load(&waiter.state) != .Parked && time.tick_since(start) < WAIT {
		time.sleep(time.Millisecond)
	}
	testing.expect(t, sync.atomic_load(&waiter.state) == .Parked, "the waiter never parked on the descriptor")
	cancel_all(l)
	woke := sync.sema_wait_with_timeout(&s.done, WAIT)
	testing.expect(t, woke, "cancel_all did not end the wait")
	testing.expect_value(t, s.result, Wait_Result.Cancelled)
	stop(l)
	if woke {
		thread.join(th)
		thread.destroy(th)
		destroy(l)
	}
}

/*
A fiber whose start reaches the loop after `cancel_all` starts cancelled. A
`spawn` from another thread checks `stopping` and posts its start under two
holds of the lock, so at shutdown one can land behind the cancel; uncancelled, it
would hold the loop for as long as its wait - an upstream reader's is the life of
its connection, which is released only after the loops have stopped.
*/
@(test)
test_a_fiber_started_after_cancel_all_starts_cancelled :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	r, started := start(t)
	if !started {
		return
	}
	Shared :: struct {
		fd:     linux.Fd,
		result: Wait_Result,
		done:   sync.Sema,
	}
	s := Shared {
		fd = a,
	}
	cancel_all(r.l)
	_, spawned := spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		s.result = wait_fd(s.fd, {.In}, time.tick_add(time.tick_now(), time.Hour))
		sync.sema_post(&s.done)
	}, &s)
	testing.expect(t, spawned, "the fiber was not started")
	woke := sync.sema_wait_with_timeout(&s.done, WAIT)
	if !woke {
		// Let the waiter go, so the loop can stop and the test end.
		_, _ = linux.write(b, transmute([]u8)string("ping"))
		_ = sync.sema_wait_with_timeout(&s.done, WAIT)
	}
	testing.expect(t, woke, "a fiber started after cancel_all waited out its deadline")
	testing.expect_value(t, s.result, Wait_Result.Cancelled)
	finish(r)
}

/*
A wait with no deadline off a loop waits, rather than failing at once: `ppoll`
with no timeout, which `core:sys/linux`'s `poll` cannot express on arm64.
*/
@(test)
test_a_wait_off_a_loop_with_no_deadline_waits :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	Writer :: struct {
		fd: linux.Fd,
	}
	w := Writer{b}
	th := thread.create_and_start_with_poly_data(&w, proc(w: ^Writer) {
		time.sleep(30 * time.Millisecond)
		_, _ = linux.write(w.fd, transmute([]u8)string("x"))
	})
	defer {
		thread.join(th)
		thread.destroy(th)
	}
	testing.expect_value(t, wait_fd(a, {.In}, {}), Wait_Result.Ready)
}

/*
A fiber that never waits - a UDP reader under a flood, yielding every batch -
does not keep the loop from its descriptors: a fiber parked on one that is
already readable still wakes while the other keeps the ready list full.
*/
@(test)
test_a_fiber_that_keeps_yielding_does_not_starve_a_descriptor :: proc(t: ^testing.T) {
	a, b, paired := socket_pair(t)
	if !paired {
		return
	}
	defer linux.close(a)
	defer linux.close(b)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:       Probe,
		fd:      linux.Fd,
		woke:    bool,
		give_up: bool,
		parked:  Sema,
		// Posted once the spinner is running, so the write below lands while
		// the loop is spinning and not in an epoll wait the spawn woke.
		running: Sema,
	}
	s := Shared {
		fd = a,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.parked)
		s.p.result = wait_fd(s.fd, {.In}, {})
		sync.atomic_store(&s.woke, true)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.running)
		for !sync.atomic_load(&s.woke) && !sync.atomic_load(&s.give_up) {
			yield()
		}
	}, &s)
	testing.expect(t, sema_wait_with_timeout(&s.running, WAIT))
	_, _ = linux.write(b, transmute([]u8)string("ping"))
	woke := sync.sema_wait_with_timeout(&s.p.done, WAIT)
	if !woke {
		// Let the spinner go, so the loop can stop and the test end.
		sync.atomic_store(&s.give_up, true)
		cancel_all(r.l)
		_ = sync.sema_wait_with_timeout(&s.p.done, WAIT)
	}
	testing.expect(t, woke, "the descriptor's waiter never woke while another fiber yielded")
	testing.expect_value(t, s.p.result, Wait_Result.Ready)
}

/*
A reader that never parks lets the other fibers of its loop run every
`TURN_BATCH` rounds, and not before: the fiber started beside it has not run one
round short of the batch, and has run once the batch is reached.
*/
@(test)
test_take_turn_yields_every_batch :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:           Probe,
		other_ran:   bool,
		before_turn: bool,
		after_turn:  bool,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		// Started from here, so it is on the ready list behind this fiber and runs
		// only once this one parks or yields.
		_, _ = spawn(current_loop(), proc(data: rawptr) {
			(^Shared)(data).other_ran = true
		}, s)
		for _ in 0 ..< TURN_BATCH - 1 {
			take_turn()
		}
		s.before_turn = s.other_ran
		take_turn()
		s.after_turn = s.other_ran
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect(t, !s.before_turn, "the other fiber ran before the batch was reached")
	testing.expect(t, s.after_turn, "the reader did not yield at the end of the batch")
}

/*
The socket wrappers take the turns themselves, so a read loop that never waits
yields without calling `take_turn`: a UDP socket with more than a batch of
datagrams already queued is read straight through by `recv_udp`, and the fiber
started beside the reader runs at the `TURN_BATCH`th read and not before.
*/
@(test)
test_a_reader_that_never_waits_yields_by_itself :: proc(t: ^testing.T) {
	rx, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind: %v", rerr) {
		return
	}
	defer net.close(rx)
	_ = net.set_blocking(rx, false)
	at, _ := net.bound_endpoint(rx)
	tx, terr := net.make_unbound_udp_socket(.IP4)
	if !testing.expectf(t, terr == nil, "no sender: %v", terr) {
		return
	}
	defer net.close(tx)
	one := [1]u8{1}
	for _ in 0 ..< TURN_BATCH + 4 {
		_, _ = net.send_udp(tx, one[:], at)
	}
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:           Probe,
		rx:          net.UDP_Socket,
		other_ran:   bool,
		before_turn: bool,
		after_turn:  bool,
	}
	s := Shared {
		rx = rx,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		_, _ = spawn(current_loop(), proc(data: rawptr) {
			(^Shared)(data).other_ran = true
		}, s)
		buf: [8]u8
		for _ in 0 ..< TURN_BATCH - 1 {
			_, _, _ = recv_udp(s.rx, buf[:])
		}
		s.before_turn = s.other_ran
		_, _, _ = recv_udp(s.rx, buf[:])
		s.after_turn = s.other_ran
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect(t, !s.before_turn, "the other fiber ran before the batch was reached")
	testing.expect(t, s.after_turn, "a read loop that never waited did not yield")
}

/*
A socket call that returns without waiting still counts as a turn. A cancelled
fiber's read returns `Would_Block` at once, as one on a descriptor epoll will not
take does, and the read and accept loops retry on exactly that: without the turn,
such a loop holds its loop for as long as the cause lasts, and the fiber started
beside it never runs.
*/
@(test)
test_a_read_that_cannot_wait_still_takes_its_turn :: proc(t: ^testing.T) {
	rx, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind: %v", rerr) {
		return
	}
	defer net.close(rx)
	_ = net.set_blocking(rx, false)
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:         Probe,
		rx:        net.UDP_Socket,
		other_ran: bool,
		// Read before the fiber finishes, which lets the other one run anyway.
		in_time:   bool,
		blocked:   bool,
	}
	s := Shared {
		rx = rx,
	}
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		_, _ = spawn(current_loop(), proc(data: rawptr) {
			(^Shared)(data).other_ran = true
		}, s)
		f := current()
		cancel(Handle{f, f.incarnation})
		buf: [8]u8
		for _ in 0 ..< 2 * TURN_BATCH {
			if s.other_ran {
				break
			}
			_, _, err := recv_udp(s.rx, buf[:])
			s.blocked = err == .Would_Block
		}
		s.in_time = s.other_ran
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect(t, s.blocked, "a cancelled read did not return Would_Block")
	testing.expect(t, s.in_time, "a read loop that could not wait held its loop")
}

/*
A cancelled fiber waiting on a cond in the usual loop - `for !ready { cond_wait }`
- parks until it is signalled, rather than having every wait return at once and
spinning its loop: the fiber that would signal it is on the same loop, and a spin
that never parks never lets it run.
*/
@(test)
test_a_cancelled_fiber_still_parks_on_a_cond :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:       Probe,
		mu:      sync.Mutex,
		cond:    Cond,
		ready:   bool,
		give_up: bool,
		parked:  Sema,
		waiting: Sema,
	}
	s: Shared
	h, ok := spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sema_post(&s.parked)
		_ = sleep(time.Hour)
		sema_post(&s.waiting)
		sync.mutex_lock(&s.mu)
		for !s.ready && !sync.atomic_load(&s.give_up) {
			cond_wait(&s.cond, &s.mu)
		}
		s.p.value = int(s.ready)
		sync.mutex_unlock(&s.mu)
		sync.sema_post(&s.p.done)
	}, &s)
	testing.expect(t, ok)
	testing.expect(t, sema_wait_with_timeout(&s.parked, WAIT))
	cancel(h)
	testing.expect(t, sema_wait_with_timeout(&s.waiting, WAIT))
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		sync.mutex_lock(&s.mu)
		s.ready = true
		cond_signal(&s.cond)
		sync.mutex_unlock(&s.mu)
	}, &s)
	woke := sync.sema_wait_with_timeout(&s.p.done, WAIT)
	if !woke {
		// Let the spinner go, so the loop can stop and the test end.
		sync.atomic_store(&s.give_up, true)
		_ = sync.sema_wait_with_timeout(&s.p.done, WAIT)
	}
	testing.expect(t, woke, "the cancelled waiter never saw the signal")
	testing.expect_value(t, s.p.value, 1)
}

/*
A fiber started from another thread and cancelled on its own loop before the
loop has taken its start runs cancelled: the start does not undo the cancel.
*/
@(test)
test_a_cancel_made_before_the_start_is_drained_holds :: proc(t: ^testing.T) {
	r, started := start(t)
	if !started {
		return
	}
	defer finish(r)
	Shared :: struct {
		p:         Probe,
		ran:       bool,
		cancelled: bool,
	}
	s: Shared
	_, _ = spawn(r.l, proc(data: rawptr) {
		s := (^Shared)(data)
		l := tl_loop
		// Spawned as another thread spawns: the start is posted, and the loop
		// takes it only after this fiber has given the loop up.
		tl_loop = nil
		h, ok := spawn(l, proc(data: rawptr) {
			s := (^Shared)(data)
			s.ran = true
			s.cancelled = cancelled()
			sync.sema_post(&s.p.done)
		}, s)
		tl_loop = l
		if !ok {
			sync.sema_post(&s.p.done)
			return
		}
		cancel(h)
	}, &s)
	testing.expect(t, sync.sema_wait_with_timeout(&s.p.done, WAIT))
	testing.expect(t, s.ran, "the fiber did not run")
	testing.expect(t, s.cancelled, "the start undid a cancel made before it was drained")
}
