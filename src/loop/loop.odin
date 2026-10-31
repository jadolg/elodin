package loop

import "base:intrinsics"
import "base:runtime"
import "core:sync"
import "core:sys/linux"
import "core:time"
import "elodin:brlock"

/*
An event loop: one thread, one epoll instance, and the fibers that take turns on
it.

The scheduler runs on the thread's own stack and does four things in a round:
runs every fiber that is ready, takes what other threads have posted, waits in
`epoll_wait` for as long as the nearest timer allows (not at all if a fiber is
ready), and wakes the fibers whose descriptors or timers came due. Nothing else
on a loop thread ever blocks: a fiber that waits parks, and a fiber that would
block the thread instead - a plain mutex held across a park, a blocking socket -
is a bug that stalls every fiber on the loop with it, which is why the waits in
this package are the only ones code on a loop may use.

Level-triggered epoll, registered for the length of one wait. A descriptor is
added when the first fiber waits on it and removed when the last stops, so a
descriptor nobody waits on is in no interest list, and closing one cannot leave
a registration behind for a later descriptor with the same number to inherit;
and a readiness that arrives with nobody waiting is reported again to whoever
waits next, rather than lost the way an edge-triggered one would be. It costs two
`epoll_ctl` calls per wait that actually parks; a read that finds data waiting
does not park at all.

Linux only, as the rest of the server is.
*/
Loop :: struct {
	epfd:                linux.Fd,
	// Written by `post` from another thread to cut `epoll_wait` short.
	wakefd:              linux.Fd,
	// The scheduler's stack pointer while a fiber runs.
	sched_sp:            rawptr,
	current:             ^Fiber,
	ready:               [dynamic]^Fiber,
	// What `ready` is swapped into while a round runs it, so a fiber woken during
	// the round waits for the next one.
	running:             [dynamic]^Fiber,
	timers:              [dynamic]^Fiber,
	fds:                 map[linux.Fd]^Fd_Watch,
	spare_watches:       [dynamic]^Fd_Watch,
	// Live fibers, for `cancel_all`.
	live:                ^Fiber,
	alive:               int,
	// Guards the free lists, `posted`, `alive` and `stopping`, which other threads
	// reach through `spawn` and `post`.
	mu:                  sync.Mutex,
	// Free fibers that still hold a stack, at most `STACK_CACHE` of them, and
	// free fibers that do not.
	free_warm:           ^Fiber,
	free_cold:           ^Fiber,
	warm:                int,
	posted:              [dynamic]Post,
	draining:            [dynamic]Post,
	// Whether the eventfd has been written since the scheduler last drained it.
	signalled:           bool,
	stopping:            bool,
	ctx:                 runtime.Context,
	/*
	The allocator the loop was made with, which everything it allocates comes
	from and `destroy` frees through. Apart from `ctx`, which `run` replaces on
	the loop thread, because `spawn` reads it from any thread.
	*/
	allocator:           runtime.Allocator,
	local_addresses:     [len(locals)]rawptr,
	thread_stack_bottom: rawptr,
	thread_stack_size:   uint,
	/*
	The clock timers are judged against. `time.tick_now` everywhere but in the
	package's own tests, which move it by hand so that "the timer fired" and "the
	timer did not fire" are decided by the test rather than by how fast the
	machine was that day.
	*/
	clock:               proc "contextless" () -> Tick,
	/*
	Whether `cancel_all` has reached this loop. Loop thread only. A fiber that
	starts after it starts cancelled: `stop` and `cancel_all` take the lock apart
	from a `spawn` on another thread, so one that passed its `stopping` check
	before the stop can post its start after the cancel has been drained.
	*/
	cancelled_all:       bool,
	// When the loop last had anything to do, for `trim_idle`.
	last_busy:           Tick,
}

Tick :: time.Tick

@(private)
Post_Kind :: enum u8 {
	// A fiber spawned from another thread, to put on the ready list.
	Start,
	Wake,
	Cancel,
	Cancel_All,
}

@(private)
Post :: struct {
	kind:  Post_Kind,
	fiber: ^Fiber,
	// The park token for `.Wake`, the incarnation for `.Cancel`.
	value: u64,
}

// Loops started and not yet destroyed, so `register_local` can tell it is late.
@(private)
loops_started: int

// The loop this thread runs, if it runs one.
@(private, thread_local)
tl_loop: ^Loop

make_loop :: proc(allocator := context.allocator) -> (l: ^Loop, ok: bool) {
	epfd, err := linux.epoll_create1({.FDCLOEXEC})
	if err != .NONE {
		return nil, false
	}
	wakefd, werr := linux.eventfd(0, {.CLOEXEC, .NONBLOCK})
	if werr != .NONE {
		linux.close(epfd)
		return nil, false
	}
	l = new(Loop, allocator)
	l.epfd = epfd
	l.wakefd = wakefd
	l.clock = time.tick_now
	l.ctx = context
	// Everything the loop allocates, and every fiber's own allocations, come from
	// the allocator it was made with; `destroy` frees through it. The lists too,
	// which would otherwise take whatever allocator the first append ran under.
	l.allocator = allocator
	l.ctx.allocator = allocator
	l.fds = make(map[linux.Fd]^Fd_Watch, allocator)
	l.ready = make([dynamic]^Fiber, allocator)
	l.running = make([dynamic]^Fiber, allocator)
	l.timers = make([dynamic]^Fiber, allocator)
	l.spare_watches = make([dynamic]^Fd_Watch, allocator)
	l.posted = make([dynamic]Post, allocator)
	l.draining = make([dynamic]Post, allocator)
	ev := linux.EPoll_Event {
		events = {.IN},
		data = {fd = wakefd},
	}
	if linux.epoll_ctl(epfd, .ADD, wakefd, &ev) != .NONE {
		linux.close(wakefd)
		linux.close(epfd)
		delete(l.fds)
		free(l, allocator)
		return nil, false
	}
	sync.atomic_add(&loops_started, 1)
	return l, true
}

/*
Release a loop that has stopped running, and every fiber and stack it kept.

Only once its thread has returned from `run`: nothing may post to it after this,
which is the caller's to arrange - every fiber has finished by then, and the
threads that could post to one are the threads that hold one.
*/
destroy :: proc(l: ^Loop) {
	if l == nil {
		return
	}
	context.allocator = l.allocator
	for list in ([]^Fiber{l.free_warm, l.free_cold}) {
		for f := list; f != nil; {
			next := f.next
			fiber_release(l, f)
			free(f)
			f = next
		}
	}
	for _, w in l.fds {
		delete(w.waiters)
		free(w)
	}
	for w in l.spare_watches {
		delete(w.waiters)
		free(w)
	}
	delete(l.fds)
	delete(l.spare_watches)
	delete(l.ready)
	delete(l.running)
	delete(l.timers)
	delete(l.posted)
	delete(l.draining)
	linux.close(l.wakefd)
	linux.close(l.epfd)
	sync.atomic_sub(&loops_started, 1)
	free(l)
}

/*
Run the loop on the calling thread until `stop` has been asked for and every
fiber on it has finished.

The context the fibers get is the one `run` is called with, with the scratch
replaced per fiber; the loop's thread-local addresses are read here because only
here is the thread known.
*/
run :: proc(l: ^Loop) {
	// Before any query takes one at first use, so each loop has a stripe of its own.
	brlock.stripe()
	tl_loop = l
	defer tl_loop = nil
	l.ctx = context
	l.ctx.allocator = l.allocator
	for i in 0 ..< locals_count {
		l.local_addresses[i] = locals[i].address()
	}
	events: [128]linux.EPoll_Event
	l.last_busy = l.clock()
	for {
		run_ready(l)
		drain_posts(l)
		/*
		Fibers still ready - one that yielded, or one woken this round - run next
		round, but epoll is asked first, without waiting: a fiber that yields for
		ever, as a UDP reader under a flood does, would otherwise keep every
		descriptor and timer on this loop from being looked at.
		*/
		busy := len(l.ready) > 0
		if !busy && stop_reached(l) {
			return
		}
		timeout := i32(-1)
		if busy {
			timeout = 0
		} else if len(l.timers) > 0 {
			left := time.tick_diff(l.clock(), l.timers[0].deadline)
			// Rounded up, so a timer due in 0.4 ms is not polled for in a loop of
			// zero-length waits until it is due.
			// Held to what `epoll_wait` takes: a deadline weeks away would
			// otherwise wrap to a negative figure, which is no timeout at all.
			timeout = i32(clamp((left + time.Millisecond - 1) / time.Millisecond, 0, time.Duration(max(i32))))
		}
		// Wake to trim, if there is anything to trim; see `trim_idle`. The lock
		// `trim_pending` takes is asked for only when the answer could matter: a
		// busy round polls without waiting, and a busy round is every round under load.
		if (timeout < 0 || timeout > i32(TRIM_AFTER / time.Millisecond)) && trim_pending(l) {
			timeout = i32(TRIM_AFTER / time.Millisecond)
		}
		n, err := epoll_wait(l.epfd, events[:], timeout)
		if err != .NONE && err != .EINTR {
			// Nothing the loop can do about a broken epoll descriptor but say so;
			// spinning on it would be worse.
			panic("epoll_wait failed")
		}
		for i in 0 ..< max(n, 0) {
			dispatch_event(l, events[i])
		}
		expire_timers(l, l.clock())
		/*
		Busy is a fiber still ready, or a descriptor or another thread having had
		something for this loop. A timer coming due is not: the listeners wake on one every
		`LISTENER_POLL` to look for a stop, and a loop that counted those as work
		would never be idle enough to trim.
		*/
		if n > 0 || busy {
			l.last_busy = l.clock()
		} else if time.tick_diff(l.last_busy, l.clock()) >= TRIM_AFTER {
			trim_idle(l)
		}
	}
}

/*
`epoll_pwait` with no signal mask, which is `epoll_wait`.

Not `core:sys/linux`'s `epoll_wait`, which on arm64 passes a pointer to a
`timespec` where `epoll_pwait` takes its timeout as milliseconds in an `int`: the
kernel reads the pointer as the timeout and a wait that should end in 20 ms ends
in hours. arm64 has no plain `epoll_wait` system call, so the same call serves
both architectures.
*/
@(private)
epoll_wait :: proc(epfd: linux.Fd, events: []linux.EPoll_Event, timeout_ms: i32) -> (i32, linux.Errno) {
	ret := intrinsics.syscall(
		linux.SYS_epoll_pwait,
		uintptr(epfd),
		uintptr(raw_data(events)),
		uintptr(len(events)),
		uintptr(int(timeout_ms)),
		0,
		0,
	)
	if int(ret) < 0 && int(ret) > -4096 {
		return 0, linux.Errno(-int(ret))
	}
	return i32(ret), .NONE
}

@(private)
stop_reached :: proc(l: ^Loop) -> bool {
	sync.mutex_lock(&l.mu)
	defer sync.mutex_unlock(&l.mu)
	return l.stopping && l.alive == 0
}

/*
Ask the loop to return from `run` once its last fiber has finished. From any
thread.

It does not end any fiber: what to cancel and in what order is the server's to
decide (connections are told before queries, so an answer in flight still goes
out). `cancel_all` is the blunt form.
*/
stop :: proc(l: ^Loop) {
	sync.mutex_lock(&l.mu)
	l.stopping = true
	signal_locked(l)
	sync.mutex_unlock(&l.mu)
}

// Cancel every fiber the loop is running now. From any thread.
cancel_all :: proc(l: ^Loop) {
	post(l, Post{kind = .Cancel_All})
}

// The loop the calling thread runs, or nil off a loop.
current_loop :: proc "contextless" () -> ^Loop {
	return tl_loop
}

// The fiber that is running, or nil off a fiber (a plain thread, or a test).
current :: proc "contextless" () -> ^Fiber {
	l := tl_loop
	if l == nil {
		return nil
	}
	return l.current
}

// Whether the running fiber has been cancelled. Always false off a fiber.
cancelled :: proc "contextless" () -> bool {
	f := current()
	return f != nil && f.cancelled
}

// Fibers running on this loop now, for the metrics endpoint.
fibers_alive :: proc(l: ^Loop) -> int {
	sync.mutex_lock(&l.mu)
	defer sync.mutex_unlock(&l.mu)
	return l.alive
}

/*
Start `fn(data)` on a fiber of `l`. From any thread, including `l`'s own fibers.

Fails only when the loop is stopping or a stack cannot be mapped; `data` is then
still the caller's. On success it belongs to `fn`, which runs on `l` - at the
loop's next round when called from one of its own fibers, as soon as the loop
notices the post otherwise.
*/
spawn :: proc(l: ^Loop, fn: proc(data: rawptr), data: rawptr) -> (h: Handle, ok: bool) {
	f: ^Fiber
	{
		sync.mutex_lock(&l.mu)
		defer sync.mutex_unlock(&l.mu)
		if l.stopping {
			return {}, false
		}
		switch {
		case l.free_warm != nil:
			f = l.free_warm
			l.free_warm = f.next
			l.warm -= 1
		case l.free_cold != nil:
			f = l.free_cold
			l.free_cold = f.next
		case:
			f = new(Fiber, l.allocator)
			f.loop = l
			f.heap_index = -1
		}
		l.alive += 1
	}
	if f.stack.base == nil {
		stack, mapped := stack_map()
		if !mapped {
			sync.mutex_lock(&l.mu)
			f.next = l.free_cold
			l.free_cold = f
			l.alive -= 1
			// The count this took kept a stopping loop from returning; as in
			// `fiber_recycle`, the one that takes it to zero says so.
			if l.alive == 0 && l.stopping {
				signal_locked(l)
			}
			sync.mutex_unlock(&l.mu)
			return {}, false
		}
		f.stack = stack
		fiber_prepare(f)
	}
	f.fn = fn
	f.data = data
	f.cancelled = false
	f.wake_reason = .None
	// A job starts from the zero values a fresh thread would, whatever the last
	// job on this fiber left in its registered thread-locals.
	f.locals = {}
	/*
	Published in this order, the state last: from another thread this struct is
	being reused while the loop may be acting on a `cancel` posted for its last
	use, and `cancel_local` reads the state first. Seeing `.New`, it is sure to
	see the new incarnation too, and leaves the new fiber alone.
	*/
	incarnation := f.incarnation + 1
	sync.atomic_store(&f.incarnation, incarnation)
	sync.atomic_store(&f.state, Fiber_State.New)
	h = Handle{f, incarnation}
	if tl_loop == l {
		live_insert(l, f)
		f.cancelled = l.cancelled_all
		append(&l.ready, f)
	} else {
		post(l, Post{kind = .Start, fiber = f})
	}
	return h, true
}

/*
Cancel the fiber `h` names, if it is still that fiber. From any thread.

The fiber's current wait, and every wait it makes after this, returns
`.Cancelled` - except a mutex being acquired, which is not given up halfway, and
a cond wait, which its caller would only make again (see `Cond`). What
cancellation means beyond that is the fiber's: it sees its reads fail and its
waits end, and unwinds the way it would for a timeout.
*/
cancel :: proc(h: Handle) {
	if h.fiber == nil {
		return
	}
	l := h.fiber.loop
	if tl_loop == l {
		cancel_local(l, h.fiber, h.incarnation)
		return
	}
	post(l, Post{kind = .Cancel, fiber = h.fiber, value = h.incarnation})
}

@(private)
cancel_local :: proc(l: ^Loop, f: ^Fiber, incarnation: u64) {
	// The state before the incarnation; `spawn` says why.
	state := sync.atomic_load(&f.state)
	if state == .Free || state == .Done || sync.atomic_load(&f.incarnation) != incarnation {
		return
	}
	f.cancelled = true
	if f.state == .Parked {
		wake_local(f, f.token, .Cancelled)
	}
}

@(private)
post :: proc(l: ^Loop, p: Post) {
	sync.mutex_lock(&l.mu)
	append(&l.posted, p)
	signal_locked(l)
	sync.mutex_unlock(&l.mu)
}

// Under `l.mu`. One eventfd write per batch of posts, not per post.
@(private)
signal_locked :: proc(l: ^Loop) {
	if l.signalled {
		return
	}
	l.signalled = true
	one := u64(1)
	_, _ = linux.write(l.wakefd, ([^]u8)(&one)[:8])
}

@(private)
drain_posts :: proc(l: ^Loop) {
	sync.mutex_lock(&l.mu)
	l.posted, l.draining = l.draining, l.posted
	if l.signalled {
		l.signalled = false
		v: u64
		_, _ = linux.read(l.wakefd, ([^]u8)(&v)[:8])
	}
	sync.mutex_unlock(&l.mu)
	for p in l.draining {
		switch p.kind {
		case .Start:
			live_insert(l, p.fiber)
			// Or'd rather than set: a `cancel` made on this loop reaches the fiber
			// at once, which may be before its start is drained here.
			p.fiber.cancelled = p.fiber.cancelled || l.cancelled_all
			append(&l.ready, p.fiber)
		case .Wake:
			wake_local(p.fiber, p.value, .Ready)
		case .Cancel:
			cancel_local(l, p.fiber, p.value)
		case .Cancel_All:
			l.cancelled_all = true
			for f := l.live; f != nil; f = f.next {
				cancel_local(l, f, f.incarnation)
			}
		}
	}
	clear(&l.draining)
}

@(private)
run_ready :: proc(l: ^Loop) {
	l.ready, l.running = l.running, l.ready
	for f in l.running {
		switch_to_fiber(l, f)
		if f.state == .Done {
			fiber_recycle(l, f)
		}
	}
	clear(&l.running)
}

@(private)
live_insert :: proc(l: ^Loop, f: ^Fiber) {
	f.prev = nil
	f.next = l.live
	if l.live != nil {
		l.live.prev = f
	}
	l.live = f
}

@(private)
live_remove :: proc(l: ^Loop, f: ^Fiber) {
	if f.prev != nil {
		f.prev.next = f.next
	} else {
		l.live = f.next
	}
	if f.next != nil {
		f.next.prev = f.prev
	}
	f.next, f.prev = nil, nil
}

/*
Put a finished fiber back on the free list, keeping its stack for the next one
while the cache has room.

A stack past the cache is unmapped, and so is one whose scratch grew past what a
recycled fiber keeps: the next query to get this struct starts on a fresh stack
and arena instead of inheriting a large one's high-water mark.
*/
@(private)
fiber_recycle :: proc(l: ^Loop, f: ^Fiber) {
	live_remove(l, f)
	f.state = .Free
	f.fn, f.data = nil, nil
	f.token += 1
	oversized := scratch_oversized(&f.scratch)
	sync.mutex_lock(&l.mu)
	// A stack kept warm goes straight back on the list, in the one lock a
	// finished query costs; only one being unmapped is let go of first, since
	// `spawn` may hand out whatever is on a list the moment it is there.
	keep := !oversized && l.warm < STACK_CACHE
	if keep {
		l.warm += 1
		f.next = l.free_warm
		l.free_warm = f
	}
	l.alive -= 1
	if l.alive == 0 && l.stopping {
		signal_locked(l)
	}
	sync.mutex_unlock(&l.mu)
	if keep {
		return
	}
	fiber_release(l, f)
	sync.mutex_lock(&l.mu)
	f.next = l.free_cold
	l.free_cold = f
	sync.mutex_unlock(&l.mu)
}

/*
How long a loop sits with nothing to do before it gives back the stacks it kept
warm, and how many it keeps through the quiet.

The cache is for the next query, which under load is microseconds away and would
otherwise pay a `mmap` and the page faults of a fresh stack. After a burst that is
over, the same cache is memory nobody will touch: a burst of two hundred
connections leaves up to `STACK_CACHE` stacks per loop resident, some twenty
kilobytes each. A second of nothing is long past any gap between the queries of a
loaded server, and a few stacks are enough for a quiet one's next query.
*/
@(private)
TRIM_AFTER :: time.Second
@(private)
WARM_IDLE_KEEP :: 8

@(private)
trim_pending :: proc(l: ^Loop) -> bool {
	sync.mutex_lock(&l.mu)
	defer sync.mutex_unlock(&l.mu)
	return l.warm > WARM_IDLE_KEEP
}

// Unmap the warm stacks past `WARM_IDLE_KEEP`; their fibers stay, cold.
@(private)
trim_idle :: proc(l: ^Loop) {
	for {
		sync.mutex_lock(&l.mu)
		if l.warm <= WARM_IDLE_KEEP || l.free_warm == nil {
			sync.mutex_unlock(&l.mu)
			return
		}
		f := l.free_warm
		l.free_warm = f.next
		l.warm -= 1
		sync.mutex_unlock(&l.mu)
		fiber_release(l, f)
		sync.mutex_lock(&l.mu)
		f.next = l.free_cold
		l.free_cold = f
		sync.mutex_unlock(&l.mu)
	}
}

/*
Unmap a free fiber's stack and destroy its scratch.

The fiber is switched into one last time with no job, so that it leaves its stack
the way it entered it - through `fiber_entry` - and AddressSanitizer is told the
stack is gone.
*/
@(private)
fiber_release :: proc(l: ^Loop, f: ^Fiber) {
	if f.stack.base == nil {
		return
	}
	f.fn = nil
	when ASAN {
		if f.sp != nil && tl_loop == l {
			switch_to_fiber(l, f)
		}
	}
	scratch_destroy(&f.scratch)
	stack_unmap(f.stack)
	f.stack = {}
	f.sp = nil
}

// --- Parking and waking -------------------------------------------------------

/*
Park the running fiber until something wakes it or `deadline` passes. The zero
deadline is none.

`cancellable` is whether `cancel` ends this park: true for every wait on the
outside world, false for acquiring a `Mutex`, which is never abandoned halfway,
and for a `Cond`, whose callers would only wait again.
A fiber already cancelled does not park at all.

A wake is a hint and never a promise: every caller re-checks what it was waiting
for and parks again if it is not so. That is what lets a stale wake - a timer
that lost its race, a readiness reported for a descriptor somebody else drained
first - be harmless rather than a bug to hunt.
*/
park :: proc(deadline: Tick, cancellable := true) -> Wake_Reason {
	l := tl_loop
	f := l.current
	assert(f != nil, "park off a fiber")
	if cancellable && f.cancelled {
		f.token += 1
		return .Cancelled
	}
	f.wake_reason = .None
	f.deadline = deadline
	if deadline != (Tick{}) {
		timer_push(l, f)
	}
	f.state = .Parked
	f.cancellable = cancellable
	switch_to_scheduler(f)
	// Running again. Whatever woke us, nothing else that signed up for this park
	// may: the token moves on, and the timer, if it did not fire, comes out.
	f.token += 1
	if f.heap_index >= 0 {
		timer_remove(l, f)
	}
	if cancellable && f.cancelled && f.wake_reason != .Timeout {
		return .Cancelled
	}
	return f.wake_reason
}

/*
Wake `f` from the park `token` was taken for, from any thread.

On `f`'s own loop the fiber is made ready at once; from anywhere else the wake is
posted and the loop makes it ready when it drains its posts, which it does only
between fibers - so a fiber that has signed up as a waiter and released the lock
it signed up under, but has not yet switched out, cannot miss a wake from another
thread.
*/
wake :: proc(f: ^Fiber, token: u64) {
	l := f.loop
	if tl_loop == l {
		wake_local(f, token, .Ready)
		return
	}
	post(l, Post{kind = .Wake, fiber = f, value = token})
}

@(private)
wake_local :: proc(f: ^Fiber, token: u64, reason: Wake_Reason) {
	if f.state != .Parked || f.token != token {
		return
	}
	if reason == .Cancelled && !f.cancellable {
		return
	}
	f.state = .Ready
	f.wake_reason = reason
	append(&f.loop.ready, f)
}

/*
Give the other ready fibers a turn, then carry on. For a fiber with a long run
of work and no waits in it, so the loop's other fibers are not held up behind it.
*/
yield :: proc() {
	l := tl_loop
	if l == nil || l.current == nil {
		return
	}
	f := l.current
	// Not `.Parked`: nothing may wake a fiber that is already on the ready list,
	// or it would be on it twice.
	f.state = .Yielded
	append(&l.ready, f)
	switch_to_scheduler(f)
	f.token += 1
}

/*
How many socket calls a fiber may complete in a row without waiting before it
yields.

A fiber whose socket always has the next message - a UDP reader under a flood,
an accept loop under a connection storm, a client pipelining queries the cache
answers, an upstream streaming replies - never parks, so without a yield it
would hold its loop for as long as the peer keeps sending: every other fiber on
the loop, the queries it started or is reading for included, would wait behind
it. Threads had the kernel's scheduler for this.
*/
TURN_BATCH :: 64

/*
Count one call that completed without giving up the loop, and `yield` at every
`TURN_BATCH`th in a row (`Fiber.turns`; a park or a yield starts the count
again). Every socket wrapper in this package calls it on success, and `tlsx`
does once its lock is released, so no read loop has to remember to: a loop that
forgot is how one connection starves the rest. A reader over something other
than a socket - h2's frame loops, which tests drive from memory - calls it
itself. Called holding no plain lock, as any wrapper call that may park already
must be. Off a fiber it does nothing.
*/
take_turn :: proc() {
	l := tl_loop
	if l == nil || l.current == nil {
		return
	}
	f := l.current
	f.turns += 1
	if f.turns >= TURN_BATCH {
		yield()
	}
}

/*
Sleep for `d`, or until cancelled; true when the whole of it passed.

Off a fiber, an ordinary sleep.
*/
sleep :: proc(d: time.Duration) -> bool {
	l := tl_loop
	if l == nil || l.current == nil {
		time.sleep(d)
		return true
	}
	deadline := time.tick_add(l.clock(), d)
	for {
		if park(deadline) == .Cancelled {
			return false
		}
		if time.tick_diff(l.clock(), deadline) <= 0 {
			return true
		}
	}
}

// --- Timers -------------------------------------------------------------------

/*
A binary heap of parked fibers by deadline.

A fiber is in it at most once - one park, one deadline - and leaves it when the
park ends however it ends, so the heap holds exactly the parks that could still
time out and never a backlog of stale entries for waits long since answered.
*/
@(private)
timer_less :: proc(a, b: ^Fiber) -> bool {
	return time.tick_diff(b.deadline, a.deadline) < 0
}

@(private)
timer_swap :: proc(h: []^Fiber, i, j: int) {
	h[i], h[j] = h[j], h[i]
	h[i].heap_index = i
	h[j].heap_index = j
}

@(private)
timer_up :: proc(h: []^Fiber, i: int) {
	i := i
	for i > 0 {
		parent := (i - 1) / 2
		if !timer_less(h[i], h[parent]) {
			break
		}
		timer_swap(h, i, parent)
		i = parent
	}
}

@(private)
timer_down :: proc(h: []^Fiber, i: int) {
	i := i
	for {
		smallest := i
		left, right := 2 * i + 1, 2 * i + 2
		if left < len(h) && timer_less(h[left], h[smallest]) {
			smallest = left
		}
		if right < len(h) && timer_less(h[right], h[smallest]) {
			smallest = right
		}
		if smallest == i {
			return
		}
		timer_swap(h, i, smallest)
		i = smallest
	}
}

@(private)
timer_push :: proc(l: ^Loop, f: ^Fiber) {
	append(&l.timers, f)
	f.heap_index = len(l.timers) - 1
	timer_up(l.timers[:], f.heap_index)
}

@(private)
timer_remove :: proc(l: ^Loop, f: ^Fiber) {
	i := f.heap_index
	last := len(l.timers) - 1
	if i != last {
		timer_swap(l.timers[:], i, last)
	}
	pop(&l.timers)
	f.heap_index = -1
	if i < len(l.timers) {
		timer_down(l.timers[:], i)
		timer_up(l.timers[:], i)
	}
}

// Wake every fiber whose deadline is at or before `now`.
@(private)
expire_timers :: proc(l: ^Loop, now: Tick) {
	for len(l.timers) > 0 {
		f := l.timers[0]
		if time.tick_diff(now, f.deadline) > 0 {
			return
		}
		timer_remove(l, f)
		wake_local(f, f.token, .Timeout)
	}
}

/*
Run `fn(data)` alongside the caller, which does not wait for it.

On a loop it is a fiber of the caller's own loop, so detached work - a racer, a
refresh, an upstream connection's reader - shares the caller's thread and costs
a stack rather than a thread. Off a loop - the tests, which drive the resolver
from a thread of their own - it is a thread that cleans up after itself, with
the signals `main` acts on blocked as every thread of this process has them.

False when nothing was started, and `data` is then still the caller's.
*/
go :: proc(fn: proc(data: rawptr), data: rawptr) -> bool {
	if l := tl_loop; l != nil {
		_, ok := spawn(l, fn, data)
		return ok
	}
	/*
	The job runs with the caller's context, but the thread's own bookkeeping is
	the heap's: a thread that cleans up after itself frees its `Thread` after
	`fn` has returned, which is after anything waiting on `fn` has been told it
	is done - so on the caller's allocator that free could land after the caller
	itself had finished with it, which under the test runner's tracking
	allocator is a leak reported against a test that leaked nothing.
	*/
	caller := context
	context.allocator = runtime.heap_allocator()
	return spawn_thread(data, fn, caller, self_cleanup = true) != nil
}
