package loop

import "core:sync"
import "core:time"

/*
Waiting on another fiber or thread, without blocking a loop.

`core:sync`'s primitives put the calling thread to sleep, and on a loop thread
that is every fiber on it asleep - and if the fiber that would have woken it is
one of them, asleep for good. These do the same job by parking the fiber instead,
and off a fiber they are the thread blocking the ordinary way, so a structure
shared between loop fibers and a plain thread (the maintenance loop, the blocklist
rebuild, a test) is waited on through one set of calls.

All three share `Waiter`: a node on the waiting party's own stack, linked into
the primitive's list under the primitive's lock. Whoever wakes it does so while
still holding that lock, and the waiter takes the lock again before it returns -
so a waker never touches a node whose frame has already been left, which is the
whole reason a node can live on a stack.
*/
@(private)
Waiter :: struct {
	next, prev: ^Waiter,
	// The fiber and the park it is in; nil for a plain thread, which waits on `sema`.
	fiber:      ^Fiber,
	token:      u64,
	sema:       sync.Sema,
	// Set by the waker, under the primitive's lock, before it wakes.
	signalled:  bool,
}

@(private)
Waiter_List :: struct {
	head, tail: ^Waiter,
}

@(private)
list_push :: proc(list: ^Waiter_List, w: ^Waiter) {
	w.next = nil
	w.prev = list.tail
	if list.tail != nil {
		list.tail.next = w
	} else {
		list.head = w
	}
	list.tail = w
}

@(private)
list_push_front :: proc(list: ^Waiter_List, w: ^Waiter) {
	w.prev = nil
	w.next = list.head
	if list.head != nil {
		list.head.prev = w
	} else {
		list.tail = w
	}
	list.head = w
}

@(private)
list_remove :: proc(list: ^Waiter_List, w: ^Waiter) {
	if w.prev != nil {
		w.prev.next = w.next
	} else {
		list.head = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else {
		list.tail = w.prev
	}
	w.next, w.prev = nil, nil
}

@(private)
list_pop :: proc(list: ^Waiter_List) -> ^Waiter {
	w := list.head
	if w != nil {
		list_remove(list, w)
	}
	return w
}

// A waiter for the calling fiber or thread.
@(private)
waiter_init :: proc(w: ^Waiter) {
	if f := current(); f != nil {
		w.fiber = f
		w.token = f.token
	}
}

// Wake `w`. Under the lock of the list it was taken off.
@(private)
waiter_wake :: proc(w: ^Waiter) {
	w.signalled = true
	if w.fiber != nil {
		wake(w.fiber, w.token)
	} else {
		sync.sema_post(&w.sema)
	}
}

/*
Wait for `w` to be woken, with `lock` released meanwhile and held again on the
way out. False when the deadline passed or the fiber was cancelled first; the
waiter is then still on whatever list it was put on, for the caller to take off
under the lock it now holds.
*/
@(private)
waiter_block :: proc(w: ^Waiter, lock: ^sync.Mutex, deadline: Tick, cancellable: bool) -> bool {
	for {
		sync.mutex_unlock(lock)
		if w.fiber != nil {
			reason := park(deadline, cancellable)
			sync.mutex_lock(lock)
			if w.signalled {
				return true
			}
			if reason == .Timeout || reason == .Cancelled {
				return false
			}
			// A stale wake: the token moved on with this park, so take the next.
			w.token = w.fiber.token
			continue
		}
		if deadline == (Tick{}) {
			sync.sema_wait(&w.sema)
		} else {
			left := time.tick_diff(time.tick_now(), deadline)
			if left > 0 {
				_ = sync.sema_wait_with_timeout(&w.sema, left)
			}
		}
		sync.mutex_lock(lock)
		if w.signalled {
			return true
		}
		if deadline != (Tick{}) && time.tick_diff(time.tick_now(), deadline) <= 0 {
			return false
		}
	}
}

// --- Mutex -----------------------------------------------------------------------

/*
A lock that may be held across a wait.

For the few structures whose lock is held while the holder waits on the network:
an h2 connection serialising its frames onto the socket, a pipelined upstream
connection's writer. A `sync.Mutex` there is a deadlock on a loop - the holder
parks, the next fiber on the same thread asks for the lock and blocks the thread,
and the holder never runs again to let it go. This one parks the second fiber
instead.

Released, not handed over: an unlock with somebody waiting frees the lock and
wakes the first waiter, which takes it if it is still free when it runs. Handed
over directly, the lock would stay owned by a waiter on another loop until that
loop got round to the wake - a whole round of its other fibers - with every
fiber that wants it, the holder's own loop's included, queued behind an owner
that is not running: on a connection shared by every loop, a convoy. Order is
kept all the same: a woken waiter that finds the lock taken again goes back to
the head of the queue, not the tail, so the waiters are served in turn and a
fiber that keeps taking and releasing it can delay the first of them but not
pass it in the queue.

Not cancellable: a lock wait always ends with the lock held. A `sync.Mutex` is
still the right lock for anything held only across code that does not wait,
which is nearly every lock in the server.
*/
Mutex :: struct {
	mu:      sync.Mutex,
	locked:  bool,
	waiters: Waiter_List,
}

lock :: proc(m: ^Mutex) {
	sync.mutex_lock(&m.mu)
	if !m.locked {
		m.locked = true
		sync.mutex_unlock(&m.mu)
		return
	}
	w: Waiter
	waiter_init(&w)
	list_push(&m.waiters, &w)
	for {
		// Ended only by `unlock`, which sets `signalled`.
		for !waiter_block(&w, &m.mu, {}, false) {
		}
		if !m.locked {
			m.locked = true
			sync.mutex_unlock(&m.mu)
			return
		}
		// Taken in between by somebody not queued: first in line again.
		w.signalled = false
		waiter_init(&w)
		list_push_front(&m.waiters, &w)
	}
}

unlock :: proc(m: ^Mutex) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	assert(m.locked, "unlocking a loop.Mutex nobody holds")
	m.locked = false
	if w := list_pop(&m.waiters); w != nil {
		waiter_wake(w)
	}
}

// --- Cond ------------------------------------------------------------------------

/*
A condition variable for a fiber or a thread, used with either kind of lock.

As with `sync.Cond`, a wake may be spurious and every caller waits in a loop that
re-checks its condition.

Not cancellable, as `Mutex` is not: every caller waits in such a loop, bounded by
a deadline of its own or by the fiber that will signal it, so a cancelled wait
that returned at once would only be made again - a spin that never parks, holding
the loop thread and with it the fiber that would have signalled.
*/
Cond :: struct {
	mu:      sync.Mutex,
	waiters: Waiter_List,
}

cond_wait :: proc {
	cond_wait_sync,
	cond_wait_loop,
}

cond_wait_with_timeout :: proc {
	cond_wait_with_timeout_sync,
	cond_wait_with_timeout_loop,
}

cond_wait_sync :: proc(c: ^Cond, m: ^sync.Mutex) {
	_ = cond_wait_until(c, m, nil, {})
}

cond_wait_loop :: proc(c: ^Cond, m: ^Mutex) {
	_ = cond_wait_until(c, nil, m, {})
}

// False when `d` passed before a signal arrived.
cond_wait_with_timeout_sync :: proc(c: ^Cond, m: ^sync.Mutex, d: time.Duration) -> bool {
	if d <= 0 {
		return false
	}
	return cond_wait_until(c, m, nil, time.tick_add(time.tick_now(), d))
}

cond_wait_with_timeout_loop :: proc(c: ^Cond, m: ^Mutex, d: time.Duration) -> bool {
	if d <= 0 {
		return false
	}
	return cond_wait_until(c, nil, m, time.tick_add(time.tick_now(), d))
}

/*
The wait behind all four: sign up under the cond's own lock, let the caller's lock
go, wait, and take it back.

Signing up before the caller's lock is released is what makes a signal sent by
anyone who takes that lock after us reach us, the same guarantee `sync.Cond`
gives.
*/
@(private)
cond_wait_until :: proc(c: ^Cond, sm: ^sync.Mutex, lm: ^Mutex, deadline: Tick) -> bool {
	w: Waiter
	waiter_init(&w)
	sync.mutex_lock(&c.mu)
	list_push(&c.waiters, &w)
	if sm != nil {
		sync.mutex_unlock(sm)
	} else {
		unlock(lm)
	}
	woken := waiter_block(&w, &c.mu, deadline, false)
	if !woken {
		list_remove(&c.waiters, &w)
	}
	sync.mutex_unlock(&c.mu)
	if sm != nil {
		sync.mutex_lock(sm)
	} else {
		lock(lm)
	}
	return woken
}

cond_signal :: proc(c: ^Cond) {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	if w := list_pop(&c.waiters); w != nil {
		waiter_wake(w)
	}
}

cond_broadcast :: proc(c: ^Cond) {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	for w := list_pop(&c.waiters); w != nil; w = list_pop(&c.waiters) {
		waiter_wake(w)
	}
}

// --- Sema ------------------------------------------------------------------------

// A counting semaphore for a fiber or a thread.
Sema :: struct {
	mu:      sync.Mutex,
	count:   int,
	waiters: Waiter_List,
}

sema_post :: proc(s: ^Sema, n := 1) {
	sync.mutex_lock(&s.mu)
	defer sync.mutex_unlock(&s.mu)
	s.count += n
	for s.count > 0 {
		w := list_pop(&s.waiters)
		if w == nil {
			return
		}
		// Taken on the waiter's behalf, so a post cannot be counted twice by a
		// waiter woken and a caller arriving at the same moment.
		s.count -= 1
		waiter_wake(w)
	}
}

sema_wait :: proc(s: ^Sema) {
	_ = sema_wait_until(s, {})
}

// False when `d` passed, or the fiber was cancelled, before a post was taken.
sema_wait_with_timeout :: proc(s: ^Sema, d: time.Duration) -> bool {
	return sema_wait_until(s, time.tick_add(time.tick_now(), max(d, 0)))
}

@(private)
sema_wait_until :: proc(s: ^Sema, deadline: Tick) -> bool {
	sync.mutex_lock(&s.mu)
	defer sync.mutex_unlock(&s.mu)
	if s.count > 0 {
		s.count -= 1
		return true
	}
	if deadline != (Tick{}) && time.tick_diff(time.tick_now(), deadline) <= 0 {
		return false
	}
	w: Waiter
	waiter_init(&w)
	list_push(&s.waiters, &w)
	if waiter_block(&w, &s.mu, deadline, true) {
		return true
	}
	list_remove(&s.waiters, &w)
	return false
}
