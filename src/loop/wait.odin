package loop

import "base:intrinsics"
import "core:sys/linux"
import "core:time"

Events :: bit_set[Event]

Event :: enum u8 {
	In,
	Out,
}

Wait_Result :: enum u8 {
	// The descriptor may be ready, or has failed or been hung up on: either way
	// the next read or write says which, and the caller makes it.
	Ready,
	Timeout,
	Cancelled,
	// The descriptor cannot be waited on at all - not open, or not a kind epoll
	// takes.
	Failed,
}

/*
The fibers of one loop that are waiting on one descriptor, and what the loop has
asked epoll to watch for on their behalf.

Several at once is the ordinary case for a shared upstream connection - one fiber
reading replies while others wait to write - so this is a list rather than a slot,
and the interest registered is the union of what they want.
*/
@(private)
Fd_Watch :: struct {
	waiters:    [dynamic]Fd_Waiter,
	// What the one-shot registration is armed for, empty once it has fired.
	registered: linux.EPoll_Event_Set,
	// Whether epoll has been given this descriptor, armed or not. What the
	// re-arm tries first; see `watch_update`.
	added:      bool,
}

@(private)
Fd_Waiter :: struct {
	fiber:  ^Fiber,
	token:  u64,
	events: Events,
}

/*
Wait until `fd` may be read or written, as `events` asks, or until `deadline`.
The zero deadline is none.

On a fiber this parks it on the loop's epoll; anywhere else - a plain thread, a
test - it is `poll(2)` on the one descriptor, so code that waits through here
behaves the same on both and the tests that drive it from a thread of their own
still mean what they did.

Readiness is reported for errors and hang-ups too, whatever `events` asked for,
since those are what the caller's next read or write is waiting to hear.
*/
wait_fd :: proc(fd: linux.Fd, events: Events, deadline: Tick) -> Wait_Result {
	l := tl_loop
	if l == nil || l.current == nil {
		return poll_fd(fd, events, deadline)
	}
	f := l.current
	if f.cancelled {
		return .Cancelled
	}
	w := l.fds[fd]
	if w == nil {
		if n := len(l.spare_watches); n > 0 {
			w = pop(&l.spare_watches)
		} else {
			w = new(Fd_Watch, l.allocator)
			w.waiters = make([dynamic]Fd_Waiter, 0, 2, l.allocator)
		}
		l.fds[fd] = w
	}
	append(&w.waiters, Fd_Waiter{f, f.token, events})
	if !watch_update(l, fd, w) {
		watch_leave(l, fd, f)
		w.added = false
		w.registered = {}
		if len(w.waiters) == 0 {
			delete_key(&l.fds, fd)
			append(&l.spare_watches, w)
		}
		return .Failed
	}
	reason := park(deadline)
	watch_leave(l, fd, f)
	switch reason {
	case .Ready:
		return .Ready
	case .Cancelled:
		return .Cancelled
	case .Timeout, .None:
	}
	return .Timeout
}

/*
Arm the one-shot registration for what `fd`'s waiters want: one `epoll_ctl` per
wait that parks.

Armed on every wait, never trusted from the last one. The descriptor may have
been closed and its number handed out again since, and the close took the old
registration away with it; nothing else would tell the new one's waiters it was
missing. So the call is MOD while epoll has had the number, which fails with
ENOENT for a new descriptor under it and becomes an ADD, and ADD the first time,
which fails with EEXIST when it had one after all and becomes a MOD.
*/
@(private)
watch_update :: proc(l: ^Loop, fd: linux.Fd, w: ^Fd_Watch) -> bool {
	want := linux.EPoll_Event_Set{.ONESHOT}
	for waiter in w.waiters {
		if .In in waiter.events {
			want += {.IN, .RDHUP}
		}
		if .Out in waiter.events {
			want += {.OUT}
		}
	}
	ev := linux.EPoll_Event {
		events = want,
		data = {fd = fd},
	}
	op := linux.EPoll_Ctl_Opcode.MOD if w.added else .ADD
	err := linux.epoll_ctl(l.epfd, op, fd, &ev)
	if op == .MOD && err == .ENOENT {
		err = linux.epoll_ctl(l.epfd, .ADD, fd, &ev)
	} else if op == .ADD && err == .EEXIST {
		err = linux.epoll_ctl(l.epfd, .MOD, fd, &ev)
	}
	if err != .NONE {
		return false
	}
	w.added = true
	w.registered = want
	return true
}

/*
Take `f` off `fd`'s waiters. Epoll is left as it is: a registration armed for
`f` alone that fires later finds nobody to wake, and firing disarms it.
*/
@(private)
watch_leave :: proc(l: ^Loop, fd: linux.Fd, f: ^Fiber) {
	w := l.fds[fd]
	if w == nil {
		return
	}
	for i := len(w.waiters) - 1; i >= 0; i -= 1 {
		if w.waiters[i].fiber == f {
			unordered_remove(&w.waiters, i)
		}
	}
}

@(private)
dispatch_event :: proc(l: ^Loop, ev: linux.EPoll_Event) {
	fd := ev.data.fd
	if fd == l.wakefd {
		// Drained with the posts, which the loop takes next.
		return
	}
	w := l.fds[fd]
	if w == nil {
		return
	}
	// Fired, so disarmed until a wait arms it again.
	w.registered = {}
	broken := ev.events & {.ERR, .HUP} != {}
	readable := broken || ev.events & {.IN, .RDHUP} != {}
	writable := broken || .OUT in ev.events
	for i := len(w.waiters) - 1; i >= 0; i -= 1 {
		waiter := w.waiters[i]
		if (readable && .In in waiter.events) || (writable && .Out in waiter.events) {
			wake_local(waiter.fiber, waiter.token, .Ready)
			unordered_remove(&w.waiters, i)
		}
	}
	/*
	Those it did not wake - a writer on a connection whose reply just came in -
	are still parked on a registration that is not armed any more. A failure
	leaves them to their deadlines, which is where a wait that cannot be watched
	ends anyway.
	*/
	if len(w.waiters) > 0 {
		_ = watch_update(l, fd, w)
	}
}

/*
`ppoll(2)` with a timeout in milliseconds, -1 for none.

Not `core:sys/linux`'s `poll`, which on arm64 builds the `timespec` for
`ppoll` from a negative timeout by casting it to unsigned: "no timeout" becomes
a timeout of some 18 quadrillion seconds, which the kernel refuses with EINVAL,
and every wait with no deadline failed at once. A NULL `timespec` is what
`ppoll` takes for none, and `ppoll` serves both architectures.
*/
@(private)
ppoll :: proc(fds: []linux.Poll_Fd, timeout_ms: i32) -> (i32, linux.Errno) {
	ts: linux.Time_Spec
	tsp: ^linux.Time_Spec
	if timeout_ms >= 0 {
		ts = linux.Time_Spec{uint(timeout_ms / 1000), uint(timeout_ms % 1000) * 1_000_000}
		tsp = &ts
	}
	ret := intrinsics.syscall(linux.SYS_ppoll, uintptr(raw_data(fds)), uintptr(len(fds)), uintptr(tsp), 0, 0)
	if int(ret) < 0 && int(ret) > -4096 {
		return 0, linux.Errno(-int(ret))
	}
	return i32(ret), .NONE
}

/*
`wait_fd` for a thread that is not running a loop.

Retried across EINTR with what is left of the deadline, which is how a blocking
socket read with SO_RCVTIMEO behaves - the wait it replaces.
*/
@(private)
poll_fd :: proc(fd: linux.Fd, events: Events, deadline: Tick) -> Wait_Result {
	want: linux.Fd_Poll_Events
	if .In in events {
		want += {.IN, .RDHUP}
	}
	if .Out in events {
		want += {.OUT}
	}
	for {
		ms := i32(-1)
		if deadline != (Tick{}) {
			left := time.tick_diff(tick_now(), deadline)
			if left <= 0 {
				return .Timeout
			}
			ms = i32(min((left + time.Millisecond - 1) / time.Millisecond, time.Duration(max(i32))))
		}
		fds := [1]linux.Poll_Fd{{fd = fd, events = want}}
		n, err := ppoll(fds[:], ms)
		if err == .EINTR {
			continue
		}
		if err != .NONE {
			return .Failed
		}
		if n == 0 {
			// A poll that slept its whole timeout is judged against the deadline
			// rather than trusted, so a timeout rounded down cannot end the wait
			// early.
			continue
		}
		if .NVAL in fds[0].revents {
			return .Failed
		}
		return .Ready
	}
}
