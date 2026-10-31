package upstream

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:loop"

/*
The bounds on the pipelined write, held against a peer that really does stop a
writer.

A writer only waits when the peer's receive window is shut and the sender's own
buffer is full, and on loopback the kernel's defaults absorb megabytes before
either happens. Two settings make it small enough to fill: `SO_RCVBUF` on the
listener before `listen`, which the accepted socket inherits and which fixes the
window it advertises in the handshake, and `SO_SNDBUF` on the pipe's socket.
Set any later and the window is already negotiated; leave the peer reading and
it never shuts.
*/

// What the peer does with what arrives.
@(private = "file")
Stall_Mode :: enum {
	// Reads nothing, ever.
	Mute,
	// Reads nothing until `Stall_Peer.drain_at`, then everything.
	Late,
	// Reads `STALL_DRIBBLE` bytes every `STALL_DRIBBLE_EVERY` from the start,
	// for `STALL_DRIBBLE_FOR`, and nothing after: a write that never gave up
	// on it fails the test rather than hanging it.
	Dribble,
}

@(private = "file")
STALL_DRIBBLE :: 256

@(private = "file")
STALL_DRIBBLE_EVERY :: 10 * time.Millisecond

@(private = "file")
STALL_DRIBBLE_FOR :: 3 * time.Second

@(private = "file")
Stall_Peer :: struct {
	listener:  net.TCP_Socket,
	mode:      Stall_Mode,
	drain_at:  time.Duration,
	stop:      bool,
	// What the peer found waiting at `drain_at`, before it read anything.
	// Stored once, by the peer thread, and read after the join.
	standing:  int,
	received:  int,
}

@(private = "file")
stall_peer_loop :: proc(p: ^Stall_Peer) {
	client: net.TCP_Socket
	for {
		if sync.atomic_load(&p.stop) {
			return
		}
		accepted, _, aerr := net.accept_tcp(p.listener)
		if aerr == nil {
			client = accepted
			break
		}
	}
	defer net.close(client)
	_ = net.set_blocking(client, false)
	start := time.tick_now()
	buf: [65536]u8
	first := true
	for !sync.atomic_load(&p.stop) {
		switch p.mode {
		case .Mute:
			time.sleep(STALL_DRIBBLE_EVERY)
			continue
		case .Late:
			if time.tick_since(start) < p.drain_at {
				time.sleep(time.Millisecond)
				continue
			}
			n, _ := net.recv_tcp(client, buf[:])
			if first {
				p.standing = max(n, 0)
				first = false
			}
			if n > 0 {
				p.received += n
			} else {
				time.sleep(time.Millisecond)
			}
		case .Dribble:
			if time.tick_since(start) >= STALL_DRIBBLE_FOR {
				time.sleep(STALL_DRIBBLE_EVERY)
				continue
			}
			n, _ := net.recv_tcp(client, buf[:STALL_DRIBBLE])
			if n > 0 {
				p.received += n
			}
			time.sleep(STALL_DRIBBLE_EVERY)
		}
	}
}

// A loopback listener whose connections advertise a window of a few KB.
@(private = "file")
stall_listener :: proc() -> (listener: net.TCP_Socket, port: int, ok: bool) {
	fd, serr := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
	if serr != .NONE {
		return
	}
	listener = net.TCP_Socket(fd)
	// Set before `listen`, so the handshake advertises it.
	if !stall_set_buffer(listener, .RCVBUF) {
		net.close(listener)
		return
	}
	if net.bind(listener, net.Endpoint{address = net.IP4_Loopback, port = 0}) != nil ||
	   linux.listen(fd, 4) != .NONE {
		net.close(listener)
		return
	}
	// So the peer's `accept` comes back to look at `stop`.
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		return
	}
	return listener, bound.port, true
}

@(private = "file")
Stall_Rig :: struct {
	peer: Stall_Peer,
	th:   ^thread.Thread,
	u:    ^Upstream,
	c:    ^Pipe_Conn,
}

/*
A pipe to a peer that will hold a writer up. `timeout` is the connection's: the
socket's own send timeout, and the cap on `pipe_framing_deadline`.
*/
@(private = "file")
stall_rig :: proc(t: ^testing.T, r: ^Stall_Rig, mode: Stall_Mode, drain_at, timeout: time.Duration) -> bool {
	listener, port, ok := stall_listener()
	if !ok {
		testing.expectf(t, false, "cannot listen on loopback")
		return false
	}
	r.peer = Stall_Peer {
		listener = listener,
		mode     = mode,
		drain_at = drain_at,
	}
	r.th = thread.create_and_start_with_poly_data(&r.peer, stall_peer_loop)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "stalled", kind = .TCP, address = "127.0.0.1", port = port},
		8,
		timeout,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return false
	}
	r.u = u
	c, derr := dial_pipe(u, timeout, timeout)
	if derr != .None {
		testing.expectf(t, false, "cannot dial: %v", derr)
		return false
	}
	r.c = c
	if !stall_set_buffer(c.stream.socket, .SNDBUF) {
		testing.expectf(t, false, "cannot shrink the pipe's send buffer")
		return false
	}
	return true
}

/*
Shrink a socket buffer to the kernel's floor, and say whether it took.

Through `setsockopt` rather than `net.set_option`, which on this toolchain
leaves `SO_SNDBUF` at megabytes whatever it is asked for - and a buffer that
size is how earlier attempts at this test found no `send` that ever waited.
Read back for the same reason: a setting that did not take reads as a test
that passes with nothing blocked.
*/
@(private = "file")
stall_set_buffer :: proc(socket: net.TCP_Socket, option: posix.Sock_Option) -> bool {
	want: i32 = 2048
	if posix.setsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &want, posix.socklen_t(size_of(want))) != .OK {
		return false
	}
	got: i32
	size := posix.socklen_t(size_of(got))
	if posix.getsockopt(posix.FD(socket), i32(posix.SOL_SOCKET), option, &got, &size) != .OK {
		return false
	}
	// Linux doubles what it is given and holds it at a floor of a few KB.
	return got <= 16 * 1024
}

@(private = "file")
stall_rig_destroy :: proc(r: ^Stall_Rig) {
	if r.c != nil {
		_ = pipe_unref(r.c)
	}
	if r.th != nil {
		sync.atomic_store(&r.peer.stop, true)
		thread.join(r.th)
		thread.destroy(r.th)
	}
	net.close(r.peer.listener)
	if r.u != nil {
		destroy(r.u)
	}
}

/*
Fill the pipe until nothing more goes in, behind the pipe's back: the peer
reads none of it, so the framing it breaks is never looked at. Returns whether
the pipe ended up full - the premise of every test that calls it.

Full means full for a write of any size, so it ends a byte at a time: the tail
of the send queue takes a small write while it has room, which a pass in 4 KB
pieces leaves behind. And full means staying full, so it is only believed
after several quiet passes some way apart - segments in flight when a pass
stopped are acknowledged a delayed ACK later and free room behind them.
*/
@(private = "file")
stall_fill :: proc(c: ^Pipe_Conn) -> bool {
	junk: [4096]u8
	quiet := 0
	for _ in 0 ..< 200 {
		total := 0
		for size in ([]int{len(junk), 1}) {
			for {
				n, err := net.send_tcp(c.stream.socket, junk[:size])
				total += n
				if err != nil {
					break
				}
			}
		}
		quiet = quiet + 1 if total == 0 else 0
		if quiet == 4 {
			return true
		}
		time.sleep(50 * time.Millisecond)
	}
	return false
}

// A message the length prefix can just about count, so a few KB of window
// takes some of it and not all.
@(private = "file")
STALL_QUERY_SIZE :: 60000

/*
A write that cannot start is bounded by the caller's deadline, not the
connection's.

The socket's `SO_SNDTIMEO` is the connection's figure from the dial, and one
blocked `send` honours exactly that. So the loop has to tell the socket what
this caller has left before every send, or a caller with a fraction of a second
to go waits out the connection's whole timeout. And because nothing went out,
the connection is still in frame and stays up.
*/
@(test)
test_a_write_that_cannot_start_ends_on_the_callers_deadline :: proc(t: ^testing.T) {
	TIMEOUT :: 5 * time.Second
	BUDGET :: 200 * time.Millisecond
	r: Stall_Rig
	defer stall_rig_destroy(&r)
	if !stall_rig(t, &r, .Mute, 0, TIMEOUT) {
		return
	}
	if !testing.expectf(t, stall_fill(r.c), "the peer's window never shut, so nothing here can block") {
		return
	}

	query: [64]u8
	start := time.tick_now()
	werr := pipe_write(r.c, query[:], time.tick_add(start, BUDGET))
	took := time.tick_since(start)
	_, dead := pipe_dead(r.c)

	testing.expectf(t, werr == .Timeout, "a write into a shut window reported %v", werr)
	testing.expectf(t, took >= BUDGET - 20 * time.Millisecond, "the write gave up after %v, before its budget of %v", took, BUDGET)
	testing.expectf(t, took < BUDGET + 500 * time.Millisecond, "a write with a budget of %v held on for %v", BUDGET, took)
	testing.expectf(t, !dead, "a write that put nothing on the wire took the connection down")
}

/*
Once bytes are on the wire, the write is finished on the framing budget rather
than the caller's.

Half a message on the stream leaves it unreadable for everybody, so a caller
that has started a message owes the connection the rest of it - the same rule
`pipe_read_one` follows. Here the caller's deadline passes with part of the
message away and the peer catching up only later; the write must see it
through, and leave the connection standing.
*/
@(test)
test_a_started_write_is_finished_past_the_callers_deadline :: proc(t: ^testing.T) {
	TIMEOUT :: 5 * time.Second
	BUDGET :: 100 * time.Millisecond
	DRAIN_AT :: 400 * time.Millisecond
	r: Stall_Rig
	defer stall_rig_destroy(&r)
	if !stall_rig(t, &r, .Late, DRAIN_AT, TIMEOUT) {
		return
	}

	query := make([]u8, STALL_QUERY_SIZE)
	defer delete(query)
	start := time.tick_now()
	werr := pipe_write(r.c, query, time.tick_add(start, BUDGET))
	took := time.tick_since(start)
	_, dead := pipe_dead(r.c)
	// Past the drain whatever the write did, so the peer has looked.
	time.sleep(DRAIN_AT + 200 * time.Millisecond - time.tick_since(start))
	sync.atomic_store(&r.peer.stop, true)
	thread.join(r.th)
	thread.destroy(r.th)
	r.th = nil

	// The premise: when the caller's budget ran out, part of the message was
	// out and part was not. What the peer found waiting when it started reading
	// is the part that was out.
	testing.expectf(
		t,
		r.peer.standing > 0 && r.peer.standing < 2 + STALL_QUERY_SIZE,
		"the peer found %v bytes waiting, so the write was not standing half done",
		r.peer.standing,
	)
	testing.expectf(t, werr == .None, "a write that had started gave up with %v", werr)
	testing.expectf(t, took >= DRAIN_AT, "the write finished after %v, before the peer read anything", took)
	testing.expectf(t, !dead, "a write that went through took the connection down")
	testing.expectf(t, r.peer.received == 2 + STALL_QUERY_SIZE, "the peer received %v of %v bytes", r.peer.received, 2 + STALL_QUERY_SIZE)
}

/*
A peer that takes a few bytes at a time cannot keep the write going.

Each of its reads opens the window a little and lets one more `send` through,
so a bound that restarted on progress would never fire. The framing budget
runs from the first byte away and covers the whole message; when it is gone the
message is half written, and the connection with it.
*/
@(test)
test_a_dribbling_peer_cannot_hold_a_write_past_the_framing_budget :: proc(t: ^testing.T) {
	// The connection's timeout caps the framing budget; above the grace, so
	// the grace is what applies.
	TIMEOUT :: 5 * time.Second
	BUDGET :: 100 * time.Millisecond
	r: Stall_Rig
	defer stall_rig_destroy(&r)
	if !stall_rig(t, &r, .Dribble, 0, TIMEOUT) {
		return
	}

	query := make([]u8, STALL_QUERY_SIZE)
	defer delete(query)
	start := time.tick_now()
	werr := pipe_write(r.c, query, time.tick_add(start, BUDGET))
	took := time.tick_since(start)
	werr_dead, dead := pipe_dead(r.c)
	sync.atomic_store(&r.peer.stop, true)
	thread.join(r.th)
	thread.destroy(r.th)
	r.th = nil

	// The premise: the peer kept taking bytes for longer than the budget, so a
	// bound that restarted on progress would have had no end inside it.
	testing.expectf(
		t,
		r.peer.received > 0 && r.peer.received < 2 + STALL_QUERY_SIZE,
		"the peer took %v of %v bytes, so it was not dribbling",
		r.peer.received,
		2 + STALL_QUERY_SIZE,
	)
	testing.expectf(t, werr == .Timeout, "a write to a dribbling peer reported %v", werr)
	testing.expectf(t, took >= PIPE_FRAMING_GRACE - 20 * time.Millisecond, "a started write gave up after %v, inside the grace", took)
	testing.expectf(t, took < PIPE_FRAMING_GRACE + 500 * time.Millisecond, "a dribbling peer held the write for %v", took)
	testing.expectf(t, dead && werr_dead == .Timeout, "a message left half written did not take the connection down (%v)", werr_dead)
}

/*
Writers queued behind a blocked one are each back on their own deadline.

`wmu` lets one message onto the wire at a time, so while the first writer waits
on a shut window every other waits for it. What keeps that bounded is that the
first gives up on its own deadline with nothing sent, and each after it finds
its own budget gone or nearly so. Measured here because the queue is otherwise
only an argument in a comment.
*/
@(test)
test_writers_queued_behind_a_blocked_one_keep_their_deadlines :: proc(t: ^testing.T) {
	TIMEOUT :: 5 * time.Second
	BUDGET :: 200 * time.Millisecond
	WRITERS :: 4
	r: Stall_Rig
	defer stall_rig_destroy(&r)
	if !stall_rig(t, &r, .Mute, 0, TIMEOUT) {
		return
	}
	if !testing.expectf(t, stall_fill(r.c), "the peer's window never shut, so nothing here can block") {
		return
	}

	Writer :: struct {
		c:        ^Pipe_Conn,
		deadline: time.Tick,
		err:      Error,
		done:     time.Tick,
	}
	start := time.tick_now()
	writers: [WRITERS]Writer
	threads: [WRITERS]^thread.Thread
	for &w, i in writers {
		w = {c = r.c, deadline = time.tick_add(start, BUDGET)}
		threads[i] = thread.create_and_start_with_poly_data(&w, proc(w: ^Writer) {
			query: [64]u8
			w.err = pipe_write(w.c, query[:], w.deadline)
			w.done = time.tick_now()
		})
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	_, dead := pipe_dead(r.c)

	for w, i in writers {
		took := time.tick_diff(start, w.done)
		testing.expectf(t, w.err == .Timeout, "writer %v reported %v", i, w.err)
		testing.expectf(t, took < BUDGET + 500 * time.Millisecond, "writer %v with a budget of %v was held %v", i, BUDGET, took)
	}
	testing.expectf(t, !dead, "writes that put nothing on the wire took the connection down")
}

/*
A cancelled writer partway through a message gives up, rather than spinning.

At shutdown the loops cancel what is left on them, a race's losers among them,
and a cancelled fiber's every wait ends at once. A write that goes round again
after a send that timed out would, cancelled, never park: each send would come
straight back and the loop would spin until the framing budget ran out - ten
seconds here - with nothing able to stop it. And the message is half written,
so the connection goes with it.
*/
@(test)
test_a_cancelled_writer_does_not_spin_on_its_loop :: proc(t: ^testing.T) {
	TIMEOUT :: 10 * time.Second
	r: Stall_Rig
	defer stall_rig_destroy(&r)
	if !stall_rig(t, &r, .Mute, 0, TIMEOUT) {
		return
	}

	l, made := loop.make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	th := loop.spawn_thread(l, loop.run, context)
	Write :: struct {
		c:     ^Pipe_Conn,
		query: []u8,
		err:   Error,
	}
	w := Write {
		c     = r.c,
		query = make([]u8, STALL_QUERY_SIZE),
	}
	defer delete(w.query)
	_, _ = loop.spawn(l, proc(data: rawptr) {
		w := (^Write)(data)
		w.err = pipe_write(w.c, w.query, time.tick_add(time.tick_now(), TIMEOUT))
	}, &w)

	// The premise: part of the message is queued on the socket and the rest
	// is not, so the writer is parked partway through it.
	queued := 0
	for start := time.tick_now(); queued == 0 && time.tick_since(start) < 5 * time.Second; {
		time.sleep(time.Millisecond)
		queued = stall_queued(r.c)
	}
	testing.expectf(t, queued > 0 && queued < 2 + STALL_QUERY_SIZE, "%v bytes queued: the writer is not partway through", queued)

	Stopper :: struct {
		l:    ^loop.Loop,
		th:   ^thread.Thread,
		done: sync.Sema,
	}
	stopper := Stopper {
		l  = l,
		th = th,
	}
	waiter := thread.create_and_start_with_poly_data(&stopper, proc(s: ^Stopper) {
		loop.stop(s.l)
		loop.cancel_all(s.l)
		thread.join(s.th)
		sync.sema_post(&s.done)
	})
	// Well short of the ten seconds, and well past what a loop with nothing to
	// spin on takes to stop.
	stopped := sync.sema_wait_with_timeout(&stopper.done, 3 * time.Second)
	testing.expect(t, stopped, "the loop did not stop: the cancelled writer is still sending")
	if !stopped {
		_ = sync.sema_wait_with_timeout(&stopper.done, 15 * time.Second)
	}
	thread.join(waiter)
	thread.destroy(waiter)
	thread.destroy(th)
	loop.destroy(l)
	werr, dead := pipe_dead(r.c)
	testing.expectf(t, w.err == .Timeout, "the cancelled writer ended as %v, expected a timeout", w.err)
	testing.expectf(t, dead && werr == .Timeout, "a message left half written did not take the connection down (%v)", werr)
}

// What the pipe's socket holds that the peer has not acknowledged: `SIOCOUTQ`.
@(private = "file")
stall_queued :: proc(c: ^Pipe_Conn) -> int {
	SIOCOUTQ :: 0x5411
	n: i32
	if i32(linux.ioctl(linux.Fd(c.stream.socket), SIOCOUTQ, uintptr(&n))) < 0 {
		return 0
	}
	return int(n)
}
