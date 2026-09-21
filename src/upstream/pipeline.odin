package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
Query pipelining for the stream transports, RFC 7766 section 6.2.

Before this, `tcp://` and `tls://` wrote one query and blocked reading its
reply, so the connection was unavailable to anyone else until that returned and
N concurrent queries cost N connections. Section 6.2.1.1 asks for the opposite
- a client SHOULD NOT wait for an outstanding reply before sending the next
query - and section 6.2.2 makes the consequence a MUST: no more than one
connection for regular queries. It matters in practice as well as on paper. A
resolver that rate-limits *new* connections (Quad9 measurably does) refuses a
share of them while answering perfectly well on one already established, so the
connection churn was itself the failure.

The shape is the DoH one, arrived at through the DNS message ID rather than an
HTTP/2 stream ID. One connection per upstream is held and shared; every caller
puts its query on it and blocks on its own reply; replies are matched back to
their caller by ID, in whatever order they arrive - section 7 recommends
servers answer out of order, so nothing here may assume FIFO.

What reads the socket is the difference from `h2client.odin`, and it is the
laziness this file is worth: there is no reader thread. Whichever caller finds
nobody reading does the reading, for everyone, until its own reply turns up;
the others wait on `cond`. A connection with nothing outstanding therefore has
nobody blocked on it and needs no poll interval, no stopping flag and no thread
to join - the whole of `H2_Conn`'s lifecycle problem does not arise.

Two things are kept from the code this replaces. A pooled connection found dead
is retried once on a fresh one, which is what makes an upstream closing an idle
connection invisible rather than a failure. And `exchange`'s contract that the
caller owns the transaction ID still holds: the ID on the wire is this
connection's, since two queries in flight on one connection cannot share one,
and the caller's is put back on the answer before it is returned.
*/

/*
How many queries may be outstanding on one connection at once.

Not a throughput limit - a connection carrying 64 unanswered queries is one
whose server has stopped answering, and the figure bounds what that costs
rather than what a working one may do. At the bound a caller opens a private
connection for its query instead of queueing behind them, so a stalled upstream
slows callers down without shutting them out.

Sized against the worker pools rather than at random: `upstream_workers` is
what can be in `exchange` at once per upstream, and a default configuration
sizes it well under this.
*/
PIPELINE_MAX_OUTSTANDING :: 64

@(private)
Pipe_Waiter :: struct {
	/*
	The query as it went out, under the ID this connection gave it.

	Read by whichever caller is reading the socket, which is not the caller
	that owns these bytes and may not be on this thread's arena. Safe because
	it is only ever reached through `Pipe_Conn.waiters` under `Pipe_Conn.mu`,
	and a caller takes itself out of that map before it returns.
	*/
	query: []u8,
	// From the connection's allocator, so the reader can allocate it without
	// knowing whose arena it is for. The waiter copies it out and frees it.
	reply: []u8,
	done:  bool,
	err:   Error,
}

@(private)
Pipe_Conn :: struct {
	stream:    Stream,
	// Held for the whole of one message going out, so two queries written at
	// once cannot interleave their bytes on the wire.
	wmu:       sync.Mutex,

	mu:        sync.Mutex,
	cond:      sync.Cond,
	waiters:   map[u16]^Pipe_Waiter,
	// Whether some caller is reading the socket on everyone's behalf.
	reading:   bool,
	// Set once the connection cannot carry another query; `err` is what to
	// tell the callers still on it.
	dead:      bool,
	err:       Error,
	next_id:   u16,
	// When the last query on this connection finished, for the idle reaper.
	last:      time.Time,

	refs:      int,
	allocator: mem.Allocator,
}

// Whether the shared connection can take this caller's query.
@(private)
Pipe_State :: enum u8 {
	// Ready for another query.
	Ready,
	// Alive, but already carrying `PIPELINE_MAX_OUTSTANDING`.
	Full,
	// Dead, or idle for longer than the upstream's idle timeout.
	Gone,
}

@(private)
pipe_ref :: proc(c: ^Pipe_Conn) {
	sync.atomic_add(&c.refs, 1)
}

/*
Drop one reference, tearing the connection down at the last.

Nobody is reading or writing it by then, which is what makes closing the socket
here safe: on Linux a close does not interrupt a read already blocked on the
socket, and the reference every caller holds for the length of its query is
what guarantees there is no such read.
*/
@(private)
pipe_unref :: proc(c: ^Pipe_Conn) {
	if c == nil || sync.atomic_sub(&c.refs, 1) != 1 {
		return
	}
	stream_close(&c.stream)
	delete(c.waiters)
	free(c, c.allocator)
}

@(private)
pipe_state :: proc(c: ^Pipe_Conn, idle_timeout: time.Duration) -> Pipe_State {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	if c.dead {
		return .Gone
	}
	if len(c.waiters) == 0 && time.diff(c.last, time.now()) >= idle_timeout {
		return .Gone
	}
	if len(c.waiters) >= PIPELINE_MAX_OUTSTANDING {
		return .Full
	}
	return .Ready
}

@(private)
pipe_dead :: proc(c: ^Pipe_Conn) -> bool {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return c.dead
}

// Kill the connection and everyone still waiting on it. Called with `c.mu`.
@(private)
pipe_kill :: proc(c: ^Pipe_Conn, err: Error) {
	if c.dead {
		return
	}
	c.dead = true
	c.err = err
}

@(private)
dial_pipe :: proc(u: ^Upstream, timeout: time.Duration) -> (c: ^Pipe_Conn, err: Error) {
	stream: Stream
	if u.spec.kind == .TLS {
		stream = open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, timeout, u) or_return
	} else {
		socket, derr := dial_tcp_timeout(u.endpoint, timeout)
		if derr != .None {
			return nil, derr
		}
		set_socket_timeouts(socket, timeout)
		_ = net.set_option(socket, .TCP_Nodelay, true)
		stream = Stream {
			socket = socket,
		}
	}

	c = new(Pipe_Conn, u.allocator)
	c.stream = stream
	c.allocator = u.allocator
	c.refs = 1
	// Drawn rather than started at zero: the first ID on a fresh connection is
	// the one an off-path attacker would have the easiest time guessing, and
	// `tcp://` upstreams are the ones with nothing else authenticating the
	// peer. From there it counts, since on one connection what matters is only
	// that two queries in flight differ.
	c.next_id = dns.random_id()
	c.waiters = make(map[u16]^Pipe_Waiter, 16, u.allocator)
	c.last = time.now()
	return c, .None
}

/*
The shared connection for `u`, dialling one if there is none or the last died.

Only one caller dials at a time, for the reason `get_h2_conn` gives: a burst of
concurrent first queries shares one handshake rather than each opening - and
all but one of them discarding - a connection of its own. Which is the whole
point here, so the losers wait on `u.conn_cond` and pick up the winner's.

`fresh` says this caller's query is the first on the connection, so a failure
on it is the upstream's and not a pooled connection going stale.
*/
@(private)
get_pipe :: proc(u: ^Upstream, timeout: time.Duration) -> (c: ^Pipe_Conn, fresh: bool, err: Error) {
	sync.mutex_lock(&u.mu)
	for {
		if u.pipe != nil {
			switch pipe_state(u.pipe, u.idle_timeout) {
			case .Ready:
				c = u.pipe
				pipe_ref(c)
				sync.mutex_unlock(&u.mu)
				return c, false, .None
			case .Full:
				// A connection of this caller's own, left out of `u.pipe` so
				// it is closed again the moment this query is done with it.
				// The shared one stays where it is for everyone else.
				sync.mutex_unlock(&u.mu)
				c, err = dial_pipe(u, timeout)
				return c, true, err
			case .Gone:
			}
		}
		if !u.connecting {
			break
		}
		sync.cond_wait(&u.conn_cond, &u.mu)
	}

	u.connecting = true
	stale := u.pipe
	u.pipe = nil
	sync.mutex_unlock(&u.mu)
	// Only the upstream's own reference; a caller still on that connection
	// holds its own and tears it down when it is finished with it.
	pipe_unref(stale)

	dialled, derr := dial_pipe(u, timeout)

	sync.mutex_lock(&u.mu)
	u.connecting = false
	if derr != .None {
		sync.cond_broadcast(&u.conn_cond)
		sync.mutex_unlock(&u.mu)
		return nil, true, derr
	}
	// This caller's, on top of the upstream's.
	pipe_ref(dialled)
	u.pipe = dialled
	sync.cond_broadcast(&u.conn_cond)
	sync.mutex_unlock(&u.mu)
	return dialled, true, .None
}

/*
One query over a pipelined connection: TCP, DoT, and a UDP upstream's retry of
an answer that would not fit a datagram.

The retry is the one the pooled TCP path used to make, narrowed to the case it was
written for. A resolver closes connections its client has left idle, so a
shared one is quite normally dead by the time a query lands on it; that is not
an upstream failure and must not be reported as one, since a handful of them
would trip the health cooldown and bench a working server. Anything else - a
timeout, a reply that did not check out - leaves the connection alone, because
it is now everyone's: tearing it down over one slow query would take every
other query in flight with it.
*/
@(private)
exchange_pipelined :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	c, fresh, gerr := get_pipe(u, timeout)
	if gerr != .None {
		return nil, gerr
	}
	response, err = pipe_query(u, c, query, timeout, allocator)
	if err == .None || fresh || !pipe_dead(c) {
		pipe_unref(c)
		return response, err
	}

	// Held until the redial is done, so `get_pipe` sees the dead connection it
	// has to replace rather than an address something else has since reused.
	retry, _, rerr := get_pipe(u, timeout)
	pipe_unref(c)
	if rerr != .None {
		return nil, rerr
	}
	response, err = pipe_query(u, retry, query, timeout, allocator)
	pipe_unref(retry)
	return response, err
}

@(private)
pipe_query :: proc(
	u: ^Upstream,
	c: ^Pipe_Conn,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	if len(query) > 0xffff {
		return nil, .Too_Large
	}
	if len(query) < dns.HEADER_SIZE {
		return nil, .Bad_Response
	}

	// Scratch, on this caller's own arena: the bytes only have to outlive the
	// exchange, and the reader reaches them through the waiter.
	asked := make([]u8, len(query), context.temp_allocator)
	copy(asked, query)
	w := Pipe_Waiter {
		query = asked,
	}

	sync.mutex_lock(&c.mu)
	if c.dead {
		err = c.err
		sync.mutex_unlock(&c.mu)
		return nil, err
	}
	id, taken := pipe_take_id(c)
	if !taken {
		sync.mutex_unlock(&c.mu)
		return nil, .IO_Error
	}
	dns.set_id_in_place(asked, id)
	c.waiters[id] = &w
	sync.mutex_unlock(&c.mu)

	deadline := time.time_add(time.now(), timeout)

	if werr := pipe_write(c, asked); werr != .None {
		sync.mutex_lock(&c.mu)
		delete_key(&c.waiters, id)
		// A half-written query leaves the stream out of frame, so the
		// connection goes with it rather than carrying anyone else's query.
		pipe_kill(c, werr)
		sync.cond_broadcast(&c.cond)
		sync.mutex_unlock(&c.mu)
		return nil, werr
	}

	if werr := pipe_wait(c, &w, id, deadline); werr != .None {
		return nil, werr
	}

	reply := w.reply
	defer delete(reply, c.allocator)
	// `response_matches` was applied by whoever read this off the wire, which
	// is what made it this caller's; the cookie needs the upstream's state and
	// is checked here, where `u.mu` is safe to take.
	if !response_accepted(u, asked, reply) {
		return nil, .Bad_Response
	}
	response = make([]u8, len(reply), allocator)
	copy(response, reply)
	dns.set_id_in_place(response, u16(query[0]) << 8 | u16(query[1]))
	return response, .None
}

// An ID nothing else on this connection is waiting on. Called with `c.mu`.
@(private)
pipe_take_id :: proc(c: ^Pipe_Conn) -> (id: u16, ok: bool) {
	// Counting rather than drawing each one: what matters on a connection is
	// that two queries in flight differ, and counting also puts the longest
	// possible distance between an ID being retired and being used again - so
	// a reply that arrives after its caller gave up cannot be taken for a
	// later query's. The question check would refuse it anyway.
	for _ in 0 ..< 1 << 16 {
		id = c.next_id
		c.next_id += 1
		if id not_in c.waiters {
			return id, true
		}
	}
	// Unreachable under PIPELINE_MAX_OUTSTANDING, which is four orders of
	// magnitude below the number of IDs.
	return 0, false
}

/*
Wait for this caller's reply, reading the socket for everyone if nobody is.

The caller that finds `reading` clear takes it, reads one message off the wire,
hands it to whichever waiter it belongs to and goes round again - so the thread
doing the reading is always one that is waiting anyway, and a connection with
nothing outstanding has nobody on it. Every other waiter parks on `cond` until
its own reply lands, the connection dies, or its own deadline passes, whichever
comes first.
*/
@(private)
pipe_wait :: proc(c: ^Pipe_Conn, w: ^Pipe_Waiter, id: u16, deadline: time.Time) -> Error {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	for {
		// Ahead of `dead`: a reply that landed before the connection went is
		// still this caller's answer.
		if w.done {
			c.last = time.now()
			return w.err
		}
		if c.dead {
			delete_key(&c.waiters, id)
			return c.err
		}
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			delete_key(&c.waiters, id)
			c.last = time.now()
			return .Timeout
		}
		if c.reading {
			sync.cond_wait_with_timeout(&c.cond, &c.mu, remaining)
			continue
		}

		c.reading = true
		sync.mutex_unlock(&c.mu)
		rerr := pipe_read_one(c, remaining)
		sync.mutex_lock(&c.mu)
		c.reading = false
		// A read that only ran out of time consumed nothing, so the connection
		// is still in frame and this is one caller's timeout rather than
		// everybody's failure. Anything else lost the framing with it.
		if rerr != .None && rerr != .Timeout {
			pipe_kill(c, rerr)
		}
		sync.cond_broadcast(&c.cond)
	}
}

/*
Read one reply off the wire and hand it to its waiter.

`.Timeout` means nothing arrived and nothing was consumed, so the connection is
untouched. Every other error means the stream can no longer be read as a
sequence of messages and the connection is finished.
*/
@(private)
pipe_read_one :: proc(c: ^Pipe_Conn, budget: time.Duration) -> Error {
	pipe_set_read_timeout(c, budget)

	length_buf: [2]u8
	n, rerr := pipe_read_full(c, length_buf[:])
	if rerr != .None {
		if rerr == .Timeout && n == 0 {
			return .Timeout
		}
		return .IO_Error if rerr == .Timeout else rerr
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE {
		return .Bad_Response
	}

	// The connection's allocator rather than any caller's: this is read before
	// it is known whose it is, and the waiter it goes to may be on a thread
	// whose arena this one has no business allocating from.
	msg := make([]u8, length, c.allocator)
	if _, merr := pipe_read_full(c, msg); merr != .None {
		delete(msg, c.allocator)
		return .IO_Error if merr == .Timeout else merr
	}
	pipe_deliver(c, msg)
	return .None
}

@(private)
pipe_deliver :: proc(c: ^Pipe_Conn, msg: []u8) {
	id := u16(msg[0]) << 8 | u16(msg[1])
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)

	w, waiting := c.waiters[id]
	if !waiting {
		// Nobody is on this ID: an answer to a query that has already given
		// up, or one nobody asked. Dropped rather than treated as a failure -
		// the connection is still in frame and everyone else's replies are
		// still coming.
		delete(msg, c.allocator)
		return
	}
	delete_key(&c.waiters, id)
	if !response_matches(w.query, msg) {
		// The refusal the pooled path made of a reply that did not answer the
		// query it was sent: on a stream there is no off-path packet to pass
		// over, so this is the server contradicting itself.
		delete(msg, c.allocator)
		w.err = .Bad_Response
		w.done = true
		return
	}
	w.reply = msg
	w.done = true
}

@(private)
pipe_read_full :: proc(c: ^Pipe_Conn, buf: []u8) -> (n: int, err: Error) {
	for n < len(buf) {
		if c.stream.tls != nil {
			got, terr := tlsx.read(c.stream.tls, buf[n:])
			if terr != .None {
				return n, roundtrip_failure(terr)
			}
			if got <= 0 {
				return n, .IO_Error
			}
			n += got
			continue
		}
		got, nerr := net.recv_tcp(c.stream.socket, buf[n:])
		if nerr != nil {
			// SO_RCVTIMEO expiring on a blocking recv() is EAGAIN on Linux,
			// which core:net reports as .Would_Block rather than .Timeout -
			// see h2client.odin's h2_io_read.
			if nerr == .Timeout || nerr == .Would_Block {
				return n, .Timeout
			}
			return n, .IO_Error
		}
		if got <= 0 {
			return n, .IO_Error
		}
		n += got
	}
	return n, .None
}

/*
Bound the next read by what the caller doing it has left.

Set per read rather than once at dial, because the caller reading is whichever
one happened to find nobody else at it, and its deadline is its own. Without
this a caller that took over the reading late would sit in a read sized by the
socket's timeout and return past the deadline it was given.

Never under a millisecond, and that is not rounding. `SO_RCVTIMEO` is a
`timeval`, so core:net turns a duration under a microsecond into a zero one -
which on Linux does not mean "expire at once" but "no timeout at all", and the
read that was meant to be the shortest of all would be the one that never
returned. The caller reaching here with a sliver of its deadline left is
ordinary: it is a waiter that woke a hair before its own expiry.
*/
@(private)
pipe_set_read_timeout :: proc(c: ^Pipe_Conn, d: time.Duration) {
	bounded := max(d, time.Millisecond)
	if c.stream.tls != nil {
		tlsx.set_read_timeout(c.stream.tls, bounded)
		return
	}
	_ = net.set_option(c.stream.socket, .Receive_Timeout, bounded)
}

@(private)
pipe_write :: proc(c: ^Pipe_Conn, query: []u8) -> Error {
	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)

	sync.mutex_lock(&c.wmu)
	defer sync.mutex_unlock(&c.wmu)
	if c.stream.tls != nil {
		if _, werr := tlsx.write(c.stream.tls, framed); werr != .None {
			return roundtrip_failure(werr)
		}
		return .None
	}
	return write_all_tcp(c.stream.socket, framed)
}

/*
Drop the shared connection if it has gone idle, or whatever the state if `all`.

The stream transports' half of `close_idle`: with one connection per upstream
there is no pool to reap, but there is still a connection a server would rather
not be holding open for a forwarder that has stopped asking.
*/
@(private)
close_pipe :: proc(u: ^Upstream, all: bool) -> (closed: int) {
	// Called with `u.mu` held.
	if u.pipe == nil {
		return 0
	}
	if !all && pipe_state(u.pipe, u.idle_timeout) != .Gone {
		return 0
	}
	c := u.pipe
	u.pipe = nil
	pipe_unref(c)
	return 1
}
