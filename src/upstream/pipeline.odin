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

A backstop, and deliberately not a throughput limit. Past it a caller dials a
connection for its own query and closes it again afterwards, which is a fresh
handshake per query and worse churn than the pool this replaced - so the figure
has to sit above every number of callers the server can actually put in
`exchange` at once, or the fix becomes the bug.

That number is the handlers, not the racers: `resolve_sequential` - failover and
round_robin, so the default - calls `exchange` on the handler thread itself, and
only a race group hands the work to `upstream_workers`. `derive_workers` stops
at `MAX_DERIVED_WORKERS`, 128, and brings half its count again in racers, so a
derived configuration tops out near 192 callers per upstream. 256 clears that.

Which leaves the bound doing what it was asked to do and nothing else: a server
that has stopped answering cannot pile up waiters without limit, and one that
is merely busy never reaches it. A hand-configured `server.workers` above this
would, and would pay the churn; `Upstream.max_outstanding` is where that would
be derived from the configuration if it ever needs to be.
*/
PIPELINE_MAX_OUTSTANDING :: 256

/*
Callers in a row that have to run out of time on a silent connection before it
is treated as gone rather than slow. See the argument in `pipe_wait`: one lone
timeout is what a slow name looks like on a quiet forwarder, and dialling on it
would spend a new connection per slow name.

Two, because the thing being told apart is "nothing at all, twice" from "one
late answer", and a third would only delay the recovery. What it costs is one
extra timeout before a connection that really has gone is replaced, against the
fifteen minutes it used to cost.
*/
PIPE_SILENT_TIMEOUTS :: 2

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
	// `Pipe_Conn.replies` as it stood when this waiter registered, so a caller
	// that runs out of time can tell "my reply never came" from "nothing at
	// all is coming". See `pipe_wait`.
	seen:  u64,
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
	// Messages read off this connection, for anyone at all. What a caller that
	// timed out compares against its own `Pipe_Waiter.seen`.
	replies:   u64,
	// Callers in a row that ran out of time on a connection that had nothing
	// to say to anybody. Back to zero the moment anything is read off it.
	silent:    int,
	/*
	What this connection was dialled with, and the budget a message half read
	is finished on.

	A caller's own deadline is the wrong bound there. Whoever is reading is a
	caller like any other and may have a sliver of its deadline left - that is
	the ordinary case for taking the reading on - but once the length prefix
	has been consumed the framing is committed to finishing that message, and
	giving up partway leaves the stream unreadable for everyone. So the bound
	is the connection's rather than the reader's: how long a peer may take over
	a message it has already started, which is the timeout the upstream is
	configured with.
	*/
	timeout:   time.Duration,

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
pipe_state :: proc(c: ^Pipe_Conn, idle_timeout: time.Duration, limit: int) -> Pipe_State {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	if c.dead {
		return .Gone
	}
	if len(c.waiters) == 0 && time.diff(c.last, time.now()) >= idle_timeout {
		return .Gone
	}
	if len(c.waiters) >= limit {
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

/*
Dial one connection.

`timeout` is what this upstream is configured with and what the connection
keeps - its socket timeouts, and the budget a message half read is finished on.
`budget` is what this particular dial may spend, which is whatever the caller
has left of its own deadline and so may be a good deal less. Kept apart because
a caller dialling with a sliver left must not leave every later reader on that
connection holding a sliver too.
*/
@(private)
dial_pipe :: proc(u: ^Upstream, timeout, budget: time.Duration) -> (c: ^Pipe_Conn, err: Error) {
	// A caller whose deadline went while it was getting here still makes one
	// bounded attempt rather than handing a negative timeval to the socket.
	spend := max(budget, time.Millisecond)
	stream: Stream
	if u.spec.kind == .TLS {
		stream = open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, spend, u) or_return
		// `open_stream` left the session on the dial's budget; what it carries
		// from here is the connection's. Guarded the way h2client.odin guards
		// it: a stream is only a TLS one when it was dialled through a context.
		if stream.tls != nil {
			tlsx.set_timeouts(stream.tls, timeout, timeout)
		}
	} else {
		socket, derr := dial_tcp_timeout(u.endpoint, spend)
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
	c.timeout = timeout
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
get_pipe :: proc(
	u: ^Upstream,
	timeout: time.Duration,
	deadline: time.Time,
) -> (
	c: ^Pipe_Conn,
	fresh: bool,
	err: Error,
) {
	sync.mutex_lock(&u.mu)
	for {
		/*
		Ahead of everything below, and that is not belt and braces.

		A dial against a blackholed upstream takes the whole timeout and fails.
		Unbounded, the caller that was waiting for it then starts a dial of its
		own with the next one waiting behind that, so a burst of N callers
		dials N times end to end and the last of them returns at N times the
		budget it was given - holding an upstream worker for all of it, long
		past the point its own caller stopped waiting. Guarding only the wait
		would leave the same queue one dial shorter, and guarding only the
		shared dial would still spend a connect on every caller that came out
		of the queue past its deadline and found the connection full.

		A caller that breaks out with a sliver left dials on that sliver, since
		`exchange_pipelined` hands every stage the same deadline: what it is
		owed is its timeout, not one per stage it passes through.
		*/
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			sync.mutex_unlock(&u.mu)
			return nil, false, .Timeout
		}
		if u.pipe != nil {
			switch pipe_state(u.pipe, u.idle_timeout, u.max_outstanding) {
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
				c, err = dial_pipe(u, timeout, time.diff(time.now(), deadline))
				return c, true, err
			case .Gone:
			}
		}
		if !u.connecting {
			break
		}
		sync.cond_wait_with_timeout(&u.conn_cond, &u.mu, remaining)
	}

	u.connecting = true
	stale := u.pipe
	u.pipe = nil
	sync.mutex_unlock(&u.mu)
	// Only the upstream's own reference; a caller still on that connection
	// holds its own and tears it down when it is finished with it.
	pipe_unref(stale)

	dialled, derr := dial_pipe(u, timeout, time.diff(time.now(), deadline))

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
	// One deadline for the whole of this, handed to every stage. Waiting for
	// somebody else's dial, dialling, asking and retrying each used to start a
	// clock of its own, so a query could cost several times the timeout its
	// caller was promised - with an upstream worker held for all of it.
	deadline := time.time_add(time.now(), timeout)

	c, fresh, gerr := get_pipe(u, timeout, deadline)
	if gerr != .None {
		return nil, gerr
	}
	response, err = pipe_query(u, c, query, deadline, allocator)
	if err == .None || fresh || !pipe_dead(c) {
		pipe_unref(c)
		return response, err
	}
	/*
	The retry is for a connection found dead before this query spent anything
	on it - a write that failed, or a read that came back closed - where the
	budget is whole and the whole point is that a server recycling an idle
	connection costs nobody an answer. A connection that went dead by running
	this query's clock out has already had the time, so there is none to spend
	again; the query after this one finds the connection dead and dials afresh,
	which is what makes a server that vanished recoverable.

	`get_pipe` would refuse the redial on the same deadline anyway, so what
	this adds is the error: it reports what actually went wrong with this query
	rather than the `Timeout` a refused redial would report, and
	`elodin_upstream_failure_kind_total` is only worth reading if a reply that
	could not be used is counted as one.
	*/
	if time.diff(time.now(), deadline) <= 0 {
		pipe_unref(c)
		return nil, err
	}

	// Held until the redial is done, so `get_pipe` sees the dead connection it
	// has to replace rather than an address something else has since reused.
	retry, _, rerr := get_pipe(u, timeout, deadline)
	pipe_unref(c)
	if rerr != .None {
		return nil, rerr
	}
	response, err = pipe_query(u, retry, query, deadline, allocator)
	pipe_unref(retry)
	return response, err
}

@(private)
pipe_query :: proc(
	u: ^Upstream,
	c: ^Pipe_Conn,
	query: []u8,
	deadline: time.Time,
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
	w.seen = c.replies
	c.waiters[id] = &w
	sync.mutex_unlock(&c.mu)

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
	// Unreachable under `Upstream.max_outstanding`, which is orders of
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
			/*
			Nobody is left on this connection and nothing came back on it for
			anybody while this caller waited. Evidence the connection has
			stopped rather than that one answer is late - and nothing else here
			would ever notice. A peer that goes away without a FIN or an RST (a
			firewall dropping an idle mapping, an upstream rebooting, a route
			moving) leaves the writes succeeding into the send buffer and every
			read timing out, and a read timeout deliberately does not kill the
			connection. The idle reaper cannot help either: a connection under
			steady traffic is never idle. Left alone, the upstream would sit
			wedged on one useless socket until the kernel gave up on the
			unacked data, which on Linux is about fifteen minutes.

			Evidence rather than proof, which is why it is counted rather than
			acted on. A forwarder with one query in flight at a time meets both
			conditions on every lone timeout it ever has, so acting on the
			first would dial a new connection for each slow name - a new
			connection being the one thing the upstream this was all written
			for rate-limits. Two in a row with nothing at all in between is a
			connection that has stopped; one is a slow answer. The count goes
			back to zero the moment anything is read, so the two cannot be
			confused by distance in time.

			Killing it puts back what the pooled path did on every failed round
			trip: `exchange_pipelined` finds the connection dead and the next
			query dials a fresh one.

			Both conditions are load-bearing. A reply having arrived for
			somebody says the connection is delivering, so a slow answer to
			this one query is this query's problem. And a caller still waiting
			says the same about the future: an impatient caller must not take
			down a connection whose answer to a patient one is still on its
			way.
			*/
			if c.replies == w.seen && len(c.waiters) == 0 {
				c.silent += 1
				if c.silent >= PIPE_SILENT_TIMEOUTS {
					pipe_kill(c, .Timeout)
					sync.cond_broadcast(&c.cond)
				}
			}
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

The reads are bounded differently on purpose, and `Pipe_Conn.timeout` says why:
until a byte of the message has been taken, this caller is free to give up and
hand the reading to somebody else; from the first byte on, the message has to
be finished or the connection is no longer readable at all.
*/
@(private)
pipe_read_one :: proc(c: ^Pipe_Conn, budget: time.Duration) -> Error {
	length_buf: [2]u8
	/*
	One byte on this caller's budget, because until a byte is taken the caller
	owes the connection nothing and may hand the reading on.

	A byte rather than the whole prefix: the bound starts where the framing is
	committed, and that is the *first* byte consumed. A length prefix split by
	a segment boundary is a message half read exactly as a header without its
	records is, and a reader that gave up holding one byte of a length would
	leave the stream unreadable for everyone on it.
	*/
	if _, rerr := pipe_read_full(c, length_buf[:1], time.time_add(time.now(), budget)); rerr != .None {
		return .Timeout if rerr == .Timeout else rerr
	}
	if _, rerr := pipe_read_full(c, length_buf[1:], time.time_add(time.now(), c.timeout)); rerr != .None {
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
	if _, merr := pipe_read_full(c, msg, time.time_add(time.now(), c.timeout)); merr != .None {
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

	// Counted before it is known whose this is, and counted even when it is
	// nobody's: what a waiter reads off this is whether the connection is
	// still delivering, not whether it was delivered anything itself.
	c.replies += 1
	c.silent = 0

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

/*
Fill `buf`, or give up at `deadline`.

The deadline is applied per turn of the loop rather than once at the top,
because the timeout underneath is a socket option and bounds one `recv` rather
than the sequence of them. Left at one setting, a peer dribbling a byte at a
time just under it would keep this loop running past whatever deadline the
caller computed - while holding the reading, so no other waiter could take the
socket on either.
*/
@(private)
pipe_read_full :: proc(c: ^Pipe_Conn, buf: []u8, deadline: time.Time) -> (n: int, err: Error) {
	for n < len(buf) {
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			return n, .Timeout
		}
		pipe_set_read_timeout(c, remaining)
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

Set per read rather than once at dial, because what is left of a deadline is
whatever the caller doing the reading has left, and that caller is whichever
one happened to find nobody else at it.

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
	if !all && pipe_state(u.pipe, u.idle_timeout, u.max_outstanding) != .Gone {
		return 0
	}
	c := u.pipe
	u.pipe = nil
	pipe_unref(c)
	return 1
}
