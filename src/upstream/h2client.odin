package upstream

import "core:net"
import "core:sync"
import "core:time"
import "elodin:h2"
import "elodin:loop"
import "elodin:tlsx"

/*
The shared HTTP/2 connection an HTTPS upstream uses once ALPN has shown it
speaks h2.

Every concurrent DoH query against an h2 upstream multiplexes onto the *same*
connection: h2.client_request opens its own stream and waits on it, while
h2.client_serve — running on a fiber of its own — reads frames for every stream
at once. See src/h2/client.odin for that machinery; this file only wires it to a
real socket and to `Upstream`'s lifecycle.

pipeline.odin does the same for TCP and DoT, demultiplexing on the DNS message
ID instead of a stream ID and without a thread of its own. The HTTP/1.1 path is
the one left pooling a connection per request in flight, because HTTP/1.1 has
no way to do anything else.
*/

// How long the reader's read waits before it gets a chance to notice
// `H2_Conn.stopping`. Idle time between queries is normal on a
// long-lived shared connection, so this is a polling interval, not a request
// deadline — a plain read timeout is not treated as a connection failure.
H2_POLL_INTERVAL :: time.Second

@(private)
h2_io_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	hc := cast(^H2_Conn)user
	for {
		// Cancelled is the server stopping: every wait from here on returns at
		// once, so retrying would spin rather than poll.
		if sync.atomic_load(&hc.stopping) || loop.cancelled() {
			return 0, false
		}
		if hc.stream.tls != nil {
			got, terr := tlsx.read(hc.stream.tls, buf)
			#partial switch terr {
			case .None:
				return got, true
			case .Timeout:
				continue
			case:
				return 0, false
			}
		}
		got, nerr := loop.recv_tcp(hc.stream.socket, buf)
		if nerr == nil {
			return got, true
		}
		// SO_RCVTIMEO expiring surfaces as EAGAIN on
		// Linux, which core:net maps to .Would_Block rather than .Timeout -
		// ETIMEDOUT (and thus .Timeout) is never actually produced by a
		// receive-timeout poll there. Treating only .Timeout as "no data yet"
		// misread every idle poll tick as the peer closing, tearing down a
		// perfectly healthy connection roughly once per H2_POLL_INTERVAL.
		if nerr == .Timeout || nerr == .Would_Block {
			continue
		}
		return 0, false
	}
}

@(private)
h2_io_write :: proc(user: rawptr, buf: []u8) -> bool {
	hc := cast(^H2_Conn)user
	return stream_write(&hc.stream, buf) == .None
}

/*
Dial and TLS-handshake `u`'s endpoint, and read off which protocol ALPN chose.

The stream is returned either way: on an HTTP/1.1 result the caller has a
handshake it would otherwise have to throw away and repeat.
*/
@(private)
negotiate_https :: proc(u: ^Upstream, timeout: time.Duration) -> (stream: Stream, proto: Protocol, err: Error) {
	endpoint := endpoint_of(u) or_return
	stream, err = open_stream(endpoint, u.tls_ctx, u.spec.hostname, timeout, u)
	if err != .None {
		return {}, .Unknown, err
	}
	if stream.tls != nil && tlsx.alpn_protocol(stream.tls) == "h2" {
		return stream, .H2, .None
	}
	return stream, .H1, .None
}

/*
Get the shared h2 connection for `u`, (re)connecting if there is none or the
last one died.

Only one caller dials at a time: a burst of concurrent first queries against a
freshly started upstream shares a single handshake rather than each opening —
and then discarding all but one of — a connection of its own. Callers that
lose the race wait on `u.conn_cond` and pick up the winner's result.

`ok` is false either when `err` is set or when the upstream turned out to
speak HTTP/1.1; in the latter case the caller falls back to the pooled
HTTP/1.1 path, and the connection this negotiated is already sitting in that
pool.
*/
@(private)
get_h2_conn :: proc(
	u: ^Upstream,
	// The upstream's own, which the connection keeps for its life, for the
	// reason `Pipe_Conn.timeout` gives.
	timeout: time.Duration,
	// What this caller has left, which bounds the wait and the dial.
	budget: time.Duration,
) -> (
	conn: ^h2.Client,
	ok: bool,
	err: Error,
) {
	deadline := time.time_add(time.now(), budget)
	sync.mutex_lock(&u.mu)
	for {
		if u.proto == .H1 {
			sync.mutex_unlock(&u.mu)
			return nil, false, .None
		}
		if u.h2 != nil && !h2.client_closed(u.h2.client) {
			conn = u.h2.client
			h2.client_ref(conn)
			sync.mutex_unlock(&u.mu)
			return conn, true, .None
		}
		// Bounded by this caller's own deadline, for the reason `get_pipe`
		// gives: a dial against an upstream that is not answering takes the
		// whole timeout and fails, and unbounded, the callers queued behind it
		// dial one after another and the last returns at a multiple of the
		// budget it was given. Above the break as well as the wait, since a
		// caller that wakes to a finished dial goes on to start one of its own.
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			sync.mutex_unlock(&u.mu)
			return nil, false, .Timeout
		}
		if !u.connecting {
			break
		}
		loop.cond_wait_with_timeout(&u.conn_cond, &u.mu, remaining)
	}
	u.connecting = true
	stale := u.h2
	u.h2 = nil
	sync.mutex_unlock(&u.mu)

	// Handed to its reader rather than joined here (#454): the reader only
	// notices `stopping` when its poll ticks, and waiting for that would put up
	// to H2_POLL_INTERVAL on this caller, outside the deadline its exchange is
	// held to.
	if stale != nil {
		retire_h2_conn(stale)
	}

	// What is left of this caller's deadline rather than the whole timeout, so
	// the caller that came out of the queue does not add a full dial to what it
	// already spent waiting for the one in front of it. `dial_pipe` splits the
	// two for the same reason. Floored, so a caller that is only just inside
	// its deadline still makes one bounded attempt.
	stream, proto, derr := negotiate_https(u, max(time.diff(time.now(), deadline), time.Millisecond))

	/*
	An h2 connection is built here, before `u.mu` is taken again: building it
	writes the connection preface, and a write may park, which no fiber may do
	holding a plain lock - the next fiber of its loop to reach for `u.mu` would
	block the loop thread under the writer that holds it.
	*/
	hc: ^H2_Conn
	if derr == .None && proto == .H2 {
		// Overrides the connect/handshake timeout `open_stream` applied: the
		// reader now lives for as long as the connection does, and normal
		// idle time between queries must not look like a read failure.
		_ = net.set_option(stream.socket, .Receive_Timeout, H2_POLL_INTERVAL)
		if stream.tls != nil {
			// A TLS connection stops taking its deadlines from the socket once the
			// handshake is done - it waits outside the lock rather than in the
			// kernel, so that a reader between queries does not hold the lock a
			// writer needs - and has to be told separately.
			tlsx.set_timeouts(stream.tls, H2_POLL_INTERVAL, timeout)
		}
		hc = make_h2_conn(u, stream)
	}

	sync.mutex_lock(&u.mu)
	u.connecting = false
	if derr != .None {
		loop.cond_broadcast(&u.conn_cond)
		sync.mutex_unlock(&u.mu)
		return nil, false, derr
	}
	u.proto = proto
	if proto != .H2 {
		loop.cond_broadcast(&u.conn_cond)
		sync.mutex_unlock(&u.mu)
		/*
		Back to the configured timeout before this goes in the pool.

		The dial above was budgeted at what its caller had left, which may be a
		sliver, and `open_stream` puts that figure on the socket. A pooled
		connection carrying it would give every later request on it a deadline
		belonging to the query that happened to open it - the same confusion
		`Pipe_Conn.timeout` exists to avoid. The h2 branch below overrides both
		already, for its own reasons.
		*/
		set_socket_timeouts(stream.socket, timeout)
		if stream.tls != nil {
			tlsx.set_timeouts(stream.tls, timeout, timeout)
		}
		put_idle(u, Idle_Conn{socket = stream.socket, tls = stream.tls})
		return nil, false, .None
	}

	start_h2_reader(u, hc)
	u.h2 = hc

	h2.client_ref(hc.client)
	conn = hc.client
	loop.cond_broadcast(&u.conn_cond)
	sync.mutex_unlock(&u.mu)
	return conn, true, .None
}

/*
Wrap a negotiated stream in an h2 client and start its reader: `make_h2_conn`,
then `start_h2_reader`, the caller holding `u.mu`. For a caller off a loop - the
tests - where a preface write that waits blocks only its own thread; a fiber
builds the connection before taking the lock instead (see `get_h2_conn`).

The reader is a fiber of the loop the dialling query runs on - a thread of its
own off a loop, which is the tests - and it reads every stream's frames for as
long as the connection lives. The connection has two owners, `u.h2` and the
reader, and whichever lets go last frees it (`release_h2_conn`). The reader is
counted in `u.h2_readers` until its last touch of `u`, which `teardown_h2` waits
for.
*/
@(private)
start_h2_conn :: proc(u: ^Upstream, stream: Stream) -> ^H2_Conn {
	hc := make_h2_conn(u, stream)
	start_h2_reader(u, hc)
	return hc
}

// The connection and its client, which writes the preface. Not under `u.mu`.
@(private)
make_h2_conn :: proc(u: ^Upstream, stream: Stream) -> ^H2_Conn {
	hc := new(H2_Conn, u.allocator)
	hc.stream = stream
	hc.allocator = u.allocator
	hc.refs = 2
	hc.upstream = u
	hc.client = h2.client_make(h2.IO{user = hc, read = h2_io_read, write = h2_io_write}, u.allocator)
	return hc
}

// Under `u.mu`, which `h2_readers` is counted under. Starting a fiber does not park.
@(private)
start_h2_reader :: proc(u: ^Upstream, hc: ^H2_Conn) {
	u.h2_readers += 1
	if !loop.go(h2_reader, hc) {
		// Nothing to run a reader on: nothing would ever read this connection's
		// answers, so it goes out already closed, the next caller dials
		// afresh, and the reader's share is let go here instead. Nobody else
		// has the client yet, so its flag needs no lock of its own.
		u.h2_readers -= 1
		sync.atomic_store(&hc.client.closed, true)
		release_h2_conn(hc)
	}
}

/*
The h2 half of `close_idle`, under `u.mu`: take `u.h2` off the upstream if the
peer has closed it, or nobody has used it for `idle_timeout`, or whatever its
age if `all`, for the caller to retire once the lock is let go.

A connection somebody holds is left alone even when `all`, as a busy pipe is:
retiring it would cut short the requests on it, and a retired generation is
groomed again at the next tick. A closed one is taken whatever holds it, since
nothing more can be asked on it. No caller can take a reference between the
check and the take, because `get_h2_conn` hands the connection out under
`u.mu` too.
*/
@(private)
take_idle_h2_locked :: proc(u: ^Upstream, all: bool) -> (stale: ^H2_Conn) {
	if u.h2 == nil {
		return nil
	}
	if !h2.client_closed(u.h2.client) {
		idle, busy := h2.client_idle_for(u.h2.client)
		if busy || (!all && idle < u.idle_timeout) {
			return nil
		}
	}
	stale = u.h2
	u.h2 = nil
	return
}

@(private)
h2_reader :: proc(data: rawptr) {
	hc := (^H2_Conn)(data)
	// Taken first: the release below may free `hc`.
	u := hc.upstream
	h2.client_serve(hc.client)
	release_h2_conn(hc)
	// The last touch of `u`, which `teardown_h2` may free once this is done.
	sync.mutex_lock(&u.mu)
	u.h2_readers -= 1
	if u.h2_readers == 0 {
		loop.cond_broadcast(&u.h2_readers_done)
	}
	sync.mutex_unlock(&u.mu)
}

/*
Let go of `u.h2`'s share of a connection, without waiting for its reader.

The reader frees the connection on its way out, or this does, if it has already
gone. It is woken with a shutdown rather than left to notice `stopping` at its
next poll: nothing waits for it, so replacements are only as far apart as a
dial, and a reader sitting out its poll would hold a fiber and a socket for each.
Shutdown, not close, because close would race a thread that might still be
reading from the descriptor; this caller's share keeps it open until then.
A connection still open says GOAWAY first, as RFC 9113 section 6.8 asks of an
endpoint closing one, and a TLS session then sends its close_notify, for the
reason `send_close_notify` gives.
*/
@(private)
retire_h2_conn :: proc(hc: ^H2_Conn) {
	h2.client_goaway(hc.client, .No_Error)
	sync.atomic_store(&hc.stopping, true)
	tlsx.send_close_notify(hc.stream.tls)
	_ = net.shutdown(hc.stream.socket, .Both)
	release_h2_conn(hc)
}

/*
Free the connection once both owners are done with it.

Safe against a caller still holding a reference to `hc.client` mid-request:
the reader is always one of the two, and `client_serve` marks the client closed
before it returns, so every write after this finds it closed without touching
`hc`.
*/
@(private)
release_h2_conn :: proc(hc: ^H2_Conn) {
	if sync.atomic_sub(&hc.refs, 1) != 1 {
		return
	}
	stream_close(&hc.stream)
	h2.client_unref(hc.client)
	free(hc, hc.allocator)
}

// Shutdown's, which unlike a replacement has nobody's deadline on it and waits
// out every reader: they free into `u.allocator`, and TLS ones use `u.tls_ctx`.
@(private)
teardown_h2 :: proc(u: ^Upstream) {
	sync.mutex_lock(&u.mu)
	hc := u.h2
	u.h2 = nil
	sync.mutex_unlock(&u.mu)
	if hc != nil {
		retire_h2_conn(hc)
	}
	sync.mutex_lock(&u.mu)
	for u.h2_readers > 0 {
		loop.cond_wait(&u.h2_readers_done, &u.mu)
	}
	sync.mutex_unlock(&u.mu)
}
