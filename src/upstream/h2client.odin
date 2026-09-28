package upstream

import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "elodin:h2"
import "elodin:tlsx"

/*
The shared HTTP/2 connection an HTTPS upstream uses once ALPN has shown it
speaks h2.

Every concurrent DoH query against an h2 upstream multiplexes onto the *same*
connection: h2.Client_request opens its own stream and blocks on it, while
h2.client_serve — running on its own thread — reads frames for every stream at
once. See src/h2/client.odin for that machinery; this file only wires it to a
real socket and to `Upstream`'s lifecycle.

pipeline.odin does the same for TCP and DoT, demultiplexing on the DNS message
ID instead of a stream ID and without a thread of its own. The HTTP/1.1 path is
the one left pooling a connection per request in flight, because HTTP/1.1 has
no way to do anything else.
*/

// How long the reader thread's blocking read waits before it gets a chance to
// notice `H2_Conn.stopping`. Idle time between queries is normal on a
// long-lived shared connection, so this is a polling interval, not a request
// deadline — a plain read timeout is not treated as a connection failure.
H2_POLL_INTERVAL :: time.Second

@(private)
h2_io_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	hc := cast(^H2_Conn)user
	for {
		if sync.atomic_load(&hc.stopping) {
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
		got, nerr := net.recv_tcp(hc.stream.socket, buf)
		if nerr == nil {
			return got, true
		}
		// SO_RCVTIMEO expiring on a blocking recv() surfaces as EAGAIN on
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
	stream, err = open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, timeout, u)
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
		sync.cond_wait_with_timeout(&u.conn_cond, &u.mu, remaining)
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

	sync.mutex_lock(&u.mu)
	u.connecting = false
	if derr != .None {
		sync.cond_broadcast(&u.conn_cond)
		sync.mutex_unlock(&u.mu)
		return nil, false, derr
	}
	u.proto = proto
	if proto != .H2 {
		sync.cond_broadcast(&u.conn_cond)
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

	// Overrides the connect/handshake timeout `open_stream` applied: the
	// reader thread now lives for as long as the connection does, and normal
	// idle time between queries must not look like a read failure.
	_ = net.set_option(stream.socket, .Receive_Timeout, H2_POLL_INTERVAL)
	if stream.tls != nil {
		// A TLS connection stops taking its deadlines from the socket once the
		// handshake is done - it waits in `poll` rather than in the kernel, so
		// that a reader between queries does not hold the lock a writer needs -
		// and has to be told separately.
		tlsx.set_timeouts(stream.tls, H2_POLL_INTERVAL, timeout)
	}

	hc := start_h2_conn(u, stream)
	u.h2 = hc

	h2.client_ref(hc.client)
	conn = hc.client
	sync.cond_broadcast(&u.conn_cond)
	sync.mutex_unlock(&u.mu)
	return conn, true, .None
}

/*
Wrap a negotiated stream in an h2 client and start its reader thread. Under
`u.mu`.

The connection has two owners, `u.h2` and the reader, and whichever lets go
last frees it (`release_h2_conn`). The reader's handle is kept on `u` instead,
since a reader that frees the connection cannot join itself; finished ones are
reaped here, as each new connection starts, and `teardown_h2` joins the rest.
*/
@(private)
start_h2_conn :: proc(u: ^Upstream, stream: Stream) -> ^H2_Conn {
	for i := len(u.h2_readers) - 1; i >= 0; i -= 1 {
		if thread.is_done(u.h2_readers[i]) {
			thread.destroy(u.h2_readers[i])
			unordered_remove(&u.h2_readers, i)
		}
	}
	hc := new(H2_Conn, u.allocator)
	hc.stream = stream
	hc.allocator = u.allocator
	hc.refs = 2
	hc.client = h2.client_make(h2.IO{user = hc, read = h2_io_read, write = h2_io_write}, u.allocator)
	reader := thread.create_and_start_with_poly_data(hc, h2_reader)
	if reader == nil {
		// No thread to be had: nothing would ever read this connection's
		// answers, so it goes out already closed, the next caller dials
		// afresh, and the reader's share is let go here instead.
		sync.mutex_lock(&hc.client.mu)
		hc.client.closed = true
		sync.mutex_unlock(&hc.client.mu)
		release_h2_conn(hc)
		return hc
	}
	append(&u.h2_readers, reader)
	return hc
}

@(private)
h2_reader :: proc(hc: ^H2_Conn) {
	h2.client_serve(hc.client)
	release_h2_conn(hc)
}

/*
Let go of `u.h2`'s share of a connection, without waiting for its reader.

The reader frees the connection on its way out, or this does, if it has already
gone. It is woken with a shutdown rather than left to notice `stopping` at its
next poll: nothing joins it any more, so replacements are only as far apart as
a dial, and a reader sitting out its poll would hold a thread and a socket for
each. Shutdown, not close, because close would race a thread that might still
be reading from the descriptor; this caller's share keeps it open until then.
*/
@(private)
retire_h2_conn :: proc(hc: ^H2_Conn) {
	sync.atomic_store(&hc.stopping, true)
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
	readers := u.h2_readers
	u.h2_readers = nil
	sync.mutex_unlock(&u.mu)
	if hc != nil {
		retire_h2_conn(hc)
	}
	for t in readers {
		thread.destroy(t)
	}
	delete(readers)
}
