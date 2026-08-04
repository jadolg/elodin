package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "elodin:h2"
import "elodin:tlsx"

/*
The shared HTTP/2 connection an HTTPS upstream uses once ALPN has shown it
speaks h2.

Unlike the HTTP/1.1 and DoT paths, which pool several connections each handling
one request at a time, every concurrent DoH query against an h2 upstream
multiplexes onto the *same* connection: h2.Client_request opens its own stream
and blocks on it, while h2.client_serve — running on its own thread — reads
frames for every stream at once. See src/h2/client.odin for that machinery;
this file only wires it to a real socket and to `Upstream`'s lifecycle.
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
	stream, err = open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, timeout)
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
lose the race wait on `u.h2_cond` and pick up the winner's result.

`ok` is false either when `err` is set or when the upstream turned out to
speak HTTP/1.1; in the latter case the caller falls back to the pooled
HTTP/1.1 path, and the connection this negotiated is already sitting in that
pool.
*/
@(private)
get_h2_conn :: proc(u: ^Upstream, timeout: time.Duration) -> (conn: ^h2.Client, ok: bool, err: Error) {
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
		if !u.connecting {
			break
		}
		sync.cond_wait(&u.h2_cond, &u.mu)
	}
	u.connecting = true
	// A dead connection, if any, is torn down below, outside the lock: it may
	// block for up to H2_POLL_INTERVAL and nothing else here needs to wait for
	// that.
	stale := u.h2
	u.h2 = nil
	sync.mutex_unlock(&u.mu)

	if stale != nil {
		close_h2_conn(stale, u.allocator)
	}

	stream, proto, derr := negotiate_https(u, timeout)

	sync.mutex_lock(&u.mu)
	u.connecting = false
	if derr != .None {
		sync.cond_broadcast(&u.h2_cond)
		sync.mutex_unlock(&u.mu)
		return nil, false, derr
	}
	u.proto = proto
	if proto != .H2 {
		sync.cond_broadcast(&u.h2_cond)
		sync.mutex_unlock(&u.mu)
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

	hc := new(H2_Conn, u.allocator)
	hc.stream = stream
	io := h2.IO {
		user  = hc,
		read  = h2_io_read,
		write = h2_io_write,
	}
	hc.client = h2.client_make(io, u.allocator)
	hc.thread = thread.create_and_start_with_poly_data(hc.client, h2.client_serve)
	u.h2 = hc

	h2.client_ref(hc.client)
	conn = hc.client
	sync.cond_broadcast(&u.h2_cond)
	sync.mutex_unlock(&u.mu)
	return conn, true, .None
}

@(private)
close_h2_conn :: proc(hc: ^H2_Conn, allocator: mem.Allocator) {
	// The reader thread notices this within H2_POLL_INTERVAL and returns on
	// its own; closing the socket first would race a thread that might still
	// be reading from it, since on Linux close does not reliably interrupt a
	// read already blocked elsewhere.
	sync.atomic_store(&hc.stopping, true)
	thread.join(hc.thread)
	thread.destroy(hc.thread)
	stream_close(&hc.stream)
	h2.client_unref(hc.client)
	free(hc, allocator)
}

@(private)
teardown_h2 :: proc(u: ^Upstream) {
	sync.mutex_lock(&u.mu)
	hc := u.h2
	u.h2 = nil
	sync.mutex_unlock(&u.mu)
	if hc == nil {
		return
	}
	close_h2_conn(hc, u.allocator)
}
