package server

import "core:mem"
import "core:sync"
import "elodin:dnssec"
import "elodin:loop"

/*
The queries one TCP or DoT connection has in flight at once.

RFC 7766 section 6.2.1.1: "The server SHOULD process TCP queries concurrently,
just as it would for UDP"; section 7: "recursive resolvers SHOULD process TCP
queries in parallel and return individual responses as soon as they are
available, possibly out of order". A client that pipelines - Android's
Private DNS sends all of a device's queries down one DoT connection - would
otherwise have a cache hit wait out the upstream round trip of the miss in
front of it.

A connection has one place of its own, which `server.max_pending` does not
count and `server.max_connections` bounds, as it bounds the connection; the
queries beside it are counted in `max_pending`, as an HTTP/2 stream's are, so a
flood of pipelined queries is shed with the datagrams rather than beside them.
Past this many on one connection the reader stops reading until one is answered,
so one client cannot take every place in `max_pending` for itself.
*/
STREAM_MAX_IN_FLIGHT :: 16

/*
One connection's queries in flight, shared between its reader fiber and the
fibers answering its queries. It lives in the reader's frame, which waits for
every query to finish (`stream_settle`) before it returns.
*/
@(private)
Stream_Session :: struct {
	server:    ^Server,
	conn:      Conn,
	proto:     Protocol,
	client:    string,
	// Guards `in_flight` and `own_busy`, and is never held across a wait.
	mu:        sync.Mutex,
	// Signalled whenever a query finishes.
	done:      loop.Cond,
	in_flight: int,
	// Whether the connection's own place - see `STREAM_MAX_IN_FLIGHT` - is taken.
	own_busy:  bool,
	// Held across one whole answer, prefix and body, so two never interleave.
	write_mu:  loop.Mutex,
	// Set under `write_mu`, read by the reader: whether an answer has gone out,
	// and whether a write has failed, after which nothing more is written.
	answered:  bool,
	broken:    bool,
}

// A query and its message in one block, the bytes trailing the struct, so a
// plain `free` releases both; see `new_udp_job`.
@(private)
Stream_Query :: struct {
	session: ^Stream_Session,
	// In the connection's own place rather than counted in `max_pending`.
	own:     bool,
	message: []u8,
}

@(private)
new_stream_query :: proc(message: []u8) -> ^Stream_Query {
	raw, err := mem.alloc(size_of(Stream_Query) + len(message), align_of(Stream_Query))
	if err != .None {
		return nil
	}
	q := cast(^Stream_Query)raw
	q.message = ([^]u8)(raw)[size_of(Stream_Query):][:len(message)]
	copy(q.message, message)
	return q
}

/*
Answer `message` on a fiber of its own, once the connection has room for it.

Waits while `STREAM_MAX_IN_FLIGHT` are in flight. Takes the connection's own
place when it is free and a place counted in `max_pending` otherwise; with
neither to be had - `max_pending` reached, no stack or no loop to start a fiber
on - waits for the own place and answers on the calling reader, one at a time
and in order, as a connection with no room to spare is answered.
*/
@(private)
stream_dispatch :: proc(session: ^Stream_Session, message: []u8) {
	own := stream_take_place(session)
	if q := new_stream_query(message); q != nil {
		q.session = session
		q.own = own
		if stream_start(session, q) {
			return
		}
		free(q)
	}
	if !own {
		stream_release(session, false)
		own = stream_take_place(session, own_only = true)
	}
	stream_answer(session, message, .Connection)
	stream_release(session, own)
}

// A place for one more query: the connection's own when free, unless `own_only`
// waits for that one alone; true when it is the own place.
@(private)
stream_take_place :: proc(session: ^Stream_Session, own_only := false) -> (own: bool) {
	sync.mutex_lock(&session.mu)
	defer sync.mutex_unlock(&session.mu)
	for session.in_flight >= STREAM_MAX_IN_FLIGHT || (own_only && session.own_busy) {
		loop.cond_wait(&session.done, &session.mu)
	}
	own = !session.own_busy
	if own {
		session.own_busy = true
	}
	session.in_flight += 1
	return own
}

// Give back a place `stream_take_place` took. The last use of `session`: the
// reader may return once it is signalled.
@(private)
stream_release :: proc(session: ^Stream_Session, own: bool) {
	sync.mutex_lock(&session.mu)
	defer sync.mutex_unlock(&session.mu)
	session.in_flight -= 1
	if own {
		session.own_busy = false
	}
	loop.cond_broadcast(&session.done)
}

// Start `q` on a fiber of the reader's loop; false leaves it the caller's.
@(private)
stream_start :: proc(session: ^Stream_Session, q: ^Stream_Query) -> bool {
	s := session.server
	if !q.own {
		max_pending: int
		{
			pin_scope(s)
			max_pending = live(s).cfg.server.max_pending
		}
		return submit_query(s, stream_query_job, q, max_pending) == .Accepted
	}
	l := loop.current_loop()
	if l == nil {
		return false
	}
	_, started := loop.spawn(l, stream_query_job, q)
	return started
}

@(private)
stream_query_job :: proc(data: rawptr) {
	q := cast(^Stream_Query)data
	session := q.session
	own := q.own
	s := session.server
	stream_answer(session, q.message, .Connection if own else .Shared)
	free(q)
	free_all(context.temp_allocator)
	if !own {
		query_done(s)
	}
	stream_release(session, own)
}

// Answer one query on `session`; see `stream_write_answer`.
@(private)
stream_answer :: proc(session: ^Stream_Session, message: []u8, pool: dnssec.Walk_Pool) {
	response, _, ok := handle_query(
		session.server,
		message,
		session.proto,
		session.client,
		context.temp_allocator,
		pool = pool,
	)
	if ok && len(response) > 0 {
		stream_write_answer(session, response)
	}
}

/*
Write `response` behind its length prefix, whole, under the connection's write
lock, so answers written from several fibers never interleave.

An answer the scratch has no room to frame goes out as its prefix and then its
body, still under the lock and so still whole on the wire. A write that fails
marks the connection broken, and every answer after it is dropped; the reader
ends the connection at its next message.
*/
@(private)
stream_write_answer :: proc(session: ^Stream_Session, response: []u8) {
	framed, framed_built := stream_frame(response, context.temp_allocator)

	loop.lock(&session.write_mu)
	defer loop.unlock(&session.write_mu)
	if sync.atomic_load(&session.broken) {
		return
	}
	written: bool
	if framed_built {
		written = conn_write_all(session.conn, framed)
	} else {
		prefix := [2]u8{u8(len(response) >> 8), u8(len(response))}
		written = conn_write_all(session.conn, prefix[:]) && conn_write_all(session.conn, response)
	}
	if written {
		sync.atomic_store(&session.answered, true)
	} else {
		sync.atomic_store(&session.broken, true)
	}
}

/*
Wait until every query `stream_dispatch` started has been answered; true when
any had to be waited for.
*/
@(private)
stream_settle :: proc(session: ^Stream_Session) -> (waited: bool) {
	sync.mutex_lock(&session.mu)
	defer sync.mutex_unlock(&session.mu)
	for session.in_flight > 0 {
		waited = true
		loop.cond_wait(&session.done, &session.mu)
	}
	return waited
}
