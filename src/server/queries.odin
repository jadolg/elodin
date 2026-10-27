package server

import "core:sync"
import "core:time"
import "elodin:loop"

/*
Queries answered on fibers of their own: every UDP datagram, every DoH request
over HTTP/2, every refresh of an expired or expiring entry.

A query that waits on an upstream parks its fiber and the loop runs others, so
how many can be in flight at once is not a count of threads. What bounds it is
`server.max_pending`, counted here: a query is counted from the moment it is
admitted until its fiber returns, which is the whole of the time it holds memory
- its stack, its scratch, the buffers it reads its answers into. Past the bound
a datagram is dropped and an HTTP/2 request answered 503 (see `max_pending` in
`docs/sizing.md`).

Queries asked over TCP, DoT and HTTP/1.1 are not counted. They are answered on
their connection's own fiber, one at a time per connection and in order, so
`server.max_connections` already bounds them; counting them here as well would
let a few slow connections turn away datagrams they were never competing with.
*/

Submit_Result :: enum u8 {
	Accepted,
	// `max_pending` queries are already in flight.
	Full,
	// The server is shutting down and starts no more.
	Stopped,
}

/*
Start `fn(data)` on a fiber of the calling fiber's loop, counted against `limit`
in flight. A limit of zero or less is none. `fn` calls `query_done` as the last
thing it does, whatever happens.

Decided and counted in one step: the readers and connections asking are on
several loops at once, so a check followed by a spawn is a gap every one of them
can pass through together.

On the caller's own loop because the query will answer on the caller's socket or
stream, which lives there; off a loop - a test driving the resolver from a
thread of its own - on the server's first loop, or nowhere when it has none.
*/
submit_query :: proc(s: ^Server, fn: proc(data: rawptr), data: rawptr, limit: int) -> Submit_Result {
	for {
		in_flight := sync.atomic_load(&s.pending)
		if limit > 0 && in_flight >= limit {
			return .Full
		}
		if _, taken := sync.atomic_compare_exchange_weak(&s.pending, in_flight, in_flight + 1); taken {
			break
		}
	}
	l := loop.current_loop()
	if l == nil && len(s.loops) > 0 {
		l = s.loops[0]
	}
	if l != nil {
		if _, ok := loop.spawn(l, fn, data); ok {
			return .Accepted
		}
	}
	query_done(s)
	return .Stopped
}

// The end of a query `submit_query` started.
query_done :: proc(s: ^Server) {
	sync.atomic_sub(&s.pending, 1)
}

// Queries in flight on fibers of their own, for the metrics endpoint and `max_pending`.
queries_pending :: proc(s: ^Server) -> int {
	return sync.atomic_load(&s.pending)
}

/*
Wait until every query `submit_query` started has finished, so that at shutdown
an answer already being worked on still goes out, and nothing it reaches for is
torn down under it.

Polled rather than signalled, as `conn_manager_shutdown` is: this runs once, at
the end of the process, and the queries it waits for end on their own clocks.
*/
drain_queries :: proc(s: ^Server) {
	for queries_pending(s) > 0 {
		time.sleep(SHUTDOWN_POLL)
	}
}

/*
The loop the `i`th of something runs on, wrapping round the server's loops; nil
for a server with none, which `conn_spawn` reads as "a thread of its own".
*/
server_loop :: proc(s: ^Server, i: int) -> ^loop.Loop {
	if len(s.loops) == 0 {
		return nil
	}
	return s.loops[i % len(s.loops)]
}

/*
The loop the next accepted connection goes to: each in turn.

Round robin rather than the least loaded, because a connection's cost is decided
after it is placed - an idle keep-alive and a client pipelining a hundred queries
look the same at the accept - and every loop already shares the one table of
connections the limits are counted on.
*/
next_loop :: proc(s: ^Server) -> ^loop.Loop {
	return server_loop(s, int(sync.atomic_add(&s.next_loop, 1)))
}

/*
Whether this server can start a query nobody waits on, such as a refresh: on a
loop, or with loops of its own to put one on. A `Server` built as a literal and
driven from a test's own thread has neither, and serves what it has.
*/
can_detach :: proc(s: ^Server) -> bool {
	return loop.current_loop() != nil || len(s.loops) > 0
}
