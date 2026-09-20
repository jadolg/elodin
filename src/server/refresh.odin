package server

import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:pool"

/*
The refresh of an expired entry, running clear of the client that asked for it.

RFC 8767 section 5 asks for two things that `resolve_query` on its own cannot
give at once: the client is answered from the expired entry once a short timer
has run out, and the refresh that would have answered it carries on anyway, so
the entry is renewed rather than left to be served stale again on the next
query. Tying the two together is what issue #164 is about - the fallback was
reached only after `upstream.resolve` had given up on every server for every
attempt, which is ten seconds with the defaults and a stub that gave up at five.

So the refresh is moved off the client's thread and the client waits on it with
a deadline. A worker of the query pool runs `resolve_query` over a copy of the
client's own query, which is what makes this cheap to be sure of: it is the
same procedure, on the same bytes, reaching the same validator, the same
blocking walk and the same store. There is no second forwarding path to keep in
step with the first, which for a store that a later client is served from is
the difference between one rule and two that have to agree.

`cache.stale_timeout` is the deadline. Whichever happens first decides what this
client gets:

  - the refresh finishes inside it, and its answer is the client's, exactly as
    though the query had never been detached;
  - the timer fires, and the held expired bytes go out while the refresh runs
    on. Its answer then reaches the cache and nobody else.

One refresh per cache key is in flight at a time, and a query that finds one
already running is served its expired bytes straight away rather than made to
wait on somebody else's. That is the stampede control the issue asks for: a
popular name whose entry has just expired costs one upstream query rather than
one per client. It is also why a refresh has at most one waiter, which is worth
naming because it is what keeps the handoff honest - the bytes that come back
carry the transaction ID and the question spelling of the one query this was
started from, and handing them to a second client would mean patching both back
out of somebody else's answer.

What an operator sees in the query log while the timer is firing is two lines
for one client query: the `outcome=cached detail=stale` this server answered
with, and the refresh's own line whenever it finishes. The counters follow the
same reading - both answers really happened, one for the client and one for the
cache - so a slow upstream under `serve_stale` shows a `cached` and a
`forwarded` for the same query. A blackholed one shows only the `cached`: a
refresh that got nothing at all counts nothing, since the client it would have
been counted for was answered from the entry instead.
*/

/*
Refreshes that may be in flight at once, for the whole server.

A ceiling rather than a table that grows, because what decides how many
distinct expired names are being asked for at once is whoever is asking. Each
refresh holds a worker of the query pool for as long as the upstream takes to
fail, which with a blackholed upstream is the full `attempts` x servers x
`timeout` - so an unbounded number of them is the query pool spent on refreshes
while the clients they were started for are already being answered from the
cache.

64 is well past what the pool can usefully run at once; `refresh_ceiling` is
the bound that actually binds on a small machine. This is the bound on the
table, and it is a fixed array so that a `Server` built as a literal - which
the tests do - needs nothing initialised.
*/
@(private)
REFRESH_SLOTS :: 64

@(private)
Refresh_Table :: struct {
	mu:    sync.Mutex,
	slots: [REFRESH_SLOTS]^Refresh,
}

@(private)
Refresh :: struct {
	/*
	Everything the detached call needs, owned here rather than borrowed.

	The client's query arrives in a receive buffer or an arena that is released
	as soon as the response has gone out, and the cache key is a view into a
	stack buffer in `resolve_query`'s frame. Neither outlives the waiter, and
	the whole point of this is that the work does.
	*/
	key:        string,
	query:      []u8,
	client:     string,
	server:     ^Server,
	proto:      Protocol,
	limit:      int,
	/*
	What every allocation above and the answer below were taken from, carried
	so that whichever thread lets go last frees them where they came from.

	A refresh is allocated by the request that started it and may be freed by
	the worker that ran it, or the other way round, and a pool worker runs with
	the default context rather than the one that submitted the job - so the
	ambient `context.allocator` is not the same allocator at the two ends. In a
	running server both are the heap and nothing would show; under the test
	runner's tracking allocator the mismatch is a free of a pointer it never
	handed out.
	*/
	allocator:  mem.Allocator,
	// The client's own start time, so the refresh's query-log line reports the
	// latency that client saw rather than the fraction of it this job ran for.
	started:    time.Time,
	mu:         sync.Mutex,
	sema:       sync.Sema,
	/*
	The waiter's, the table's and the job's. The last one to let go frees it,
	which is how a refresh that outlives its client is cleaned up by the worker
	that was still running it.
	*/
	refs:       int,
	// Set once the fields below are final, so a waiter that arrives after the
	// job has finished reads them instead of waiting for a post that has been.
	done:       bool,
	response:   []u8,
	outcome:    Outcome,
	ok:         bool,
	/*
	Whether the upstream produced nothing at all, which is the one failure the
	expired entry covers.

	`resolve_query` normally decides this for itself and reaches for the entry
	it is holding. A detached refresh has no entry and no client, so it says so
	here instead and the waiter - which does hold the bytes - serves them. The
	distinction matters: a refusal this server reached on purpose, a Bogus
	verdict or an answer the chain walk could not read, is not an outage and
	does not get the fallback. See the `uerr != .None` branch in `resolve_query`.
	*/
	unanswered: bool,
}

/*
How many refreshes this server will run at once.

A quarter of the query pool, and the figure is about a burst rather than a
steady state. A refresh holds a worker for as long as the upstream takes to
fail, which against a blackholed one is the whole `attempts` x servers x
`timeout`; the client that started it holds a second worker for up to
`cache.stale_timeout`. So a burst of queries for that many distinct expired
names at once costs twice the ceiling in workers, and a quarter leaves half the
pool for the clients that are not waiting on any of this.

Well above what a healthy upstream needs, which is the case that decides whether
the fraction is too small: a refresh against a resolver that is answering is
over in milliseconds, so the slots turn over hundreds of times a second and a
query finds one free. It is the unhealthy case that holds them, and holding
fewer of them is the point.

Never zero, so a single-worker pool still refreshes one name at a time rather
than serving expired data for as long as the entry is kept.

`ponytail: a flat fraction of the workers. A figure worth deriving from the
upstream timeout and the deadline - how many refreshes one worker retires per
second - only once somebody has a pool this starves.`
*/
@(private)
refresh_ceiling :: proc(s: ^Server) -> int {
	return clamp(pool.worker_count(s.handler_pool) / 4, 1, REFRESH_SLOTS)
}

/*
Start a refresh for `key`, or report that this query is not the one to run it.

Nil is returned for every reason a client should stop waiting and take the
expired bytes it is holding: a refresh for this key is already running, the
ceiling is reached, the pool has no room for the job or is shutting down, or
there is no pool at all - which is a `Server` built as a literal, where the
only honest thing left to do is what this server did before the timer existed.

The caller owns the reference that comes back and releases it with
`refresh_release`, whether or not it waited for the answer.
*/
@(private)
start_refresh :: proc(
	s: ^Server,
	key: string,
	query: []u8,
	proto: Protocol,
	client: string,
	limit: int,
	started: time.Time,
) -> ^Refresh {
	if s.handler_pool == nil {
		return nil
	}
	ceiling := refresh_ceiling(s)

	sync.mutex_lock(&s.refreshes.mu)
	free_slot := -1
	live := 0
	for i in 0 ..< REFRESH_SLOTS {
		held := s.refreshes.slots[i]
		if held == nil {
			if free_slot < 0 {
				free_slot = i
			}
			continue
		}
		live += 1
		// Already being refreshed. The keys are the cache's own, so this is the
		// same question with the same DO and CD bits and nothing else.
		if held.key == key {
			sync.mutex_unlock(&s.refreshes.mu)
			return nil
		}
	}
	if free_slot < 0 || live >= ceiling {
		sync.mutex_unlock(&s.refreshes.mu)
		return nil
	}

	r := new(Refresh)
	r.allocator = context.allocator
	r.key = strings.clone(key, r.allocator)
	r.query = make([]u8, len(query), r.allocator)
	copy(r.query, query)
	r.client = strings.clone(client, r.allocator)
	r.server = s
	r.proto = proto
	r.limit = limit
	r.started = started
	// The waiter's, the table's and the job's, taken before the job can run.
	r.refs = 3
	s.refreshes.slots[free_slot] = r
	sync.mutex_unlock(&s.refreshes.mu)

	if pool.try_submit(s.handler_pool, refresh_job, r, s.cfg.server.max_pending) != .Accepted {
		/*
		The backlog is full or the pool is stopping, so nothing will run this.
		The table's reference, the job's and the caller's all go here - the
		caller is handed nil and has nothing left to release.
		*/
		release_slot(s, r)
		refresh_release(r)
		refresh_release(r)
		return nil
	}
	return r
}

// Take this refresh out of the table, so the next query for the name starts a
// new one, and let go of the reference the table held.
@(private)
release_slot :: proc(s: ^Server, r: ^Refresh) {
	sync.mutex_lock(&s.refreshes.mu)
	for i in 0 ..< REFRESH_SLOTS {
		if s.refreshes.slots[i] == r {
			s.refreshes.slots[i] = nil
			break
		}
	}
	sync.mutex_unlock(&s.refreshes.mu)
	refresh_release(r)
}

@(private)
refresh_release :: proc(r: ^Refresh) {
	sync.mutex_lock(&r.mu)
	r.refs -= 1
	last := r.refs == 0
	sync.mutex_unlock(&r.mu)
	if !last {
		return
	}
	// Read out before the struct holding it is freed.
	allocator := r.allocator
	delete(r.key, allocator)
	delete(r.query, allocator)
	delete(r.client, allocator)
	if r.response != nil {
		delete(r.response, allocator)
	}
	free(r, allocator)
}

/*
Wait out the client response timer, and take the refresh's answer if it beat it.

`taken` is false wherever the client is better served by the expired bytes it is
holding: the timer fired with the refresh still running, or the refresh finished
having got nothing at all out of the upstream. Everything else the refresh
reached is this client's answer, including the refusals - a Bogus verdict, an
unreadable answer - which are decisions this server made rather than outages,
and which the fallback has never covered.

The bytes are copied into the caller's arena. What is behind them belongs to the
refresh, which may still be the only thing keeping itself alive by the time this
returns.
*/
@(private)
refresh_take :: proc(
	r: ^Refresh,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	outcome: Outcome,
	taken: bool,
) {
	sync.mutex_lock(&r.mu)
	finished := r.done
	sync.mutex_unlock(&r.mu)
	if !finished {
		finished = sync.sema_wait_with_timeout(&r.sema, timeout)
	}
	if !finished {
		return nil, .Failed, false
	}

	sync.mutex_lock(&r.mu)
	defer sync.mutex_unlock(&r.mu)
	if !r.ok || r.unanswered || len(r.response) == 0 {
		return nil, .Failed, false
	}
	out := make([]u8, len(r.response), allocator)
	copy(out, r.response)
	return out, r.outcome, true
}

@(private)
refresh_job :: proc(data: rawptr) {
	r := cast(^Refresh)data
	/*
	The same arena discipline as `udp_job` and `race_worker`: a pool worker runs
	for the life of the process, every decode below takes scratch out of this
	thread's arena, and the arena chains a new block rather than reusing the old
	one. The answer is copied onto the heap before this runs, since the waiter
	may read it after the frame this was built in is gone.
	*/
	defer {
		finish_refresh(r)
		free_all(context.temp_allocator)
	}

	s := r.server
	/*
	Decoded again rather than handed over. `dns.Message` is a tree of slices
	into the arena the client's request owns, which is released as soon as that
	request has been answered - and the timer firing is exactly the case where
	that happens while this is still running. The bytes are this refresh's own,
	so the reading taken from them is too.
	*/
	spent: int
	msg, derr := dns.decode_message(r.query, context.temp_allocator, &spent)
	if derr != .None || msg.flags.qr || len(msg.question) != 1 {
		return
	}
	/*
	And the cookie is inspected again, against the same client address and the
	same bytes, so a server with `cookies.required` on reaches the same verdict
	here that it reached for the client. Carrying the verdict over instead would
	be a value read on one thread and used on another for no gain; this is a
	hash of eight bytes.
	*/
	cookie := inspect_cookie(s.cookies, msg, r.client)

	unanswered: bool
	resp, outcome, ok := resolve_query(
		s,
		r.query,
		msg,
		r.proto,
		r.client,
		r.limit,
		cookie,
		r.started,
		&spent,
		context.temp_allocator,
		true,
		&unanswered,
	)

	heap: []u8
	if ok && len(resp) > 0 {
		heap = make([]u8, len(resp), r.allocator)
		copy(heap, resp)
	}
	sync.mutex_lock(&r.mu)
	r.response = heap
	r.outcome = outcome
	r.ok = ok
	r.unanswered = unanswered
	sync.mutex_unlock(&r.mu)
}

/*
Publish the result and stand down.

The slot goes first, so that the next query for this name starts a refresh of
its own rather than joining one that has already finished. The job's own
reference is released last, after the post: it is what guarantees there is still
a `Refresh` to post to, since the waiter may have timed out and let go of its
own reference at any point.
*/
@(private)
finish_refresh :: proc(r: ^Refresh) {
	release_slot(r.server, r)
	sync.mutex_lock(&r.mu)
	r.done = true
	sync.mutex_unlock(&r.mu)
	sync.sema_post(&r.sema)
	refresh_release(r)
}
