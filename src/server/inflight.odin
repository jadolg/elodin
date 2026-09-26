package server

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:upstream"

/*
Identical questions in flight at once go to the upstream once (issue #311).

The first query to miss the cache for a key leads: it registers a `Flight` here
and forwards as it always did. A query that misses for the same key while the
leader is still out follows: it waits for the leader to land and is served the
leader's answer through `serve_from_cache`, exactly as it would have been had it
arrived a moment later and found that answer stored. The key is the cache's own,
so anything the cache would share between two clients this shares, and nothing
else - which is also why an answer the cache declines to keep (a zero TTL, a
routed apex `DS` nobody proved) is shared: it is the same answer to the same
question, produced for a query that was waiting alongside this one.

What a follower does when the leader lands without an answer - the upstream
produced nothing, the leader refused what came back (a Bogus verdict, a
rebinding or cloaking refusal, an unreadable reply), or the upstream answered
FORMERR to the leader's message - is start over once: back to the cache, where a
refusal the leader remembered is now found, and back to this table, where one of
the followers leads the next exchange and the rest wait on it. Once, because
what the leader got may be about the leader alone - its datagram lost, or its
message carrying records of the client's own that the upstream would not read -
and a second exchange settles that; a second failure is the upstream's, and the
follower takes its expired entry or SERVFAIL, or forwards its own question after
a refusal, which is what every query did before this. A follower that runs out
of patience forwards on its own too.

The leader waits for its followers to take their copies before it lets go, which
is what lets the `Flight` live in its stack frame and the answer in its arena:
nothing here is allocated, and a `Server` built as a literal needs nothing
initialised.

No deadlock: a thread leads at most one flight - the rewrite chase and the stale
refresh, the only nested `resolve_query` calls, both start from a query that
returned before it could join - and a leader waits on nothing a follower holds.
*/

/*
Distinct questions that can be coalesced at once. A miss that finds the table
full forwards without joining it, which is what it did before there was a table.

`ponytail: a fixed array scanned under one lock. A hash map once a box forwards
more distinct misses at once than this.`
*/
@(private)
INFLIGHT_SLOTS :: 256

@(private)
Inflight_Table :: struct {
	mu:    sync.Mutex,
	slots: [INFLIGHT_SLOTS]^Flight,
}

// Every field is guarded by `Inflight_Table.mu`.
@(private)
Flight :: struct {
	// The leader's own key, which outlives the flight: the leader lands before
	// its frame goes.
	key:      string,
	cond:     sync.Cond,
	waiters:  int,
	landed:   bool,
	// The answer as the cache would have stored it, in the leader's arena. Nil
	// when the leader forwarded nothing it could share.
	answer:   []u8,
	ede:      u16,
	// The upstream produced nothing at all.
	failed:   bool,
	// Where this flight sits in the table, so landing need not look for it.
	slot:     int,
}

/*
How long a follower waits before it forwards on its own: what the leader's
exchange can take, every server for every attempt plus the readable-rcode
sweep's two timeouts. A leader past that is validating a long chain or stuck,
and either way this query is no worse off asking for itself.
*/
@(private)
flight_patience :: proc(g: ^upstream.Group) -> time.Duration {
	if g == nil {
		return 0
	}
	return time.Duration(g.attempts * len(g.servers) + 2) * g.timeout
}

/*
Join the flight for `key`, leading it if there is none.

`leading` true: the caller owns `flight` and must `flight_land` it. `leading`
false with a flight: the caller is a follower and must `flight_follow` it. Nil:
the table is full, and the caller forwards on its own.
*/
@(private)
flight_join :: proc(s: ^Server, key: string, own: ^Flight) -> (flight: ^Flight, leading: bool) {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	free_slot := -1
	for f, i in s.inflight.slots {
		if f == nil {
			if free_slot < 0 {
				free_slot = i
			}
		} else if f.key == key {
			f.waiters += 1
			return f, false
		}
	}
	if free_slot < 0 {
		return nil, false
	}
	own^ = Flight {
		key  = key,
		slot = free_slot,
	}
	s.inflight.slots[free_slot] = own
	return own, true
}

/*
Wait for the leader, and take a copy of what it landed with.

`landed` false means patience ran out first. The answer is copied into this
request's arena, since the leader's goes the moment the last follower leaves.
*/
@(private)
flight_follow :: proc(
	s: ^Server,
	f: ^Flight,
	patience: time.Duration,
	allocator: mem.Allocator,
) -> (
	answer: []u8,
	ede: u16,
	failed: bool,
	landed: bool,
) {
	sync.mutex_lock(&s.inflight.mu)
	start := time.tick_now()
	for !f.landed {
		left := patience - time.tick_since(start)
		if left <= 0 {
			break
		}
		_ = sync.cond_wait_with_timeout(&f.cond, &s.inflight.mu, left)
	}
	shared := f.answer if f.landed else nil
	ede, failed, landed = f.ede, f.failed, f.landed
	sync.mutex_unlock(&s.inflight.mu)

	// Copied outside the lock, which every miss on the server takes: the bytes
	// cannot change while this follower is still counted, since the leader waits
	// for the count to reach zero before it lets them go.
	if shared != nil {
		answer = make([]u8, len(shared), allocator)
		copy(answer, shared)
	}

	sync.mutex_lock(&s.inflight.mu)
	f.waiters -= 1
	// The leader may be waiting for this one to leave.
	sync.cond_broadcast(&f.cond)
	sync.mutex_unlock(&s.inflight.mu)
	return
}

/*
Offer the answer this leader is about to serve to whoever is waiting.

`answer` must stay as it is until the leader lands, so the leader lands before
it writes into it again.
*/
@(private)
flight_share :: proc(s: ^Server, f: ^Flight, answer: []u8, ede: u16) {
	sync.mutex_lock(&s.inflight.mu)
	f.answer, f.ede = answer, ede
	sync.mutex_unlock(&s.inflight.mu)
}

@(private)
flight_failed :: proc(s: ^Server, f: ^Flight) {
	sync.mutex_lock(&s.inflight.mu)
	f.failed = true
	sync.mutex_unlock(&s.inflight.mu)
}

/*
Take the flight out of the table, wake its followers, and wait until every one
has taken its copy - the flight and the answer both belong to the caller's frame.
*/
@(private)
flight_land :: proc(s: ^Server, f: ^Flight) {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	s.inflight.slots[f.slot] = nil
	f.landed = true
	sync.cond_broadcast(&f.cond)
	for f.waiters > 0 {
		sync.cond_wait(&f.cond, &s.inflight.mu)
	}
}
