package server

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:pool"
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

Only a query shaped like a question leads or follows: nothing in the answer or
authority sections and nothing in the additional one but its OPT record - see
`coalescable`. Every other part of the message the upstream reads is this
server's own by then (the ID, the payload size, the options it strips), so the
exchange a leader makes is the one any follower would have made, and what comes
back from it is about the question rather than about one client's bytes.

That is what lets a failure be shared. A leader the upstream gave nothing - after
`upstream.attempts` rounds over every server, which is where a lost datagram is
retried - leaves its followers the expired entry or SERVFAIL, as it has itself:
the same exchange again would cost each of them a second full wait for the same
nothing, which in an outage is every pool worker held twice as long.

A leader that got an answer it could not share - a Bogus verdict, a rebinding or
cloaking refusal, an unreadable reply, a FORMERR - sends its followers back once
to the start: to the cache, where a refusal the leader remembered is now found,
and to this table, where one of them leads the next exchange for the rest.
After a second such landing, or when patience runs out, a follower forwards on
its own, which is what every query did before this.

A cache lookup counted as a miss is counted again on that second pass, which
leaves `cache_misses` a little ahead of the queries behind it after a refusal.
That is the one accounting gap here, and it is the rare path's.

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
	mu:        sync.Mutex,
	slots:     [INFLIGHT_SLOTS]^Flight,
	// Followers waiting on a worker of the shared pool; see `follower_ceiling`.
	followers: int,
}

/*
Whether this query may lead or follow a flight: nothing in it that the upstream
reads beyond the question and an OPT record. A client's own records in the
answer, authority or additional sections are forwarded as they stand, and an
upstream may refuse or drop such a message - which must be that client's
failure alone, not the answer every identical question waiting on it is given.
*/
@(private)
coalescable :: proc(msg: dns.Message) -> bool {
	if len(msg.answer) > 0 || len(msg.authority) > 0 || len(msg.additional) > 1 {
		return false
	}
	return len(msg.additional) == 0 || msg.additional[0].type == .OPT
}

/*
How many followers may wait on workers of the shared pool at once: a quarter,
the same share `refresh_ceiling` gives the stale refreshes.

A follower holds its worker for as long as the leader takes, and a leader
validating a slow chain holds one of `dnssec.max_chain_walks` - so without a
ceiling, one flood of a single cold signed name would park every worker behind
one walk, which is the exhaustion that bound exists to prevent (issue #356).
Past the ceiling a query forwards on its own and meets that bound like any
other. Queries on a connection's own thread are bounded by `max_connections`
instead, and are not counted. No pool - a `Server` built as a literal - is no
ceiling.
*/
@(private)
follower_ceiling :: proc(s: ^Server) -> int {
	if s.handler_pool == nil {
		return 0
	}
	return max(pool.worker_count(s.handler_pool) / 4, 1)
}

// Every field is guarded by `Inflight_Table.mu`.
@(private)
Flight :: struct {
	// The leader's own key, which outlives the flight: the leader lands before
	// its frame goes.
	key:     string,
	cond:    sync.Cond,
	waiters: int,
	landed:  bool,
	// The answer as the cache would have stored it, in the leader's arena. Nil
	// when the leader forwarded nothing it could share.
	answer:  []u8,
	ede:     u16,
	// The upstream produced nothing at all.
	failed:  bool,
	// Where this flight sits in the table, so landing need not look for it.
	slot:    int,
}

/*
How long a follower waits before it forwards on its own: what the leader's
exchange can take, every server for every attempt - twice, for a UDP reply that
comes back truncated and is asked again over TCP with a timeout of its own - plus
the readable-rcode sweep's two timeouts. A leader past that is validating a long
chain or stuck, and either way this query is no worse off asking for itself.
*/
@(private)
flight_patience :: proc(g: ^upstream.Group) -> time.Duration {
	if g == nil {
		return 0
	}
	return time.Duration(2 * g.attempts * len(g.servers) + 2) * g.timeout
}

/*
Join the flight for `key`, leading it if there is none.

`leading` true: the caller owns `flight` and must `flight_land` it. `leading`
false with a flight: the caller is a follower and must `flight_follow` it, with
the same `shared`. Nil: the table is full, or `shared` and the followers on the
shared pool are at `ceiling` (zero is none), and the caller forwards on its own.
*/
@(private)
flight_join :: proc(
	s: ^Server,
	key: string,
	own: ^Flight,
	shared := false,
	ceiling := 0,
) -> (
	flight: ^Flight,
	leading: bool,
) {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	free_slot := -1
	for f, i in s.inflight.slots {
		if f == nil {
			if free_slot < 0 {
				free_slot = i
			}
		} else if f.key == key {
			if shared && ceiling > 0 {
				if s.inflight.followers >= ceiling {
					return nil, false
				}
				s.inflight.followers += 1
			}
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
	// As given to `flight_join`, so the follower comes off the count it went on.
	shared := false,
	ceiling := 0,
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
	landed_with := f.answer if f.landed else nil
	ede, failed, landed = f.ede, f.failed, f.landed
	sync.mutex_unlock(&s.inflight.mu)

	// Copied outside the lock, which every miss on the server takes: the bytes
	// cannot change while this follower is still counted, since the leader waits
	// for the count to reach zero before it lets them go.
	if landed_with != nil {
		answer = make([]u8, len(landed_with), allocator)
		copy(answer, landed_with)
	}

	sync.mutex_lock(&s.inflight.mu)
	if shared && ceiling > 0 {
		s.inflight.followers -= 1
	}
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
