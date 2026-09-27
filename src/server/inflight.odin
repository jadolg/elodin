package server

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:pool"

/*
Identical questions in flight at once go to the upstream once (issue #311).

The first query to miss the cache for a key leads: it registers a `Flight` here
and forwards as it always did. A query that misses for the same key while the
leader is still out follows: it waits for the leader to land and is served the
leader's answer through `serve_from_cache`, as it would have been had it arrived
a moment later and found that answer stored - bar `cache.min_ttl`, which is
applied to a stored copy on the way out and so not to this one. The key is the cache's own,
so anything the cache would share between two clients this shares, and nothing
else - which is also why an answer the cache declines to keep (a zero TTL, a
routed apex `DS` nobody proved) is shared: it is the same answer to the same
question, produced for a query that was waiting alongside this one.

A NOERROR or NXDOMAIN answer is shared with every follower, which is what the
cache does with one - and so, with the cache off, only as the rest below is. What else the leader lands with - any other rcode, or the
upstream giving it nothing after `upstream.attempts` rounds over every server,
where a lost datagram is retried - is shared only with a follower whose outgoing
message is the leader's, byte for byte bar the ID, so that what came back is
about that message rather than about one client's spelling of it. Under the
DNSSEC rewrite, which writes the whole OPT record, that is most of them; without
it the payload size and the OPT flags stay the client's, so it is the clients
that ask alike. A follower given a failure takes the expired entry or SERVFAIL as the
leader did, rather than wait a second full exchange for the same nothing, which
in an outage is every pool worker held twice as long.

A follower that cannot use what the leader landed with forwards on its own, which
is what every query did before this - except where the leader stored a verdict
(a Bogus refusal, a cloaking refusal worth keeping), when it reads that verdict
straight out of the cache and is refused from it - or, for a cloaking refusal a
list reload lifted during the wait, answered from it. The cloaking lookup is a
counted one, so that follower's query shows as a miss and then a hit, or as two
misses where the entry was evicted in between; the Bogus one is a probe, as it
is on the way in, and counts nothing. A follower whose
patience ran out forwards on its own too - on a deadline that is spent by then,
so it asks nobody and takes the expired entry or SERVFAIL (see
`flight_patience`) - and so does one that finds the
verdict already evicted - outside the table, since it is past its turn to join
one, which on a cache under that much pressure costs a burst its coalescing.

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
What a leader lands with, and a follower is handed.

Written by the leader without the lock, into its own flight: a follower reads it
only once it has seen `landed` under the lock `flight_land` set it under.
*/
@(private)
Landing :: struct {
	// What the leader sent upstream, in its arena, for a follower to hold its
	// own against.
	forwarded: []u8,
	// The answer as the cache would have stored it, in the leader's arena, or in
	// the follower's once copied. Nil when the leader forwarded nothing.
	answer:    []u8,
	ede:       u16,
	// The upstream produced nothing at all.
	failed:    bool,
	// Which verdict the leader stored, for a follower to read straight out of
	// the cache.
	stored:    Stored_Verdict,
}

@(private)
Flight :: struct {
	// The leader's own key, which outlives the flight: the leader lands before
	// its frame goes.
	key:           string,
	cond:          sync.Cond,
	waiters:       int,
	landed:        bool,
	// Where this flight sits in the table, so landing need not look for it.
	slot:          int,
	using landing: Landing,
}

@(private)
Stored_Verdict :: enum u8 {
	None,
	// A cloaking refusal, under the question's own key.
	Cloak,
	// A Bogus refusal, under the question's verdict key.
	Bogus,
}

/*
How many followers may wait on workers of the shared pool at once: a quarter,
the same share `refresh_ceiling` gives the stale refreshes.

A follower holds its worker for as long as the leader takes, up to its
`flight_patience`, about four of its longest group's timeouts - and a leader
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

/*
How long a follower waits before it forwards on its own: what is left of its
own upstream deadline, and one `span` more (issue #446).

The deadline is armed before the join, and the leader's before this one's, so
the leader has spent its upstream wait by then - all but the one exchange it may
still finish, and what it does after it, which is the `span` on top: two
timeouts of the longest-timed of the question's groups (`question_span`,
`upstream.query_budget`), since the leader's last exchange may be a chain lookup
on the default group rather than the route. One is that exchange, which
`upstream.exchange` holds to one timeout whatever it does inside - bootstrap
resolution, a cookie retry, a truncated reply's retry over TCP (issue #449). The
other is slack for the leader's own work after it, decoding, validating and
storing, which no deadline covers. A leader past that is validating a long
chain or stuck, and the follower gains nothing by waiting on: its own forward,
once patience runs out, finds the deadline spent and asks nobody. The old
figure - every server for every attempt, twice for a truncated reply, plus the
sweep - was sized for a forward nothing bounded, and held a worker ten timeouts
for a group of two.
*/
@(private)
flight_patience :: proc(deadline: time.Tick, span: time.Duration) -> time.Duration {
	return max(time.tick_diff(time.tick_now(), deadline), 0) + span
}

/*
Join the flight for `key`, leading it if there is none.

`own` back: the caller leads, and must `flight_land` it. Another flight: the
caller follows, and must `flight_follow` it, passing back `counted`. Nil: the
table is full, or `shared` and the followers on the shared pool are at `ceiling`
(zero is none), and the caller forwards on its own.
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
	counted: bool,
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
				counted = true
			}
			f.waiters += 1
			return f, counted
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
	return own, false
}

/*
Wait for the leader, and take a copy of what it landed with.

`landed` false means patience ran out first, and the rest of the result is then
empty. `same` says `forwarded`, this follower's outgoing message, is the
leader's bar the ID. The answer is copied into this request's arena, and the
comparison made, before this follower leaves: the leader's bytes go the moment
the last follower does.
*/
@(private)
flight_follow :: proc(
	s: ^Server,
	f: ^Flight,
	patience: time.Duration,
	allocator: mem.Allocator,
	counted := false,
	forwarded: []u8 = nil,
) -> (
	result: Landing,
	landed: bool,
	same: bool,
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
	landed = f.landed
	if landed {
		result = f.landing
	}
	sync.mutex_unlock(&s.inflight.mu)

	// Copied outside the lock, which every miss on the server takes: the bytes
	// cannot change while this follower is still counted, since the leader waits
	// for the count to reach zero before it lets them go.
	if result.answer != nil {
		copied := make([]u8, len(result.answer), allocator)
		copy(copied, result.answer)
		result.answer = copied
	}
	leader := result.forwarded
	same =
		len(leader) >= 2 &&
		len(leader) == len(forwarded) &&
		string(leader[2:]) == string(forwarded[2:])
	result.forwarded = nil

	sync.mutex_lock(&s.inflight.mu)
	if counted {
		s.inflight.followers -= 1
	}
	f.waiters -= 1
	// The leader waits for exactly this, and nothing else sleeps on the cond
	// once it has landed.
	if f.landed && f.waiters == 0 {
		sync.cond_signal(&f.cond)
	}
	sync.mutex_unlock(&s.inflight.mu)
	return
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
