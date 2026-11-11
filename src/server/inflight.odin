package server

import "core:crypto"
import "core:crypto/siphash"
import "core:mem"
import "core:sync"
import "core:time"
import "elodin:loop"

/*
Identical questions in flight at once go to the upstream once (issue #311).

The first query to miss the cache for a key leads: it registers a `Flight` here
and forwards as any miss does. A query that misses for the same key while the
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
message is the leader's, byte for byte bar the ID. `upstream_query` builds that
message from the key and nothing of the client's (issue #423), so it is every
follower bar one whose query was shaped under different settings - a reload
between the two that changed whether the question is validated: the validator,
a trust anchor, an `upstream.zones` route or the special-use table. A follower
given a failure takes the expired entry or SERVFAIL as the leader did, rather
than wait a second full exchange for the same nothing, which
in an outage is every query in flight held twice as long.

A follower that cannot use what the leader landed with forwards on its own, which
is what every query does without coalescing - except where the leader stored a verdict
(a Bogus refusal, a cloaking refusal worth keeping), when it reads that verdict
straight out of the cache and is refused from it - or, for a cloaking refusal a
list reload lifted during the wait, answered from it. The cloaking lookup is a
counted one, so that follower's query shows as a miss and then a hit, or as two
misses where the entry was evicted in between, and once more for a follower
that goes round (below); the Bogus one is a probe, as it is on the way in, and
counts nothing. A follower whose
patience ran out forwards on its own too - on a deadline that is spent by then,
so it asks nobody and takes the expired entry or SERVFAIL (see
`flight_patience`). One that finds the verdict already evicted or expired joins
the table once more, so the burst leads and follows a second exchange between
them (issue #428); a second verdict gone as fast, and it forwards on its own.

The leader waits for its followers to take their copies before it lets go, which
is what lets the `Flight` live in its stack frame and the answer in its scratch:
nothing here is allocated, and a `Server` built as a literal needs nothing
initialised. The frame is on the leader's fiber, whose stack stays mapped while
it waits, so a follower on another loop reads it as one on the same loop does.

No deadlock: a fiber leads at most one flight - the rewrite chase and the stale
refresh, the only nested `resolve_query` calls, both start from a query that
returned before it could join - and a leader waits on nothing a follower holds.
*/

/*
Distinct questions that can be coalesced at once, and how far from its hash a
key may sit.

A key lives in the `INFLIGHT_PROBE` slots from where its hash points, so a join
or a land looks at that many and no more, however full the table, under the
lock every miss takes. The slots are far more than the few hundred distinct
misses a 20 ms upstream keeps in flight at tens of thousands of misses a second,
so each of them is coalesced (#612). The hash is SipHash keyed from the entropy
source at first use, as the cache's shards are, so a client cannot choose names
that crowd one window; a miss that finds its window full forwards on its own,
uncoalesced. 4096 slots of a pointer each are 32 KiB per server.
*/
@(private)
INFLIGHT_SLOTS :: 4096
@(private)
INFLIGHT_PROBE :: 16

@(private)
Inflight_Table :: struct {
	mu:        sync.Mutex,
	slots:     [INFLIGHT_SLOTS]^Flight,
	// The SipHash key for `slots`, drawn at the first join; see `flight_home`.
	seed:      [16]u8,
	seeded:    sync.Once,
	// Followers waiting on a leader; see `follower_ceiling`.
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
	// The leader's own key, in its request's arena, which outlives the flight:
	// the leader lands before `resolve_query` returns, and the arena is dropped
	// only after the answer is written.
	key:           string,
	cond:          loop.Cond,
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
How many followers counted in `server.max_pending` may wait on leaders at once:
a quarter of it, the share `refresh_ceiling` gives the stale refreshes.

A follower holds its place in flight for as long as the leader takes, up to its
`flight_patience`, about four of its longest group's timeouts, twice over for
one that goes round after an evicted verdict (issue #428) - and a leader
validating a slow chain holds one of `dnssec.max_chain_walks` - so without a
ceiling, one flood of a single cold signed name would park everything in flight
behind one walk, which is the exhaustion that bound exists to prevent (issue
#356). Past the ceiling a query forwards on its own and meets that bound like
any other. Queries answered on a connection's fiber are not counted:
`max_connections` bounds them, one at a time per connection, and a share of
`max_pending` that they could fill would leave the datagrams for a hot name to
forward on their own. No bound - a `Server` built as a literal - is no ceiling.
*/
@(private)
follower_ceiling :: proc(s: ^Server) -> int {
	limit := live(s).cfg.server.max_pending
	if limit <= 0 {
		return 0
	}
	return max(limit / 4, 1)
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
once patience runs out, finds the deadline spent and asks nobody.
*/
@(private)
flight_patience :: proc(deadline: time.Tick, span: time.Duration) -> time.Duration {
	return max(time.tick_diff(loop.tick_now(), deadline), 0) + span
}

/*
Join the flight for `key`, leading it if there is none.

`own` back: the caller leads, and must `flight_land` it. Another flight: the
caller follows, and must `flight_follow` it, passing back `counted`. Nil: the
key's window is full, or `counted_query` and the followers counted in `max_pending` are
at `ceiling` (zero is none), and the caller forwards on its own.
*/
@(private)
flight_join :: proc(
	s: ^Server,
	key: string,
	own: ^Flight,
	// Whether the caller is a query counted against `max_pending`; see `follower_ceiling`.
	counted_query := false,
	ceiling := 0,
) -> (
	flight: ^Flight,
	counted: bool,
) {
	home := flight_home(&s.inflight, key)
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	free_slot := -1
	// The whole window, holes and all: a land leaves a hole wherever its flight sat.
	for probe in 0 ..< INFLIGHT_PROBE {
		i := (home + probe) % INFLIGHT_SLOTS
		f := s.inflight.slots[i]
		if f == nil {
			if free_slot < 0 {
				free_slot = i
			}
		} else if f.key == key {
			if counted_query && ceiling > 0 {
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
Where `key`'s window starts. Hashed outside the lock every miss takes; the seed
is drawn once, at the first join, so a `Server` built as a literal needs nothing
initialised.
*/
@(private)
flight_home :: proc(t: ^Inflight_Table, key: string) -> int {
	sync.once_do(&t.seeded, proc(data: rawptr) {
		seed := (^[16]u8)(data)
		crypto.rand_bytes(seed[:])
	}, &t.seed)
	return int(siphash.sum_bytes_2_4(transmute([]u8)key, t.seed[:]) % INFLIGHT_SLOTS)
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
	start := loop.tick_now()
	for !f.landed {
		left := patience - loop.tick_since(start)
		if left <= 0 {
			break
		}
		_ = loop.cond_wait_with_timeout(&f.cond, &s.inflight.mu, left)
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
		loop.cond_signal(&f.cond)
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
	loop.cond_broadcast(&f.cond)
	for f.waiters > 0 {
		loop.cond_wait(&f.cond, &s.inflight.mu)
	}
}
