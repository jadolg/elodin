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

A NOERROR or NXDOMAIN answer is shared with every follower, which is what the
cache does with one. What else the leader lands with - any other rcode, or the
upstream giving it nothing after `upstream.attempts` rounds over every server,
where a lost datagram is retried - is shared only between queries that are both
`canonical`: whose outgoing messages are the same bytes bar the ID, so that what
came back is about the question rather than about one client's message. A
follower given a failure takes the expired entry or SERVFAIL as the leader did,
rather than wait a second full exchange for the same nothing, which in an outage
is every pool worker held twice as long.

A follower that cannot use what the leader landed with forwards on its own, which
is what every query did before this - except where the leader stored a verdict
(a Bogus refusal, a cloaking refusal worth keeping), when it goes back once to the
start and finds that verdict in the cache. A cache miss counted on the first pass
is counted again on the second, which leaves `cache_misses` a little ahead of the
queries behind it - the one accounting gap here, on the rare path. So does a
follower whose patience ran out.

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
	// The leader's message is `canonical`.
	canonical: bool,
	// The answer as the cache would have stored it, in the leader's arena, or in
	// the follower's once copied. Nil when the leader forwarded nothing.
	answer:    []u8,
	ede:       u16,
	// The upstream produced nothing at all.
	failed:    bool,
	// The leader stored a verdict a follower starting over will find.
	stored:    bool,
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

/*
Whether this query's outgoing message is the one this server would build for
its key and nothing else: the question, RD, the client's AD, CD, and an OPT
record at `UPSTREAM_UDP_SIZE` carrying DO and no options.

Compared as bytes, bar the ID, with a message built here, rather than by
inspecting the fields that can differ: everything the forwarding path leaves as
the client wrote it - records beside the question, EDNS options, header bits,
OPT flags, a payload size below the clamp, no OPT at all, bytes past the last
record - is then a difference without having to be named. `validating` says the
DNSSEC rewrite ran, which sets CD and DO whatever the client asked.
*/
@(private)
canonical :: proc(msg: dns.Message, forwarded: []u8, validating: bool, allocator: mem.Allocator) -> bool {
	if len(msg.question) != 1 || len(forwarded) < dns.HEADER_SIZE {
		return false
	}
	ref := dns.Message {
		question   = msg.question,
		additional = []dns.Record{dns.make_opt(UPSTREAM_UDP_SIZE, validating || dns.edns_do(msg))},
	}
	ref.flags.rd = true
	ref.flags.ad = msg.flags.ad
	ref.flags.cd = validating || msg.flags.cd
	wire, _, err := dns.encode_message(ref, allocator)
	if err != .None || len(wire) != len(forwarded) {
		return false
	}
	return string(wire[2:]) == string(forwarded[2:])
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
empty. The answer is copied into this request's arena, since the leader's goes
the moment the last follower leaves.
*/
@(private)
flight_follow :: proc(
	s: ^Server,
	f: ^Flight,
	patience: time.Duration,
	allocator: mem.Allocator,
	counted := false,
) -> (
	result: Landing,
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
