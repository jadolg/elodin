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

What else the leader lands with is shared only when it is about the question
rather than about the leader's own message, and that turns on whether the leader
was `canonical`: whether what it sent upstream is, byte for byte bar the ID, what
any follower would have sent. Then a failure after `upstream.attempts` rounds
over every server - where a lost datagram is retried - is the upstream's, and
its followers take the expired entry or SERVFAIL as the leader did, rather than
each wait a second full exchange for the same nothing, which in an outage is
every pool worker held twice as long. A FORMERR from it is an answer like any
other. A leader that was not canonical - no OPT record, a smaller payload size, an
option of the client's own forwarded, records beside the question - may have
failed over its own bytes, so its followers start over instead.

Starting over is once, and it is back to the start: to the cache, and to this
table, where one of them leads the next exchange for the rest. It is also what a
follower does when the leader stored a verdict - a Bogus refusal, a cloaking
refusal worth keeping - since the cache now holds the answer to give it. A
refusal nothing remembers (a rebinding refusal, an unreadable reply) would only
be reached again, so a follower of one forwards on its own at once, which is what
every query did before this; so does one whose patience ran out, and one landing
with nothing on its second pass. A cache miss counted on the first pass is
counted again on the second, which leaves `cache_misses` a little ahead of the
queries behind it - the one accounting gap here, on the rare path.

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
The flight, and what its leader landed with.

The result fields are the leader's alone until it lands: it writes them without
the lock, and a follower reads them only once it has seen `landed` under the
lock `flight_land` set it under.
*/
@(private)
Flight :: struct {
	// The leader's own key, which outlives the flight: the leader lands before
	// its frame goes.
	key:       string,
	cond:      sync.Cond,
	waiters:   int,
	landed:    bool,
	// Where this flight sits in the table, so landing need not look for it.
	slot:      int,
	// The leader's message is the one any follower would have sent; see
	// `canonical`.
	canonical: bool,
	// The answer as the cache would have stored it, in the leader's arena. Nil
	// when the leader forwarded nothing it could share.
	answer:    []u8,
	ede:       u16,
	// The upstream produced nothing at all.
	failed:    bool,
	// The leader stored a verdict a follower starting over will find.
	stored:    bool,
}

/*
Whether what this query sends upstream is what any identical one would.

The forwarding path makes most of the outgoing message this server's own - the
ID, the extended rcode, the cookie, subnet and keepalive options - and clamps
the payload size to `UPSTREAM_UDP_SIZE`. What it leaves is the client's: records
beside the question, every other EDNS option, and a payload size below the
clamp, or no OPT record at all, either of which turns a mid-sized answer into a
truncated one retried over TCP. So canonical is none of those.
*/
@(private)
canonical :: proc(msg: dns.Message, query: []u8) -> bool {
	if len(msg.answer) > 0 || len(msg.authority) > 0 || len(msg.additional) != 1 {
		return false
	}
	opt := msg.additional[0]
	if opt.type != .OPT || dns.peek_udp_size(query) < UPSTREAM_UDP_SIZE {
		return false
	}
	if data, is_opt := opt.data.(dns.Rdata_OPT); is_opt {
		for o in data.options {
			#partial switch dns.EDNS_Option_Code(o.code) {
			case .Cookie, .Client_Subnet, .TCP_Keepalive:
			case:
				return false
			}
		}
	}
	return true
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

`leading` true: the caller owns `flight` and must `flight_land` it. `leading`
false with a flight: the caller is a follower and must `flight_follow` it,
passing back `counted`. Nil: the table is full, or `shared` and the followers on
the shared pool are at `ceiling` (zero is none), and the caller forwards on its
own.
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
					return nil, false, false
				}
				s.inflight.followers += 1
				counted = true
			}
			f.waiters += 1
			return f, false, counted
		}
	}
	if free_slot < 0 {
		return nil, false, false
	}
	own^ = Flight {
		key  = key,
		slot = free_slot,
	}
	s.inflight.slots[free_slot] = own
	return own, true, false
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
	result: Flight,
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
		result.canonical, result.answer, result.ede = f.canonical, f.answer, f.ede
		result.failed, result.stored = f.failed, f.stored
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
