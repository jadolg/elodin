package server

import "core:crypto"
import "core:crypto/siphash"
import "core:mem"
import "core:net"
import "core:sync"
import "core:time"
import "elodin:logx"

/*
Response rate limiting.

A datagram carries no proof of where it came from, so an answer sent over UDP
goes wherever the source address said - which is how a resolver becomes an
amplifier. A ~40 byte query with an OPT record advertising 4096 buys the sender
two orders of magnitude of traffic aimed at whoever they named, and DNSSEC and
ANY answers are the usual way to get the most of it.

What bounds that is a limit on how much this server will send *to one place*.
The attacker's own rate is not the thing to measure: they are not the ones
receiving it, and with spoofed sources there is nothing of theirs to measure
anyway. The victim is, and every response in a reflection attack is addressed to
the victim - so a budget kept per destination prefix caps what any one target
can be made to receive, whoever asked for it.

By prefix rather than by address: /24 for IPv4 and /64 for IPv6, since an
attacker spoofing addresses picks them freely within the range they are aiming
at, and a per-address budget would just be spread across it.

Over-limit queries are not all dropped. Every `slip`th one is answered with a
header and a question and the TC bit set, which is 30-odd bytes rather than
4096 - too small to be worth reflecting - and which tells a real client to ask
again over TCP, where the handshake proves the address. A client stuck behind a
busy NAT therefore still resolves, at the cost of a round trip, while a spoofed
source gets a truncated answer it cannot follow up.

This is what BIND's `rate-limit` and Knot's RRL do, and the shape is theirs.

The stream transports - TCP, DoT, DoH - are charged too, for the other half of
what a flood costs. Amplification is not their problem: a handshake settled that
whoever is asking is where they said they were, and no answer goes anywhere else.
What they share with UDP is the work behind an answer, which is the upstream round
trips and the cache churn, and a client pipelining queries down one connection
reaches that as fast as the socket allows. `server.max_connections` bounds how
many clients are here at once, not how fast one of them asks, so without this a
flood delivered over a handful of connections is one the limiter never sees.

Charged to a budget of their own, though. Each prefix has two: datagrams are spent
out of one and connections out of the other, at the same rate, and neither is a
way to spend the other. See `Rate_Class`.

One shared budget is what this began as, and it was wrong - which is worth writing
down, because the argument for sharing is the one that reads better. It goes: what
is bounded is what this server does for one prefix, so a prefix that has spent its
budget on datagrams has spent it, and two budgets are just a way to have twice as
much by asking twice as many ways. What it misses is that the two transports have
different claims on the address the budget is keyed to. The key comes off the
query's source, and over UDP the sender writes that field, so anyone able to send
a datagram can spend any prefix's budget: a spoofed flood naming sources inside
prefix P, at more than `responses_per_second`, keeps P's bucket empty for as long
as it runs. Under one budget every genuine TCP, DoT and DoH connection from P then
has its first query refused and its connection closed - so an attacker who cannot
receive anything at P, and who is asking none of P's questions, decides what this
server does for the clients who actually live there, on a default configuration.
It also shuts the one door the slip exists to open: a truncated answer says come
back over TCP, and coming back over TCP arrived at the budget the flood had
already emptied.

So the two are separated, and the doubling is accepted deliberately. A prefix
willing to ask both ways can draw `responses_per_second` out of each, which is a
factor of two on the work behind an answer - a constant, applied to a figure an
operator chose, and half of it reachable only over a completed handshake from an
address that is therefore real. What the shared budget bought instead was letting
anyone with a raw socket switch off a stranger's TCP.

The property to keep is that neither pool can be spent from the other side: a
change that charges one class against the other's pool, or lends a token across
when the first runs dry, hands the flood back its authority over the connections.
`test_the_stream_budget_is_not_the_datagram_one` is the test that says so, and the
reason it is worth more than it looks.

What differs besides the pool is what an over-limit query is answered with: `slip`
sends a truncated answer over UDP and does not apply to a connection, for the
reason in `stream_rate_check`. So the slip counter belongs to the datagram pool
alone - see `Rate_Bucket.over`.

Which is also what makes the slip's invitation worth accepting. The TCP retry it
asks for is charged to the other pool, so a client sent to TCP by a flood in its
prefix arrives at a budget that flood has not touched. Still a budget: a client
that has emptied the stream pool itself is refused there like anything else, and a
slip says the address is worth proving rather than reserving anything for the
proof. But the retry is no longer answerable only in the gaps a flood leaves.
*/

/*
The table is fixed at construction and never grows.

A cache of buckets that allocated per source would be a memory bound written in
terms of how many distinct addresses an attacker cares to name, which is not a
bound. Sixteen thousand buckets is 640 KB - a bucket carries a budget per transport
class - and more prefixes than a resolver serves; what collides shares a budget,
which is a limit that is too strict on rare occasions rather than a limit that
fails.
*/
@(private)
RRL_BUCKETS :: 16384

/*
Seconds of unused budget a prefix may bank.

A client that has been quiet may answer a burst at once - a browser opening a
page asks for a dozen names in as many milliseconds - so the bucket holds more
than one second's worth. Two seconds is enough for any burst a real client
produces and still bounds what one moment of an attack delivers.
*/
@(private)
RRL_BURST_SECONDS :: 2

/*
Which of a prefix's two budgets a query is charged to.

The separation is the point, and the note at the top of this file is where the
reasoning for it lives: under one budget a spoofed datagram flood could empty the
bucket of a prefix it was only naming, and close the connections of the clients who
live there.

`Datagram` is UDP, where the source address is whatever the sender wrote and what
the budget bounds is amplification - how much traffic one address can be made to
receive. `Stream` is TCP, DoT and DoH, where a handshake settled where the client
is and what the budget bounds is work - the upstream round trips and the cache
churn behind an answer.
*/
@(private)
Rate_Class :: enum u8 {
	Datagram,
	Stream,
}

@(private)
Rate_Bucket :: struct {
	// The hashed prefix this bucket is accounting for; 0 when unused.
	key:     u64,
	// One budget per class, refilled together and spent apart - see `Rate_Class`.
	tokens:  [Rate_Class]f64,
	// When both were last brought forward, which is whenever either was charged.
	last_ns: i64,
	/*
	Over-limit datagrams since the last one that was answered, for `slip`.

	Datagrams and nothing else, because a datagram is all a slip can be spent on: a
	truncated answer is an instruction to ask again over TCP, so a query that is
	already on a connection can neither be answered with one nor be allowed to
	decide which datagram the next one lands on. Charging the two classes to
	separate pools is what keeps that true without a guard - a connection's query
	does not reach this counter at all, answered or refused. See `rate_check`.
	*/
	over:    u32,
}

Rate_Limiter :: struct {
	buckets:   []Rate_Bucket,
	// Tokens per second, and the most that may be banked. Per pool: each of a
	// bucket's two gets this, which is the doubling the file's note accepts.
	rate:      f64,
	capacity:  f64,
	slip:      int,
	/*
	Keyed with process entropy, so which prefixes share a bucket is not
	something an attacker can work out and use.

	Without it the mapping is a published function of the address: an attacker
	who wanted a particular victim's answers dropped could send from whatever
	prefix collides with theirs and spend the shared budget on purpose. With it
	the table's layout is unknown outside this process.
	*/
	hash_key:  [16]u8,
	/*
	The bucket table, which has as many callers as there are connections.

	One thread reads the UDP socket, but every TCP, DoT and DoH connection is
	served on a thread of its own and charges the queries it reads from there, so
	the single-reader assumption this table was written under no longer holds.
	Unlocked, what that costs is not a crash but a limiter that under-counts at
	exactly the moment it is counting something: `tokens` read, decremented and
	written back by two threads at once loses one of the two decrements, and
	`over` loses slips the same way.

	One mutex for the table rather than one per bucket, or an atomic bucket. The
	critical section is a hash, a compare and a few flops - shorter than the
	syscall that delivered the query and orders of magnitude shorter than
	answering it - so a finer lock would buy contention on a lock nobody holds.
	*/
	lock:      sync.Mutex,
	allocator: mem.Allocator,
	// Counted here rather than in Stats because these are properties of the
	// limiter, and read by tests.
	limited:   u64,
	slipped:   u64,
}

make_rate_limiter :: proc(
	responses_per_second: int,
	slip: int,
	allocator := context.allocator,
) -> ^Rate_Limiter {
	r := new(Rate_Limiter, allocator)
	r.allocator = allocator
	r.buckets = make([]Rate_Bucket, RRL_BUCKETS, allocator)
	r.rate = f64(max(responses_per_second, 1))
	r.capacity = r.rate * RRL_BURST_SECONDS
	r.slip = max(slip, 0)
	crypto.rand_bytes(r.hash_key[:])
	return r
}

destroy_rate_limiter :: proc(r: ^Rate_Limiter) {
	if r == nil {
		return
	}
	delete(r.buckets, r.allocator)
	free(r, r.allocator)
}

Rate_Verdict :: enum u8 {
	// Under the budget: answer it as usual.
	Allow,
	// Over the budget, and this is the one in `slip` that gets told so.
	Truncate,
	// Over the budget: send nothing at all.
	Drop,
}

/*
The bucket accounting for `client`'s prefix, with both of its budgets brought
forward to `now_ns`. The caller holds the lock.

Both are refilled on every charge, whichever one is about to be spent: they accrue
at the same rate from the same instant, so bringing the idle one along costs a
flop and lets a single `last_ns` stand for the pair.
*/
@(private)
rate_bucket :: proc(r: ^Rate_Limiter, client: net.Endpoint, now_ns: i64) -> ^Rate_Bucket {
	key := prefix_key(r, client.address)
	b := &r.buckets[key % RRL_BUCKETS]

	// What both pools have accrued since either was last charged, read once: the
	// collision check below weighs it and the refill afterwards spends it.
	gained := elapsed_tokens(r, b.last_ns, now_ns)

	if b.key != key {
		/*
		Somebody else's bucket, or one never used.

		Taken over only once it has refilled: a bucket still spending is one a
		live prefix is being accounted by, and handing it to a newcomer would
		let a flood from one prefix clear the accounting of another. Otherwise
		the two share what is left, which is the conservative reading of a
		collision.

		Both pools have to have refilled, not either: a prefix whose connections
		are still spending is as live as one whose datagrams are, and taking the
		bucket on the strength of the quiet pool would clear the busy one - which
		is the flood-clears-the-accounting hole again, reached through whichever
		transport the owner was not using.
		*/
		refilled :=
			b.key == 0 ||
			(b.tokens[.Datagram] + gained >= r.capacity && b.tokens[.Stream] + gained >= r.capacity)
		if refilled {
			b.key = key
			for &tokens in b.tokens {
				tokens = r.capacity
			}
			b.over = 0
			// Full as of now, so there is nothing left of the elapsed time to
			// bring forward below.
			gained = 0
		}
	}

	for &tokens in b.tokens {
		tokens = min(r.capacity, tokens + gained)
	}
	b.last_ns = now_ns
	return b
}

/*
Charge one datagram to `client`'s prefix and say what to do with it.

Called from the UDP read loop. `stream_rate_check` is the other half, charging the
other pool, and the two run from as many threads as there are connections, which is
why the table is locked - see `lock`.

`now` is passed in rather than read here so a test can run a bucket through an
hour in a few microseconds. Monotonic, because a wall clock stepped backwards by
an NTP correction would hand out a bucket's worth of budget, and stepped forwards,
none.
*/
rate_check :: proc(r: ^Rate_Limiter, client: net.Endpoint, now: time.Tick) -> Rate_Verdict {
	if r == nil {
		return .Allow
	}
	sync.mutex_lock(&r.lock)
	defer sync.mutex_unlock(&r.lock)

	b := rate_bucket(r, client, now._nsec)

	if b.tokens[.Datagram] >= 1 {
		b.tokens[.Datagram] -= 1
		b.over = 0
		return .Allow
	}

	sync.atomic_add(&r.limited, 1)
	b.over += 1
	if r.slip > 0 && int(b.over) % r.slip == 0 {
		sync.atomic_add(&r.slipped, 1)
		return .Truncate
	}
	return .Drop
}

/*
Charge one query read off a connection and say whether to answer it.

The stream pool, not the datagram one, which is the separation the top of this
file argues for: a spoofed flood aimed at this prefix cannot reach what a
connection spends, so a client that got here over a handshake is not refused on
the strength of datagrams it never sent.

Everything over the budget is refused, with no slip, so the caller has one thing
to do with a refusal rather than two. Both of the things that make a truncated
answer worth sending are missing on a connection: the TC bit is an instruction to
ask again over TCP, and the client is already there, so a client that acted on it
would ask again on the connection it is holding - the same query, charged again -
and one that did not would give up. Nor is there an address to protect: the
handshake established where the client is, so the small answer would not be
standing in for a large one aimed at somebody else. `slipped=` in the stats line
counts truncated answers that went out, and there are none from here.

What the caller does with a `false` is stop serving: see `serve_dns_stream` for
why the connection ends rather than the query being quietly skipped.
*/
stream_rate_check :: proc(r: ^Rate_Limiter, client: net.Endpoint, now: time.Tick) -> bool {
	if r == nil {
		return true
	}
	sync.mutex_lock(&r.lock)
	defer sync.mutex_unlock(&r.lock)

	b := rate_bucket(r, client, now._nsec)

	if b.tokens[.Stream] >= 1 {
		b.tokens[.Stream] -= 1
		return true
	}

	sync.atomic_add(&r.limited, 1)
	return false
}

@(private)
elapsed_tokens :: proc(r: ^Rate_Limiter, last_ns, now_ns: i64) -> f64 {
	if last_ns == 0 || now_ns <= last_ns {
		return 0
	}
	return f64(now_ns - last_ns) / f64(time.Second) * r.rate
}

/*
The prefix an answer would be delivered to, hashed.

/24 and /64 are the units an attacker picks addresses within, so they are the
units the budget is kept in. The hash is keyed (see `hash_key`), and never
returns 0, which marks a bucket as unused.

The v4 mapping is undone first, so an IPv4 client is keyed on its /24 whichever
kind of socket it arrived on. Left mapped it would be keyed as IPv6, and every
`::ffff:a.b.c.d` address is zeroes in the four groups a /64 is taken from - so
the whole IPv4 side of a listener bound to `::` would share one bucket, and any
one client there could spend the budget of all the others. `unmap_v4` is the same
normalisation `is_loopback` reads a source through, and the rule the ACL compared
it against on the way in.
*/
@(private)
prefix_key :: proc(r: ^Rate_Limiter, address: net.Address) -> u64 {
	buf: [16]u8
	n := 0
	switch a in unmap_v4(address) {
	case net.IP4_Address:
		buf[0], buf[1], buf[2] = a[0], a[1], a[2]
		n = 3
	case net.IP6_Address:
		for i in 0 ..< 4 {
			buf[i * 2] = u8(u16(a[i]) >> 8)
			buf[i * 2 + 1] = u8(u16(a[i]))
		}
		n = 8
	}
	if n == 0 {
		return 1
	}
	h := siphash.sum_bytes_2_4(buf[:n], r.hash_key[:])
	return h if h != 0 else 1
}

start_rate_limiter :: proc(s: ^Server) -> bool {
	cfg := s.cfg.server.rate_limit
	if !cfg.enabled {
		return true
	}
	s.limiter = make_rate_limiter(cfg.responses_per_second, cfg.slip)
	// The two budgets are named in the line rather than left to the documentation:
	// an operator reading `500` needs to know it is 500 datagrams and 500 queries
	// on connections, not 500 between them.
	if cfg.slip > 0 {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64), counted separately for datagrams and for connections; 1 in %d over the datagram budget answered truncated, and over a connection nothing is",
			cfg.responses_per_second,
			cfg.slip,
		)
	} else {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64), counted separately for datagrams and for connections; anything over that dropped",
			cfg.responses_per_second,
		)
	}
	return true
}

stop_rate_limiter :: proc(s: ^Server) {
	destroy_rate_limiter(s.limiter)
	s.limiter = nil
}

// Read for the periodic stats line and by tests.
rate_limit_stats :: proc(r: ^Rate_Limiter) -> (limited, slipped: u64) {
	if r == nil {
		return 0, 0
	}
	return sync.atomic_load(&r.limited), sync.atomic_load(&r.slipped)
}
