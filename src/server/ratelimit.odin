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

Over-limit queries are not all dropped. At most every `slip`th one is answered
with a header and a question and the TC bit set, which is 30-odd bytes rather
than 4096 - too small to be worth reflecting - and which tells a real client to
ask again over TCP, where the handshake proves the address. A client stuck behind
a busy NAT therefore still resolves, at the cost of a round trip, while a spoofed
source gets a truncated answer it cannot follow up. At most, because those
answers are charged to a budget of their own - further down.

This is what BIND's `rate-limit` and Knot's RRL do, and the shape is theirs.

The stream transports - TCP, DoT, DoH - are charged too, for the other half of
what a flood costs. Amplification is not their problem: a handshake settled that
whoever is asking is where they said they were, and no answer goes anywhere else.
What they share with UDP is the work behind an answer, which is the upstream round
trips and the cache churn, and a client pipelining queries down one connection
reaches that as fast as the socket allows. `server.max_connections` bounds how
many clients are here at once, not how fast one of them asks, so without this a
flood delivered over a handful of connections is one the limiter never sees.

Opening one is charged as well, which is a different thing from the queries asked
on it. A client that dials, completes a TLS handshake and hangs up asks nothing,
so no budget of answers ever sees it - and a handshake is 205 µs of this server's
CPU, from an address that has to be real, so it needs no spoofing and no volume.
Measured on a four-core machine, 32 dialers drew 6,922 handshakes a second, 1.4 of
those four cores, while taking a sixth of the answers from a DoT client in another
prefix that was running its one connection at capacity - with every counter this
server published reading zero. `bench/results/2026-09-03-handshake-floods.md` is
that run. So arriving is charged too, one token per accepted connection, spent in
the accept loop before a thread exists and before `accept_tls` runs, where a
refusal costs a prefix compare and a close.

What is still not charged here is *occupancy*: how long a connection is held once
it has been paid for, and therefore how much of the table one client may fill. That
is `server.max_connections_per_prefix`, in `conns.odin`, keyed through the same
`client_prefix` as the budgets - so all three bounds agree about who a client is
while bounding different things, arrival rate, query rate and occupancy. And a
share cannot stand in for an arrival budget: bounding how many connections are
*held* bounds arrivals only where the share is small enough to be reached, and the
run above never reached the shipped 256 of 512 with a flood that holds 32
connections at a time.

Charged to a budget of their own, though - all of them. A prefix's datagrams are
spent out of one pool, the queries it asks over connections out of another, and the
connections themselves out of a third, and none is a way to spend another. There is
a fourth, for the truncated answers, further down. See `Rate_Class`.

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

The connection pool is separate for the same reason and more sharply. A datagram
that could spend it would be a way to stop a stranger's clients from *connecting*,
which is a door further out than the one above: a client refused a query at least
got here, and can retry. `test_a_datagram_flood_cannot_stop_a_prefix_connecting`
is that property. It is separate from the stream pool too, and there the argument
is not spoofing but arithmetic: a connection is the vehicle for a query, and a
client is entitled to spend one on each - `dig +tcp`, a `curl` per lookup and every
stub that does not keep a connection open all ask exactly that way, and the
`handshake-flood/arriving-client` arm is that client measured. So the connection
pool gets the whole of `responses_per_second` and not a share of it: anything
smaller would be a quiet reduction of the query budget for the clients that
reconnect, reached through a setting that says nothing about connections.

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

The truncated answers themselves are charged too, to a third pool. What `slip`
picks is every Nth datagram *over* the budget, so left uncharged the number this
server sends is a fixed fraction of whatever arrives, with no ceiling in it:
measured at two million spoofed datagrams a second, the shipped default sent
497,131 truncated answers a second - 19 MB/s - at the address the flood had
named, where the same configuration's 500 responses/s implies 0.58 MB/s. Byte for
byte that is a loss for the sender, so it is not amplification and never was the
reason to keep the slip. It is this server made a source of traffic proportional
to an attack, at an address that never asked, on a figure its operator set to
500 - and half a million writes a second taken from the one thread reading the UDP
socket, which is what dropped a bystander in an unrelated prefix from 99% of its
queries answered to 55%. `bench/results/2026-09-03-rate-limit-bystander.md` is
where both were measured, and `2026-09-03-slip-budget.md` is the same arms with
this pool in place: 58 truncated answers a second against 497,131, 0.54 MB/s
against 18.97, and the bystander back to 99%.

So the slip has a pool of its own, refilled like the others, and an over-limit
datagram is answered truncated only when there is a token to spend on it. `slip:
2` still means at most one in two; what changes is that the second, third and
millionth over-limit datagram in a second stop each buying a reply.

A fraction of `responses_per_second` rather than the whole of it, because an
invitation is worth more than an answer - see `RRL_SLIP_SHARE`.

What it costs, said plainly: the slip is worth less to a client *inside* a flooded
prefix than it used to be, and against a large enough flood it is worth nothing.
The pool is per prefix and the flood draws from it too, so where an uncharged slip
truncated every second datagram in the bucket - and therefore half of that client's
own queries - the pool reaches it in proportion to its share of the arrivals. The
bench measures the same client going from 250 truncated answers in 500 queries to
1, under a flood forty times the budget from the address beside it.

No choice of fraction fixes that, which is worth knowing before reaching for one:
a pool of the whole 500 would have reached it twelve times in those 500 rather than
once. The pool is per prefix because an attacker picks addresses freely inside one,
and a client's share of a pool it shares with a flood is its share of the flood.

Where the invitation does survive is the overload it was written for. A prefix
asking twice its budget has a few hundred over-limit datagrams a second for those
62 to land among, and one that lands moves the client onto the stream pool for good
- out of a budget no datagram flood can empty, which is the arm that answers 100%
at every setting. What a client loses is the signal under an attack, not the
recourse.

That is the trade: an operator who configured 500 responses/s gets a server that
sends about that much, rather than one that sends a stranger 19 MB/s and costs an
uninvolved client 44 points of its answer rate. `slip: 0` is still there for a
deployment that wants neither, and it is now within 0.01 MB/s of the default on
every figure the bench reports - the default stopped being the expensive choice.

What the connection budget is worth, and what it is not, said as plainly. On the
shipped 500 it holds one unspoofed client to 500 arrivals a second where nothing
held it before, which measured as 0.25 to 0.29 of four cores against the 1.25 to
1.42 the same flood drew uncharged - a fifth, and the remainder is the accepts and
closes rather than the key work, since a bound this cheap to trip is one the flood
trips four times as often. What it is not is a defence against a botnet. It is per prefix like
everything else here, so an actor with addresses in n prefixes has n of it, and on
IPv6 a routine /48 is 65,536 /64s - the same granularity and the same limitation
the response budget has, and the reason a publicly reachable instance still wants a
per-source connection *rate* limit in front of it, in the packet filter or whatever
terminates TLS in the deployment. The bound here is what keeps a single client with
one real address from spending a third of the server; it is not what makes the
address count stop mattering.

It is also not free to a client that shares a prefix with a flood, in exactly the
way the slip pool is not: a NAT whose /24 somebody is dialling into gets its share
of 500 arrivals a second and no more. That is the same trade the rest of this file
makes, and it is the direction to fail in - a client behind that NAT holding a
connection open keeps resolving on the stream pool, which the arrivals cannot
touch.
*/

/*
The table is fixed at construction and never grows.

A cache of buckets that allocated per source would be a memory bound written in
terms of how many distinct addresses an attacker cares to name, which is not a
bound. Sixteen thousand buckets is 768 KB - a bucket carries a budget per pool -
and more prefixes than a resolver serves; what collides shares a budget, which is
a limit that is too strict on rare occasions rather than a limit that fails.
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
How much smaller a prefix's slip budget is than its response budget.

An eighth, so the shipped 500 responses/s carries 62 truncated answers a second
per prefix - 2.5 KB/s beside the 0.58 MB/s of the answers themselves, which is
what makes `responses_per_second` a description of what this server emits again.

Smaller than the response budget because a truncated answer is an invitation
rather than an answer, and the invitation is the more valuable of the two: a
client that acts on one moves that query, and everything it asks next on the
connection it opens, to the stream pool - a budget of its own that a datagram
flood cannot empty. So a prefix needs far fewer invitations than answers, and the
ones it gets go further.

Not so small that a busy prefix gets none, either: 62 a second, banked
`RRL_BURST_SECONDS` deep, is more than the clients behind a NAT this server sits
behind will be sent to TCP for at once. The floor of a token a second keeps a
deliberately tiny `responses_per_second` from rounding the slip away altogether,
which would leave `slip` configured on and doing nothing - worse than either
thing an operator can ask for.
*/
@(private)
RRL_SLIP_SHARE :: 8

/*
Which of a prefix's four budgets something is charged to.

The separation is the point, and the note at the top of this file is where the
reasoning for it lives: under one budget a spoofed datagram flood could empty the
bucket of a prefix it was only naming, and close the connections of the clients who
live there - or, once arrivals are charged, stop them opening one at all.

`Datagram` is UDP, where the source address is whatever the sender wrote and what
the budget bounds is amplification - how much traffic one address can be made to
receive. `Stream` is queries read off a connection - TCP, DoT and DoH - where a
handshake settled where the client is and what the budget bounds is work: the
upstream round trips and the cache churn behind an answer.

`Connection` is the connection itself, one token per accepted arrival, spent in
the accept loop before a thread exists and before any TLS handshake. What it
bounds is the cost of *getting here*, which is the one load on this server that
neither of the two above charges and the cheapest one to mount: a client that
dials, handshakes and hangs up asks nothing, so it spends nothing out of
`Datagram` or `Stream` however fast it does it.

`Slip` is the truncated answer an over-limit datagram is given instead of nothing,
which is neither a transport nor an answer: what it bounds is how much traffic an
attack can have this server aim at the address it named, and how many writes that
costs the thread reading the UDP socket. It is spent only once `Datagram` is
empty - that is the precondition for a slip at all - so no reply is ever charged
to both.
*/
@(private)
Rate_Class :: enum u8 {
	Datagram,
	Stream,
	Connection,
	Slip,
}

@(private)
Rate_Bucket :: struct {
	// The hashed prefix this bucket is accounting for; 0 when unused.
	key:     u64,
	// One budget per class, brought forward together and spent apart, each at its
	// own rate - see `Rate_Class`.
	tokens:  [Rate_Class]f64,
	// When the pools were last brought forward, which is whenever any of them
	// was charged.
	last_ns: i64,
	/*
	Over-limit datagrams since the last one answered in full, for `slip`. A
	truncated answer does not reset it; only a datagram the `Datagram` pool paid
	for does.

	Datagrams and nothing else, because a datagram is all a slip can be spent on: a
	truncated answer is an instruction to ask again over TCP, so a query that is
	already on a connection can neither be answered with one nor be allowed to
	decide which datagram the next one lands on. Charging the two classes to
	separate pools is what keeps that true without a guard - a connection's query
	does not reach this counter at all, answered or refused. See `rate_check`.

	This says which datagrams a slip may be spent on and not how many are: a
	datagram this counter picks and the `Slip` pool cannot pay for is dropped, and
	the count carries on rather than restarting. So the spacing stays the 1-in-
	`slip` an operator asked for while the pool decides how many of those pass.
	*/
	over:    u32,
}

Rate_Limiter :: struct {
	buckets:   []Rate_Bucket,
	/*
	Tokens per second, and the most that may be banked, one of each per pool.

	`Datagram`, `Stream` and `Connection` all get `responses_per_second` - the
	multiplication the file's note accepts, and the whole figure for `Connection`
	because a connection is what a query is asked over; `Slip` gets a fraction of
	it, for the reason in `RRL_SLIP_SHARE`.
	*/
	rate:      [Rate_Class]f64,
	capacity:  [Rate_Class]f64,
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
	The bucket table, which has as many callers as there are connections, plus
	the loops.

	One thread reads the UDP socket, but every TCP, DoT and DoH connection is
	served on a thread of its own and charges the queries it reads from there, and
	each of the three accept loops charges the connections it accepts - so the
	single-reader assumption this table was written under no longer holds.
	Unlocked, what that costs is not a crash but a limiter that under-counts at
	exactly the moment it is counting something: `tokens` read, decremented and
	written back by two threads at once loses one of the two decrements, and
	`over` loses slips the same way.

	One mutex for the table rather than one per bucket, or an atomic bucket. The
	critical section is a hash, a compare and a few flops - shorter than the
	syscall that delivered the query and orders of magnitude shorter than
	answering it - so a finer lock would buy contention on a lock nobody holds.

	Which is worth checking rather than asserting, now the accept loops are on it:
	refusing an arrival is cheap, so a flood held to its budget dials several times
	faster than one being served, and 27,000 acquisitions a second off an accept
	loop is not the load this was written against. Measured, the datagram path does
	not notice - `handshake-flood/udp-bystander` in
	`bench/results/2026-09-04-handshake-budget.md` answers every query at 22.5 ms
	against its own quiet 20.4 ms, under a flood taking this lock 27,499 times a
	second. That is one rate on four cores and not a bound on what a much larger
	accept rate would do; the answer to a much larger accept rate is the packet
	filter the README asks for.
	*/
	lock:      sync.Mutex,
	allocator: mem.Allocator,
	// Counted here rather than in Stats because these are properties of the
	// limiter, and read by tests.
	limited:   u64,
	slipped:   u64,
	/*
	Connections refused for want of a `Connection` token.

	Apart from `limited`, which counts queries this server withheld an answer
	from, because this one is not a query: nothing was asked and nothing was
	withheld. Folded together, a handshake flood would read as a query flood to
	whoever is watching the counter, and the two do not ask for the same thing -
	`cookies.require` and a smaller `slip` are answers to one and nothing to the
	other.

	Apart from the `conn_refused` in `Stats` too, which is the connection *table*
	being full or a prefix holding its share of it. That is a bound on occupancy
	and this is a bound on arrival: an operator seeing `conn_refused` raises
	`max_connections` or its share, and one seeing this raises
	`rate_limit.responses_per_second` or decides the client should be refused.
	`conn_refused` reading zero right through a handshake flood is what this
	counter exists to stop.
	*/
	conn_limited: u64,
}

make_rate_limiter :: proc(
	responses_per_second: int,
	slip: int,
	allocator := context.allocator,
) -> ^Rate_Limiter {
	r := new(Rate_Limiter, allocator)
	r.allocator = allocator
	r.buckets = make([]Rate_Bucket, RRL_BUCKETS, allocator)
	configured := max(responses_per_second, 1)
	rps := f64(configured)
	r.rate[.Datagram] = rps
	r.rate[.Stream] = rps
	r.rate[.Connection] = rps
	// Divided as integers, so the slip pool refills at the whole number the
	// startup line prints and the documentation quotes rather than at a figure
	// an eighth of a token above it.
	r.rate[.Slip] = f64(max(configured / RRL_SLIP_SHARE, 1))
	for class in Rate_Class {
		r.capacity[class] = r.rate[class] * RRL_BURST_SECONDS
	}
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
The bucket accounting for `client`'s prefix, with all of its budgets brought
forward to `now_ns`. The caller holds the lock.

Every pool is refilled on every charge, whichever one is about to be spent: they
accrue from the same instant, differing only in rate, so bringing the idle ones
along costs a flop each and lets a single `last_ns` stand for the set.
*/
@(private)
rate_bucket :: proc(r: ^Rate_Limiter, client: net.Endpoint, now_ns: i64) -> ^Rate_Bucket {
	key := prefix_key(r, client.address)
	b := &r.buckets[key % RRL_BUCKETS]

	// What each pool has accrued since any of them was last charged, read once:
	// the collision check below weighs it and the refill afterwards spends it.
	gained := elapsed_tokens(r, b.last_ns, now_ns)

	if b.key != key {
		/*
		Somebody else's bucket, or one never used.

		Taken over only once it has refilled: a bucket still spending is one a
		live prefix is being accounted by, and handing it to a newcomer would
		let a flood from one prefix clear the accounting of another. Otherwise
		the two share what is left, which is the conservative reading of a
		collision.

		Every pool has to have refilled, not one of them: a prefix whose
		connections are still spending is as live as one whose datagrams are, and
		taking the bucket on the strength of a quiet pool would clear the busy
		one - which is the flood-clears-the-accounting hole again, reached through
		whichever transport the owner was not using.
		*/
		refilled := true
		if b.key != 0 {
			for class in Rate_Class {
				if b.tokens[class] + gained[class] < r.capacity[class] {
					refilled = false
					break
				}
			}
		}
		if refilled {
			b.key = key
			for class in Rate_Class {
				b.tokens[class] = r.capacity[class]
				// Full as of now, so there is nothing left of the elapsed time
				// to bring forward below.
				gained[class] = 0
			}
			b.over = 0
		}
	}

	for class in Rate_Class {
		b.tokens[class] = min(r.capacity[class], b.tokens[class] + gained[class])
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
	/*
	A truncated answer is a reply this server sends, so it is charged like one -
	to its own pool, for the reason at the top of this file. `over` says which
	datagram may be answered that way and the pool says whether it is; a
	candidate that finds the pool empty is dropped like the rest.
	*/
	if r.slip > 0 && int(b.over) % r.slip == 0 && b.tokens[.Slip] >= 1 {
		b.tokens[.Slip] -= 1
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

/*
Charge one accepted connection to `client`'s prefix and say whether to serve it.

Called from the accept loop, once per connection, before a thread is created and
before `accept_tls` runs a handshake. That is the whole point of it: a handshake is
the expensive part and a refusal at the accept is a prefix compare and a close, so
the token has to be spent while a refusal is still cheap. A budget checked further
in would be a budget checked after the cost it is bounding.

Its own pool, for the two reasons the top of this file gives. A datagram must not
be able to spend it, or a spoofed flood naming a prefix would stop the clients who
live there from connecting at all; and the queries asked over connections must not
spend it either, since a client that opens a connection per query is entitled to
both.

What is charged is *arriving*, not being served. A connection this returns `true`
for and that `conn_spawn` then refuses for want of a slot has still spent its
token: it arrived, it cost an accept, and the alternative is asking the connection
table - which walks its thread list and asks the OS about each entry - before the
cheaper of the two bounds. Nothing is given back either, since there is nothing to
give back to: a bucket refills on time and not on outcomes.

`false` means close the socket. There is nothing to write on it and nothing worth
writing: a refusal a client can read costs a connection to deliver, which is the
cost being refused. `report_conn_rate_limit` in `listeners.odin` is what says so
in the log, once.
*/
conn_rate_check :: proc(r: ^Rate_Limiter, client: net.Endpoint, now: time.Tick) -> bool {
	if r == nil {
		return true
	}
	sync.mutex_lock(&r.lock)
	defer sync.mutex_unlock(&r.lock)

	b := rate_bucket(r, client, now._nsec)

	if b.tokens[.Connection] >= 1 {
		b.tokens[.Connection] -= 1
		return true
	}

	sync.atomic_add(&r.conn_limited, 1)
	return false
}

/*
What every pool has accrued between `last_ns` and `now_ns`, one figure per class.

The elapsed time is converted once and each pool's rate multiplied through it: the
pools differ only in rate, so a division per pool would be the same division four
times - on the path every datagram takes, under the table lock.
*/
@(private)
elapsed_tokens :: proc(r: ^Rate_Limiter, last_ns, now_ns: i64) -> (gained: [Rate_Class]f64) {
	if last_ns == 0 || now_ns <= last_ns {
		return
	}
	seconds := f64(now_ns - last_ns) / f64(time.Second)
	for class in Rate_Class {
		gained[class] = seconds * r.rate[class]
	}
	return
}

/*
Who a client is, for every per-client bound this server keeps: the /24 an IPv4
address sits in, or the /64 an IPv6 one does.

/24 and /64 are the units an attacker picks addresses within, so they are the
units a bound has to be kept in - a bound kept per address is one they multiply
by picking another. Two things ask: the response budget below, keyed on the
prefix an answer would be delivered to, and the share of `max_connections` one
client may hold (`conn_spawn` in `conns.odin`). They ask the same procedure so
they cannot come to different views of who is being limited, which would make
the looser of the two the only bound.

The v4 mapping is undone first, so an IPv4 client is read as its /24 whichever
kind of socket it arrived on. Left mapped it would be read as IPv6, and every
`::ffff:a.b.c.d` address is zeroes in the four groups a /64 is taken from - so
the whole IPv4 side of a listener bound to `::` would be one prefix, and any one
client there could spend the budget, or occupy the connections, of all the
others. `unmap_v4` is the same normalisation `is_loopback` reads a source
through, and the rule the ACL compared it against on the way in.

`n` of 0 is an address that was neither family, which nothing this server
accepts produces; each caller says what it does with one. Compared by value, so
`bytes` beyond `n` has to stay zero - which is why the whole struct is returned
fresh rather than filled in through a pointer.
*/
Client_Prefix :: struct {
	bytes: [8]u8,
	n:     u8,
}

client_prefix :: proc(address: net.Address) -> Client_Prefix {
	p: Client_Prefix
	switch a in unmap_v4(address) {
	case net.IP4_Address:
		p.bytes[0], p.bytes[1], p.bytes[2] = a[0], a[1], a[2]
		p.n = 3
	case net.IP6_Address:
		for i in 0 ..< 4 {
			p.bytes[i * 2] = u8(u16(a[i]) >> 8)
			p.bytes[i * 2 + 1] = u8(u16(a[i]))
		}
		p.n = 8
	}
	return p
}

/*
The prefix an answer would be delivered to, hashed into a bucket key.

The hash is keyed (see `hash_key`), and never returns 0, which marks a bucket as
unused. Only the prefix's own bytes are hashed, so the two families cannot
collide by length: three bytes of IPv4 against eight of IPv6.
*/
@(private)
prefix_key :: proc(r: ^Rate_Limiter, address: net.Address) -> u64 {
	p := client_prefix(address)
	if p.n == 0 {
		return 1
	}
	h := siphash.sum_bytes_2_4(p.bytes[:p.n], r.hash_key[:])
	return h if h != 0 else 1
}

start_rate_limiter :: proc(s: ^Server) -> bool {
	cfg := s.cfg.server.rate_limit
	if !cfg.enabled {
		return true
	}
	s.limiter = make_rate_limiter(cfg.responses_per_second, cfg.slip)
	// The budgets are named in the line rather than left to the documentation: an
	// operator reading `500` needs to know it is 500 datagrams, 500 queries on
	// connections and 500 connections opened, not 500 between them - and that the
	// truncated answers have a figure of their own, since it is the one thing here
	// they did not write.
	if cfg.slip > 0 {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64), counted separately for datagrams, for queries on a connection and for connections opened; 1 in %d over the datagram budget answered truncated, up to %d truncated answers/s, and over a connection nothing is",
			cfg.responses_per_second,
			cfg.slip,
			int(s.limiter.rate[.Slip]),
		)
	} else {
		logx.infof(
			"rate limit: %d responses/s per client prefix (/24, /64), counted separately for datagrams, for queries on a connection and for connections opened; anything over that dropped",
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
rate_limit_stats :: proc(r: ^Rate_Limiter) -> (limited, slipped, conn_limited: u64) {
	if r == nil {
		return 0, 0, 0
	}
	return sync.atomic_load(&r.limited),
		sync.atomic_load(&r.slipped),
		sync.atomic_load(&r.conn_limited)
}
