package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"

/*
What the limiter owes, stated as tests.

The subject is amplification: a spoofed query is a way to have this server send
somebody else's address far more traffic than the attacker spent. The limit is
kept per destination prefix, because that is the party being flooded and the
only one whose rate means anything - the sender's address is fiction.
*/

@(private = "file")
at :: proc(ms: i64) -> time.Tick {
	// Not from zero: a bucket's `last_ns` of zero means "never used".
	return time.Tick{_nsec = (3600 + ms) * i64(time.Millisecond)}
}

@(private = "file")
v4 :: proc(a, b, c, d: u8, port: int = 30000) -> net.Endpoint {
	return net.Endpoint{address = net.IP4_Address{a, b, c, d}, port = port}
}

@(private = "file")
v6 :: proc(prefix: u16, host: u16, port: int = 30000) -> net.Endpoint {
	addr: net.IP6_Address
	addr[0] = 0x2001
	addr[1] = 0x0db8
	addr[2] = u16be(prefix)
	addr[3] = 0
	addr[7] = u16be(host)
	return net.Endpoint{address = addr, port = port}
}

/*
A prefix may spend its budget and no more, and it comes back with time.

The numbers: a burst of `rate * RRL_BURST_SECONDS` is what a bucket holds, so
that is what a quiet prefix may take at once and what a second of the limit
refills a fifth of.
*/
@(test)
test_rate_limit_spends_and_refills :: proc(t: ^testing.T) {
	RATE :: 100
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	client := v4(203, 0, 113, 7)
	allowed := 0
	for _ in 0 ..< 1000 {
		if rate_check(r, client, at(0)) == .Allow {
			allowed += 1
		}
	}
	testing.expectf(
		t,
		allowed == RATE * RRL_BURST_SECONDS,
		"a full bucket allowed %d at once, expected %d",
		allowed,
		RATE * RRL_BURST_SECONDS,
	)

	// Nothing left, and no time has passed.
	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Drop)

	// A quarter of a second is a quarter of the rate, and not a token more.
	refilled := 0
	for _ in 0 ..< 1000 {
		if rate_check(r, client, at(250)) == .Allow {
			refilled += 1
		}
	}
	testing.expectf(t, refilled == RATE / 4, "a quarter second refilled %d, expected %d", refilled, RATE / 4)

	// Long enough to have refilled many times over, capped at the burst.
	banked := 0
	for _ in 0 ..< 10000 {
		if rate_check(r, client, at(60_000)) == .Allow {
			banked += 1
		}
	}
	testing.expectf(
		t,
		banked == RATE * RRL_BURST_SECONDS,
		"a minute of idling banked %d, expected the %d cap",
		banked,
		RATE * RRL_BURST_SECONDS,
	)
}

/*
The budget is per prefix, not per address and not global.

An attacker aiming at one victim picks addresses freely inside the victim's
range, so /24 and /64 are the units that make the limit mean anything. Two
addresses in one /24 share; two /24s do not.
*/
@(test)
test_rate_limit_is_kept_per_prefix :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// Spend one /24 dry, one address at a time.
	spent := 0
	for i in 0 ..< 1000 {
		if rate_check(r, v4(198, 51, 100, u8(i % 256)), at(0)) == .Allow {
			spent += 1
		}
	}
	testing.expectf(
		t,
		spent == RATE * RRL_BURST_SECONDS,
		"a /24 spread over 256 addresses got %d responses, expected %d",
		spent,
		RATE * RRL_BURST_SECONDS,
	)

	// A different /24 is a different budget.
	testing.expect_value(t, rate_check(r, v4(198, 51, 101, 1), at(0)), Rate_Verdict.Allow)
	// And the source port is not part of it: it is the address that receives.
	testing.expect_value(t, rate_check(r, v4(198, 51, 100, 1, 40000), at(0)), Rate_Verdict.Drop)

	// The same, a /64 at a time.
	v6_spent := 0
	for i in 0 ..< 1000 {
		if rate_check(r, v6(0xaaaa, u16(i)), at(0)) == .Allow {
			v6_spent += 1
		}
	}
	testing.expectf(
		t,
		v6_spent == RATE * RRL_BURST_SECONDS,
		"a /64 spread over 1000 addresses got %d responses, expected %d",
		v6_spent,
		RATE * RRL_BURST_SECONDS,
	)
	testing.expect_value(t, rate_check(r, v6(0xbbbb, 1), at(0)), Rate_Verdict.Allow)
}

/*
Every `slip`th query over the budget is answered truncated rather than dropped.

That is what keeps a real client behind a busy NAT resolving: a TC response is
too small to be worth reflecting and tells it to come back over TCP, where the
handshake proves the address. A spoofed source cannot follow that up, which is
the whole point of answering that way rather than at length.
*/
@(test)
test_rate_limit_slips_a_truncated_answer :: proc(t: ^testing.T) {
	RATE :: 5
	SLIP :: 2
	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(192, 0, 2, 1)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}

	// Over the budget from here: one dropped, one truncated, alternating.
	truncated, dropped := 0, 0
	for _ in 0 ..< 100 {
		switch rate_check(r, client, at(0)) {
		case .Allow:
			testing.expect(t, false, "an empty bucket allowed a response")
		case .Truncate:
			truncated += 1
		case .Drop:
			dropped += 1
		}
	}
	testing.expectf(t, truncated == 50, "%d of 100 over-limit queries were truncated, expected 50", truncated)
	testing.expectf(t, dropped == 50, "%d of 100 over-limit queries were dropped, expected 50", dropped)

	limited, slipped := rate_limit_stats(r)
	testing.expect_value(t, limited, u64(100))
	testing.expect_value(t, slipped, u64(50))

	// slip = 0 is "drop them all".
	strict := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(strict)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		rate_check(strict, client, at(0))
	}
	for _ in 0 ..< 10 {
		testing.expect_value(t, rate_check(strict, client, at(0)), Rate_Verdict.Drop)
	}
}

/*
A limiter that is off allows everything, since that is what a nil one means to
every caller.
*/
@(test)
test_rate_limit_disabled_allows_everything :: proc(t: ^testing.T) {
	for i in 0 ..< 1000 {
		testing.expect_value(t, rate_check(nil, v4(192, 0, 2, u8(i % 256)), at(0)), Rate_Verdict.Allow)
	}
	limited, slipped := rate_limit_stats(nil)
	testing.expect_value(t, limited, u64(0))
	testing.expect_value(t, slipped, u64(0))
}

/*
A flood from every prefix there is must not take a quiet client's budget with
it.

The table is a fixed number of buckets, so prefixes collide - and if a colliding
newcomer could take over a bucket that was still being spent, an attacker with
enough source addresses would clear everyone's accounting as fast as it filled.
A bucket is only handed over once it has refilled, which is the point at which
its previous owner has nothing left to lose.
*/
@(test)
test_a_flood_of_prefixes_does_not_reset_a_live_bucket :: proc(t: ^testing.T) {
	RATE :: 4
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	victim := v4(198, 51, 100, 10)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, victim, at(0)), Rate_Verdict.Allow)
	}
	testing.expect_value(t, rate_check(r, victim, at(0)), Rate_Verdict.Drop)

	// Four times as many distinct /24s as there are buckets, all at the same
	// instant, so nothing has had a chance to refill.
	for i in 0 ..< RRL_BUCKETS * 4 {
		rate_check(r, v4(10, u8(i >> 8), u8(i), 1), at(0))
	}

	testing.expectf(
		t,
		rate_check(r, victim, at(0)) == .Drop,
		"a flood of other prefixes gave the limited one its budget back",
	)
}

/*
Two things a datagram's source can say that no answer could ever reach.

Port 0 receives nothing. Our own listening endpoint is this server talking to
itself: every answer arrives as the next query, and the loop runs at whatever
rate the socket sustains. The wildcard bind is the case that needs care - the
source of our own datagrams is then whichever local address the route picked,
not the 0.0.0.0 we bound - so a source on our port from a loopback address is
refused too.
*/
@(test)
test_implausible_sources_are_refused :: proc(t: ^testing.T) {
	socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if err != nil {
		testing.expectf(t, false, "cannot bind a loopback socket: %v", err)
		return
	}
	defer net.close(socket)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}
	l := Listeners {
		udp_socket = socket,
		udp_bound  = bound,
		udp_open   = true,
	}

	Case :: struct {
		client:    net.Endpoint,
		plausible: bool,
		what:      string,
	}

	CASES := []Case {
		{net.Endpoint{address = net.IP4_Address{192, 0, 2, 1}, port = 40000}, true, "an ordinary client"},
		{net.Endpoint{address = net.IP4_Address{192, 0, 2, 1}, port = 0}, false, "source port zero"},
		{net.Endpoint{address = net.IP4_Loopback, port = bound.port}, false, "our own endpoint"},
		{net.Endpoint{address = net.IP6_Loopback, port = bound.port}, false, "loopback on our port"},
		// Somebody else's resolver on our port is a loop between two servers,
		// but it is not one this end can tell from a client that picked an
		// unusual source port, so it is answered.
		{net.Endpoint{address = net.IP4_Address{192, 0, 2, 1}, port = bound.port}, true, "another host on our port"},
	}

	for c in CASES {
		got := plausible_source(&l, c.client)
		testing.expectf(t, got == c.plausible, "%s: plausible_source said %v", c.what, got)
	}
}

/*
A query read off a connection is refused whenever it is over the budget, `slip`
and all.

The TC bit is an instruction to ask again over TCP, and a client that is already
there can do nothing with it but ask again on the connection it is holding - the
same query, charged again. So the slip is a UDP answer, and what must not happen
is a stream caller reinterpreting a `Truncate` into a refusal after `rate_check`
has counted it as an answer that went out: `slipped=` is a figure about truncated
responses this server sent.

The limiter here has a slip configured, which is what makes that observable at
all, and the last part of the test is the same limiter still slipping for UDP -
this is the caller's choice per query, not a mode the bucket is put into.
*/
@(test)
test_stream_queries_are_refused_rather_than_truncated :: proc(t: ^testing.T) {
	RATE :: 5
	SLIP :: 2
	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(198, 51, 100, 4)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, stream_rate_check(r, client, at(0)), "a connection was refused a query the budget had room for")
	}
	for _ in 0 ..< 20 {
		testing.expect(t, !stream_rate_check(r, client, at(0)), "an over-budget query was answered on a connection")
	}

	limited, slipped := rate_limit_stats(r)
	testing.expect_value(t, limited, u64(20))
	testing.expect_value(t, slipped, u64(0))

	// The same limiter, a prefix of its own, over UDP: still every SLIPth one.
	over_udp := v4(198, 51, 101, 4)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		rate_check(r, over_udp, at(0))
	}
	truncated := 0
	for _ in 0 ..< 10 {
		if rate_check(r, over_udp, at(0)) == .Truncate {
			truncated += 1
		}
	}
	testing.expectf(t, truncated == 10 / SLIP, "%d of 10 over-limit datagrams were truncated, expected %d", truncated, 10 / SLIP)
}

/*
A refusal on a connection does not move the slip along.

`over` is the counter the slip is taken off, and the queries it counts have to be
the ones the slip can be spent on: a stream refusal that advanced it would decide
which *datagram* comes back truncated. Alternating traffic over one budget is
where that shows - with the connection counted, one interleaving truncates every
over-limit datagram, well past the 1-in-`slip` an operator asked for, and the
other truncates none of them and leaves a client behind a busy NAT with nothing
to act on.

One refusal, then two over-limit datagrams: the first is the slip's first, so it
is dropped, and the second is its second.
*/
@(test)
test_a_stream_refusal_does_not_advance_the_slip :: proc(t: ^testing.T) {
	SLIP :: 2
	r := make_rate_limiter(1, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(198, 51, 102, 7)
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}

	testing.expect(t, !stream_rate_check(r, client, at(0)), "an over-budget query was answered on a connection")

	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Drop)
	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Truncate)

	limited, slipped := rate_limit_stats(r)
	// Three over the budget: the connection's and the two datagrams.
	testing.expect_value(t, limited, u64(3))
	testing.expect_value(t, slipped, u64(1))
}

/*
One budget per prefix, not one per transport.

What the limit bounds is what this server does for one prefix, so a prefix that
has spent its budget answering datagrams has spent it - otherwise the same flood
delivered two ways gets twice as much, and the way to have more of it is to ask
over more transports.
*/
@(test)
test_the_budget_is_shared_across_transports :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// One address of the prefix spends it all over UDP.
	client := v4(203, 0, 113, 20)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}
	// Another address in the same /24, over a connection, finds nothing left.
	testing.expect(
		t,
		!stream_rate_check(r, v4(203, 0, 113, 21), at(0)),
		"a connection was served out of a budget UDP had already spent",
	)

	// And the other way about, on a prefix of its own.
	stream_first := v6(0xcccc, 1)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, stream_rate_check(r, stream_first, at(0)), "the budget refused a query it had room for")
	}
	testing.expect_value(t, rate_check(r, v6(0xcccc, 2), at(0)), Rate_Verdict.Drop)
}

// One charging thread's share of the work below, and what it saw.
@(private = "file")
Hammer :: struct {
	limiter:   ^Rate_Limiter,
	client:    net.Endpoint,
	rounds:    int,
	allowed:   int,
	truncated: int,
}

@(private = "file")
hammer :: proc(h: ^Hammer) {
	for _ in 0 ..< h.rounds {
		switch rate_check(h.limiter, h.client, at(0)) {
		case .Allow:
			h.allowed += 1
		case .Truncate:
			h.truncated += 1
		case .Drop:
		}
	}
}

/*
The bucket table is reached from as many threads as there are connections, and
this is what says the accounting survives it.

Every stream connection charges the queries it reads on its own thread, so the
single-reader assumption the table was first written under is gone. What its
absence costs is not a crash but a limiter that under-counts at the moment it is
counting something: `tokens` read, decremented and written back by two threads at
once loses one of the two decrements, and `over` loses slips the same way. Both
are counted here rather than only the first, because the numbers an operator reads
are as much of the limiter as the verdicts are.

Every thread charges the same prefix at the same instant, so nothing refills
during the run and the arithmetic is exact: a full bucket and no more, whoever
spent it. Unlocked, the total comes out above the capacity - by how much depends
on the interleaving, which is why the assertion is an equality rather than a
threshold.
*/
@(test)
test_rate_limit_accounts_exactly_under_concurrent_callers :: proc(t: ^testing.T) {
	RATE :: 100
	SLIP :: 2
	THREADS :: 8
	ROUNDS :: 500

	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(192, 0, 2, 40)
	hammers: [THREADS]Hammer
	threads: [THREADS]^thread.Thread
	for i in 0 ..< THREADS {
		hammers[i] = Hammer {
			limiter = r,
			client  = client,
			rounds  = ROUNDS,
		}
		threads[i] = thread.create_and_start_with_poly_data(&hammers[i], hammer)
		if threads[i] == nil {
			testing.expect(t, false, "could not start a charging thread")
			return
		}
	}
	allowed, truncated := 0, 0
	for i in 0 ..< THREADS {
		thread.join(threads[i])
		thread.destroy(threads[i])
		allowed += hammers[i].allowed
		truncated += hammers[i].truncated
	}

	testing.expectf(
		t,
		allowed == RATE * RRL_BURST_SECONDS,
		"%d threads spent %d responses out of a bucket holding %d",
		THREADS,
		allowed,
		RATE * RRL_BURST_SECONDS,
	)

	limited, slipped := rate_limit_stats(r)
	over := u64(THREADS * ROUNDS - RATE * RRL_BURST_SECONDS)
	testing.expect_value(t, limited, over)
	// `over` counted once per over-limit query and never lost, so every SLIPth one
	// of them slipped - exactly, not approximately.
	testing.expect_value(t, slipped, over / SLIP)
	testing.expect_value(t, u64(truncated), over / SLIP)
}
