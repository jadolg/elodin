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
The bucket table has no lock, and this is what says so out loud.

`rate_check` is written for one caller, and the cost of a second is not a crash
but a limiter that quietly under-counts: torn `tokens`, lost `over`. A second
reader is the obvious thing to add the day the read loop becomes the bottleneck,
so the assumption is held as state and claimed by whoever calls first.

`claim_reader` rather than `rate_check` itself, because what `rate_check` does
with the answer is assert, and a test cannot observe an abort.
*/
@(test)
test_limiter_is_claimed_by_one_thread :: proc(t: ^testing.T) {
	r := make_rate_limiter(100, 2)
	defer destroy_rate_limiter(r)

	testing.expect(t, claim_reader(r), "the first caller was not given the limiter")
	testing.expect(t, claim_reader(r), "the owner was refused its own limiter on the second call")

	Probe :: struct {
		limiter: ^Rate_Limiter,
		claimed: bool,
	}
	probe := Probe {
		limiter = r,
	}
	other := thread.create_and_start_with_poly_data(&probe, proc(p: ^Probe) {
		p.claimed = claim_reader(p.limiter)
	})
	testing.expect(t, other != nil, "could not start a second thread")
	thread.join(other)
	thread.destroy(other)

	testing.expect(t, !probe.claimed, "a second thread was allowed into an unlocked bucket table")
	// And the owner still owns it: a refused claim must not have taken it away.
	testing.expect(t, claim_reader(r), "the owner lost the limiter to a thread that was refused")
}

// A limiter nobody has called yet belongs to nobody, so the first thread to
// arrive gets it whichever thread that is - the read loop is not this one.
@(test)
test_limiter_owner_is_the_first_caller_not_the_maker :: proc(t: ^testing.T) {
	r := make_rate_limiter(100, 2)
	defer destroy_rate_limiter(r)

	Probe :: struct {
		limiter: ^Rate_Limiter,
		claimed: bool,
	}
	probe := Probe {
		limiter = r,
	}
	owner := thread.create_and_start_with_poly_data(&probe, proc(p: ^Probe) {
		p.claimed = claim_reader(p.limiter)
	})
	testing.expect(t, owner != nil, "could not start the owning thread")
	thread.join(owner)
	thread.destroy(owner)

	testing.expect(t, probe.claimed, "a thread that made the first call was refused")
	testing.expect(t, !claim_reader(r), "the thread that made the limiter was let in after another claimed it")
}
