package server

import "core:log"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"

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
`::ffff:a.b.c.d`, the form an IPv4 client arrives in on a socket bound to `::`.

A supported, documented deployment: `config.source_allowed` undoes this mapping
before it compares a source against `server.allow_from`, so an operator who
wrote `192.168.0.0/16` covers the mapped client too. The limiter is asked to
answer the same question the same way.
*/
@(private = "file")
mapped :: proc(a, b, c, d: u8, port: int = 30000) -> net.Endpoint {
	addr: net.IP6_Address
	addr[5] = 0xffff
	addr[6] = u16be(u16(a) << 8 | u16(b))
	addr[7] = u16be(u16(c) << 8 | u16(d))
	return net.Endpoint{address = addr, port = port}
}

// An IPv6 address written as its eight groups, for the forms that only resemble
// the mapped one.
@(private = "file")
v6_of :: proc(groups: [8]u16) -> net.Address {
	addr: net.IP6_Address
	for g, i in groups {
		addr[i] = u16be(g)
	}
	return addr
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
An IPv4 client that arrived mapped is keyed on its own /24, not on `::/64`.

A socket bound to `::` serving IPv4 clients is a documented deployment - see
`mapped` above - and every `::ffff:a.b.c.d` address is zeroes in the four groups
an IPv6 source is keyed on. Keying such a source as IPv6 therefore put the whole
IPv4 side of a wildcard listener into one bucket: at the shipped defaults, 500
responses a second between all of them, half the excess dropped and half
truncated. Any one client inside `server.allow_from` - a busy stub, a NAT
gateway, or something deliberately trying - then spent the budget of every
other, which is the limiter denying service to the clients it exists to protect.
*/
@(test)
test_mapped_v4_sources_keep_their_own_budget :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// One /24, spread across every address in it: one budget between them, the
	// same as the unmapped form gets.
	spent := 0
	for i in 0 ..< 1000 {
		if rate_check(r, mapped(198, 51, 100, u8(i % 256)), at(0)) == .Allow {
			spent += 1
		}
	}
	testing.expectf(
		t,
		spent == RATE * RRL_BURST_SECONDS,
		"a mapped /24 spread over 256 addresses got %d responses, expected %d",
		spent,
		RATE * RRL_BURST_SECONDS,
	)

	// The /24 next door, and a wholly unrelated IPv4 network: budgets of their own.
	testing.expectf(
		t,
		rate_check(r, mapped(198, 51, 101, 1), at(0)) == .Allow,
		"the neighbouring mapped /24 was answered out of the spent one's budget",
	)
	testing.expectf(
		t,
		rate_check(r, mapped(203, 0, 113, 9), at(0)) == .Allow,
		"an unrelated mapped IPv4 network was answered out of the spent one's budget",
	)
	// And the source port is not part of it: it is the address that receives.
	testing.expect_value(t, rate_check(r, mapped(198, 51, 100, 1, 40000), at(0)), Rate_Verdict.Drop)
}

/*
Whichever way it arrives, one client is one prefix.

The two spellings are the same destination, so an answer sent to either is an
answer the other's budget has to have paid for. It is not only tidiness: a
server with both a `0.0.0.0` and a `::` listener sees the same IPv4 client
unmapped on one and mapped on the other, and a prefix that got a full budget per
spelling would get twice what the operator configured for the price of asking
both ways.

Both pools, because the mapping is not a UDP matter: a DoT or DoH connection to
a `::` listener arrives with a mapped peer address too.
*/
@(test)
test_a_mapped_source_and_its_v4_form_are_one_prefix :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// Mapped first, then charged unmapped.
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, mapped(203, 0, 113, 7), at(0)), Rate_Verdict.Allow)
	}
	testing.expectf(
		t,
		rate_check(r, v4(203, 0, 113, 7), at(0)) == .Drop,
		"the unmapped form of a spent prefix was given a budget of its own",
	)
	testing.expectf(
		t,
		rate_check(r, v4(203, 0, 113, 200), at(0)) == .Drop,
		"another address in the spent /24 was given a budget of its own, unmapped",
	)

	// The other way about, on a prefix of its own.
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, v4(192, 0, 2, 5), at(0)), Rate_Verdict.Allow)
	}
	testing.expectf(
		t,
		rate_check(r, mapped(192, 0, 2, 5), at(0)) == .Drop,
		"the mapped form of a spent prefix was given a budget of its own",
	)

	// The stream pool keys off the same address, so it answers the same way.
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, stream_rate_check(r, mapped(198, 51, 100, 1), at(0)), "the stream budget refused a query it had room for")
	}
	testing.expectf(
		t,
		!stream_rate_check(r, v4(198, 51, 100, 2), at(0)),
		"a connection from the unmapped form of a spent prefix was given a budget of its own",
	)
}

/*
The mapped clients of a wildcard listener are told apart over connections too.

The datagram pool is where amplification lives, so it is where the collapse was
worth the most to an attacker, but the stream pool is keyed by the same procedure
and a `::` bind is how DoT and DoH are usually served. Collapsed, one pipelining
client would close every other IPv4 client's connections on a default
configuration.
*/
@(test)
test_mapped_v4_sources_keep_their_own_stream_budget :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	answered := 0
	for i in 0 ..< 1000 {
		if stream_rate_check(r, mapped(198, 51, 100, u8(i % 256)), at(0)) {
			answered += 1
		}
	}
	testing.expectf(
		t,
		answered == RATE * RRL_BURST_SECONDS,
		"a mapped /24's connections got %d answers, expected %d",
		answered,
		RATE * RRL_BURST_SECONDS,
	)
	testing.expectf(
		t,
		stream_rate_check(r, mapped(203, 0, 113, 9), at(0)),
		"an unrelated mapped IPv4 network's connection was refused out of the spent one's budget",
	)
}

/*
Exactly the mapped prefix is unmapped, and nothing that merely resembles it.

The rule is `config.address_bytes`'s rule, and keeping it one rule is the point:
ten zero bytes, then `ff ff`, then the four octets. `::ffff:0:a.b.c.d`,
`::a.b.c.d` and anything with a bit set higher up are IPv6 addresses that happen
to carry four familiar octets, and reading them as IPv4 would hand a v6 sender
the choice of which IPv4 prefix's budget to spend - the far side of the same
coin, and the direction the ACL is careful about.

Keys rather than verdicts here: two distinct prefixes land in the same bucket
about one time in `RRL_BUCKETS`, and `rate_check` cannot tell that from one
prefix, so an inequality asserted through it would be a test that fails now and
then for a reason that is not a bug. The key is what "same prefix" means.
*/
@(test)
test_only_the_v4_mapped_prefix_is_unmapped :: proc(t: ^testing.T) {
	r := make_rate_limiter(10, 0)
	defer destroy_rate_limiter(r)

	// 198.51.100.1 is c6:33:64:01, which is the tail the near-miss forms below
	// carry - they are the same four octets under a prefix that is not the mapping.
	V4 := net.Address(net.IP4_Address{198, 51, 100, 1})

	Keying :: struct {
		a, b: net.Address,
		same: bool,
		what: string,
	}

	CASES := []Keying {
		// The mapping, undone.
		{mapped(198, 51, 100, 1).address, V4, true, "a mapped source is the IPv4 address it names"},
		{mapped(198, 51, 100, 1).address, mapped(198, 51, 100, 254).address, true, "two mapped addresses in one /24"},
		{mapped(198, 51, 100, 1).address, v4(198, 51, 100, 99).address, true, "mapped and unmapped inside one /24"},
		{mapped(127, 0, 0, 1).address, v4(127, 0, 0, 1).address, true, "mapped loopback"},
		{mapped(255, 255, 255, 255).address, v4(255, 255, 255, 255).address, true, "the top of the IPv4 space"},
		{mapped(0, 0, 0, 1).address, mapped(0, 0, 0, 254).address, true, "the bottom of it, where every byte of the key is zero"},

		// Undone, and still a /24 at a time.
		{mapped(198, 51, 100, 1).address, mapped(198, 51, 101, 1).address, false, "the mapped /24 next door"},
		{mapped(198, 51, 100, 1).address, mapped(203, 0, 113, 1).address, false, "an unrelated mapped network"},
		// The collapse itself: mapped addresses are zeroes in the four groups an
		// IPv6 source is keyed on, so this pair shared a key and a bucket.
		{mapped(0, 0, 0, 1).address, v6_of({0, 0, 0, 0, 0, 0, 0, 1}), false, "`::ffff:0.0.0.1` is not `::1`"},

		// Forms that are not the mapping and must not be read as one.
		{v6_of({0, 0, 0, 0, 0xffff, 0, 0xc633, 0x6401}), V4, false, "`::ffff:0:198.51.100.1`, the IPv4-translated form"},
		{v6_of({0, 0, 0, 0, 0, 0xfffe, 0xc633, 0x6401}), V4, false, "one bit off the mapped prefix"},
		{v6_of({0, 0, 0, 0, 0, 0, 0xc633, 0x6401}), V4, false, "`::198.51.100.1`, the deprecated IPv4-compatible form"},
		{v6_of({0, 0, 0, 0, 1, 0xffff, 0xc633, 0x6401}), V4, false, "a bit set just above the mapped prefix"},
		{v6_of({0, 0, 0, 1, 0, 0xffff, 0xc633, 0x6401}), V4, false, "a bit set inside the four groups the /64 is taken from"},
		{v6_of({1, 0, 0, 0, 0, 0xffff, 0xc633, 0x6401}), V4, false, "a mapped tail under a prefix of its own"},
		{
			v6_of({0x2001, 0x0db8, 0, 0, 0, 0xffff, 0xc633, 0x6401}),
			V4,
			false,
			"`2001:db8::ffff:198.51.100.1`, a global address carrying the octets",
		},
		// And what being IPv6 means for them: `::/64`, the same as the ACL reads
		// them as. Sharing that bucket is the ordinary cost of sharing a /64.
		{
			v6_of({0, 0, 0, 0, 0, 0, 0xc633, 0x6401}),
			v6_of({0, 0, 0, 0, 0, 0xfffe, 0xc633, 0x6401}),
			true,
			"two addresses inside `::/64`, which is what they are",
		},

		// Neither family's own keying moved.
		{V4, v4(198, 51, 100, 200).address, true, "IPv4 keeps its /24"},
		{V4, v4(198, 51, 99, 1).address, false, "and the /24 next door is not it"},
		{v6(0xaaaa, 1).address, v6(0xaaaa, 2).address, true, "IPv6 keeps its /64"},
		{v6(0xaaaa, 1).address, v6(0xbbbb, 1).address, false, "and the /64 next door is not it"},
	}

	for c in CASES {
		ka, kb := prefix_key(r, c.a), prefix_key(r, c.b)
		testing.expectf(
			t,
			(ka == kb) == c.same,
			"%s: keys %s, expected %s",
			c.what,
			"agree" if ka == kb else "differ",
			"agreement" if c.same else "a difference",
		)
		// Zero is how an unused bucket is marked, so no address may hash to it.
		testing.expectf(t, ka != 0 && kb != 0, "%s: an address keyed to 0", c.what)
	}

	// An address of neither family is not a prefix; it gets the one key that is
	// not a hash of anything.
	testing.expect_value(t, prefix_key(r, nil), u64(1))
}

/*
The address a v4 client actually arrives as, from the kernel rather than a literal.

Every other test here builds `::ffff:a.b.c.d` by hand, which proves the judgement
and assumes the premise. This one binds `::`, sends a datagram to 127.0.0.1 from
an IPv4 socket, and asks both questions of whatever address `recv_udp` reports -
so the fix rests on what a client really arrives as rather than on a reading of
`core:net`, and it stays honest if a platform or a future `core:net` ever reports
the unmapped form instead.

Skipped, out loud, where `::` cannot be bound or is not dual-stack: that is a
property of the machine (`net.ipv6.bindv6only`, a container without IPv6) rather
than of the code, and a hard failure there would be a false alarm. The line in
the log is so that a runner where this never executes is visible rather than
quietly green.
*/
@(test)
test_a_real_v4_client_on_a_wildcard_bind_is_judged_by_its_v4_address :: proc(t: ^testing.T) {
	server_socket, serr := net.make_bound_udp_socket(net.IP6_Any, 0)
	if serr != nil {
		log.infof("skipped: this machine cannot bind `::` (%v)", serr)
		return
	}
	defer net.close(server_socket)
	_ = net.set_option(server_socket, .Receive_Timeout, 2 * time.Second)

	bound, berr := net.bound_endpoint(server_socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client_socket, cerr := net.make_unbound_udp_socket(.IP4)
	if cerr != nil {
		testing.expectf(t, false, "cannot open an IPv4 socket: %v", cerr)
		return
	}
	defer net.close(client_socket)

	payload := [1]u8{0}
	to := net.Endpoint {
		address = net.IP4_Loopback,
		port    = bound.port,
	}
	if _, err := net.send_udp(client_socket, payload[:], to); err != nil {
		log.infof("skipped: a `::` bind is not reachable over IPv4 here (%v)", err)
		return
	}
	buf: [4]u8
	_, from, rerr := net.recv_udp(server_socket, buf[:])
	if rerr != nil {
		log.infof("skipped: nothing arrived on the `::` socket from an IPv4 client (%v)", rerr)
		return
	}

	// Whatever form it is in, these are the two judgements that have to come out
	// the way they would for 127.0.0.1 itself.
	testing.expectf(t, is_loopback(from.address), "a real IPv4 client (%v) did not read as loopback", from.address)

	r := make_rate_limiter(10, 0)
	defer destroy_rate_limiter(r)
	testing.expectf(
		t,
		prefix_key(r, from.address) == prefix_key(r, net.IP4_Loopback),
		"a real IPv4 client (%v) was keyed as a different prefix from 127.0.0.1",
		from.address,
	)
	// And it must not be keyed as `::/64`, which is what every mapped address
	// collapsed to and the reason one bucket held the whole IPv4 side.
	testing.expectf(
		t,
		prefix_key(r, from.address) != prefix_key(r, net.IP6_Any),
		"a real IPv4 client (%v) was keyed as `::/64`",
		from.address,
	)

	// The premise itself, on the record: mapped is what a dual-stack `::` bind
	// reports, and a platform that ever stops doing so should say so here.
	if _, is6 := from.address.(net.IP6_Address); !is6 {
		log.infof("note: this platform reports an IPv4 client on a `::` bind unmapped (%v)", from.address)
	}
}

/*
No single bit off the mapped prefix is read as IPv4.

`unmap_v4`'s guard is ten zero bytes and then `ff ff`, and a guard is worth
sweeping rather than sampling: a loop bound one short, a mask on the wrong byte,
a comparison against the wrong half of the pair. Every bit that can be set in
the ten zero bytes, and every bit that can be cleared in the pair, must leave the
address IPv6 - because reading one of them as IPv4 is what would let a v6 sender
choose which IPv4 prefix's budget to spend.
*/
@(test)
test_no_single_bit_off_the_mapped_prefix_is_read_as_ipv4 :: proc(t: ^testing.T) {
	r := make_rate_limiter(10, 0)
	defer destroy_rate_limiter(r)

	// `::ffff:198.51.100.1`, and the key it has to have.
	MAPPED :: [8]u16{0, 0, 0, 0, 0, 0xffff, 0xc633, 0x6401}
	v4_key := prefix_key(r, net.IP4_Address{198, 51, 100, 1})
	testing.expect_value(t, prefix_key(r, v6_of(MAPPED)), v4_key)

	// A bit set anywhere in the ten bytes that have to be zero.
	for group in 0 ..< 5 {
		for bit in 0 ..< 16 {
			groups := MAPPED
			groups[group] |= u16(1) << uint(bit)
			testing.expectf(
				t,
				prefix_key(r, v6_of(groups)) != v4_key,
				"bit %d of group %d set, and the address was still read as 198.51.100.0/24",
				bit,
				group,
			)
		}
	}
	// And a bit cleared anywhere in the `ff ff` pair.
	for bit in 0 ..< 16 {
		groups := MAPPED
		groups[5] &~= u16(1) << uint(bit)
		testing.expectf(
			t,
			prefix_key(r, v6_of(groups)) != v4_key,
			"bit %d of the `ff ff` pair cleared, and the address was still read as 198.51.100.0/24",
			bit,
		)
	}
}

/*
An unmapped source is keyed on its /24 exactly: all of it, and no more of it.

Swept over every value of every octet, because "keyed on the /24" is two claims
and a mistake in either is a real one. Too few bytes - a /16, say - and two
unrelated networks share a budget, which is the collapse this fix is about in
miniature. Too many - the whole address - and the budget is per host, so an
attacker aiming at one victim spreads a flood across the 256 addresses of its
/24 and pays nothing for it, which is the reason the limit is kept per prefix at
all.
*/
@(test)
test_a_mapped_source_is_keyed_on_its_24_exactly :: proc(t: ^testing.T) {
	r := make_rate_limiter(10, 0)
	defer destroy_rate_limiter(r)

	ORIGIN := [4]u8{198, 51, 100, 1}
	v4_key := prefix_key(r, mapped(ORIGIN[0], ORIGIN[1], ORIGIN[2], ORIGIN[3]).address)

	for pos in 0 ..< 4 {
		for value in 0 ..< 256 {
			octets := ORIGIN
			octets[pos] = u8(value)
			// The host octet is below the prefix, so only it may differ freely.
			want := pos == 3 || u8(value) == ORIGIN[pos]
			got := prefix_key(r, mapped(octets[0], octets[1], octets[2], octets[3]).address) == v4_key
			testing.expectf(
				t,
				got == want,
				"octet %d set to %d: keys %s, expected %s",
				pos,
				value,
				"agree" if got else "differ",
				"agreement" if want else "a difference",
			)
		}
	}
}

/*
Every `slip`th query over the budget is answered truncated rather than dropped.

That is what keeps a real client behind a busy NAT resolving: a TC response is
too small to be worth reflecting and tells it to come back over TCP, where the
handshake proves the address. A spoofed source cannot follow that up, which is
the whole point of answering that way rather than at length.

Every `slip`th while there is a slip token to spend, that is: what the spacing
decides is which over-limit datagram may be truncated, and the pool decides how
many of those are - so this asserts the alternation over as many datagrams as the
pool can pay for, and `test_the_slip_budget_is_a_pool_of_its_own` takes it from
there. `RATE` is 80 so that an eighth of it is a whole number: 10 truncated
answers a second, `RRL_BURST_SECONDS` of them banked.
*/
@(test)
test_rate_limit_slips_a_truncated_answer :: proc(t: ^testing.T) {
	RATE :: 80
	SLIP :: 2
	SLIPS :: RATE / RRL_SLIP_SHARE * RRL_BURST_SECONDS
	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(192, 0, 2, 1)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}

	// Over the budget from here: one dropped, one truncated, alternating, for as
	// long as the slip pool holds out - which is `SLIP` of these per token in it.
	truncated, dropped := 0, 0
	for _ in 0 ..< SLIP * SLIPS {
		switch rate_check(r, client, at(0)) {
		case .Allow:
			testing.expect(t, false, "an empty bucket allowed a response")
		case .Truncate:
			truncated += 1
		case .Drop:
			dropped += 1
		}
	}
	testing.expectf(
		t,
		truncated == SLIPS,
		"%d of the first %d over-limit queries were truncated, expected %d",
		truncated,
		SLIP * SLIPS,
		SLIPS,
	)
	testing.expectf(
		t,
		dropped == SLIPS,
		"%d of the first %d over-limit queries were dropped, expected %d",
		dropped,
		SLIP * SLIPS,
		SLIPS,
	)

	limited, slipped, _ := rate_limit_stats(r)
	testing.expect_value(t, limited, u64(SLIP * SLIPS))
	testing.expect_value(t, slipped, u64(SLIPS))

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
Truncated answers are bounded by a budget of their own, not by how much arrives.

`slip` picks every Nth over-limit datagram, so charged to nothing the count of
truncated answers is a fixed fraction of the flood: at two million datagrams a
second the shipped default sent half a million truncated answers a second at
whatever address the flood had named. Byte for byte that is a loss for the sender
- a 51-byte query draws a 40-byte reply - so it is not amplification. What it is
instead is this server made the source of traffic proportional to an attack, at
an address that never asked, on a figure the operator set to 500; and a write per
reply, competing with the single UDP read loop that would otherwise be picking up
other clients' queries.

So what is asserted is a ratio and not a count: the same limiter offered ten
times as much must truncate no more. The bound is `responses_per_second`, the
figure an operator configured, rather than the arrival rate, which is the
attacker's. `test_the_slip_budget_is_a_pool_of_its_own` says what the bound
actually is; this one says only that the flood does not set it.

`bench/results/2026-09-03-rate-limit-bystander.md` is where the unbounded figures
were measured.
*/
@(test)
test_slip_replies_are_bounded_by_a_budget_not_by_the_flood :: proc(t: ^testing.T) {
	RATE :: 500
	SLIP :: 2

	small := truncated_under_flood(RATE, SLIP, 20_000)
	large := truncated_under_flood(RATE, SLIP, 200_000)

	testing.expectf(
		t,
		small == large,
		"a flood ten times the size drew %d truncated answers against %d, so their number follows the attack and not a budget",
		large,
		small,
	)
	testing.expectf(
		t,
		large <= RATE * RRL_BURST_SECONDS,
		"%d truncated answers went out at one instant, past the %d a prefix's whole response budget holds",
		large,
		RATE * RRL_BURST_SECONDS,
	)
}

/*
Truncated answers a fresh limiter sends when `offered` over-limit datagrams
arrive at one instant, the prefix's datagram pool already emptied.

One instant throughout, so nothing refills and the count is the pool's and not
the clock's.
*/
@(private = "file")
truncated_under_flood :: proc(rate, slip, offered: int) -> int {
	r := make_rate_limiter(rate, slip)
	defer destroy_rate_limiter(r)

	client := v4(192, 0, 2, 77)
	for _ in 0 ..< rate * RRL_BURST_SECONDS {
		rate_check(r, client, at(0))
	}

	truncated := 0
	for _ in 0 ..< offered {
		if rate_check(r, client, at(0)) == .Truncate {
			truncated += 1
		}
	}
	return truncated
}

/*
What the bound on truncated answers actually is: a pool, refilled like the others
and spent from neither of them.

An eighth of `responses_per_second` per prefix, banked `RRL_BURST_SECONDS` deep -
the arithmetic and the reason for the fraction are in `RRL_SLIP_SHARE`. Three
things are asserted about it, and the third is the one that matters most: a second
of quiet buys the prefix its whole `responses_per_second` in *full* answers,
undiminished by the truncated ones sent while the budget was empty. The slip is a
reply this server sends and is charged for, but it is not charged to the pool an
answer comes out of - a client whose prefix was flooded is not made to pay for the
invitations the flood drew.

The other two: the pool is exactly its capacity however much is offered against
it, and it comes back with the clock rather than staying dry - a client behind a
busy NAT keeps being told to go to TCP for as long as the flood lasts, just not
once per datagram the flood sends.

One instant per stage, so nothing refills except where the stage is the refill.
*/
@(test)
test_the_slip_budget_is_a_pool_of_its_own :: proc(t: ^testing.T) {
	// An eighth of 80 is a whole number, so the figures below are exact rather
	// than rounded: 10 truncated answers a second, 20 banked.
	RATE :: 80
	SLIP :: 2
	SLIPS :: RATE / RRL_SLIP_SHARE * RRL_BURST_SECONDS

	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(203, 0, 113, 5)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}

	// The pool, to the token, against a flood far larger than it.
	truncated := 0
	for _ in 0 ..< 10_000 {
		if rate_check(r, client, at(0)) == .Truncate {
			truncated += 1
		}
	}
	testing.expectf(t, truncated == SLIPS, "%d truncated answers came out of a pool holding %d", truncated, SLIPS)

	// A second on, and the response budget is the whole of what an operator
	// configured: the slips were not taken out of it.
	allowed := 0
	for _ in 0 ..< RATE {
		if rate_check(r, client, at(1000)) == .Allow {
			allowed += 1
		}
	}
	testing.expectf(
		t,
		allowed == RATE,
		"a second of refill answered %d datagrams in full, not the %d responses/s configured",
		allowed,
		RATE,
	)

	// Nor was the stream pool, which is the one the truncated answers send a
	// client to.
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, stream_rate_check(r, client, at(1000)), "a connection was refused a query the stream pool had room for")
	}
	testing.expect(t, !stream_rate_check(r, client, at(1000)), "the stream pool answered past what it holds")

	// And the slip pool refills too: a second of it, and no more, for the flood
	// that is still arriving.
	refilled := 0
	for _ in 0 ..< 10_000 {
		if rate_check(r, client, at(1000)) == .Truncate {
			refilled += 1
		}
	}
	testing.expectf(
		t,
		refilled == RATE / RRL_SLIP_SHARE,
		"a second of refill truncated %d answers, expected the %d a second the pool accrues",
		refilled,
		RATE / RRL_SLIP_SHARE,
	)
}

/*
A limiter that is off allows everything, since that is what a nil one means to
every caller.
*/
@(test)
test_rate_limit_disabled_allows_everything :: proc(t: ^testing.T) {
	for i in 0 ..< 1000 {
		testing.expect_value(t, rate_check(nil, v4(192, 0, 2, u8(i % 256)), at(0)), Rate_Verdict.Allow)
		testing.expect(
			t,
			stream_rate_check(nil, v4(192, 0, 2, u8(i % 256)), at(0)),
			"a disabled limiter refused a query on a connection",
		)
		// Including the connections themselves: `rate_limit.enabled: false` has
		// to mean the accept loop is back to where it was, or turning the
		// limiter off would leave a bound on nothing an operator asked for.
		testing.expect(
			t,
			conn_rate_check(nil, v4(192, 0, 2, u8(i % 256)), at(0)),
			"a disabled limiter refused a connection",
		)
	}
	limited, slipped, conn_limited := rate_limit_stats(nil)
	testing.expect_value(t, limited, u64(0))
	testing.expect_value(t, slipped, u64(0))
	testing.expect_value(t, conn_limited, u64(0))
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
	// `plausible_source` reads the bound endpoint and nothing else, so the
	// socket is here only to have bound a port that no other test can hold.
	l := Listeners {
		udp_bound = bound,
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
Under a wildcard bind, our own datagram to an IPv4 destination comes back mapped.

`plausible_source`'s last line is there for exactly one case: bound to the
wildcard, the source of our own datagrams is whichever local address the route
picked rather than the address we asked for, so a datagram from a loopback
address on our own port is this server talking to itself. On a `::` bind, that
address is `::ffff:127.0.0.1` - which read as a plain IPv6 address is not
`::1`, and so was taken for a client.

Milder than the budget above, because `handle_query` drops anything with QR set
before it looks at the question, so the exchange is one datagram each way rather
than a loop. It is the same missing normalisation, and the test above already
asserts the unmapped form, so leaving the mapped one out was an oversight rather
than a decision.

Bound to `::` here, since that is the deployment the mapping arises in at all,
and no socket: `plausible_source` reads `udp_bound` and nothing else.
*/
@(test)
test_mapped_loopback_on_our_own_port_is_not_a_client :: proc(t: ^testing.T) {
	PORT :: 5353
	l := Listeners {
		udp_bound = net.Endpoint{address = net.IP6_Any, port = PORT},
	}

	Case :: struct {
		client:    net.Endpoint,
		plausible: bool,
		what:      string,
	}

	CASES := []Case {
		{mapped(127, 0, 0, 1, PORT), false, "our own datagram to an IPv4 destination"},
		{mapped(127, 1, 2, 3, PORT), false, "the rest of 127/8, mapped"},
		{mapped(127, 255, 255, 254, PORT), false, "the top of 127/8, mapped"},
		{net.Endpoint{address = net.IP4_Loopback, port = PORT}, false, "the unmapped form"},
		{net.Endpoint{address = net.IP6_Loopback, port = PORT}, false, "`::1`, unmapped"},
		{net.Endpoint{address = net.IP6_Any, port = PORT}, false, "the wildcard we bound, claimed as a source"},
		// Loopback is not refused as such - only on our own port, where it can
		// only be us. A local stub resolver asks from 127.0.0.1 like anything else.
		{mapped(127, 0, 0, 1, 40000), true, "a mapped loopback client on a port of its own"},
		{mapped(127, 0, 0, 1, 0), false, "port zero outranks all of it"},
		// The edges of 127/8, which is the whole of what loopback means for IPv4.
		{mapped(126, 255, 255, 255, PORT), true, "just below 127/8, on our port"},
		{mapped(128, 0, 0, 1, PORT), true, "just above it, on our port"},
		{mapped(0, 0, 0, 1, PORT), true, "and 0.0.0.0/8 is not loopback either"},
		// Not the mapping, so not unmapped - the rule `config.address_bytes`
		// applies. `::7f00:1` is the deprecated compat form of 127.0.0.1 and is
		// not an address this stack sources datagrams from.
		{net.Endpoint{address = v6_of({0, 0, 0, 0, 0, 0, 0x7f00, 0x0001}), port = PORT}, true, "the compat form of 127.0.0.1"},
		{
			net.Endpoint{address = v6_of({0, 0, 0, 0, 0xffff, 0, 0x7f00, 0x0001}), port = PORT},
			true,
			"the translated form of 127.0.0.1",
		},
		// An ordinary client, for the same reason the test above has one.
		{mapped(192, 0, 2, 1, 40000), true, "an ordinary mapped client"},
	}

	for c in CASES {
		got := plausible_source(&l, c.client)
		testing.expectf(t, got == c.plausible, "%s: plausible_source said %v", c.what, got)
	}
}

/*
The address we bound is the address we bound, in either spelling.

The other half of `plausible_source`: a concrete bind refuses a source claiming
to be the address it is answering on, which is the self-talking loop that the
wildcard case above reaches through loopback. `::ffff:192.0.2.53` and
192.0.2.53 are one address, so a source naming one of them while we are bound to
the other is naming us.

Deliberately not a loopback address, so `is_loopback` cannot be what refuses it:
the two checks are layered here, and one that shadows the other is one that is
not being tested. Defence in depth rather than a case seen in the wild - a socket
reports its bound address the way it reports its peers', so the two forms do not
normally meet - which is the reason to have it asserted rather than a reason not
to.
*/
@(test)
test_the_bound_address_is_recognised_through_the_v4_mapping :: proc(t: ^testing.T) {
	PORT :: 5353

	mapped_bind := Listeners {
		udp_bound = mapped(192, 0, 2, 53, PORT),
	}
	v4_bind := Listeners {
		udp_bound = v4(192, 0, 2, 53, PORT),
	}

	testing.expectf(
		t,
		!plausible_source(&mapped_bind, v4(192, 0, 2, 53, PORT)),
		"an unmapped source claiming the mapped address we bound was taken for a client",
	)
	testing.expectf(
		t,
		!plausible_source(&v4_bind, mapped(192, 0, 2, 53, PORT)),
		"a mapped source claiming the address we bound was taken for a client",
	)
	// Same address, either way about, and still only on our own port: it is the
	// pair that makes a loop, not the address.
	testing.expect(t, plausible_source(&mapped_bind, v4(192, 0, 2, 53, 40000)), "a client from that address on a port of its own was refused")
	testing.expect(t, plausible_source(&v4_bind, mapped(192, 0, 2, 53, 40000)), "a client from that address on a port of its own was refused")
	// And a neighbour of it is not it.
	testing.expect(t, plausible_source(&mapped_bind, v4(192, 0, 2, 54, PORT)), "another address on our port was refused")
	testing.expect(t, plausible_source(&v4_bind, mapped(192, 0, 2, 54, PORT)), "another mapped address on our port was refused")
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
the slip belongs to the datagram pool, not to a mode the bucket is put into.

The rate is 40 rather than a handful because what that last part asserts is the
1-in-`SLIP` spacing, and the truncated answers come out of a pool of their own at
an eighth of the rate - so the rate has to be large enough that the pool has room
for the slips being counted. `test_the_slip_budget_is_a_pool_of_its_own` is where
running it dry is the subject.
*/
@(test)
test_stream_queries_are_refused_rather_than_truncated :: proc(t: ^testing.T) {
	RATE :: 40
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

	limited, slipped, _ := rate_limit_stats(r)
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
which *datagram* comes back truncated. Alternating traffic is where that shows -
with the connection counted, one interleaving truncates every over-limit datagram,
well past the 1-in-`slip` an operator asked for, and the other truncates none of
them and leaves a client behind a busy NAT with nothing to act on.

Charging the two classes to separate pools is what keeps a connection away from
this counter, so the test reads as one about the pools now. It is kept as one about
the slip because that is the behaviour a reader can check: both budgets are spent
dry first, since a refusal is the only way a stream query gets far enough to be
capable of touching `over` at all.

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
		testing.expect(t, stream_rate_check(r, client, at(0)), "the stream budget refused a query it had room for")
	}
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}

	testing.expect(t, !stream_rate_check(r, client, at(0)), "an over-budget query was answered on a connection")

	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Drop)
	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Truncate)

	limited, slipped, _ := rate_limit_stats(r)
	// Three over the budget: the connection's and the two datagrams.
	testing.expect_value(t, limited, u64(3))
	testing.expect_value(t, slipped, u64(1))
}

/*
Nor does a query a connection was *given* put the slip back to the start.

The counter's rule is one rule, not two: `over` counts over-limit datagrams since
the last one a slip could have been spent on, so a query on a connection - which a
slip can never be spent on - has to leave it exactly where it was, answered or
refused. Clearing it would be the same interference as advancing it, from the other
end: one connection in the prefix asking while its neighbours are over the budget
would zero the count between every pair of over-limit datagrams, and at any `slip`
above 2 no datagram would come back truncated at all - the client behind the busy
NAT the slip exists for would be left with nothing to act on.

Three over-limit datagrams, then a query answered on a connection out of the pool
the flood has not touched, and then the fourth datagram - which is the SLIPth and
must be the one that is truncated.
*/
@(test)
test_a_stream_answer_does_not_reset_the_slip :: proc(t: ^testing.T) {
	SLIP :: 4
	r := make_rate_limiter(1, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(198, 51, 103, 9)
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Allow)
	}
	for _ in 0 ..< SLIP - 1 {
		testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Drop)
	}

	testing.expect(t, stream_rate_check(r, client, at(0)), "the stream budget refused a query it had room for")

	testing.expect_value(t, rate_check(r, client, at(0)), Rate_Verdict.Truncate)

	limited, slipped, _ := rate_limit_stats(r)
	testing.expect_value(t, limited, u64(SLIP))
	testing.expect_value(t, slipped, u64(1))
}

/*
A budget per prefix per class, and a datagram flood cannot reach the one
connections are answered out of. `test_a_datagram_flood_cannot_stop_a_prefix_connecting`
is the same property for the third of them, the arrivals.

Stated as the attack rather than as a property, because the attack is the reason
the separation is there. The bucket is keyed on the query's source address, and over
UDP the sender writes that field: somebody spoofing sources inside prefix P, at
more than the configured rate, keeps P's datagram pool empty for as long as they
care to run it. When one pool served both, every genuine TCP, DoT or DoH connection
from P then had its first query refused and its connection closed - so a party who
could not receive a byte at P, and who was asking none of P's questions, decided
what this server did for the clients who live there, on a default configuration. It
also emptied the budget the slip's own advice sends a client to, which is the whole
of what a truncated answer is for.

Both directions, since a pool that can be drained from the other side is not a
separate pool: the flood must not reach the connections, and a client pipelining
over a connection must not empty what its neighbours' datagrams are answered out
of.

The cost of the split is asserted here too rather than left implicit. The prefix
draws RATE*BURST out of each pool, so a client willing to use every way in gets a
multiple of what an operator configured - a constant, and the trade is argued at
the top of `ratelimit.odin`. What must not come back is one pool lending to the
other.
*/
@(test)
test_the_stream_budget_is_not_the_datagram_one :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// The flood: one prefix's datagram pool spent dry and held there.
	victim := v4(203, 0, 113, 20)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect_value(t, rate_check(r, victim, at(0)), Rate_Verdict.Allow)
	}
	for _ in 0 ..< 50 {
		testing.expect_value(t, rate_check(r, victim, at(0)), Rate_Verdict.Drop)
	}

	// A real client in the same /24, over a connection: a budget of its own, and
	// the whole of it.
	answered := 0
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		if stream_rate_check(r, v4(203, 0, 113, 21), at(0)) {
			answered += 1
		}
	}
	testing.expectf(
		t,
		answered == RATE * RRL_BURST_SECONDS,
		"a datagram flood took %d of the %d answers the prefix's connections were owed",
		answered,
		RATE * RRL_BURST_SECONDS,
	)
	// A budget of its own, not an exemption.
	testing.expect(
		t,
		!stream_rate_check(r, v4(203, 0, 113, 22), at(0)),
		"the stream budget answered past what it holds",
	)

	// The other way about, on a prefix of its own: a pipelining client spends the
	// stream pool dry and its neighbours' datagrams are answered anyway.
	stream_first := v6(0xcccc, 1)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, stream_rate_check(r, stream_first, at(0)), "the stream budget refused a query it had room for")
	}
	testing.expect(t, !stream_rate_check(r, stream_first, at(0)), "the stream budget answered past what it holds")
	testing.expect_value(t, rate_check(r, v6(0xcccc, 2), at(0)), Rate_Verdict.Allow)
}

/*
Opening a connection is charged, which is the load nothing here used to see.

The client this is about asks nothing at all: it dials, completes a TLS handshake
and hangs up. So it spends no datagram budget and no stream budget however fast it
goes, and the connection table it touches is a table it holds one slot of for the
length of a handshake - measured, 6,922 of them a second and 1.4 of four cores,
with every counter this server published reading zero
(`bench/results/2026-09-03-handshake-floods.md`).

The numbers are the same shape as every other pool: `rate * RRL_BURST_SECONDS`
banked, and a second of quiet worth a second of the rate.
*/
@(test)
test_connections_are_charged_to_a_budget_of_their_own :: proc(t: ^testing.T) {
	RATE :: 100
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	client := v4(203, 0, 113, 40)
	opened := 0
	for _ in 0 ..< 1000 {
		if conn_rate_check(r, client, at(0)) {
			opened += 1
		}
	}
	testing.expectf(
		t,
		opened == RATE * RRL_BURST_SECONDS,
		"a full bucket accepted %d connections at once, expected %d",
		opened,
		RATE * RRL_BURST_SECONDS,
	)
	testing.expect(t, !conn_rate_check(r, client, at(0)), "a connection was accepted past what the pool holds")

	// A quarter of a second is a quarter of the rate, and not a connection more.
	refilled := 0
	for _ in 0 ..< 1000 {
		if conn_rate_check(r, client, at(250)) {
			refilled += 1
		}
	}
	testing.expectf(t, refilled == RATE / 4, "a quarter second refilled %d connections, expected %d", refilled, RATE / 4)

	// Counted, and counted apart from the queries: nothing was asked here, so
	// `limited=` must not move for it - a handshake flood and a query flood are
	// different problems with different settings behind them.
	limited, slipped, conn_limited := rate_limit_stats(r)
	testing.expect_value(t, limited, u64(0))
	testing.expect_value(t, slipped, u64(0))
	// Every dial above that was not accepted: 1000 less the burst, the one
	// asserted refusal between the loops, and 1000 less the quarter-second refill.
	refusals := u64(1000 - opened) + 1 + u64(1000 - refilled)
	testing.expectf(t, conn_limited == refusals, "conn_limited counted %d refusals, expected %d", conn_limited, refusals)
}

/*
A spoofed datagram flood must not be able to stop a prefix's clients connecting.

The sharper half of the separation the top of `ratelimit.odin` argues for. A UDP
source address is written by whoever sent the datagram, so if arrivals were
charged to the datagram pool, anyone with a raw socket could keep prefix P's pool
empty and P's real clients would be refused *on accept* - not refused an answer
they could retry for, but unable to get a connection at all. That is a door
further out than the one the stream pool closed.

Both ways round, since a pool that can be drained from the other side is not a
separate pool: the flood must not reach the arrivals, and a client dialling flat
out must not empty what its neighbours' datagrams and queries are answered out of.
*/
@(test)
test_a_datagram_flood_cannot_stop_a_prefix_connecting :: proc(t: ^testing.T) {
	RATE :: 10
	SLIP :: 2
	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	// The flood: one prefix's datagram pool spent dry, and its slip pool with it.
	victim := v4(198, 51, 100, 30)
	for _ in 0 ..< 1000 {
		_ = rate_check(r, victim, at(0))
	}
	testing.expect_value(t, rate_check(r, victim, at(0)), Rate_Verdict.Drop)

	// A real client in the same /24 opens its prefix's whole allowance anyway.
	opened := 0
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		if conn_rate_check(r, v4(198, 51, 100, 31), at(0)) {
			opened += 1
		}
	}
	testing.expectf(
		t,
		opened == RATE * RRL_BURST_SECONDS,
		"a datagram flood took %d of the %d connections the prefix was owed",
		opened,
		RATE * RRL_BURST_SECONDS,
	)
	// A budget of its own, not an exemption.
	testing.expect(
		t,
		!conn_rate_check(r, v4(198, 51, 100, 32), at(0)),
		"the connection budget accepted past what it holds",
	)

	// The other way about, on a prefix of its own: a client dialling flat out
	// spends the connection pool dry, and the prefix's datagrams and its queries
	// on the connections it did get are answered regardless.
	dialer := v6(0xdddd, 1)
	for _ in 0 ..< RATE * RRL_BURST_SECONDS {
		testing.expect(t, conn_rate_check(r, dialer, at(0)), "a connection was refused that the pool had room for")
	}
	testing.expect(t, !conn_rate_check(r, dialer, at(0)), "the connection budget accepted past what it holds")
	testing.expect_value(t, rate_check(r, v6(0xdddd, 2), at(0)), Rate_Verdict.Allow)
	testing.expect(t, stream_rate_check(r, v6(0xdddd, 2), at(0)), "dialling emptied the pool the queries are answered out of")
}

/*
The arrival budget is per prefix, like everything else here.

Same reasoning: an attacker picks addresses freely inside the range they hold, so
a bound kept per address is one they multiply by picking another - and a bound
kept globally would let one dialer decide whether anybody else may connect, which
is the failure a shared bound always is. Two addresses in one /24 share; two /24s
do not.
*/
@(test)
test_the_connection_budget_is_kept_per_prefix :: proc(t: ^testing.T) {
	RATE :: 10
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)

	// One /24 dialled dry, one address at a time.
	opened := 0
	for i in 0 ..< 1000 {
		if conn_rate_check(r, v4(203, 0, 113, u8(i % 256)), at(0)) {
			opened += 1
		}
	}
	testing.expectf(
		t,
		opened == RATE * RRL_BURST_SECONDS,
		"256 addresses in one /24 opened %d connections, expected the prefix's %d",
		opened,
		RATE * RRL_BURST_SECONDS,
	)

	// The /24 beside it has its own, untouched.
	testing.expect(t, conn_rate_check(r, v4(203, 0, 114, 1), at(0)), "a neighbouring /24 was refused a connection")
	// And so does another /64.
	testing.expect(t, conn_rate_check(r, v6(0xeeee, 1), at(0)), "an IPv6 prefix was refused a connection")
}

// Which of a prefix's pools a charging thread below spends from. All three
// entry points are hammered, because all three decrement under the one lock.
@(private = "file")
Charge :: enum {
	Datagram,
	Stream,
	Connection,
}

// One charging thread's share of the work below, and what it saw.
@(private = "file")
Hammer :: struct {
	limiter:   ^Rate_Limiter,
	client:    net.Endpoint,
	charge:    Charge,
	rounds:    int,
	allowed:   int,
	truncated: int,
}

@(private = "file")
hammer :: proc(h: ^Hammer) {
	for _ in 0 ..< h.rounds {
		switch h.charge {
		case .Stream:
			if stream_rate_check(h.limiter, h.client, at(0)) {
				h.allowed += 1
			}
		case .Connection:
			if conn_rate_check(h.limiter, h.client, at(0)) {
				h.allowed += 1
			}
		case .Datagram:
			switch rate_check(h.limiter, h.client, at(0)) {
			case .Allow:
				h.allowed += 1
			case .Truncate:
				h.truncated += 1
			case .Drop:
			}
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

A third of the threads charge datagrams, a third queries on connections and a
third connections opened, so all three pools are spent concurrently and each is
asserted to the token: they live in one bucket behind one lock, and a pool that
came out over its capacity would be one the others' decrements had raced with. The
arrival pool belongs here as much as the other two - there is an accept loop per
stream transport, so three threads charge it whatever the connections are doing.

Every thread charges the same prefix at the same instant, so nothing refills
during the run and the arithmetic is exact: a full pool and no more, whoever spent
it. Unlocked, the totals come out above the capacity - by how much depends on the
interleaving, which is why the assertions are equalities rather than thresholds.
*/
@(test)
test_rate_limit_accounts_exactly_under_concurrent_callers :: proc(t: ^testing.T) {
	RATE :: 80
	SLIP :: 2
	// One per class, three deep, so every pool has several threads on it.
	PER_CLASS :: 3
	THREADS :: PER_CLASS * len(Charge)
	ROUNDS :: 500
	CAPACITY :: RATE * RRL_BURST_SECONDS
	// The slip pool, an eighth of the rate; 80 so that eighth divides evenly.
	SLIPS :: RATE / RRL_SLIP_SHARE * RRL_BURST_SECONDS

	r := make_rate_limiter(RATE, SLIP)
	defer destroy_rate_limiter(r)

	client := v4(192, 0, 2, 40)
	hammers: [THREADS]Hammer
	threads: [THREADS]^thread.Thread
	for i in 0 ..< THREADS {
		hammers[i] = Hammer {
			limiter = r,
			client  = client,
			charge  = Charge(i % len(Charge)),
			rounds  = ROUNDS,
		}
		threads[i] = thread.create_and_start_with_poly_data(&hammers[i], hammer)
		if threads[i] == nil {
			testing.expect(t, false, "could not start a charging thread")
			return
		}
	}
	spent: [Charge]int
	truncated := 0
	for i in 0 ..< THREADS {
		thread.join(threads[i])
		thread.destroy(threads[i])
		spent[hammers[i].charge] += hammers[i].allowed
		truncated += hammers[i].truncated
	}

	for charge in Charge {
		testing.expectf(
			t,
			spent[charge] == CAPACITY,
			"%d threads spent %d out of the %s pool, which holds %d",
			PER_CLASS,
			spent[charge],
			charge,
			CAPACITY,
		)
	}

	limited, slipped, conn_limited := rate_limit_stats(r)
	// Each third spent its own pool, so each went over by its own rounds less that
	// pool's capacity.
	over := u64(PER_CLASS * ROUNDS - CAPACITY)
	/*
	`limited` is the datagrams and the queries, and the connections are counted
	apart - see `Rate_Limiter.conn_limited`. A change that folded the two together
	would leave this test passing on the sum and lose the distinction an operator
	reads the counters for, so both are asserted.
	*/
	testing.expect_value(t, limited, over * 2)
	testing.expect_value(t, conn_limited, over)
	/*
	The slip pool spent to the token, like the other three: this flood offers far
	more than `SLIPS` over-limit datagrams, so what comes back truncated is the
	pool and not a share of the arrival rate - and it is that exactly, which a
	decrement lost between two threads would put it over. Neither the connections'
	queries nor their arrivals are among them: they reach neither the pool nor
	`over`.
	*/
	testing.expect(t, over / SLIP > SLIPS, "the flood was too small to run the slip pool dry")
	testing.expect_value(t, slipped, u64(SLIPS))
	testing.expect_value(t, u64(truncated), u64(SLIPS))
}

/*
An override, written the way the loader hands one over.

The loader fills `slip` in from the top-level figure when an entry does not name
one, so a helper that left it at zero here would be testing a configuration the
loader cannot produce - `slip: 0` means "drop them all" rather than "inherit".
*/
@(private = "file")
override :: proc(text: string, rps: int, slip: int) -> config.Rate_Limit_Override {
	p, ok := config.parse_prefix(text)
	if !ok {
		panic("the test named a prefix that does not parse")
	}
	return {prefix = p, responses_per_second = rps, slip = slip}
}

/*
How many datagrams a prefix is answered in full, out of a bucket brought to
`ms`, offering far more than any budget under test.
*/
@(private = "file")
drain :: proc(r: ^Rate_Limiter, client: net.Endpoint, ms: i64 = 0) -> int {
	allowed := 0
	for _ in 0 ..< 20_000 {
		if rate_check(r, client, at(ms)) == .Allow {
			allowed += 1
		}
	}
	return allowed
}

/*
A named network is answered out of its own figure, and nothing else moves.

The whole of #234: the budget is kept per /24 and per /64 because that is the
granularity an attacker picks addresses within, and the consequence is that the
unit means "a household" on a LAN and "thousands of subscribers behind carrier
NAT" on the internet - with one figure for both and no way to say which a given
prefix was. So a prefix can be named and given its own.

Asserted in both directions, because an override that leaked would be worse than
one that did nothing: the named network gets its figure, and the /24 beside it
gets the default rather than the override's.
*/
@(test)
test_an_override_gives_a_named_network_its_own_budget :: proc(t: ^testing.T) {
	RATE :: 10
	CGNAT :: 100
	overrides := []config.Rate_Limit_Override{override("198.51.100.0/24", CGNAT, 2)}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	named := drain(r, v4(198, 51, 100, 7))
	testing.expectf(
		t,
		named == CGNAT * RRL_BURST_SECONDS,
		"the named /24 was answered %d datagrams, expected its own %d",
		named,
		CGNAT * RRL_BURST_SECONDS,
	)

	// The /24 next door, which the file says nothing about.
	other := drain(r, v4(198, 51, 101, 7))
	testing.expectf(
		t,
		other == RATE * RRL_BURST_SECONDS,
		"an unnamed /24 was answered %d datagrams, expected the default %d",
		other,
		RATE * RRL_BURST_SECONDS,
	)

	// And it refills at its own rate too, not the default's: a tier that got the
	// capacity right and the rate wrong would pass the two checks above.
	refilled := drain(r, v4(198, 51, 100, 7), 1000)
	testing.expectf(
		t,
		refilled == CGNAT,
		"a second of refill answered %d datagrams, expected the named network's %d",
		refilled,
		CGNAT,
	)
}

/*
Where two entries both contain a client, the more specific one decides.

An operator who writes `10.0.0.0/8` beside `10.1.2.0/24` means the /24's figure
inside it and the /8's everywhere else, which is how every routing table and
every ACL they have met behaves. The alternative - first match wins - would make
the figure a client gets depend on the order the file happens to list the
networks in, which is the one thing `config.prefix_match` promises does not
decide anything.
*/
@(test)
test_the_most_specific_override_decides :: proc(t: ^testing.T) {
	RATE :: 10
	WIDE :: 50
	NARROW :: 500
	// Written widest first, so a first-match implementation would answer with
	// `WIDE` for the /24 and pass nothing below.
	overrides := []config.Rate_Limit_Override {
		override("10.0.0.0/8", WIDE, 2),
		override("10.1.2.0/24", NARROW, 2),
	}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	inside := drain(r, v4(10, 1, 2, 3))
	testing.expectf(
		t,
		inside == NARROW * RRL_BURST_SECONDS,
		"the /24 inside the /8 was answered %d, expected the /24's %d",
		inside,
		NARROW * RRL_BURST_SECONDS,
	)

	elsewhere := drain(r, v4(10, 9, 9, 9))
	testing.expectf(
		t,
		elsewhere == WIDE * RRL_BURST_SECONDS,
		"a /24 elsewhere in the /8 was answered %d, expected the /8's %d",
		elsewhere,
		WIDE * RRL_BURST_SECONDS,
	)

	outside := drain(r, v4(192, 0, 2, 1))
	testing.expectf(
		t,
		outside == RATE * RRL_BURST_SECONDS,
		"a /24 outside both was answered %d, expected the default %d",
		outside,
		RATE * RRL_BURST_SECONDS,
	)
}

/*
An override carries its own `slip`, because the two settings are one decision.

A public prefix wants a large budget and often `slip: 0`: a truncated answer is
an invitation to open a connection, and an operator who has concluded that
nobody legitimate is behind the address being flooded does not want to send one.
A LAN wants the small budget and `slip: 2`. Under one global `slip` those two
shapes cannot both be configured, which is what #234 means by "two coherent
profiles rather than four independent knobs".
*/
@(test)
test_an_override_carries_its_own_slip :: proc(t: ^testing.T) {
	RATE :: 10
	overrides := []config.Rate_Limit_Override{override("203.0.113.0/24", RATE, 0)}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	/*
	Counted in the same pass that spends the budget, not after it.

	The slip pool is an eighth of the figure and holds two seconds of that, so at
	`RATE` 10 it is two tokens: a first pass that drained the datagram budget
	would spend both on the way and leave a second pass reading zero whatever the
	`slip` was. That is the pool doing its job, and it would have made this case
	pass for the wrong reason.
	*/
	named, elsewhere := 0, 0
	for _ in 0 ..< 1000 {
		if rate_check(r, v4(203, 0, 113, 9), at(0)) == .Truncate {
			named += 1
		}
		if rate_check(r, v4(192, 0, 2, 9), at(0)) == .Truncate {
			elsewhere += 1
		}
	}
	testing.expectf(t, named == 0, "a network configured slip: 0 was sent %d truncated answers", named)
	// The network on the default is still invited to TCP, so the row above is
	// this entry's `slip` and not a limiter that stopped slipping.
	testing.expect(t, elsewhere > 0, "the default slip stopped working once an override set slip: 0")
}

/*
A bucket handed from one prefix to another is accounted on the newcomer's
figures.

The one ordering hazard in `rate_bucket`. The takeover test has to weigh what is
in the bucket against the capacity of the prefix that *has* it, and the claim has
to fill it to the capacity of the prefix taking it over. Read the other way round,
a newcomer from a network with a large figure would find a small bucket "not yet
refilled" and never take it, and a newcomer with a small figure would be handed a
bucket filled past anything it is entitled to.

Reaching it needs an actual collision, and the table is 16,384 buckets behind a
hash keyed with process entropy - so the collision is searched for rather than
constructed. Every /24 in `10.0.0.0/8` is walked to fill the table, then a /24
outside the override is tried until it lands on a bucket a `10.x` prefix already
holds. With four times as many prefixes as buckets the first candidate normally
does.
*/
@(test)
test_a_bucket_changing_hands_takes_the_new_prefixs_figures :: proc(t: ^testing.T) {
	RATE :: 10
	WIDE :: 500
	overrides := []config.Rate_Limit_Override{override("10.0.0.0/8", WIDE, 2)}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	// Which bucket each /24 of the override lands in, so a collision can be
	// looked up rather than hunted pairwise.
	owners := make(map[u64]net.Endpoint, 1 << 16)
	defer delete(owners)
	for a in 0 ..< 256 {
		for b in 0 ..< 256 {
			client := v4(10, u8(a), u8(b), 1)
			owners[prefix_key(r, client.address) % RRL_BUCKETS] = client
		}
	}

	// A /24 on the default tier that shares a bucket with one on the override's.
	newcomer: net.Endpoint
	incumbent: net.Endpoint
	found := false
	search: for a in 0 ..< 256 {
		for b in 0 ..< 256 {
			candidate := v4(192, u8(a), u8(b), 1)
			slot := prefix_key(r, candidate.address) % RRL_BUCKETS
			if owner, ok := owners[slot]; ok {
				newcomer, incumbent, found = candidate, owner, true
				break search
			}
		}
	}
	if !testing.expect(t, found, "no collision was found, so the takeover path was never reached") {
		return
	}

	/*
	The incumbent spends its own budget dry and is left there. Its bucket now
	holds nothing, and nothing is below the *default* capacity as well as below
	the override's - so a takeover test that weighed the newcomer's figures would
	refuse the handover just the same, and this half of the case says only that
	the bucket is occupied.
	*/
	testing.expect_value(t, drain(r, incumbent), WIDE * RRL_BURST_SECONDS)

	/*
	A second later the incumbent's pools have refilled by a second of `WIDE`,
	which is under its own capacity of `WIDE * 2`, so the bucket is *not* handed
	over - and the newcomer shares what is in it. What it can spend there is the
	incumbent's tokens, at the incumbent's rate, because that is what sharing a
	bucket has always meant: `RRL_BUCKETS` calls it "what collides shares a
	budget", and with figures per prefix it is a rate as well.

	Asserted rather than glossed over, because it is the one direction of this
	change that gives a prefix *more* than its own configuration says. It is not
	reachable on purpose: the collision was hunted for above over 65,536 prefixes
	against a table keyed with process entropy, which is exactly what an attacker
	outside this process cannot do. See `Rate_Bucket.tier`.
	*/
	shared := drain(r, newcomer, 1000)
	testing.expectf(
		t,
		shared == WIDE,
		"a client sharing a named network's bucket was answered %d, expected the second of %d that bucket had accrued",
		shared,
		WIDE,
	)

	/*
	And once the incumbent has been quiet long enough to be entitled to
	everything, the bucket does change hands - to the newcomer's figures and not
	the incumbent's. This is the half that would break if the claim filled the
	bucket to the tier it read before reassigning.
	*/
	taken := drain(r, newcomer, 60_000)
	testing.expectf(
		t,
		taken == RATE * RRL_BURST_SECONDS,
		"the newcomer took over a refilled bucket and was answered %d, expected its own %d",
		taken,
		RATE * RRL_BURST_SECONDS,
	)
}

/*
A limiter with no overrides is the limiter that was here before there were any.

The guard on the whole change: `tiers[0]` is the configured pair, every bucket
starts on tier 0, and `resolve_tier` returns 0 without looking at anything when
the list is empty. So a deployment that names no network pays nothing for the
setting existing - not a walk per bucket claim, and not a byte in the table.
*/
@(test)
test_no_overrides_is_the_default_everywhere :: proc(t: ^testing.T) {
	RATE :: 25
	r := make_rate_limiter(RATE, 2)
	defer destroy_rate_limiter(r)

	testing.expect_value(t, len(r.tiers), 1)
	testing.expect_value(t, len(r.prefixes), 0)
	testing.expect_value(t, r.tiers[0].slip, 2)
	testing.expect_value(t, resolve_tier(r, v4(198, 51, 100, 1).address), u8(0))

	for client in ([]net.Endpoint{v4(198, 51, 100, 1), v4(10, 0, 0, 1), v6(0xabcd, 1)}) {
		got := drain(r, client)
		testing.expectf(
			t,
			got == RATE * RRL_BURST_SECONDS,
			"a prefix was answered %d datagrams with no overrides configured, expected %d",
			got,
			RATE * RRL_BURST_SECONDS,
		)
	}
}

/*
An IPv6 override is keyed on the /64, like everything else here.

The families are separate all the way down - `client_prefix` reads three bytes of
IPv4 and eight of IPv6, and `config.prefix_match` refuses to compare one against
the other - so this is the half of the change that a v4-only test would not have
reached.
*/
@(test)
test_an_ipv6_override_is_keyed_on_the_64 :: proc(t: ^testing.T) {
	RATE :: 10
	BIG :: 200
	// The /32 the `v6` helper's addresses sit in. It varies the third group, so
	// `2001:db8::/32` is the shortest entry that covers every /64 it can
	// produce - a /48 would claim one of them and miss the rest.
	overrides := []config.Rate_Limit_Override{override("2001:db8::/32", BIG, 2)}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	inside := drain(r, v6(0x1111, 1))
	testing.expectf(
		t,
		inside == BIG * RRL_BURST_SECONDS,
		"a /64 inside the named /32 was answered %d, expected %d",
		inside,
		BIG * RRL_BURST_SECONDS,
	)

	// An IPv4 client is not inside an IPv6 entry, however the bytes line up.
	outside := drain(r, v4(32, 1, 13, 184))
	testing.expectf(
		t,
		outside == RATE * RRL_BURST_SECONDS,
		"an IPv4 client matched an IPv6 override: answered %d, expected the default %d",
		outside,
		RATE * RRL_BURST_SECONDS,
	)
}

/*
A v4-mapped client matches an IPv4 override.

The deployment `config.source_allowed` goes out of its way to support - an IPv4
client arriving on a socket bound to `::` - and the one every judgement about a
source has to make the same way. An override resolved without undoing the
mapping would read such a client as IPv6, miss the entry, and put the whole IPv4
side of a wildcard listener on the default while its operator was looking at a
configuration that said otherwise.
*/
@(test)
test_a_mapped_client_matches_an_ipv4_override :: proc(t: ^testing.T) {
	RATE :: 10
	BIG :: 100
	overrides := []config.Rate_Limit_Override{override("198.51.100.0/24", BIG, 2)}

	r := make_rate_limiter(RATE, 2, overrides)
	defer destroy_rate_limiter(r)

	got := drain(r, mapped(198, 51, 100, 7))
	testing.expectf(
		t,
		got == BIG * RRL_BURST_SECONDS,
		"a v4-mapped client was answered %d, expected the IPv4 override's %d",
		got,
		BIG * RRL_BURST_SECONDS,
	)
}

/*
The lines an operator reads name the network and the figures it will be charged.

These lines are the whole of the visibility this setting has: the counters are
not labelled per prefix, so nothing else can say which figures a client was
accounted against, and the commonest way to get a per-prefix setting wrong is an
entry that does not match the clients it was meant for. A renderer that dropped a
network, or printed a figure the limiter does not use, would leave that mistake
undiagnosable.

The truncated-answer budget is the one worth asserting: an eighth of the figure
and at least one a second, which is arithmetic the operator did not write and
cannot check against the file.
*/
@(test)
test_the_override_lines_say_what_will_be_charged :: proc(t: ^testing.T) {
	overrides := []config.Rate_Limit_Override {
		override("198.51.100.0/24", 4000, 2),
		override("203.0.113.0/24", 50, 0),
	}
	lines := rate_limit_override_lines(overrides, context.temp_allocator)
	// A header and one line per network.
	if !testing.expect_value(t, len(lines), 3) {
		return
	}

	testing.expect(t, strings.contains(lines[0], "2 network(s)"), "the header did not count the networks")
	// And says what decides where they overlap, since the lines are in file
	// order and file order decides nothing.
	testing.expect(t, strings.contains(lines[0], "most specific"), "the header did not say which entry wins")

	testing.expect(t, strings.contains(lines[1], "198.51.100.0/24"), "the first network was not named")
	testing.expect(t, strings.contains(lines[1], "4000 responses/s"), "the first figure was not printed")
	// 4000/8, derived by `make_rate_tier` and nowhere in the file.
	testing.expect(t, strings.contains(lines[1], "500 truncated answers/s"), "the derived slip budget was not printed")

	testing.expect(t, strings.contains(lines[2], "203.0.113.0/24"), "the second network was not named")
	testing.expect(t, strings.contains(lines[2], "50 responses/s"), "the second figure was not printed")
	// `slip: 0` is a different sentence, not a slip budget of zero.
	testing.expect(t, strings.contains(lines[2], "dropped"), "slip: 0 was not reported as dropping")

	// Nothing configured, nothing said - so a deployment with no overrides gets
	// no line at startup and none under `--check`.
	testing.expect_value(t, len(rate_limit_override_lines(nil, context.temp_allocator)), 0)
	free_all(context.temp_allocator)
}
