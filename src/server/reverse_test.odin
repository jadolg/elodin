package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
The reverse name for fd00::1 and for fe80::1, written out rather than built by a
helper.

A helper that assembles a nibble name shares whatever the parser believes about
nibble order, so the two would agree with each other over a reversed address as
happily as over a correct one. These are literal, and a miscounted label cannot
pass: the parser demands exactly thirty-two of them, so a typo fails the test
rather than hiding in it. The second is upper case because DNS names compare
without regard to it (RFC 4343) and a client is free to ask that way.
*/
FD00_1_REVERSE ::
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa."
FE80_1_REVERSE ::
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.IP6.ARPA."

@(test)
test_reverse_v4_name_parses_to_its_address :: proc(t: ^testing.T) {
	addr, ok := parse_reverse_v4("50.1.168.192.in-addr.arpa.")
	testing.expect(t, ok, "the reverse name of 192.168.1.50 should parse")
	testing.expect_value(t, addr, [4]u8{192, 168, 1, 50})

	upper, upper_ok := parse_reverse_v4("50.1.168.192.IN-ADDR.ARPA.")
	testing.expect(t, upper_ok, "the suffix comparison must fold case")
	testing.expect_value(t, upper, [4]u8{192, 168, 1, 50})
}

/*
The names that are not a host's address, each of which would otherwise become a
PTR for an address that was never written down.

`1.168.192.in-addr.arpa.` is a zone cut, five labels is a name below a host,
`050` is a spelling the reverse tree does not use - taking it would give one
address two names to be found by - and `256` is not an octet at all.
*/
@(test)
test_reverse_v4_rejects_names_that_are_not_a_host :: proc(t: ^testing.T) {
	bad := [?]string {
		"1.168.192.in-addr.arpa.",
		"192.in-addr.arpa.",
		"in-addr.arpa.",
		"1.50.1.168.192.in-addr.arpa.",
		"050.1.168.192.in-addr.arpa.",
		"256.1.168.192.in-addr.arpa.",
		"1234.1.168.192.in-addr.arpa.",
		"x.1.168.192.in-addr.arpa.",
		".1.168.192.in-addr.arpa.",
		"50.1.168.192.in-addr.arpa",
		"50.1.168.192.example.com.",
		"50.1.168.192.notin-addr.arpa.",
	}
	for name in bad {
		_, ok := parse_reverse_v4(name)
		testing.expectf(t, !ok, "%s must not parse as a host's reverse name", name)
	}
}

@(test)
test_reverse_v6_name_parses_to_its_address :: proc(t: ^testing.T) {
	ula, ula_ok := parse_reverse_v6(FD00_1_REVERSE)
	testing.expect(t, ula_ok, "the reverse name of fd00::1 should parse")
	want_ula := [16]u8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testing.expect_value(t, ula, want_ula)

	ll, ll_ok := parse_reverse_v6(FE80_1_REVERSE)
	testing.expect(t, ll_ok, "an upper-case nibble name should parse")
	want_ll := [16]u8{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testing.expect_value(t, ll, want_ll)
}

// The nibble order is the whole of the v6 parse, so it is pinned on an address
// whose bytes are all different: a reversal or a swapped half shows up here and
// nowhere else.
@(test)
test_reverse_v6_nibble_order :: proc(t: ^testing.T) {
	// fd12:3400:: - the first four bytes are fd 12 34 00 and the rest zero, so
	// the name runs 0.0.…0.0.4.3.2.1.d.f.
	name :: "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.d.f.ip6.arpa."
	addr, ok := parse_reverse_v6(name)
	testing.expect(t, ok, "the reverse name of fd12:3400:: should parse")
	testing.expect_value(t, addr, [16]u8{0xfd, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

@(test)
test_reverse_v6_rejects_names_that_are_not_a_host :: proc(t: ^testing.T) {
	bad := [?]string {
		"d.f.ip6.arpa.",
		"ip6.arpa.",
		// Thirty-one nibbles, and thirty-three.
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
		// A two-character label, which makes the length right and the shape wrong.
		"10.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
		// A label that is not a hex digit.
		"g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
	}
	for name in bad {
		_, ok := parse_reverse_v6(name)
		testing.expectf(t, !ok, "%s must not parse as a host's reverse name", name)
	}
}

/*
An answer list that outlives the procedure that wrote it.

`[]T{...}` slices a temporary the compiler puts in the enclosing frame, so a
rule set built that way and returned carries slices into a frame that has gone -
which reads as rules matching addresses nobody configured rather than as a
crash. Copying into the temporary allocator keeps the list alive for as long as
the test that asked for it.
*/
@(private = "file")
answers_of :: proc(list: ..config.Rewrite_Answer) -> []config.Rewrite_Answer {
	out := make([]config.Rewrite_Answer, len(list), context.temp_allocator)
	copy(out, list)
	return out
}

// The rules the itest and the example config are written against: one host, one
// wildcard, one alias of the host, and one name pointed at public space.
@(private = "file")
sample_rules :: proc() -> []config.Rewrite {
	rules := make([]config.Rewrite, 5, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "nas.home.",
		answers = answers_of(
			{kind = .A, v4 = {192, 168, 1, 50}},
			{kind = .AAAA, v6 = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		),
		ttl     = 111,
	}
	rules[1] = config.Rewrite {
		domain   = "lan.",
		wildcard = true,
		answers  = answers_of({kind = .A, v4 = {10, 0, 0, 1}}),
		ttl      = 300,
	}
	rules[2] = config.Rewrite {
		domain  = "media.home.",
		answers = answers_of({kind = .A, v4 = {192, 168, 1, 50}}),
		ttl     = 300,
	}
	rules[3] = config.Rewrite {
		domain  = "www.example.org.",
		answers = answers_of({kind = .A, v4 = {203, 0, 113, 9}}),
		ttl     = 300,
	}
	rules[4] = config.Rewrite {
		domain  = "sink.example.org.",
		answers = answers_of({kind = .A, v4 = {0, 0, 0, 0}}, {kind = .A, v4 = {127, 0, 0, 1}}),
		ttl     = 300,
	}
	return rules
}

/*
The address an operator wrote down gets its name back, in both families, with
the rule's own TTL.
*/
@(test)
test_reverse_rewrite_answers_a_configured_address :: proc(t: ^testing.T) {
	rules := sample_rules()

	domain, ttl, found := reverse_rewrite_target(rules, "50.1.168.192.in-addr.arpa.")
	testing.expect(t, found, "192.168.1.50 is named by a rewrite and should have a reverse")
	testing.expect_value(t, domain, "nas.home.")
	testing.expect_value(t, ttl, u32(111))

	v6_domain, v6_ttl, v6_found := reverse_rewrite_target(rules, FD00_1_REVERSE)
	testing.expect(t, v6_found, "fd00::1 is named by a rewrite and should have a reverse")
	testing.expect_value(t, v6_domain, "nas.home.")
	testing.expect_value(t, v6_ttl, u32(111))

	free_all(context.temp_allocator)
}

/*
Two names for one address is legal, so one of them has to be chosen, and the
choice is the one an operator can predict: the first rule in the file, which is
the precedence `find_rewrite` gives the forward direction.
*/
@(test)
test_reverse_rewrite_takes_the_first_rule :: proc(t: ^testing.T) {
	rules := sample_rules()
	domain, _, found := reverse_rewrite_target(rules, "50.1.168.192.in-addr.arpa.")
	testing.expect(t, found, "a duplicated address still has a reverse")
	testing.expect_value(t, domain, "nas.home.")

	// The same two rules the other way round, to show the order is what decided
	// it rather than anything about the names themselves.
	swapped := make([]config.Rewrite, 2, context.temp_allocator)
	swapped[0] = rules[2]
	swapped[1] = rules[0]
	swapped_domain, _, swapped_found := reverse_rewrite_target(swapped, "50.1.168.192.in-addr.arpa.")
	testing.expect(t, swapped_found, "a duplicated address still has a reverse")
	testing.expect_value(t, swapped_domain, "media.home.")

	free_all(context.temp_allocator)
}

/*
The three kinds of address that get no reverse, each for its own reason: a
wildcard rule has no one name to point back at, a public address belongs to
whoever really is delegated it, and a name pointed at `0.0.0.0` or loopback is
being blackholed rather than addressed.
*/
@(test)
test_reverse_rewrite_leaves_addresses_it_cannot_speak_for :: proc(t: ^testing.T) {
	rules := sample_rules()

	_, _, wildcard := reverse_rewrite_target(rules, "1.0.0.10.in-addr.arpa.")
	testing.expect(t, !wildcard, "a wildcard rule names no host, so it has no reverse")

	_, _, public := reverse_rewrite_target(rules, "9.113.0.203.in-addr.arpa.")
	testing.expect(t, !public, "a public address must keep its own delegation's PTR")

	_, _, unspecified := reverse_rewrite_target(rules, "0.0.0.0.in-addr.arpa.")
	testing.expect(t, !unspecified, "0.0.0.0 is a blackhole, not a host")

	_, _, loopback := reverse_rewrite_target(rules, "1.0.0.127.in-addr.arpa.")
	testing.expect(t, !loopback, "127.0.0.1 is a blackhole here, not a host")

	// And a private address nobody wrote down is still the upstream's business.
	_, _, unnamed := reverse_rewrite_target(rules, "51.1.168.192.in-addr.arpa.")
	testing.expect(t, !unnamed, "an address no rule mentions has no reverse here")

	free_all(context.temp_allocator)
}

/*
The invariant the placement rests on: every name this can answer is inside a
locally-served zone.

`reverse.odin` claims a synthesised PTR can never be a name the validator is
holding to the public chain of trust, and that claim is what keeps it from
producing the exact shape `localzones.odin` exists to prevent - an unsigned
answer under a signed `in-addr.arpa`. The claim is about the address test rather
than about the placement, so it is asserted here against the address test: every
address a rule can be reversed into has a reverse name `is_locally_served`
claims.
*/
@(test)
test_every_synthesised_reverse_name_is_locally_served :: proc(t: ^testing.T) {
	names := [?]string {
		"50.1.168.192.in-addr.arpa.",
		"1.0.0.10.in-addr.arpa.",
		"1.1.16.172.in-addr.arpa.",
		"1.1.31.172.in-addr.arpa.",
		"1.1.254.169.in-addr.arpa.",
		FD00_1_REVERSE,
		FE80_1_REVERSE,
	}
	for name in names {
		v4, v4_ok := parse_reverse_v4(name)
		v6, v6_ok := parse_reverse_v6(name)
		local := (v4_ok && address_is_local_v4(v4)) || (v6_ok && address_is_local_v6(v6))
		testing.expectf(t, local, "%s should be an address a rewrite may be reversed into", name)
		testing.expectf(
			t,
			is_locally_served(name),
			"%s can be synthesised but is not inside a locally-served zone",
			name,
		)
	}
}

// The zone the SOA of an empty synthesised answer belongs to is the RFC 6303
// zone, not the queried name's parent.
@(test)
test_locally_served_zone_names_the_apex :: proc(t: ^testing.T) {
	zone, found := locally_served_zone("50.1.168.192.in-addr.arpa.")
	testing.expect(t, found, "a private reverse name is inside a locally-served zone")
	testing.expect_value(t, zone, "168.192.in-addr.arpa.")

	v6_zone, v6_found := locally_served_zone(FD00_1_REVERSE)
	testing.expect(t, v6_found, "a ULA reverse name is inside a locally-served zone")
	testing.expect_value(t, v6_zone, "d.f.ip6.arpa.")

	_, public := locally_served_zone("8.8.8.8.in-addr.arpa.")
	testing.expect(t, !public, "a public reverse name is in no locally-served zone")
}

@(private = "file")
reverse_test_server :: proc(rules: []config.Rewrite) -> config.Config {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.rewrites = rules
	return cfg
}

@(private = "file")
ask :: proc(cfg: ^config.Config, name: string, type: dns.Type) -> (dns.Message, Outcome, bool) {
	s := Server {
		cfg = cfg,
	}
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	// RD=0, so a name this does not answer cannot reach the forwarding path -
	// there is no upstream here - and comes back Refused instead, which names
	// the failure exactly.
	query := dns.Message {
		id       = 0x2c11,
		question = questions,
	}
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if enc != .None {
		return {}, .Failed, false
	}
	out, outcome, ok := handle_query(&s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !ok {
		return {}, outcome, false
	}
	resp, derr := dns.decode_message(out, context.temp_allocator)
	if derr != .None {
		return {}, outcome, false
	}
	return resp, outcome, true
}

// The whole path, which is what says the synthesis is actually reachable rather
// than only that the helper agrees with itself.
@(test)
test_query_for_a_rewritten_address_is_answered_with_its_name :: proc(t: ^testing.T) {
	cfg := reverse_test_server(sample_rules())

	resp, outcome, ok := ask(&cfg, "50.1.168.192.in-addr.arpa.", .PTR)
	if !testing.expect(t, ok, "the PTR for a rewritten address went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	testing.expect_value(t, resp.flags.rcode, u8(dns.Rcode.No_Error))
	if !testing.expect(t, len(resp.answer) == 1, "the synthesis produced no answer record") {
		return
	}
	testing.expect_value(t, resp.answer[0].type, dns.Type.PTR)
	testing.expect_value(t, resp.answer[0].ttl, u32(111))
	ptr, is_name := resp.answer[0].data.(dns.Rdata_Name)
	testing.expect(t, is_name, "the synthesised answer is not a name")
	testing.expect_value(t, ptr.name, "nas.home.")

	free_all(context.temp_allocator)
}

/*
Another type for the same name is NODATA with an SOA, not NXDOMAIN and not a
forwarded query: the name exists, this server having just answered its PTR, and
the SOA is what lets a client remember that there is nothing else there.
*/
@(test)
test_a_synthesised_name_is_nodata_for_other_types :: proc(t: ^testing.T) {
	cfg := reverse_test_server(sample_rules())

	resp, outcome, ok := ask(&cfg, "50.1.168.192.in-addr.arpa.", .A)
	if !testing.expect(t, ok, "an A query for a synthesised name went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	testing.expect_value(t, resp.flags.rcode, u8(dns.Rcode.No_Error))
	testing.expect_value(t, len(resp.answer), 0)
	if !testing.expect(t, len(resp.authority) == 1, "NODATA carries no SOA to cache it against") {
		return
	}
	testing.expect_value(t, resp.authority[0].type, dns.Type.SOA)
	testing.expect_value(t, resp.authority[0].name, "168.192.in-addr.arpa.")

	free_all(context.temp_allocator)
}

/*
An address no rule names is still the upstream's to answer for, which with no
upstream configured and RD=0 is a refusal rather than a made-up name.
*/
@(test)
test_an_unnamed_private_address_is_not_answered_here :: proc(t: ^testing.T) {
	cfg := reverse_test_server(sample_rules())

	_, outcome, _ := ask(&cfg, "51.1.168.192.in-addr.arpa.", .PTR)
	testing.expect_value(t, outcome, Outcome.Refused)

	free_all(context.temp_allocator)
}

/*
A rule written for the reverse name itself wins, the synthesis being what
happens when nothing more specific was said.
*/
@(test)
test_an_explicit_rule_for_a_reverse_name_outranks_the_synthesis :: proc(t: ^testing.T) {
	rules := make([]config.Rewrite, 2, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "50.1.168.192.in-addr.arpa.",
		answers = answers_of({kind = .CNAME, name = "elsewhere.example."}),
		ttl     = 60,
	}
	rules[1] = config.Rewrite {
		domain  = "nas.home.",
		answers = answers_of({kind = .A, v4 = {192, 168, 1, 50}}),
		ttl     = 111,
	}
	cfg := reverse_test_server(rules)

	resp, outcome, ok := ask(&cfg, "50.1.168.192.in-addr.arpa.", .PTR)
	if !testing.expect(t, ok, "the explicit rule went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	if !testing.expect(t, len(resp.answer) == 1, "the explicit rule produced no answer") {
		return
	}
	testing.expect_value(t, resp.answer[0].type, dns.Type.CNAME)

	free_all(context.temp_allocator)
}
