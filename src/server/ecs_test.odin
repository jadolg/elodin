package server

import "core:testing"
import "elodin:dns"

/*
EDNS Client Subnet on the way to an upstream.

An ECS option is a client saying which network the answer should be tailored
for, and forwarding one is only correct alongside the caching RFC 7871 section
7.3 describes - an entry per network, chosen by longest prefix match. This
server's cache key is the question plus DO and CD, so it has no such thing, and
the option is taken back out of every query on the way upstream instead.

What that has to hold against is a client naming somebody else's network: the
tailored answer would otherwise be filed under the bare question and handed to
everyone behind this resolver, and the client's claim about its own address
would have travelled to a public upstream under this server's name (section
11.1). So the mock below answers one address when it is told a subnet and
another when it is not, which makes the two halves visible at once - what the
upstream was told, and which of the two answers the next client is given.

Both the validating and the plain path are covered: `upstream_query` builds
the outgoing query for each, with DO and CD forced on for the first.
*/

// The address the mock serves when it is told a subnet, and the one it serves
// when it is not. Nothing distinguishes them but which question was asked.
@(private = "file")
TAILORED :: [4]u8{203, 0, 113, 9}
@(private = "file")
GLOBAL :: [4]u8{192, 0, 2, 1}

// An ECS option's payload for `prefix`/24: FAMILY IPv4, SOURCE PREFIX-LENGTH
// 24, SCOPE PREFIX-LENGTH 0, and the address.
@(private = "file")
ecs_payload :: proc(prefix: [4]u8) -> []u8 {
	payload := make([]u8, 8, context.temp_allocator)
	payload[0], payload[1] = 0, 1 // FAMILY: IPv4
	payload[2] = 24 // SOURCE PREFIX-LENGTH
	payload[3] = 0 // SCOPE PREFIX-LENGTH
	pfx := prefix
	copy(payload[4:], pfx[:])
	return payload
}

// An OPT record carrying one ECS option for `prefix`/24.
@(private = "file")
ecs_opt :: proc(prefix: [4]u8) -> dns.Record {
	return opt_with(.Client_Subnet, ecs_payload(prefix))
}

// An A query, optionally carrying an ECS option naming `prefix`/24.
@(private = "file")
ecs_query :: proc(name: string, prefix: [4]u8, with_ecs: bool) -> []u8 {
	return query_with_records(name, ecs_opt(prefix) if with_ecs else dns.make_opt(1232, false))
}

/*
The mock: it serves TAILORED to a query that names a subnet and GLOBAL to one
that does not, so the answer alone says which the upstream was asked.
*/
@(private = "file")
ecs_mock :: proc(name: string) -> Option_Mock {
	return Option_Mock{code = .Client_Subnet, reply = edns_reply(name, GLOBAL), reply_seen = edns_reply(name, TAILORED)}
}

// The first address in a response, which is the whole of what the mock varies.
@(private = "file")
answer_addr :: proc(wire: []u8) -> (addr: [4]u8, found: bool) {
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if derr != .None {
		return {}, false
	}
	for rec in m.answer {
		if a, is_a := rec.data.(dns.Rdata_A); is_a {
			return a.addr, true
		}
	}
	return {}, false
}

/*
Every case runs on a cached harness. The one about the DNSSEC rewrite also
validates; the verdict is not what this file is about - a chain for a name the
mock invented could not be built from anything it would answer - and the
harness's `no_chain` reaches the assertion, which is about what went out on the
wire before any of that happened.
*/

@(test)
test_a_client_subnet_scoped_answer_does_not_reach_other_clients :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	// One client asks with an ECS option naming a network that is not its own.
	// The mock serves TAILORED to anyone who names a subnet.
	x := ecs_mock("cdn.example.")
	first, _, first_ok := harness_sniff(&h, &x, ecs_query("cdn.example.", {198, 51, 100, 0}, true))

	testing.expect(t, x.served, "the mock upstream never answered")
	testing.expect(t, !x.saw, "the client's ECS option was forwarded to the upstream")

	// The client that asked gets the untailored answer too. Its claim about
	// where it is bought it nothing, which is the point of dropping the option
	// rather than acting on it.
	testing.expect(t, first_ok, "the first query produced nothing at all")
	if addr, found := answer_addr(first); testing.expect(t, found, "the first client got no address") {
		testing.expect_value(t, addr, GLOBAL)
	}

	/*
	A second client, on another address, asking without ECS at all. No mock is
	listening now, so what it gets is the entry the first query left behind -
	and that entry has to be an answer for everybody rather than one somebody
	chose. Which is what makes the cache key honest without carrying a subnet:
	nothing tailored ever reaches it.
	*/
	second, _, second_ok := handle_query(
		&h.srv,
		ecs_query("cdn.example.", {0, 0, 0, 0}, false),
		.UDP,
		"127.0.0.2:5555",
		context.temp_allocator,
	)
	testing.expect(t, second_ok, "the second query produced nothing at all")
	if addr, found := answer_addr(second); testing.expect(t, found, "the second client got no address") {
		testing.expectf(
			t,
			addr == GLOBAL,
			"an answer scoped to somebody else's subnet was served from the cache: %v",
			addr,
		)
	}
	free_all(context.temp_allocator)
}

/*
A subnet the strip cannot reach costs the client its answer, not everyone else
theirs.

`remove_edns_option` edits the first OPT record and no other, so an ECS option
in a second one would survive a removal that reported success. `handle_query`
turns that message away before any of this - FORMERR, as RFC 6891 section 6.1.1
says of it - so what this case pins is that the subnet never reaches the
upstream, whichever gate is the one that stops it.
*/
@(test)
test_an_unstrippable_client_subnet_is_not_forwarded :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	expect_refused_unforwarded(
		t,
		&h,
		query_with_records("cdn.example.", dns.make_opt(1232, false), ecs_opt({198, 51, 100, 0})),
		"the query reached the upstream with a subnet still on it",
	)
	free_all(context.temp_allocator)
}

/*
The same, for a subnet the decoder cannot see rather than one it can see in the
wrong place.

`decode_record` keeps RDATA it cannot parse as raw bytes rather than rejecting
the message, so an option list ending in a partial option header decodes to an
OPT record holding `Rdata_Raw` rather than an option list - and the ECS option
in front of that stump reads as absent to anything asking the decoded message,
`find_edns_option` included. It is not absent to the upstream, which walks the
same bytes and stops at the option it understands. So the query is stopped by
the `edns_opt_readable` gate rather than forwarded with the subnet still on it -
which it is whether or not the stump has a subnet in front of it, the case
`edns_opt_test.odin` pins from the other side.
*/
@(test)
test_a_client_subnet_behind_unreadable_opt_bytes_is_not_forwarded :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	// One well-formed ECS option, then three bytes of a fourth option header:
	// enough for `decode_rdata` to give up on the list, not enough to hide the
	// option from a resolver reading it the same way this one would have.
	raw := make([dynamic]u8, context.temp_allocator)
	append(&raw, 0, 8, 0, 8) // OPTION-CODE: Client Subnet, OPTION-LENGTH 8
	append(&raw, ..ecs_payload({198, 51, 100, 0}))
	append(&raw, 0, 3, 0) // an option header cut short

	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_Raw{data = raw[:]}
	expect_refused_unforwarded(
		t,
		&h,
		query_with_records("cdn.example.", opt),
		"the query reached the upstream with a subnet still on it",
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_client_subnet_does_not_survive_the_dnssec_rewrite :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true, validating = true) {
		return
	}
	defer harness_stop(&h)

	x := ecs_mock("cdn.example.")
	// CD is left clear and the validator is in place, so the question is asked
	// with DO and CD set.
	harness_sniff(&h, &x, ecs_query("cdn.example.", {198, 51, 100, 0}, true))

	testing.expect(t, x.served, "the mock upstream never answered")
	// Without this the case could quietly become the plain forwarding one
	// above, and prove nothing about the path it is named for.
	testing.expect(t, x.saw_do, "the query did not go out through the DNSSEC rewrite")
	testing.expect(t, !x.saw, "the DNSSEC rewrite carried the client's ECS option upstream")
	free_all(context.temp_allocator)
}

// An OPT record carrying `n` ECS options at once, each naming a different /24.
@(private = "file")
ecs_opt_repeated :: proc(n: int) -> dns.Record {
	options := make([]dns.EDNS_Option, n, context.temp_allocator)
	for i in 0 ..< n {
		options[i] = dns.EDNS_Option{code = u16(dns.EDNS_Option_Code.Client_Subnet), data = ecs_payload({198, 51, u8(100 + i), 0})}
	}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}
	return opt
}

/*
The OPT record is not required to be the last thing in the additional section.

RFC 6891 section 6.1.1 puts one OPT in the additional section and says nothing
about where; a client is free to write it first and something else after it.
`remove_edns_option` rewrites the record in place and has the rest of the
section to carry past it, which is the part that would go wrong quietly - a
strip that reported success while leaving the option, or one that truncated
whatever followed.

Pinned rather than left to the round trip because a query shaped like this is
rare enough that no other test here builds one, and the failure it guards
against is the client's subnet reaching the upstream after this server decided
it had removed it.
*/
@(test)
test_a_client_subnet_is_stripped_from_an_opt_that_is_not_last :: proc(t: ^testing.T) {
	extra := dns.Record {
		name  = "extra.example.",
		type  = .TXT,
		class = .IN,
		ttl   = 0,
		data  = dns.Rdata_TXT{strings = nil},
	}
	wire := query_with_records("cdn.example.", ecs_opt({198, 51, 100, 0}), extra)

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	_, noticed := dns.find_edns_option(decoded, .Client_Subnet)
	testing.expect(t, noticed, "the subnet was not noticed at all")

	out, ok := dns.remove_edns_option(wire, .Client_Subnet, context.temp_allocator)
	if !testing.expect(t, ok, "the strip failed on an OPT that is not last") {
		return
	}
	after, aerr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, aerr, dns.Decode_Error.None)
	_, survived := dns.find_edns_option(after, .Client_Subnet)
	testing.expect(t, !survived, "the subnet survived the strip")
	// The record that followed the OPT is still there and still readable.
	testing.expect_value(t, len(after.additional), 2)
	free_all(context.temp_allocator)
}

/*
One OPT record may carry the option twice.

Nothing in RFC 6891 section 6.1.2 stops a client repeating an option inside one
OPT's RDATA, and `remove_edns_option` rebuilds that RDATA from the options it
kept rather than cutting the first match out of it - so both copies go. The
distinction worth pinning is against the neighbouring case: two ECS options in
*one* OPT record are strippable and the query is forwarded, while two OPT
*records* are not and the query is refused. A change that conflated the two
would either leak a subnet or start refusing ordinary queries.
*/
@(test)
test_a_repeated_client_subnet_in_one_opt_is_stripped_whole :: proc(t: ^testing.T) {
	wire := query_with_records("cdn.example.", ecs_opt_repeated(2))

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	_, noticed := dns.find_edns_option(decoded, .Client_Subnet)
	testing.expect(t, noticed, "the repeated subnet was not noticed")

	out, ok := dns.remove_edns_option(wire, .Client_Subnet, context.temp_allocator)
	if !testing.expect(t, ok, "the strip failed on a repeated option") {
		return
	}
	after, aerr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, aerr, dns.Decode_Error.None) {
		return
	}
	_, survived := dns.find_edns_option(after, .Client_Subnet)
	testing.expect(t, !survived, "a second copy of the subnet survived the strip")
	free_all(context.temp_allocator)
}
