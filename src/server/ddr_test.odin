package server

import "core:testing"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"

/*
Discovery of Designated Resolvers, from the forwarder's side.

A client that wants to move off Do53 asks for the SVCB record at
`_dns.resolver.arpa` and takes what comes back as the encrypted resolver it
should use instead - RFC 9462. Forwarded, that question is answered by whichever
upstream this server happens to be talking to, and the client is handed *that*
resolver's DoT and DoH endpoints. It then leaves, and every policy this server
applies - the block lists, the rewrites, the query log - goes with it.

No upstream is configured in these tests: `s.group` is left nil, so a query that
reached the forwarding step would fault rather than answer, which is what makes
a mistake in the placement loud rather than silent.
*/

// The name the whole mechanism hangs off, answered here and not forwarded.
@(test)
test_ddr_query_is_answered_locally :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)

	out, outcome, ok := handle_query(&s, test_query("_dns.resolver.arpa.", .SVCB), .UDP, TEST_CLIENT, context.temp_allocator)
	if !testing.expect(t, ok, "a DDR query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Local)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	// NODATA: the zone is ours, and we designate nothing. The client stays on
	// Do53 and keeps talking to this server.
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.No_Error)
	testing.expect_value(t, len(decoded.answer), 0)
	testing.expect(t, len(decoded.authority) == 1, "no SOA to bound how long the client remembers this")

	free_all(context.temp_allocator)
}

// "or any subdomains", RFC 9462 section 6.1 - and the zone's own apex with it.
@(test)
test_ddr_covers_the_whole_zone :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)

	names := []string{"resolver.arpa.", "_dns.resolver.arpa.", "_dNS.RESolVER.arpA.", "anything.else.resolver.arpa."}
	for name in names {
		out, outcome, ok := handle_query(&s, test_query(name), .UDP, TEST_CLIENT, context.temp_allocator)
		testing.expectf(t, ok && outcome == .Local, "%s was not answered locally", name)
		decoded, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		testing.expectf(t, len(decoded.answer) == 0, "%s came back with an answer", name)
	}

	free_all(context.temp_allocator)
}

// A bare string suffix is not a subtree: `notresolver.arpa.` is somebody else's
// name and goes upstream like any other.
@(test)
test_ddr_does_not_swallow_neighbouring_names :: proc(t: ^testing.T) {
	testing.expect(t, is_resolver_arpa("resolver.arpa."), "the apex is in the zone")
	testing.expect(t, is_resolver_arpa("_dns.RESOLVER.arpa."), "the match folds case")
	testing.expect(t, !is_resolver_arpa("notresolver.arpa."), "a string suffix is not a subtree")
	testing.expect(t, !is_resolver_arpa("resolver.arpa.example.com."), "the zone has to be at the end")
	testing.expect(t, !is_resolver_arpa("arpa."), "the parent is not the zone")
}

/*
A blocklist entry that reaches `resolver.arpa` wins, because the block lists run
first.

This is the placement, pinned. The DDR answer is built behind the block lists,
so that everything this server answers for itself goes in one place and a reader
learns the rule once. See the ordering note in `answer_locally`, and
`test_a_blocklist_entry_for_a_reserved_name_wins` for the other half of it.

The case given up is written out here rather than left implicit: a list broad
enough to match `resolver.arpa` - a rule over `arpa` itself, as below - blocks
the probe instead of having it answered NODATA. A list like that is already
breaking every reverse lookup on the machine, which is why this is an acceptable
trade and not a regression anybody will meet.
*/
@(test)
test_a_blocklist_entry_over_arpa_beats_the_ddr_answer :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	cfg.blocking.enabled = true

	// The whole subtree, which is what it takes to reach this name at all.
	engine, listed := test_filters(t, "||arpa^\n", .Adblock)
	defer filter.engine_destroy(engine)
	if !listed {
		return
	}
	s.filters = engine

	_, outcome, ok := handle_query(
		&s,
		test_query("_dns.resolver.arpa.", .SVCB),
		.UDP,
		TEST_CLIENT,
		context.temp_allocator,
	)
	testing.expect(t, ok, "the blocked DDR query went unanswered")
	testing.expectf(
		t,
		outcome == .Blocked,
		"came back as %v: the DDR answer was built ahead of the block lists",
		outcome,
	)

	// The control: with nothing listed, the same query is answered from here, so
	// the above is the list winning rather than DDR having stopped working.
	clean: config.Config
	c := local_server(&clean)
	_, plain, plain_ok := handle_query(
		&c,
		test_query("_dns.resolver.arpa.", .SVCB),
		.UDP,
		TEST_CLIENT,
		context.temp_allocator,
	)
	testing.expect(t, plain_ok, "an unlisted DDR query went unanswered")
	testing.expectf(t, plain == .Local, "an unlisted DDR query came back as %v", plain)

	free_all(context.temp_allocator)
}

/*
`resolver.arpa` is a locally served zone per RFC 6303 (RFC 9462 section 6.4): its
apex answers SOA and NS in the answer section, every other question in the zone
is NODATA with the zone's SOA, and every answer is authoritative (AA=1).
*/
@(test)
test_resolver_arpa_is_an_rfc_6303_zone :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)

	Ask :: struct {
		name:   string,
		type:   dns.Type,
		answer: dns.Type,
	}
	ASKS := []Ask {
		{name = "resolver.arpa.", type = .SOA, answer = .SOA},
		{name = "RESOLVER.arpa.", type = .NS, answer = .NS},
		{name = "resolver.arpa.", type = .A},
		{name = "x.resolver.arpa.", type = .SOA},
		{name = "_dns.resolver.arpa.", type = .SVCB},
	}
	for a in ASKS {
		out, outcome, ok := handle_query(&s, test_query(a.name, a.type), .UDP, TEST_CLIENT, context.temp_allocator)
		if !testing.expectf(t, ok && outcome == .Local, "%s %v was not answered locally", a.name, a.type) {
			continue
		}
		m, derr := dns.decode_message(out, context.temp_allocator)
		if !testing.expectf(t, derr == .None, "%s %v: the answer does not decode: %v", a.name, a.type, derr) {
			continue
		}
		testing.expectf(t, m.flags.aa, "%s %v: AA clear", a.name, a.type)
		testing.expectf(t, dns.rcode_of(m) == .No_Error, "%s %v: rcode %v", a.name, a.type, dns.rcode_of(m))
		if a.answer == dns.Type(0) {
			testing.expectf(t, len(m.answer) == 0, "%s %v: %d answers, want NODATA", a.name, a.type, len(m.answer))
			if testing.expectf(t, len(m.authority) == 1, "%s %v: no SOA in authority", a.name, a.type) {
				expect_local_zone_soa(t, m.authority[0], RESOLVER_ARPA)
			}
			continue
		}
		if !testing.expectf(t, len(m.answer) == 1, "%s %v: %d answers, want the apex record", a.name, a.type, len(m.answer)) {
			continue
		}
		testing.expectf(t, m.answer[0].type == a.answer, "%s %v: answered %v", a.name, a.type, m.answer[0].type)
		testing.expectf(t, len(m.authority) == 0, "%s %v: an SOA in authority beside the answer", a.name, a.type)
		expect_local_zone_soa(t, m.answer[0], RESOLVER_ARPA)
		if ns, is_ns := m.answer[0].data.(dns.Rdata_Name); is_ns {
			testing.expectf(t, dns.name_equal_fold(ns.name, RESOLVER_ARPA), "the NS names %q, want the zone", ns.name)
		}
	}
	free_all(context.temp_allocator)
}
