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

@(private = "file")
ddr_query :: proc(name: string, type := dns.Type.SVCB) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x4242,
		question = questions,
	}
	msg.flags.rd = true

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
ddr_server :: proc(cfg: ^config.Config) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	return Server{cfg = cfg}
}

// The name the whole mechanism hangs off, answered here and not forwarded.
@(test)
test_ddr_query_is_answered_locally :: proc(t: ^testing.T) {
	cfg: config.Config
	s := ddr_server(&cfg)

	out, outcome, ok := handle_query(&s, ddr_query("_dns.resolver.arpa."), .UDP, "127.0.0.1:5555", context.temp_allocator)
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
	s := ddr_server(&cfg)

	names := []string{"resolver.arpa.", "_dns.resolver.arpa.", "_dNS.RESolVER.arpA.", "anything.else.resolver.arpa."}
	for name in names {
		out, outcome, ok := handle_query(&s, ddr_query(name, .A), .UDP, "127.0.0.1:5555", context.temp_allocator)
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

This is the placement, pinned. The DDR answer used to be built ahead of the block
lists, on the argument that nothing legitimately lists this name; it is now
behind them, so that everything this server answers for itself goes in one place
and a reader learns the rule once. See the ordering note in `resolve_query`, and
`test_a_blocklist_entry_for_a_reserved_name_wins` for the other half of it.

The case given up is written out here rather than left implicit: a list broad
enough to match `resolver.arpa` - a rule over `arpa` itself, as below - now
blocks the probe instead of having it answered NODATA. A list like that is
already breaking every reverse lookup on the machine, which is why this is an
acceptable trade and not a regression anybody will meet.
*/
@(test)
test_a_blocklist_entry_over_arpa_beats_the_ddr_answer :: proc(t: ^testing.T) {
	cfg: config.Config
	s := ddr_server(&cfg)
	cfg.blocking.enabled = true

	block, allow := filter.set_make(), filter.set_make()
	// The whole subtree, which is what it takes to reach this name at all.
	filter.parse_list(block, allow, "||arpa^\n", .Adblock)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, block, allow)
	s.filters = engine

	_, outcome, ok := handle_query(
		&s,
		ddr_query("_dns.resolver.arpa."),
		.UDP,
		"127.0.0.1:5555",
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
	c := ddr_server(&clean)
	_, plain, plain_ok := handle_query(
		&c,
		ddr_query("_dns.resolver.arpa."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, plain_ok, "an unlisted DDR query went unanswered")
	testing.expectf(t, plain == .Local, "an unlisted DDR query came back as %v", plain)

	free_all(context.temp_allocator)
}
