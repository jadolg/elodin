package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

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
