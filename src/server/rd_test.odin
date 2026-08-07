package server

import "core:testing"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"

/*
RD=0 asks for whatever this server already knows, not for a fresh lookup -
RFC 1035 section 4.1.1. `resolve_query` refuses rather than forwards on such a
query's behalf, since forwarding is the only recursion this server ever does.

No upstream is configured in these tests: `s.group` is left nil, so a query
that reached the forwarding step would panic rather than hang, which is what
makes a mistake in the gate's placement loud instead of a timeout.
*/

@(private = "file")
rd_query :: proc(rd: bool, name := "example.com.", type := dns.Type.A, edns := false) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x1234,
		question = questions,
	}
	msg.flags.rd = rd

	if edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, false)
		msg.additional = additional
	}

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(test)
test_rd_zero_is_refused_without_forwarding :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	s := Server {
		cfg = &cfg,
	}

	out, outcome, ok := handle_query(&s, rd_query(false), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "an RD=0 query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Refused)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.Refused)
	// RA says the server offers recursion, not that this query used it - RFC
	// 1035 section 4.1.1. Declining to recurse for this one does not mean the
	// service is off.
	testing.expect(t, decoded.flags.ra, "RA not set on a refusal, though the server still offers recursion")

	free_all(context.temp_allocator)
}

// The refusal goes through `dns.error_response`, same as any other policy
// refusal in `resolve_query` - so an OPT record on the query comes back on the
// answer the same way it would for the class or cookie checks beside it.
@(test)
test_rd_zero_refusal_echoes_edns :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	s := Server {
		cfg = &cfg,
	}

	out, outcome, ok := handle_query(&s, rd_query(false, edns = true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "an RD=0 query with EDNS went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Refused)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, dns.edns_present(decoded), "the OPT record did not survive a refusal on the RD gate")

	free_all(context.temp_allocator)
}

/*
A cache hit answers what this server already knows without going anywhere, so
RD=0 does not stand in its way - the gate sits after the cache lookup, not
before it. The stored answer's own RA - the upstream's, from whenever it was
first fetched - rides along untouched: it is not rebuilt through
`make_response`, and nothing here re-derives it from this client's RD, which
this client set to false specifically to catch that mistake if it is ever
made.
*/
@(test)
test_rd_zero_is_still_served_from_cache :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}

	name := "example.com."
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = name,
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
	stored := dns.Message {
		id       = 0x1234,
		question = []dns.Question{{name = name, type = .A, class = .IN}},
		answer   = answer,
	}
	stored.flags.qr = true
	stored.flags.ra = true
	wire, _, enc := dns.encode_message(stored, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	// RD plays no part in `cache.make_key` - stored under a key an RD=1 lookup
	// would have made too, which is what makes this hit reachable at all.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], name, .A, .IN, false, false)
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !testing.expect(t, cache.put(answers, key, wire, decoded), "the answer was not cached") {
		return
	}

	out, outcome, ok := handle_query(&s, rd_query(false, name), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "the cached answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expect(
		t,
		served.flags.ra,
		"RA on a cached answer was recomputed from this query's RD instead of carrying the stored bit through",
	)

	free_all(context.temp_allocator)
}

/*
The RD gate sits in `resolve_query` after rewriting and blocking, which both
answer from configuration rather than the network - so RD=0 must not stand in
their way either. Nothing enforces that ordering beyond where the gate happens
to be written; this pins it, so a future move of the gate past these two would
fail a test here instead of only showing up as a REFUSED a blocklist operator
did not expect.
*/
@(test)
test_rd_zero_still_gets_blocked_and_rewritten_answers :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = true

	cfg.rewrites = make([]config.Rewrite, 1, context.temp_allocator)
	cfg.rewrites[0] = config.Rewrite {
		domain  = "rewritten.example.",
		answers = []config.Rewrite_Answer{{kind = .A, v4 = {192, 0, 2, 1}}},
		ttl     = 300,
	}

	block, allow := filter.set_make(), filter.set_make()
	filter.parse_list(block, allow, "0.0.0.0 blocked.example.com\n", .Hosts)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, block, allow)

	s := Server {
		cfg     = &cfg,
		filters = engine,
	}

	_, blocked_outcome, blocked_ok := handle_query(
		&s,
		rd_query(false, "blocked.example.com."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, blocked_ok, "an RD=0 query for a blocked name went unanswered")
	testing.expect_value(t, blocked_outcome, Outcome.Blocked)

	_, rewritten_outcome, rewritten_ok := handle_query(
		&s,
		rd_query(false, "rewritten.example."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, rewritten_ok, "an RD=0 query for a rewritten name went unanswered")
	testing.expect_value(t, rewritten_outcome, Outcome.Rewritten)

	free_all(context.temp_allocator)
}
