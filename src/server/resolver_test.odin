package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
How large a response this server will build, and what bounds it.

`response_limit` is the one place the UDP ceiling is applied, so it is the one
place the two numbers that meet there - what the client advertised and what
`server.max_udp_response` allows - have to be resolved the right way round.
*/

// The OPT record is allocated rather than written as a slice literal: a literal
// lives in the frame that made it, and this one has to outlive this call.
@(private = "file")
query_advertising :: proc(size: u16) -> dns.Message {
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.make_opt(size, false)
	return dns.Message{additional = records}
}

// The smaller of the two wins, whichever one it is: the client's number is a
// request and the setting is a ceiling, and neither is a floor under the other.
@(test)
test_response_limit_takes_the_smaller_of_the_two :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}

	// Asked for more than the ceiling: held to the ceiling.
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.DEFAULT_MAX_UDP_RESPONSE)
	// Asked for less: given what it asked for, not the ceiling.
	testing.expect_value(t, response_limit(&s, query_advertising(512), .UDP), 512)
	// No OPT record at all is 512 by RFC 1035, and the ceiling does not raise it.
	testing.expect_value(t, response_limit(&s, dns.Message{}, .UDP), 512)

	// Raised, and the client's larger number is now the one that binds.
	cfg.server.max_udp_response = config.MAX_UDP_RESPONSE
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.MAX_UDP_RESPONSE)
	testing.expect_value(t, response_limit(&s, query_advertising(1232), .UDP), 1232)
	free_all(context.temp_allocator)
}

/*
The ceiling is UDP's alone.

The stream transports establish a connection before a query arrives, so the
address is proven and there is nothing to reflect. A ceiling leaking onto them
would cost a client a second round trip for an answer that was always going to
fit.
*/
@(test)
test_response_limit_does_not_apply_to_streams :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	streams := []Protocol{.TCP, .DoT, .DoH}
	for proto in streams {
		testing.expectf(
			t,
			response_limit(&s, query_advertising(4096), proto) == dns.MAX_MESSAGE,
			"%v is bounded by the UDP ceiling",
			proto,
		)
	}
	free_all(context.temp_allocator)
}

/*
A ceiling nobody set does not truncate every answer to nothing.

Every `Config` in a running server comes from `default_config` and is then
validated, so the field is in range there. A `Config` built literally is not, and
a zero ceiling read straight through would make `min` return zero for every UDP
answer - a resolver that responds to nothing, from a field nobody noticed was
unset. The floor keeps that invariant local to the procedure that depends on it.
*/
@(test)
test_response_limit_floors_an_unset_ceiling :: proc(t: ^testing.T) {
	cfg := config.Config{}
	s := Server {
		cfg = &cfg,
	}
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.MIN_UDP_RESPONSE)
	testing.expect_value(t, response_limit(&s, dns.Message{}, .UDP), config.MIN_UDP_RESPONSE)
	free_all(context.temp_allocator)
}

/*
The ceiling holds on the paths that go wrong too.

`fit_response` is the only thing between an answer and the wire, so whatever it
returns is what a UDP client receives. An answer it cannot re-encode used to be
returned unchanged, which meant the one case where the size was not under this
server's control was the case where the size was not bounded either - and the
number it is bounded by is an amplification factor.
*/
@(test)
test_fit_response_never_exceeds_the_limit :: proc(t: ^testing.T) {
	query := dns.Message {
		id       = 0x1234,
		question = []dns.Question{{name = "big.example.", type = .TXT, class = .IN}},
	}
	// Bytes no decoder will accept, past the ceiling: the path where there is
	// nothing to re-encode and what is in hand is too large to send.
	junk := make([]u8, 2048, context.temp_allocator)
	for i in 0 ..< len(junk) {
		junk[i] = 0xff
	}

	out := fit_response(junk, config.DEFAULT_MAX_UDP_RESPONSE, query, context.temp_allocator)
	testing.expectf(
		t,
		len(out) <= config.DEFAULT_MAX_UDP_RESPONSE,
		"fit_response returned %d bytes against a %d-byte ceiling",
		len(out),
		config.DEFAULT_MAX_UDP_RESPONSE,
	)
	if testing.expect(t, len(out) >= dns.HEADER_SIZE, "nothing came back that a client could read") {
		testing.expect(t, out[2] & 0x02 != 0, "the client was not told to retry over TCP")
	}
	free_all(context.temp_allocator)
}

/*
The snapshot carries every counter, and this is what makes that true.

`stats_of` reads the live counters one at a time, so a counter added to `Stats`
and not added here reports zero forever - which is worse than not reporting it,
because the stats line still prints the name and an operator reads the zero as
the answer. `refused` was exactly that: incremented on every refused datagram
and connection, and absent from the snapshot the report is built from.

Whole-struct equality rather than a field-by-field walk, because the failure
being guarded against is a field nobody thought to check.
*/
@(test)
test_stats_of_carries_every_counter :: proc(t: ^testing.T) {
	// Distinct values, so a snapshot that reads the wrong field is a failure
	// rather than a coincidence.
	want := Stats {
		queries      = 1,
		blocked      = 2,
		cached       = 3,
		forwarded    = 4,
		failed       = 5,
		rewritten    = 6,
		dropped      = 7,
		refused      = 8,
		conn_refused = 9,
		conn_failed  = 10,
		secure       = 11,
		bogus        = 12,
	}
	s := Server {
		stats = want,
	}
	got := stats_of(&s)
	testing.expectf(t, got == want, "stats_of did not carry every counter: got %v, want %v", got, want)
}

/*
Which names a rewrite rule claims, and in particular that the claim does not
depend on how the client happened to spell them.

DNS names compare without regard to case (RFC 1035 section 2.3.3, restated for
every label by RFC 4343), and nothing folds the question name on its way in:
`resolve_query` reads it straight off the wire so that the response can echo
back the exact bytes the client sent, which is what a resolver doing DNS-0x20
(RFC 5452 section 9.2) is checking. The whole of the case-insensitivity has
therefore to live in the matcher. A wildcard that only recognised lowercase
would leave "answer: block" bypassable by shifting a single letter, and would
send a split-horizon name upstream instead of answering it locally.
*/
@(test)
test_wildcard_rewrite_matches_regardless_of_case :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "lan.", wildcard = true, ttl = 60}}

	names := [?]string{"host.lan.", "host.LAN.", "HOST.Lan.", "deep.HOST.lAn."}
	for name in names {
		_, found := find_rewrite(rules, name)
		testing.expectf(t, found, "%s should match the wildcard rule *.lan.", name)
	}
}

/*
The two edges a wildcard has to keep, which the case-insensitive comparison
must not quietly widen.

"*.lan." stands for at least one label below "lan.", so the zone apex is
outside the rule however it is spelled; and the suffix has to begin on a label
break, or "notlan." would be swallowed by a rule written for "lan.".
*/
@(test)
test_wildcard_rewrite_excludes_the_apex_and_bare_suffixes :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "lan.", wildcard = true, ttl = 60}}

	outside := [?]string{"lan.", "LAN.", "notlan.", "NOTLAN.", "an.", "example.com."}
	for name in outside {
		_, found := find_rewrite(rules, name)
		testing.expectf(t, !found, "%s must not match the wildcard rule *.lan.", name)
	}
}

/*
An exact rewrite is unaffected by any of this and has always folded case; it is
pinned here beside the wildcard so that a change to one matcher that forgets the
other shows up.
*/
@(test)
test_exact_rewrite_matches_regardless_of_case :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "host.lan.", ttl = 60}}

	_, exact := find_rewrite(rules, "HOST.LAN.")
	testing.expect(t, exact, "an exact rewrite must match a differently-cased name")

	_, deeper := find_rewrite(rules, "sub.HOST.LAN.")
	testing.expect(t, !deeper, "an exact rewrite must not claim names below it")
}

/*
The same property end to end, which is what says the bypass is actually closed
rather than only that the helper agrees with itself.

The query carries RD=0 so that a rewrite which failed to match cannot reach the
forwarding path - there is no upstream configured - and comes back as Refused
instead, naming the failure exactly. A wildcard rule with `answer: block` is
the same code path with a different verdict, so a mixed-case query answered
from configuration here is a mixed-case query blocked in that deployment.
*/
@(test)
test_mixed_case_query_is_answered_by_a_wildcard_rewrite :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false

	cfg.rewrites = make([]config.Rewrite, 1, context.temp_allocator)
	cfg.rewrites[0] = config.Rewrite {
		domain   = "lan.",
		wildcard = true,
		answers  = []config.Rewrite_Answer{{kind = .A, v4 = {192, 0, 2, 1}}},
		ttl      = 300,
	}

	s := Server {
		cfg = &cfg,
	}

	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = "HOST.LaN.",
		type  = .A,
		class = .IN,
	}
	query := dns.Message {
		id       = 0x4d21,
		question = questions,
	}
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	out, outcome, ok := handle_query(&s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "a mixed-case query under a wildcard rewrite went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)

	resp, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !testing.expect(t, len(resp.answer) == 1, "the rewrite produced no answer record") {
		return
	}
	a, is_a := resp.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the rewritten answer is not an A record")
	testing.expect_value(t, a.addr, [4]u8{192, 0, 2, 1})

	free_all(context.temp_allocator)
}
