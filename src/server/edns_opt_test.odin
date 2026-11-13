package server

import "core:testing"
import "elodin:dns"

/*
EDNS this server cannot account for, refused before it is read.

`edns_opt_readable` refuses four shapes. Two of them reach `decode_message`
intact and then hide an option from every reader here: a second OPT record,
which `find_opt` and `find_opt_span` both stop short of, and an OPT whose RDATA
is not a well-formed option list, which `decode_record` keeps as raw bytes with
the options in front of the fault unreadable. Either one survives a strip that
reports success, so `handle_query` answers both FORMERR - RFC 6891 section
6.1.1, which permits exactly one OPT record and an option list to be a list -
before a cookie is looked for, a name is looked up or a cache is consulted.

The cases below are the two properties that follow - what the gate keeps off the
wire (a client's cookie, the secret of the two options that stop here), and that
it holds whatever the cache would otherwise have answered - and the fourth
shape, an OPT owned by a name other than the root (#301). The client-subnet half
of the same gate is in `ecs_test.odin`.
*/

@(private = "file")
SERVED :: [4]u8{192, 0, 2, 7}

// An OPT record carrying one eight-byte client cookie.
@(private = "file")
cookie_opt :: proc() -> dns.Record {
	payload := make([]u8, 8, context.temp_allocator)
	for i in 0 ..< len(payload) {
		payload[i] = u8(0xa0 + i)
	}
	return opt_with(.Cookie, payload)
}

// A query for `name` with two OPT records, the client's cookie in the second.
@(private = "file")
two_opts_with_cookie :: proc(name: string) -> []u8 {
	return query_with_records(name, dns.make_opt(1232, false), cookie_opt())
}

// The mock: it answers `name` with SERVED and reports a cookie that reached it.
@(private = "file")
cookie_mock :: proc(name: string) -> Option_Mock {
	return Option_Mock{code = .Cookie, reply = edns_reply(name, SERVED)}
}

/*
An OPT record whose option list stops in the middle of an option header, with
nothing else in it.

Three bytes are not enough for the four an option header takes, so
`decode_rdata` gives up on the list and `decode_record` keeps the RDATA as raw
bytes - the shape the gate refuses. Deliberately empty of anything else: what it
pins is that the refusal is about the RDATA and not about what happens to be
inside it.
*/
@(private = "file")
truncated_opt :: proc() -> dns.Record {
	raw := make([]u8, 3, context.temp_allocator)
	raw[0], raw[1] = 0, 12 // OPTION-CODE: Padding, and then nothing to say how long
	raw[2] = 0
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_Raw{data = raw}
	return opt
}

/*
A cookie in a second OPT record does not reach the upstream.

`inspect_cookie` reads the first OPT record and no other, so a cookie in a
second one is a cookie this server never notices it was sent. `upstream_query`
forwards none of the client's options, and the gate turns the shape away before
that. Forwarded, it would hand a secret shared between the client and this
server to a third party that cannot check it and did not need it, which is the
whole of what the cookie strip exists to prevent.

The first half of the case is the one that keeps the gate honest: an ordinary
query with one OPT record and a cookie in it is answered, and the cookie still
does not reach the upstream. A gate that refused that too would close the leak
by turning away every client that uses cookies.
*/
@(test)
test_a_cookie_in_a_second_opt_record_is_not_forwarded :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	// One OPT record, a cookie in it: answered, and stripped on the way out.
	{
		x := cookie_mock("cookie.example.")
		out, outcome, ok := harness_sniff(&h, &x, query_with_records("cookie.example.", cookie_opt()))

		testing.expect(t, x.served, "the mock upstream never answered an ordinary cookie query")
		testing.expect(t, !x.saw, "the client's cookie was forwarded to the upstream")
		testing.expect(t, ok, "an ordinary cookie query produced nothing at all")
		testing.expect_value(t, outcome, Outcome.Forwarded)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)
	}

	// Two OPT records, the cookie in the second: refused, and nothing sent.
	{
		// Nothing arrived, so neither did the cookie in the second record.
		expect_refused_unforwarded(t, &h, two_opts_with_cookie("hidden.example."), "the query was forwarded instead of being refused")
	}
	free_all(context.temp_allocator)
}

/*
An OPT record owned by a name other than the root is refused like the other
shapes `edns_opt_readable` turns away. RFC 6891 section 6.1.2: NAME MUST be 0
(root). Unbound (`parse_edns_from_query_pkt`) and BIND (`dns_message_parse`)
answer it FORMERR. Read as the query's EDNS record instead, it is answered from
the cache, a block or a local zone with EDNS, and forwarded on a miss. Issue #301.
*/
@(test)
test_an_opt_with_a_non_root_owner_is_refused :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	opt := dns.make_opt(1232, false)
	opt.name = "example."
	expect_refused_unforwarded(t, &h, query_with_records("owner.example.", opt), "a query with a non-root OPT owner was forwarded")
	free_all(context.temp_allocator)
}

/*
An OPT this decoder cannot walk is refused whether or not anything is hiding
behind the fault.

Worth pinning as its own case because it is the cost of the gate rather than its
benefit: a client whose OPT record is merely malformed loses the answer, not
only the option it mangled. That is what RFC 6891 section 6.1.1 asks for, and
the alternative is guessing at bytes this server has already established it
cannot read - but it is broader than the leak that motivated the gate, so it
should fail loudly if anyone narrows it by accident.
*/
@(test)
test_an_unreadable_opt_is_refused_with_nothing_hidden_in_it :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	expect_refused_unforwarded(
		t,
		&h,
		query_with_records("stump.example.", truncated_opt()),
		"an OPT record this server cannot read was forwarded",
	)
	free_all(context.temp_allocator)
}

/*
The refusal is a property of the message, not of what the cache happens to hold.

The gate sits in `handle_query`, ahead of the rewrites, the blocklist, the
special-use table and the cache lookup, so the same bytes get the same answer
twice. Below any of those, a client sending one malformed query twice would be
told FORMERR on the miss and handed an answer on the hit - two rcodes for one
message, decided by what some other client asked for earlier.
*/
@(test)
test_a_second_opt_record_is_refused_whatever_the_cache_holds :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	// A plain query for the name first, so there is an entry to be tempted by.
	warm := cookie_mock("warm.example.")
	_, first, _ := harness_sniff(&h, &warm, query_with_records("warm.example.", dns.make_opt(1232, false)))
	if !testing.expect(t, warm.served, "the mock upstream never answered the first query") {
		return
	}
	testing.expect_value(t, first, Outcome.Forwarded)

	// The same name, now cached, asked with two OPT records. No mock is
	// listening, so a query that got past the gate would be answered from the
	// entry rather than time out - which is the mistake being guarded against.
	out := expect_refused_unforwarded(t, &h, two_opts_with_cookie("warm.example."), "a cached name's malformed query was forwarded")
	if m, derr := dns.decode_message(out, context.temp_allocator); derr == .None {
		testing.expect_value(t, len(m.answer), 0)
	}
	free_all(context.temp_allocator)
}
