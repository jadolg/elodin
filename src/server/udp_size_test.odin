package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
What the OPT record in an answer says this server's UDP payload size is.

RFC 6891 section 6.2.4 makes that field the responder's number, not a copy of
the requestor's: it is what this server will reassemble and deliver, and it is
the counterpart to `max-udp-size` in BIND and Unbound, both of which set it from
the configured ceiling. Echoing the client's own figure back tells a forwarder
chaining through here to size its buffers for an answer that will never arrive,
and it then pays for a TC bit and a TCP round trip it was told it would not need.

The number that is true of this server is `server.max_udp_response` itself, not
`response_limit`: the field says what can be delivered, and a client that asked
for less than the ceiling has not lowered that. What bounds the reply in hand is
`response_limit`, which is the smaller of the two, and it is a separate question.

Every path an answer can reach the wire by has to carry it: locally built,
forwarded, served from cache, and re-encoded afterwards to carry a cookie.
*/

@(private = "file")
QNAME :: "www.example.com."

// Larger than the shipped ceiling and smaller than the raised one, so a
// client's figure and this server's are never the same number and echoing one
// for the other is a visible failure.
@(private = "file")
CLIENT_ADVERTISED :: u16(2048)

// What the mock upstream advertises in its own OPT record: neither the client's
// figure nor a ceiling of this server's.
@(private = "file")
UPSTREAM_ADVERTISED :: u16(4096)

// The client's query, with an OPT record advertising `advertised` (carrying a
// client cookie with `cookie`) unless `edns` is off.
@(private = "file")
client_query :: proc(
	advertised: u16,
	name := QNAME,
	type := dns.Type.A,
	class := dns.Class.IN,
	edns := true,
	cookie := false,
) -> []u8 {
	if !edns {
		return test_query(name, type, class = class)
	}
	opt := opt_with(.Cookie, test_client_cookie(), advertised) if cookie else opt_record(advertised)
	return test_query(name, type, opt = opt, class = class)
}

/*
An upstream answer carrying an OPT record of the upstream's own.

Not the ceiling, because a forwarded answer's OPT is the upstream's and passes
through untouched: whatever it says is what the client reads unless something
on the way out replaces it.
*/
@(private = "file")
mock_reply :: proc() -> []u8 {
	return edns_reply(QNAME, {192, 0, 2, 1}, udp_size = UPSTREAM_ADVERTISED)
}

/*
A locally built answer is the plainest case: `make_response` echoes the client's
own advertised size straight into the OPT record it puts back, so left at that,
a client asking with more than the shipped ceiling would be told its own figure
and given the ceiling.

Asked over CHAOS, which is answered from this process without a cache, a filter
or an upstream - so what the OPT says is the only thing under test.
*/
@(test)
test_a_local_answer_advertises_the_ceiling :: proc(t: ^testing.T) {
	cfg := test_config()
	s := Server {
		cfg = &cfg,
	}

	query := client_query(CLIENT_ADVERTISED, "version.bind.", .TXT, .CH)
	out, outcome, ok := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
	testing.expect(t, ok, "the chaos query went unanswered")
	testing.expect_value(t, outcome, Outcome.Local)
	testing.expect_value(t, int(dns.peek_udp_size(out)), config.DEFAULT_MAX_UDP_RESPONSE)

	// And raised past the client's own figure, the answer reports the raised
	// ceiling: the field is `max_udp_response`, not the client's number.
	cfg.server.max_udp_response = config.MAX_UDP_RESPONSE
	raised, _, raised_ok := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
	if !testing.expect(t, raised_ok, "the chaos query went unanswered at the raised ceiling") {
		return
	}
	testing.expect_value(t, int(dns.peek_udp_size(raised)), config.MAX_UDP_RESPONSE)

	free_all(context.temp_allocator)
}

/*
A client that asked for less than the ceiling is still told the ceiling.

The field is what this server can deliver, not the size of the reply in hand -
that is bounded separately, by `response_limit`, and the two only agree when the
client asked for at least the ceiling. Reporting the smaller number here would be
the same defect inverted: a downstream forwarder that advertised a conservative
512 would read 512 back, conclude this server cannot
deliver more, and go on paying for TC bits and TCP retries the 1232 ceiling would
have spared it.
*/
@(test)
test_a_client_below_the_ceiling_is_still_told_the_ceiling :: proc(t: ^testing.T) {
	cfg := test_config()
	s := Server {
		cfg = &cfg,
	}

	query := client_query(dns.MAX_UDP_SIZE, "version.bind.", .TXT, .CH)
	out, _, ok := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
	if !testing.expect(t, ok, "the chaos query went unanswered") {
		return
	}
	testing.expect_value(t, int(dns.peek_udp_size(out)), config.DEFAULT_MAX_UDP_RESPONSE)
	// And the answer itself is still held to what the client asked for.
	testing.expectf(t, len(out) <= dns.MAX_UDP_SIZE, "the answer is %d bytes, past the client's own buffer", len(out))

	free_all(context.temp_allocator)
}

// A client that asked without EDNS gets no OPT record back, and nothing here
// invents one to write a number into.
@(test)
test_a_query_without_edns_gets_no_opt_back :: proc(t: ^testing.T) {
	cfg := test_config()
	s := Server {
		cfg = &cfg,
	}

	query := client_query(0, "version.bind.", .TXT, .CH, edns = false)
	out, _, ok := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
	if !testing.expect(t, ok, "the chaos query went unanswered") {
		return
	}

	m, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	testing.expect(t, !dns.edns_present(m), "an OPT record was invented for a client that sent none")

	free_all(context.temp_allocator)
}

/*
A forwarded answer's OPT is the upstream's, and passes through this server
untouched. The upstream answered its own question about its own buffers; what
reaches the client has to be this server's number instead.
*/
@(test)
test_a_forwarded_answer_advertises_the_ceiling :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	out, ok := forward_once(t, &h, client_query(CLIENT_ADVERTISED), mock_reply())
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}
	// The mock said its own figure, which is neither the client's nor the ceiling.
	testing.expect_value(t, int(dns.peek_udp_size(out)), config.DEFAULT_MAX_UDP_RESPONSE)

	free_all(context.temp_allocator)
}

/*
A cached answer carries whatever the upstream said when it was stored, and the
ceiling is per-request - the same entry may be served to a client that advertised
less, and the configuration may have been reloaded in between. So the number has
to be written on the way out rather than on the way in.
*/
@(test)
test_a_cached_answer_advertises_the_ceiling_of_the_request :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)

	// Fills the cache; the entry stores the upstream's own figure.
	if _, ok := forward_once(t, &h, client_query(CLIENT_ADVERTISED), mock_reply()); !ok {
		return
	}

	hit, outcome, ok := handle_query(&h.srv, client_query(CLIENT_ADVERTISED), .UDP, TEST_CLIENT, context.temp_allocator)
	testing.expect(t, ok, "the cached query went unanswered")
	testing.expect_value(t, outcome, Outcome.Cached)
	testing.expect_value(t, int(dns.peek_udp_size(hit)), config.DEFAULT_MAX_UDP_RESPONSE)

	// The same entry served to a client that asked for less reports the same
	// number: the field is this server's, and it did not change between the two.
	small, small_outcome, small_ok := handle_query(&h.srv, client_query(dns.MAX_UDP_SIZE), .UDP, TEST_CLIENT, context.temp_allocator)
	testing.expect(t, small_ok, "the second cached query went unanswered")
	testing.expect_value(t, small_outcome, Outcome.Cached)
	testing.expect_value(t, int(dns.peek_udp_size(small)), config.DEFAULT_MAX_UDP_RESPONSE)

	free_all(context.temp_allocator)
}

/*
`attach_cookie` re-encodes the answer after the fact, and an answer from an
upstream that dropped EDNS gets a whole OPT record minted here. Either way it
must not put the upstream's number, or the client's, back.
*/
@(test)
test_an_answer_carrying_a_cookie_advertises_the_ceiling :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, cookies = true) {
		return
	}
	defer harness_stop(&h)

	out, ok := forward_once(t, &h, client_query(CLIENT_ADVERTISED, cookie = true), mock_reply())
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	m, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	_, has_cookie := dns.find_edns_option(m, .Cookie)
	testing.expect(t, has_cookie, "no cookie came back, so the re-encode is not what is under test")
	testing.expect_value(t, int(dns.peek_udp_size(out)), config.DEFAULT_MAX_UDP_RESPONSE)

	free_all(context.temp_allocator)
}

/*
The stream transports carry an answer's OPT record out as it stands.

A UDP payload size bounds a datagram, and nothing on a stream is bounded by it -
so there is no number of ours to report there. Writing the ceiling would claim a
bound that does not apply, and writing `response_limit` would advertise 65535,
which is not a payload size at all. A locally built answer therefore goes out
echoing the client's figure, which is what `make_response` put there.
*/
@(test)
test_a_stream_answer_leaves_a_local_opt_alone :: proc(t: ^testing.T) {
	cfg := test_config()
	s := Server {
		cfg = &cfg,
	}

	query := client_query(CLIENT_ADVERTISED, "version.bind.", .TXT, .CH)
	for proto in ([]Protocol{.TCP, .DoT, .DoH}) {
		out, _, ok := handle_query(&s, query, proto, TEST_CLIENT, context.temp_allocator)
		testing.expectf(t, ok, "%v: the chaos query went unanswered", proto)
		testing.expectf(
			t,
			int(dns.peek_udp_size(out)) == int(CLIENT_ADVERTISED),
			"%v: the answer advertised %d, not the client's own %d",
			proto,
			int(dns.peek_udp_size(out)),
			int(CLIENT_ADVERTISED),
		)
	}

	free_all(context.temp_allocator)
}

/*
And "as it stands" means the upstream's figure on a forwarded answer, not the
client's.

Worth its own case because the two are the same number on the chaos query above
and would stay the same if the stream path started rewriting the field. The mock
answers with its own figure against a client that asked for the shipped ceiling,
so only one of the two can be there.
*/
@(test)
test_a_forwarded_stream_answer_keeps_the_upstream_opt :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	out, ok := forward_once(t, &h, client_query(config.DEFAULT_MAX_UDP_RESPONSE), mock_reply(), .TCP)
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}
	testing.expect_value(t, dns.peek_udp_size(out), UPSTREAM_ADVERTISED)

	free_all(context.temp_allocator)
}

/*
An error built before the query was understood goes out under the same rule.

`error_response` echoes the client's OPT for anything it could decode a header
from, so a FORMERR or a REFUSED advertised the client's figure just as an answer
did.
*/
@(test)
test_an_error_response_advertises_the_ceiling :: proc(t: ^testing.T) {
	cfg := test_config()
	s := Server {
		cfg = &cfg,
	}

	// A zone transfer is refused outright, and the refusal carries the OPT back.
	query := client_query(CLIENT_ADVERTISED, QNAME, .AXFR, .IN)
	out, outcome, ok := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
	testing.expect(t, ok, "the transfer request went unanswered")
	testing.expect_value(t, outcome, Outcome.Refused)
	testing.expect_value(t, int(dns.peek_udp_size(out)), config.DEFAULT_MAX_UDP_RESPONSE)

	free_all(context.temp_allocator)
}
