package server

import "core:testing"
import "elodin:dns"

/*
The transaction ID a forwarded query carries is ours, not the client's.

RFC 5452 section 9.2. On a plain UDP upstream the ID is half of what stops an
off-path attacker from having a forged datagram accepted as the upstream's
answer: the source and destination addresses are known, the question is the one
the attacker asked for, and what is left to guess is our ephemeral source port
and the ID. Forwarding the client's own ID hands one of those two away to
whoever sent the query, and the search space collapses from about 2^31 to the
port alone.

Driven through `handle_query` against a real socket rather than against the
rewriting procedures directly, because the property is not any one of theirs:
each path builds the outgoing query from the client's message, and each must
replace the ID. So all three are exercised here - a plain forward, the DNSSEC rewrite,
and the one that strips a client cookie - and what is asserted is what arrived
at the far end.
*/

// Enough draws that a fixed or counting ID cannot pass by chance, and few
// enough that 16-bit collisions stay unlikely.
@(private = "file")
DRAWS :: 32

// The ID the client asks with throughout. Any value does; this one is easy to
// spot in a failure message.
@(private = "file")
CLIENT_ID :: u16(0x4242)

@(private = "file")
QNAME :: "www.example.com."

// The answer the mock upstream gives, for the question every case here asks.
@(private = "file")
mock_reply :: proc() -> []u8 {
	return test_reply(QNAME, .A, a_record(QNAME, {93, 184, 216, 34}, 300))
}

/*
A query as a client sends it.

`cookie` puts a COOKIE option in the OPT record, which is what sends the
forwarding path through `remove_edns_option` - one of the three ways the
outgoing buffer comes about.
*/
@(private = "file")
id_client_query :: proc(cookie := false) -> []u8 {
	opt: Maybe(dns.Record)
	if cookie {
		client_half := make([]u8, 8, context.temp_allocator)
		for i in 0 ..< len(client_half) {
			client_half[i] = u8(0xa0 + i)
		}
		opt = opt_with(.Cookie, client_half)
	}
	return test_query(QNAME, id = CLIENT_ID, opt = opt)
}

/*
Put one query through the server and report the ID the upstream saw.

The validating case's validator can fetch nothing (`no_chain`): the verdict is
not what these cases are about, and the chain for a name the mock invented could
not be built from anything it would answer. Refusing to fetch makes the answer
indeterminate straight away, which is the quick way to reach the assertion: what
went out on the wire before any of that happened.
*/
@(private = "file")
ask_for_id :: proc(
	t: ^testing.T,
	h: ^Harness,
	query: []u8,
) -> (
	forwarded_id: u16,
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	x := Canned_Mock {
		reply = mock_reply(),
	}
	out, result, served := harness_exchange(h, &x, query)
	if !testing.expect(t, x.got, "the upstream was never asked") {
		return 0, nil, result, false
	}
	if !testing.expect(t, served, "the query went unanswered") {
		return 0, nil, result, false
	}
	return u16(x.seen[0]) << 8 | u16(x.seen[1]), out, result, true
}

@(test)
test_forwarded_query_id_is_not_the_client_id :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	seen: map[u16]bool
	defer delete(seen)

	// See the assertion below: counted across the draws rather than asserted on
	// each one, because a fresh draw is allowed to land here by chance.
	coincidences := 0

	for _ in 0 ..< DRAWS {
		query := id_client_query()
		forwarded_id, out, outcome, ok := ask_for_id(t, &h, query)
		if !ok {
			return
		}
		testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
		if forwarded_id == CLIENT_ID {
			coincidences += 1
		}
		seen[forwarded_id] = true

		// The client is waiting on the ID it wrote, so that is what comes back.
		id, id_ok := dns.peek_id(out)
		testing.expect(t, id_ok, "the response is too short to carry an id")
		testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	}

	/*
	Coincidence is not a copy.

	A fresh 16-bit draw lands on whatever the client happened to ask with about
	once in 65536, so across 32 draws it happens about once in 2000 runs: rare
	enough to be a surprise in CI and certain enough to turn up eventually. It
	is not what this test is for. An ID carried across from the client is
	carried across every time, so the failure being watched for is DRAWS of
	these rather than one - and two by chance is about one run in ten million.
	Counting them separates the two; asserting on each draw cannot.
	*/
	testing.expectf(
		t,
		coincidences <= 1,
		"%d of %d queries went upstream with the client's own transaction id %04x",
		coincidences,
		DRAWS,
		CLIENT_ID,
	)

	/*
	Distinctness is what makes the ID worth anything: a single fresh value
	reused for every query afterwards is as good as the client's to an attacker
	who has seen one answer. 32 draws from 16 bits collide about 0.8% of the
	time, so a couple of repeats is not a failure - a handful is.
	*/
	testing.expectf(
		t,
		len(seen) >= DRAWS - 2,
		"only %d distinct transaction ids across %d queries",
		len(seen),
		DRAWS,
	)
	free_all(context.temp_allocator)
}

@(test)
test_forwarded_query_id_is_replaced_on_the_dnssec_path :: proc(t: ^testing.T) {
	// The DNSSEC rewrite re-encodes the client's message to set CD and DO, and
	// would carry its ID across with everything else.
	h: Harness
	if !harness_start(t, &h, validating = true) {
		return
	}
	defer harness_stop(&h)

	forwarded_id, out, _, ok := ask_for_id(t, &h, id_client_query())
	if !ok {
		return
	}
	testing.expectf(
		t,
		forwarded_id != CLIENT_ID,
		"the rewritten query kept the client's transaction id %04x",
		forwarded_id,
	)
	/*
	And the client still hears its own ID back, on a path that answers from
	somewhere else entirely: the chain cannot be built, so this is the SERVFAIL
	that `dnssec_failure_response` composes rather than the upstream's answer
	with its ID corrected. A reply carrying the wrong ID is not a failure a
	client can see - it is dropped as unsolicited, and the query waits out its
	whole timeout instead.
	*/
	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	free_all(context.temp_allocator)
}

@(test)
test_forwarded_query_id_is_replaced_when_the_cookie_is_stripped :: proc(t: ^testing.T) {
	// A third buffer: the client's message with its COOKIE option taken out.
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	query := id_client_query(cookie = true)
	forwarded_id, out, outcome, ok := ask_for_id(t, &h, query)
	if !ok {
		return
	}
	testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
	testing.expectf(
		t,
		forwarded_id != CLIENT_ID,
		"the cookie-stripped query kept the client's transaction id %04x",
		forwarded_id,
	)
	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	free_all(context.temp_allocator)
}
