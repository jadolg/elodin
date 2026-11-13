package server

import "core:net"
import "core:testing"
import "core:thread"
import "elodin:cache"
import "elodin:dns"
import "elodin:upstream"

/*
What a forwarded answer tells the client to hold the record for.

The cache bounds the copies it serves by bounding what it stores, which leaves
the copy handed to the client on the miss that filled the entry - the upstream's
own bytes, on their way past. That is the client the ceiling has to reach most:
it is the one whose query fetched the record, so a name that is looked up once
is pinned in the only cache that ever sees it. Driven against a real socket
because the whole point is a response that came from off this machine.
*/

@(private = "file")
HOSTILE_NAME :: "hostile.example."

@(private = "file")
upstream_reply :: proc(ttl: u32) -> []u8 {
	return test_reply(HOSTILE_NAME, .A, a_record(HOSTILE_NAME, {192, 0, 2, 7}, ttl))
}

/*
Put one query through `handle_query` against a mock upstream that answers with
`reply`, and report what came back. The cache is on and bounded by `max_ttl`, as
`cache.max_ttl` bounds it.

`ok` false means the exchange itself did not happen, which the caller reports
rather than reading an answer out of nothing.
*/
@(private = "file")
exchange_once :: proc(
	t: ^testing.T,
	reply: []u8,
	max_ttl: u32,
) -> (
	out: []u8,
	outcome: Outcome,
	ok: bool,
) {
	socket, spec, bound := bind_mock(t)
	if !bound {
		return nil, .Failed, false
	}
	defer net.close(socket)

	cfg := test_config(loopback_upstream(spec.port))
	cfg.cache.enabled = true
	cfg.cache.max_ttl = max_ttl
	group, gerr := upstream.make_group(cfg.upstream)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return nil, .Failed, false
	}
	defer upstream.destroy_group(group)
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = max_ttl})
	defer cache.destroy(answers)
	s := Server {
		cfg     = &cfg,
		answers = answers,
		group   = group,
	}

	x := Canned_Mock {
		socket = socket,
		reply  = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_canned)
	response, got_outcome, done := handle_query(
		&s,
		test_query(HOSTILE_NAME, id = 0x2468),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return nil, .Failed, false
	}
	if !testing.expect(t, done, "nothing came back at all") {
		return nil, .Failed, false
	}
	return response, got_outcome, true
}

/*
Forward one query to a mock upstream that answers with `ttl`, and report the TTL
the client is handed.
*/
@(private = "file")
forwarded_ttl :: proc(t: ^testing.T, ttl: u32, max_ttl: u32) -> (served: u32, ok: bool) {
	out, outcome, done := exchange_once(t, upstream_reply(ttl), max_ttl)
	if !done {
		return 0, false
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)

	served_msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the forwarded copy did not decode") {
		return 0, false
	}
	if !testing.expect(t, len(served_msg.answer) == 1, "the forwarded copy carried no record") {
		return 0, false
	}
	return served_msg.answer[0].ttl, true
}

/*
RFC 2181 section 8, on the path that does not go through the cache:

	Implementations should treat TTL values received with the most significant
	bit set as if the entire value received was zero.

`cache.put` refuses such an answer, which is section 8 as far as this server's
own storage goes, but refusing to keep it is not the same as refusing to pass it
on: the client that caused the fetch still gets the response, and 2^31 seconds
is sixty-eight years in whatever holds it next. One answer, no follow-up
traffic, and nothing in the operator's logs to say it happened.
*/
@(test)
test_a_forwarded_high_bit_ttl_reaches_the_client_as_zero :: proc(t: ^testing.T) {
	ttl, ok := forwarded_ttl(t, 0x8000_0000, 86400)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(0))
	free_all(context.temp_allocator)
}

/*
And `cache.max_ttl` bounds the forwarded copy as well as the cached one.

The answer a miss forwards is the same answer the next client is handed out of
the entry it just filled. Bounding one and not the other would leave the setting
skipping exactly one client per fetch - the one that asked first - which is the
reading dnsmasq's `--max-ttl` has never had: the maximum TTL handed out to
clients.
*/
@(test)
test_max_ttl_bounds_a_forwarded_answer :: proc(t: ^testing.T) {
	ttl, ok := forwarded_ttl(t, 86400, 60)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(60))
	free_all(context.temp_allocator)
}

/*
An answer the walk cannot finish is still bounded as far as the walk got.

The reply here answers the question that was asked, so `response_matches` takes
it, but its ARCOUNT claims a record that is not there: `scan_ttl_offsets` refuses
it outright, and `cache.put` with it, so nothing about this answer is ever
stored. What is left is the copy handed to the client, and the section that copy
is read for - the answer - sits before the point the walk gives up at. So it is
bounded, and section 8 turns `max(u32)` into a zero that tells the client to come
back rather than to keep the record for as long as the machine lasts.

Refused outright for a round, and three tests in this package say why it is not:
an upstream or a middlebox mangling a section this server never reads is not
grounds for making the name unresolvable. See `dns.cap_ttls`.

The offset is taken from the intact reply, because once the header is mangled
nothing will walk the message far enough to find it - which is exactly the
condition under test. `handle_query` rewrites the ID in place and the reply is
far too small to be trimmed, so the answer sits where it did.
*/
@(test)
test_an_unbounded_answer_is_forwarded_with_what_could_be_bounded :: proc(t: ^testing.T) {
	reply := upstream_reply(max(u32))
	if !testing.expect(t, len(reply) >= dns.HEADER_SIZE, "the mock reply was not built") {
		return
	}
	offsets, scanned := dns.scan_ttl_offsets(reply, context.temp_allocator)
	if !testing.expect(t, scanned && len(offsets) == 1, "the intact reply did not scan") {
		return
	}
	// One more additional record than the message carries, so the walk runs off
	// the end. The question is untouched, so the reply is still accepted.
	reply[10], reply[11] = 0, 1

	out, outcome, ok := exchange_once(t, reply, 86400)
	if !ok {
		return
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)
	if !testing.expect(t, len(out) == len(reply), "the answer was not forwarded as it stood") {
		return
	}
	testing.expect_value(t, dns.read_ttl_at(out, int(offsets[0])), u32(0))
	free_all(context.temp_allocator)
}
