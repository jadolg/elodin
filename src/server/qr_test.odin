package server

import "core:sync"
import "core:testing"
import "elodin:config"

// `query` with the QR bit set: the same bytes, sent as a response.
@(private = "file")
as_response :: proc(query: []u8) -> []u8 {
	out := make([]u8, len(query), context.temp_allocator)
	copy(out, query)
	out[2] |= 0x80
	return out
}

/*
RFC 1035 section 4.1.1: QR says "whether this message is a query (0), or a
response (1)". A response reaching a listener is dropped before it is decoded:
not answered - not even with the FORMERR one that does not decode would get as
a query - and not counted as a query. Unbound (`worker_check_request`) and BIND
(`ns__client_request`) drop it the same way, ahead of parsing.
*/
@(test)
test_a_response_is_dropped_before_it_is_read :: proc(t: ^testing.T) {
	cfg: config.Config
	s := rewrite_server(&cfg, "qr.test.")

	well_formed := test_query("qr.test.", id = 0x6921)
	// A header claiming a question, with the name cut off mid-label.
	garbled := []u8{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a', 'b', 'c'}
	for query in ([][]u8{well_formed, garbled}) {
		// The premise: sent as a query, each is answered.
		_, _, answered := handle_query(&s, query, .UDP, TEST_CLIENT, context.temp_allocator)
		testing.expect(t, answered, "the premise: the query was answered")

		queries, dropped := sync.atomic_load(&s.stats.queries), sync.atomic_load(&s.stats.dropped)
		out, _, ok := handle_query(&s, as_response(query), .UDP, TEST_CLIENT, context.temp_allocator)
		testing.expectf(t, !ok && out == nil, "a response was answered with %d bytes", len(out))
		testing.expect_value(t, sync.atomic_load(&s.stats.queries), queries)
		testing.expect_value(t, sync.atomic_load(&s.stats.dropped), dropped + 1)
	}
	free_all(context.temp_allocator)
}

/*
Over DoH a response is the client's error, so it is a 400 (RFC 9110 section
15.5.1), not the 500 that would have a client retry or fail over.
*/
@(test)
test_doh_answers_a_response_with_400 :: proc(t: ^testing.T) {
	query := test_query("qr.test.", id = 0x6922)
	_, _, _, is_query := doh_query_message("POST", DOH_CONTENT_TYPE, query, "")
	testing.expect(t, is_query, "the premise: a query is taken")
	_, status, why, taken := doh_query_message("POST", DOH_CONTENT_TYPE, as_response(query), "")
	testing.expectf(t, !taken && status == 400, "a response was taken (%v) or refused with %d %q", taken, status, why)
	free_all(context.temp_allocator)
}
