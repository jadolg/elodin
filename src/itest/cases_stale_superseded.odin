package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
Issue #419: an answer the cache will not keep still supersedes the expired copy.

The upstream answers a refresh with TTL 0 - the zone saying "do not cache this"
(RFC 2181 section 8) - and later than `stale_timeout`, so the client is lent the
expired copy and the refresh lands behind it. The copy then stands for nothing:
the next query must wait for the upstream rather than be lent the old address
again, which it would be for the rest of the day `serve_stale` keeps it.

The store is waited on through `elodin_cache_entries` rather than slept on: the
gauge drops by one when the refresh lands and forgets the copy, and never does
if it keeps it.
*/
run_stale_superseded_cases :: proc(r: ^Runner) {
	qname := "superseded.example."
	upstream_port := next_port(r)
	udp_port := next_port(r)
	metrics_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "3s",
		upstream_extra = "  attempts: 1",
		cache = "{ enabled: true, max_entries: 100, max_ttl: 1, serve_stale: true, stale_timeout: 300ms }",
		extra = fmt.tprintf(`metrics: {{ enabled: true, address: "127.0.0.1", port: %d }}`, metrics_port),
	)

	before := mock_make("superseded-before", upstream_port)
	mock_synth_all(before, {203, 0, 113, 41})
	if !mock_start_or_skip(r, before, "serve_stale superseded") {
		return
	}
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		mock_stop(before)
		return
	}
	defer stop_server(&srv)

	start_case(r, "serve_stale: a late TTL-0 answer is not followed by the expired copy")
	defer end_case(r)

	first := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 41))
	mock_stop(before)
	if !check(r, first.ok, "no response to the query that filled the cache") {
		return
	}
	check_eq_str(r, first_address(r, first.wire), "203.0.113.41", "the answer that was cached")

	// Past `max_ttl`, which is what the entry was stored under: the clock is
	// what this waits for.
	time.sleep(1500 * time.Millisecond)

	after := mock_make("superseded-after", upstream_port)
	mock_delay_all(after, 800 * time.Millisecond, make_a_response(qname, {203, 0, 113, 42}, 0, context.allocator))
	// Stopped whether or not it started: `mock_stop` frees a failed start too.
	defer mock_stop(after)
	if !check(r, mock_start(after), "cannot restart the mock upstream") {
		return
	}
	held := superseded_entries(metrics_port)
	if !check(r, held >= 1, "elodin_cache_entries read %d with the expired copy held", held) {
		return
	}

	// The premise: the client is lent the expired copy, and the refresh runs on.
	lent := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 42))
	if !check(r, lent.ok, "the expired copy was never lent") {
		return
	}
	check_eq_str(r, first_address(r, lent.wire), "203.0.113.41", "the lent copy")

	deadline := time.tick_now()
	for v := superseded_entries(metrics_port); (v < 0 || v >= held) && time.tick_since(deadline) < 5 * time.Second; v = superseded_entries(metrics_port) {
		time.sleep(50 * time.Millisecond)
	}
	check_eq_int(r, mock_total(after), 1, "upstream queries for the refresh")
	left := superseded_entries(metrics_port)
	if !check(r, left >= 0 && left < held, "the expired copy outlived the upstream's TTL-0 answer (%d entries)", left) {
		return
	}

	again := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 43))
	if check(r, again.ok, "no response once the refresh had landed") {
		check_eq_str(r, first_address(r, again.wire), "203.0.113.42", "the answer after the refresh")
	}
}

@(private = "file")
superseded_entries :: proc(metrics_port: int) -> int {
	// -1 when the endpoint never answers: `metric_value` finds nothing in "".
	return metric_value(metrics_page(metrics_port), "elodin_cache_entries")
}
