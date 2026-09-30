package server

import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:pool"
import "elodin:upstream"

/*
Move `STALE_NAME`'s entry into the last `left` of a 300-second lifetime.

`cache_an_answer` stores it with a TTL of 300; this is the same trick its
`expired` flag plays, stopping short of the expiry instead of passing it.
*/
@(private = "file")
age_to :: proc(answers: ^cache.Cache, left: time.Duration) {
	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	if e, found := answers.entries[key]; found {
		e.expires = time.time_add(time.now(), left)
		e.inserted = time.time_add(e.expires, -300 * time.Second)
	}
}

@(private = "file")
prefetch_answers :: proc() -> ^cache.Cache {
	return cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, prefetch = true, prefetch_min_ttl = 9})
}

/*
A hit near expiry is answered from the cache at once and refreshes the entry
behind it (issue #468).

Without this, the first query after a popular name's entry expires waits a full
upstream round trip - which a monitoring probe asking every fifteen seconds sees
as a peak once in every TTL. The upstream here sits on the refresh for 400 ms,
so a client that waited for it would get its address; the one served here gets
the old one, and the cache ends up holding the new one.

The client's lookup is one cache hit and one cached answer. The refresh is
counted as a prefetch and nothing else: it is not a query anybody sent, so it
is neither a miss nor a forwarded answer.
*/
@(test)
test_a_hit_near_expiry_is_refreshed_behind_the_client :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return
	}

	answers := prefetch_answers()
	defer cache.destroy(answers)
	cfg: config.Config
	s := stale_server(&cfg, answers, nil)
	cfg.cache.serve_stale = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 5 * time.Second
	cfg.upstream.servers = blackhole_servers(bound.port)
	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s.group = group
	workers := pool.make_pool(2)
	joined := false
	defer if !joined {
		pool.destroy(workers)
	}
	s.handler_pool = workers

	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}
	age_to(answers, 20 * time.Second)

	x := Stale_Exchange {
		socket = socket,
		reply  = live_reply(),
		delay  = 400 * time.Millisecond,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)

	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "the cached answer went unserved") {
		thread.join(mock)
		thread.destroy(mock)
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)
	served, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, len(served.answer) == 1, "the answer carried no record") {
		a, _ := served.answer[0].data.(dns.Rdata_A)
		testing.expectf(t, a.addr != LIVE_ADDR, "the client waited for the refresh")
	}

	thread.join(mock)
	thread.destroy(mock)
	testing.expect(t, x.got, "nothing refreshed the entry ahead of its expiry")
	pool.destroy(workers)
	joined = true
	s.handler_pool = nil

	cs := cache.stats(answers)
	testing.expect_value(t, cs.prefetches, 1)
	testing.expect_value(t, cs.prefetch_failures, 0)
	testing.expect_value(t, cs.hits, 1)
	testing.expect_value(t, cs.misses, 0)
	testing.expect_value(t, s.stats.cached, 1)
	testing.expect_value(t, s.stats.forwarded, 0)

	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	wire, _, found := cache.get(answers, key, context.temp_allocator)
	if !testing.expect(t, found, "the entry is gone") {
		return
	}
	stored, cerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, cerr, dns.Decode_Error.None)
	if testing.expect(t, len(stored.answer) == 1, "the stored answer carried no record") {
		a, _ := stored.answer[0].data.(dns.Rdata_A)
		testing.expectf(t, a.addr == LIVE_ADDR, "the cache still holds %v", a.addr)
	}
	free_all(context.temp_allocator)
}

/*
A prefetch that fails is not tried again for the same entry.

The refresh leaves the entry as it was, still inside its window, so without the
entry's one claim every later hit would start another: an upstream query per
client query, against an upstream that has just shown it is not answering. The
entry expires as it would have without prefetching, and the failure is counted.

The pool is joined between the two queries so the second finds the first
refresh finished rather than still in its slot, which would hold it off for a
different reason.
*/
@(test)
test_a_failed_prefetch_is_not_retried :: proc(t: ^testing.T) {
	answers := prefetch_answers()
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}
	age_to(answers, 20 * time.Second)

	for _ in 0 ..< 2 {
		s.handler_pool = pool.make_pool(1)
		_, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
		testing.expect(t, ok, "the cached answer went unserved")
		testing.expect_value(t, outcome, Outcome.Cached)
		pool.destroy(s.handler_pool)
	}
	s.handler_pool = nil

	cs := cache.stats(answers)
	testing.expect_value(t, cs.prefetches, 1)
	testing.expect_value(t, cs.prefetch_failures, 1)
	testing.expect_value(t, s.stats.cached, 2)
	testing.expect_value(t, s.stats.failed, 0)
	free_all(context.temp_allocator)
}

/*
An RD=0 query near expiry is answered from the entry and starts nothing.

It asked for what this server already knows, and a refresh on its behalf is the
recursion it did not ask for (RFC 1035 section 4.1.1) - so it must neither start
one nor spend the entry's claim, which the next query that does recurse is owed.
*/
@(test)
test_an_rd_zero_hit_does_not_prefetch :: proc(t: ^testing.T) {
	answers := prefetch_answers()
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}
	age_to(answers, 20 * time.Second)

	s.handler_pool = pool.make_pool(1)
	_, _, ok := handle_query(&s, stale_query(false), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the RD=0 query went unserved")
	pool.destroy(s.handler_pool)
	testing.expect_value(t, cache.stats(answers).prefetches, 0)

	s.handler_pool = pool.make_pool(1)
	_, _, ok = handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the RD=1 query went unserved")
	pool.destroy(s.handler_pool)
	s.handler_pool = nil
	testing.expect_value(t, cache.stats(answers).prefetches, 1)
	free_all(context.temp_allocator)
}

// Both prefetch counters reach the endpoint, each from its own field.
@(test)
test_prefetch_counters_reach_the_endpoint :: proc(t: ^testing.T) {
	answers := prefetch_answers()
	defer cache.destroy(answers)
	answers.stats.prefetches = 7
	answers.stats.prefetch_failures = 3
	s, cfg := metrics_fixture(Stats{})
	s.cfg = &cfg
	s.answers = answers
	listeners: Listeners
	page := render_metrics(&s, &listeners, context.temp_allocator)
	testing.expect(t, strings.contains(page, "\nelodin_cache_prefetches_total 7\n"), page)
	testing.expect(t, strings.contains(page, "\nelodin_cache_prefetch_failures_total 3\n"), page)
	free_all(context.temp_allocator)
}
