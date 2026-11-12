package server

import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:loop"

/*
Move `STALE_NAME`'s entry into the last `left` of a 300-second lifetime.

`cache_an_answer` stores it with a TTL of 300; this is the same trick its
`expired` flag plays, stopping short of the expiry instead of passing it.
*/
@(private = "file")
age_to :: proc(answers: ^cache.Cache, left: time.Duration) {
	if e := stale_entry(answers); e != nil {
		e.expires = loop.moment_add(loop.moment_now(), left)
		e.inserted = loop.moment_add(e.expires, -300 * time.Second)
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
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second, looped = true, expired = false, answers = prefetch_answers()) {
		return
	}
	defer stale_fixture_stop(&f)
	f.cfg.cache.serve_stale = false
	age_to(f.answers, 20 * time.Second)

	x := Stale_Exchange {
		socket = f.socket,
		reply  = live_reply(),
		delay  = 400 * time.Millisecond,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)

	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
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
	stale_fixture_join(&f)

	cs := cache.stats(f.answers)
	testing.expect_value(t, cs.prefetches, 1)
	testing.expect_value(t, cs.prefetch_failures, 0)
	testing.expect_value(t, cs.hits, 1)
	testing.expect_value(t, cs.misses, 0)
	testing.expect_value(t, f.srv.stats.cached, 1)
	testing.expect_value(t, f.srv.stats.forwarded, 0)

	wire, _, found := stale_get(f.answers)
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

The loop is stopped between the two queries so the second finds the first
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
		tl: Test_Loop
		if !testing.expect(t, start_test_loop(&tl), "no loop") {
			return
		}
		s.loops = tl.loops[:]
		_, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
		testing.expect(t, ok, "the cached answer went unserved")
		testing.expect_value(t, outcome, Outcome.Cached)
		stop_test_loop(&tl)
	}
	s.loops = nil

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

	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	s.loops = tl.loops[:]
	_, _, ok := handle_query(&s, stale_query(false), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the RD=0 query went unserved")
	stop_test_loop(&tl)
	testing.expect_value(t, cache.stats(answers).prefetches, 0)

	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	s.loops = tl.loops[:]
	_, _, ok = handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the RD=1 query went unserved")
	stop_test_loop(&tl)
	s.loops = nil
	testing.expect_value(t, cache.stats(answers).prefetches, 1)
	free_all(context.temp_allocator)
}

/*
With every place to wait on an upstream taken, a hit near expiry starts no
prefetch, as with `max_pending` full: one started would be turned away before it
asked, and count as a prefetch and a failed one (issue #623).
*/
@(test)
test_no_prefetch_past_the_upstream_waits :: proc(t: ^testing.T) {
	answers := prefetch_answers()
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	cfg.server.max_pending = 8
	s.upstream_waits = upstream_wait_ceiling(&s)
	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}
	age_to(answers, 20 * time.Second)

	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	s.loops = tl.loops[:]
	_, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok && outcome == .Cached, "the hit went unserved")
	stop_test_loop(&tl)
	s.loops = nil
	cs := cache.stats(answers)
	testing.expect_value(t, cs.prefetches, 0)
	testing.expect_value(t, cs.prefetch_failures, 0)
	testing.expect_value(t, s.stats.upstream_shed, 0)
	free_all(context.temp_allocator)
}

// Both prefetch counters reach the endpoint, each from its own field.
@(test)
test_prefetch_counters_reach_the_endpoint :: proc(t: ^testing.T) {
	answers := prefetch_answers()
	defer cache.destroy(answers)
	answers.prefetches = 7
	answers.prefetch_failures = 3
	cfg: config.Config
	s := metrics_fixture(&cfg, Stats{})
	s.answers = answers
	listeners: Listeners
	page := render_metrics(&s, &listeners, context.temp_allocator)
	testing.expect(t, strings.contains(page, "\nelodin_cache_prefetches_total 7\n"), page)
	testing.expect(t, strings.contains(page, "\nelodin_cache_prefetch_failures_total 3\n"), page)
	free_all(context.temp_allocator)
}

/*
A prefetch that meets a remembered Bogus verdict counts nothing.

Serving the verdict replays a refusal reached earlier, for a client; the
prefetch is not one, and no validation ran to count in the DNSSEC series.
*/
@(test)
test_a_prefetch_does_not_count_a_replayed_verdict :: proc(t: ^testing.T) {
	cfg: config.Config
	s := stale_server(&cfg, nil, nil)
	query := stale_query(true)
	msg, derr := dns.decode_message(query, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	hit := Cached_Answer {
		wire = make([]u8, len(query), context.temp_allocator),
	}
	copy(hit.wire, query)

	{
		prefetching = true
		defer prefetching = false
		serve_bogus_verdict(&s, hit, query, msg, msg.question[0], .UDP, "127.0.0.1:5555", time.tick_now())
	}
	testing.expect_value(t, s.stats.bogus, 0)
	testing.expect_value(t, s.stats.failed, 0)

	serve_bogus_verdict(&s, hit, query, msg, msg.question[0], .UDP, "127.0.0.1:5555", time.tick_now())
	testing.expect_value(t, s.stats.bogus, 1)
	testing.expect_value(t, s.stats.failed, 1)
	free_all(context.temp_allocator)
}
