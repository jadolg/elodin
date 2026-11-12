package server

import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

/*
Issue #623: misses held by a dead upstream must not take the whole of
`server.max_pending`, or the readers shed cache hits with them.
*/

// Everything but a reserved quarter, never fewer than two reserved; none
// without a `max_pending`.
@(test)
test_the_upstream_wait_ceiling_reserves_a_quarter :: proc(t: ^testing.T) {
	cfg: config.Config
	s := Server{cfg = &cfg}
	cfg.server.max_pending = 409
	testing.expect_value(t, upstream_wait_ceiling(&s), 409 - 102)
	cfg.server.max_pending = 4
	testing.expect_value(t, upstream_wait_ceiling(&s), 2)
	// Never fewer than one place to wait in.
	cfg.server.max_pending = 2
	testing.expect_value(t, upstream_wait_ceiling(&s), 1)
	cfg.server.max_pending = 1
	testing.expect_value(t, upstream_wait_ceiling(&s), 1)
	cfg.server.max_pending = 0
	testing.expect_value(t, upstream_wait_ceiling(&s), 0)
}

// The places stop at the ceiling, come back as they are given up, and are
// unbounded at zero.
@(test)
test_upstream_waits_stop_at_the_ceiling :: proc(t: ^testing.T) {
	s: Server
	testing.expect(t, upstream_wait_begin(&s, 2), "the first wait was refused")
	testing.expect(t, upstream_wait_begin(&s, 2), "the second wait was refused")
	testing.expect(t, !upstream_wait_begin(&s, 2), "a wait past the ceiling was let in")
	upstream_wait_end(&s)
	testing.expect(t, upstream_wait_begin(&s, 2), "the place given back was not free again")
	testing.expect(t, upstream_wait_begin(&s, 0), "no ceiling refused a wait")
	testing.expect_value(t, s.upstream_waits, 3)
}

/*
With every place taken, a miss is answered SERVFAIL at once and counted, and a
cache hit is still answered: hits need no place. No upstream group is set, so a
miss that reached the exchange would crash rather than pass.

A query on a connection is not held to the places at all, and the refresh that
would wait on its behalf reports it was not answered rather than counting a
client's failure.
*/
@(test)
test_a_miss_past_the_upstream_waits_fails_and_a_hit_is_served :: proc(t: ^testing.T) {
	cfg := test_config()
	cfg.cache.enabled = true
	cfg.server.max_pending = 8
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	s.upstream_waits = upstream_wait_ceiling(&s)

	hit := "hit.example."
	if !seed_cache(t, answers, hit, test_reply(hit, .A, a_record(hit, {192, 0, 2, 1}, 300))) {
		return
	}

	_, outcome, ok := handle_query(&s, test_query(hit, id = 0x2345), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the hit went unanswered")
	testing.expect_value(t, outcome, Outcome.Cached)

	out, missed, answered_miss := handle_query(&s, test_query("miss.example.", id = 0x2345), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if testing.expect(t, answered_miss, "the miss went unanswered") {
		testing.expect_value(t, missed, Outcome.Failed)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Serv_Fail)
	}
	testing.expect_value(t, s.stats.upstream_shed, 1)
	testing.expect_value(t, s.stats.failed, 1)
	testing.expect_value(t, s.upstream_waits, upstream_wait_ceiling(&s))

	msg, derr := dns.decode_message(test_query("refresh.example.", id = 0x2345), context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	spent := 0
	r := resolve_query(&s, test_query("refresh.example.", id = 0x2345), msg, .UDP, "", 512, {}, {}, &spent, context.temp_allocator, refresh = true)
	testing.expect(t, r.unanswered, "a refresh with no place counted as a client's failure")
	testing.expect_value(t, s.stats.failed, 1)
	testing.expect_value(t, s.stats.upstream_shed, 2)

	free_all(context.temp_allocator)
}

/*
A client waiting on an expired entry's refresh is waiting on an upstream, and
holds a place for it as the refresh does: the refreshes are a quarter of
`max_pending` and the clients waiting on them a quarter more, which with the
places full would be all of it. With one place left the client takes it and
its refresh finds none, so the held bytes go out without the wait; with none
left the client is served them at once and no refresh is started.

The group has no servers, so a refresh that did get a place fails at once
rather than holding one; `upstream_shed` is what says which way it went.
*/
@(test)
test_a_wait_on_a_refresh_holds_a_place :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	group := down_upstream()
	cfg: config.Config
	s := stale_server(&cfg, answers, &group)
	cfg.server.max_pending = 8
	cfg.cache.stale_timeout = 5 * time.Second
	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	s.loops = tl.loops[:]
	defer stop_test_loop(&tl)
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}
	ceiling := upstream_wait_ceiling(&s)

	for left in 0 ..= 1 {
		s.upstream_waits = ceiling - left
		before := s.stats.upstream_shed
		begun := time.tick_now()
		_, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
		testing.expectf(t, ok && outcome == .Cached, "%d left: the expired entry was not served (%v)", left, outcome)
		testing.expectf(t, time.tick_since(begun) < 2 * time.Second, "%d left: the client waited %v", left, time.tick_since(begun))
		// None with none left: the client is served as when `start_refresh`
		// declines, and starts no refresh. Its refresh's, with one.
		testing.expectf(t, int(s.stats.upstream_shed - before) == left, "%d left: %d turned away, want %d", left, s.stats.upstream_shed - before, left)
		drained := wait_until(proc(data: rawptr) -> bool {return queries_pending((^Server)(data)) == 0}, &s, 2 * time.Second)
		testing.expectf(t, drained, "%d left: queries still pending", left)
		testing.expectf(t, s.upstream_waits == ceiling - left, "%d left: %d places held after, want %d", left, s.upstream_waits, ceiling - left)
	}
	free_all(context.temp_allocator)
}
