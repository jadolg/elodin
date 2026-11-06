package server

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

/*
`Query_State` sits in `resolve_query`'s frame, which a query waiting on its
upstream holds for the whole wait, so its size is stack every query in flight
keeps resident (#614). Nothing in it is a buffer sized for the worst case: the
cache keys, which were two of `cache.KEY_MAX`, are the request's.
*/
@(test)
test_a_parked_query_holds_no_key_buffer :: proc(t: ^testing.T) {
	testing.expectf(
		t,
		size_of(Query_State) < cache.KEY_MAX,
		"Query_State is %d bytes, a key buffer's worth of every parked query's stack",
		size_of(Query_State),
	)
}

@(private = "file")
stage_state :: proc(s: ^Server, name: string, spent: ^int, allocator: mem.Allocator) -> Query_State {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = {name = name, type = .AAAA, class = .IN}
	msg := dns.Message {
		id       = 0x1234,
		flags    = {rd = true, cd = true},
		question = questions,
	}
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	return Query_State {
		s = s,
		query = wire,
		msg = msg,
		q = questions[0],
		proto = .UDP,
		client = "127.0.0.1:5555",
		limit = 512,
		started = time.tick_now(),
		spent = spent,
		allocator = allocator,
	}
}

/*
The keys the cache stage settles are byte for byte the ones a `KEY_MAX` buffer
gives, for an ordinary name and for the longest a question can carry, and are
as long as the name and the tail.
*/
@(test)
test_cache_keys_are_as_long_as_the_name :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	s := Server {
		cfg = &cfg,
	}
	defer free_all(context.temp_allocator)

	// 127 labels of one escaped byte: 127 * 5 = 635 presentation bytes, a
	// 255-byte wire name.
	long := make([]u8, 127 * 5, context.temp_allocator)
	for i in 0 ..< 127 {
		copy(long[i * 5:], "\\000.")
	}
	for name in ([]string{"www.Example.COM.", string(long)}) {
		spent: int
		st := stage_state(&s, name, &spent, context.temp_allocator)
		testing.expect(t, !answer_from_cache(&st), "an RD=1 miss with no cache was not handed on")

		want_buf: [cache.KEY_MAX]u8
		want := cache.make_key(want_buf[:], name, .AAAA, .IN, false, true, policy = live(&s).policy)
		testing.expect_value(t, st.key, want)
		testing.expect_value(t, len(st.key), len(name) + cache.KEY_TAIL)

		want_verdict_buf: [cache.KEY_MAX]u8
		want_verdict := cache.make_key(want_verdict_buf[:], name, .AAAA, .IN, false, true, verdict = true, policy = live(&s).policy)
		testing.expect_value(t, st.verdict_key, want_verdict)
	}
}

// `key_size` is what `make_key` writes, the cap included.
@(test)
test_key_size_is_what_make_key_writes :: proc(t: ^testing.T) {
	over := make([]u8, cache.KEY_MAX + 100, context.temp_allocator)
	defer free_all(context.temp_allocator)
	for &b in over {
		b = 'a'
	}
	for name in ([]string{"", "a.", string(over)}) {
		buf: [cache.KEY_MAX]u8
		testing.expect_value(t, cache.key_size(name), len(cache.make_key(buf[:], name, .A, .IN, false)))
	}
}

/*
A request whose arena hands back nothing for the keys fails the question rather
than indexing an empty slice. A nil allocator returns no memory and no error, so
it is the length that is checked.
*/
@(test)
test_a_request_with_no_room_for_its_keys_fails :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	s := Server {
		cfg = &cfg,
	}
	defer free_all(context.temp_allocator)
	spent: int
	st := stage_state(&s, "example.com.", &spent, mem.nil_allocator())
	testing.expect(t, answer_from_cache(&st), "a question with no keys was handed on")
	testing.expect(t, !st.ok, "a question with no keys was answered")
	testing.expect_value(t, st.outcome, Outcome.Failed)
	testing.expect_value(t, st.key, "")
}
