package server

import "core:mem"
import "core:testing"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

/*
`Query_State` sits in `resolve_query`'s frame, which a query waiting on its
upstream holds for the whole wait, so its size is stack every query in flight
keeps resident (#614). Nothing in it is a buffer sized for the worst case: the
cache keys are the request's, not two `cache.KEY_MAX` arrays in the frame.
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

// An RD and CD question for `name`'s AAAA, the shape the key cases read.
@(private = "file")
aaaa_question :: proc(name: string) -> dns.Message {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = {name = name, type = .AAAA, class = .IN}
	return dns.Message{id = 0x1234, flags = {rd = true, cd = true}, question = questions}
}

/*
The keys the cache stage settles are byte for byte the ones a `KEY_MAX` buffer
gives, for an ordinary name and for the longest a question can carry, and are
as long as the name and the tail.
*/
@(test)
test_cache_keys_are_as_long_as_the_name :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	defer free_all(context.temp_allocator)

	// Labels of 63, 63, 63 and 61 escaped bytes: a 255-byte wire name, and at
	// four presentation bytes a byte, the longest presentation name there is.
	long_name: [dynamic]u8
	long_name.allocator = context.temp_allocator
	for label_len in ([]int{63, 63, 63, 61}) {
		for _ in 0 ..< label_len {
			append(&long_name, "\\000")
		}
		append(&long_name, '.')
	}
	long := long_name[:]
	testing.expect_value(t, len(long), 1004)
	for name in ([]string{"www.Example.COM.", string(long)}) {
		spent: int
		st := stage_state(&s, aaaa_question(name), &spent, context.temp_allocator)
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
	cfg: config.Config
	s := local_server(&cfg)
	defer free_all(context.temp_allocator)
	for refresh in ([]bool{false, true}) {
		spent: int
		st := stage_state(&s, aaaa_question("example.com."), &spent, mem.nil_allocator())
		st.refresh = refresh
		testing.expect(t, answer_from_cache(&st), "a question with no keys was handed on")
		testing.expect(t, !st.ok, "a question with no keys was answered")
		testing.expect_value(t, st.outcome, Outcome.Failed)
		testing.expect_value(t, st.key, "")
		// A detached refresh is counted by the client holding the entry, not here.
		testing.expect_value(t, st.unanswered, refresh)
		testing.expect_value(t, s.stats.failed, 1)
	}
}
