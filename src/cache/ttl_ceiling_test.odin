package cache

import "core:testing"
import "elodin:dns"

/*
What the client is told a record is good for.

`cache.max_ttl` bounds how long an entry lives here. It does not bound the TTL
written into the copy handed to the client, so a downstream resolver or stub
goes on holding the record long after this cache has dropped it.
*/

@(private = "file")
served_ttl :: proc(t: ^testing.T, c: ^Cache, name: string, ttl: u32) -> (u32, bool) {
	wire, msg := build_answer(name, ttl, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], name)
	if !testing.expect(t, put(c, key, wire, msg), "the answer was not stored") {
		return 0, false
	}
	got, _, ok := get(c, key, context.temp_allocator)
	if !testing.expect(t, ok, "the entry was not found") {
		return 0, false
	}
	decoded, derr := dns.decode_message(got, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the served copy did not decode") {
		return 0, false
	}
	if !testing.expect(t, len(decoded.answer) == 1, "the served copy carried no record") {
		return 0, false
	}
	return decoded.answer[0].ttl, true
}

/*
`cache.min_ttl` is applied to the TTL that goes out - `patch_ttls` takes it as a
floor - and `cache.max_ttl` was not applied to it at all. The two settings read
as a pair in the configuration and only one of them was a statement about what
anybody else is told.
*/
@(test)
test_max_ttl_bounds_the_ttl_the_client_is_given :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 60})
	defer destroy(c)

	ttl, ok := served_ttl(t, c, "example.com.", 86400)
	if !ok {
		return
	}
	// The entry expires in 60 seconds and the client is told 60, rather than the
	// 86400 that had it holding the record long after this cache had dropped it.
	testing.expect_value(t, ttl, u32(60))
	free_all(context.temp_allocator)
}

/*
RFC 8767 section 4: a TTL with the top bit set is positive ("Interpreting
values that have the high-order bit set as being positive, rather than 0, is a
change from [RFC2181]"), so the answer is cached and served at `max_ttl`.
*/
@(test)
test_a_ttl_with_the_high_bit_set_is_cached_at_max_ttl :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400})
	defer destroy(c)

	ttl, ok := served_ttl(t, c, "highbit.example.", 0x8000_0010)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(86400))
	free_all(context.temp_allocator)
}

// `cache.min_ttl` still raises a TTL of zero: the operator has said how long
// the shortest answer this cache keeps is good for.
@(test)
test_a_zero_ttl_is_still_raised_by_min_ttl :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, min_ttl = 300, max_ttl = 3600})
	defer destroy(c)

	ttl, ok := served_ttl(t, c, "floored.example.", 0)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(300))
	free_all(context.temp_allocator)
}

// With no cache, the ceiling is the RFC 8767 section 4 cap.
@(test)
test_no_cache_caps_at_the_rfc_8767_figure :: proc(t: ^testing.T) {
	testing.expect_value(t, ttl_ceiling(nil), dns.TTL_CAP)
	testing.expect_value(t, dns.TTL_CAP, u32(7 * 24 * 60 * 60))
}

/*
The ceiling reaches the stale answer too.

`STALE_TTL` is a fixed thirty seconds, there to bring a client back soon rather
than to stand as a floor - so an operator whose ceiling is shorter than that has
asked for sooner still, and a figure that ignored them would leave one answer
this cache hands out above `max_ttl`. The counted-down TTL cannot cover this:
the stale branch does not use it, because by then it has reached zero.
*/
@(test)
test_a_stale_answer_is_bounded_by_max_ttl :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 10, serve_stale = true})
	defer destroy(c)

	wire, msg := build_answer("stale.example.", 300, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "stale.example.")
	if !testing.expect(t, put(c, key, wire, msg), "the answer was not stored") {
		return
	}
	sync_expire(c, key)

	got, hit, ok := get(c, key, context.temp_allocator)
	if !testing.expect(t, ok && hit.stale, "the expired entry was not lent out") {
		return
	}
	decoded, derr := dns.decode_message(got, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the stale copy did not decode") {
		return
	}
	if !testing.expect(t, len(decoded.answer) == 1, "the stale copy carried no record") {
		return
	}
	testing.expect_value(t, decoded.answer[0].ttl, u32(10))
	free_all(context.temp_allocator)
}
