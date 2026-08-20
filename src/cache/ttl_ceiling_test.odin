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
answer_with_ttl :: proc(name: string, ttl: u32, allocator := context.allocator) -> ([]u8, dns.Message) {
	m := dns.Message {
		id       = 0x1111,
		question = []dns.Question{{name = name, type = .A, class = .IN}},
		answer   = []dns.Record {
			{name = name, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = {1, 2, 3, 4}}},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		panic("cannot encode the test answer")
	}
	decoded, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		panic("cannot decode the test answer")
	}
	return wire, decoded
}

@(private = "file")
served_ttl :: proc(t: ^testing.T, c: ^Cache, name: string, ttl: u32) -> (u32, bool) {
	wire, msg := answer_with_ttl(name, ttl, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], name, .A, .IN, false)
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
RFC 2181 section 8: a TTL arriving with the top bit set is taken as zero.

Zero is not a TTL an answer can be cached under, so the answer is refused
outright rather than stored with the top bit masked off - which is the whole of
what the RFC asks for, since a record nobody keeps is a record nobody has
pinned. Before this it was stored, and then served verbatim: 2^31 seconds,
sixty-eight years.

What the client is told on the way past is not this package's to decide - the
answer was never cached, so nothing here serves it - and is checked over in
`server`, where `dns.cap_ttls` bounds the forwarded copy.
*/
@(test)
test_a_ttl_with_the_high_bit_set_is_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400})
	defer destroy(c)

	wire, msg := answer_with_ttl("hostile.example.", 0x8000_0000, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "hostile.example.", .A, .IN, false)
	testing.expect(t, !put(c, key, wire, msg), "an answer with the top TTL bit set was stored")
	_, _, found := get(c, key, context.temp_allocator)
	testing.expect(t, !found, "an answer with the top TTL bit set can be served")
	free_all(context.temp_allocator)
}

/*
`cache.min_ttl` still raises a zero.

A TTL of zero reaching a floor an operator set is old behaviour and not
something section 8 changes: the operator has said how long the shortest answer
this cache keeps is good for, and a zeroed TTL is a short answer like any other.
The point of the pair is that both ends now reach the client - the floor through
`patch_ttls`, the ceiling through what `put` stores - so the hostile figure is
gone either way.
*/
@(test)
test_a_zeroed_ttl_is_still_raised_by_min_ttl :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, min_ttl = 300, max_ttl = 3600})
	defer destroy(c)

	ttl, ok := served_ttl(t, c, "floored.example.", 0x8000_0000)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(300))
	free_all(context.temp_allocator)
}
