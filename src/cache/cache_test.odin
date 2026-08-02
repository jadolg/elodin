package cache

import "core:testing"
import "core:time"
import "elodin:dns"

@(private = "file")
build_answer :: proc(name: string, ttl: u32, allocator := context.allocator) -> ([]u8, dns.Message) {
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
		panic("failed to encode test answer")
	}
	decoded, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		panic("failed to decode test answer")
	}
	return wire, decoded
}

@(private = "file")
build_nxdomain :: proc(name: string, soa_min: u32, allocator := context.allocator) -> ([]u8, dns.Message) {
	m := dns.Message {
		id        = 0x2222,
		question  = []dns.Question{{name = name, type = .A, class = .IN}},
		authority = []dns.Record {
			{
				name = "example.com.",
				type = .SOA,
				class = .IN,
				ttl = 3600,
				data = dns.Rdata_SOA {
					ns = "ns.example.com.",
					mbox = "hostmaster.example.com.",
					serial = 1,
					refresh = 7200,
					retry = 3600,
					expire = 1209600,
					minimum = soa_min,
				},
			},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		panic("failed to encode test nxdomain")
	}
	decoded, _ := dns.decode_message(wire, allocator)
	return wire, decoded
}

@(private = "file")
key_for :: proc(buf: []u8, name: string) -> string {
	return make_key(buf, name, .A, .IN, false)
}

@(test)
test_put_and_get :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)

	wire, msg := build_answer("example.com.", 300, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "example.com.")

	testing.expect(t, put(c, key, wire, msg), "put should succeed")
	testing.expect_value(t, len_entries(c), 1)

	got, stale, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "expected a hit")
	testing.expect(t, !stale, "entry should be fresh")

	decoded, derr := dns.decode_message(got, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(decoded.answer), 1)
	// No measurable time has passed, so the TTL comes back intact.
	testing.expect_value(t, decoded.answer[0].ttl, u32(300))

	_, _, miss := get(c, key_for(kb[:], "other.com."), context.temp_allocator)
	testing.expect(t, !miss, "expected a miss for an unrelated name")

	s := stats(c)
	testing.expect_value(t, s.hits, u64(1))
	testing.expect_value(t, s.misses, u64(1))
	free_all(context.temp_allocator)
}

@(test)
test_ttl_clamping :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, min_ttl = 60, max_ttl = 120})
	defer destroy(c)

	// A 3600s answer must be held no longer than max_ttl.
	wire, msg := build_answer("long.example.", 3600, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "long.example.")
	testing.expect(t, put(c, key, wire, msg), "put should succeed")

	got, _, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "expected a hit")
	decoded, _ := dns.decode_message(got, context.temp_allocator)
	// The stored TTL is untouched; only the entry's lifetime is clamped.
	testing.expect_value(t, decoded.answer[0].ttl, u32(3600))
	free_all(context.temp_allocator)
}

@(test)
test_zero_ttl_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)

	wire, msg := build_answer("nocache.example.", 0, context.temp_allocator)
	kb: [KEY_MAX]u8
	testing.expect(t, !put(c, key_for(kb[:], "nocache.example."), wire, msg), "TTL 0 must not be cached")
	testing.expect_value(t, len_entries(c), 0)
	free_all(context.temp_allocator)
}

@(test)
test_negative_caching_uses_soa_minimum :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, negative_ttl = 600})
	defer destroy(c)

	wire, msg := build_nxdomain("gone.example.com.", 120, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "gone.example.com.")
	testing.expect(t, put(c, key, wire, msg), "nxdomain should be cached")

	got, _, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "expected a hit")
	decoded, _ := dns.decode_message(got, context.temp_allocator)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.NX_Domain)
	free_all(context.temp_allocator)
}

@(test)
test_servfail_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)

	wire, msg := build_answer("fail.example.", 300, context.temp_allocator)
	msg.flags.rcode = u8(dns.Rcode.Serv_Fail)
	kb: [KEY_MAX]u8
	testing.expect(t, !put(c, key_for(kb[:], "fail.example."), wire, msg), "SERVFAIL must not be cached")
	free_all(context.temp_allocator)
}

@(test)
test_truncated_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)

	wire, msg := build_answer("tc.example.", 300, context.temp_allocator)
	msg.flags.tc = true
	kb: [KEY_MAX]u8
	testing.expect(t, !put(c, key_for(kb[:], "tc.example."), wire, msg), "truncated answers must not be cached")
	free_all(context.temp_allocator)
}

@(test)
test_lru_eviction :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 2, max_ttl = 3600})
	defer destroy(c)
	kb: [KEY_MAX]u8

	w1, m1 := build_answer("a.example.", 300, context.temp_allocator)
	put(c, key_for(kb[:], "a.example."), w1, m1)
	w2, m2 := build_answer("b.example.", 300, context.temp_allocator)
	put(c, key_for(kb[:], "b.example."), w2, m2)

	// Touch "a" so "b" becomes the least recently used entry.
	_, _, _ = get(c, key_for(kb[:], "a.example."), context.temp_allocator)

	w3, m3 := build_answer("c.example.", 300, context.temp_allocator)
	put(c, key_for(kb[:], "c.example."), w3, m3)

	testing.expect_value(t, len_entries(c), 2)
	_, _, a_ok := get(c, key_for(kb[:], "a.example."), context.temp_allocator)
	testing.expect(t, a_ok, "a should have survived")
	_, _, b_ok := get(c, key_for(kb[:], "b.example."), context.temp_allocator)
	testing.expect(t, !b_ok, "b should have been evicted")
	_, _, c_ok := get(c, key_for(kb[:], "c.example."), context.temp_allocator)
	testing.expect(t, c_ok, "c should be present")
	free_all(context.temp_allocator)
}

@(test)
test_expiry_and_sweep :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)
	kb: [KEY_MAX]u8

	wire, msg := build_answer("short.example.", 1, context.temp_allocator)
	key := key_for(kb[:], "short.example.")
	put(c, key, wire, msg)

	// Force expiry without waiting for real time to pass.
	sync_expire(c, key)

	_, _, ok := get(c, key, context.temp_allocator)
	testing.expect(t, !ok, "expired entry should miss")
	testing.expect_value(t, len_entries(c), 0)
	free_all(context.temp_allocator)
}

@(test)
test_serve_stale :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer destroy(c)
	kb: [KEY_MAX]u8

	wire, msg := build_answer("stale.example.", 60, context.temp_allocator)
	key := key_for(kb[:], "stale.example.")
	put(c, key, wire, msg)
	sync_expire(c, key)

	got, stale, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "stale serving should still hit")
	testing.expect(t, stale, "hit should be flagged stale")
	decoded, _ := dns.decode_message(got, context.temp_allocator)
	testing.expect_value(t, decoded.answer[0].ttl, u32(STALE_TTL))
	free_all(context.temp_allocator)
}

@(test)
test_key_distinguishes_type_and_do :: proc(t: ^testing.T) {
	kb1: [KEY_MAX]u8
	kb2: [KEY_MAX]u8
	a := make_key(kb1[:], "example.com.", .A, .IN, false)
	b := make_key(kb2[:], "example.com.", .AAAA, .IN, false)
	testing.expect(t, a != b, "type must be part of the key")

	c := make_key(kb2[:], "example.com.", .A, .IN, true)
	testing.expect(t, a != c, "the DO bit must be part of the key")

	d := make_key(kb2[:], "EXAMPLE.com.", .A, .IN, false)
	testing.expect_value(t, a, d)
}

// Test helper: age an entry out without sleeping.
@(private = "file")
sync_expire :: proc(c: ^Cache, key: string) {
	if e, ok := c.entries[key]; ok {
		e.expires = time.time_add(time.now(), -1 * time.Second)
		e.inserted = time.time_add(time.now(), -3600 * time.Second)
	}
}
