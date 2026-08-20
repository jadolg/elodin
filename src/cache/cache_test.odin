package cache

import "core:fmt"
import "core:mem"
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
	// And handed out no longer either: the stored figure is clamped with the
	// lifetime, so what the client is told cannot outlast the entry it came
	// from. See `ttl_ceiling_test.odin` for what that is worth.
	testing.expect_value(t, decoded.answer[0].ttl, u32(120))
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

/*
The sweep leaves alone the entries stale serving exists to keep.

`main.maintenance_loop` sweeps every thirty seconds, so an entry the sweep drops
the moment it expires is gone long before an outage has been noticed - and an
outage is the only thing `serve_stale` is for. That left the setting a window of
0 to 30 seconds after expiry to work in, which is precisely the window in which
an upstream that has just stopped answering still looks fine, and an upstream
down for two minutes found the cache already emptied of everything it would have
served.

With the setting off nothing changes: the entry goes at expiry, as it always
has, because keeping expired answers nobody will serve is only memory held for
no reason.
*/
@(test)
test_sweep_keeps_stale_entries :: proc(t: ^testing.T) {
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "stale.example.")
	wire, msg := build_answer("stale.example.", 60, context.temp_allocator)

	c := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer destroy(c)
	testing.expect(t, put(c, key, wire, msg), "the entry was not stored")
	sync_expire(c, key)

	testing.expect_value(t, sweep(c), 0)
	_, stale, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "the entry did not survive a sweep with serve_stale on")
	testing.expect(t, stale, "the surviving entry was not flagged stale")

	off := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(off)
	testing.expect(t, put(off, key, wire, msg), "the entry was not stored")
	sync_expire(off, key)
	testing.expect_value(t, sweep(off), 1)
	free_all(context.temp_allocator)
}

/*
Stale serving is bounded; it is not a licence to answer from last week.

RFC 8767 section 5 asks for a cap on how long expired data may be used and puts
it in the region of a day. Without one, an entry that nothing refreshes would
sit here for as long as the process runs and be handed out during whatever bad
minute an upstream has next - an address that changed months ago, served with
every appearance of being current.

Both the sweep and `get` are held to the same deadline. Either one alone leaves
the other free to contradict it: a sweep that kept the entry would have `get`
serving it, and a `get` that refused it would leave the memory held for a day by
an entry that can no longer be used for anything.
*/
@(test)
test_stale_entries_do_not_outlive_max_stale :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer destroy(c)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "ancient.example.")
	wire, msg := build_answer("ancient.example.", 60, context.temp_allocator)

	testing.expect(t, put(c, key, wire, msg), "the entry was not stored")
	sync_expire(c, key, MAX_STALE + time.Minute)
	_, _, ok := get(c, key, context.temp_allocator)
	testing.expect(t, !ok, "an entry a day past its expiry was still served")
	testing.expect_value(t, len_entries(c), 0)

	testing.expect(t, put(c, key, wire, msg), "the entry was not stored")
	sync_expire(c, key, MAX_STALE + time.Minute)
	testing.expect_value(t, sweep(c), 1)

	// Still inside the window, so both leave it where it is.
	testing.expect(t, put(c, key, wire, msg), "the entry was not stored")
	sync_expire(c, key, MAX_STALE - time.Minute)
	testing.expect_value(t, sweep(c), 0)
	_, _, fresh_enough := get(c, key, context.temp_allocator)
	testing.expect(t, fresh_enough, "an entry inside the stale window was refused")
	free_all(context.temp_allocator)
}

/*
An expired entry is not a lookup the cache answered.

`get` lends the caller an expired copy to fall back on; whether the client ever
sees it depends on an upstream the cache knows nothing about. Counting that as a
hit would put every stale lookup into `elodin_cache_hits_total`, whose help text
says the lookups it counts were answered from the cache, while the resolver
counts the same query as forwarded - a hit rate above what the cache actually
served, and highest exactly when the data is oldest. The stale answers that do
reach a client are counted by `note_stale_served`, once the resolver knows there
was one.
*/
@(test)
test_a_stale_lookup_is_counted_as_a_miss :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer destroy(c)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "counted.example.")

	wire, msg := build_answer("counted.example.", 60, context.temp_allocator)
	testing.expect(t, put(c, key, wire, msg), "the entry was not stored")

	_, _, fresh := get(c, key, context.temp_allocator)
	testing.expect(t, fresh, "expected a hit while the entry was fresh")
	testing.expect_value(t, stats(c).hits, u64(1))

	sync_expire(c, key)
	_, stale, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok && stale, "expected a stale hit")

	s := stats(c)
	testing.expect_value(t, s.hits, u64(1))
	testing.expect_value(t, s.misses, u64(1))
	testing.expect_value(t, s.stale, u64(0))

	note_stale_served(c)
	testing.expect_value(t, stats(c).stale, u64(1))
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

/*
An answer as large as the ones this bound exists for.

`count` A records under one owner name, which the encoder writes as a pointer
apiece, so each record is sixteen bytes of wire and carries an offset and a TTL
of its own alongside it.
*/
@(private = "file")
build_bulky_answer :: proc(
	name: string,
	count: int,
	ttl: u32,
	allocator := context.allocator,
) -> (
	[]u8,
	dns.Message,
) {
	answers := make([]dns.Record, count, allocator)
	for i in 0 ..< count {
		answers[i] = dns.Record {
			name = name,
			type = .A,
			class = .IN,
			ttl = ttl,
			data = dns.Rdata_A{addr = {10, u8(i >> 16), u8(i >> 8), u8(i)}},
		}
	}
	m := dns.Message {
		id       = 0x3333,
		question = []dns.Question{{name = name, type = .A, class = .IN}},
		answer   = answers,
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		panic("failed to encode a bulky test answer")
	}
	decoded, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		panic("failed to decode a bulky test answer")
	}
	return wire, decoded
}

/*
The entry count was the only bound, and a count is not a bound on memory.

An entry holds the response as it arrived - up to 64 KiB, since a query over
TCP, DoT or DoH is answered with a whole message rather than a 512-byte UDP one
- plus an offset and a TTL for each of its records, which for a response packed
with minimal records is about twice the wire size again. So the default ten
thousand entries stood for something in the region of 640 MB, and an attacker
serving maximal answers from a zone it controls needs only distinct names to
walk elodin there. What ends it is the resolver being killed for the memory it
took.

Both halves are checked, because one without the other proves little: the byte
total the eviction loop reads, and what the allocator was actually asked for.
A total that says the right thing while the memory is still held is the failure
this is here to catch.
*/
@(test)
test_cache_holds_to_its_byte_budget :: proc(t: ^testing.T) {
	RECORDS :: 2000 // ~32 KB of wire, ~56 KB accounted, per entry
	INSERTS :: 40
	BUDGET :: 512 * 1024

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	// Told it may hold far more entries than the budget has room for, so the
	// count bound is never what stops it.
	c := make_cache(
		Options{max_entries = INSERTS * 2, max_bytes = BUDGET, max_ttl = 3600},
		mem.tracking_allocator(&track),
	)
	defer destroy(c)

	kb: [KEY_MAX]u8
	names := make([]string, INSERTS, context.temp_allocator)
	for i in 0 ..< INSERTS {
		names[i] = fmt.tprintf("host%d.example.", i)
		wire, msg := build_bulky_answer(names[i], RECORDS, 300, context.temp_allocator)
		testing.expectf(t, put(c, key_for(kb[:], names[i]), wire, msg), "put %d failed", i)
	}

	entry_size := bytes_used(c) / max(1, len_entries(c))
	testing.expectf(
		t,
		bytes_used(c) <= BUDGET,
		"the cache accounts for %d bytes against a %d byte budget",
		bytes_used(c),
		BUDGET,
	)
	// The insertions came to several times the budget, so something had to go.
	testing.expectf(
		t,
		len_entries(c) < INSERTS,
		"all %d entries survived a budget that fits about %d of them",
		INSERTS,
		BUDGET / max(1, entry_size),
	)

	/*
	And the memory itself. The allowance over the budget is what the cache holds
	that entries do not: the Cache, the map's table, and the slack in the
	allocations behind each entry.
	*/
	held := track.current_memory_allocated
	testing.expectf(
		t,
		held <= BUDGET + BUDGET / 2,
		"the cache is holding %d bytes of allocations against a %d byte budget",
		held,
		BUDGET,
	)

	// Evicted from the tail, so the oldest is gone and the newest is not.
	_, _, first_ok := get(c, key_for(kb[:], names[0]), context.temp_allocator)
	testing.expect(t, !first_ok, "the least recently used entry survived")
	_, _, last_ok := get(c, key_for(kb[:], names[INSERTS - 1]), context.temp_allocator)
	testing.expect(t, last_ok, "the most recently used entry was evicted")

	free_all(context.temp_allocator)
}

// Nothing an operator can set makes this reachable with a real answer, but a
// budget smaller than one entry must refuse it rather than empty the cache for
// something it then drops as well.
@(test)
test_an_entry_larger_than_the_budget_is_refused :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_bytes = 1024, max_ttl = 3600})
	defer destroy(c)
	kb: [KEY_MAX]u8

	small, small_msg := build_answer("small.example.", 300, context.temp_allocator)
	testing.expect(t, put(c, key_for(kb[:], "small.example."), small, small_msg), "the small answer was refused")

	wire, msg := build_bulky_answer("huge.example.", 500, 300, context.temp_allocator)
	testing.expect(t, !put(c, key_for(kb[:], "huge.example."), wire, msg), "an entry past the whole budget was stored")

	testing.expect_value(t, len_entries(c), 1)
	_, _, ok := get(c, key_for(kb[:], "small.example."), context.temp_allocator)
	testing.expect(t, ok, "the entry that did fit was evicted for one that did not")
	free_all(context.temp_allocator)
}

/*
The byte total has to come back to zero by every route out of the cache.

A total that only ever goes up is a cache that stops accepting entries once it
has seen enough of them, and a total that goes down too far is a bound that
stops binding. Each path removes an entry somewhere different - `get` on an
expired one, `put` over a key already held, `sweep`, `clear_all` - and each is
its own opportunity to forget.
*/
@(test)
test_byte_accounting_comes_back_to_zero :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	c := make_cache(Options{max_entries = 8, max_ttl = 3600}, mem.tracking_allocator(&track))
	kb: [KEY_MAX]u8

	put_one :: proc(c: ^Cache, kb: []u8, name: string) {
		wire, msg := build_answer(name, 300, context.temp_allocator)
		put(c, key_for(kb, name), wire, msg)
	}

	// Replaced in place: the total must count the new entry, not both.
	put_one(c, kb[:], "a.example.")
	one := bytes_used(c)
	put_one(c, kb[:], "a.example.")
	testing.expect_value(t, bytes_used(c), one)
	testing.expect_value(t, len_entries(c), 1)

	// Dropped by `get`, which is what an expired entry meets first.
	sync_expire(c, key_for(kb[:], "a.example."))
	_, _, _ = get(c, key_for(kb[:], "a.example."), context.temp_allocator)
	testing.expect_value(t, bytes_used(c), 0)

	// Dropped by `sweep`.
	put_one(c, kb[:], "b.example.")
	sync_expire(c, key_for(kb[:], "b.example."))
	testing.expect_value(t, sweep(c), 1)
	testing.expect_value(t, bytes_used(c), 0)

	// Dropped by eviction, with the count as the bound this time.
	small := make_cache(Options{max_entries = 1, max_ttl = 3600}, mem.tracking_allocator(&track))
	put_one(small, kb[:], "c.example.")
	after_one := bytes_used(small)
	put_one(small, kb[:], "d.example.")
	testing.expect_value(t, len_entries(small), 1)
	testing.expect_value(t, bytes_used(small), after_one)
	destroy(small)

	// Dropped by `clear_all`, as a reload does it.
	put_one(c, kb[:], "e.example.")
	clear_all(c)
	testing.expect_value(t, bytes_used(c), 0)

	destroy(c)
	free_all(context.temp_allocator)
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes still held, allocated at %v", entry.size, entry.location)
	}
}

// Test helper: age an entry out without sleeping. `ago` is how far past its
// expiry the entry should land, which the stale-lifetime tests need to push
// beyond a day.
@(private = "file")
sync_expire :: proc(c: ^Cache, key: string, ago := 1 * time.Second) {
	if e, ok := c.entries[key]; ok {
		e.expires = time.time_add(time.now(), -ago)
		e.inserted = time.time_add(time.now(), -ago - 3600 * time.Second)
	}
}
