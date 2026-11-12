package cache

import "base:runtime"
import "core:fmt"
import "core:sync"
import "core:testing"
import "core:thread"
import "elodin:dns"

// A cache the default size is split; one too small for a working share in each
// is not, and keeps the one LRU order its size needs.
@(test)
test_shard_count_follows_the_limits :: proc(t: ^testing.T) {
	testing.expect_value(t, shard_count(10_000, DEFAULT_MAX_BYTES), MAX_SHARDS)
	testing.expect_value(t, shard_count(8, DEFAULT_MAX_BYTES), 1)
	testing.expect_value(t, shard_count(2 * MIN_SHARD_ENTRIES - 1, DEFAULT_MAX_BYTES), 1)
	testing.expect_value(t, shard_count(2 * MIN_SHARD_ENTRIES, DEFAULT_MAX_BYTES), 2)
	testing.expect_value(t, shard_count(1_000_000, 2 * MIN_SHARD_BYTES - 1), 1)
	testing.expect_value(t, shard_count(1_000_000, 4 * MIN_SHARD_BYTES), 4)

	c := make_cache(Options{max_entries = 10_000})
	defer destroy(c)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)
	small := make_cache(Options{max_entries = 8})
	defer destroy(small)
	testing.expect_value(t, shards_in_use(small), 1)
}

// The shares add up to exactly the configured limits, after a reload too, so
// splitting the cache neither loosens the bound nor wastes any of it.
@(test)
test_shares_add_up_to_the_limits :: proc(t: ^testing.T) {
	sums :: proc(c: ^Cache) -> (entries, bytes: int) {
		for &s in c.shards {
			entries += s.max_entries
			bytes += s.max_bytes
		}
		return
	}
	c := make_cache(Options{max_entries = 10_007, max_bytes = 64 * 1024 * 1024 + 5})
	defer destroy(c)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)
	entries, bytes := sums(c)
	testing.expect_value(t, entries, 10_007)
	testing.expect_value(t, bytes, 64 * 1024 * 1024 + 5)

	reconfigure(c, Options{max_entries = 10, max_bytes = 3_000_001})
	entries, bytes = sums(c)
	testing.expect_value(t, entries, 10)
	testing.expect_value(t, bytes, 3_000_001)
}

/*
A flood of distinct names leaves the whole cache within the limits however
the names fall across the shards, and fills it: a keyed hash spreads them, so
no shard runs dry while another evicts.
*/
@(test)
test_a_flood_fills_every_shard_within_the_limits :: proc(t: ^testing.T) {
	MAX :: MIN_SHARD_ENTRIES * MAX_SHARDS
	c := make_cache(Options{max_entries = MAX, max_ttl = 3600})
	defer destroy(c)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)

	kb: [KEY_MAX]u8
	for i in 0 ..< 3 * MAX {
		name := fmt.tprintf("f%d.example.", i)
		wire, msg := build_nxdomain(name, 300, context.temp_allocator)
		put(c, key_for(kb[:], name), wire, msg)
		free_all(context.temp_allocator)
	}
	testing.expectf(t, len_entries(c) <= MAX, "%d entries held under a limit of %d", len_entries(c), MAX)
	testing.expectf(t, len_entries(c) >= MAX * 99 / 100, "%d entries held under a limit of %d", len_entries(c), MAX)
	for &s in c.shards {
		testing.expect_value(t, len(s.entries), s.max_entries)
	}
	testing.expect_value(t, stats(c).inserts, u64(3 * MAX))
	testing.expect_value(t, stats(c).evictions, u64(3 * MAX - len_entries(c)))
}

// Whether every entry sits in the shard its key hashes to, and every shard's
// byte total is what its entries hold.
@(private = "file")
consistent :: proc(t: ^testing.T, c: ^Cache) {
	for &s in c.shards {
		held := 0
		for k, e in s.entries {
			held += entry_bytes(e)
			testing.expect(t, shard_for(c, k, c.shard_bits) == &s, "an entry sits in a shard its key does not hash to")
		}
		testing.expect_value(t, s.bytes, held)
		testing.expect(t, len(s.entries) <= s.max_entries)
	}
}

/*
A reload counts the shards again from the new limits and moves the entries it
keeps, which stay where a lookup finds them. A count kept from the old limits
would split the new ones below the per-shard floors.
*/
@(test)
test_a_reload_counts_the_shards_again :: proc(t: ^testing.T) {
	opts := Options{max_entries = 100_000, max_ttl = 3600}
	c := make_cache(opts)
	defer destroy(c)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)
	kb: [KEY_MAX]u8
	for i in 0 ..< 2000 {
		name := fmt.tprintf("m%d.example.", i)
		wire, msg := build_answer(name, 300, context.temp_allocator)
		testing.expect(t, put(c, key_for(kb[:], name), wire, msg))
		free_all(context.temp_allocator)
	}
	found :: proc(c: ^Cache) -> (n: int) {
		kb: [KEY_MAX]u8
		for i in 0 ..< 2000 {
			if _, _, ok := get(c, key_for(kb[:], fmt.tprintf("m%d.example.", i)), context.temp_allocator, probe = true); ok {
				n += 1
			}
			free_all(context.temp_allocator)
		}
		return
	}

	opts.max_entries = 300
	reconfigure(c, opts)
	testing.expect_value(t, shards_in_use(c), 1)
	testing.expect_value(t, c.shards[0].max_entries, 300)
	testing.expect_value(t, len_entries(c), 300)
	testing.expect_value(t, found(c), 300)
	consistent(t, c)

	opts.max_entries = 100_000
	reconfigure(c, opts)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)
	testing.expect_value(t, len_entries(c), 300)
	testing.expect_value(t, found(c), 300)
	consistent(t, c)
}

/*
A reload to a smaller budget still takes the largest answers it has room for.
Sixteen shards kept across a reload to 1 MiB would give each 64 KiB, under
what one large answer takes.
*/
@(test)
test_a_reload_to_a_small_budget_keeps_room_for_a_large_answer :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 10_000, max_ttl = 3600})
	defer destroy(c)
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)
	reconfigure(c, Options{max_entries = 10_000, max_bytes = MIN_SHARD_BYTES, max_ttl = 3600})

	records := make([]dns.Record, 3000, context.temp_allocator)
	for &r, i in records {
		r = {name = "big.example.", type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {10, 0, u8(i >> 8), u8(i)}}}
	}
	m := dns.Message {
		question = []dns.Question{{name = "big.example.", type = .A, class = .IN}},
		answer   = records,
	}
	m.flags.qr = true
	wire, msg := wire_and_msg(m)
	defer free_all(context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for(kb[:], "big.example.")
	offsets, _ := dns.scan_ttl_offsets(wire, context.temp_allocator)
	size := sizeof_entry(len(key), len(wire), len(offsets))
	testing.expectf(t, size > MIN_SHARD_BYTES / MAX_SHARDS, "the premise: an entry of %d bytes", size)
	testing.expect(t, put(c, key, wire, msg), "a large answer the budget has room for was refused")
}

// A reload that moves the entries hands no serial out twice: one held across it
// never names a later entry under the same key.
@(test)
test_a_reload_hands_no_serial_out_twice :: proc(t: ^testing.T) {
	opts := Options{max_entries = 100_000, max_ttl = 3600}
	c := make_cache(opts)
	defer destroy(c)
	kb: [KEY_MAX]u8
	highest: u64
	key: string
	for i in 0 ..< 200 {
		name := fmt.tprintf("q%d.example.", i)
		wire, msg := build_answer(name, 300, context.temp_allocator)
		key = key_for(kb[:], name)
		put(c, key, wire, msg)
		_, hit, _ := get(c, key, context.temp_allocator)
		highest = max(highest, hit.serial)
		free_all(context.temp_allocator)
	}
	opts.max_entries = 300
	reconfigure(c, opts)
	for i in 0 ..< 200 {
		name := fmt.tprintf("q%d.example.", i)
		wire, msg := build_answer(name, 300, context.temp_allocator)
		key = key_for(kb[:], name)
		put(c, key, wire, msg)
		_, hit, _ := get(c, key, context.temp_allocator)
		testing.expectf(t, hit.serial > highest, "serial %d handed out again after a reload", hit.serial)
		free_all(context.temp_allocator)
	}
}

// The hits and misses each shard counts add up to what was asked of the cache.
@(test)
test_stats_add_up_across_shards :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 100_000, max_ttl = 3600})
	defer destroy(c)
	kb: [KEY_MAX]u8
	for i in 0 ..< 100 {
		name := fmt.tprintf("s%d.example.", i)
		wire, msg := build_answer(name, 300, context.temp_allocator)
		testing.expect(t, put(c, key_for(kb[:], name), wire, msg))
		_, _, ok := get(c, key_for(kb[:], name), context.temp_allocator)
		testing.expect(t, ok)
		_, _, ok = get(c, key_for(kb[:], fmt.tprintf("absent%d.example.", i)), context.temp_allocator)
		testing.expect(t, !ok)
		free_all(context.temp_allocator)
	}
	st := stats(c)
	testing.expect_value(t, st.hits, u64(100))
	testing.expect_value(t, st.misses, u64(100))
	testing.expect_value(t, st.inserts, u64(100))
	testing.expect_value(t, len_entries(c), 100)
}

// Which names share a shard is the cache's own secret: two caches split the
// same names differently.
@(test)
test_the_split_is_keyed :: proc(t: ^testing.T) {
	a := make_cache(Options{max_entries = 100_000})
	defer destroy(a)
	b := make_cache(Options{max_entries = 100_000})
	defer destroy(b)
	kb: [KEY_MAX]u8
	differ := false
	for i in 0 ..< 64 {
		key := key_for(kb[:], fmt.tprintf("k%d.example.", i))
		ia := int(uintptr(shard_for(a, key, a.shard_bits)) - uintptr(&a.shards[0])) / size_of(Shard)
		ib := int(uintptr(shard_for(b, key, b.shard_bits)) - uintptr(&b.shards[0])) / size_of(Shard)
		differ ||= ia != ib
	}
	testing.expect(t, differ, "two caches put 64 names in the same shards")
}

@(private = "file")
Probe :: struct {
	c:    ^Cache,
	key:  string,
	done: bool,
}

/*
What the shards are for (issue #582): a lookup in one shard does not wait on
another. Behind a single lock for the whole cache, the lookup below would sit
behind the lock the test holds.
*/
@(test)
test_a_lookup_does_not_wait_on_another_shard :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 100_000, max_ttl = 3600})
	defer destroy(c)
	kb, other: [KEY_MAX]u8
	held := shard_for(c, key_for(kb[:], "held.example."), c.shard_bits)
	p := new(Probe)
	defer free(p)
	p.c = c
	for i in 0 ..< 1000 {
		p.key = key_for(other[:], fmt.tprintf("o%d.example.", i))
		if shard_for(c, p.key, c.shard_bits) != held {
			break
		}
	}
	testing.expect(t, shard_for(c, p.key, c.shard_bits) != held, "the premise: no name fell in another shard")
	testing.expect_value(t, shards_in_use(c), MAX_SHARDS)

	sync.mutex_lock(&held.mu)
	th := thread.create_and_start_with_data(p, proc(data: rawptr) {
		p := (^Probe)(data)
		_, _, _ = get(p.c, p.key)
		sync.atomic_store(&p.done, true)
	})
	// Bounded, and a passing run leaves at once; a failing one is let go below
	// rather than left hanging.
	for i := 0; i < 100_000_000 && !sync.atomic_load(&p.done); i += 1 {
		thread.yield()
	}
	done := sync.atomic_load(&p.done)
	sync.mutex_unlock(&held.mu)
	thread.join(th)
	thread.destroy(th)
	testing.expect(t, done, "a lookup waited on a lock held over another shard")
}

@(private = "file")
Racer :: struct {
	c:  ^Cache,
	id: int,
}

/*
Lookups, stores, removals and reloads from several threads at once leave every
entry in the shard its key hashes to, every shard's byte total equal to what
its entries hold, and the whole within the limits. The reloads move between
four and sixteen shards, so lookups race the entries being moved. A total that
drifts is a bound that does not hold.
*/
@(test)
test_shards_account_under_concurrency :: proc(t: ^testing.T) {
	THREADS :: 4
	ROUNDS :: 4000
	// The heap, not the test's tracking allocator, which the racers would share.
	c := make_cache(Options{max_entries = 40_000, max_ttl = 3600}, runtime.heap_allocator())
	defer destroy(c)
	rs: [THREADS]Racer
	ts: [THREADS]^thread.Thread
	for &r, i in rs {
		r = {c, i}
		ts[i] = thread.create_and_start_with_data(&r, proc(data: rawptr) {
			r := (^Racer)(data)
			kb: [KEY_MAX]u8
			for i in 0 ..< ROUNDS {
				name := fmt.tprintf("r%d.example.", (i * 7 + r.id) % 3000)
				key := key_for(kb[:], name)
				wire, msg := build_nxdomain(name, 300, context.temp_allocator)
				put(r.c, key, wire, msg)
				if _, hit, ok := get(r.c, key, context.temp_allocator); ok && i % 5 == 0 {
					forget(r.c, key, hit.serial)
				}
				if r.id == 0 && i % 500 == 0 {
					reconfigure(r.c, Options{max_entries = 2000 + i, max_ttl = 3600})
				}
				free_all(context.temp_allocator)
			}
		})
	}
	for th in ts {
		thread.join(th)
		thread.destroy(th)
	}
	consistent(t, c)
	testing.expect(t, len_entries(c) <= c.max_entries)
}
