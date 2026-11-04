package cache

import "base:runtime"
import "core:fmt"
import "core:sync"
import "core:testing"
import "core:thread"

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
	testing.expect_value(t, len(c.shards), MAX_SHARDS)
	small := make_cache(Options{max_entries = 8})
	defer destroy(small)
	testing.expect_value(t, len(small.shards), 1)
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
	testing.expect_value(t, len(c.shards), MAX_SHARDS)
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
	testing.expect_value(t, len(c.shards), MAX_SHARDS)

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

/*
A reload that sets a limit below the number of shards leaves some shards no
part of it, and those store nothing, so the cache holds what the limit says
rather than one entry a shard.
*/
@(test)
test_a_limit_below_the_shard_count_holds :: proc(t: ^testing.T) {
	opts := Options{max_entries = 100_000, max_ttl = 3600}
	c := make_cache(opts)
	defer destroy(c)
	testing.expect_value(t, len(c.shards), MAX_SHARDS)
	opts.max_entries = 3
	reconfigure(c, opts)

	kb: [KEY_MAX]u8
	for i in 0 ..< 200 {
		name := fmt.tprintf("z%d.example.", i)
		wire, msg := build_nxdomain(name, 300, context.temp_allocator)
		key := key_for(kb[:], name)
		stored := put(c, key, wire, msg)
		testing.expect_value(t, stored, shard_for(c, key).max_entries > 0)
		free_all(context.temp_allocator)
	}
	testing.expect_value(t, len_entries(c), 3)
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
		ia := int(uintptr(shard_for(a, key)) - uintptr(raw_data(a.shards))) / size_of(Shard)
		ib := int(uintptr(shard_for(b, key)) - uintptr(raw_data(b.shards))) / size_of(Shard)
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
another. With the one lock this held before, the lookup below would sit behind
the lock the test holds.
*/
@(test)
test_a_lookup_does_not_wait_on_another_shard :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 100_000, max_ttl = 3600})
	defer destroy(c)
	kb, other: [KEY_MAX]u8
	held := shard_for(c, key_for(kb[:], "held.example."))
	p := new(Probe)
	defer free(p)
	p.c = c
	for i in 0 ..< 1000 {
		p.key = key_for(other[:], fmt.tprintf("o%d.example.", i))
		if shard_for(c, p.key) != held {
			break
		}
	}
	testing.expect(t, shard_for(c, p.key) != held, "the premise: no name fell in another shard")
	testing.expect_value(t, len(c.shards), MAX_SHARDS)

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
shard's byte total equal to what its entries hold, and the whole within the
limits. A total that drifts is a bound that does not hold.
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
	total := 0
	for &s in c.shards {
		held := 0
		for _, e in s.entries {
			held += entry_bytes(e)
		}
		testing.expect_value(t, s.bytes, held)
		testing.expect(t, len(s.entries) <= s.max_entries)
		total += len(s.entries)
	}
	testing.expect(t, total <= c.max_entries)
}
