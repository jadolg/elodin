package cache

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:loop"

foreign import libc "system:c"

@(private)
@(default_calling_convention = "c")
foreign libc {
	malloc_usable_size :: proc(p: rawptr) -> uint ---
}

/*
What the cache's allocations take from the C heap, read off the heap itself.

A tracking allocator counts what was asked for. What a budget in bytes has to
answer for is what was taken: glibc's chunk header and rounding, and the
pointer and padding Odin's heap allocator puts in front of each block to align
it. So this goes to the platform for each block's size - the start of the block
Odin keeps just before the pointer it returns, and the chunk's usable size plus
its header - rather than to a model of it that the code under test also uses.
*/
@(private)
Resident :: struct {
	held: int,
}

@(private)
resident_allocator :: proc(r: ^Resident) -> mem.Allocator {
	return {procedure = resident_proc, data = r}
}

// What the block at `p`, from Odin's heap allocator, takes from the C heap.
@(private)
chunk :: proc(p: rawptr) -> int {
	if p == nil {
		return 0
	}
	start := ([^]rawptr)(p)[-1]
	return int(malloc_usable_size(start)) + size_of(uint)
}

@(private)
resident_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	r := (^Resident)(data)
	#partial switch mode {
	case .Free, .Resize, .Resize_Non_Zeroed:
		r.held -= chunk(old_memory)
	}
	res, err := runtime.heap_allocator_proc(nil, mode, size, alignment, old_memory, old_size, loc)
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		r.held += chunk(raw_data(res))
	}
	return res, err
}

// Stores NXDOMAINs for `n0.example.` up to `n` and counts how many `put` took.
@(private = "file")
fill :: proc(c: ^Cache, n: int, edns := false) -> (stored: int) {
	kb: [KEY_MAX]u8
	for i in 0 ..< n {
		name := fmt.tprintf("n%d.example.", i)
		wire, msg := build_nxdomain(name, 300, context.temp_allocator, edns = edns)
		if put(c, key_for(kb[:], name), wire, msg) {
			stored += 1
		}
		free_all(context.temp_allocator)
	}
	return
}

/*
`max_bytes` is what the cache holds, with the smallest entries a flood of
distinct names leaves behind (issue #531).

An NXDOMAIN with one SOA is a few dozen bytes of wire, so what it costs is
mostly the five allocations an entry is and its slot in the map - and the count
has been raised so far that the byte budget is what binds, which is the setting
under which those have to be counted. With an OPT record, as an upstream asked
over EDNS sends it, whose slot `scan_ttl_offsets` sizes for and then drops.
*/
@(test)
test_cache_bytes_are_what_small_entries_hold :: proc(t: ^testing.T) {
	BUDGET :: 4 * 1024 * 1024
	INSERTS :: 40_000

	r: Resident
	c := make_cache(Options{max_entries = 1_000_000, max_bytes = BUDGET, max_ttl = 3600}, resident_allocator(&r))
	defer destroy(c)

	stored := fill(c, INSERTS, edns = true)
	testing.expect_value(t, stored, INSERTS)

	// The premise: the budget binds, not the count.
	testing.expectf(t, len_entries(c) < INSERTS, "all %d entries fit in the budget", INSERTS)

	// The Cache itself is the only allocation the count leaves out.
	held := r.held - chunk(c)
	used := bytes_used(c)
	/*
	The budget binds the count, exactly, and eviction stops near it rather than
	well short; the heap agrees with the count to 2%. `held` is not held to the
	budget itself: it is what glibc made of the allocations, which differs run to
	run on arm64 CI (8 bytes over the budget once, under it on the rerun) while
	the count does not.
	*/
	testing.expectf(
		t,
		used <= BUDGET && used >= BUDGET * 3 / 4,
		"the cache counts %d bytes against a %d byte budget",
		used,
		BUDGET,
	)
	testing.expectf(
		t,
		abs(held - used) <= held / 50,
		"the cache counts %d bytes and holds %d over %d entries",
		used,
		held,
		len_entries(c),
	)
}

// An empty cache holds next to nothing, whatever count it is allowed.
@(test)
test_an_empty_cache_reserves_no_table :: proc(t: ^testing.T) {
	r: Resident
	c := make_cache(Options{max_entries = 1_000_000, max_ttl = 3600}, resident_allocator(&r))
	defer destroy(c)
	testing.expectf(t, r.held <= 4096, "an empty cache holds %d bytes", r.held)
}

// A smaller limit gives back the table the larger one grew, not only the entries.
@(test)
test_reconfigure_shrinks_the_table :: proc(t: ^testing.T) {
	r: Resident
	opts := Options{max_entries = 1_000_000, max_ttl = 3600}
	c := make_cache(opts, resident_allocator(&r))
	defer destroy(c)

	fill(c, 20_000)
	full := r.held

	opts.max_entries = 10
	reconfigure(c, opts)
	testing.expect_value(t, len_entries(c), 10)
	testing.expectf(t, r.held <= 16 * 1024, "%d bytes held for 10 entries, %d before", r.held, full)
	testing.expectf(
		t,
		abs(r.held - chunk(c) - bytes_used(c)) <= 256,
		"the cache counts %d bytes and holds %d",
		bytes_used(c),
		r.held,
	)
}

// A cache that stops being queried gives back the table along with the entries.
@(test)
test_sweep_shrinks_the_table :: proc(t: ^testing.T) {
	r: Resident
	c := make_cache(Options{max_entries = 1_000_000, max_ttl = 3600}, resident_allocator(&r))
	defer destroy(c)

	fill(c, 20_000)

	gone := loop.moment_add(loop.moment_now(), -time.Second)
	for _, e in c.entries {
		e.expires = gone
	}
	testing.expect_value(t, sweep(c), 20_000)
	testing.expectf(t, r.held <= 4096, "an emptied cache holds %d bytes", r.held)
}

/*
The table is charged to the budget, so an entry that only just fits can tip the
total over with the table it is indexed in. What gets evicted for that is
something else: `put` reports the entry stored, and it is.
*/
@(test)
test_put_keeps_the_entry_its_table_tipped_over :: proc(t: ^testing.T) {
	kb: [KEY_MAX]u8
	wire, msg := build_nxdomain("tipped.example.", 300, context.temp_allocator)
	defer free_all(context.temp_allocator)
	key := key_for(kb[:], "tipped.example.")

	c := make_cache(Options{max_entries = 8, max_ttl = 3600})
	defer destroy(c)
	testing.expect(t, put(c, key, wire, msg), "the answer was refused with the default budget")
	size := c.bytes

	// Room for the entry and none for the table.
	clear_all(c)
	sync.atomic_store(&c.max_bytes, size)
	testing.expect(t, put(c, key, wire, msg), "an entry that fits was refused")
	testing.expect_value(t, len_entries(c), 1)
	testing.expectf(t, bytes_used(c) > size, "the table is not counted: %d for an entry of %d", bytes_used(c), size)
	_, _, ok := get(c, key, context.temp_allocator)
	testing.expect(t, ok, "put reported an entry stored that it had evicted")
}

/*
A sweep gives the table back once it is under a quarter full, and not before.

Odin would halve it below three eighths, which is where a table at the byte
budget sits after an insert doubled it and evictions paid for that: halved by
one sweep and regrown by the next inserts, every sweep would rehash the cache
twice under its lock. And the entries need not have left through the sweep
itself - `get` drops an expired entry it meets first - so a sweep that removes
nothing still looks.
*/
@(test)
test_sweep_shrinks_only_a_mostly_empty_table :: proc(t: ^testing.T) {
	ENTRIES :: 3000
	c := make_cache(Options{max_entries = 1_000_000, max_ttl = 3600})
	defer destroy(c)

	fill(c, ENTRIES)
	kb: [KEY_MAX]u8
	full := cap(c.entries)

	// Each dropped by `get` on meeting it expired, so no sweep removes them.
	gone := loop.moment_add(loop.moment_now(), -time.Second)
	drop_until :: proc(c: ^Cache, kb: []u8, from, to: int, gone: loop.Moment) {
		for i in from ..< to {
			key := key_for(kb, fmt.tprintf("n%d.example.", i))
			c.entries[key].expires = gone
			_, _, _ = get(c, key, context.temp_allocator)
			free_all(context.temp_allocator)
		}
	}

	// Under three eighths, which Odin would halve, and over a quarter.
	drop_until(c, kb[:], 0, 1800, gone)
	testing.expectf(t, len(c.entries) * 8 < full * 3 && len(c.entries) * 4 >= full, "the premise: %d entries in %d slots", len(c.entries), full)
	testing.expect_value(t, sweep(c), 0)
	testing.expect_value(t, cap(c.entries), full)

	// Under a quarter.
	drop_until(c, kb[:], 1800, 2200, gone)
	testing.expectf(t, len(c.entries) * 4 < full, "the premise: %d entries in %d slots", len(c.entries), full)
	testing.expect_value(t, sweep(c), 0)
	testing.expectf(t, cap(c.entries) < full, "a sweep left %d slots for %d entries", cap(c.entries), len(c.entries))
}

// A reload that drops everything gives back the table too.
@(test)
test_clear_all_shrinks_the_table :: proc(t: ^testing.T) {
	r: Resident
	c := make_cache(Options{max_entries = 1_000_000, max_ttl = 3600}, resident_allocator(&r))
	defer destroy(c)

	fill(c, 20_000)
	clear_all(c)
	testing.expectf(t, r.held <= 4096, "a cleared cache holds %d bytes", r.held)
}

/*
A reload that lowers `max_bytes` below the table the old budget grew keeps what
the new budget holds. Evicting against the table at its peak would empty the
cache for room that shrinking the table gives back.
*/
@(test)
test_reconfigure_to_a_smaller_budget_keeps_what_fits :: proc(t: ^testing.T) {
	BUDGET :: 1024 * 1024
	opts := Options{max_entries = 1_000_000, max_bytes = 8 * BUDGET, max_ttl = 3600}
	c := make_cache(opts)
	defer destroy(c)

	fill(c, 40_000, edns = true)
	testing.expectf(t, table_bytes(c) >= BUDGET, "the premise: a table of %d bytes", table_bytes(c))

	opts.max_bytes = BUDGET
	reconfigure(c, opts)
	used := bytes_used(c)
	testing.expectf(t, used <= BUDGET && used >= BUDGET * 3 / 4, "%d bytes kept of a %d byte budget, %d entries", used, BUDGET, len_entries(c))
}

/*
A reload gives back a table its entries have already left, when it has nothing
to evict. Here `get` dropped them on meeting them expired, so neither a sweep
nor an eviction has looked at the table since.
*/
@(test)
test_reconfigure_shrinks_a_table_with_nothing_to_evict :: proc(t: ^testing.T) {
	opts := Options{max_entries = 1_000_000, max_ttl = 3600}
	c := make_cache(opts)
	defer destroy(c)

	fill(c, 3000)
	full := cap(c.entries)
	kb: [KEY_MAX]u8
	gone := loop.moment_add(loop.moment_now(), -time.Second)
	for i in 0 ..< 2900 {
		key := key_for(kb[:], fmt.tprintf("n%d.example.", i))
		c.entries[key].expires = gone
		_, _, _ = get(c, key, context.temp_allocator)
		free_all(context.temp_allocator)
	}
	testing.expect_value(t, cap(c.entries), full)

	reconfigure(c, opts)
	testing.expect_value(t, len_entries(c), 100)
	testing.expectf(t, cap(c.entries) < full, "a reload left %d slots for %d entries", cap(c.entries), len(c.entries))
}
