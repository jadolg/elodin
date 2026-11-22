package filter

import "base:runtime"
import "core:fmt"
import "core:testing"
import "elodin:dns"

@(test)
test_table_holds_every_name_through_growth_and_trim :: proc(t: ^testing.T) {
	N :: 20_000
	block := set_make()
	for i in 0 ..< N {
		testing.expect(t, set_add(block, fmt.tprintf("sink-%d.bench.invalid", i), {.Apex}))
	}
	testing.expect_value(t, block.count, N)
	// Never fuller than the load an insert allows, and never without an empty
	// slot for a miss to stop at.
	testing.expect(t, block.names.used * 5 <= len(block.names.slots) * TABLE_LOAD_FIFTHS)

	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, set_make())
	// The swap trims the slots to the count at full load.
	testing.expect_value(t, len(block.names.slots), N * 5 / TABLE_LOAD_FIFTHS + 1)
	testing.expect_value(t, len(block.names.blob), cap(block.names.blob))

	for i in 0 ..< N {
		if !testing.expectf(t, engine_match(e, fmt.tprintf("sink-%d.bench.invalid.", i), .A) == .Blocked, "sink-%d lost", i) {
			return
		}
		if !testing.expectf(t, engine_match(e, fmt.tprintf("sink-%d.bench.valid.", i), .A) == .None, "sink-%d.bench.valid matched", i) {
			return
		}
	}

	// What a rule costs once loaded (#494): the name, its flags byte and NUL, and
	// a slot at 80%. These names are 20 to 24 bytes.
	bytes := len(block.names.slots) * size_of(Slot) + cap(block.names.blob)
	testing.expectf(t, bytes / N <= 38, "%d bytes a rule", bytes / N)
}

@(test)
test_table_hash_match_is_not_a_name_match :: proc(t: ^testing.T) {
	s := set_make()
	defer set_destroy(s)
	set_add(s, "ads.example", {.Apex})
	set_add(s, "ads", {.Apex})
	// Give every entry the hash of "ad" and place them by it, so a probe for "ad"
	// compares each entry's bytes: "ads" holds it as a prefix and "ads.example"
	// as a longer one.
	h := table_hash(&s.names, "ad")
	for &slot in s.names.slots {
		if slot.off != 0 {
			slot.hash = h
		}
	}
	table_resize(&s.names, len(s.names.slots))
	testing.expect(t, table_entry(&s.names, "ad") == nil)
	testing.expect(t, !set_lookup(s, "ad", .A))
}

@(test)
test_table_cancelled_name_reads_as_absent :: proc(t: ^testing.T) {
	s := set_make()
	defer set_destroy(s)
	set_add(s, "ads.example", {.Apex, .Subdomains})
	set_cancel(s, "ads.example", {.Apex, .Subdomains})
	testing.expect_value(t, s.count, 0)
	testing.expect(t, !set_lookup(s, "ads.example", .A))
	testing.expect(t, !set_lookup(s, "x.ads.example", .A))
	// Cancelling it again counts nothing twice.
	set_cancel(s, "ads.example", {.Apex})
	testing.expect_value(t, s.count, 0)

	// The entry stays, so a rule for the name once nothing cancels it is counted
	// once more and matches.
	clear(&s.cancelled)
	testing.expect(t, set_add(s, "ads.example", {.Apex}))
	testing.expect_value(t, s.count, 1)
	testing.expect_value(t, s.names.used, 1)
	testing.expect(t, set_lookup(s, "ads.example", .A))
	testing.expect(t, !set_lookup(s, "x.ads.example", .A))
}

@(test)
test_table_offsets_stay_in_a_u32 :: proc(t: ^testing.T) {
	limit := int(max(u32))
	testing.expect(t, blob_fits(limit - 10, 8))
	testing.expect(t, !blob_fits(limit - 10, 9))
	testing.expect(t, blob_fits(0, 1021))

	// And an insert asks it before writing anything: a blob that says it is
	// full turns a name away, which no real list can be made big enough to show.
	s := set_make()
	defer set_destroy(s)
	raw := (^runtime.Raw_Dynamic_Array)(&s.names.blob)
	held := raw.len
	raw.len = limit
	testing.expect(t, !set_add(s, "ads.example", {.Apex}))
	testing.expect_value(t, s.count, 0)
	testing.expect_value(t, s.names.used, 0)
	raw.len = held
}

// Whether a rule covers `normalised` for `qtype`, as the tests ask it.
@(private)
set_lookup :: proc(s: ^Set, normalised: string, qtype: dns.Type) -> bool {
	return set_cover(s, normalised, qtype) != .None
}
