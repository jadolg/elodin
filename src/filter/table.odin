package filter

import "base:intrinsics"
import "base:runtime"
import "core:math/rand"
import "core:mem"

/*
The names a Set holds: an open-addressed hash table over one byte blob.

Each name is written once into `blob` as its flags byte, the name, and a NUL,
which `rule_key` never lets into a name. A `.Typed` entry is followed by the ids
of its two `$dnstype` filters (TYPED_IDS), so a name a typed rule covers costs
eight bytes more and no second probe. A slot holds the name's 32-bit hash and
the offset of its entry, so a probe compares hashes in the slot array and reads
the blob only on a match: a lookup is one hash and a short linear scan. A rule
costs its name, two bytes, and an 8-byte slot at up to 80% load.

Nothing is deleted: a name a `$badfilter` takes back keeps its entry with no
flags, which reads as absent, so there are no tombstones. Both arrays are on the
heap rather than the Set's arena, so a growth frees what it replaces, and
`table_trim` cuts the slots to the final count once a load is done.
*/

@(private)
Slot :: struct {
	hash: u32,
	// Where the entry starts in `blob`; zero is an empty slot, which the pad byte
	// `table_init` writes keeps from naming an entry.
	off:  u32,
}

@(private)
Table :: struct {
	slots:     []Slot,
	blob:      [dynamic]u8,
	// Occupied slots, including names whose flags were all taken back.
	used:      int,
	// Per table, as Odin's own maps seed theirs, so a list cannot be written to
	// collide on every machine.
	seed:          u64,
	allocator:     mem.Allocator,
	// An insert found no memory, so the table lacks a name it was given.
	out_of_memory: bool,
}

// The most a table holds before it grows, in fifths: 4 is 80%.
@(private)
TABLE_LOAD_FIFTHS :: 4

// False when there is no memory for the first blob.
@(private)
table_init :: proc(t: ^Table, allocator: mem.Allocator) -> bool {
	t.allocator = allocator
	t.seed = rand.uint64()
	// The pad byte first.
	err: mem.Allocator_Error
	t.blob, err = make([dynamic]u8, 1, 1024, allocator)
	return err == nil
}

@(private)
table_destroy :: proc(t: ^Table) {
	delete(t.slots, t.allocator)
	delete(t.blob)
}

// What an Odin map hashes a string with, eight bytes a step, folded to 32 bits.
@(private)
table_hash :: #force_inline proc(t: ^Table, key: string) -> u32 {
	key := key
	h := u64(runtime.default_hasher_string(&key, uintptr(t.seed)))
	return u32(h ~ (h >> 32))
}

// The slot `hash` starts probing at: the high bits of hash * len, which spreads
// it over a table of any size, so `table_trim` need not round up to a power of two.
@(private)
table_home :: #force_inline proc(hash: u32, n: int) -> int {
	return int((u64(hash) * u64(n)) >> 32)
}

// The flags stored for `key`, or nil when the table has no entry for it. The
// pointer is into the blob, so it is good only until the next insert.
@(private)
table_entry :: proc(t: ^Table, key: string) -> ^Rule_Flags {
	i := table_find(t, key)
	return nil if i < 0 else (^Rule_Flags)(&t.blob[t.slots[i].off])
}

// The slot holding `key`, or -1.
@(private)
table_find :: proc(t: ^Table, key: string) -> int {
	n := len(t.slots)
	if n == 0 {
		return -1
	}
	h := table_hash(t, key)
	i := table_home(h, n)
	for d := 0; ; d += 1 {
		slot := t.slots[i]
		// Robin Hood order: every entry this far from its home or further sits
		// before any entry nearer to its own, so the first nearer one ends a miss.
		if slot.off == 0 || table_distance(slot, i, n) < d {
			return -1
		}
		if slot.hash == h {
			start := int(slot.off) + 1
			end := start + len(key)
			if end < len(t.blob) && t.blob[end] == 0 && string(t.blob[start:end]) == key {
				return i
			}
		}
		i += 1
		if i == n {
			i = 0
		}
	}
}

// Whether an entry for a `key_len`-byte name still starts at an offset a slot
// can hold.
@(private)
blob_fits :: proc(blob_len, key_len: int) -> bool {
	return blob_len + key_len + 2 <= int(max(u32))
}

/*
Add `key`, which the caller has found absent, with `flags`, and the zeroed ids
that follow a `.Typed` entry. False when the blob can take no more: 4 GiB of
names is no list a resolver can be asked to hold, and refusing it is what keeps
every offset in a u32. False too, setting `out_of_memory` and leaving the table
as it was, when the slots or the blob cannot grow.
*/
@(private)
table_insert :: proc(t: ^Table, key: string, flags: Rule_Flags) -> bool {
	if !blob_fits(len(t.blob), len(key) + TYPED_IDS) {
		return false
	}
	if (t.used + 1) * 5 > len(t.slots) * TABLE_LOAD_FIFTHS && !table_resize(t, max(len(t.slots) * 2, 64)) {
		t.out_of_memory = true
		return false
	}
	off := table_write(t, key, flags) or_return
	table_place(t.slots, Slot{hash = table_hash(t, key), off = off})
	t.used += 1
	return true
}

/*
Append an entry for `key` to the blob, returning where it starts. False, setting
`out_of_memory` and leaving the blob as it was, when it cannot grow.
*/
@(private)
table_write :: proc(t: ^Table, key: string, flags: Rule_Flags) -> (off: u32, ok: bool) {
	off = u32(len(t.blob))
	size := len(key) + 2 + (TYPED_IDS if .Typed in flags else 0)
	// Grown for the whole entry before any byte is written, doubling as
	// `append` does: an `append` that cannot grow copies what fits, and a name
	// cut short is stored as another.
	if len(t.blob) + size > cap(t.blob) && reserve(&t.blob, max(2 * cap(t.blob), len(t.blob) + size)) != nil {
		t.out_of_memory = true
		return 0, false
	}
	// Inside the capacity, so it cannot fail, and zeroes the NUL and the ids.
	resize(&t.blob, len(t.blob) + size)
	t.blob[off] = transmute(u8)flags
	copy(t.blob[off + 1:], key)
	return off, true
}

/*
Give `key`'s entry the room for its `$dnstype` filters, returning it: written
again at the end of the blob with `.Typed` set, and its slot pointed there. The
old bytes stay, unreachable; a name is moved once, since `.Typed` is never taken
away. Nil, leaving the entry as it was, when `key` is absent or the blob is full
or cannot grow.
*/
@(private)
table_retype :: proc(t: ^Table, key: string) -> ^Rule_Flags {
	i := table_find(t, key)
	if i < 0 || !blob_fits(len(t.blob), len(key) + TYPED_IDS) {
		return nil
	}
	flags := (transmute(Rule_Flags)t.blob[t.slots[i].off]) + {.Typed}
	off, written := table_write(t, key, flags)
	if !written {
		return nil
	}
	t.slots[i].off = off
	return (^Rule_Flags)(&t.blob[t.slots[i].off])
}

// The bytes after a `.Typed` entry's NUL: the filter ids for its apex and for
// below it, unaligned.
TYPED_IDS :: size_of([2]u32)

@(private)
typed_ids :: proc(entry: ^Rule_Flags, key_len: int) -> [2]u32 {
	return intrinsics.unaligned_load((^[2]u32)(uintptr(entry) + uintptr(key_len + 2)))
}

@(private)
typed_ids_store :: proc(entry: ^Rule_Flags, key_len: int, ids: [2]u32) {
	intrinsics.unaligned_store((^[2]u32)(uintptr(entry) + uintptr(key_len + 2)), ids)
}

// How many slots past its home `slot` sits at `i`.
@(private)
table_distance :: #force_inline proc(slot: Slot, i, n: int) -> int {
	d := i - table_home(slot.hash, n)
	return d + n if d < 0 else d
}

/*
Linear probing in Robin Hood order, as Odin's own maps do: an entry passing one
nearer to its home takes that slot and carries the other on. At 80% load plain
linear probing walks about 13 slots to find a name absent, and most lookups are
for absent names: each parent of a query name is one.
*/
@(private)
table_place :: proc(slots: []Slot, slot: Slot) {
	n := len(slots)
	slot := slot
	i := table_home(slot.hash, n)
	for d := 0; ; d += 1 {
		held := slots[i]
		if held.off == 0 {
			slots[i] = slot
			return
		}
		if hd := table_distance(held, i, n); hd < d {
			slots[i] = slot
			slot = held
			d = hd
		}
		i += 1
		if i == n {
			i = 0
		}
	}
}

// Rehash into `n` slots; false, leaving the table as it was, when there is no
// memory for them.
@(private)
table_resize :: proc(t: ^Table, n: int) -> bool {
	slots, err := make([]Slot, n, t.allocator)
	if err != nil {
		return false
	}
	for slot in t.slots {
		if slot.off != 0 {
			table_place(slots, slot)
		}
	}
	delete(t.slots, t.allocator)
	t.slots = slots
	return true
}

/*
Cut the slots to what `used` needs at the most load an insert allows, and the
blob to what it holds. A table grown by doubling is between 40% and 80% full;
this is what makes a loaded list cost its 80% figure whatever its size.
*/
@(private)
table_trim :: proc(t: ^Table) {
	n := t.used * 5 / TABLE_LOAD_FIFTHS + 1
	if t.used > 0 && n < len(t.slots) {
		// With no memory for the smaller slots the larger still hold every name.
		table_resize(t, n)
	}
	shrink(&t.blob)
}
