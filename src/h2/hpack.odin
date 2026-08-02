package h2

import "core:mem"
import "core:strings"

/*
HPACK header compression (RFC 7541).

The decoder is complete: static and dynamic tables, all four literal
representations, integer continuation, dynamic table size updates, and Huffman
decoding.

The encoder is deliberately minimal. It emits indexed fields for exact static
table matches and otherwise literals without indexing, uncompressed. That is
fully conformant — HPACK never requires a sender to compress — and it keeps the
encoder free of a dynamic table whose state would have to stay in lockstep with
the peer's. DNS response headers are a handful of short fields, so the bytes
saved would not pay for the risk.
*/

// Bound on a decoded header list, to stop a hostile peer from making us
// allocate without limit.
MAX_HEADER_LIST :: 32 * 1024
MAX_HEADER_COUNT :: 128

Hpack_Error :: enum u8 {
	None,
	Truncated,
	Bad_Index,
	Bad_Huffman,
	Too_Large,
	Bad_Update,
}

Dynamic_Table :: struct {
	// Newest first, which is the order HPACK indexes them in.
	entries:   [dynamic]Header_Field,
	size:      int,
	max_size:  int,
	allocator: mem.Allocator,
}

// RFC 7541 section 4.1: each entry costs its name and value plus 32 bytes.
@(private)
entry_size :: proc(f: Header_Field) -> int {
	return len(f.name) + len(f.value) + 32
}

dynamic_table_init :: proc(t: ^Dynamic_Table, max_size: int, allocator := context.allocator) {
	t.allocator = allocator
	t.max_size = max_size
	t.entries = make([dynamic]Header_Field, 0, 16, allocator)
}

dynamic_table_destroy :: proc(t: ^Dynamic_Table) {
	for e in t.entries {
		delete(e.name, t.allocator)
		delete(e.value, t.allocator)
	}
	delete(t.entries)
}

dynamic_table_set_max :: proc(t: ^Dynamic_Table, max_size: int) {
	t.max_size = max_size
	evict(t)
}

@(private)
evict :: proc(t: ^Dynamic_Table) {
	for t.size > t.max_size && len(t.entries) > 0 {
		last := t.entries[len(t.entries) - 1]
		t.size -= entry_size(last)
		delete(last.name, t.allocator)
		delete(last.value, t.allocator)
		pop(&t.entries)
	}
}

@(private)
dynamic_table_add :: proc(t: ^Dynamic_Table, name, value: string) {
	f := Header_Field {
		name  = strings.clone(name, t.allocator),
		value = strings.clone(value, t.allocator),
	}
	size := entry_size(f)
	// An entry larger than the whole table empties it and is not stored.
	if size > t.max_size {
		for e in t.entries {
			delete(e.name, t.allocator)
			delete(e.value, t.allocator)
		}
		clear(&t.entries)
		t.size = 0
		delete(f.name, t.allocator)
		delete(f.value, t.allocator)
		return
	}
	inject_at(&t.entries, 0, f)
	t.size += size
	evict(t)
}

// Index 1..61 is the static table; anything above indexes the dynamic table.
@(private)
table_lookup :: proc(t: ^Dynamic_Table, index: int) -> (f: Header_Field, ok: bool) {
	if index <= 0 {
		return {}, false
	}
	if index < len(STATIC_TABLE) {
		return STATIC_TABLE[index], true
	}
	i := index - len(STATIC_TABLE)
	if i >= len(t.entries) {
		return {}, false
	}
	return t.entries[i], true
}

@(private)
Bit_Reader :: struct {
	buf: []u8,
	pos: int,
}

/*
Decode an HPACK integer with an N-bit prefix (RFC 7541 section 5.1).

`prefix_bits` is how many low bits of the first byte carry the value.
*/
@(private)
read_integer :: proc(r: ^Bit_Reader, prefix_bits: uint) -> (value: int, err: Hpack_Error) {
	if r.pos >= len(r.buf) {
		return 0, .Truncated
	}
	mask := int(1 << prefix_bits) - 1
	v := int(r.buf[r.pos]) & mask
	r.pos += 1
	if v < mask {
		return v, .None
	}

	shift: uint = 0
	for {
		if r.pos >= len(r.buf) {
			return 0, .Truncated
		}
		b := r.buf[r.pos]
		r.pos += 1
		v += int(b & 0x7f) << shift
		if v > MAX_HEADER_LIST {
			return 0, .Too_Large
		}
		if b & 0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return 0, .Too_Large
		}
	}
	return v, .None
}

@(private)
read_string :: proc(r: ^Bit_Reader, allocator: mem.Allocator) -> (s: string, err: Hpack_Error) {
	if r.pos >= len(r.buf) {
		return "", .Truncated
	}
	huffman := r.buf[r.pos] & 0x80 != 0
	length := read_integer(r, 7) or_return
	if r.pos + length > len(r.buf) {
		return "", .Truncated
	}
	raw := r.buf[r.pos:r.pos + length]
	r.pos += length

	if !huffman {
		return strings.clone(string(raw), allocator), .None
	}
	return huffman_decode(raw, allocator)
}

/*
Decode a header block.

Returns the header list allocated from `allocator`. `table` carries the dynamic
table across calls on the same connection, as HPACK requires.
*/
decode :: proc(
	table: ^Dynamic_Table,
	block: []u8,
	allocator := context.allocator,
) -> (
	headers: []Header_Field,
	err: Hpack_Error,
) {
	r := Bit_Reader {
		buf = block,
	}
	out := make([dynamic]Header_Field, 0, 16, allocator)
	// Every failure below abandons the whole list, and there are eight ways to
	// reach one. Releasing the fields decoded so far here rather than at each
	// return keeps a peer from leaking a header block per rejected connection.
	defer if err != .None {
		for f in out {
			delete(f.name, allocator)
			delete(f.value, allocator)
		}
		delete(out)
	}
	total := 0

	for r.pos < len(r.buf) {
		if len(out) >= MAX_HEADER_COUNT {
			return nil, .Too_Large
		}
		b := r.buf[r.pos]

		switch {
		case b & 0x80 != 0:
			// Indexed header field.
			index := read_integer(&r, 7) or_return
			f, ok := table_lookup(table, index)
			if !ok {
				return nil, .Bad_Index
			}
			append(&out, Header_Field{strings.clone(f.name, allocator), strings.clone(f.value, allocator)})

		case b & 0xc0 == 0x40:
			// Literal with incremental indexing.
			f := read_literal(&r, table, 6, allocator) or_return
			dynamic_table_add(table, f.name, f.value)
			append(&out, f)

		case b & 0xe0 == 0x20:
			// Dynamic table size update.
			size := read_integer(&r, 5) or_return
			if size > 65536 {
				return nil, .Bad_Update
			}
			dynamic_table_set_max(table, size)
			continue

		case:
			// Literal without indexing (0x00) or never indexed (0x10). Both are
			// read the same way; the distinction only matters to intermediaries
			// that re-encode, which we do not.
			f := read_literal(&r, table, 4, allocator) or_return
			append(&out, f)
		}

		if len(out) > 0 {
			last := out[len(out) - 1]
			total += len(last.name) + len(last.value) + 32
			if total > MAX_HEADER_LIST {
				return nil, .Too_Large
			}
		}
	}
	return out[:], .None
}

@(private)
read_literal :: proc(
	r: ^Bit_Reader,
	table: ^Dynamic_Table,
	prefix_bits: uint,
	allocator: mem.Allocator,
) -> (
	f: Header_Field,
	err: Hpack_Error,
) {
	index := read_integer(r, prefix_bits) or_return
	name: string
	if index == 0 {
		name = read_string(r, allocator) or_return
	} else {
		entry, ok := table_lookup(table, index)
		if !ok {
			return {}, .Bad_Index
		}
		name = strings.clone(entry.name, allocator)
	}
	// The name is held locally until the value is known: a field is returned
	// whole or not at all, so a truncated value cannot orphan the name.
	value, verr := read_string(r, allocator)
	if verr != .None {
		delete(name, allocator)
		return {}, verr
	}
	return Header_Field{name = name, value = value}, .None
}

// --- encoding --------------------------------------------------------------

encode_header :: proc(out: ^[dynamic]u8, name, value: string) {
	// An exact static match is a single byte, which is worth the lookup.
	for entry, i in STATIC_TABLE {
		if i == 0 {
			continue
		}
		if entry.name == name && entry.value == value {
			write_integer(out, 7, i, 0x80)
			return
		}
	}
	// Otherwise a literal without indexing, reusing a static name index when
	// one exists so only the value goes on the wire.
	name_index := 0
	for entry, i in STATIC_TABLE {
		if i == 0 {
			continue
		}
		if entry.name == name {
			name_index = i
			break
		}
	}
	write_integer(out, 4, name_index, 0x00)
	if name_index == 0 {
		write_string(out, name)
	}
	write_string(out, value)
}

@(private)
write_integer :: proc(out: ^[dynamic]u8, prefix_bits: uint, value: int, flags: u8) {
	mask := int(1 << prefix_bits) - 1
	if value < mask {
		append(out, flags | u8(value))
		return
	}
	append(out, flags | u8(mask))
	v := value - mask
	for v >= 0x80 {
		append(out, u8(v & 0x7f) | 0x80)
		v >>= 7
	}
	append(out, u8(v))
}

@(private)
write_string :: proc(out: ^[dynamic]u8, s: string) {
	// Length with the Huffman bit clear: the string follows as-is.
	write_integer(out, 7, len(s), 0x00)
	append(out, ..transmute([]u8)s)
}
