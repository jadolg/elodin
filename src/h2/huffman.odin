package h2

import "core:strings"
import "core:sync"

/*
HPACK Huffman decoding.

The code is canonical, so decoding needs only, per code length, the first code
of that length and the index of its first symbol. Those are derived once from
the tables and then a decode is a bit walk: accumulate bits, and at each length
check whether the accumulated value falls inside that length's range.

Bit-at-a-time is slower than a multi-level lookup table, but header strings in a
DoH request are a few dozen bytes and the difference does not show up next to
the TLS and DNS work on either side of it.
*/

@(private)
Huffman_Index :: struct {
	// For each code length 1..30: the numeric value of the first code of that
	// length, the number of codes, and where its symbols start in `symbols`.
	first_code:   [31]u32,
	count:        [31]int,
	first_symbol: [31]int,
	symbols:      [257]u16,
	built:        bool,
}

@(private)
huffman_index: Huffman_Index

@(private)
huffman_once: sync.Once

@(private)
build_huffman_index :: proc() {
	idx := &huffman_index

	for sym in 0 ..< 257 {
		idx.count[HUFFMAN_LEN[sym]] += 1
	}

	// Canonical assignment: codes of each length follow on from the previous
	// length, shifted left by one.
	code: u32 = 0
	next: int = 0
	for length in 1 ..= 30 {
		code = (code + u32(idx.count[length - 1])) << 1
		idx.first_code[length] = code
		idx.first_symbol[length] = next
		next += idx.count[length]
	}

	// Fill the symbol lists in code order.
	offset: [31]int
	for length in 1 ..= 30 {
		offset[length] = idx.first_symbol[length]
	}
	for sym in 0 ..< 257 {
		length := int(HUFFMAN_LEN[sym])
		idx.symbols[offset[length]] = u16(sym)
		offset[length] += 1
	}
	idx.built = true
}

/*
Decode a Huffman-coded string.

Trailing padding must be all-ones and shorter than 8 bits (RFC 7541 section
5.2); anything else, and any appearance of EOS, is a decoding error.
*/
huffman_decode :: proc(data: []u8, allocator := context.allocator) -> (s: string, err: Hpack_Error) {
	sync.once_do(&huffman_once, build_huffman_index)
	idx := &huffman_index

	b := strings.builder_make(allocator)
	// A Huffman string never expands beyond 8/5 of its encoded length, since
	// the shortest code is 5 bits.
	strings.builder_grow(&b, len(data) * 8 / 5 + 1)

	code: u32 = 0
	length := 0

	for byte_value in data {
		for bit := 7; bit >= 0; bit -= 1 {
			code = (code << 1) | u32((byte_value >> uint(bit)) & 1)
			length += 1
			if length > 30 {
				strings.builder_destroy(&b)
				return "", .Bad_Huffman
			}
			if idx.count[length] == 0 {
				continue
			}
			first := idx.first_code[length]
			if code < first || code >= first + u32(idx.count[length]) {
				continue
			}
			sym := idx.symbols[idx.first_symbol[length] + int(code - first)]
			if int(sym) == HUFFMAN_EOS {
				strings.builder_destroy(&b)
				return "", .Bad_Huffman
			}
			strings.write_byte(&b, u8(sym))
			code = 0
			length = 0
		}
	}

	// Whatever is left must be a prefix of the EOS code: all ones, under a byte.
	if length >= 8 {
		strings.builder_destroy(&b)
		return "", .Bad_Huffman
	}
	if length > 0 {
		padding := (u32(1) << uint(length)) - 1
		if code != padding {
			strings.builder_destroy(&b)
			return "", .Bad_Huffman
		}
	}
	return strings.to_string(b), .None
}
