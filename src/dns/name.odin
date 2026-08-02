package dns

import "core:strings"

// Domain names are carried around in escaped presentation form, always fully
// qualified: "www.example.com." and "." for the root. Any byte that is not a
// printable non-special ASCII character is escaped as \DDD, so a name string
// round-trips to the exact wire bytes it came from.

// Worst case: 255 wire bytes, each rendered as a 4-character escape.
MAX_NAME_PRESENTATION :: MAX_NAME_WIRE * 4

@(private)
needs_escape :: proc "contextless" (c: u8) -> bool {
	return c <= 0x20 || c >= 0x7f || c == '.' || c == '\\'
}

@(private)
append_escaped_byte :: proc(buf: []u8, n: int, c: u8) -> int {
	n := n
	if needs_escape(c) {
		buf[n] = '\\'
		buf[n + 1] = '0' + (c / 100)
		buf[n + 2] = '0' + ((c / 10) % 10)
		buf[n + 3] = '0' + (c % 10)
		return n + 4
	}
	buf[n] = c
	return n + 1
}

/*
Decode a domain name starting at `offset`.

Returns the presentation form, plus the offset of the first byte after the name
*in the section being parsed* (following a compression pointer does not advance
the caller's cursor past the pointer itself).
*/
decode_name :: proc(msg: []u8, offset: int, allocator := context.allocator) -> (name: string, next: int, err: Decode_Error) {
	buf: [MAX_NAME_PRESENTATION]u8
	blen := 0

	pos := offset
	next = -1
	wire_len := 0
	jumps := 0

	for {
		if pos < 0 || pos >= len(msg) {
			return "", 0, .Short_Buffer
		}
		n := msg[pos]

		switch n & 0xc0 {
		case 0x00:
			if n == 0 {
				pos += 1
				if next < 0 {
					next = pos
				}
				if blen == 0 {
					buf[0] = '.'
					blen = 1
				}
				return strings.clone(string(buf[:blen]), allocator), next, .None
			}
			label_len := int(n)
			if pos + 1 + label_len > len(msg) {
				return "", 0, .Short_Buffer
			}
			wire_len += 1 + label_len
			if wire_len > MAX_NAME_WIRE {
				return "", 0, .Name_Too_Long
			}
			for c in msg[pos + 1:pos + 1 + label_len] {
				blen = append_escaped_byte(buf[:], blen, c)
			}
			buf[blen] = '.'
			blen += 1
			pos += 1 + label_len

		case 0xc0:
			if pos + 1 >= len(msg) {
				return "", 0, .Short_Buffer
			}
			target := (int(n & 0x3f) << 8) | int(msg[pos + 1])
			if next < 0 {
				next = pos + 2
			}
			// A pointer must always point backwards; that alone bounds the
			// walk, but keep an explicit counter as a second line of defence.
			if target >= pos {
				return "", 0, .Bad_Pointer
			}
			jumps += 1
			if jumps > MAX_NAME_WIRE / 2 {
				return "", 0, .Loop_Detected
			}
			pos = target

		case:
			// 0x40 and 0x80 are reserved / obsolete (EDNS0 extended labels).
			return "", 0, .Bad_Label
		}
	}
}

/*
Encode a presentation-form name into wire bytes, writing into `out`.

`out` must be at least MAX_NAME_WIRE bytes. Also fills `label_offsets` with the
index into `out` of every label boundary (including the terminating root), which
the message writer uses to find compression targets.
*/
encode_name :: proc(name: string, out: []u8, label_offsets: ^[dynamic]int = nil) -> (n: int, err: Encode_Error) {
	if label_offsets != nil {
		clear(label_offsets)
	}
	if name == "" || name == "." {
		if len(out) < 1 {
			return 0, .Buffer_Too_Small
		}
		if label_offsets != nil {
			append(label_offsets, 0)
		}
		out[0] = 0
		return 1, .None
	}

	i := 0
	n = 0
	for i < len(name) {
		if label_offsets != nil {
			append(label_offsets, n)
		}
		if n >= len(out) {
			return 0, .Buffer_Too_Small
		}
		len_pos := n
		n += 1
		label_len := 0

		for i < len(name) {
			c := name[i]
			if c == '.' {
				i += 1
				break
			}
			if c == '\\' {
				i += 1
				if i >= len(name) {
					return 0, .Bad_Escape
				}
				d := name[i]
				if d >= '0' && d <= '9' {
					if i + 2 >= len(name) {
						return 0, .Bad_Escape
					}
					v := 0
					for k in 0 ..< 3 {
						dd := name[i + k]
						if dd < '0' || dd > '9' {
							return 0, .Bad_Escape
						}
						v = v * 10 + int(dd - '0')
					}
					if v > 255 {
						return 0, .Bad_Escape
					}
					c = u8(v)
					i += 3
				} else {
					c = d
					i += 1
				}
			} else {
				i += 1
			}

			if label_len >= MAX_LABEL_LEN {
				return 0, .Label_Too_Long
			}
			if n >= len(out) {
				return 0, .Buffer_Too_Small
			}
			out[n] = c
			n += 1
			label_len += 1
		}

		if label_len == 0 {
			// An empty label is only valid as the terminating root, which the
			// loop below writes explicitly.
			return 0, .Bad_Name
		}
		out[len_pos] = u8(label_len)
		if n + 1 > MAX_NAME_WIRE {
			return 0, .Name_Too_Long
		}
	}

	if label_offsets != nil {
		append(label_offsets, n)
	}
	if n >= len(out) {
		return 0, .Buffer_Too_Small
	}
	out[n] = 0
	n += 1
	if n > MAX_NAME_WIRE {
		return 0, .Name_Too_Long
	}
	return n, .None
}

// Lowercase ASCII letters only, per DNS case-insensitivity rules.
name_fold :: proc(name: string, allocator := context.allocator) -> string {
	buf := make([]u8, len(name), allocator)
	for i in 0 ..< len(name) {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		buf[i] = c
	}
	return string(buf)
}

name_equal_fold :: proc(a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// "www.example.com." -> "example.com."; "." -> "."
name_parent :: proc(name: string) -> string {
	if name == "" || name == "." {
		return "."
	}
	i := 0
	for i < len(name) {
		if name[i] == '\\' {
			i += 2
			continue
		}
		if name[i] == '.' {
			rest := name[i + 1:]
			return rest if rest != "" else "."
		}
		i += 1
	}
	return "."
}

// Drops the trailing root dot for display / config matching. "." becomes "".
name_trim_root :: proc(name: string) -> string {
	if len(name) > 0 && name[len(name) - 1] == '.' {
		return name[:len(name) - 1]
	}
	return name
}

// Accepts "example.com" or "example.com." and returns the canonical form.
name_canonical :: proc(name: string, allocator := context.allocator) -> string {
	if name == "" || name == "." {
		return strings.clone(".", allocator)
	}
	if name[len(name) - 1] == '.' {
		return name_fold(name, allocator)
	}
	lowered := name_fold(name, allocator)
	defer delete(lowered, allocator)
	return strings.concatenate({lowered, "."}, allocator)
}
