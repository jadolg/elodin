package yaml

import "core:math"
import "core:strconv"
import "core:strings"
import "core:time"

// Look a key up in a mapping. Returns nil for a missing key or a non-mapping.
get :: proc(n: ^Node, key: string) -> ^Node {
	if n == nil || n.kind != .Mapping {
		return nil
	}
	return n.fields[key] or_else nil
}

items :: proc(n: ^Node) -> []^Node {
	if n == nil || n.kind != .Sequence {
		return nil
	}
	return n.seq[:]
}

keys :: proc(n: ^Node) -> []string {
	if n == nil || n.kind != .Mapping {
		return nil
	}
	return n.keys[:]
}

is_null :: proc(n: ^Node) -> bool {
	if n == nil {
		return true
	}
	if n.kind != .Scalar || n.quoted {
		return false
	}
	return n.scalar == "" || n.scalar == "~" || n.scalar == "null" || n.scalar == "Null" || n.scalar == "NULL"
}

as_string :: proc(n: ^Node) -> (string, bool) {
	if n == nil || n.kind != .Scalar {
		return "", false
	}
	if is_null(n) {
		return "", false
	}
	return n.scalar, true
}

/*
A boolean as YAML 1.2's core schema has it (1.2.2 section 10.3.2): `true`,
`True`, `TRUE`, `false`, `False` or `FALSE`, plain. YAML 1.1's `yes`, `on` and
`y` are strings in 1.2, and so is anything quoted.
*/
as_bool :: proc(n: ^Node) -> (bool, bool) {
	s, ok := as_string(n)
	if !ok || n.quoted {
		return false, false
	}
	return core_bool(s)
}

/*
Whether `s` is one of YAML 1.1's booleans that 1.2 reads as a string, for a
refusal to say so: 1.1's `bool` type less 1.2's six spellings.
*/
yaml_1_1_bool :: proc(s: string) -> bool {
	switch s {
	case "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF":
		return true
	}
	return false
}

/*
Whether `s` is one of YAML 1.1's integers that 1.2 reads as a string, for a
refusal to say so: 1.1's `int` type written with `_` separators or as `0b`
binary, or with a sign before `0x`. Two more 1.1 forms are not caught: its
`0`-led octal, which 1.2 reads as the decimal it looks like (`0755` is 755),
and its sexagesimal `1:30`, a string in 1.2 that is refused with no hint.
*/
yaml_1_1_int :: proc(s: string) -> bool {
	t := s
	signed := strings.has_prefix(t, "+") || strings.has_prefix(t, "-")
	if signed {
		t = t[1:]
	}
	only :: proc(s, set: string) -> bool {
		return len(s) > 0 && strings.trim_left(s, set) == ""
	}
	switch {
	case strings.has_prefix(t, "0b"):
		return only(t[2:], "01_")
	case strings.has_prefix(t, "0x"):
		return only(t[2:], "0123456789abcdefABCDEF_") && (signed || strings.contains_rune(t, '_'))
	}
	return only(t, "0123456789_") && t[0] != '_' && strings.contains_rune(t, '_')
}

/*
Whether `s` reads as an integer under the core schema, as `as_int` would read
it from a plain scalar.
*/
core_int :: proc(s: string) -> (i64, bool) {
	s := s
	neg := false
	base := 10
	switch {
	case strings.has_prefix(s, "0x"):
		base, s = 16, s[2:]
	case strings.has_prefix(s, "0o"):
		base, s = 8, s[2:]
	case strings.has_prefix(s, "-"):
		neg, s = true, s[1:]
	case strings.has_prefix(s, "+"):
		s = s[1:]
	}
	// Guarded before each step, as `as_bytes` is: strconv wraps silently, which
	// reads "18446744073709551617" as 1 and lets it past any range a caller
	// checks.
	if s == "" {
		return 0, false
	}
	limit := u64(max(i64)) + (1 if neg else 0)
	v: u64
	for c in transmute([]u8)s {
		digit, is_digit := hex_digit(c)
		d := u64(digit)
		if !is_digit || d >= u64(base) || v > (limit - d) / u64(base) {
			return 0, false
		}
		v = v * u64(base) + d
	}
	return -i64(v) if neg else i64(v), true
}

// Whether `s` is one of the core schema's six booleans, and which.
core_bool :: proc(s: string) -> (value: bool, ok: bool) {
	switch s {
	case "true", "True", "TRUE":
		return true, true
	case "false", "False", "FALSE":
		return false, true
	}
	return false, false
}

/*
An integer as YAML 1.2's core schema has it (1.2.2 section 10.3.2), plain:
`[-+]? [0-9]+`, `0o [0-7]+` or `0x [0-9a-fA-F]+`, and no wider than an i64.
YAML 1.1's `_` separators, `0b` and a sign before a base prefix are strings in
1.2, and so is anything quoted.
*/
as_int :: proc(n: ^Node) -> (i64, bool) {
	s, ok := as_string(n)
	if !ok || n.quoted {
		return 0, false
	}
	return core_int(s)
}

/*
Byte sizes accept a plain count or a suffixed form: "64MiB", "512KB", "2GiB".

The binary suffixes are the powers of 1024 and the decimal ones the powers of
1000, as they are written. A bare number is bytes, and "MB" and "MiB" are far
enough apart by the time they matter that guessing which was meant is not this
parser's business.

Unlike `as_duration` there is no compound form: "1MiB512KiB" is a typo, not a
size. Overflow is refused rather than wrapped - what a wrapped size configures
is a bound nobody chose.
*/
as_bytes :: proc(n: ^Node) -> (i64, bool) {
	s, ok := as_string(n)
	if !ok {
		return 0, false
	}
	s = strings.trim_space(s)

	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits += 1
	}
	if digits == 0 {
		return 0, false
	}

	unit := i64(1)
	switch strings.trim_space(s[digits:]) {
	case "", "B", "b":
	case "K", "KB", "kb":
		unit = 1000
	case "KiB", "kib", "Ki":
		unit = 1024
	case "M", "MB", "mb":
		unit = 1000 * 1000
	case "MiB", "mib", "Mi":
		unit = 1024 * 1024
	case "G", "GB", "gb":
		unit = 1000 * 1000 * 1000
	case "GiB", "gib", "Gi":
		unit = 1024 * 1024 * 1024
	case:
		return 0, false
	}

	// Guarded before each step rather than after: a sum that has already wrapped
	// is no longer a number anything can be compared against.
	total := i64(0)
	for i in 0 ..< digits {
		d := i64(s[i] - '0')
		if total > (max(i64) - d) / 10 {
			return 0, false
		}
		total = total * 10 + d
		if total > max(i64) / unit {
			return 0, false
		}
	}
	return total * unit, true
}

/*
Durations accept a plain number of seconds or a suffixed form: "500ms", "30s",
"5m", "12h", "7d". Compound values like "1h30m" are also accepted.
*/
as_duration :: proc(n: ^Node) -> (time.Duration, bool) {
	s, ok := as_string(n)
	if !ok {
		return 0, false
	}
	s = strings.trim_space(s)
	if s == "" {
		return 0, false
	}

	total := time.Duration(0)
	i := 0
	saw_any := false
	for i < len(s) {
		start := i
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			i += 1
		}
		if i == start {
			return 0, false
		}
		value, vok := strconv.parse_f64(s[start:i])
		if !vok {
			return 0, false
		}
		unit_start := i
		for i < len(s) && !(s[i] >= '0' && s[i] <= '9') {
			i += 1
		}
		unit := s[unit_start:i]

		scale: f64
		switch unit {
		case "", "s", "sec", "secs":
			scale = f64(time.Second)
		case "ms":
			scale = f64(time.Millisecond)
		case "us":
			scale = f64(time.Microsecond)
		case "m", "min", "mins":
			scale = f64(time.Minute)
		case "h", "hr", "hrs":
			scale = f64(time.Hour)
		case "d", "day", "days":
			scale = f64(time.Hour) * 24
		case "w":
			scale = f64(time.Hour) * 24 * 7
		case:
			return 0, false
		}
		// Rounded to the nanosecond, not cut: "2.3h" multiplies out a hair under
		// 8280s, and a figure that must come to whole seconds, a TTL, would be
		// refused for it.
		part := math.round(value * scale)
		// Saturating, so a figure too large to hold reads as the largest there is
		// and fails a caller's ceiling, rather than wrapping round into a small
		// one that passes it.
		if part >= f64(max(time.Duration)) || time.Duration(part) > max(time.Duration) - total {
			total = max(time.Duration)
		} else {
			total += time.Duration(part)
		}
		saw_any = true
	}
	return total, saw_any
}

// Convenience for `key: value` or `key: [a, b]`, both yielding a string slice.
as_string_list :: proc(n: ^Node, allocator := context.allocator) -> ([]string, bool) {
	if n == nil {
		return nil, false
	}
	if n.kind == .Scalar {
		if is_null(n) {
			return nil, true
		}
		out := make([]string, 1, allocator)
		out[0] = n.scalar
		return out, true
	}
	if n.kind != .Sequence {
		return nil, false
	}
	out := make([]string, len(n.seq), allocator)
	for item, i in n.seq {
		s, ok := as_string(item)
		if !ok {
			delete(out, allocator)
			return nil, false
		}
		out[i] = s
	}
	return out, true
}
