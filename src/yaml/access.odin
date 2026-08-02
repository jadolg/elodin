package yaml

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

// Dotted path lookup: at(root, "upstream.cache.max_entries").
at :: proc(n: ^Node, path: string) -> ^Node {
	cur := n
	rest := path
	for len(rest) > 0 && cur != nil {
		key := rest
		if idx := strings.index_byte(rest, '.'); idx >= 0 {
			key = rest[:idx]
			rest = rest[idx + 1:]
		} else {
			rest = ""
		}
		cur = get(cur, key)
	}
	return cur
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

as_string :: proc(n: ^Node, default: string = "") -> (string, bool) {
	if n == nil || n.kind != .Scalar {
		return default, false
	}
	if is_null(n) {
		return default, false
	}
	return n.scalar, true
}

as_bool :: proc(n: ^Node) -> (bool, bool) {
	s, ok := as_string(n)
	if !ok {
		return false, false
	}
	switch strings.to_lower(s, context.temp_allocator) {
	case "true", "yes", "on", "y":
		return true, true
	case "false", "no", "off", "n":
		return false, true
	}
	return false, false
}

as_int :: proc(n: ^Node) -> (i64, bool) {
	s, ok := as_string(n)
	if !ok {
		return 0, false
	}
	s = strings.trim_space(s)
	neg := false
	if strings.has_prefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.has_prefix(s, "+") {
		s = s[1:]
	}
	base := 10
	switch {
	case strings.has_prefix(s, "0x"), strings.has_prefix(s, "0X"):
		base, s = 16, s[2:]
	case strings.has_prefix(s, "0o"), strings.has_prefix(s, "0O"):
		base, s = 8, s[2:]
	case strings.has_prefix(s, "0b"), strings.has_prefix(s, "0B"):
		base, s = 2, s[2:]
	}
	// YAML allows digit grouping with underscores.
	if strings.contains(s, "_") {
		s, _ = strings.remove_all(s, "_", context.temp_allocator)
	}
	v, vok := strconv.parse_u64_of_base(s, base)
	if !vok {
		return 0, false
	}
	return -i64(v) if neg else i64(v), true
}

as_f64 :: proc(n: ^Node) -> (f64, bool) {
	s, ok := as_string(n)
	if !ok {
		return 0, false
	}
	return strconv.parse_f64(strings.trim_space(s))
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
		total += time.Duration(value * scale)
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
