package filter

import "core:reflect"
import "core:slice"
import "core:strings"
import "elodin:dns"
import "elodin:netx"

/*
`$dnstype`: a rule narrowed to some query types (#406).

urlfilter reads `$dnstype=A|~AAAA` into a permitted and a restricted list, and a
rule matches a type the restricted list does not name and, when the permitted
one names any, one it does (`matchDNSType`). So a rule is either "one of P \ R"
or, permitting none, "anything but R": one `Type_Filter`. Several rules for one
name match what any of them does, and that union is one of the two shapes again
(`type_union`), so a name holds one filter however many rules name it. A set
keeps each distinct filter once (`type_intern`) and a name its id, since lists
narrow names to the same few types.

A filter lists at most MAX_RULE_TYPES types, which bounds what adding a rule
costs: a union only ever shrinks an exclusion, and grows a permitted list to the
bound, past which the rule is skipped - as any rule this engine cannot honour is
skipped rather than widened.
*/
MAX_RULE_TYPES :: 64

Type_Filter :: struct {
	// Sorted, without repeats.
	types:   []u16,
	// The filter matches every type but `types`.
	negated: bool,
}

// What a rule with no `$dnstype` matches. The zero filter matches nothing.
ANY_TYPE :: Type_Filter{nil, true}

// Whether `f` matches every type, as a rule without `$dnstype` does.
type_is_any :: proc(f: Type_Filter) -> bool {
	return f.negated && len(f.types) == 0
}

type_matches :: proc(f: Type_Filter, qtype: dns.Type) -> bool {
	_, found := slice.binary_search(f.types, u16(qtype))
	return found != f.negated
}

/*
`$dnstype`'s value, as urlfilter's `parseDNSTypes` reads it, with its types in
`buf`; false for one it refuses, which skips the rule, and for one that names
every type it permits as excluded too, which matches nothing. A type is a
mnemonic in any case, or RFC 3597 section 5's `TYPEnnn`, which urlfilter refuses.
*/
@(private)
parse_dnstype :: proc(value: string, buf: []u16) -> (f: Type_Filter, ok: bool) {
	if len(buf) < MAX_RULE_TYPES {
		return
	}
	// A type named again takes no room, so only distinct ones count.
	permit, exclude: [MAX_RULE_TYPES]u16
	np, ne := 0, 0
	rest := value
	for {
		bar := strings.index_byte(rest, '|')
		if bar < 0 {
			bar = len(rest)
		}
		item := rest[:bar]
		negated := len(item) > 0 && item[0] == '~'
		if negated {
			item = item[1:]
		}
		t := parse_type_name(item) or_return
		if negated {
			if !slice.contains(exclude[:ne], t) {
				if ne == len(exclude) {
					return
				}
				exclude[ne] = t
				ne += 1
			}
		} else if !slice.contains(permit[:np], t) {
			if np == len(permit) {
				return
			}
			permit[np] = t
			np += 1
		}
		if bar == len(rest) {
			break
		}
		rest = rest[bar + 1:]
	}
	ps, es := permit[:np], exclude[:ne]
	slice.sort(ps)
	slice.sort(es)
	if len(ps) == 0 {
		return {buf[:copy(buf, es)], true}, true
	}
	n := sorted_combine(ps, es, true, false, false, buf)
	return {buf[:n], false}, n > 0
}

@(private)
parse_type_name :: proc(s: string) -> (t: u16, ok: bool) {
	buf: [16]u8
	if len(s) == 0 || len(s) > len(buf) {
		return
	}
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case 'a' ..= 'z':
			c -= 32
		case '-':
			// IANA's `NSAP-PTR` is the enum's `NSAP_PTR`.
			c = '_'
		case '_':
			return
		}
		buf[i] = c
	}
	name := string(buf[:len(s)])
	if len(name) > 4 && name[:4] == "TYPE" {
		n, digits := netx.parse_decimal(name[4:], 0xffff)
		return u16(n), digits && n > 0
	}
	// `None` is spelt so that no upper-cased name finds it; it is type 0, which
	// urlfilter refuses too.
	v, found := reflect.enum_from_name(dns.Type, name)
	return u16(v), found && v != .None
}

/*
What matches either filter, its types in `buf`, which holds 2 * MAX_RULE_TYPES;
false when it lists more than MAX_RULE_TYPES.

Either list: their union. Anything but either list: anything but what both
name. One of P, or anything but R: anything but what R names and P does not.
*/
@(private)
type_union :: proc(a, b: Type_Filter, buf: []u16) -> (out: Type_Filter, ok: bool) {
	n: int
	switch {
	case !a.negated && !b.negated:
		n = sorted_combine(a.types, b.types, true, true, true, buf)
	case a.negated && b.negated:
		n = sorted_combine(a.types, b.types, false, false, true, buf)
	case a.negated:
		n = sorted_combine(a.types, b.types, true, false, false, buf)
	case:
		n = sorted_combine(b.types, a.types, true, false, false, buf)
	}
	return {buf[:n], a.negated || b.negated}, n <= MAX_RULE_TYPES
}

/*
The id of `f` among the set's filters, added if it is new. Id 0 is the filter
that matches nothing, which a name's anchor without a `$dnstype` rule has.

A filter stays once interned, including each step a name's filter takes on
its way to the last: a name named by 64 rules adding a type each holds 64
filters. So a set keeps at most MAX_TYPE_FILTERS, and false past them skips the
rule, which bounds what a list built to make every step distinct can make this
hold, at about 300 bytes each, where lists in use narrow names to a few.
*/
MAX_TYPE_FILTERS :: 4096

@(private)
type_intern :: proc(s: ^Set, f: Type_Filter) -> (id: u32, ok: bool) {
	key_buf: [1 + 2 * MAX_RULE_TYPES]u8
	key_buf[0] = u8(f.negated)
	n := 1 + copy(key_buf[1:], slice.to_bytes(f.types))
	key := string(key_buf[:n])
	if held, found := s.filter_ids[key]; found {
		return held, true
	}
	if len(s.filters) >= MAX_TYPE_FILTERS {
		return
	}
	id = u32(len(s.filters))
	append(&s.filters, Type_Filter{slice.clone(f.types, s.allocator) if len(f.types) > 0 else nil, f.negated})
	s.filter_ids[strings.clone(key, s.allocator)] = id
	return id, true
}

// What a regex rule keeps for `f`: the interned copy, or ANY_TYPE, which needs
// no storage and so leaves `filters` to say whether any `$dnstype` rule is held.
@(private)
type_keep :: proc(s: ^Set, f: Type_Filter) -> (kept: Type_Filter, ok: bool) {
	if type_is_any(f) {
		return ANY_TYPE, true
	}
	id := type_intern(s, f) or_return
	return s.filters[id], true
}

// Walk two sorted lists together, keeping what is only in `x`, only in `y`, or
// in both, as asked; returns how many went into `out`.
@(private)
sorted_combine :: proc(x, y: []u16, x_only, y_only, both: bool, out: []u16) -> (n: int) {
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		v: u16
		keep: bool
		switch {
		case j == len(y) || (i < len(x) && x[i] < y[j]):
			v, keep = x[i], x_only
			i += 1
		case i == len(x) || y[j] < x[i]:
			v, keep = y[j], y_only
			j += 1
		case:
			v, keep = x[i], both
			i += 1
			j += 1
		}
		if keep {
			out[n] = v
			n += 1
		}
	}
	return
}
