package netx

import "core:net"
import "core:strings"

/*
`core:net`'s address parsers, held to what an address and a port are.

`core:net` reads a port with `strconv.parse_int`, so a sign, `_` separators and
digits that wrap past 2^64 all pass; it drops a port from an address it parses,
so `1.2.3.4:5353` is 1.2.3.4; and it takes a name or an IPv4 address in brackets,
`[1.1.1.1]:53`, and a host with a stray bracket, `]:53` as `]` on port 53 and
`[dns.example:80` as `[dns.example` on port 80.

Each parser here runs its input through this package's `split_port` first, which
refuses all of those, so whatever `core:net` then reads is an address, or an
address and a port, in the forms RFC 3986 section 3.2.2 allows.

Use these, not `core:net`'s, for every address string: `mise run check` refuses
a call to `core:net`'s outside this package, the tests, itest and fuzz.
*/

/*
A port is digits only, at most 65535: `strconv.parse_int` also reads a sign and
`_` separators, and wraps on overflow, so `core:net` reads `1.1.1.1:-1` as port
-1 and `1.1.1.1:18446744073709551669` as 53.

A `[literal]` is an IPv6 address, RFC 3986 section 3.2.2, with or without a
port; `core:net` takes a name or an IPv4 address in brackets too, and hands one
with no port back whole, so `[2606:4700::1111]` would be a name to look up.
*/
split_port :: proc(s: string) -> (addr_or_host: string, port: int, ok: bool) {
	if strings.has_prefix(s, "[") && strings.has_suffix(s, "]") {
		if inner := s[1:len(s) - 1]; is_ip6_literal(inner) {
			return inner, 0, true
		}
		return s, 0, false
	}
	addr_or_host, port, ok = net.split_port(s)
	// Any other bracket is stray: `core:net` hands `[dns.example:80` back as the
	// host `[dns.example`, and `dns]example:53` as `dns]example`.
	if strings.contains_any(s, "[]") && !(strings.has_prefix(s, "[") && is_ip6_literal(addr_or_host)) {
		return s, 0, false
	}
	if ok && addr_or_host != s {
		n := 0
		for c in s[strings.last_index_byte(s, ':') + 1:] {
			n = n * 10 + int(c - '0')
			if c < '0' || c > '9' || n > 65535 {
				return s, 0, false
			}
		}
	}
	return
}

/*
An address alone. `core:net`'s parsers take an optional port and drop it, so
`address: 1.1.1.1:5353` read through them is 1.1.1.1 on the default port, with
nothing said; here it is not an address, and the caller says why. A port is
read by `split_port` and `parse_endpoint`.
*/
@(private)
is_bare :: proc(s: string) -> bool {
	host, _, ok := split_port(s)
	return ok && host == s
}

// An IPv6 address, with no bracket inside it to stand for another one.
@(private)
is_ip6_literal :: proc(s: string) -> bool {
	if strings.contains_any(s, "[]") {
		return false
	}
	_, ok := net.parse_ip6_address(s)
	return ok && is_dotted_quad(s)
}

// Whether `s` splits into a host and a port. `[::1]` is not bare but has none:
// `split_port` takes it out of its brackets with no port.
has_port :: proc(s: string) -> bool {
	host, _, ok := split_port(s)
	return ok && host != s && !strings.has_suffix(s, "]")
}

/*
A host alone: an IP address, or a name, which holds no colon or bracket.
`is_bare` passes any string of two or more colons as an IPv6 literal it has not
parsed, so `dns.example::853` and `[::1]x` would stand as names to look up and
certificate names to check. Nor is a name numeric: that is an address mistyped.
Nor empty: a field that may be left out is checked only when it is not.
*/
is_host :: proc(s: string) -> bool {
	return parse_address(s) != nil || (s != "" && !strings.contains_any(s, ":[]") && !is_numeric_name(s))
}

/*
Whether `s` ends in an all-digit label, which RFC 3696 section 2 says no top-level
domain is: `10.20.30` is an IPv4 address short a part, not a name to look up.
*/
is_numeric_name :: proc(s: string) -> bool {
	name := strings.trim_suffix(s, ".")
	last := name[strings.last_index_byte(name, '.') + 1:]
	if last == "" {
		return false
	}
	for c in last {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

/*
An IPv4 address is four decimal parts, alone or as an IPv6 address's last 32
bits. `core:net` also takes the short `inet_aton` forms, so `192.168.1` is
192.168.0.1, `10.2.3.` is 10.2.0.3 and `::ffff:10.2.3.` is ::ffff:10.2.0.3: an
allow list entry `192.168.1/24` would be another network. An IPv6 address with
no IPv4 part passes.
*/
@(private)
is_dotted_quad :: proc(s: string) -> bool {
	v4 := s[strings.last_index_byte(s, ':') + 1:]
	if v4 != s && !strings.contains_rune(v4, '.') {
		return true
	}
	return strings.count(v4, ".") == 3 && !strings.has_suffix(v4, ".")
}

parse_address :: proc(s: string) -> net.Address {
	if !is_bare(s) || !is_dotted_quad(s) {
		return nil
	}
	return net.parse_address(s)
}

parse_ip4_address :: proc(s: string) -> (addr: net.IP4_Address, ok: bool) {
	if !is_bare(s) || !is_dotted_quad(s) {
		return
	}
	return net.parse_ip4_address(s)
}

parse_ip6_address :: proc(s: string) -> (addr: net.IP6_Address, ok: bool) {
	if !is_bare(s) || !is_dotted_quad(s) {
		return
	}
	return net.parse_ip6_address(s)
}

// The host it splits out is parsed here too, so a port inside the brackets,
// `[1.1.1.1:-1]:53`, is held to the same rule as the one after them.
parse_endpoint :: proc(s: string) -> (ep: net.Endpoint, ok: bool) {
	host, port := split_port(s) or_return
	if addr := parse_address(host); addr != nil {
		return {address = addr, port = port}, true
	}
	return
}

// A host alone, as `is_host` holds it: `core:net`'s `resolve` splits a port off
// by its own rule, and looks `[::1]` up as a name.
resolve :: proc(s: string) -> (ep4, ep6: net.Endpoint, err: net.Network_Error) {
	if !is_host(s) {
		return {}, {}, net.Parse_Endpoint_Error.Bad_Hostname
	}
	return net.resolve(s)
}

/*
An address as sixteen bytes, IPv4 in the first four, and whether it is IPv6.
As written: a v4-mapped address stays IPv6 here, `unmap_bytes` undoes it.
*/
address_bytes :: proc(address: net.Address) -> (out: [16]u8, v6: bool) {
	switch a in address {
	case net.IP4_Address:
		out[0], out[1], out[2], out[3] = a[0], a[1], a[2], a[3]
	case net.IP6_Address:
		for i in 0 ..< 8 {
			out[i * 2] = u8(u16(a[i]) >> 8)
			out[i * 2 + 1] = u8(u16(a[i]))
		}
		v6 = true
	}
	return
}

/*
The IPv4 address inside `::ffff:a.b.c.d` (RFC 4291 section 2.5.5.2), when that
is what the sixteen bytes hold.

Exactly the mapped prefix: ten zero bytes, then `ff ff`. The deprecated compat
form `::a.b.c.d` and the translated form `::ffff:0:a.b.c.d` are IPv6 addresses
that happen to carry four familiar octets, and no stack sources a datagram from
them; reading them as IPv4 would judge a source by an address the ACL compares
as IPv6, which is the way round that gives a v6 sender the choice. Every check
that undoes the mapping - the ACL, the rate limiter, loopback, the answer-side
rebinding check - comes through here, so all of them agree on it.
*/
unmap_bytes :: proc(addr: [16]u8) -> (v4: [16]u8, mapped: bool) {
	for i in 0 ..< 10 {
		if addr[i] != 0 {
			return {}, false
		}
	}
	if addr[10] != 0xff || addr[11] != 0xff {
		return {}, false
	}
	v4[0], v4[1], v4[2], v4[3] = addr[12], addr[13], addr[14], addr[15]
	return v4, true
}

// `unmap_bytes` for a `net.Address`: the IPv4 address a mapped one carries, and
// anything else as it is.
unmap :: proc(a: net.Address) -> net.Address {
	bytes, v6 := address_bytes(a)
	if v4, mapped := unmap_bytes(bytes); v6 && mapped {
		return net.IP4_Address{v4[0], v4[1], v4[2], v4[3]}
	}
	return a
}

// Mapped or not is not a difference between two addresses: `::ffff:10.0.0.1` is
// 10.0.0.1 to every stack, so a peer answering from one form of the address
// asked is answering from that address.
addresses_equal :: proc(a, b: net.Address) -> bool {
	switch x in unmap(a) {
	case net.IP4_Address:
		y, ok := unmap(b).(net.IP4_Address)
		return ok && x == y
	case net.IP6_Address:
		y, ok := unmap(b).(net.IP6_Address)
		return ok && x == y
	}
	return false
}
