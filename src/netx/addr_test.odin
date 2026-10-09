package netx

import "core:net"
import "core:testing"

/*
A bracket that does not close a `[literal]`: `core:net` reads `]:53` as the host
`]` on port 53, and `[dns.example:80` as `[dns.example` on port 80. A blocklist
line or a redirect's Location can carry one.
*/
@(test)
test_a_stray_bracket_is_refused :: proc(t: ^testing.T) {
	// `a]:]:80` to `[]:]:80` split, by `core:net`'s rule, into the host `]:`.
	for s in ([]string {
			"]:",
			"]:53",
			"]:1.2.3.4",
			"]:\tads.example",
			"a]:]:80",
			"x]:]:80",
			"[]:]:80",
			"[dns.example:80",
			"[1.1.1.1:53",
			"dns]example:53",
			"a[b",
			"::1]",
		}) {
		testing.expect(t, parse_address(s) == nil, s)
		_, ok4 := parse_ip4_address(s)
		testing.expect(t, !ok4, s)
		_, ok6 := parse_ip6_address(s)
		testing.expect(t, !ok6, s)
		_, okep := parse_endpoint(s)
		testing.expect(t, !okep, s)
		_, _, oksp := split_port(s)
		testing.expect(t, !oksp, s)
		_, _, rerr := resolve(s)
		testing.expect(t, rerr != nil, s)
	}
}

@(test)
test_a_port_is_digits :: proc(t: ^testing.T) {
	// `strconv.parse_int` reads all of these: a sign, a separator, and digits
	// that wrap past 2^64 to 53 or past 2^63 to a negative port.
	for s in ([]string {
			"1.1.1.1:-1",
			"1.1.1.1:+53",
			"1.1.1.1:5_3",
			"[::1]:-1",
			"1.1.1.1:18446744073709551669",
			"1.1.1.1:9223372036854775861",
			"[::1]:18446744073709551669",
		}) {
		_, _, ok := split_port(s)
		testing.expect(t, !ok, s)
		_, okep := parse_endpoint(s)
		testing.expect(t, !okep, s)
	}
	// A port inside the brackets too: the host split out of them is parsed here.
	_, okin := parse_endpoint("[1.1.1.1:-1]:53")
	testing.expect(t, !okin, "a signed port inside the brackets")
}

@(test)
test_well_formed_input_parses_as_core_net_parses_it :: proc(t: ^testing.T) {
	host, port, ok := split_port("[::1]:53")
	testing.expect(t, ok && host == "::1" && port == 53, "a bracketed literal and a port")
	host, port, ok = split_port("1.2.3.4:853")
	testing.expect(t, ok && host == "1.2.3.4" && port == 853, "an IPv4 address and a port")
	host, port, ok = split_port("dns.example")
	testing.expect(t, ok && host == "dns.example" && port == 0, "a name with no port")
	host, port, ok = split_port("::1")
	testing.expect(t, ok && host == "::1" && port == 0, "a bare IPv6 literal")
	host, port, ok = split_port("[::1]")
	testing.expect(t, ok && host == "::1" && port == 0, "a bracketed literal with no port")
	_, _, ok = split_port("[[::1]]")
	testing.expect(t, !ok, "a bracket inside the brackets")
	ep0, ep0ok := parse_endpoint("[2620:fe::fe]")
	testing.expect(t, ep0ok && ep0.port == 0, "a bracketed endpoint with no port")
	testing.expect(t, parse_address("::1") != nil, "an IPv6 address")
	testing.expect(t, parse_address("1.2.3.4") != nil, "an IPv4 address")
	ep, epok := parse_endpoint("[::1]:53")
	testing.expect(t, epok && ep.port == 53, "an endpoint")
}

// An address alone: `core:net` reads `1.2.3.4:53` as 1.2.3.4 and drops the port.
@(test)
test_an_address_carries_no_port :: proc(t: ^testing.T) {
	for s in ([]string{"1.2.3.4:53", "[::1]:53", "[::1]"}) {
		testing.expect(t, parse_address(s) == nil, s)
		_, ok4 := parse_ip4_address(s)
		testing.expect(t, !ok4, s)
		_, ok6 := parse_ip6_address(s)
		testing.expect(t, !ok6, s)
	}
	testing.expect(t, is_bare("dns.example") && is_bare("::1") && !is_bare("dns.example:853"), "a name alone is bare")
	testing.expect(t, has_port("1.2.3.4:0") && has_port("[::1]:53") && !has_port("[::1]") && !has_port("::1"), "a port is one written")
}

// RFC 3986 section 3.2.2: brackets hold an IPv6 address, not IPv4 or a name.
@(test)
test_brackets_hold_only_ipv6 :: proc(t: ^testing.T) {
	for s in ([]string{"[1.1.1.1]", "[1.1.1.1]:53", "[dns.example]", "[dns.example]:53", "[]", "[]:53"}) {
		_, _, ok := split_port(s)
		testing.expect(t, !ok, s)
		_, okep := parse_endpoint(s)
		testing.expect(t, !okep, s)
	}
}

// `inet_aton`'s short forms: `192.168.1` is 192.168.0.1 to `core:net`.
@(test)
test_an_ipv4_address_has_four_parts :: proc(t: ^testing.T) {
	for s in ([]string{"192.168.1", "10.20.30", "10.2.3.", "127.0.1", "::ffff:10.20.30.", "::ffff:10.20.30"}) {
		testing.expect(t, parse_address(s) == nil, s)
		_, ok4 := parse_ip4_address(s)
		testing.expect(t, !ok4, s)
		_, okep := parse_endpoint(s)
		testing.expect(t, !okep, s)
	}
	_, ok := parse_ip4_address("192.168.1.1")
	testing.expect(t, ok && parse_address("192.168.1.1") != nil, "a dotted quad")
	for s in ([]string{"[::ffff:10.20.30.]", "[::ffff:10.20.30.]:53"}) {
		_, _, split_ok := split_port(s)
		testing.expect(t, !split_ok, s)
	}
	_, ok = parse_ip6_address("::ffff:10.20.30.40")
	testing.expect(t, ok, "an IPv6 address with a whole IPv4 part")
	// A host alone, so neither a port nor brackets reach `core:net`'s lookup.
	for s in ([]string{"[::1]", "1.1.1.1:53", "dns.example::53"}) {
		_, _, rerr := resolve(s)
		testing.expect(t, rerr != nil, s)
	}
}

// RFC 3696 section 2: no top-level domain is all digits, so a name ending in one
// is an address mistyped, not a host.
@(test)
test_a_numeric_name_is_no_host :: proc(t: ^testing.T) {
	for s in ([]string{"10.20.30", "10.20.30.", "1.2.3.4.5", "123", ""}) {
		testing.expect(t, !is_host(s), s)
	}
	for s in ([]string{"1.2.3.4", "dns.example", "1dns.example", "dns.example.", "::1"}) {
		testing.expect(t, is_host(s), s)
	}
}

// Exactly `::ffff:0:0/96` is undone; the compat and translated forms that also
// carry four familiar octets stay the IPv6 addresses they are.
@(test)
test_unmap_takes_only_the_mapped_prefix :: proc(t: ^testing.T) {
	Case :: struct {
		text: string,
		want: string,
	}
	cases := []Case {
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"::10.0.0.1", "::10.0.0.1"},
		{"::ffff:0:10.0.0.1", "::ffff:0:10.0.0.1"},
		{"::fffe:10.0.0.1", "::fffe:10.0.0.1"},
		{"1::ffff:10.0.0.1", "1::ffff:10.0.0.1"},
		{"::1", "::1"},
	}
	for c in cases {
		got := unmap(net.parse_address(c.text))
		testing.expectf(t, got == net.parse_address(c.want), "%s unmapped to %v, want %s", c.text, got, c.want)
	}
	testing.expect(t, addresses_equal(net.parse_address("::ffff:10.0.0.1"), net.IP4_Address{10, 0, 0, 1}), "a mapped address is not its IPv4 one")
	testing.expect(t, !addresses_equal(net.parse_address("::10.0.0.1"), net.IP4_Address{10, 0, 0, 1}), "a compat address is its IPv4 one")
	testing.expect(t, !addresses_equal(nil, nil), "no address equals no address")
}
