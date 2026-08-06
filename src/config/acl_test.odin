package config

import "core:mem"
import "core:net"
import "core:testing"

/*
Who may ask, stated as tests.

The property under test is one a resolver is judged on from outside: a source
that is not on the list is not served, and a source that is, is. The parsing
tests are here for the same reason `parse_prefix` is in this package - a list
that does not mean what it says is an ACL that is not one.
*/

@(private = "file")
v4 :: proc(a, b, c, d: u8) -> net.Address {
	return net.IP4_Address{a, b, c, d}
}

@(private = "file")
v6 :: proc(parts: ..u16) -> net.Address {
	addr: net.IP6_Address
	for p, i in parts {
		addr[i] = u16be(p)
	}
	return addr
}

@(private = "file")
prefix :: proc(t: ^testing.T, text: string) -> Prefix {
	p, ok := parse_prefix(text)
	testing.expectf(t, ok, "%q did not parse", text)
	return p
}

@(test)
test_parse_prefix_reads_both_families :: proc(t: ^testing.T) {
	p := prefix(t, "192.168.0.0/16")
	testing.expect_value(t, p.bits, 16)
	testing.expect(t, !p.v6, "an IPv4 network came back marked v6")
	testing.expect_value(t, p.addr[0], 192)
	testing.expect_value(t, p.addr[1], 168)

	q := prefix(t, "2001:db8::/32")
	testing.expect_value(t, q.bits, 32)
	testing.expect(t, q.v6, "an IPv6 network came back marked v4")
	testing.expect_value(t, q.addr[0], 0x20)
	testing.expect_value(t, q.addr[1], 0x01)
}

// A bare address is the single host it names, which is the form an operator
// reaches for when allowing one machine.
@(test)
test_parse_prefix_without_a_length_is_one_host :: proc(t: ^testing.T) {
	p := prefix(t, "10.1.2.3")
	testing.expect_value(t, p.bits, 32)
	testing.expect(t, source_allowed({p}, v4(10, 1, 2, 3)), "the host it names is not allowed")
	testing.expect(t, !source_allowed({p}, v4(10, 1, 2, 4)), "the neighbour is allowed too")

	q := prefix(t, "::1")
	testing.expect_value(t, q.bits, 128)
	testing.expect(t, source_allowed({q}, v6(0, 0, 0, 0, 0, 0, 0, 1)), "::1 is not allowed by ::1")
}

/*
Host bits below the length are cleared rather than refused.

`127.0.0.1/8` and `127.0.0.0/8` are the same network, and both are things people
write. Refusing the first would be a configuration error over a difference that
does not exist; what must not happen is the extra bits surviving into the
comparison, where they would narrow the network to nothing.
*/
@(test)
test_parse_prefix_masks_host_bits :: proc(t: ^testing.T) {
	p := prefix(t, "127.0.0.1/8")
	testing.expect_value(t, p.addr[3], 0)
	testing.expect(t, source_allowed({p}, v4(127, 4, 5, 6)), "the network was narrowed to the host written")

	q := prefix(t, "10.1.2.3/8")
	testing.expect_value(t, q.addr[1], 0)
	testing.expect(t, source_allowed({q}, v4(10, 255, 255, 255)), "10.0.0.0/8 does not contain 10.255.255.255")

	// A length that is not a whole number of bytes is where masking is easiest
	// to get wrong: 172.16.0.0/12 covers 172.16 through 172.31 and no further.
	r := prefix(t, "172.16.0.0/12")
	testing.expect(t, source_allowed({r}, v4(172, 16, 0, 1)), "172.16.0.1 is outside 172.16.0.0/12")
	testing.expect(t, source_allowed({r}, v4(172, 31, 255, 254)), "172.31.255.254 is outside 172.16.0.0/12")
	testing.expect(t, !source_allowed({r}, v4(172, 32, 0, 1)), "172.32.0.1 is inside 172.16.0.0/12")
	testing.expect(t, !source_allowed({r}, v4(172, 15, 255, 255)), "172.15.255.255 is inside 172.16.0.0/12")
}

@(test)
test_parse_prefix_refuses_what_is_not_a_network :: proc(t: ^testing.T) {
	cases := []string {
		"",
		"   ",
		"not-an-address",
		// Longer than the family has bits, which would otherwise read as a
		// network narrower than one host.
		"192.168.0.0/33",
		"::1/129",
		"192.168.0.0/-1",
		// `parse_int` would take the leading digits of both and leave the rest.
		"192.168.0.0/16bits",
		"192.168.0.0/1 6",
		"192.168.0.0/",
		// A scope makes an address usable on one host and one interface; there
		// is no zone on the wire to compare it against.
		"fe80::1%eth0/64",
	}
	for c in cases {
		_, ok := parse_prefix(c)
		testing.expectf(t, !ok, "%q was accepted as a network", c)
	}
}

// A zero length is every address of that family. Legal, occasionally meant, and
// only correct if nothing below the length is compared.
@(test)
test_parse_prefix_zero_length_is_every_address :: proc(t: ^testing.T) {
	p := prefix(t, "0.0.0.0/0")
	testing.expect(t, source_allowed({p}, v4(198, 51, 100, 7)), "0.0.0.0/0 did not contain a public address")
	testing.expect(t, !source_allowed({p}, v6(0x2001, 0xdb8)), "an IPv4 network matched an IPv6 source")
}

/*
An empty list is no restriction.

This is how a deliberately public resolver is configured, so it has to mean
"everybody" and not "nobody": the second would be a shipped default that turns
into an outage the moment somebody writes `allow_from: []` meaning the first.
*/
@(test)
test_empty_list_allows_everything :: proc(t: ^testing.T) {
	testing.expect(t, source_allowed(nil, v4(198, 51, 100, 7)), "an empty list refused a source")
	testing.expect(t, source_allowed({}, v6(0x2001, 0xdb8)), "an empty list refused an IPv6 source")
}

// The two families never match each other, whatever the bytes look like.
@(test)
test_families_do_not_match_each_other :: proc(t: ^testing.T) {
	v4_only := []Prefix{prefix(t, "10.0.0.0/8")}
	testing.expect(t, !source_allowed(v4_only, v6(0x0a00)), "an IPv6 source matched an IPv4 network")

	v6_only := []Prefix{prefix(t, "2001:db8::/32")}
	testing.expect(t, !source_allowed(v6_only, v4(32, 1, 13, 184)), "an IPv4 source matched an IPv6 network")
}

/*
An IPv4 client on a socket bound to `::` arrives as `::ffff:a.b.c.d`.

An operator who wrote `192.168.0.0/16` means that client, and an ACL that let it
through only when the listener happened to be IPv4-only would be one that stops
working when somebody changes the bind address.
*/
@(test)
test_v4_mapped_sources_match_v4_networks :: proc(t: ^testing.T) {
	list := []Prefix{prefix(t, "192.168.0.0/16")}
	mapped := v6(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0105) // ::ffff:192.168.1.5
	testing.expect(t, source_allowed(list, mapped), "a v4-mapped source did not match the v4 network")

	outside := v6(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808) // ::ffff:8.8.8.8
	testing.expect(t, !source_allowed(list, outside), "a v4-mapped source outside the network was allowed")
}

/*
What the shipped default covers, and what it does not.

This is the security property the default exists for, so it is written out
address by address rather than left to the reader of the table.
*/
@(test)
test_default_allow_from_is_local_networks_only :: proc(t: ^testing.T) {
	inside := []net.Address {
		v4(127, 0, 0, 1),
		v4(10, 0, 0, 1),
		v4(172, 16, 5, 5),
		v4(172, 31, 255, 254),
		v4(192, 168, 1, 1),
		v4(169, 254, 1, 1),
		v6(0, 0, 0, 0, 0, 0, 0, 1), // ::1
		v6(0xfd00, 0, 0, 0, 0, 0, 0, 1), // unique local
		v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), // link-local
	}
	for a in inside {
		testing.expectf(t, source_allowed(DEFAULT_ALLOW_FROM, a), "%v is not covered by the default list", a)
	}

	outside := []net.Address {
		v4(8, 8, 8, 8),
		v4(198, 51, 100, 7),
		// Adjacent to the private ranges without being in them, which is where
		// an off-by-one in the masking would show.
		v4(172, 15, 0, 1),
		v4(172, 32, 0, 1),
		v4(192, 167, 1, 1),
		v4(11, 0, 0, 1),
		// Carrier-grade NAT: private in the sense that matters to an ISP, and
		// deliberately not on the list, since a resolver behind one is serving
		// somebody else's customers.
		v4(100, 64, 0, 1),
		v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), // global unicast
		v6(0xfb00, 0, 0, 0, 0, 0, 0, 1), // just below fc00::/7
	}
	for a in outside {
		testing.expectf(t, !source_allowed(DEFAULT_ALLOW_FROM, a), "%v is covered by the default list", a)
	}
}

/*
An entry written in the v4-mapped form is the IPv4 network it names.

`source_allowed` compares a mapped source as IPv4, so an entry left as IPv6
could never match one - a rule `--check` accepts, startup prints, and the
matcher is guaranteed to ignore. The mapping is undone on both sides or on
neither.
*/
@(test)
test_v4_mapped_entries_become_v4_networks :: proc(t: ^testing.T) {
	host := prefix(t, "::ffff:192.168.1.5")
	testing.expect(t, !host.v6, "a mapped host stayed an IPv6 network")
	testing.expect_value(t, host.bits, 32)
	testing.expect(t, source_allowed({host}, v4(192, 168, 1, 5)), "the host it names is not allowed")
	testing.expect(
		t,
		source_allowed({host}, v6(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0105)),
		"the same host arriving mapped is not allowed",
	)

	// /112 of the mapped range is /16 of the IPv4 one.
	net16 := prefix(t, "::ffff:192.168.0.0/112")
	testing.expect(t, !net16.v6, "a mapped network stayed an IPv6 network")
	testing.expect_value(t, net16.bits, 16)
	testing.expect(t, source_allowed({net16}, v4(192, 168, 77, 3)), "192.168.77.3 is outside ::ffff:192.168.0.0/112")
	testing.expect(t, !source_allowed({net16}, v4(192, 169, 0, 1)), "192.169.0.1 is inside ::ffff:192.168.0.0/112")

	// The whole mapped range is every IPv4 address, and still no IPv6 one.
	all := prefix(t, "::ffff:0:0/96")
	testing.expect_value(t, all.bits, 0)
	testing.expect(t, source_allowed({all}, v4(8, 8, 8, 8)), "::ffff:0:0/96 does not cover an IPv4 address")
	testing.expect(t, !source_allowed({all}, v6(0x2001, 0xdb8)), "::ffff:0:0/96 covered a real IPv6 address")

	// Shorter than /96 reaches outside the mapped range, so it is an IPv6
	// network in its own right and stays one.
	wide := prefix(t, "::/64")
	testing.expect(t, wide.v6, "a network reaching past the mapped range was rewritten as IPv4")
}

// The line an operator reads at startup has to say the network they wrote.
@(test)
test_format_prefix_round_trips :: proc(t: ^testing.T) {
	cases := []string{"192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8", "0.0.0.0/0"}
	for c in cases {
		testing.expect_value(t, format_prefix(prefix(t, c), context.temp_allocator), c)
	}
	// The v6 text is whatever the standard shortening makes of it, so only the
	// length is asserted literally.
	testing.expect_value(t, format_prefix(prefix(t, "fe80::/10"), context.temp_allocator), "fe80::/10")
}

/*
`format_prefix` returns one string and keeps nothing.

The IPv6 path builds the address text before the text with the length on it, and
`aprintf` copies the first into the second. Both callers happen to pass an
allocator that is thrown away wholesale, which is exactly the condition under
which a leak in a procedure taking an arbitrary allocator goes unnoticed - so it
is measured here rather than left to them.
*/
@(test)
test_format_prefix_keeps_nothing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	cases := []string{"fe80::/10", "2001:db8::/32", "::1/128", "10.0.0.0/8"}
	for text in cases {
		p, ok := parse_prefix(text)
		testing.expectf(t, ok, "%q did not parse", text)
		out := format_prefix(p, allocator)
		testing.expect_value(t, out, text)
		delete(out, allocator)
		testing.expectf(
			t,
			len(track.allocation_map) == 0,
			"%q left %d allocation(s) behind",
			text,
			len(track.allocation_map),
		)
	}
}

// An address of neither family is not somebody this server knows how to answer,
// and against a whitelist the safe reading of that is no.
@(test)
test_no_address_is_not_allowed :: proc(t: ^testing.T) {
	list := []Prefix{prefix(t, "0.0.0.0/0"), prefix(t, "::/0")}
	testing.expect(t, !source_allowed(list, nil), "an address of neither family was allowed")
	// Except where there is no list at all, which is not a decision about this
	// source but the absence of one.
	testing.expect(t, source_allowed(nil, nil), "an empty list should still mean no restriction")
}
