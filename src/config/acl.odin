package config

import "core:fmt"
import "core:net"
import "core:strconv"
import "core:strings"

/*
Which sources may ask.

A recursive resolver that answers every address on the internet is an open
resolver, and that is a property of who may ask rather than of how much any one
victim is sent. Response rate limiting bounds the second and does nothing about
the first: it caps what a reflection attack delivers, while the server carries on
taking part in one. `server.allow_from` is the other half - a list of networks a
query is accepted from at all, checked before the message is parsed and before
it is queued, so a source outside it costs a prefix compare and nothing else.

Defaulting to the local networks is where BIND lands with `allow-recursion`,
which is `localnets` plus `localhost` when nothing says otherwise. Unbound is
stricter still: `access-control` starts at `0.0.0.0/0 refuse` with only
`127.0.0.0/8` allowed, so a LAN client has to be named before it is served.
(BIND's `allow-query` is a different setting and does default to `any`; it is
recursion, not the query itself, that it holds back.) This list sits between the
two, and for the reason both of them have one: an installation that has not been
configured yet should serve the machine and the network it is on, not the
internet. An empty list is how an operator asks for a public resolver, which is
a thing to write down on purpose rather than to inherit.

The parsing lives here rather than beside the listeners that enforce it so that
`--check` and startup agree by construction - the same reasoning as
`parse_cookie_secret`. Two parsers written to the same rule are two parsers that
can drift, and the shape of that bug is a configuration `--check` passes and the
resolver then refuses every client on.
*/

/*
A network, held as the masked network bytes and a length.

The text is parsed once at load; matching a source is then a compare of at most
sixteen bytes with no allocation, which is what lets the check sit in the read
loop. IPv4 occupies the first four bytes and IPv6 all sixteen, and the two never
match each other: an address is one family or the other.
*/
Prefix :: struct {
	addr: [16]u8,
	bits: u8,
	v6:   bool,
}

/*
What `server.allow_from` is when the file does not say.

Loopback, the RFC 1918 ranges, IPv4 and IPv6 link-local, and IPv6 unique local
addresses - the networks a resolver is on rather than the ones it is reachable
from. A machine resolving for itself, a household behind a NAT and a datacentre
private network are all served by this unchanged; a public resolver is not, and
has to say so.

Written masked and by hand rather than parsed at startup: these are the bytes a
security default comes down to, and a table that can be read straight through is
worth more here than one assembled from strings.
*/
DEFAULT_ALLOW_FROM := []Prefix {
	{addr = {0 = 127}, bits = 8}, // 127.0.0.0/8      loopback
	{addr = {0 = 10}, bits = 8}, // 10.0.0.0/8       private (RFC 1918)
	{addr = {0 = 172, 1 = 16}, bits = 12}, // 172.16.0.0/12   private (RFC 1918)
	{addr = {0 = 192, 1 = 168}, bits = 16}, // 192.168.0.0/16  private (RFC 1918)
	{addr = {0 = 169, 1 = 254}, bits = 16}, // 169.254.0.0/16  link-local (RFC 3927)
	{addr = {15 = 1}, bits = 128, v6 = true}, // ::1/128          loopback
	{addr = {0 = 0xfc}, bits = 7, v6 = true}, // fc00::/7         unique local (RFC 4193)
	{addr = {0 = 0xfe, 1 = 0x80}, bits = 10, v6 = true}, // fe80::/10        link-local (RFC 4291)
}

/*
The addresses no name on the public internet resolves to.

`DEFAULT_ALLOW_FROM` above is the same set of bytes asked a different question -
"which sources may query this server" - and the two are deliberately not one
variable. That one is a default an operator replaces wholesale, and a site that
writes `allow_from: [203.0.113.0/24]` has not thereby declared 203.0.113.0/24
private; this one is a property of the address space and is not configurable at
all. Sharing the list would make each of those edits silently change the other
feature, which is the kind of coupling that is only ever found by the bug it
causes. What *is* shared is the matching - `Prefix`, the masking and
`prefix_list_contains` - since two implementations of a prefix compare are two
that can disagree.

Two entries are here that are not in the allow list, for the same reason the
allow list leaves them out: nothing queries from them.

  - `0.0.0.0/8` is RFC 1122's "this network" and unroutable in its entirety.
    Its first address is also a working bypass rather than merely an odd
    answer: browsers on Linux and macOS reach services bound to 127.0.0.1 by
    connecting to 0.0.0.0, which is what the "0.0.0.0 Day" disclosure was
    about. Leaving it out would open the most interesting target in the set.
  - `::/128` is the unspecified address, and is the same bypass in the other
    family.

Carrier-grade NAT (`100.64.0.0/10`, RFC 6598) is left out, matching the allow
list, but for the opposite reason: it is a shared address space rather than a
private one, and a resolver behind an ISP that uses it would be refusing answers
about hosts it can legitimately reach. Unbound lists the documentation ranges
(192.0.2.0/24 and friends) here too; they are left out because an answer
carrying one is a broken zone rather than a machine an attacker gains anything
by reaching.

The IPv6 forms that carry an IPv4 address inside them are not entries here, and
only one of them is handled below. `address_in` undoes `::ffff:a.b.c.d`, because
that one reaches this check from the client side as well. `64:ff9b::a.b.c.d`
(RFC 6052) and `::a.b.c.d` (RFC 4291, deprecated) reach a private IPv4 host too,
but only ever as something an answer said, so they are unwrapped by
`rebind_unwrap` in `src/server/rebind.odin` rather than here - a client that
arrives from one is a question about the ACL, and that question has not been
asked. Nothing is silently missing from the table on their account; what a table
of prefixes cannot express is an address that has to be rewritten before it is
matched.
*/
PRIVATE_NETWORKS := []Prefix {
	{addr = {0 = 127}, bits = 8}, // 127.0.0.0/8      loopback
	{addr = {}, bits = 8}, // 0.0.0.0/8        "this network" (RFC 1122)
	{addr = {0 = 10}, bits = 8}, // 10.0.0.0/8       private (RFC 1918)
	{addr = {0 = 172, 1 = 16}, bits = 12}, // 172.16.0.0/12   private (RFC 1918)
	{addr = {0 = 192, 1 = 168}, bits = 16}, // 192.168.0.0/16  private (RFC 1918)
	{addr = {0 = 169, 1 = 254}, bits = 16}, // 169.254.0.0/16  link-local (RFC 3927)
	{addr = {15 = 1}, bits = 128, v6 = true}, // ::1/128          loopback
	{addr = {}, bits = 128, v6 = true}, // ::/128           unspecified
	{addr = {0 = 0xfc}, bits = 7, v6 = true}, // fc00::/7         unique local (RFC 4193)
	{addr = {0 = 0xfe, 1 = 0x80}, bits = 10, v6 = true}, // fe80::/10        link-local (RFC 4291)
}

/*
The loopback subset of `PRIVATE_NETWORKS`, which is exempted on its own.

dnsmasq's `--rebind-localhost-ok` draws the line here and nowhere else: a name
answered with 127.0.0.1 reaches a service on the machine that asked, which is
the one private address a client can also reach without this resolver's help.
`0.0.0.0/8` and `::` are not in it - they are not loopback, whatever a stack
happens to do with a connection to them.
*/
LOOPBACK_NETWORKS := []Prefix {
	{addr = {0 = 127}, bits = 8}, // 127.0.0.0/8
	{addr = {15 = 1}, bits = 128, v6 = true}, // ::1/128
}

/*
Whether an address that came out of an answer is one of `prefixes`.

Takes the bytes rather than a `net.Address` because the caller has them: an A
record is four bytes and an AAAA record sixteen, and going through
`net.IP6_Address` to get back to the same sixteen would be a conversion in each
direction for nothing.

The v4-mapped form is undone first, on both families' behalf. An AAAA record
holding `::ffff:192.168.1.1` is 192.168.1.1 to every stack that connects to it,
so a check that read it as a v6 address outside `fc00::/7` would be a way to
write a private address that this does not see.
*/
address_in :: proc(prefixes: []Prefix, addr: [16]u8, v6: bool) -> bool {
	bytes, family := addr, v6
	if v6 {
		if v4, mapped := unmap_bytes(addr); mapped {
			bytes, family = v4, false
		}
	}
	return prefix_list_contains(prefixes, bytes, family)
}

@(private)
prefix_list_contains :: proc(prefixes: []Prefix, addr: [16]u8, v6: bool) -> bool {
	for p in prefixes {
		if p.v6 == v6 && prefix_contains(p, addr) {
			return true
		}
	}
	return false
}

/*
Read one entry of `server.allow_from`.

Accepts `10.0.0.0/8`, `::1/128` and a bare address, which is taken as the single
host it names. Host bits below the prefix length are masked off rather than
refused, which is what BIND and Unbound do with the same input, so `127.0.0.1/8`
and `127.0.0.0/8` are the same network.
*/
parse_prefix :: proc(text: string) -> (p: Prefix, ok: bool) {
	trimmed := strings.trim_space(text)
	if trimmed == "" {
		return {}, false
	}

	addr_text := trimmed
	bits_text := ""
	// Tracked apart from the text, so a trailing slash with nothing after it is
	// a length that was meant and left out rather than a length never written.
	has_length := false
	if slash := strings.index_byte(trimmed, '/'); slash >= 0 {
		addr_text = trimmed[:slash]
		bits_text = trimmed[slash + 1:]
		has_length = true
	}

	address := net.parse_address(addr_text)
	if address == nil {
		return {}, false
	}
	/*
	A zone index makes an address a thing only one host can use, and
	`parse_address` takes `fe80::1%eth0` without one. An allow list is compared
	against what arrived on the wire, which carries no zone, so an entry that
	depends on one would never match and is a mistake worth reporting.
	*/
	if strings.contains(addr_text, "%") {
		return {}, false
	}

	switch a in address {
	case net.IP4_Address:
		p.addr[0], p.addr[1], p.addr[2], p.addr[3] = a[0], a[1], a[2], a[3]
		p.bits = 32
	case net.IP6_Address:
		for i in 0 ..< 8 {
			p.addr[i * 2] = u8(u16(a[i]) >> 8)
			p.addr[i * 2 + 1] = u8(u16(a[i]))
		}
		p.v6 = true
		p.bits = 128
	}

	if has_length {
		// `parse_int` stops at the first byte it cannot use, so "8junk" parses as
		// happily as "8"; how much of the text it consumed is what rejects it.
		used := 0
		n, nok := strconv.parse_int(bits_text, 10, &used)
		if !nok || used != len(bits_text) || n < 0 || n > int(p.bits) {
			return {}, false
		}
		p.bits = u8(n)
	}

	unmap_prefix(&p)
	mask_prefix(&p)
	return p, true
}

/*
Rewrite a v4-mapped entry as the IPv4 network it names.

`address_bytes` undoes the `::ffff:a.b.c.d` mapping on the way in, so a source
that arrives mapped is compared as IPv4. An entry written in the mapped form and
left as IPv6 would therefore be one the matcher can never match - accepted by
`--check`, printed at startup, and dead. Undoing the mapping on both sides is
what keeps that from being a way to write a rule that silently does nothing.

Only from `/96` down, where the mapped prefix is wholly inside the length: a
shorter one covers addresses outside `::ffff:0:0/96` as well and is a network in
its own right, not a way of writing an IPv4 one.
*/
@(private)
unmap_prefix :: proc(p: ^Prefix) {
	if !p.v6 || p.bits < 96 {
		return
	}
	v4, mapped := unmap_bytes(p.addr)
	if !mapped {
		return
	}
	p.addr = v4
	p.bits -= 96
	p.v6 = false
}

// Clear everything below the prefix length, so a match never has to look at
// bits the operator did not name.
@(private)
mask_prefix :: proc(p: ^Prefix) {
	width := 16 if p.v6 else 4
	for i in 0 ..< width {
		bit := i * 8
		switch {
		case bit + 8 <= int(p.bits):
		// Wholly inside the prefix; nothing to clear.
		case bit >= int(p.bits):
			p.addr[i] = 0
		case:
			keep := uint(int(p.bits) - bit)
			p.addr[i] &= u8(0xff << (8 - keep))
		}
	}
	// Bytes past the family's width are not part of the address either way.
	if !p.v6 {
		for i in 4 ..< 16 {
			p.addr[i] = 0
		}
	}
}

/*
Whether `address` is one this server answers.

An empty list means no restriction, which is how a deliberately public resolver
is configured. Anything else is a whitelist: a source that matches no entry is
not served.
*/
source_allowed :: proc(prefixes: []Prefix, address: net.Address) -> bool {
	if len(prefixes) == 0 {
		return true
	}
	// Neither family is not an address this server can answer, and against a
	// whitelist the safe reading of "no idea who that is" is no.
	if address == nil {
		return false
	}
	bytes, v6 := address_bytes(address)
	return prefix_list_contains(prefixes, bytes, v6)
}

/*
An address as the bytes a prefix is compared against.

An IPv4 client reaching a socket bound to `::` arrives as `::ffff:a.b.c.d`, and
an operator who wrote `192.168.0.0/16` means that client too - so the mapping is
undone here rather than left for every entry in the list to have to anticipate.
*/
@(private)
address_bytes :: proc(address: net.Address) -> (out: [16]u8, v6: bool) {
	switch a in address {
	case net.IP4_Address:
		out[0], out[1], out[2], out[3] = a[0], a[1], a[2], a[3]
		return out, false
	case net.IP6_Address:
		for i in 0 ..< 8 {
			out[i * 2] = u8(u16(a[i]) >> 8)
			out[i * 2 + 1] = u8(u16(a[i]))
		}
		if v4, mapped := unmap_bytes(out); mapped {
			return v4, false
		}
		return out, true
	}
	// Unreachable: `source_allowed` turns an address of neither family away
	// before asking for its bytes.
	return out, false
}

// The IPv4 address inside `::ffff:a.b.c.d`, when that is what the sixteen bytes
// hold. Split out from `address_bytes` so that the answer-side check in
// `address_in` undoes the mapping by the same rule the source-side check does.
@(private)
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

@(private)
prefix_contains :: proc(p: Prefix, addr: [16]u8) -> bool {
	full := int(p.bits) / 8
	for i in 0 ..< full {
		if p.addr[i] != addr[i] {
			return false
		}
	}
	if rest := uint(int(p.bits) % 8); rest != 0 {
		mask := u8(0xff << (8 - rest))
		if p.addr[full] != addr[full] & mask {
			return false
		}
	}
	return true
}

// Render a prefix the way it was written, for the startup line and `--check`.
format_prefix :: proc(p: Prefix, allocator := context.allocator) -> string {
	if p.v6 {
		a: net.IP6_Address
		for i in 0 ..< 8 {
			a[i] = u16be(u16(p.addr[i * 2]) << 8 | u16(p.addr[i * 2 + 1]))
		}
		text := net.address_to_string(net.Address(a), allocator)
		// `aprintf` copies it, so the intermediate goes back here rather than
		// resting on every caller happening to pass an allocator that is reset
		// wholesale.
		defer delete(text, allocator)
		return fmt.aprintf("%s/%d", text, p.bits, allocator = allocator)
	}
	return fmt.aprintf("%d.%d.%d.%d/%d", p.addr[0], p.addr[1], p.addr[2], p.addr[3], p.bits, allocator = allocator)
}
