package server

import "core:mem"
import "elodin:config"
import "elodin:dns"

/*
The other half of a `rewrites` rule: the PTR for an address it hands out.

An operator who writes `nas.home -> 192.168.1.50` has said everything there is
to say about that address, and the peer set takes them at their word. dnsmasq
synthesises the reverse for every `--host-record`, every `address=` host and
every DHCP lease; AdGuard Home does the same from its rewrites and its leases.
Neither asks for the mapping to be written twice, there being nothing a second
copy could say that the first did not. Without this, `nslookup 192.168.1.50`
against a server that answers `nas.home` with that address gets whatever the
upstream says, which for RFC 1918 space is the blackhole servers' NXDOMAIN - so
an `ssh` banner, a mail server's forward-confirmed check and every log viewer
that resolves addresses report a name that does not exist, and the operator
keeps dnsmasq running beside this one for the reverse zone alone.

Four things it deliberately does not do.

A wildcard rule is skipped. `*.lan. -> 192.168.1.1` says that every name below
`lan.` answers with that address, which leaves no one name to point back at, and
picking a label out of the air would be this server inventing a hostname rather
than repeating one an operator wrote down.

Several names for one address is legal and common - a host with an alias, a
service name beside the machine's own - and only one PTR can be right. The
first matching rule wins, in file order, which is the precedence `find_rewrite`
already gives the forward direction: an operator reading their file top to
bottom sees the same rule claim the name and the address.

Nothing outside private space is synthesised. A rule pointing a name at a public
address must not make this server answer PTR for somebody else's reverse zone,
where a real delegation exists and a real answer with it. The addresses that
qualify are exactly the ones a host on this network can hold: RFC 1918, RFC 3927
IPv4 link-local, RFC 4193 unique-local and RFC 4291 IPv6 link-local. Loopback
and `0.0.0.0` are private in the same sense and are still left out, because a
rule pointing a name at one of those is blackholing it rather than addressing
it - `ads.example.com -> 0.0.0.0` is a common way to write `answer: block`, and
having it turn up as the reverse of `0.0.0.0` would be a made-up answer for the
one address that most certainly has no host behind it.

And the shape has to be a host's, not a zone's. Four decimal labels under
`in-addr.arpa.` or thirty-two nibbles under `ip6.arpa.`, canonically spelled;
`1.168.192.in-addr.arpa.` names a zone cut rather than an address, and there is
nothing for it to point at.

Where this sits is the other half of the argument. It runs from `apply_rewrite`,
which is above everything in `localzones.odin` - so a synthesised name is
answered before the reverse tree can be considered, which is what it has to be,
and it stays inside the same bypass those zones already have: `is_locally_served`
covers every name this can answer, by construction, since the address test above
is that table's private subset. A synthesised PTR under a signed `in-addr.arpa`
with the validator still watching is exactly the shape `localzones.odin` exists
to keep away from the chain of trust, and this cannot produce one.

A trust anchor over the reverse zone does not stand this down, though it stands
the bypass in `localzones.odin` down. The two questions look alike and are not:
there the anchor is the operator asking for an upstream's answer to be checked,
and there is an upstream answer to check. Here the answer is the operator's own
configuration, and `apply_rewrite` above already hands such a rule its name
whatever the anchor says - a rewrite for a name in an anchored zone is answered
unsigned today. Deferring in one direction and not the other would leave the two
halves of one rule behaving differently; a site that signs its own reverse space
should be serving it, not rewriting into it.

What it does change for an existing installation is narrow and worth naming: a
site whose upstream really does serve its own reverse zone now gets this
server's answer for the addresses named in `rewrites`, rather than the router's.
The two disagree only where the operator wrote one of them down, and the one
they wrote down is this one.
*/
@(private)
apply_reverse_rewrite :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> (
	response: []u8,
	matched: bool,
) {
	if len(s.cfg.rewrites) == 0 {
		return nil, false
	}
	domain, ttl, found := reverse_rewrite_target(s.cfg.rewrites, q.name)
	if !found {
		return nil, false
	}

	answers := make([dynamic]dns.Record, 0, 1, allocator)
	if q.type == .PTR || q.type == .ANY {
		append(
			&answers,
			dns.Record {
				name = q.name,
				type = .PTR,
				class = .IN,
				ttl = ttl,
				data = dns.Rdata_Name{name = domain},
			},
		)
	}

	resp := dns.make_response(query, .No_Error, allocator)
	resp.answer = answers[:]
	if len(answers) == 0 {
		/*
		NODATA for every other type, which is `apply_rewrite`'s own answer for a
		type its rule has no record of and is right here for the same reason: the
		name exists - this server has just said so by answering its PTR - and the
		types it has no record of are questions whose true answer is "none",
		not "no such name".

		The SOA goes at the RFC 6303 zone rather than at the queried name's
		parent, `1.168.192.in-addr.arpa.` being a zone nobody was ever
		authoritative for. `locally_served_zone` always finds one for a name that
		got this far, and an empty apex leaves `synth_soa` to fall back to the
		parent rather than making the caller handle a case that cannot happen.
		*/
		zone, _ := locally_served_zone(q.name)
		resp.authority = synth_soa(q.name, ttl, allocator, zone)
	}

	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		return nil, false
	}
	return out, true
}

/*
The name a `rewrites` rule gives the address `name` is the reverse of, if any.

Both halves have to hold: the name has to parse as a host's reverse name in
space this network holds, and some non-wildcard rule has to answer with exactly
that address.
*/
@(private)
reverse_rewrite_target :: proc(
	rules: []config.Rewrite,
	name: string,
) -> (
	domain: string,
	ttl: u32,
	found: bool,
) {
	if v4, ok := parse_reverse_v4(name); ok {
		if !address_is_local_v4(v4) {
			return "", 0, false
		}
		return rewrite_naming_address(rules, config.Rewrite_Answer{kind = .A, v4 = v4})
	}
	if v6, ok := parse_reverse_v6(name); ok {
		if !address_is_local_v6(v6) {
			return "", 0, false
		}
		return rewrite_naming_address(rules, config.Rewrite_Answer{kind = .AAAA, v6 = v6})
	}
	return "", 0, false
}

// The first rule that answers with `want`, wildcards skipped. See above for why
// each of those is what it is.
@(private)
rewrite_naming_address :: proc(
	rules: []config.Rewrite,
	want: config.Rewrite_Answer,
) -> (
	domain: string,
	ttl: u32,
	found: bool,
) {
	for r in rules {
		if r.wildcard {
			continue
		}
		for a in r.answers {
			if a.kind != want.kind {
				continue
			}
			same := a.v4 == want.v4 if want.kind == .A else a.v6 == want.v6
			if same {
				return r.domain, r.ttl, true
			}
		}
	}
	return "", 0, false
}

/*
The addresses a host on this network can hold, and the only ones a rewrite may
be reversed into. RFC 1918, RFC 3927 link-local, RFC 4193 unique-local and RFC
4291 IPv6 link-local - the private subset of `LOCALLY_SERVED_ZONES`, minus
loopback and `0.0.0.0`, for the reason in the file comment.
*/
@(private)
address_is_local_v4 :: proc(a: [4]u8) -> bool {
	switch {
	case a[0] == 10:
		return true
	case a[0] == 172 && a[1] >= 16 && a[1] <= 31:
		return true
	case a[0] == 192 && a[1] == 168:
		return true
	case a[0] == 169 && a[1] == 254:
		return true
	}
	return false
}

@(private)
address_is_local_v6 :: proc(a: [16]u8) -> bool {
	// fd00::/8, the half of RFC 4193's fc00::/7 that is defined and deployed,
	// and fe80::/10.
	return a[0] == 0xfd || (a[0] == 0xfe && a[1] & 0xc0 == 0x80)
}

@(private)
V4_REVERSE_SUFFIX :: "in-addr.arpa."

@(private)
V6_REVERSE_SUFFIX :: "ip6.arpa."

/*
"50.1.168.192.in-addr.arpa." -> 192.168.1.50.

Exactly four decimal labels, least significant first (RFC 1035 section 3.5),
and each spelled the one way the reverse tree spells it: no leading zeros, so a
single address cannot be reached by two names here. Anything else - a zone cut
with three labels, a fifth label below the host, a label that is not a number -
is not a name this synthesises for.
*/
@(private)
parse_reverse_v4 :: proc(name: string) -> (addr: [4]u8, ok: bool) {
	if !name_below(name, V4_REVERSE_SUFFIX) {
		return {}, false
	}
	rest := name[:len(name) - len(V4_REVERSE_SUFFIX) - 1]

	seen := 0
	start := 0
	for i := 0; i <= len(rest); i += 1 {
		if i != len(rest) && rest[i] != '.' {
			continue
		}
		if seen == 4 {
			return {}, false
		}
		octet, valid := decimal_octet(rest[start:i])
		if !valid {
			return {}, false
		}
		addr[3 - seen] = octet
		seen += 1
		start = i + 1
	}
	if seen != 4 {
		return {}, false
	}
	return addr, true
}

/*
"1.0.…0.0.d.f.ip6.arpa." -> fd00::1.

Thirty-two single-hex-digit labels, least significant nibble first (RFC 3596
section 2.5). The length check does most of the work: a name of any other shape
is a zone cut or a typo, and either way names no host.
*/
@(private)
parse_reverse_v6 :: proc(name: string) -> (addr: [16]u8, ok: bool) {
	if !name_below(name, V6_REVERSE_SUFFIX) {
		return {}, false
	}
	rest := name[:len(name) - len(V6_REVERSE_SUFFIX) - 1]
	// Thirty-two digits with a dot between each pair.
	if len(rest) != 32 * 2 - 1 {
		return {}, false
	}

	for i in 0 ..< 32 {
		if i > 0 && rest[i * 2 - 1] != '.' {
			return {}, false
		}
		nibble, valid := hex_nibble(rest[i * 2])
		if !valid {
			return {}, false
		}
		// Label `i` is the low half of byte `15 - i/2` when `i` is even and the
		// high half when it is odd, the labels running from the last nibble of
		// the address back to the first.
		b := 15 - i / 2
		if i % 2 == 0 {
			addr[b] |= nibble
		} else {
			addr[b] |= nibble << 4
		}
	}
	return addr, true
}

@(private)
decimal_octet :: proc(label: string) -> (v: u8, ok: bool) {
	if len(label) == 0 || len(label) > 3 {
		return 0, false
	}
	// "050" is not how the reverse tree spells 50, and taking it would give one
	// address several names to be looked up by.
	if len(label) > 1 && label[0] == '0' {
		return 0, false
	}
	n := 0
	for i in 0 ..< len(label) {
		c := label[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n * 10 + int(c - '0')
	}
	if n > 255 {
		return 0, false
	}
	return u8(n), true
}

// Case-folded, DNS names being compared without regard to it and a nibble label
// being no exception (RFC 4343).
@(private)
hex_nibble :: proc(c: u8) -> (v: u8, ok: bool) {
	switch c {
	case '0' ..= '9':
		return c - '0', true
	case 'a' ..= 'f':
		return c - 'a' + 10, true
	case 'A' ..= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
