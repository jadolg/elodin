package server

import "elodin:dns"

/*
The reverse-DNS zones that name private, link-local and loopback address space.

These are the zones RFC 6303 ("Locally Served DNS Zones") lists: the reverse
trees for the RFC 1918 private ranges, RFC 3927 IPv4 link-local, RFC 4193 IPv6
unique-local, RFC 4291 IPv6 link-local, and loopback. They exist only inside a
network, so no authoritative server on the public Internet answers for them and
none ever signs them.

A validating forwarder must not hold them to the public chain of trust. The
answer for such a name comes from whatever resolves the site's own reverse
space - a router, a local authoritative server - and arrives unsigned. Walking
the public hierarchy to decide whether that is forgery or merely unsigned
reaches `168.192.in-addr.arpa` (and its siblings), which has no DS a parent
signed and, from a local resolver, none of the AS112 delegation's NSEC proof
that no DS exists. The walk cannot finish, so the verdict is Bogus and the
client is handed SERVFAIL for a PTR that should simply have come back unvalidated
- a LAN reverse lookup that breaks the moment DNSSEC is turned on.

Unbound ships these as built-in `local-zone`s and BIND enables them through
`empty-zones-enable`, both for the same reason. Here they turn validation off
for names inside them, which lets the unsigned local answer through as insecure
rather than refusing it. The 172.16/12 block is sixteen /16 reverse zones - one
per second octet, 16 through 31 - listed out so the set is plainly what it
claims to be.

This is the private/link-local/loopback subset of RFC 6303, which is what
breaks a LAN reverse lookup. The rest of that document's list is left out on
purpose: the TEST-NET reverse zones and the IPv6 loopback/unspecified zones are
not names a running network resolves, and CGNAT space (100.64/10, RFC 6598,
added after RFC 6303) is delegated in the public tree rather than served
locally. None of them are the failure this addresses.

The bypass is off, though, for a name an operator has anchored themselves. A
site that signs its own reverse space and configures a trust anchor over it is
asking for those names to be validated; `covered_by_local_anchor` sees that and
leaves validation on, so the deliberate configuration wins over the default.
*/
@(private)
LOCALLY_SERVED_ZONES := [?]string {
	// RFC 1918 private IPv4 space.
	"10.in-addr.arpa.",
	"16.172.in-addr.arpa.",
	"17.172.in-addr.arpa.",
	"18.172.in-addr.arpa.",
	"19.172.in-addr.arpa.",
	"20.172.in-addr.arpa.",
	"21.172.in-addr.arpa.",
	"22.172.in-addr.arpa.",
	"23.172.in-addr.arpa.",
	"24.172.in-addr.arpa.",
	"25.172.in-addr.arpa.",
	"26.172.in-addr.arpa.",
	"27.172.in-addr.arpa.",
	"28.172.in-addr.arpa.",
	"29.172.in-addr.arpa.",
	"30.172.in-addr.arpa.",
	"31.172.in-addr.arpa.",
	"168.192.in-addr.arpa.",
	// RFC 3927 IPv4 link-local (169.254/16).
	"254.169.in-addr.arpa.",
	// RFC 1122 loopback (127/8) and "this host" (0/8).
	"127.in-addr.arpa.",
	"0.in-addr.arpa.",
	// RFC 4193 IPv6 unique-local (fc00::/7, of which fd00::/8 is in use).
	"d.f.ip6.arpa.",
	// RFC 4291 IPv6 link-local (fe80::/10).
	"8.e.f.ip6.arpa.",
	"9.e.f.ip6.arpa.",
	"a.e.f.ip6.arpa.",
	"b.e.f.ip6.arpa.",
}

/*
Whether `name` sits at or below one of the locally-served zones.

`name` is the question name in presentation form with its root dot, the shape
`resolve_query` holds. The match is on label boundaries and case-insensitive:
a zone is a suffix of the name only when what precedes it is a label break, so
`fake168.192.in-addr.arpa.` is not inside `168.192.in-addr.arpa.`, while
`20.2.168.192.in-addr.arpa.` is.
*/
@(private)
is_locally_served :: proc(name: string) -> bool {
	for zone in LOCALLY_SERVED_ZONES {
		if name_at_or_below(name, zone) {
			return true
		}
	}
	return false
}

/*
Whether the operator anchored a zone at or above `name`.

`s.anchor_zones` holds their configured anchors with the root left out, so a
match means a deliberate request to validate this name - the one case where the
locally-served bypass has to stand down. Same label-boundary rule as everything
else here: the anchor has to sit on a label break, not merely be a string suffix.
*/
@(private)
covered_by_local_anchor :: proc(s: ^Server, name: string) -> bool {
	for zone in s.anchor_zones {
		if name_at_or_below(name, zone) {
			return true
		}
	}
	return false
}

/*
Whether `name` sits strictly below `zone`, the zone's own name excluded.

This is what a wildcard means: "*.lan." stands for at least one label under
"lan.", so `find_rewrite` in the resolver asks this question while the callers
above ask the inclusive one. Both go through the same test so that neither can
be tightened or loosened without the other following, which is how the two came
to disagree about case in the first place.

The comparison folds case throughout, since DNS names compare without regard to
it (RFC 1035 section 2.3.3, restated for every label by RFC 4343) and the names
reaching here are whatever the client spelled - nothing upstream of this lowers
them, deliberately, so that a response can echo the question back byte for
byte. That rules out any byte-wise shortcut on the suffix, however tempting one
looks in front of the fold.
*/
@(private)
name_below :: proc(name, zone: string) -> bool {
	if len(name) <= len(zone) {
		return false
	}
	// The zone has to begin right after a label break, or it is a bare string
	// suffix of some other name rather than a subtree of it.
	if name[len(name) - len(zone) - 1] != '.' {
		return false
	}
	return dns.name_equal_fold(name[len(name) - len(zone):], zone)
}

@(private)
name_at_or_below :: proc(name, zone: string) -> bool {
	if len(name) == len(zone) {
		return dns.name_equal_fold(name, zone)
	}
	return name_below(name, zone)
}
