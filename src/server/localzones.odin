package server

import "core:mem"
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
The forward-side sibling of the table above: names the RFCs reserved, which are
answered here and never asked about.

RFC 6761 set `localhost.`, `invalid.`, `test.` and `example.` aside, RFC 6762
section 22 set `local.` aside for mDNS, and RFC 7686 set `onion.` aside. The
root delegates none of them, so no answer a public resolver gives for one of
these can be the right answer - and the query that fetched the wrong answer has
already told somebody what was being looked for.

For `.onion` that disclosure is the whole harm. The query names, to the upstream
operator and to anyone on the path to a plain-UDP upstream, one specific hidden
service that somebody on this network is reaching for: exactly what Tor was
being used not to publish, leaving through a resolver nobody thought was on the
path. RFC 7686 section 2 tells a caching server "where not explicitly adapted to
interoperate with Tor" not to look these up and to answer NXDOMAIN, which is
both halves of the behaviour here - and the escape clause is why `onion.` has a
key rather than only the whole table having one. An operator whose upstream is a
local tor with `DNSPort` and `AutomapHostsOnResolve` is the adapted case the RFC
is describing, and `special_use.onion: false` is how they say so. Making them
reach for `special_use.enabled: false` instead would have cost them `localhost.`
and `invalid.` to get one zone back.

`localhost.` is the correctness half rather than the privacy half. The only
answer that name is allowed to have is the loopback address (RFC 6761 section
6.3); forwarded, it is whatever the upstream feels like returning, which is a
rebinding primitive handed over for free. `invalid.` is guaranteed never to
exist (RFC 6761 section 6.4), so NXDOMAIN from here is the answer the root
would have given anyway, minus the round trip and minus the leak.

Those two have no key of their own, and the asymmetry with `onion.`, `local.`
and `test.` below is the point. Each of those three names a deployment somebody
runs - a Tor-aware upstream, an Active Directory domain, an internal `.test`
zone - and the key exists because that deployment does. There is no such
deployment for `localhost.` or `invalid.`: no upstream is authoritative for
either, and RFC 6761 sections 6.3 and 6.4 leave a resolver nothing to defer to
about them. A key nobody can describe a legitimate use for is one that only ever
gets set while somebody is working around a symptom, so neither gets one; the
whole table still has `special_use.enabled` for the operator who wants none of
this.

`example.` is deliberately absent, though RFC 6761 reserves it too. Section 6.5
is the one entry in that document that asks for the opposite of the rest:
caching servers SHOULD NOT recognise example names as special, because
`example.com`, `example.net` and `example.org` are delegated and do resolve.
Answering them from here would break names that work today to honour a
reservation that exists to stop registries selling them.

The three keys are not symmetric with each other either: `onion` is on and
turning it off is a statement about the upstream, while `local` and `test` are
off and turning them on is a statement about this network. Each default leaves
an installation answering as it did before the table existed, which is the
weaker claim it sounds like but is not: a site whose upstream really does serve
`.local` is not necessarily *working* today, since with `dnssec.enabled` on -
the default - that unsigned answer is checked against a root that publishes a
signed proof there is no `local.` to delegate, and SERVFAIL is the likely
verdict. Such a site has already turned validation off, or has not noticed. What
the default guarantees is only that nothing here is what changed for them, and
that turning `local` on is a decision rather than an upgrade.

`local.` and `test.` are in the table only when `special_use.local` and
`special_use.test` ask for them. RFC 6762 section 22 and RFC 6761 section 6.2
do want this handling by default, and this is a deliberate departure from both:
those two are the reserved names that deployed networks really do serve - an
Active Directory domain under `.local` older than the reservation, an internal
`.test` zone that section 6.2 itself tells users they may run. NXDOMAIN by
default would take a working network's own hostnames away on an upgrade, which
is the forward-side version of the breakage `LOCALLY_SERVED_ZONES` above exists
to avoid. It costs little to leave them behind a key: against a public upstream
the only case where turning one on changes what a client sees is the case where
the upstream was answering, the root having no `local.` or `test.` to delegate.

A rewrite outranks all of this, because `apply_rewrite` runs first - a site that
has written down what its own names resolve to keeps that answer. What a rewrite
cannot do is send the query somewhere else, there being no per-domain upstream
here, so a network whose router answers `.local` dynamically needs the
configuration key rather than a rule. That is what the key is for.
*/
@(private)
Special_Use :: enum u8 {
	None,
	// Answered with the loopback address: `localhost.` and anything under it.
	Loopback,
	// Answered NXDOMAIN, the name being one that cannot exist.
	Nonexistent,
}

/*
Ten minutes on a synthesised answer.

Nothing behind these can change while the setting stands, so the TTL is not
about freshness - it is how long a client goes on believing this after an
operator has changed their mind. A day would be the honest figure for `onion.`
and be wrong the first time somebody turns `special_use.local` off to get their
Active Directory domain back and finds their own clients still holding the
NXDOMAIN. Ten minutes is short enough that the restart which changes the setting
takes effect while the operator is still watching, and long enough that a chatty
`.local` client is not asking every second.
*/
@(private)
SPECIAL_USE_TTL :: 600

/*
Which special-use zone `name` falls in, and how it is to be answered.

The zone comes back with the verdict because the SOA the caller synthesises
belongs at the zone's apex - `onion.` for a name under it - rather than at the
queried name's parent, which for `a.b.onion.` is `b.onion.`, a zone nobody has
ever been authoritative for. Same label-boundary, case-folding test as
everything else in this file, so `notlocalhost.` is not inside `localhost.`.
*/
@(private)
special_use_zone :: proc(s: ^Server, name: string) -> (zone: string, kind: Special_Use) {
	if !s.cfg.special_use.enabled {
		return "", .None
	}
	// The two with no key of their own.
	if name_at_or_below(name, "localhost.") {
		return "localhost.", .Loopback
	}
	if name_at_or_below(name, "invalid.") {
		return "invalid.", .Nonexistent
	}
	// The three an operator can hand back to the upstream, each for a
	// deployment that really is served there.
	if s.cfg.special_use.onion && name_at_or_below(name, "onion.") {
		return "onion.", .Nonexistent
	}
	if s.cfg.special_use.local && name_at_or_below(name, "local.") {
		return "local.", .Nonexistent
	}
	if s.cfg.special_use.test && name_at_or_below(name, "test.") {
		return "test.", .Nonexistent
	}
	return "", .None
}

/*
Whether `name` is a reserved name this configuration has deliberately handed
back to the upstream, and so must not be held to the public chain of trust.

What such an upstream answers for a `.onion` name is unsigned, and can be
nothing else - the root delegates no `onion.` for anybody to sign under. A
validator walking down from the root asks for `onion. DS`, is shown an NSEC
proving the name is not in the root zone at all, concludes from that that
nothing is delegated there and the root's own keys still cover the subtree, and
then meets an answer carrying no signature under them. That is Bogus, and the
client gets SERVFAIL - so a Tor-aware upstream would be worth nothing while
`dnssec.enabled` stands, which it does by default.

The condition is that the table is not answering `onion.` itself, by either of
the two keys that can take it out: `special_use.onion: false`, which says the
upstream is Tor-aware, or `special_use.enabled: false`, which says none of this
handling is wanted. Keying it on `onion` alone was the narrower reading, and it
left a trap: an operator with a local tor who reached for `enabled: false` -
the blunter key, and the one whose name sounds like it covers everything - got
the forwarding they asked for and a SERVFAIL for every `.onion` name, because
the bypass was still waiting for a key they had no reason to think they needed.
A startup warning used to point at it. Answering it in the code is better: the
rule is now that a `.onion` name this server forwards is a `.onion` name it does
not validate, which holds however the operator said to forward it.

The same standing-down `is_locally_served` performs above, for the same reason
and at the same price: the answer is served as insecure. Neither key is ever set
by default, so nothing reaches this without an operator having written something
down, and writing it down is the claim that makes it right.

`covered_by_local_anchor` stands it down in turn, the same way it does the
reverse-side bypass. The argument for leaving it out was that this bypass is
already what an operator asked for, so no anchor could be more deliberate than
the key that turned it on - but that is only true while the two cannot be written
together, and they can. An operator who runs a privately signed tree under
`onion.` behind their own resolver and configures a trust anchor over it has said
something more specific than either key, and the reverse side already settles
which of those wins: the anchor. Having the forward side answer the same question
the other way would mean the narrower instruction losing to the broader one, in
one of two places that read as a pair.

`local.` and `test.` get no such treatment, deliberately, and the line between
them and `onion.` is what an operator had to do to get here. Those two are
forwarded by a *default* configuration, and a public upstream's NXDOMAIN for
them really is signed by the root - bypassing the check would turn an answer
this server can prove into one it merely repeats, for every installation rather
than for one that asked. `enabled: false` is on the other side of that line: it
is not a default, and the installation that set it asked.

What it costs, so the trade is written down rather than discovered. An operator
who set `enabled: false` for some reason other than tor, and whose upstream is
an ordinary public resolver, now gets that upstream's NXDOMAIN for a `.onion`
name as insecure rather than as the root-signed nonexistence it could have
proved - and a forged address for one, from a hostile upstream or somebody on
the path, is passed on as insecure instead of being caught as Bogus. That is the
same exposure `onion: false` already accepts, extended to the other key that
also forwards these names. It is the price of the rule holding whichever key was
used, and it is bounded by both keys being explicit.
*/
@(private)
special_use_deferred :: proc(s: ^Server, name: string) -> bool {
	if s.cfg.special_use.enabled && s.cfg.special_use.onion {
		return false
	}
	if !name_at_or_below(name, "onion.") {
		return false
	}
	// An anchor over the zone is the operator asking for the opposite, and it is
	// the more specific of the two things they have written down.
	return !covered_by_local_anchor(s, name)
}

/*
The answer for a name that is never forwarded.

`localhost.` gets 127.0.0.1 for A and ::1 for AAAA (RFC 6761 section 6.3), and
NODATA for every other type - not NXDOMAIN, because the name exists, and not a
made-up record of some other type, because this server has no zone to invent
one from. An MX or a TXT for `localhost.` is a question with a real answer of
"there is none", and NODATA is how that is spelled.

The rest get NXDOMAIN. Both shapes carry a synthesised SOA in the authority
section for the same reason `build_block_response` does: without one there is
nothing for a downstream resolver to cache the negative answer against (RFC
2308 section 5), and a client that re-asks every second is a client whose
`.onion` lookups this server is now generating rather than merely refusing to
forward.

The answers themselves do not go in the cache. `cache.put` is there so an
upstream need not be asked twice; these are built from a table already in
memory, they can never go stale, and an entry would only spend the cache's
budget on the one kind of answer that cannot need it.
*/
@(private)
answer_special_use :: proc(
	query: dns.Message,
	q: dns.Question,
	zone: string,
	kind: Special_Use,
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	rcode := dns.Rcode.No_Error
	answers := make([dynamic]dns.Record, 0, 2, allocator)

	switch kind {
	case .None:
	// Not reached: the caller checks before it asks for an answer.
	case .Loopback:
		if q.type == .A || q.type == .ANY {
			append(
				&answers,
				dns.Record {
					name = q.name,
					type = .A,
					class = .IN,
					ttl = SPECIAL_USE_TTL,
					data = dns.Rdata_A{addr = {127, 0, 0, 1}},
				},
			)
		}
		if q.type == .AAAA || q.type == .ANY {
			append(
				&answers,
				dns.Record {
					name = q.name,
					type = .AAAA,
					class = .IN,
					ttl = SPECIAL_USE_TTL,
					data = dns.Rdata_AAAA{addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
				},
			)
		}
	case .Nonexistent:
		rcode = .NX_Domain
	}

	resp := dns.make_response(query, rcode, allocator)
	resp.answer = answers[:]
	if len(answers) == 0 {
		resp.authority = synth_soa(q.name, SPECIAL_USE_TTL, allocator, zone)
	}

	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		fallback, _ := dns.error_response(nil, query, rcode, allocator, limit)
		return fallback
	}
	return out
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
