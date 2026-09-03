package server

import "elodin:dns"
import "elodin:upstream"

/*
Per-domain upstreams: the zones this server sends somewhere other than
`upstream.servers`, and the group each of them goes to.

A network that runs its own DNS for its own zone is the deployment this exists
for. A domain controller answers `corp.example`, a router answers `home.arpa.`,
a lab server answers an internal `.test` - and none of them can recurse the
public Internet, while the public resolver that can has never heard of the zone.
Without a route the operator has to choose which half of their name space works.
`server=/corp.example/10.0.0.1` is how dnsmasq says this, `forward-zone` how
unbound does, `conditionalMapping` how blocky does; `upstream.zones` is how it is
said here. See `config.Zone_Route` for the configuration and RFC 8375 section 3
for the one zone an RFC names.

Three things follow from a route, and only the first is about where the packet
goes:

  1. The client's question is sent to the route's group instead of the default -
     every question but one. A `DS` at the route's own apex asks about the
     delegation rather than about anything inside the zone, and the proof lives
     in the parent; `route_group` sends that one to whoever answers the parent.
  2. The chain walk is not, ever. A router authoritative for `home.arpa.`
     answers `home.arpa. DS` out of its own zone - NODATA, unsigned, no NSEC -
     rather than forwarding to `arpa.` where the proof that the delegation
     carries no DS actually lives. Sending the validator's own lookups down the
     route would rebuild exactly the broken chain that issue #194 was about, so
     `validator_query` keeps using `s.group` and says so.
  3. A routed name is served insecure, unless the operator anchored the zone
     themselves. The zone holds local, unsigned data under a signed public
     parent, so walking the public hierarchy for a name inside it reaches a
     delegation that is not there and calls the answer Bogus - SERVFAIL for a
     name that was never public. This is the same bypass `is_locally_served`
     grants the RFC 6303 reverse zones, with the same escape hatch:
     `covered_by_local_anchor` stands it down for an operator who signed the
     zone and configured an anchor over it, that being a deliberate request to
     validate exactly these names. Standing it down is all it does: the chain
     walk starts at the root and descends by `DS`, so an anchor below the root
     is not a starting point, and a zone signed purely internally still cannot
     be reached. Anchoring such a zone trades an insecure answer for SERVFAIL.

A fourth falls out in `rebind.odin`: a routed zone may answer with private
addresses, because answering with private addresses is what a local authority
is for. Split horizon is the named reason the rebinding guard defaults off, and
a route is the operator saying this zone is served locally in as many words -
so it implies membership in `rebind.allow_domains` for the names it claims,
rather than making them configure the same fact twice.

What a route does not change is the cache. The key is name/type/class/DO/CD with
no upstream identity in it, which stays sound only because a question always
routes the same way: the table is built once at startup from a file that is
never reloaded (SIGHUP reloads TLS certificates and nothing else). A future
reload that could move a zone from one route to another would have to flush, or
key on the route, or it would serve one upstream's answers on another's behalf.
The apex `DS` carve-out is within that: what it splits is one name's types, and
the type is in the key, so the parent's answer and the zone's own cannot be
served for each other.
*/
Zone_Route :: struct {
	// Canonical, lowercase, root-dotted, as `config.Zone_Route` left them.
	domains: []string,
	group:   ^upstream.Group,
}

/*
The group that answers `name`: the longest route that claims it, or the default.

Longest match, so `dev.corp.example.` can be routed away from `corp.example.`
by adding a second entry rather than by restating the first. Ties cannot arise:
two routes claiming the same domain are refused at load, and two domains of the
same length that both match one name would have to be the same domain.

`name` is the question name in presentation form with its root dot, which is
what `resolve_query` holds. Matching is `name_at_or_below`: label boundaries and
case-insensitive, so `notcorp.example.` is outside `corp.example.` and
`NAS.Corp.Example.` is inside it.

`type` is here for one carve-out, the same one `special_use_zone` makes and for
the same reason: a `DS` query at a route's apex is answered by the zone's parent
and by nothing else, so it is asked of whoever answers the parent rather than of
the zone's own authority (issue #227). A validating stub below this server walks
down from `arpa.` and asks `home.arpa. DS` for itself; the router the route
points at is authoritative for `home.arpa.` and answers that out of its own zone
- an unsigned NODATA with no NSEC beside it - while the signed proof that the
delegation carries no DS lives in `arpa.`. The stub is then shown a chain broken
rather than proved absent, which is Bogus, which is SERVFAIL for every name in
the zone. RFC 8375 section 4 item 4.B carves the same query out of the same MUST
NOT ("MUST result in forwarding whatever queries are necessary"), and
`validator_query` already carves it out for the lookups this server makes on its
own account, so leaving the client's copy of that question on the route was the
one place the three disagreed.

Three things the carve-out deliberately is not:

  - It is not `DNSKEY`. A zone's keys are its own data, published in the zone
    and signed by it, so the authority a route points at is exactly the right
    place to ask - the argument that moves `DS` off the route is the argument
    for leaving `DNSKEY` on it.
  - It is not the names below the apex. `nas.home.arpa. DS` asks about a
    delegation inside a zone that exists nowhere but this network, and the
    answer to that one really is on the router.
  - It is not conditional on the zone being delegated in the public tree.
    Nothing at load can tell an internal zone from a public signed one, and the
    unconditional form costs a zone with no public parent one query answered
    NXDOMAIN or SERVFAIL by the default group - where following the route would
    have got an unsigned NODATA that no validator can use either.

What it does not touch is whether the answer is validated. `served_locally` still
covers the routed zone's apex, so the parent's signed DS is passed to the client
with the upstream's signatures intact and without the AD bit, for the client to
check against its own anchor - which is exactly what `LOCALLY_SERVED_ZONES` does
with the same query for `home.arpa.` today, and the client asking it is the only
party that has a use for the proof.

The privacy cost is one name and it is worth naming: a route otherwise means the
public resolver never hears any part of the zone (issue #200), and the apex `DS`
is now one question that reaches it. No host inside the zone is in it - the name
is the zone's own, which its public parent already publishes if the delegation
exists and answers NXDOMAIN for if it does not - and only a validating client
below this server ever asks it. RFC 8375 section 4 item 4.B makes the same
trade for `home.arpa.` explicitly, weighing this one query against SERVFAIL for
every name in the zone.

The parent rather than `s.group` flatly, because the parent may itself be routed:
with `corp.example.` on the domain controller and `dev.corp.example.` on a lab
server, `dev.corp.example. DS` is the domain controller's to answer, and it is
the one machine that holds that delegation. `dns.name_parent` of a route domain
is always shorter than the domain, and the root is refused as a route domain at
load, so the walk up is one step and cannot land back on the same route.
*/
@(private)
route_group :: proc(s: ^Server, name: string, type: dns.Type) -> ^upstream.Group {
	target := name
	if type == .DS && is_route_apex(s, name) {
		target = dns.name_parent(name)
	}
	if route, found := zone_route(s, target); found {
		return route.group
	}
	return s.group
}

/*
Whether `name` is the apex of a route: a domain some entry names exactly.

Equality against every route's domains rather than a question about the longest
match, which comes to the same thing and says it in fewer moving parts: a domain
equal to the name is the longest domain that can match it, so the route that
claims the name is the route that names it.
*/
@(private)
is_route_apex :: proc(s: ^Server, name: string) -> bool {
	for candidate in s.routes {
		for domain in candidate.domains {
			if dns.name_equal_fold(name, domain) {
				return true
			}
		}
	}
	return false
}

/*
The route that claims `name`, if one does.

Separate from `route_group` because two callers want the fact rather than the
group: the DNSSEC bypass and the rebinding exemption both ask only whether this
name is served locally on purpose.
*/
@(private)
zone_route :: proc(s: ^Server, name: string) -> (route: Zone_Route, found: bool) {
	best := -1
	for candidate in s.routes {
		for domain in candidate.domains {
			if !name_at_or_below(name, domain) {
				continue
			}
			if best < 0 || len(domain) > best {
				best = len(domain)
				route = candidate
				found = true
			}
		}
	}
	return
}

// Whether `name` sits inside a zone the operator routed to a local authority.
@(private)
is_zone_routed :: proc(s: ^Server, name: string) -> bool {
	_, found := zone_route(s, name)
	return found
}

/*
Close idle connections on every upstream this server has, routed or not.

The maintenance loop used to groom the one group there was. A route's
connections go idle exactly as the default group's do - more so, since an
internal zone is usually a smaller share of the traffic - and a pool nobody
grooms is one that holds file descriptors open against a server that may have
gone away.
*/
groom_upstreams :: proc(s: ^Server) -> (closed: int) {
	if s.group != nil {
		closed += upstream.groom(s.group)
	}
	// Guarded the same way the default group is: `upstream.groom` walks
	// `g.servers` without a nil check of its own, and a `Zone_Route` is a plain
	// struct anybody can build with no group in it.
	for route in s.routes {
		if route.group != nil {
			closed += upstream.groom(route.group)
		}
	}
	return
}

/*
Whether `name` is served by something inside this network, so that holding it to
the public chain of trust would be wrong.

Two ways to be: the RFC 6303 table in `localzones.odin`, which needs no
configuration because those zones are local by definition, and an
`upstream.zones` route, which is the operator saying so about a zone of their
own. Both mean the same thing about validation - unsigned local data under a
public parent that delegates nothing to it, so a chain walk finds a missing
delegation rather than a signed one and calls a perfectly good answer Bogus.

One escape hatch, for both: an operator who signed the zone and configured a
trust anchor over it has asked for exactly these names to be validated, and that
request outranks a default meant for zones nobody signs.

A named procedure rather than the expression inline in `resolve_query`, because
each of the three parts has to be testable on its own. Two layers of the same
bypass mask each other: with the RFC 6303 table also matching, a route that
never fired would look like it had.
*/
@(private)
served_locally :: proc(s: ^Server, name: string) -> bool {
	if !is_locally_served(name) && !is_zone_routed(s, name) {
		return false
	}
	return !covered_by_local_anchor(s, name)
}
