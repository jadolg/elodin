package server

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

  1. The client's question is sent to the route's group instead of the default.
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
     validate exactly these names.

A fourth falls out in `rebind.odin`: a routed zone may answer with private
addresses, because answering with private addresses is what a local authority
is for. Split horizon is the named reason the rebinding guard defaults off, and
a route is the operator saying this zone is served locally in as many words -
so it implies membership in `rebind.allow_domains` for the names it claims,
rather than making them configure the same fact twice.

What a route does not change is the cache. The key is name/type/class/DO/CD with
no upstream identity in it, which stays sound only because a name always routes
the same way: the table is built once at startup from a file that is never
reloaded (SIGHUP reloads TLS certificates and nothing else). A future reload
that could move a zone from one route to another would have to flush, or key on
the route, or it would serve one upstream's answers on another's behalf.
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
*/
@(private)
route_group :: proc(s: ^Server, name: string) -> ^upstream.Group {
	if route, found := zone_route(s, name); found {
		return route.group
	}
	return s.group
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
	for route in s.routes {
		closed += upstream.groom(route.group)
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
