package server

import "core:mem"
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
The apex `DS` carve-out is the one question where that reading is not the whole
story, and it is worth saying so rather than resting on "the type is in the key".
The type is in the key, but the carve-out does not split by type: both the
parent's proof and the route's answer are answers to the same `DS` at the same
name, so both would be filed under the one entry. What keeps that sound is the
narrowness of the choice between them. Which upstream answers is a function of
what the parent's group said, so a name that reached its proof goes on reaching
it; and wherever the parent established nothing - no reply, a rewritten rcode, a
group already parked - `resolve_query` serves the route's answer and stores
nothing, so the entry is never the stand-in for a fact nobody checked. What is
left is a parent *group* whose members disagree about the zone - one that
publishes the proof beside one that rewrites the rcode - where the entry can be
the parent's proof on one query and the route's own NODATA on the next. That is
the worst this carve-out can do to the cache, and it is the behaviour the zone
had before the carve-out existed: an unsigned NODATA for the apex `DS`, served
for the entry's lifetime.
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
  - It is not decided at load by whether the public tree delegates the zone,
    because nothing at load can know that. It is decided by the answer, and by
    the narrowest reading of it: the one reply that keeps the question at the
    parent is the one this carve-out went to fetch - a NODATA, the statement
    that the delegation carries no DS. Anything else and `resolve_query` puts
    the question back on the route. See `apex_ds_off_route` and
    `parent_answers_apex_ds`, where that reading is argued case by case.

What it does not touch is whether the answer is validated. `served_locally` still
covers the routed zone's apex, so the parent's proof is passed to the client with
the upstream's signatures intact and without the AD bit, for the client to check
against its own anchor - which is exactly what `LOCALLY_SERVED_ZONES` does with
the same query for `home.arpa.` today, and the client asking it is the only
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
load, so the walk up is one step and terminates. It can land back on the route
it started from, one entry being free to list a zone and its parent together,
and that is the right answer rather than a loop to guard against: the parent's
authority is the route's own, so the question stays where it was going and
`resolve_query` skips the fallback for it.
*/
@(private)
route_group :: proc(s: ^Server, name: string, type: dns.Type) -> ^upstream.Group {
	if apex_ds_off_route(s, name, type) {
		return zone_route_group(s, dns.name_parent(name))
	}
	return zone_route_group(s, name)
}

/*
The group the route points at for `name`, the apex `DS` carve-out ignored.

`route_group` answers where a question goes. This answers where the zone is,
which for the one question that leaves the route is a different place, and both
callers of it want the second: `route_group` itself, to ask the question of the
parent's zone rather than of the parent's name, and `resolve_query`, to put an
apex `DS` back on the route when the parent's group established no delegation.
*/
@(private)
zone_route_group :: proc(s: ^Server, name: string) -> ^upstream.Group {
	if route, found := zone_route(s, name); found {
		return route.group
	}
	return s.group
}

/*
Whether this is the apex `DS` that `route_group` sends to the parent's group.

`resolve_query` asks because for this one question, and no other, the parent's
answer has to be read before it is passed on. Exactly one answer is the one this
carve-out was built to fetch: a NODATA, the parent saying it holds no DS for this
name. That is RFC 8375 section 4 item 4.B's whole subject, it is `home.arpa.`'s
answer from `arpa.`, and it is the only thing the parent can tell a validating
client that the route cannot. Every other reply goes back on the route -
`parent_answers_apex_ds` is the test, and there are five ways to fail it:

  - NXDOMAIN. The parent zone has no such name, so nothing in the public tree
    delegates this zone: there is no proof of an insecure delegation to be had,
    and the route's authority is the only thing that can say anything about the
    name at all. Passing it on is worse than the answer it replaced, too. An
    unsigned NODATA from the route leaves a lenient validator free to treat the
    zone as unsigned and resolve it - systemd-resolved's default
    `DNSSEC=allow-downgrade` does exactly that - while a signed proof of
    non-existence takes that freedom away, and a validator implementing RFC
    8020, as unbound's `harden-below-nxdomain` does by default, reads it as
    proof that every name under the apex is gone with it. A routed
    `corp.example.com` under a signed `example.com` going dark is the failure
    this carve-out exists to prevent, met coming the other way.
  - A `DS` RRset. The zone is delegated and signed in the public tree, and the
    route points at a view of it that is very unlikely to be the signed one -
    split horizon, which `rebind.odin` names as the reason its guard defaults
    off. Handing the client the public DS makes it demand a `DNSKEY` the
    internal view has no matching key for, and Bogus is what it gets, where
    before the carve-out the same deployment resolved. An operator who really
    is mirroring the signed zone loses the secure path and keeps the insecure
    one, which is the trade this whole file makes for a routed zone anyway
    (point 3 above), and `trust_anchors` is the escape hatch there as here.
  - No reply at all. A routed zone used to answer for itself with the public
    upstream uninvolved, which on a network with an internal authority and a
    poor path out is most of the point; an outage out there must not take the
    chain out from under every name in a zone that is answering perfectly well.
    `group_reachable` keeps that from being paid for twice over: a parent group
    already parked by its own failures is not asked at all.
  - A reply that says nothing about the name: SERVFAIL, REFUSED, and every other
    rcode that is neither NOERROR nor NXDOMAIN. An upstream with an ACL, or a
    CPE resolver that mangles every `DS` it meets, is not a statement about this
    delegation, and `parent_answers_apex_ds` sets out why this file reads those
    the same way `upstream.resolve_answerable` does rather than the way an
    ordinary client question is read.
  - A NOERROR that is not a NODATA: the rcode says the name is there and the
    answer section carries something other than a DS. An NXDOMAIN-hijacking
    resolver answers exactly that for a name its parent zone does not delegate -
    NOERROR with a synthesised address - which is the deployment the NXDOMAIN
    case above is written around, met through an upstream that rewrites the
    rcode. Read as the proof it is not, the route would never be asked and a
    validating client would be handed an answer to a `DS` query that is neither
    a DS nor a denial of one: a broken chain, which is this carve-out's own
    failure arriving through the question it sends out.

What the NODATA does not distinguish is worth setting down, because the
distinction is real and this does not draw it. "No DS for this name" is the
answer both to an insecure delegation - a zone the parent delegates and does not
sign, which is `home.arpa.` and every case this carve-out was written for - and
to a name that sits in the parent's own zone without being a delegation at all:
`corp.example.com.` published as an A record for a portal, or standing as an
empty non-terminal because `vpn.corp.example.com.` is public. Telling the two
apart means reading the NS bit out of the type bitmap of the NSEC or NSEC3 record
in the authority section, which nothing here does - `decode_through_answer` stops
where its name says.

For the second shape the proof is passed on and the client is right to act on it:
the public tree really does cover those names with signed data, so the local
authority's unsigned answers below them really are Bogus, and a validator that
resolved the zone before this carve-out existed did so only because the route's
own unsigned NODATA kept the parent's proof out of its sight. The remedy is the
one this file already documents for a routed zone the public tree signs:
`trust_anchors` over the zone, or not routing a name the public tree publishes.
An operator who wants elodin to make that distinction for them wants the bitmap
read, which is a change to this predicate and not to the shape of the carve-out.

`home.arpa.` is the one deployment none of that touches, which is the point:
`arpa.` delegates the zone and publishes the proof, so the answer is a NODATA,
it passes, and the client gets what issue #227 was about.

When the route cannot be reached to answer in the parent's place, the query is a
SERVFAIL rather than the parent's reply passed on. `resolve_query` argues it
beside the second exchange; the short of it is that a reply which is not the
proof is not an answer to this question, and that the cache which does the damage
is the client's - it keeps a signed denial for the parent's negative TTL - so
withholding only this server's copy would never have reached it.

Deciding it on the answer rather than at load is what the issue left open as
"cannot be known at load". It cannot - but it can be read off the reply, at the
cost of one extra query for a routed apex whose parent says anything else, and
only for `DS`.
*/
@(private)
apex_ds_off_route :: proc(s: ^Server, name: string, type: dns.Type) -> bool {
	return type == .DS && is_route_apex(s, name)
}

/*
What the parent's group's reply settles about a routed zone's apex `DS`.

Two things, read off the one reply, because `resolve_query` has two decisions to
make about it and they are not the same decision.

`proved` is whether this is the client's answer, so that the route is not asked
in its place: NOERROR with an empty answer section, which is a NODATA and says
the parent holds no DS for this name. It does not say the name is a delegation -
`apex_ds_off_route` sets out what that leaves out and why the answer still
passes. The name
is there and the type is not. That is the reply this carve-out went to fetch, and
`apex_ds_off_route` argues why every other one is the route's to answer.

An *empty* section rather than merely one with no `DS` in it, because a NODATA
carries nothing in the answer at all - a denial's NSEC or NSEC3 travels in the
authority section, and a positive answer's DS and its RRSIG are what the answer
section holds when the delegation is signed. So NOERROR with anything else in it
is neither: an NXDOMAIN-hijacking resolver's synthesised address is the one that
actually arrives, and reading that as the proof would keep the question at a
parent that never answered it. It is `settled` no more than a SERVFAIL is, the
rcode having been rewritten by something that is not the parent zone.

The NODATA is read from the answer section alone. Whether the NSEC or NSEC3
beside it actually proves it is the client's question and not this server's - a
routed zone is served insecure here either way, so the records travel with their
signatures intact and the client checks them against its own anchor. What this
decides is only which upstream the question belongs to.

`settled` is whether the parent said anything about the delegation that holds
for as long as a cache entry does. The proof does; so does NXDOMAIN ("nothing
public delegates this zone") and so does a `DS` RRset ("it is delegated and
signed out here"). Those are facts about the public tree, and the route's answer
standing in for one of them is the answer for that zone until the public tree
changes. Nothing else is: no reply at all, an rcode that is neither NOERROR nor
NXDOMAIN, a NOERROR whose answer section holds something that is not a DS, and a
reply that would not decode are all this server failing to reach a statement
rather than a statement, so the route's answer stands in for a fact nobody
established. `resolve_query` serves that answer and declines to store it,
for the reason it gives at the store.

SERVFAIL and REFUSED being no statement at all is worth setting down, because
`upstream.resolve_answerable` draws the line elsewhere for a different question:
there, the rcode of a client's question is the client's answer, and only the
lookups this server makes on its own account insist on a reply that says
something. What that procedure says about *why* is the rule here too - "NOERROR
and NXDOMAIN are the only rcodes that say anything about a delegation" - and
this question, though the client's, is about a delegation. Being about the
delegation is the whole reason `route_group` diverts it by type.

So a REFUSED from an upstream with an ACL, or the SERVFAIL a CPE resolver hands
back for every `DS` it does not understand, says nothing about this zone, and
passing it on would take every name in an internal zone that is answering
perfectly well down with it - issue #227's failure reached through an upstream
that has nothing to do with the zone. The route can answer, so the route is
asked, and the parent's rcode reaches the client only when the route cannot be
reached either.

`reached` is `uerr == .None`. A reply that never arrived says nothing by the
same reading, so the route is asked then too and nothing is kept.
*/
@(private)
parent_answers_apex_ds :: proc(
	resp: []u8,
	reached: bool,
	allocator: mem.Allocator,
) -> (
	proved: bool,
	settled: bool,
) {
	if !reached {
		return false, false
	}
	rcode := dns.peek_rcode(resp)
	if rcode == .NX_Domain {
		return false, true
	}
	if rcode != .No_Error {
		return false, false
	}
	msg, err := dns.decode_through_answer(resp, allocator)
	if err != .None {
		return false, false
	}
	for rec in msg.answer {
		if rec.type == .DS {
			return false, true
		}
	}
	// A NODATA carries nothing here. Anything else under a NOERROR is a rcode
	// somebody rewrote rather than the parent's answer to this question.
	if len(msg.answer) != 0 {
		return false, false
	}
	return true, true
}

/*
Whether any upstream in `g` is out of its failure cooldown.

Asked about the parent's group before an apex `DS` is sent there, and only
there. `resolve_sequential` spends the group's whole budget on a group that is
entirely parked - round 0 skips the unhealthy servers, round 1 tries them anyway
- so with the default `timeout: 5s` and `attempts: 2` a public upstream that has
gone away costs ten seconds or more before the route is asked in its place. A
validating stub gives up in two to five, so the deployment `apex_ds_off_route`
describes - an internal authority behind a poor path out - would still see the
zone fail, having waited for an upstream this server already knows is down.

Three consecutive failures park an upstream and the cooldown is ten seconds, so
what this skips is a group that has already proved itself unreachable, for as
long as that is still true. Nothing else consults it: an ordinary question has
nowhere else to go, and waiting is the honest thing to do there.

The cooldown is all it skips, which leaves the first apex `DS` after each one to
pay the parent's full budget again - nothing was stored to answer it from, by
the rule at the store. That is the price of not memoising an outage, and it is
the right way round: a stall every ten seconds recovers the moment the path
does, where a stored answer would go on being served after it.
*/
@(private)
group_reachable :: proc(g: ^upstream.Group) -> bool {
	if g == nil {
		return false
	}
	for u in g.servers {
		if upstream.healthy(u) {
			return true
		}
	}
	return false
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
