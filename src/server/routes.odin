package server

import "core:mem"
import "core:sync"
import "core:time"
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
left is a parent *group* whose members disagree about the zone, where the entry
can be the parent's proof on one query and the route's own NODATA on the next.
Most of that is closed rather than merely narrow: a member that rewrites the
rcode to SERVFAIL or REFUSED is passed over, `resolve_query` asking the group
through `upstream.resolve_answerable`, so the proof is found wherever the group
holds it. What survives is a member whose reply is answerable without being the
proof, since that one stops the sweep before the member holding the proof is
reached: a NOERROR with something in the answer section, an NXDOMAIN, or a `DS`
RRset. The first of those keeps nothing - `parent_answers_apex_ds` leaves it
unsettled, so `resolve_query` serves the route's answer and stores none of it,
and the next query is free to reach the member that can prove the delegation.
The other two are settled by design, being statements about the public tree, so
the route's answer does go into the entry and stands for `cache.negative_ttl`
while another member of the same group was publishing the proof all along - one
upstream answering NXDOMAIN for an empty non-terminal that its neighbour answers
NODATA for, against RFC 8020, is how that actually arises. That is the worst
this carve-out can do to the cache, and it is the behaviour the zone had before
the carve-out existed: an unsigned NODATA for the apex `DS`, served for the
entry's lifetime.
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
    already parked by its own failures is not asked at all, so long as the route
    is out of its own cooldown and can answer in its place.
  - A reply that says nothing about the name: SERVFAIL, REFUSED, and every other
    rcode that is neither NOERROR nor NXDOMAIN. An upstream with an ACL, or a
    CPE resolver that mangles every `DS` it meets, is not a statement about this
    delegation, so `resolve_query` asks the parent's group through
    `upstream.resolve_answerable` - the group's other members first, and the
    route only once none of them will say anything. `parent_answers_apex_ds`
    sets out why that is the reading here rather than the way an ordinary client
    question is read.
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
passes. The name is there and the type is not. That is the reply this carve-out
went to fetch, and `apex_ds_off_route` argues why every other one is the route's
to answer.

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

SERVFAIL and REFUSED being no statement at all is the reading
`upstream.resolve_answerable` already takes, and `resolve_query` asks the
parent's group through it rather than through `resolve` for that reason: what
that procedure says about *why* - "NOERROR and NXDOMAIN are the only rcodes that
say anything about a delegation" - is the rule here too, and this question,
though the client's, is about a delegation. Being about the delegation is the
whole reason `route_group` diverts it by type. So a group with one member that
publishes the proof and one that mangles every `DS` answers from the one that
can, rather than from whichever it reached first, and this predicate sees the
reply that says something wherever the group holds one. Only the route's own
exchange keeps the ordinary reading, its rcode being the client's answer.

So a REFUSED from an upstream with an ACL, or the SERVFAIL a CPE resolver hands
back for every `DS` it does not understand, says nothing about this zone, and
passing it on would take every name in an internal zone that is answering
perfectly well down with it - issue #227's failure reached through an upstream
that has nothing to do with the zone. The route can answer, so the route is
asked, and the parent's rcode is not passed on at all: where the route cannot be
reached either the query is a SERVFAIL, or an expired entry where `serve_stale`
kept one, which is the paragraph above this one.

`reached` is `uerr == .None`. A reply that never arrived says nothing by the
same reading, so the route is asked then too and nothing is kept.

`name` is the question's own name, and the `DS` that makes the reply `settled`
has to be at it. `upstream.response_matches` pins the reply's *question* to the
one that went out, and nothing pins its answer section: a `DS` for some other
name in there is not "the public tree delegates and signs this zone", so reading
it as one would keep the route's answer in the cache on the strength of a record
about a different zone. Held to the name it falls through to the empty-section
test below, which is the unsettled reading the rest of a rewritten NOERROR gets.
*/
@(private)
parent_answers_apex_ds :: proc(
	resp: []u8,
	name: string,
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
		if rec.type == .DS && dns.name_equal_fold(rec.name, name) {
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

Asked about both groups before an apex `DS` is sent to the parent's, and nowhere
else. `resolve_sequential` spends the group's whole budget on a group that is
entirely parked - round 0 skips the unhealthy servers, round 1 tries them anyway
- so with the default `timeout: 5s` and `attempts: 2` a public upstream that has
gone away costs ten seconds or more before the route is asked in its place. A
validating stub gives up in two to five, so the deployment `apex_ds_off_route`
describes - an internal authority behind a poor path out - would still see the
zone fail, having waited for an upstream this server already knows is down.

Both, because the skip is only worth making when something else can answer.
Round 1's honest try is exactly the one that pays off when a parked group has
come back inside its ten seconds, so passing over a parked parent for a route
that is parked too throws that try away and buys a certain SERVFAIL with it.
`resolve_query` asks for the pair.

Three consecutive failures park an upstream and the cooldown is ten seconds, so
what this skips is a group that has already proved itself unreachable, for as
long as that is still true. Nothing else consults it: an ordinary question has
nowhere else to go, and waiting is the honest thing to do there.

The cooldown is all it skips, which leaves the first apex `DS` after each one to
pay the parent's full budget again - nothing was stored to answer it from, by
the rule at the store. That is the price of not memoising an outage, and it is
the right way round: a stall every ten seconds recovers the moment the path
does, where a stored answer would go on being served after it.

The price is worth stating in full, because it is paid by the client rather than
by this server. `healthy` goes true again the moment the cooldown elapses, so
against an uplink that blackholes packets - no ICMP, nothing to fail fast on -
the first apex `DS` after each expiry runs the group to the end of its budget,
`attempts` rounds over every server, twenty seconds at the defaults. A
validating stub gives up in two to five and SERVFAILs the zone for that round,
so what recovers in ten seconds is this server's willingness to try, not
necessarily the client's answer. Bounding it means a deadline of this question's
own or asking both groups at once, neither of which belongs in the same change
as the carve-out.
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
	_, found := route_apex_name(s, name)
	return found
}

/*
The route table's own spelling of `name`, when `name` is a route's apex.

`is_route_apex` wants only the fact. The memo below wants the string, and it
wants this one rather than the question's: the question's name is decoded into
the per-request arena and is gone the moment the response is written, where a
route's domain is read from the configuration at startup and outlives every
request. Same name either way - `dns.name_equal_fold` is what picked it - so
what this buys is a key the memo can hold on to.
*/
@(private)
route_apex_name :: proc(s: ^Server, name: string) -> (apex: string, found: bool) {
	for candidate in s.routes {
		for domain in candidate.domains {
			if dns.name_equal_fold(name, domain) {
				return domain, true
			}
		}
	}
	return "", false
}

/*
What a parent could not settle about a routed apex, and for how long that stands.

The probe `route_group` sends to the parent's group is paid for by the client's
own question, and where the parent settles nothing the route answers and nothing
is stored - the rule at `resolve_query`'s store, which is there so that an outage
is not memoised into the failure this carve-out exists to prevent. The price is
that the probe is re-paid by every query, and there are two configurations where
that is not a rounding error (issue #243):

  - An uplink that blackholes packets. `group_reachable` passes over the parent's
    group only while every member is parked, and `healthy` goes true again the
    moment `COOLDOWN` elapses however many failures stand against the server, so
    the first apex `DS` after each expiry runs the group to the end of its budget
    - `attempts` rounds over every server, twenty seconds at the defaults. A
    validating stub gives up in two to five, so it SERVFAILs the apex `DS` and
    with it every name in a zone whose own authority is answering in
    milliseconds, once per cooldown cycle.
  - A parent that answers but never settles. `exchange` counts a reply as a
    success whatever its rcode, so a member that REFUSEs or SERVFAILs every `DS`
    - an upstream with an ACL, a CPE resolver that mangles the type - never
    accrues a failure, is never parked, and `group_reachable` is true forever.
    Every client `DS` at a routed apex then costs two upstream exchanges for as
    long as the configuration stands.

This is the memory for the second of those, which is the one nothing else bounds.
The first has a memory already and it is `group_reachable`'s: three consecutive
failures park the group, the skip above fires for the whole cooldown, and what is
left over there is the first query of each cycle paying the budget - the wait
rather than its repetition, which is `Apex_Memo`'s business nowhere and issue
#243's other two options everywhere. The second has nothing at all: a group that
answers is never parked, so without this it costs its two exchanges per query for
as long as it stands.
It keeps no answer and stands in for none: what it remembers is that this parent
said nothing lasting about this apex, which is `parent_answers_apex_ds`'s
`settled` read false, and all that follows from it is that the route is asked
first while the memory holds. The client is handed what it would have been handed
after the wait, `unproven_apex_ds` travels with it exactly as it does when the
parent's group is parked, and the store refuses it for the same reason - so
nothing reaches the cache that the no-store rule would have kept out of it. The
window is `upstream.COOLDOWN`, the clock the parked-group skip already runs on,
so a parent that recovers is asked again within ten seconds of doing so and the
proof is back in the client's hands.

A parent that does settle clears its slot rather than leaving it to expire: the
question was asked, the answer arrived, and the memory of the last failure has
been overtaken by it.

Only a reply is remembered. A parent that said nothing at all - the blackholed
uplink, the lost datagram - has established nothing about the next ten seconds
either, and the next query is exactly as likely to reach it and come back with
the proof; skipping it on that would trade the answer this carve-out exists to
fetch for a wait, and trade it for every query in the window rather than for the
one that timed out. What the repeated stall against a group that really is gone
is bounded by is the parking `group_reachable` reads, which is the skip above
and needs no memory at all. So what is written down here is the reading a reply
carried: SERVFAIL, REFUSED, a NOERROR somebody rewrote - the configuration
answering rather than the network failing, which is the shape that never parks
and therefore never stops costing.

What the memory is not, even then, is a reason to stop asking. What it stands on
is `upstream.FAILURE_THRESHOLD` unsettled replies in a row - the count that parks
an upstream, borrowed because the question is the same one - and a group that
answers everything else perfectly well can still reach it.
`resolve_query` reaches past it for that reason, and the test it reaches on is
this memory's own bet: that what the route has to say is the unsigned twin of the
proof, a NODATA at the apex, which is the answer the parent's silence would have
left the client with anyway. `parent_answers_apex_ds` is the reading, applied to
the route's reply rather than the parent's. Anything else - no reply, a SERVFAIL,
an NXDOMAIN, a `DS` RRset, a NOERROR somebody rewrote - is not that answer, so
the bet is off and the parent is asked after the fact; a parent that has come
back with the proof is read and remembered as it always would have been, and
where it still says nothing the route's reply stands exactly as it would have
after the wait. The saving is of a wait the route can cover, never of the answer
itself.

What is left is the one divergence a memory of this kind cannot avoid and this
file will not pretend away: where the parent recovers inside the window *and* the
route answered the NODATA, the client is handed the route's unsigned one rather
than the parent's signed proof, for as long as the window holds. That is the
trade issue #243 asks for in as many words, and it is bounded on every side - one
`upstream.COOLDOWN`, one apex, a zone the operator did not anchor, and only after
the parent itself replied three times running without settling anything.

The window it closes is between one probe and the next, not around the probe
itself. Nothing is written until the parent's leg returns, so queries that arrive
while a first one is still in flight find no memory and take their own leg.
Bounding that means bounding the leg rather than remembering it: a deadline of
this question's own, or asking both groups at once, which is where issue #243
leaves it and what this deliberately is not.

Fixed slots rather than a map keyed by name. The names are route apexes, so the
set is settled at startup and small; an array needs no allocation, no destructor,
and nothing from a `Server` built as a literal. The ceiling is that an operator
routing more zones than there are slots keeps the memory for the apexes that hold
one and no others, the rest paying what every apex pays today - a map here is the
upgrade if a deployment ever wants it. `remember_apex_ds_parent` is where that
ceiling is enforced, and it is enforced by leaving live slots alone: a table that
evicted one apex's count to start another's would, past the slot count, leave
every apex restarting and none of them ever remembered.
*/
Apex_Memo :: struct {
	mu:    sync.Mutex,
	slots: [APEX_MEMO_SLOTS]Apex_Memo_Slot,
}

// How many apexes can be remembered at once. See `Apex_Memo`.
APEX_MEMO_SLOTS :: 8

Apex_Memo_Slot :: struct {
	// A route's own domain string, which outlives the request; see
	// `route_apex_name`. Empty in a slot nothing has claimed.
	name:    string,
	// When this stops being remembered, and until when the count below stays
	// consecutive. The zero value is in the past, which is what makes a cleared
	// slot read as no memory at all.
	until:   time.Time,
	// Unsettled replies in a row inside the window, against
	// `upstream.FAILURE_THRESHOLD`. See `apex_ds_parent_unsettled`.
	strikes: int,
}

/*
Whether the memory may answer for the parent's group here at all.

The window is the whole of it wherever the route's answer can be served, and an
anchor over the zone is where it cannot. A routed zone is served insecure - that
is what `served_locally` does, and what this memory bets on when it lets the
route's unsigned NODATA stand in for the parent's signed proof - unless the
operator anchored the zone themselves, which is a request to hold exactly these
names to the public chain. The route has no signatures to offer that chain, so
its answer there is a Bogus verdict and a SERVFAIL rather than a stand-in, and a
memory would spend a whole cooldown of them while the parent was healthy and
holding what the client asked for. `routes.odin`'s summary of anchoring a routed
zone - an insecure answer traded for SERVFAIL - is what that operator asked for,
and this must not make the trade for them ten seconds at a time.

`covered_by_local_anchor` rather than `resolve_query`'s `validating`, which is
the same fact for an ordinary query and not for every query. `validating` also
goes false when the client sets CD, and a downstream resolver doing its own
validation is exactly who sets it - it wants the signed proof to check, and it is
the party an anchor over a routed zone is configured for. It goes false again
when the validator could not be built. Neither is a statement that this zone's
unsigned answer will do, and the zone is what this asks about.

The skip above it is the same shape with no such choice: a parent whose every
member is parked cannot be asked instead, so the route's answer, validated or
not, is all there is.
*/
@(private)
apex_ds_memo_applies :: proc(s: ^Server, name: string) -> bool {
	return !covered_by_local_anchor(s, name) && apex_ds_parent_unsettled(s, name)
}

/*
Whether the parent's group has failed to settle this apex `DS` often enough,
recently enough, to be passed over for it.

`upstream.FAILURE_THRESHOLD` consecutive unsettled replies inside the window, the
same count that parks an upstream and for the same reason: one reply is a blip,
and the blip is exactly the case where the next query reaches a parent that has
come back and is holding the proof. Three in a row inside ten seconds is a
parent that is not going to settle this delegation today - the ACL, the CPE
resolver that mangles every `DS` - which is the shape this memory is for.

The window does double duty, and deliberately: it is how long a memory stands and
how long the count that built it stays consecutive. A slot whose window has run
out starts again at one, so a parent that stumbles once an hour never accumulates
its way into being skipped.

Replies rather than moments, which is worth saying because it is what the count
is: three questions in flight together against a parent having one bad second
each come back unsettled and each leave a strike, so a busy resolver can reach
the threshold on a stumble that a quiet one would never have remembered. What
that costs is what the window and the fallback already bound - the route's
answer, for ten seconds, where the route can answer at all - and what it would
take to distinguish is a clock per slot for something the cooldown already
expires. Named here because the next reader will otherwise read "three in a row"
as three separate occasions.
*/
@(private)
apex_ds_parent_unsettled :: proc(s: ^Server, name: string) -> bool {
	now := time.now()
	sync.mutex_lock(&s.apex_memo.mu)
	defer sync.mutex_unlock(&s.apex_memo.mu)
	for slot in s.apex_memo.slots {
		if slot.name != "" && dns.name_equal_fold(slot.name, name) {
			return slot.strikes >= upstream.FAILURE_THRESHOLD && time.diff(now, slot.until) > 0
		}
	}
	return false
}

/*
Write down what the parent's group managed to say about this apex `DS`.

`reached` is `parent_answers_apex_ds`'s own third argument, and nothing is written
without it: a parent that never replied established nothing to remember, for the
reason `Apex_Memo` gives. Not even a clearing - an existing memory of a parent
that would not settle this apex is not disproved by a datagram going missing.

Nor is anything written for a zone the operator anchored, which is the same
question `apex_ds_memo_applies` asks before reading one. A memory that can never
be acted on is not free: the table is a fixed size, and an entry in it is a slot
an apex that would have been spared the wait does not get.

`settled` is `parent_answers_apex_ds`'s second return read straight: true and the
slot is cleared, false and it counts as one more reply in a row that settled
nothing - `upstream.FAILURE_THRESHOLD` of them inside the window and the route is
asked first for the rest of it.

The slot chosen is this apex's own where it has one, and otherwise the one whose
memory expires soonest - which takes an unclaimed slot first, its zero `until`
being older than any real one, and evicts the stalest memory when every slot is
in use.
*/
@(private)
remember_apex_ds_parent :: proc(s: ^Server, name: string, reached, settled: bool) {
	if !reached {
		return
	}
	apex, found := route_apex_name(s, name)
	if !found || covered_by_local_anchor(s, apex) {
		return
	}
	now := time.now()
	sync.mutex_lock(&s.apex_memo.mu)
	defer sync.mutex_unlock(&s.apex_memo.mu)
	victim := -1
	for slot, i in s.apex_memo.slots {
		if slot.name == apex {
			victim = i
			break
		}
		// A parent that settled has nothing to write down, so it takes no slot
		// from an apex that has something in one.
		if settled {
			continue
		}
		/*
		And a slot whose window is still running belongs to the apex that wrote
		it. Taking it would restart that apex's count, and with more failing
		apexes than slots and traffic going round them, every apex would be
		evicted before its own next reply and none would ever reach the
		threshold - the memory would be a table that is always full and never
		read. A slot nobody has claimed, or one whose window has run out, is
		free; where none is, this apex is one of the ones the ceiling leaves out
		and it pays what every apex paid before this memory existed.
		*/
		if victim < 0 && time.diff(now, slot.until) <= 0 {
			victim = i
		}
	}
	if victim < 0 {
		return
	}
	if settled {
		s.apex_memo.slots[victim] = {}
		return
	}
	// Consecutive means inside the window: a slot whose own has run out is a
	// count that expired with it, and this reply is the first of the next one.
	strikes := 1
	if s.apex_memo.slots[victim].name == apex && time.diff(now, s.apex_memo.slots[victim].until) > 0 {
		strikes = s.apex_memo.slots[victim].strikes + 1
	}
	s.apex_memo.slots[victim] = {
		name    = apex,
		until   = time.time_add(now, upstream.COOLDOWN),
		strikes = strikes,
	}
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
