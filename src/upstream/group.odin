package upstream

import "core:mem"
import "core:slice"
import "core:sync"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"
import "elodin:pool"

/*
A set of upstreams plus the policy for choosing between them.

  Failover     ask each server in configured order until one answers
  Round_Robin  the same, but the starting position advances per query
  Race         ask every healthy server at once and take the first answer
*/
Group :: struct {
	servers:    []^Upstream,
	strategy:   config.Strategy,
	timeout:    time.Duration,
	attempts:   int,
	cursor:     u64,
	race_pool:  ^pool.Pool,
	allocator:  mem.Allocator,
}

make_group :: proc(
	cfg: config.Upstream_Config,
	race_pool: ^pool.Pool,
	allocator := context.allocator,
	// Whether plain upstreams are asked with a DNS cookie; see upstream/cookie.odin.
	cookies := false,
) -> (
	g: ^Group,
	err: Error,
) {
	g = new(Group, allocator)
	g.strategy = cfg.strategy
	g.timeout = cfg.timeout
	g.attempts = max(cfg.attempts, 1)
	g.race_pool = race_pool
	g.allocator = allocator

	servers := make([dynamic]^Upstream, 0, len(cfg.servers), allocator)
	for spec in cfg.servers {
		u, uerr := make_upstream(spec, cfg.max_idle, cfg.idle_timeout, allocator, cookies)
		if uerr != .None {
			logx.errorf("upstream %s: not usable (%v)", spec.name, uerr)
			continue
		}
		append(&servers, u)
	}
	if len(servers) == 0 {
		return nil, .Not_Resolved
	}
	g.servers = servers[:]
	return g, .None
}

destroy_group :: proc(g: ^Group) {
	if g == nil {
		return
	}
	for u in g.servers {
		destroy(u)
	}
	delete(g.servers, g.allocator)
	free(g, g.allocator)
}

/*
Resolve `query` through the group.

Returns the upstream response bytes, allocated from `allocator`, along with the
upstream that produced them for logging.
*/
resolve :: proc(
	g: ^Group,
	query: []u8,
	allocator := context.allocator,
	/*
	Where non-nil, every member this call asked and could not reach is appended.
	`resolve_insisting` reads it so its sweep does not spend another `g.timeout`
	on a server that has just proved silent; see there.

	Filled by the sequential paths, which learn of a failure by waiting for it.
	A race of two or more fills nothing: it returns the moment the first member
	answers, and the member that is not there says so only at the end of its own
	timeout, long after - so at the point this returns there is nothing true to
	report. That is the strategy `resolve_insisting` already names as the one
	paying most for a sweep, and the fix for it is the same one sketched there:
	take the first *acceptable* reply inside the race.
	*/
	unreachable: ^[dynamic]^Upstream = nil,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	switch g.strategy {
	case .Race:
		return resolve_race(g, query, allocator, unreachable)
	case .Round_Robin:
		start := int(sync.atomic_add(&g.cursor, 1) % u64(len(g.servers)))
		return resolve_sequential(g, query, start, allocator, unreachable)
	case .Failover:
		return resolve_sequential(g, query, 0, allocator, unreachable)
	}
	return nil, nil, .IO_Error
}

/*
Resolve `query`, insisting on a reply that says something about the name.

`resolve` hands back whatever the first upstream to reply said, and SERVFAIL is
a reply: `exchange` reads the rcode only for BADCOOKIE, so a server answering
"I could not" ends a search that a server which could would have finished. For
a client's own question that is right - the rcode is the answer, and passing it
on is honest. For a lookup this server makes on its own account, walking the
DNSSEC chain, it is not. NOERROR and NXDOMAIN are the only rcodes that say
anything about a delegation; anything else leaves the chain unestablished, and
an unestablished chain is a SERVFAIL for a name that may be perfectly good.

The ordinary path is untouched: an answerable reply returns from the first
exchange and none of the sweep runs. Where nobody in the group can manage one
the first reply comes back as it stands, rcode and all, for the caller to read
and decide on - see `resolve_insisting`, which is the sweep both of these are.
*/
resolve_answerable :: proc(
	g: ^Group,
	query: []u8,
	allocator := context.allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	return resolve_insisting(g, query, answerable, allocator)
}

/*
Resolve `query`, insisting on a reply the client's own question can be answered
with: an rcode it can read, and one that says something about the name.

`dns.peek_rcode` composes twelve bits - the header's four, and eight more out of
the OPT record's TTL (RFC 6891 section 6.1.3). A stub reads the four. So an
extended rcode reaches the client as a different rcode entirely, and where its
low nibble is zero it reaches it as a plausible one: BADVERS is 16, so a client
handed that reply sees NOERROR over an empty answer section, which is a NODATA.
The upstream said "not in that EDNS version"; the client is told the name has no
such record. A DANE or MTA-STS client that believes it downgrades.

Which makes it neither a reply to pass on nor a verdict about the name: it is a
server declining the transport this one asked in. elodin only ever sends EDNS
version 0, which every EDNS implementation is required to support, so a BADVERS
in answer to one is that server violating the protocol rather than saying
anything about the question. The rest of the group is asked, the way a chain
lookup asks past a server that would not answer it.

SERVFAIL and REFUSED are swept past for a plainer reason: neither is an answer
about the name. RFC 2308 section 7.1 reads SERVFAIL as the responder reporting
on itself, and REFUSED is it declining to be asked at all - policy, or an ACL
that no longer lists this server. A failover group exists so that one member can
be in that state, and before issue #309 it did not help: `record_failure` counts
transport failures, so a member that answers REFUSED to everything, promptly and
forever, is never parked and every client query stopped at it while the member
beside it held the answer. dnsmasq, Unbound and BIND all move to the next server
on these two.

The ordinary path is untouched: a usable reply returns from the first exchange
and none of the sweep runs. Where no member of the group can manage one the
first reply still comes back, rcode and all - which is what a group of one, the
ordinary deployment, gets for every SERVFAIL its upstream states.
`resolve_query` reads it and decides, because turning one reply into another is
no more this procedure's business here than it is below.
*/
resolve_readable :: proc(
	g: ^Group,
	query: []u8,
	allocator := context.allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	return resolve_insisting(g, query, usable_rcode, allocator)
}

/*
Ask the group, and sweep it once when what came back is not a reply `acceptable`
will have.

The two callers above differ only in what they will take - a chain lookup wants
a reply that says something about the name, a client's own question wants one
whose rcode the client can read - and everything else about the sweep is common
to both, so it is written once here.

Transport failures are deliberately not retried: `resolve` has already exhausted
them, every server for `attempts` rounds. What it leaves unretried is the reply
that did arrive and was no use, so that is what this asks again.
*/
@(private)
resolve_insisting :: proc(
	g: ^Group,
	query: []u8,
	acceptable: proc(response: []u8) -> bool,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	// Scratch, on the request's own thread, whose arena the caller resets - and
	// only ever as long as the group.
	// No capacity asked for: the fast path is a first reply the caller can use,
	// where nothing is ever appended and this stays an empty header.
	unreachable: [dynamic]^Upstream
	unreachable.allocator = context.temp_allocator

	response, winner, err = resolve(g, query, allocator, &unreachable)
	if err != .None || acceptable(response) {
		return response, winner, err
	}

	/*
	One pass, and the server that already spoke is skipped: it gave its answer
	and asking it again gets the same one. That bounds the sweep by the server
	count. A chain walk calling this is itself bounded by
	MAX_LOOKUPS_PER_QUERY, and a client's own question reaches it once, so no
	client can turn one question into an unbounded fan-out.

	Health is left alone where the rcode is concerned, on purpose. SERVFAIL is a
	legitimate answer to plenty of questions, and a server that gives one has not
	failed in the sense `record_failure` tracks - it answered, promptly, and it
	keeps its place at the head of the failover order. What parking it would cost
	is a member the group no longer has when the next one times out.

	The sweep's own cost is worth stating plainly, because SERVFAIL is a far more
	common reply than the unreadable rcode this was first written for. A group of
	two pays one extra exchange for a name its first member cannot answer. A
	group of three or more pays up to one per remaining member, and a member that
	is unreachable but has not yet accrued its three failures - a fresh start, or
	the ten seconds after a cooldown expired - costs `g.timeout` of that on the
	client's own latency path before the next is tried. The same arithmetic
	applies to upstream traffic: a client asking names that SERVFAIL turns each
	of its queries into up to one exchange per member of the group. Both are the
	price of the group having somewhere else to go, and both were already the
	arrangement for the rcodes above; what issue #309 changed is how often it is
	reached.

	An unreadable rcode is left alone for a sharper reason: those eight bits are
	two bytes an on-path attacker can write into any reply it can reach. Counting
	them as a failure would let it park a healthy upstream, and then every member
	of the group in turn, from one forged packet per query - which is a worse
	outage than the answer this sweeps past.

	A server already in its cooldown is another matter, and is skipped. It is
	there because its own exchanges timed out three times over, so what asking it
	again buys is `g.timeout` of waiting per parked member before this returns -
	and the callers cannot afford it. A chain walk pays that at every step of a
	descent bounded by `MAX_LOOKUPS_PER_QUERY`, and `resolve_query` puts a
	client's own apex `DS` through here, where a validating stub gives up in two
	to five seconds. `resolve_sequential`'s first round skips parked servers for
	the same reason, and its second round tries them anyway because it has
	nothing else to offer; this has the rest of the group.

	A group whose every member is parked therefore sweeps nobody, and the first
	reply stands - which is the same answer as before for a group that has
	nothing to give, reached without the wait.

	Under `strategy: race` the sweep asks members the race has already asked in
	parallel, and whose replies `resolve_race` threw away once it had a winner.
	That is real duplicated work - up to one sequential exchange per remaining
	member, at `g.timeout` each where they do not answer - and it is still the
	right trade here: the reply that won the race is one the caller cannot use,
	and the answer another member gave microseconds later is the client's answer
	rather than a SERVFAIL. Taking the first *acceptable* reply inside the race
	instead would spend nothing at all, and wants its own change: it means
	teaching `Race_State` to keep a reply it will not return yet, on the one
	path where a worker can outlive the caller.

	Since #309 that cost is worth reading twice, because a racing group has a
	way of paying it on every query. `resolve_race` returns the first reply to
	arrive whatever its rcode, and the member that REFUSES this server on an ACL
	is the member that answers in microseconds - so it wins the race essentially
	always, and the sweep runs behind every race rather than behind the rare
	unreadable rcode this was written for. A racing group with a member in that
	state is a group running at up to two exchanges per member per query, with
	the client waiting on the sequential half. `strategy: failover` pays one
	exchange for it instead, and the upgrade path above is what would fix it in
	place.

	What bounds it meanwhile is the rule below: the sweep stops at the first
	member it cannot reach, so it spends at most one `g.timeout` waiting however
	many members are left. What a racing group pays is therefore duplicated
	exchanges rather than waiting - its members are there and answer, they simply
	answer the same unusable thing.
	*/
	/*
	Counted here, against the member whose reply sent the group looking, and
	once per such reply rather than once per exchange the sweep then makes.

	Before where the sweep succeeds, and before knowing whether it will ask
	anybody at all, because the question the figure answers is which member is
	answering what its group cannot use - and the arrangement that most needs an
	answer to it is the one where the sweep finds nowhere to go: a member
	REFUSING everything beside a member in its cooldown breaks every query this
	server takes, while `failures` and `up` both report it well. What the sweep
	spends is a different question, and `elodin_upstream_queries_total` per
	member is where it is already answered.
	*/
	note_swept_rcode(winner)

	/*
	And the sweep stops at the first member it cannot reach at all.

	Which is what bounds it. Asking every remaining member at the full timeout
	is a group of four spending three of them - fifteen seconds as elodin ships
	- to hand back the reply it had in the first millisecond, holding one of a
	bounded set of query workers for the whole wait; a client repeating one such
	name is then a way to empty the pool. Stopping at the first silence caps the
	whole sweep at one timeout however many members are left.

	Not by dividing the timeout between them, which was tried and taken back
	out. `exchange` counts a timeout as a failure, so a member cut off by a
	share it would have answered inside gets `record_failure` for being asked
	impatiently, and three of those park the spare this whole change exists to
	keep. The wait is what must be bounded; what a member is judged on has to go
	on being the group's own timeout.

	What it costs is a live spare standing behind a dead one: the dead one is
	asked first, the sweep stops there, and the client gets the reply in hand.
	That is three queries long. Each of those exchanges is a real failure at the
	real timeout, so the dead member parks, the sweep skips it from then on and
	reaches the live one - and after each cooldown expiry one query pays for it
	again, which is the arrangement every other part of this file already makes.
	*/
	for u in g.servers {
		if u == winner {
			continue
		}
		/*
		And a server this very call already failed to reach is skipped too,
		which the cooldown above does not cover: three consecutive failures is
		what parks a server, so the first two cost `g.timeout` each and leave it
		`healthy`. Without this, a group of one unreachable member and one that
		answers REFUSED pays that timeout twice for one question - once in
		`resolve`, once more here - to be handed the same REFUSED, which is a
		second `timeout` added to a query that took one before issue #309.

		Only what this call proved. A failure from a minute ago is somebody
		else's news and the member goes on being asked, because a group whose
		second member is reached only when the first breaks would otherwise
		carry a stale failure for as long as the first one holds.

		Under `strategy: race` this list is empty for a group of two or more, so
		the saving is the sequential strategies'. `resolve` says why: the race
		is over before a dead member has finished not answering.
		*/
		if slice.contains(unreachable[:], u) {
			logx.debugf("upstream %s did not answer this query, not asked again for it", u.spec.name)
			continue
		}
		if !healthy(u) {
			logx.debugf("upstream %s is in its cooldown, not asked again for this one", u.spec.name)
			continue
		}
		resp, xerr := exchange(u, sweep_query(query), g.timeout, allocator)
		if xerr != .None {
			logx.debugf("upstream %s failed: %v, ending the sweep for this query", u.spec.name, xerr)
			break
		}
		if acceptable(resp) {
			// Said here rather than above, because what makes a filtering
			// member's block bypassed is another member *answering* - a second
			// REFUSED from behind the same ACL bypasses nothing, and warning
			// about it would spend the one-shot line on it.
			report_swept_refusal(winner, response)
			// The rcode as a number: 4080 of the 4096 composed values have no
			// name, and `%v` renders one of those as a placeholder - the same
			// reading `unreadable_rcode_refusal` gives its own line.
			logx.debugf(
				"upstream %s answered rcode %d, swept past it to %s",
				winner.spec.name,
				u16(dns.peek_rcode(response)),
				u.spec.name,
			)
			// The first reply is superseded. It came from the caller's
			// allocator, which is an arena per request on the query path,
			// where this is a no-op; it matters where one is not.
			_ = delete(response, allocator)
			return resp, u, .None
		}
		_ = delete(resp, allocator)
	}

	// Nobody could answer. The first reply stands, rcode and all: the caller
	// reads it and decides, and turning one verdict into another is not this
	// procedure's business.
	return response, winner, .None
}

// The two rcodes that say something about the name that was asked for. The
// same test `dnssec.answerable_rcode` makes, over the wire bytes this package
// deals in rather than a decoded message.
@(private)
answerable :: proc(response: []u8) -> bool {
	#partial switch dns.peek_rcode(response) {
	case .No_Error, .NX_Domain:
		return true
	}
	return false
}

/*
The query as it goes to the next server in the sweep: the same bytes under a
transaction ID of its own.

RFC 5452 section 9.2, and the same reasoning `resolve_query` gives for drawing a
fresh ID before its second exchange - each exchange is a new one on the wire. It
matters more here than there. What triggers this sweep is a reply, so the server
that sent the first one chooses the moment: an upstream that is hostile, or one
whose traffic an attacker can read, answers with something the caller cannot use
and thereby induces a second query for the same name to another member of the
group - carrying, if the ID went unchanged, the ID it has just been told. That
leaves only the fresh source port between an off-path forgery and an answer this
server would cache for every client behind it. `cookie_matches` does not cover
the gap either: a reply with no COOKIE option is accepted from an upstream that
has never issued one, which is what a spoofed datagram would send.

A copy, because `query` is the caller's buffer and is sent again after this
returns - `resolve_query` re-sends it to the route, and `attach_cookie` reads it
per upstream. Scratch space, as `exchange` itself uses for the cookie copy: the
sweep runs on the request's own thread, whose arena the caller resets.

A message too short to hold a header is handed on untouched. `exchange` is where
that is refused; inventing bytes for it here would only hide it.
*/
@(private)
sweep_query :: proc(query: []u8) -> []u8 {
	if len(query) < dns.HEADER_SIZE {
		return query
	}
	out := make([]u8, len(query), context.temp_allocator)
	copy(out, query)
	dns.set_id_in_place(out, dns.random_id())
	return out
}

/*
The RFC 8914 extended errors that make a SERVFAIL a statement about the name
rather than about the server: every one of them says the data for this name
could not be made to verify.

Which is the exception to the paragraph below, and the sharper half of what
`usable_rcode` decides. A validating upstream that has found a zone bogus
answers SERVFAIL; sweeping past it asks the next member of the group, and if
that one does not validate, what comes back is the forgery - cached here, and
served to every client behind this server. An extended error is how the first
member says which of the two SERVFAILs it meant, so where there is one, it is
taken at its word.

How far that reaches is worth stating exactly, because it is less than the whole
of the case. Cloudflare and Google attach these, and so does PowerDNS Recursor
from 5.0, where it is on by default. Unbound has them from 1.16 but `ede:`
defaults to `no`. BIND 9.18 shipped only codes 3, 18 and 19 - none of them these
- with the DNSSEC ones arriving later. dnsmasq sends none at all. So a bogus
SERVFAIL from an upstream in its default configuration may well carry nothing to
read, and this check will let the sweep go on.

Which is why it is a second line rather than the defence. `dnssec.enabled` is on
as elodin ships, and with it on two things are true at once: the question goes
out with CD set, so a validating upstream hands over the bogus data rather than
a SERVFAIL and there is no extended error to read at all, and `validate` refuses
that data here whichever member of the group supplied it. What this covers is
the deployment that turned validation off and left a mixed group behind - and it
covers as much of it as the upstream is willing to say.

With validation off the question goes out as the client wrote it, which adds a
precondition of its own: a client that asked without EDNS gets a reply that
cannot legally carry an OPT record, so it cannot carry an extended error either,
and the sweep goes on. A stub that asks with EDNS - which most resolvers and
every DNSSEC-aware client do - is what this can protect.

Only the first extended error in a reply is read, which is what
`peek_edns_option` returns. RFC 8914 section 2 permits several, and a reply
whose validation code is not the first would be swept past - the same outcome as
the far more common reply that carries no extended error at all, and no worse
than it.

Codes 6 to 12 of RFC 8914 section 4 - bogus, the two signature-validity ones,
DNSKEY and RRSIG missing, the zone key bit, NSEC missing. Not 0 (`Other`), which
carries no such claim, and not the policy codes: a REFUSED or a SERVFAIL over an
ACL is exactly what the sweep is for.

The cost of believing any of them is that a validator which is itself broken
holds the group. A member whose clock has drifted says Signature Expired about
every signed name it is asked; one carrying a stale root key says DNSSEC Bogus
about them just as widely. Either pins this server on that member for those
names and no failover happens - issue #309's own failure, for the subset of
names that are signed, and a quiet one: the reply is accepted rather than swept,
so `note_swept_rcode` is not called and nothing in the metrics names the member.
What an operator has then is the SERVFAILs their clients report and a group whose
every figure looks well, which is where #309 started. The two cannot be told
apart from here: a validator that
has found a zone bogus and a validator that is wrong about every zone send the
same bytes, and reading the claim is the only way to protect the client that
this does not cover otherwise. So it stands, with the remedy being the
`dnssec.enabled` that is on by default - where elodin decides this for itself -
or an operator taking the broken member out of the group. Narrowing the set to
code 6 alone would not change the shape, only which broken validator does it.
*/
@(private)
BOGUS_EDE_FIRST :: 6
@(private)
BOGUS_EDE_LAST :: 12

/*
And the extended errors that make a REFUSED a statement about the name: 15
(Blocked), 16 (Censored) and 17 (Filtered) of RFC 8914 section 4. Each one says
the responder holds an answer and will not give it *for this name* - an internal
blocklist, an external requirement, or a list the client itself asked for.

Which is a policy about the question rather than a report about the server, so
it is the client's answer and the group is not swept. It is also the one thing
that keeps a filtering resolver usable as a member of a group: elodin in front
of AdGuard Home, Blocky or an RPZ rule that blocks with REFUSED, with a public
resolver beside it for everything else, would otherwise have every blocked name
re-asked of the public one and answered.

Not 18 (Prohibited), which is the opposite case and the one the sweep is for:
that is the responder declining *this client* - an ACL that no longer lists this
server - and it says nothing about the name at all.

Believing it costs what believing the SERVFAIL codes costs, and in the same
quiet way: a filtering member whose blocklist has gone wrong, or one that says
Blocked where it means Prohibited, states this about every name and is taken at
its word, so the group is pinned on it while `failures` stays at zero, `up` at
one and `swept_rcode` at zero - the reply was accepted rather than swept, so
nothing counts it. What an operator has is clients being refused everything and
a group whose figures all look well. The remedy is the same: the member that is
refusing is named in its own logs, and an upstream meant to filter belongs on
its own rather than in a group.
*/
@(private)
POLICY_EDE_FIRST :: 15
@(private)
POLICY_EDE_LAST :: 17

/*
Whether a reply is one the client's own question can be answered with.

Two ways it is not, and `resolve_readable` argues both.

An rcode of 16 or above, because the rcode a client reads off the header is then
not the rcode the responder meant - the upper eight bits live in the OPT
record's TTL, which a stub does not look at. A reply too short to hold a header,
or one carrying no OPT record, reads as its header's own four bits, which is
what `peek_rcode` returns for both.

SERVFAIL or REFUSED, because neither says anything about the name asked for
(RFC 2308 section 7.1): the first is the responder reporting on itself and the
second is it declining to be asked, and the next member of the group may well
know the answer. Unless the reply says otherwise in an extended error - a
validation failure behind the SERVFAIL (`BOGUS_EDE_FIRST`) or a blocklist behind
the REFUSED (`POLICY_EDE_FIRST`), each of which is about the name after all.
Every other rcode a stub can read is a statement about the name and stands as
the client's answer.
*/
@(private)
usable_rcode :: proc(response: []u8) -> bool {
	rcode := dns.peek_rcode(response)
	#partial switch rcode {
	case .Serv_Fail:
		return extended_error_within(response, BOGUS_EDE_FIRST, BOGUS_EDE_LAST)
	case .Refused:
		return extended_error_within(response, POLICY_EDE_FIRST, POLICY_EDE_LAST)
	}
	return u16(rcode) <= 0xf
}

/*
Say once, at warn, that a REFUSED carrying no policy extended error was swept.

The one deployment this change can quietly break: a filtering resolver as a
member of a group - AdGuard Home in its REFUSED blocking mode, Blocky, an RPZ
rule - beside a public resolver for everything else. A blocked name is now
re-asked of the member beside it and answered, and where the filtering member
says why it refused (`POLICY_EDE_FIRST`) that does not happen; where it says
nothing, which is most of them today, it does. An operator's first sign would
otherwise be the ads coming back.

Once per process and at debug after that, the shape `unreadable_rcode_refusal`
uses and for the same reason: the line names bytes an upstream chose, so a
per-query warn would let one decide how much this server writes to disk.

Only REFUSED. A swept SERVFAIL is the ordinary business of this sweep - a name
whose authority is down produces them all day - and warning about those would
bury the one line that means something.
*/
@(private)
refusal_reported: bool

@(private)
report_swept_refusal :: proc(u: ^Upstream, response: []u8) {
	if dns.peek_rcode(response) != .Refused {
		return
	}
	if sync.atomic_exchange(&refusal_reported, true) {
		logx.debugf("upstream %s refused this name without saying why; another member answered it", u.spec.name)
		return
	}
	logx.warnf(
		"upstream %s refused a name without an extended error saying why, and another member of its group answered it: if %s is a filtering resolver, its blocks are being asked elsewhere - see elodin_upstream_swept_rcode_total",
		u.spec.name,
		u.spec.name,
	)
}

// Whether the reply carries an RFC 8914 extended error between `first` and
// `last`, which is how both exceptions above are read. A reply with no OPT
// record, no extended error, or an option too short to hold the two-byte
// info-code makes no such claim.
@(private)
extended_error_within :: proc(response: []u8, first, last: u16) -> bool {
	data, found := dns.peek_edns_option(response, .Ext_Error)
	if !found || len(data) < 2 {
		return false
	}
	info := u16(data[0]) << 8 | u16(data[1])
	return first <= info && info <= last
}

@(private)
resolve_sequential :: proc(
	g: ^Group,
	query: []u8,
	start: int,
	allocator: mem.Allocator,
	unreachable: ^[dynamic]^Upstream = nil,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	last_err := Error.Unhealthy

	for round in 0 ..< g.attempts {
		// The first pass skips upstreams in cooldown; a later pass takes them
		// anyway, so a total outage still gets one honest try per server.
		skip_unhealthy := round == 0
		for offset in 0 ..< len(g.servers) {
			u := g.servers[(start + offset) % len(g.servers)]
			if skip_unhealthy && !healthy(u) {
				continue
			}
			resp, xerr := exchange(u, query, g.timeout, allocator)
			if xerr == .None {
				return resp, u, .None
			}
			last_err = xerr
			if unreachable != nil {
				append(unreachable, u)
			}
			logx.debugf("upstream %s failed: %v", u.spec.name, xerr)
		}
	}
	return nil, nil, last_err
}

/*
Racing state, shared between the caller and the workers it spawned.

Everything a worker touches is heap-allocated and reference counted. A worker
can outlive the caller — the caller gives up at the group timeout while a
worker sits in its own socket timeout — so nothing here may live in the
caller's per-request arena, including the query bytes and the response buffers.
The last reference to leave frees the block.
*/
@(private)
Race_State :: struct {
	mu:          sync.Mutex,
	sema:        sync.Sema,
	refs:        int,
	// Set once a winner is recorded; later arrivals discard their answers.
	done:        bool,
	outstanding: int,
	response:    []u8,
	winner:      ^Upstream,
	last_err:    Error,
	query:       []u8,
	timeout:     time.Duration,
	jobs:        []Race_Job,
}

@(private)
Race_Job :: struct {
	upstream: ^Upstream,
	state:    ^Race_State,
}

@(private)
race_state_release :: proc(st: ^Race_State) {
	sync.mutex_lock(&st.mu)
	st.refs -= 1
	should_free := st.refs == 0
	sync.mutex_unlock(&st.mu)
	if !should_free {
		return
	}
	if st.response != nil {
		delete(st.response)
	}
	delete(st.query)
	delete(st.jobs)
	free(st)
}

@(private)
race_worker :: proc(data: rawptr) {
	// A race-pool worker runs for the life of the process and `exchange` below
	// takes scratch space for every query it makes. Nothing else resets this
	// thread's arena, and the arena chains a new block rather than reusing the
	// old one, so without this it grows for as long as the server runs.
	defer free_all(context.temp_allocator)

	job := cast(^Race_Job)data
	st := job.state

	// Responses go on the heap: the caller's arena may already be gone.
	resp, err := exchange(job.upstream, st.query, st.timeout, context.allocator)

	sync.mutex_lock(&st.mu)
	won := false
	if err == .None && !st.done {
		st.done = true
		st.response = resp
		st.winner = job.upstream
		won = true
	} else if err != .None {
		st.last_err = err
	}
	st.outstanding -= 1
	last_one := st.outstanding == 0
	sync.mutex_unlock(&st.mu)

	if err == .None && !won {
		delete(resp)
	}
	if won || last_one {
		sync.sema_post(&st.sema)
	}
	race_state_release(st)
}

@(private)
resolve_race :: proc(
	g: ^Group,
	query: []u8,
	allocator: mem.Allocator,
	unreachable: ^[dynamic]^Upstream = nil,
) -> (
	response: []u8,
	winner: ^Upstream,
	err: Error,
) {
	candidates := make([dynamic]^Upstream, 0, len(g.servers), context.temp_allocator)
	for u in g.servers {
		if healthy(u) {
			append(&candidates, u)
		}
	}
	if len(candidates) == 0 {
		for u in g.servers {
			append(&candidates, u)
		}
	}
	if len(candidates) == 1 {
		resp, xerr := exchange(candidates[0], query, g.timeout, allocator)
		return resp, candidates[0], xerr
	}

	st := new(Race_State)
	st.refs = 1
	st.last_err = .Timeout
	st.timeout = g.timeout
	st.query = make([]u8, len(query))
	copy(st.query, query)
	st.jobs = make([]Race_Job, len(candidates))
	defer race_state_release(st)

	submitted := 0
	for u, i in candidates {
		st.jobs[i] = Race_Job {
			upstream = u,
			state    = st,
		}
		sync.mutex_lock(&st.mu)
		st.refs += 1
		st.outstanding += 1
		sync.mutex_unlock(&st.mu)

		if !pool.submit(g.race_pool, race_worker, &st.jobs[i]) {
			// The pool is shutting down; undo this leg's bookkeeping.
			sync.mutex_lock(&st.mu)
			st.refs -= 1
			st.outstanding -= 1
			sync.mutex_unlock(&st.mu)
			continue
		}
		submitted += 1
	}
	if submitted == 0 {
		return resolve_sequential(g, query, 0, allocator, unreachable)
	}

	if !sync.sema_wait_with_timeout(&st.sema, g.timeout) {
		// Nobody answered in time. Workers still running will see `done` and
		// throw their answers away rather than writing into a dead frame.
		sync.mutex_lock(&st.mu)
		st.done = true
		sync.mutex_unlock(&st.mu)
		return nil, nil, .Timeout
	}

	sync.mutex_lock(&st.mu)
	defer sync.mutex_unlock(&st.mu)
	if st.response == nil {
		return nil, nil, st.last_err
	}
	// Hand the caller a copy in its own allocator; the shared buffer is freed
	// with the state once the last worker has let go of it.
	out := make([]u8, len(st.response), allocator)
	copy(out, st.response)
	return out, st.winner, .None
}

// Close idle connections that have been sitting around too long.
groom :: proc(g: ^Group) -> (closed: int) {
	for u in g.servers {
		closed += close_idle(u)
	}
	return
}
