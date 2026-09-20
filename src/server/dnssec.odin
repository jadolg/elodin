package server

import "core:mem"
import "core:sync"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:logx"
import "elodin:upstream"

/*
DNSSEC validation, from the resolver's side.

Two things change once validation is on. Queries go upstream with DO and CD set,
because the validator needs the signatures and wants to reach its own verdict
rather than inherit the upstream's. And the answer is no longer handed back
untouched: a bogus one becomes SERVFAIL, a good one may gain the AD bit, and a
client that never asked for DNSSEC records has them taken back out.
*/

// Extended DNS error codes, RFC 8914. Sent only to clients that use EDNS0,
// which is the only place there is to put them.
EDE_DNSSEC_BOGUS :: 6
EDE_NO_REACHABLE_AUTHORITY :: 22
EDE_UNSUPPORTED_NSEC3_ITERATIONS :: 27

/*
Build the validator and wire it to the upstream group.

Returns false when a configured trust anchor cannot be read, which is worth
refusing to start over: an anchor nobody can parse is an anchor nobody is
validating against.
*/
start_validator :: proc(s: ^Server) -> bool {
	if !s.cfg.dnssec.enabled {
		return true
	}

	/*
	Before anything is validated, and before the line below reports what we are
	validating against: this asks the linked libcrypto which algorithms it will
	actually run, and it is where an operator on a host whose crypto policy
	rules one out finds that out - as a warning at start-up, rather than as a
	zone that is insecure here and secure everywhere else.
	*/
	dnssec.probe_algorithms()

	anchors: []dnssec.Trust_Anchor
	if len(s.cfg.dnssec.trust_anchors) > 0 {
		parsed := make([dynamic]dnssec.Trust_Anchor, 0, len(s.cfg.dnssec.trust_anchors))
		for line in s.cfg.dnssec.trust_anchors {
			anchor, ok := dnssec.parse_trust_anchor(line)
			if !ok {
				logx.errorf("dnssec: cannot read trust anchor %q", line)
				// The ones before it parsed, and this is where they stop being
				// anybody's: the server is refusing to start, so `stop_validator`
				// never runs to release them.
				for done in parsed {
					dnssec.destroy_trust_anchor(done)
				}
				delete(parsed)
				return false
			}
			append(&parsed, anchor)
		}
		anchors = parsed[:]
		s.anchors = anchors

		// An operator who anchors a zone below the root is asking for that zone
		// to be validated, so the locally-served bypass must step aside for a
		// name it covers. The root anchor is not one of these: it covers every
		// name yet cannot validate the AS112 zones the bypass exists for, which
		// is the whole reason the bypass is there.
		zones := make([dynamic]string, 0, len(parsed))
		for anchor in parsed {
			if anchor.zone != "." {
				append(&zones, anchor.zone)
			}
		}
		s.anchor_zones = zones[:]
	}

	/*
	And refused to start on, for the reason an anchor that will not parse is: an
	anchor naming an algorithm the library will not run anchors nothing, so the
	zone it covers is an insecure delegation the moment it is asked about.

	The root is the zone that decides. Every chain starts there - `zone_trust`
	asks for the root's keys and walks down through DS records - so a set that
	cannot seed the root seeds nothing, whatever else is in it.

	The two ways of failing that fail differently, which is why they are told
	apart below. An anchor for the root whose algorithm the library will not run
	leaves `fetch_keys` with nothing checkable, so the root is insecure and
	every answer goes out unvalidated: no AD bit anywhere and no SERVFAIL
	either, which is the failure a validating resolver exists to not have. No
	root anchor at all leaves `zone_keys` with nothing to match, which is
	`Indeterminate` and SERVFAILs every name instead. Neither is a server worth
	starting; an operator who does want unvalidated answers has
	`dnssec.enabled: false` to ask for them with.
	*/
	in_use := anchors if len(anchors) > 0 else dnssec.root_anchors()
	if !dnssec.usable_anchor(in_use, ".") {
		if dnssec.anchors_the_root(in_use) {
			logx.errorf("dnssec: no trust anchor for the root names an algorithm and digest this build can check")
			logx.errorf("dnssec: nothing would be validated; check the host crypto policy, or set dnssec.enabled: false")
		} else {
			logx.errorf("dnssec: no trust anchor covers the root, which is where every chain of trust starts")
			logx.errorf("dnssec: every name would fail to validate; anchor `.` as well, or set dnssec.enabled: false")
		}
		// The validator is still nil, and `destroy_validator` takes that; what
		// this is here for is the anchors parsed above, which the refusal to
		// start would otherwise leave behind.
		stop_validator(s)
		return false
	}

	/*
	A number that leaves no reservation is the bound switched off, and #356 with
	it: the walks are what hold the workers, so allowing as many walks as there
	are workers allows a client to hold all of them.

	Only for a figure somebody wrote. On a one-worker configuration the
	derivation has nowhere to reserve from and returns one, and a server warning
	about the number it chose for itself is a warning nobody can act on or
	silence.

	Said rather than refused or held down, which is this file's rule for a
	configured number everywhere else: an operator who names a figure gets it. A
	resolver that will not start, or one quietly running at a number nobody
	chose, is worse than one that says what it is doing. The comparison is
	against the handler pool because that is what the bound protects - see
	`handle_query`'s `shared_worker`.
	*/
	if !s.cfg.server.sizing.derived_chain_walks && s.cfg.dnssec.max_chain_walks >= s.cfg.server.workers {
		logx.warnf(
			"dnssec: max_chain_walks %d leaves none of the %d workers reserved, so a flood of fresh names can hold them all; see issue #356",
			s.cfg.dnssec.max_chain_walks,
			s.cfg.server.workers,
		)
	}
	// The same for the other pool, and said the same way. A bound that allows as
	// many walks as there are connection threads is that bound switched off, and
	// nothing else in the configuration would tell an operator so.
	if !s.cfg.server.sizing.derived_connection_walks &&
	   s.cfg.dnssec.max_connection_walks >= s.cfg.server.max_connections {
		logx.warnf(
			"dnssec: max_connection_walks %d leaves none of the %d connection threads reserved, so a flood of fresh names can hold them all; see issue #356",
			s.cfg.dnssec.max_connection_walks,
			s.cfg.server.max_connections,
		)
	}

	s.validator = dnssec.make_validator(
		validator_query,
		s,
		dnssec.Options {
			anchors = anchors,
			max_nsec3_iterations = s.cfg.dnssec.max_nsec3_iterations,
			max_chain_walks = s.cfg.dnssec.max_chain_walks,
			// The connection transports get their own, sized from the threads
			// they actually have. See `Dnssec_Config.max_connection_walks`.
			max_connection_walks = s.cfg.dnssec.max_connection_walks,
		},
	)
	// The bound is named here because it is the number an operator watching
	// `elodin_dnssec_queries_shed_total` rise is being told to raise, and
	// `config.derive_chain_walks` usually picked it rather than the file. Read
	// back off the validator rather than off the configuration: a validator
	// built from a configuration that never went through `config.validate` -
	// which is every one the tests assemble by hand - substitutes its own
	// default, and a log line naming a number nothing is using is worse than no
	// line at all.
	logx.infof(
		"dnssec: validating against %d trust anchor(s), at most %d chain walks upstream at once on the handler pool and %d on connection threads",
		len(anchors) if len(anchors) > 0 else len(dnssec.root_anchors()),
		dnssec.chain_walk_limit(s.validator, .Shared),
		dnssec.chain_walk_limit(s.validator, .Connection),
	)
	return true
}

/*
Tear the validator down, and release the anchors it was validating against.

The anchors are not the validator's to free - it borrows the slice, and an
unconfigured one borrows `dnssec.root_anchors`, which is static - so
`destroy_validator` leaves them alone and this is where the ones
`start_validator` parsed go. Nothing here runs for the built-in anchors, which
never filled `s.anchors` in the first place.
*/
stop_validator :: proc(s: ^Server) {
	dnssec.destroy_validator(s.validator)
	s.validator = nil

	for anchor in s.anchors {
		dnssec.destroy_trust_anchor(anchor)
	}
	delete(s.anchors)
	s.anchors = nil
	// Only the slice: the strings in it are the anchors' own `zone` fields,
	// released just above.
	delete(s.anchor_zones)
	s.anchor_zones = nil
}

// Drop cached zone keys whose lifetime has run out.
sweep_validator :: proc(s: ^Server) -> int {
	return dnssec.sweep(s.validator)
}

/*
Fetch a DS or DNSKEY set for the validator.

Runs on the handler thread that is already answering a client, so it borrows
that request's arena and blocks on the same upstream group. Racing upstreams
submit to their own pool, so there is no way for this to wait on a worker it is
occupying.

It is still a worker held for a round trip, and a chain walk makes one of these
per label of a name the client chose. What stops a client choosing how many
workers are held that way is `dnssec.max_chain_walks`, which
`config.derive_chain_walks` sets to everything but a reserved quarter of the
pool: that quarter cannot be inside a walk, so it turns over in a round trip
rather than in thirty of them, whatever a flood is doing. Free of the walk
rather than idle - a reserved worker may still be parked on its own upstream
forward, which is not bounded here. A walk past the bound reads the caches and gives up where it would
have called this, which the client sees as the SERVFAIL an unreachable authority
produces.

Not only the flood's own names, and the difference is worth knowing before
setting the number: a walk needs a DS lookup at every label below the deepest
zone it has cached, and it cannot call a zone unsigned without one either - so
while every slot is held, what still answers is what the caches hold, and every
other cold name is SERVFAIL, signed or not.

Which is why only a query on a pool worker spends a slot. The bound is there to
keep these workers free; a question answered on its own connection thread is
bounded by `max_connections` instead and is never turned away. See
`handle_query`'s `shared_worker`, `Validator.walks`, `dnssec.max_chain_walks`
and issue #356.
*/
@(private)
validator_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	s := cast(^Server)ctx

	question := make([]dns.Question, 1, allocator)
	question[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	additional := make([]dns.Record, 1, allocator)
	additional[0] = dns.make_opt(UPSTREAM_UDP_SIZE, true)

	q := dns.Message {
		id         = dns.random_id(),
		question   = question,
		additional = additional,
	}
	q.flags.rd = true
	q.flags.cd = true

	asked, _, err := dns.encode_message(q, allocator)
	if err != .None {
		return nil, false
	}
	/*
	`resolve_answerable` rather than `resolve`: this is a lookup the server
	makes on its own account, and a SERVFAIL from the first upstream to reply
	is not an answer about the delegation - it is one server declining to say.
	Another in the group may know, and if none do the reply still comes back
	for `zone_step` to read the rcode off and call the chain unavailable.

	`s.group` rather than `route_group`, deliberately: no lookup this server makes
	on its own account follows a route, whatever the name or the type. The
	client's own question does follow one, with the single exception `route_group`
	carves out for a `DS` at a route's apex - the same argument as this one
	reached from the other side, and the reason the client's copy of that question
	no longer lands somewhere this one calls wrong. The two are not the same
	selector even so: `route_group` asks the group that answers the *parent*,
	which for a route nested inside another route is that outer route's group
	rather than `s.group`. A chain walk reaching an anchored zone that deep wants
	the public tree, which is what this hands it. The route points at a local
	authority for the zone, and a local authority answers questions about its own
	zone out of its own data: a router authoritative for `home.arpa.` answers
	`home.arpa. DS` with an unsigned NODATA rather than forwarding to `arpa.`,
	where the signed proof that the delegation carries no DS is the only copy
	there is. That answer breaks the chain instead of completing it - the failure
	of issue #194, rebuilt by a different road. The default group is the one that
	can reach the public parent, so the chain walk always goes there. See
	`routes.odin`.

	Nothing is lost by it: a routed zone is served insecure anyway, so the walk
	is not run for its names at all unless the operator anchored the zone, and
	an operator who anchored it wants it checked against their anchor rather
	than against whatever their router says about the public tree.
	*/
	response, _, uerr := upstream.resolve_answerable(s.group, asked, allocator)
	if uerr != .None {
		logx.debugf("dnssec: %s %s could not be fetched: %v", dns.type_name(type), name, uerr)
		return nil, false
	}
	return response, true
}

/*
Re-ask the client's question with DO and CD set.

The client's own EDNS options ride along, but the payload size and the DO bit
are ours. The three an upstream has no business seeing - its cookie, its
client-subnet option and its keepalive request - are taken back out further
down, and its transaction ID replaced, once this and the plain forwarding path
have converged.
*/
@(private)
dnssec_upstream_query :: proc(query: dns.Message, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	out := query
	out.flags.cd = true

	opt := dns.make_opt(UPSTREAM_UDP_SIZE, true)
	if client_opt, had := dns.find_opt(query); had {
		opt.data = client_opt.data
	}

	additional := make([dynamic]dns.Record, 0, len(query.additional) + 1, allocator)
	for rec in query.additional {
		if rec.type != .OPT {
			append(&additional, rec)
		}
	}
	append(&additional, opt)
	out.additional = additional[:]

	encoded, _, err := dns.encode_message(out, allocator)
	return encoded, err == .None
}

/*
Turn a validated upstream answer into the one the client gets.

An answer this server is about to vouch for is first cut down to the records it
actually checked. The verdict covers the RRsets the validator looked at, and a
response carries whatever else its sender chose to put in the authority and
additional sections - so passing those on under an AD bit would lend our name to
a delegation, or an address, that nothing here examined (RFC 4035 section
3.2.3). `dnssec.strip_unauthenticated` has the whole argument for taking them
out rather than trying to check them - and for the one part of it that is
checked instead, the address hints beside an HTTPS, SVCB, SRV or MX answer.

A client that set DO asked for the signatures and keeps every record that
survived the prune above. One that did not has the DNSSEC records taken back
out, because RFC 4035 says not to send them unasked and because they would
otherwise push ordinary answers past the point where they need a retry over TCP.
*/
// Set once the first answer has lost its AD bit to a failed rebuild; see below.
@(private)
prune_failure_reported: bool

/*
And a third, for the verdict this server reached about itself.

Same argument as the one above, one step further in. A shed walk is an
`Indeterminate`, so it would share that flag - and the two are provoked by
different things at different rates. A shed is the only one of the three whose
rate a client chooses: under a flood it is every query, so sharing would have
the first shed spend the `warn` that a genuinely unreachable parent needed, or
the reverse. They are also the two an operator would act on differently, which
is the test for whether a flag is worth splitting.

Its line says what no other line here can: which setting was reached, and where
the count lives. See `report_bogus`.
*/
@(private)
chain_walk_shed_reported: bool

@(private)
present_response :: proc(
	wire: []u8,
	query: dns.Message,
	qtype: dns.Type,
	result: dnssec.Result,
	// The request's reading counter: both rebuilds below read this response
	// again, into the same arena. See `dns.REQUEST_DECODE_BUDGET`.
	spent: ^int,
	allocator: mem.Allocator,
) -> []u8 {
	out := wire
	secure := result.status == .Secure
	if secure {
		/*
		Rebuilt at full size, as below: this is what goes into the cache.

		A response that cannot be rebuilt keeps its records and loses the bit
		instead. The alternative - serving the message as it stands with AD set
		- is the thing this call exists to prevent, and refusing the answer
		outright would let a message we merely failed to re-encode take down a
		name that validated perfectly well.
		*/
		if pruned, ok := dnssec.strip_unauthenticated(out, result, allocator, dns.MAX_MESSAGE, spent); ok {
			out = pruned
		} else {
			/*
			Said out loud, because everything else about this is silent. The
			answer validated - `Stats.secure` has already counted it - and the
			client is about to get it without the bit that says so, which from
			the outside is indistinguishable from a zone that is not signed. The
			copy stored in the cache is the AD-less one too, so every later
			client for that name loses it as well, for the life of the entry.

			Reachable rather than theoretical: `encode_message` refuses raw RDATA
			of a compressible type that still holds a compression pointer, which
			is what `decode_raw_rdata` leaves behind when it could not expand
			one, so an MX or an NS this decoder could not fully read takes the
			bit down with it.
			*/
			/*
			Once at warn, then at debug, like `report_udp_ceiling`. The condition
			is per-answer and remotely reachable, so a name that trips it every
			time would otherwise let whoever queries it decide how much this
			server writes to disk.
			*/
			name := dns.name_trim_root(query.question[0].name if len(query.question) > 0 else "?")
			if sync.atomic_exchange(&prune_failure_reported, true) {
				logx.debugf(
					"dnssec: %s %s validated but could not be rebuilt without its unauthenticated records; answering without the AD bit",
					dns.type_name(qtype),
					name,
				)
			} else {
				logx.warnf(
					"dnssec: %s %s validated but could not be rebuilt without its unauthenticated records; answering without the AD bit",
					dns.type_name(qtype),
					name,
				)
				logx.warnf("further answers losing the AD bit this way are logged at debug level")
			}
			secure = false
		}
	}
	if !dns.edns_do(query) {
		/*
		Rebuilt at full size rather than at this client's limit. What comes back
		here is what goes into the cache, and a copy trimmed to one client's UDP
		buffer would then be all any later client could be given. Shrinking to
		fit is `fit_response`'s job, once per client.
		*/
		out = strip_dnssec_records(out, query, qtype, spent, allocator, dns.MAX_MESSAGE)
	}
	/*
	AD records the verdict, not the audience. This message may end up in the
	cache and be served to clients that asked different questions about DNSSEC,
	so the bit is set from what was established and narrowed per client by
	`apply_ad_policy` on the way out.
	*/
	set_ad_bit(out, secure)
	/*
	CD went out on our own query and comes back echoed. Left alone it would tell
	the client that checking had been disabled, which is the opposite of what
	happened, so it is put back the way the client wrote it (RFC 4035 section
	3.2.2). Validation only runs when the client left it clear, so that is what
	it goes back to.
	*/
	set_cd_bit(out, query.flags.cd)
	return out
}

/*
Take the AD bit back off for a client that never asked about authentication.

RFC 6840 section 5.8: the bit is an answer to a question, and a client that set
neither DO nor AD did not ask it. Applied to cache hits as much as to fresh
answers, so which client happened to warm an entry cannot change what a later
one is told.
*/
/*
Decide what the AD bit on the way out is allowed to say.

Every answer goes through here, whether it came from the cache or from an
upstream a moment ago. Where we validated, `apply_ad_policy` narrows the stored
verdict to what this client asked about. Where we did not - DNSSEC switched off,
the client set CD, a class we do not validate - there is no verdict at all, and
whatever the upstream put in that bit is its claim rather than ours. Forwarding
it would lend our name to an assertion nothing here checked, which RFC 4035
section 3.2.2 asks a resolver never to do; on a plain UDP upstream, or one
reached over a connection nobody authenticated, that claim is anyone's to make.
*/
@(private)
settle_ad_bit :: proc(wire: []u8, query: dns.Message, validated: bool) {
	if validated {
		apply_ad_policy(wire, query)
		return
	}
	set_ad_bit(wire, false)
}

@(private)
apply_ad_policy :: proc(wire: []u8, query: dns.Message) {
	if dns.edns_do(query) || query.flags.ad {
		return
	}
	set_ad_bit(wire, false)
}

@(private)
set_ad_bit :: proc(wire: []u8, value: bool) {
	if len(wire) < dns.HEADER_SIZE {
		return
	}
	if value {
		wire[3] |= 0x20
	} else {
		wire[3] &~= 0x20
	}
}

@(private)
set_cd_bit :: proc(wire: []u8, value: bool) {
	if len(wire) < dns.HEADER_SIZE {
		return
	}
	if value {
		wire[3] |= 0x10
	} else {
		wire[3] &~= 0x10
	}
}

@(private)
strip_dnssec_records :: proc(
	wire: []u8,
	query: dns.Message,
	qtype: dns.Type,
	spent: ^int,
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	msg, err := dns.decode_message(wire, allocator, spent)
	if err != .None {
		return wire
	}
	// Read before the OPT record goes, since the top bits of the rcode live in it.
	rcode := dns.rcode_of(msg)

	msg.answer = without_dnssec(msg.answer, qtype, allocator)
	msg.authority = without_dnssec(msg.authority, qtype, allocator)
	additional := without_dnssec(msg.additional, qtype, allocator)

	if _, had := dns.find_opt(query); had {
		with_opt := make([dynamic]dns.Record, 0, len(additional) + 1, allocator)
		append(&with_opt, ..additional)
		append(&with_opt, dns.make_opt(dns.edns_udp_size(query), false, u8(u16(rcode) >> 4)))
		additional = with_opt[:]
	}
	msg.additional = additional

	out, _, enc := dns.encode_message(msg, allocator, limit)
	if enc != .None {
		return wire
	}
	return out
}

@(private)
without_dnssec :: proc(records: []dns.Record, qtype: dns.Type, allocator: mem.Allocator) -> []dns.Record {
	out := make([dynamic]dns.Record, 0, len(records), allocator)
	for rec in records {
		if rec.type == .OPT {
			continue
		}
		#partial switch rec.type {
		case .RRSIG, .NSEC, .NSEC3, .NSEC3PARAM:
			// Unless of course that is what was asked for.
			if rec.type != qtype && qtype != .ANY {
				continue
			}
		}
		append(&out, rec)
	}
	return out[:]
}

/*
Say, once, that an answer did not validate.

Both lines name the upstream the refused answer came from.

A verdict here is a property of the answer and not of the name, so the same
question put to a different server can validate perfectly. A group whose members
disagree about a zone - one that cannot reach it at all, one handing out a denial
that proves nothing - is then a server that fails some queries for that name and
answers the rest, and every other field on these two lines is identical across
both. Without the upstream there is nothing in the log to tell them apart and the
next step is a packet capture; with it, the counts per server say which one to
stop asking.

`client` is kept beside it. The pair is the point: one says whose query went
unanswered, the other says who is to blame for that, and an operator reading
either alone has half the story.

Through `report_once`, like every other per-query warning on the client path.
Which question is asked is the client's to choose, so a line per refusal is a
line per query for anyone who cares to ask for a name whose zone is broken - and
at the rate `ratelimit` allows one source, that is gigabytes a day of identical
warnings, dropped by journald's per-unit limit along with every legitimate line
or filling the disk where `log.file` is set. The first refusal since start is the
`warn` an operator has to have, every one after it is `debug`, and `bogus=` in
the stats line carries the count. The memory this server keeps of the verdict
(`cache.BOGUS_TTL`) bounds the upstream traffic behind them; this bounds what
they write down.
*/
@(private)
bogus_reported: bool

/*
A flag of its own for the verdict that is not one.

`Indeterminate` reaches this procedure beside `Bogus` because both are SERVFAIL
to the client, and it is the cheap one to provoke: a lost DNSKEY datagram or a
walk that ran out of its allowance under load produces it, and unlike a `Bogus`
verdict nothing remembers it, so it stays cheap. Sharing one flag, the first
such transient since start would spend the single `warn` and a zone that really
is broken would be debug lines for the life of the process - which is the
guarantee this is here to make, lost to the failure mode least worth hearing
about.
*/
@(private)
indeterminate_reported: bool

@(private)
report_bogus :: proc(q: dns.Question, client: string, result: dnssec.Result, from: string, shed := false) {
	reported := &bogus_reported if result.status == .Bogus else &indeterminate_reported
	if shed {
		reported = &chain_walk_shed_reported
	}
	say, first := report_once(reported, logx.enabled(.Debug))
	if !say {
		return
	}
	format := "dnssec: %s %s from %s did not validate: %v (%s); answer came from %s"
	if !first {
		logx.debugf(format, dns.type_name(q.type), dns.name_trim_root(q.name), client, result.status, result.reason, from)
		return
	}
	/*
	The one verdict here that is about this server rather than about the answer,
	so the line says so and names the setting - and leaves the upstream out of
	it, since blaming a server that answered perfectly well for a lookup this
	one declined to make would send an operator to the wrong place entirely.
	*/
	if shed {
		logx.warnf(
			"dnssec: %s %s from %s was not validated: this server was already walking as many chains of trust as dnssec.max_chain_walks and dnssec.max_connection_walks allow, so it stopped looking. Counted as elodin_dnssec_queries_shed_total; further ones are logged at debug level",
			dns.type_name(q.type),
			dns.name_trim_root(q.name),
			client,
		)
		return
	}
	logx.warnf(format, dns.type_name(q.type), dns.name_trim_root(q.name), client, result.status, result.reason, from)
}

/*
The answer for a question whose response did not check out.

SERVFAIL is the only correct reply: an answer that cannot be authenticated must
not reach the client, and there is nothing else to send. The extended error says
which reason it was, so the difference between a forged answer, an unreachable
parent zone and a zone asking for more hashing than this server does is visible
from the client side.

The third has a code of its own (RFC 8914 section 4.28) and is worth using:
"no reachable authority" over a zone whose NSEC3 iteration count is past the
ceiling sends whoever is debugging it to look at connectivity, which is the one
thing that is fine.
*/
@(private)
dnssec_failure_response :: proc(
	query: dns.Message,
	result: dnssec.Result,
	allocator: mem.Allocator,
	limit: int,
) -> (
	out: []u8,
	ok: bool,
) {
	code := u16(EDE_NO_REACHABLE_AUTHORITY)
	switch {
	case result.status == .Bogus:
		code = u16(EDE_DNSSEC_BOGUS)
	case result.reason == dnssec.NSEC3_OVER_CEILING:
		code = u16(EDE_UNSUPPORTED_NSEC3_ITERATIONS)
	}
	/*
	The reason goes out as RFC 8914 extra text, except this one.

	Every other reason here describes the answer or the zone, which is what the
	client asked about. `WALKS_IN_FLIGHT` describes how busy this server is
	right now, and that is a different thing to hand out: it is state one client
	can read about every other client's traffic. An attacker running a slow
	probe for any cold name beside their flood would be told exactly when the
	slots saturate, which turns tuning the flood from guesswork into a closed
	loop.

	The code is unchanged - 22, the same an unreachable authority gets, which is
	the truth here - and the operator loses nothing: the reason is in the log
	line and the count is in `elodin_dnssec_queries_shed_total`. A client is
	told the answer could not be established, which is all it can act on.
	*/
	text := result.reason
	if result.reason == dnssec.WALKS_IN_FLIGHT {
		text = ""
	}
	resp := dns.make_response(query, .Serv_Fail, allocator)
	attach_extended_error(&resp, code, text, allocator)

	encoded, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		return nil, false
	}
	return encoded, true
}

@(private)
attach_extended_error :: proc(resp: ^dns.Message, code: u16, text: string, allocator: mem.Allocator) {
	for &rec in resp.additional {
		if rec.type != .OPT {
			continue
		}
		payload := make([]u8, 2 + len(text), allocator)
		payload[0] = u8(code >> 8)
		payload[1] = u8(code)
		copy(payload[2:], transmute([]u8)text)

		options := make([]dns.EDNS_Option, 1, allocator)
		options[0] = dns.EDNS_Option {
			code = u16(dns.EDNS_Option_Code.Ext_Error),
			data = payload,
		}
		rec.data = dns.Rdata_OPT{options = options}
		return
	}
}
