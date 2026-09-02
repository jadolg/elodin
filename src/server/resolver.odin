package server

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:filter"
import "elodin:logx"
import "elodin:pool"
import "elodin:upstream"

Protocol :: enum u8 {
	UDP,
	TCP,
	DoT,
	DoH,
}

Outcome :: enum u8 {
	Forwarded,
	Cached,
	Blocked,
	Rewritten,
	Local,
	Failed,
	Refused,
}

Stats :: struct {
	queries:      u64,
	blocked:      u64,
	cached:       u64,
	forwarded:    u64,
	failed:       u64,
	rewritten:    u64,
	/*
	Queries refused before any work was done: the backlog was full, or the
	source was one no answer could reach - see `plausible_source`. Queries the
	rate limiter withheld are counted by the limiter itself.
	*/
	dropped:      u64,
	/*
	Traffic turned away because of `server.allow_from`: a datagram on UDP, and a
	connection on the stream transports, where the check runs on accept before a
	byte has been read. The number is the sum of the two units rather than a
	count of queries, which is what the log line's wording says of each one.

	Counted apart from `dropped` because the two ask different questions of an
	operator. A rising `dropped` is a server that cannot keep up; a rising
	`refused` is a client that is not on the list - which is either the internet
	finding an open port, or somebody's own subnet that nobody added.
	*/
	refused:      u64,
	/*
	Connections turned away because `server.max_connections` was already full.

	Counted rather than only logged, because the log says it once. The line for
	this is demoted to `debug` after the first, on the reasoning that a peer
	opening connections past the limit would otherwise decide how much this
	server writes to disk - and that reasoning only holds if something else goes
	on counting. Without this, a server sitting at its limit for a week shows one
	`warn` from the first minute and nothing since.

	Apart from `refused`, which is the allow list turning a source away: this is
	a client this server would serve and has no room for, and the setting to
	reach for is a different one.
	*/
	conn_refused: u64,
	/*
	Connections turned away because the OS would not start a thread for one.

	Counted apart from `conn_refused` because it happens *below* the limit -
	`RLIMIT_NPROC`, a cgroup `pids.max`, or memory - and the two point an
	operator in opposite directions. Folded together, a host that ran out of
	threads at a tenth of `max_connections` would read as a server that had
	filled it, and the obvious response would be to raise a number that was never
	the bound.
	*/
	conn_failed:  u64,
	// Answers that carried a valid chain of signatures, and answers refused
	// because they did not.
	secure:       u64,
	bogus:        u64,
	/*
	Answers withheld because a public name was pointed into private address
	space - see `rebind.odin`.

	Counted apart from `blocked`, which is the filter engine, because the two
	answer different questions. A rising `blocked` is the lists doing their job
	on names clients asked for; a rising `rebind` is either an attack or a split
	horizon that nobody exempted, and folding it into the first would hide both
	inside a number that is meant to be large.
	*/
	rebind:       u64,
	/*
	Queries answered out of the RFC 6761/6762/7686 table rather than forwarded -
	see `localzones.odin`.

	Counted, where the other things this server answers from itself are not,
	because this one is a privacy control and the count is the only aggregate
	evidence it worked. `answer_chaos` serves a version string and DDR serves a
	discovery probe, and nobody needs to know how many of either went by; a
	rising `special_use` says something specific and worth seeing, that clients
	on this network are asking for `.onion` or `localhost.` names and that those
	questions stopped here. Without it an operator has to turn query logging on
	to learn whether the table has ever done anything.

	Apart from `blocked` for the reason `rebind` is: the lists are meant to
	produce a large number, and a handful of stopped leaks folded into it would
	be invisible in both directions.
	*/
	special_use:  u64,
}

Server :: struct {
	cfg:          ^config.Config,
	group:        ^upstream.Group,
	answers:      ^cache.Cache,
	filters:      ^filter.Engine,
	validator:    ^dnssec.Validator,
	/*
	The operator's own trust anchors, as parsed.

	Held here rather than left to the validator because the validator borrows
	them: with none configured it points at `dnssec.root_anchors`, which is
	static, so `destroy_validator` cannot free what it has and these would have
	nobody to release them. Empty when the built-in anchors are in use.
	*/
	anchors:      []dnssec.Trust_Anchor,
	// The zones of the operator's own trust anchors, root excluded, in canonical
	// form. An anchor here is a deliberate request to validate the zone it names,
	// which the locally-served bypass has to defer to; see `covered_by_local_anchor`.
	// The strings are the anchors' own; only the slice belongs to this field.
	anchor_zones: []string,
	cookies:      ^Cookie_Keeper,
	// Nil when rate limiting is off; `rate_check` takes that as "allow".
	limiter:      ^Rate_Limiter,
	handler_pool: ^pool.Pool,
	race_pool:    ^pool.Pool,
	stats:        Stats,
	// When this process began serving. Not a setting and not a counter: the
	// metrics endpoint reports uptime from it, and Prometheus's
	// `process_start_time_seconds` is what every client library calls the same
	// thing.
	started:      time.Time,
	running:      bool,
}

/*
Answer one query.

`query` is the raw client message. The returned bytes are allocated from
`allocator` — callers pass a per-request scratch allocator and release it once
the response has been written to the wire.

`ok` is false only when no response should be sent at all, which is the right
behaviour for a datagram too malformed to derive a header from.
*/
handle_query :: proc(
	s: ^Server,
	query: []u8,
	proto: Protocol,
	client: string,
	allocator := context.allocator,
) -> (
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	started := time.now()
	sync.atomic_add(&s.stats.queries, 1)

	if len(query) < dns.HEADER_SIZE {
		return nil, .Failed, false
	}

	msg, derr := dns.decode_message(query, allocator)
	limit := response_limit(s, msg, proto)
	advertise := advertised_udp_size(s, msg, proto)
	if derr != .None {
		out, built := dns.error_response(query, {}, .Form_Err, allocator, limit)
		return advertise_udp_size(out, advertise, proto), .Failed, built
	}
	// A response arriving on a listener port is not something to answer.
	if msg.flags.qr {
		return nil, .Failed, false
	}

	/*
	EDNS this server cannot account for is refused before anything is read out of
	it.

	FORMERR because RFC 6891 section 6.1.1 says exactly that of a query carrying
	more than one OPT record, and because RDATA that is not a well-formed option
	list is no more answerable: every option in it is one this server can neither
	see nor take back out, while the upstream reading the same bytes can.

	Ahead of `inspect_cookie` for the reason the version check below is ahead of
	`resolve_query`: this is a property of the request and not of the name. A gate
	any lower answers identical bytes differently depending on what else happened
	to be true - FORMERR on a cache miss, the entry on a hit, a blocklist verdict
	or a rewrite where a rule matches the name - and the client's cookie would by
	then have been looked for in the first OPT record, found absent, and left
	standing in the second one all the way to the upstream.

	Not counted, matching the malformed-cookie FORMERR below and the class, XFR
	and RD refusals: none of those has a counter either. It reaches the query log
	as `outcome=failed detail=opt` and goes no higher - a line an
	unauthenticated peer can print once per datagram does not belong at warn.
	*/
	if !edns_opt_readable(msg) {
		out, built := dns.error_response(query, msg, .Form_Err, allocator, limit)
		// As the version gate below: this runs before the question count is
		// checked, so there may be no question to name.
		q: dns.Question
		if len(msg.question) > 0 {
			q = msg.question[0]
		}
		log_query(s, client, proto, q, .Failed, "opt", started)
		return advertise_udp_size(out, advertise, proto), .Failed, built
	}

	cookie := inspect_cookie(s.cookies, msg, client)

	// A cookie of an impossible length is the one case RFC 7873 section 5.2.2
	// answers with FORMERR, and the one response that carries no cookie back:
	// there is no telling which eight of those bytes were the client's.
	if cookie.verdict == .Malformed {
		out, built := dns.error_response(query, msg, .Form_Err, allocator, limit)
		out = advertise_udp_size(out, advertise, proto)
		// Padded like any other answer to this client. The two refusals above
		// are not, and cannot be: one has a query that did not decode and the
		// other a query whose EDNS this server has just declined to read, so
		// neither can say whether padding was asked for. This one can.
		return pad_answer(out, msg, proto, limit, advertise, allocator), .Failed, built
	}

	/*
	A requestor asking in an EDNS version this server does not implement is told
	so, and nothing is looked up on its behalf.

	RFC 6891 section 6.1.3 requires BADVERS for a VERSION the responder does not
	implement, and 0 is the only version implemented here. Refused ahead of
	`resolve_query` rather than somewhere inside it because the version is a
	property of the request and not of the name: a rewrite, a blocklist hit, a
	CHAOS answer and a cache hit would each otherwise reply in a version the two
	ends never agreed on, and the forwarding path would put the question to an
	upstream in the version this server chose rather than the one asked for.

	The response `error_response` builds carries the extended half of rcode 16 in
	its own OPT record, and states version 0 in the same field, which is the rest
	of what section 6.1.3 asks for.

	Not counted, matching the class, XFR and RD refusals it belongs with: none of
	those has a counter, and `Stats.refused` is `server.allow_from` turning a
	source away before there is a query at all. Logged for the same reason those
	are - BADVERS answers leaving a server with nothing in the query log to
	account for them are answers an operator has no way to trace back to here.
	*/
	if dns.edns_version(msg) > 0 {
		out, built := dns.error_response(query, msg, .Bad_Vers, allocator, limit)
		// This gate runs before the question count is checked, so there may be no
		// question to name; one that arrives without any is refused for its
		// version all the same.
		q: dns.Question
		if len(msg.question) > 0 {
			q = msg.question[0]
		}
		log_query(s, client, proto, q, .Refused, "edns", started)
		response, outcome, ok = out, .Refused, built
	} else {
		response, outcome, ok = resolve_query(s, query, msg, proto, client, limit, cookie, started, allocator)
	}
	if ok {
		response = attach_cookie(s.cookies, response, cookie, msg, limit, advertise, allocator)
		/*
		Last, so that nothing after it can put another number back.

		The four ways an answer reaches this point disagree about what its OPT
		record says: a locally built one echoes the client's figure, a forwarded
		or cached one carries the upstream's, and `attach_cookie` re-encodes over
		the top of either. Writing it here rather than in each of them is what
		makes the guarantee hold for a path added later, and the cached case
		needs it here anyway - the stored wire is shared between clients and is
		not this server's number to begin with.
		*/
		response = advertise_udp_size(response, advertise, proto)
		// After that rather than before it: padding is a statement about the
		// length of the bytes that leave, so nothing may change the length -
		// or, as `set_edns_udp_size` would, rewrite the OPT record - behind it.
		response = pad_answer(response, msg, proto, limit, advertise, allocator)
	}
	return response, outcome, ok
}

/*
The ceiling on a UDP response, floored at the smallest response there is.

Every `Config` in a running server comes from `default_config` and is then
validated, so the field is never below 512 there. But a zero one - a `Config`
built literally, which is a thing a caller can do - would truncate every answer
to nothing, and a resolver that answers nothing at all is too quiet a failure to
leave resting on a convention held one package away.
*/
@(private)
udp_ceiling :: proc(s: ^Server) -> int {
	return max(s.cfg.server.max_udp_response, config.MIN_UDP_RESPONSE)
}

/*
The UDP payload size this server puts in an answer's OPT record.

RFC 6891 section 6.2.4 makes that field the responder's own maximum rather than
a copy of the requestor's - the counterpart to `max-udp-size` in BIND and
Unbound, both of which report their own figure independently of what was asked
for. So it is the ceiling, not `response_limit`: the two differ for a client that
advertised less than the ceiling, and reporting the smaller number there is the
same defect as reporting the larger one, inverted. A downstream forwarder that
advertised a conservative 512 would read 512 back, conclude this server cannot
deliver more, and keep paying for TC bits and TCP retries the 1232 ceiling would
have spared it.

What bounds the answer itself is still `response_limit`, which is the smaller of
the two. The field says what this server can deliver; it was never a statement
about one reply.

On the stream transports the limit is the DNS framing rather than a datagram, so
there is no payload size of ours to report - writing the ceiling there would
claim a UDP bound on a transport it does not apply to, and writing
`response_limit` would advertise 65535, which is not a payload size at all. The
answer's OPT goes back as it stands, whatever it says.
*/
@(private)
advertised_udp_size :: proc(s: ^Server, query: dns.Message, proto: Protocol) -> u16 {
	if proto != .UDP {
		return dns.edns_udp_size(query)
	}
	// `udp_ceiling` already lands in [512, 4096] for every `Config` this server
	// runs on. Clamped anyway, because what is being written is two bytes of a
	// field with its own range, and a number from outside it would be truncated
	// into something arbitrary rather than refused.
	return u16(clamp(udp_ceiling(s), config.MIN_UDP_RESPONSE, config.MAX_UDP_RESPONSE))
}

/*
Write that size onto an answer that is already encoded.

A no-op for a client that asked without EDNS: there is no OPT record to carry a
number and none is invented for one. A no-op on the stream transports too, where
the field bounds nothing and the answer's own OPT is left as it is.
*/
@(private)
advertise_udp_size :: proc(wire: []u8, size: u16, proto: Protocol) -> []u8 {
	if proto != .UDP || len(wire) < dns.HEADER_SIZE {
		return wire
	}
	_ = dns.set_edns_udp_size(wire, size)
	return wire
}

/*
Round an answer up to a block boundary, on the transports where its length is
worth hiding and for the clients that asked.

Both halves of that are conditions rather than policy. RFC 8467 section 5 rules
out padding on UDP and plain TCP - an observer reading the message does not need
its length - and on UDP it would additionally spend `server.max_udp_response` on
bytes that hide nothing while enlarging the amplification surface that setting
exists to bound. RFC 7830 section 4 rules out padding a client that did not send
the option: a requestor that never asked has not budgeted for the bytes, and on
UDP would be the one paying for them.

468 octets, from RFC 8467 section 4.2, which is what a responder pads to when
the requestor padded to the 128 that section 4.1 names. Not configurable, for
the reason the RFC gives one number rather than a knob: a deployment that picked
its own block would be distinguishable by it, which is the opposite of what the
padding is for.

`limit` is the transport's own ceiling, 65535 on both of these, so a block that
would not fit is a message that is already within 467 bytes of the largest one
there is. It goes out unpadded rather than partway padded - see `dns.pad_response`.

Every caller sits behind `edns_opt_readable`, so an option found here is an
option this server can account for, and the padding written over it is one the
upstream cannot see a second copy of.
*/
@(private)
pad_answer :: proc(
	wire: []u8,
	query: dns.Message,
	proto: Protocol,
	limit: int,
	advertise: u16,
	allocator: mem.Allocator,
) -> []u8 {
	if proto != .DoT && proto != .DoH {
		return wire
	}
	if len(wire) < dns.HEADER_SIZE {
		return wire
	}
	if _, asked := dns.find_edns_option(query, .Padding); !asked {
		return wire
	}
	out, ok := dns.pad_response(wire, dns.PAD_RESPONSE_BLOCK, limit, advertise, allocator)
	if !ok {
		// Nothing to do but send the answer as it stands: an answer withheld
		// would tell the same observer rather more than its length does.
		return wire
	}
	return out
}

/*
Whether this server can account for the EDNS on a message, which is what every
later edit to one depends on.

Two shapes cannot be accounted for, and they are the same defect read from
either end. A second OPT record is one RFC 6891 section 6.1.1 forbids outright,
and every reader here - `find_opt` on the decoded message, `find_opt_span` on
the wire, and so both the cookie strip and the subnet strip - takes the first
one and looks no further, so an option sitting in the second travels upstream
untouched past a removal that reported success. An OPT whose RDATA is not a
well-formed option list is the other: `decode_record` keeps RDATA it cannot
parse as raw bytes rather than rejecting the message, so a list ending in three
bytes of a fourth option header arrives as an OPT record holding `Rdata_Raw`,
and every option in front of that stump reads as absent to anything asking the
decoded message - `find_edns_option` included. Absent to this server, that is,
and not to the upstream, which walks the same bytes and stops where this decoder
stopped.

Asked of the message rather than of one option, because the answer is the same
for every option in it and asking per option is what went wrong before: the
client's subnet had a gate of its own and the client's cookie, which is a secret
and the more expensive of the two to hand to a stranger, had none.

Only the additional section is counted, because that is the only section
`find_opt` and `find_opt_span` look in. A record of type OPT in the answer
section is not the message's EDNS record, and a client can put one there for the
asking.
*/
@(private)
edns_opt_readable :: proc(msg: dns.Message) -> bool {
	seen := false
	for rec in msg.additional {
		if rec.type != .OPT {
			continue
		}
		if seen {
			return false
		}
		seen = true
		if _, is_opt := rec.data.(dns.Rdata_OPT); !is_opt {
			return false
		}
	}
	return true
}

/*
Whether the client asked with an EDNS Client Subnet option.

Read off the decoded message, which is the whole of what it takes by the time
this is asked: `handle_query` has already turned away the two shapes that could
hide an option from this decoder - a second OPT record, and an OPT whose RDATA
is not a well-formed option list - so an option that is not in the list here is
not in the message either, and the one that is can be taken back out.
*/
@(private)
client_subnet_sent :: proc(msg: dns.Message) -> bool {
	for rec in msg.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for o in rdata.options {
			if o.code == u16(dns.EDNS_Option_Code.Client_Subnet) {
				return true
			}
		}
	}
	return false
}

@(private)
resolve_query :: proc(
	s: ^Server,
	query: []u8,
	msg: dns.Message,
	proto: Protocol,
	client: string,
	limit: int,
	cookie: Cookie_Request,
	started: time.Time,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	if msg.flags.opcode != .Query {
		out, built := dns.error_response(query, msg, .Not_Impl, allocator, limit)
		return out, .Refused, built
	}
	if len(msg.question) != 1 {
		out, built := dns.error_response(query, msg, .Form_Err, allocator, limit)
		return out, .Failed, built
	}

	q := msg.question[0]

	/*
	A client that cannot show a cookie we issued is turned away before any work
	is done, when that is what the configuration asks for.

	This is the whole point of the mechanism: an off-path attacker forging a
	query from someone else's address has never seen a cookie for that address,
	so it cannot get past here, and the answer it was trying to have sent
	somewhere is never looked up. The cost falls on the honest client too - one
	extra round trip the first time it asks - which is why it is off by default
	and meant for use while an attack is actually happening (RFC 7873 section
	5.2.3).
	*/
	if cookie_must_be_refused(s.cookies, cookie, proto) {
		out, built := dns.error_response(query, msg, .Bad_Cookie, allocator, limit)
		log_query(s, client, proto, q, .Refused, "cookie", started)
		return out, .Refused, built
	}

	if q.class == .CH {
		if out, handled := answer_chaos(s, msg, q, allocator, limit); handled {
			log_query(s, client, proto, q, .Local, "chaos", started)
			return out, .Local, true
		}
	}
	if q.class != .IN && q.class != .ANY {
		out, built := dns.error_response(query, msg, .Refused, allocator, limit)
		log_query(s, client, proto, q, .Refused, "class", started)
		return out, .Refused, built
	}

	// Zone transfers make no sense against a forwarder.
	#partial switch q.type {
	case .AXFR, .IXFR:
		out, built := dns.error_response(query, msg, .Refused, allocator, limit)
		log_query(s, client, proto, q, .Refused, "xfr", started)
		return out, .Refused, built
	}

	if out, matched := apply_rewrite(s, msg, q, allocator, limit); matched {
		sync.atomic_add(&s.stats.rewritten, 1)
		log_query(s, client, proto, q, .Rewritten, "rewrite", started)
		return out, .Rewritten, true
	}

	/*
	The reverse of a rewrite, from the same table and immediately below it.

	`rewrites` is where an operator writes down what their own names resolve to,
	and the address in such a rule has a reverse whether or not they wrote that
	down too - see `reverse.odin`. It is one rule set, so it answers in one
	place: below the explicit rules, since a rule naming a reverse name outright
	is the more specific of the two and must win, and above everything else for
	the same reasons the forward direction is - nothing here can leak, and an
	operator's own configuration outranks a table.

	Counted as a rewrite, because it is one, and separated in the query log:
	`detail=rewrite-ptr` is what tells an operator debugging a reverse lookup
	that this server answered it out of a forward rule rather than forwarding it.
	*/
	if out, matched := apply_reverse_rewrite(s, msg, q, allocator, limit); matched {
		sync.atomic_add(&s.stats.rewritten, 1)
		log_query(s, client, proto, q, .Rewritten, "rewrite-ptr", started)
		return out, .Rewritten, true
	}

	if s.cfg.blocking.enabled && s.filters != nil {
		if filter.engine_match(s.filters, q.name) == .Blocked {
			sync.atomic_add(&s.stats.blocked, 1)
			out := build_block_response(s, msg, q, allocator, limit)
			log_query(s, client, proto, q, .Blocked, "list", started)
			return out, .Blocked, true
		}
	}

	/*
	A DDR probe is answered from here and never forwarded - the upstream's
	designated resolvers are not ours to hand a client, and its unsigned answer
	under the signed `arpa` zone does not validate. See `ddr.odin`.

	One rule for everything this server answers for itself, and this is it:
	below the rewrites and the block lists, above the cache and the RD gate. The
	rewrites so an operator who wants to designate this server's own DoT or DoH
	endpoints can say so and be obeyed; the block lists so that an entry an
	operator wrote down wins and is counted as blocked, rather than a table
	answering first and leaving the list looking like it did nothing.

	This used to sit above the block lists while the reserved-name table below sat
	beneath them, each with its own reasoning and neither referring to the other.
	The distinction was real but thin - a blocklist can plausibly name something
	under `onion.` and cannot plausibly name `resolver.arpa` - and it is not worth
	two orderings for. One place to reason about is worth more than the case it
	gives up, which is this: a list broad enough to match `resolver.arpa`, which
	means a rule over `arpa` itself, now blocks a DDR probe instead of having it
	answered NODATA. Such a list is already breaking every reverse lookup on the
	machine, so it is not a configuration this ordering has to protect.
	*/
	if is_resolver_arpa(q.name) {
		out := build_resolver_arpa_response(msg, q, allocator, limit)
		log_query(s, client, proto, q, .Local, "ddr", started)
		return out, .Local, true
	}

	/*
	The names that are never forwarded, whatever `upstream.servers` says. See
	`localzones.odin` for which they are and why.

	Placed after the rewrites and the block lists on purpose. Both of those are
	the operator having said something explicit about this name, both answer it
	locally, and neither can leak it - so letting them run first costs nothing
	and leaves a site that legitimately serves `.local` able to say so, and an
	operator who put a name on a blocklist still seeing it counted as blocked.
	This table is the default for the names nobody configured.

	The DDR zone above is in the same place for the same reasons, which it was not
	always: it used to be answered ahead of the block lists, on the argument that
	nothing legitimately lists `resolver.arpa`. True, but not worth two orderings
	in one procedure - a reader should be able to learn where locally answered
	names go once. Both now sit below the rewrites and the block lists and above
	the cache and the RD gate.

	Ahead of the cache, and of the RD gate below. Ahead of the cache because
	there is nothing there to find: these answers are never stored, and one a
	previous configuration forwarded and stored cannot outlive the restart it
	takes to change the setting. The order is what keeps that true rather than
	something to re-check if either of those facts ever stops holding. Ahead of
	the RD gate because RD=0 asks for what this server already knows without
	recursion, and this is precisely that: an answer from a table, with nowhere
	to forward to even if the client had asked for it.

	The query type reaches `special_use_zone` for one carve-out: the `DS` at the
	apex of `home.arpa.` is forwarded even with `special_use.home_arpa` on, RFC
	8375 section 4 item 4.B requiring the signed proof that the delegation has no
	DS - which lives in `arpa.` - to be fetched rather than invented. It falls
	through to the forwarding path below like any other name, where the
	`home.arpa.` entry in `LOCALLY_SERVED_ZONES` keeps it off the chain walk.

	Counted in `stats.special_use`, and shown in the query log as `outcome=local
	detail=special-use`. That is a departure from `answer_chaos` and the DDR
	probe, which are answered from here too and counted nowhere: those two are a
	version string and a discovery probe, while a stopped `.onion` query is the
	one thing here an operator has a reason to watch, and the counter is the only
	way to see it without running the query log.
	*/
	if zone, kind := special_use_zone(s, q.name, q.type); kind != .None {
		out := answer_special_use(msg, q, zone, kind, allocator, limit)
		sync.atomic_add(&s.stats.special_use, 1)
		log_query(s, client, proto, q, .Local, "special-use", started)
		return out, .Local, true
	}

	// A client that sets CD is asking for the upstream's answer whatever we
	// think of it, so validation is skipped - and the answer is kept apart in
	// the cache so it cannot be served to a client that did want it checked.
	//
	// The locally-served zones are skipped too. Nothing on the public Internet
	// signs the RFC 6303 reverse trees for private, link-local and loopback
	// space, so their unsigned local answers have no chain to check and
	// validating one only turns a LAN PTR lookup into SERVFAIL. RFC 8375's
	// `home.arpa.` is delegated insecure and would validate on its own, but the
	// router that answers the zone swallows the `DS` query that proves it,
	// breaking the walk the same way. Both are served as insecure, which is what
	// `settle_ad_bit` records once `validating` is off - unless the operator
	// anchored the zone themselves, in which case that request to validate it
	// wins and the bypass stands down.
	//
	// `special_use_deferred` is the forward-side case of the same thing: a
	// `.onion` name an operator handed to a Tor-aware upstream with
	// `special_use.onion: false` comes back unsigned under a root that signs a
	// proof there is no `onion.` at all, which is Bogus to a validator and
	// SERVFAIL to the client. See `localzones.odin`.
	validating :=
		s.validator != nil &&
		!msg.flags.cd &&
		q.class == .IN &&
		!(is_locally_served(q.name) && !covered_by_local_anchor(s, q.name)) &&
		!special_use_deferred(s, q.name)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], q.name, q.type, q.class, dns.edns_do(msg), msg.flags.cd)

	/*
	Which rule sets an answer is matched against here, read once and used for
	both the cache lookup and the store below.

	Taken before the chain walk rather than after. A reload landing partway
	through leaves the answer stamped with the older number, which costs one more
	walk on the next hit; taking it afterwards would stamp an answer with the
	number of a rule set that arrived after it had been matched, and that entry
	would then never be looked at again.

	Not read at all unless both halves are on. The number exists to date a stored
	answer against the rule sets, so with nothing stored, or no rule sets to date
	it against, it is a second trip through the engine's lock on every query for a
	value nothing reads. With blocking off the engine is never swapped at all -
	`reload_filters` runs only under that flag - so the number would sit at zero
	and match every entry's stamp for the life of the process.
	*/
	generation: u64
	if s.cfg.cache.enabled && s.cfg.blocking.enabled && s.filters != nil {
		generation = filter.engine_generation(s.filters)
	}

	/*
	An expired entry that `serve_stale` kept, held back rather than served.

	RFC 8767 section 5 has a resolver try the refresh first and use expired data
	only once that attempt has failed, which is what the setting says it does:
	answer from an expired entry *if the upstream is down*. So a stale hit falls
	through to the forwarding path exactly as a miss would, and these bytes come
	out below only if that path cannot produce an answer at all.

	They stay valid for as long as they are needed: `cache.get` copies the entry
	into the per-request arena, which outlives the upstream call and is released
	only once the response has gone out.
	*/
	stale_hit: Cached_Answer

	if s.cfg.cache.enabled {
		if wire, hit, found := cache.get(s.answers, key, allocator, checked_against = generation); found {
			stored := Cached_Answer {
				wire    = wire,
				key     = key,
				stale   = hit.stale,
				recheck = hit.recheck,
				refused = hit.refused,
				serial  = hit.serial,
				checked = generation,
			}
			if !hit.stale {
				return serve_from_cache(s, stored, query, msg, q, proto, client, limit, validating, started, allocator)
			}
			stale_hit = stored
		}
	}

	/*
	RD=0 asks for whatever this server already knows, not for a fresh lookup -
	RFC 1035 section 4.1.1. A fresh cache hit above already answered that without
	going anywhere; reaching this point means answering it would mean forwarding
	to an upstream, which is the recursion the client did not ask for. Refused
	rather than silently dropped, matching the other policy refusals above -
	the allow-list is what keeps this from being a free reflection.

	An expired entry held back for the upstream is served here rather than
	refused. It is something this server already knows and no recursion is needed
	to produce it, so the reason for the refusal does not reach it - and the
	forwarding path that would have refreshed it is closed to this query anyway.
	Refusing would withhold the fallback from exactly the clients that asked for
	local knowledge and nothing else.

	No counter of its own, again matching the class, XFR and cookie refusals
	beside it: `Stats.refused` is `server.allow_from` turning away a datagram or
	connection before a query exists at all, and stretching it to cover this too
	would blur two different questions an operator asks of it - "is a network I
	never added reaching this port" against "are RD=0 probes arriving". The
	query log is where this one shows, as `outcome=refused detail=rd`, when
	`log.queries` is on.
	*/
	if !msg.flags.rd {
		if stale_hit.wire != nil {
			return serve_from_cache(s, stale_hit, query, msg, q, proto, client, limit, validating, started, allocator)
		}
		out, built := dns.error_response(query, msg, .Refused, allocator, limit)
		log_query(s, client, proto, q, .Refused, "rd", started)
		return out, .Refused, built
	}

	// Validation needs the signatures, so the question goes out again with DO
	// and CD set rather than as the client wrote it.
	forwarded := query
	if validating {
		if rewritten, built := dnssec_upstream_query(msg, allocator); built {
			forwarded = rewritten
		} else {
			validating = false
		}
	}

	/*
	The client's cookie stops here.

	It is a shared secret between that client and this server, so an upstream
	has no business seeing it - a stable identifier for the client, handed to
	somebody who cannot check it and did not need it. And the server half of it
	is one we minted: an upstream that implements cookies would hash it against
	its own secret, decide it is a forgery and answer BADCOOKIE instead of
	answering the question. Cookies towards the upstream are a separate exchange
	of our own - `cookies.upstream`, in `src/upstream/cookie.odin` - which puts
	its own client cookie on the query after this strip has run.

	Asked as "the query carried one" rather than as anything about this server's
	own cookie settings. With `cookies.enabled` off there is no verdict to reach
	and every query looks cookie-less, and with `cookies.upstream` off nothing
	replaces the option on the way out - so reading the verdict here let the
	client's cookie travel whenever both were turned off, and to DoT and DoH
	upstreams, which never carry a cookie of ours, whenever the first one was.
	*/
	if cookie.sent {
		stripped, done := dns.remove_edns_option(forwarded, .Cookie, allocator)
		if !done {
			/*
			Failing closed. A query this server cannot take the cookie back out
			of is not one to send on: forwarding it anyway would hand the
			client's secret to the upstream, which is the one outcome this whole
			block exists to prevent. Losing the answer is the cheaper mistake,
			and the client is told so rather than left waiting.
			*/
			sync.atomic_add(&s.stats.failed, 1)
			out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
			logx.warnf(
				"could not strip the client cookie from %s %s from %s; not forwarding",
				dns.type_name(q.type),
				dns.name_trim_root(q.name),
				client,
			)
			log_query(s, client, proto, q, .Failed, "cookie", started)
			return out, .Failed, built
		}
		forwarded = stripped
	}

	/*
	The client's subnet stops here as well.

	RFC 7871 section 7.5 puts no condition on this: an intermediate nameserver
	that forwards ECS options received from its clients "MUST fully implement
	the caching behavior described in Section 7.3", and this server does not.
	Its key is the question plus DO and CD and nothing else (`cache.make_key`),
	so an answer tailored to whatever network a client named would be filed
	under the bare question and handed to every other client behind this
	resolver until it expired - section 7.3.1's requirement that a cached answer
	be tied to the network it was scoped to, absent. One well-formed query from
	anyone `server.allow_from` lets in, and the whole network gets the CDN edge
	that client chose.

	The leak is the other half, and it holds with the cache switched off:
	`server.allow_from` decides who may ask here, not what they may claim about
	themselves, so a client can have this server tell a public upstream that its
	users are somewhere they are not (section 11.1).

	Stripped rather than refused. Section 7.5 does offer REFUSED for an option
	an intermediate does not want to use, but a stub that sends ECS is asking
	for a nearer CDN edge and not committing an offence, and refusing it teaches
	the client to route around this resolver. Dropping the option leaves the
	upstream scoping on this server's own address, which is the answer everyone
	behind it should be getting, and the reply then carries no ECS option back -
	which section 7.3 reads as "suitable for all client addresses", true here
	rather than the false tailoring claim that section warns about.

	Nothing is put in its place. Section 7.1.2 gives SOURCE PREFIX-LENGTH 0 to a
	stub that wants no scoping at all and section 7.1.3 says a forwarder looks
	like a stub, but sending it would forbid the upstream from scoping on *our*
	address too - every client behind this resolver losing the locality it has
	today, to fix a leak that is already fixed by the option being gone. That is
	an operator's decision and a larger one than this. An absent option says
	this server does not do ECS, which is the truth.

	No setting to turn it back on, either. Forwarding ECS is only correct
	together with the section 7.3 caching, and until the cache can hold a scope
	per network the key would either be a lie or be the client's own bytes -
	which is the cache pollution section 11.3 is about, an attacker sitting on
	one name and evicting the table with a fresh subnet each time. The option
	belongs with that work, not ahead of it.

	Placed after the DNSSEC rewrite for the reason the cookie is: that path
	copies the client's OPT data across wholesale, so this is the point where
	both ways of building the outgoing query have converged.

	The strip below is trusted to reach the option because `handle_query` has
	already refused the two shapes it could not - a second OPT record, and an OPT
	whose RDATA is not a well-formed option list. Both would have survived a
	removal that reported success; see `edns_opt_readable`.
	*/
	if client_subnet_sent(msg) {
		stripped, done := dns.remove_edns_option(forwarded, .Client_Subnet, allocator)
		if !done {
			/*
			Failing closed, as the cookie above does, and for a reason that
			survives the objection that a cookie is a secret and a subnet is
			only a hint. It is a hint that steers a shared cache: forwarding one
			this server could not account for is what lets a single client pick
			the answer the rest of them get, which no amount of "it is only a
			hint" makes cheaper than one lost answer for the client that sent
			it. Nobody else's queries are affected by the refusal, and the
			client is told rather than left waiting.
			*/
			sync.atomic_add(&s.stats.failed, 1)
			out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
			logx.warnf(
				"could not strip the client subnet from %s %s from %s; not forwarding",
				dns.type_name(q.type),
				dns.name_trim_root(q.name),
				client,
			)
			log_query(s, client, proto, q, .Failed, "ecs", started)
			return out, .Failed, built
		}
		forwarded = stripped
	}

	/*
	The transaction ID on the way out is ours.

	The client chose the one on the query coming in, and forwarding it means an
	attacker that can reach this listener picks the ID this server will then
	accept from the upstream - half of what RFC 5452 section 9.2 asks an
	off-path attacker to guess, handed over for the asking. What is left is the
	ephemeral source port, and a search space of 2^16 is minutes of packets on a
	fast link rather than the 2^31 it should be. A win is cached and served to
	every client behind this resolver for the whole TTL.

	Placed here rather than in the procedures above because all three ways the
	outgoing buffer comes about pass through this point: the client's message
	forwarded as it stands, the DNSSEC rewrite, and the one with the client's
	cookie taken back out. The reply's ID is put back to the client's below,
	which the DoH path already relied on.

	Cloned first when the buffer is still the caller's. `query` is needed intact
	afterwards - `error_response` answers from it, and on the UDP listener it is
	a receive buffer this thread does not own - and `remove_edns_option` hands
	back the message unchanged when there was no option to remove, so a buffer
	arriving here can be the client's own either way.
	*/
	if raw_data(forwarded) == raw_data(query) {
		forwarded = dns.clone_message_bytes(forwarded, allocator)
	}
	dns.set_id_in_place(forwarded, dns.random_id())

	resp, winner, uerr := upstream.resolve(s.group, forwarded, allocator)
	if uerr != .None {
		logx.debugf("query %s %s from %s failed: %v", dns.type_name(q.type), q.name, client, uerr)
		/*
		The condition `cache.serve_stale` was always documented by: the refresh
		was attempted, and there is nothing to answer with but what expired.

		Only a failure to get an answer at all counts. An upstream that answered
		SERVFAIL answered, and a response this server refused to hand on -
		because it did not validate - was refused deliberately; serving expired
		data instead of either would be reaching past a verdict rather than
		covering an outage. RFC 8767 section 5 leaves both open; neither is
		decided here.
		*/
		if stale_hit.wire != nil {
			return serve_from_cache(s, stale_hit, query, msg, q, proto, client, limit, validating, started, allocator)
		}
		sync.atomic_add(&s.stats.failed, 1)
		out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
		log_query(s, client, proto, q, .Failed, "upstream", started)
		return out, .Failed, built
	}

	// The answer carries the ID we forwarded with, which is not the client's and
	// on a DoH upstream is zero. The client is waiting on its own.
	dns.set_id_in_place(resp, msg.id)

	if validating {
		result := dnssec.validate(s.validator, q.name, q.type, resp, time.now(), allocator)
		#partial switch result.status {
		case .Bogus, .Indeterminate:
			sync.atomic_add(&s.stats.bogus, 1)
			sync.atomic_add(&s.stats.failed, 1)
			logx.warnf(
				"dnssec: %s %s from %s did not validate: %v (%s)",
				dns.type_name(q.type),
				dns.name_trim_root(q.name),
				client,
				result.status,
				result.reason,
			)
			out, built := dnssec_failure_response(msg, result, allocator, limit)
			log_query(s, client, proto, q, .Failed, "dnssec", started)
			return out, .Failed, built
		case .Secure:
			sync.atomic_add(&s.stats.secure, 1)
		}
		resp = present_response(resp, msg, q.type, result, allocator)
	}

	// Before the cache, not after it: an answer stored first is one every later
	// client is served without this running again. See `rebind.odin`.
	if out, detail, blocked := rebind_refusal(s, msg, q, resp, limit, allocator); blocked {
		log_query(s, client, proto, q, .Blocked, detail, started)
		return out, .Blocked, true
	}

	/*
	The TTLs bounded once, here, so the client's copy and the entry's are the
	same bytes.

	RFC 2181 section 8 is not a setting and runs whatever the cache is doing: a
	TTL with the top bit set becomes zero, which tells the client to come back
	rather than to hold the record for sixty-eight years, and leaves `put` below
	with an `effective` of zero - so the answer is not kept either, unless
	`cache.min_ttl` raises it, which is the operator saying how long the shortest
	answer this cache keeps is good for and reaches a zeroed TTL like any other.
	Doing it in `cache.put` alone would leave the forwarded copy carrying the
	hostile figure to the client that caused the fetch, and with
	`cache.enabled: false` would leave every answer carrying it.

	The ceiling is the cache's `max_ttl`, and `ttl_ceiling` reports no ceiling
	when there is no cache, since the setting is then not in play at all. An
	answer forwarded on a miss is the same answer the next client is handed out
	of the entry it just filled, so bounding one and not the other would make
	the client that caused the fetch the one client the setting never reaches.
	This is the reading dnsmasq's `--max-ttl` has always had: the maximum TTL
	handed out to clients.

	`min_ttl` deliberately stays where it is, on the copies `cache.get` serves.
	A ceiling can only shorten what a client is told, which is safe wherever it
	is applied; the floor lengthens it, and it is honest on the way out of the
	cache because the entry really is being held that long. Applied here it
	would stretch the TTL of an answer that may not be kept at all - the cache
	can be off, and `put` refuses plenty of what it is handed.

	Above the decode below, not below it, so that `decoded` is a reading of the
	bytes as they now stand. The cache derives an entry's lifetime and its
	`redirects` flag from that decode while storing `resp` itself; bounding the
	wire afterwards would leave the two disagreeing about the same answer, with
	the entry outliving what its own bytes tell a client.

	After the rebinding refusal, not before it. An answer that refusal turns
	back is replaced wholesale, so bounding its TTLs first is work done on bytes
	nobody is handed - and `rebind.odin` reads the answer section, not the TTLs,
	so nothing it decides changes by waiting.

	Best-effort, and it does not refuse. `dns.cap_ttls` bounds every record it
	can read and stops at the first it cannot, which for the malformed messages
	that actually arrive means the answer section is bounded and the junk that
	follows it is not. Refusing the whole message instead - SERVFAIL, the way
	`fit_response` fails on the size ceiling - turned junk in an authority or
	additional section into a dead name whose answer section was perfectly good,
	which is the fail-closed-on-the-wrong-evidence the chain walk below spells
	out at length and settles the same way.

	What the ceiling gives up by not refusing is one forwarded copy of a message
	this server could not fully walk, with whatever TTLs sat past the point the
	walk stopped. Nothing is stored: `cache.put` scans with `scan_ttl_offsets`,
	which refuses what this walk stopped short on, so no entry pins the figure
	and no later client is served it.
	*/
	dns.cap_ttls(resp, cache.ttl_ceiling(s.answers))

	/*
	Decoded once for the two things below that both need it: the chain walk reads
	the answer section, and the cache reads the whole message. Decoding for each
	of them separately meant a second full pass over every forwarded response,
	which is the one part of this that every query pays for.

	Skipped when neither of them will run, which is the only arrangement that was
	not already paying for a decode here.
	*/
	decoded: dns.Message
	have_decoded := false
	walking := s.cfg.blocking.enabled && s.filters != nil
	if s.cfg.cache.enabled || walking {
		if d, dec_err := dns.decode_message(resp, allocator); dec_err == .None {
			decoded, have_decoded = d, true
		}
	}

	/*
	What the walk needs is the answer section, and only that.

	Read separately from the decode above, which wants the whole message because
	the cache stores the whole message. Holding the walk to that standard turned
	one malformed record in an authority or additional section - sections the
	walk never looks at - into SERVFAIL for a name whose answer section was
	clean, and only once blocking was on. That is not the check failing closed,
	it is the check refusing an answer it had no opinion about.

	Only reached when the full decode already failed, so the common path pays
	nothing for it.
	*/
	walk_answer: []dns.Record
	walkable := have_decoded
	if have_decoded {
		walk_answer = decoded.answer
	} else if walking {
		if d, dec_err := dns.decode_through_answer(resp, allocator); dec_err == .None {
			walk_answer, walkable = d.answer, true
		}
	}

	/*
	An answer the walk was going to look at and cannot read is refused.

	This read the other way round - hand it to the client, it is the upstream's
	answer and not ours to withhold over our own reading of it - which is a fair
	argument about an answer nobody was going to inspect, and the wrong one about
	an answer that was about to be checked. An answer section that does not
	decode is not walked, and serving what could not be walked is the same
	fail-open the `Unwalkable` verdict exists to refuse, reachable by writing one
	CNAME with a bad compression pointer or an RDLENGTH that runs off the end.
	The cloaked chain rides out in that same section, which a lenient stub parses
	perfectly well. `serve_from_cache` already refuses the stored equivalent; the
	two paths have to agree or the check is only as strong as whichever one an
	attacker picks.

	An allow rule on the question is honoured here as it is inside the walk. This
	gate sits above `block_cloaked_answer`, where that rule is otherwise read, so
	without asking for it the one escape hatch the blocking section documents
	would be the one hatch that did not open: an operator told to allowlist the
	name would find it refused anyway, under a detail that says unreadable rather
	than blocked.

	Gated on the walk actually being due. With blocking off there is nothing this
	would have checked, and refusing then would be this server withholding an
	answer over a parse it had no use for - which is what the old comment was
	right about.

	The cost is an upstream whose *answer sections* this decoder rejects becoming
	unresolvable rather than merely unfiltered, for the names it does that on.
	Every rejection is a name or a length that ran outside the message, which a
	client has to reject too, so the answer was not going to be usable; and the
	failure says so in the query log rather than passing something through
	unchecked.
	*/
	if walking && !walkable && filter.engine_match(s.filters, q.name) != .Allowed {
		/*
		No stale fallback, deliberately, and it had one for a round.

		The rule for that is set out where the upstream fails, above: expired
		data covers an outage, and only a failure to get an answer at all counts
		as one. This is not an outage. The upstream answered, and this server
		refused what it said - the same shape as the DNSSEC verdict below, which
		returns without reaching for `stale_hit` for the same reason. Serving
		expired data over a refusal reaches past a verdict rather than covering
		anything, and it tells the operator the wrong story besides: `detail=stale`
		and a climbing `elodin_cache_stale_total` say the upstream is down while
		it is answering perfectly well.
		*/
		sync.atomic_add(&s.stats.failed, 1)
		out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
		log_query(s, client, proto, q, .Failed, "answer-unreadable", started)
		return out, .Failed, built
	}

	/*
	The answer is stored anyway, with the refusal stamped on it.

	Leaving it out was the first shape of this, on the reasoning that an answer
	this server will not hand out is not one to keep a copy of. What that missed
	is which case it applies to: a cloaked name that is *not* already cached -
	the ordinary one, and the one an attacker arranges - then costs an upstream
	round trip on every single query, forever, because nothing about the refusal
	is remembered. A name blocked on the question costs none at all. So the
	cheapest name to serve became one of the most expensive, and the memoisation
	built for the hit path stopped short of the case that needed it most.

	Storing it does not put the hole back: the entry carries the verdict, so the
	hit path serves the refusal from it rather than the bytes, and it is walked
	again as soon as a reload moves the generation past its stamp. The bytes are
	kept only so that later walk has something to walk.

	Behind validation, because an answer that will not be served at all is not one
	to spend a list lookup on - and the order cannot change a verdict, since
	everything this can decide is to withhold an answer the validator was willing
	to pass.
	*/
	/*
	Settled here, above everything that might store these bytes, rather than
	beside one of the stores.

	`validating` is recomputed for every request and can be turned off after the
	key is built - the upstream query failing to rebuild does exactly that - so
	nothing otherwise ties the AD bit an entry carries to whether that entry was
	ever validated. A later request that does validate reads the stored bit as a
	verdict of ours and hands the upstream's claim to a client under our name.

	It lived next to the ordinary store until a second store was added below it,
	for an answer refused as cloaked, and quietly did not get it: that entry went
	in carrying the upstream's bit, and a reload that cleared the name later
	served it with the bit intact. One statement above both is what stops the
	third one being written without it.
	*/
	if !validating {
		set_ad_bit(resp, false)
	}

	if walkable {
		if out, verdict := block_cloaked_answer(
			s,
			walk_answer,
			msg,
			q,
			proto,
			client,
			limit,
			started,
			allocator,
		); verdict != .Clear {
			/*
			`have_decoded`, not `walkable`. The two part company for an answer
			whose section beyond the answer would not parse: the walk runs on the
			partial decode, and `decoded` is still the zero message it was
			declared as.

			Storing from that puts an entry in built from nothing to do with
			these bytes. `scan_ttl_offsets` is far more forgiving than the
			decoder - it follows no compression pointers and bounds no name - so
			it succeeds on the real wire and the entry goes in with
			`redirects = false` and a lifetime derived as if the answer were a
			denial. `redirects = false` is the trap: `get` computes `recheck`
			from it, so the entry can never be re-walked, and the refusal it
			carries is replayed on every hit until it expires. An operator who
			then writes the documented allow rule and reloads gets nothing - the
			name stays blocked against the very rule meant to release it, which
			is the opposite of the invariant the comment above states.

			So it is not cached at all in that case. The next query for the name
			asks the upstream again, which is what happened before any of this
			was memoised.
			*/
			/*
			`Unreadable` is not stored. The other two verdicts are stable
			properties of an answer somebody built - a name is on a list, a chain
			is seventeen long - and they are worth remembering, which is the
			whole argument for storing a refusal at all: without it the cheapest
			name to refuse becomes the most expensive one to serve.

			A record this decoder could not parse is not that. It is as likely to
			be an upstream or a middlebox having a bad day as an attack, which is
			the same reasoning that gives it SERVFAIL rather than the operator's
			block response - and memoising it takes that reasoning back. Stored,
			one malformed CNAME pins the name to SERVFAIL for up to
			`cache.max_ttl`, a day by default, with the upstream never asked
			again; a list reload does not release it either, because the re-walk
			reads the same stored bytes and reaches the same verdict. The name
			stays broken until the entry expires, for a record the upstream may
			have stopped sending within the minute.

			So it goes unstored and the next query asks again, which is what the
			whole-message version of this - `answer-unreadable` above - already
			does.
			*/
			if s.cfg.cache.enabled && have_decoded && cloak_verdict_worth_keeping(verdict) {
				cache.put(s.answers, key, resp, decoded, generation, u8(verdict))
			}
			return out, cloak_outcome(verdict), true
		}
	}

	if s.cfg.cache.enabled && have_decoded {
		cache.put(s.answers, key, resp, decoded, generation)
	}

	sync.atomic_add(&s.stats.forwarded, 1)
	out := fit_response(resp, limit, msg, allocator)
	settle_ad_bit(out, msg, validating)
	name := winner.spec.name if winner != nil else "?"
	log_query(s, client, proto, q, .Forwarded, name, started)
	return out, .Forwarded, true
}

/*
A hit as `resolve_query` found it.

Carried as one value because these seven travel together from `cache.get` to
whichever of the three places ends up serving them, and because what has to be
done with them - re-match the chain, then put the stamp back on the entry the
bytes came out of - needs all seven at once.
*/
@(private)
Cached_Answer :: struct {
	// The stored response, already copied into this request's arena.
	wire:    []u8,
	// What the entry is stored under, and which entry it was, so the stamp goes
	// back on the answer that was looked at rather than on whatever has replaced
	// it since.
	key:     string,
	serial:  u64,
	stale:   bool,
	recheck: bool,
	// What the last walk decided, as a `Cloak_Verdict`, when `recheck` says that
	// decision is current. Stored as the byte the cache keeps rather than the
	// enum, which is the caller's type and not the cache's.
	refused: u8,
	// The rule sets the re-match is made against, and the number stamped on the
	// entry when it comes back clean.
	checked: u64,
}

/*
Hand a stored answer to the client that asked for it.

The fresh hit and the stale fallback are the same answer as far as everything
downstream is concerned - the same transaction ID to put back, the same question
case to restore, the same verdict to settle, the same limit to fit - and they go
through one procedure so that a step added for one of them cannot be missed for
the other. The two differ in what an operator is told: `hit.stale` is what the
query log reports as the detail, and what tells the cache that the copy it lent
out was used.

Counted as a cached query either way, because that is what happened: the client
was answered from this server's cache without an upstream producing the answer.
The upstream failure behind a stale answer is a debug line of its own and not a
failed query - the client got an answer. The exception is an entry the lists now
refuse, which never becomes a served answer at all and is counted as the block
it is.
*/
@(private)
serve_from_cache :: proc(
	s: ^Server,
	hit: Cached_Answer,
	query: []u8,
	msg: dns.Message,
	q: dns.Question,
	proto: Protocol,
	client: string,
	limit: int,
	validating: bool,
	started: time.Time,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	/*
	An answer the lists have not been over since they last changed is matched
	again before it is served, and only then.

	Lists are reloaded under a running server and the answer cache is not touched
	by the swap, so an entry can outlive the reload that named something in its
	chain. The question side of the same rule set is matched on every query - it
	runs before the cache is consulted at all - so an entry left alone here would
	make one half of a rule take effect on the next query and the other half when
	the TTL ran out, up to `cache.max_ttl` later.

	What it must not cost is a decode per hit. `cache.get` answers that: an entry
	whose answer section goes nowhere never asks for this at all, and one that
	does asks only while the number it was stored under is behind the rule sets in
	force. `note_checked` then puts the number forward, so a chain is walked once
	per reload rather than once per hit - which is the whole of what this costs in
	the steady state, against the copy and the handful of TTL writes that serving
	a hit is meant to be.

	Clearing the cache in `reload_filters` instead is one line and was not taken:
	it throws away every unrelated entry on every refresh interval, and buys a
	burst of upstream traffic each time to re-learn answers nothing was wrong
	with.

	An entry that is refused stays where it is, and its refusal is stamped on it
	along with the number. Nothing here can tell whether the next reload will put
	it back in service, and dropping it would cost an upstream query per client
	query until something did.

	Keeping it and *not* recording the verdict was the first shape of this, and
	it was wrong in a way worth naming: an entry cannot be stamped as merely
	checked, because a stamp says "serve it", so the refusal had to be re-derived
	from the bytes on every hit - a decode and a walk, on the hot path, at
	whatever rate a client cares to ask, for as long as the entry lived. That is
	the per-hit decode the stamp exists to avoid, reintroduced for exactly the
	names an attacker is interested in. With the verdict recorded, a refused
	entry costs one walk per reload like any other.
	*/
	if !hit.recheck && cloak_refusal_stands(s) {
		if verdict := Cloak_Verdict(hit.refused); verdict != .Clear {
			/*
			No target, because the entry does not carry one. The name that
			matched was a name in the stored answer's chain, and keeping a copy
			of it would mean the cache holding a string on the caller's behalf
			for the sake of one debug line. What the entry does carry is which
			of the two refusals it was, so the query log says the same thing for
			this hit as it said for the walk that decided it.
			*/
			cache.note_withheld(s.answers)
			out := refuse_cloaked(s, "", verdict, msg, q, proto, client, limit, started, allocator)
			return out, cloak_outcome(verdict), true
		}
	}
	if hit.recheck {
		// The entry decoded once already, on the way in, so this is the copy being
		// decoded rather than a question of whether it can be. That rests on the
		// two `have_decoded` guards at the stores above and not on anything
		// `cache.put` checks: `put` never decodes, it takes an already-decoded
		// message and trusts it to describe the bytes beside it. A third store
		// written without that guard would break this quietly.
		if stored, derr := dns.decode_message(hit.wire, allocator); derr == .None {
			if out, verdict := block_cloaked_answer(
				s,
				stored.answer,
				msg,
				q,
				proto,
				client,
				limit,
				started,
				allocator,
			); verdict != .Clear {
				/*
				A verdict not worth keeping takes the entry with it. Stamping it
				would pin the name until the entry expired - the forwarding path
				declines to store one for that reason, and this path reaches the
				same verdict from bytes that are already stored, so the only way
				to decline it here is to drop them.

				An entry can arrive at this branch having gone in clean: stored
				while the question was allowlisted, or with a listed name at the
				same owner scanned before the malformed one. The rule changes,
				the re-walk reaches the record this decoder cannot read, and
				without this the answer is pinned to SERVFAIL from then on with
				the upstream never asked again.
				*/
				if cloak_verdict_worth_keeping(verdict) {
					cache.note_checked(s.answers, hit.key, hit.serial, hit.checked, u8(verdict))
				} else {
					cache.forget(s.answers, hit.key, hit.serial)
				}
				cache.note_withheld(s.answers)
				return out, cloak_outcome(verdict), true
			}
			// Inside the decode, not after it. An entry nothing could read has
			// not been looked at, and stamping it here would say it had - which
			// is the one way this mechanism could come to skip a walk it owed.
			// Unreachable as things stand, because both stores are guarded on
			// `have_decoded`, and not a thing to leave resting on that.
			cache.note_checked(s.answers, hit.key, hit.serial, hit.checked, u8(Cloak_Verdict.Clear))
		} else {
			/*
			The stored bytes would not decode, so the walk it is owed cannot be
			run at all - and an answer this server could not check is one it
			withholds, exactly as it withholds a chain that outran the budget.

			Serving it was the other way this could have gone and it is the same
			mistake `Unwalkable` exists to refuse: the check is not a thing to
			skip on the inputs that defeat it. Nothing reaches here as things
			stand - `cache.put` stores no message it could not read - which is
			the reason refusing costs nothing, not a reason to fall through.

			The entry is dropped rather than stamped. It cannot be walked on any
			later hit either, so leaving it would refuse this name for as long
			as it lived; dropping it sends the next query upstream for an answer
			that can be read.
			*/
			cache.forget(s.answers, hit.key, hit.serial)
			cache.note_withheld(s.answers)
			sync.atomic_add(&s.stats.failed, 1)
			out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
			log_query(s, client, proto, q, .Failed, "cache-unreadable", started)
			return out, .Failed, built
		}
	}

	wire := hit.wire
	dns.set_id_in_place(wire, msg.id)
	dns.copy_question_case(wire, query)
	// The stored answer carries the verdict; whether this client gets to hear it
	// is a separate question.
	settle_ad_bit(wire, msg, validating)
	if hit.stale {
		cache.note_stale_served(s.answers)
	}
	sync.atomic_add(&s.stats.cached, 1)
	out := fit_response(wire, limit, msg, allocator)
	log_query(s, client, proto, q, .Cached, "stale" if hit.stale else "cache", started)
	return out, .Cached, true
}

/*
Largest response the transport will carry.

UDP is bound by what the client advertised via EDNS0 and by
`server.max_udp_response`, whichever is smaller. The client's number is a
request, not a promise: it arrives on a datagram whose source is unverified, so
an attacker aiming answers at somebody else advertises the largest buffer it can
and that number is its amplification factor. The configured ceiling is what
bounds it.

The stream transports are bound only by the DNS framing. A connection was
established before the query arrived, so there is nothing to reflect and no
reason to make a client ask twice for an answer that fits.
*/
@(private)
response_limit :: proc(s: ^Server, msg: dns.Message, proto: Protocol) -> int {
	if proto == .UDP {
		// Floored by `udp_ceiling` rather than trusted to be in range: a zero
		// ceiling read straight through would truncate every answer to nothing.
		return min(int(dns.edns_udp_size(msg)), udp_ceiling(s))
	}
	return dns.MAX_MESSAGE
}

/*
Shrink an already-encoded response to fit `limit`.

Forwarded answers are normally sized correctly because the client's own EDNS0
options are passed through to the upstream. A cached answer, though, may have
been stored for a client that advertised a larger buffer, and `limit` on UDP is
`server.max_udp_response` where that is the smaller of the two - a number no
upstream was ever told about. Both are re-encoded here with the truncation rules
and the TC bit set.

Whatever comes back is no larger than `limit`, on every path including the ones
that fail. That is what the callers rely on: this is the last thing between an
answer and the wire.
*/
@(private)
fit_response :: proc(wire: []u8, limit: int, query: dns.Message, allocator: mem.Allocator) -> []u8 {
	if len(wire) <= limit {
		return wire
	}
	report_udp_ceiling(wire, limit, query)
	if decoded, err := dns.decode_message(wire, allocator); err == .None {
		if out, _, enc_err := dns.encode_message(decoded, allocator, limit); enc_err == .None {
			return out
		}
	}
	/*
	Nothing could be re-encoded, and what is in hand is over the limit.

	Sending it as it stands is the tempting answer - the bytes are a valid
	message, just a larger one than was asked for - and it is what this did when
	either step failed. On UDP that is the one outcome the limit exists to
	prevent: `limit` there is `server.max_udp_response`, which is an
	amplification factor, and an answer that reaches it by failing to re-encode
	is exactly as large as one that was allowed to. The ceiling has to hold on
	the paths that go wrong or it is not a ceiling.

	Neither step is reachable from a well-formed answer - a message that decoded
	re-encodes, and one that did not is answered from the query instead - which
	is the reason to settle it here rather than to reason about how an upstream
	might arrive at one. The client is told to ask again over TCP, where the
	address is proven and the whole answer fits. If even that cannot be built,
	nothing is sent: a client that waits out its timeout is a better failure than
	a datagram this server promised not to send.
	*/
	out, ok := dns.error_response(wire, query, .No_Error, allocator, limit)
	if !ok || len(out) < dns.HEADER_SIZE || len(out) > limit {
		return nil
	}
	out[2] |= 0x02
	return out
}

/*
Say so, once, when `server.max_udp_response` is what cut an answer short.

A client that advertised a small buffer and got a truncated answer got what it
asked for, and nothing here is worth telling anybody. A client that asked for
more than the ceiling and was held to the ceiling is a different thing: the
answer is on its way back over TCP, one round trip slower, because of a number
in the configuration - and that number is only findable if something says which
one it is. So the message names the setting, the two sizes, and what the trade
is in both directions.

Once, at warn, and every time after at debug. The condition is per-answer, so a
resolver serving one large signed zone would otherwise print this for every
query about it, and a line repeated ten thousand times is one an operator
filters out rather than reads.
*/
@(private)
udp_ceiling_reported: bool

@(private)
report_udp_ceiling :: proc(wire: []u8, limit: int, query: dns.Message) {
	// Not our ceiling: the client asked for no more than this, so the
	// truncation is the client's own arithmetic and not something to change.
	if limit >= int(dns.edns_udp_size(query)) {
		return
	}
	name := query.question[0].name if len(query.question) > 0 else "?"
	if sync.atomic_exchange(&udp_ceiling_reported, true) {
		logx.debugf(
			"server.max_udp_response truncated a %d-byte answer for %s to %d bytes",
			len(wire),
			name,
			limit,
		)
		return
	}
	logx.warnf(
		"a %d-byte answer for %s was truncated to %d bytes and the client told to retry over TCP: it asked for %d, and server.max_udp_response is %d",
		len(wire),
		name,
		limit,
		int(dns.edns_udp_size(query)),
		limit,
	)
	logx.warnf(
		"to send it over UDP instead, raise server.max_udp_response in the configuration (up to %d); the cost is that a spoofed query can make this server send that much to an address it did not verify",
		config.MAX_UDP_RESPONSE,
	)
	logx.warnf("further truncations at this ceiling are logged at debug level")
}

@(private)
build_block_response :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	ttl := s.cfg.blocking.block_ttl

	rcode := dns.Rcode.No_Error
	answers := make([dynamic]dns.Record, 0, 1, allocator)

	switch s.cfg.blocking.response {
	case .NX_Domain:
		rcode = .NX_Domain
	case .Refused:
		rcode = .Refused
	case .No_Data:
	// NOERROR with an empty answer section
	case .Zero_IP:
		#partial switch q.type {
		case .A:
			append(&answers, dns.Record{name = q.name, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{}})
		case .AAAA:
			append(&answers, dns.Record{name = q.name, type = .AAAA, class = .IN, ttl = ttl, data = dns.Rdata_AAAA{}})
		}
	case .Custom_IP:
		#partial switch q.type {
		case .A:
			append(
				&answers,
				dns.Record {
					name = q.name,
					type = .A,
					class = .IN,
					ttl = ttl,
					data = dns.Rdata_A{addr = s.cfg.blocking.custom_ipv4},
				},
			)
		case .AAAA:
			append(
				&answers,
				dns.Record {
					name = q.name,
					type = .AAAA,
					class = .IN,
					ttl = ttl,
					data = dns.Rdata_AAAA{addr = s.cfg.blocking.custom_ipv6},
				},
			)
		}
	}

	resp := dns.make_response(query, rcode, allocator)
	resp.answer = answers[:]
	if len(answers) == 0 && rcode != .Refused {
		// An SOA in the authority section tells resolvers how long to remember
		// this, which keeps blocked names from being re-asked every second.
		resp.authority = synth_soa(q.name, ttl, allocator)
	}

	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		fallback, _ := dns.error_response(nil, query, rcode, allocator, limit)
		return fallback
	}
	return out
}

/*
A minimal SOA for a name we are answering for locally.

`apex` names the zone the record is to be owned by, for a caller that knows one:
the special-use table does, and the parent of `a.b.onion.` is `b.onion.`, which
nobody has ever been authoritative for. Empty falls back to the queried name's
parent, which is the best guess available to the blocking and rewrite paths -
they answer for names scattered through zones this server knows nothing about.
*/
@(private)
synth_soa :: proc(name: string, ttl: u32, allocator: mem.Allocator, apex := "") -> []dns.Record {
	zone := apex
	if zone == "" {
		zone = dns.name_parent(name)
		if zone == "." {
			zone = name
		}
	}
	return synth_soa_for_zone(zone, ttl, allocator)
}

// The same, for a caller that knows the zone rather than a name inside it.
@(private)
synth_soa_for_zone :: proc(zone: string, ttl: u32, allocator: mem.Allocator) -> []dns.Record {
	recs := make([]dns.Record, 1, allocator)
	recs[0] = dns.Record {
		name = zone,
		type = .SOA,
		class = .IN,
		ttl = ttl,
		data = dns.Rdata_SOA {
			ns = "localhost.",
			mbox = "hostmaster.invalid.",
			serial = 1,
			refresh = 3600,
			retry = 900,
			expire = 604800,
			minimum = ttl,
		},
	}
	return recs
}

@(private)
apply_rewrite :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> (
	response: []u8,
	matched: bool,
) {
	/*
	The rules are walked rather than the first match taken, because a rule that
	only adds records to a name may have nothing to say about the type being
	asked for - see the fall-through below, and `rule_claims_name`.

	Stopping at the first match was what the search did while every rule
	answered for the whole of its name. It cannot now: with

	    - domain: mail.lan
	      answers: ["MX 10 mx.lan"]
	    - domain: "*.lan"
	      answers: [192.168.1.10]

	written in the order anybody writes it, specific before general, an `A`
	query for `mail.lan` matches the MX rule, finds nothing of its own type, and
	would leave for the upstream with the wildcard below never consulted - the
	internal name out of the building and a public answer coming back for it.
	So the search resumes at the rule after the one that had nothing, and the
	first rule with something to say is the one that answers.

	What it does not do is gather records from several rules into one answer. The
	first rule that answers is the whole of the answer, which is the precedence
	`rewrites` has always had; a name wanting an address and an MX wants them in
	one rule, and that is the rule the operator writes.
	*/
	from := 0
	records_held := false
	search: for {
		i, found := find_rewrite_index(s.cfg.rewrites, q.name, from)
		if !found {
			return nil, false
		}
		rule := s.cfg.rewrites[i]

		answers := make([dynamic]dns.Record, 0, len(rule.answers), allocator)
		blocked := false

		for a in rule.answers {
			switch a.kind {
			case .Block:
				blocked = true
			case .A:
				if q.type == .A || q.type == .ANY {
					append(
						&answers,
						dns.Record{name = q.name, type = .A, class = .IN, ttl = rule.ttl, data = dns.Rdata_A{addr = a.v4}},
					)
				}
			case .AAAA:
				if q.type == .AAAA || q.type == .ANY {
					append(
						&answers,
						dns.Record {
							name = q.name,
							type = .AAAA,
							class = .IN,
							ttl = rule.ttl,
							data = dns.Rdata_AAAA{addr = a.v6},
						},
					)
				}
			case .CNAME:
				// A CNAME answers every type; the client follows it from here.
				append(
					&answers,
					dns.Record {
						name = q.name,
						type = .CNAME,
						class = .IN,
						ttl = rule.ttl,
						data = dns.Rdata_Name{name = a.name},
					},
				)
			case .MX:
				if q.type == .MX || q.type == .ANY {
					append(
						&answers,
						dns.Record {
							name = q.name,
							type = .MX,
							class = .IN,
							ttl = rule.ttl,
							data = dns.Rdata_MX{preference = a.preference, exchange = a.name},
						},
					)
				}
			case .TXT:
				if q.type == .TXT || q.type == .ANY {
					append(
						&answers,
						dns.Record {
							name = q.name,
							type = .TXT,
							class = .IN,
							ttl = rule.ttl,
							data = dns.Rdata_TXT{strings = a.strings},
						},
					)
				}
			case .SRV:
				if q.type == .SRV || q.type == .ANY {
					append(
						&answers,
						dns.Record {
							name = q.name,
							type = .SRV,
							class = .IN,
							ttl = rule.ttl,
							data = dns.Rdata_SRV {
								priority = a.priority,
								weight = a.weight,
								port = a.port,
								target = a.name,
							},
						},
					)
				}
			}
		}

		/*
		No additional section, for the MX exchange or the SRV target.

		A zone's own server would put the target's address there and save the client
		a round trip, and this cannot: the target is a name in some other zone as
		often as not, and the only way to learn its address is to resolve it -
		upstream, from inside the procedure that exists to answer without going
		upstream. A client that needs the address asks for it, which is what every
		client already does when a real server declines to glue.
		*/

		if blocked {
			return build_block_response(s, query, q, allocator, limit), true
		}

		/*
		An alias cannot answer a name that some rule above it holds records for.

		The walk is what makes this reachable, and it is the same rule
		`answers_agree` enforces inside one rule (RFC 2181 section 10.1) meeting
		the case that spans two of them:

		    - domain: mail.lan
		      answers: ["MX 10 mx.lan"]
		    - domain: "*.lan"
		      answer: host.example.com

		An `A mail.lan` query walks past the MX rule and reaches the wildcard,
		and answering it with that CNAME would make `mail.lan` an alias and the
		holder of an MX at once - a client following the alias resolves the MX
		somewhere else and gets a different answer than this server just gave.
		By the time the walk has stepped past records, an alias is the one thing
		the rules below cannot say, so the rule is skipped whole: `answers_agree`
		has already established that a rule with a CNAME holds nothing else, so
		there is nothing else in it to lose.

		`block` is looked at first, above, and keeps its precedence: a rule that
		sinks the name is not making a claim about records at all.
		*/
		if records_held && rule_holds_alias(rule) {
			from = i + 1
			continue search
		}

		/*
		A rule that only adds records to a name does not get to answer for the rest
		of it.

		Every rule used to say where a name points - an address, an alias, or the
		sink - so a rule matching at all meant the name was this configuration's,
		and NODATA for a type it had no record of was the truthful answer: the name
		exists, here is everything there is. `MX`, `TXT` and `SRV` break that
		assumption, because the ordinary reason to write one is a name whose address
		is somebody else's business. `example.com` with two MX records and an SPF
		`TXT` is a real domain that resolves on the public Internet, and answering
		its `A` query NODATA out of this rule would take the website away from every
		client behind this server - with an SOA on it, so they would remember the
		denial for the rule's TTL.

		So a rule holding only these kinds is additive: the types it has are answered
		here and the rest are forwarded, which is what `--mx-host` and
		`--txt-record` do in dnsmasq, and what the operator meant by writing down one
		record rather than a name's whole existence. Add an address, an alias or
		`block` to the same rule and the old reading is back, deliberately: those are
		the answers that say the name is ours.

		`matched = false` is how the forwarding happens, so such a query is not
		counted as rewritten and not logged as one either. That is the honest
		accounting - nothing was rewritten - and it costs the operator the one signal
		that the rule was consulted at all. The alternative was a third outcome for
		the query log, which is a lot of machinery for a rule that did nothing.
		*/
		if len(answers) == 0 && !rule_claims_name(rule) {
			from = i + 1
			if len(rule.answers) > 0 {
				records_held = true
			}
			continue search
		}

		resp := dns.make_response(query, .No_Error, allocator)
		resp.answer = answers[:]
		if len(answers) == 0 {
			resp.authority = synth_soa(q.name, rule.ttl, allocator)
		}
		out, _, err := dns.encode_message(resp, allocator, limit)
		if err != .None {
			return nil, false
		}
		return out, true
	}
}

/*
Whether `rule` says where its name points, rather than only adding a record to
it.

An address, an alias and the sink are each an answer to "what is this name",
which is what earns a rule the right to say NODATA for the types it has no
record of. `MX`, `TXT` and `SRV` answer a different question about a name whose
own address is usually somebody else's to give, so a rule holding nothing but
those leaves the rest of the name alone. See `apply_rewrite`.
*/
@(private)
rule_claims_name :: proc(rule: config.Rewrite) -> bool {
	for a in rule.answers {
		switch a.kind {
		case .A, .AAAA, .CNAME, .Block:
			return true
		case .MX, .TXT, .SRV:
		}
	}
	return false
}

@(private)
find_rewrite :: proc(rules: []config.Rewrite, name: string) -> (rule: config.Rewrite, found: bool) {
	i := find_rewrite_index(rules, name) or_return
	return rules[i], true
}

/*
The same search, reporting which rule won rather than what it says.

`reverse.odin` needs the identity: a rule only gets to supply the PTR for its
address if it is the rule that would answer its own name, and "the same domain"
is not enough to decide that - a duplicated `domain:` is two rules with one name
between them, and only the first of them is ever reached. Both callers go
through one loop so that the precedence cannot be described twice and drift.
*/
// Whether `rule` makes the name an alias. `answers_agree` in the loader keeps a
// CNAME from sharing a rule with any record, so this is a property of the whole
// rule rather than of one answer. See `apply_rewrite`.
@(private)
rule_holds_alias :: proc(rule: config.Rewrite) -> bool {
	for a in rule.answers {
		if a.kind == .CNAME {
			return true
		}
	}
	return false
}

@(private)
find_rewrite_index :: proc(
	rules: []config.Rewrite,
	name: string,
	from := 0,
) -> (
	index: int,
	found: bool,
) {
	for r, offset in rules[from:] {
		i := offset + from
		if r.wildcard {
			// "*.lan." matches any strictly deeper name, which is `name_below`
			// exactly: the label-break guard that keeps "notlan." out of a rule
			// written for "lan.", and the case-insensitive comparison that DNS
			// requires, are both its business rather than this loop's.
			if name_below(name, r.domain) {
				return i, true
			}
			continue
		}
		if dns.name_equal_fold(name, r.domain) {
			return i, true
		}
	}
	return 0, false
}

// CHAOS-class queries used by monitoring tools: version.bind and hostname.bind.
@(private)
answer_chaos :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> (
	response: []u8,
	handled: bool,
) {
	if q.type != .TXT && q.type != .ANY {
		return nil, false
	}
	text: string
	switch {
	case dns.name_equal_fold(q.name, "version.bind."), dns.name_equal_fold(q.name, "version.server."):
		text = "elodin " + VERSION
	case dns.name_equal_fold(q.name, "hostname.bind."), dns.name_equal_fold(q.name, "id.server."):
		text = "elodin"
	case:
		return nil, false
	}

	strs := make([]string, 1, allocator)
	strs[0] = text
	answers := make([]dns.Record, 1, allocator)
	answers[0] = dns.Record {
		name = q.name,
		type = .TXT,
		class = .CH,
		ttl = 0,
		data = dns.Rdata_TXT{strings = strs},
	}

	resp := dns.make_response(query, .No_Error, allocator)
	resp.answer = answers
	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		return nil, false
	}
	return out, true
}

@(private)
log_query :: proc(
	s: ^Server,
	client: string,
	proto: Protocol,
	q: dns.Question,
	outcome: Outcome,
	detail: string,
	started: time.Time,
) {
	if !s.cfg.log.queries {
		return
	}
	elapsed := time.diff(started, time.now())
	/*
	Two of these are not this server's text, so both go through `quote`: a
	query name is bytes a client chose, and `detail` carries an upstream's name
	out of the configuration when one answered.

	Presentation form is not enough on its own. It escapes the control range,
	the space and the backslash, but `"` and `=` are printable and go through as
	they are - which are exactly the two bytes that would otherwise end the
	value early and let a name invent a field of its own.

	The rest are addresses, enum names and numbers.
	*/
	logx.eventf(
		.Info,
		"query",
		"client=%s proto=%s qtype=%s qname=%s outcome=%s detail=%s ms=%.1f",
		client,
		proto_name(proto),
		dns.type_name(q.type),
		logx.quote(dns.name_trim_root(q.name)),
		outcome_name(outcome),
		logx.quote(detail),
		time.duration_milliseconds(elapsed),
	)
}

@(private)
outcome_name :: proc(o: Outcome) -> string {
	switch o {
	case .Forwarded:
		return "forwarded"
	case .Cached:
		return "cached"
	case .Blocked:
		return "blocked"
	case .Rewritten:
		return "rewritten"
	case .Local:
		return "local"
	case .Failed:
		return "failed"
	case .Refused:
		return "refused"
	}
	return "unknown"
}

@(private)
proto_name :: proc(p: Protocol) -> string {
	switch p {
	case .UDP:
		return "udp"
	case .TCP:
		return "tcp"
	case .DoT:
		return "dot"
	case .DoH:
		return "doh"
	}
	return "?"
}

stats_of :: proc(s: ^Server) -> Stats {
	return Stats {
		queries = sync.atomic_load(&s.stats.queries),
		blocked = sync.atomic_load(&s.stats.blocked),
		cached = sync.atomic_load(&s.stats.cached),
		forwarded = sync.atomic_load(&s.stats.forwarded),
		failed = sync.atomic_load(&s.stats.failed),
		rewritten = sync.atomic_load(&s.stats.rewritten),
		dropped = sync.atomic_load(&s.stats.dropped),
		refused = sync.atomic_load(&s.stats.refused),
		conn_refused = sync.atomic_load(&s.stats.conn_refused),
		conn_failed = sync.atomic_load(&s.stats.conn_failed),
		secure = sync.atomic_load(&s.stats.secure),
		bogus = sync.atomic_load(&s.stats.bogus),
		rebind = sync.atomic_load(&s.stats.rebind),
		special_use = sync.atomic_load(&s.stats.special_use),
	}
}
