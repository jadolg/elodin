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
}

Server :: struct {
	cfg:          ^config.Config,
	group:        ^upstream.Group,
	answers:      ^cache.Cache,
	filters:      ^filter.Engine,
	validator:    ^dnssec.Validator,
	// The zones of the operator's own trust anchors, root excluded, in canonical
	// form. An anchor here is a deliberate request to validate the zone it names,
	// which the locally-served bypass has to defer to; see `covered_by_local_anchor`.
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

	cookie := inspect_cookie(s.cookies, msg, client)

	// A cookie of an impossible length is the one case RFC 7873 section 5.2.2
	// answers with FORMERR, and the one response that carries no cookie back:
	// there is no telling which eight of those bytes were the client's.
	if cookie.verdict == .Malformed {
		out, built := dns.error_response(query, msg, .Form_Err, allocator, limit)
		return advertise_udp_size(out, advertise, proto), .Failed, built
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
	A DDR probe is answered from here and never forwarded - the upstream's
	designated resolvers are not ours to hand a client, and its unsigned answer
	under the signed `arpa` zone does not validate. See `ddr.odin`.

	Below the rewrites, so an operator who wants to designate this server's own
	DoT or DoH endpoints can say so and be obeyed; above the block lists and the
	cache, which have nothing to add to a name this server answers for itself.
	*/
	if is_resolver_arpa(q.name) {
		out := build_resolver_arpa_response(msg, q, allocator, limit)
		log_query(s, client, proto, q, .Local, "ddr", started)
		return out, .Local, true
	}

	if s.cfg.blocking.enabled && s.filters != nil {
		if filter.engine_match(s.filters, q.name) == .Blocked {
			sync.atomic_add(&s.stats.blocked, 1)
			out := build_block_response(s, msg, q, allocator, limit)
			log_query(s, client, proto, q, .Blocked, "list", started)
			return out, .Blocked, true
		}
	}

	// A client that sets CD is asking for the upstream's answer whatever we
	// think of it, so validation is skipped - and the answer is kept apart in
	// the cache so it cannot be served to a client that did want it checked.
	//
	// The RFC 6303 locally-served zones - the reverse trees for private,
	// link-local and loopback space - are skipped too. Nothing on the public
	// Internet signs them, so their unsigned local answers have no chain to
	// check and validating one only turns a LAN PTR lookup into SERVFAIL. They
	// are served as insecure, which is what `settle_ad_bit` records once
	// `validating` is off - unless the operator anchored the zone themselves, in
	// which case that request to validate it wins and the bypass stands down.
	validating :=
		s.validator != nil &&
		!msg.flags.cd &&
		q.class == .IN &&
		!(is_locally_served(q.name) && !covered_by_local_anchor(s, q.name))

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], q.name, q.type, q.class, dns.edns_do(msg), msg.flags.cd)

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
	stale_hit: []u8

	if s.cfg.cache.enabled {
		if hit, stale, found := cache.get(s.answers, key, allocator); found {
			if !stale {
				return serve_from_cache(s, hit, query, msg, q, proto, client, limit, validating, false, started, allocator)
			}
			stale_hit = hit
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
	query log is where this one shows, as `outcome=refused detail="rd"`, when
	`log.queries` is on.
	*/
	if !msg.flags.rd {
		if stale_hit != nil {
			return serve_from_cache(s, stale_hit, query, msg, q, proto, client, limit, validating, true, started, allocator)
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
	answering the question. Cookies towards the upstream, if they are ever
	wanted, are ours to negotiate separately.

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
		if stale_hit != nil {
			return serve_from_cache(s, stale_hit, query, msg, q, proto, client, limit, validating, true, started, allocator)
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
		resp = present_response(resp, msg, q.type, result.status == .Secure, allocator)
	}

	/*
	The TTLs bounded once, here, so the client's copy and the entry's are the
	same bytes.

	RFC 2181 section 8 is not a setting and runs whatever the cache is doing: a
	TTL with the top bit set becomes zero, which makes the answer uncacheable
	below - `effective` works out at zero - and tells the client to come back
	rather than to hold the record for sixty-eight years. Doing it in
	`cache.put` alone would leave the forwarded copy carrying the hostile figure
	to the client that caused the fetch, and with `cache.enabled: false` would
	leave every answer carrying it.

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
	*/
	_ = dns.cap_ttls(resp, cache.ttl_ceiling(s.answers), allocator)

	if s.cfg.cache.enabled {
		if decoded, dec_err := dns.decode_message(resp, allocator); dec_err == .None {
			/*
			Settled before the entry goes in, rather than only on the way out to
			this client.

			`validating` is recomputed for every request and can be turned off
			after the key is built - the upstream query failing to rebuild does
			exactly that - so nothing otherwise ties the AD bit an entry carries
			to whether that entry was ever validated. A later request that does
			validate reads the stored bit as a verdict of ours and hands the
			upstream's claim to a client under our name.
			*/
			if !validating {
				set_ad_bit(resp, false)
			}
			cache.put(s.answers, key, resp, decoded)
		}
	}

	sync.atomic_add(&s.stats.forwarded, 1)
	out := fit_response(resp, limit, msg, allocator)
	settle_ad_bit(out, msg, validating)
	name := winner.spec.name if winner != nil else "?"
	log_query(s, client, proto, q, .Forwarded, name, started)
	return out, .Forwarded, true
}

/*
Hand a stored answer to the client that asked for it.

The fresh hit and the stale fallback are the same answer as far as everything
downstream is concerned - the same transaction ID to put back, the same question
case to restore, the same verdict to settle, the same limit to fit - and they go
through one procedure so that a step added for one of them cannot be missed for
the other. The two differ in what an operator is told: `stale` is what the query
log reports as the detail, and what tells the cache that the copy it lent out
was used.

Counted as a cached query either way, because that is what happened: the client
was answered from this server's cache without an upstream producing the answer.
The upstream failure behind a stale answer is a debug line of its own and not a
failed query - the client got an answer.
*/
@(private)
serve_from_cache :: proc(
	s: ^Server,
	hit: []u8,
	query: []u8,
	msg: dns.Message,
	q: dns.Question,
	proto: Protocol,
	client: string,
	limit: int,
	validating: bool,
	stale: bool,
	started: time.Time,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	dns.set_id_in_place(hit, msg.id)
	dns.copy_question_case(hit, query)
	// The stored answer carries the verdict; whether this client gets to hear it
	// is a separate question.
	settle_ad_bit(hit, msg, validating)
	if stale {
		cache.note_stale_served(s.answers)
	}
	sync.atomic_add(&s.stats.cached, 1)
	out := fit_response(hit, limit, msg, allocator)
	log_query(s, client, proto, q, .Cached, "stale" if stale else "cache", started)
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

// A minimal SOA for a name we are answering for locally.
@(private)
synth_soa :: proc(name: string, ttl: u32, allocator: mem.Allocator) -> []dns.Record {
	zone := dns.name_parent(name)
	if zone == "." {
		zone = name
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
	rule, found := find_rewrite(s.cfg.rewrites, q.name)
	if !found {
		return nil, false
	}

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
		}
	}

	if blocked {
		return build_block_response(s, query, q, allocator, limit), true
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

@(private)
find_rewrite :: proc(rules: []config.Rewrite, name: string) -> (rule: config.Rewrite, found: bool) {
	for r in rules {
		if r.wildcard {
			// "*.lan." matches any strictly deeper name, which is `name_below`
			// exactly: the label-break guard that keeps "notlan." out of a rule
			// written for "lan.", and the case-insensitive comparison that DNS
			// requires, are both its business rather than this loop's.
			if name_below(name, r.domain) {
				return r, true
			}
			continue
		}
		if dns.name_equal_fold(name, r.domain) {
			return r, true
		}
	}
	return {}, false
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
	}
}
