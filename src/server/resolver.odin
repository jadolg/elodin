package server

import "core:mem"
import "core:strings"
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
	queries:   u64,
	blocked:   u64,
	cached:    u64,
	forwarded: u64,
	failed:    u64,
	rewritten: u64,
	// Queries refused before any work was done, because the backlog was full.
	dropped:   u64,
	// Answers that carried a valid chain of signatures, and answers refused
	// because they did not.
	secure:    u64,
	bogus:     u64,
}

Server :: struct {
	cfg:          ^config.Config,
	group:        ^upstream.Group,
	answers:      ^cache.Cache,
	filters:      ^filter.Engine,
	validator:    ^dnssec.Validator,
	cookies:      ^Cookie_Keeper,
	handler_pool: ^pool.Pool,
	race_pool:    ^pool.Pool,
	stats:        Stats,
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
	if derr != .None {
		out, built := dns.error_response(query, {}, .Form_Err, allocator, response_limit(msg, proto))
		return out, .Failed, built
	}
	// A response arriving on a listener port is not something to answer.
	if msg.flags.qr {
		return nil, .Failed, false
	}

	cookie := inspect_cookie(s.cookies, msg, client)
	limit := response_limit(msg, proto)

	// A cookie of an impossible length is the one case RFC 7873 section 5.2.2
	// answers with FORMERR, and the one response that carries no cookie back:
	// there is no telling which eight of those bytes were the client's.
	if cookie.verdict == .Malformed {
		out, built := dns.error_response(query, msg, .Form_Err, allocator, limit)
		return out, .Failed, built
	}

	response, outcome, ok = resolve_query(s, query, msg, proto, client, limit, cookie, started, allocator)
	if ok {
		response = attach_cookie(s.cookies, response, cookie, msg, limit, allocator)
	}
	return response, outcome, ok
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
	5.2.3). Only UDP is checked; the stream transports already made the client
	prove it can receive at the address it claims.
	*/
	if proto == .UDP && s.cookies != nil && s.cookies.require && cookie.verdict == .Unproven {
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
	validating := s.validator != nil && !msg.flags.cd && q.class == .IN

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], q.name, q.type, q.class, dns.edns_do(msg), msg.flags.cd)

	if s.cfg.cache.enabled {
		if hit, stale, found := cache.get(s.answers, key, allocator); found {
			dns.set_id_in_place(hit, msg.id)
			dns.copy_question_case(hit, query)
			// The stored answer carries the verdict; whether this client gets to
			// hear it is a separate question.
			settle_ad_bit(hit, msg, validating)
			sync.atomic_add(&s.stats.cached, 1)
			out := fit_response(hit, limit, msg, allocator)
			log_query(s, client, proto, q, .Cached, "stale" if stale else "cache", started)
			return out, .Cached, true
		}
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
	*/
	if cookie.verdict != .Absent {
		if stripped, done := dns.remove_edns_option(forwarded, .Cookie, allocator); done {
			forwarded = stripped
		}
	}

	resp, winner, uerr := upstream.resolve(s.group, forwarded, allocator)
	if uerr != .None {
		sync.atomic_add(&s.stats.failed, 1)
		out, built := dns.error_response(query, msg, .Serv_Fail, allocator, limit)
		logx.debugf("query %s %s from %s failed: %v", dns.type_name(q.type), q.name, client, uerr)
		log_query(s, client, proto, q, .Failed, "upstream", started)
		return out, .Failed, built
	}

	// Upstream answers carry our forwarded ID already, but a DoH upstream is
	// asked with a zeroed ID, so set it unconditionally.
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

// Largest response the transport will carry. UDP is bound by what the client
// advertised via EDNS0; the stream transports are bound only by the DNS framing.
@(private)
response_limit :: proc(msg: dns.Message, proto: Protocol) -> int {
	if proto == .UDP {
		return int(dns.edns_udp_size(msg))
	}
	return dns.MAX_MESSAGE
}

/*
Shrink an already-encoded response to fit `limit`.

Forwarded answers are normally sized correctly because the client's own EDNS0
options are passed through to the upstream. A cached answer, though, may have
been stored for a client that advertised a larger buffer, so it is re-encoded
with the truncation rules and the TC bit set.
*/
@(private)
fit_response :: proc(wire: []u8, limit: int, query: dns.Message, allocator: mem.Allocator) -> []u8 {
	if len(wire) <= limit {
		return wire
	}
	decoded, err := dns.decode_message(wire, allocator)
	if err != .None {
		// Cannot re-encode it; a truncated header at least tells the client to
		// retry over TCP.
		out, ok := dns.error_response(wire, query, .No_Error, allocator, limit)
		if !ok {
			return wire
		}
		if len(out) >= 4 {
			out[2] |= 0x02
		}
		return out
	}
	out, _, enc_err := dns.encode_message(decoded, allocator, limit)
	if enc_err != .None {
		return wire
	}
	return out
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
			// "*.lan." matches any strictly deeper name.
			if len(name) > len(r.domain) && strings.has_suffix(name, r.domain) {
				// Guard against "notlan." matching "lan.".
				boundary := name[len(name) - len(r.domain) - 1]
				if boundary == '.' && dns.name_equal_fold(name[len(name) - len(r.domain):], r.domain) {
					return r, true
				}
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
	logx.infof(
		"%s %s %s %s -> %v (%s) %.1fms",
		client,
		proto_name(proto),
		dns.type_name(q.type),
		dns.name_trim_root(q.name),
		outcome,
		detail,
		time.duration_milliseconds(elapsed),
	)
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
		secure = sync.atomic_load(&s.stats.secure),
		bogus = sync.atomic_load(&s.stats.bogus),
	}
}
