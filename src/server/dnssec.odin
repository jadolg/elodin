package server

import "core:mem"
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

// A signed answer rarely fits in 512 bytes, so our own upstream queries always
// advertise room for one.
UPSTREAM_UDP_SIZE :: 4096

// Extended DNS error codes, RFC 8914. Sent only to clients that use EDNS0,
// which is the only place there is to put them.
EDE_DNSSEC_BOGUS :: 6
EDE_NO_REACHABLE_AUTHORITY :: 22

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

	anchors: []dnssec.Trust_Anchor
	if len(s.cfg.dnssec.trust_anchors) > 0 {
		parsed := make([dynamic]dnssec.Trust_Anchor, 0, len(s.cfg.dnssec.trust_anchors))
		for line in s.cfg.dnssec.trust_anchors {
			anchor, ok := dnssec.parse_trust_anchor(line)
			if !ok {
				logx.errorf("dnssec: cannot read trust anchor %q", line)
				delete(parsed)
				return false
			}
			append(&parsed, anchor)
		}
		anchors = parsed[:]

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

	s.validator = dnssec.make_validator(
		validator_query,
		s,
		dnssec.Options{anchors = anchors, max_nsec3_iterations = s.cfg.dnssec.max_nsec3_iterations},
	)
	logx.infof(
		"dnssec: validating against %d trust anchor(s)",
		len(anchors) if len(anchors) > 0 else len(dnssec.root_anchors()),
	)
	return true
}

stop_validator :: proc(s: ^Server) {
	dnssec.destroy_validator(s.validator)
	s.validator = nil
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
	response, _, uerr := upstream.resolve(s.group, asked, allocator)
	if uerr != .None {
		logx.debugf("dnssec: %s %s could not be fetched: %v", dns.type_name(type), name, uerr)
		return nil, false
	}
	return response, true
}

/*
Re-ask the client's question with DO and CD set.

The client's own EDNS options ride along - a subnet hint still belongs to it -
but the payload size and the DO bit are ours. Its cookie is taken back out
further down, and its transaction ID replaced, once this and the plain
forwarding path have converged.
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

A client that set DO asked for the whole thing and gets it byte for byte. One
that did not has the DNSSEC records taken back out, because RFC 4035 says not to
send them unasked and because they would otherwise push ordinary answers past
the point where they need a retry over TCP.
*/
@(private)
present_response :: proc(
	wire: []u8,
	query: dns.Message,
	qtype: dns.Type,
	secure: bool,
	allocator: mem.Allocator,
) -> []u8 {
	out := wire
	if !dns.edns_do(query) {
		/*
		Rebuilt at full size rather than at this client's limit. What comes back
		here is what goes into the cache, and a copy trimmed to one client's UDP
		buffer would then be all any later client could be given. Shrinking to
		fit is `fit_response`'s job, once per client.
		*/
		out = strip_dnssec_records(wire, query, qtype, allocator, dns.MAX_MESSAGE)
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
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	msg, err := dns.decode_message(wire, allocator)
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
The answer for a question whose response did not check out.

SERVFAIL is the only correct reply: an answer that cannot be authenticated must
not reach the client, and there is nothing else to send. The extended error says
which of the two reasons it was, so the difference between a forged answer and
an unreachable parent zone is visible from the client side.
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
	code := u16(EDE_DNSSEC_BOGUS) if result.status == .Bogus else u16(EDE_NO_REACHABLE_AUTHORITY)
	resp := dns.make_response(query, .Serv_Fail, allocator)
	attach_extended_error(&resp, code, result.reason, allocator)

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
