package server

import "core:testing"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

/*
The room reserved for an OPT record has to be the room the record actually
takes.

`encode_message` keeps space behind a cut for the message's OPT record, measured
with `opt_wire_len` on the message it is handed - and on a forwarded or a cached
answer that record is the upstream's, options and all. `match_client_opt` and
`normalise_client_opt` then make it this server's own: the options come out, or
the whole record does for a client that asked without EDNS. Every byte of that
is room the encoder had already spent, so an answer fitted before the record was
settled is packed against a ceiling lower than the one it goes out under.

Nothing put those records back, and the client is the one that paid for it. Two
ways, both here:

  - a TCP round trip for records that fitted. The answer is cut and TC set, the
    client asks again over TCP, and the datagram it was sent had room for the
    rest all along;
  - an additional record dropped in silence. In the additional section it is a
    glue address that pays for the OPT record's room, which is the right trade
    when the room is real (see `dns.additional_overflow_test`). Nothing on the
    wire says an additional record was left out, so a client simply never learns
    the address - and there is no TC to send it back for the rest.

Both are pinned against a cached answer, which is the shortest way to a reply
carrying an upstream's OPT record with the size chosen here: the entry is stored
with the record an upstream would have written, and the cache key does not carry
EDNS presence, so the same bytes answer a client that asked with EDNS and one
that asked without. Issue #281.
*/

@(private = "file")
QNAME :: "reserve.example.com."

// An address record in the additional section that is nobody's in-domain glue:
// the answer section is not empty, so `omitted_glue_truncates` says leaving it
// out is not a truncation, and a client that loses it is told nothing.
@(private = "file")
EXTRA_NAME :: "ns.other.example."

@(private = "file")
CLIENT :: "198.51.100.7:9999"

// The OPT record's own encoded length: a root owner name, TYPE, CLASS, TTL and
// RDLENGTH. What this server sends, and what it should therefore reserve.
@(private = "file")
OPT_LEN :: 11

/*
The NSID an upstream wrote into the record it answered with: four bytes of
option header and twenty of payload.

An option, rather than the length of one, because these are the bytes that must
not reach a client (RFC 6891 section 6.1.1) and so the bytes
`normalise_client_opt` hands back after the answer has been packed. NSID is the
plain case - it names the instance that answered a question this client never
asked - and any other option of an upstream's would do as well.
*/
@(private = "file")
NSID_LEN :: 20

@(private = "file")
OPTION_LEN :: 4 + NSID_LEN

/*
An answer as an upstream would have sent it: `records` addresses for the
question, an OPT record carrying an NSID, and optionally one more address record
in the additional section ahead of it.

The OPT record goes last, where an OPT record goes, so the strip is the byte cut
rather than the rebuild - which is the shape a real upstream produces and the one
the sizes below are worked out against.
*/
@(private = "file")
upstream_answer :: proc(records: int, extra: bool) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}

	answer := make([]dns.Record, records, context.temp_allocator)
	for i in 0 ..< records {
		answer[i] = dns.Record {
			name  = QNAME,
			type  = .A,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_A{addr = {192, 0, 2, u8(1 + i)}},
		}
	}

	nsid := make([]u8, NSID_LEN, context.temp_allocator)
	for i in 0 ..< len(nsid) {
		nsid[i] = u8('a' + i % 26)
	}
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option {
		code = u16(dns.EDNS_Option_Code.NSID),
		data = nsid,
	}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}

	additional := make([dynamic]dns.Record, 0, 2, context.temp_allocator)
	if extra {
		append(
			&additional,
			dns.Record {
				name = EXTRA_NAME,
				type = .A,
				class = .IN,
				ttl = 300,
				data = dns.Rdata_A{addr = {192, 0, 2, 200}},
			},
		)
	}
	append(&additional, opt)

	m := dns.Message {
		id         = 0x4242,
		question   = question,
		answer     = answer,
		additional = additional[:],
	}
	m.flags.qr = true
	m.flags.ra = true

	encoded, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		return nil
	}
	return encoded
}

@(private = "file")
client_query :: proc(advertised: u16, edns: bool) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}

	msg := dns.Message {
		id       = 0x1234,
		question = question,
	}
	msg.flags.rd = true
	if edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(advertised, false)
		msg.additional = additional
	}

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
Answer one query out of the cache, so the client-facing path runs end to end
with no upstream behind it and the stored answer's size chosen here.

Cookies off: `attach_cookie` writes twenty-eight bytes into the same record
after the answer is encoded, which is a size question of its own and is pinned
in `cookie_fit_test.odin`.
*/
@(private = "file")
answer_once :: proc(t: ^testing.T, stored: []u8, query: []u8) -> (out: []u8, ok: bool) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.cookies.enabled = false

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], QNAME, .A, .IN, false, false)
	decoded, derr := dns.decode_message(stored, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return nil, false
	}
	if !cache.put(answers, key, stored, decoded) {
		testing.expect(t, false, "the answer was not cached")
		return nil, false
	}

	response, outcome, served := handle_query(&s, query, .UDP, CLIENT, context.temp_allocator)
	testing.expect_value(t, outcome, Outcome.Cached)
	return response, served
}

// What the cases below read off a reply.
@(private = "file")
Reply :: struct {
	answers:    int,
	// The additional records that are not the OPT record, which is the one an
	// EDNS client is owed and is counted separately.
	extra:      int,
	tc:         bool,
	opt:        bool,
	nsid:       bool,
	length:     int,
}

@(private = "file")
read_reply :: proc(t: ^testing.T, wire: []u8) -> (r: Reply) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect_value(t, err, dns.Decode_Error.None) {
		return {}
	}
	_, has_nsid := dns.find_edns_option(m, .NSID)
	r = Reply {
		answers = len(m.answer),
		tc      = m.flags.tc,
		opt     = dns.edns_present(m),
		nsid    = has_nsid,
		length  = len(wire),
	}
	for rec in m.additional {
		if rec.type != .OPT {
			r.extra += 1
		}
	}
	return r
}

/*
What one more answer record costs on the wire, measured rather than asserted, so
these cases do not have to be rewritten when name compression or the record
shape changes.
*/
@(private = "file")
per_record_cost :: proc(t: ^testing.T, records: int) -> int {
	shorter := upstream_answer(records, false)
	longer := upstream_answer(records + 1, false)
	if !testing.expect(t, len(shorter) > 0 && len(longer) > 0, "the answer would not encode") {
		return 0
	}
	return len(longer) - len(shorter)
}

/*
An answer cut to the client's datagram is cut to the client's datagram: if a
record was left out, the smallest one left out must not have fitted.

That is the whole of what TC buys the client. The answer here is past the buffer
whatever is done about the OPT record, so the cut and the TC bit are honest and
the retry over TCP is coming; what is not honest is how much was cut. The walk
back in `encode_message` sheds answer records until the OPT record fits behind
them, measured on the record it was handed - the upstream's, with its options -
and the options are gone by the time the datagram leaves. So the records nearest
the cut were dropped for room the strip handed back, and the client pays for them
on this round trip and again on the retry.

The property rather than a record count, for the reason the parity harness
(`pc_tc` in src/itest/parity_compare.odin) judges a truncation the same way: what
matters is that the datagram went out full, not which records happened to fill
it.
*/
@(test)
test_a_truncated_answer_is_filled_to_the_clients_datagram :: proc(t: ^testing.T) {
	stored := upstream_answer(40, false)
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}
	per_record := per_record_cost(t, 40)
	// Above the 512 floor `dns.edns_udp_size` clamps to and below the 1232
	// ceiling `udp_ceiling` holds, or the buffer under test is not the one the
	// answer is fitted to. Under the answer's own size, or nothing is cut.
	advertised := u16(600)
	if !testing.expectf(
		t,
		int(advertised) > 512 &&
		int(advertised) <= config.DEFAULT_MAX_UDP_RESPONSE &&
		len(stored) > int(advertised),
		"the answer is %d bytes, so %d is not the ceiling this cuts it to",
		len(stored),
		int(advertised),
	) {
		return
	}

	out, ok := answer_once(t, stored, client_query(advertised, true))
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect(t, r.tc, "an answer that lost records went out without TC")
	testing.expect(t, r.answers > 0, "the whole answer section went, so this is not the case under test")
	testing.expect(t, r.opt, "the truncated answer lost the OPT record it was cut to make room for")
	testing.expect(t, !r.nsid, "the upstream's NSID reached the client")
	testing.expectf(
		t,
		r.answers == 40 || r.length + per_record > int(advertised),
		"the answer was cut to %d bytes with %d of its 40 records, and another %d-byte record would have fitted the %d advertised",
		r.length,
		r.answers,
		per_record,
		int(advertised),
	)
	testing.expectf(t, r.length <= int(advertised), "the answer is %d bytes, past the %d advertised", r.length, int(advertised))

	free_all(context.temp_allocator)
}

/*
The same, for the additional record that used to pay for the options' room.

Worse for the client than the case above, and it is the same arithmetic: an
additional record left out sets no TC bit, so nothing in the reply says the
address was ever there. The client does not retry - it just never learns it.
*/
@(test)
test_an_additional_record_is_not_dropped_for_options_that_are_stripped :: proc(t: ^testing.T) {
	stored := upstream_answer(40, true)
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}
	advertised := u16(len(stored) - OPTION_LEN)
	if !testing.expectf(
		t,
		int(advertised) > 512 && int(advertised) <= config.DEFAULT_MAX_UDP_RESPONSE,
		"the answer is %d bytes, so %d is not this client's limit",
		len(stored),
		int(advertised),
	) {
		return
	}

	out, ok := answer_once(t, stored, client_query(advertised, true))
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect_value(t, r.answers, 40)
	testing.expectf(
		t,
		r.extra == 1,
		"the additional address was dropped from a %d-byte reply the client had %d bytes for",
		r.length,
		int(advertised),
	)
	testing.expect(t, !r.tc, "an answer that fitted the client's datagram came back truncated")
	testing.expect(t, r.opt, "the client asked with EDNS and got no OPT record back")
	testing.expect(t, !r.nsid, "the upstream's NSID reached the client")

	free_all(context.temp_allocator)
}

/*
A client that asked without EDNS is cut to the datagram it can read, not to that
less the record it is not going to be sent.

The whole OPT record goes for a client that never negotiated one, which is more
room handed back than the options alone - and the answer here is one that has to
be cut whatever happens, so this is the truncation being measured against the
wrong ceiling rather than a truncation that need not have happened. TC is set
either way; what the client pays is the records the record's room cost it, on the
retry as well as here.

The same property as the truncation above, and 512 is the ceiling: a client that
asked without EDNS never advertised a buffer, so RFC 1035 section 4.2.1 is what
bounds the datagram.
*/
@(test)
test_a_client_without_edns_is_cut_to_its_own_datagram :: proc(t: ^testing.T) {
	stored := upstream_answer(33, false)
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}
	per_record := per_record_cost(t, 33)
	// The answer without its OPT record is past what a client that asked
	// without EDNS can read, which is what makes this a truncation.
	if !testing.expectf(
		t,
		len(stored) - OPT_LEN - OPTION_LEN > 512,
		"the answer is %d bytes, so a 512-byte datagram holds it and nothing is cut",
		len(stored),
	) {
		return
	}

	out, ok := answer_once(t, stored, client_query(0, false))
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect(t, !r.opt, "a client that asked without EDNS got an OPT record back")
	testing.expect(t, r.tc, "an answer that lost records went out without TC")
	testing.expect(t, r.answers > 0, "the whole answer section went, so this is not the case under test")
	testing.expectf(
		t,
		r.answers == 33 || r.length + per_record > 512,
		"the answer was cut to %d bytes with %d of its 33 records, and another %d-byte record would have fitted the client's 512",
		r.length,
		r.answers,
		per_record,
	)
	testing.expectf(t, r.length <= 512, "the answer is %d bytes, past the 512 a client without EDNS can read", r.length)

	free_all(context.temp_allocator)
}
