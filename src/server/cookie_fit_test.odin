package server

import "core:testing"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"

/*
What happens to a cookie, and to the TC bit, when the cookie is the thing that
will not fit.

`attach_cookie` writes twenty-eight bytes into the answer's OPT record - four of
option header and twenty-four of cookie - after the answer is already encoded.
An answer sitting within thirty bytes of what the client advertised is therefore
one the cookie pushes over, and there are two quite different ways to be over:

  - the answer itself does not fit, which is what the comment on `attach_cookie`
    was written against. Records are dropped, the client is told to ask again
    over TCP, and the OPT record is re-added behind the cut so the cookie
    survives the round trip;
  - the answer fits and only the cookie does not. There is nothing behind the
    OPT record to drop, so the answer goes out whole and without one.

The second used to arrive at the worst of both: `encode_message` set TC for the
OPT record it could not fit, re-added it on the same arithmetic and dropped it
again, so the client was handed a complete answer with TC set, no OPT record and
no cookie - and asked again over TCP for bytes it already had. Now the cookie is
abandoned instead, which is what `match_client_opt` does with an OPT record it
cannot mint (see the comment there): an answer that fits is worth more to the
client than the EDNS parameters it would have carried.

Both cases are pinned here, along with the ordinary one where the cookie fits.
*/

@(private = "file")
QNAME :: "probe.example.com."

@(private = "file")
CLIENT :: "198.51.100.100:9999"

@(private = "file")
SECRET :: "e5e973e5a6b2a43f48e7dc849e37bfcf"

// The answer's OPT record before anything is written into it: a root owner name,
// type, class, TTL and RDLENGTH.
@(private = "file")
OPT_LEN :: 11

// Option header plus a 24-byte reply cookie, which is what `attach_cookie` adds.
@(private = "file")
COOKIE_OPTION_LEN :: 4 + COOKIE_REPLY_LEN

/*
An answer big enough to sit near a UDP buffer without going over it: one address
and fourteen TXT records, which is the shape the ticket measured.
*/
@(private = "file")
big_answer :: proc() -> (wire: []u8, records: int) {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}

	answer := make([dynamic]dns.Record, 0, 15, context.temp_allocator)
	append(
		&answer,
		dns.Record{name = QNAME, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 1}}},
	)
	for i in 0 ..< 14 {
		text := make([]u8, 48, context.temp_allocator)
		for j in 0 ..< len(text) {
			text[j] = u8('a' + (i + j) % 26)
		}
		strs := make([]string, 1, context.temp_allocator)
		strs[0] = string(text)
		append(
			&answer,
			dns.Record {
				name = QNAME,
				type = .TXT,
				class = .IN,
				ttl = 300,
				data = dns.Rdata_TXT{strings = strs},
			},
		)
	}

	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)

	m := dns.Message {
		id         = 0x4242,
		question   = question,
		answer     = answer[:],
		additional = additional,
	}
	m.flags.qr = true
	m.flags.ra = true

	encoded, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		return nil, 0
	}
	return encoded, len(answer)
}

@(private = "file")
client_query :: proc(advertised: u16) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	// Eight bytes, which is a client that has not been here before: the verdict
	// is `Unproven` and a cookie is minted for it.
	half := make([]u8, 8, context.temp_allocator)
	for i in 0 ..< len(half) {
		half[i] = u8(0xa0 + i)
	}
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option {
		code = u16(dns.EDNS_Option_Code.Cookie),
		data = half,
	}
	opt := dns.make_opt(advertised, false)
	opt.data = dns.Rdata_OPT{options = options}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt

	msg := dns.Message {
		id         = 0x1234,
		question   = question,
		additional = additional,
	}
	msg.flags.rd = true

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
Answer one cookie-carrying query from the cache, so the client-facing path runs
end to end with no upstream behind it and the answer's size chosen here.
*/
@(private = "file")
answer_once :: proc(t: ^testing.T, stored_wire: []u8, advertised: u16) -> (out: []u8, ok: bool) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.cookies.enabled = true
	cfg.cookies.secret = SECRET

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	if !start_cookies(&s) {
		testing.expect(t, false, "the cookie keeper would not start")
		return nil, false
	}
	defer stop_cookies(&s)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], QNAME, .A, .IN, false, false)
	decoded, derr := dns.decode_message(stored_wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !cache.put(answers, key, stored_wire, decoded) {
		testing.expect(t, false, "the answer was not cached")
		return nil, false
	}

	response, _, served := handle_query(&s, client_query(advertised), .UDP, CLIENT, context.temp_allocator)
	return response, served
}

// What the cases below read off a reply.
@(private = "file")
Reply :: struct {
	answers: int,
	tc:      bool,
	opt:     bool,
	cookie:  bool,
	length:  int,
}

@(private = "file")
read_reply :: proc(t: ^testing.T, wire: []u8) -> (r: Reply) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect_value(t, err, dns.Decode_Error.None) {
		return {}
	}
	_, has_cookie := dns.find_edns_option(m, .Cookie)
	return Reply {
		answers = len(m.answer),
		tc = m.flags.tc,
		opt = dns.edns_present(m),
		cookie = has_cookie,
		length = len(wire),
	}
}

/*
The answer fits and the cookie does not: the answer goes out whole, with its OPT
record and without a cookie, and TC stays clear.

The buffer is the answer's own size plus twenty bytes - room to spare, and eight
short of the twenty-eight a cookie needs - so the cookie is the only thing in
the reply that cannot be delivered.
*/
@(test)
test_a_cookie_that_will_not_fit_does_not_truncate_the_answer :: proc(t: ^testing.T) {
	stored, records := big_answer()
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}
	advertised := u16(len(stored) + 20)
	// Above the 512 floor `dns.edns_udp_size` clamps to, or the arithmetic
	// above is not the arithmetic under test.
	if !testing.expectf(t, int(advertised) > 512, "the answer is only %d bytes", len(stored)) {
		return
	}
	testing.expect(t, COOKIE_OPTION_LEN > 20, "the cookie fits after all, so this case is not reachable")

	out, ok := answer_once(t, stored, advertised)
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect_value(t, r.answers, records)
	testing.expect(t, !r.tc, "a complete answer inside the client's buffer came back truncated")
	testing.expect(t, r.opt, "the answer lost the OPT record the cookie could not fit into")
	testing.expect(t, !r.cookie, "a cookie came back after all, so nothing overflowed")
	testing.expectf(t, r.length <= int(advertised), "the answer is %d bytes, past the %d advertised", r.length, int(advertised))

	free_all(context.temp_allocator)
}

/*
The same answer to a client with room for the cookie gets one.

Beside the case above because the two differ only in the buffer: without this,
an `attach_cookie` that had stopped attaching cookies altogether would pass.
*/
@(test)
test_a_cookie_that_fits_is_still_attached :: proc(t: ^testing.T) {
	stored, records := big_answer()
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}

	out, ok := answer_once(t, stored, u16(len(stored) + COOKIE_OPTION_LEN))
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect_value(t, r.answers, records)
	testing.expect(t, !r.tc, "a complete answer inside the client's buffer came back truncated")
	testing.expect(t, r.cookie, "the cookie fits in the buffer advertised and did not come back")

	free_all(context.temp_allocator)
}

/*
An answer larger than the client's buffer is cut, keeps its OPT record, and
still has no room for the cookie.

512 against an answer of nine hundred-odd bytes, so the answer section is cut
whatever is done about the cookie - and the cut is measured against the OPT
record as it stands, which the cookie is then spliced into afterwards. Twenty-
eight bytes past the buffer again, and the answer is what goes out.

Which costs the client nothing it was not already paying: TC sends it to TCP for
the whole answer, and the reply there carries a cookie in 65535 bytes of room.
`cookies.require` gates UDP alone (`cookie_must_be_refused`), so the retry is
not turned away for arriving without one.
*/
@(test)
test_an_answer_over_the_buffer_is_truncated_and_keeps_its_opt :: proc(t: ^testing.T) {
	stored, records := big_answer()
	if !testing.expect(t, len(stored) > 0, "the answer would not encode") {
		return
	}
	if !testing.expectf(t, len(stored) > 512 + OPT_LEN, "the answer is only %d bytes", len(stored)) {
		return
	}

	out, ok := answer_once(t, stored, 512)
	if !testing.expect(t, ok, "the query went unanswered") {
		return
	}

	r := read_reply(t, out)
	testing.expect(t, r.answers < records, "an answer past the client's buffer kept every record")
	testing.expect(t, r.answers > 0, "the whole answer section went, so this is not the case under test")
	testing.expect(t, r.tc, "an answer that lost records went out without TC")
	// The record survives the cut even though the cookie in it does not, so the
	// client still reads what this server can deliver over UDP.
	testing.expect(t, r.opt, "the truncated answer lost its OPT record")
	testing.expect(t, !r.cookie, "the cookie fits after all, so this case is not reachable")
	testing.expectf(t, r.length <= 512, "the answer is %d bytes, past the 512 advertised", r.length)

	free_all(context.temp_allocator)
}
