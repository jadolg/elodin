package dns

import "core:testing"

/*
A message carrying two OPT records goes out with one: the first, which is the
record `find_opt` reads and the encoder measures and puts back behind a cut.

RFC 6891 section 6.1.1 allows a message one OPT record. A second one is never
written in place of a first dropped for size, because the first is where an
rcode of 16 or more keeps its upper bits (section 6.1.3): written, the second
would state BADVERS as NOERROR, without TC.
*/

@(private = "file")
two_opts :: proc(first_options: int) -> Message {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	first := make_opt(1232, false)
	// BADVERS: 16, all of it in the record's extended-rcode byte.
	first.ttl = 0x0100_0000
	if first_options > 0 {
		options := make([]EDNS_Option, 1, context.temp_allocator)
		options[0] = EDNS_Option {
			code = u16(EDNS_Option_Code.Padding),
			data = make([]u8, first_options, context.temp_allocator),
		}
		first.data = Rdata_OPT{options = options}
	}
	second := make_opt(4096, false)
	additional := make([]Record, 2, context.temp_allocator)
	additional[0] = first
	additional[1] = second
	m := Message {
		id         = 1,
		question   = questions,
		additional = additional,
	}
	m.flags.qr = true
	return m
}

@(test)
second_opt_record_is_not_written :: proc(t: ^testing.T) {
	wire, _, err := encode_message(two_opts(0), context.temp_allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	out, dec_err := decode_message(wire, context.temp_allocator)
	if !testing.expect_value(t, dec_err, Decode_Error.None) {
		return
	}
	testing.expect_value(t, len(out.additional), 1)
	opt, found := find_opt(out)
	testing.expect(t, found, "the message lost its OPT record")
	testing.expect_value(t, opt.class, Class(1232))
	testing.expect_value(t, rcode_of(out), Rcode(16))
}

// The first record does not fit and the second would: the client is sent to
// TCP for the rcode rather than handed the second record's NOERROR.
@(test)
second_opt_record_does_not_stand_in_for_a_dropped_first :: proc(t: ^testing.T) {
	wire, truncated, err := encode_message(two_opts(600), context.temp_allocator, 512)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	out, dec_err := decode_message(wire, context.temp_allocator)
	if !testing.expect_value(t, dec_err, Decode_Error.None) {
		return
	}
	testing.expect(t, truncated && out.flags.tc, "the rcode was lost without TC")
	_, found := find_opt(out)
	testing.expect(t, !found, "the second OPT record was written in place of the first")
}

/*
An option editor that has to rebuild a message keeps a second OPT record, so the
rewritten reply still fails `peek_opt_unreadable` as the one that arrived does.
The encoder writes only the first, and a rebuild through it would hand on a
reply with a cookie in the first of two OPT records as an acceptable one once
`upstream.exchange_with_cookie` had stripped the cookie (issue #353).
*/
@(test)
an_option_rebuild_keeps_a_second_opt_record :: proc(t: ^testing.T) {
	m := two_opts(0)
	cookie := make([]EDNS_Option, 1, context.temp_allocator)
	cookie[0] = EDNS_Option {
		code = u16(EDNS_Option_Code.Cookie),
		data = make([]u8, 24, context.temp_allocator),
	}
	m.additional[0].data = Rdata_OPT{options = cookie}
	wire, _, err := encode_with_every_opt(m, context.temp_allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	testing.expect(t, peek_opt_unreadable(wire), "the reply does not carry two OPT records")

	stripped, removed := remove_edns_option(wire, .Cookie, context.temp_allocator)
	if testing.expect(t, removed, "the cookie strip failed") {
		_, still := peek_edns_option(stripped, .Cookie)
		testing.expect(t, !still, "the cookie is still there")
		testing.expect(t, peek_opt_unreadable(stripped), "the cookie strip handed back the reply with one OPT record")
	}
	padded, set := set_edns_option(wire, .Padding, {0, 0}, context.temp_allocator)
	if testing.expect(t, set, "the padding write failed") {
		testing.expect(t, peek_opt_unreadable(padded), "the padding write handed back the reply with one OPT record")
	}
}

/*
The records a rebuild appends behind the encoder's message fit inside
`MAX_MESSAGE` with it: the encoder is held back by their room, so a message
that filled the limit on its own is cut instead of outgrowing it.
*/
@(test)
the_records_every_opt_appends_stay_within_the_limit :: proc(t: ^testing.T) {
	m := two_opts(0)
	long := make([]u8, 255, context.temp_allocator)
	for &b in long {
		b = 'x'
	}
	// 244 TXT records of 268 bytes and one of 103 bring the message, with the
	// first OPT record, to 65535 bytes exactly.
	answer := make([]Record, 245, context.temp_allocator)
	for &rec, i in answer {
		text := string(long) if i < 244 else string(long[:90])
		strings := make([]string, 1, context.temp_allocator)
		strings[0] = text
		rec = Record {
			name  = "example.com.",
			type  = .TXT,
			class = .IN,
			ttl   = 60,
			data  = Rdata_TXT{strings = strings},
		}
	}
	m.answer = answer
	alone, _, alone_err := encode_message(m, context.temp_allocator)
	if !testing.expect_value(t, alone_err, Encode_Error.None) {
		return
	}
	testing.expect_value(t, len(alone), MAX_MESSAGE)

	wire, truncated, err := encode_with_every_opt(m, context.temp_allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	testing.expectf(t, len(wire) <= MAX_MESSAGE, "%d bytes, over MAX_MESSAGE", len(wire))
	testing.expect(t, truncated, "a message cut for the second record's room did not say so")
	testing.expect(t, peek_opt_unreadable(wire), "the second OPT record is gone")
}
