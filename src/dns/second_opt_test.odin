package dns

import "core:testing"

/*
A message carrying two OPT records goes out with one: the first, which is the
record `find_opt` reads and the encoder measures and puts back behind a cut.

RFC 6891 section 6.1.1 allows a message one OPT record. Writing whichever of two
happened to fit let the second stand in for the first after the first was
dropped for size, and the first is where an rcode of 16 or more keeps its upper
bits (section 6.1.3): BADVERS went out as NOERROR, without TC.
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
`encode_message`, but writing every OPT record the additional section holds,
for the tests whose subject is a message carrying a second one - a shape the
encoder will not produce and a peer still can. Each record past the first is
appended to the end, written as the encoder writes one.
*/
encode_with_every_opt :: proc(
	m: Message,
	allocator := context.allocator,
) -> (
	out: []u8,
	truncated: bool,
	err: Encode_Error,
) {
	kept := make([dynamic]Record, 0, len(m.additional), context.temp_allocator)
	extra := make([dynamic]Record, 0, 1, context.temp_allocator)
	seen := false
	for rec in m.additional {
		if rec.type == .OPT {
			if seen {
				append(&extra, rec)
				continue
			}
			seen = true
		}
		append(&kept, rec)
	}
	first := m
	first.additional = kept[:]
	wire: []u8
	wire, truncated, err = encode_message(first, allocator)
	if err != .None {
		return
	}
	buf := make([dynamic]u8, 0, len(wire), allocator)
	append(&buf, ..wire)
	arcount := int(wire[10]) << 8 | int(wire[11])
	for rec in extra {
		lone, _, lone_err := encode_message(Message{additional = {rec}}, context.temp_allocator, compress = false)
		if lone_err != .None {
			return nil, false, lone_err
		}
		append(&buf, ..lone[HEADER_SIZE:])
		arcount += 1
	}
	buf[10] = u8(arcount >> 8)
	buf[11] = u8(arcount)
	return buf[:], truncated, .None
}
