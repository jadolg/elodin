package dns

import "core:testing"

/*
Reading and bounding the TTL field.

RFC 2181 section 8 makes the field an unsigned 31-bit number and says a value
arriving with the top bit set is to be treated as zero. `sane_ttl` is that
reading, `read_ttls` applies it to what the cache stores, and `cap_ttls` applies
it plus a ceiling to a message on its way out.
*/

@(private = "file")
answer_with_ttls :: proc(ttls: []u32, ext_rcode: u8 = 0) -> []u8 {
	question := make([]Question, 1, context.temp_allocator)
	question[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, len(ttls), context.temp_allocator)
	for ttl, i in ttls {
		answer[i] = Record {
			name  = "example.com.",
			type  = .A,
			class = .IN,
			ttl   = ttl,
			data  = Rdata_A{addr = {192, 0, 2, u8(i + 1)}},
		}
	}
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = make_opt(1232, true, ext_rcode)

	m := Message {
		question   = question,
		answer     = answer,
		additional = additional,
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(test)
test_sane_ttl_zeroes_the_top_bit :: proc(t: ^testing.T) {
	testing.expect_value(t, sane_ttl(300), u32(300))
	testing.expect_value(t, sane_ttl(TTL_MAX), TTL_MAX)
	// Zero, not the low 31 bits: RFC 2181 section 8 discards the whole value.
	testing.expect_value(t, sane_ttl(0x8000_0000), u32(0))
	testing.expect_value(t, sane_ttl(max(u32)), u32(0))
}

@(test)
test_read_ttls_applies_section_8 :: proc(t: ^testing.T) {
	wire := answer_with_ttls([]u32{300, 0x8000_0001})
	offsets, ok := scan_ttl_offsets(wire, context.temp_allocator)
	if !testing.expect(t, ok, "the message could not be walked") {
		return
	}
	ttls := read_ttls(wire, offsets, context.temp_allocator)
	if !testing.expect(t, len(ttls) == 2, "the OPT record aside, there are two TTLs here") {
		return
	}
	testing.expect_value(t, ttls[0], u32(300))
	testing.expect_value(t, ttls[1], u32(0))
	free_all(context.temp_allocator)
}

/*
`cap_ttls` shortens and never lengthens, and leaves the OPT record alone.

The last of those is the one worth a test. What sits in an OPT record's TTL
field is the extended rcode and the DO bit rather than a lifetime - RFC 6891
section 6.1.3 - and the header this test builds has the top bit of it set, so a
pass that treated it as a TTL would zero it and take the client's DNSSEC-OK
answer flag and the top half of its rcode with it. `scan_ttl_offsets` skips OPT
for exactly this reason and `cap_ttls` inherits that; the test is here so the
two cannot drift apart.
*/
@(test)
test_cap_ttls_bounds_the_wire_and_spares_the_opt :: proc(t: ^testing.T) {
	wire := answer_with_ttls([]u32{86400, 0x8000_0000, 30}, ext_rcode = 0x80)
	if !testing.expect(t, cap_ttls(wire, 3600, context.temp_allocator), "the message could not be walked") {
		return
	}
	m, err := decode_message(wire, context.temp_allocator)
	if !testing.expect(t, err == .None, "the bounded message did not decode") {
		return
	}
	if !testing.expect(t, len(m.answer) == 3, "the bounded message lost a record") {
		return
	}
	testing.expect_value(t, m.answer[0].ttl, u32(3600))
	testing.expect_value(t, m.answer[1].ttl, u32(0))
	// Below the ceiling and left where it was: this is a bound, not a rewrite.
	testing.expect_value(t, m.answer[2].ttl, u32(30))

	opt, found := find_opt(m)
	if !testing.expect(t, found, "the OPT record went missing") {
		return
	}
	testing.expect_value(t, opt.ttl, u32(0x8000_8000))
	free_all(context.temp_allocator)
}

// A message that cannot be walked is left as it stands rather than half
// rewritten - the same messages `scan_ttl_offsets` refuses, which are not ones
// this server goes on to send.
@(test)
test_cap_ttls_refuses_a_message_it_cannot_walk :: proc(t: ^testing.T) {
	short := []u8{0x12, 0x34, 0x81, 0x80}
	testing.expect(t, !cap_ttls(short, 60, context.temp_allocator), "a truncated header was walked")
	free_all(context.temp_allocator)
}
