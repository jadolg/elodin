package dns

import "core:mem"
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
	cap_ttls(wire, 3600)
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

/*
Junk past the answer section does not stop the answer section being bounded.

This is the case that decided the shape of `cap_ttls`. Records are laid out
answer first, so by the time a walk goes wrong in an authority or additional
section the records a client actually acts on have already been bounded.
Refusing the whole message instead - which this did for a round - turned a
mangled additional section into SERVFAIL for a name whose answer was clean,
and `server` has three tests of its own saying it must not.

The offsets are taken before the header is mangled, because afterwards nothing
in this package will walk the message far enough to find them again - which is
the point: `scan_ttl_offsets` refuses these bytes, so `cache.put` refuses them
too and the copy this bounds is never stored.
*/
@(test)
test_cap_ttls_bounds_what_it_can_reach :: proc(t: ^testing.T) {
	wire := answer_with_ttls([]u32{86400, 0x8000_0000})
	offsets, ok := scan_ttl_offsets(wire, context.temp_allocator)
	if !testing.expect(t, ok && len(offsets) == 2, "the intact message did not scan") {
		return
	}
	// An additional count no message this size could satisfy: the walk gets
	// through the answers and the OPT record, then runs out of bytes.
	wire[10], wire[11] = 0x00, 0x64
	if _, still := scan_ttl_offsets(wire, context.temp_allocator); still {
		testing.fail_now(t, "the mangled message was meant to defeat the strict scan")
	}

	cap_ttls(wire, 3600)
	testing.expect_value(t, read_ttl_at(wire, offsets[0]), u32(3600))
	testing.expect_value(t, read_ttl_at(wire, offsets[1]), u32(0))
	free_all(context.temp_allocator)
}

// A header too short to hold one is left exactly as it stands, and does not
// take the walk off the end of it.
@(test)
test_cap_ttls_leaves_a_truncated_header_alone :: proc(t: ^testing.T) {
	short := []u8{0x12, 0x34, 0x81, 0x80}
	cap_ttls(short, 60)
	testing.expect_value(t, short[2], u8(0x81))
	free_all(context.temp_allocator)
}

/*
A reply claiming more records than it could possibly hold is refused before the
count is spent as a capacity.

Three sections of 65535 records fit in a header that is seventeen bytes long in
total, and the array they ask `scan_ttl_offsets` to reserve is 1.5 MB, spent on
a walk that fails at the first name.

Written when `cap_ttls` walked undecoded bytes through this scan and every query
paid for it. It does its own walk and allocates nothing now, so the guard stands
for `cache.put`, whose counts come from a caller rather than from this package.

Tracked rather than asserted on the outcome, because the outcome cannot tell the
two apart: the message is refused either way, and what is under test is what was
spent to refuse it.
*/
@(test)
test_scan_refuses_counts_that_cannot_fit :: proc(t: ^testing.T) {
	// A header claiming one question and 65535 records in each of the other
	// three sections, then the question: the root name, type A, class IN.
	msg := []u8 {
		0x12, 0x34, 0x81, 0x80, // id, flags
		0x00, 0x01, 0xff, 0xff, // qdcount 1, ancount 65535
		0xff, 0xff, 0xff, 0xff, // nscount 65535, arcount 65535
		0x00, 0x00, 0x01, 0x00, 0x01, // the root name, type A, class IN
	}

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	tracked := mem.tracking_allocator(&track)

	_, ok := scan_ttl_offsets(msg, tracked)
	testing.expect(t, !ok, "a message claiming 196605 records was walked")
	// The same counts through `cap_ttls`, which reserves nothing for them and
	// gives up at the first record that will not fit.
	cap_ttls(msg, 60)
	testing.expectf(
		t,
		track.peak_memory_allocated < 4096,
		"refusing the message reserved %d bytes",
		track.peak_memory_allocated,
	)
}
