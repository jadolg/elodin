package dns

import "core:mem"
import "core:testing"

/*
Reading and bounding the TTL field.

RFC 8767 section 4 reads the field as an unsigned 32-bit number, a value with
the top bit set included, and caps it. `sane_ttl` is that reading, capped at
`TTL_MAX`; `read_ttls` applies it to what the cache stores, and `cap_ttls`
applies it plus a ceiling to a message on its way out.
*/

@(private = "file")
answer_with_ttls :: proc(ttls: []u32, ext_rcode: u8 = 0) -> []u8 {
	answer := make([]Record, len(ttls), context.temp_allocator)
	// An owner each: one RRset of several TTLs would be brought to its lowest
	// (`test_cap_ttls_gives_an_rrset_its_lowest_ttl`), which is not what these ask.
	owners := []string{"r1.example.com.", "r2.example.com.", "r3.example.com.", "r4.example.com."}
	for ttl, i in ttls {
		answer[i] = a_answer(owners[i % len(owners)], ttl, u8(i + 1))
	}
	m := Message {
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		answer     = answer,
		additional = []Record{make_opt(1232, true, ext_rcode)},
	}
	m.flags.qr = true
	return test_wire(m)
}

@(test)
test_sane_ttl_reads_the_top_bit_as_positive :: proc(t: ^testing.T) {
	testing.expect_value(t, sane_ttl(0), u32(0))
	testing.expect_value(t, sane_ttl(300), u32(300))
	testing.expect_value(t, sane_ttl(TTL_MAX), TTL_MAX)
	// Positive and capped, not zero and not the low 31 bits (RFC 8767 section 4).
	testing.expect_value(t, sane_ttl(0x8000_0000), TTL_MAX)
	testing.expect_value(t, sane_ttl(0x8000_0010), TTL_MAX)
	testing.expect_value(t, sane_ttl(max(u32)), TTL_MAX)
}

@(test)
test_read_ttls_reads_the_top_bit_as_positive :: proc(t: ^testing.T) {
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
	testing.expect_value(t, ttls[1], TTL_MAX)
	free_all(context.temp_allocator)
}

/*
`cap_ttls` shortens and never lengthens, and leaves the OPT record alone.

The last of those is the one worth a test. What sits in an OPT record's TTL
field is the extended rcode and the DO bit rather than a lifetime - RFC 6891
section 6.1.3 - and the header this test builds has the top bit of it set, so a
pass that treated it as a TTL would cap it and take the client's DNSSEC-OK
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
	testing.expect_value(t, m.answer[1].ttl, u32(3600))
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
	testing.expect_value(t, read_ttl_at(wire, int(offsets[0])), u32(3600))
	testing.expect_value(t, read_ttl_at(wire, int(offsets[1])), u32(3600))
	free_all(context.temp_allocator)
}

// A record whose RDATA runs past the end still has its TTL bounded: its fixed
// fields are inside the message, and the walk ends with it.
@(test)
test_cap_ttls_bounds_a_record_whose_rdata_is_cut :: proc(t: ^testing.T) {
	wire := answer_with_ttls([]u32{86400, 86400})
	offsets, ok := scan_ttl_offsets(wire, context.temp_allocator)
	if !testing.expect(t, ok && len(offsets) == 2, "the intact message did not scan") {
		return
	}
	// TTL and RDLENGTH, then one byte of the four the second A record's RDATA holds.
	cut := wire[:int(offsets[1]) + 4 + 2 + 1]
	cap_ttls(cut, 3600)
	testing.expect_value(t, read_ttl_at(cut, int(offsets[0])), u32(3600))
	testing.expect_value(t, read_ttl_at(cut, int(offsets[1])), u32(3600))
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
total, and the array they ask `scan_ttl_offsets` to reserve is 384 KiB, spent on
a walk that fails at the first name.

`cap_ttls` does its own walk and allocates nothing, so the guard stands for
`cache.put`, whose counts come from a caller rather than from this package.

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

/*
A message longer than any DNS message can be is refused, rather than scanned
into offsets that wrap. RFC 1035 section 4.2.2 frames a message with a two-byte
length, so `u16` holds every offset into a real one; the cache keeps them as
`u16` for as long as it keeps the answer (issue #599).
*/
@(test)
test_scan_refuses_a_message_past_max_message :: proc(t: ^testing.T) {
	// `n` A records owned by the root, 15 bytes each, and nothing else.
	a_records :: proc(n: int) -> []u8 {
		msg := make([]u8, HEADER_SIZE + n * 15, context.temp_allocator)
		msg[6] = u8(n >> 8)
		msg[7] = u8(n)
		for i in 0 ..< n {
			at := HEADER_SIZE + i * 15
			msg[at + 2] = 1 // type A
			msg[at + 4] = 1 // class IN
			msg[at + 10] = 4 // rdlength
		}
		return msg
	}
	defer free_all(context.temp_allocator)

	// The premise: the most records that fit in MAX_MESSAGE scan.
	fits := a_records((MAX_MESSAGE - HEADER_SIZE) / 15)
	offsets, ok := scan_ttl_offsets(fits, context.temp_allocator)
	if testing.expect(t, ok, "a message of MAX_MESSAGE bytes or fewer was refused") {
		testing.expect_value(t, int(offsets[len(offsets) - 1]), len(fits) - 15 + 5)
	}

	// Two more, and the last TTL is past what an offset can hold.
	past := a_records((MAX_MESSAGE - HEADER_SIZE) / 15 + 2)
	testing.expect(t, len(past) > MAX_MESSAGE, "the premise: the message is longer than MAX_MESSAGE")
	_, ok = scan_ttl_offsets(past, context.temp_allocator)
	testing.expect(t, !ok, "a message past MAX_MESSAGE was scanned")
}

/*
A list that cannot be reserved is a refusal, not a shorter list: one missing
a record would read as a message with fewer TTLs, and the cache would store the
answer with nothing to count those down.
*/
@(test)
test_scan_refuses_when_its_list_cannot_be_reserved :: proc(t: ^testing.T) {
	refuse :: proc(
		_: rawptr,
		mode: mem.Allocator_Mode,
		_, _: int,
		_: rawptr,
		_: int,
		_ := #caller_location,
	) -> (
		[]byte,
		mem.Allocator_Error,
	) {
		return nil, .Out_Of_Memory if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed else .None
	}
	// One A record owned by the root.
	msg := []u8 {
		0x12, 0x34, 0x81, 0x80, // id, flags
		0x00, 0x00, 0x00, 0x01, // qdcount 0, ancount 1
		0x00, 0x00, 0x00, 0x00, // nscount 0, arcount 0
		0x00, 0x00, 0x01, 0x00, 0x01, // the root name, type A, class IN
		0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 1, 2, 3, 4, // TTL 300, rdlength 4, the address
	}
	// The premise: the message scans.
	offsets, ok := scan_ttl_offsets(msg, context.temp_allocator)
	testing.expect_value(t, len(offsets), 1)
	free_all(context.temp_allocator)

	offsets, ok = scan_ttl_offsets(msg, mem.Allocator{procedure = refuse})
	testing.expectf(t, !ok, "scanned into a list of %d offsets for a message with one TTL", len(offsets))
}

@(private = "file")
answer_records :: proc(answer: []Record, authority: []Record = nil) -> []u8 {
	m := Message {
		question  = []Question{{name = "set.example.", type = .A, class = .IN}},
		answer    = answer,
		authority = authority,
	}
	m.flags.qr = true
	return test_wire(m)
}

@(private = "file")
answer_ttls :: proc(t: ^testing.T, wire: []u8) -> (ttls: [dynamic]u32, ok: bool) {
	m, err := decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the message did not decode: %v", err) {
		return nil, false
	}
	ttls = make([dynamic]u32, context.temp_allocator)
	for r in m.answer {
		append(&ttls, r.ttl)
	}
	for r in m.authority {
		append(&ttls, r.ttl)
	}
	return ttls, true
}

/*
RFC 2181 section 5.2: "In no case may a server send an RRSet with TTLs not all
equal", and one that arrives so is treated "as if all TTLs in the RRSet had been
set to the value of the lowest TTL in the RRSet". An owner spelled in another
case, or reached through a compression pointer, is the same owner; another
owner, type or section is another RRset; an RRSIG keeps its own.
*/
@(test)
test_cap_ttls_gives_an_rrset_its_lowest_ttl :: proc(t: ^testing.T) {
	// Two RRSIGs on one owner, one covering A (type 1) and one AAAA (type 28).
	sig := Record{name = "set.example.", type = .RRSIG, class = .IN, ttl = 900, data = Rdata_Raw{data = []u8{0, 1}}}
	other_sig := Record{name = "set.example.", type = .RRSIG, class = .IN, ttl = 300, data = Rdata_Raw{data = []u8{0, 28}}}
	wire := answer_records(
		[]Record {
			a_answer("set.example.", 3600, 1),
			a_answer("SET.Example.", 10, 2),
			a_answer("set.example.", 600, 3),
			sig,
			other_sig,
			a_answer("other.example.", 3600, 4),
			a_answer("other.example.", 300, 5),
			a_answer("set.example.", 50, 6),
		},
		// Right after the answer's last record, with its owner and type: another
		// section, so another RRset.
		authority = []Record{a_answer("set.example.", 3600, 7)},
	)
	cap_ttls(wire, TTL_MAX)
	ttls, ok := answer_ttls(t, wire)
	if !ok || !testing.expect_value(t, len(ttls), 9) {
		return
	}
	// The RRSIG covering A takes the A RRset's TTL (RFC 4034 section 3); the one
	// covering AAAA keeps its own.
	want := [9]u32{10, 10, 10, 10, 300, 300, 300, 50, 3600}
	for got, i in ttls {
		testing.expectf(t, got == want[i], "record %d: TTL %d, want %d", i, got, want[i])
	}
	free_all(context.temp_allocator)
}

/*
An RRset is the run of its records next to each other: a member that turns up
apart from the rest is not gathered back, as `encode_message` does not gather
one either.
*/
@(test)
test_cap_ttls_reads_an_rrset_as_its_run :: proc(t: ^testing.T) {
	wire := answer_records([]Record{a_answer("set.example.", 3600, 1), a_answer("between.example.", 60, 2), a_answer("set.example.", 10, 3)})
	cap_ttls(wire, TTL_MAX)
	ttls, ok := answer_ttls(t, wire)
	if !ok || !testing.expect_value(t, len(ttls), 3) {
		return
	}
	testing.expect_value(t, ttls[0], u32(3600))
	testing.expect_value(t, ttls[2], u32(10))
	free_all(context.temp_allocator)
}

// Names compared on the wire: case, pointers, a mismatch, and pointers that
// go forwards, at themselves or into the header, none of which is followed.
@(test)
test_wire_names_equal :: proc(t: ^testing.T) {
	H :: HEADER_SIZE
	msg := make([dynamic]u8, context.temp_allocator)
	resize(&msg, H)
	// H+0: "a.b." ; H+5: "A.B." ; H+10: pointer to H+0 ; H+12: "a.c." ;
	// H+17: pointer forwards to H+19 ; H+19: pointer to itself ; H+21: pointer into the header,
	// which spells "a.b." there.
	append(&msg, 1, 'a', 1, 'b', 0, 1, 'A', 1, 'B', 0, 0xC0, H, 1, 'a', 1, 'c', 0, 0xC0, H + 19, 0xC0, H + 19, 0xC0, 2)
	// H+23: pointer forwards to H+25, which spells "a.b." - equal, were it followed.
	append(&msg, 0xC0, H + 25, 1, 'a', 1, 'b', 0)
	// The header spells "a.b." from its third byte, which H+21 points at.
	copy(msg[2:7], []u8{1, 'a', 1, 'b', 0})
	testing.expect(t, wire_names_equal(msg[:], H, H + 5), "a case difference made two names")
	testing.expect(t, wire_names_equal(msg[:], H + 5, H + 10), "a pointer made two names")
	testing.expect(t, !wire_names_equal(msg[:], H, H + 12), "a.b. and a.c. read as one")
	testing.expect(t, !wire_names_equal(msg[:], H, H + 17), "a forward pointer was followed")
	testing.expect(t, !wire_names_equal(msg[:], H, H + 19), "a pointer to itself was followed")
	testing.expect(t, !wire_names_equal(msg[:], H, H + 21), "a pointer into the header was followed")
	testing.expect(t, !wire_names_equal(msg[:], H, H + 23), "a forward pointer to the same name was followed")
	// And with the pointer on the other side.
	testing.expect(t, !wire_names_equal(msg[:], H + 21, H), "a pointer into the header was followed, as the first name")
	testing.expect(t, !wire_names_equal(msg[:], H + 23, H), "a forward pointer was followed, as the first name")
	testing.expect(t, !wire_names_equal(msg[:], H, len(msg)), "a name past the end read as one")
	free_all(context.temp_allocator)
}
