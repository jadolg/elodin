package dns

import "core:mem"
import "core:testing"

/*
Minting an OPT record by appending it to the bytes (issue #598).

Each case is checked three ways: the bytes ahead of the record are the bytes
handed in, so nothing was decoded and encoded again; nothing was charged to the
request's decode budget, which is the decode not happening seen from the side
that pays for one; and the result decodes to the message `rebuild_with_opt`, the
decode and re-encode it replaces, makes of the same input.
*/

@(private = "file")
APPEND_QNAME :: "example.com."

@(private = "file")
append_fixture :: proc(additional: []Record = nil, raw_len := -1, compress := true) -> []u8 {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = APPEND_QNAME,
		type  = .A,
		class = .IN,
	}
	answer := make([dynamic]Record, context.temp_allocator)
	append(
		&answer,
		Record{name = APPEND_QNAME, type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {192, 0, 2, 1}}},
		Record{name = "www." + APPEND_QNAME, type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {192, 0, 2, 2}}},
	)
	if raw_len >= 0 {
		append(
			&answer,
			Record {
				name = APPEND_QNAME,
				type = Type(65280),
				class = .IN,
				ttl = 60,
				data = Rdata_Raw{data = make([]u8, raw_len, context.temp_allocator)},
			},
		)
	}
	m := Message {
		id         = 1,
		question   = questions,
		answer     = answer[:],
		additional = additional,
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator, compress = compress)
	if err != .None {
		return nil
	}
	return wire
}

// A message of exactly `size` bytes: the fixture, padded out with one raw record.
@(private = "file")
append_fixture_of_size :: proc(size: int) -> []u8 {
	empty := append_fixture(raw_len = 0, compress = false)
	return append_fixture(raw_len = size - len(empty), compress = false)
}

// The two messages decode, and to the same thing: each is encoded again by the
// one encoder, and the bytes compared.
@(private = "file")
expect_same_message :: proc(t: ^testing.T, got, want: []u8, loc := #caller_location) {
	a, aerr := decode_message(got, context.temp_allocator)
	b, berr := decode_message(want, context.temp_allocator)
	testing.expect_value(t, aerr, Decode_Error.None, loc)
	testing.expect_value(t, berr, Decode_Error.None, loc)
	ae, _, _ := encode_message(a, context.temp_allocator, compress = false)
	be, _, _ := encode_message(b, context.temp_allocator, compress = false)
	testing.expect(t, mem.compare(ae, be) == 0, "the appended message differs from the rebuilt one", loc = loc)
}

@(private = "file")
expect_appended :: proc(t: ^testing.T, wire: []u8, options: []EDNS_Option = nil, loc := #caller_location) {
	if !testing.expect(t, wire != nil, "could not build the fixture", loc = loc) {
		return
	}
	spent := 0
	out, ok := add_opt_record(wire, 1232, options, context.temp_allocator, &spent)
	if !testing.expect(t, ok, "add_opt_record failed", loc = loc) {
		return
	}
	testing.expect_value(t, spent, 0, loc)
	rdlen := 0
	for o in options {
		rdlen += 4 + len(o.data)
	}
	testing.expect_value(t, len(out), len(wire) + 11 + rdlen, loc)
	if len(out) >= len(wire) {
		testing.expect(t, mem.compare(out[:10], wire[:10]) == 0, "the header changed ahead of ARCOUNT", loc = loc)
		testing.expect(t, mem.compare(out[12:len(wire)], wire[12:]) == 0, "the bytes ahead of the record changed", loc = loc)
	}
	arcount := int(u16(wire[10]) << 8 | u16(wire[11]))
	testing.expect_value(t, int(u16(out[10]) << 8 | u16(out[11])), arcount + 1, loc)

	rebuilt, rok := rebuild_with_opt(wire, 1232, options, context.temp_allocator, nil)
	testing.expect(t, rok, "rebuild_with_opt failed", loc = loc)
	expect_same_message(t, out, rebuilt, loc)

	m, _ := decode_message(out, context.temp_allocator)
	testing.expect_value(t, int(edns_udp_size(m)), 1232, loc)
	testing.expect(t, !edns_do(m), "DO was set on a minted record", loc = loc)
	testing.expect_value(t, int(edns_version(m)), 0, loc)
}

@(test)
test_add_opt_record_appends_with_no_additional_records :: proc(t: ^testing.T) {
	expect_appended(t, append_fixture())
	free_all(context.temp_allocator)
}

@(test)
test_add_opt_record_appends_behind_additional_records :: proc(t: ^testing.T) {
	glue := []Record{{name = "ns." + APPEND_QNAME, type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {192, 0, 2, 53}}}}
	expect_appended(t, append_fixture(glue))
	free_all(context.temp_allocator)
}

// The encoder would compress these names; the client gets them as they came.
@(test)
test_add_opt_record_appends_to_an_uncompressed_message :: proc(t: ^testing.T) {
	expect_appended(t, append_fixture(compress = false))
	free_all(context.temp_allocator)
}

@(test)
test_add_opt_record_appends_an_option :: proc(t: ^testing.T) {
	wire := append_fixture()
	cookie := []u8{1, 2, 3, 4, 5, 6, 7, 8}
	expect_appended(t, wire, []EDNS_Option{{code = u16(EDNS_Option_Code.Cookie), data = cookie}})

	out, ok := ensure_edns_option(wire, .Cookie, cookie, 1232, context.temp_allocator)
	testing.expect(t, ok, "ensure_edns_option failed")
	got, found := peek_edns_option(out, .Cookie)
	testing.expect(t, found && mem.compare(got, cookie) == 0, "the cookie is not in the appended record")
	free_all(context.temp_allocator)
}

// `ensure_opt` itself takes the append, which is the cache hit's road.
@(test)
test_ensure_opt_decodes_nothing :: proc(t: ^testing.T) {
	wire := append_fixture(compress = false)
	spent := 0
	out, ok := ensure_opt(wire, 1232, context.temp_allocator, &spent)
	testing.expect(t, ok, "ensure_opt failed")
	testing.expect_value(t, spent, 0)
	testing.expect_value(t, len(out), len(wire) + 11)
	free_all(context.temp_allocator)
}

// Up to `MAX_MESSAGE` the record is appended; one byte more is the rebuild's to
// cut.
@(test)
test_add_opt_record_at_the_size_limit :: proc(t: ^testing.T) {
	fits := append_fixture_of_size(MAX_MESSAGE - 11)
	testing.expect_value(t, len(fits), MAX_MESSAGE - 11)
	expect_appended(t, fits)

	over := append_fixture_of_size(MAX_MESSAGE - 10)
	testing.expect_value(t, len(over), MAX_MESSAGE - 10)
	spent := 0
	out, ok := add_opt_record(over, 1232, nil, context.temp_allocator, &spent)
	rebuilt, rok := rebuild_with_opt(over, 1232, nil, context.temp_allocator, nil)
	testing.expect_value(t, ok, rok)
	testing.expect(t, spent > 0, "a message too long to append to was not rebuilt")
	testing.expect(t, len(out) <= MAX_MESSAGE, "the message outgrew MAX_MESSAGE")
	testing.expect(t, mem.compare(out, rebuilt) == 0, "the fallback is not the rebuild")

	// An option list RDLENGTH cannot state is past the size limit too.
	big := make([]u8, 0xffff, context.temp_allocator)
	_, bok := add_opt_record(append_fixture(), 1232, []EDNS_Option{{code = 65001, data = big}}, context.temp_allocator, nil)
	testing.expect(t, !bok, "an option longer than RDLENGTH can state was written")
	free_all(context.temp_allocator)
}

// Bytes behind the last record are not the message's; the rebuild drops them,
// and an append would leave them between the answer and its OPT record.
@(test)
test_add_opt_record_rebuilds_a_message_with_trailing_bytes :: proc(t: ^testing.T) {
	wire := append_fixture()
	trailing := make([]u8, len(wire) + 3, context.temp_allocator)
	copy(trailing, wire)
	spent := 0
	out, ok := add_opt_record(trailing, 1232, nil, context.temp_allocator, &spent)
	testing.expect(t, ok, "add_opt_record failed")
	testing.expect(t, spent > 0, "a message with trailing bytes was appended to")
	expect_same_message(t, out, append_fixture(one_minted_opt()))
	free_all(context.temp_allocator)
}

// A message that already has an OPT record is refused, not given a second.
@(test)
test_add_opt_record_refuses_a_message_with_one :: proc(t: ^testing.T) {
	wire := append_fixture(one_minted_opt())
	_, ok := add_opt_record(wire, 1232, nil, context.temp_allocator, nil)
	testing.expect(t, !ok, "a second OPT record was appended")
	free_all(context.temp_allocator)
}

@(private = "file")
one_minted_opt :: proc() -> []Record {
	r := make([]Record, 1, context.temp_allocator)
	r[0] = make_opt(1232, false)
	return r
}

// A record of type OPT outside the additional section is not the message's EDNS
// record (`find_opt_span`), so the message still gets one appended.
@(test)
test_add_opt_record_appends_past_an_opt_typed_answer :: proc(t: ^testing.T) {
	wire := append_fixture()
	answer_opt := make([]u8, len(wire) + 11, context.temp_allocator)
	copy(answer_opt, wire)
	// A root-owned OPT record with an empty RDATA, counted in ANCOUNT.
	answer_opt[len(wire) + 2] = u8(Type.OPT)
	answer_opt[7] += 1
	spent := 0
	out, ok := add_opt_record(answer_opt, 1232, nil, context.temp_allocator, &spent)
	testing.expect(t, ok, "an OPT-typed answer record stopped the mint")
	testing.expect_value(t, spent, 0)
	testing.expect_value(t, len(out), len(answer_opt) + 11)
	free_all(context.temp_allocator)
}
