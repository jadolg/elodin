package dns

import "core:mem"
import "core:testing"

@(private = "file")
opt_query :: proc(options: []EDNS_Option, allocator := context.temp_allocator) -> []u8 {
	q := Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	questions := make([]Question, 1, allocator)
	questions[0] = q

	opt := make_opt(1232, false)
	if options != nil {
		opt.data = Rdata_OPT{options = options}
	}
	additional := make([]Record, 1, allocator)
	additional[0] = opt

	m := Message {
		id         = 0x1234,
		question   = questions,
		additional = additional,
	}
	wire, _, err := encode_message(m, allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
option_data :: proc(wire: []u8, code: EDNS_Option_Code) -> (data: []u8, found: bool) {
	m, err := decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return find_edns_option(m, code)
}

@(test)
test_edns_option_appended_to_empty_opt :: proc(t: ^testing.T) {
	wire := opt_query(nil)
	testing.expect(t, wire != nil, "could not build the query")

	out, ok := set_edns_option(wire, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, context.temp_allocator)
	testing.expect(t, ok, "set_edns_option failed")
	testing.expect_value(t, len(out), len(wire) + 4 + 8)

	got, found := option_data(out, .Cookie)
	testing.expect(t, found, "the option is not readable after the splice")
	testing.expect(t, mem.compare(got, []u8{1, 2, 3, 4, 5, 6, 7, 8}) == 0, "option data differs")

	free_all(context.temp_allocator)
}

@(test)
test_edns_option_replaced_in_place :: proc(t: ^testing.T) {
	// Two options, the one being replaced first, so the tail has to move.
	existing := []EDNS_Option {
		{code = u16(EDNS_Option_Code.Cookie), data = []u8{9, 9, 9, 9, 9, 9, 9, 9}},
		{code = u16(EDNS_Option_Code.NSID), data = []u8{'x'}},
	}
	wire := opt_query(existing)
	testing.expect(t, wire != nil, "could not build the query")

	fresh := []u8{1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb}
	out, ok := set_edns_option(wire, .Cookie, fresh, context.temp_allocator)
	testing.expect(t, ok, "set_edns_option failed")

	got, found := option_data(out, .Cookie)
	testing.expect(t, found, "the option went missing")
	testing.expect(t, mem.compare(got, fresh) == 0, "the old option was not replaced")

	// The neighbour must survive untouched.
	nsid, has_nsid := option_data(out, .NSID)
	testing.expect(t, has_nsid, "the NSID option was lost")
	testing.expect(t, mem.compare(nsid, []u8{'x'}) == 0, "the NSID option was corrupted")

	free_all(context.temp_allocator)
}

@(test)
test_edns_option_removed :: proc(t: ^testing.T) {
	existing := []EDNS_Option {
		{code = u16(EDNS_Option_Code.NSID), data = []u8{'x'}},
		{code = u16(EDNS_Option_Code.Cookie), data = []u8{9, 9, 9, 9, 9, 9, 9, 9}},
	}
	wire := opt_query(existing)
	testing.expect(t, wire != nil, "could not build the query")

	out, ok := remove_edns_option(wire, .Cookie, context.temp_allocator)
	testing.expect(t, ok, "remove_edns_option failed")
	testing.expect_value(t, len(out), len(wire) - 4 - 8)

	_, found := option_data(out, .Cookie)
	testing.expect(t, !found, "the option is still there")

	nsid, has_nsid := option_data(out, .NSID)
	testing.expect(t, has_nsid, "the NSID option was lost")
	testing.expect(t, mem.compare(nsid, []u8{'x'}) == 0, "the NSID option was corrupted")

	free_all(context.temp_allocator)
}

@(test)
test_edns_option_remove_when_absent_is_a_no_op :: proc(t: ^testing.T) {
	wire := opt_query(nil)
	out, ok := remove_edns_option(wire, .Cookie, context.temp_allocator)
	testing.expect(t, ok, "remove_edns_option failed")
	testing.expect(t, mem.compare(out, wire) == 0, "the message changed")
	free_all(context.temp_allocator)
}

@(test)
test_edns_option_without_opt_record_fails :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	wire, _, err := encode_message(Message{id = 1, question = questions}, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	_, ok := set_edns_option(wire, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, context.temp_allocator)
	testing.expect(t, !ok, "an option was written into a message with no OPT record")
	free_all(context.temp_allocator)
}

/*
A record after the OPT rules out the byte splice, because everything past the
insertion point would move and any compression pointer aimed there would rot.
The rebuild has to produce a message that still decodes, with both records
intact.
*/
@(test)
test_edns_option_with_a_record_after_the_opt :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	additional := make([]Record, 2, context.temp_allocator)
	additional[0] = make_opt(1232, false)
	additional[1] = Record {
		name  = "ns.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = Rdata_A{addr = {192, 0, 2, 1}},
	}
	wire, _, err := encode_message(
		Message{id = 1, question = questions, additional = additional},
		context.temp_allocator,
	)
	testing.expect_value(t, err, Encode_Error.None)

	out, ok := set_edns_option(wire, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, context.temp_allocator)
	testing.expect(t, ok, "set_edns_option failed")

	got, found := option_data(out, .Cookie)
	testing.expect(t, found, "the option is not readable after the rebuild")
	testing.expect(t, mem.compare(got, []u8{1, 2, 3, 4, 5, 6, 7, 8}) == 0, "option data differs")

	decoded, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, len(decoded.additional), 2)

	free_all(context.temp_allocator)
}

@(test)
test_edns_option_rejects_a_truncated_option_list :: proc(t: ^testing.T) {
	wire := opt_query(nil)
	// Claim eight bytes of option data that are not there.
	bad := make([]u8, len(wire) + 4, context.temp_allocator)
	copy(bad, wire)
	bad[len(bad) - 6] = 0
	bad[len(bad) - 5] = 4 // rdlength = 4
	bad[len(bad) - 4] = 0
	bad[len(bad) - 3] = 10 // COOKIE
	bad[len(bad) - 2] = 0
	bad[len(bad) - 1] = 8 // option length 8, with no data behind it

	_, ok := set_edns_option(bad, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, context.temp_allocator)
	testing.expect(t, !ok, "a truncated option list was accepted")
	free_all(context.temp_allocator)
}

/*
An OPT record only counts in the additional section.

`find_edns_option` reads through `find_opt`, which looks nowhere else, so a
writer that took the first OPT in any section would edit a record the reader
never consults - and leave the option the reader does see standing. A client can
put one in its answer section for the asking, and on the forwarding path that is
the difference between the cookie being stripped and being sent on.
*/
@(test)
test_edns_option_ignores_an_opt_outside_the_additional_section :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}

	decoy := make([]Record, 1, context.temp_allocator)
	decoy[0] = make_opt(1232, false)

	real := make([]Record, 1, context.temp_allocator)
	real[0] = make_opt(1232, false)
	options := make([]EDNS_Option, 1, context.temp_allocator)
	options[0] = EDNS_Option {
		code = u16(EDNS_Option_Code.Cookie),
		data = []u8{9, 9, 9, 9, 9, 9, 9, 9},
	}
	real[0].data = Rdata_OPT{options = options}

	wire, _, err := encode_message(
		Message{id = 1, question = questions, answer = decoy, additional = real},
		context.temp_allocator,
	)
	testing.expect_value(t, err, Encode_Error.None)

	// The reader sees the cookie in the additional section, so the writer has to
	// be looking at that same record.
	_, before := option_data(wire, .Cookie)
	testing.expect(t, before, "the fixture does not carry a readable cookie")

	out, ok := remove_edns_option(wire, .Cookie, context.temp_allocator)
	testing.expect(t, ok, "remove_edns_option failed")

	_, still := option_data(out, .Cookie)
	testing.expect(t, !still, "the cookie survived removal: the decoy OPT was edited instead")

	free_all(context.temp_allocator)
}

@(private = "file")
plain_answer :: proc(allocator := context.temp_allocator) -> []u8 {
	questions := make([]Question, 1, allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 1, allocator)
	answer[0] = Record {
		name  = "example.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = Rdata_A{addr = {192, 0, 2, 1}},
	}
	wire, _, err := encode_message(Message{id = 1, question = questions, answer = answer}, allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
An answer from an upstream that dropped EDNS still has to carry a cookie back to
a client that asked with one, so `ensure_edns_option` adds the OPT record that
`set_edns_option` would have refused for want of one.
*/
@(test)
test_ensure_edns_option_adds_a_missing_opt_record :: proc(t: ^testing.T) {
	wire := plain_answer()
	testing.expect(t, wire != nil, "could not build the answer")

	_, none := set_edns_option(wire, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, context.temp_allocator)
	testing.expect(t, !none, "set_edns_option invented an OPT record")

	cookie := []u8{1, 2, 3, 4, 5, 6, 7, 8}
	out, ok := ensure_edns_option(wire, .Cookie, cookie, 1232, context.temp_allocator)
	testing.expect(t, ok, "ensure_edns_option failed")

	got, found := option_data(out, .Cookie)
	testing.expect(t, found, "the option is not readable after the rebuild")
	testing.expect(t, mem.compare(got, cookie) == 0, "option data differs")

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	// The answer the client asked for has to survive the rebuild.
	testing.expect_value(t, len(m.answer), 1)
	testing.expect_value(t, len(m.additional), 1)
	// Advertised on our terms, and with DO clear: this answer reached us without
	// signatures and the bit would say otherwise.
	testing.expect_value(t, int(edns_udp_size(m)), 1232)
	testing.expect(t, !edns_do(m), "DO was set on an OPT record we invented")

	free_all(context.temp_allocator)
}

// With an OPT record already there, the splice does the work and no second one
// appears.
@(test)
test_ensure_edns_option_uses_an_existing_opt_record :: proc(t: ^testing.T) {
	existing := []EDNS_Option{{code = u16(EDNS_Option_Code.NSID), data = []u8{'x'}}}
	wire := opt_query(existing)
	testing.expect(t, wire != nil, "could not build the query")

	cookie := []u8{1, 2, 3, 4, 5, 6, 7, 8}
	out, ok := ensure_edns_option(wire, .Cookie, cookie, 4096, context.temp_allocator)
	testing.expect(t, ok, "ensure_edns_option failed")
	testing.expect_value(t, len(out), len(wire) + 4 + len(cookie))

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, len(m.additional), 1)
	// The record that was already there wins; `udp_size` is only for one we mint.
	testing.expect_value(t, int(edns_udp_size(m)), 1232)

	got, found := find_edns_option(m, .Cookie)
	testing.expect(t, found, "the option is not readable after the splice")
	testing.expect(t, mem.compare(got, cookie) == 0, "option data differs")

	nsid, has_nsid := find_edns_option(m, .NSID)
	testing.expect(t, has_nsid, "the NSID option was lost")
	testing.expect(t, mem.compare(nsid, []u8{'x'}) == 0, "the NSID option was corrupted")

	free_all(context.temp_allocator)
}

// A message that cannot be walked is not one to hand back half-changed.
@(test)
test_ensure_edns_option_refuses_a_message_it_cannot_read :: proc(t: ^testing.T) {
	wire := opt_query(nil)
	// Claim four bytes of option data that are not there, which the decoder
	// rejects outright.
	bad := make([]u8, len(wire) + 4, context.temp_allocator)
	copy(bad, wire)
	bad[len(bad) - 6] = 0
	bad[len(bad) - 5] = 4 // rdlength = 4
	bad[len(bad) - 4] = 0
	bad[len(bad) - 3] = 10 // COOKIE
	bad[len(bad) - 2] = 0
	bad[len(bad) - 1] = 8 // option length 8, with no data behind it

	_, ok := ensure_edns_option(bad, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, 1232, context.temp_allocator)
	testing.expect(t, !ok, "a message that does not decode was rewritten")

	// Nor is one with a header promising records it does not carry.
	short := make([]u8, HEADER_SIZE, context.temp_allocator)
	short[11] = 1 // arcount = 1, and nothing behind the header
	_, short_ok := ensure_edns_option(short, .Cookie, []u8{1, 2, 3, 4, 5, 6, 7, 8}, 1232, context.temp_allocator)
	testing.expect(t, !short_ok, "a truncated message was rewritten")

	free_all(context.temp_allocator)
}

/*
The extended rcode lives in the OPT record, not in the header, so a message
carrying BADCOOKIE (23) reads as YXRRSET (7) to anything that stops at the
header's four bits.
*/
@(test)
test_peek_rcode_reads_the_extended_bits :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	query := Message {
		id       = 1,
		question = questions,
	}

	resp := make_response(query, .Bad_Cookie, context.temp_allocator)
	// make_response only echoes an OPT when the query had one, and this query
	// has none, so the record is put there by hand.
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = make_opt(1232, false, u8(u16(Rcode.Bad_Cookie) >> 4))
	resp.additional = additional

	wire, _, err := encode_message(resp, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect_value(t, wire[3] & 0xf, u8(7))
	testing.expect_value(t, peek_rcode(wire), Rcode.Bad_Cookie)

	// Without an OPT record the header is all there is.
	plain, _, perr := encode_message(make_response(query, .NX_Domain, context.temp_allocator), context.temp_allocator)
	testing.expect_value(t, perr, Encode_Error.None)
	testing.expect_value(t, peek_rcode(plain), Rcode.NX_Domain)

	testing.expect_value(t, peek_rcode([]u8{1, 2}), Rcode.No_Error)
	free_all(context.temp_allocator)
}

/*
The payload size an answer advertises is written back onto the bytes it will go
out as.

RFC 6891 section 6.2.4 makes the OPT record's CLASS field in a response the
responder's own number rather than a copy of the requestor's, and the number
this server can honour is only known once the transport and the configured
ceiling have been resolved - by which point the answer is already encoded, and
may be an upstream's bytes or a cache entry that must keep the name compression
it came with. So the two bytes are set in place.
*/
@(test)
test_set_edns_udp_size_rewrites_the_opt_class :: proc(t: ^testing.T) {
	wire := opt_query(nil)
	testing.expect(t, wire != nil, "could not build the query")
	testing.expect_value(t, int(peek_udp_size(wire)), 1232)

	testing.expect(t, set_edns_udp_size(wire, 512), "set_edns_udp_size failed")
	testing.expect_value(t, int(peek_udp_size(wire)), 512)

	// Nothing else moved: the message still decodes and still carries one OPT.
	m, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, len(m.additional), 1)
	testing.expect_value(t, int(edns_udp_size(m)), 512)

	// And it is a plain assignment, not a ceiling: raising it works too.
	testing.expect(t, set_edns_udp_size(wire, 4096), "set_edns_udp_size failed on the way up")
	testing.expect_value(t, int(peek_udp_size(wire)), 4096)

	free_all(context.temp_allocator)
}

// The options behind the record are untouched: only the class field moves.
@(test)
test_set_edns_udp_size_keeps_the_options :: proc(t: ^testing.T) {
	existing := []EDNS_Option{{code = u16(EDNS_Option_Code.NSID), data = []u8{'x', 'y'}}}
	wire := opt_query(existing)
	testing.expect(t, wire != nil, "could not build the query")

	testing.expect(t, set_edns_udp_size(wire, 1232), "set_edns_udp_size failed")
	testing.expect_value(t, int(peek_udp_size(wire)), 1232)

	nsid, found := option_data(wire, .NSID)
	testing.expect(t, found, "the NSID option was lost")
	testing.expect(t, mem.compare(nsid, []u8{'x', 'y'}) == 0, "the NSID option was corrupted")

	free_all(context.temp_allocator)
}

/*
A message with no OPT record is left alone and says so.

A client that asked without EDNS gets no OPT back, and there is no field to
write a number into. Reporting that is what lets the caller tell it apart from a
message it could not walk, and neither is a reason to refuse the answer.
*/
@(test)
test_set_edns_udp_size_reports_a_message_with_no_opt :: proc(t: ^testing.T) {
	plain := plain_answer()
	testing.expect(t, plain != nil, "could not build the answer")
	before := make([]u8, len(plain), context.temp_allocator)
	copy(before, plain)

	testing.expect(t, !set_edns_udp_size(plain, 1232), "set_edns_udp_size invented an OPT record")
	testing.expect(t, mem.compare(plain, before) == 0, "the message was changed anyway")

	testing.expect(t, !set_edns_udp_size([]u8{1, 2, 3}, 1232), "a message too short to hold a header was accepted")

	free_all(context.temp_allocator)
}

/*
An answer whose AFSDB hostname is compressed into the message, with the pointer
aimed at the NS target written before it.

The twin of `message_prefix` in dns_test.odin, kept separate because both are
file-private; either one on its own says too little about what the other tests
build, and sharing them would put wire-format scaffolding in the package proper.
*/
@(private = "file")
answer_with_compressed_afsdb :: proc() -> []u8 {
	m := make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&m, 0x12, 0x34, 0x80, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00)
	// Question: example.com. A IN, at offset 12.
	append(&m, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	append(&m, 0x00, 0x01, 0x00, 0x01)
	// Answer 1: example.com. NS ns1.example.com.
	append(&m, 0xc0, 0x0c)
	append(&m, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x06)
	ns_target := len(m)
	append(&m, 3, 'n', 's', '1', 0xc0, 0x0c)
	// Answer 2: example.com. AFSDB 1 <pointer at the NS target above>
	append(&m, 0xc0, 0x0c)
	append(&m, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04)
	append(&m, 0x00, 0x01, 0xc0 | u8(ns_target >> 8), u8(ns_target))
	return m[:]
}

/*
Attaching a cookie to an answer that has no OPT record leaves its AFSDB record
naming the same host.

This is the path a real answer takes rather than a codec round-trip made up for
a test: an upstream that does not do EDNS replies without an OPT record, so
`ensure_edns_option` has nothing to rewrite in place and rebuilds the message
through the writer instead. Whatever the RDATA of a record the codec keeps as
raw bytes meant on the way in, it has to mean on the way out, because the client
cannot tell that its answer went through a second encoder at all.
*/
@(test)
test_raw_rdata_pointer_survives_cookie_attach :: proc(t: ^testing.T) {
	original := answer_with_compressed_afsdb()
	cookie: [24]u8

	out, ok := ensure_edns_option(original, .Cookie, cookie[:], 1232, context.temp_allocator)
	testing.expect(t, ok, "the cookie could not be attached")

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)

	found := false
	for rec in m.answer {
		if rec.type != .AFSDB {
			continue
		}
		raw, is_raw := rec.data.(Rdata_Raw)
		testing.expect(t, is_raw, "the AFSDB record stopped being raw")
		if !is_raw {
			break
		}
		found = true
		host, _, herr := decode_name(raw.data, 2, context.temp_allocator)
		testing.expect_value(t, herr, Decode_Error.None)
		testing.expect_value(t, host, "ns1.example.com.")
	}
	testing.expect(t, found, "the AFSDB record did not survive the cookie attach")

	_, has_cookie := option_data(out, .Cookie)
	testing.expect(t, has_cookie, "the cookie was not attached")

	free_all(context.temp_allocator)
}

/*
The VERSION field, and the two fields it is wedged between.

RFC 6891 section 6.1.3 lays the OPT record's TTL out as an extended rcode in the
top eight bits, VERSION in the next eight, and sixteen flag bits below that, of
which DO is the highest. The three readers over that one number are pinned
together here because the mistake this guards against is arithmetic rather than
logic: a shift one byte too far reports the extended rcode as the version, and
one byte short reports the flags, and either would be read as a version this
server implements or refuses purely by accident.
*/
@(test)
test_edns_version_reads_the_middle_of_the_ttl :: proc(t: ^testing.T) {
	asked_in :: proc(version: u8, do_bit: bool, ext_rcode: u8) -> Message {
		opt := make_opt(1232, do_bit, ext_rcode)
		opt.ttl |= u32(version) << 16
		additional := make([]Record, 1, context.temp_allocator)
		additional[0] = opt
		return Message{additional = additional}
	}

	testing.expect_value(t, edns_version(asked_in(0, false, 0)), u8(0))
	testing.expect_value(t, edns_version(asked_in(1, false, 0)), u8(1))
	testing.expect_value(t, edns_version(asked_in(255, false, 0)), u8(255))

	// Neither neighbour bleeds into the version, and the version bleeds into
	// neither of them.
	crowded := asked_in(1, true, u8(u16(Rcode.Bad_Vers) >> 4))
	testing.expect_value(t, edns_version(crowded), u8(1))
	testing.expect(t, edns_do(crowded), "the DO bit was lost to the version beside it")
	testing.expect_value(t, rcode_of(crowded), Rcode.Bad_Vers)

	// A message with no OPT record asked in no version at all, which is not a
	// version to refuse.
	testing.expect_value(t, edns_version(Message{}), u8(0))
	free_all(context.temp_allocator)
}

/*
BADVERS is unreadable without the OPT record it travels in.

Rcode 16 is four zero bits in the header and a one in the extended byte, so a
response that lost the extended half does not read as a weaker refusal - it
reads as NOERROR, which is agreement, and the client that asked in a version
this server cannot answer in would take it for an answer. The whole path is
pinned rather than the pieces: `make_response` through `make_opt`, onto the
wire, and back out of both readers, since a client uses one or the other and
they must not disagree.
*/
@(test)
test_badvers_needs_its_opt_record_to_read_as_a_refusal :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	opt := make_opt(1232, false)
	// Asked in version 1, which is what makes the version on the way back a
	// statement rather than an echo.
	opt.ttl |= u32(1) << 16
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = opt
	query := Message {
		id         = 0x4321,
		question   = questions,
		additional = additional,
	}

	resp := make_response(query, .Bad_Vers, context.temp_allocator)
	wire, _, err := encode_message(resp, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	testing.expect_value(t, wire[3] & 0xf, u8(0))
	testing.expect_value(t, peek_rcode(wire), Rcode.Bad_Vers)

	decoded, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, rcode_of(decoded), Rcode.Bad_Vers)

	// RFC 6891 section 6.1.3 has the response state the highest version the
	// responder implements, which is 0 - not the version that was asked for.
	testing.expect_value(t, edns_version(decoded), u8(0))

	/*
	And the same through `error_response`, which is what the version gate
	actually calls, for the one query that has nothing else to build from: id
	zero and no question at all. That is the shape which sends `error_response`
	down its header-patching fallback, and a twelve-byte header has no OPT
	record to carry the top four bits of rcode 16 - so the refusal would go back
	as NOERROR, which is this server agreeing to a version it cannot speak. The
	gate runs before the question count is checked, so the shape is reachable.
	*/
	bare := Message {
		additional = additional,
	}
	bare_wire, bare_ok := error_response(make([]u8, HEADER_SIZE, context.temp_allocator), bare, .Bad_Vers, context.temp_allocator)
	testing.expect(t, bare_ok, "no answer was built for a version refusal with no question")
	testing.expect_value(t, peek_rcode(bare_wire), Rcode.Bad_Vers)
	bare_decoded, bare_derr := decode_message(bare_wire, context.temp_allocator)
	testing.expect_value(t, bare_derr, Decode_Error.None)
	testing.expect_value(t, rcode_of(bare_decoded), Rcode.Bad_Vers)

	free_all(context.temp_allocator)
}
