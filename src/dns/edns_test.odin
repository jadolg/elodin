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
