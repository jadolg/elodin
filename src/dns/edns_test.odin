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
