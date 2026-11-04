package dns

import "core:testing"

/*
A compression pointer into the header is not a name (issue #605).

The header's bytes are ones this server writes in place: the ID for each client,
AD, and ARCOUNT when an OPT record is appended for an EDNS client (#598) or cut
for a client without one. A name that pointed there would read differently for
the client than it did for the checks run on it here, by a change the sender can
predict, so the decoder refuses it.
*/

// One question, `a.test. A IN`, and one A record whose owner is a pointer to
// `target`. With ARCOUNT zero, offset 11 is a zero octet: the root.
@(private = "file")
pointer_owner_answer :: proc(target: u8) -> []u8 {
	msg := make([dynamic]u8, context.temp_allocator)
	append(&msg, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
	append(&msg, 1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1)
	append(&msg, 0xc0, target, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	return msg[:]
}

@(test)
test_a_pointer_into_the_header_is_refused :: proc(t: ^testing.T) {
	// The premise: the owner reads ARCOUNT's low byte, which an append changes.
	wire := pointer_owner_answer(11)
	testing.expect_value(t, wire[11], u8(0))

	_, err := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, err, Decode_Error.Bad_Pointer)
	testing.expect(t, !name_is_root(wire, len(wire) - 16), "name_is_root followed a pointer into the header")

	// Every offset in the header, the ID's first byte included.
	for target in 0 ..< HEADER_SIZE {
		_, herr := decode_message(pointer_owner_answer(u8(target)), context.temp_allocator)
		testing.expectf(t, herr != .None, "a pointer to header offset %d decoded", target)
	}
	free_all(context.temp_allocator)
}

// The first byte past the header is where the question's name starts, and the
// most common pointer target there is.
@(test)
test_a_pointer_to_the_question_still_decodes :: proc(t: ^testing.T) {
	wire := pointer_owner_answer(HEADER_SIZE)
	m, err := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, err, Decode_Error.None)
	if len(m.answer) == 1 {
		testing.expect_value(t, m.answer[0].name, "a.test.")
	}
	free_all(context.temp_allocator)
}
