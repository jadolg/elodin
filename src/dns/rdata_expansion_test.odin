package dns

import "core:mem"
import "core:testing"

/*
What a repeated RDATA element costs in memory, against what it costs on the wire.

Names are not the decoder's only expansion. Two RDATA types hold a list whose
length the wire chooses: TXT's `<character-string>`s and OPT's options. Both were
collected into a `[dynamic]` that started at two elements and doubled, and under
an arena - which is what a caller serving a query hands in - every buffer the
doubling walks past is abandoned where it lies. So the list cost about twice what
it keeps, on top of an element that is already far larger in memory than the wire
asks for it.

A `<character-string>` may be zero bytes long, so one length byte buys a 16-byte
`string` header: 16x before the doubling and 32x after it, which is more than the
budget in #350 permits for the shapes it does bound, and nothing here was bounded
at all. An EDNS option is four wire bytes at its smallest and 24 in memory, so it
reached 12x the same way. Issue #351.

The count is on the wire in both cases - follow the length fields and stop at the
RDATA's end - so it is read before anything is taken and the list is allocated
once, at its exact size. That is the whole of what these measure: the doubling is
gone, and what is left is the element itself, which is inherent to keeping it.
*/

@(private = "file")
put_ar_header :: proc(buf: ^[dynamic]u8, arcount: u16) {
	append(buf, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, u8(arcount >> 8), u8(arcount))
}

/*
One TXT record whose RDATA is nothing but length bytes of zero.

65,504 well-formed empty character-strings in 65,535 bytes of wire, which is the
shape reported in #351 and the most `[]string` headers a message can ask for.
*/
@(private = "file")
txt_of_empty_character_strings :: proc() -> []u8 {
	msg := make([dynamic]u8, 0, 65535)
	put_header(&msg, 1)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.TXT))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0xc0, 0x0c)
	put_u16(&msg, u16(Type.TXT))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0, 0, 0x0e, 0x10)
	rdlength := 65535 - (len(msg) + 2)
	put_u16(&msg, u16(rdlength))
	for _ in 0 ..< rdlength {
		append(&msg, 0)
	}
	return msg[:]
}

@(test)
test_txt_of_empty_character_strings_stays_within_the_decode_ceiling :: proc(t: ^testing.T) {
	msg := txt_of_empty_character_strings()
	defer delete(msg)

	used, err := decode_into_arena(msg)
	testing.expect_value(t, err, Decode_Error.None)
	testing.expectf(
		t,
		used <= DECODE_CEILING * len(msg),
		"a %d-byte reply of empty character-strings expanded into %d bytes of arena",
		len(msg),
		used,
	)
}

// One OPT record whose RDATA is 16,376 options of zero length: four wire bytes
// each, and the most `EDNS_Option`s a message can ask for.
@(private = "file")
opt_of_empty_options :: proc() -> []u8 {
	msg := make([dynamic]u8, 0, 65535)
	put_ar_header(&msg, 1)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0) // OPT's owner is the root
	put_u16(&msg, u16(Type.OPT))
	put_u16(&msg, 4096) // class: the requestor's payload size
	append(&msg, 0, 0, 0, 0)
	options := (65535 - (len(msg) + 2)) / 4
	put_u16(&msg, u16(options * 4))
	for _ in 0 ..< options {
		put_u16(&msg, 0) // an unassigned option code
		put_u16(&msg, 0) // of zero length
	}
	return msg[:]
}

@(test)
test_opt_of_empty_options_is_barely_charged :: proc(t: ^testing.T) {
	msg := opt_of_empty_options()
	defer delete(msg)

	used, err := decode_into_arena(msg)
	testing.expect_value(t, err, Decode_Error.None)
	// Tighter than `DECODE_CEILING` on purpose: an option is 24 bytes in memory
	// against four on the wire, so six times over is what this shape costs once
	// the doubling is gone and there is nothing else in the message to pay for.
	testing.expectf(
		t,
		used <= 8 * len(msg),
		"a %d-byte reply of empty EDNS options expanded into %d bytes of arena",
		len(msg),
		used,
	)
}

/*
Counting the elements before reading them does not change what is read.

Both lists are now sized from a pass that follows the length fields, so that pass
and the read after it have to agree about where every element starts and where
the RDATA ends - including for the RDATA that is wrong, which the decoder keeps
as `Rdata_Raw` rather than rejecting.
*/
@(test)
test_a_counted_list_decodes_to_what_it_always_did :: proc(t: ^testing.T) {
	backing := make([]u8, 1 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	// A TXT of three strings, one empty and one 255 bytes long: the count has to
	// survive both ends of the length byte's range.
	rdata := make([dynamic]u8, 0, 512)
	defer delete(rdata)
	append(&rdata, 2, 'h', 'i')
	append(&rdata, 0)
	append(&rdata, 255)
	for _ in 0 ..< 255 {
		append(&rdata, 'z')
	}

	msg := one_record_message(.TXT, rdata[:])
	defer delete(msg)
	m, err := decode_message(msg, a)
	testing.expect_value(t, err, Decode_Error.None)
	if txt, ok := m.answer[0].data.(Rdata_TXT); testing.expect(t, ok, "expected a TXT record") {
		testing.expect_value(t, len(txt.strings), 3)
		testing.expect_value(t, txt.strings[0], "hi")
		testing.expect_value(t, len(txt.strings[1]), 0)
		testing.expect_value(t, len(txt.strings[2]), 255)
	}

	// An empty TXT RDATA holds no strings at all.
	empty := one_record_message(.TXT, {})
	defer delete(empty)
	em, eerr := decode_message(empty, a)
	testing.expect_value(t, eerr, Decode_Error.None)
	if etxt, ok := em.answer[0].data.(Rdata_TXT); testing.expect(t, ok, "expected a TXT record") {
		testing.expect_value(t, len(etxt.strings), 0)
	}

	// A well-formed OPT of two options, one of them empty.
	opt_msg := one_opt_message({0, 10, 0, 2, 'a', 'b', 0, 11, 0, 0})
	defer delete(opt_msg)
	om, oerr := decode_message(opt_msg, a)
	testing.expect_value(t, oerr, Decode_Error.None)
	if opt, ok := om.additional[0].data.(Rdata_OPT); testing.expect(t, ok, "expected an OPT record") {
		testing.expect_value(t, len(opt.options), 2)
		testing.expect_value(t, string(opt.options[0].data), "ab")
		testing.expect_value(t, len(opt.options[1].data), 0)
	}

	/*
	RDATA whose last length field runs past the end of the RDATA.

	The decoder keeps RDATA it could not parse as `Rdata_Raw` rather than
	rejecting the message, and that is what these reached before the counting
	pass existed - through `.Short_Buffer` or through the end-of-RDATA check,
	depending on whether the overrun left the message as well. The pass has to
	refuse exactly the same ones: a count taken from lengths the read then
	disagrees with is a list the wrong size.
	*/
	for fixture in ([]struct {
			what:  string,
			type:  Type,
			rdata: []u8,
		} {
			{"a character-string longer than the RDATA left", .TXT, {2, 'h', 'i', 5, 'a', 'b'}},
			{"an option longer than the RDATA left", .OPT, {0, 3, 0, 9, 'a', 'b'}},
			{"an option header split by the end of the RDATA", .OPT, {0, 3, 0, 0, 0}},
		}) {
		bad := one_record_message(fixture.type, fixture.rdata)
		defer delete(bad)
		bm, berr := decode_message(bad, a)
		testing.expect_value(t, berr, Decode_Error.None)
		_, raw := bm.answer[0].data.(Rdata_Raw)
		testing.expectf(t, raw, "%s: expected raw RDATA, got %v", fixture.what, bm.answer[0].data)
	}
}

@(private = "file")
one_record_message :: proc(type: Type, rdata: []u8) -> []u8 {
	msg := make([dynamic]u8, 0, 512)
	put_header(&msg, 1)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(type))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0xc0, 0x0c)
	put_u16(&msg, u16(type))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0, 0, 0x0e, 0x10)
	put_u16(&msg, u16(len(rdata)))
	append(&msg, ..rdata)
	return msg[:]
}

// An OPT record in the additional section, with its root owner and the payload
// size its class field carries.
@(private = "file")
one_opt_message :: proc(rdata: []u8) -> []u8 {
	msg := make([dynamic]u8, 0, 512)
	put_ar_header(&msg, 1)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0)
	put_u16(&msg, u16(Type.OPT))
	put_u16(&msg, 4096)
	append(&msg, 0, 0, 0, 0)
	put_u16(&msg, u16(len(rdata)))
	append(&msg, ..rdata)
	return msg[:]
}
