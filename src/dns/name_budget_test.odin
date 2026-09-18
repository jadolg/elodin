package dns

import "core:mem"
import "core:testing"

// A 255-octet wire name (four labels of low bytes) whose presentation form is
// four characters per octet: the worst expansion a single name can buy.
@(private = "file")
long_wire_name :: proc() -> []u8 {
	out := make([dynamic]u8, 0, 256)
	for l in ([]int{63, 63, 63, 61}) {
		append(&out, u8(l))
		for _ in 0 ..< l {
			append(&out, 0x01)
		}
	}
	append(&out, 0)
	return out[:]
}

@(private = "file")
put_header :: proc(buf: ^[dynamic]u8, ancount: u16) {
	append(buf, 0x12, 0x34, 0x81, 0x80, 0, 1, u8(ancount >> 8), u8(ancount), 0, 0, 0, 0)
}

@(private = "file")
put_u16 :: proc(buf: ^[dynamic]u8, v: u16) {
	append(buf, u8(v >> 8), u8(v))
}

// An answer of MX records whose owner and exchange are both two-byte pointers
// to one 255-octet name, which is the shape reported in issue #298.
@(private = "file")
pointer_mx_answer :: proc() -> []u8 {
	name := long_wire_name()
	defer delete(name)

	// 16 bytes a record: pointer owner, type, class, ttl, rdlength, rdata.
	count := u16((65535 - 12 - len(name) - 4) / 16)
	msg := make([dynamic]u8, 0, 65535)
	put_header(&msg, count)
	append(&msg, ..name)
	put_u16(&msg, u16(Type.MX))
	put_u16(&msg, u16(Class.IN))
	for _ in 0 ..< count {
		append(&msg, 0xc0, 0x0c) // owner: the question's name
		put_u16(&msg, u16(Type.MX))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4) // rdlength
		put_u16(&msg, 10) // preference
		append(&msg, 0xc0, 0x0c) // exchange: the same name again
	}
	return msg[:]
}

/*
An answer of PX records - a type the codec keeps as raw bytes - whose two RDATA
names point at one 255-octet name.

The owners are pointers to a two-byte question name, so nothing but the RDATA
expansion pays for anything here: this is the same amplification reached through
`decode_raw_rdata` rather than through the record's own owner.
*/
@(private = "file")
pointer_px_answer :: proc() -> []u8 {
	name := long_wire_name()
	defer delete(name)

	msg := make([dynamic]u8, 0, 65535)
	// Header (12) + question "x." (3) + qtype/qclass (4): the long name then
	// starts at offset 19 as the first record's owner.
	long_at := u16(19)
	count := u16((65535 - 19 - (len(name) + 16) - 1) / 18 + 1)
	put_header(&msg, count)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.PX))
	put_u16(&msg, u16(Class.IN))
	for i in 0 ..< count {
		if i == 0 {
			append(&msg, ..name)
		} else {
			append(&msg, 0xc0, 0x0c)
		}
		put_u16(&msg, u16(Type.PX))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 6) // rdlength
		put_u16(&msg, 10) // preference
		append(&msg, 0xc0, u8(long_at))
		append(&msg, 0xc0, u8(long_at))
	}
	return msg[:]
}

/*
An answer of NXT records whose RDATA holds a pointer byte but no walkable name.

`decode_raw_rdata` takes the expansion buffer before it knows whether the walk
will get anywhere, and an arena does not take it back when the walk fails on the
first byte. That buffer is 255 bytes and more whatever the RDATA holds, and the
record buying it is fourteen wire bytes, so it is charged like the names it was
meant to hold.
*/
@(private = "file")
unwalkable_raw_answer :: proc() -> []u8 {
	msg := make([dynamic]u8, 0, 65535)
	put_header(&msg, 0)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.NXT))
	put_u16(&msg, u16(Class.IN))
	count := 0
	for len(msg) + 14 <= 65535 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.NXT))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 2) // rdlength
		// A reserved label type, so the name walk fails before it starts - but
		// the second byte is a pointer byte, which is what makes it look worth
		// walking.
		append(&msg, 0x80, 0xc0)
		count += 1
	}
	msg[6] = u8(count >> 8)
	msg[7] = u8(count)
	return msg[:]
}

@(test)
test_unwalkable_raw_rdata_stays_within_the_name_budget :: proc(t: ^testing.T) {
	msg := unwalkable_raw_answer()
	defer delete(msg)

	used, err := decode_into_arena(t, msg)
	testing.expect_value(t, err, Decode_Error.Name_Budget)
	testing.expectf(
		t,
		used <= DECODE_CEILING * len(msg),
		"a %d-byte reply expanded into %d bytes of arena through raw RDATA that never walked",
		len(msg),
		used,
	)
}

@(private = "file")
decode_into_arena :: proc(t: ^testing.T, msg: []u8) -> (used: int, err: Decode_Error) {
	backing := make([]u8, 48 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)

	_, derr := decode_message(msg, mem.arena_allocator(&arena))
	return arena.offset, derr
}

/*
The whole decode has to stay within a small multiple of the message.

The budget bounds the names. The record array and the RDATA copies beside them
are not in it and do not need to be - a record costs at least eleven wire bytes,
so both are already a fixed multiple of the message - but they are in what the
arena holds, which is what is measured here. Twenty-four times over covers the
shapes below, which cost a hundred and thirty times their own length and more
with nothing bounding the names.

It is not a ceiling on the decoder. Names are not its only expansion: a TXT
record of 65 KB of zero-length character-strings decodes to 32 times its own
length through the retained `[dynamic]string`, which this budget does not touch
and issue #351 covers.
*/
@(private = "file")
DECODE_CEILING :: 24

@(test)
test_pointer_mx_answer_stays_within_the_name_budget :: proc(t: ^testing.T) {
	msg := pointer_mx_answer()
	defer delete(msg)

	used, err := decode_into_arena(t, msg)
	testing.expect_value(t, err, Decode_Error.Name_Budget)
	testing.expectf(
		t,
		used <= DECODE_CEILING * len(msg),
		"a %d-byte reply expanded into %d bytes of arena",
		len(msg),
		used,
	)
}

@(test)
test_pointer_px_rdata_stays_within_the_name_budget :: proc(t: ^testing.T) {
	msg := pointer_px_answer()
	defer delete(msg)

	used, err := decode_into_arena(t, msg)
	// The owners are cheap here, so it is the RDATA expansion that spends the
	// budget; the record after it then fails on its own owner name, which is
	// what refuses the message.
	testing.expect_value(t, err, Decode_Error.Name_Budget)
	testing.expectf(
		t,
		used <= DECODE_CEILING * len(msg),
		"a %d-byte reply expanded into %d bytes of arena through raw RDATA",
		len(msg),
		used,
	)
}

/*
A record of a two-name layout takes its expansion buffer once.

`expand_rdata_names` reserves the buffer before it walks, and PX, SOA, MINFO and
RP carry two names - each of which may expand from a two-byte pointer to a whole
`MAX_NAME_WIRE`. Reserved for one name the buffer outgrows its block on the
second, and under an arena the block it abandons is never given back and was
never charged: one PX record whose two names point at a 255-octet name costs
4,648 bytes with the reserve right and 5,170 with it wrong.

A tight figure on purpose. The gap is one abandoned block, not an order of
magnitude, and nothing else here would notice it.
*/
@(test)
test_a_two_name_layout_does_not_outgrow_its_buffer :: proc(t: ^testing.T) {
	name := long_wire_name()
	defer delete(name)

	msg := make([dynamic]u8, 0, 512)
	defer delete(msg)
	put_header(&msg, 1)
	append(&msg, ..name)
	put_u16(&msg, u16(Type.PX))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0xc0, 0x0c)
	put_u16(&msg, u16(Type.PX))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0, 0, 0x0e, 0x10)
	put_u16(&msg, 6) // rdlength
	put_u16(&msg, 10) // preference
	append(&msg, 0xc0, 0x0c)
	append(&msg, 0xc0, 0x0c)

	used, err := decode_into_arena(t, msg[:])
	testing.expect_value(t, err, Decode_Error.None)
	testing.expectf(t, used < 5000, "one PX record cost %d bytes of arena", used)
}

/*
A full-length answer whose owner names are as long as a real one's get still
decodes.

The shape that costs the most and is still something a server would send: one
name written out once and pointed at by every record of an RRset under it, at
the largest a reply gets. A hundred characters is a long hostname and 4000 A
records is a large RRset; together they come to 404 KB of names against the
640 KB budget.

The names here come to 404 KB against the 640 KB budget, so the test is a real
hold on the figure rather than a shape that could never reach it. The boundary
is a good way further out: a pointer-owned record costs 16 wire bytes for about
101 of name here, and it takes around 160 characters of name before a
full-length reply of them is refused.
*/
@(test)
test_long_name_pointed_at_by_a_whole_rrset_still_decodes :: proc(t: ^testing.T) {
	name := make([dynamic]u8, 0, 128)
	defer delete(name)
	for l in ([]int{63, 36}) {
		append(&name, u8(l))
		for _ in 0 ..< l {
			append(&name, 'a')
		}
	}
	append(&name, 0)

	msg := make([dynamic]u8, 0, 65535)
	defer delete(msg)
	put_header(&msg, 0)
	append(&msg, ..name[:])
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	count := 0
	for len(msg) + 16 <= 65535 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.A))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		append(&msg, 93, 184, 216, 34)
		count += 1
	}
	msg[6] = u8(count >> 8)
	msg[7] = u8(count)

	_, err := decode_into_arena(t, msg[:])
	testing.expect_value(t, err, Decode_Error.None)
}
