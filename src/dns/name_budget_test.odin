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

`decode_raw_rdata` used to take the expansion buffer before it knew whether the
walk would get anywhere - 255 bytes and more whatever the RDATA held, for a
record of fourteen wire bytes - and an arena does not take it back when the walk
fails on the first byte. Nothing is taken until the walk has finished now, so
these records cost what their bytes cost and no more.
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

	used, err := decode_into_arena(msg)
	testing.expect_value(t, err, Decode_Error.None)
	testing.expectf(
		t,
		used <= DECODE_CEILING * len(msg),
		"a %d-byte reply expanded into %d bytes of arena through raw RDATA that never walked",
		len(msg),
		used,
	)
}

@(private = "file")
decode_into_arena :: proc(msg: []u8) -> (used: int, err: Decode_Error) {
	// Enough for the unbudgeted shapes these fixtures reach when the budget is
	// taken out to check that they still do - 11.4 MB is the largest - and not
	// the 48 MB it once was, with four of these running side by side.
	backing := make([]u8, 16 << 20)
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

	used, err := decode_into_arena(msg)
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

	used, err := decode_into_arena(msg)
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
A name the budget refused does not come back as a raw record holding a pointer.

`decode_record` keeps RDATA it could not parse as `Rdata_Raw` rather than
rejecting the message, which is right for RDATA that is genuinely odd. A name
refused for the budget is not odd - it is well formed and was simply not paid
for - and readers take a raw record to mean the opposite: `cnamecheck` refuses
an answer over a raw CNAME because its target is one no client could read
either, which would be refusing an answer every client reads fine.

Both kinds of record reach it. A CNAME is a type this decoder models, so the
refusal comes back from `decode_rdata` as an error; a PX is not, so it goes to
`decode_raw_rdata`, which never fails and would keep the bytes without a word.
That one also has to be caught, and by more than the error: what it leaves
behind is a blob `encode_message` will not write, so a message that decoded
could not be built again.

The shape is A records under a 255-octet name up to the budget, then the record
in question: it is the last record that can reach this at all, since a message
with more in it fails on the next owner name anyway.
*/
@(private = "file")
answer_ending_in :: proc(type: Type, rdata: []u8, records: int) -> []u8 {
	name := long_wire_name()
	defer delete(name)

	msg := make([dynamic]u8, 0, 16384)
	put_header(&msg, 0)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))

	// The long name inline, as the first record's owner, for the rest to point
	// at - so the owner names are what spends nearly all of the budget.
	append(&msg, ..name)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0, 0, 0x0e, 0x10)
	put_u16(&msg, 4)
	append(&msg, 93, 184, 216, 34)

	count := 1
	for count < records - 1 {
		append(&msg, 0xc0, 0x13)
		put_u16(&msg, u16(Type.A))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		append(&msg, 93, 184, 216, 34)
		count += 1
	}

	// This one's owner is the short question name, so the only thing left that
	// can cross the budget is its RDATA.
	append(&msg, 0xc0, 0x0c)
	put_u16(&msg, u16(type))
	put_u16(&msg, u16(Class.IN))
	append(&msg, 0, 0, 0x0e, 0x10)
	put_u16(&msg, u16(len(rdata)))
	append(&msg, ..rdata)
	count += 1

	msg[6] = u8(count >> 8)
	msg[7] = u8(count)
	return msg[:]
}

@(test)
test_a_refused_name_does_not_become_a_raw_record :: proc(t: ^testing.T) {
	// What one of these owner names costs, read rather than written down, so
	// the fixture follows `NAME_BUDGET` and the escaping wherever they go.
	wire := long_wire_name()
	defer delete(wire)
	owner, _, derr := decode_name(wire, 0)
	defer delete(owner)
	testing.expect_value(t, derr, Decode_Error.None)

	// As many owner names as fit beside the two-byte question name, and then
	// the record under test. What is left over has to be enough for that
	// record's own cheap owner and not enough for the name in its RDATA, or the
	// budget would be crossed somewhere other than where this is looking.
	owners := (NAME_BUDGET - 2) / len(owner)
	left := NAME_BUDGET - 2 - owners * len(owner)
	testing.expectf(t, left > 2 && left - 2 < len(owner), "the fixture leaves %d bytes, which lands elsewhere", left)

	// A CNAME whose target is a pointer, and a PX whose two names are: the
	// modelled path into the check and the unmodelled one.
	for fixture in ([]struct {
			type:  Type,
			rdata: []u8,
		}{{.CNAME, {0xc0, 0x13}}, {.PX, {0, 10, 0xc0, 0x13, 0xc0, 0x13}}}) {
		msg := answer_ending_in(fixture.type, fixture.rdata, owners + 1)
		defer delete(msg)

		backing := make([]u8, 16 << 20)
		defer delete(backing)
		arena: mem.Arena
		mem.arena_init(&arena, backing)
		a := mem.arena_allocator(&arena)

		m, err := decode_message(msg, a)
		testing.expectf(t, err == .Name_Budget, "%v: decoded %v, %d records", fixture.type, err, len(m.answer))
		if err != .None {
			continue
		}
		// It decoded, so it has to be something that can be written again. This
		// is what fails when the refusal is swallowed: the record kept its
		// compression pointer, and `encode_message` will not write one.
		_, _, eerr := encode_message(m, a)
		testing.expectf(t, eerr == .None, "%v: decoded but would not re-encode: %v", fixture.type, eerr)
	}
}

/*
A message this codebase rebuilds still decodes afterwards.

`add_opt_record`, `strip_dnssec_records` and their neighbours all decode a reply
and encode it again, and RDLENGTH grows when a compressed RDATA name is written
back out in full - a two-byte pointer becomes up to 255 octets. A budget that
counted RDLENGTH would therefore rise on the rebuild, and a reply that decoded
on the way in would fail to decode on the way out: `fit_response` re-reads that
wire whenever it passes the client's limit, and would answer TC for a message it
had already read.

The fixture is the one that found it: 100 PX records whose two RDATA names are
pointers, with 300 A records behind them, 6871 bytes on the wire and 57471 once
the names are expanded. The name octets are 0xc0 so the blob still looks worth
walking after the rebuild, which is what makes the second reading charge for the
expansion again.
*/
@(test)
test_a_rebuilt_message_still_decodes :: proc(t: ^testing.T) {
	name := make([dynamic]u8, 0, 256)
	defer delete(name)
	for l in ([]int{63, 63, 63, 61}) {
		append(&name, u8(l))
		for _ in 0 ..< l {
			append(&name, 0xc0)
		}
	}
	append(&name, 0)

	msg := make([dynamic]u8, 0, 16384)
	defer delete(msg)
	put_header(&msg, 400)
	append(&msg, ..name[:])
	put_u16(&msg, u16(Type.PX))
	put_u16(&msg, u16(Class.IN))
	for _ in 0 ..< 100 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.PX))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 6)
		put_u16(&msg, 10)
		append(&msg, 0xc0, 0x0c)
		append(&msg, 0xc0, 0x0c)
	}
	for _ in 0 ..< 300 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.A))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		append(&msg, 93, 184, 216, 34)
	}

	backing := make([]u8, 16 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	first, err := decode_message(msg[:], a)
	testing.expect_value(t, err, Decode_Error.None)

	rebuilt, truncated, eerr := encode_message(first, a)
	testing.expect_value(t, eerr, Encode_Error.None)
	testing.expect(t, !truncated, "the rebuild should have fitted")

	_, again := decode_message(rebuilt, a)
	testing.expectf(
		t,
		again == .None,
		"%d bytes decoded, rebuilt to %d, and would not decode again: %v",
		len(msg),
		len(rebuilt),
		again,
	)
}

/*
A record whose names do not expand is not charged as though they had.

The expansion buffer used to be reserved - and charged - at what a record of the
type might come to, `layout.names * MAX_NAME_WIRE`, whether or not a single name
grew. A PX carries two, so every one of them cost 510 bytes of budget, and
`holds_pointer_byte` is a byte scan: a preference field of 0xc000 is a legal
number and enough to send the record down this path.

A thousand of those fit in 20 KB, and the reply is well formed - both names are
the root, nothing expands, and every byte comes out as it went in. It was
refused at 1280 records and cost 37.8 times its own length in arena, which is a
long way from the full-length bomb the budget exists for.
*/
@(test)
test_a_record_whose_names_do_not_expand_is_barely_charged :: proc(t: ^testing.T) {
	msg := make([dynamic]u8, 0, 65535)
	defer delete(msg)
	put_header(&msg, 0)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.PX))
	put_u16(&msg, u16(Class.IN))
	count := 0
	for len(msg) + 18 <= 30000 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.PX))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		put_u16(&msg, 0xc000) // preference: legal, and looks like a pointer
		append(&msg, 0, 0) // both names are the root
		count += 1
	}
	msg[6] = u8(count >> 8)
	msg[7] = u8(count)

	used, err := decode_into_arena(msg[:])
	testing.expect_value(t, err, Decode_Error.None)
	testing.expectf(
		t,
		used <= 8 * len(msg),
		"%d records that expand nothing cost %d bytes of arena for %d of wire",
		count,
		used,
		len(msg),
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

	used, err := decode_into_arena(msg[:])
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

	_, err := decode_into_arena(msg[:])
	testing.expect_value(t, err, Decode_Error.None)
}
