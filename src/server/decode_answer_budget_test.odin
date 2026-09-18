package server

import "core:mem"
import "core:testing"
import "elodin:dns"

/*
A reply of MX records whose owner and exchange are both two-byte pointers to one
255-octet name of unprintable bytes, which is the shape of issue #298: every
name costs four characters an octet and every record buys two fresh copies.
*/
@(private = "file")
name_budget_bomb :: proc(records := 0, trailing_authority := false) -> []u8 {
	msg := make([dynamic]u8, 0, 65535)
	append(&msg, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
	for l in ([]int{63, 63, 63, 61}) {
		append(&msg, u8(l))
		for _ in 0 ..< l {
			append(&msg, 0x01)
		}
	}
	append(&msg, 0)
	append(&msg, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))

	count := 0
	for len(msg) + 16 <= 65535 && (records == 0 || count < records) {
		append(&msg, 0xc0, 0x0c)
		append(&msg, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		append(&msg, 0, 4, 0, 10)
		append(&msg, 0xc0, 0x0c)
		count += 1
	}
	msg[6] = u8(count >> 8)
	msg[7] = u8(count)

	if trailing_authority {
		// One authority record whose RDLENGTH runs off the end, which is the
		// ordinary malformed-tail case `decode_through_answer` exists for.
		msg[8], msg[9] = 0, 1
		append(&msg, 0xc0, 0x0c)
		append(&msg, 0, u8(dns.Type.A), 0, u8(dns.Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		append(&msg, 0xff, 0xff)
	}
	return msg[:]
}

/*
What the arena may hold after `decode_answer`: two readings, each costing a name
budget and a record array with the RDATA copies beside it.

The array and the copies are not in the budget and do not need to be - a record
costs at least eleven wire bytes, so they are already a fixed multiple of the
message - but they are in what is measured here, and each reading makes its own.
Six times the message covers them.
*/
@(private = "file")
budget_ceiling :: proc(msg_len: int) -> int {
	return 2 * (dns.NAME_BUDGET + 6 * msg_len)
}

@(private = "file")
read_answer :: proc(msg: []u8, arena: ^mem.Arena) -> Decoded_Answer {
	backing := make([]u8, 16 << 20)
	mem.arena_init(arena, backing)
	return decode_answer(msg, true, mem.arena_allocator(arena))
}

@(private = "file")
free_arena :: proc(arena: ^mem.Arena) {
	delete(arena.data)
}

/*
What both readings of one reply may come to.

`decode_answer` falls back to the answer section alone when the whole message
will not read, and both readings expand the same message into the one arena the
request is served from - which therefore holds both expansions at once. Each is
given `dns.NAME_BUDGET`, so this is the ceiling on the pair, and it is what the
issue's own fixture now costs instead of 8.5 MB.
*/
@(test)
test_reading_a_reply_twice_costs_two_budgets_at_most :: proc(t: ^testing.T) {
	msg := name_budget_bomb()
	defer delete(msg)

	arena: mem.Arena
	out := read_answer(msg, &arena)
	defer free_arena(&arena)

	testing.expect(t, !out.full && !out.partial, "the reply should not have read at all")
	testing.expect_value(t, out.full_err, dns.Decode_Error.Name_Budget)
	testing.expect_value(t, out.partial_err, dns.Decode_Error.Name_Budget)
	testing.expectf(
		t,
		arena.offset <= budget_ceiling(len(msg)),
		"reading a %d-byte reply cost %d bytes of arena",
		len(msg),
		arena.offset,
	)
}

/*
The bound holds when the first reading failed for some reason other than names.

An answer section that stops just short of the budget, followed by a malformed
record in the authority section: the whole-message decode fails on the malformed
record, the answer section is read again, and those names are expanded a second
time into the same arena. Nothing about that is particular to a budget failure,
which is why the ceiling is stated for the pair rather than for the one error.
*/
@(test)
test_a_near_budget_answer_read_twice_stays_within_the_pair :: proc(t: ^testing.T) {
	msg := name_budget_bomb(records = 320, trailing_authority = true)
	defer delete(msg)

	arena: mem.Arena
	out := read_answer(msg, &arena)
	defer free_arena(&arena)

	testing.expect_value(t, out.full_err, dns.Decode_Error.Short_Buffer)
	testing.expect(t, out.partial, "the answer section should have read on its own")
	testing.expectf(
		t,
		arena.offset <= budget_ceiling(len(msg)),
		"reading a %d-byte reply cost %d bytes of arena",
		len(msg),
		arena.offset,
	)
}

/*
A reply whose answer section is cheap still gets its shorter reading.

The budget is spent in the additional section here, so the whole message will not
read - but the answer section is a few hundred bytes and reading it costs almost
nothing. Refusing it would be refusing an answer this server had no opinion
about, which is the thing `decode_through_answer` was added to stop.
*/
@(test)
test_a_cheap_answer_survives_an_expensive_additional_section :: proc(t: ^testing.T) {
	bomb := name_budget_bomb()
	defer delete(bomb)

	// The same bytes, with the answer count moved to the additional count: one
	// A record answers, the rest of the reply is somebody else's problem.
	msg := make([dynamic]u8, 0, len(bomb) + 16)
	defer delete(msg)
	append(&msg, ..bomb[:])
	an := (int(msg[6]) << 8 | int(msg[7])) - 1
	msg[6], msg[7] = 0, 1
	msg[10], msg[11] = u8(an >> 8), u8(an)

	arena: mem.Arena
	out := read_answer(msg[:], &arena)
	defer free_arena(&arena)

	testing.expect_value(t, out.full_err, dns.Decode_Error.Name_Budget)
	testing.expect(t, out.partial, "the answer section should have read on its own")
	testing.expect_value(t, len(out.msg.answer), 1)
}
