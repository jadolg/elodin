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
name_budget_bomb :: proc() -> []u8 {
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
	for len(msg) + 16 <= 65535 {
		append(&msg, 0xc0, 0x0c)
		append(&msg, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		append(&msg, 0, 4, 0, 10)
		append(&msg, 0xc0, 0x0c)
		count += 1
	}
	msg[6] = u8(count >> 8)
	msg[7] = u8(count)
	return msg[:]
}

/*
A reply refused for its name budget is not decoded a second time.

`decode_answer` falls back to the answer section alone when the whole message
will not read, and both decodes go into the one arena the request is served
from. The budget is per decode, so a reply built to spend it would spend it
twice - and the fallback has nothing to find, since the budget stopped it inside
the answer section and the shorter decode is given the same allowance over the
same bytes.
*/
@(test)
test_name_budget_refusal_is_not_decoded_twice :: proc(t: ^testing.T) {
	msg := name_budget_bomb()
	defer delete(msg)

	backing := make([]u8, 16 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)

	out := decode_answer(msg, true, mem.arena_allocator(&arena))
	testing.expect(t, !out.full && !out.partial, "the reply should not have read at all")
	testing.expect_value(t, out.full_err, dns.Decode_Error.Name_Budget)
	// Not attempted, so nothing stopped it.
	testing.expect_value(t, out.partial_err, dns.Decode_Error.None)
	testing.expectf(
		t,
		arena.offset <= 2 * dns.NAME_BUDGET,
		"one refused reading of a %d-byte reply cost %d bytes of arena",
		len(msg),
		arena.offset,
	)
}
