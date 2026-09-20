package dns

import "core:mem"
import "core:testing"

/*
Issue #354: the name budget is per reading, and one request holds many of them.

`NAME_BUDGET` lives on the `Reader`, so every `decode_message` starts a fresh
one. A single query reads far more than one message into the arena it is served
from: the reply is read for the cache and again for the answer section alone,
`fit_response` reads it a third time when it passes the client's limit, and the
validator reads a reply of its own for every step of the chain, up to
`dnssec.MAX_LOOKUPS_PER_QUERY` of them. Thirty-five readings, each entitled to a
budget of its own, is what the box actually feels.
*/

// The readings one request can hold: two in `decode_answer`, one in
// `fit_response`, and `dnssec.MAX_LOOKUPS_PER_QUERY` chain lookups.
@(private = "file")
READINGS :: 35

// A 255-octet wire name of unprintable octets: 1004 presentation characters,
// the worst a single name can cost.
@(private = "file")
long_name :: proc() -> []u8 {
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

/*
A reply that spends a whole name budget out of a few kilobytes of wire.

MX records whose owner and exchange are both two-byte pointers at one
full-length name, which is issue #298's shape: sixteen wire bytes buy two
expansions of about `MAX_NAME_PRESENTATION` each. Short deliberately - what is
being measured here is the names, and a 64 KB reply would bury them under the
record arrays every reading also builds.
*/
@(private = "file")
budget_bomb :: proc() -> []u8 {
	name := long_name()
	defer delete(name)
	// What one of these costs once escaped, read rather than written down, so
	// the fixture follows `NAME_BUDGET` wherever the escaping goes.
	owner, _, _ := decode_name(name, 0)
	defer delete(owner)

	msg := make([dynamic]u8, 0, 8192)
	put_header(&msg, 0)
	append(&msg, ..name)
	put_u16(&msg, u16(Type.MX))
	put_u16(&msg, u16(Class.IN))

	// One record past the budget: two names apiece, and the reading has to be
	// refused rather than land just inside it.
	count := u16(0)
	for int(count) * 2 * len(owner) <= NAME_BUDGET {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.MX))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		put_u16(&msg, 10)
		append(&msg, 0xc0, 0x0c)
		count += 1
	}
	msg[6], msg[7] = u8(count >> 8), u8(count)
	return msg[:]
}

/*
What the readings of one request may come to.

The names are the request's budget and nothing more. Everything else each
reading builds - its record array, its RDATA copies - is outside that budget and
stays a fixed multiple of the message it read, which `DECODE_CEILING` covers
with room to spare.
*/
@(private = "file")
request_ceiling :: proc(msg_len: int) -> int {
	return REQUEST_NAME_BUDGET + READINGS * DECODE_CEILING * msg_len
}

/*
Every reading of a request charges the one budget the request owns.

Without it each of the thirty-five is entitled to `NAME_BUDGET` of its own, so
five kilobytes of wire reach about 22 MB of names in a single in-flight request.
*/
@(test)
test_the_readings_of_one_request_share_one_name_budget :: proc(t: ^testing.T) {
	msg := budget_bomb()
	defer delete(msg)

	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	spent := 0
	for _ in 0 ..< READINGS {
		decode_message(msg, a, &spent)
	}

	testing.expectf(
		t,
		arena.offset <= request_ceiling(len(msg)),
		"%d readings of a %d-byte reply cost %d bytes of arena, over the %d one request may hold",
		READINGS,
		len(msg),
		arena.offset,
		request_ceiling(len(msg)),
	)
}

/*
The per-reading budget still holds inside a request.

One reading cannot spend the request's whole allowance, which is what keeps a
single bomb from taking the readings after it down with it: the reply above is
refused for `NAME_BUDGET` having paid for about one budget's worth of names, not
for the four megabytes the request owns.
*/
@(test)
test_one_reading_of_a_request_still_stops_at_its_own_budget :: proc(t: ^testing.T) {
	msg := budget_bomb()
	defer delete(msg)

	backing := make([]u8, 8 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)

	spent := 0
	_, err := decode_message(msg, mem.arena_allocator(&arena), &spent)
	testing.expect_value(t, err, Decode_Error.Name_Budget)
	testing.expectf(
		t,
		spent <= NAME_BUDGET + 2 * MAX_NAME_PRESENTATION,
		"one reading charged the request %d bytes, past its own %d",
		spent,
		NAME_BUDGET,
	)
}

/*
A reading refused for the request's budget says so, rather than blaming the
message.

The same bytes read on their own decode perfectly well here - the fixture is a
single ordinary MX record - so `Name_Budget` would be this server reporting its
own accounting as something the reply did. The validator reads that distinction
and answers `Indeterminate` instead of calling a zone forged; see `zone_step`.
*/
@(test)
test_a_reading_past_the_request_budget_is_not_blamed_on_the_message :: proc(t: ^testing.T) {
	msg := budget_bomb()
	defer delete(msg)

	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	spent := 0
	for spent <= REQUEST_NAME_BUDGET {
		decode_message(msg, a, &spent)
	}

	// One plain MX record under a short name: nothing here is worth a budget.
	plain := make([dynamic]u8, 0, 64)
	defer delete(plain)
	put_header(&plain, 1)
	append(&plain, 1, 'x', 0)
	put_u16(&plain, u16(Type.MX))
	put_u16(&plain, u16(Class.IN))
	append(&plain, 0xc0, 0x0c)
	put_u16(&plain, u16(Type.MX))
	put_u16(&plain, u16(Class.IN))
	append(&plain, 0, 0, 0x0e, 0x10)
	put_u16(&plain, 4)
	put_u16(&plain, 10)
	append(&plain, 0xc0, 0x0c)

	_, err := decode_message(plain[:], a, &spent)
	testing.expect_value(t, err, Decode_Error.Request_Name_Budget)

	// And on its own, with a counter of its own, it is a message like any other.
	fresh := 0
	_, ferr := decode_message(plain[:], a, &fresh)
	testing.expect_value(t, ferr, Decode_Error.None)
}

/*
An ordinary request is nowhere near the budget, however many readings it makes.

The reply here is a full 64 KB of records under printable names of the length a
real zone uses, read the thirty-five times a request can read one. What the
budget is there to refuse costs a budget out of five kilobytes; what real
traffic does costs this.
*/
@(test)
test_an_ordinary_reply_read_thirty_five_times_does_not_reach_the_budget :: proc(t: ^testing.T) {
	msg := make([dynamic]u8, 0, 65535)
	defer delete(msg)
	put_header(&msg, 0)
	// `www.example.com.`, written out in full as every record's owner: sixteen
	// presentation characters for twenty-six wire bytes of record.
	name := []u8{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	append(&msg, ..name)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	count := u16(0)
	for len(msg) + len(name) + 14 <= 65535 {
		append(&msg, ..name)
		put_u16(&msg, u16(Type.A))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 4)
		append(&msg, 93, 184, 216, 34)
		count += 1
	}
	msg[6], msg[7] = u8(count >> 8), u8(count)

	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	spent := 0
	for i in 0 ..< READINGS {
		_, err := decode_message(msg[:], a, &spent)
		testing.expectf(t, err == .None, "reading %d of an ordinary reply was refused: %v", i, err)
	}
	testing.expectf(
		t,
		spent < REQUEST_NAME_BUDGET,
		"%d readings of %d ordinary records spent %d of the request's %d",
		READINGS,
		count,
		spent,
		REQUEST_NAME_BUDGET,
	)
}
