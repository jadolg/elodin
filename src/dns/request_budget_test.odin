package dns

import "core:mem"
import "core:testing"

/*
Issue #354: the decoder's budgets were per reading, and one request holds many
of them.

`NAME_BUDGET` lived on the `Reader`, so every `decode_message` started a fresh
one - and what a reading allocates besides names was never bounded at all. A
single query reads the upstream's reply for the cache, reads it again when only
the answer section will parse, reads it a third time in `fit_response` when it
passes the client's limit, and the validator reads a reply of its own for every
step of the chain. Thirty-five readings, all into the one arena the request is
served from.

Measured over those thirty-five, before the counter was the request's:

	names, five kilobytes of pointers at one 255-octet name   23,989,840 B
	65,504 empty character-strings in one TXT record          36,686,720 B
	5,957 minimal records in one message                      18,554,196 B

The first is what `NAME_BUDGET` bounds per reading; the other two it never sees.
*/

// What one request can hold: two readings in `decode_answer`, one in
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
A reply that spends a whole reading's name budget out of a few kilobytes of wire.

MX records whose owner and exchange are both two-byte pointers at one
full-length name, which is issue #298's shape: sixteen wire bytes buy two
expansions of about `MAX_NAME_PRESENTATION` each. Short deliberately - what is
being measured is the names, and a 64 KB reply would bury them under everything
else a reading builds.
*/
@(private = "file")
name_bomb :: proc() -> []u8 {
	name := long_name()
	defer delete(name)
	// What one of these costs once escaped, read rather than written down, so
	// the fixture follows `NAME_BUDGET` and the escaping wherever they go.
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
One TXT record whose RDATA is nothing but length bytes of zero.

A `<character-string>` may be zero bytes long, so one wire byte is one 16-byte
`string` header: 65,504 of them in a full-length message, and the most memory a
message can ask for per byte of wire. Issue #351 took this from 32x to 16x by
counting the list before taking it; what is left is the element itself, and
nothing bounded how many readings of it one request could make.
*/
@(private = "file")
character_string_bomb :: proc() -> []u8 {
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

/*
The most records a message can carry: a root owner, a type this decoder does not
model, and no RDATA at all - eleven wire bytes for a `Record` of about ninety.

The cheap end of the same amplification. Nothing here expands a name or holds a
list; it is the record array itself, once per reading.
*/
@(private = "file")
record_count_bomb :: proc() -> []u8 {
	msg := make([dynamic]u8, 0, 65535)
	put_header(&msg, 0)
	append(&msg, 1, 'x', 0)
	put_u16(&msg, u16(Type.A))
	put_u16(&msg, u16(Class.IN))
	count := 0
	for len(msg) + 11 <= 65535 {
		append(&msg, 0)
		put_u16(&msg, 999)
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 0)
		count += 1
	}
	msg[6], msg[7] = u8(count >> 8), u8(count)
	return msg[:]
}

/*
What the readings of one request may come to.

`REQUEST_DECODE_BUDGET` is what the decoder takes out of the arena; the slop
above it is the overshoot each kind of charge can reach. A name is charged after
it is decoded, because that is when what it cost is known, and an RDATA layout
reads its names one after another before anything checks again. Everything else
is charged before it is taken - the sizes are known - except the two copies
`decode_raw_rdata` makes, which cannot fail and are one record's RDATA each.
*/
@(private = "file")
request_ceiling :: proc() -> int {
	return REQUEST_DECODE_BUDGET + 2 * MAX_NAME_PRESENTATION + 2 * MAX_MESSAGE
}

@(private = "file")
read_many :: proc(msg: []u8, readings: int) -> (used: int, spent: int) {
	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	for _ in 0 ..< readings {
		decode_message(msg, a, &spent)
	}
	return arena.offset, spent
}

/*
Every reading of a request charges the one budget the request owns.

Three shapes, because the amplification has three ends and the budget has to
hold for all of them: names, a repeated RDATA element, and the record array.
Without the request's counter each is bounded per reading, which is to say
bounded thirty-five times over.
*/
@(test)
test_the_readings_of_one_request_share_one_budget :: proc(t: ^testing.T) {
	for fixture in ([]struct {
			what: string,
			msg:  []u8,
		} {
			{"names", name_bomb()},
			{"character-strings", character_string_bomb()},
			{"records", record_count_bomb()},
		}) {
		defer delete(fixture.msg)

		used, _ := read_many(fixture.msg, READINGS)
		testing.expectf(
			t,
			used <= request_ceiling(),
			"%s: %d readings of a %d-byte reply cost %d bytes of arena, over the %d one request may take",
			fixture.what,
			READINGS,
			len(fixture.msg),
			used,
			request_ceiling(),
		)
	}
}

/*
The per-reading name budget still holds inside a request.

One reading cannot spend the request's whole allowance on names, which is what
keeps a single bomb from taking the readings after it down with it: the reply
here is refused for `NAME_BUDGET` having paid for about one budget's worth of
names, not for the eight megabytes the request owns.
*/
@(test)
test_one_reading_of_a_request_still_stops_at_its_own_name_budget :: proc(t: ^testing.T) {
	msg := name_bomb()
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
		spent <= NAME_BUDGET + 12 * len(msg),
		"one reading charged the request %d bytes, past its own %d plus what the records cost",
		spent,
		NAME_BUDGET,
	)
}

/*
A reading refused for the request's budget says so, rather than blaming the
message.

The same bytes read on their own decode perfectly well here - the fixture is a
single ordinary MX record - so `Name_Budget`, or any other error about the
message, would be this server reporting its own accounting as something the
reply did. The validator reads that distinction and answers `Indeterminate`
instead of calling a zone forged; see `zone_step`.
*/
@(test)
test_a_reading_past_the_request_budget_is_not_blamed_on_the_message :: proc(t: ^testing.T) {
	msg := name_bomb()
	defer delete(msg)

	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	spent := 0
	for spent <= REQUEST_DECODE_BUDGET {
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
	testing.expect_value(t, err, Decode_Error.Request_Budget)

	// And on its own, with a counter of its own, it is a message like any other.
	fresh := 0
	_, ferr := decode_message(plain[:], a, &fresh)
	testing.expect_value(t, ferr, Decode_Error.None)
}

// A full-length answer of ordinary A records under one printable name, which is
// what a large legitimate reply looks like.
@(private = "file")
ordinary_answer :: proc() -> []u8 {
	name := []u8{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg := make([dynamic]u8, 0, 65535)
	put_header(&msg, 0)
	append(&msg, ..name)
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
	msg[6], msg[7] = u8(count >> 8), u8(count)
	return msg[:]
}

// What a chain step answers with: a DNSKEY RRset of the size a rollover reaches.
@(private = "file")
chain_reply :: proc() -> []u8 {
	name := []u8{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg := make([dynamic]u8, 0, 4096)
	put_header(&msg, 4)
	append(&msg, ..name)
	put_u16(&msg, u16(Type.DNSKEY))
	put_u16(&msg, u16(Class.IN))
	for _ in 0 ..< 4 {
		append(&msg, 0xc0, 0x0c)
		put_u16(&msg, u16(Type.DNSKEY))
		put_u16(&msg, u16(Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		put_u16(&msg, 512)
		for _ in 0 ..< 512 {
			append(&msg, 0x2a)
		}
	}
	return msg[:]
}

/*
A heavy request of the ordinary kind is nowhere near the budget.

The worst shape a legitimate query reaches, and the figure the budget is sized
against: a full-length answer read the three times the answer path reads one,
and a DNSKEY reply for each of the thirty-two steps a chain walk may take. That
is 1,356,752 bytes measured, against the eight megabytes a request may have -
what the budget refuses costs that much out of a few kilobytes of wire, and what
real traffic does costs this.
*/
@(test)
test_a_heavy_but_ordinary_request_stays_well_inside_the_budget :: proc(t: ^testing.T) {
	answer := ordinary_answer()
	defer delete(answer)
	chain := chain_reply()
	defer delete(chain)

	backing := make([]u8, 64 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	a := mem.arena_allocator(&arena)

	spent := 0
	for i in 0 ..< 3 {
		_, err := decode_message(answer, a, &spent)
		testing.expectf(t, err == .None, "reading %d of an ordinary answer was refused: %v", i, err)
	}
	for i in 0 ..< 32 {
		_, err := decode_message(chain, a, &spent)
		testing.expectf(t, err == .None, "chain step %d was refused: %v", i, err)
	}
	testing.expectf(
		t,
		spent * 4 < REQUEST_DECODE_BUDGET,
		"a heavy but ordinary request spent %d of the request's %d, which leaves too little room to be a bound on abuse",
		spent,
		REQUEST_DECODE_BUDGET,
	)
}
