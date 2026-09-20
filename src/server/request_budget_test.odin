package server

import "core:mem"
import "core:testing"
import "elodin:dns"

/*
Issue #354: a request reads far more than one message, and every budget the
decoder had was per reading.

`decode_answer` reads the upstream's reply for the cache and again for the
answer section alone, `fit_response` reads it a third time when it passes the
client's limit, and the validator reads a reply of its own for every step of the
chain - about thirty-five readings, all into the one arena the request is served
from. Each got a fresh `dns.NAME_BUDGET` and nothing at all bounded what it
allocated besides names, so five kilobytes of wire reached 23 MB of names and a
full-length TXT record reached 37 MB of `string` headers, in a single in-flight
request; against a pool of sixteen to a hundred and twenty-eight workers, a few
dozen such queries are the box.

The counter belongs to the request now. `handle_query` owns it and hands it to
everything that reads into its arena, which is what the readings below stand in
for. What each shape costs is `dns/request_budget_test.odin`; what is measured
here is that the request's own procedures charge the one counter.
*/

// What one request can hold: two readings in `decode_answer`, one in
// `fit_response`, and `dnssec.MAX_LOOKUPS_PER_QUERY` chain lookups.
@(private = "file")
READINGS :: 35

/*
A reply that spends a whole reading's budget out of a few kilobytes of wire.

MX records whose owner and exchange are both two-byte pointers at one 255-octet
name of unprintable bytes - issue #298's shape, where sixteen wire bytes buy two
expansions of about `dns.MAX_NAME_PRESENTATION`. Short on purpose: a 64 KB reply
spends the same budget and buries it under the record arrays every reading also
builds, and it is the names this is about.
*/
@(private = "file")
budget_bomb :: proc(answer_records := 0) -> []u8 {
	msg := make([dynamic]u8, 0, 8192)
	append(&msg, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
	for l in ([]int{63, 63, 63, 61}) {
		append(&msg, u8(l))
		for _ in 0 ..< l {
			append(&msg, 0x01)
		}
	}
	append(&msg, 0)
	append(&msg, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))

	// What one of these names costs once escaped, read rather than written
	// down, so the fixture follows `dns.NAME_BUDGET` wherever the escaping
	// goes. Two a record, and one record past the budget.
	owner, _, _ := dns.decode_name(msg[dns.HEADER_SIZE:], 0)
	defer delete(owner)

	count := 0
	for count * 2 * len(owner) <= dns.NAME_BUDGET {
		append(&msg, 0xc0, 0x0c)
		append(&msg, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))
		append(&msg, 0, 0, 0x0e, 0x10)
		append(&msg, 0, 4, 0, 10)
		append(&msg, 0xc0, 0x0c)
		count += 1
	}
	// Which section they land in. The default puts the lot in the answer, so
	// both of `decode_answer`'s readings pay for them; a caller asking for
	// fewer leaves the rest in the additional section, where the answer-only
	// reading does not go.
	an := count if answer_records == 0 else answer_records
	msg[6], msg[7] = u8(an >> 8), u8(an)
	ar := count - an
	msg[10], msg[11] = u8(ar >> 8), u8(ar)
	return msg[:]
}

@(private = "file")
BOMB_QUESTION := []dns.Question{{name = "x.", type = .MX, class = .IN}}

/*
What the readings of one request may come to.

The names are `dns.REQUEST_DECODE_BUDGET` and nothing else. Everything else a
reading builds - the record array, the RDATA copies - is outside that budget and
stays a fixed multiple of the message read, which twenty-four times over covers
with room to spare.
*/
@(private = "file")
request_ceiling :: proc(msg_len: int) -> int {
	return dns.REQUEST_DECODE_BUDGET + READINGS * 24 * msg_len
}

/*
Every reading a request makes charges the one counter the request owns.

The readings here are the request's real ones - `decode_answer`'s pair, then
`fit_response` - run until the issue's thirty-five are spent. Without the shared
counter this is 23 MB of arena for a reply of five kilobytes.
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

	spent: int
	// Each call reads the whole message, fails, and reads the answer section
	// again: two of the thirty-five, and `fit_response` is the last one.
	for _ in 0 ..< (READINGS - 1) / 2 {
		decode_answer(msg, true, &spent, a)
	}
	fit_response(msg, 512, dns.Message{question = BOMB_QUESTION}, &spent, a)

	testing.expectf(
		t,
		arena.offset <= request_ceiling(len(msg)),
		"%d readings of a %d-byte reply cost %d bytes of arena, over the %d one request may hold",
		READINGS,
		len(msg),
		arena.offset,
		request_ceiling(len(msg)),
	)
	/*
	The overshoot is one reading's and not one per reading. A name is charged
	after it is decoded, because that is when what it cost is known, so the
	reading that crosses the budget pays for the name that told it - and for
	the other name of the same RDATA layout, which are read one after another
	before anything checks again. Every reading after that one is refused
	before it reads anything.
	*/
	testing.expectf(
		t,
		spent <= dns.REQUEST_DECODE_BUDGET + 2 * dns.MAX_NAME_PRESENTATION,
		"the request took %d bytes, past the %d it may",
		spent,
		dns.REQUEST_DECODE_BUDGET,
	)
}

/*
The shorter reading still gets a budget of its own to work with.

This is the failure mode a shared counter has, and the reason the request's
figure is several times the reading's rather than equal to it: `decode_answer`
falls back to the answer section alone precisely when the whole message would
not parse, so a counter the first reading can empty refuses the second one too -
and that is refusing an answer this server had no opinion about, which is the
thing the fallback exists to stop.

The reply here spends a reading's whole budget in its additional section and
holds one cheap record in its answer.
*/
@(test)
test_an_expensive_first_reading_does_not_take_the_shorter_one_with_it :: proc(t: ^testing.T) {
	msg := budget_bomb(answer_records = 1)
	defer delete(msg)

	backing := make([]u8, 8 << 20)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)

	spent: int
	out := decode_answer(msg, true, &spent, mem.arena_allocator(&arena))
	testing.expect_value(t, out.full_err, dns.Decode_Error.Name_Budget)
	testing.expect(t, out.partial, "the answer section should have read on its own")
	testing.expect_value(t, len(out.msg.answer), 1)
}
