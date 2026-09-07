package dns

import "core:testing"

/*
What `encode_message` does when the section that will not fit is the additional
one.

RFC 2181 section 9 reads TC as being about answer and authority data left out of
a reply: it is the bit that says "the records you asked for did not all fit, ask
again over TCP". Additional data is not that. A responder that could not fit a
glue address or an OPT record behind a complete answer has answered the question,
and a client told to throw the datagram away and ask again gets the same records
one round trip later.

So the encoder splits the two. An answer or authority record dropped sets
`truncated` and the TC bit, as it always did; an additional record dropped is
left out quietly. The OPT record is the everyday case - it is the last thing in
the section and eleven bytes long before any option is written into it - and the
one that reaches a client, through `server.attach_cookie` and
`server.match_client_opt`.
*/

@(private = "file")
QNAME :: "example.com."

@(private = "file")
a_record :: proc(last: u8) -> Record {
	return Record {
		name = QNAME,
		type = .A,
		class = .IN,
		ttl = 300,
		data = Rdata_A{addr = {192, 0, 2, last}},
	}
}

// Big enough that no message under test has room for it behind its answer.
@(private = "file")
big_txt :: proc() -> Record {
	text := make([]u8, 200, context.temp_allocator)
	for i in 0 ..< len(text) {
		text[i] = 'x'
	}
	strs := make([]string, 1, context.temp_allocator)
	strs[0] = string(text)
	return Record{name = QNAME, type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = strs}}
}

@(private = "file")
message_with :: proc(additional: []Record) -> Message {
	question := make([]Question, 1, context.temp_allocator)
	question[0] = Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 2, context.temp_allocator)
	answer[0] = a_record(1)
	answer[1] = a_record(2)
	authority := make([]Record, 1, context.temp_allocator)
	authority[0] = Record {
		name = QNAME,
		type = .NS,
		class = .IN,
		ttl = 300,
		data = Rdata_Name{name = "ns1.example.com."},
	}

	m := Message {
		id         = 0x1234,
		question   = question,
		answer     = answer,
		authority  = authority,
		additional = additional,
	}
	m.flags.qr = true
	m.flags.ra = true
	return m
}

@(private = "file")
opt_records :: proc(before: []Record = nil, after: []Record = nil) -> []Record {
	out := make([dynamic]Record, 0, len(before) + len(after) + 1, context.temp_allocator)
	append(&out, ..before)
	append(&out, make_opt(1232, false))
	append(&out, ..after)
	return out[:]
}

/*
The same message with one answer record and nothing behind it, which is what the
answer-section case measures its room from.
*/
@(private = "file")
one_answer :: proc() -> Message {
	m := message_with(nil)
	m.answer = m.answer[:1]
	m.authority = nil
	return m
}

// The size the message needs to hold everything in it, which is what the cases
// below then subtract from.
@(private = "file")
encoded_size :: proc(t: ^testing.T, m: Message) -> int {
	wire, truncated, err := encode_message(m, context.temp_allocator, MAX_MESSAGE)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, !truncated, "the message did not fit at MAX_MESSAGE")
	return len(wire)
}

/*
An additional record that will not fit is left out, and the answer goes out
whole with TC clear.

The OPT record behind it still fits and is still written: the section is not
abandoned because one record in it overflowed, or a client asking with EDNS
would lose the record it negotiated to the glue it never asked for.
*/
@(test)
test_an_additional_record_that_will_not_fit_leaves_tc_clear :: proc(t: ^testing.T) {
	whole := message_with(opt_records(before = []Record{big_txt()}))
	// Room for everything but the TXT record, which is the only thing that has
	// to be dropped to make this fit.
	room := encoded_size(t, message_with(opt_records()))

	wire, truncated, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, !truncated, "an additional record that would not fit reported a truncation")
	testing.expectf(t, len(wire) <= room, "the message is %d bytes, past the %d it was given", len(wire), room)

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, !got.flags.tc, "TC is set on an answer nothing was dropped from")
	testing.expect_value(t, len(got.answer), 2)
	testing.expect_value(t, len(got.authority), 1)
	// The TXT is gone and the OPT is there: one record in the section, and it
	// is the one the client negotiated.
	testing.expect_value(t, len(got.additional), 1)
	testing.expect(t, edns_present(got), "the OPT record went out with the record that overflowed")

	free_all(context.temp_allocator)
}

/*
The OPT record is itself what does not fit.

There is nothing behind it to drop, so it goes out without one - and the answer
is still complete, so TC stays clear. This is the case `server.attach_cookie`
reaches when the cookie is the twenty-eight bytes that push the answer over the
client's buffer: before this split, the client was handed a complete answer with
TC set, no OPT record and no cookie, and asked again over TCP for bytes it
already had.
*/
@(test)
test_an_opt_record_that_will_not_fit_leaves_tc_clear :: proc(t: ^testing.T) {
	whole := message_with(opt_records())
	// One byte short of the OPT record, so the answer and authority sections
	// fit and nothing else does.
	room := encoded_size(t, whole) - 1

	wire, truncated, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, !truncated, "an OPT record that would not fit reported a truncation")
	testing.expectf(t, len(wire) <= room, "the message is %d bytes, past the %d it was given", len(wire), room)

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, !got.flags.tc, "TC is set on an answer nothing was dropped from")
	testing.expect_value(t, len(got.answer), 2)
	testing.expect_value(t, len(got.authority), 1)
	testing.expect_value(t, len(got.additional), 0)

	free_all(context.temp_allocator)
}

/*
An answer record that will not fit still sets TC, which is the whole of what the
bit is for. Pinned beside the two above so a later change cannot quiet this one
too.
*/
@(test)
test_an_answer_record_that_will_not_fit_still_sets_tc :: proc(t: ^testing.T) {
	whole := message_with(opt_records())
	/*
	Room for the first answer record and eleven bytes behind it: the second
	needs sixteen, so the cut lands in the answer section, and an OPT record is
	eleven, so the re-add behind the cut fits exactly.
	*/
	room := encoded_size(t, one_answer()) + 11

	wire, truncated, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, got.flags.tc, "TC is clear on an answer that lost records")
	testing.expect(t, len(got.answer) < 2, "nothing was dropped after all")
	// The client's EDNS parameters survive the cut, as they always did.
	testing.expect(t, edns_present(got), "the OPT record was not re-added after the truncation")

	free_all(context.temp_allocator)
}

/*
The OPT record is re-added after a cut, and exactly once.

The re-add walks the additional section for an OPT record without asking whether
one was already written, so a section holding the OPT ahead of the record that
overflows would come back carrying two of them - one message, two sets of EDNS
parameters, and a reader entitled to disagree with the next about which is the
one. Reachable only in the additional section, since a cut anywhere earlier
leaves the whole section unwritten.
*/
@(test)
test_an_overflowing_additional_section_re_adds_one_opt :: proc(t: ^testing.T) {
	whole := message_with(opt_records(after = []Record{big_txt()}))
	/*
	A hundred bytes of slack behind the OPT record: enough for a second one to
	be appended where nothing stops it, and nowhere near the two hundred and
	fifteen the TXT record needs. A room measured exactly to the OPT would hide
	the fault, since the duplicate would not fit either.
	*/
	room := encoded_size(t, message_with(opt_records())) + 100

	wire, _, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expectf(t, len(wire) <= room, "the message is %d bytes, past the %d it was given", len(wire), room)

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	opts := 0
	for rec in got.additional {
		if rec.type == .OPT {
			opts += 1
		}
	}
	testing.expect_value(t, opts, 1)
	testing.expect_value(t, len(got.additional), 1)

	free_all(context.temp_allocator)
}

/*
A cut that leaves the OPT record nowhere to go takes another record with it.

The re-add is what keeps a client's EDNS parameters on a truncated answer, and
before this it only worked when the record the cut dropped happened to be larger
than the OPT record: below that, the client was handed TC with no OPT record at
all - no payload size to size its retry with, no upper bits of the rcode, and,
where `server.attach_cookie` had put one in, no cookie. So the walk back goes to
the last record that leaves room, which is a record dropped from an answer
section the client is being told to discard anyway.

Room here is the first answer record plus twenty-one bytes: the second answer
record is sixteen and fits, the authority record behind it does not, and eleven
bytes for the OPT record do not fit behind either of them. So the second answer
record goes back too.
*/
@(test)
test_a_truncation_drops_a_record_to_keep_the_opt_record :: proc(t: ^testing.T) {
	whole := message_with(opt_records())
	room := encoded_size(t, one_answer()) + 21

	wire, truncated, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")
	testing.expectf(t, len(wire) <= room, "the message is %d bytes, past the %d it was given", len(wire), room)

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, got.flags.tc, "TC is clear on an answer that lost records")
	testing.expect(t, edns_present(got), "the OPT record was dropped rather than made room for")
	// One answer record rather than the two that would have fit with the OPT
	// record left out.
	testing.expect_value(t, len(got.answer), 1)
	testing.expect_value(t, len(got.authority), 0)

	free_all(context.temp_allocator)
}
