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
	return a_answer(QNAME, 300, last)
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

// Encodes `whole` into `room` and reads it back, failing `t` on an encode or
// decode error or a message longer than `room`.
@(private = "file")
encode_within :: proc(t: ^testing.T, whole: Message, room: int, loc := #caller_location) -> (got: Message, truncated: bool) {
	wire, trunc, err := encode_message(whole, context.temp_allocator, room)
	testing.expect_value(t, err, Encode_Error.None, loc = loc)
	testing.expectf(t, len(wire) <= room, "the message is %d bytes, past the %d it was given", len(wire), room, loc = loc)
	decoded, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None, loc = loc)
	return decoded, trunc
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

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, !truncated, "an additional record that would not fit reported a truncation")
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
client's buffer: setting TC there would hand the client a complete answer with
no OPT record and no cookie, and send it back over TCP for bytes it already
has.
*/
@(test)
test_an_opt_record_that_will_not_fit_leaves_tc_clear :: proc(t: ^testing.T) {
	whole := message_with(opt_records())
	// One byte short of the OPT record, so the answer and authority sections
	// fit and nothing else does.
	room := encoded_size(t, whole) - 1

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, !truncated, "an OPT record that would not fit reported a truncation")
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

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")
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

	got, _ := encode_within(t, whole, room)
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
it cannot rest on the record the cut dropped happening to be larger than the OPT
record: below that, the client would be handed TC with no OPT record at all - no
payload size to size its retry with, no upper bits of the rcode, and, where
`server.attach_cookie` had put one in, no cookie. So the walk back goes to
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

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")
	testing.expect(t, got.flags.tc, "TC is clear on an answer that lost records")
	testing.expect(t, edns_present(got), "the OPT record was dropped rather than made room for")
	// One answer record rather than the two that would have fit with the OPT
	// record left out.
	testing.expect_value(t, len(got.answer), 1)
	testing.expect_value(t, len(got.authority), 0)

	free_all(context.temp_allocator)
}

/*
Three shapes the walk back must not read as its own, all of them reachable from
a reply this decoder will hand back unchanged and none of them from a message
this server builds.

An OPT record whose owner name is not the root. RFC 6891 section 6.1.2 makes it
the root, the decoder reads the RDATA and never looks at the name, and
`w_record` writes whatever is there in full - so the eleven bytes the walk back
reserves would be short by the length of the name. Records would go back for a
record that then did not fit either, which is worse than the truncation it was
trying to improve, so no room is kept for one at all.
*/
@(test)
test_a_non_root_opt_owner_keeps_no_room :: proc(t: ^testing.T) {
	named := make_opt(1232, false)
	named.name = QNAME
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = named
	whole := message_with(additional)

	// The room the root-owner case sheds a record at; see the case above.
	room := encoded_size(t, one_answer()) + 21

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")
	// Both, where the root-owner case keeps one: the record that would not fit
	// took nothing with it.
	testing.expect_value(t, len(got.answer), 2)
	testing.expect_value(t, len(got.additional), 0)

	free_all(context.temp_allocator)
}

/*
An OPT record in the answer section, which is not the message's EDNS record:
`find_opt` reads the additional section alone, and a client can put a record of
type OPT in the question it sends for the asking.

Taken for the real one, it would mark the message's OPT as already written -
so the walk back would shed answer records to keep room the re-add then
declined to use, and the client would get neither the records nor the record.
*/
@(test)
test_an_opt_in_the_answer_section_is_not_the_messages_own :: proc(t: ^testing.T) {
	answer := make([]Record, 3, context.temp_allocator)
	answer[0] = make_opt(1232, false)
	answer[1] = a_record(1)
	answer[2] = a_record(2)
	whole := message_with(opt_records())
	whole.answer = answer

	// Room for the OPT-shaped answer record, the first address behind it and
	// eleven bytes for the message's own OPT record: the second address needs
	// sixteen and is what the cut lands on.
	head := whole
	head.answer = answer[:2]
	head.authority = nil
	head.additional = nil
	room := encoded_size(t, head) + 11

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, truncated, "an answer record was dropped without a truncation being reported")
	testing.expect(t, got.flags.tc, "TC is clear on an answer that lost records")
	testing.expect_value(t, len(got.answer), 2)
	// The message's own record, from the section `find_opt` reads.
	testing.expect(t, edns_present(got), "the additional section's OPT record was taken for written")

	free_all(context.temp_allocator)
}

/*
An rcode of 16 or more lives half in the header and half in the OPT record's TTL
(RFC 6891 section 6.1.3), so a message that loses the record to the size ceiling
goes out as a different rcode: BADVERS read as NOERROR over an empty answer
section, which is a NODATA, and BADCOOKIE read as YXRRSET.

Dropping the record quietly is what the rest of this file is about, and this is
the one message it must not be quiet about. The client is sent to TCP instead,
where the record fits and the rcode it was answered with arrives.
*/
@(test)
test_an_extended_rcode_is_not_dropped_quietly :: proc(t: ^testing.T) {
	// BADVERS: rcode 16, so the header's four bits are zero and the extended
	// byte in the TTL is one.
	badvers := make_opt(1232, false)
	badvers.ttl = 1 << 24
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = badvers

	question := make([]Question, 1, context.temp_allocator)
	question[0] = Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	m := Message {
		id         = 0x1234,
		question   = question,
		additional = additional,
	}
	m.flags.qr = true
	testing.expect_value(t, rcode_of(m), Rcode.Bad_Vers)

	// One byte short of the record the top bits live in.
	room := encoded_size(t, m) - 1

	got, truncated := encode_within(t, m, room)
	testing.expect(t, truncated, "a refusal that lost its rcode reported no truncation")
	testing.expect(t, got.flags.tc, "the client was not told to ask again for the rcode it lost")

	// And an OPT record carrying no extended rcode is still dropped quietly,
	// which is the case either side of this one.
	plain := m
	plain_opt := make([]Record, 1, context.temp_allocator)
	plain_opt[0] = make_opt(1232, false)
	plain.additional = plain_opt
	_, plain_truncated, plain_err := encode_message(plain, context.temp_allocator, room)
	testing.expect_value(t, plain_err, Encode_Error.None)
	testing.expect(t, !plain_truncated, "an OPT record with nothing in its TTL was reported as a truncation")

	free_all(context.temp_allocator)
}

/*
The additional section is filled as far as it goes.

Nothing on the wire says a record was left out of it, which is the whole of what
the split at the top of this file is - so abandoning the section at the first
record that will not fit would drop the records behind it in silence, for a
client that had room for every one of them. The glue behind the big record here
is sixteen bytes and the OPT record eleven, against a ceiling with room for
both.
*/
@(test)
test_the_additional_section_is_filled_past_a_record_that_will_not_fit :: proc(t: ^testing.T) {
	glue := Record {
		name  = "ns1.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = Rdata_A{addr = {192, 0, 2, 53}},
	}
	whole := message_with(opt_records(before = []Record{big_txt(), glue}))
	/*
	Room for everything but the TXT record, and thirty-two bytes over: the drop
	takes the compression map with it, so the glue's owner name goes out in full
	where the measurement below had it as a two-byte pointer. Nowhere near the
	two hundred and fifteen the TXT record needs.
	*/
	room := encoded_size(t, message_with(opt_records(before = []Record{glue}))) + 32

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, !truncated, "an additional record that would not fit reported a truncation")
	testing.expect(t, !got.flags.tc, "TC is set on an answer nothing was dropped from")
	testing.expect_value(t, len(got.answer), 2)
	// The glue and the OPT record, both of which were behind the record that
	// overflowed and both of which fit.
	testing.expect_value(t, len(got.additional), 2)
	testing.expect(t, edns_present(got), "the OPT record went out with the record that overflowed")

	free_all(context.temp_allocator)
}

/*
A message whose rcode is 16 or more spends a record on its OPT record even where
the answer came out whole.

The top eight bits live in that record's TTL and nowhere else, so leaving it out
states a different rcode - and the client cannot tell. Dropping an answer record
sets TC, which sends it to TCP for the records it lost, and it reads the rcode it
was actually answered with while it is there. Reading the wrong one, it would
come back over TCP for the same thing and be no better off.

Room here is one byte short of the whole message, so the answer and authority
sections fit and only the OPT record does not.
*/
@(test)
test_an_extended_rcode_is_kept_at_the_cost_of_a_record :: proc(t: ^testing.T) {
	// BADVERS: rcode 16, four zero bits in the header and a one in the TTL.
	badvers := make_opt(1232, false)
	badvers.ttl = 1 << 24
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = badvers
	whole := message_with(additional)
	testing.expect_value(t, rcode_of(whole), Rcode.Bad_Vers)

	room := encoded_size(t, whole) - 1

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, truncated, "records were dropped without a truncation being reported")
	testing.expect(t, got.flags.tc, "records went missing without the client being told")
	testing.expect(t, edns_present(got), "the record the rcode lives in was dropped")
	// The rcode it was answered with, which is the point of the exercise.
	testing.expect_value(t, rcode_of(got), Rcode.Bad_Vers)
	// Paid for out of the authority section, which is the last thing the walk
	// back reaches; the answer is untouched.
	testing.expect_value(t, len(got.answer), 2)
	testing.expect_value(t, len(got.authority), 0)

	free_all(context.temp_allocator)
}

/*
The room the OPT record needs is kept against the records ahead of it too.

It is normally the last record in the section, so the glue in front of it spends
the ceiling first - and where that leaves eleven bytes short, a client that
asked with EDNS would get an answer with no OPT record in it at all: no payload
size, no cookie, no extended error, and no cut for the walk back to work from,
since the answer comes out whole. The glue goes instead, which is a hint the
client can ask for again.

Reachable from `server.strip_dnssec_records`, which appends a minted OPT record
behind the additional records that survived the strip and encodes the lot at the
client's ceiling, and from `fit_response` re-encoding a forwarded referral for a
client that advertised less than the entry was stored for.
*/
@(test)
test_the_records_ahead_of_the_opt_do_not_spend_its_room :: proc(t: ^testing.T) {
	glue := Record {
		name  = "ns1.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = Rdata_A{addr = {192, 0, 2, 53}},
	}
	whole := message_with(opt_records(before = []Record{glue}))
	// One byte short of the two of them, so exactly one can be sent.
	room := encoded_size(t, whole) - 1

	got, truncated := encode_within(t, whole, room)
	testing.expect(t, !truncated, "an additional record that would not fit reported a truncation")
	testing.expect(t, !got.flags.tc, "TC is set on an answer nothing was dropped from")
	testing.expect_value(t, len(got.answer), 2)
	testing.expect_value(t, len(got.authority), 1)
	// The OPT record, and the glue is what paid for it.
	testing.expect_value(t, len(got.additional), 1)
	testing.expect(t, edns_present(got), "the glue was sent and the OPT record was not")

	free_all(context.temp_allocator)
}

/*
Glue a referral cannot be read without is the additional section's one
exception, and RFC 9471 section 3.3 is where it comes from.

A name server named inside the zone being delegated has an address that is
learnable from this reply and nowhere else, so a referral that could not carry
it says so. Otherwise the resolver reading it cannot tell a glue set with one
address in it from a delegation that only has one, and follows it an address
short - which is the failure the RFC's rule exists to stop, and one this file's
general reading of TC would otherwise reintroduce.
*/
@(private = "file")
referral :: proc(glue: []Record) -> Message {
	question := make([]Question, 1, context.temp_allocator)
	question[0] = Question {
		name  = "www.sub.example.com.",
		type  = .A,
		class = .IN,
	}
	authority := make([]Record, 1, context.temp_allocator)
	authority[0] = Record {
		name = "sub.example.com.",
		type = .NS,
		class = .IN,
		ttl = 300,
		// In-domain: the name server lives inside the zone being delegated.
		data = Rdata_Name{name = "ns1.sub.example.com."},
	}

	additional := make([dynamic]Record, 0, len(glue) + 1, context.temp_allocator)
	append(&additional, ..glue)
	append(&additional, make_opt(1232, false))

	m := Message {
		id         = 0x1234,
		question   = question,
		authority  = authority,
		additional = additional[:],
	}
	m.flags.qr = true
	return m
}

@(private = "file")
address :: proc(name: string, last: u8) -> Record {
	return Record{name = name, type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, last}}}
}

@(test)
test_a_referral_that_drops_in_domain_glue_is_truncated :: proc(t: ^testing.T) {
	two := referral([]Record{address("ns1.sub.example.com.", 1), address("ns1.sub.example.com.", 2)})
	// One byte short of the second address, so the glue set goes out partial or
	// not at all.
	room := encoded_size(t, two) - 1

	got, truncated := encode_within(t, two, room)
	testing.expect(t, truncated, "a referral short of its own glue reported no truncation")
	testing.expect(t, got.flags.tc, "the resolver was handed a partial glue set with nothing to say so")

	free_all(context.temp_allocator)
}

/*
And the exception is only the exception. Glue for a name server named outside
the zone being delegated is an address the resolver can go and look up, so
leaving it out is the ordinary quiet drop - as is any other additional record.
*/
@(test)
test_a_referral_that_drops_out_of_domain_glue_is_not :: proc(t: ^testing.T) {
	two := referral([]Record{address("ns1.elsewhere.test.", 1), address("ns1.elsewhere.test.", 2)})
	room := encoded_size(t, two) - 1

	got, truncated := encode_within(t, two, room)
	testing.expect(t, !truncated, "a referral was truncated for glue the resolver can resolve itself")
	testing.expect(t, !got.flags.tc, "TC over a referral whose own glue is complete")
	testing.expect_value(t, len(got.authority), 1)
	// The OPT record still keeps its room against the glue ahead of it.
	testing.expect(t, edns_present(got), "the OPT record was spent on glue")

	free_all(context.temp_allocator)
}

/*
A delegation from the root has every name server inside the zone being
delegated, so all of its glue is in-domain (RFC 9471 section 3.3) and leaving
any of it out is a truncation like the one above.
*/
@(test)
test_a_root_referral_that_drops_glue_is_truncated :: proc(t: ^testing.T) {
	two := referral([]Record{address("a.root-servers.net.", 1), address("a.root-servers.net.", 2)})
	two.authority[0].name = "."
	two.authority[0].data = Rdata_Name{name = "a.root-servers.net."}
	room := encoded_size(t, two) - 1

	got, truncated := encode_within(t, two, room)
	testing.expect(t, truncated, "a root referral short of its glue reported no truncation")
	testing.expect(t, got.flags.tc, "the resolver was handed a partial root glue set with nothing to say so")

	free_all(context.temp_allocator)
}

/*
An additional RRset that does not fit whole is left out whole, with TC clear
(RFC 2181 section 9: "the entire RRSet that will not fit in the response should
be omitted, and the reply sent as is, with the TC bit clear"). Not the records
of it that happened to fit ahead of the one that overflowed: a client or a cache
reading two of a name's three addresses has no way to know there was a third.
An RRset is the run of records with one owner, type and class.
*/
@(test)
test_an_additional_rrset_that_will_not_fit_is_left_out_whole :: proc(t: ^testing.T) {
	mail := proc(last: u8) -> Record {
		return address("mail.example.com.", last)
	}
	other := address("other.example.com.", 9)
	// An RRSIG at the TXT records' owner covering `covered`: the type covered
	// is its RDATA's first two bytes, and the rest is padding to a size that
	// fits where a long TXT record was taken back from.
	rrsig_over := proc(covered: Type) -> Record {
		rdata := make([]u8, 20, context.temp_allocator)
		rdata[0], rdata[1] = u8(u16(covered) >> 8), u8(covered)
		return Record{name = QNAME, type = .RRSIG, class = .IN, ttl = 300, data = Rdata_Raw{data = rdata}}
	}
	// One TXT RRset: a short record, one past the room, and a short one again,
	// which would fit where the long one was taken back to.
	txt := proc(text: string) -> Record {
		strs := make([]string, 1, context.temp_allocator)
		strs[0] = text
		return Record{name = QNAME, type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = strs}}
	}
	cases := []struct {
		name:      string,
		// The additional section, and the one whose size is the room.
		whole:     []Record,
		fits:      []Record,
		// What goes out, by owner and last address byte.
		kept:      []Record,
		with_opt:  bool,
	} {
		{name = "two of one RRset, room for one", whole = {mail(1), mail(2)}, fits = {mail(1)}, kept = {}},
		{
			name = "an RRset that fit, then one that straddles the room",
			whole = {other, mail(1), mail(2)},
			fits = {other, mail(1)},
			kept = {other},
		},
		{
			name = "an RRset that will not fit, then a smaller one that does",
			whole = {mail(1), mail(2), mail(3), other},
			fits = {mail(1), other},
			kept = {other},
		},
		{
			name = "the rest of an RRset that will not fit, short enough to",
			whole = {txt("a"), big_txt(), txt("b"), other},
			fits = {txt("a"), txt("b"), other},
			kept = {other},
		},
		{
			name = "a later record of an RRset left out, not next to it",
			whole = {txt("a"), big_txt(), other, txt("b")},
			fits = {txt("a"), other, txt("b")},
			kept = {other},
		},
		{
			name = "a signature over an RRset left out",
			whole = {txt("a"), big_txt(), rrsig_over(.TXT), other},
			fits = {txt("a"), rrsig_over(.TXT), other},
			kept = {other},
		},
		{
			name = "another type at the same owner is another RRset",
			whole = {address(QNAME, 7), big_txt()},
			fits = {address(QNAME, 7)},
			kept = {address(QNAME, 7)},
		},
		{
			name = "an RRset that will not fit ahead of the OPT record",
			whole = opt_records(before = []Record{mail(1), mail(2)}),
			fits = opt_records(before = []Record{mail(1)}),
			kept = {},
			with_opt = true,
		},
	}
	for c in cases {
		room := encoded_size(t, message_with(c.fits))
		got, truncated := encode_within(t, message_with(c.whole), room)
		testing.expectf(t, !truncated && !got.flags.tc, "%s: TC set for additional data", c.name)
		testing.expectf(t, len(got.answer) == 2, "%s: %d answer records", c.name, len(got.answer))
		addresses := 0
		for rec in got.additional {
			if rec.type == .A {
				addresses += 1
			}
		}
		testing.expectf(t, addresses == len(c.kept), "%s: %d address records went out, want %d: %v", c.name, addresses, len(c.kept), got.additional)
		for rec in got.additional {
			testing.expectf(t, rec.type != .TXT, "%s: part of the TXT RRset went out: %v", c.name, got.additional)
			testing.expectf(t, rec.type != .RRSIG, "%s: a signature went out without its RRset: %v", c.name, got.additional)
		}
		for want in c.kept {
			found := false
			for rec in got.additional {
				got_a, got_ok := rec.data.(Rdata_A)
				want_a, want_ok := want.data.(Rdata_A)
				found ||= rec.type == .A && name_equal_fold(rec.name, want.name) && got_ok && want_ok && got_a.addr == want_a.addr
			}
			testing.expectf(t, found, "%s: %s %v was left out", c.name, want.name, want.data)
		}
		testing.expectf(t, edns_present(got) == c.with_opt, "%s: the OPT record is %v, want %v", c.name, edns_present(got), c.with_opt)
	}
	free_all(context.temp_allocator)
}

/*
The RRsets left out are held up to `DROPPED_RRSETS`, as every record behind a
drop is compared against each; one more, and the rest of the additional section
but its OPT record is left out with them, which is the reply's to do without.
Each of these RRsets is one address too big for the room behind the one before.
*/
@(test)
test_past_the_rrsets_it_tracks_the_rest_of_the_section_goes :: proc(t: ^testing.T) {
	OWNERS :: [?]string {
		"r0.example.com.",
		"r1.example.com.",
		"r2.example.com.",
		"r3.example.com.",
		"r4.example.com.",
		"r5.example.com.",
		"r6.example.com.",
		"r7.example.com.",
		"r8.example.com.",
	}
	#assert(len(OWNERS) == DROPPED_RRSETS + 1)
	owners := OWNERS
	text := make([]u8, 200, context.temp_allocator)
	for j in 0 ..< len(text) {
		text[j] = 'x'
	}
	strs := make([]string, 1, context.temp_allocator)
	strs[0] = string(text)
	whole := make([dynamic]Record, 0, len(owners) + 1, context.temp_allocator)
	for owner in owners {
		append(&whole, Record{name = owner, type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = strs}})
	}
	small := address("last.example.com.", 1)
	append(&whole, small)
	room := encoded_size(t, message_with([]Record{small})) + 32

	got, truncated := encode_within(t, message_with(whole[:]), room)
	testing.expect(t, !truncated && !got.flags.tc, "TC set for additional data")
	// One RRset past the bound left out: the address behind them, which would
	// have fitted, goes with them.
	testing.expectf(t, len(got.additional) == 0, "past %d RRsets left out, %v still went out", DROPPED_RRSETS, got.additional)

	// The premise: one RRset fewer, and the address goes out.
	got, truncated = encode_within(t, message_with(whole[1:]), room)
	testing.expectf(t, !truncated && len(got.additional) == 1, "at %d RRsets left out, the address did not go out: %v", DROPPED_RRSETS, got.additional)
	free_all(context.temp_allocator)
}

/*
Past `DROPPED_RRSETS` the rest of the additional section is left out, but glue
a referral cannot be read without still truncates (RFC 9471 section 3.3): a
referral whose in-domain glue sits behind nine RRsets too big to fit goes out
with TC set, not as a delegation the client cannot follow.
*/
@(test)
test_glue_past_the_tracked_rrsets_still_truncates :: proc(t: ^testing.T) {
	text := make([]u8, 200, context.temp_allocator)
	for j in 0 ..< len(text) {
		text[j] = 'x'
	}
	strs := make([]string, 1, context.temp_allocator)
	strs[0] = string(text)
	OWNERS :: [?]string {
		"r0.elsewhere.test.",
		"r1.elsewhere.test.",
		"r2.elsewhere.test.",
		"r3.elsewhere.test.",
		"r4.elsewhere.test.",
		"r5.elsewhere.test.",
		"r6.elsewhere.test.",
		"r7.elsewhere.test.",
		"r8.elsewhere.test.",
	}
	#assert(len(OWNERS) == DROPPED_RRSETS + 1)
	owners := OWNERS
	glue := make([dynamic]Record, 0, len(owners) + 1, context.temp_allocator)
	for owner in owners {
		append(&glue, Record{name = owner, type = .TXT, class = .IN, ttl = 300, data = Rdata_TXT{strings = strs}})
	}
	in_domain := address("ns1.sub.example.com.", 53)
	append(&glue, in_domain)
	room := encoded_size(t, referral([]Record{in_domain})) + 32

	got, truncated := encode_within(t, referral(glue[:]), room)
	testing.expect(t, truncated && got.flags.tc, "in-domain glue past the tracked RRsets went missing with TC clear")
	free_all(context.temp_allocator)
}

/*
Signatures over two types at one owner are two RRsets: one that will not fit
takes none of the other's with it.
*/
@(test)
test_a_signature_over_another_type_is_another_rrset :: proc(t: ^testing.T) {
	sig := proc(covered: Type, size: int) -> Record {
		rdata := make([]u8, size, context.temp_allocator)
		rdata[0], rdata[1] = u8(u16(covered) >> 8), u8(covered)
		return Record{name = QNAME, type = .RRSIG, class = .IN, ttl = 300, data = Rdata_Raw{data = rdata}}
	}
	small := sig(.A, 20)
	whole := []Record{address(QNAME, 7), small, sig(.AAAA, 300)}
	room := encoded_size(t, message_with([]Record{address(QNAME, 7), small}))
	got, truncated := encode_within(t, message_with(whole), room)
	testing.expect(t, !truncated && !got.flags.tc, "TC set for additional data")
	signed := 0
	for rec in got.additional {
		if rec.type == .RRSIG {
			signed += 1
		}
	}
	testing.expectf(t, signed == 1, "%d signatures went out, want the one over A: %v", signed, got.additional)
	free_all(context.temp_allocator)
}
