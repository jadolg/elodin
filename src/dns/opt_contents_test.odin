package dns

import "core:mem"
import "core:testing"

/*
The two writers that make a response's OPT record the responder's own: the
option list emptied, and the version and flag bits stated.

`server.normalise_client_opt` is the caller and is where the reading of RFC 6891
section 6.1.1 is argued. What is pinned here is the mechanics, on both shapes a
message comes in - an OPT record at the end, where the bytes can be cut, and one
with records behind it, where the message has to be built again.
*/

@(private = "file")
NAME :: "www.example.com."

@(private = "file")
answer_record :: proc() -> Record {
	return Record {
		name = NAME,
		type = .A,
		class = .IN,
		ttl = 300,
		data = Rdata_A{addr = [4]u8{192, 0, 2, 1}},
	}
}

/*
An answer whose OPT record carries `options`, with `trailing` extra records
behind it in the additional section.

`trailing` is what picks the path: none of them and the OPT record is the tail
of the message, so `strip_edns_options` cuts the bytes; one or more and it has to
decode and encode again.
*/
@(private = "file")
answer_with_options :: proc(options: []EDNS_Option, trailing := 0) -> []u8 {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = NAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 1, context.temp_allocator)
	answer[0] = answer_record()

	additional := make([]Record, 1 + trailing, context.temp_allocator)
	opt := make_opt(1232, false)
	opt.data = Rdata_OPT{options = options}
	additional[0] = opt
	for i in 0 ..< trailing {
		additional[1 + i] = answer_record()
	}

	wire, _, err := encode_message(
		Message{id = 0x4242, question = questions, answer = answer, additional = additional},
		context.temp_allocator,
	)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
two_options :: proc() -> []EDNS_Option {
	options := make([]EDNS_Option, 2, context.temp_allocator)
	options[0] = EDNS_Option {
		code = u16(EDNS_Option_Code.NSID),
		data = transmute([]u8)string("upstream-7"),
	}
	options[1] = EDNS_Option {
		code = u16(EDNS_Option_Code.Ext_Error),
		data = transmute([]u8)string("\x00\x0fblocked"),
	}
	return options
}

// The record is still there and still says what it said; only the list under it
// is gone.
@(private = "file")
expect_bare_opt :: proc(t: ^testing.T, wire: []u8, label: string) {
	m, derr := decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "%s did not decode: %v", label, derr) {
		return
	}
	opt, found := find_opt(m)
	if !testing.expectf(t, found, "%s lost its OPT record", label) {
		return
	}
	rdata, is_opt := opt.data.(Rdata_OPT)
	if !testing.expectf(t, is_opt, "%s: the OPT record's RDATA is not an option list", label) {
		return
	}
	testing.expectf(t, len(rdata.options) == 0, "%s still carries %d option(s)", label, len(rdata.options))
	// The fields beside the list are untouched, so the payload size a caller
	// wrote before this ran is still readable after it.
	testing.expectf(t, edns_udp_size(m) == 1232, "%s: the advertised size came back as %d", label, edns_udp_size(m))
	testing.expectf(t, len(m.answer) == 1, "%s: the answer section holds %d records", label, len(m.answer))
	_, found_option := peek_edns_option(wire, .NSID)
	testing.expectf(t, !found_option, "%s: the NSID is still readable off the wire", label)
}

/*
The fast path: the OPT record is the last thing in the message, so its options
are the tail and the strip is a shorter copy with RDLENGTH zeroed.
*/
@(test)
test_strip_edns_options_cuts_a_trailing_option_list :: proc(t: ^testing.T) {
	wire := answer_with_options(two_options())
	testing.expect(t, wire != nil, "could not build the answer")
	// The premise: without options in it there is nothing for this to strip.
	_, present := peek_edns_option(wire, .NSID)
	testing.expect(t, present, "the fixture carries no NSID, so this case tests nothing")

	out, ok := strip_edns_options(wire, context.temp_allocator)
	testing.expect(t, ok, "strip_edns_options failed")
	testing.expect(t, len(out) < len(wire), "the strip did not shorten the message")
	expect_bare_opt(t, out, "the stripped answer")

	free_all(context.temp_allocator)
}

/*
The slow path: a record sits behind the OPT record, so the bytes cannot be cut
and the message is built again.

The record behind it has to survive that, which is the whole risk of the path -
a rebuild that dropped it would pass every assertion about the OPT record.
*/
@(test)
test_strip_edns_options_rebuilds_around_a_record_behind_the_opt :: proc(t: ^testing.T) {
	wire := answer_with_options(two_options(), trailing = 1)
	testing.expect(t, wire != nil, "could not build the answer")

	before, berr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, berr, Decode_Error.None)
	testing.expect_value(t, len(before.additional), 2)

	out, ok := strip_edns_options(wire, context.temp_allocator)
	testing.expect(t, ok, "strip_edns_options failed")
	expect_bare_opt(t, out, "the rebuilt answer")

	after, aerr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, aerr, Decode_Error.None)
	testing.expect_value(t, len(after.additional), 2)

	free_all(context.temp_allocator)
}

/*
The caller's bytes are not written.

They may be a cache entry other clients are still being served from, so an
option's absence has to be this client's answer alone - the rule `remove_opt`
holds to for the whole record.
*/
@(test)
test_strip_edns_options_leaves_the_callers_bytes_alone :: proc(t: ^testing.T) {
	wire := answer_with_options(two_options())
	testing.expect(t, wire != nil, "could not build the answer")

	original := make([]u8, len(wire), context.temp_allocator)
	copy(original, wire)

	_, ok := strip_edns_options(wire, context.temp_allocator)
	testing.expect(t, ok, "strip_edns_options failed")
	testing.expect(t, mem.compare(wire, original) == 0, "the strip wrote over the bytes it was handed")

	free_all(context.temp_allocator)
}

/*
Nothing to do is not a failure.

A message with no OPT record and one whose record carries no options are both
returned as they stand and `ok`, so a caller can ask for this without looking
first and without paying for a copy in the common case.
*/
@(test)
test_strip_edns_options_is_a_no_op_with_nothing_to_strip :: proc(t: ^testing.T) {
	empty := answer_with_options(nil)
	testing.expect(t, empty != nil, "could not build the answer")
	out, ok := strip_edns_options(empty, context.temp_allocator)
	testing.expect(t, ok, "an empty option list was reported as a failure")
	testing.expect(t, raw_data(out) == raw_data(empty), "an empty option list was copied")

	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = NAME,
		type  = .A,
		class = .IN,
	}
	bare, _, err := encode_message(Message{id = 1, question = questions}, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)
	out, ok = strip_edns_options(bare, context.temp_allocator)
	testing.expect(t, ok, "a message with no OPT record was reported as a failure")
	testing.expect(t, raw_data(out) == raw_data(bare), "a message with no OPT record was copied")

	free_all(context.temp_allocator)
}

/*
The version and the flags are written; the extended rcode beside them is not.

All three share the OPT record's TTL (RFC 6891 section 6.1.3), so this is the
arithmetic `edns_version` is pinned against read from the other side: a write one
byte off would land on the rcode - turning a BADVERS into a NOERROR over an empty
answer - or on the flags.
*/
@(test)
test_set_edns_version_and_flags_writes_only_its_own_two_fields :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = NAME,
		type  = .A,
		class = .IN,
	}
	// An upstream's record: version 1, DO set, a reserved flag bit set, and the
	// top half of a BADVERS in the extended rcode.
	opt := make_opt(1232, true, u8(u16(Rcode.Bad_Vers) >> 4))
	opt.ttl |= u32(1) << 16
	opt.ttl |= 0x0000_0040
	additional := make([]Record, 1, context.temp_allocator)
	additional[0] = opt

	wire, _, err := encode_message(
		Message{id = 9, question = questions, additional = additional},
		context.temp_allocator,
	)
	testing.expect_value(t, err, Encode_Error.None)

	testing.expect(t, set_edns_version_and_flags(wire, 0, false), "set_edns_version_and_flags found no OPT record")

	m, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, edns_version(m), u8(0))
	testing.expect(t, !edns_do(m), "DO survived being written clear")
	// The reserved bit went with it, and the extended rcode did not.
	opt_back, found := find_opt(m)
	testing.expect(t, found, "the OPT record is gone")
	testing.expectf(t, opt_back.ttl & 0x0000_7fff == 0, "a reserved flag bit survived: ttl %x", opt_back.ttl)
	testing.expect_value(t, peek_rcode(wire), Rcode.Bad_Vers)

	// And the other way, which is the copy a client that asked with DO gets.
	testing.expect(t, set_edns_version_and_flags(wire, 0, true), "set_edns_version_and_flags found no OPT record")
	back, berr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, berr, Decode_Error.None)
	testing.expect(t, edns_do(back), "DO was not written back")
	testing.expect_value(t, peek_rcode(wire), Rcode.Bad_Vers)

	// A message with no OPT record has no field to write, which is reported and
	// is not a failure to pass on.
	bare, _, berr2 := encode_message(Message{id = 1, question = questions}, context.temp_allocator)
	testing.expect_value(t, berr2, Encode_Error.None)
	testing.expect(t, !set_edns_version_and_flags(bare, 0, false), "a message with no OPT record reported a write")

	free_all(context.temp_allocator)
}

/*
A reply carrying two OPT records comes back carrying one.

RFC 6891 section 6.1.1 allows exactly one, to the point of requiring FORMERR for
a query that carries more, and nothing in this server applies that reading to a
reply. Emptying both and leaving both would be the half-fix: every other writer
in `edns.odin` walks with `find_opt_span` and stops at the first record, so the
second would go to the client still stating the upstream's own EDNS version and
DO bit - which is the field this whole normalisation exists to make the
responder's own. So the extra is dropped, and what a caller writes afterwards
covers the whole of what is left.
*/
@(test)
test_strip_edns_options_drops_a_second_opt_record :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = NAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 1, context.temp_allocator)
	answer[0] = answer_record()

	// Both carry options, and the second states version 1 with DO set: the
	// fields a writer reaching only the first would leave behind.
	first := make_opt(1232, false)
	first.data = Rdata_OPT{options = two_options()}
	second := make_opt(512, true)
	second.ttl |= u32(1) << 16
	second.data = Rdata_OPT{options = two_options()}

	additional := make([]Record, 2, context.temp_allocator)
	additional[0] = first
	additional[1] = second

	wire, _, err := encode_message(
		Message{id = 7, question = questions, answer = answer, additional = additional},
		context.temp_allocator,
	)
	testing.expect_value(t, err, Encode_Error.None)

	// The premise: two records went in, or this case is about nothing.
	before, berr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, berr, Decode_Error.None)
	opts_in := 0
	for rec in before.additional {
		if rec.type == .OPT {
			opts_in += 1
		}
	}
	testing.expect_value(t, opts_in, 2)

	out, ok := strip_edns_options(wire, context.temp_allocator)
	testing.expect(t, ok, "strip_edns_options failed")
	expect_bare_opt(t, out, "the answer with two OPT records")

	after, aerr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, aerr, Decode_Error.None)
	opts_out := 0
	for rec in after.additional {
		if rec.type == .OPT {
			opts_out += 1
		}
	}
	testing.expectf(t, opts_out == 1, "%d OPT records came back, not 1", opts_out)

	// And the one left is the one a writer reaches, so writing over it covers
	// the whole of what the client will read.
	testing.expect(t, set_edns_version_and_flags(out, 0, false), "no OPT record to write")
	settled, serr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, Decode_Error.None)
	for rec in settled.additional {
		if rec.type != .OPT {
			continue
		}
		testing.expectf(t, u8(rec.ttl >> 16) == 0, "an OPT record still states version %d", u8(rec.ttl >> 16))
		testing.expectf(t, rec.ttl & 0x0000_8000 == 0, "an OPT record still has DO set")
	}

	free_all(context.temp_allocator)
}

/*
And the same, with the *first* OPT record empty.

The shape that slipped past the first version of this: "there are no options
here" is a fact about the record `find_opt_span` stopped at, not about the
message, so an early return on it handed a second record - options, version, DO
bit and all - straight to the client. The early return is behind the `span.last`
check now, which is what makes the two readings the same one.
*/
@(test)
test_strip_edns_options_drops_a_second_opt_behind_an_empty_first :: proc(t: ^testing.T) {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = NAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 1, context.temp_allocator)
	answer[0] = answer_record()

	// Nothing in the first, everything in the second.
	first := make_opt(1232, false)
	second := make_opt(512, true)
	second.ttl |= u32(1) << 16
	second.data = Rdata_OPT{options = two_options()}

	additional := make([]Record, 2, context.temp_allocator)
	additional[0] = first
	additional[1] = second

	wire, _, err := encode_message(
		Message{id = 11, question = questions, answer = answer, additional = additional},
		context.temp_allocator,
	)
	testing.expect_value(t, err, Encode_Error.None)
	// The premise: the option is in the message, in the record that is not the
	// one a walk stops at.
	testing.expect(t, holds_an_option(wire), "the fixture carries no option, so this case tests nothing")

	out, ok := strip_edns_options(wire, context.temp_allocator)
	testing.expect(t, ok, "strip_edns_options failed")
	testing.expect(t, !holds_an_option(out), "an option survived in the second OPT record")

	after, aerr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, aerr, Decode_Error.None)
	opts_out := 0
	for rec in after.additional {
		if rec.type == .OPT {
			opts_out += 1
		}
	}
	testing.expectf(t, opts_out == 1, "%d OPT records came back, not 1", opts_out)
	testing.expect_value(t, len(after.answer), 1)

	free_all(context.temp_allocator)
}

// Whether any OPT record anywhere in the message carries an option, which is the
// question `peek_edns_option` cannot answer: it walks to the first record and
// stops, which is the whole subject of the case above.
@(private = "file")
holds_an_option :: proc(wire: []u8) -> bool {
	m, err := decode_message(wire, context.temp_allocator)
	if err != .None {
		return false
	}
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		if rdata, is_opt := rec.data.(Rdata_OPT); is_opt && len(rdata.options) > 0 {
			return true
		}
	}
	return false
}
