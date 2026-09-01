package dns

import "core:strings"
import "core:testing"

/*
EDNS(0) padding: what `pad_query` and `pad_response` promise the transports that
call them.

The property under test is one number - the padded message is a whole number of
blocks long - held across the shapes that make the length hard to predict: a
message whose OPT record is not the last thing in it and so has to go back
through the encoder, one that already carries padding from somewhere else, and
one carrying no OPT record at all. A padded message that lands anywhere other
than a boundary still states its own size, so "roughly padded" is the same
failure as unpadded and each case checks the modulus rather than a delta.
*/

@(private = "file")
padded_query :: proc(name: string, options: []EDNS_Option, trailer := false) -> []u8 {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = name,
		type  = .A,
		class = .IN,
	}

	opt := make_opt(1232, false)
	if options != nil {
		opt.data = Rdata_OPT{options = options}
	}
	/*
	`trailer` puts a record behind the OPT one, which is the shape that costs
	more than an option header to pad: `find_opt_span` refuses to splice into an
	OPT record that is not last, so the message is decoded and encoded again and
	the encoder is free to compress the names differently than this one did.
	*/
	count := 2 if trailer else 1
	additional := make([]Record, count, context.temp_allocator)
	additional[0] = opt
	if trailer {
		additional[1] = Record {
			name  = name,
			type  = .A,
			class = .IN,
			ttl   = 60,
			data  = Rdata_A{addr = {192, 0, 2, 1}},
		}
	}

	m := Message {
		id         = 0x2f2f,
		question   = questions,
		additional = additional,
	}
	m.flags.rd = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// A name of `labels` labels, each eight characters, so the caller can walk a
// query across a block boundary a byte at a time.
@(private = "file")
long_name :: proc(labels: int, tail: int) -> string {
	b := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< labels {
		strings.write_string(&b, "abcdefgh.")
	}
	for _ in 0 ..< tail {
		strings.write_byte(&b, 'z')
	}
	if tail > 0 {
		strings.write_byte(&b, '.')
	}
	return strings.to_string(b)
}

@(private = "file")
padding_of :: proc(wire: []u8) -> (data: []u8, found: bool) {
	m, err := decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return find_edns_option(m, .Padding)
}

@(private = "file")
all_zero :: proc(data: []u8) -> bool {
	for b in data {
		if b != 0 {
			return false
		}
	}
	return true
}

@(test)
test_a_padded_query_lands_on_a_block_boundary :: proc(t: ^testing.T) {
	/*
	Across a spread of natural lengths, because the interesting ones are the
	boundaries: a query one byte short of a block, one byte over, and one that
	already measures a whole number of blocks all take different routes through
	the arithmetic.
	*/
	for tail in 0 ..< 24 {
		wire := padded_query(long_name(3, tail), nil)
		if !testing.expect(t, wire != nil, "could not build the query") {
			return
		}

		out, ok := pad_query(wire, PAD_QUERY_BLOCK, MAX_MESSAGE, context.temp_allocator)
		if !testing.expectf(t, ok, "a %d-byte query was not padded", len(wire)) {
			return
		}
		testing.expectf(
			t,
			len(out) % PAD_QUERY_BLOCK == 0,
			"a %d-byte query padded to %d, which is %d past a block",
			len(wire),
			len(out),
			len(out) % PAD_QUERY_BLOCK,
		)
		testing.expectf(t, len(out) >= len(wire), "padding made the query shorter: %d -> %d", len(wire), len(out))

		data, found := padding_of(out)
		testing.expect(t, found, "the padded query carries no padding option")
		testing.expect(t, all_zero(data), "the padding is not zeroes")

		// The question still has to survive all of this.
		q, qok := peek_question(out, context.temp_allocator)
		testing.expect(t, qok, "the padded query has no readable question")
		testing.expect(t, name_equal_fold(q.name, long_name(3, tail)), "the padded query asks something else")

		free_all(context.temp_allocator)
	}
}

@(test)
test_padding_survives_an_opt_record_that_is_not_last :: proc(t: ^testing.T) {
	/*
	The rebuild path. Adding the option costs four bytes plus whatever the
	encoder decides to do with the names, so a caller that predicted the length
	instead of measuring it would land off the boundary here and nowhere else.
	*/
	for tail in 0 ..< 8 {
		wire := padded_query(long_name(2, tail), nil, trailer = true)
		if !testing.expect(t, wire != nil, "could not build the query") {
			return
		}

		out, ok := pad_query(wire, PAD_QUERY_BLOCK, MAX_MESSAGE, context.temp_allocator)
		if !testing.expectf(t, ok, "a %d-byte query was not padded", len(wire)) {
			return
		}
		testing.expectf(
			t,
			len(out) % PAD_QUERY_BLOCK == 0,
			"a rebuilt %d-byte query padded to %d, %d past a block",
			len(wire),
			len(out),
			len(out) % PAD_QUERY_BLOCK,
		)

		_, found := padding_of(out)
		testing.expect(t, found, "the rebuilt query carries no padding option")

		free_all(context.temp_allocator)
	}
}

@(test)
test_padding_replaces_padding_that_was_already_there :: proc(t: ^testing.T) {
	/*
	An upstream's own padded reply passing back through here is the case: the
	block it was padded to was a statement about that hop, and leaving it in
	place while adding more would make the message longer than the boundary the
	next hop wants.
	*/
	existing := make([]u8, 300, context.temp_allocator)
	options := make([]EDNS_Option, 2, context.temp_allocator)
	options[0] = EDNS_Option {
		code = u16(EDNS_Option_Code.Padding),
		data = existing,
	}
	options[1] = EDNS_Option {
		code = u16(EDNS_Option_Code.NSID),
		data = []u8{'x'},
	}
	wire := padded_query("example.com.", options)
	if !testing.expect(t, wire != nil, "could not build the query") {
		return
	}

	out, ok := pad_response(wire, PAD_RESPONSE_BLOCK, MAX_MESSAGE, 1232, context.temp_allocator)
	if !testing.expect(t, ok, "an already-padded message was not repadded") {
		return
	}
	testing.expectf(
		t,
		len(out) % PAD_RESPONSE_BLOCK == 0,
		"repadding landed on %d, %d past a block",
		len(out),
		len(out) % PAD_RESPONSE_BLOCK,
	)
	// One block, not two: the 300 bytes that were there are gone rather than
	// added to.
	testing.expect_value(t, len(out), PAD_RESPONSE_BLOCK)

	// The neighbouring option is not this file's to remove.
	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	_, has_nsid := find_edns_option(m, .NSID)
	testing.expect(t, has_nsid, "repadding dropped the NSID option next to it")

	free_all(context.temp_allocator)
}

@(test)
test_a_query_with_no_opt_record_is_left_alone :: proc(t: ^testing.T) {
	/*
	There is nowhere to put the option, and minting an OPT record would put a
	client into an EDNS negotiation it never asked for - so the query goes out
	as it is and the caller is told it is unpadded.
	*/
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	m := Message {
		id       = 0x0101,
		question = questions,
	}
	wire, _, err := encode_message(m, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	_, ok := pad_query(wire, PAD_QUERY_BLOCK, MAX_MESSAGE, context.temp_allocator)
	testing.expect(t, !ok, "a query with no OPT record reported itself padded")

	free_all(context.temp_allocator)
}

@(test)
test_a_response_that_lost_its_opt_record_still_gets_padded :: proc(t: ^testing.T) {
	// An upstream that does not do EDNS answers without an OPT record. The
	// client asked with one - that is what made this response one to pad - so a
	// record is minted to carry the option.
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = "example.com.",
		type  = .A,
		class = .IN,
	}
	m := Message {
		id       = 0x0202,
		question = questions,
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	out, ok := pad_response(wire, PAD_RESPONSE_BLOCK, MAX_MESSAGE, 1232, context.temp_allocator)
	if !testing.expect(t, ok, "a response with no OPT record was not padded") {
		return
	}
	testing.expect_value(t, len(out) % PAD_RESPONSE_BLOCK, 0)

	decoded, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, edns_udp_size(decoded), u16(1232))
	_, found := find_edns_option(decoded, .Padding)
	testing.expect(t, found, "the minted OPT record carries no padding")

	free_all(context.temp_allocator)
}

@(test)
test_padding_that_does_not_fit_is_not_applied :: proc(t: ^testing.T) {
	/*
	Padding partway to the boundary is not padding: the length would still name
	the message. A limit that cannot hold the whole block leaves the message
	unpadded instead, and the caller sends what it had.
	*/
	wire := padded_query("example.com.", nil)
	if !testing.expect(t, wire != nil, "could not build the query") {
		return
	}

	_, ok := pad_query(wire, PAD_QUERY_BLOCK, PAD_QUERY_BLOCK - 1, context.temp_allocator)
	testing.expect(t, !ok, "padding was applied past the limit it was given")

	// The same message pads when the block does fit.
	out, fits := pad_query(wire, PAD_QUERY_BLOCK, PAD_QUERY_BLOCK, context.temp_allocator)
	testing.expect(t, fits, "the limit turned away padding that fits inside it")
	testing.expect_value(t, len(out), PAD_QUERY_BLOCK)

	free_all(context.temp_allocator)
}

@(test)
test_a_block_this_file_does_not_implement_is_refused :: proc(t: ^testing.T) {
	wire := padded_query("example.com.", nil)
	if !testing.expect(t, wire != nil, "could not build the query") {
		return
	}

	for block in ([]int{0, 1, -128, PAD_BLOCK_MAX + 1}) {
		_, ok := pad_query(wire, block, MAX_MESSAGE, context.temp_allocator)
		testing.expectf(t, !ok, "a block size of %d was accepted", block)
	}

	free_all(context.temp_allocator)
}
