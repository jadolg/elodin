package dns

import "core:mem"
import "core:testing"

/*
Adding and taking away a whole OPT record, which is the pair a response's OPT
presence is decided with.

RFC 6891 section 6.1.1 forbids caching or forwarding an OPT record, so whether
one goes back to a client is a fact about that client's own query. A server
passing answers through as the bytes they arrived as therefore has to be able to
put one on an answer that has none and take one off an answer that has one -
`server.match_client_opt` is the caller, and both directions are reachable there
from one cache entry.

The taking-away half has two paths for the reason `remove_edns_option` has two:
the record can be cut out of the bytes when nothing follows it, and has to be
rebuilt around when something does.
*/

@(private = "file")
QNAME :: "example.com."

@(private = "file")
answer_with :: proc(additional: []Record) -> []u8 {
	questions := make([]Question, 1, context.temp_allocator)
	questions[0] = Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]Record, 1, context.temp_allocator)
	answer[0] = Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = Rdata_A{addr = {192, 0, 2, 1}},
	}
	m := Message {
		id         = 1,
		question   = questions,
		answer     = answer,
		additional = additional,
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
one_opt :: proc(options: []EDNS_Option = nil) -> []Record {
	additional := make([]Record, 1, context.temp_allocator)
	opt := make_opt(1232, false)
	if options != nil {
		opt.data = Rdata_OPT{options = options}
	}
	additional[0] = opt
	return additional
}

// Whether the answer the client asked for came through whatever was done to the
// message around it.
@(private = "file")
expect_the_answer_survived :: proc(t: ^testing.T, m: Message) {
	if !testing.expectf(t, len(m.answer) == 1, "the answer section holds %d records, not 1", len(m.answer)) {
		return
	}
	addr, is_a := m.answer[0].data.(Rdata_A)
	if !testing.expect(t, is_a, "the answer's RDATA did not survive") {
		return
	}
	testing.expect(t, addr.addr == [4]u8{192, 0, 2, 1}, "the address came back changed")
	testing.expect_value(t, len(m.question), 1)
	testing.expect_value(t, m.id, u16(1))
}

/*
Nothing follows the OPT record in an answer this server would send, so the
ordinary case is the cheap one: the record is the tail of the message and
dropping it is a shorter copy and a smaller ARCOUNT.
*/
@(test)
test_remove_opt_cuts_a_trailing_record :: proc(t: ^testing.T) {
	wire := answer_with(one_opt())
	testing.expect(t, wire != nil, "could not build the answer")

	out, ok := remove_opt(wire, context.temp_allocator)
	testing.expect(t, ok, "remove_opt failed")
	testing.expectf(t, len(out) < len(wire), "the message did not get shorter: %d bytes", len(out))

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, !edns_present(m), "the OPT record is still there")
	testing.expect_value(t, len(m.additional), 0)
	// And the count in the header came down with it, or the message would not
	// have decoded at all.
	testing.expect_value(t, int(u16(out[10]) << 8 | u16(out[11])), 0)
	expect_the_answer_survived(t, m)

	// The bytes handed in are untouched: they may be a cache entry other
	// clients are still being served from.
	before, berr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, berr, Decode_Error.None)
	testing.expect(t, edns_present(before), "remove_opt wrote through its input")

	free_all(context.temp_allocator)
}

/*
A record after the OPT is the case the bytes cannot simply be cut: the names
behind the record being dropped move, and a compression pointer aimed at one of
them would then be aimed at the wrong offset. So it is rebuilt.

The `A` record here has an owner name the encoder compresses against the
question, which is exactly the pointer that has to still resolve afterwards.
*/
@(test)
test_remove_opt_rebuilds_around_a_record_after_it :: proc(t: ^testing.T) {
	additional := make([]Record, 2, context.temp_allocator)
	additional[0] = make_opt(1232, false)
	additional[1] = Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = Rdata_A{addr = {192, 0, 2, 9}},
	}
	wire := answer_with(additional)
	testing.expect(t, wire != nil, "could not build the answer")

	out, ok := remove_opt(wire, context.temp_allocator)
	testing.expect(t, ok, "remove_opt failed")

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, !edns_present(m), "the OPT record is still there")
	if testing.expect_value(t, len(m.additional), 1) {
		testing.expect_value(t, m.additional[0].type, Type.A)
		testing.expect(t, name_equal_fold(m.additional[0].name, QNAME), "the record's owner name did not survive")
		addr, is_a := m.additional[0].data.(Rdata_A)
		testing.expect(t, is_a, "the record's RDATA did not survive")
		testing.expect(t, addr.addr == [4]u8{192, 0, 2, 9}, "the record's address came back changed")
	}
	expect_the_answer_survived(t, m)

	free_all(context.temp_allocator)
}

// A message with no OPT record is already what a caller asking for this wants,
// so it comes straight back and no copy is made of it.
@(test)
test_remove_opt_with_no_record_is_a_no_op :: proc(t: ^testing.T) {
	wire := answer_with(nil)
	testing.expect(t, wire != nil, "could not build the answer")

	out, ok := remove_opt(wire, context.temp_allocator)
	testing.expect(t, ok, "remove_opt failed on a message with no OPT record")
	// The caller's own bytes back, not a copy of them: the contract is that a
	// caller can ask for this without looking first and pay nothing when there
	// is nothing to do, and equal bytes out of a fresh allocation would satisfy
	// every assertion here while costing that on every answer.
	testing.expect(t, raw_data(out) == raw_data(wire), "a copy was made of a message with no OPT record")
	testing.expect(t, mem.compare(out, wire) == 0, "the message came back changed")

	free_all(context.temp_allocator)
}

/*
The minting half, for a client that asked with EDNS and an answer that has no
OPT record - an upstream that dropped it, or a cache entry stored for a client
that never sent one.

The record carries the payload size and nothing else: no option, and DO clear,
because an answer that arrived without an OPT record arrived without signatures.
*/
@(test)
test_ensure_opt_mints_a_bare_record :: proc(t: ^testing.T) {
	wire := answer_with(nil)
	testing.expect(t, wire != nil, "could not build the answer")

	out, ok := ensure_opt(wire, 1232, context.temp_allocator)
	testing.expect(t, ok, "ensure_opt failed")

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, edns_present(m), "no OPT record was added")
	testing.expect_value(t, len(m.additional), 1)
	testing.expect_value(t, int(edns_udp_size(m)), 1232)
	testing.expect(t, !edns_do(m), "DO was set on an OPT record we invented")
	testing.expect_value(t, int(edns_version(m)), 0)
	testing.expect_value(t, int(peek_rcode(out)), int(Rcode.No_Error))

	opt, found := find_opt(m)
	if testing.expect(t, found, "the minted record is not readable") {
		rdata, is_opt := opt.data.(Rdata_OPT)
		testing.expect(t, is_opt, "the minted record's RDATA is not an option list")
		testing.expect_value(t, len(rdata.options), 0)
	}
	expect_the_answer_survived(t, m)

	free_all(context.temp_allocator)
}

/*
An answer that already has an OPT record keeps the one it has, whatever it says.

`set_edns_udp_size` and the option writers are what set the fields in a record
that is already there; a second one minted here would leave two for a reader to
disagree over, and the size passed in would silently win over an option list
somebody else had written.
*/
@(test)
test_ensure_opt_leaves_an_existing_record_alone :: proc(t: ^testing.T) {
	options := make([]EDNS_Option, 1, context.temp_allocator)
	options[0] = EDNS_Option {
		code = u16(EDNS_Option_Code.NSID),
		data = []u8{'x'},
	}
	wire := answer_with(one_opt(options))
	testing.expect(t, wire != nil, "could not build the answer")

	out, ok := ensure_opt(wire, 4096, context.temp_allocator)
	testing.expect(t, ok, "ensure_opt failed")
	// As `remove_opt` on a message with none: the answer comes straight back.
	testing.expect(t, raw_data(out) == raw_data(wire), "a copy was made of a message that already had one")
	testing.expect(t, mem.compare(out, wire) == 0, "the message came back changed")

	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, len(m.additional), 1)
	// The record that was already there wins; the size passed in is only for one
	// that has to be minted.
	testing.expect_value(t, int(edns_udp_size(m)), 1232)
	nsid, has_nsid := find_edns_option(m, .NSID)
	testing.expect(t, has_nsid, "the NSID option was lost")
	testing.expect(t, mem.compare(nsid, []u8{'x'}) == 0, "the NSID option was corrupted")

	free_all(context.temp_allocator)
}

/*
The two are inverses on the shape they are used on.

Both directions are reached from one cache entry - a client that asked with EDNS
and a client that asked without - so an answer that goes round the pair has to
come back as the answer it was, not merely as one that still decodes.
*/
@(test)
test_ensure_opt_and_remove_opt_round_trip :: proc(t: ^testing.T) {
	wire := answer_with(nil)
	testing.expect(t, wire != nil, "could not build the answer")

	minted, added := ensure_opt(wire, 1232, context.temp_allocator)
	testing.expect(t, added, "ensure_opt failed")
	stripped, removed := remove_opt(minted, context.temp_allocator)
	testing.expect(t, removed, "remove_opt failed")

	testing.expect(t, mem.compare(stripped, wire) == 0, "the answer did not survive the round trip")

	free_all(context.temp_allocator)
}

// Issues #353 and #301: the five OPT shapes `find_opt_span` cannot account for,
// and the one it can.
@(test)
test_peek_opt_unreadable_names_each_shape :: proc(t: ^testing.T) {
	a := Record{name = "www.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 1}}}
	opt := make_opt(4096, false)
	owned := opt
	owned.name = "example."
	with_option := opt
	with_option.data = Rdata_OPT {
		options = []EDNS_Option{{code = 65001, data = {1, 2, 3, 4}}},
	}

	Case :: struct {
		label:      string,
		answer:     []Record,
		authority:  []Record,
		additional: []Record,
		cut:        bool,
		expect:     bool,
	}
	cases := []Case {
		{label = "no opt", answer = {a}},
		{label = "one opt with an option", answer = {a}, additional = {with_option}},
		{label = "opt in the answer", answer = {a, opt}, expect = true},
		{label = "opt in authority", answer = {a}, authority = {opt}, expect = true},
		{label = "two opt records", answer = {a}, additional = {opt, opt}, expect = true},
		{label = "an option past its rdata", answer = {a}, additional = {with_option}, cut = true, expect = true},
		{label = "an owner other than root", answer = {a}, additional = {owned}, expect = true},
	}
	for c in cases {
		m := Message {
			id         = 0x3530,
			question   = []Question{{name = "www.example.com.", type = .A, class = .IN}},
			answer     = c.answer,
			authority  = c.authority,
			additional = c.additional,
		}
		m.flags.qr = true
		wire, _, err := encode_with_every_opt(m, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: encode: %v", c.label, err) {
			continue
		}
		if c.cut {
			// The option's length, four bytes of data back from the end.
			wire[len(wire) - 5] = 9
		}
		testing.expectf(t, peek_opt_unreadable(wire) == c.expect, "%s: want %v", c.label, c.expect)
	}
	// A message that cannot be walked is the decoder's to refuse.
	testing.expect(t, !peek_opt_unreadable([]u8{1, 2}), "a short message was reported")

	/*
	The owner is judged as the name it decodes to, not by its first byte: a
	pointer to the question name's terminating zero is the root (RFC 1035 section
	4.1.4), and a pointer to the question name is not, nor one to itself, which
	`name_is_root` would follow forever. The bare OPT is the last eleven bytes,
	and the question's root is at 12 + 16.
	*/
	m := Message {
		id         = 0x3530,
		question   = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		additional = {opt},
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if testing.expectf(t, err == .None, "encode: %v", err) {
		for target, i in ([3]int{28, 12, len(wire) - 11}) {
			ptr := make([dynamic]u8, 0, len(wire) + 1, context.temp_allocator)
			append(&ptr, ..wire[:len(wire) - 11])
			append(&ptr, 0xc0, u8(target))
			append(&ptr, ..wire[len(wire) - 10:])
			testing.expectf(t, peek_opt_unreadable(ptr[:]) == (i != 0), "owner pointer to offset %d", target)
		}
	}
	free_all(context.temp_allocator)
}

/*
An OPT owner reached through a chain of pointers is root up to the jumps
`decode_name` follows, and not one past them, so a reply this check passes is
one the decoder reads the same owner from.
*/
@(test)
test_peek_opt_unreadable_caps_the_owner_s_pointer_chain :: proc(t: ^testing.T) {
	for jumps in ([2]int{MAX_NAME_WIRE / 2, MAX_NAME_WIRE / 2 + 1}) {
		// No question; one answer of a private-use type whose RDATA is a zero
		// octet and then a chain of pointers, each to the one before, ending at
		// the zero.
		rdlen := 1 + 2 * (jumps - 1)
		msg := make([dynamic]u8, context.temp_allocator)
		append(&msg, 0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 1)
		append(&msg, 0, 0xff, 0, 0, 1, 0, 0, 0, 0, u8(rdlen >> 8), u8(rdlen))
		zero := len(msg)
		append(&msg, 0)
		prev := zero
		for _ in 0 ..< jumps - 1 {
			here := len(msg)
			append(&msg, 0xc0 | u8(prev >> 8), u8(prev))
			prev = here
		}
		// The OPT record, owned by a pointer to the last link: `jumps` in all.
		append(&msg, 0xc0 | u8(prev >> 8), u8(prev), 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)

		_, derr := decode_message(msg[:], context.temp_allocator)
		decodes := derr == .None
		testing.expectf(t, decodes == (jumps == MAX_NAME_WIRE / 2), "%d jumps: decode_message said %v", jumps, derr)
		testing.expectf(t, peek_opt_unreadable(msg[:]) == !decodes, "%d jumps: peek_opt_unreadable disagrees with the decoder", jumps)
	}
	free_all(context.temp_allocator)
}
