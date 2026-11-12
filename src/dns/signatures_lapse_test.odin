package dns

import "core:testing"

// `signatures_lapse` reads the wire, so these build the message with the
// encoder and hand it the bytes (#165).

@(private = "file")
sl_rrsig :: proc(expiration: u32, rdlength := 24) -> Record {
	d := make([]u8, rdlength, context.temp_allocator)
	if rdlength >= 12 {
		write_ttl_at(d, 8, expiration)
	}
	return {name = "example.com.", type = .RRSIG, class = .IN, ttl = 300, data = Rdata_Raw{data = d}}
}

@(private = "file")
sl_wire :: proc(answer, additional: []Record) -> []u8 {
	m := Message {
		id         = 1,
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		answer     = answer,
		additional = additional,
	}
	m.flags.qr = true
	return test_wire(m)
}

@(test)
test_signatures_lapse_reads_every_rrsig :: proc(t: ^testing.T) {
	now := u32(1_800_000_000)
	a := Record{name = "example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {1, 2, 3, 4}}}

	left, signed := signatures_lapse(sl_wire([]Record{a}, nil), now)
	testing.expect(t, !signed, "a message with no RRSIG reads as signed")

	left, signed = signatures_lapse(sl_wire([]Record{a, sl_rrsig(now + 500)}, []Record{sl_rrsig(now + 90)}), now)
	testing.expect(t, signed, "the RRSIGs were not seen")
	testing.expect_value(t, left, u32(90))

	// Lapsed, or too short to say when it expires: nothing to keep it for.
	left, signed = signatures_lapse(sl_wire([]Record{a, sl_rrsig(now - 1)}, nil), now)
	testing.expect(t, signed && left == 0, "a lapsed RRSIG left time")
	left, signed = signatures_lapse(sl_wire([]Record{a, sl_rrsig(0, 11)}, nil), now)
	testing.expect(t, signed && left == 0, "an RRSIG too short for its expiration left time")

	// Serial arithmetic across the 2106 wrap: an expiration just past it is
	// still ahead of a `now` just before it.
	left, signed = signatures_lapse(sl_wire([]Record{a, sl_rrsig(50)}, nil), max(u32) - 49)
	testing.expect_value(t, left, u32(100))

	// A header claiming records the bytes do not hold: what was read stands.
	wire := sl_wire([]Record{a, sl_rrsig(now + 60)}, nil)
	wire[7] = 9
	left, signed = signatures_lapse(wire, now)
	testing.expect(t, signed && left == 60, "a short message lost what had been read")
	free_all(context.temp_allocator)
}
