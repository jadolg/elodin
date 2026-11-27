package dns

import "core:testing"

/*
`age_ttls` takes an HTTP `Age` off a DoH reply's TTLs (RFC 8484 section 5.1).
*/

// `example.`'s SOA at a TTL of an hour and a MINIMUM of five minutes.
@(private = "file")
age_soa :: proc() -> Record {
	return Record {
		name = "example.",
		type = .SOA,
		class = .IN,
		ttl = 3600,
		data = Rdata_SOA{ns = "ns.example.", mbox = "h.example.", serial = 1, refresh = 2, retry = 3, expire = 4, minimum = 300},
	}
}

// Every TTL loses the age, floored at zero; an authority SOA's TTL is first held
// to its MINIMUM, so the negative TTL loses it too while the signed RDATA stays
// as it came. The OPT record's flags do not. No allocator is involved, so none
// can run dry.
@(test)
test_age_ttls_takes_the_age_off_every_ttl :: proc(t: ^testing.T) {
	m := Message {
		question   = []Question{{name = "age.example.", type = .A, class = .IN}},
		answer     = []Record{{name = "age.example.", type = .A, class = .IN, ttl = 600, data = Rdata_A{addr = {10, 9, 9, 9}}}},
		authority  = []Record {
			{name = "example.", type = .NS, class = .IN, ttl = 100, data = Rdata_Name{name = "ns.example."}},
			age_soa(),
		},
		additional = []Record{make_opt(1232, true)},
	}
	m.flags.qr = true
	// A denial, so its SOA is held to MINIMUM.
	m.flags.rcode = u8(Rcode.NX_Domain)
	wire, _, err := encode_message(m, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the reply does not encode: %v", err) {
		return
	}
	age_ttls(wire, 250)
	got, derr := decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None && len(got.answer) == 1 && len(got.authority) == 2, "the aged reply does not decode: %v", derr) {
		return
	}
	testing.expect_value(t, got.answer[0].ttl, u32(350))
	testing.expect_value(t, got.authority[0].ttl, u32(0))
	// Brought down to its MINIMUM, then aged: the negative TTL loses the age.
	testing.expect_value(t, got.authority[1].ttl, u32(50))
	soa, is_soa := got.authority[1].data.(Rdata_SOA)
	// The RDATA is under the SOA's RRSIG, and is left as it came.
	if testing.expect(t, is_soa, "the SOA did not decode as one") {
		testing.expect_value(t, soa.minimum, u32(300))
	}
	negative, has_soa := negative_ttl(got)
	testing.expect(t, has_soa && negative == 50, "the negative TTL is not the SOA's less the age")
	testing.expect(t, edns_do(got), "the OPT record's DO bit was taken as a TTL")
	free_all(context.temp_allocator)
}

// A SOA in the answer section, the data asked for, keeps its own TTL less the
// age, MINIMUM or not; and a top-bit TTL is read through `sane_ttl` first.
@(test)
test_age_ttls_holds_only_an_authority_soa_to_its_minimum :: proc(t: ^testing.T) {
	m := Message {
		question = []Question{{name = "example.", type = .SOA, class = .IN}},
		answer   = []Record {
			age_soa(),
			{name = "example.", type = .TXT, class = .IN, ttl = 0x8000_0064, data = Rdata_TXT{strings = []string{"x"}}},
		},
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the reply does not encode: %v", err) {
		return
	}
	age_ttls(wire, 250)
	got, derr := decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None && len(got.answer) == 2, "the aged reply does not decode: %v", derr) {
		return
	}
	testing.expect_value(t, got.answer[0].ttl, u32(3350))
	testing.expect_value(t, got.answer[1].ttl, TTL_MAX - 250)
	free_all(context.temp_allocator)
}

// An answer with data keeps its authority SOA's own TTL less the age: only a
// denial's SOA is held to its MINIMUM.
@(test)
test_age_ttls_holds_a_soa_to_minimum_only_in_a_denial :: proc(t: ^testing.T) {
	m := Message {
		question  = []Question{{name = "age.example.", type = .A, class = .IN}},
		answer    = []Record{{name = "age.example.", type = .A, class = .IN, ttl = 600, data = Rdata_A{addr = {10, 9, 9, 9}}}},
		authority = []Record {
			age_soa(),
		},
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the reply does not encode: %v", err) {
		return
	}
	age_ttls(wire, 250)
	got, derr := decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None && len(got.answer) == 1 && len(got.authority) == 1, "the aged reply does not decode: %v", derr) {
		return
	}
	testing.expect_value(t, got.answer[0].ttl, u32(350))
	testing.expect_value(t, got.authority[0].ttl, u32(3350))
	free_all(context.temp_allocator)
}
