package dns

import "core:testing"

/*
`peek_referral` against RFC 2308 section 2.2's shapes: type 4 is a referral,
types 1 to 3 are NODATA, and nothing with an answer or another rcode is either
(issue #410).
*/
@(private = "file")
referral_wire :: proc(rcode: Rcode, answer, authority: []Record) -> []u8 {
	msg := Message {
		question  = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer    = answer,
		authority = authority,
	}
	msg.flags.qr = true
	msg.flags.rcode = u8(rcode)
	wire, _, err := encode_message(msg, context.temp_allocator)
	assert(err == .None)
	return wire
}

@(test)
test_peek_referral_reads_the_authority_section :: proc(t: ^testing.T) {
	ns := Record{name = "example.com.", type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.example.com."}}
	soa := Record {
		name  = "example.com.",
		type  = .SOA,
		class = .IN,
		ttl   = 300,
		data  = Rdata_SOA{ns = "ns1.example.com.", mbox = "h.example.com.", minimum = 60},
	}
	a := Record{name = "www.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{{1, 2, 3, 4}}}
	glue := Record{name = "ns1.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{{1, 2, 3, 4}}}

	testing.expect(t, peek_referral(referral_wire(.No_Error, nil, {ns})), "NS alone: type 4, a referral")
	testing.expect(t, peek_referral(referral_wire(.No_Error, nil, {glue, ns})), "NS after another record")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {soa, ns})), "SOA and NS: type 1 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {ns, soa})), "NS then SOA: type 1 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {soa})), "SOA alone: type 2 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, nil)), "empty authority: type 3 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, {a}, {ns})), "an answer beside NS is an answer")
	testing.expect(t, !peek_referral(referral_wire(.NX_Domain, nil, {ns})), "NXDOMAIN is not a referral")
	testing.expect(t, !peek_referral(referral_wire(.Serv_Fail, nil, {ns})), "SERVFAIL is not a referral")
	authoritative := referral_wire(.No_Error, nil, {ns})
	authoritative[2] |= 0x04
	testing.expect(t, !peek_referral(authoritative), "AA set: an authority's SOA-less NODATA, not a referral")

	// The composed rcode: BADVERS is 16, a zero low nibble under an OPT.
	opt := make_opt(1232, false, 1)
	badvers := Message {
		question   = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		authority  = []Record{ns},
		additional = []Record{opt},
	}
	badvers.flags.qr = true
	wire, _, err := encode_message(badvers, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect_value(t, peek_rcode(wire), Rcode(16))
	testing.expect(t, !peek_referral(wire), "BADVERS is not a NOERROR")

	// Truncated anywhere in the walk: not a referral, and no read past the end.
	full := referral_wire(.No_Error, nil, {ns})
	for n in 0 ..< len(full) {
		testing.expectf(t, !peek_referral(full[:n]), "cut at %d of %d read as a referral", n, len(full))
	}
	free_all(context.temp_allocator)
}
