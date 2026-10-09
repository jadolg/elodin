package server

import "core:testing"
import "elodin:dns"

/*
`Cache-Control: max-age` for a denial is the SOA's figure, and nothing without
one.

RFC 8484 section 5.1 bounds a response with no answer records by the SOA's
MINIMUM, which the smallest TTL in the message does not: the SOA record's own
TTL is usually the larger. NODATA after a CNAME is a denial as well (RFC 2308
section 2.2, issue #418), and with no SOA an HTTP cache must not hold it for the
CNAME's TTL.
*/
@(private = "file")
max_age_of :: proc(rcode: dns.Rcode, cname_ttl: u32, target_a, soa: bool) -> u32 {
	answer: [dynamic]dns.Record
	answer.allocator = context.temp_allocator
	if cname_ttl > 0 {
		append(&answer, dns.Record{name = "www.example.com.", type = .CNAME, class = .IN, ttl = cname_ttl, data = dns.Rdata_Name{"cdn.example.net."}})
	}
	if target_a {
		append(&answer, dns.Record{name = "cdn.example.net.", type = .A, class = .IN, ttl = 600, data = dns.Rdata_A{addr = {203, 0, 113, 7}}})
	}
	authority: [dynamic]dns.Record
	authority.allocator = context.temp_allocator
	if soa {
		append(
			&authority,
			dns.Record {
				name = "example.net.",
				type = .SOA,
				class = .IN,
				ttl = 3600,
				data = dns.Rdata_SOA {
					ns = "ns.example.net.",
					mbox = "hostmaster.example.net.",
					serial = 1,
					refresh = 7200,
					retry = 3600,
					expire = 1209600,
					minimum = 300,
				},
			},
		)
	}
	m := dns.Message {
		question  = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer    = answer[:],
		authority = authority[:],
	}
	m.flags.qr = true
	m.flags.rcode = u8(rcode)
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("failed to encode the test response")
	}
	return doh_max_age(wire)
}

@(test)
test_doh_max_age_for_a_denial_is_the_soa_figure :: proc(t: ^testing.T) {
	// A plain NODATA and NXDOMAIN: the MINIMUM, not the SOA record's TTL.
	testing.expect_value(t, max_age_of(.No_Error, 0, false, true), u32(300))
	testing.expect_value(t, max_age_of(.NX_Domain, 0, false, true), u32(300))
	// NODATA after a CNAME: the SOA figure, or the CNAME where it is shorter.
	testing.expect_value(t, max_age_of(.No_Error, 86400, false, true), u32(300))
	testing.expect_value(t, max_age_of(.No_Error, 60, false, true), u32(60))
	// And none at all without a SOA.
	testing.expect_value(t, max_age_of(.No_Error, 86400, false, false), u32(0))
	// An answer that reaches the type gets its smallest TTL.
	testing.expect_value(t, max_age_of(.No_Error, 86400, true, false), u32(600))
	free_all(context.temp_allocator)
}

// The reading is charged to the request: one that has spent its budget gets no
// freshness rather than a decode on top of the bound.
@(test)
test_doh_max_age_is_charged_to_the_request :: proc(t: ^testing.T) {
	m := dns.Message {
		question = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer = []dns.Record{{name = "www.example.com.", type = .A, class = .IN, ttl = 600, data = dns.Rdata_A{addr = {203, 0, 113, 7}}}},
	}
	m.flags.qr = true
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	spent := 0
	testing.expect_value(t, doh_max_age(wire, context.temp_allocator, &spent), u32(600))
	testing.expect(t, spent > 0, "the reading was not charged")
	spent = dns.REQUEST_DECODE_BUDGET + 1
	testing.expect_value(t, doh_max_age(wire, context.temp_allocator, &spent), u32(0))
	free_all(context.temp_allocator)
}
