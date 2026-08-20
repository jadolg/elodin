package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
What the Secure verdict actually covers.

`validate_answer` walks the RRsets in the ANSWER section and nothing else. The
verdict it reaches is then written onto the whole message as the AD bit, and the
message goes to the client with its AUTHORITY and ADDITIONAL sections exactly as
they arrived.

RFC 4035 section 3.2.3 puts the boundary somewhere else: AD may be set only when
every RRset in the Answer *and Authority* sections has been authenticated. So
anything able to add records to a response - a malicious authoritative server
for a zone it owns, or anyone on the path to a plain UDP upstream who leaves the
signed answer alone - gets its own unsigned records stamped as authenticated.

The answer itself is genuine in both tests below, so the verdict is `Secure` and
stays that way: what is checked here is that the records nobody signed are no
longer part of the message that verdict is written onto, and that the ones a
client cannot do without - the denial, and the SOA it is remembered by - still
are.
*/

@(private = "file")
ad_fixture :: proc(key: string) -> Fixture {
	for f in FIXTURES {
		if f.key == key {
			return f
		}
	}
	return {}
}

@(private = "file")
ad_unhex :: proc(text: string, allocator := context.temp_allocator) -> []u8 {
	out, _ := decode_hex(text, allocator)
	return out
}

@(private = "file")
ad_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return ad_unhex(f.wire, allocator), true
		}
	}
	return nil, false
}

// A delegation to a nameserver of the attacker's choosing. Unsigned, because
// nothing at a zone cut is signed - which is why it can never be checked and
// has to be dropped instead.
@(private = "file")
forged_ns :: proc(zone: string) -> dns.Record {
	return dns.Record {
		name = zone,
		type = .NS,
		class = .IN,
		ttl = 86400,
		data = dns.Rdata_Name{name = "ns.attacker.example."},
	}
}

@(private = "file")
holds :: proc(records: []dns.Record, name: string, type: dns.Type) -> bool {
	for rec in records {
		if rec.type == type && dns.name_equal_fold(rec.name, name) {
			return true
		}
	}
	return false
}

@(test)
test_unsigned_authority_records_do_not_reach_the_client :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	// A real, correctly signed answer for www.example.com.
	msg, derr := dns.decode_message(ad_unhex(ad_fixture("example_a").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// Records nobody signed, in the two sections a client also reads: a
	// delegation pointing at the attacker's nameserver, and its address.
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = forged_ns("example.com.")
	msg.authority = authority

	additional := make([dynamic]dns.Record, 0, len(msg.additional) + 1, context.temp_allocator)
	for rec in msg.additional {
		append(&additional, rec)
	}
	append(
		&additional,
		dns.Record {
			name = "ns.attacker.example.",
			type = .A,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_A{addr = {203, 0, 113, 66}},
		},
	)
	msg.additional = additional[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	// The answer is genuine, so the verdict is - and the AD bit will go out.
	testing.expect_value(t, result.status, Status.Secure)

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator)
	testing.expect(t, ok, "the pruned response should rebuild")
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	testing.expect(
		t,
		!holds(pruned.authority, "example.com.", .NS),
		"an unsigned NS RRset went out under the AD bit",
	)
	testing.expect(
		t,
		!holds(pruned.additional, "ns.attacker.example.", .A),
		"unsigned glue went out under the AD bit",
	)

	// And the answer it was bolted onto is still there, signature and all, for
	// a client that wants to check the work.
	testing.expect(t, holds(pruned.answer, "www.example.com.", .A), "the validated answer should survive")
	testing.expect(t, holds(pruned.answer, "www.example.com.", .RRSIG), "the answer's signature should survive")
	testing.expect(t, dns.edns_present(pruned), "the OPT record should survive")
	free_all(context.temp_allocator)
}

/*
The same forgery on a denial, where more has to be kept.

An NXDOMAIN is proven by the NSEC or NSEC3 records in its authority section,
which `validate_denial` does check, and it is remembered for as long as the SOA
beside them says - RFC 2308. Neither may be thrown away with the forgery, and
the SOA is only allowed to stay because it is checked against the keys the proof
was already established with.
*/
@(test)
test_a_proven_denial_keeps_its_proof_and_its_soa :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("nxdomain_root").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}
	testing.expect(t, holds(msg.authority, ".", .SOA), "the fixture should carry the zone's SOA")

	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	for rec in msg.authority {
		append(&authority, rec)
	}
	append(&authority, forged_ns("."))
	msg.authority = authority[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "zzzz-does-not-exist-xq7.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator)
	testing.expect(t, ok, "the pruned response should rebuild")
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	testing.expect(t, !holds(pruned.authority, ".", .NS), "an unsigned NS RRset went out under the AD bit")
	testing.expect(t, holds(pruned.authority, ".", .SOA), "the SOA a client caches the denial by was dropped")
	testing.expect(t, holds(pruned.authority, ".", .RRSIG), "the SOA's own signature was dropped")

	proof := false
	for rec in pruned.authority {
		if rec.type == .NSEC || rec.type == .NSEC3 {
			proof = true
		}
	}
	testing.expect(t, proof, "the denial of existence was dropped along with the forgery")
	testing.expect_value(t, dns.rcode_of(pruned), dns.Rcode.NX_Domain)
	free_all(context.temp_allocator)
}
