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

// Asked for by what it covers, because an apex carries signatures over several
// types at once and "an RRSIG survived" would be answered by any of them.
@(private = "file")
holds_signature_over :: proc(records: []dns.Record, name: string, covered: dns.Type) -> bool {
	for rec in records {
		if rec.type != .RRSIG || !dns.name_equal_fold(rec.name, name) {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, context.temp_allocator)
		if err == .None && sig.type_covered == covered {
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
	testing.expect(
		t,
		holds_signature_over(pruned.authority, ".", .SOA),
		"the SOA survived without the signature that is the only reason it was allowed to",
	)

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

/*
A pile of forged RRSIGs does not ride out on the RRset they claim to cover.

The prune keeps a signature by what it says it covers rather than by having been
the one that verified, so that an algorithm rollover does not lose the signature
a downstream validator can check. That is the only thing here that leaves
unchecked, which is why the two things sayable about a signature without
verifying it are checked: its signer has to lie in the owner's ancestry, and no
more than `MAX_SIGNATURES_PER_RRSET` are kept for one RRset.

Without those an attacker who can add records - a zone it owns, or the path to a
plain UDP upstream - appends as many as it likes at an authenticated owner and
type. Every one matched, survived, went out under AD, and was cached for every
later client: an unauthenticated RRset in the answer section under the AD bit,
which is what this procedure exists to remove.
*/
@(private = "file")
forged_rrsig :: proc(owner: string, signer: string) -> dns.Record {
	// RRSIG RDATA: type covered A, algorithm 13, labels 3, original TTL,
	// expiration, inception, key tag, signer name, then the signature bytes.
	rdata := make([dynamic]u8, 0, 64, context.temp_allocator)
	append(&rdata, 0, 1) // TYPE COVERED = A
	append(&rdata, 13) // ALGORITHM
	append(&rdata, 3) // LABELS
	append(&rdata, 0, 0, 1, 44) // ORIGINAL TTL
	append(&rdata, 0x6a, 0xff, 0xff, 0xff) // EXPIRATION
	append(&rdata, 0x6a, 0x00, 0x00, 0x00) // INCEPTION
	append(&rdata, 0xff, 0xff) // KEY TAG
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name(signer, name_buf[:])
	if err != .None {
		panic("cannot encode the forged signer")
	}
	append(&rdata, ..name_buf[:n])
	for _ in 0 ..< 16 {
		append(&rdata, 0x41) // the "signature"
	}
	return dns.Record {
		name = owner,
		type = .RRSIG,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = rdata[:]},
	}
}

@(test)
test_forged_signatures_do_not_survive_the_prune_in_bulk :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("example_a").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	genuine := len(msg.answer)
	answer := make([dynamic]dns.Record, 0, genuine + 40, context.temp_allocator)
	append(&answer, ..msg.answer)
	// Thirty-two more, all claiming to cover the answer's A RRset. Half name a
	// signer inside the owner's ancestry and half name one outside it.
	for i in 0 ..< 16 {
		append(&answer, forged_rrsig("www.example.com.", "example.com."))
		append(&answer, forged_rrsig("www.example.com.", "attacker.example."))
	}
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	sigs := 0
	for rec in pruned.answer {
		if rec.type != .RRSIG {
			continue
		}
		sigs += 1
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, serr := parse_rrsig(rdata, context.temp_allocator)
		if serr != .None {
			continue
		}
		testing.expectf(
			t,
			name_in_zone(rec.name, sig.signer),
			"a signature signed by %s survived over an RRset at %s",
			sig.signer,
			rec.name,
		)
	}
	testing.expectf(
		t,
		sigs <= MAX_SIGNATURES_PER_RRSET,
		"%d signatures survived for one RRset, against a cap of %d",
		sigs,
		MAX_SIGNATURES_PER_RRSET,
	)
	free_all(context.temp_allocator)
}
