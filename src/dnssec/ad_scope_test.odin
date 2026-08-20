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
A denial has to be claimed as well as implied by the chain.

The pair with `chain_shape`: that one says the chain stopped short, this one says
the sender is asserting there is nothing more. Both are needed, and finding out
why cost a regression - a DNAME redirection is a chain that stops short and is
not a denial at all, so refusing AD on the shape alone took the bit off every one
of them.

This is the one place on this path that reads fields the sender writes, and
deliberately: what is guarded against is a false denial going out under our AD
bit, so a sender that claims no denial has made nothing to guard against.
Deleting the claim removes the harm rather than hiding it.
*/
@(test)
test_denial_claimed_reads_the_assertion :: proc(t: ^testing.T) {
	soa := dns.Record {
		name  = "other.example.",
		type  = .SOA,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Raw{data = make([]u8, 4, context.temp_allocator)},
	}
	nsec3 := dns.Record {
		name  = "brand.example.",
		type  = .NSEC3,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Raw{data = make([]u8, 4, context.temp_allocator)},
	}

	// NODATA: NOERROR with an SOA behind it.
	testing.expect(t, denial_claimed(dns.Message{authority = []dns.Record{soa}}), "an SOA claims a NODATA")

	// NXDOMAIN, with the authority section deleted. The rcode cannot be removed
	// by sending less, only set - and setting it is the claim.
	stripped := dns.Message{}
	stripped.flags.rcode = u8(dns.Rcode.NX_Domain)
	testing.expect(t, denial_claimed(stripped), "NXDOMAIN claims a denial whatever else was dropped")

	// A bare redirection claims nothing: the client follows the chain.
	testing.expect(t, !denial_claimed(dns.Message{}), "a bare chain claims no denial")

	// A wildcard-expansion proof is not a claim of denial either - it stands
	// beside an answer rather than against one, and carries no SOA.
	testing.expect(
		t,
		!denial_claimed(dns.Message{authority = []dns.Record{nsec3}}),
		"an NSEC3 with no SOA is a wildcard proof, not a denial",
	)
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
type. Every one matched what it claimed to cover and rode out under the AD bit.

The filter is signer equality against the signature that actually carried the
set, which admits an algorithm rollover - those name the same signer - and
refuses what the validator never looked at. The rest are capped, and the
signature that verified is exempt from the cap: a plain count cap was tried
first and evicted the genuine signature instead, the forgeries coming first in
a section whose order the attacker chooses.
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
	for _ in 0 ..< 16 {
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
	testing.expect(t, sigs > 0, "every signature was dropped, including the genuine one")
	testing.expectf(
		t,
		sigs <= MAX_SIGNATURES_PER_RRSET + 1,
		"%d signatures survived for one RRset: the cap is %d beyond the one that verified",
		sigs,
		MAX_SIGNATURES_PER_RRSET,
	)

	/*
	The assertion that matters, and the one a count cap failed.

	Capping how many signatures survive sounds prudent and is the opposite: the
	signer field is written by whoever wrote the record, so the cap fills with
	forgeries placed ahead of the real signature and the genuine one is what
	gets evicted - leaving a message that goes out under AD with nothing in it
	that verifies. Re-validating the pruned bytes is what says that has not
	happened, rather than counting what came through.
	*/
	after := validate(v, "www.example.com.", .A, out, time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		after.status == .Secure,
		"the pruned answer no longer validates (%v: %s) - the signature that carried it did not survive",
		after.status,
		after.reason,
	)
	free_all(context.temp_allocator)
}

/*
Forgeries placed *ahead* of the genuine signature, in the authority section.

This is the shape a count cap loses to, and the reason there is no longer one.
The section order belongs to whoever wrote the answer, so eight RRSIGs at the
head of a denial's NSEC RRset fill any per-RRset allowance before the real
signature is reached - and what gets evicted is the only record in the message
that verifies. The answer then goes out under AD with a denial nothing supports,
and is cached that way for every downstream validator behind this resolver.

The authority section rather than the answer, because that is where the two
filters disagreed: the validator accepts a denial's signature only when its
signer *is* the established zone, while the prune was asking the looser question
of whether the signer lay somewhere in the owner's ancestry. `com.` passes the
loose test over `cloudflare.com.` and fails the strict one.
*/
@(test)
test_forgeries_ahead_of_the_real_signature_do_not_evict_it :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("nodata_cloudflare").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// Eight signatures signed by `com.`, ahead of everything the zone sent.
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 8, context.temp_allocator)
	planted := false
	for rec in msg.authority {
		if rec.type != .NSEC {
			continue
		}
		for _ in 0 ..< 8 {
			append(&authority, forged_denial_rrsig(rec.name, "com."))
		}
		planted = true
		break
	}
	if !testing.expect(t, planted, "the fixture carried no NSEC record, so nothing was planted") {
		return
	}
	append(&authority, ..msg.authority)
	msg.authority = authority[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	// The verdict must survive the forgeries: the validator skips a signature
	// whose signer is not the zone, so they cost it nothing.
	result := validate(v, "nosuchname-xq7.cloudflare.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	if !testing.expectf(
		t,
		result.status == .Secure,
		"forged signatures ahead of the real one broke the verdict itself (%v: %s)",
		result.status,
		result.reason,
	) {
		return
	}

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}

	// And the pruned message must still stand on its own.
	after := validate(v, "nosuchname-xq7.cloudflare.com.", .A, out, time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		after.status == .Secure,
		"the pruned denial no longer validates (%v: %s) - the genuine signature was evicted by the forgeries in front of it",
		after.status,
		after.reason,
	)
	free_all(context.temp_allocator)
}

/*
A forgery built from the genuine signature beside it.

Everything an RRSIG carries except the signature itself is public - the signer
is a name, the key tag and algorithm come out of the zone's DNSKEY set, and the
validity window is in the real record. So a forgery copies all of it and changes
only the bytes it cannot produce, which is what a cheap pre-check cannot tell
apart and what any cap therefore has to survive.

Built from `real` for exactly that reason. An earlier version of this wrote a
key tag of its own, which matched no key in the zone - so `signature_worth_trying`
rejected every one of them for free, `spend_verification` was never called, and
the test passed while touching none of the code it names.
*/
@(private = "file")
forged_like :: proc(real: dns.Record) -> dns.Record {
	rdata, is_raw := real.data.(dns.Rdata_Raw)
	if !is_raw {
		panic("the record to copy is not raw RDATA")
	}
	out := make([]u8, len(rdata.data), context.temp_allocator)
	copy(out, rdata.data)
	// Only the signature bytes differ, and only in the last few: the signature
	// begins after the fixed fields and the signer name, and flipping the tail
	// is enough to make it not verify.
	for i in max(0, len(out) - 8) ..< len(out) {
		out[i] ~= 0xff
	}
	return dns.Record {
		name = real.name,
		type = .RRSIG,
		class = real.class,
		ttl = real.ttl,
		data = dns.Rdata_Raw{data = out},
	}
}

@(private = "file")
forged_denial_rrsig :: proc(owner: string, signer: string) -> dns.Record {
	rdata := make([dynamic]u8, 0, 64, context.temp_allocator)
	append(&rdata, 0, 47) // TYPE COVERED = NSEC
	append(&rdata, 13) // ALGORITHM
	append(&rdata, 3) // LABELS
	append(&rdata, 0, 0, 0, 60) // ORIGINAL TTL
	append(&rdata, 0x6a, 0xff, 0xff, 0xff) // EXPIRATION
	append(&rdata, 0x6a, 0x00, 0x00, 0x00) // INCEPTION
	append(&rdata, 0xff, 0xfe) // KEY TAG
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name(signer, name_buf[:])
	if err != .None {
		panic("cannot encode the forged signer")
	}
	append(&rdata, ..name_buf[:n])
	for _ in 0 ..< 16 {
		append(&rdata, 0x42)
	}
	return dns.Record{name = owner, type = .RRSIG, class = .IN, ttl = 60, data = dns.Rdata_Raw{data = rdata[:]}}
}

/*
Junk in front of a real signature costs nothing, so it cannot starve anything.

This is the half of the starvation problem that is actually solvable, and the
one that used to break a zone: a signature was tried whenever its signer named
the zone, and the signer is a name in the RDATA. Eight RRSIGs naming
`cloudflare.com` in front of the genuine one therefore spent a per-RRset
allowance before it was reached, the RRset was dropped, and every NXDOMAIN in
the zone came back SERVFAIL.

They cost nothing now: their key tag names no key the zone published, so
`signature_worth_trying` refuses them without touching the budget.

What this does *not* claim is that no forgery can drain it. One that copies the
genuine signature's key tag, algorithm and validity window - all public - buys a
real verification apiece, and enough of them in front of the real signature will
exhaust the budget and turn the answer Bogus. That is not fixable by tuning the
number: the attacker chooses the order and the count, so any budget spent in
section order can be spent before the record that matters. It is also not a
capability worth much, since anyone able to rewrite a response that far can deny
the answer outright by corrupting it or dropping it. What the budget buys is
that the work stays bounded, which is what `test_copies_of_the_real_signature_do_not_inherit_its_exemption`
holds on the other side of the same problem.
*/
@(test)
test_free_rejectable_forgeries_do_not_touch_the_budget :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("nodata_cloudflare").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// Signed by the zone itself, so the signer test cannot skip them - but with a
	// key tag the zone never published, so the free reject can.
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 8, context.temp_allocator)
	planted := false
	for rec in msg.authority {
		if rec.type != .NSEC {
			continue
		}
		for _ in 0 ..< 8 {
			append(&authority, forged_denial_rrsig(rec.name, "cloudflare.com."))
		}
		planted = true
		break
	}
	if !testing.expect(t, planted, "the fixture carried no NSEC record, so nothing was planted") {
		return
	}
	append(&authority, ..msg.authority)
	msg.authority = authority[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "nosuchname-xq7.cloudflare.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"eight free-rejectable forgeries in front of the real one turned a good denial into %v (%s)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

/*
Copies of the genuine signature do not take its exemption with them.

The prune keeps the record that verified whatever else it drops, so that a cap
can never evict the one thing the answer rests on. That exemption was first
keyed on the key tag and algorithm - both of which are printed in the zone's
DNSKEY set - so a forgery copied them and took the exemption too, the cap never
fired, and an answer padded with hundreds of them went out under AD and into the
cache for every downstream validator to work through on each hit.

Keyed on the signature bytes now: the one field of an RRSIG that cannot be
copied from public data and still be the record that verified.
*/
@(test)
test_copies_of_the_real_signature_do_not_inherit_its_exemption :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("example_a").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	answer := make([dynamic]dns.Record, 0, len(msg.answer) + 40, context.temp_allocator)
	append(&answer, ..msg.answer)
	planted := 0
	for rec in msg.answer {
		if rec.type != .RRSIG {
			continue
		}
		for _ in 0 ..< 40 {
			append(&answer, forged_like(rec))
			planted += 1
		}
		break
	}
	if !testing.expect(t, planted == 40, "the fixture carried no RRSIG to copy") {
		return
	}
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	if !testing.expectf(t, result.status == .Secure, "the verdict did not survive (%v)", result.status) {
		return
	}

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	sigs := 0
	for rec in pruned.answer {
		if rec.type == .RRSIG {
			sigs += 1
		}
	}
	testing.expectf(
		t,
		sigs <= MAX_SIGNATURES_PER_RRSET + 1,
		"%d signatures survived: forgeries copying the real tag and algorithm took the exemption",
		sigs,
	)
	// And the one that matters is still there.
	after := validate(v, "www.example.com.", .A, out, time.unix(FIXTURE_TIME, 0))
	testing.expectf(t, after.status == .Secure, "the pruned answer no longer validates (%v)", after.status)
	free_all(context.temp_allocator)
}

/*
Verbatim copies of the genuine signature do not each take the exemption.

The exemption is decided by comparing signature bytes, which is a test of
content and not of identity - and the genuine signature is public. So an
attacker does not need to forge anything at all: it appends copies of the real
record, every copy matches, and an exemption that fired once per match let all
of them through the cap. The padding then goes out under AD and into the cache,
which is what the cap exists to stop, reached by copying rather than forging.

Fires once now, and the copies are charged against the cap like anything else.
*/
@(test)
test_verbatim_copies_of_the_real_signature_are_capped :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("example_a").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	answer := make([dynamic]dns.Record, 0, len(msg.answer) + 40, context.temp_allocator)
	append(&answer, ..msg.answer)
	copies := 0
	for rec in msg.answer {
		if rec.type != .RRSIG {
			continue
		}
		for _ in 0 ..< 40 {
			append(&answer, rec)
			copies += 1
		}
		break
	}
	if !testing.expect(t, copies == 40, "the fixture carried no RRSIG to copy") {
		return
	}
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	if !testing.expectf(t, result.status == .Secure, "the verdict did not survive (%v)", result.status) {
		return
	}

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}
	pruned, _ := dns.decode_message(out, context.temp_allocator)
	sigs := 0
	for rec in pruned.answer {
		if rec.type == .RRSIG {
			sigs += 1
		}
	}
	testing.expectf(
		t,
		sigs <= MAX_SIGNATURES_PER_RRSET + 1,
		"%d signatures survived: copies of the real one each took the exemption",
		sigs,
	)
	after := validate(v, "www.example.com.", .A, out, time.unix(FIXTURE_TIME, 0))
	testing.expectf(t, after.status == .Secure, "the pruned answer no longer validates (%v)", after.status)
	free_all(context.temp_allocator)
}

/*
A near-copy of the genuine signature cannot steal its exemption.

The sharpest form of this, and the one two earlier tests both walked past: one
copies the whole record, the other changes the signature bytes, and neither
varies a field *other* than the signature while holding the signature fixed.

That is the gap. Take the genuine RRSIG, flip a bit of its ORIGINAL TTL, leave
the signature alone. It keeps the real key tag, algorithm and validity window,
so nothing rejects it early and `check_signature` simply fails on it - but an
exemption keyed on the signature bytes matched it. The mutant took the
exemption, the forgeries behind it filled the cap, and the record that actually
verified was the one dropped. The answer went out under AD, was cached, and
validated for nobody.

Ordered the way an attacker would: mutant first, padding next, the genuine
record last.
*/
@(test)
test_a_near_copy_does_not_evict_the_record_that_verified :: proc(t: ^testing.T) {
	v := make_validator(ad_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(ad_unhex(ad_fixture("example_a").wire), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	genuine: dns.Record
	found := false
	answer := make([dynamic]dns.Record, 0, len(msg.answer) + 16, context.temp_allocator)
	for rec in msg.answer {
		if rec.type == .RRSIG && !found {
			genuine, found = rec, true
			continue
		}
		append(&answer, rec)
	}
	if !testing.expect(t, found, "the fixture carried no RRSIG") {
		return
	}

	// The mutant: every byte of the genuine record except one bit of the
	// ORIGINAL TTL, which sits at offset 4 of the RDATA and is not the signature.
	raw, is_raw := genuine.data.(dns.Rdata_Raw)
	if !testing.expect(t, is_raw, "the RRSIG did not arrive as raw RDATA") {
		return
	}
	mutated := make([]u8, len(raw.data), context.temp_allocator)
	copy(mutated, raw.data)
	mutated[4] ~= 0x01
	append(
		&answer,
		dns.Record {
			name = genuine.name,
			type = .RRSIG,
			class = genuine.class,
			ttl = genuine.ttl,
			data = dns.Rdata_Raw{data = mutated},
		},
	)
	// Padding, then the record that actually verifies, last.
	for _ in 0 ..< MAX_SIGNATURES_PER_RRSET {
		append(&answer, forged_like(genuine))
	}
	append(&answer, genuine)
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	if !testing.expectf(t, result.status == .Secure, "the verdict did not survive (%v)", result.status) {
		return
	}

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}
	after := validate(v, "www.example.com.", .A, out, time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		after.status == .Secure,
		"the pruned answer no longer validates (%v: %s) - a near-copy took the exemption and the genuine record was evicted",
		after.status,
		after.reason,
	)
	free_all(context.temp_allocator)
}

/*
What the chain does with the question, and what it must not be talked out of.

`chain_shape` decides whether the AD bit may go out over an answer whose chain
stops short of the type asked for, so it is worth testing on its own. Five
earlier attempts at this question consulted something the sender writes - an SOA
in the authority section, an NSEC, the rcode - and each was defeated either by
adding a record or by deleting one. This consults the chain and nothing else.

The cases below are the ones those attempts got wrong, kept as the record of
what the predicate has to survive.
*/
@(test)
test_chain_shape_reads_only_the_chain :: proc(t: ^testing.T) {
	cname := dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "target.other.example."},
	}
	aaaa := dns.Record {
		name  = "target.other.example.",
		type  = .AAAA,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_AAAA{addr = {}},
	}

	// The chain reaches the type: an answer, and AD may cover it.
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname, aaaa}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.Direct,
	)

	// The chain stops short: a redirection, and whatever explains the missing
	// type was never checked.
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.Chain_Only,
	)

	/*
	An unrelated record of the right type does not answer the question.

	A predicate that scanned the whole section for the type stopped here: an
	attacker with a signed zone appends `x.evil.example. A`, every RRset
	verifies, and the guard was talked out of firing by a record with nothing to
	do with the name asked about.
	*/
	unrelated := dns.Record {
		name  = "x.evil.example.",
		type  = .AAAA,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_AAAA{addr = {}},
	}
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname, unrelated}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.Chain_Only,
	)

	/*
	Deleting records does not make the answer look more complete.

	The other direction, and the one an on-path attacker reaches for: strip the
	AAAA and its signature, strip the authority section, and a predicate that
	asked whether a denial had been *claimed* saw nothing to object to. The chain
	still stops short, which is all this asks.
	*/
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.Chain_Only,
	)

	// Nothing addressing the question at all.
	testing.expect_value(
		t,
		chain_shape([]dns.Record{unrelated}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.None,
	)

	// A CNAME or ANY question is answered by the chain itself.
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname}, "www.brand.example.", .CNAME, .IN),
		Answer_Shape.Direct,
	)
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname}, "www.brand.example.", .ANY, .IN),
		Answer_Shape.Direct,
	)

	// Class is part of the question.
	other_class := dns.Record {
		name  = "target.other.example.",
		type  = .AAAA,
		class = .CH,
		ttl   = 60,
		data  = dns.Rdata_AAAA{addr = {}},
	}
	testing.expect_value(
		t,
		chain_shape([]dns.Record{cname, other_class}, "www.brand.example.", .AAAA, .IN),
		Answer_Shape.Chain_Only,
	)
	free_all(context.temp_allocator)
}
