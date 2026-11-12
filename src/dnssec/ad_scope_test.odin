package dnssec

import "core:slice"
import "core:testing"
import "elodin:dns"

/*
What the Secure verdict actually covers.

The verdict `validate` reaches is written onto the whole message as the AD bit.
RFC 4035 section 3.2.3 says AD may be set only when every RRset in the Answer
*and Authority* sections has been authenticated, so `strip_unauthenticated`
prunes the AUTHORITY and ADDITIONAL sections of a `Secure` response down to what
the verdict names. Without that, anything able to add records to a response - a
malicious authoritative server for a zone it owns, or anyone on the path to a
plain UDP upstream who leaves the signed answer alone - would get its own
unsigned records stamped as authenticated.

The answer itself is genuine in both tests below, so the verdict is `Secure` and
stays that way: what is checked here is that the records nobody signed are not
part of the message that verdict is written onto, and that the ones a client
cannot do without - the denial, and the SOA it is remembered by - still are.
*/

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

/*
`msg` as an upstream sent it, judged `Secure` and pruned the way a client is sent
it. `ok` is false, with the step that failed reported, when any of that does not
hold.
*/
@(private = "file")
ad_prune :: proc(t: ^testing.T, v: ^Validator, msg: dns.Message, qname: string, qtype: dns.Type) -> (out: []u8, pruned: dns.Message, ok: bool) {
	wire, _, enc := dns.encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, enc, dns.Encode_Error.None) {
		return nil, {}, false
	}
	result := validate(v, qname, qtype, wire, fixture_now())
	if !testing.expectf(t, result.status == .Secure, "%s: want Secure, got %v (%s)", qname, result.status, result.reason) {
		return nil, {}, false
	}
	stripped: bool
	out, stripped = strip_unauthenticated(wire, result, context.temp_allocator)
	if !testing.expect(t, stripped, "the pruned response should rebuild") {
		return nil, {}, false
	}
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return nil, {}, false
	}
	return out, decoded, true
}

@(test)
test_unsigned_authority_records_do_not_reach_the_client :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	// A real, correctly signed answer for www.example.com.
	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// Records nobody signed, in the two sections a client also reads: a
	// delegation pointing at the attacker's nameserver, and its address.
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = forged_ns("example.com.")
	msg.authority = authority

	additional := make([dynamic]dns.Record, 0, len(msg.additional) + 1, context.temp_allocator)
	append(&additional, ..msg.additional)
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

	// The answer is genuine, so the verdict is - and the AD bit will go out.
	_, pruned, pruned_ok := ad_prune(t, v, msg, "www.example.com.", .A)
	if !pruned_ok {
		return
	}

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

The pair with `chain_walk`: that one says the chain stopped short, this one says
the sender is asserting there is nothing more. Both are needed: a DNAME
redirection is a chain that stops short and is not a denial at all, so refusing
AD on the shape alone would take the bit off every one of them.

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
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "nxdomain_root"), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}
	testing.expect(t, holds(msg.authority, ".", .SOA), "the fixture should carry the zone's SOA")

	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	append(&authority, ..msg.authority)
	append(&authority, forged_ns("."))
	msg.authority = authority[:]

	_, pruned, pruned_ok := ad_prune(t, v, msg, "zzzz-does-not-exist-xq7.", .A)
	if !pruned_ok {
		return
	}

	testing.expect(t, !holds(pruned.authority, ".", .NS), "an unsigned NS RRset went out under the AD bit")
	testing.expect(t, holds(pruned.authority, ".", .SOA), "the SOA a client caches the denial by was dropped")
	testing.expect(
		t,
		holds_signature_over(pruned.authority, ".", .SOA) > 0,
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
plain UDP upstream - would append as many as it liked at an authenticated owner
and type, and every one would match what it claimed to cover and ride out under
the AD bit.

The filter is signer equality against the signature that actually carried the
set, which admits an algorithm rollover - those name the same signer - and
refuses what the validator never looked at. The rest are capped, and the
signature that verified is exempt from the cap: a plain count cap would evict
the genuine signature instead, the forgeries coming first in a section whose
order the attacker chooses.
*/
@(private = "file")
forged_rrsig :: proc(owner: string, signer: string) -> dns.Record {
	sig := Rrsig {
		type_covered = .A,
		algorithm    = ALG_ECDSAP256SHA256,
		labels       = 3,
		original_ttl = 300,
		expiration   = 0x6affffff,
		inception    = 0x6a000000,
		key_tag      = 0xffff,
		signer       = signer,
		signature    = slice.repeat([]u8{0x41}, 16, context.temp_allocator),
	}
	return rrsig_record(owner, sig)
}

@(test)
test_forged_signatures_do_not_survive_the_prune_in_bulk :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
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

	out, pruned, pruned_ok := ad_prune(t, v, msg, "www.example.com.", .A)
	if !pruned_ok {
		return
	}

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
			dns.name_at_or_below(rec.name, sig.signer),
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
	The assertion that matters, and the one a plain count cap fails.

	A cap with no exemption is not prudent: the signer field is written by
	whoever wrote the record, so such a cap fills with forgeries placed ahead of
	the real signature and the genuine one is what gets evicted - leaving a
	message that goes out under AD with nothing in it that verifies. The cap
	here exempts the signature that verified. Re-validating the pruned bytes is what says that has not
	happened, rather than counting what came through.
	*/
	after := validate(v, "www.example.com.", .A, out, fixture_now())
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

This is the shape a plain count cap loses to, and the reason the cap exempts the
signature that verified. The section order belongs to whoever wrote the answer,
so eight RRSIGs at the head of a denial's NSEC RRset would fill any unexempted
allowance before the real signature is reached - and what would be evicted is
the only record in the message that verifies. The answer would then go out under
AD with a denial nothing supports, and be cached that way for every downstream
validator behind this resolver.

The authority section rather than the answer, because that is where two filters
can disagree: the validator accepts a denial's signature only when its signer
*is* the established zone, while a prune asking only whether the signer lies
somewhere in the owner's ancestry is looser. `com.` passes the loose test over
`cloudflare.com.` and fails the strict one.
*/
@(test)
test_forgeries_ahead_of_the_real_signature_do_not_evict_it :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	// Eight signatures signed by `com.`, ahead of everything the zone sent.
	tampered, planted := ad_plant_ahead_of_nsec(t, "com.")
	if !planted {
		return
	}

	// The verdict must survive the forgeries: the validator skips a signature
	// whose signer is not the zone, so they cost it nothing.
	result := validate(v, "nosuchname-xq7.cloudflare.com.", .A, tampered, fixture_now())
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
	after := validate(v, "nosuchname-xq7.cloudflare.com.", .A, out, fixture_now())
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

Built from `real` for exactly that reason. A key tag of its own would match no
key in the zone - so `signature_worth_trying` would reject every one of them for
free, `spend_verification` would never be called, and the test would pass while
touching none of the code it names.
*/
@(private = "file")
forged_like :: proc(real: dns.Record) -> dns.Record {
	return rrsig_mutant(real, {.Signature})
}

/*
Cloudflare's captured NODATA with eight `forged_denial_rrsig`s by `signer`
planted ahead of everything the zone sent, owned by the first NSEC.
*/
@(private = "file")
ad_plant_ahead_of_nsec :: proc(t: ^testing.T, signer: string) -> (wire: []u8, ok: bool) {
	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "nodata_cloudflare"), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return nil, false
	}
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 8, context.temp_allocator)
	for rec in msg.authority {
		if rec.type != .NSEC {
			continue
		}
		for _ in 0 ..< 8 {
			append(&authority, forged_denial_rrsig(rec.name, signer))
		}
		break
	}
	if !testing.expect(t, len(authority) == 8, "the fixture carried no NSEC record, so nothing was planted") {
		return nil, false
	}
	append(&authority, ..msg.authority)
	msg.authority = authority[:]

	enc: dns.Encode_Error
	wire, _, enc = dns.encode_message(msg, context.temp_allocator)
	return wire, testing.expect_value(t, enc, dns.Encode_Error.None)
}

@(private = "file")
forged_denial_rrsig :: proc(owner: string, signer: string) -> dns.Record {
	sig := Rrsig {
		type_covered = .NSEC,
		algorithm    = ALG_ECDSAP256SHA256,
		labels       = 3,
		original_ttl = 60,
		expiration   = 0x6affffff,
		inception    = 0x6a000000,
		key_tag      = 0xfffe,
		signer       = signer,
		signature    = slice.repeat([]u8{0x42}, 16, context.temp_allocator),
	}
	return rrsig_record(owner, sig, ttl = 60)
}

/*
Junk in front of a real signature costs nothing, so it cannot starve anything.

This is the half of the starvation problem that is actually solvable: were a
signature tried whenever its signer named the zone - and the signer is a name in
the RDATA - eight RRSIGs naming `cloudflare.com` in front of the genuine one
would spend a per-RRset allowance before it was reached, the RRset would be
dropped, and every NXDOMAIN in the zone would come back SERVFAIL.

They cost nothing: their key tag names no key the zone published, so
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
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	// Signed by the zone itself, so the signer test cannot skip them - but with a
	// key tag the zone never published, so the free reject can.
	tampered, planted := ad_plant_ahead_of_nsec(t, "cloudflare.com.")
	if !planted {
		return
	}

	result := validate(v, "nosuchname-xq7.cloudflare.com.", .A, tampered, fixture_now())
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
can never evict the one thing the answer rests on. Keyed on the key tag and
algorithm - both of which are printed in the zone's DNSKEY set - a forgery would
copy them and take the exemption too, the cap would never fire, and an answer
padded with hundreds of them would go out under AD and into the cache for every
downstream validator to work through on each hit.

The exemption compares the whole record (`rrsig_equal`), signature bytes
included: the one field of an RRSIG that cannot be copied from public data and
still be the record that verified.
*/
@(test)
test_copies_of_the_real_signature_do_not_inherit_its_exemption :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
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

	out, pruned, pruned_ok := ad_prune(t, v, msg, "www.example.com.", .A)
	if !pruned_ok {
		return
	}

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
	after := validate(v, "www.example.com.", .A, out, fixture_now())
	testing.expectf(t, after.status == .Secure, "the pruned answer no longer validates (%v)", after.status)
	free_all(context.temp_allocator)
}

/*
Verbatim copies of the genuine signature do not each take the exemption.

The exemption is decided by comparing the record, which is a test of content and
not of identity - and the genuine signature is public. So an attacker does not
need to forge anything at all: it appends copies of the real record, and every
copy matches. An exemption that fired once per match would let all of them
through the cap, and the padding would go out under AD and into the cache, which
is what the cap exists to stop, reached by copying rather than forging.

It fires once, and the copies are charged against the cap like anything else.
*/
@(test)
test_verbatim_copies_of_the_real_signature_are_capped :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
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

	out, pruned, pruned_ok := ad_prune(t, v, msg, "www.example.com.", .A)
	if !pruned_ok {
		return
	}
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
	after := validate(v, "www.example.com.", .A, out, fixture_now())
	testing.expectf(t, after.status == .Secure, "the pruned answer no longer validates (%v)", after.status)
	free_all(context.temp_allocator)
}

/*
A near-copy of the genuine signature cannot steal its exemption.

The sharpest form of this, and the one the two tests above both walk past: one
copies the whole record, the other changes the signature bytes, and neither
varies a field *other* than the signature while holding the signature fixed.

Take the genuine RRSIG, flip a bit of its ORIGINAL TTL, leave the signature
alone. It keeps the real key tag, algorithm and validity window, so nothing
rejects it early and `check_signature` simply fails on it - but an exemption
keyed on the signature bytes alone would match it. The mutant would take the
exemption, the forgeries behind it would fill the cap, and the record that
actually verified would be the one dropped. The answer would go out under AD,
be cached, and validate for nobody.

Ordered the way an attacker would: mutant first, padding next, the genuine
record last.
*/
@(test)
test_a_near_copy_does_not_evict_the_record_that_verified :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "example_a"), context.temp_allocator)
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
	// Original TTL, which is signed data and not the signature.
	append(&answer, rrsig_mutant(genuine, {.Original_Ttl}))
	// Padding, then the record that actually verifies, last.
	for _ in 0 ..< MAX_SIGNATURES_PER_RRSET {
		append(&answer, forged_like(genuine))
	}
	append(&answer, genuine)
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, fixture_now())
	if !testing.expectf(t, result.status == .Secure, "the verdict did not survive (%v)", result.status) {
		return
	}

	out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, ok, "the pruned response should rebuild") {
		return
	}
	after := validate(v, "www.example.com.", .A, out, fixture_now())
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

`chain_walk` decides whether the AD bit may go out over an answer whose chain
stops short of the type asked for, so it is worth testing on its own. A
predicate that consults something the sender writes - an SOA in the authority
section, an NSEC, the rcode - is defeated either by adding a record or by
deleting one. This consults the chain and nothing else.

The cases below are what the predicate has to survive. Where the walk ended is
checked beside the shape: for `.Chain_Only` it is the name a denial beside the
chain is about.
*/
@(test)
test_chain_walk_reads_only_the_chain :: proc(t: ^testing.T) {
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
	shape, end := chain_walk([]dns.Record{cname, aaaa}, "www.brand.example.", .AAAA, .IN)
	testing.expect_value(t, shape, Answer_Shape.Direct)
	testing.expect_value(t, end, "target.other.example.")

	/*
	The chain stops short: a redirection, and whatever explains the missing type
	was never checked.

	Deleting records does not make the answer look more complete either. This is
	the direction an on-path attacker reaches for: strip the AAAA and its
	signature, and a predicate that asked whether a denial had been *claimed*
	would see nothing to object to. The chain still stops short, which is all
	this asks.
	*/
	shape, end = chain_walk([]dns.Record{cname}, "www.brand.example.", .AAAA, .IN)
	testing.expect_value(t, shape, Answer_Shape.Chain_Only)
	testing.expect_value(t, end, "target.other.example.")

	/*
	An unrelated record of the right type does not answer the question.

	A predicate that scanned the whole section for the type would stop here: an
	attacker with a signed zone appends `x.evil.example. A`, every RRset
	verifies, and the guard is talked out of firing by a record with nothing to
	do with the name asked about.
	*/
	unrelated := dns.Record {
		name  = "x.evil.example.",
		type  = .AAAA,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_AAAA{addr = {}},
	}
	shape, end = chain_walk([]dns.Record{cname, unrelated}, "www.brand.example.", .AAAA, .IN)
	testing.expect_value(t, shape, Answer_Shape.Chain_Only)
	testing.expect_value(t, end, "target.other.example.")

	// Nothing addressing the question at all.
	shape, _ = chain_walk([]dns.Record{unrelated}, "www.brand.example.", .AAAA, .IN)
	testing.expect_value(t, shape, Answer_Shape.None)

	// A CNAME or ANY question is answered by the chain itself.
	shape, end = chain_walk([]dns.Record{cname}, "www.brand.example.", .CNAME, .IN)
	testing.expect_value(t, shape, Answer_Shape.Direct)
	testing.expect_value(t, end, "www.brand.example.")
	shape, end = chain_walk([]dns.Record{cname}, "www.brand.example.", .ANY, .IN)
	testing.expect_value(t, shape, Answer_Shape.Direct)
	testing.expect_value(t, end, "www.brand.example.")

	// Class is part of the question.
	other_class := dns.Record {
		name  = "target.other.example.",
		type  = .AAAA,
		class = .CH,
		ttl   = 60,
		data  = dns.Rdata_AAAA{addr = {}},
	}
	shape, end = chain_walk([]dns.Record{cname, other_class}, "www.brand.example.", .AAAA, .IN)
	testing.expect_value(t, shape, Answer_Shape.Chain_Only)
	testing.expect_value(t, end, "target.other.example.")
	free_all(context.temp_allocator)
}

/*
The denial records behind a wildcard proof are verified once for the message.

An answer may expand from several wildcards, and each expansion needs the same
authority section verified against the same zone. Doing that per expansion is
not free, since the verification spends `MAX_VERIFICATIONS_PER_QUERY`, and what
it would spend it on is work already done: eight expansions over five NSEC3
RRsets is forty verifications carrying five sets' worth of information, most of
the allowance gone before the answer's own RRsets are reached. The response that
would pay for it is a legitimate one - an attacker gains nothing by making a
zone answer from its own wildcards - so the budget would fire on size rather
than on forgery, and a good answer would reach the client as SERVFAIL.

Asserted on the budget rather than on a verdict because that is where the
difference shows: both calls return the same records either way, and only the
meter says whether the second one paid for them again.
*/
@(test)
test_a_messages_denial_records_are_verified_once :: proc(t: ^testing.T) {
	v := scenario_validator(&FIXTURES)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(FIXTURES, "nodata_cloudflare"), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	now := fixture_now()
	budget := query_budget(v)
	trust, keys, established := zone_trust(v, &budget, "cloudflare.com.", now, context.temp_allocator)
	if !testing.expectf(t, trust == .Secure, "the fixture's zone did not establish, got %v", trust) {
		return
	}

	seen := make([dynamic]Verified_Denial, 0, 1, context.temp_allocator)
	first := denial_records_for(
		v,
		&budget,
		&seen,
		msg.authority,
		established,
		.IN,
		keys,
		u32(FIXTURE_TIME),
		now,
		context.temp_allocator,
	)
	spent := budget.verifications
	// Otherwise the comparison below holds for the wrong reason: nothing was
	// verified on the first pass either.
	if !testing.expect(t, spent > 0, "the first pass verified nothing, so the second cannot be shown to be free") {
		return
	}
	if !testing.expect(t, len(first.nsecs) > 0 || len(first.nsec3s) > 0, "the fixture carried no denial records") {
		return
	}

	second := denial_records_for(
		v,
		&budget,
		&seen,
		msg.authority,
		established,
		.IN,
		keys,
		u32(FIXTURE_TIME),
		now,
		context.temp_allocator,
	)
	testing.expectf(
		t,
		budget.verifications == spent,
		"a second expansion re-verified the same denial records: %d verifications became %d",
		spent,
		budget.verifications,
	)
	testing.expect_value(t, len(second.nsecs), len(first.nsecs))
	testing.expect_value(t, len(second.nsec3s), len(first.nsec3s))
	testing.expect_value(t, len(second.verified), len(first.verified))
	free_all(context.temp_allocator)
}
