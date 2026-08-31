package dnssec

import "core:testing"
import "elodin:dns"

/*
`check_signature` on its own, at the point where nothing else is guarding it.

Three of the tests it makes are duplicated elsewhere on the ordinary path -
`validate_rrset` and `verified_rrset` run `signature_worth_trying` first, which
also refuses a lapsed signature - and that duplication is deliberate: one call
decides whether to spend a verification, the other decides the answer. But the
chain walk does not go through the cheap one. `zone_step` checks the signature
over a DS set and `fetch_keys` checks the one over a DNSKEY set by calling
straight in here, so on the two lookups that build the chain of trust these are
the only checks there are.

That makes them worth testing where they live rather than through a caller that
has already refused the same signature for its own reasons. Each test below
takes a real Ed25519 signature that verifies, changes one field, and expects a
refusal:

  - a validity window that has closed, or has not opened. An attacker replaying
    a signature the zone has since rotated away from needs only for nobody to
    read the dates.
  - a signer that is not an ancestor of the owner name. Without this any signed
    zone may vouch for any name on the internet, which is the hierarchy itself
    going away.
  - a Labels field that disagrees with the owner name. Too many labels is
    nonsense; too few is a claim that the answer came from a wildcard, and a
    forged claim of that sort sends the validator looking for a denial proof
    over a name the attacker chose.
*/

@(private = "file")
CS_DNSKEY_RDATA :: "0101030fe6087a0da6db23c6753cb6ee6edc1cc7683652baa4d3edf04c5c62bd8cbfc884"
@(private = "file")
CS_KEY_TAG :: 14506
@(private = "file")
CS_PLAIN_SIG ::
	"800c80cf38a569a0905c7b59170241df08cd21d8e1f2c500cdafea9f80641d70" +
	"17ac1408528ea0e89b4c5ddf40ff1838db43681ba856095c0bfa5ea6af60ec0b"
@(private = "file")
CS_WILDCARD_SIG ::
	"a8ed75e817a41b1637d8778ea4c7cb6aeda93c1486209cfefe84bd70b2bbc2f0" +
	"5763b7f507f69528f1830037f5824183241c36ebc76e33b10c2e1b2b9da5d10e"

/*
The two below are the forgeries a check that only verifies bytes would let
through. Each is a real signature, made over exactly the fields it carries, so
the arithmetic succeeds and only the rule refuses it - which is the situation
the rule exists for. A signature that disagreed with its own header would be
caught by the maths and would prove nothing about whether the rule is still
there.
*/

// Signed with `example.org.` in the signer field, over a name in example.com.
@(private = "file")
CS_OUT_OF_BAILIWICK_SIG ::
	"cfcf57c6e45c05a8ee42e7a38e711f770a9445eee73f1dd8fcbf2a25ae45a7df" +
	"51f225457778886f76f1cde9f884150938551908278ac59e176343b35c740303"

// Signed with a Labels field of 1, so the wildcard it claims to have come from
// is `*.com.` - above the zone that signed it.
@(private = "file")
CS_ABOVE_ZONE_SIG ::
	"42390c8d7c4bc99e205e38348449b6239247c05b8f16d77eb6179f70b1c91636" +
	"5428363de5f62121da9a69c9533739c7d1fea2748b3ae42742b65841731b4807"

@(private = "file")
CS_INCEPTION :: 1783072800
@(private = "file")
CS_EXPIRATION :: 2101024800
// A second inside the window above, and the one every case here is judged at.
@(private = "file")
CS_NOW :: 1785664800

@(private = "file")
cs_key :: proc() -> []Dnskey {
	rdata, ok := decode_hex(CS_DNSKEY_RDATA, context.temp_allocator)
	if !ok {
		return nil
	}
	key, err := parse_dnskey(rdata)
	if err != .None {
		return nil
	}
	keys := make([]Dnskey, 1, context.temp_allocator)
	keys[0] = key
	return keys
}

@(private = "file")
cs_sig :: proc(hex_signature: string) -> Rrsig {
	signature, _ := decode_hex(hex_signature, context.temp_allocator)
	return Rrsig {
		type_covered = .A,
		algorithm = ALG_ED25519,
		labels = 3,
		original_ttl = 3600,
		expiration = CS_EXPIRATION,
		inception = CS_INCEPTION,
		key_tag = CS_KEY_TAG,
		signer = "example.com.",
		signature = signature,
	}
}

@(private = "file")
cs_records :: proc() -> []dns.Record {
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.Record {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 3600,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
	return records
}

@(test)
test_check_signature_accepts_the_signature_it_should :: proc(t: ^testing.T) {
	// The control. Every test below is this one with a single field moved, so
	// if this fails the rest say nothing.
	result, encloser := check_signature(
		cs_sig(CS_PLAIN_SIG),
		"www.example.com.",
		.IN,
		cs_records(),
		cs_key(),
		CS_NOW,
		context.temp_allocator,
	)
	testing.expect_value(t, result, Verify_Result.Ok)
	testing.expect_value(t, encloser, "")
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_reads_the_validity_window_itself :: proc(t: ^testing.T) {
	/*
	The chain walk calls in here without the cheaper currency check in front of
	it, so a DS or DNSKEY signature that has lapsed is refused here or not at
	all. A signature the zone has rotated away from is exactly what an attacker
	who kept a copy would replay.
	*/
	records := cs_records()
	keys := cs_key()

	lapsed := cs_sig(CS_PLAIN_SIG)
	result, _ := check_signature(lapsed, "www.example.com.", .IN, records, keys, CS_EXPIRATION + 1, context.temp_allocator)
	testing.expect_value(t, result, Verify_Result.Bad)

	early, _ := check_signature(lapsed, "www.example.com.", .IN, records, keys, CS_INCEPTION - 1, context.temp_allocator)
	testing.expect_value(t, early, Verify_Result.Bad)

	// And the boundaries themselves are inside the window.
	on_inception, _ := check_signature(lapsed, "www.example.com.", .IN, records, keys, CS_INCEPTION, context.temp_allocator)
	testing.expect_value(t, on_inception, Verify_Result.Ok)
	on_expiration, _ := check_signature(lapsed, "www.example.com.", .IN, records, keys, CS_EXPIRATION, context.temp_allocator)
	testing.expect_value(t, on_expiration, Verify_Result.Ok)
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_refuses_a_signer_outside_the_owners_zone :: proc(t: ^testing.T) {
	/*
	A zone may sign only what is inside it. Drop this and the hierarchy stops
	meaning anything: any name with a signed zone of its own could vouch for any
	other name on the internet, and the chain of trust would no longer say who
	is allowed to answer for what.

	The signature itself is untouched here - it is a real one, over these very
	records - so nothing but the bailiwick check stands between this call and a
	verdict of Ok.
	*/
	records := cs_records()
	keys := cs_key()

	// A sibling zone, and a child of the owner rather than a parent.
	for signer in ([]string{"example.org.", "attacker.example.", "www.www.example.com.", "ample.com."}) {
		sig := cs_sig(CS_PLAIN_SIG)
		sig.signer = signer
		result, _ := check_signature(sig, "www.example.com.", .IN, records, keys, CS_NOW, context.temp_allocator)
		testing.expectf(t, result == .Bad, "%q must not be able to sign www.example.com., got %v", signer, result)
	}

	// The owner's own zone and its parents are all inside bailiwick, and fail
	// only because the signature was not made with those fields.
	sig := cs_sig(CS_PLAIN_SIG)
	sig.signer = "com."
	sig.labels = 2
	in_bailiwick, _ := check_signature(sig, "www.example.com.", .IN, records, keys, CS_NOW, context.temp_allocator)
	testing.expect(t, in_bailiwick == .Bad, "a parent zone is in bailiwick, though this signature is not its")
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_refuses_a_labels_field_the_owner_contradicts :: proc(t: ^testing.T) {
	/*
	RFC 4034 section 3.1.3. The Labels field counts the owner name's labels, so
	more of them than the name has is nonsense, and fewer than the signer's zone
	has is a signature reaching above its own zone.
	*/
	records := cs_records()
	keys := cs_key()

	for labels in ([]u8{4, 5, 255}) {
		sig := cs_sig(CS_PLAIN_SIG)
		sig.labels = labels
		result, _ := check_signature(sig, "www.example.com.", .IN, records, keys, CS_NOW, context.temp_allocator)
		testing.expectf(t, result == .Bad, "a labels field of %d over a three-label name must be refused", labels)
	}

	// Fewer labels than the signer zone carries: `example.com.` is two, so one
	// would put the wildcard above the zone that signed it.
	sig := cs_sig(CS_PLAIN_SIG)
	sig.labels = 1
	result, _ := check_signature(sig, "www.example.com.", .IN, records, keys, CS_NOW, context.temp_allocator)
	testing.expect_value(t, result, Verify_Result.Bad)
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_reports_the_encloser_a_wildcard_expansion_claims :: proc(t: ^testing.T) {
	/*
	A Labels field one short of the owner name says the zone answered out of
	`*.example.com.`, and the signature really is over that wildcard - so the
	verification succeeds and the caller is handed the closest encloser the
	answer is claiming.

	That name is the whole point: the caller has to go and find a denial proof
	lined up with it, showing the queried name genuinely did not exist and the
	wildcard was entitled to answer. Handing back the wrong encloser, or none,
	is how a wildcard answer gets accepted for a name that exists.
	*/
	expansion := cs_sig(CS_WILDCARD_SIG)
	expansion.labels = 2
	result, encloser := check_signature(
		expansion,
		"www.example.com.",
		.IN,
		cs_records(),
		cs_key(),
		CS_NOW,
		context.temp_allocator,
	)
	testing.expect_value(t, result, Verify_Result.Ok)
	testing.expect_value(t, encloser, "example.com.")

	// The same signature does not verify with its Labels field put back to the
	// owner name's own count: the bytes it was made over name the wildcard, not
	// the queried name.
	as_plain := cs_sig(CS_WILDCARD_SIG)
	plain_result, _ := check_signature(
		as_plain,
		"www.example.com.",
		.IN,
		cs_records(),
		cs_key(),
		CS_NOW,
		context.temp_allocator,
	)
	testing.expect_value(t, plain_result, Verify_Result.Bad)
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_counts_a_literal_wildcard_owner_without_its_asterisk :: proc(t: ^testing.T) {
	/*
	`*.example.com.` is an ordinary name a zone may hold records for, and RFC
	4034 section 3.1.3 counts its labels without the asterisk - so a correct
	signature over it carries 2, not 3. Counting the asterisk would make that
	signature look one label short, which is the mark of a wildcard expansion,
	and the answer would be sent off for a proof that the name does not exist
	when it plainly does.
	*/
	sig := cs_sig(CS_PLAIN_SIG)
	sig.labels = 2
	records := cs_records()
	records[0].name = "*.example.com."

	result, encloser := check_signature(sig, "*.example.com.", .IN, records, cs_key(), CS_NOW, context.temp_allocator)
	// The bytes were signed over `www.`, so this cannot verify - but it must
	// fail on the signature, not by being mistaken for an expansion.
	testing.expect_value(t, result, Verify_Result.Bad)
	testing.expect_value(t, encloser, "")
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_refuses_a_consistent_out_of_bailiwick_signature :: proc(t: ^testing.T) {
	/*
	The signature here really was made with `example.org.` as its signer, over
	these records, by the key handed in. Everything agrees; the arithmetic
	succeeds. The only thing that refuses it is the rule that a zone signs what
	is inside it.

	That is what makes this the test worth having. Pointing a signer field
	somewhere else without re-signing produces bytes that fail on the maths
	alone, and would go on passing if the bailiwick check were deleted
	tomorrow - so it would tell us nothing. This one goes bad the moment the
	rule does.
	*/
	sig := cs_sig(CS_OUT_OF_BAILIWICK_SIG)
	sig.signer = "example.org."
	result, _ := check_signature(sig, "www.example.com.", .IN, cs_records(), cs_key(), CS_NOW, context.temp_allocator)
	testing.expect_value(t, result, Verify_Result.Bad)
	free_all(context.temp_allocator)
}

@(test)
test_check_signature_refuses_a_consistent_wildcard_above_the_signing_zone :: proc(t: ^testing.T) {
	/*
	A Labels field of 1 under a signer of `example.com.` claims the answer was
	expanded from `*.com.` - a wildcard two labels above the zone that signed
	it. The signature was made over exactly that, so it verifies.

	Left unchecked, `check_signature` would hand its caller `com.` as the
	closest encloser the answer claims, and the caller would go looking for a
	denial proof anchored there. A zone that holds one name gets to make
	statements about the shape of its grandparent, which is the hierarchy
	inverted. The Labels field has to be held to the signer's own depth before
	any of that is computed.
	*/
	sig := cs_sig(CS_ABOVE_ZONE_SIG)
	sig.labels = 1
	result, encloser := check_signature(sig, "www.example.com.", .IN, cs_records(), cs_key(), CS_NOW, context.temp_allocator)
	testing.expect_value(t, result, Verify_Result.Bad)
	testing.expectf(t, encloser == "", "no encloser should be claimed on a refusal, got %q", encloser)
	free_all(context.temp_allocator)
}
