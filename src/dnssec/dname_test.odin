package dnssec

import "core:testing"
import "elodin:dns"

/*
A synthetic zone whose apex holds a DNAME, generated rather than captured.

RFC 6672 section 3.4.1 has the server synthesize a CNAME for the redirected
name and send it *unsigned* - the DNAME is what carries the signature, and a
validating resolver is meant to reconstruct the CNAME from it rather than
expect one of its own. Nothing published on the internet would let a test tell
the difference between handling that correctly and simply trusting whatever
unsigned CNAME turned up, so the zone is built here: `dname_answer` is the
redirection as a server would send it, and `dname_answer_mismatched` is the
same DNAME beside a CNAME it could not have produced.

Ed25519 throughout, with the root replaced by a trust anchor of its own so the
chain is three fixtures rather than the whole public hierarchy.

Reproducible, so the bytes can be rebuilt rather than taken on trust. Two
Ed25519 keys from fixed seeds - the root's is the 32 bytes 1..32, the zone's is
101..132 - each published as a single DNSKEY with flags 257 and protocol 3. The
root's key hashes to the anchor below; the zone's DNSKEY set is signed by
itself and attested by a DS the root signs. Every RRSIG runs from
FIXTURE_TIME - 86400 to FIXTURE_TIME + 86400*365, so the same window every
other fixture here is judged in. `dnametest.` holds one record, a DNAME at the
apex pointing at `target.example.`, and `a.dnametest.` is the name the answers
redirect.
*/

@(private = "file")
DNAME_ANCHOR :: ". IN DS 36560 15 2 87C69552A404AA168A8EED61EAACEE6E244DC2FCCA0AC25A246390A0F73BF1F2"

@(private = "file")
DNAME_FIXTURES := []Fixture{
	{
		key   = "dname_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f79b5562e8fe654f94078b112e8a98ba7" +
			"901f853ae695bed7e0e3910bad04966400002e000100000e10005300300f0000000e106c5048a06a6dc3a08ed0006181" +
			"ffd430f869c1e25cc602eaa481b7ed979d4b66748967831f52e117e0e00cc6fd4a336e3149a82f527e4d5bf26a0f5a81" +
			"cdd8929b7c051e25ace1b4469902",
	},
	{
		key   = "dname_zone_ds",
		name  = "dnametest.",
		type  = .DS,
		wire  = "12348580000100020000000009646e616d657465737400002b000109646e616d657465737400002b000100000e100024" +
			"d2010f025fd5e7854b4379b0f20d894b839b0d5ea0e05e4f261af2faf7933f7b2c9655fb09646e616d65746573740000" +
			"2e000100000e100053002b0f0100000e106c5048a06a6dc3a08ed000a457d9b878f6fa529ddc5c8eccf7a7f11fd7f022" +
			"0de45040f18bbce9148630e965b29fbb80d903cf3c830bf0d98bea9c87582c07e4a1554da63e2da1be516800",
	},
	{
		key   = "dname_zone_dnskey",
		name  = "dnametest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000009646e616d6574657374000030000109646e616d6574657374000030000100000e100024" +
			"0101030fda29e95b02e00ffa15645775fb1d2ba222a1943395eea06b94e2c057b7be69d009646e616d65746573740000" +
			"2e000100000e10005d00300f0100000e106c5048a06a6dc3a0d20109646e616d657465737400746400e5582042b5c689" +
			"15a20255f21c98ce8a504407f903996f5288828dc1b97af8e62c1d3e3a0006ac2f76964116c1d2d9a444d773b85a70f9" +
			"dc335d284107",
	},
	{
		key   = "dname_answer",
		name  = "a.dnametest.",
		type  = .A,
		wire  = "123485800001000300000000016109646e616d6574657374000001000109646e616d6574657374000027000100000e10" +
			"001006746172676574076578616d706c650009646e616d657465737400002e000100000e10005d00270f0100000e106c" +
			"5048a06a6dc3a0d20109646e616d657465737400d4034a2983ff550a934d9de59c7901bc39e837429a5109b750a2a08b" +
			"6e29f2de80f1df0ce28e76ad293b66a50725aae4f082f47129b643320d34db50590e270e016109646e616d6574657374" +
			"000005000100000e100012016106746172676574076578616d706c6500",
	},
	{
		key   = "dname_answer_mismatched",
		name  = "a.dnametest.",
		type  = .A,
		wire  = "123485800001000300000000016109646e616d6574657374000001000109646e616d6574657374000027000100000e10" +
			"001006746172676574076578616d706c650009646e616d657465737400002e000100000e10005d00270f0100000e106c" +
			"5048a06a6dc3a0d20109646e616d657465737400d4034a2983ff550a934d9de59c7901bc39e837429a5109b750a2a08b" +
			"6e29f2de80f1df0ce28e76ad293b66a50725aae4f082f47129b643320d34db50590e270e016109646e616d6574657374" +
			"000005000100000e1000120861747461636b6572076578616d706c6500",
	},
}

@(test)
test_dname_zone_chain_is_sound :: proc(t: ^testing.T) {
	/*
	The control. These fixtures are generated, so if the canonical form they
	were built against ever drifts from the one the validator computes, the
	tests below would start reporting on the drift rather than on DNAME. This
	walks the synthetic chain on its own: root anchor, DS, DNSKEY.
	*/
	v := scenario_validator(&DNAME_FIXTURES, DNAME_ANCHOR)
	defer destroy_validator(v)

	budget := query_budget(v)
	status, keys, zone := zone_trust(v, &budget, "dnametest.", fixture_now(), context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "dnametest.")
	testing.expect(t, len(keys) > 0, "the zone should publish a key")
	free_all(context.temp_allocator)
}

@(test)
test_dname_redirection_validates :: proc(t: ^testing.T) {
	/*
	The redirection as a server sends it: a signed DNAME at the apex, and the
	CNAME it synthesized for the queried name, unsigned because RFC 6672 says
	so.

	Treating that CNAME as an ordinary unsigned RRset makes it bogus - it sits
	inside a signed zone with no signature of its own - and takes the whole
	response down with it. Every name behind a DNAME then fails to resolve.
	*/
	result := scenario_validate(&DNAME_FIXTURES, "a.dnametest.", .A, scenario_fixture(DNAME_FIXTURES, "dname_answer"), DNAME_ANCHOR)
	testing.expectf(
		t,
		result.status == .Secure,
		"a DNAME redirection should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_cname_a_dname_does_not_account_for_is_refused :: proc(t: ^testing.T) {
	/*
	The other half, and the reason the synthesis is recomputed rather than
	assumed. The DNAME here is the same signed record; the CNAME beside it
	points somewhere the DNAME could never have sent it.

	A validator that accepted any unsigned CNAME sitting under a validated
	DNAME would hand out a redirect to anywhere, for every name below every
	DNAME in existence - which is a great deal worse than the bug it set out
	to fix.
	*/
	v := scenario_validator(&DNAME_FIXTURES, DNAME_ANCHOR)
	defer destroy_validator(v)

	result := validate(
		v,
		"a.dnametest.",
		.A,
		scenario_fixture(DNAME_FIXTURES, "dname_answer_mismatched"),
		fixture_now(),
	)
	testing.expectf(
		t,
		result.status != .Secure,
		"a CNAME the DNAME could not have produced was accepted (%v, %q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_dname_synthesis_is_recomputed_exactly :: proc(t: ^testing.T) {
	/*
	The substitution, case by case. This is the whole safeguard: it is what
	stands between accepting a CNAME a DNAME really produced and accepting any
	unsigned CNAME that turned up underneath one.
	*/
	check :: proc(owner, target, cname_owner, cname_target: string) -> bool {
		return dname_synthesizes(owner, target, cname_owner, cname_target, context.temp_allocator)
	}

	testing.expect(
		t,
		check("dnametest.", "target.example.", "a.dnametest.", "a.target.example."),
		"the substitution a DNAME produces should be accepted",
	)
	testing.expect(
		t,
		check("dnametest.", "target.example.", "x.y.dnametest.", "x.y.target.example."),
		"a multi-label prefix should carry over whole",
	)
	testing.expect(
		t,
		check("redirect.dnametest.", "t.example.", "a.redirect.dnametest.", "a.t.example."),
		"a DNAME below the apex should work the same way",
	)
	testing.expect(
		t,
		check("dnametest.", "target.example.", "A.DNAMETEST.", "a.TARGET.example."),
		"names should match case-insensitively",
	)
	// RFC 6672 section 2.2 puts no restriction on the target, the root included.
	testing.expect(
		t,
		check("example.", ".", "a.example.", "a."),
		"a DNAME to the root should leave the prefix alone",
	)
	testing.expect(
		t,
		check("example.", ".", "x.y.example.", "x.y."),
		"a multi-label prefix under a DNAME to the root should carry over whole",
	)
	testing.expect(
		t,
		check(".", "target.example.", "a.", "a.target.example."),
		"a DNAME at the root should redirect what is below it",
	)
	testing.expect(
		t,
		!check("example.", ".", "a.example.", "b."),
		"a DNAME to the root must still refuse a prefix it did not produce",
	)

	// The redirect an attacker would want.
	testing.expect(
		t,
		!check("dnametest.", "target.example.", "a.dnametest.", "attacker.example."),
		"a target the DNAME did not produce must be refused",
	)
	testing.expect(
		t,
		!check("dnametest.", "target.example.", "a.dnametest.", "b.target.example."),
		"the right suffix with the wrong prefix must be refused",
	)
	testing.expect(
		t,
		!check("dnametest.", "target.example.", "a.dnametest.", "a.target.example.evil."),
		"a target that merely starts the same must be refused",
	)

	// A DNAME never applies to its own name.
	testing.expect(
		t,
		!check("dnametest.", "target.example.", "dnametest.", "target.example."),
		"a DNAME does not redirect its own owner",
	)
	testing.expect(
		t,
		!check("dnametest.", "target.example.", "a.elsewhere.", "a.target.example."),
		"a name outside the DNAME's own subtree is not redirected by it",
	)
	free_all(context.temp_allocator)
}

/*
A second, unsigned CNAME beside the one the DNAME produced is not vouched for.

The DNAME rescue exists because RFC 6672 section 3.4.1 has the responder
synthesize its CNAME unsigned, the DNAME being what carries the authority. The
verdict it produces names an RRset, though, and the prune keeps everything
matching that name, type and class - so asking whether *one* record is covered
and then vouching for the set would let a second CNAME at the same owner go out
under the AD bit, pointing wherever the sender chose, with nothing having signed
it or looked at it.

Reachable by whoever writes the answer: a malicious upstream, or anyone on the
path to a plain UDP or TCP one. A zone may not publish two CNAMEs at one name
(RFC 1034 section 3.6.2) and a DNAME synthesizes exactly one, so a set carrying
a second is not one a DNAME produced.
*/
@(test)
test_a_second_cname_beside_a_dname_synthesis_is_not_authenticated :: proc(t: ^testing.T) {
	v := scenario_validator(&DNAME_FIXTURES, DNAME_ANCHOR)
	defer destroy_validator(v)

	msg, derr := dns.decode_message(scenario_fixture(DNAME_FIXTURES, "dname_answer"), context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// The synthesized CNAME, plus one the sender added at the same owner.
	answer := make([dynamic]dns.Record, 0, len(msg.answer) + 1, context.temp_allocator)
	planted := false
	for rec in msg.answer {
		append(&answer, rec)
		if rec.type == .CNAME && !planted {
			append(
				&answer,
				dns.Record {
					name = rec.name,
					type = .CNAME,
					class = rec.class,
					ttl = rec.ttl,
					data = dns.Rdata_Name{name = "evil.example."},
				},
			)
			planted = true
		}
	}
	if !testing.expect(t, planted, "the fixture carried no CNAME to sit beside") {
		return
	}
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "a.dnametest.", .A, tampered, fixture_now())
	if result.status == .Secure {
		// If the verdict stands, the planted record must not be in what it covers.
		out, ok := strip_unauthenticated(tampered, result, context.temp_allocator)
		if !testing.expect(t, ok, "the pruned response should rebuild") {
			return
		}
		pruned, perr := dns.decode_message(out, context.temp_allocator)
		if !testing.expect_value(t, perr, dns.Decode_Error.None) {
			return
		}
		for rec in pruned.answer {
			name, is_name := rec.data.(dns.Rdata_Name)
			if !is_name {
				continue
			}
			testing.expectf(
				t,
				name.name != "evil.example.",
				"an unsigned CNAME to %s went out under AD beside a DNAME synthesis",
				name.name,
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
The CNAME a DNAME synthesized carries no signature of its own, so its ceiling
under RFC 4035 section 5.3.3 is the DNAME's: it goes out with the TTL it came
with, held to the DNAME's signature, and never with zero for want of one (#337).
*/
@(test)
test_a_synthesized_cname_keeps_its_ttl :: proc(t: ^testing.T) {
	v := scenario_validator(&DNAME_FIXTURES, DNAME_ANCHOR)
	defer destroy_validator(v)

	wire := scenario_fixture(DNAME_FIXTURES, "dname_answer")
	result := validate(v, "a.dnametest.", .A, wire, fixture_now())
	testing.expect_value(t, result.status, Status.Secure)
	out, ok := strip_unauthenticated(wire, result)
	if !testing.expect(t, ok, "the prune failed") {
		return
	}
	// Undecoded, the answer would read as holding no CNAME at all.
	served, serr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, serr, dns.Decode_Error.None) {
		return
	}
	cnames := 0
	for rec in served.answer {
		if rec.type == .CNAME {
			cnames += 1
			testing.expect_value(t, rec.ttl, u32(3600))
		}
	}
	testing.expect_value(t, cnames, 1)
	free_all(context.temp_allocator)
}

/*
The same redirection with the root as the DNAME's target: `drtest. DNAME .`,
and `a.drtest.` synthesized to `a.` (RFC 6672 section 2.2 puts no restriction
on the target). Generated - `testdata/gen/sign_fixtures.py`, scenario
`dname_to_root`.
*/

@(private = "file")
DNAME_ROOT_ANCHOR :: ". IN DS 38011 15 2 9F36BC8BBE370FB49D208DB0E2E102AC7F52EE2727B7DE33100CE52BAB1738B2"

@(private = "file")
DNAME_ROOT_FIXTURES := []Fixture{
	{
		key   = "dr_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f25507178926f8a6e8349f1621f6d6c59" +
			"ae8cd552bd7c7bdc5b661a3b6d243c5300002e000100000e10005300300f0000000e107d3b18206a478820947b005797" +
			"ead9ffb0bed0f9dc1ca7269fd80da2deeb67842f497c2d70ca734dfb5cc0cca73fc3222cf7428f01d65ba2e628a4ce82" +
			"75abfb4b1d8d50aad3d5b61fef0c",
	},
	{
		key   = "dr_ds",
		name  = "drtest.",
		type  = .DS,
		wire  = "1234858000010002000000000664727465737400002b00010664727465737400002b000100000e1000248caa0f02263d" +
			"0e6094fafd9e33ee754b2afccc181fd90915777bf075f0976b8ccf2c41c10664727465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820947b00ce97b7173133293059bdc107be6b3a162407c623fc91ed341838594cb4" +
			"b8ca4ce95ce7a4cdb99f0fed41f41458d22fadd178e4ca5e16bc19d7d536eca340bc04",
	},
	{
		key   = "dr_dnskey",
		name  = "drtest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000006647274657374000030000106647274657374000030000100000e1000240101030f87d9" +
			"37ab655d1be48be7e8e31b7563e40ebf8f5d2cec690319a4903c148b61370664727465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a4788208caa06647274657374004e5e99d45a6c1ec293b1e1d7a4e4878ef3a2f558790d" +
			"d15a16498ff11b386731a0492d9ccd97ef4e4b4753df8b775ba64c9268467a244efff42c9cbad943f509",
	},
	{
		key   = "dr_answer",
		name  = "a.drtest.",
		type  = .A,
		wire  = "123485800001000300000000016106647274657374000001000106647274657374000027000100000e10000100066472" +
			"7465737400002e000100000e10005a00270f0100000e107d3b18206a4788208caa0664727465737400dc7411eb334c97" +
			"42708845a61c8253bc12f43956c7926f4f4a3489c1e8edb0d85cc37dd321708e4d51396eaba67b5b44dfa9444519e059" +
			"5d44b3c072024d990c016106647274657374000005000100000e100003016100",
	},
	{
		key   = "dr_answer_mismatched",
		name  = "a.drtest.",
		type  = .A,
		wire  = "123485800001000300000000016106647274657374000001000106647274657374000027000100000e10000100066472" +
			"7465737400002e000100000e10005a00270f0100000e107d3b18206a4788208caa0664727465737400dc7411eb334c97" +
			"42708845a61c8253bc12f43956c7926f4f4a3489c1e8edb0d85cc37dd321708e4d51396eaba67b5b44dfa9444519e059" +
			"5d44b3c072024d990c016106647274657374000005000100000e100003016200",
	},
}

@(test)
test_dname_to_the_root_validates :: proc(t: ^testing.T) {
	result := scenario_validate(&DNAME_ROOT_FIXTURES, "a.drtest.", .A, scenario_fixture(DNAME_ROOT_FIXTURES, "dr_answer"), DNAME_ROOT_ANCHOR)
	testing.expectf(
		t,
		result.status == .Secure,
		"a DNAME to the root should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_dname_to_the_root_refuses_a_cname_it_did_not_produce :: proc(t: ^testing.T) {
	result := scenario_validate(&DNAME_ROOT_FIXTURES, "a.drtest.", .A, scenario_fixture(DNAME_ROOT_FIXTURES, "dr_answer_mismatched"), DNAME_ROOT_ANCHOR)
	testing.expectf(
		t,
		result.status != .Secure,
		"a CNAME a DNAME to the root could not have produced was accepted (%v, %q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
