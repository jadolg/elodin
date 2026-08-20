package dnssec

import "core:mem"
import "core:testing"
import "core:time"
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
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f79b5562e8fe654f94078b112e8a98ba7" +
			"901f853ae695bed7e0e3910bad04966400002e000100000e10005300300f0000000e106c5048a06a6dc3a08ed0006181" +
			"ffd430f869c1e25cc602eaa481b7ed979d4b66748967831f52e117e0e00cc6fd4a336e3149a82f527e4d5bf26a0f5a81" +
			"cdd8929b7c051e25ace1b4469902",
	},
	{
		key   = "dname_zone_ds",
		name  = "dnametest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000009646e616d657465737400002b000109646e616d657465737400002b000100000e100024" +
			"d2010f025fd5e7854b4379b0f20d894b839b0d5ea0e05e4f261af2faf7933f7b2c9655fb09646e616d65746573740000" +
			"2e000100000e100053002b0f0100000e106c5048a06a6dc3a08ed000a457d9b878f6fa529ddc5c8eccf7a7f11fd7f022" +
			"0de45040f18bbce9148630e965b29fbb80d903cf3c830bf0d98bea9c87582c07e4a1554da63e2da1be516800",
	},
	{
		key   = "dname_zone_dnskey",
		name  = "dnametest.",
		type  = .DNSKEY,
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
		wire  = "123485800001000300000000016109646e616d6574657374000001000109646e616d6574657374000027000100000e10" +
			"001006746172676574076578616d706c650009646e616d657465737400002e000100000e10005d00270f0100000e106c" +
			"5048a06a6dc3a0d20109646e616d657465737400d4034a2983ff550a934d9de59c7901bc39e837429a5109b750a2a08b" +
			"6e29f2de80f1df0ce28e76ad293b66a50725aae4f082f47129b643320d34db50590e270e016109646e616d6574657374" +
			"000005000100000e1000120861747461636b6572076578616d706c6500",
	},
}

@(private = "file")
dname_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in DNAME_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
dname_fixture :: proc(key: string) -> []u8 {
	for f in DNAME_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(private = "file")
dname_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(DNAME_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(dname_query, nil, Options{anchors = anchors})
}

@(test)
test_dname_zone_chain_is_sound :: proc(t: ^testing.T) {
	/*
	The control. These fixtures are generated, so if the canonical form they
	were built against ever drifts from the one the validator computes, the
	tests below would start reporting on the drift rather than on DNAME. This
	walks the synthetic chain on its own: root anchor, DS, DNSKEY.
	*/
	v := dname_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, "dnametest.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
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
	v := dname_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "a.dnametest.", .A, dname_fixture("dname_answer"), time.unix(FIXTURE_TIME, 0))
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
	v := dname_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(
		v,
		"a.dnametest.",
		.A,
		dname_fixture("dname_answer_mismatched"),
		time.unix(FIXTURE_TIME, 0),
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
and then vouching for the set let a second CNAME at the same owner go out under
the AD bit, pointing wherever the sender chose. Nothing signed it and nothing
looked at it.

Reachable by whoever writes the answer: a malicious upstream, or anyone on the
path to a plain UDP or TCP one. A zone may not publish two CNAMEs at one name
(RFC 1034 section 3.6.2) and a DNAME synthesizes exactly one, so a set carrying
a second is not one a DNAME produced.
*/
@(test)
test_a_second_cname_beside_a_dname_synthesis_is_not_authenticated :: proc(t: ^testing.T) {
	v := dname_validator()
	if !testing.expect(t, v != nil, "cannot build the dname validator") {
		return
	}
	defer destroy_validator(v)

	msg, derr := dns.decode_message(dname_fixture("dname_answer"), context.temp_allocator)
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

	result := validate(v, "a.dnametest.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	if result.status == .Secure {
		// If the verdict stands, the planted record must not be in what it covers.
		out, ok := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
		if !testing.expect(t, ok, "the pruned response should rebuild") {
			return
		}
		pruned, _ := dns.decode_message(out, context.temp_allocator)
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
