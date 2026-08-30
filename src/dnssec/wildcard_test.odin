package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A synthetic NSEC3 zone reproducing a shape real traffic actually sends:
`oisd.nl` answers every name under it from an apex wildcard (`*.oisd.nl.`) and,
per RFC 5155 sections 7.2.6 and 8.8, proves the wildcard was allowed to answer
with a single NSEC3 RR covering the "next closer" name - no separate NSEC3
matching the closest encloser, that encloser being named by the wildcard the
signature was made over rather than searched for among the records. Quad9
validates that exact response and sets the AD bit.

Generated rather than captured, for the same reason as `dname_test.odin`:
reproducibility, and a signature window that does not rot. Ed25519 throughout,
root replaced by a trust anchor of its own. `wc_wildcard_answer` is the
single-NSEC3 proof shape above, for `sub.wildcardtest.`; `wc_wildcard_answer_no_cover`
is the attack the proof exists to stop - a wildcard-signed RRset for
`other.wildcardtest.` beside an NSEC3 that matches the zone apex but covers
nothing near `other.wildcardtest.`, so the "next closer does not exist" half was
never supplied. `closest_encloser_test.odin` covers the other half, where the
records do carry a cover but for the next closer of a different wildcard.
*/

@(private = "file")
WILDCARD_ANCHOR :: ". IN DS 62786 15 2 BC2B09FCBE5A67767B184CAACEE0CADDDF25E5483A97E8C2FEFAF771B4FCB629"

@(private = "file")
WILDCARD_FIXTURES := []Fixture{
	{
		key   = "wc_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030ff4826d5e29ec166dd1a984670cd00ffc" +
			"25bd67c7e6a1633aaa1170aaaeb13b4c00002e000100000e10005300300f0000000e106c5048a06a6dc3a0f54200de5d" +
			"0c1b0ea76282b8ff78374cad43cb7493e4de7de8d86dcd0877d68a6df44522e754962878c10f7c6f6265e974292e0392" +
			"fc01974c12498fd88ccce5b6c403",
	},
	{
		key   = "wc_wildcardtest_ds",
		name  = "wildcardtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000c77696c64636172647465737400002b00010c77696c64636172647465737400002b0001" +
			"00000e1000242dce0f0224411bd43ba86dfa16033a9dada582c4d6b9fac41297728307416643bede24a70c77696c6463" +
			"6172647465737400002e000100000e100053002b0f0100000e106c5048a06a6dc3a0f54200269938a3744189751bebe0" +
			"d40c78c7677240582eef8d3be0921033a6b15c7567e00d3528144d5effd18beace0a271e27c63db447e0806bc034be7b" +
			"04c767c30e",
	},
	{
		key   = "wc_wildcardtest_dnskey",
		name  = "wildcardtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000c77696c64636172647465737400003000010c77696c6463617264746573740000300001" +
			"00000e1000240101030f1539353867c32e5572052d9ada1ba5078aafd733dc8402acf12eccc38ea09cc90c77696c6463" +
			"6172647465737400002e000100000e10006000300f0100000e106c5048a06a6dc3a02dce0c77696c6463617264746573" +
			"74008346e6a42bf1d44222a42797cdc5d4413ff10615bdfe4f3e31ea785f0c2e5aba07568bd37d84a2dc879eb0f0def0" +
			"14736422ad6d91188dc16420c9fc05e2eb02",
	},
	{
		key   = "wc_sub_ds",
		name  = "sub.wildcardtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000037375620c77696c64636172647465737400002b000120723863386b706b3265386e6d69" +
			"63306c3234626f64626a72677373673264656d0c77696c64636172647465737400003200010000003c001a0100000000" +
			"14da188a6682722f693015111786ae7b87390135d820723863386b706b3265386e6d6963306c3234626f64626a726773" +
			"73673264656d0c77696c64636172647465737400002e00010000003c006000320f020000003c6c5048a06a6dc3a02dce" +
			"0c77696c6463617264746573740085f11ff6a08cdd5297ddf8dd0d5d9e59d83fee10e65cdf16db83c81cc5987a9ae168" +
			"1f2b791afb7250a0bdb3f2fcba8b6564db4e78c05969a6f5c24f2e736101",
	},
	{
		key   = "wc_wildcard_answer",
		name  = "sub.wildcardtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200020000037375620c77696c6463617264746573740000010001037375620c77696c646361726474" +
			"657374000001000100000e100004c0000201037375620c77696c64636172647465737400002e000100000e1000600001" +
			"0f0100000e106c5048a06a6dc3a02dce0c77696c64636172647465737400ed9a557337f35cc312529045b73e5709eb23" +
			"cd005aefec0064c1e0440718661e93d185ac32d35f4d8eff8bc6bb2a28bd2be0caa084f48c3d5c9901bdbd91cd0f2072" +
			"3863386b706b3265386e6d6963306c3234626f64626a72677373673264656d0c77696c64636172647465737400003200" +
			"010000003c001a010000000014da188a6682722f693015111786ae7b87390135d820723863386b706b3265386e6d6963" +
			"306c3234626f64626a72677373673264656d0c77696c64636172647465737400002e00010000003c006000320f020000" +
			"003c6c5048a06a6dc3a02dce0c77696c6463617264746573740085f11ff6a08cdd5297ddf8dd0d5d9e59d83fee10e65c" +
			"df16db83c81cc5987a9ae1681f2b791afb7250a0bdb3f2fcba8b6564db4e78c05969a6f5c24f2e736101",
	},
	{
		key   = "wc_other_ds",
		name  = "other.wildcardtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000056f746865720c77696c64636172647465737400002b000120616a66347361626f616134" +
			"73643372743863376f6a6a68666b646368396168650c77696c64636172647465737400003200010000003c001a010000" +
			"00001454de4e29785289c68f7d430f89ce2fa35914aa3020616a66347361626f61613473643372743863376f6a6a6866" +
			"6b646368396168650c77696c64636172647465737400002e00010000003c006000320f020000003c6c5048a06a6dc3a0" +
			"2dce0c77696c646361726474657374006f46391dab157a438f0783438710aaead52e54b8d3c93d9697fd6b37a9a7ef9b" +
			"82031b7998bbb1e3bed86f554df3abca78053ab0a1cf787cf3d9a6c45c6d0f01",
	},
	{
		key   = "wc_wildcard_answer_no_cover",
		name  = "other.wildcardtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200020000056f746865720c77696c6463617264746573740000010001056f746865720c77696c6463" +
			"61726474657374000001000100000e100004c0000201056f746865720c77696c64636172647465737400002e00010000" +
			"0e10006000010f0100000e106c5048a06a6dc3a02dce0c77696c64636172647465737400ed9a557337f35cc312529045" +
			"b73e5709eb23cd005aefec0064c1e0440718661e93d185ac32d35f4d8eff8bc6bb2a28bd2be0caa084f48c3d5c9901bd" +
			"bd91cd0f206c6669696a69656e387675633732326e6b35646e74336e7031613172726539620c77696c64636172647465" +
			"737400003200010000003c001a010000000014abe529c9d747fcc38857a15b7e8ef90a83bdbd13206c6669696a69656e" +
			"387675633732326e6b35646e74336e7031613172726539620c77696c64636172647465737400002e00010000003c0060" +
			"00320f020000003c6c5048a06a6dc3a02dce0c77696c64636172647465737400cf80dd79661048ed950dc6ec22445e32" +
			"5ce94bd6997e234564d58a3582db0cd17979f888305dce135d3f102cba26cd9c7dcdb2a616bdd32fe649e9f82b60f30a",
	},
}

@(private = "file")
wildcard_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in WILDCARD_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
wildcard_fixture :: proc(key: string) -> []u8 {
	for f in WILDCARD_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(private = "file")
wildcard_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(WILDCARD_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(wildcard_query, nil, Options{anchors = anchors})
}

@(test)
test_wildcard_zone_chain_is_sound :: proc(t: ^testing.T) {
	// The control, as in test_dname_zone_chain_is_sound: if the canonical form
	// these fixtures were signed against ever drifts from the one the
	// validator computes, this is what starts reporting the drift.
	v := wildcard_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, "wildcardtest.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "wildcardtest.")
	testing.expect(t, len(keys) > 0, "the zone should publish a key")
	free_all(context.temp_allocator)
}

@(test)
test_wildcard_answer_with_apex_closest_encloser_validates :: proc(t: ^testing.T) {
	/*
	`sub.wildcardtest.` does not exist; `*.wildcardtest.` answers for it. The
	zone proves that the way oisd.nl's nameserver does for names under it: one
	NSEC3 RR covering `sub.wildcardtest.` (the next closer name), and nothing
	matching `wildcardtest.` itself - the closest encloser is the apex, which
	the signature's own label count already names. A validator that goes
	looking for an in-band NSEC3 match for it instead rejects this as bogus
	even though it is a sound proof and every other validator accepts it
	(confirmed against Quad9's live answer for big.oisd.nl, which sets the AD
	bit on exactly this shape).
	*/
	v := wildcard_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "sub.wildcardtest.", .A, wildcard_fixture("wc_wildcard_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"a wildcard answer whose closest encloser is the zone apex should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_wildcard_answer_without_next_closer_cover_is_bogus :: proc(t: ^testing.T) {
	/*
	The attack the wildcard proof exists to stop: an NSEC3 RR matching the zone
	apex proves nothing about whether `other.wildcardtest.` itself has a real
	record. Skipping the "next closer is covered" check would let this
	wildcard-signed RRset - genuinely signed, just for the wrong name - stand
	in for any name in the zone, including ones with real records of their own.
	*/
	v := wildcard_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(
		v,
		"other.wildcardtest.",
		.A,
		wildcard_fixture("wc_wildcard_answer_no_cover"),
		time.unix(FIXTURE_TIME, 0),
	)
	testing.expectf(
		t,
		result.status == .Bogus,
		"a wildcard answer whose next-closer name was never covered should be bogus, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
