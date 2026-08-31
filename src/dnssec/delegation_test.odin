package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Delegations no operator builds on purpose.

The captured fixtures in `fixtures_test.odin` cover the chain as it is actually
deployed, and that is the right control: real signatures from real zones catch a
canonicalisation bug that would otherwise agree with itself. What they cannot
reach is the shape an attacker arranges, or the shape a zone passes through for
one afternoon during a rollover, because nobody publishes those on the public
internet for us to capture.

So these are generated - `testdata/gen/sign_fixtures.py`, Ed25519 throughout,
the root replaced by a trust anchor of the generator's own making. Ed25519
signatures carry no per-signature randomness, so regenerating a scenario
produces the same bytes and the diff stays readable.

Each one turns on a single decision, and each of those decisions can fail in two
directions:

  - a DS set naming an algorithm we do not implement alongside one we do. Refuse
    the set and every zone mid rollover goes dark; accept the unknown DS as
    sufficient and an attacker who strips the usable one downgrades the zone to
    insecure. Neither is acceptable, so the answer must stay Secure by way of
    the DS we can follow.
  - a DS set naming *only* what we cannot implement, in the algorithm field and
    then in the digest field. RFC 6840 section 5.2 calls that an insecure
    delegation, not a broken one: the answer is served without the AD bit rather
    than refused, because a validator that cannot check something must treat it
    as unsigned rather than as forged.
  - an apex key published with the revoke bit set, RFC 5011. The DS matches it,
    because revoking is something the key's owner does rather than something the
    parent republishes - so the only thing standing between an attacker replaying
    a withdrawn key and a working chain of trust is the validator reading that
    bit.
*/

@(private = "file")
DG_ANCHOR :: ". IN DS 44320 15 2 C3683F50610E9C83A81DDD2772550043CFA72B6EAAE0B25024332EBAF39E8A99"

@(private = "file")
DG_FIXTURES := []Fixture{
	{
		key   = "dg_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fd2b3ce6ad6a85347f7b968151177f3b3" +
			"bb7ba273c7c165fd09d7db6088a67f7a00002e000100000e10005300300f0000000e107d3b18206a478820ad2000d2c2" +
			"ad767f43be51298dd67dbd599b3c8a7f1deb4973514e14903e7159f83429921b7f893ee73bb330b8f3538372ccbab008" +
			"a28eeba1a93955c58993ddad9a01",
	},
	{
		key   = "dg_ds",
		name  = "dgtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010003000000000664677465737400002b00010664677465737400002b000100000e100024ecbcfd02ca37" +
			"04aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce0664677465737400002b000100000e100024" +
			"ecbc0f029f614b9657d7993e35706328e6b70d15630626b9667f17ec8e3399052e1d888a0664677465737400002e0001" +
			"00000e100053002b0f0100000e107d3b18206a478820ad20002481101501fce3e4b18ce5519fb62ad70c0aaa3a86bb60" +
			"45f3a631bfa1e9a81a346434c41fb2c70a684ca03fe73bc881acac6894a9b118858a5ec283806df103",
	},
	{
		key   = "dg_dnskey",
		name  = "dgtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006646774657374000030000106646774657374000030000100000e1000240101030f1532" +
			"525e97ca5c39f69a2ae7acdb02080f16b1c01ba556d77f99507b3e207b2a0664677465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820ecbc0664677465737400934b83938a5478d61741e7e67891ed98a87ce5bb8232" +
			"eb562a0d3ea1c1ecba1ef38c73cb9abfd35e51babaf9eb1b636697a5db222b48922c140f0ce5402a7100",
	},
	{
		key   = "dg_answer",
		name  = "www.dgtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770664677465737400000100010377777706646774657374000001000100000e10" +
			"0004c0000201037777770664677465737400002e000100000e10005a00010f0200000e107d3b18206a478820ecbc0664" +
			"677465737400ca6d1e359004763a8fdb15eebebeafe330ef8c7276a75e3b4315a655eb7d39f97fac33f22ba097d89a66" +
			"e739d8b9546de8643cdf811ccc739c8a399895f10906",
	},
}

@(private = "file")
UA_ANCHOR :: ". IN DS 1073 15 2 A368A1FB450AD3071D7EF8878407CBC7FFD695FE4A9D9EA5259D1BDBF766FF3B"

@(private = "file")
UA_FIXTURES := []Fixture{
	{
		key   = "ua_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fc43973ad54ecfdc5f1733a4bc4e960c0" +
			"bce138cf37e3c985ca13d938b55fd45700002e000100000e10005300300f0000000e107d3b18206a4788200431008eee" +
			"de4bed6de8bd92eaee628226b8a0f4bd14acb5bf51b023d15fb9d77f0a2088ca39e4b7a2aa42ce59ea66842ad419d93f" +
			"1a1197a6d7b56db519b7d757ff0d",
	},
	{
		key   = "ua_ds",
		name  = "uatest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000675617465737400002b00010675617465737400002b000100000e10002478f2fd02ca37" +
			"04aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce0675617465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820043100a2f87aac0a7d69aa35696141f53444b0232db6bedd74c6edd615cb3bec" +
			"5b1a1672c716cbca7bdb72bd26d44a926aa0e436553c03ae5d96ba15cc0afaa88e4e05",
	},
	{
		key   = "ua_dnskey",
		name  = "uatest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006756174657374000030000106756174657374000030000100000e1000240101030fcb3b" +
			"4180c213d2fe0f0d27855dfdcb1399693bf3cadeb054b328b2d15bc061250675617465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a47882078f206756174657374002e6471c7115d7d00e4ea216b53cc392395baefd73a42" +
			"a6794aac29dd641353d5c322d82eec10adec01ba784e58d0fa2ab22241de9162cde8e15685d6b296b10a",
	},
	{
		key   = "ua_answer",
		name  = "www.uatest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770675617465737400000100010377777706756174657374000001000100000e10" +
			"0004c0000201037777770675617465737400002e000100000e10005a00010f0200000e107d3b18206a47882078f20675" +
			"61746573740017327ead80817fbb0f870e24e07470d2f0999a400c08b736d16e09a87926f9a12074a2b7a233a43c2ab7" +
			"abc840fba8f57b9255823070f700ca08d35ab372bc0a",
	},
}

@(private = "file")
UD_ANCHOR :: ". IN DS 37386 15 2 4AE958167E780CB0C0BBAAE25B785AEAF0618EC3E63280B5EF8AE9183E946A0B"

@(private = "file")
UD_FIXTURES := []Fixture{
	{
		key   = "ud_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f11ad3f548e7ab27bf7c7c2453f285931" +
			"9629c660af2d4a4168e476cf0e9f654f00002e000100000e10005300300f0000000e107d3b18206a478820920a009275" +
			"75d1548e22af1a8205296ba398c1b9b8ace52ebd3b3ee8c4c2e3cbd2aadd0c4560a299640af21a259274b12fbd1aeaac" +
			"7aa16f8db3a0f3907b398f867e08",
	},
	{
		key   = "ud_ds",
		name  = "udtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000675647465737400002b00010675647465737400002b000100000e1000243e700f03584b" +
			"64d60e0dd8be1d26889c981d5965b5d22dd77f36b8f1c76d2b7fca38ff870675647465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820920a007b2c655a43caef089caad1c808d6ad37cebb34977c3645b90378e88605" +
			"7ba262e64e9b9c226c2f0c8c7d829a5e7f8cd53551e002feb7c5b3fe56235bd75ed209",
	},
	{
		key   = "ud_dnskey",
		name  = "udtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006756474657374000030000106756474657374000030000100000e1000240101030fa008" +
			"24532ad9b4866a68bc08b5459057fc87ee79824d4d23257e78846be1663f0675647465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a4788203e7006756474657374002f7864d51935895bb619bab436ce72138726b548fabc" +
			"d49c38eb1ead484bc14d18c9328c17984edb204cc08adfd3a6aaa673898f5c04179e07b62e89c583cc00",
	},
	{
		key   = "ud_answer",
		name  = "www.udtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770675647465737400000100010377777706756474657374000001000100000e10" +
			"0004c0000201037777770675647465737400002e000100000e10005a00010f0200000e107d3b18206a4788203e700675" +
			"647465737400e8e692d9aeedd2ae03796087fd0dedda2a30194de21797358e5bf9aec2cdbad4b4418c82aa0bd8b49248" +
			"53723f4cc0fd7ced47732593ff4d901ad5e75ef63d08",
	},
}

@(private = "file")
RV_ANCHOR :: ". IN DS 53642 15 2 BA63F9960D984D6DC514DA7ED851A058732343699E82DAF822CB4E26AA4EE1FA"

@(private = "file")
RV_FIXTURES := []Fixture{
	{
		key   = "rv_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fa533ff6ccb745bf3b62870ad2885252c" +
			"1c91ce71f7ff9e76dfceb879627910af00002e000100000e10005300300f0000000e107d3b18206a478820d18a008271" +
			"c3fb5ac39b64a6123d545c3e42226f02f60e90d33fd9a98ed4e39b29fe6c7fe64b87d644a8aa99ed4f577869cff8aa41" +
			"eebcdd18bab888871ab2aae8370d",
	},
	{
		key   = "rv_ds",
		name  = "rvtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000672767465737400002b00010672767465737400002b000100000e100024e0390f02e831" +
			"8e9943aa3beaf2441ec74305a4ffca854e578069492792ca1cab36ecb36b0672767465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820d18a002f9dad1d7db30b3e0b82053baa0577f71c9086fd18defe3ab7a0ae7be3" +
			"a3054734ee0cc8628f7e3913e3ab750626a0dc0eef8098bba2d2f2b06020ca0de0080e",
	},
	{
		key   = "rv_dnskey",
		name  = "rvtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006727674657374000030000106727674657374000030000100000e1000240181030f1da3" +
			"bf58cc695535f99c04190578a760b19efbf4f3a905f3c28d550996c9dcee0672767465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820e0390672767465737400e0f9c318ac287d118237370066aae7faa56536772c36" +
			"1b49d19de748f5f4813063fc244459c74c190536cb5c32b57c7f90a1396b155ef082412614293a29200d",
	},
	{
		key   = "rv_answer",
		name  = "www.rvtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770672767465737400000100010377777706727674657374000001000100000e10" +
			"0004c0000201037777770672767465737400002e000100000e10005a00010f0200000e107d3b18206a478820e0390672" +
			"7674657374003e91ef58cd6a1796bbdf0eaf85abe61b832b8c7037dff312ac2df45108d4beb3e248751734db337fc1e6" +
			"724ad472db7ec65ea2d9ac128c6a4bd861460508ed09",
	},
}

@(private = "file")
UF_ANCHOR :: ". IN DS 51757 15 2 87FA83EDF4BE0B606BA146148A99FD163B005DDFDA45C002D2788DF45E9D6AA9"

@(private = "file")
UF_FIXTURES := []Fixture{
	{
		key   = "uf_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f206bcadfddd24b03c8d6383c0f445c4c" +
			"c182f48629dacf05b88ed9c16e2695f800002e000100000e10005300300f0000000e107d3b18206a478820ca2d00161d" +
			"0fc6fd33816ac96a41122d0304d1fcd3c02590f19797e0145e6165b6bfcb382282844b31b8f93d3b77f4a06ad76079e6" +
			"767ef28356a127fea6a8fcfd100f",
	},
	{
		key   = "uf_ds",
		name  = "uftest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010003000000000675667465737400002b00010675667465737400002b000100000e1000244a2c0f02502d" +
			"4adc0eb887e32b524c45ff33e5a21796f6e152e2c969347c64264d8249520675667465737400002b000100000e100024" +
			"4a2cfd02ca3704aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce0675667465737400002e0001" +
			"00000e100053002b0f0100000e107d3b18206a478820ca2d00aee0fbb4130829bfb45488365142ead38ae01691503015" +
			"8f3401b35291f9d04fa10bc7bad4d4ded43b696d540d38787b055a31388c06fe76adeb652fc2f9ba01",
	},
	{
		key   = "uf_dnskey",
		name  = "uftest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006756674657374000030000106756674657374000030000100000e1000240101030f3b22" +
			"3d41c8ea7339bfcaf02d4cbef41cc379718a7c465dd07c0b2d662f62b8d10675667465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a4788204a2c06756674657374006227c26d9f21d1176e3878a89a86741130fcb5830493" +
			"e97e6b753e64a46483d28354988cbea5353daabd92192ac384c4936feb506cf582f8bdee75c17b78880c",
	},
	{
		key   = "uf_answer",
		name  = "www.uftest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770675667465737400000100010377777706756674657374000001000100000e10" +
			"0004c0000201037777770675667465737400002e000100000e10005a00010f0200000e107d3b18206a4788204a2c0675" +
			"6674657374003de8296155c34f68a8590a0a2c66be9972e6513f2046efbbf219f89eabbd8910852ad5abebc177d8eb0e" +
			"91a55495c38c8c42e6422670629df1cc69efe250a809",
	},
}

@(private = "file")
scenario_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	fixtures := (^[]Fixture)(ctx)^
	for f in fixtures {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
scenario_validator :: proc(anchor_text: string, fixtures: ^[]Fixture) -> ^Validator {
	anchor, ok := parse_trust_anchor(anchor_text, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(scenario_query, rawptr(fixtures), Options{anchors = anchors})
}

@(private = "file")
scenario_fixture :: proc(fixtures: []Fixture, key: string) -> []u8 {
	for f in fixtures {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(test)
test_a_ds_for_an_unknown_algorithm_does_not_break_a_rollover :: proc(t: ^testing.T) {
	/*
	`dgtest.` publishes two DS records: one naming algorithm 253, which this
	build does not implement, and one naming Ed25519, which it does. RFC 6840
	section 5.11 has the validator follow what it can. Reading the set as
	unusable because part of it is unusable would take every zone adding an
	algorithm off the air for the length of its rollover.
	*/
	v := scenario_validator(DG_ANCHOR, &DG_FIXTURES)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.dgtest.", .A, scenario_fixture(DG_FIXTURES, "dg_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"a DS set with one usable algorithm should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_ds_set_of_only_unknown_algorithms_is_insecure_not_bogus :: proc(t: ^testing.T) {
	/*
	`uatest.` publishes one DS, for algorithm 253. Nothing in the chain can be
	followed past it. RFC 6840 section 5.2 makes that an insecure delegation:
	the name still resolves, without the AD bit. Calling it bogus instead would
	mean this server takes a zone off the air for signing with something it has
	not heard of - the failure mode that keeps validators from ever adopting a
	new algorithm.
	*/
	v := scenario_validator(UA_ANCHOR, &UA_FIXTURES)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.uatest.", .A, scenario_fixture(UA_FIXTURES, "ua_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Insecure,
		"a delegation we cannot follow is insecure, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_ds_set_of_only_unknown_digests_is_insecure_not_bogus :: proc(t: ^testing.T) {
	/*
	The same conclusion reached through the other field. `udtest.`'s DS names
	Ed25519, which we implement, and digest type 3 - GOST, withdrawn by RFC 6986
	- which we do not. Both fields have to be consulted, and checking only the
	algorithm would have this delegation look followable right up to the point
	the digest fails to match, which is bogus rather than insecure.
	*/
	v := scenario_validator(UD_ANCHOR, &UD_FIXTURES)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.udtest.", .A, scenario_fixture(UD_FIXTURES, "ud_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Insecure,
		"a digest we cannot compute is an insecure delegation, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_revoked_apex_key_cannot_carry_the_chain :: proc(t: ^testing.T) {
	/*
	`rvtest.` publishes one apex key, with the revoke bit set, and the parent's
	DS is computed over that key exactly as published - so the hash matches and
	the only thing left to stop it is RFC 5011's rule that a revoked key signs
	nothing. Ignoring the bit would leave a key its owner has publicly withdrawn
	still able to vouch for the zone, which is the entire purpose of revoking
	one.

	The zone is then signed by a key that may not sign, which is a broken zone
	rather than an unsigned one: the parent says there is a chain here, and there
	is not.
	*/
	v := scenario_validator(RV_ANCHOR, &RV_FIXTURES)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.rvtest.", .A, scenario_fixture(RV_FIXTURES, "rv_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Bogus,
		"a zone whose only key is revoked cannot validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_an_unfollowable_ds_beside_an_unknown_one_is_still_insecure :: proc(t: ^testing.T) {
	/*
	`uftest.`'s DS set holds one record naming Ed25519 and SHA-256 - both of
	which we implement, so the set is not refused out of hand - whose digest
	matches no key the zone publishes, and one naming algorithm 253, which we
	cannot evaluate at all.

	The first check, the one that spares a pointless DNSKEY lookup, passes this
	set through. So the verdict has to be reached the second time, after the
	keys are in hand and none of them satisfies the DS we could follow. A DS we
	cannot read may well be the one that was right, so the honest answer is an
	insecure delegation and not a forgery.

	Without this scenario the two checks cover for each other: break either one
	and the other still produces `Insecure`, and nothing fails.
	*/
	v := scenario_validator(UF_ANCHOR, &UF_FIXTURES)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.uftest.", .A, scenario_fixture(UF_FIXTURES, "uf_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Insecure,
		"a DS set we cannot follow to a key is insecure, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(private = "file")
Counting_Ctx :: struct {
	fixtures: []Fixture,
	dnskey:   int,
}

@(private = "file")
counting_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	counter := (^Counting_Ctx)(ctx)
	if type == .DNSKEY && !dns.name_equal_fold(name, ".") {
		counter.dnskey += 1
	}
	for f in counter.fixtures {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(test)
test_a_ds_set_with_nothing_usable_costs_no_dnskey_lookup :: proc(t: ^testing.T) {
	/*
	The other half of the pair above, pinning the check that comes first.

	`uatest.` publishes a single DS for an algorithm we do not implement. The
	delegation is insecure whichever check notices, so the verdict alone cannot
	tell us that the early one still runs - what tells us is that the zone's
	DNSKEY set is never asked for. That is not only a saved round trip: every
	lookup comes out of a per-query budget, and spending one to fetch keys that
	cannot be checked against anything is how a chain walk runs out of
	allowance on a name that had a perfectly good answer waiting.
	*/
	anchor, ok := parse_trust_anchor(UA_ANCHOR, context.temp_allocator)
	testing.expect(t, ok, "the anchor should parse")
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor

	counter := Counting_Ctx {
		fixtures = UA_FIXTURES,
	}
	v := make_validator(counting_query, &counter, Options{anchors = anchors})
	defer destroy_validator(v)

	result := validate(v, "www.uatest.", .A, scenario_fixture(UA_FIXTURES, "ua_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Insecure)
	testing.expectf(
		t,
		counter.dnskey == 0,
		"a delegation with no usable DS should not send us after its keys, but we asked %d time(s)",
		counter.dnskey,
	)
	free_all(context.temp_allocator)
}
