package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"
import "elodin:loop"

/*
A walk whose DS question lands on a CNAME the parent signed (issue #552).

The walk asks for a DS at every label down to the queried name, and a name that
owns a CNAME answers that question with the CNAME - followed, by a resolver, to
its target, so the authority section carries the target's proof and says
nothing about the name asked for. `bitcoin.sipa.be.`, `dnsseed.bluematt.me.`,
`ing.ingdirect.es.` and `outlook.office.com.` all answer this way, and the
parent's signature over the CNAME is what says the name is no cut.

Generated - `testdata/gen/sign_fixtures.py`, scenario
`ds_question_answered_by_cname`. Ed25519 throughout, root replaced by a trust
anchor of the generator's own making.
*/

@(private = "file")
CN_ANCHOR :: ". IN DS 38238 15 2 40E1F56970C030AC9C29ECDE1BCBEC8BAF2F3A7EA2F10F0DAFCFAAB21D97D062"

@(private = "file")
CN_FIXTURES := []Fixture{

	{
		key   = "cn_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fa15de06394cbcc6242eaa59d54806a7d" +
			"b8c930cd535fd1c847e671286f49cfc100002e000100000e10005300300f0000000e107d3b18206a478820955e001aba" +
			"f9dfe8787dab8d8d0974506f758c460ac4686f416951207b1c43c768b5873818f8e5bb529a0522076a6ba31941ee91e0" +
			"25278a3984767c877646a3a3e900",
	},
	{
		key   = "cn_ds",
		name  = "cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000006636e7465737400002b000106636e7465737400002b000100000e100024bfff0f029095" +
			"3f5000b30c645214439149b19d38c41026c3635ceac33d529aa20be1729f06636e7465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820955e00f5a79cf84b2be059d6e40ab2acb3572bf15ca95b80f707f3d8012eafc2" +
			"bbdedeea11ef3f1411d8c4e48d3b791b7b5211bd80c784b094e51f49cbc17405419003",
	},
	{
		key   = "cn_dnskey",
		name  = "cntest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006636e74657374000030000106636e74657374000030000100000e1000240101030f90d7" +
			"e2bf3507ea374eb3d3e895b59e5bfa06084c951bd61f669cf62fe599227706636e7465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820bfff06636e7465737400f80ac7049ca9bc1b9030aed8d2e6c0789251a982eb84" +
			"954279ad27bbbdaf71580faae90255054715308645487f0cb670ad6f8d919812fc4194b5b8f3d35f7b0a",
	},
	{
		key   = "cn_alias_ds",
		name  = "alias.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020004000005616c69617306636e7465737400002b000105616c69617306636e746573740000050001" +
			"00000e10000c037a707306636e746573740005616c69617306636e7465737400002e000100000e10005a00050f020000" +
			"0e107d3b18206a478820bfff06636e7465737400f7f9cb69c2ca5bccf9be1ac0f4f5794128806d32b7ec5d3a432b4f4b" +
			"130b7fa05194d8671626323d6c4731ef625a872261aa0d1d8e84204f4e0d79e52c68080b06636e746573740000060001" +
			"00000e100032026e7306636e74657374000a686f73746d617374657206636e74657374000000000100000e1000000384" +
			"00093a800000012c06636e7465737400002e000100000e10005a00060f0100000e107d3b18206a478820bfff06636e74" +
			"65737400133ba91516584434584d8c511113ab982110fbbac80f8f65dfb91383f1cb2bd28e2c4b5a642f5064e3ac63c6" +
			"a292d2aded5dc84c967c009aa712d1fe834e5b0d037a707306636e7465737400002f000100000e10001006636e746573" +
			"74000006400000000003037a707306636e7465737400002e000100000e10005a002f0f0200000e107d3b18206a478820" +
			"bfff06636e74657374001c1d18f58de0cbb4f3edfd438e7fd15638ed298d5c10a87929af7407553b51fc31d5d705c28a" +
			"e898b689dd4afc36354d2e76ea76b22e8a9329e8b0137ca8b608",
	},
	{
		key   = "cn_lone_ds",
		name  = "lone.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000200010000046c6f6e6506636e7465737400002b0001046c6f6e6506636e7465737400000500010000" +
			"0e10000e0465646765076578616d706c6500046c6f6e6506636e7465737400002e000100000e10005a00050f0200000e" +
			"107d3b18206a478820bfff06636e746573740086689d99353846604a3e80813ff1551ddabb5594a9a934ce4b89940d1f" +
			"9308e29b3e9a75a2a3cdda4ed003c17b13a72711d53c8c79a6e60b67598e1f40bf8904076578616d706c650000060001" +
			"00000e100034026e73076578616d706c65000a686f73746d6173746572076578616d706c65000000000100000e100000" +
			"038400093a800000012c",
	},
	{
		key   = "cn_seed_ds",
		name  = "seed.alias.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000047365656405616c69617306636e7465737400002b000106636e74657374000006000100" +
			"000e100032026e7306636e74657374000a686f73746d617374657206636e74657374000000000100000e100000038400" +
			"093a800000012c06636e7465737400002e000100000e10005a00060f0100000e107d3b18206a478820bfff06636e7465" +
			"737400133ba91516584434584d8c511113ab982110fbbac80f8f65dfb91383f1cb2bd28e2c4b5a642f5064e3ac63c6a2" +
			"92d2aded5dc84c967c009aa712d1fe834e5b0d047365656405616c69617306636e7465737400002f000100000e100014" +
			"037a707306636e74657374000006200000000003047365656405616c69617306636e7465737400002e000100000e1000" +
			"5a002f0f0300000e107d3b18206a478820bfff06636e7465737400c933eac562cbdef32ea33b4a055b6c876b60a419c1" +
			"68f052c881c12000348feb976d289e0bc7375b47c8be48574e0bec1c08ee04b14051009ff70ea39660de08",
	},
	{
		key   = "cn_seed_answer",
		name  = "seed.alias.cntest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000100000000047365656405616c69617306636e746573740000010001047365656405616c6961730663" +
			"6e74657374000001000100000e100004c0000201",
	},
	{
		key   = "cn_bare_ds",
		name  = "bare.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000100040000046261726506636e7465737400002b0001046261726506636e7465737400000500010000" +
			"0e10000c037a707306636e746573740006636e74657374000006000100000e100032026e7306636e74657374000a686f" +
			"73746d617374657206636e74657374000000000100000e100000038400093a800000012c06636e7465737400002e0001" +
			"00000e10005a00060f0100000e107d3b18206a478820bfff06636e7465737400133ba91516584434584d8c511113ab98" +
			"2110fbbac80f8f65dfb91383f1cb2bd28e2c4b5a642f5064e3ac63c6a292d2aded5dc84c967c009aa712d1fe834e5b0d" +
			"037a707306636e7465737400002f000100000e10001006636e74657374000006400000000003037a707306636e746573" +
			"7400002e000100000e10005a002f0f0200000e107d3b18206a478820bfff06636e74657374001c1d18f58de0cbb4f3ed" +
			"fd438e7fd15638ed298d5c10a87929af7407553b51fc31d5d705c28ae898b689dd4afc36354d2e76ea76b22e8a9329e8" +
			"b0137ca8b608",
	},
	{
		key   = "cn_wild_ds",
		name  = "wild.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000400000477696c6406636e7465737400002b00010477696c6406636e7465737400000500010000" +
			"0e10000c037a707306636e74657374000477696c6406636e7465737400002e000100000e10005a00050f0100000e107d" +
			"3b18206a478820bfff06636e746573740041b4ea95bd07f6f7f656736d22be0cad74cfe44467fcba6a8034704f88f75b" +
			"f2478374eef8ba062e6803b963f36f103c4a3f223fa088b2841f7b2db7b5f7a80706636e74657374000006000100000e" +
			"100032026e7306636e74657374000a686f73746d617374657206636e74657374000000000100000e100000038400093a" +
			"800000012c06636e7465737400002e000100000e10005a00060f0100000e107d3b18206a478820bfff06636e74657374" +
			"00133ba91516584434584d8c511113ab982110fbbac80f8f65dfb91383f1cb2bd28e2c4b5a642f5064e3ac63c6a292d2" +
			"aded5dc84c967c009aa712d1fe834e5b0d037a707306636e7465737400002f000100000e10001006636e746573740000" +
			"06400000000003037a707306636e7465737400002e000100000e10005a002f0f0200000e107d3b18206a478820bfff06" +
			"636e74657374001c1d18f58de0cbb4f3edfd438e7fd15638ed298d5c10a87929af7407553b51fc31d5d705c28ae898b6" +
			"89dd4afc36354d2e76ea76b22e8a9329e8b0137ca8b608",
	},
	{
		key   = "cn_stray_ds",
		name  = "stray.cntest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020004000005737472617906636e7465737400002b000105737472617906636e746573740000050001" +
			"00000e10000c037a707306636e746573740005737472617906636e7465737400002e000100000e10005a00050f020000" +
			"0e107d3b18206a478820b54b06636e7465737400837c120ea440320e45c91fd8cf84df3429be89f5d4b241d9467e8bb6" +
			"c5dee2cabc062ebae2040af726ca0cb6ee372429aeef6a8d636a86d47bd943d00325430f06636e746573740000060001" +
			"00000e100032026e7306636e74657374000a686f73746d617374657206636e74657374000000000100000e1000000384" +
			"00093a800000012c06636e7465737400002e000100000e10005a00060f0100000e107d3b18206a478820bfff06636e74" +
			"65737400133ba91516584434584d8c511113ab982110fbbac80f8f65dfb91383f1cb2bd28e2c4b5a642f5064e3ac63c6" +
			"a292d2aded5dc84c967c009aa712d1fe834e5b0d037a707306636e7465737400002f000100000e10001006636e746573" +
			"74000006400000000003037a707306636e7465737400002e000100000e10005a002f0f0200000e107d3b18206a478820" +
			"bfff06636e74657374001c1d18f58de0cbb4f3edfd438e7fd15638ed298d5c10a87929af7407553b51fc31d5d705c28a" +
			"e898b689dd4afc36354d2e76ea76b22e8a9329e8b0137ca8b608",
	},
}

@(private = "file")
cn_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> (wire: []u8, ok: bool) {
	for f in CN_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
cn_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(CN_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(cn_query, nil, Options{anchors = anchors})
}

@(private = "file")
cn_fixture :: proc(key: string) -> []u8 {
	for f in CN_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(test)
test_a_cname_the_parent_signed_is_no_cut :: proc(t: ^testing.T) {
	// The CNAME is signed by `cntest.` at its own name, so the name is data in
	// `cntest.` and no delegation: the deepest zone is `cntest.`, and the walk
	// remembers the non-cut as it would one a denial proved. `alias.` has the
	// target's proof behind it, `lone.` only an unsigned SOA.
	v := cn_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	for name in ([]string{"alias.cntest.", "lone.cntest."}) {
		budget := query_budget(v)
		status, keys, zone := zone_trust(v, &budget, name, now, context.temp_allocator)
		testing.expectf(t, status == .Secure, "%s: got %v (%q)", name, status, budget.broken)
		testing.expect_value(t, zone, "cntest.")
		testing.expectf(t, len(keys) > 0, "%s: the zone should publish a key", name)
		_, _, non_cut := cache_get(v, name, loop.moment_now(), context.temp_allocator)
		testing.expectf(t, non_cut, "%s: the non-cut should be remembered", name)
	}
	free_all(context.temp_allocator)
}

@(test)
test_an_unsigned_delegation_under_a_cname_owner_is_insecure :: proc(t: ^testing.T) {
	// `seed.bitcoin.sipa.be.` in the issue: the walk has to pass the CNAME owner
	// to reach the delegation below it, which has no DS.
	v := cn_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "seed.alias.cntest.", .A, cn_fixture("cn_seed_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Insecure,
		"an answer from an unsigned delegation under a CNAME owner should be insecure, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_cname_that_does_not_speak_for_its_owner_is_no_proof :: proc(t: ^testing.T) {
	// Unsigned, signed as an expansion of `*.cntest.`, and signed by a key
	// `cntest.` does not publish: none of them is the parent saying the name is
	// its own, and the target's proof behind them says nothing about it either.
	v := cn_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	for name in ([]string{"bare.cntest.", "wild.cntest.", "stray.cntest."}) {
		budget := query_budget(v)
		status, _, _ := zone_trust(v, &budget, name, now, context.temp_allocator)
		testing.expectf(t, status == .Bogus, "%s: got %v", name, status)
		_, _, non_cut := cache_get(v, name, loop.moment_now(), context.temp_allocator)
		testing.expectf(t, !non_cut, "%s: should not be remembered as a non-cut", name)
	}
	free_all(context.temp_allocator)
}

@(test)
test_a_cname_step_out_of_verifications_is_undecided :: proc(t: ^testing.T) {
	// The CNAME was never checked, which is this server's limit and not the
	// zone's word: `Indeterminate`, and nothing remembered.
	v := cn_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	budget := query_budget(v)
	status, keys, _ := zone_trust(v, &budget, "cntest.", now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)

	budget.verifications = MAX_VERIFICATIONS_PER_QUERY
	// `lone.cntest.`, whose authority section holds nothing signed, so the
	// denial path behind this one has nothing to run out on.
	step, _ := zone_step(v, &budget, "cntest.", keys, "lone.cntest.", now, context.temp_allocator)
	end_walk(v, &budget)
	testing.expect_value(t, step, Step.Indeterminate)
	_, _, non_cut := cache_get(v, "lone.cntest.", loop.moment_now(), context.temp_allocator)
	testing.expect(t, !non_cut, "an unread CNAME should not be remembered as a non-cut")
	free_all(context.temp_allocator)
}
