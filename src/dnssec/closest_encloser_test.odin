package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A synthetic NSEC3 zone for the half of the wildcard proof that is about *which*
wildcard answered.

RFC 5155 section 8.8 has the verified RRset hand the validator its closest
encloser - "the immediate ancestor to the generating wildcard" - and only then
asks for an NSEC3 covering the next closer name. Reading the encloser off the
denial records instead lets the sender choose it, and `cetest.` is the zone
where that choice matters: it holds both `*.cetest.` and `*.y.cetest.`, and
`y.cetest.` is a real name with an A record of its own.

`ce_inner_wildcard` and `ce_outer_wildcard` carry the *same* authority section -
one NSEC3 matching `y.cetest.`, one covering `x.y.cetest.` - and differ only in
which wildcard signed the answer. The first is `*.y.cetest.`, the wildcard that
genuinely applies to `x.y.cetest.`; its next closer is `x.y.cetest.`, which the
authority covers, so it validates. The second is `*.cetest.`, a signature an
attacker can lift from any name directly under the apex; its next closer is
`y.cetest.`, which exists, so no NSEC3 can ever cover it and the answer has to
be refused. A validator that walks up from the queried name until some NSEC3
matches stops at `y.cetest.` in both cases and accepts both, turning what should
be `y.cetest.`'s own answer into whatever the apex wildcard holds.

Generated rather than captured, for the same reason as `wildcard_test.odin`:
reproducibility, and a signature window that does not rot. Ed25519 throughout,
root replaced by a trust anchor of its own.
*/

@(private = "file")
CE_ANCHOR :: ". IN DS 951 15 2 963C615100F292D31344F590790425AED6F3CF2D7C7D853B6C34D6F5A7BD811B"

@(private = "file")
CE_FIXTURES := []Fixture{
	{
		key   = "ce_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f92a58b30b5cc4acd2f0f8ffa0596d005" +
			"976cbddc790c21b25b954699daa9dfb000002e000100000e10005300300f0000000e106c5048a06a6dc3a003b7006c3e" +
			"8c42e037abfb44d9cc174376c9d683fbbaa477469574d6b838d45140f734c3a77074e1932169f448c0dbd4f0497b8d5f" +
			"76059c4e69dd08f197a051601806",
	},
	{
		key   = "ce_cetest_ds",
		name  = "cetest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000663657465737400002b00010663657465737400002b000100000e100024f8310f02aba6" +
			"721fc8c247d625857793fc184b6634c14e39fc10c906add2ec263a2897e00663657465737400002e000100000e100053" +
			"002b0f0100000e106c5048a06a6dc3a003b70046f1c4882e20b980f367caa9f9b965ba2c2df3d830d9b244acbfbc0733" +
			"1b2831a84f6dcda1db8ab836655c57160e961879df992b3c93bc85863230d0a35d0f09",
	},
	{
		key   = "ce_cetest_dnskey",
		name  = "cetest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006636574657374000030000106636574657374000030000100000e1000240101030fc4a5" +
			"c31f6e07d31c734ce29e33e049d756ecaf81de75f0c3e67c88266684acc50663657465737400002e000100000e10005a" +
			"00300f0100000e106c5048a06a6dc3a0f831066365746573740050f20d8112aa83a9118f805a01c6742d50bd0641ffa7" +
			"a9ec82e08d81944d02af17320a74e1a48e1c4db8401478a5c4860b70553787c5f1b53653ca6954c9790b",
	},
	{
		key   = "ce_y_ds",
		name  = "y.cetest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100000002000001790663657465737400002b0001206b6f38613233746a766d63707038707374636b3339" +
			"64626271626f72613034620663657465737400003200010000003c00260100000004aabbccdd14b8538eff7a35b68dab" +
			"6165f9c24f46a1ea0d070e0006400000000002206b6f38613233746a766d63707038707374636b333964626271626f72" +
			"613034620663657465737400002e00010000003c005a00320f020000003c6c5048a06a6dc3a0f8310663657465737400" +
			"5b807227fa716314e75f98b9cee87efd472039597fd08d72d3ed073b40f1cd283c5837664ad79898bdd36d4dfa66e71f" +
			"981c338884464562d9d7e148b00a0300",
	},
	// The same NSEC3 records the answers below carry, answering a DS lookup:
	// the chain walk asks about every label down to the name, and `x.y.cetest.`
	// is one of them. A covering NSEC3 with opt-out clear says nothing is
	// delegated there, so the walk settles on `cetest.`.
	{
		key   = "ce_x_ds",
		name  = "x.y.cetest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000017801790663657465737400002b0001206b6f38613233746a766d63707038707374636b" +
			"333964626271626f72613034620663657465737400003200010000003c00260100000004aabbccdd14b8538eff7a35b6" +
			"8dab6165f9c24f46a1ea0d070e0006400000000002206b6f38613233746a766d63707038707374636b33396462627162" +
			"6f72613034620663657465737400002e00010000003c005a00320f020000003c6c5048a06a6dc3a0f831066365746573" +
			"74005b807227fa716314e75f98b9cee87efd472039597fd08d72d3ed073b40f1cd283c5837664ad79898bdd36d4dfa66" +
			"e71f981c338884464562d9d7e148b00a0300206e31396f74767271366d723872617231636e7373346a71366b376c3071" +
			"316f650663657465737400003200010000003c00270100000004aabbccdd14728fa9acbe6d8ac03290a63f45f44ef789" +
			"28b7510007220000000002a0206e31396f74767271366d723872617231636e7373346a71366b376c3071316f65066365" +
			"7465737400002e00010000003c005a00320f020000003c6c5048a06a6dc3a0f83106636574657374009b063d3f67d190" +
			"5eae286821e0f1c5c08fb3fd6cba4ce1ab66942e1cae0cf13700f07023f82491d71e09a47bdcbb1449a4c7bf899a5c7d" +
			"0e7d7ba71f8a633301",
	},
	{
		key   = "ce_inner_wildcard",
		name  = "x.y.cetest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200040000017801790663657465737400000100010178017906636574657374000001000100000e10" +
			"0004c0000202017801790663657465737400002e000100000e10005a00010f0200000e106c5048a06a6dc3a0f8310663" +
			"657465737400d056f21fe634e7f037dbb81aac722190104a0601fcf511ada07e1d3ecf2d748f913209ef5d20f5565841" +
			"e07c5c770f124b690ff281de4090919a44c5b3170504206b6f38613233746a766d63707038707374636b333964626271" +
			"626f72613034620663657465737400003200010000003c00260100000004aabbccdd14b8538eff7a35b68dab6165f9c2" +
			"4f46a1ea0d070e0006400000000002206b6f38613233746a766d63707038707374636b333964626271626f7261303462" +
			"0663657465737400002e00010000003c005a00320f020000003c6c5048a06a6dc3a0f83106636574657374005b807227" +
			"fa716314e75f98b9cee87efd472039597fd08d72d3ed073b40f1cd283c5837664ad79898bdd36d4dfa66e71f981c3388" +
			"84464562d9d7e148b00a0300206e31396f74767271366d723872617231636e7373346a71366b376c3071316f65066365" +
			"7465737400003200010000003c00270100000004aabbccdd14728fa9acbe6d8ac03290a63f45f44ef78928b751000722" +
			"0000000002a0206e31396f74767271366d723872617231636e7373346a71366b376c3071316f65066365746573740000" +
			"2e00010000003c005a00320f020000003c6c5048a06a6dc3a0f83106636574657374009b063d3f67d1905eae286821e0" +
			"f1c5c08fb3fd6cba4ce1ab66942e1cae0cf13700f07023f82491d71e09a47bdcbb1449a4c7bf899a5c7d0e7d7ba71f8a" +
			"633301",
	},
	{
		key   = "ce_outer_wildcard",
		name  = "x.y.cetest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200040000017801790663657465737400000100010178017906636574657374000001000100000e10" +
			"0004c0000201017801790663657465737400002e000100000e10005a00010f0100000e106c5048a06a6dc3a0f8310663" +
			"6574657374001bdecdb5c6445952d243276b622b15e670eb9c7ba57b884ae763db6e76858dac8ac890964935276b68f7" +
			"a892cb2eb9fd35c788ce1784811ffcd9864354edc70a206b6f38613233746a766d63707038707374636b333964626271" +
			"626f72613034620663657465737400003200010000003c00260100000004aabbccdd14b8538eff7a35b68dab6165f9c2" +
			"4f46a1ea0d070e0006400000000002206b6f38613233746a766d63707038707374636b333964626271626f7261303462" +
			"0663657465737400002e00010000003c005a00320f020000003c6c5048a06a6dc3a0f83106636574657374005b807227" +
			"fa716314e75f98b9cee87efd472039597fd08d72d3ed073b40f1cd283c5837664ad79898bdd36d4dfa66e71f981c3388" +
			"84464562d9d7e148b00a0300206e31396f74767271366d723872617231636e7373346a71366b376c3071316f65066365" +
			"7465737400003200010000003c00270100000004aabbccdd14728fa9acbe6d8ac03290a63f45f44ef78928b751000722" +
			"0000000002a0206e31396f74767271366d723872617231636e7373346a71366b376c3071316f65066365746573740000" +
			"2e00010000003c005a00320f020000003c6c5048a06a6dc3a0f83106636574657374009b063d3f67d1905eae286821e0" +
			"f1c5c08fb3fd6cba4ce1ab66942e1cae0cf13700f07023f82491d71e09a47bdcbb1449a4c7bf899a5c7d0e7d7ba71f8a" +
			"633301",
	},
}

@(private = "file")
ce_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in CE_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
ce_fixture :: proc(key: string) -> []u8 {
	for f in CE_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(private = "file")
ce_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(CE_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(ce_query, nil, Options{anchors = anchors})
}

@(test)
test_ce_zone_chain_is_sound :: proc(t: ^testing.T) {
	// The control: if the canonical form these fixtures were signed against
	// ever drifts from the one the validator computes, this reports the drift
	// before the two tests below start failing for reasons of their own.
	v := ce_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, "x.y.cetest.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "cetest.")
	testing.expect(t, len(keys) > 0, "the zone should publish a key")
	free_all(context.temp_allocator)
}

@(test)
test_wildcard_answer_from_the_applicable_wildcard_validates :: proc(t: ^testing.T) {
	// `*.y.cetest.` is the wildcard that applies to `x.y.cetest.`, and its next
	// closer name is `x.y.cetest.` itself, which the authority section covers.
	v := ce_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "x.y.cetest.", .A, ce_fixture("ce_inner_wildcard"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"a wildcard answer proving its own next closer name should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_wildcard_answer_from_a_shallower_wildcard_is_bogus :: proc(t: ^testing.T) {
	/*
	The same denial records, under a signature made by `*.cetest.`. That
	wildcard's next closer name is `y.cetest.`, which exists - the authority
	section matches it rather than covering it, and nothing else could. Taking
	the closest encloser from the records instead of from the signature stops
	the walk at that match and asks only for the cover it was already handed,
	which is exactly the cover an honest answer for a name under `y.cetest.`
	comes with.
	*/
	v := ce_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "x.y.cetest.", .A, ce_fixture("ce_outer_wildcard"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Bogus,
		"an answer signed by a wildcard that does not apply to the name should be bogus, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
