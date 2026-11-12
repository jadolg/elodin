package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A trust anchor below the root (issue #226).

`corp.` is signed with a key its parent never vouched for: the root's NSEC
proves `corp.` a delegation with no DS. The operator configures an anchor for
`corp.` beside the root's, and RFC 4035 section 4.3 has a validator start the
chain at the closest anchor above the name, so `www.corp.` is Secure.

Generated - `testdata/gen/sign_fixtures.py`, scenario `anchor_below_the_root`.
*/

@(private = "file")
BA_ROOT_ANCHOR :: ". IN DS 62725 15 2 ABC5EF374889AA7743573C09F9FFF5FFAEB1B6B80A23C13799C038EEA6C0F772"
@(private = "file")
BA_CORP_ANCHOR :: "corp. IN DS 59822 15 2 AA600608B2CC2DC29227168B7DBF3D93605731324BAD56BA9C15A198557C6224"

@(private = "file")
BA_FIXTURES := []Fixture{
	{
		key   = "ba_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f9aa36cfdc2469ccfdbee5b177e22353c" +
			"c4f0524bf270a77569b46f709c25796c00002e000100000e10005300300f0000000e107d3b18206a478820f505002f57" +
			"ca5f74fe667787d19e4e9149ac59a561d288842fe2d2b97fb0f9ca7e5b32521b39a0b8034749fa558b8d8185ad59e40e" +
			"20dd24d4e3b81e689a103491300e",
	},
	{
		key   = "ba_corp_ds",
		name  = "corp.",
		type  = .DS,
		wire  = "12348580000100000002000004636f727000002b000104636f727000002f000100000e10000c027a7a00000620000000" +
			"000304636f727000002e000100000e100053002f0f0100000e107d3b18206a478820f5050046a4b72cd1ac7bc9e92880" +
			"03fee1636bd2f259033862625fb13845747480028b86d956b8d1862db5b2445cfbe1fee6fb41095e26e7c33b796b53c0" +
			"0d0123e408",
	},
	{
		key   = "ba_corp_dnskey",
		name  = "corp.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000004636f7270000030000104636f7270000030000100000e1000240101030f9e4f410e0d27" +
			"e5b1e02c5e0d20fef98b9cb0d04501da9f25aa4729d05278861d04636f727000002e000100000e10005800300f010000" +
			"0e107d3b18206a478820e9ae04636f727000993749ca4cab114e6973dc5e1ed4df5bdeffe3c7ac1e0133da20ed58dcc8" +
			"3b404af15fd56a67e95b521ba246bedda2bfa1fcdc0c8e99349240ab097198bc6c0a",
	},
	{
		key   = "ba_answer",
		name  = "www.corp.",
		type  = .A,
		wire  = "1234858000010002000000000377777704636f727000000100010377777704636f7270000001000100000e100004c000" +
			"02010377777704636f727000002e000100000e10005800010f0200000e107d3b18206a478820e9ae04636f727000e8e0" +
			"91bda553191268e258e74248939de3b6240cad6590c11a8c78395921d2acdcaa919c90da8c0e5a28949dc5029ddf60fb" +
			"25716e297d75661c24592fa4d305",
	},
	{
		key   = "ba_root_signed_answer",
		name  = "www.corp.",
		type  = .A,
		wire  = "1234858000010002000000000377777704636f727000000100010377777704636f7270000001000100000e100004c000" +
			"02010377777704636f727000002e000100000e10005300010f0200000e107d3b18206a478820f50500524d3e093f0284" +
			"cb87e3ebbefd68ccea01c55db629517276cb015d44dd5077b775347b17b6b96eb702a878f6af87a18e461dcb02440d84" +
			"46ccef1b9c9980ca01",
	},
	{
		key   = "ba_www_ds",
		name  = "www.corp.",
		type  = .DS,
		wire  = "1234858000010000000200000377777704636f727000002b00010377777704636f727000002f000100000e10000e0463" +
			"6f72700000064000000000030377777704636f727000002e000100000e100058002f0f0200000e107d3b18206a478820" +
			"e9ae04636f727000141dc621b15022ed5d2200c464bd6cb08be1ec9ecae197cbce2dad4f3082a756e32e2362ce216319" +
			"378816691397eb754f3d255f97f508efa8c9fc4189b4c003",
	},
}

@(private = "file")
ba_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> (wire: []u8, ok: bool) {
	for f in BA_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return decode_hex(f.wire, allocator)
		}
	}
	return nil, false
}

@(private = "file")
ba_validator :: proc(anchor_texts: ..string) -> ^Validator {
	anchors := make([]Trust_Anchor, len(anchor_texts), context.temp_allocator)
	for text, i in anchor_texts {
		anchor, ok := parse_trust_anchor(text, context.temp_allocator)
		if !ok {
			return nil
		}
		anchors[i] = anchor
	}
	return make_validator(ba_query, nil, Options{anchors = anchors})
}

@(private = "file")
ba_answer :: proc() -> []u8 {
	out, _ := decode_hex(BA_FIXTURES[3].wire, context.temp_allocator)
	return out
}

@(test)
test_the_public_chain_alone_reads_the_zone_as_insecure :: proc(t: ^testing.T) {
	// The premise: with the root as the only anchor, the root's NSEC proves
	// no DS for `corp.`, so the answer is Insecure - not Bogus, not broken.
	v := ba_validator(BA_ROOT_ANCHOR)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "www.corp.", .A, ba_answer(), time.unix(FIXTURE_TIME, 0))
	testing.expectf(t, result.status == .Insecure, "root anchor only: want Insecure, got %v (%q)", result.status, result.reason)
	free_all(context.temp_allocator)
}

@(test)
test_an_anchor_below_the_root_starts_the_chain :: proc(t: ^testing.T) {
	v := ba_validator(BA_ROOT_ANCHOR, BA_CORP_ANCHOR)
	testing.expect(t, v != nil, "the anchors should parse")
	defer destroy_validator(v)
	now := time.unix(FIXTURE_TIME, 0)

	// The premise: the `corp.` anchor on its own establishes the zone's keys.
	budget := query_budget(v)
	anchored, keys := zone_keys(v, &budget, "corp.", now, context.temp_allocator)
	testing.expectf(t, anchored == .Secure && len(keys) > 0, "the corp. anchor should vouch for its keys, got %v", anchored)

	// The walk must start at the closest anchor, `corp.`, not at the root.
	fresh := ba_validator(BA_ROOT_ANCHOR, BA_CORP_ANCHOR)
	defer destroy_validator(fresh)
	walk := query_budget(fresh)
	// Walked to the zone the answer's signature names, as `validate` does.
	status, _, zone := zone_trust(fresh, &walk, "corp.", now, context.temp_allocator)
	testing.expectf(
		t,
		status == .Secure && zone == "corp.",
		"zone_trust(corp.) should establish corp. from its anchor, got %v at %q - the walk started at the root and never used the corp. anchor",
		status,
		zone,
	)

	result := validate(fresh, "www.corp.", .A, ba_answer(), now)
	testing.expectf(t, result.status == .Secure, "www.corp. under a corp. anchor: want Secure, got %v (%q)", result.status, result.reason)
	free_all(context.temp_allocator)
}

@(test)
test_a_wrong_anchor_below_the_root_is_bogus_not_insecure :: proc(t: ^testing.T) {
	// The anchor pins the zone's keys: one naming a key `corp.` does not
	// publish is a broken chain, and the root's proof that `corp.` has no DS
	// does not get to turn that into an unsigned zone (RFC 6840 Appendix C.1).
	wrong := "corp. IN DS 59822 15 2 0000000000000000000000000000000000000000000000000000000000000000"
	v := ba_validator(BA_ROOT_ANCHOR, wrong)
	testing.expect(t, v != nil, "the anchors should parse")
	defer destroy_validator(v)

	result := validate(v, "www.corp.", .A, ba_answer(), time.unix(FIXTURE_TIME, 0))
	testing.expectf(t, result.status == .Bogus, "a corp. anchor naming the wrong key: want Bogus, got %v (%q)", result.status, result.reason)
	// And the operator is told it was their anchor, not some parent's DS.
	testing.expectf(
		t,
		result.detail == "corp: no DNSKEY both matches a trust anchor and signs the DNSKEY set",
		"the detail should blame the anchor, got %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_key_above_the_anchor_does_not_vouch_for_a_name_inside_it :: proc(t: ^testing.T) {
	// `www.corp. A` signed by the root's key. The `corp.` anchor pins the zone
	// (RFC 6840 Appendix C.1), so a signer above it - a public ancestor's view
	// of a split-horizon name - is not a key the zone's names are read against.
	answer, _ := decode_hex(BA_FIXTURES[4].wire, context.temp_allocator)
	now := time.unix(FIXTURE_TIME, 0)

	// The premise: with only the root anchored, the root's signature holds.
	public := ba_validator(BA_ROOT_ANCHOR)
	testing.expect(t, public != nil, "the anchor should parse")
	defer destroy_validator(public)
	premise := validate(public, "www.corp.", .A, answer, now)
	testing.expectf(t, premise.status == .Secure, "root anchor only: want Secure, got %v (%q)", premise.status, premise.reason)

	v := ba_validator(BA_ROOT_ANCHOR, BA_CORP_ANCHOR)
	testing.expect(t, v != nil, "the anchors should parse")
	defer destroy_validator(v)
	result := validate(v, "www.corp.", .A, answer, now)
	testing.expectf(t, result.status == .Bogus, "a root signature under a corp. anchor: want Bogus, got %v (%q)", result.status, result.reason)
	free_all(context.temp_allocator)
}

@(test)
test_a_ds_at_an_anchored_zone_is_the_parents :: proc(t: ^testing.T) {
	// A DS lives in the parent (RFC 4035 section 5.3.1), so `corp. DS` is
	// walked to the root and read against the root's key - the `corp.` anchor
	// sits below the zone that answers it and has no say.
	v := ba_validator(BA_ROOT_ANCHOR, BA_CORP_ANCHOR)
	testing.expect(t, v != nil, "the anchors should parse")
	defer destroy_validator(v)

	denial, _ := decode_hex(BA_FIXTURES[1].wire, context.temp_allocator)
	result := validate(v, "corp.", .DS, denial, time.unix(FIXTURE_TIME, 0))
	testing.expectf(t, result.status == .Secure, "the root's signed denial of corp. DS: want Secure, got %v (%q)", result.status, result.reason)
	free_all(context.temp_allocator)
}

@(test)
test_closest_anchor_is_the_deepest_on_a_label_boundary :: proc(t: ^testing.T) {
	anchors := []Trust_Anchor{{zone = "."}, {zone = "example."}, {zone = "zone.example."}}
	testing.expect_value(t, closest_anchor(anchors, "www.sub.zone.example."), "zone.example.")
	testing.expect_value(t, closest_anchor(anchors, "zone.example."), "zone.example.")
	testing.expect_value(t, closest_anchor(anchors, "otherzone.example."), "example.")
	testing.expect_value(t, closest_anchor(anchors, "example.org."), ".")
	testing.expect_value(t, closest_anchor(anchors[2:], "example.org."), ".")
}

@(test)
test_an_unfollowable_anchor_below_the_root_is_found :: proc(t: ^testing.T) {
	// `start_validator` refuses to start on this zone: it is a starting point
	// for the walk, and an anchor nothing here can check would serve it insecure.
	unknown := []Trust_Anchor {
		{zone = ".", ds = {key_tag = 1, algorithm = ALG_ED25519, digest_type = DIGEST_SHA256}},
		{zone = "corp.", ds = {key_tag = 2, algorithm = 200, digest_type = DIGEST_SHA256}},
	}
	zone, found := unfollowable_anchor_zone(unknown)
	testing.expectf(t, found && zone == "corp.", "want corp., got %q (%v)", zone, found)

	// One followable anchor is a way into the zone, as for the root.
	mixed := []Trust_Anchor {
		unknown[0],
		unknown[1],
		{zone = "corp.", ds = {key_tag = 3, algorithm = ALG_ED25519, digest_type = DIGEST_SHA256}},
	}
	_, found = unfollowable_anchor_zone(mixed)
	testing.expect(t, !found, "a zone with one followable anchor is followable")
}
