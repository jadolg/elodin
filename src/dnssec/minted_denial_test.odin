package dnssec

import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A zone that answers every DS below its apex with a denial minted for the
question.

RFC 4470 lets a signer answer a name it does not hold with an NSEC built on the
spot, and such a record says the name is there and carries no NS - which is
indistinguishable from an empty non-terminal, because that is what an empty
non-terminal looks like. A zone serving them therefore answers every label of
every name that way, and Cloudflare serves them for every signed zone it hosts.

Nothing here is forged. Every record verifies against `drtest.`'s own key, and
the answer the client gets is correct. What the shape costs is the chain walk:
`zone_trust` cannot stop at a name that is not a cut, so a question about a name
eight labels deep descends all eight, one blocking DS lookup apiece, on the
thread already answering the client. That is issue #330 - and the name is a
client's to choose, so the depth was too, and every question under the same run
used to pay for the whole of it again.

Generated - `testdata/gen/sign_fixtures.py`, scenario
`deep_run_of_empty_non_terminals`. Ed25519 throughout, root replaced by a trust
anchor of the generator's own making.
*/

@(private = "file")
DR_ANCHOR :: ". IN DS 53447 15 2 466D69A4558C0297C2B2CAE4867A8156C47696CA6C7990070C0988D0B2BA2090"

@(private = "file")
DR_QNAME :: "l1.l2.l3.l4.l5.l6.l7.l8.drtest."

// A signed zone of its own, below every one of those eight.
@(private = "file")
DR_SUB_QNAME :: "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest."

@(private = "file")
DR_FIXTURES := []Fixture{
	{
		key   = "dr_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030fde306b46123761bf4844692b2f015019" +
			"0c044d26c77dc73bfcc1cd0a8d439fcb00002e000100000e10005300300f0000000e107d3b18206a478820d0c70080f4" +
			"037d933b1e30dc90a08a968a6cab939724334ae2eeed5a6c8bb5910087fb5dd070f35ccf2a9fbfc8192d30d614550dd4" +
			"d5181eeb430840b565e77b4a7008",
	},
	{
		key   = "dr_ds",
		name  = "drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000664727465737400002b00010664727465737400002b000100000e100024979c0f02589e" +
			"a37ced5411574b33601e7ab21825d1c07a68b75cd87a0917130af327373b0664727465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820d0c700b32cb085caed54ff8ab502986e8f44fc7b064f1e163d9bfd0d2cb89012" +
			"38710197cb5f0abb0ffad36be81faf43207475294ba0cd1f22782ad70a2284c829c109",
	},
	{
		key   = "dr_dnskey",
		name  = "drtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006647274657374000030000106647274657374000030000100000e1000240101030f2ab6" +
			"0ae3e0f5bce02cbe2b056532161861914462c55b5c638bccf126a93eff290664727465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820979c0664727465737400d4865c6e2ffde4cb7138dfc1a15096070f00d6094de7" +
			"b0d0ae334716c5a0d38cee26ecf79c8542e4c3aaa1c7b3abfeeca99161652c2471c618e4ae26aee8540d",
	},
	{
		key   = "dr_ds_l1",
		name  = "l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002b0001" +
			"026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f000100000e10002a0100026c3102" +
			"6c32026c33026c34026c35026c36026c37026c3806647274657374000006000000000003026c31026c32026c33026c34" +
			"026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f0900000e107d3b18206a478820979c" +
			"0664727465737400fe1b4e2ffad6c4dfd57f81290b5400a04f70cb180ead6acc9adcdf7b35e83f5567d93bfaa8d99e2e" +
			"76224359b4cae5f944d56231ec98a482633ba3e84a802709",
	},
	{
		key   = "dr_ds_l2",
		name  = "l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c32026c33026c34026c35026c36026c37026c380664727465737400002b0001026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002f000100000e1000270100026c32026c33026c3402" +
			"6c35026c36026c37026c3806647274657374000006000000000003026c32026c33026c34026c35026c36026c37026c38" +
			"0664727465737400002e000100000e10005a002f0f0800000e107d3b18206a478820979c0664727465737400b2048454" +
			"0be55ea56899074b80c81cd4219c29ddfa4d428c4cb36a3dbbb61b3e83261b87b584395155821f1bd4eb37dc3b3c5796" +
			"58504ab9d4535c4c6603c30e",
	},
	{
		key   = "dr_ds_l3",
		name  = "l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c33026c34026c35026c36026c37026c380664727465737400002b0001026c33026c34" +
			"026c35026c36026c37026c380664727465737400002f000100000e1000240100026c33026c34026c35026c36026c3702" +
			"6c3806647274657374000006000000000003026c33026c34026c35026c36026c37026c380664727465737400002e0001" +
			"00000e10005a002f0f0700000e107d3b18206a478820979c0664727465737400f3ed962537e1ecdf8fa0c5c11c44a6ae" +
			"d6fffd095d4c667dfe7c5e87e72d977a5886c17774393aec4592bdbe1aa937984c3a52aa63521dce00b596133cc95f04",
	},
	{
		key   = "dr_ds_l4",
		name  = "l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c34026c35026c36026c37026c380664727465737400002b0001026c34026c35026c36" +
			"026c37026c380664727465737400002f000100000e1000210100026c34026c35026c36026c37026c3806647274657374" +
			"000006000000000003026c34026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f060000" +
			"0e107d3b18206a478820979c0664727465737400cf077c3e866848058e2ca3e5ccec717489af65ae8d39fca376316d19" +
			"4263d413e3302e8872a0f145c26c310aa98d059a5519a8e18ac5de37f25607cfda880b0e",
	},
	{
		key   = "dr_ds_l5",
		name  = "l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c35026c36026c37026c380664727465737400002b0001026c35026c36026c37026c38" +
			"0664727465737400002f000100000e10001e0100026c35026c36026c37026c3806647274657374000006000000000003" +
			"026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f0500000e107d3b18206a478820979c" +
			"0664727465737400b54d4cf2d179877ff0dd83502c0de9835e596d820431ce01004a6a4ecc06164eb134335271497eef" +
			"e34b80472981d0996cabf2dcbaa97f539cd139f218c39a04",
	},
	{
		key   = "dr_ds_l6",
		name  = "l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c36026c37026c380664727465737400002b0001026c36026c37026c38066472746573" +
			"7400002f000100000e10001b0100026c36026c37026c3806647274657374000006000000000003026c36026c37026c38" +
			"0664727465737400002e000100000e10005a002f0f0400000e107d3b18206a478820979c0664727465737400edca654c" +
			"e10b1babbca6ae6dc04b1a523e5e8950cb26d92f3c0bae89923b9ced3fdaeddbca5b2da24dbe72f75b172515fc6712e2" +
			"658239e95609eb33d813f70b",
	},
	{
		key   = "dr_ds_l7",
		name  = "l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c37026c380664727465737400002b0001026c37026c380664727465737400002f0001" +
			"00000e1000180100026c37026c3806647274657374000006000000000003026c37026c380664727465737400002e0001" +
			"00000e10005a002f0f0300000e107d3b18206a478820979c066472746573740013546dc26538b7917db4b0c9629f0f88" +
			"5e8542dd06ffd742539f263ddc7cd0ba8d2d570369bdd060c431f8b59ad6663f5ca0fec9e2878273224f2d7cfa102603",
	},
	{
		key   = "dr_ds_l8",
		name  = "l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000026c380664727465737400002b0001026c380664727465737400002f000100000e100015" +
			"0100026c3806647274657374000006000000000003026c380664727465737400002e000100000e10005a002f0f020000" +
			"0e107d3b18206a478820979c0664727465737400af23c6a9189517aa4665b409370bf6db4df0a54f62470a5045672df9" +
			"27140ae2500afa054fdd54d9c382b22c8470d72fc34275fbc78347d44618491964a41403",
	},
	{
		key   = "dr_nodata",
		name  = "l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000000020000026c31026c32026c33026c34026c35026c36026c37026c38066472746573740000010001" +
			"026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f000100000e10002a0100026c3102" +
			"6c32026c33026c34026c35026c36026c37026c3806647274657374000006000000000003026c31026c32026c33026c34" +
			"026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f0900000e107d3b18206a478820979c" +
			"0664727465737400fe1b4e2ffad6c4dfd57f81290b5400a04f70cb180ead6acc9adcdf7b35e83f5567d93bfaa8d99e2e" +
			"76224359b4cae5f944d56231ec98a482633ba3e84a802709",
	},
	{
		key   = "dr_sub_ds",
		name  = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"002b000103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002b000100000e10" +
			"0024cea60f022d6d2aa542713cfa3d696a27d868ad3878e3589dfdd1fb30657706e619cb581203737562026c31026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002e000100000e10005a002b0f0a00000e107d3b1820" +
			"6a478820979c0664727465737400b347ae39750320ea5c8acd9ed30f22c68e8f9fb7f79b3d7868f4e66b994c0bf34766" +
			"6e895464b975f44ffd56232eeb675a007daa6e00de5092c64407fd132203",
	},
	{
		key   = "dr_sub_dnskey",
		name  = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"0030000103737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000030000100000e10" +
			"00240101030f3e08aabfb6984cc366becf0853851f546f541a01e6269e743e5ea48bd12673d003737562026c31026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002e000100000e10007600300f0a00000e107d3b1820" +
			"6a478820cea603737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000c2373b08768" +
			"aa442c6ee25aeb21b11a5fa1eec30424d442d8414f79e15d6bbf2fa5338d1b056e81cc9b3c7d2f5e334dc34e471220f0" +
			"a899dbb31250bdfd2b07",
	},
	{
		key   = "dr_sub_answer",
		name  = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .A,
		rcode = 0,
		wire  = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"0001000103737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000001000100000e10" +
			"0004c000020103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002e00010000" +
			"0e10007600010f0a00000e107d3b18206a478820cea603737562026c31026c32026c33026c34026c35026c36026c3702" +
			"6c3806647274657374005f28964758c450d9879d586223df7d0581a1d8821cdc729f0b6bd5b55619ae972ead77c40b47" +
			"be621d8d4c1da973979e491ad683db70912be181d4451d433507",
	},
	{
		key   = "dr_stray_denial",
		name  = "b.c.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000016201630664727465737400002b0001037a7a7a0664727465737400002f000100000e10" +
			"00160100037a7a7a06647274657374000006000000000003037a7a7a0664727465737400002e000100000e10005a002f" +
			"0f0200000e107d3b18206a478820979c0664727465737400d149be5926f0dc3cf29580006d5f852a1cb9e24a130762a0" +
			"67df13860d42f0b45fe10b275e51cc01c8e2d165240def1a78af4d36b65b6d629f64c64f83aaa90d",
	},
	{
		key   = "dr_bare_ds",
		name  = "e.f.drtest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000000000016501660664727465737400002b0001",
	},
	{
		key   = "dr_sub_nodata",
		name  = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .AAAA,
		rcode = 0,
		wire  = "12348580000100000002000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"001c000103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f000100000e10" +
			"0030027a7a03737562026c31026c32026c33026c34026c35026c36026c37026c38066472746573740000076200000000" +
			"038003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002e000100000e100076" +
			"002f0f0a00000e107d3b18206a478820cea603737562026c31026c32026c33026c34026c35026c36026c37026c380664" +
			"727465737400de8199040647383b977ae2bae7c89e01b63f59a8ac424ae78e00d744d2ff5d4911275908842ca55fda76" +
			"0fd3f9d1d002ebccebd85af2051f87276e7d2f9a4905",
	},
	{
		key   = "dr_delegation_nsec",
		name  = "www.sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .A,
		rcode = 3,
		wire  = "1234858300010000000200000377777703737562026c31026c32026c33026c34026c35026c36026c37026c3806647274" +
			"657374000001000103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f0001" +
			"00000e10002f027a7a03737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400000620" +
			"000000000303737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002e000100000e" +
			"10005a002f0f0a00000e107d3b18206a478820979c0664727465737400ed5b4ef2d1b6a07c4734de622ce01faa44013b" +
			"c06546ae07ca9b2de7f9bd2cc51d7daf6667703113a89f0671463c48127f90052737a346aac1fcb3a51d95d30a",
	},
	{
		key   = "dr_www_ds",
		name  = "www.sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		type  = .DS,
		rcode = 3,
		wire  = "1234858300010000000200000377777703737562026c31026c32026c33026c34026c35026c36026c37026c3806647274" +
			"65737400002b000103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f0001" +
			"00000e10002f027a7a03737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400000620" +
			"000000000303737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002e000100000e" +
			"10005a002f0f0a00000e107d3b18206a478820979c0664727465737400ed5b4ef2d1b6a07c4734de622ce01faa44013b" +
			"c06546ae07ca9b2de7f9bd2cc51d7daf6667703113a89f0671463c48127f90052737a346aac1fcb3a51d95d30a",
	},
}
@(private = "file")
Dr_Calls :: struct {
	// DS lookups for a name below `drtest.`, which is one per label of the
	// question that the walk descended through.
	below_apex: int,
}

@(private = "file")
dr_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	calls := cast(^Dr_Calls)ctx
	if calls != nil && type == .DS && !dns.name_equal_fold(name, "drtest.") && name != "." {
		calls.below_apex += 1
	}
	for f in DR_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
dr_fixture :: proc(key: string) -> []u8 {
	for f in DR_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

// What the walk itself reads: `cache_get` answers for both maps at once, and
// the third value is the memo's word on a name no zone entry covers.
@(private = "file")
dr_remembered :: proc(v: ^Validator, name: string, now: time.Time) -> bool {
	_, _, non_cut := cache_get(v, name, now, context.temp_allocator)
	return non_cut
}

@(private = "file")
dr_validator :: proc(calls: ^Dr_Calls) -> ^Validator {
	anchor, parsed := parse_trust_anchor(DR_ANCHOR, context.temp_allocator)
	if !parsed {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	v := make_validator(dr_query, calls, Options{anchors = anchors})
	// A fixed seed makes the hash table deterministic, so no pair of names
	// these tests use lands on the same slot.  Without this, the random seed
	// drawn at start-up can produce a collision that evicts a name mid-walk
	// and changes the verdict from what the test asserts - see issue #362.
	//
	// Seed 0 is chosen as the simplest constant basis; modulo 1024, the eight
	// labels of DR_QNAME below the apex and DR_SUB_QNAME map to:
	//   l8: 1002, l7: 587, l6: 771, l5: 748, l4: 438,
	//   l3: 775,  l2: 11,  l1: 964, sub: 664.
	// All nine slots are distinct.
	v.non_cut_seed = 0
	return v
}

@(test)
test_dr_fixture_names_do_not_collide_in_non_cut_table :: proc(t: ^testing.T) {
	/*
	Issue #362: tests in this file assume that warming the run leaves the
	walk with nothing to insert, which requires that DR_SUB_QNAME and the eight
	labels of DR_QNAME never collide in the 1024-slot non_cuts table.
	This test guards that invariant so any future name addition or change
	that collides with the seed fails here directly rather than flaking CI.
	*/
	v := dr_validator(nil)
	defer destroy_validator(v)

	slots: [dynamic]int
	defer delete(slots)

	// The 8 labels below the apex:
	for i in 1 ..= 8 {
		name := name_drop_labels(DR_QNAME, 9 - i)
		slot := non_cut_slot(v, name)
		for existing in slots {
			testing.expectf(
				t,
				existing != slot,
				"hash collision in non_cut table: %s maps to existing slot %d",
				name,
				slot,
			)
		}
		append(&slots, slot)
	}

	sub_slot := non_cut_slot(v, DR_SUB_QNAME)
	for existing in slots {
		testing.expectf(
			t,
			existing != sub_slot,
			"hash collision in non_cut table: DR_SUB_QNAME maps to existing slot %d",
			sub_slot,
		)
	}
}

@(test)
test_a_run_of_non_cuts_is_walked_once :: proc(t: ^testing.T) {
	/*
	Issue #330. Eight labels of the question are answered as names that are
	there and hold no delegation, so the walk descends all eight and pays a
	blocking DS lookup for each - and used to pay them again for the next
	question underneath the same run, because only zones were remembered.

	The numbers are written out rather than derived from a constant: a test
	that says "no more than the limit" passes when somebody raises the limit,
	which is the one change it exists to notice.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	result := validate(v, DR_QNAME, .A, dr_fixture("dr_nodata"), now)
	testing.expectf(
		t,
		result.status == .Secure,
		"the minted denial is signed by the apex, so it should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	testing.expect_value(t, calls.below_apex, 8)

	// The same run again, walked on its own: every step of it is now known, so
	// the walk reaches the same zone without asking anybody anything.
	budget := Budget{}
	status, _, zone := zone_trust(v, &budget, DR_QNAME, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "drtest.")
	testing.expectf(
		t,
		calls.below_apex == 8,
		"the second walk should ask nothing, got %d ds lookups in total",
		calls.below_apex,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_flood_of_non_cuts_keeps_neither_the_zones_nor_the_slots_it_wants :: proc(t: ^testing.T) {
	/*
	The names here are the client's to choose - under a zone minting its
	denials every name anyone asks about is a non-cut - so a random-subdomain
	flood fills the table as fast as it can send. Two things it must not do.

	It must not take the chain with it: the root's keys are what every later
	question starts from, and refetching them under a flood is the
	amplification this whole issue is about.

	And it must not push out the names still being asked for. That is the half
	a size limit alone does not give: a table that holds its limit while
	throwing out whatever is most useful saves nothing under exactly the
	traffic it exists for. A name keeps its slot until another name hashes to
	it - one insert in a thousand, rather than whichever entry a policy happens
	to find first - and a name still being asked for is put back on the miss.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	cache_put(v, ".", .Secure, nil, MAX_ZONE_TTL, now)

	// Saturate first, so what follows measures the steady state under attack
	// rather than a table with room left in it.
	for i in 0 ..< MAX_CACHED_NON_CUTS {
		non_cut_remember(v, fmt.tprintf("fill%d.flood.drtest.", i), 300, now)
	}

	/*
	Then the issue's own shape: a run of empty non-terminals every question
	walks, and one fresh label per question that nobody asks twice. What is
	counted is what the run costs - a name still remembered costs nothing.
	*/
	RUN :: 8
	QUESTIONS :: 200
	lookups := 0
	for q in 0 ..< QUESTIONS {
		for label in 0 ..< RUN {
			name := fmt.tprintf("e%d.run.drtest.", label)
			if !dr_remembered(v, name, now) {
				lookups += 1
				non_cut_remember(v, name, 300, now)
			}
		}
		non_cut_remember(v, fmt.tprintf("q%d.run.drtest.", q), 300, now)
	}

	// Eight to learn the run, and after that only what the flood collides
	// with - about sixteen, and not a fixed number, because the slot a name
	// owns comes from a basis drawn at start-up. Uncached it is 1600, and a table that
	// gives up its front row on every insert comes out in the high hundreds,
	// so the bound is close enough to notice a policy regression rather than
	// only a total one.
	testing.expectf(
		t,
		lookups < 40,
		"a run of %d walked %d times should cost about %d lookups once learned, got %d",
		RUN,
		QUESTIONS,
		RUN,
		lookups,
	)

	_, found, _ := cache_get(v, ".", now, context.temp_allocator)
	testing.expect(t, found, "the root should still be cached after the flood")
	free_all(context.temp_allocator)
}

@(test)
test_a_real_cut_below_the_run_is_still_reached :: proc(t: ^testing.T) {
	/*
	The other half of the contract, and the one worth pinning: a name that is
	no cut may be remembered, but it may never end the walk. `sub.<eight minted
	non-cuts>.drtest.` is a signed zone of its own, and its DS sits under all
	eight of them, so a walk that stopped early - at a bound on how many
	non-cuts it will descend, say - would establish `drtest.` instead and
	report this zone's own signature as a forgery.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, DR_SUB_QNAME, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, DR_SUB_QNAME)
	testing.expect(t, len(keys) > 0, "the zone below the run should publish a key")

	result := validate(v, DR_SUB_QNAME, .A, dr_fixture("dr_sub_answer"), now)
	testing.expectf(
		t,
		result.status == .Secure,
		"an answer signed by the zone below the run should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_zone_learned_later_replaces_what_the_memo_says :: proc(t: ^testing.T) {
	/*
	The two maps keep their own lifetimes, so a name in both is a name whose
	memo entry can outlive its zone entry - and once it does, the walk reads a
	live signed cut as no cut and refuses every signature that zone makes.

	`zone_step` reads the zones first, so this is invisible until the zone
	entry expires, which is what makes it worth pinning here rather than
	leaving to the ordering.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	non_cut_remember(v, "cut.drtest.", 3600, now)
	testing.expect(t, dr_remembered(v, "cut.drtest.", now), "the memo should hold it to begin with")

	cache_put(v, "cut.drtest.", .Secure, nil, MIN_ZONE_TTL, now)
	testing.expect(
		t,
		!dr_remembered(v, "cut.drtest.", now),
		"a name settled as a zone should leave nothing behind in the memo",
	)

	/*
	And the same race arriving the other way round. Both orderings are
	reachable - two walks missing the caches for one child, one upstream
	answering with the DS and another with a stale denial of it - and only the
	memo entry is dangerous, because it outlives the zone entry and then
	answers before any lookup can correct it.

	Read past the zone entry's own lifetime and after the sweep has collected
	it, which is where an entry written here starts doing harm: while the
	expired zone entry is still in the map it shadows the memo, so the damage
	only surfaces once housekeeping has been round.
	*/
	cache_put(v, "other.drtest.", .Secure, nil, MIN_ZONE_TTL, now)
	non_cut_remember(v, "other.drtest.", MAX_ZONE_TTL, now)
	expired := time.time_add(now, time.Duration(MIN_ZONE_TTL + 1) * time.Second)
	sweep(v, expired)
	_, still_a_zone, _ := cache_get(v, "other.drtest.", expired, context.temp_allocator)
	testing.expect(t, !still_a_zone, "the zone entry should have expired by then")
	testing.expect(
		t,
		!dr_remembered(v, "other.drtest.", expired),
		"a name already settled as a zone should never enter the memo",
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_broken_step_forgets_the_name_the_walk_skipped :: proc(t: ^testing.T) {
	/*
	A remembered non-cut says a name exists and holds no delegation, and
	existence is the half that can lapse into something worse than a stale
	answer: once the last record under an empty non-terminal goes, a walk that
	skips the name on the memo's word asks about one a label further down, and
	an NSEC3 name error does not speak for that one. The step reads as forged,
	and nothing corrects it while the memo still answers.

	So a broken step forgets the name above it. This drives that with a denial
	that verifies against the zone's key and speaks for somebody else, which is
	the same thing from the step's point of view.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, "drtest.", now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "drtest.")

	non_cut_remember(v, "c.drtest.", MAX_ZONE_TTL, now)
	testing.expect(t, dr_remembered(v, "c.drtest.", now), "the memo should hold it to begin with")

	step, _ := zone_step(v, &budget, "drtest.", keys, "b.c.drtest.", now, context.temp_allocator)
	testing.expect_value(t, step, Step.Bogus)
	testing.expect(
		t,
		!dr_remembered(v, "c.drtest.", now),
		"a broken step should forget the name above it rather than keep answering from it",
	)

	/*
	And the shape that matters most, which is a step broken by there being
	nothing to read rather than by the wrong thing to read: a delegation
	appearing where the memo still says no cut puts the DS question inside the
	new child zone, and what answers it is signed by the child rather than the
	parent, so it is dropped and the step has no denial at all. That return
	comes before the one above, so it needs its own way out of the memo or the
	new zone stays refused until the entry ages out.
	*/
	non_cut_remember(v, "f.drtest.", MAX_NON_CUT_TTL, now)
	testing.expect(t, dr_remembered(v, "f.drtest.", now), "the memo should hold it to begin with")

	bare, _ := zone_step(v, &budget, "drtest.", keys, "e.f.drtest.", now, context.temp_allocator)
	testing.expect_value(t, bare, Step.Bogus)
	testing.expect(
		t,
		!dr_remembered(v, "f.drtest.", now),
		"a step with no denial to read should forget the name above it too",
	)
	free_all(context.temp_allocator)
}

@(test)
test_the_memo_is_believed_for_less_time_than_a_zone :: proc(t: ^testing.T) {
	/*
	A stale zone entry is a zone checked against yesterday's keys, which the DNS
	bounds by the TTL its operator published. A stale memo entry suppresses the
	lookup that would notice it, so a delegation appearing where an empty
	non-terminal was leaves the new zone refused - and a question about that
	name itself finds no step below it to break and give the name back.

	So the memo keeps its own ceiling, and a denial offering more than that does
	not get it.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	non_cut_remember(v, "long.drtest.", MAX_ZONE_TTL, now)

	within := time.time_add(now, time.Duration(MAX_NON_CUT_TTL - 1) * time.Second)
	testing.expect(t, dr_remembered(v, "long.drtest.", within), "it should hold up to its own ceiling")

	past := time.time_add(now, time.Duration(MAX_NON_CUT_TTL + 1) * time.Second)
	testing.expect(
		t,
		!dr_remembered(v, "long.drtest.", past),
		"a denial offering an hour should still be forgotten at the memo's own ceiling",
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_ds_the_parent_did_not_sign_forgets_the_name_above :: proc(t: ^testing.T) {
	/*
	The third way a delegation appearing at a remembered non-cut reaches
	`zone_step`, and the only one that arrives carrying records: the first name
	below the new cut is a signed zone itself, so its DS is served and signed
	by the new zone, and nothing over it names the parent the walk established.
	The step is broken, and if the memo keeps the skipped name nothing can
	correct it - the next walk skips it again without asking.

	`sub.l1...l8.drtest.` has a DS signed by `drtest.`, so asking for it with
	the root as the established parent is that shape exactly.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	budget := Budget{}
	root_status, root_keys := zone_keys(v, &budget, ".", now, context.temp_allocator)
	testing.expect_value(t, root_status, Status.Secure)

	non_cut_remember(v, DR_QNAME, MAX_NON_CUT_TTL, now)
	testing.expect(t, dr_remembered(v, DR_QNAME, now), "the memo should hold it to begin with")

	step, _ := zone_step(v, &budget, ".", root_keys, DR_SUB_QNAME, now, context.temp_allocator)
	testing.expect_value(t, step, Step.Bogus)
	testing.expect(
		t,
		!dr_remembered(v, DR_QNAME, now),
		"a ds the established parent did not sign should forget the name above it too",
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_delegation_at_a_remembered_name_heals_on_the_next_question :: proc(t: ^testing.T) {
	/*
	The case the three forgets in `zone_step` cannot reach. All of them sit
	after that proc's DS query, and a memo hit returns before it - so when the
	remembered name is itself the one that became a zone, no lookup is made and
	nothing notices. Every signature the new zone makes is refused, and asking
	again used to change nothing.

	`sub.l1...l8.drtest.` is a real signed cut in these fixtures, so
	remembering it as a non-cut is exactly the state an operator creates by
	delegating a name that was an empty non-terminal when the memo was written.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	/*
	Walk the run first, so the table already holds every name below the apex.
	Without that the validation below inserts those eight names as it goes, and
	a slot is owned by whatever hashes to it - so one of them can land on the
	name this test is about and evict it mid-walk, which reads as the heal
	happening a question early. Warming the run leaves the walk with nothing to
	insert.
	*/
	warm := Budget{}
	zone_trust(v, &warm, DR_QNAME, now, context.temp_allocator)
	non_cut_remember(v, DR_SUB_QNAME, MAX_NON_CUT_TTL, now)
	testing.expect(t, dr_remembered(v, DR_SUB_QNAME, now), "the table should hold the name to begin with")

	first := validate(v, DR_SUB_QNAME, .A, dr_fixture("dr_sub_answer"), now)
	testing.expectf(
		t,
		first.status == .Bogus,
		"while the memo holds the name the walk cannot reach the zone, so the answer is refused, got %v",
		first.status,
	)
	testing.expect(
		t,
		!dr_remembered(v, DR_SUB_QNAME, now),
		"the refused question should have given the name back",
	)

	second := validate(v, DR_SUB_QNAME, .A, dr_fixture("dr_sub_answer"), now)
	testing.expectf(
		t,
		second.status == .Secure,
		"the question that was refused should have given the name back, so the next one validates, got %v (%q)",
		second.status,
		second.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_from_a_delegation_at_a_remembered_name_heals_too :: proc(t: ^testing.T) {
	/*
	The same heal reached by the other road. An answer goes through
	`validate_rrset`, which walks to the signature's signer; a denial goes
	through `validate_denial`, which walks to the queried name and never sees
	that code at all. Both have to give back a name the walk could not reach,
	or the delegation stays refused for the table's whole lifetime for whichever
	of the two the client happens to ask.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	// The run is warmed first for the reason the answer-path test gives: the
	// walk must have nothing left to insert, or it can evict the very name
	// under test.
	warm := Budget{}
	zone_trust(v, &warm, DR_QNAME, now, context.temp_allocator)
	non_cut_remember(v, DR_SUB_QNAME, MAX_NON_CUT_TTL, now)
	testing.expect(t, dr_remembered(v, DR_SUB_QNAME, now), "the table should hold the name to begin with")

	first := validate(v, DR_SUB_QNAME, .AAAA, dr_fixture("dr_sub_nodata"), now)
	testing.expectf(
		t,
		first.status == .Bogus,
		"while the table holds the name the proof comes from a zone the walk did not reach, got %v",
		first.status,
	)
	testing.expect(
		t,
		!dr_remembered(v, DR_SUB_QNAME, now),
		"the refused question should have given the name back",
	)

	second := validate(v, DR_SUB_QNAME, .AAAA, dr_fixture("dr_sub_nodata"), now)
	testing.expectf(
		t,
		second.status == .Secure,
		"the refused question should have given the name back, so the next one validates, got %v (%q)",
		second.status,
		second.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_parents_delegation_nsec_cannot_deny_a_name_inside_the_child :: proc(t: ^testing.T) {
	/*
	RFC 6840 section 4.1: an NSEC from the parent side of a zone cut - NS set,
	SOA clear - speaks for the delegation and for nothing below it. Its span
	swallows every name in the child all the same, so a validator that reads
	the span without reading the bit map will prove any name in the child does
	not exist, against the parent's keys, and hand the client AD.

	`nsec_proves_no_data` has always made that check. The name-error path did
	not, and what made it unreachable was the walk: it descends to the child
	and judges the denial against the child's keys, so the parent's record is
	dropped before it is read. The table takes that away - a name remembered as
	no cut is a name the walk stops above - so the check has to be where the
	proof is instead.
	*/
	calls := Dr_Calls{}
	v := dr_validator(&calls)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	// Warmed first, as in the heal tests: the walk must not be able to evict
	// the name under test while it runs.
	warm := Budget{}
	zone_trust(v, &warm, DR_QNAME, now, context.temp_allocator)
	non_cut_remember(v, DR_SUB_QNAME, MAX_NON_CUT_TTL, now)

	result := validate(v, "www." + DR_SUB_QNAME, .A, dr_fixture("dr_delegation_nsec"), now)
	testing.expectf(
		t,
		result.status != .Secure,
		"a delegation nsec must not prove a name inside the child does not exist, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
