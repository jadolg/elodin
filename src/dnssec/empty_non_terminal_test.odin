package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A signed zone whose apex sits two labels below its signed parent.

`entest.` delegates `deep.mid.entest.`, and `mid.entest.` in between is an empty
non-terminal: it exists only because a name below it does, and holds no NS, no
DS, nothing. Walking down to the keys that signed an answer therefore has to
pass through a name that is not a zone cut and keep going, because the cut is
below it.

Nobody builds this on purpose and it is not rare either - `seed.btc.petertodd.net.`
and `seed.bitcoin.sprovoost.nl.` are both exactly this shape, and a walk that
stops at the first name without a delegation never reaches their keys. Every
signature they carry is then a signature from a zone the walk never established,
which is refused, and a zone that validates everywhere else comes back to the
client as SERVFAIL with "no valid signature" - or, for a name that does not
exist there, "no denial of existence".

Generated - `testdata/gen/sign_fixtures.py`, scenario
`zone_cut_under_empty_non_terminal`. Ed25519 throughout, root replaced by a
trust anchor of the generator's own making.
*/

@(private = "file")
ENT_ANCHOR :: ". IN DS 35627 15 2 C65E0794F1A136AF3A0463B04BE8C537DC23FC04B720C95C85210DC1F1F9FE0F"

@(private = "file")
ENT_FIXTURES := []Fixture{
	{
		key   = "en_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f81e71453f40a682e54e198c37851ea71" +
			"b12b144705f20eef1592c4b1c3dccbca00002e000100000e10005300300f0000000e107d3b18206a4788208b2b00ef93" +
			"c59df3531eeadbbdbd078cf8208ab08d0eaa5a68a73f60b8f8de86f6c8534ef641e45d29f4165138ff7b609a9304b950" +
			"e7b46d7a03e72c39959fbe93e904",
	},
	{
		key   = "en_ds",
		name  = "entest.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000006656e7465737400002b000106656e7465737400002b000100000e100024425b0f023550" +
			"44dd9d69907d1ecf01d803a274003101b3d378a4379a0168a9ff6e77a20906656e7465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a4788208b2b0059527868818e10ad18bea8910a92bd6d88955172c94aaf6b8483387498" +
			"4bb162cb65c9fa46d7ec75f5703f0790550cece9cd14fb877b46199971dacee3d73e00",
	},
	{
		key   = "en_dnskey",
		name  = "entest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006656e74657374000030000106656e74657374000030000100000e1000240101030f6cb0" +
			"de057b68213e69d2e06cc52f492bf90e46b2eed78331cb9531ffaf589f9b06656e7465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820425b06656e74657374003619dbce3eddafa2c73dec827ced8428e5516b57d052" +
			"07f7162b3ad26a60a464b9f5fc4ceaf6b316535dc72bb94fda2f5db1a2b8a94a430dbf57b952bf741c0f",
	},
	{
		key   = "en_mid_ds",
		name  = "mid.entest.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000020000036d696406656e7465737400002b0001036d696406656e7465737400002f000100000e10" +
			"00190464656570036d696406656e74657374000006000000000003036d696406656e7465737400002e000100000e1000" +
			"5a002f0f0200000e107d3b18206a478820425b06656e746573740058ad48e846d04f8ded914f61d36f126a4277c666c1" +
			"cb06e6e336a43307cc3ecb0794b3f60a866f992aa461286adde0cb4c627deeb2c71a9deb521f3e8981d10e",
	},
	{
		key   = "en_deep_ds",
		name  = "deep.mid.entest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000464656570036d696406656e7465737400002b00010464656570036d696406656e746573" +
			"7400002b000100000e100024eee50f021b9154a52e3a7f2448dbe674627cf5d42f1015ee59574f2177708be17c8a1000" +
			"0464656570036d696406656e7465737400002e000100000e10005a002b0f0300000e107d3b18206a478820425b06656e" +
			"74657374005ba3320ff4e54f80da8e361bebe214a0f7f1561dcdf7842d05eede632115c44afe109b2e1f59603a742613" +
			"21b3fb065577d7f6c06e4aca3dcc653589193fa108",
	},
	{
		key   = "en_deep_dnskey",
		name  = "deep.mid.entest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000464656570036d696406656e7465737400003000010464656570036d696406656e746573" +
			"74000030000100000e1000240101030ff00d74da41b5839d389839ecc436d5e3cdc4617380ac233691b8db1dbba3b866" +
			"0464656570036d696406656e7465737400002e000100000e10006300300f0300000e107d3b18206a478820eee5046465" +
			"6570036d696406656e746573740010fbafb878b89584d882d0807b32216b2d5ecfaef8c712a2ef06a5506815d4048757" +
			"6004f25d5b62324f6f02d0d57441b2cdcf317874cd9e2d704b17c78a0601",
	},
	{
		key   = "en_answer",
		name  = "deep.mid.entest.",
		type  = .A,
		rcode = 0,
		wire  = "1234858000010002000000000464656570036d696406656e7465737400000100010464656570036d696406656e746573" +
			"74000001000100000e100004c00002010464656570036d696406656e7465737400002e000100000e10006300010f0300" +
			"000e107d3b18206a478820eee50464656570036d696406656e74657374007a5e76dad181c944f2951976340d09a7f171" +
			"a7211ae0487ab600f0264039f0d6cf19876bd62d5ab17948bb8e96bf75067c8f3dcb32db7ede870446183a94440c",
	},
	{
		key   = "en_nx",
		name  = "nx.deep.mid.entest.",
		type  = .A,
		rcode = 3,
		wire  = "123485830001000000020000026e780464656570036d696406656e7465737400000100010464656570036d696406656e" +
			"7465737400002f000100000e10001d027a7a0464656570036d696406656e746573740000076200000000038004646565" +
			"70036d696406656e7465737400002e000100000e100063002f0f0300000e107d3b18206a478820eee50464656570036d" +
			"696406656e746573740015de7421a82fbab6046eca7f56f79987d98b816dd29ac5b8500b77f836d0fac799461242ff87" +
			"942622d7d7b881f9c0aff96f45a23faaf8edff251dc5a57c0607",
	},
	{
		key   = "en_nx_ds",
		name  = "nx.deep.mid.entest.",
		type  = .DS,
		rcode = 3,
		wire  = "123485830001000000020000026e780464656570036d696406656e7465737400002b00010464656570036d696406656e" +
			"7465737400002f000100000e10001d027a7a0464656570036d696406656e746573740000076200000000038004646565" +
			"70036d696406656e7465737400002e000100000e100063002f0f0300000e107d3b18206a478820eee50464656570036d" +
			"696406656e746573740015de7421a82fbab6046eca7f56f79987d98b816dd29ac5b8500b77f836d0fac799461242ff87" +
			"942622d7d7b881f9c0aff96f45a23faaf8edff251dc5a57c0607",
	},
}

@(private = "file")
ent_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in ENT_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
ent_validator :: proc() -> ^Validator {
	anchor, ok := parse_trust_anchor(ENT_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(ent_query, nil, Options{anchors = anchors})
}

@(private = "file")
ent_fixture :: proc(key: string) -> []u8 {
	for f in ENT_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(test)
test_the_walk_passes_through_an_empty_non_terminal :: proc(t: ^testing.T) {
	// The statement the two tests below rest on: the deepest signed zone at or
	// above `deep.mid.entest.` is that zone itself, not the `entest.` the walk
	// meets an empty non-terminal under.
	v := ent_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	budget := Budget{}
	status, keys, zone := zone_trust(v, &budget, "deep.mid.entest.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "deep.mid.entest.")
	testing.expect(t, len(keys) > 0, "the zone should publish a key")
	free_all(context.temp_allocator)
}

@(test)
test_an_answer_from_a_zone_below_an_empty_non_terminal_validates :: proc(t: ^testing.T) {
	v := ent_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "deep.mid.entest.", .A, ent_fixture("en_answer"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"an answer signed by the zone below an empty non-terminal should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_from_a_zone_below_an_empty_non_terminal_validates :: proc(t: ^testing.T) {
	// The same walk, reached by the other path: a denial is established against
	// the zone the queried name lives in rather than against a signer it names.
	v := ent_validator()
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	result := validate(v, "nx.deep.mid.entest.", .A, ent_fixture("en_nx"), time.unix(FIXTURE_TIME, 0))
	testing.expectf(
		t,
		result.status == .Secure,
		"an NXDOMAIN proven by the zone below an empty non-terminal should validate, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
