package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
The address hints that ride beside an HTTPS, SVCB, SRV or MX answer.

#177 cut a `Secure` response's additional section down to the OPT record before
the AD bit went on it, which is right for what it was about: glue below a zone
cut is unsigned by design, nobody can ever check it, and it must not travel under
this server's authentication. It was heavier than it needed to be for everything
else in there. The A and AAAA records an authoritative server sends beside an
HTTPS, SVCB, SRV or MX answer are not glue - they are ordinary signed zone data,
and RFC 9460 section 5 asks a recursive resolver to pass them on precisely so a
client does not have to ask again before it can connect.

`validated_hints` keeps the ones it can authenticate. The rule it applies is
narrow on purpose, and every clause of it is a test below: the target has to be
named by an RRset this server *authenticated*, the record has to be an A or AAAA
at that target, its own zone has to be established from a trust anchor, its
signature has to hold over the records actually present, and it must not be a
wildcard expansion - because the denial proof that goes with one is in a zone
this message is not about.

Everything else is dropped exactly as it was before, and the tests that say so
are as much the point as the ones that keep a record: passing an unchecked
address through under AD=1 is the harm #177 was filed about, and a client that
reads AD=1 and then opens a connection to what it finds here is the shape of it.

The fixtures are generated rather than captured - `testdata/gen/sign_fixtures.py`,
scenario `signed_address_hints` - for the reason `closest_encloser_test.odin`
gives: a signature window that does not rot, and a second signed zone to walk to
that no real capture would hold still for. Ed25519 throughout, with a trust
anchor of the generator's own making in place of the root.
*/

@(private = "file")
SH_ANCHOR :: ". IN DS 58920 15 2 8634C4342F8843ED8E69651285A6A2DA99709FE9BE8B9F70E9C54666E8668F0D"

@(private = "file")
SH_FIXTURES := []Fixture{
	{
		key   = "sh_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f6cedb9d2c1e0b4d2d1ddff3932930bba" +
			"e07d6183140545e525e7efafd61dad9f00002e000100000e10005300300f0000000e107d3b18206a478820e628002b22" +
			"0a81d5d9dad2f723880be57f013dcae4df8b129796fefb373cbcbc80356bbfa3d363221cd16bf0c14b2fce5dff12a91a" +
			"68107d22e9aee1553cda1e581008",
	},
	{
		key   = "sh_hinttest_ds",
		name  = "hinttest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000868696e747465737400002b00010868696e747465737400002b000100000e1000245dcd" +
			"0f0284aece07d28b8c6feeeb94e7a93a08ca1a9036c6a899006fb13039d233b826fa0868696e747465737400002e0001" +
			"00000e100053002b0f0100000e107d3b18206a478820e6280035a097e8ff9c63fcb14bf67142a4d2ca5e71c9417c9c0c" +
			"f0046f2c697e1af7b973de46436b13cb6f116866cf2272f120fc4a5289ec3c7242364b65ae1055c902",
	},
	{
		key   = "sh_hinttest_dnskey",
		name  = "hinttest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000868696e747465737400003000010868696e7474657374000030000100000e1000240101" +
			"030f27b245e5de10f24c161ee4b5135f93c7083cb77da3f5d7f7b718b162dd87f8220868696e747465737400002e0001" +
			"00000e10005c00300f0100000e107d3b18206a4788205dcd0868696e747465737400fbbd436f90d841b03fe7f07d97ac" +
			"7946d4b25d1adbf4cd853d8c31b24af890e6bfc60abf59aac5318281bc0114bb6d88d6a9f824a72a0e1c2c1f2c28f4e1" +
			"5000",
	},
	{
		key   = "sh_other_ds",
		name  = "other.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000200000000056f7468657200002b0001056f7468657200002b000100000e10002440860f026f079bf9" +
			"04f95215cefe15c380d6d390786a9fcacd10c5021749c60bf1193928056f7468657200002e000100000e100053002b0f" +
			"0100000e107d3b18206a478820e62800ca9c6a5c6350fdf6e4d934087724b019f28d0de2e63c63e801448e91d092b048" +
			"81831333360cda88a98a9079ce4e984148007481a8d8857121466853f095870b",
	},
	{
		key   = "sh_other_dnskey",
		name  = "other.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "123485800001000200000000056f746865720000300001056f74686572000030000100000e1000240101030ff0c904c5" +
			"74d4b10a52568a5186cfd3296caee8bc6a9c233c6b8c5cc19fda9efa056f7468657200002e000100000e10005900300f" +
			"0100000e107d3b18206a4788204086056f7468657200580199cbe4a5ffb492609f10fc3e2a3b2224fbdeacfe43637683" +
			"cbde56fc80defecad47ceb5d270a1ce955aa8d3a80113038d5eb2771be337377549c37b5e403",
	},
	{
		key   = "sh_srv_same_zone",
		name  = "_svc._tcp.hinttest.",
		type  = .SRV,
		rcode = 0,
		wire  = "123485800001000200000004045f737663045f7463700868696e74746573740000210001045f737663045f7463700868" +
			"696e7474657374000021000100000e1000140000000001bb037376630868696e747465737400045f737663045f746370" +
			"0868696e747465737400002e000100000e10005c00210f0300000e107d3b18206a4788205dcd0868696e747465737400" +
			"bbfcf418fa1d70c84e3276243d5c573bedbde46c8fba2465eed38c04d8ed9cfca874065d5710c2148a6742ce898e61c5" +
			"d9a607c910dc17210641f8af4cf2780f037376630868696e7474657374000001000100000e100004c000020a03737663" +
			"0868696e747465737400001c000100000e10001020010db8000000000000000000000010037376630868696e74746573" +
			"7400002e000100000e10005c00010f0200000e107d3b18206a4788205dcd0868696e74746573740053a91b39b29926d8" +
			"127c6ef9eae27818576bf94508a6eb3db1ead70adbd8689ed4c1651d9ded05be0f1dc9dcc94b1b8db6968d1a394dfd9e" +
			"78a3dbce9eb6fd01037376630868696e747465737400002e000100000e10005c001c0f0200000e107d3b18206a478820" +
			"5dcd0868696e7474657374005cf14b6b211927cec075d2f56f61976eb375ce044ca48be8781ee873214179ec5d3d98ad" +
			"6e54444e61272308a779d4cf66c7d3e8a057cca5cddc2eb2a2f7e209",
	},
	{
		key   = "sh_https_cross_zone",
		name  = "alt.hinttest.",
		type  = .HTTPS,
		rcode = 0,
		wire  = "12348580000100020000000403616c740868696e7474657374000041000103616c740868696e74746573740000410001" +
			"00000e10000e00010465646765056f746865720003616c740868696e747465737400002e000100000e10005c00410f02" +
			"00000e107d3b18206a4788205dcd0868696e747465737400a32b176d324a74c7013c774889fb93f683ed5ae0a3bed505" +
			"3b6329cce379dcbd2530e58e27f753a3f396b75d2727a46c6c7485477cbba5a5b8dd101eb305b60f0465646765056f74" +
			"686572000001000100000e100004c63364140465646765056f7468657200001c000100000e10001020010db800000000" +
			"00000000000000200465646765056f7468657200002e000100000e10005900010f0200000e107d3b18206a4788204086" +
			"056f746865720028ffd10534c359d8b7a117f9b2a9efe97099c1acc1aa5bf2aa203027940c3068699f1fddbfff7b4a89" +
			"62fa72aba397795dc26f033b426ca1e19482eb251e2c020465646765056f7468657200002e000100000e100059001c0f" +
			"0200000e107d3b18206a4788204086056f74686572009a81ae63fac29bdc8cfd63a8da8018b2ea7496c72ea3016bc347" +
			"a2c91e97cc5428e26b1270e64f90b04974f64f6339a3e2ed687fdeae0d627dd3697817882102",
	},
	{
		key   = "sh_https_service_form",
		name  = "hinttest.",
		type  = .HTTPS,
		rcode = 0,
		wire  = "1234858000010002000000020868696e747465737400004100010868696e7474657374000041000100000e1000030001" +
			"000868696e747465737400002e000100000e10005c00410f0100000e107d3b18206a4788205dcd0868696e7474657374" +
			"00db9db4fa8ef99489b67f6a423b1d03f95ec4e757ca76ff5b02eb8b6f92ad8a7c4e5387ca9420c5613269e3550c23f7" +
			"673d18076d7c889229fc358e0658493e0d0868696e7474657374000001000100000e100004c00002010868696e747465" +
			"737400002e000100000e10005c00010f0100000e107d3b18206a4788205dcd0868696e74746573740027c64fc240151e" +
			"8be2782133be5910af1783754d2817c677a9adefa939b6db716a0ac818ac81c27626201c9f034953e534fd2c20f1da8f" +
			"3f6882e678d8051808",
	},
	{
		key   = "sh_mx_mixed",
		name  = "hinttest.",
		type  = .MX,
		rcode = 0,
		wire  = "1234858000010002000000060868696e747465737400000f00010868696e747465737400000f000100000e100011000a" +
			"046d61696c0868696e7474657374000868696e747465737400002e000100000e10005c000f0f0100000e107d3b18206a" +
			"4788205dcd0868696e747465737400797026fefb4a0abb447de0b47b9d6117c308dabd01b4ab3956d0d4a7e636fef565" +
			"46ef56f339a740a7ef2658630d3cf300d133d08605119e3a11d320eb38fe04046d61696c0868696e7474657374000001" +
			"000100000e100004c000021e046d61696c0868696e747465737400002e000100000e10005c00010f0200000e107d3b18" +
			"206a4788205dcd0868696e7474657374009a797b18de811928ae489b735b1e0958ce02cb10ee6069cc017f57253871d1" +
			"d26c1a70acfa77006af5af06eeeb3bf9f44327eccb80145b3aadac85b6c1a0a80e046d61696c0868696e747465737400" +
			"001c000100000e10001020010db80000000000000000000000300962797374616e6465720868696e7474657374000001" +
			"000100000e100004c000021f0962797374616e6465720868696e747465737400002e000100000e10005c00010f020000" +
			"0e107d3b18206a4788205dcd0868696e74746573740080628d3c210922aa070d90afbf86e8674f16ce51f80bc60ec075" +
			"960fd2a74abdbf31798fe67853e394e6598b27d209d0ff3c920a04a10a3499300eea848db706026e730861747461636b" +
			"6572076578616d706c65000001000100000e100004cb007142",
	},
	{
		key   = "sh_forged_hint",
		name  = "_svc._tcp.hinttest.",
		type  = .SRV,
		rcode = 0,
		wire  = "123485800001000200000002045f737663045f7463700868696e74746573740000210001045f737663045f7463700868" +
			"696e7474657374000021000100000e1000140000000001bb037376630868696e747465737400045f737663045f746370" +
			"0868696e747465737400002e000100000e10005c00210f0300000e107d3b18206a4788205dcd0868696e747465737400" +
			"bbfcf418fa1d70c84e3276243d5c573bedbde46c8fba2465eed38c04d8ed9cfca874065d5710c2148a6742ce898e61c5" +
			"d9a607c910dc17210641f8af4cf2780f037376630868696e7474657374000001000100000e100004cb00716303737663" +
			"0868696e747465737400002e000100000e10005c00010f0200000e107d3b18206a4788205dcd0868696e747465737400" +
			"53a91b39b29926d8127c6ef9eae27818576bf94508a6eb3db1ead70adbd8689ed4c1651d9ded05be0f1dc9dcc94b1b8d" +
			"b6968d1a394dfd9e78a3dbce9eb6fd01",
	},
	{
		key   = "sh_alias_mode",
		name  = "alias.hinttest.",
		type  = .HTTPS,
		rcode = 0,
		wire  = "12348580000100020000000205616c6961730868696e7474657374000041000105616c6961730868696e747465737400" +
			"0041000100000e10000e00000465646765056f746865720005616c6961730868696e747465737400002e000100000e10" +
			"005c00410f0200000e107d3b18206a4788205dcd0868696e747465737400ed7c2f198b09e58cb932399212033271a3cf" +
			"3b0762c4f11b8b38285127a004359155628bfae3d829829f3e4d38204d640edcb9cf4b3722c6f1110fad945ea9060465" +
			"646765056f74686572000001000100000e100004c63364140465646765056f7468657200002e000100000e1000590001" +
			"0f0200000e107d3b18206a4788204086056f746865720028ffd10534c359d8b7a117f9b2a9efe97099c1acc1aa5bf2aa" +
			"203027940c3068699f1fddbfff7b4a8962fa72aba397795dc26f033b426ca1e19482eb251e2c02",
	},
	{
		key   = "sh_wildcard_hint",
		name  = "alt2.hinttest.",
		type  = .HTTPS,
		rcode = 0,
		wire  = "12348580000100020000000204616c74320868696e7474657374000041000104616c74320868696e7474657374000041" +
			"000100000e10001100010477696c640868696e74746573740004616c74320868696e747465737400002e000100000e10" +
			"005c00410f0200000e107d3b18206a4788205dcd0868696e74746573740035a8ed7b5c625d07a9601a2e79e7aba7c743" +
			"a6c554660b3f56d2868bffca8397271f0ce4b19de252196f78655630443f3ad3690edd257dffe11389bfa6e96b0a0477" +
			"696c640868696e7474657374000001000100000e100004c00002280477696c640868696e747465737400002e00010000" +
			"0e10005c00010f0100000e107d3b18206a4788205dcd0868696e7474657374008646c3bb4ea1f3af4d8fd26f32edcc0e" +
			"ca26a1ec0c2cd7006e510227fabf32963466cd210aed61453e840f4c89fd9eaab2cde7ae1b42ad7d9e7958554192c606",
	},
	{
		key   = "sh_unreachable_zone",
		name  = "alt3.hinttest.",
		type  = .HTTPS,
		rcode = 0,
		wire  = "12348580000100020000000204616c74330868696e7474657374000041000104616c74330868696e7474657374000041" +
			"000100000e10000f00010465646765066e6f737563680004616c74330868696e747465737400002e000100000e10005c" +
			"00410f0200000e107d3b18206a4788205dcd0868696e7474657374007eccf9908360e17e2c0588085db3719c12821fc4" +
			"30a21f72994dc7986268f912f96989ca79aa34ba63d3d8567a038bb2d56ff1be24f325000dd9f73010b9ce0604656467" +
			"65066e6f73756368000001000100000e100004c00002320465646765066e6f7375636800002e000100000e10005a0001" +
			"0f0200000e107d3b18206a478820575f066e6f7375636800f02230c75e015e78cd9075b3163c289bac6b56fd8e258f5c" +
			"8abd40beb914770bbc1d7c5ed702cc3005c97c9e46cedbf9315216f87f739f3f140801f61d626e0a",
	},
	{
		key   = "sh_many_targets",
		name  = "hinttest.",
		type  = .MX,
		rcode = 0,
		wire  = "1234858000010029000000280868696e747465737400000f00010868696e747465737400000f000100000e10000a0000" +
			"036d7830027a30000868696e747465737400000f000100000e10000a0001036d7831027a31000868696e747465737400" +
			"000f000100000e10000a0002036d7832027a32000868696e747465737400000f000100000e10000a0003036d7833027a" +
			"33000868696e747465737400000f000100000e10000a0004036d7834027a34000868696e747465737400000f00010000" +
			"0e10000a0005036d7835027a35000868696e747465737400000f000100000e10000a0006036d7836027a36000868696e" +
			"747465737400000f000100000e10000a0007036d7837027a37000868696e747465737400000f000100000e10000a0008" +
			"036d7838027a38000868696e747465737400000f000100000e10000a0009036d7839027a39000868696e747465737400" +
			"000f000100000e10000c000a046d783130037a3130000868696e747465737400000f000100000e10000c000b046d7831" +
			"31037a3131000868696e747465737400000f000100000e10000c000c046d783132037a3132000868696e747465737400" +
			"000f000100000e10000c000d046d783133037a3133000868696e747465737400000f000100000e10000c000e046d7831" +
			"34037a3134000868696e747465737400000f000100000e10000c000f046d783135037a3135000868696e747465737400" +
			"000f000100000e10000c0010046d783136037a3136000868696e747465737400000f000100000e10000c0011046d7831" +
			"37037a3137000868696e747465737400000f000100000e10000c0012046d783138037a3138000868696e747465737400" +
			"000f000100000e10000c0013046d783139037a3139000868696e747465737400000f000100000e10000c0014046d7832" +
			"30037a3230000868696e747465737400000f000100000e10000c0015046d783231037a3231000868696e747465737400" +
			"000f000100000e10000c0016046d783232037a3232000868696e747465737400000f000100000e10000c0017046d7832" +
			"33037a3233000868696e747465737400000f000100000e10000c0018046d783234037a3234000868696e747465737400" +
			"000f000100000e10000c0019046d783235037a3235000868696e747465737400000f000100000e10000c001a046d7832" +
			"36037a3236000868696e747465737400000f000100000e10000c001b046d783237037a3237000868696e747465737400" +
			"000f000100000e10000c001c046d783238037a3238000868696e747465737400000f000100000e10000c001d046d7832" +
			"39037a3239000868696e747465737400000f000100000e10000c001e046d783330037a3330000868696e747465737400" +
			"000f000100000e10000c001f046d783331037a3331000868696e747465737400000f000100000e10000c0020046d7833" +
			"32037a3332000868696e747465737400000f000100000e10000c0021046d783333037a3333000868696e747465737400" +
			"000f000100000e10000c0022046d783334037a3334000868696e747465737400000f000100000e10000c0023046d7833" +
			"35037a3335000868696e747465737400000f000100000e10000c0024046d783336037a3336000868696e747465737400" +
			"000f000100000e10000c0025046d783337037a3337000868696e747465737400000f000100000e10000c0026046d7833" +
			"38037a3338000868696e747465737400000f000100000e10000c0027046d783339037a3339000868696e747465737400" +
			"002e000100000e10005c000f0f0100000e107d3b18206a4788205dcd0868696e7474657374009d47b643f5c361d51319" +
			"5c5e9aab28d693c151da7882fbbd50f396b664edca7812dd600004798fa5be83593cdee392e75620427aa89b0dec684d" +
			"5852da29690d036d7830027a30000001000100000e100004c0000264036d7831027a31000001000100000e100004c000" +
			"0265036d7832027a32000001000100000e100004c0000266036d7833027a33000001000100000e100004c0000267036d" +
			"7834027a34000001000100000e100004c0000268036d7835027a35000001000100000e100004c0000269036d7836027a" +
			"36000001000100000e100004c000026a036d7837027a37000001000100000e100004c000026b036d7838027a38000001" +
			"000100000e100004c000026c036d7839027a39000001000100000e100004c000026d046d783130037a31300000010001" +
			"00000e100004c000026e046d783131037a3131000001000100000e100004c000026f046d783132037a31320000010001" +
			"00000e100004c0000270046d783133037a3133000001000100000e100004c0000271046d783134037a31340000010001" +
			"00000e100004c0000272046d783135037a3135000001000100000e100004c0000273046d783136037a31360000010001" +
			"00000e100004c0000274046d783137037a3137000001000100000e100004c0000275046d783138037a31380000010001" +
			"00000e100004c0000276046d783139037a3139000001000100000e100004c0000277046d783230037a32300000010001" +
			"00000e100004c0000278046d783231037a3231000001000100000e100004c0000279046d783232037a32320000010001" +
			"00000e100004c000027a046d783233037a3233000001000100000e100004c000027b046d783234037a32340000010001" +
			"00000e100004c000027c046d783235037a3235000001000100000e100004c000027d046d783236037a32360000010001" +
			"00000e100004c000027e046d783237037a3237000001000100000e100004c000027f046d783238037a32380000010001" +
			"00000e100004c0000280046d783239037a3239000001000100000e100004c0000281046d783330037a33300000010001" +
			"00000e100004c0000282046d783331037a3331000001000100000e100004c0000283046d783332037a33320000010001" +
			"00000e100004c0000284046d783333037a3333000001000100000e100004c0000285046d783334037a33340000010001" +
			"00000e100004c0000286046d783335037a3335000001000100000e100004c0000287046d783336037a33360000010001" +
			"00000e100004c0000288046d783337037a3337000001000100000e100004c0000289046d783338037a33380000010001" +
			"00000e100004c000028a046d783339037a3339000001000100000e100004c000028b",
	},
}

// What the query callback was asked for, so a test can say what a hint cost.
// `misses` counts the lookups no fixture answers, which for these responses is
// exactly the probe into a target's own zone.
@(private = "file")
Sh_Calls :: struct {
	lookups: int,
	misses:  int,
}

@(private = "file")
sh_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	calls := (^Sh_Calls)(ctx)
	if calls != nil {
		calls.lookups += 1
	}
	for f in SH_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	if calls != nil {
		calls.misses += 1
	}
	return nil, false
}

@(private = "file")
sh_fixture :: proc(key: string) -> []u8 {
	for f in SH_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

@(private = "file")
sh_validator :: proc(calls: ^Sh_Calls) -> ^Validator {
	anchor, ok := parse_trust_anchor(SH_ANCHOR, context.temp_allocator)
	if !ok {
		return nil
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	return make_validator(sh_query, calls, Options{anchors = anchors})
}

@(private = "file")
sh_holds :: proc(records: []dns.Record, name: string, type: dns.Type) -> bool {
	for rec in records {
		if rec.type == type && dns.name_equal_fold(rec.name, name) {
			return true
		}
	}
	return false
}

// Asked for by what it covers: one owner name carries signatures over several
// types at once, so "an RRSIG survived" would be answered by any of them.
@(private = "file")
sh_holds_signature_over :: proc(records: []dns.Record, name: string, covered: dns.Type) -> int {
	found := 0
	for rec in records {
		if rec.type != .RRSIG || !dns.name_equal_fold(rec.name, name) {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, context.temp_allocator)
		if err == .None && sig.type_covered == covered {
			found += 1
		}
	}
	return found
}

// Validate one fixture and hand back the message a client would be sent.
@(private = "file")
sh_resolve :: proc(
	t: ^testing.T,
	key: string,
	qname: string,
	qtype: dns.Type,
	calls: ^Sh_Calls,
) -> (
	result: Result,
	pruned: dns.Message,
	ok: bool,
) {
	v := sh_validator(calls)
	if !testing.expect(t, v != nil, "the anchor should parse") {
		return {}, {}, false
	}
	defer destroy_validator(v)

	wire := sh_fixture(key)
	if !testing.expectf(t, wire != nil, "no fixture named %s", key) {
		return {}, {}, false
	}
	result = validate(v, qname, qtype, wire, time.unix(FIXTURE_TIME, 0))
	out, stripped := strip_unauthenticated(wire, result, context.temp_allocator, dns.MAX_MESSAGE)
	if !testing.expect(t, stripped, "the pruned response should rebuild") {
		return result, {}, false
	}
	msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return result, {}, false
	}
	return result, msg, true
}

/*
The control. If the canonical form these fixtures were signed against ever drifts
from the one the validator computes, this says so before every test below starts
failing for a reason of its own.
*/
@(test)
test_sh_zone_chain_is_sound :: proc(t: ^testing.T) {
	v := sh_validator(nil)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	budget := Budget{}
	for zone in ([]string{"hinttest.", "other."}) {
		status, keys, established := zone_trust(v, &budget, zone, time.unix(FIXTURE_TIME, 0), context.temp_allocator)
		testing.expect_value(t, status, Status.Secure)
		testing.expect_value(t, established, zone)
		testing.expect(t, len(keys) > 0, "the zone should publish a key")
	}
	free_all(context.temp_allocator)
}

/*
The everyday case, and the one that has to cost nothing.

An SRV answer whose target sits in the zone the answer already established: the
keys are in hand, `zone_step` finds the zone in the validator's cache, and the
addresses come out authenticated for no upstream query at all. The lookup count
is asserted for that reason - "the hints survived" would be satisfied by an
implementation that walked the chain again for each of them, which is the cost
`MAX_LOOKUPS_PER_QUERY` was sized against.
*/
@(test)
test_hints_in_the_answers_own_zone_are_kept :: proc(t: ^testing.T) {
	calls := Sh_Calls{}
	result, pruned, ok := sh_resolve(t, "sh_srv_same_zone", "_svc._tcp.hinttest.", .SRV, &calls)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "_svc._tcp.hinttest.", .SRV), "the answer should survive")

	testing.expect(
		t,
		sh_holds(pruned.additional, "svc.hinttest.", .A),
		"the signed A hint for the SRV target was dropped",
	)
	testing.expect(
		t,
		sh_holds(pruned.additional, "svc.hinttest.", .AAAA),
		"the signed AAAA hint for the SRV target was dropped",
	)
	// A client that validates for itself needs the signature, not just the
	// address: without it the record is one it has to refuse or re-fetch, which
	// is the round trip this whole change is about saving.
	testing.expect_value(t, sh_holds_signature_over(pruned.additional, "svc.hinttest.", .A), 1)
	testing.expect_value(t, sh_holds_signature_over(pruned.additional, "svc.hinttest.", .AAAA), 1)

	// Root DNSKEY, the delegation to hinttest., and its keys. Nothing more: the
	// target's zone is the answer's zone.
	testing.expectf(
		t,
		calls.lookups == 3,
		"a hint inside the answer's own zone cost %d lookups; it should reuse the keys already in hand",
		calls.lookups,
	)
	free_all(context.temp_allocator)
}

/*
A target in a second zone, which is the chain walk #189 is really asking for.

`edge.other.` is signed by `other.`, a zone nothing about this question
established, so keeping its address means walking down to it. That is the cost
the issue weighed against a round trip for every client, and it is bounded
rather than avoided.
*/
@(test)
test_a_hint_in_a_second_zone_is_walked_to :: proc(t: ^testing.T) {
	calls := Sh_Calls{}
	result, pruned, ok := sh_resolve(t, "sh_https_cross_zone", "alt.hinttest.", .HTTPS, &calls)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "alt.hinttest.", .HTTPS), "the answer should survive")

	testing.expect(
		t,
		sh_holds(pruned.additional, "edge.other.", .A),
		"the A hint signed by the target's own zone was dropped",
	)
	testing.expect(
		t,
		sh_holds(pruned.additional, "edge.other.", .AAAA),
		"the AAAA hint signed by the target's own zone was dropped",
	)

	// The premise, not just the judgement: the addresses were kept *because* a
	// second chain was walked, so the walk has to show up in what was asked for.
	asked_ds := false
	asked_dnskey := false
	for f in SH_FIXTURES {
		if !dns.name_equal_fold(f.name, "other.") {
			continue
		}
		asked_ds ||= f.type == .DS
		asked_dnskey ||= f.type == .DNSKEY
	}
	testing.expect(t, asked_ds && asked_dnskey, "the fixture set should carry the second zone's chain")
	testing.expectf(
		t,
		calls.lookups == 5,
		"reaching a target in a second zone took %d lookups, not the answer's three plus that zone's two",
		calls.lookups,
	)
	free_all(context.temp_allocator)
}

/*
A ServiceMode TargetName of "." means the owner name, not the root.

RFC 9460 section 2.5, and the shape almost every HTTPS answer on the wire has
today: `example.com. HTTPS 1 . alpn=...`, with the addresses for `example.com.`
itself beside it. Reading the "." literally would look up the root's addresses,
find none, and drop the hints the record was sent with.
*/
@(test)
test_a_service_form_target_names_the_owner :: proc(t: ^testing.T) {
	result, pruned, ok := sh_resolve(t, "sh_https_service_form", "hinttest.", .HTTPS, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(
		t,
		sh_holds(pruned.additional, "hinttest.", .A),
		"an HTTPS record in service form kept no address for its own owner",
	)
	free_all(context.temp_allocator)
}

/*
AliasMode names no hint.

Priority zero is a redirection the client resolves by name (RFC 9460 section
2.4.2) rather than a service it connects to, so section 5's argument for
carrying the addresses does not apply - and the address here is genuinely signed,
which is what makes this a test of the rule rather than of the signature check.
*/
@(test)
test_alias_mode_keeps_no_hint :: proc(t: ^testing.T) {
	result, pruned, ok := sh_resolve(t, "sh_alias_mode", "alias.hinttest.", .HTTPS, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "edge.other.", .A),
		"an AliasMode target's address went out under the AD bit",
	)
	free_all(context.temp_allocator)
}

/*
One MX answer carrying every kind of record that must not survive it.

The exchange's A is signed and kept. Beside it: the exchange's AAAA with no
signature at all, an address for a name the answer never mentioned that is
nonetheless correctly signed by the same zone, and a plain piece of attacker's
glue. Each is a different way to be in the additional section without being
something this server may vouch for, and all three go.

The signed bystander is the sharp one. It would pass any test that asked only
"did this zone sign it" - so what keeps it out is that the answer named no such
target, which is the clause that stops a response's additional section being a
free channel for whatever its sender wants stamped with AD.
*/
@(test)
test_only_the_named_target_keeps_its_addresses :: proc(t: ^testing.T) {
	result, pruned, ok := sh_resolve(t, "sh_mx_mixed", "hinttest.", .MX, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "hinttest.", .MX), "the answer should survive")

	testing.expect(
		t,
		sh_holds(pruned.additional, "mail.hinttest.", .A),
		"the signed address for the MX exchange was dropped",
	)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "mail.hinttest.", .AAAA),
		"an unsigned address for the MX exchange went out under the AD bit",
	)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "bystander.hinttest.", .A),
		"a signed address for a name the answer never named went out under the AD bit",
	)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "ns.attacker.example.", .A),
		"unsigned glue went out under the AD bit",
	)
	free_all(context.temp_allocator)
}

/*
A hint whose signature does not cover the record beside it.

The RRSIG is the zone's, names this owner and this type, and is inside its
window - everything a cheap check reads. Only the addresses differ, which is
exactly the substitution an on-path attacker makes in front of a plain UDP
upstream: leave the answer alone, rewrite the address the client will connect to.
The verdict on the answer must not move either, or a forged hint becomes a way to
SERVFAIL a name that resolves perfectly well.
*/
@(test)
test_a_forged_hint_is_dropped_and_the_answer_stands :: proc(t: ^testing.T) {
	result, pruned, ok := sh_resolve(t, "sh_forged_hint", "_svc._tcp.hinttest.", .SRV, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "_svc._tcp.hinttest.", .SRV), "the answer should survive")
	testing.expect(
		t,
		!sh_holds(pruned.additional, "svc.hinttest.", .A),
		"an address the signature beside it does not cover went out under the AD bit",
	)
	free_all(context.temp_allocator)
}

/*
A hint that verifies against a wildcard is still dropped.

RFC 4035 section 5.3.4 has a validator demand a denial that the expanded name has
nothing of its own, and for a hint that proof would live in the authority section
of a zone this message is not even about. Without it, one wildcard signature
vouches for an address at every name under the encloser - including names the
zone answers for directly, which is the wildcard replay `validate_wildcard_proof`
exists to refuse on the answer path.

The premise is asserted rather than assumed. A test that only watched the record
disappear would pass just as happily if the signature were broken, and would then
be pinning nothing: so the signature is put to `validate_rrset` on its own first,
where it comes back `Secure` and names the encloser it expanded from.
*/
@(test)
test_a_wildcard_hint_is_dropped :: proc(t: ^testing.T) {
	v := sh_validator(nil)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	wire := sh_fixture("sh_wildcard_hint")
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	budget := Budget{}
	unix := u32(FIXTURE_TIME)
	records := records_of(msg.additional, "wild.hinttest.", .A, .IN, context.temp_allocator)
	sigs := sigs_covering(msg.additional, "wild.hinttest.", .A, .IN, context.temp_allocator)
	status, encloser, _, _, _ := validate_rrset(
		v,
		&budget,
		"wild.hinttest.",
		.A,
		.IN,
		records,
		sigs,
		unix,
		time.unix(FIXTURE_TIME, 0),
		context.temp_allocator,
	)
	testing.expect_value(t, status, Status.Secure)
	testing.expectf(
		t,
		encloser == "hinttest.",
		"the hint was meant to be a wildcard expansion and reported an encloser of %q",
		encloser,
	)

	result, pruned, ok := sh_resolve(t, "sh_wildcard_hint", "alt2.hinttest.", .HTTPS, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "wild.hinttest.", .A),
		"a wildcard-expanded address went out under the AD bit with no proof behind it",
	)
	free_all(context.temp_allocator)
}

/*
A hint in a zone nothing delegates to.

The signature is real, made by a key that really does sign for `nosuch.`, and
there is no chain from any trust anchor down to it - so this server has no
opinion on the record and says so by dropping it. `Insecure` data is not
authenticated data, and the AD bit does not distinguish.
*/
@(test)
test_a_hint_whose_zone_cannot_be_reached_is_dropped :: proc(t: ^testing.T) {
	result, pruned, ok := sh_resolve(t, "sh_unreachable_zone", "alt3.hinttest.", .HTTPS, nil)
	if !ok {
		return
	}
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "alt3.hinttest.", .HTTPS), "the answer should survive")
	testing.expect(
		t,
		!sh_holds(pruned.additional, "edge.nosuch.", .A),
		"an address from a zone with no chain of trust went out under the AD bit",
	)
	free_all(context.temp_allocator)
}

/*
Forty targets in forty zones do not buy forty chain walks.

`MAX_LOOKUPS_PER_QUERY` was sized for one walk per answer, and a response is free
to name as many targets as fit in it - which is the budget question #189 raised
against doing this at all. `MAX_HINT_TARGETS` is the answer: the walks stop at
eight whatever the sender writes, and the answer keeps the verdict it earned
before any of them ran.
*/
@(test)
test_many_targets_do_not_buy_a_walk_apiece :: proc(t: ^testing.T) {
	calls := Sh_Calls{}
	result, pruned, ok := sh_resolve(t, "sh_many_targets", "hinttest.", .MX, &calls)
	if !ok {
		return
	}
	// Whatever the hints cost, they must not cost the answer its verdict.
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect(t, sh_holds(pruned.answer, "hinttest.", .MX), "the answer should survive")
	testing.expect_value(t, len(result.additional), 0)

	// Every miss is a probe into a target's own zone: no fixture answers for
	// `zN.`, so the count is the number of walks the hints provoked.
	testing.expectf(
		t,
		calls.misses <= MAX_HINT_TARGETS,
		"40 targets provoked %d chain walks; the cap is %d",
		calls.misses,
		MAX_HINT_TARGETS,
	)
	testing.expectf(
		t,
		calls.lookups <= MAX_LOOKUPS_PER_QUERY,
		"one question cost %d lookups, past the %d it is allowed",
		calls.lookups,
		MAX_LOOKUPS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

/*
A denial keeps no hints.

Nothing on that path authenticates an answer RRset, so nothing on it names a
target - and the additional section goes back to holding the OPT record and
nothing else, which is what #177 left it holding. Worth pinning separately
because `Result.additional` is a field the prune reads on every `Secure` verdict,
and a denial reaching it with something in it would be a hole the answer path's
tests could not see.
*/
@(test)
test_a_denial_keeps_no_hints :: proc(t: ^testing.T) {
	v := make_validator(sh_denial_query, nil, Options{})
	defer destroy_validator(v)

	wire, _ := decode_hex(sh_denial_fixture("nodata_cloudflare"), context.temp_allocator)
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture did not decode") {
		return
	}

	// An address bolted onto a denial, at the name that was asked about.
	additional := make([dynamic]dns.Record, 0, len(msg.additional) + 1, context.temp_allocator)
	append(&additional, ..msg.additional)
	append(
		&additional,
		dns.Record {
			name = "nosuchname-xq7.cloudflare.com.",
			type = .A,
			class = .IN,
			ttl = 300,
			data = dns.Rdata_A{addr = {203, 0, 113, 66}},
		},
	)
	msg.additional = additional[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "nosuchname-xq7.cloudflare.com.", .A, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect_value(t, len(result.additional), 0)

	out, stripped := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect(t, stripped, "the pruned response should rebuild")
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)
	testing.expect(
		t,
		!sh_holds(pruned.additional, "nosuchname-xq7.cloudflare.com.", .A),
		"an address bolted onto a denial went out under the AD bit",
	)
	testing.expect(t, dns.edns_present(pruned), "the OPT record should survive")
	free_all(context.temp_allocator)
}

@(private = "file")
sh_denial_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

@(private = "file")
sh_denial_fixture :: proc(key: string) -> string {
	for f in FIXTURES {
		if f.key == key {
			return f.wire
		}
	}
	return ""
}

/*
The targets are read from the RRsets that were authenticated, not from the answer
section.

Defence in depth rather than the only line: an unsigned RRset in the answer
section drags the whole verdict below `Secure` and no hint is ever reached. But
`hint_targets` is what decides where this server spends its chain walks, and a
list built by scanning the section would be a list whoever wrote the response
chose - so the rule is pinned on its own, with two MX records at two owners and
only one of them vouched for.
*/
@(test)
test_hint_targets_come_only_from_authenticated_rrsets :: proc(t: ^testing.T) {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name = "real.example.",
		type = .MX,
		class = .IN,
		ttl = 3600,
		data = dns.Rdata_MX{preference = 10, exchange = "mail.real.example."},
	}
	answer[1] = dns.Record {
		name = "appended.example.",
		type = .MX,
		class = .IN,
		ttl = 3600,
		data = dns.Rdata_MX{preference = 10, exchange = "mail.attacker.example."},
	}

	answered := make([]Authenticated_Set, 1, context.temp_allocator)
	answered[0] = Authenticated_Set {
		name  = "real.example.",
		type  = .MX,
		class = .IN,
	}

	targets := hint_targets(dns.Message{answer = answer}, answered, .IN, context.temp_allocator)
	testing.expect_value(t, len(targets), 1)
	if len(targets) == 1 {
		testing.expect_value(t, targets[0], "mail.real.example.")
	}
	free_all(context.temp_allocator)
}

/*
A hint padded with signatures is capped like everything else.

`authenticated_only` holds every RRset it keeps to `MAX_SIGNATURES_PER_RRSET`
beyond the one that verified, so that an answer padded with hundreds of
same-signer forgeries is not stamped with AD, cached, and handed to every
downstream validator to grind through on every hit. Hints go through the same
procedure, and this says so - the additional section is a new way into it, and a
new way in is a new way for the cap to have been missed.
*/
@(test)
test_a_padded_hint_keeps_a_bounded_number_of_signatures :: proc(t: ^testing.T) {
	v := sh_validator(nil)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	wire := sh_fixture("sh_srv_same_zone")
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	/*
	Forgeries in front of the genuine signature, each a copy of it naming the
	same signer over the same type - which is all `authenticated_only` reads,
	and so all it takes to be kept.

	The key tag is flipped rather than the signature bytes, and that is what
	isolates the cap from the budget. A copy that keeps the real tag has to be
	verified before it can be refused, and sixty-four of those spend
	`MAX_VERIFICATIONS_PER_QUERY` outright - the hint is then dropped for want of
	allowance, which is safe and is the next test, but it says nothing about
	whether the cap here works. A flipped tag names a key the zone never
	published, so `signature_worth_trying` throws each away for nothing, the
	genuine signature is reached, and what is left to decide is how many of the
	forgeries travel with it.
	*/
	padded := make([dynamic]dns.Record, 0, len(msg.additional) + 64, context.temp_allocator)
	for rec in msg.additional {
		if rec.type != .RRSIG {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, context.temp_allocator)
		if err != .None || sig.type_covered != .A {
			continue
		}
		for _ in 0 ..< 64 {
			copied := make([]u8, len(rdata), context.temp_allocator)
			copy(copied, rdata)
			// The key tag sits at offset 16, after the fixed fields and
			// before the signer name.
			copied[16] ~= 0xff
			copied[17] ~= 0xff
			append(
				&padded,
				dns.Record {
					name = rec.name,
					type = .RRSIG,
					class = rec.class,
					ttl = rec.ttl,
					data = dns.Rdata_Raw{data = copied},
				},
			)
		}
	}
	testing.expect(t, len(padded) == 64, "the fixture should carry one signature over the A hint")
	append(&padded, ..msg.additional)
	msg.additional = padded[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "_svc._tcp.hinttest.", .SRV, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)

	out, stripped := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect(t, stripped, "the pruned response should rebuild")
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	// The genuine record survives the padding - that is what makes a cap safe
	// here, and it is the failure a plain count cap had.
	testing.expect(t, sh_holds(pruned.additional, "svc.hinttest.", .A), "the authenticated hint was dropped")
	kept := sh_holds_signature_over(pruned.additional, "svc.hinttest.", .A)
	testing.expectf(
		t,
		kept <= MAX_SIGNATURES_PER_RRSET + 1,
		"64 forged signatures over one hint left %d of them in the answer",
		kept,
	)
	free_all(context.temp_allocator)
}

/*
A hint padded with signatures that have to be verified is dropped, and the answer
is not.

The other half of the pair above. Sixty-four copies of the genuine signature with
the signature bytes flipped keep the real key tag, the real algorithm and the
real window, so each one has to be verified before it can be refused -
`MAX_VERIFICATIONS_PER_QUERY` is spent, the genuine signature behind them is
never reached, and the hint goes.

That is the documented trade the budget already makes, and what matters here is
where the loss lands. Hints are authenticated after the verdict is settled, so a
padded additional section costs a client one round trip for an address and
nothing else: the answer keeps its records, keeps its signature and keeps the AD
bit. If it did not, appending signatures to a section nobody asked for would be a
way to SERVFAIL any name.
*/
@(test)
test_padding_a_hint_cannot_take_the_answer_with_it :: proc(t: ^testing.T) {
	v := sh_validator(nil)
	testing.expect(t, v != nil, "the anchor should parse")
	defer destroy_validator(v)

	wire := sh_fixture("sh_srv_same_zone")
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	padded := make([dynamic]dns.Record, 0, len(msg.additional) + 64, context.temp_allocator)
	for rec in msg.additional {
		if rec.type != .RRSIG {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, context.temp_allocator)
		if err != .None || sig.type_covered != .A {
			continue
		}
		for _ in 0 ..< 64 {
			copied := make([]u8, len(rdata), context.temp_allocator)
			copy(copied, rdata)
			copied[len(copied) - 1] ~= 0xff
			append(
				&padded,
				dns.Record {
					name = rec.name,
					type = .RRSIG,
					class = rec.class,
					ttl = rec.ttl,
					data = dns.Rdata_Raw{data = copied},
				},
			)
		}
	}
	testing.expect(t, len(padded) == 64, "the fixture should carry one signature over the A hint")
	append(&padded, ..msg.additional)
	msg.additional = padded[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "_svc._tcp.hinttest.", .SRV, tampered, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)

	out, stripped := strip_unauthenticated(tampered, result, context.temp_allocator, dns.MAX_MESSAGE)
	testing.expect(t, stripped, "the pruned response should rebuild")
	pruned, perr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, perr, dns.Decode_Error.None)

	testing.expect(t, sh_holds(pruned.answer, "_svc._tcp.hinttest.", .SRV), "the answer should survive")
	testing.expect(t, sh_holds_signature_over(pruned.answer, "_svc._tcp.hinttest.", .SRV) == 1, "the answer's signature should survive")
	testing.expect(
		t,
		!sh_holds(pruned.additional, "svc.hinttest.", .A),
		"a hint whose signature was never reached went out under the AD bit",
	)
	free_all(context.temp_allocator)
}
