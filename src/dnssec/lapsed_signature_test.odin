package dnssec

import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #360: a signature outside its validity window is reported by its window.

RFC 8914 has a code for each side of it - 7, Signature Expired (section 4.8),
and 8, Signature Not Yet Valid (section 4.9) - for when "no signatures are
presently valid". It is the one DNSSEC failure whose cause is usually this
server's clock, so it is not reported as code 6 and "broken chain of trust",
the words a forged zone gets: a box running two hours slow refuses every
unsigned delegation under .org whose DS denial is signed in its future, and
the operator has to be pointed at the clock rather than the zone.

Each road a signature is checked on gets one step lapsed and every other step
current, so a verdict naming the window could only have come from that road.

Generated - `testdata/gen/sign_fixtures.py`, scenario `lapsed_signatures`.
*/

@(private = "file")
LP_ANCHOR :: ". IN DS 58035 15 2 40943A68A2E3F606BFEEAC456469D9F16E5E088D23C7875041F9E763F9E827E2"

// The scenario's two windows, as the reason names them.
@(private = "file")
LP_EXPIRED :: "signature expired at 2026-07-03T10:00:00Z"

@(private = "file")
LP_NOT_YET :: "signature not yet valid until 2046-07-28T10:00:00Z"

@(private = "file")
LP_FIXTURES := []Fixture{
	{
		key   = "lp_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f81f4e642ed7202d4ef022045404b937b" +
			"7f938584a4d09bee7b475cc06f4515f200002e000100000e10005300300f0000000e107d3b18206a478820e2b300ad60" +
			"f6b6dd69da0b671e4051d60562c774759cfc6cd3a7d3b88047c6148c7b086243788c983df000e7d38368e0dd491084d0" +
			"8df3737fa3fc6091bf867a2b380a",
	},
	{
		key   = "lp_dsx_ds",
		name  = "dsx.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000364737800002b00010364737800002b000100000e100024e2700f029bb4260e8944bda5" +
			"89235091f018a26ec4f4e334fa1d64ef74c19867b02896f90364737800002e000100000e100053002b0f0100000e106a" +
			"4788206a1ffb20e2b30092d006526f56c9cc955fdd55aca7ddd06bf61b1fdda7377e9c17c6936a1956bb27adea8affa5" +
			"d4d06eca793cd260a046fe37726ca74ce0bf14e75bda1e36ec02",
	},
	{
		key   = "lp_dsx_dnskey",
		name  = "dsx.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000003647378000030000103647378000030000100000e1000240101030fd3db90225fa61ba0" +
			"4385ad795157f6e5ad07677c30c27fc2ca9994b8fd99a3ea0364737800002e000100000e10005700300f0100000e107d" +
			"3b18206a478820e27003647378007cf2e13ce76a7c101d544441c9244adfbe93143b2c5b5887df0a0a6d196f9b39fce5" +
			"4407d790478719d9bc578747c1ee38435759d090dad0d78236c183597d01",
	},
	{
		key   = "lp_dkx_ds",
		name  = "dkx.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000003646b7800002b000103646b7800002b000100000e100024a2560f02194a5897db1be12a" +
			"ade58e79bb1984335666031548a1965f8ee93dfddd75223503646b7800002e000100000e100053002b0f0100000e107d" +
			"3b18206a478820e2b3009dd17be67808aae6deb18a8e641f7c599db3ae2f0fa0e642bf081994fab4906d6e36c25ef82c" +
			"61e457efb4d53f2717238ac821a2d118fd1f43f980f45d4c700a",
	},
	{
		key   = "lp_dkx_dnskey",
		name  = "dkx.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000003646b78000030000103646b78000030000100000e1000240101030f9cb3e6d850e115f8" +
			"9eb3ac7c541796f594ae93f8b22c9b37f62980d0fd19938303646b7800002e000100000e10005700300f0100000e10a2" +
			"d31e2090071b20a25603646b78001d27284790f10052ec64ac4dd90f59d8db31337cf2eb88a8468bc4c2bcc98befa1a3" +
			"52eb5f56863b7062edb91b73632bc5cfa8c6c5b54c0f6a932024f18b8203",
	},
	{
		key   = "lp_lt_ds",
		name  = "lt.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000200000000026c7400002b0001026c7400002b000100000e10002403a10f0233fcfd070d35f771e284" +
			"76257e4660107ed7600cb369e097a9e35e53eea31c8e026c7400002e000100000e100053002b0f0100000e107d3b1820" +
			"6a478820e2b300c68113d4c918b2d40ee94a2e68e9871e9ac303aae79dc05a8ae9f8ddf6278c16f458d1e69fac8fc559" +
			"96eeeea20eacb6d191972274e312083c536ca28a23350f",
	},
	{
		key   = "lp_lt_dnskey",
		name  = "lt.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "123485800001000200000000026c740000300001026c74000030000100000e1000240101030f4b3d1bf5bfc5181c684c" +
			"63bfd4ff8116dca28511f7a404868c1f4216e61c8c28026c7400002e000100000e10005600300f0100000e107d3b1820" +
			"6a47882003a1026c7400afd737140c268a71cb4254dfeb6288148932730d857d590bafdff8192d07e287b0817cbd82aa" +
			"ccf43eef6e8ecf8c70107ddf01ee9a66e2b4df7cae18341da601",
	},
	{
		key   = "lp_wl_ds",
		name  = "wl.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000002776c00002b000102776c00002b000100000e100024abed0f028b0b42e5ad0a95c38a22" +
			"4acfa1f61026ad8f46c5647140db4f5ad1bc808f194102776c00002e000100000e100053002b0f0100000e107d3b1820" +
			"6a478820e2b300dd09778285203c3256ae587582609c14556111ac9241cac11925b304c65385bec675640d27c6673894" +
			"737d99a1dc09d6b68c832642b9cc2be057ae9ecda2e308",
	},
	{
		key   = "lp_wl_dnskey",
		name  = "wl.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000002776c000030000102776c000030000100000e1000240101030f914fb84388fc4ea2bfd3" +
			"dee6f08575bf68f33f8394354ad6ad36eed49f18bf0402776c00002e000100000e10005600300f0100000e107d3b1820" +
			"6a478820abed02776c00cf2f8e73371f8fbdfbd00f1827efe6b5729d52938fd0e25085c527a4042ba885322cbc558c63" +
			"bd439a54419078f9ec731e8d711af03fe6155f857db102f22c07",
	},
	{
		key   = "lp_wm_ds",
		name  = "wm.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020000000002776d00002b000102776d00002b000100000e100024d13d0f0206cd099045f981474c00" +
			"a41ddf6f1f88d0123519bdd2f4730434f4f85cef768502776d00002e000100000e100053002b0f0100000e107d3b1820" +
			"6a478820e2b30003802f682089ae949f06fad9f98abed6d83f632c1f717cde4b171c1992a70f00ce9e7d7bd9b6b183e9" +
			"a1a3f01386e61b3dbad471adb358c24761f6b053a1a604",
	},
	{
		key   = "lp_wm_dnskey",
		name  = "wm.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000002776d000030000102776d000030000100000e1000240101030f7f026e69e0c673ea935a" +
			"d14c76692eb7aca7f0c85dc4e9cd2ce87841cf5e27bd02776d00002e000100000e10005600300f0100000e107d3b1820" +
			"6a478820d13d02776d00fd24f1958165d41734b83dfbafd789920bbd6edd1f564b1d56a7f1685eecc150cdb72b5cf29b" +
			"dc9e514f4dea1eb332f13327b54122c854940bd2d03e4b0f2207",
	},
	{
		key   = "lp_dsx_www",
		name  = "www.dsx.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000037777770364737800000100010377777703647378000001000100000e100004c0000201" +
			"037777770364737800002e000100000e10005700010f0200000e107d3b18206a478820e27003647378001afe4eb08370" +
			"33af24d38de0c2868a932f9c89e5931f5ae544fd865fa71bbc025499ff078043e256c77281febabefdb0261cf2ace569" +
			"e0c1b3900d56faaaa20e",
	},
	{
		key   = "lp_dkx_www",
		name  = "www.dkx.",
		type  = .A,
		rcode = 0,
		wire  = "1234858000010002000000000377777703646b7800000100010377777703646b78000001000100000e100004c0000201" +
			"0377777703646b7800002e000100000e10005700010f0200000e107d3b18206a478820a25603646b7800afca433a7965" +
			"76a4acfa195418c8d2173f7762000879d26f78af31acae8e56c641238e3268bf3dc2275db8067eebe402eff757f59653" +
			"e5eec2056586c958ee0b",
	},
	{
		key   = "lp_both_ds",
		name  = "both.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100000004000004626f7468026c7400002b000104626f7468026c7400002f000100000e10001205656172" +
			"6c79026c7400000640000000000304626f7468026c7400002e000100000e100056002f0f0200000e107d3b18206a4788" +
			"2003a1026c7400f25903211d7e2c4a033a9e00607d8ff83fd179d528eb482b3bad47d98cec995c786deaa46e7772ec3f" +
			"4cbac1a1c4d7b5837adef71b7d57cdeebc180ef166f005026c74000006000100000e10002a026e73026c74000a686f73" +
			"746d6173746572026c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600060f" +
			"0100000e107d3b18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a29" +
			"1ec399890ff4a37cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_early_ds",
		name  = "early.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000056561726c79026c7400002b0001056561726c79026c7400002f000100000e100011046c" +
			"617465026c74000006400000000003056561726c79026c7400002e000100000e100056002f0f0200000e107d3b18206a" +
			"47882003a1026c74002e501706869488cc9e37e714e1c9c25a6e828af724547eb50dedd9d6c9b2907289a37aa5560661" +
			"ec8c61b084ac25fafaaf9d257db839d22aa0d94e0d342aeb0e026c74000006000100000e10002a026e73026c74000a68" +
			"6f73746d6173746572026c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600" +
			"060f0100000e107d3b18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e" +
			"5a291ec399890ff4a37cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_late_ds",
		name  = "late.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000046c617465026c7400002b0001046c617465026c7400002f000100000e100012056d6978" +
			"6564026c74000006400000000003046c617465026c7400002e000100000e100056002f0f0200000e107d3b18206a4788" +
			"2003a1026c7400395f58050813beebab1e21b4a73062b080bf9ecb08fa6dc9bbba7413e0f232e203063abbd34cfc1075" +
			"f5aa79d689cd8f40ff3cbd0c1190d934a55465a57b4c0b026c74000006000100000e10002a026e73026c74000a686f73" +
			"746d6173746572026c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600060f" +
			"0100000e107d3b18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a29" +
			"1ec399890ff4a37cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_mixed_ds",
		name  = "mixed.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000056d69786564026c7400002b0001056d69786564026c7400002f000100000e1000150875" +
			"6e7369676e6564026c74000006400000000003056d69786564026c7400002e000100000e100056002f0f0200000e107d" +
			"3b18206a47882003a1026c7400114910af92ecc6260a8da0f22b41e725fc5cd377e315a7fe7b335e02a8400df1594e77" +
			"47bba6fa0b75b19ce98d12bb8be2b756d6640bb290521ee9f05fb31f01026c74000006000100000e10002a026e73026c" +
			"74000a686f73746d6173746572026c74000000000100000e100000038400093a800000012c026c7400002e000100000e" +
			"10005600060f0100000e107d3b18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d080" +
			"7197585e5a291ec399890ff4a37cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_late_a",
		name  = "late.lt.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000046c617465026c740000010001046c617465026c74000001000100000e100004c0000202" +
			"046c617465026c7400002e000100000e10005600010f0200000e106a4788206a1ffb2003a1026c7400a0982dee0715b4" +
			"97d1b39c35a498612b8e897609d84b25dff37989a3e81f73e5fd77e7f2bdcdbd31fa51ac1d478b3b95e2c75e509b4203" +
			"547b3306d3952d810b",
	},
	{
		key   = "lp_early_a",
		name  = "early.lt.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200000000056561726c79026c740000010001056561726c79026c74000001000100000e100004c000" +
			"0202056561726c79026c7400002e000100000e10005600010f0200000e10a2d31e2090071b2003a1026c7400d2316d66" +
			"8b15d95dcbae0733259207c48137dbbf89f56a5a9f034513b873115cdf79c75ecf09d1029bd89f8076908b73b7117099" +
			"14feb32e43038ce79c41dc07",
	},
	{
		key   = "lp_both_a",
		name  = "both.lt.",
		type  = .A,
		rcode = 0,
		wire  = "12348580000100030000000004626f7468026c74000001000104626f7468026c74000001000100000e100004c0000203" +
			"04626f7468026c7400002e000100000e10005600010f0200000e106a4788206a1ffb2003a1026c7400510558d202a226" +
			"6a3b20d14cda16efd856211c7b1688dad57fda121d12f21ff67306658bf5bd8b36d575aa95560afe348f732fdd2adb6b" +
			"1a352e8bf67426310c04626f7468026c7400002e000100000e10005600010f0200000e107d3b18206a47882003a1026c" +
			"7400ba671a3173ffc4a710f082a19d63de88e446c478e8d51d24c09a88b3b56409e9117876508ce9ea2c8046e65e3112" +
			"1e1e38a606769d19c3daea49355b6e679f03",
	},
	{
		key   = "lp_mixed_a",
		name  = "mixed.lt.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000300000000056d69786564026c740000010001056d69786564026c74000001000100000e100004c000" +
			"0204056d69786564026c7400002e000100000e10005600010f0200000e106a4788206a1ffb2003a1026c74003e8dca2e" +
			"d707d9202d5a6a9c3bfd0f827d1588ecfe78942f5404af36282c9755083eed44de386bb9d9ff0349ea7b30b27e920751" +
			"986b71434c01d75cd5d23a03056d69786564026c7400002e000100000e10005600010f0200000e107d3b18206a478820" +
			"03a1026c7400e29bba1dd3015f2cdd38369bd8afd869b50b1ca838d1a495faa061137a1c324c4b2eb6eaf0b1a51febe7" +
			"5e739141428df7f6f09b260e1183325576eb160b0409",
	},
	{
		key   = "lp_unsigned_ds",
		name  = "unsigned.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100000004000008756e7369676e6564026c7400002b000108756e7369676e6564026c7400002f00010000" +
			"0e10000c026c7400000620000000000108756e7369676e6564026c7400002e000100000e100056002f0f0200000e10a2" +
			"d31e2090071b2003a1026c7400760231a69a1e360d0424b6f25cb665d9faf2a047a4322bd7f5df1470c07ff25eb059fb" +
			"14088cbe37df714b2a7111d3d4da9a6a5c0ee46aa24b4eeded648a4f0e026c74000006000100000e10002a026e73026c" +
			"74000a686f73746d6173746572026c74000000000100000e100000038400093a800000012c026c7400002e000100000e" +
			"10005600060f0100000e107d3b18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d080" +
			"7197585e5a291ec399890ff4a37cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_insecure_a",
		name  = "www.unsigned.lt.",
		type  = .A,
		rcode = 0,
		wire  = "1234858000010001000000000377777708756e7369676e6564026c7400000100010377777708756e7369676e6564026c" +
			"74000001000100000e100004c0000205",
	},
	{
		key   = "lp_nope_ds",
		name  = "nope.lt.",
		type  = .DS,
		rcode = 3,
		wire  = "123485830001000000060000046e6f7065026c7400002b0001056d69786564026c7400002f000100000e10001508756e" +
			"7369676e6564026c74000006400000000003056d69786564026c7400002e000100000e100056002f0f0200000e107d3b" +
			"18206a47882003a1026c7400114910af92ecc6260a8da0f22b41e725fc5cd377e315a7fe7b335e02a8400df1594e7747" +
			"bba6fa0b75b19ce98d12bb8be2b756d6640bb290521ee9f05fb31f01026c7400002f000100000e10001204626f746802" +
			"6c7400000722000000000380026c7400002e000100000e100056002f0f0100000e107d3b18206a47882003a1026c7400" +
			"8bde0c3110e6b0a41e60506ded3c5a8abe94c16fe2a254e80afe8339696d9511709bbdb7aa16fe96aebe5096822a25c7" +
			"258021f7fdd28bf1c11ebacafe041702026c74000006000100000e10002a026e73026c74000a686f73746d6173746572" +
			"026c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600060f0100000e107d3b" +
			"18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a291ec399890ff4a3" +
			"7cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_nope_nxdomain",
		name  = "nope.lt.",
		type  = .A,
		rcode = 3,
		wire  = "123485830001000000060000046e6f7065026c740000010001056d69786564026c7400002f000100000e10001508756e" +
			"7369676e6564026c74000006400000000003056d69786564026c7400002e000100000e100056002f0f0200000e10a2d3" +
			"1e2090071b2003a1026c740087adb362396ed4c0e7df42f055e174f1bc27318707a21876d75d5a53d1619f4d018a22d4" +
			"a127d9d11da14e7ea8244c71c5465596ce2858ce1228eec13443ec08026c7400002f000100000e10001204626f746802" +
			"6c7400000722000000000380026c7400002e000100000e100056002f0f0100000e107d3b18206a47882003a1026c7400" +
			"8bde0c3110e6b0a41e60506ded3c5a8abe94c16fe2a254e80afe8339696d9511709bbdb7aa16fe96aebe5096822a25c7" +
			"258021f7fdd28bf1c11ebacafe041702026c74000006000100000e10002a026e73026c74000a686f73746d6173746572" +
			"026c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600060f0100000e107d3b" +
			"18206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a291ec399890ff4a3" +
			"7cdf25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_x_ds",
		name  = "x.wl.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000017802776c00002b0001012a02776c00002f000100000e10000c02776c00000640000000" +
			"0003012a02776c00002e000100000e100056002f0f0100000e107d3b18206a478820abed02776c00a6743e76d1c5a5f5" +
			"97d704c72faa996580ec28bb4f79734ac1be9c2d00f3662d24bfe90caad5e045b276738e01b565096b7993ce647a71e3" +
			"d2513ca0f6777f0702776c000006000100000e10002a026e7302776c000a686f73746d617374657202776c0000000001" +
			"00000e100000038400093a800000012c02776c00002e000100000e10005600060f0100000e107d3b18206a478820abed" +
			"02776c00b207c3bcb872cca93e83f41e2d27eb0325a38a5e107ab07b73942fd476d1357b357a394eaf3b2bc45e61a13c" +
			"c5753837474d255ac8743be8968caf3381891f02",
	},
	{
		key   = "lp_x_a",
		name  = "x.wl.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000200020000017802776c0000010001017802776c000001000100000e100004c0000206017802776c00" +
			"002e000100000e10005600010f0100000e107d3b18206a478820abed02776c005be3418969aedc7db3b5abf4b478ee61" +
			"fb4535b7e60e8fd0134ccbdc054f7553630b67f3d160c9867d3aff8a942a742a2aecaddf690228e3c98eebb50a3c6300" +
			"012a02776c00002f000100000e10000c02776c000006400000000003012a02776c00002e000100000e100056002f0f01" +
			"00000e106a4788206a1ffb20abed02776c006809b084cdc11b601d3bb50fba7bd0c1c532b5c1d9d612816d6bb1406839" +
			"3f5c5881e2634b13e13050bec2f823355728862071ec3c21c7d310999d648ba82909",
	},
	{
		key   = "lp_pair_lapse_first",
		name  = "late.lt.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000400000000046c617465026c740000010001046c617465026c74000005000100000e10000a056d6978" +
			"6564026c7400046c617465026c7400002e000100000e10005600050f0200000e106a4788206a1ffb2003a1026c7400d6" +
			"1d9e09f7701c8fa404b5617bc20f1b73ae3b2697a7100ba23071d3ead30a13e1f8955f9bce00e6b39075f132a38d5c6c" +
			"cd71e489bdadd996bfa734adb92d01056d69786564026c74000001000100000e100004c0000204056d69786564026c74" +
			"00002e000100000e10005600010f0200000e107d3b18206a47882003a1026c7400e29bba1dd3015f2cdd38369bd8afd8" +
			"69b50b1ca838d1a495faa061137a1c324c4b2eb6eaf0b1a51febe75e739141428df7f6f09b260e1183325576eb160b04" +
			"09",
	},
	{
		key   = "lp_pair_forgery_first",
		name  = "late.lt.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000400000000046c617465026c740000010001056d69786564026c74000001000100000e100004c00002" +
			"04056d69786564026c7400002e000100000e10005600010f0200000e107d3b18206a47882003a1026c7400e29bba1dd3" +
			"015f2cdd38369bd8afd869b50b1ca838d1a495faa061137a1c324c4b2eb6eaf0b1a51febe75e739141428df7f6f09b26" +
			"0e1183325576eb160b0409046c617465026c74000005000100000e10000a056d69786564026c7400046c617465026c74" +
			"00002e000100000e10005600050f0200000e106a4788206a1ffb2003a1026c7400d61d9e09f7701c8fa404b5617bc20f" +
			"1b73ae3b2697a7100ba23071d3ead30a13e1f8955f9bce00e6b39075f132a38d5c6ccd71e489bdadd996bfa734adb92d" +
			"01",
	},
	{
		key   = "lp_y_ds",
		name  = "y.wm.",
		type  = .DS,
		rcode = 0,
		wire  = "123485800001000000040000017902776d00002b0001012a02776d00002f000100000e10000c02776d00000640000000" +
			"0003012a02776d00002e000100000e100056002f0f0100000e107d3b18206a478820d13d02776d00be4a684b40579a4a" +
			"34d37d36e069f1965cf9a0d44deea6703bb3d2f27995f7b741b2757bf5ef8157ad5d67cd936ec218b805242613e57dc5" +
			"a9f3e573bb9ba90902776d000006000100000e10002a026e7302776d000a686f73746d617374657202776d0000000001" +
			"00000e100000038400093a800000012c02776d00002e000100000e10005600060f0100000e107d3b18206a478820d13d" +
			"02776d0032548d68306c20dbb0a613583cb2ef2b456daf4468a35c62ef6b78556b32a35a572860f860bf634e9a7d2617" +
			"c6c76681c90459ab4eef146889b59159f55e000d",
	},
	{
		key   = "lp_two_wildcards",
		name  = "x.wl.",
		type  = .A,
		rcode = 0,
		wire  = "123485800001000400040000017802776c0000010001017802776c000005000100000e100006017902776d0001780277" +
			"6c00002e000100000e10005600050f0100000e107d3b18206a478820abed02776c0019331a588f3bfdb27c99121543e5" +
			"e75ec2e255a2f0284a6fbc3142ea14f4d71f3833b91472cef1405c1c2c1c25791869495dd8b9f3ae3c9beedfde0c6c93" +
			"e60f017902776d000001000100000e100004c0000207017902776d00002e000100000e10005600010f0100000e107d3b" +
			"18206a478820d13d02776d00eefbce88ccb427fab994fb76699422378691509cd6e09a68e8054cfa0c226231c6bfea4b" +
			"886a58a4af63d238c95d79626fd8bd8d59b5c9564d9c63ea9233100b012a02776c00002f000100000e10000c02776c00" +
			"0006400000000003012a02776c00002e000100000e100056002f0f0100000e106a4788206a1ffb20abed02776c006809" +
			"b084cdc11b601d3bb50fba7bd0c1c532b5c1d9d612816d6bb14068393f5c5881e2634b13e13050bec2f8233557288620" +
			"71ec3c21c7d310999d648ba82909012a02776d00002f000100000e10000c02776d000006400000000003012a02776d00" +
			"002e000100000e100056002f0f0100000e107d3b18206a478820d13d02776d0070d7da921baf41929c12501078dfe823" +
			"24b3214597c16603a31affe0c1fd132a82ef7ce31a030806f9c75bf24feb26652f0fd2bce92f71f214cb4e7d5e982609",
	},
	{
		key   = "lp_cn_ds",
		name  = "cn.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020004000002636e026c7400002b000102636e026c74000005000100000e10000904626f7468026c74" +
			"0002636e026c7400002e000100000e10005600050f0200000e10a2d31e2090071b2003a1026c740037965c601979d88a" +
			"fdb706c010a13e2e76dc3e3623aecc93ba398e4a46463bf9c400dc349d0c9de4ca9912da8d6b4d0da8f28165e6bbf477" +
			"bd2a27687644240504626f7468026c7400002f000100000e100012056561726c79026c7400000640000000000304626f" +
			"7468026c7400002e000100000e100056002f0f0200000e107d3b18206a47882003a1026c7400bb560aebab2d2ce23b29" +
			"6aab3e7241876be3d955be7b56a357c5b1fb269cd02cc6d2d5383a770289c02b7c5b2bc650f68b35c80d921908cd7ea1" +
			"e731b4708d09026c74000006000100000e10002a026e73026c74000a686f73746d6173746572026c7400000000010000" +
			"0e100000038400093a800000012c026c7400002e000100000e10005600060f0100000e107d3b18206a47882003a1026c" +
			"74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a291ec399890ff4a37cdf25d934525cb25373" +
			"0b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_cn_www",
		name  = "www.cn.lt.",
		type  = .A,
		rcode = 0,
		wire  = "1234858000010001000000000377777702636e026c7400000100010377777702636e026c74000001000100000e100004" +
			"c0000208",
	},
	{
		key   = "lp_dname_ds",
		name  = "www.late.lt.",
		type  = .DS,
		rcode = 3,
		wire  = "12348583000100000006000003777777046c617465026c7400002b0001046c617465026c7400002f000100000e100012" +
			"056d69786564026c74000006400000000003046c617465026c7400002e000100000e100056002f0f0200000e107d3b18" +
			"206a47882003a1026c7400395f58050813beebab1e21b4a73062b080bf9ecb08fa6dc9bbba7413e0f232e203063abbd3" +
			"4cfc1075f5aa79d689cd8f40ff3cbd0c1190d934a55465a57b4c0b026c7400002f000100000e10001204626f7468026c" +
			"7400000722000000000380026c7400002e000100000e100056002f0f0100000e107d3b18206a47882003a1026c74008b" +
			"de0c3110e6b0a41e60506ded3c5a8abe94c16fe2a254e80afe8339696d9511709bbdb7aa16fe96aebe5096822a25c725" +
			"8021f7fdd28bf1c11ebacafe041702026c74000006000100000e10002a026e73026c74000a686f73746d617374657202" +
			"6c74000000000100000e100000038400093a800000012c026c7400002e000100000e10005600060f0100000e107d3b18" +
			"206a47882003a1026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a291ec399890ff4a37c" +
			"df25d934525cb253730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_dname_a",
		name  = "www.late.lt.",
		type  = .A,
		rcode = 0,
		wire  = "12348580000100030000000003777777046c617465026c740000010001046c617465026c74000027000100000e100009" +
			"04626f7468026c7400046c617465026c7400002e000100000e10005600270f0200000e106a4788206a1ffb2003a1026c" +
			"74001147a3808504239369c8f6758ca8d16ea505a3ed9aab674088c2ed93532038f7e096e1ec58364c2f0e891449395d" +
			"edba4c8ac0b31c17ae75f29608c3879caf0503777777046c617465026c74000005000100000e10000d0377777704626f" +
			"7468026c7400",
	},
	{
		key   = "lp_cn2_ds",
		name  = "cn2.lt.",
		type  = .DS,
		rcode = 0,
		wire  = "12348580000100020006000003636e32026c7400002b000103636e32026c74000005000100000e10000904626f746802" +
			"6c740003636e32026c7400002e000100000e10005600050f0200000e107d3b18206a47882003a1026c74005c66be3606" +
			"91f46ea0a1e798b2cccfab9ee00fed430f0feb726d4a94212adccf2f4d069cbca8afbed2e0b048563415e326e34d4121" +
			"9bb6aca9610bf310e5970c056561726c79026c7400002f000100000e100011046c617465026c74000006400000000003" +
			"056561726c79026c7400002e000100000e100056002f0f0200000e107d3b18206a47882003a1026c74002e5017068694" +
			"88cc9e37e714e1c9c25a6e828af724547eb50dedd9d6c9b2907289a37aa5560661ec8c61b084ac25fafaaf9d257db839" +
			"d22aa0d94e0d342aeb0e04626f7468026c7400002f000100000e100012056561726c79026c7400000640000000000304" +
			"626f7468026c7400002e000100000e100056002f0f0200000e10a2d31e2090071b2003a1026c74001fa9aae63a0c483e" +
			"5c07463e7367d0a5b5085c1253ee65ba375b81bf0d329d0f643c690824b2460ed473b74b7bf1b81746e22b6f9d31eb4c" +
			"f8c91c4bc13dae06026c74000006000100000e10002a026e73026c74000a686f73746d6173746572026c740000000001" +
			"00000e100000038400093a800000012c026c7400002e000100000e10005600060f0100000e107d3b18206a47882003a1" +
			"026c74002f2f61631826be86c19f8e55a637879c4d48f1da45d0807197585e5a291ec399890ff4a37cdf25d934525cb2" +
			"53730b5fe4cb8590de4b73ddfc4f849c3f3cff0f",
	},
	{
		key   = "lp_cn2_www",
		name  = "www.cn2.lt.",
		type  = .A,
		rcode = 0,
		wire  = "1234858000010001000000000377777703636e32026c7400000100010377777703636e32026c74000001000100000e10" +
			"0004c0000209",
	},
}

@(private = "file")
lp_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> (wire: []u8, ok: bool) {
	for f in LP_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return decode_hex(f.wire, allocator)
		}
	}
	return nil, false
}

@(private = "file")
lp_validate :: proc(key, qname: string, now := i64(FIXTURE_TIME)) -> Result {
	return lp_validate_with(key, qname, "", "", now)
}

// `lp_validate` with `old` replaced by `new` in the fixture's hex, which is how
// a test alters one signature without a fixture of its own.
@(private = "file")
lp_validate_with :: proc(key, qname, old, new: string, now := i64(FIXTURE_TIME)) -> Result {
	anchor, parsed := parse_trust_anchor(LP_ANCHOR, context.temp_allocator)
	if !parsed {
		return {status = .Indeterminate, reason = "the anchor did not parse"}
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	v := make_validator(lp_query, nil, Options{anchors = anchors})
	defer destroy_validator(v)
	for f in LP_FIXTURES {
		if f.key == key {
			hex := f.wire
			if old != "" {
				hex, _ = strings.replace(hex, old, new, 1, context.temp_allocator)
			}
			wire, _ := decode_hex(hex, context.temp_allocator)
			return validate(v, qname, .A, wire, time.unix(now, 0))
		}
	}
	return {status = .Indeterminate, reason = "no such fixture"}
}

@(test)
test_a_signature_outside_its_window_is_named_on_every_road :: proc(t: ^testing.T) {
	cases := []struct {
		key, qname: string,
		window:     Sig_Window,
		reason:     string,
		road:       string,
	} {
		{"lp_dsx_www", "www.dsx.", .Expired, LP_EXPIRED, "the parent's signature over a DS"},
		{"lp_dkx_www", "www.dkx.", .Not_Yet_Valid, LP_NOT_YET, "a zone's signature over its DNSKEY set"},
		{"lp_late_a", "late.lt.", .Expired, LP_EXPIRED, "the answer's own signature"},
		{"lp_early_a", "early.lt.", .Not_Yet_Valid, LP_NOT_YET, "the answer's own signature"},
		{"lp_insecure_a", "www.unsigned.lt.", .Not_Yet_Valid, LP_NOT_YET, "the parent's denial of a DS"},
		{"lp_nope_nxdomain", "nope.lt.", .Not_Yet_Valid, LP_NOT_YET, "the NSEC an NXDOMAIN rests on"},
		{"lp_x_a", "x.wl.", .Expired, LP_EXPIRED, "the NSEC a wildcard expansion rests on"},
		{"lp_dname_a", "www.late.lt.", .Expired, LP_EXPIRED, "a DNAME and the unsigned CNAME it synthesized"},
	}
	for c in cases {
		result := lp_validate(c.key, c.qname)
		testing.expectf(
			t,
			result.status == .Bogus && result.lapsed.window == c.window && result.reason == c.reason,
			"%s (%s) should be refused naming its window, %v %q: got %v %v %q",
			c.road,
			c.qname,
			c.window,
			c.reason,
			result.status,
			result.lapsed.window,
			result.reason,
		)
	}
	free_all(context.temp_allocator)
}

// The step stays in the detail, beside the window in the reason.
@(test)
test_a_lapsed_step_still_names_the_step :: proc(t: ^testing.T) {
	result := lp_validate("lp_dsx_www", "www.dsx.")
	testing.expectf(
		t,
		result.detail == "dsx: the DS set is not signed by any key of its parent, or its signature expanded a wildcard",
		"the step that broke should be named in the detail, got %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

// Away from the chain there is no step, so the check that failed is the
// detail: the answer's signature, an NXDOMAIN's proof, a wildcard's.
@(test)
test_a_lapsed_check_off_the_chain_is_named_in_the_detail :: proc(t: ^testing.T) {
	cases := []struct {
		key, qname, detail: string,
	} {
		{"lp_late_a", "late.lt.", "no valid signature"},
		{"lp_nope_nxdomain", "nope.lt.", "denial of existence not proven"},
		{"lp_x_a", "x.wl.", "wildcard expansion not proven"},
	}
	for c in cases {
		result := lp_validate(c.key, c.qname)
		testing.expectf(t, result.detail == c.detail, "%s: the detail should name %q, got %q", c.qname, c.detail, result.detail)
	}
	free_all(context.temp_allocator)
}

/*
The window is what the verdict rests on, or it is not mentioned.

A current signature beside an expired one is what a zone mid-re-sign publishes,
and it verifies. A current one that does not verify is a forgery whatever lapsed
beside it - RFC 8914's codes 7 and 8 are for when "no signatures are presently
valid" - so that stays code 6, in the words it always had.
*/
@(test)
test_a_lapsed_signature_beside_a_current_one_is_not_the_verdict :: proc(t: ^testing.T) {
	both := lp_validate("lp_both_a", "both.lt.")
	testing.expectf(t, both.status == .Secure, "a current signature beside an expired one should hold, got %v %q", both.status, both.reason)
	testing.expectf(t, both.lapsed.window == .Current, "and no window should be reported, got %v", both.lapsed.window)

	mixed := lp_validate("lp_mixed_a", "mixed.lt.")
	testing.expectf(
		t,
		mixed.status == .Bogus && mixed.lapsed.window == .Current && mixed.reason == "no valid signature",
		"a current signature that fails is a forgery, not a lapse, got %v %v %q",
		mixed.status,
		mixed.lapsed.window,
		mixed.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_signature_window_sides :: proc(t: ^testing.T) {
	NOW :: u32(1_000_000)
	cases := []struct {
		inception, expiration: u32,
		want:                  Sig_Window,
	} {
		{NOW - 10, NOW + 10, .Current},
		{NOW - 10, NOW, .Current},
		{NOW - 20, NOW - 10, .Expired},
		{NOW + SIG_INCEPTION_SKEW + 1, NOW + 100_000, .Not_Yet_Valid},
		// Inside the skew: accepted, as `signature_current` accepts it.
		{NOW + SIG_INCEPTION_SKEW, NOW + 100_000, .Current},
		// Inside the skew, but ending before it starts: not yet valid, and never
		// will be.
		{NOW + 100, NOW + 50, .Not_Yet_Valid},
		// RFC 1982 serial arithmetic across the 32-bit wrap.
		{max(u32) - 10, 5, .Current},
	}
	for c in cases {
		now := NOW if c.inception != max(u32) - 10 else 0
		got := signature_window(Rrsig{inception = c.inception, expiration = c.expiration}, now)
		testing.expectf(t, got == c.want, "inception %d expiration %d at %d: want %v, got %v", c.inception, c.expiration, now, c.want, got)
	}
}

// A window that ends before it starts is a signature no clock makes current, so
// it does not verify - code 6 - and is not reported as a lapse.
@(test)
test_an_inverted_window_is_no_lapse :: proc(t: ^testing.T) {
	NOW :: u32(1_000_000)
	key := Dnskey {
		flags     = DNSKEY_FLAG_ZONE,
		protocol  = 3,
		algorithm = 15,
		tag       = 7,
	}
	keys := []Dnskey{key}
	lapsed: Lapsed
	// Inside the skew, ending before it starts.
	note_lapsed(&lapsed, Rrsig{algorithm = 15, key_tag = 7, inception = NOW + 100, expiration = NOW + 50}, keys, NOW)
	// Wholly in the past, ending before it starts.
	note_lapsed(&lapsed, Rrsig{algorithm = 15, key_tag = 7, inception = NOW - 10, expiration = NOW - 20}, keys, NOW)
	testing.expectf(t, lapsed.window == .Current, "an inverted window should be no lapse, got %v", lapsed.window)
	note_lapsed(&lapsed, Rrsig{algorithm = 15, key_tag = 7, inception = NOW - 20, expiration = NOW - 10}, keys, NOW)
	testing.expectf(t, lapsed == Lapsed{window = .Expired, at = NOW - 10}, "the control should lapse, got %v", lapsed)
}

/*
A denial proof missing a set whose signature inside its window failed rests on
that signature, whatever lapsed beside it: code 6, as for an answer RRset.

The NXDOMAIN for `nope.lt.` has its cover signed in the future and the apex
NSEC current; the apex NSEC's signature is altered here so it fails.
*/
@(test)
test_a_denial_with_a_failed_current_signature_is_not_a_lapse :: proc(t: ^testing.T) {
	result := lp_validate_with("lp_nope_nxdomain", "nope.lt.", "8bde0c3110e6b0a4", "8bde0c3110e6b0a5")
	testing.expectf(
		t,
		result.status == .Bogus && result.lapsed.window == .Current && result.reason == "no denial of existence",
		"a proof missing a set that failed in its window is a forgery, got %v %v %q",
		result.status,
		result.lapsed.window,
		result.reason,
	)
	free_all(context.temp_allocator)
}

// Several lapsed signatures on one side: the instant named is the one nearest
// `now` - the latest expiration, the earliest inception - in whatever order the
// signatures, or the sets of one proof, arrive.
@(test)
test_a_lapse_names_the_instant_nearest_now :: proc(t: ^testing.T) {
	NOW :: u32(1_000_000)
	SKEW :: u32(SIG_INCEPTION_SKEW)
	keys := []Dnskey{{flags = DNSKEY_FLAG_ZONE, protocol = 3, algorithm = 15, tag = 7}}
	expired: Lapsed
	note_lapsed(&expired, Rrsig{algorithm = 15, key_tag = 7, inception = NOW - 90, expiration = NOW - 50}, keys, NOW)
	note_lapsed(&expired, Rrsig{algorithm = 15, key_tag = 7, inception = NOW - 90, expiration = NOW - 10}, keys, NOW)
	note_lapsed(&expired, Rrsig{algorithm = 15, key_tag = 7, inception = NOW - 90, expiration = NOW - 30}, keys, NOW)
	testing.expectf(t, expired == Lapsed{window = .Expired, at = NOW - 10}, "the latest expiration should be named, got %v", expired)

	early: Lapsed
	note_lapsed(&early, Rrsig{algorithm = 15, key_tag = 7, inception = NOW + SKEW + 50, expiration = NOW + 900_000}, keys, NOW)
	note_lapsed(&early, Rrsig{algorithm = 15, key_tag = 7, inception = NOW + SKEW + 10, expiration = NOW + 900_000}, keys, NOW)
	note_lapsed(&early, Rrsig{algorithm = 15, key_tag = 7, inception = NOW + SKEW + 30, expiration = NOW + 900_000}, keys, NOW)
	testing.expectf(t, early == Lapsed{window = .Not_Yet_Valid, at = NOW + SKEW + 10}, "the earliest inception should be named, got %v", early)

	across := Lapsed{window = .Expired, at = NOW - 50}
	keep_lapse(&across, Lapsed{window = .Expired, at = NOW - 10})
	keep_lapse(&across, Lapsed{window = .Expired, at = NOW - 30})
	testing.expectf(t, across == Lapsed{window = .Expired, at = NOW - 10}, "across sets, the latest expiration should be kept, got %v", across)

	// A refuted set rules the window out whichever side of it it arrives on.
	keep_lapse(&across, Lapsed{refuted = true})
	keep_lapse(&across, Lapsed{window = .Not_Yet_Valid, at = NOW + SKEW + 10})
	testing.expectf(t, across == Lapsed{refuted = true}, "a refuted set should stay refuted, got %v", across)
}

// A forgery and a lapse in one message is a forgery, whichever came first:
// codes 7 and 8 are for when no signature is presently valid.
@(test)
test_a_forgery_beside_a_lapse_takes_the_reason :: proc(t: ^testing.T) {
	lapse := Lapsed{window = .Expired, at = 1}
	testing.expect(t, takes_reason(.Bogus, .Bogus, lapse, {}), "a forgery after a lapse should take the reason")
	testing.expect(t, takes_reason(.Bogus, .Bogus, lapse, {refuted = true}), "a refuted set after a lapse should take the reason")
	testing.expect(t, !takes_reason(.Bogus, .Bogus, {}, lapse), "a lapse after a forgery should not take the reason")
	testing.expect(t, !takes_reason(.Bogus, .Bogus, lapse, lapse), "a second lapse should not take the reason")
	testing.expect(t, takes_reason(.Insecure, .Bogus, {}, lapse), "a worse verdict should take the reason")
	testing.expect(t, !takes_reason(.Bogus, .Indeterminate, lapse, {}), "a better verdict should not take the reason")
}

/*
A forgery anywhere in the message is code 6, whatever lapsed beside it and in
whichever order: RFC 8914 codes 7 and 8 are for when "no signatures are
presently valid". One shape per place the verdict's reason is chosen - two
answer RRsets, two wildcard proofs, and the DS question a CNAME answered.
*/
@(test)
test_a_forgery_beside_a_lapse_is_a_forgery_end_to_end :: proc(t: ^testing.T) {
	cases := []struct {
		key, qname, reason, shape: string,
	} {
		{"lp_pair_lapse_first", "late.lt.", "no valid signature", "a lapsed CNAME before a forged A"},
		{"lp_pair_forgery_first", "late.lt.", "no valid signature", "a forged A before a lapsed CNAME"},
		{"lp_two_wildcards", "x.wl.", "wildcard expansion not proven", "a lapsed wildcard proof before a refuted one"},
		{"lp_cn_www", "www.cn.lt.", BROKEN_CHAIN, "a lapsed CNAME at a DS question beside a refuted denial"},
		{"lp_cn2_www", "www.cn2.lt.", BROKEN_CHAIN, "a refuted CNAME at a DS question beside a lapsed denial that proves nothing"},
	}
	for c in cases {
		result := lp_validate(c.key, c.qname)
		testing.expectf(
			t,
			result.status == .Bogus && result.lapsed.window == .Current && result.reason == c.reason,
			"%s should be refused as a forgery, %q: got %v %v %q",
			c.shape,
			c.reason,
			result.status,
			result.lapsed.window,
			result.reason,
		)
	}
	free_all(context.temp_allocator)
}
