package dnssec

import "core:slice"
import "core:strings"
import "core:testing"
import "elodin:dns"

/*
Whose name a signature speaks for.

An RRSIG names the type, the signer and a label count, and nothing else. RFC
4034 section 3.1.3 lets that count fall short of the owner name's, which is how
a wildcard answer is signed: the signature is computed over `*.<encloser>`
rather than over the name the asterisk stood in for. So the owner field is not
covered by the signature at all, and a zone's genuine `*.wctest. NSEC` with its
genuine RRSIG - both public, both fetchable with one harmless query - verifies
unchanged after that field has been rewritten to any other name in the zone.

For an answer RRset that is a fact, not a hole: `validate_rrset` sees the short
count and goes looking for the RFC 4035 section 5.3.4 proof that a wildcard
expansion was the right thing to do. A denial record has no such proof to look
for, and a relocated NSEC would be a bit map that answers for a name it was
never published under. Once would be NODATA for a type the name really has;
twice, with the owners chosen so the two spans cover a qname and the wildcard,
NXDOMAIN for a name the zone answers for - both at AD=1 and into the cache.

RFC 4592 section 4.7 is what makes this always a forgery rather than a case
to be handled: a wildcard owns an NSEC of its own, but "synthesis of these
records will only occur when the query exactly matches the record", so a denial
record whose signature expanded is a denial record that was moved. Unbound
rewrites the owner to the canonical one before verifying, for the same reason
and with the same effect.

`wdtest.` is the other side of the same routine. A DS RRset whose signature
expanded would hand the chain walk a zone cut the parent never signed under
that name, and the walk continues under keys nobody attested there.

`testdata/gen/sign_fixtures.py relocated_wildcard_denial` generates all of it.
*/

@(private = "file")
WC_ANCHOR :: ". IN DS 38604 15 2 29C6A6368F8EBB40965A5E075A85060E1F83976955C525C25B1457B96E5E4405"

@(private = "file")
WC_FIXTURES := []Fixture{

	{
		key   = "wc_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f21e262a0451d37ef5b2d0d0e217a92db" +
			"3a409b7a3f5c7054a1c58bcd5026717700002e000100000e10005300300f0000000e107d3b18206a47882096cc004fca" +
			"53f493de3ed4de28b4ec590d7954f73756fd226953651150618ec931829f35a7dac1428e37e03586769817e79e535a0f" +
			"894b892aec16b5d798ec4a292508",
	},
	{
		key   = "wc_ds",
		name  = "wctest.",
		type  = .DS,
		wire  = "1234858000010002000000000677637465737400002b00010677637465737400002b000100000e100024ec370f02a19a" +
			"92472283ee3426d1cc7bbde5f5386cc063a64c98ddadd37023aaefb839370677637465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00ac86466a41d9725933dc07d981022c00974142d199f4885de89b6d0b0c" +
			"4b9ee4687a5cf27cea35b4aafc9892f86b2763b2f6d9ce5a73fc26909f38d4c3089e0b",
	},
	{
		key   = "wc_dnskey",
		name  = "wctest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000006776374657374000030000106776374657374000030000100000e1000240101030fa30d" +
			"93548b4ca234f2db94ce2dbcc6a1b4e683557915664e3dd71de7d50abfd20677637465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820ec3706776374657374007125a56774a22bfd00caf3f760d24208f604e3b45033" +
			"8305addb216595e83e2300515277d82b386df870e82936d2a781ce07c08715d78876a8587ca6fd98380e",
	},
	{
		key   = "wc_real_ds",
		name  = "real.wctest.",
		type  = .DS,
		wire  = "123485800001000000040000047265616c0677637465737400002b0001047265616c0677637465737400002f00010000" +
			"0e10001006776374657374000006400080000003047265616c0677637465737400002e000100000e10005a002f0f0200" +
			"000e107d3b18206a478820ec3706776374657374004f63ff1d2d3194702640919b3e2551ae708ceb46817fedb87f7ff8" +
			"f8035b529e8b17a7250c0ddc729ebbe2baafbc627ce68808cdbcd2c973804038b3708034080677637465737400000600" +
			"0100000e100032026e7306776374657374000a686f73746d617374657206776374657374000000000100000e10000003" +
			"8400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820ec37067763" +
			"746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c41438374e8b74cc3c4" +
			"b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_www_ds",
		name  = "www.wctest.",
		type  = .DS,
		wire  = "123485800001000000060000037777770677637465737400002b0001047265616c0677637465737400002f000100000e" +
			"10001006776374657374000006400080000003047265616c0677637465737400002e000100000e10005a002f0f020000" +
			"0e107d3b18206a478820ec3706776374657374004f63ff1d2d3194702640919b3e2551ae708ceb46817fedb87f7ff8f8" +
			"035b529e8b17a7250c0ddc729ebbe2baafbc627ce68808cdbcd2c973804038b370803408012a0677637465737400002f" +
			"000100000e100015047265616c06776374657374000006400000000003012a0677637465737400002e000100000e1000" +
			"5a002f0f0100000e107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870" +
			"874513452e8a8384cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b62050677637465" +
			"7374000006000100000e100032026e7306776374657374000a686f73746d617374657206776374657374000000000100" +
			"000e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a4788" +
			"20ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c414383" +
			"74e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_relocated_nodata",
		name  = "real.wctest.",
		type  = .TXT,
		wire  = "123485800001000000040000047265616c067763746573740000100001047265616c0677637465737400002f00010000" +
			"0e100015047265616c06776374657374000006400000000003047265616c0677637465737400002e000100000e10005a" +
			"002f0f0100000e107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c087087" +
			"4513452e8a8384cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b6205067763746573" +
			"74000006000100000e100032026e7306776374657374000a686f73746d61737465720677637465737400000000010000" +
			"0e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820" +
			"ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c41438374" +
			"e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_relocated_nxdomain",
		name  = "www.wctest.",
		type  = .A,
		wire  = "1234858300010000000600000377777706776374657374000001000101730677637465737400002f000100000e100015" +
			"047265616c0677637465737400000640000000000301730677637465737400002e000100000e10005a002f0f0100000e" +
			"107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870874513452e8a8384" +
			"cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b620501210677637465737400002f00" +
			"0100000e100015047265616c0677637465737400000640000000000301210677637465737400002e000100000e10005a" +
			"002f0f0100000e107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c087087" +
			"4513452e8a8384cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b6205067763746573" +
			"74000006000100000e100032026e7306776374657374000a686f73746d61737465720677637465737400000000010000" +
			"0e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820" +
			"ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c41438374" +
			"e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_wildcard_nodata",
		name  = "www.wctest.",
		type  = .TXT,
		wire  = "12348580000100000006000003777777067763746573740000100001012a0677637465737400002f000100000e100015" +
			"047265616c06776374657374000006400000000003012a0677637465737400002e000100000e10005a002f0f0100000e" +
			"107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870874513452e8a8384" +
			"cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b6205047265616c0677637465737400" +
			"002f000100000e10001006776374657374000006400080000003047265616c0677637465737400002e000100000e1000" +
			"5a002f0f0200000e107d3b18206a478820ec3706776374657374004f63ff1d2d3194702640919b3e2551ae708ceb4681" +
			"7fedb87f7ff8f8035b529e8b17a7250c0ddc729ebbe2baafbc627ce68808cdbcd2c973804038b3708034080677637465" +
			"7374000006000100000e100032026e7306776374657374000a686f73746d617374657206776374657374000000000100" +
			"000e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a4788" +
			"20ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c414383" +
			"74e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_relocated_answer_nsec",
		name  = "nx.wctest.",
		type  = .NSEC,
		wire  = "123485800001000200040000026e780677637465737400002f0001026e780677637465737400002f000100000e100015" +
			"047265616c06776374657374000006400000000003026e780677637465737400002e000100000e10005a002f0f010000" +
			"0e107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870874513452e8a83" +
			"84cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b6205012a0677637465737400002f" +
			"000100000e100015047265616c06776374657374000006400000000003012a0677637465737400002e000100000e1000" +
			"5a002f0f0100000e107d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870" +
			"874513452e8a8384cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b62050677637465" +
			"7374000006000100000e100032026e7306776374657374000a686f73746d617374657206776374657374000000000100" +
			"000e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a4788" +
			"20ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c414383" +
			"74e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_nx_ds",
		name  = "nx.wctest.",
		type  = .DS,
		wire  = "123485800001000000060000026e780677637465737400002b0001012a0677637465737400002f000100000e10001504" +
			"7265616c06776374657374000006400000000003012a0677637465737400002e000100000e10005a002f0f0100000e10" +
			"7d3b18206a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870874513452e8a8384cf" +
			"b879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b6205047265616c067763746573740000" +
			"2f000100000e10001006776374657374000006400080000003047265616c0677637465737400002e000100000e10005a" +
			"002f0f0200000e107d3b18206a478820ec3706776374657374004f63ff1d2d3194702640919b3e2551ae708ceb46817f" +
			"edb87f7ff8f8035b529e8b17a7250c0ddc729ebbe2baafbc627ce68808cdbcd2c973804038b370803408067763746573" +
			"74000006000100000e100032026e7306776374657374000a686f73746d61737465720677637465737400000000010000" +
			"0e100000038400093a800000012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820" +
			"ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c41438374" +
			"e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_expanded_ds_answer",
		name  = "nx.wctest.",
		type  = .DS,
		wire  = "123485800001000200040000026e780677637465737400002b0001026e780677637465737400002b000100000e100024" +
			"7aa70f02335f2cfd3f90a99d69cb7a23326394dc425d26ffe41547587c4f501c955d299e026e78067763746573740000" +
			"2e000100000e10005a002b0f0100000e107d3b18206a478820ec370677637465737400f61e0fbd28accc96acb7b8640e" +
			"80dde7736f561a1c4725d608efd379362c7984213ef2825690cd9674c224d77befa76d544cc02a88ba1b124535a70c07" +
			"6c3803012a0677637465737400002f000100000e100015047265616c06776374657374000006400000000003012a0677" +
			"637465737400002e000100000e10005a002f0f0100000e107d3b18206a478820ec3706776374657374000d68c8d5dc40" +
			"d3f7c0db71853379cd1fd3843c0870874513452e8a8384cfb879d6f0e24496d31170eb85f95dbc793b4c7a0cf3382d7d" +
			"0f70f65694bedf0b620506776374657374000006000100000e100032026e7306776374657374000a686f73746d617374" +
			"657206776374657374000000000100000e100000038400093a800000012c0677637465737400002e000100000e10005a" +
			"00060f0100000e107d3b18206a478820ec37067763746573740086680c77a5776baafe6dc6996b459f2db0022c6b7be0" +
			"12df9a745cc780e505b5655c41438374e8b74cc3c4b96d7c2005bf0dbd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wc_expanded_soa_answer",
		name  = "nx.wctest.",
		type  = .SOA,
		wire  = "123485800001000200040000026e78067763746573740000060001026e7806776374657374000006000100000e100038" +
			"026e73026e7806776374657374000a686f73746d6173746572026e7806776374657374000000000100000e1000000384" +
			"00093a800000012c026e780677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820ec3706" +
			"77637465737400a060d20ac5c4a71e15350345e127966224003e4a1398988a70e914f736009bfbde6620e859affbf405" +
			"31d9fabfd22e3b4daf3030f8b280cb0881eb81d14f4700012a0677637465737400002f000100000e100015047265616c" +
			"06776374657374000006400000000003012a0677637465737400002e000100000e10005a002f0f0100000e107d3b1820" +
			"6a478820ec3706776374657374000d68c8d5dc40d3f7c0db71853379cd1fd3843c0870874513452e8a8384cfb879d6f0" +
			"e24496d31170eb85f95dbc793b4c7a0cf3382d7d0f70f65694bedf0b620506776374657374000006000100000e100032" +
			"026e7306776374657374000a686f73746d617374657206776374657374000000000100000e100000038400093a800000" +
			"012c0677637465737400002e000100000e10005a00060f0100000e107d3b18206a478820ec3706776374657374008668" +
			"0c77a5776baafe6dc6996b459f2db0022c6b7be012df9a745cc780e505b5655c41438374e8b74cc3c4b96d7c2005bf0d" +
			"bd8e48945fd8935e28ddf4e18405",
	},
	{
		key   = "wd_ds",
		name  = "wdtest.",
		type  = .DS,
		wire  = "1234858000010002000000000677647465737400002b00010677647465737400002b000100000e100024e4410f022360" +
			"32fc58fd0abe4e2bd9a7519ef8ec4b6e97da3a6810e0e7ad69e4ee518f5b0677647465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00c87b19f4d2990a924d2469710f61b3dd1a9e353f28a8b42bf2400694ca" +
			"668de1369c6eb5c3679093ef96bf8e7ea3b218a4c535a0a93d14d1f70cb64a0382ac0a",
	},
	{
		key   = "wd_dnskey",
		name  = "wdtest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000006776474657374000030000106776474657374000030000100000e1000240101030f7503" +
			"a108781965e34b9e9ad8647514e27b77794dd7a51ba5574180a8dc5ff0000677647465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820e4410677647465737400261d7eddd6bb9dad50f17b539349d4dac6120a77b399" +
			"e5ca8a353916754f5b11a3a4d7a47577157f2603f282b5cbcda0c572ea946cf5f9b48e66360a429bc605",
	},
	{
		key   = "wd_evil_ds",
		name  = "evil.wdtest.",
		type  = .DS,
		wire  = "123485800001000200000000046576696c0677647465737400002b0001046576696c0677647465737400002b00010000" +
			"0e100024b5ef0f021b2b21d08210c0fb0a5c4c516a6a1d6d018285a2020c6a5c7da2194ee55e098c046576696c067764" +
			"7465737400002e000100000e10005a002b0f0100000e107d3b18206a478820e4410677647465737400e31609f542ee73" +
			"fc560e96b663595db695f167c7d78b024b5a7133f24e89d99783190ee2ecbfbc6808dbc728cddc3aa847bfb6477b4b6d" +
			"0a40c76eefabe65d01",
	},
	{
		key   = "wd_evil_dnskey",
		name  = "evil.wdtest.",
		type  = .DNSKEY,
		wire  = "123485800001000200000000046576696c067764746573740000300001046576696c0677647465737400003000010000" +
			"0e1000240101030f7f4dce865b52e657c0ea48541b83a6031b0aa91d2f3523be66b85b8a378046bd046576696c067764" +
			"7465737400002e000100000e10005f00300f0200000e107d3b18206a478820b5ef046576696c06776474657374002a1b" +
			"a39c7c5bccf3a2bb59e59fda01ed7c321e1d98f295595b9caab2d8fd8dffe969e7d15a28227c0ce3c538890dd9d9a4fb" +
			"eaaeb4c66d04c3dca8678c3e750f",
	},
	{
		key   = "wd_evil_answer",
		name  = "evil.wdtest.",
		type  = .A,
		wire  = "123485800001000200000000046576696c067764746573740000010001046576696c0677647465737400000100010000" +
			"0e100004c0000242046576696c0677647465737400002e000100000e10005f00010f0200000e107d3b18206a478820b5" +
			"ef046576696c0677647465737400b97c2503c26f58efe0d68a36f39dbfb875bb4e8048936beca38a0dc0c631534c2632" +
			"57547614a10416d2efe4849f8bbb4f5927f74834e3a8498bb54f80025a06",
	},
	{
		key   = "wd_wild_under_evil",
		name  = "x.evil.wdtest.",
		type  = .A,
		wire  = "1234858000010002000000000178046576696c0677647465737400000100010178046576696c06776474657374000001" +
			"000100000e100004c00002440178046576696c0677647465737400002e000100000e10005a00010f0100000e107d3b18" +
			"206a478820e441067764746573740097fc699f627c7cd3c0f940aa47562d0dd9f3bb0fc0a2844b641d5db06468b5a61a" +
			"6e5bb65a25ff9ee2e8a3c31afb75426e9bfb211c766a0f1c847dc2cebbec09",
	},
	{
		key   = "wd_fine_ds",
		name  = "fine.wdtest.",
		type  = .DS,
		wire  = "1234858000010002000000000466696e650677647465737400002b00010466696e650677647465737400002b00010000" +
			"0e1000245f0f0f02da239b4bca4a13effccef4a0dcfea231ba6730741ccea505b5adb4b453bc45cd0466696e65067764" +
			"7465737400002e000100000e10005a002b0f0200000e107d3b18206a478820e4410677647465737400ba779b3c967f06" +
			"bd3c7b886fde21703b5bddb4e52fb37cb15a7ba2e22f2c6922a07c8a970e00f8342c02ea4fab7566aaac3f90883d7624" +
			"8dffe2f218c257ed0c",
	},
	{
		key   = "wd_fine_dnskey",
		name  = "fine.wdtest.",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000466696e650677647465737400003000010466696e650677647465737400003000010000" +
			"0e1000240101030fdb4c915f4675d09a5135477812ffff8d545f0a79dc954b1b2e7560db971a7f130466696e65067764" +
			"7465737400002e000100000e10005f00300f0200000e107d3b18206a4788205f0f0466696e650677647465737400c767" +
			"c8a2b6a22f9e4e640ffd30214efefcb4a99ac8a9b2a1ce65e64d01260df6bc9a0bf3fb2f3b74e53d39a9e2b0d2dc039b" +
			"02be0f2ab6ad7085facb7741d408",
	},
	{
		key   = "wd_fine_answer",
		name  = "fine.wdtest.",
		type  = .A,
		wire  = "1234858000010002000000000466696e650677647465737400000100010466696e650677647465737400000100010000" +
			"0e100004c00002430466696e650677647465737400002e000100000e10005f00010f0200000e107d3b18206a4788205f" +
			"0f0466696e6506776474657374008a2e7b53562980de5ef6e5053fa60f5049f698436502ffb0b7e51158f0bd968b90f7" +
			"3beed9e0bdde6c18470bd86a0de6e8e38dbedf58890de7bfebe1f836e50a",
	},
	{
		key   = "wd_gs_ds",
		name  = "gs.wdtest.",
		type  = .DS,
		wire  = "1234858000010002000000000267730677647465737400002b00010267730677647465737400002b000100000e100024" +
			"45ac0f023a2aa85451df85fb7feded9e2ce2135d3b05d67ab75a4059ada04949ec89bf0f026773067764746573740000" +
			"2e000100000e100053002b0f0200000e107d3b18206a478820e4410041bdfeb61d61e3346dfd1918109574bbe005de8c" +
			"226b21daa95348c0f07f7808356534f89e3eab99e2483b8edfd51e06dfcfa62b795539da40e80e1982f3670a",
	},
	{
		key   = "wd_gs_dnskey",
		name  = "gs.wdtest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000002677306776474657374000030000102677306776474657374000030000100000e100024" +
			"0101030f4f243603c278451fd35eddcc2942679550468cf7af37d014716a481b9f83bd45026773067764746573740000" +
			"2e000100000e10005d00300f0200000e107d3b18206a47882045ac026773067764746573740068ce4af419e365268d49" +
			"87f183d564d76f1aee36cf0b81ec97b0d5b561aa5f9a73ef07e9ef3325df57739fcf4e30cd19b6b4ac92439740669e77" +
			"6db2e7f8fd03",
	},
	{
		key   = "wd_gs_answer",
		name  = "gs.wdtest.",
		type  = .A,
		wire  = "12348580000100020000000002677306776474657374000001000102677306776474657374000001000100000e100004" +
			"c00002450267730677647465737400002e000100000e10005d00010f0200000e107d3b18206a47882045ac0267730677" +
			"6474657374004a15872a44761502dcea4834e22d9520c9fb14d1b70fcdbbff9f1886f4afeaae452a283e0cfbe2699264" +
			"30debf04396852a173410698c8ee92685eed8b535c04",
	},
	{
		key   = "dw_ds",
		name  = "dwtest.",
		type  = .DS,
		wire  = "1234858000010002000000000664777465737400002b00010664777465737400002b000100000e10002438a40f027c40" +
			"d2bd5572ced63f66168aa050975672c9fadcf23af1480ed26580278ac46e0664777465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00c9254d2f3e36290405fcdf2ee517276b71f4e6be732ddb9d51b8021951" +
			"93a3bc9f7c9a303dc07b173971dd4dd42636f175239a6025b18c2a71d9085232634c07",
	},
	{
		key   = "dw_dnskey",
		name  = "dwtest.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000006647774657374000030000106647774657374000030000100000e1000240101030f4779" +
			"9087d45d7a0017d85a88ea57d4b17a8cfcb13a4654feff1f181bc3b7fb540664777465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a47882038a4066477746573740039a79a95fc94e712da316c656c1db52af649082d9e5e" +
			"74d5b2f2af32781df8c9b4acfaf7d0f12a218c3b1fcff98117349d91d92b4e46b031f45e91d7300ad505",
	},
	{
		key   = "dw_y_ds",
		name  = "y.dwtest.",
		type  = .DS,
		wire  = "12348580000100000006000001790664777465737400002b0001012a0664777465737400002f000100000e1000150472" +
			"65616c06647774657374000006000000000103012a0664777465737400002e000100000e10005a002f0f0100000e107d" +
			"3b18206a47882038a40664777465737400ef8b5fb6e836b8e0cdfd57ceb2edc3cd2e12f5b69b958d8ae963307fa9c453" +
			"a8179f67d4b01bcefd60c48ab92e250a8e3108436757aa145947ea54328f0d0c0c047265616c0664777465737400002f" +
			"000100000e10001006647774657374000006400000000003047265616c0664777465737400002e000100000e10005a00" +
			"2f0f0200000e107d3b18206a47882038a40664777465737400d8f035e8e32d5a48b619c1cba65e3677721d00bc82df78" +
			"069f8c005bb02805efd13f507101eb0b516816e13f9791c5274986c30382f6a91dcd1b56258be7ed0706647774657374" +
			"000006000100000e100032026e7306647774657374000a686f73746d617374657206647774657374000000000100000e" +
			"100000038400093a800000012c0664777465737400002e000100000e10005a00060f0100000e107d3b18206a47882038" +
			"a406647774657374004bc7f692c8954110e932b63c559d5eee0b6b4f31a7fddf973411fe1fb17174720f69e071776106" +
			"32debdaf8afe90f45f9e1d2b993e18f0420b370af1c11b7a00",
	},
	{
		key   = "dw_xy_ds",
		name  = "x.y.dwtest.",
		type  = .DS,
		wire  = "123485800001000000060000017801790664777465737400002b0001012a0664777465737400002f000100000e100015" +
			"047265616c06647774657374000006000000000103012a0664777465737400002e000100000e10005a002f0f0100000e" +
			"107d3b18206a47882038a40664777465737400ef8b5fb6e836b8e0cdfd57ceb2edc3cd2e12f5b69b958d8ae963307fa9" +
			"c453a8179f67d4b01bcefd60c48ab92e250a8e3108436757aa145947ea54328f0d0c0c047265616c0664777465737400" +
			"002f000100000e10001006647774657374000006400000000003047265616c0664777465737400002e000100000e1000" +
			"5a002f0f0200000e107d3b18206a47882038a40664777465737400d8f035e8e32d5a48b619c1cba65e3677721d00bc82" +
			"df78069f8c005bb02805efd13f507101eb0b516816e13f9791c5274986c30382f6a91dcd1b56258be7ed070664777465" +
			"7374000006000100000e100032026e7306647774657374000a686f73746d617374657206647774657374000000000100" +
			"000e100000038400093a800000012c0664777465737400002e000100000e10005a00060f0100000e107d3b18206a4788" +
			"2038a406647774657374004bc7f692c8954110e932b63c559d5eee0b6b4f31a7fddf973411fe1fb17174720f69e07177" +
			"610632debdaf8afe90f45f9e1d2b993e18f0420b370af1c11b7a00",
	},
	{
		key   = "dw_real_ds",
		name  = "real.dwtest.",
		type  = .DS,
		wire  = "123485800001000000060000047265616c0664777465737400002b0001012a0664777465737400002f000100000e1000" +
			"15047265616c06647774657374000006000000000103012a0664777465737400002e000100000e10005a002f0f010000" +
			"0e107d3b18206a47882038a40664777465737400ef8b5fb6e836b8e0cdfd57ceb2edc3cd2e12f5b69b958d8ae963307f" +
			"a9c453a8179f67d4b01bcefd60c48ab92e250a8e3108436757aa145947ea54328f0d0c0c047265616c06647774657374" +
			"00002f000100000e10001006647774657374000006400000000003047265616c0664777465737400002e000100000e10" +
			"005a002f0f0200000e107d3b18206a47882038a40664777465737400d8f035e8e32d5a48b619c1cba65e3677721d00bc" +
			"82df78069f8c005bb02805efd13f507101eb0b516816e13f9791c5274986c30382f6a91dcd1b56258be7ed0706647774" +
			"657374000006000100000e100032026e7306647774657374000a686f73746d6173746572066477746573740000000001" +
			"00000e100000038400093a800000012c0664777465737400002e000100000e10005a00060f0100000e107d3b18206a47" +
			"882038a406647774657374004bc7f692c8954110e932b63c559d5eee0b6b4f31a7fddf973411fe1fb17174720f69e071" +
			"77610632debdaf8afe90f45f9e1d2b993e18f0420b370af1c11b7a00",
	},
	{
		key   = "dw_xreal_ds",
		name  = "x.real.dwtest.",
		type  = .DS,
		wire  = "1234858000010000000600000178047265616c0664777465737400002b0001012a0664777465737400002f000100000e" +
			"100015047265616c06647774657374000006000000000103012a0664777465737400002e000100000e10005a002f0f01" +
			"00000e107d3b18206a47882038a40664777465737400ef8b5fb6e836b8e0cdfd57ceb2edc3cd2e12f5b69b958d8ae963" +
			"307fa9c453a8179f67d4b01bcefd60c48ab92e250a8e3108436757aa145947ea54328f0d0c0c047265616c0664777465" +
			"737400002f000100000e10001006647774657374000006400000000003047265616c0664777465737400002e00010000" +
			"0e10005a002f0f0200000e107d3b18206a47882038a40664777465737400d8f035e8e32d5a48b619c1cba65e3677721d" +
			"00bc82df78069f8c005bb02805efd13f507101eb0b516816e13f9791c5274986c30382f6a91dcd1b56258be7ed070664" +
			"7774657374000006000100000e100032026e7306647774657374000a686f73746d617374657206647774657374000000" +
			"000100000e100000038400093a800000012c0664777465737400002e000100000e10005a00060f0100000e107d3b1820" +
			"6a47882038a406647774657374004bc7f692c8954110e932b63c559d5eee0b6b4f31a7fddf973411fe1fb17174720f69" +
			"e07177610632debdaf8afe90f45f9e1d2b993e18f0420b370af1c11b7a00",
	},
	{
		key   = "dw_wildcard_dname",
		name  = "x.y.dwtest.",
		type  = .A,
		wire  = "12348580000100030002000001780179066477746573740000010001017906647774657374000027000100000e10000b" +
			"0174076578616d706c650001790664777465737400002e000100000e10005a00270f0100000e107d3b18206a47882038" +
			"a40664777465737400b422618c323e1e91aa81448e98ddea3d18072d7b14e9fd867dcaa8c5e623905b01ada0924fb209" +
			"692df7983fd907dd2fe6cc1e0b837c3f6d7fac51554e5dfb0b0178017906647774657374000005000100000e10000d01" +
			"780174076578616d706c6500047265616c0664777465737400002f000100000e10001006647774657374000006400000" +
			"000003047265616c0664777465737400002e000100000e10005a002f0f0200000e107d3b18206a47882038a406647774" +
			"65737400d8f035e8e32d5a48b619c1cba65e3677721d00bc82df78069f8c005bb02805efd13f507101eb0b516816e13f" +
			"9791c5274986c30382f6a91dcd1b56258be7ed07",
	},
	{
		key   = "dw_relocated_dname",
		name  = "x.real.dwtest.",
		type  = .A,
		wire  = "1234858000010003000000000178047265616c066477746573740000010001047265616c066477746573740000270001" +
			"00000e10000b0174076578616d706c6500047265616c0664777465737400002e000100000e10005a00270f0100000e10" +
			"7d3b18206a47882038a40664777465737400b422618c323e1e91aa81448e98ddea3d18072d7b14e9fd867dcaa8c5e623" +
			"905b01ada0924fb209692df7983fd907dd2fe6cc1e0b837c3f6d7fac51554e5dfb0b0178047265616c06647774657374" +
			"000005000100000e10000d01780174076578616d706c6500",
	},
}

/*
What the chain walk sees from `WC_FIXTURES`, which is not always what the
client was sent.

`fixture_answer` matches on name and type, first entry wins - and two fixtures here share
`nx.wctest. DS` on purpose. `wc_nx_ds` is the honest denial the walk needs on
its way down to that name; `wc_expanded_ds_answer` is an attack reply, handed
to `validate` by key through `wc_reply` and never something an upstream should
be answering a walk with. `wc_nx_ds` is listed first so the walk gets the
denial, and `test_an_expanded_ds_or_soa_answer_is_not_secure_either` asserts
that it still does: with the two swapped, the DS and NSEC repros quietly stop
reproducing - every test still passes, because the message is refused a step
earlier for an unrelated reason.
*/

/*
The reasons a refusal has to carry.

`Bogus` on its own would be satisfied by a fixture chain that had quietly come
apart - a signature whose window `FIXTURE_TIME` drifted out of, a lookup that
matched the wrong record - and a test reading only the verdict would stay green
while exercising nothing. `NO_DENIAL` is what a denial with no record left
standing settles as, which is what dropping the relocated NSEC leaves behind;
`WC_IMPOSSIBLE` is what `validate_answer` settles at for a type RFC 4592
section 4 says a wildcard never produces.
*/
@(private = "file")
WC_IMPOSSIBLE :: "wildcard expansion not possible"

@(private = "file")
wc_reply :: proc(key: string) -> []u8 {
	return scenario_fixture(WC_FIXTURES, key)
}

// Validate `wire` under `WC_ANCHOR`, or the fixture under `key` with `wc_validate`.
@(private = "file")
wc_validate_wire :: proc(qname: string, type: dns.Type, wire: []u8) -> Result {
	v := scenario_validator(&WC_FIXTURES, WC_ANCHOR)
	defer destroy_validator(v)
	return validate(v, qname, type, wire, fixture_now())
}

@(private = "file")
wc_validate :: proc(key, qname: string, type: dns.Type) -> Result {
	return wc_validate_wire(qname, type, wc_reply(key))
}

@(test)
test_a_relocated_wildcard_nsec_cannot_prove_nodata :: proc(t: ^testing.T) {
	// `real.wctest.` really holds a TXT. The wildcard's bit map does not list
	// one, so the record proves the opposite of the truth as soon as its owner
	// is read as the name it was published under.
	result := wc_validate("wc_relocated_nodata", "real.wctest.", .TXT)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == NO_DENIAL,
		"a wildcard's NSEC re-owned to a real name cannot deny that name's TXT, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_relocated_wildcard_nsec_cannot_prove_nxdomain :: proc(t: ^testing.T) {
	// Two copies of the one record, under owners chosen so the spans cover both
	// `www.wctest.` and the wildcard that answers for it.
	result := wc_validate("wc_relocated_nxdomain", "www.wctest.", .A)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == NO_DENIAL,
		"two relocated copies of a wildcard's NSEC cannot deny a name the zone answers for, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_wildcards_own_nsec_still_proves_nodata :: proc(t: ^testing.T) {
	/*
	The control, and the reason the refusal cannot be "the signature expanded".

	`*.wctest.` is an ordinary name a zone may hold records for, and it has an
	NSEC of its own. That record, under its own owner, is what proves NODATA for
	a type the wildcard does not hold - and RFC 4034 section 3.1.3 counts its
	Labels field without the asterisk, so the count is not short and nothing
	here expanded. Refusing this one would take every wildcard NODATA in every
	NSEC zone with it.
	*/
	result := wc_validate("wc_wildcard_nodata", "www.wctest.", .TXT)
	testing.expectf(
		t,
		result.status == .Secure,
		"a wildcard's own NSEC still denies a type it does not hold, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_zone_cut_whose_ds_signature_expanded_is_refused :: proc(t: ^testing.T) {
	/*
	The same check, one call site over.

	A DS digest binds the child's name, so replaying some other delegation's DS
	here dies in `ds_matches` rather than in the signature. What does not is a
	DS set signed as a wildcard expansion: the digest names `evil.wdtest.` and
	matches the key served under it, and only the Labels field says the parent
	signed `*.wdtest.` instead. Taking the cut moves the walk onto keys the
	parent never attested at this name, and everything below it is then signed
	by whoever holds them.
	*/
	result := wc_validate("wd_evil_answer", "evil.wdtest.", .A)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == BROKEN_CHAIN,
		"a DS whose signature expanded a wildcard is not a zone cut, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_zone_cut_whose_ds_signature_is_its_own_still_holds :: proc(t: ^testing.T) {
	// The control for the one above. `fine.wdtest.` is the same delegation a
	// label over, with its DS signed at its own name, so a chain that came
	// apart in the fixtures fails here too rather than leaving that refusal
	// looking like a verdict about the Labels field.
	result := wc_validate("wd_fine_answer", "fine.wdtest.", .A)
	testing.expectf(
		t,
		result.status == .Secure,
		"an ordinary signed delegation is still a zone cut, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_zone_cut_whose_ds_another_ancestor_signed_is_refused :: proc(t: ^testing.T) {
	/*
	The other half of "the parent's word": who signed it. The DS set at
	`gs.wdtest.` carries a signature in the root's name, made with the very key
	`wdtest.` signs with - a root and a child sharing a key, as one operator's
	zones may. It verifies under a key of the parent's, and the root is an
	ancestor of the owner, so `check_signature` has nothing against it; only
	`verified_rrset` holding the signer to the parent refuses it. A DS is the
	parent's to vouch for (RFC 4035 section 5.2), and taken on another zone's
	word the cut would make everything below it `Secure` on keys the parent
	never attested.
	*/
	result := wc_validate("wd_gs_answer", "gs.wdtest.", .A)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == BROKEN_CHAIN,
		"a DS set another ancestor signed is not a zone cut, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_wildcard_dname_still_redirects :: proc(t: ^testing.T) {
	/*
	`dname_covered` is the third caller of the same routine and reads only the
	status, so it is the site a guard like the two above would be copied to
	next. It must not be.

	RFC 6672 section 3.4.1 has the server send the synthesised CNAME unsigned,
	the DNAME being what carries the authority - and a DNAME may sit at a
	wildcard like any other type, so the RRSIG behind a legitimate redirection
	is routinely one label short. Refusing that here would take out every name
	behind every wildcard DNAME.
	*/
	result := wc_validate("dw_wildcard_dname", "x.y.dwtest.", .A)
	testing.expectf(
		t,
		result.status == .Secure,
		"a wildcard DNAME still redirects, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_relocated_wildcard_dname_does_not_redirect :: proc(t: ^testing.T) {
	/*
	And what stands in for that guard: the DNAME is in the answer section, so
	`validate_answer`'s own loop validates the same RRset, sees the short label
	count and records the expansion - which makes the RFC 4035 section 5.3.4
	proof a condition of the whole message. Moving the owner to a name the
	wildcard does not stand for leaves that proof unmakeable, and the unsigned
	CNAME `dname_covered` vouched for goes down with the message.
	*/
	result := wc_validate("dw_relocated_dname", "x.real.dwtest.", .A)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == "wildcard expansion not proven",
		"a wildcard DNAME re-owned elsewhere cannot redirect, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_relocated_wildcard_nsec_in_the_answer_is_not_secure :: proc(t: ^testing.T) {
	/*
	The same relocation one section over, and the reason "the expansion was
	proven" is not enough on its own.

	`validate_answer` reads a short Labels field as a wildcard expansion and
	asks for the RFC 4035 section 5.3.4 proof that the expansion was the right
	thing to do. Here that proof is real: the authority section carries the
	genuine `*.wctest. NSEC`, unmodified, and it does cover `nx.wctest.`. The
	attacker is proving something true.

	What the proof does not say is that the answer's own NSEC belongs at that
	owner, and RFC 4592 section 4.7 is why it never can: an NSEC at a wildcard
	is synthesised "only ... when the query exactly matches the record", so an
	expanded one was moved. Without the refusal the record goes out at AD=1,
	with a next-name and a type bit map of the sender's choosing, saying
	`nx.wctest.` exists.
	*/
	result := wc_validate("wc_relocated_answer_nsec", "nx.wctest.", .NSEC)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == WC_IMPOSSIBLE,
		"a wildcard's NSEC re-owned into the answer section is not authenticated, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(test)
test_an_expanded_ds_or_soa_answer_is_not_secure_either :: proc(t: ^testing.T) {
	/*
	The other two types on the same line, and they arrive differently.

	An NSEC is relocated by rewriting an owner, because the signature never
	covered it. A DS or an SOA cannot be moved that way - the digest and the
	apex are part of what was signed, so a rewrite dies in the signature. What
	reaches here instead is what a signer that wildcard signed one emits, which
	is the shape `wdtest.` already models for the chain walk.

	RFC 4592 makes both meaningless rather than merely unproven: section 4.6
	has a DS at a wildcard "meaningless and harmless" and a synthesized one of
	no use away from a delegation point, and section 4.1 has a wildcard owning
	an SOA be the zone apex, which is not a source of synthesis. The chain walk
	refuses an expanded DS and `verified_rrset` refuses an expanded SOA in the
	authority section; this holds the answer section to the same, so neither
	goes out at AD=1.
	*/
	// The walk down to `nx.wctest.` asks for its DS, and both the denial and
	// the attack are filed under that name and type. `fixture_answer` takes
	// the first, so the order of the two decides whether what follows
	// reproduces anything; see the note after `WC_FIXTURES`.
	walked, answered := fixture_answer(WC_FIXTURES, "nx.wctest.", .DS, context.temp_allocator)
	testing.expect(
		t,
		answered && slice.equal(walked, wc_reply("wc_nx_ds")),
		"the chain walk has to reach the denial at nx.wctest., not an attack reply filed under it",
	)

	ds := wc_validate("wc_expanded_ds_answer", "nx.wctest.", .DS)
	testing.expectf(
		t,
		ds.status == .Bogus && ds.reason == WC_IMPOSSIBLE,
		"a DS answer whose signature expanded a wildcard is not authenticated, got %v (%q)",
		ds.status,
		ds.reason,
	)
	soa := wc_validate("wc_expanded_soa_answer", "nx.wctest.", .SOA)
	testing.expectf(
		t,
		soa.status == .Bogus && soa.reason == WC_IMPOSSIBLE,
		"an SOA answer whose signature expanded a wildcard is not authenticated, got %v (%q)",
		soa.status,
		soa.reason,
	)
	free_all(context.temp_allocator)
}

/*
A verdict of "broken chain of trust" names the step that broke.

The reason alone says a chain is broken and not where: it cannot tell a DS the
parent signed that was refused from a denial that proved nothing or keys that
did not match, and an incident over by the time debug logging is switched on
leaves nothing else to reconstruct it from. The reason is unchanged - it goes to
the client as extended error text - and `detail` carries the zone and the step,
for the log.
*/
@(test)
test_a_broken_chain_names_the_zone_and_the_step :: proc(t: ^testing.T) {
	result := wc_validate("wd_evil_answer", "evil.wdtest.", .A)
	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, BROKEN_CHAIN)
	testing.expectf(
		t,
		strings.contains(result.detail, "evil.wdtest"),
		"the detail does not name the zone whose step broke: %q",
		result.detail,
	)
	testing.expectf(
		t,
		strings.contains(result.detail, "DS"),
		"the detail does not say which step broke: %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

// A verdict that is not a failure has nothing to explain.
@(test)
test_a_secure_verdict_carries_no_detail :: proc(t: ^testing.T) {
	result := wc_validate("wd_fine_answer", "fine.wdtest.", .A)
	testing.expect_value(t, result.status, Status.Secure)
	testing.expect_value(t, result.detail, "")
	free_all(context.temp_allocator)
}

// A `Bogus` that is about the message and not a step of the chain has no step to
// name, and must not carry one left over from elsewhere in the question.
@(test)
test_a_bogus_that_is_not_a_chain_step_carries_no_detail :: proc(t: ^testing.T) {
	result := wc_validate("wc_relocated_nxdomain", "www.wctest.", .A)
	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, NO_DENIAL)
	testing.expect_value(t, result.detail, "")
	free_all(context.temp_allocator)
}

/*
The detail belongs to the record set whose verdict is returned.

An answer holds more than one RRset - a CNAME and its target in another zone is
the everyday case - and each walks its own chain. The verdict is the worst one,
so the step that explains it is the one that set the worst, not whichever walk
ran last: a later RRset in a zone that holds up must not leave the broken one's
verdict with nothing to say for it.
*/
@(test)
test_a_broken_chain_keeps_its_detail_past_a_later_rrset :: proc(t: ^testing.T) {
	evil, eerr := dns.decode_message(wc_reply("wd_evil_answer"), context.temp_allocator)
	fine, ferr := dns.decode_message(wc_reply("wd_fine_answer"), context.temp_allocator)
	testing.expect_value(t, eerr, dns.Decode_Error.None)
	testing.expect_value(t, ferr, dns.Decode_Error.None)
	answer := make([dynamic]dns.Record, 0, len(evil.answer) + len(fine.answer), context.temp_allocator)
	append(&answer, ..evil.answer)
	append(&answer, ..fine.answer)
	evil.answer = answer[:]
	wire, _, encerr := dns.encode_message(evil, context.temp_allocator, compress = false)
	testing.expect_value(t, encerr, dns.Encode_Error.None)

	result := wc_validate_wire("evil.wdtest.", .A, wire)

	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, BROKEN_CHAIN)
	testing.expectf(
		t,
		strings.contains(result.detail, "evil.wdtest"),
		"the detail does not name the zone whose step broke: %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

/*
A broken chain met while proving a wildcard expansion names its step too.

The answer verifies against the parent's key as an expansion of `*.wdtest.`, and
the proof of that expansion walks to the owner's zone, through the cut at
`evil.wdtest.` whose DS the parent signed as a wildcard. That walk is what
breaks, so the verdict is the broken chain's and the detail says where.
*/
@(test)
test_a_broken_chain_under_a_wildcard_names_its_step :: proc(t: ^testing.T) {
	result := wc_validate("wd_wild_under_evil", "x.evil.wdtest.", .A)
	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, BROKEN_CHAIN)
	testing.expectf(
		t,
		strings.contains(result.detail, "evil.wdtest"),
		"the detail does not name the zone whose step broke: %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

/*
The root is checked against the trust anchors, not a parent's DS, and the
detail says so: an operator whose anchor is stale is otherwise sent looking for
a DS the root does not have.
*/
@(test)
test_a_root_that_matches_no_anchor_says_so :: proc(t: ^testing.T) {
	// The real anchor's key tag and algorithm, with a digest that is not its key's.
	stale := ". IN DS 38604 15 2 0000000000000000000000000000000000000000000000000000000000000000"
	v := scenario_validator(&WC_FIXTURES, stale)
	defer destroy_validator(v)
	result := validate(v, "fine.wdtest.", .A, wc_reply("wd_fine_answer"), fixture_now())

	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, BROKEN_CHAIN)
	testing.expectf(
		t,
		strings.has_prefix(result.detail, ".: ") && strings.contains(result.detail, "trust anchor"),
		"the detail does not say the root matched no trust anchor: %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}

/*
The detail is the RRset's own, read before anything else walks.

An unsigned CNAME is given a second chance through a DNAME that could have
synthesized it, and checking that DNAME is a walk of its own - one that clears
the step the CNAME's walk recorded. The CNAME here sits below the broken cut at
`evil.wdtest.`, and the DNAME at `wdtest.` matches it and is unsigned, so the
second chance fails and the verdict is still the CNAME's broken chain.
*/
@(test)
test_a_dname_check_does_not_take_the_cnames_detail :: proc(t: ^testing.T) {
	msg, derr := dns.decode_message(wc_reply("wd_evil_answer"), context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	msg.question[0].name = "x.evil.wdtest."
	msg.answer = []dns.Record {
		{name = "x.evil.wdtest.", type = .CNAME, class = .IN, ttl = 3600, data = dns.Rdata_Name{name = "x.evil.other.example."}},
		{name = "wdtest.", type = .DNAME, class = .IN, ttl = 3600, data = dns.Rdata_Name{name = "other.example."}},
	}
	wire, _, encerr := dns.encode_message(msg, context.temp_allocator, compress = false)
	testing.expect_value(t, encerr, dns.Encode_Error.None)

	result := wc_validate_wire("x.evil.wdtest.", .A, wire)

	testing.expect_value(t, result.status, Status.Bogus)
	testing.expect_value(t, result.reason, BROKEN_CHAIN)
	testing.expectf(
		t,
		strings.contains(result.detail, "evil.wdtest"),
		"the detail does not name the zone whose step broke: %q",
		result.detail,
	)
	free_all(context.temp_allocator)
}
