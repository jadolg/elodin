package dnssec

import "core:mem"
import "core:testing"
import "core:time"
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
expansion was the right thing to do. For a denial record nothing looked, and a
relocated NSEC is a bit map that answers for a name it was never published
under. Once is NODATA for a type the name really has; twice, with the owners
chosen so the two spans cover a qname and the wildcard, is NXDOMAIN for a name
the zone answers for. Both go out with AD=1 and into the cache.

RFC 4035 section 3.1.3.3 is what makes this always a forgery rather than a
case to be handled: NSEC records are published under their own names and are
never synthesised from a wildcard, so a denial record whose signature expanded
is a denial record that was moved. Unbound rewrites the owner to the canonical
one before verifying, for the same reason and with the same effect.

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
		rcode = 0,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f21e262a0451d37ef5b2d0d0e217a92db" +
			"3a409b7a3f5c7054a1c58bcd5026717700002e000100000e10005300300f0000000e107d3b18206a47882096cc004fca" +
			"53f493de3ed4de28b4ec590d7954f73756fd226953651150618ec931829f35a7dac1428e37e03586769817e79e535a0f" +
			"894b892aec16b5d798ec4a292508",
	},
	{
		key   = "wc_ds",
		name  = "wctest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000677637465737400002b00010677637465737400002b000100000e100024ec370f02a19a" +
			"92472283ee3426d1cc7bbde5f5386cc063a64c98ddadd37023aaefb839370677637465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00ac86466a41d9725933dc07d981022c00974142d199f4885de89b6d0b0c" +
			"4b9ee4687a5cf27cea35b4aafc9892f86b2763b2f6d9ce5a73fc26909f38d4c3089e0b",
	},
	{
		key   = "wc_dnskey",
		name  = "wctest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006776374657374000030000106776374657374000030000100000e1000240101030fa30d" +
			"93548b4ca234f2db94ce2dbcc6a1b4e683557915664e3dd71de7d50abfd20677637465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820ec3706776374657374007125a56774a22bfd00caf3f760d24208f604e3b45033" +
			"8305addb216595e83e2300515277d82b386df870e82936d2a781ce07c08715d78876a8587ca6fd98380e",
	},
	{
		key   = "wc_real_ds",
		name  = "real.wctest.",
		type  = .DS,
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
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
		rcode = 3,
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
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
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
		key   = "wd_ds",
		name  = "wdtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000677647465737400002b00010677647465737400002b000100000e100024e4410f022360" +
			"32fc58fd0abe4e2bd9a7519ef8ec4b6e97da3a6810e0e7ad69e4ee518f5b0677647465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00c87b19f4d2990a924d2469710f61b3dd1a9e353f28a8b42bf2400694ca" +
			"668de1369c6eb5c3679093ef96bf8e7ea3b218a4c535a0a93d14d1f70cb64a0382ac0a",
	},
	{
		key   = "wd_dnskey",
		name  = "wdtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006776474657374000030000106776474657374000030000100000e1000240101030f7503" +
			"a108781965e34b9e9ad8647514e27b77794dd7a51ba5574180a8dc5ff0000677647465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820e4410677647465737400261d7eddd6bb9dad50f17b539349d4dac6120a77b399" +
			"e5ca8a353916754f5b11a3a4d7a47577157f2603f282b5cbcda0c572ea946cf5f9b48e66360a429bc605",
	},
	{
		key   = "wd_evil_ds",
		name  = "evil.wdtest.",
		type  = .DS,
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
		wire  = "123485800001000200000000046576696c067764746573740000010001046576696c0677647465737400000100010000" +
			"0e100004c0000242046576696c0677647465737400002e000100000e10005f00010f0200000e107d3b18206a478820b5" +
			"ef046576696c0677647465737400b97c2503c26f58efe0d68a36f39dbfb875bb4e8048936beca38a0dc0c631534c2632" +
			"57547614a10416d2efe4849f8bbb4f5927f74834e3a8498bb54f80025a06",
	},
	{
		key   = "wd_fine_ds",
		name  = "fine.wdtest.",
		type  = .DS,
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
		wire  = "1234858000010002000000000466696e650677647465737400000100010466696e650677647465737400000100010000" +
			"0e100004c00002430466696e650677647465737400002e000100000e10005f00010f0200000e107d3b18206a4788205f" +
			"0f0466696e6506776474657374008a2e7b53562980de5ef6e5053fa60f5049f698436502ffb0b7e51158f0bd968b90f7" +
			"3beed9e0bdde6c18470bd86a0de6e8e38dbedf58890de7bfebe1f836e50a",
	},
	{
		key   = "dw_ds",
		name  = "dwtest.",
		type  = .DS,
		rcode = 0,
		wire  = "1234858000010002000000000664777465737400002b00010664777465737400002b000100000e10002438a40f027c40" +
			"d2bd5572ced63f66168aa050975672c9fadcf23af1480ed26580278ac46e0664777465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a47882096cc00c9254d2f3e36290405fcdf2ee517276b71f4e6be732ddb9d51b8021951" +
			"93a3bc9f7c9a303dc07b173971dd4dd42636f175239a6025b18c2a71d9085232634c07",
	},
	{
		key   = "dw_dnskey",
		name  = "dwtest.",
		type  = .DNSKEY,
		rcode = 0,
		wire  = "12348580000100020000000006647774657374000030000106647774657374000030000100000e1000240101030f4779" +
			"9087d45d7a0017d85a88ea57d4b17a8cfcb13a4654feff1f181bc3b7fb540664777465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a47882038a4066477746573740039a79a95fc94e712da316c656c1db52af649082d9e5e" +
			"74d5b2f2af32781df8c9b4acfaf7d0f12a218c3b1fcff98117349d91d92b4e46b031f45e91d7300ad505",
	},
	{
		key   = "dw_y_ds",
		name  = "y.dwtest.",
		type  = .DS,
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
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
		rcode = 0,
		wire  = "1234858000010003000000000178047265616c066477746573740000010001047265616c066477746573740000270001" +
			"00000e10000b0174076578616d706c6500047265616c0664777465737400002e000100000e10005a00270f0100000e10" +
			"7d3b18206a47882038a40664777465737400b422618c323e1e91aa81448e98ddea3d18072d7b14e9fd867dcaa8c5e623" +
			"905b01ada0924fb209692df7983fd907dd2fe6cc1e0b837c3f6d7fac51554e5dfb0b0178047265616c06647774657374" +
			"000005000100000e10000d01780174076578616d706c6500",
	},
}

@(private = "file")
wc_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in WC_FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return decode_hex(f.wire, allocator)
		}
	}
	return nil, false
}

@(private = "file")
wc_reply :: proc(key: string) -> []u8 {
	for f in WC_FIXTURES {
		if f.key == key {
			out, _ := decode_hex(f.wire, context.temp_allocator)
			return out
		}
	}
	return nil
}

/*
The reason a refusal has to carry.

`Bogus` on its own would be satisfied by a fixture chain that had quietly come
apart - a signature whose window `FIXTURE_TIME` drifted out of, a lookup that
matched the wrong record - and a test reading only the verdict would stay green
while exercising nothing. This is what a denial with no record left standing
settles as, which is what dropping the relocated NSEC leaves behind.
*/
@(private = "file")
WC_UNPROVEN :: "no denial of existence"

@(private = "file")
wc_validate :: proc(key, qname: string, type: dns.Type) -> Result {
	anchor, parsed := parse_trust_anchor(WC_ANCHOR, context.temp_allocator)
	if !parsed {
		return {status = .Indeterminate, reason = "the anchor did not parse"}
	}
	anchors := make([]Trust_Anchor, 1, context.temp_allocator)
	anchors[0] = anchor
	v := make_validator(wc_query, nil, Options{anchors = anchors})
	defer destroy_validator(v)
	return validate(v, qname, type, wc_reply(key), time.unix(FIXTURE_TIME, 0))
}

@(test)
test_a_relocated_wildcard_nsec_cannot_prove_nodata :: proc(t: ^testing.T) {
	// `real.wctest.` really holds a TXT. The wildcard's bit map does not list
	// one, so the record proves the opposite of the truth as soon as its owner
	// is read as the name it was published under.
	result := wc_validate("wc_relocated_nodata", "real.wctest.", .TXT)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == WC_UNPROVEN,
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
		result.status == .Bogus && result.reason == WC_UNPROVEN,
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
	The same discarded return, one call site over.

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
		result.status == .Bogus && result.reason == "broken chain of trust",
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
	owner, and RFC 4035 section 3.1.3.3 is why it never can: a zone does not
	synthesise an NSEC or an NSEC3 from a wildcard, so an expanded one was
	moved. Without the refusal the record goes out at AD=1, with a next-name
	and a type bit map of the sender's choosing, saying `nx.wctest.` exists.
	*/
	result := wc_validate("wc_relocated_answer_nsec", "nx.wctest.", .NSEC)
	testing.expectf(
		t,
		result.status == .Bogus && result.reason == "relocated denial record",
		"a wildcard's NSEC re-owned into the answer section is not authenticated, got %v (%q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}
