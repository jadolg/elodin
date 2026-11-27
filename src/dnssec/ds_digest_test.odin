package dnssec

import "core:fmt"
import "core:log"
import "core:strings"
import "core:testing"

/*
RFC 4509 section 3: "Validator implementations SHOULD ignore DS RRs containing
SHA-1 digests if DS RRs with SHA-256 digests are present in the DS RRset." Each
zone's DS set holds a SHA-1 DS that matches its key. Beside it:

- `ddsha1.`: nothing, so the SHA-1 DS is followed;
- `ddboth.`: a SHA-256 DS that matches too;
- `ddwrong.`, `ddwrong384.`: a SHA-256 or SHA-384 DS that matches nothing, so
  the SHA-1 one is ignored and the zone is bogus;
- `ddshort.`: a SHA-256 DS one byte short, which is no SHA-256 DS, as BIND
  reads it, so the SHA-1 one is followed.

The root is anchored the same way for the trust anchor road.

Generated - `testdata/gen/sign_fixtures.py`, scenario `ds_digest_preference`.
*/

@(private = "file")
DD_ANCHOR :: ". IN DS 31591 15 2 A897B0C3112F70C2A5C7A534A896C0900F6CA166B9DE713822C5581D25095EC3"
@(private = "file")
DD_ANCHOR_SHA1 :: ". IN DS 31591 15 1 03946E40807E1B1972DECCB0D48A8C3F95FC98C3"
@(private = "file")
DD_ANCHOR_WRONG_SHA256 :: ". IN DS 31591 15 2 A5BED7447D48E5A7FD55833807C2BA009FAD806E9F023E471168A7C58621E4BB"

@(private = "file")
DD_FIXTURES := []Fixture{
	{
		key   = "dd_root_dnskey",
		name  = ".",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000000300001000030000100000e1000240101030f1ce1a8c332f3ae32eca4354644e41f3f" +
			"8e3531f282ff1b089a9c65d496aa553300002e000100000e10005300300f0000000e107d3b18206a4788207b67002b88" +
			"3aeccf8f1b54ad845aabb4f47dce7233ea1d558c175d2f47f7bd6a22338f8047e25f18e9e339c2a991cbafafe038fcfa" +
			"149fc8c45219f0e61d0da0274504",
	},
	{
		key   = "dd_sha1_ds",
		name  = "ddsha1.",
		type  = .DS,
		wire  = "1234858000010002000000000664647368613100002b00010664647368613100002b000100000e10001813950f019a13" +
			"2c899f6b975c2b6069e7adce43798e75b4410664647368613100002e000100000e100053002b0f0100000e107d3b1820" +
			"6a4788207b67000dd361b2125d3b3950d07a93c6fcd395cb371017c48f3f82c7e15160e09eac78195e50eb5774fb50df" +
			"b2d092e619aae42609132146361e40f21c29de9552b202",
	},
	{
		key   = "dd_sha1_dnskey",
		name  = "ddsha1.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000006646473686131000030000106646473686131000030000100000e1000240101030f07a4" +
			"77c186b9a15ac82ff572e8d46fc881ddc2732a85b5b831cca56b4a5c0ba80664647368613100002e000100000e10005a" +
			"00300f0100000e107d3b18206a47882013950664647368613100d02473ccc08450ea057aa5b84bd1feecfc717409dc39" +
			"23dd96657724a26592765381b9bcc8dfd0c7f26e8a68225ce5028a6d394b4ae8a533b8209220f053b607",
	},
	{
		key   = "dd_sha1_answer",
		name  = "www.ddsha1.",
		type  = .A,
		wire  = "123485800001000200000000037777770664647368613100000100010377777706646473686131000001000100000e10" +
			"0004c0000201037777770664647368613100002e000100000e10005a00010f0200000e107d3b18206a47882013950664" +
			"647368613100daba0b0e678fe1c0f808a64029f65b917ec67c5c45b805798222aff0e28df35f8e051ae0312851193b2a" +
			"08584cd137f9106d3766a39d5f70703b8a15e1064505",
	},
	{
		key   = "dd_sha1_www_ds",
		name  = "www.ddsha1.",
		type  = .DS,
		wire  = "123485800001000000020000037777770664647368613100002b0001037777770664647368613100002f000100000e10" +
			"001006646473686131000006400000000003037777770664647368613100002e000100000e10005a002f0f0200000e10" +
			"7d3b18206a478820139506646473686131003ea4b461a9f741eeeac391cdf86e846351f057cfafe6fedd5e640f20600b" +
			"3eb5deec7aa528359142a54fbdd44eff32e6ad25a67a8e7ad06c70d8ea61fc53e40b",
	},
	{
		key   = "dd_both_ds",
		name  = "ddboth.",
		type  = .DS,
		wire  = "123485800001000300000000066464626f746800002b0001066464626f746800002b000100000e100018ad5d0f01a5fc" +
			"3b06413fda4b00c6ffc13aaf6c84ca4a6278066464626f746800002b000100000e100024ad5d0f02585bc1287f898cae" +
			"38543e15a956d65ed6a62f718a8ae17f49ff3c003892310b066464626f746800002e000100000e100053002b0f010000" +
			"0e107d3b18206a4788207b67009889528a0390c491145f4f201fc3cb3450e4416a130477f77ec1db63c0886178320524" +
			"d635473bb782be7f72b1ff564a6c03c5b2b32a71c8081d4917b730d908",
	},
	{
		key   = "dd_both_dnskey",
		name  = "ddboth.",
		type  = .DNSKEY,
		wire  = "123485800001000200000000066464626f74680000300001066464626f7468000030000100000e1000240101030f8bdf" +
			"48ef3f4cc2a4e3b0dba6adf8306dddfd2d8c7652cfc6abfa42bff933fb3e066464626f746800002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820ad5d066464626f7468004d84bbf41e8bf263bca275d34414330913d92b8f24c9" +
			"c3a5c7dd31c2195c1de6def149249fee1dcb192ccf2141686b4db298b75c3651b0e2b70c8d2c57d7b007",
	},
	{
		key   = "dd_both_answer",
		name  = "www.ddboth.",
		type  = .A,
		wire  = "12348580000100020000000003777777066464626f7468000001000103777777066464626f7468000001000100000e10" +
			"0004c000020103777777066464626f746800002e000100000e10005a00010f0200000e107d3b18206a478820ad5d0664" +
			"64626f746800494dc6414708744ff43182065466b94ec2078fcbee993229a2cbcd337c8f1ba223b47457fe87fbe0246a" +
			"dec19092cd79543aa98d0908bce7afbbd5b6ae06b603",
	},
	{
		key   = "dd_both_www_ds",
		name  = "www.ddboth.",
		type  = .DS,
		wire  = "12348580000100000002000003777777066464626f746800002b000103777777066464626f746800002f000100000e10" +
			"0010066464626f746800000640000000000303777777066464626f746800002e000100000e10005a002f0f0200000e10" +
			"7d3b18206a478820ad5d066464626f74680001c5ecef9b94a8cd4e29996e20c6858ed384ab696201868f680697ac185a" +
			"f11a55d512e122b27314458608b67ba9667e8b3c0d00e79dcca4dc49ccdcee70d509",
	},
	{
		key   = "dd_wrong_ds",
		name  = "ddwrong.",
		type  = .DS,
		wire  = "12348580000100030000000007646477726f6e6700002b000107646477726f6e6700002b000100000e100018eb080f01" +
			"676a2369fa52e570cdada23b453d76f639b6f8b407646477726f6e6700002b000100000e100024eb080f02a5bed7447d" +
			"48e5a7fd55833807c2ba009fad806e9f023e471168a7c58621e4bb07646477726f6e6700002e000100000e100053002b" +
			"0f0100000e107d3b18206a4788207b6700b15dc32037f6f41814965a62b0406ad8107daa947cb903de5d13fc70641c0d" +
			"8973aa07fc12604c212b121f53d5ef57a2e79a7dc533e95054ddd874f5c9b30004",
	},
	{
		key   = "dd_wrong_dnskey",
		name  = "ddwrong.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000007646477726f6e67000030000107646477726f6e67000030000100000e1000240101030f" +
			"e62bd7b9cc6c8533e7d826087a455262ce3b73f6c4a1711059355584922b442007646477726f6e6700002e000100000e" +
			"10005b00300f0100000e107d3b18206a478820eb0807646477726f6e6700b95fed158a29c506059303eaf0e4fe5057ed" +
			"c6c3cc2f0a8eaa51c244dc7f43c1b5c4d82d183f9d5ad9f126b25d58399d4205c8131aca82d20243bfcaef1b5d05",
	},
	{
		key   = "dd_wrong_answer",
		name  = "www.ddwrong.",
		type  = .A,
		wire  = "1234858000010002000000000377777707646477726f6e6700000100010377777707646477726f6e6700000100010000" +
			"0e100004c00002010377777707646477726f6e6700002e000100000e10005b00010f0200000e107d3b18206a478820eb" +
			"0807646477726f6e6700ad9350779657f65839129f8d9e32cd107a669581632f4c49511d8432cc78c990553fa882c168" +
			"9fcda833ac8d9c159b83ed2ff8dcf4bfc40a65e3dfd5fd9ac80e",
	},
	{
		key   = "dd_wrong_www_ds",
		name  = "www.ddwrong.",
		type  = .DS,
		wire  = "1234858000010000000200000377777707646477726f6e6700002b00010377777707646477726f6e6700002f00010000" +
			"0e10001107646477726f6e670000064000000000030377777707646477726f6e6700002e000100000e10005b002f0f02" +
			"00000e107d3b18206a478820eb0807646477726f6e67008e0cd557d3e6d1f20f399de182f79c2a0612a15b431a5c6042" +
			"a9b8907689075a1069af50ea6e2f74025612e147cdb70ed91059e02b213af5d0d7b497a9b4640b",
	},
	{
		key   = "dd_wrong384_ds",
		name  = "ddwrong384.",
		type  = .DS,
		wire  = "1234858000010003000000000a646477726f6e6733383400002b00010a646477726f6e6733383400002b000100000e10" +
			"001845140f01f59a4936dfb8981a80bf1afdd6b75615590f81500a646477726f6e6733383400002b000100000e100034" +
			"45140f0431be6ebfaf1e13bce0cb4022f241c84ff9bbe12bdbcafb071e855c382d11c4682a399f1a36dd63bf4a227d7f" +
			"ccd244960a646477726f6e6733383400002e000100000e100053002b0f0100000e107d3b18206a4788207b6700826cd9" +
			"a0fb81a0255979bc09be73a869cab4839403dec8edde56bb38dc24286a6779d3cd4fc82b6fe73971b357acb286684298" +
			"7b006e991f6b2634dde149380d",
	},
	{
		key   = "dd_wrong384_dnskey",
		name  = "ddwrong384.",
		type  = .DNSKEY,
		wire  = "1234858000010002000000000a646477726f6e6733383400003000010a646477726f6e67333834000030000100000e10" +
			"00240101030f63cd5b4c7835bf307eb061fb11f3df8c05e88a82e1a2aba07539618aeac9991c0a646477726f6e673338" +
			"3400002e000100000e10005e00300f0100000e107d3b18206a47882045140a646477726f6e67333834003d59ff6e0337" +
			"64a62a916ff06fed60780601aef8119e4a03bd9ba7fe9edcc815c7f1ce013fe707d68ec3b07c9de15eabc13a19a49c72" +
			"7c31b77b93c7a74dcd00",
	},
	{
		key   = "dd_wrong384_answer",
		name  = "www.ddwrong384.",
		type  = .A,
		wire  = "123485800001000200000000037777770a646477726f6e673338340000010001037777770a646477726f6e6733383400" +
			"0001000100000e100004c0000201037777770a646477726f6e6733383400002e000100000e10005e00010f0200000e10" +
			"7d3b18206a47882045140a646477726f6e6733383400126d05469721fe9617cd7817bec5802a4606ebae6916b101705b" +
			"9e8fb8003304aefafad31189f076065752e017b40d60ba7eaca01cad92da355aaa60a7a4d204",
	},
	{
		key   = "dd_wrong384_www_ds",
		name  = "www.ddwrong384.",
		type  = .DS,
		wire  = "123485800001000000020000037777770a646477726f6e6733383400002b0001037777770a646477726f6e6733383400" +
			"002f000100000e1000140a646477726f6e67333834000006400000000003037777770a646477726f6e6733383400002e" +
			"000100000e10005e002f0f0200000e107d3b18206a47882045140a646477726f6e6733383400041857c3f7f74d118440" +
			"0682b6d757867760b120f02aadcedb8652b98c9485492bcd8bc3d8d070ec7e90cdb77d844741a39fc97a7af6e5593237" +
			"746ad6007301",
	},
	{
		key   = "dd_short_ds",
		name  = "ddshort.",
		type  = .DS,
		wire  = "12348580000100030000000007646473686f727400002b000107646473686f727400002b000100000e100018e1340f01" +
			"13f4ca6ec6e23ead3d34466df08b9eac6cee96e007646473686f727400002b000100000e100023e1340f0249a844e2e7" +
			"ad2a26c01a69befc329d55bef1bc8ec53d0450b4a5e4c09eb5d207646473686f727400002e000100000e100053002b0f" +
			"0100000e107d3b18206a4788207b6700dc7ca95f7d0a8a7ff81077f0cfbfa6ebc15e26fa81f90e5dffd33b432d4de30f" +
			"000c28a55c7f7f902519139ca243ef3fad781f871170c8916120a0425a2eda00",
	},
	{
		key   = "dd_short_dnskey",
		name  = "ddshort.",
		type  = .DNSKEY,
		wire  = "12348580000100020000000007646473686f7274000030000107646473686f7274000030000100000e1000240101030f" +
			"9acf738be6455472581d64ebed851d4f7b5f23713c78b91a947d45423d82208e07646473686f727400002e000100000e" +
			"10005b00300f0100000e107d3b18206a478820e13407646473686f72740061210ee38f11fa189b077376f19b57ad61fb" +
			"1e64d4f15c70c78f32475cf5328df21fddd28240a3cf0464555d7454a2cc263820d2753cbe8155a1453e1bb45d0b",
	},
	{
		key   = "dd_short_answer",
		name  = "www.ddshort.",
		type  = .A,
		wire  = "1234858000010002000000000377777707646473686f727400000100010377777707646473686f727400000100010000" +
			"0e100004c00002010377777707646473686f727400002e000100000e10005b00010f0200000e107d3b18206a478820e1" +
			"3407646473686f727400a415640f06cbcc93c9437aa27c15bdcaf97b7dc887ba9df25ad8f7e38f2c13f2c986e57a63d4" +
			"a53791a84f0fb3eef3fa5a79f465f84958169c7c7a6d8e0ac400",
	},
	{
		key   = "dd_short_www_ds",
		name  = "www.ddshort.",
		type  = .DS,
		wire  = "1234858000010000000200000377777707646473686f727400002b00010377777707646473686f727400002f00010000" +
			"0e10001107646473686f72740000064000000000030377777707646473686f727400002e000100000e10005b002f0f02" +
			"00000e107d3b18206a478820e13407646473686f727400940760e39f3a769c920c91e19654990fae6c1103eb6d967351" +
			"4f2320967fb02feb188b0e83ab59d9ec2b5157c98816a8d4a761ee8cf6775e00e2f391c93f2d08",
	},
}

@(test)
test_a_sha1_ds_is_ignored_beside_a_stronger_one :: proc(t: ^testing.T) {
	if !dd_supported() {
		return
	}
	cases := []struct {
		zone:   string,
		status: Status,
	} {
		{zone = "ddsha1", status = .Secure},
		{zone = "ddboth", status = .Secure},
		{zone = "ddwrong", status = .Bogus},
		{zone = "ddwrong384", status = .Bogus},
		{zone = "ddshort", status = .Secure},
	}
	for c in cases {
		v := scenario_validator(&DD_FIXTURES, DD_ANCHOR)
		defer destroy_validator(v)
		qname := fmt.tprintf("www.%s.", c.zone)
		answer := scenario_fixture(DD_FIXTURES, fmt.tprintf("dd_%s_answer", c.zone[2:]))
		result := validate(v, qname, .A, answer, fixture_now())
		testing.expectf(t, result.status == c.status, "%s: got %v (%q / %q), want %v", qname, result.status, result.reason, result.detail, c.status)
		if c.status == .Bogus {
			testing.expectf(t, strings.contains(result.detail, SHA1_DS_IGNORED), "%s: the detail does not say SHA-1 was set aside: %q", qname, result.detail)
		}
	}
	free_all(context.temp_allocator)
}

@(test)
test_a_sha1_trust_anchor_is_ignored_beside_a_stronger_one :: proc(t: ^testing.T) {
	if !dd_supported() {
		return
	}
	answer := scenario_fixture(DD_FIXTURES, "dd_sha1_answer")
	{
		v := scenario_validator(&DD_FIXTURES, DD_ANCHOR_SHA1)
		defer destroy_validator(v)
		result := validate(v, "www.ddsha1.", .A, answer, fixture_now())
		testing.expectf(t, result.status == .Secure, "a SHA-1 anchor alone: got %v (%q / %q)", result.status, result.reason, result.detail)
	}
	{
		v := scenario_validator(&DD_FIXTURES, DD_ANCHOR_SHA1, DD_ANCHOR_WRONG_SHA256)
		defer destroy_validator(v)
		result := validate(v, "www.ddsha1.", .A, answer, fixture_now())
		testing.expectf(t, result.status == .Bogus, "a SHA-1 anchor beside a SHA-256 one: got %v (%q)", result.status, result.reason)
		testing.expectf(t, strings.contains(result.detail, SHA1_DS_IGNORED), "the detail does not say SHA-1 was set aside: %q", result.detail)
	}
	free_all(context.temp_allocator)
}

// Only a usable SHA-256 or SHA-384 DS of its type's length puts SHA-1 aside.
@(test)
test_ds_set_reading :: proc(t: ^testing.T) {
	if !dd_supported() {
		return
	}
	testing.expect(t, !algorithm_supported(253), "premise: algorithm 253 is one nothing implements")
	d20, d31, d32, d48: [48]u8
	sha1 := Ds{algorithm = ALG_ED25519, digest_type = DIGEST_SHA1, digest = d20[:20]}
	cases := []struct {
		name:      string,
		set:       []Ds,
		checkable: bool,
		skip_sha1: bool,
	} {
		{name = "SHA-1 alone", set = {sha1}, checkable = true, skip_sha1 = false},
		{name = "beside SHA-256", set = {sha1, {algorithm = ALG_ED25519, digest_type = DIGEST_SHA256, digest = d32[:32]}}, checkable = true, skip_sha1 = true},
		{name = "beside SHA-384", set = {sha1, {algorithm = ALG_ED25519, digest_type = DIGEST_SHA384, digest = d48[:48]}}, checkable = true, skip_sha1 = true},
		{name = "beside a short SHA-256", set = {sha1, {algorithm = ALG_ED25519, digest_type = DIGEST_SHA256, digest = d31[:31]}}, checkable = true, skip_sha1 = false},
		// An algorithm nothing implements makes the stronger DS unusable.
		{name = "beside an unusable SHA-256", set = {sha1, {algorithm = 253, digest_type = DIGEST_SHA256, digest = d32[:32]}}, checkable = true, skip_sha1 = false},
		{name = "an unknown digest type", set = {{algorithm = ALG_ED25519, digest_type = 99, digest = d32[:32]}}, checkable = false, skip_sha1 = false},
	}
	for c in cases {
		checkable, skip_sha1 := ds_set_reading(c.set)
		testing.expectf(t, checkable == c.checkable && skip_sha1 == c.skip_sha1, "%s: checkable %v, skip SHA-1 %v", c.name, checkable, skip_sha1)
	}
}

/*
Whether this host's crypto policy runs everything the fixtures need: Ed25519
and the three DS digests. A host refusing SHA-384, say, reads `ddwrong384.`'s
SHA-384 DS as unusable and follows the SHA-1 one, which is right there and
wrong here.
*/
@(private = "file")
dd_supported :: proc() -> bool {
	probe_algorithms()
	for digest in ([]u8{DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384}) {
		if !digest_supported(digest) {
			log.infof("skipped: this host's crypto policy refuses DS digest type %d", digest)
			return false
		}
	}
	if !algorithm_supported(ALG_ED25519) {
		log.info("skipped: this host's crypto policy refuses Ed25519")
		return false
	}
	return true
}

// `ds_matches` hashes into a buffer of `MAX_DIGEST_SIZE`: a digest type that
// outgrew it would never match its DS, and every zone using it would be Bogus.
@(test)
test_every_digest_fits_the_ds_buffer :: proc(t: ^testing.T) {
	for d in 0 ..= 255 {
		testing.expectf(t, digest_size(u8(d)) <= MAX_DIGEST_SIZE, "digest type %d is %d bytes, past MAX_DIGEST_SIZE", d, digest_size(u8(d)))
	}
}
