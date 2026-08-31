package dnssec

import "core:mem"
import "core:testing"

/*
The signature checks, and the byte wrangling in front of them.

OpenSSL does the arithmetic; everything in this file is about handing it the
right bytes. DNSSEC puts keys and signatures on the wire in its own compact
formats - RFC 3110 for RSA, RFC 6605 for ECDSA, RFC 8080 for the Edwards curves
- and each has to be repackaged into the DER structures the library expects. A
mistake there does not announce itself: the signature simply fails, the answer
becomes bogus, and the name stops resolving for everyone behind this server.

The vectors below are real signatures, produced outside this implementation and
checked by OpenSSL through a different binding before being written down. Two of
the ECDSA ones were selected for the bit patterns that break a naive DER
encoder:

  - a signature whose R and S both begin with the high bit set. DER integers are
    signed, so each needs a 0x00 byte in front of it. Omit that and roughly one
    signature in four fails - the intermittent, unreproducible DNSSEC failure.
  - a signature whose R begins with a zero byte, which DER requires be dropped
    rather than encoded as a redundant leading zero.
*/

// The canonical signing input from `canonical_unit_test.odin`, which is what
// each of these vectors was signed over.
@(private = "file")
SIGNED_DATA ::
	"00010d0300000e106a000000690000001234076578616d706c6503636f6d0003777777076578616d706c6503636f6d00" +
	"0001000100000e100004c000020103777777076578616d706c6503636f6d000001000100000e100004c0000202"

@(private = "file")
P256_HIGH_BIT_KEY ::
	"35b9e4db7d6507bce05990f788182bb2dc1c02c4279688bb2649e062a8ed86b0" +
	"3862c0800530d034eb36da18b5697968fa02a0d7b6726e0183e43d497c842cc6"
@(private = "file")
P256_HIGH_BIT_SIG ::
	"f520ea3ea1b513d4f9f6d9e023e1fa764e3199f228df4546d3dc053d3ea8aaf2" +
	"c60e2b79965c880f40f7f620a0d261532e070f8d3dce0e70be6cf449c06cad3e"

@(private = "file")
P256_LEADING_ZERO_KEY ::
	"6e0452a53394e122fdb58260106a865cdfac6f6104999bf453285598642bd295" +
	"d8d2d4440af919c25ec2e904a89681ae9e1789e0a11202f8fda9f6494d57aa31"
@(private = "file")
P256_LEADING_ZERO_SIG ::
	"008229879522db6703c33558513f0b1da45602e644aa246e45cd34da04f309e5" +
	"6a5938895ce298a5ee32f75e9ac61bf79417511d279bbcfb67a1173dd3df8774"

@(private = "file")
ED25519_KEY :: "ea354127438791d9aea70ecfda53c1692a6abf76ef740d4126cb187dcb960cf8"
@(private = "file")
ED25519_SIG ::
	"f1f60113e853c698305569d6dd1531054f31443a1bcb0e1021ba2afccd7f7f16" +
	"1db52bd222cad4c7ecbff7b35cbefad2c9f5533fdfa677bbdfc55ac15fe26007"

@(private = "file")
RSA_KEY ::
	"03010001b546dd45827e3e95425757cac526bd61e4257557f530b0eec3fea17e907fd70c9db925864542b1c9aff3b9bf" +
	"83cb668e2c595f6c9075944abd0578426c0be979f0116dd9e19ac008a906dfa32fae2b506b465dc75f27a713324782173" +
	"167f659d7695c30256d6e01296dcafbad038953361d0e4bf51c5b70d6a096cfb46119a5ea6a23719308c1ea139508a5f5" +
	"9880bf083795b27f5bf9609c50fcc2667717024c5a15094468625684068a2621ffffe8e9065408089b85374fed92cf6d3" +
	"0c8b32d08451d5b5446ea6a16c11bee0a134a2ca062c6d84308dbab8985ca69792eb6571ad9678d906461c4eb02dbca8b" +
	"37d4d985fe1cea4d631904833224b871b32b"
@(private = "file")
RSA_SIG ::
	"17bd8eddeec3606c36351145334966ccb2d00202df6fe599284a692cbee22976f3235a8578e34020e0ce612621fc3c418" +
	"e35219d116da40b90135565a3c297a3d83ed7e331561effeec840c20f47f019f4a8e5869d6ff3593cdb4fa92142e4de26" +
	"ab445933c0b39a23c41d68c2a7024c4b8c5e5dfde896ff0a44ef2f5af24273cad4386c201008e898fd800275a313bd17b" +
	"ad5b34b5c09fe94716a6a00c9921f1875f4db226eb71147fc578d100c6f1723b2ffb52594ca73258e1423f6bb6b57e870" +
	"45e92c2c8b53d63334f61eb2d4a2984ea7bef174f063ed76f26450041f2f6a7d1e99ee781ae1dd4c7e7aa8b6768858c84" +
	"bbc741f9a1c6bdbaf5042e90942"

@(private = "file")
hex :: proc(text: string) -> []u8 {
	out, ok := decode_hex(text, context.temp_allocator)
	if !ok {
		return nil
	}
	return out
}

@(private = "file")
check :: proc(algorithm: u8, key, sig, data: string) -> Verify_Result {
	return verify_signature(algorithm, hex(key), hex(sig), hex(data), context.temp_allocator)
}

@(test)
test_verifies_an_ecdsa_signature_whose_r_and_s_have_the_top_bit_set :: proc(t: ^testing.T) {
	// Both halves need a 0x00 byte in front of them in DER. This is the vector
	// that fails if `der_integer` skips that.
	testing.expect_value(
		t,
		check(ALG_ECDSAP256SHA256, P256_HIGH_BIT_KEY, P256_HIGH_BIT_SIG, SIGNED_DATA),
		Verify_Result.Ok,
	)
	free_all(context.temp_allocator)
}

@(test)
test_verifies_an_ecdsa_signature_with_a_leading_zero_byte :: proc(t: ^testing.T) {
	// R begins 0x00, which DER requires be dropped rather than carried through
	// as a redundant leading zero.
	testing.expect_value(
		t,
		check(ALG_ECDSAP256SHA256, P256_LEADING_ZERO_KEY, P256_LEADING_ZERO_SIG, SIGNED_DATA),
		Verify_Result.Ok,
	)
	free_all(context.temp_allocator)
}

@(test)
test_verifies_an_ed25519_signature :: proc(t: ^testing.T) {
	// RFC 8080. The curve hashes internally, so no digest is named and the
	// 32-byte key is wrapped straight into a SubjectPublicKeyInfo.
	testing.expect_value(t, check(ALG_ED25519, ED25519_KEY, ED25519_SIG, SIGNED_DATA), Verify_Result.Ok)
	free_all(context.temp_allocator)
}

@(test)
test_verifies_an_rsa_signature :: proc(t: ^testing.T) {
	// RFC 3110: a one-byte exponent length, the exponent, then the modulus to
	// the end of the field.
	testing.expect_value(t, check(ALG_RSASHA256, RSA_KEY, RSA_SIG, SIGNED_DATA), Verify_Result.Ok)
	free_all(context.temp_allocator)
}

@(test)
test_a_signature_over_other_data_does_not_verify :: proc(t: ^testing.T) {
	// The whole point. Every vector above signs one specific byte string, and
	// changing any of it must break the check.
	altered := hex(SIGNED_DATA)
	altered[len(altered) - 1] ~= 0x01
	testing.expect_value(
		t,
		verify_signature(ALG_ECDSAP256SHA256, hex(P256_HIGH_BIT_KEY), hex(P256_HIGH_BIT_SIG), altered, context.temp_allocator),
		Verify_Result.Bad,
	)
	testing.expect_value(
		t,
		verify_signature(ALG_ED25519, hex(ED25519_KEY), hex(ED25519_SIG), altered, context.temp_allocator),
		Verify_Result.Bad,
	)
	testing.expect_value(
		t,
		verify_signature(ALG_RSASHA256, hex(RSA_KEY), hex(RSA_SIG), altered, context.temp_allocator),
		Verify_Result.Bad,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_flipped_bit_in_the_signature_does_not_verify :: proc(t: ^testing.T) {
	data := hex(SIGNED_DATA)

	// One bit in R, and one bit in S, for each of the two curves in use.
	ecdsa := hex(P256_HIGH_BIT_SIG)
	ecdsa[0] ~= 0x01
	testing.expect_value(
		t,
		verify_signature(ALG_ECDSAP256SHA256, hex(P256_HIGH_BIT_KEY), ecdsa, data, context.temp_allocator),
		Verify_Result.Bad,
	)

	ed := hex(ED25519_SIG)
	ed[63] ~= 0x01
	testing.expect_value(
		t,
		verify_signature(ALG_ED25519, hex(ED25519_KEY), ed, data, context.temp_allocator),
		Verify_Result.Bad,
	)

	rsa := hex(RSA_SIG)
	rsa[10] ~= 0x80
	testing.expect_value(
		t,
		verify_signature(ALG_RSASHA256, hex(RSA_KEY), rsa, data, context.temp_allocator),
		Verify_Result.Bad,
	)
	free_all(context.temp_allocator)
}

@(test)
test_a_key_or_signature_of_the_wrong_size_is_refused :: proc(t: ^testing.T) {
	/*
	The fixed-width formats have exactly one legal length each, and a key or
	signature of any other size is refused before OpenSSL is handed anything.
	Wrapping a short key into a SubjectPublicKeyInfo would build a structure
	whose declared length disagrees with its contents.
	*/
	data := hex(SIGNED_DATA)

	short_key := hex(P256_HIGH_BIT_KEY)[:63]
	testing.expect_value(
		t,
		verify_signature(ALG_ECDSAP256SHA256, short_key, hex(P256_HIGH_BIT_SIG), data, context.temp_allocator),
		Verify_Result.Bad,
	)
	short_sig := hex(P256_HIGH_BIT_SIG)[:63]
	testing.expect_value(
		t,
		verify_signature(ALG_ECDSAP256SHA256, hex(P256_HIGH_BIT_KEY), short_sig, data, context.temp_allocator),
		Verify_Result.Bad,
	)
	testing.expect_value(
		t,
		verify_signature(ALG_ED25519, hex(ED25519_KEY)[:31], hex(ED25519_SIG), data, context.temp_allocator),
		Verify_Result.Bad,
	)
	testing.expect_value(
		t,
		verify_signature(ALG_ED25519, hex(ED25519_KEY), hex(ED25519_SIG)[:63], data, context.temp_allocator),
		Verify_Result.Bad,
	)
	// An empty key, which is what a DNSKEY truncated to its header would give.
	testing.expect_value(
		t,
		verify_signature(ALG_RSASHA256, nil, hex(RSA_SIG), data, context.temp_allocator),
		Verify_Result.Bad,
	)
	free_all(context.temp_allocator)
}

@(test)
test_an_unsupported_algorithm_is_not_reported_as_a_forgery :: proc(t: ^testing.T) {
	/*
	The distinction the whole insecure-versus-bogus decision rests on. RFC 4035
	has a validator treat what it cannot check as unsigned rather than as
	forged, so an algorithm this build does not implement has to come back
	`Unsupported` and not `Bad` - otherwise a zone signing with something new
	would go dark for every client behind this server instead of degrading to
	insecure.
	*/
	data := hex(SIGNED_DATA)
	for algorithm in ([]u8{0, 1, 2, 3, 4, 6, 9, 11, 12, 17, 99, 253, 254, 255}) {
		result := verify_signature(algorithm, hex(P256_HIGH_BIT_KEY), hex(P256_HIGH_BIT_SIG), data, context.temp_allocator)
		testing.expectf(t, result == .Unsupported, "algorithm %d should be unsupported, got %v", algorithm, result)
		testing.expectf(t, !algorithm_supported(algorithm), "and the table should agree about %d", algorithm)
	}
	for algorithm in ([]u8{ALG_RSASHA1, ALG_RSASHA1_NSEC3, ALG_RSASHA256, ALG_RSASHA512, ALG_ECDSAP256SHA256, ALG_ECDSAP384SHA384, ALG_ED25519, ALG_ED448}) {
		testing.expectf(t, algorithm_supported(algorithm), "algorithm %d is implemented", algorithm)
	}
	free_all(context.temp_allocator)
}

@(test)
test_der_integers_are_signed_and_minimally_encoded :: proc(t: ^testing.T) {
	/*
	The rule underneath the two ECDSA vectors above, checked directly so a
	failure says which half is wrong.
	*/
	buf := make([dynamic]u8, context.temp_allocator)

	// Top bit clear: encoded as it stands.
	der_integer(&buf, []u8{0x7f, 0x01})
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x02, 0x7f, 0x01}) == 0, "a positive integer is encoded as it stands")

	// Top bit set: a zero byte goes in front, and the length grows with it.
	clear(&buf)
	der_integer(&buf, []u8{0x80, 0x01})
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x03, 0x00, 0x80, 0x01}) == 0, "a high bit needs a leading zero")

	// Redundant leading zeros are dropped.
	clear(&buf)
	der_integer(&buf, []u8{0x00, 0x00, 0x2a})
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x01, 0x2a}) == 0, "leading zeros are not encoded")

	// A zero that becomes high-bit-set once the padding is dropped keeps one.
	clear(&buf)
	der_integer(&buf, []u8{0x00, 0xff})
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x02, 0x00, 0xff}) == 0, "stripping must not make the value negative")

	// Zero itself is one byte.
	clear(&buf)
	der_integer(&buf, []u8{0x00, 0x00, 0x00})
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x01, 0x00}) == 0, "zero is a single zero octet")

	clear(&buf)
	der_integer(&buf, nil)
	testing.expect(t, mem.compare(buf[:], []u8{0x02, 0x01, 0x00}) == 0, "and so is nothing at all")
	free_all(context.temp_allocator)
}

@(test)
test_der_lengths_use_the_shortest_form :: proc(t: ^testing.T) {
	buf := make([dynamic]u8, context.temp_allocator)
	der_length(&buf, 0x7f)
	testing.expect(t, mem.compare(buf[:], []u8{0x7f}) == 0, "a short length is one byte")

	clear(&buf)
	der_length(&buf, 0x80)
	testing.expect(t, mem.compare(buf[:], []u8{0x81, 0x80}) == 0, "0x80 needs the long form")

	clear(&buf)
	der_length(&buf, 0x1234)
	testing.expect(t, mem.compare(buf[:], []u8{0x82, 0x12, 0x34}) == 0, "two bytes when it will not fit in one")

	clear(&buf)
	der_length(&buf, 0x12_3456)
	testing.expect(t, mem.compare(buf[:], []u8{0x83, 0x12, 0x34, 0x56}) == 0, "three when it will not fit in two")
	free_all(context.temp_allocator)
}

@(test)
test_ecdsa_signature_der_wraps_both_halves :: proc(t: ^testing.T) {
	// A signature is R and S back to back at a fixed width, and anything else
	// is not one.
	sig := []u8{0x80, 0x01, 0x7f, 0x02}
	der, ok := ecdsa_signature_der(sig, 2, context.temp_allocator)
	testing.expect(t, ok, "an even split should wrap")
	// SEQUENCE { INTEGER 00 80 01, INTEGER 7f 02 }
	testing.expect(
		t,
		mem.compare(der, []u8{0x30, 0x09, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x02, 0x7f, 0x02}) == 0,
		"the two halves become two DER integers in a sequence",
	)

	_, wrong := ecdsa_signature_der(sig, 3, context.temp_allocator)
	testing.expect(t, !wrong, "a signature that is not twice the half width is not one")
	_, empty := ecdsa_signature_der(nil, 32, context.temp_allocator)
	testing.expect(t, !empty, "and neither is nothing at all")
	free_all(context.temp_allocator)
}

@(test)
test_rsa_spki_refuses_an_impossible_exponent :: proc(t: ^testing.T) {
	/*
	RFC 3110's length field is attacker-controlled, and every way of lying about
	it has to be refused before the exponent and modulus are sliced out of the
	key.
	*/
	_, empty := rsa_spki(nil, context.temp_allocator)
	testing.expect(t, !empty, "an empty key has no exponent")

	// A one-byte form claiming zero, which escapes into the three-byte form,
	// which then also claims zero.
	_, zero := rsa_spki([]u8{0, 0, 0, 1, 2, 3}, context.temp_allocator)
	testing.expect(t, !zero, "an exponent of no bytes is not an exponent")

	// The three-byte form with nothing behind it.
	_, short := rsa_spki([]u8{0, 1}, context.temp_allocator)
	testing.expect(t, !short, "a three-byte length field must fit in the key")

	// An exponent length reaching past the end of the key, leaving no modulus.
	_, past := rsa_spki([]u8{4, 1, 2, 3}, context.temp_allocator)
	testing.expect(t, !past, "an exponent past the end of the key is refused")

	// Exactly consuming the key, so the modulus is empty.
	_, no_modulus := rsa_spki([]u8{3, 1, 0, 1}, context.temp_allocator)
	testing.expect(t, !no_modulus, "a key with no modulus is refused")

	// An exponent longer than anything real, which is the field being read as
	// one huge number rather than as a key.
	huge := make([]u8, 4096, context.temp_allocator)
	huge[0] = 0
	huge[1] = 0x0f
	huge[2] = 0xff
	_, oversized := rsa_spki(huge, context.temp_allocator)
	testing.expect(t, !oversized, "an exponent beyond the ceiling is refused")

	// The real key still wraps.
	_, good := rsa_spki(hex(RSA_KEY), context.temp_allocator)
	testing.expect(t, good, "a well-formed key wraps")
	free_all(context.temp_allocator)
}

@(test)
test_digest_tables_and_a_known_vector :: proc(t: ^testing.T) {
	testing.expect_value(t, digest_size(DIGEST_SHA1), 20)
	testing.expect_value(t, digest_size(DIGEST_SHA256), 32)
	testing.expect_value(t, digest_size(DIGEST_SHA384), 48)
	// Digest type 3 is GOST, withdrawn by RFC 6986 and not implemented here.
	testing.expect_value(t, digest_size(3), 0)
	testing.expect(t, !digest_supported(3), "GOST is not supported")
	testing.expect(t, !digest_supported(0), "nor is the reserved zero")
	testing.expect(t, digest_supported(DIGEST_SHA256), "SHA-256 is")

	// The empty string, hashed. Published everywhere, so a broken binding shows
	// up here rather than as a DS that will not match.
	out: [32]u8
	testing.expect(t, digest(DIGEST_SHA256, nil, out[:]), "SHA-256 of nothing should compute")
	want := hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	testing.expect(t, mem.compare(out[:], want) == 0, "SHA-256 of the empty string is a published number")

	// A buffer too small for the digest must be refused rather than half filled.
	small: [16]u8
	testing.expect(t, !digest(DIGEST_SHA256, nil, small[:]), "a short buffer cannot take a digest")
	testing.expect(t, !digest(99, nil, out[:]), "an unknown digest type computes nothing")
	free_all(context.temp_allocator)
}
