package dnssec

import "core:c"
import "core:mem"

/*
The cryptography DNSSEC needs, bound straight to libcrypto.

This is deliberately separate from `elodin:tlsx`, which binds libssl for the
DoT and DoH transports: nothing here has anything to do with TLS, and the two
would otherwise share a package for no better reason than both calling into
OpenSSL.

Public keys arrive in DNSKEY RDATA form, which is not a format OpenSSL parses.
Rather than assembling keys through the OSSL_PARAM interface, each key is
re-encoded as a DER SubjectPublicKeyInfo and handed to `d2i_PUBKEY`, which is
the one entry point that covers RSA, ECDSA and the Edwards curves alike.
*/

foreign import libcrypto "system:crypto"

EVP_MD :: struct {}
EVP_MD_CTX :: struct {}
EVP_PKEY :: struct {}

@(default_calling_convention = "c")
foreign libcrypto {
	EVP_sha1 :: proc() -> ^EVP_MD ---
	EVP_sha256 :: proc() -> ^EVP_MD ---
	EVP_sha384 :: proc() -> ^EVP_MD ---
	EVP_sha512 :: proc() -> ^EVP_MD ---

	EVP_Digest :: proc(data: rawptr, count: c.size_t, md: [^]u8, size: ^c.uint, type: ^EVP_MD, impl: rawptr) -> c.int ---

	EVP_MD_CTX_new :: proc() -> ^EVP_MD_CTX ---
	EVP_MD_CTX_free :: proc(ctx: ^EVP_MD_CTX) ---
	EVP_DigestVerifyInit :: proc(ctx: ^EVP_MD_CTX, pctx: rawptr, type: ^EVP_MD, e: rawptr, pkey: ^EVP_PKEY) -> c.int ---
	EVP_DigestVerify :: proc(ctx: ^EVP_MD_CTX, sig: [^]u8, siglen: c.size_t, tbs: [^]u8, tbslen: c.size_t) -> c.int ---

	EVP_PKEY_free :: proc(pkey: ^EVP_PKEY) ---
	d2i_PUBKEY :: proc(a: ^^EVP_PKEY, pp: ^[^]u8, length: c.long) -> ^EVP_PKEY ---

	ERR_clear_error :: proc() ---
}

Verify_Result :: enum u8 {
	// The signature is good.
	Ok,
	// The signature does not match, or the key is malformed.
	Bad,
	/*
	The algorithm is one we cannot check at all.

	Distinct from `Bad` on purpose: RFC 4035 has a validator treat data it
	cannot check as unsigned rather than as forged, so a zone that has moved to
	an algorithm we do not know becomes insecure instead of bogus. Distribution
	crypto policy lands here too — Fedora and RHEL ship an OpenSSL that refuses
	SHA-1 signatures outright, which takes algorithms 5 and 7 with it.
	*/
	Unsupported,
}

// A modulus larger than this is not a key anyone is using, and refusing it early
// keeps a hostile DNSKEY from turning into a large allocation and a slow verify.
MAX_MODULUS_BYTES :: 1024

// RFC 3110 allows three bytes of exponent length, so a DNSKEY may claim 64 KB of
// exponent. Real ones are three bytes; this leaves room to spare and keeps the
// rest of the field from being read as one.
MAX_EXPONENT_BYTES :: 512

algorithm_supported :: proc "contextless" (algorithm: u8) -> bool {
	switch algorithm {
	case ALG_RSASHA1, ALG_RSASHA1_NSEC3, ALG_RSASHA256, ALG_RSASHA512:
		return true
	case ALG_ECDSAP256SHA256, ALG_ECDSAP384SHA384, ALG_ED25519, ALG_ED448:
		return true
	}
	return false
}

digest_supported :: proc "contextless" (digest_type: u8) -> bool {
	switch digest_type {
	case DIGEST_SHA1, DIGEST_SHA256, DIGEST_SHA384:
		return true
	}
	return false
}

digest_size :: proc "contextless" (digest_type: u8) -> int {
	switch digest_type {
	case DIGEST_SHA1:
		return 20
	case DIGEST_SHA256:
		return 32
	case DIGEST_SHA384:
		return 48
	}
	return 0
}

/*
Hash `data` into `out`, which must hold `digest_size(digest_type)` bytes.

Used for DS digests and, with SHA-1, for the iterated NSEC3 hash.
*/
digest :: proc(digest_type: u8, data: []u8, out: []u8) -> bool {
	md: ^EVP_MD
	switch digest_type {
	case DIGEST_SHA1:
		md = EVP_sha1()
	case DIGEST_SHA256:
		md = EVP_sha256()
	case DIGEST_SHA384:
		md = EVP_sha384()
	case:
		return false
	}
	if md == nil || len(out) < digest_size(digest_type) {
		return false
	}
	size: c.uint
	ERR_clear_error()
	return EVP_Digest(raw_data(data), c.size_t(len(data)), raw_data(out), &size, md, nil) == 1
}

/*
Check one DNSSEC signature.

`public_key` is the DNSKEY RDATA's public key field and `signature` the RRSIG's,
both exactly as they appear on the wire; `data` is the canonical signing input.
*/
verify_signature :: proc(
	algorithm: u8,
	public_key: []u8,
	signature: []u8,
	data: []u8,
	allocator := context.temp_allocator,
) -> Verify_Result {
	spki: []u8
	sig := signature
	md: ^EVP_MD
	ok: bool

	switch algorithm {
	case ALG_RSASHA1, ALG_RSASHA1_NSEC3:
		md = EVP_sha1()
		spki, ok = rsa_spki(public_key, allocator)
	case ALG_RSASHA256:
		md = EVP_sha256()
		spki, ok = rsa_spki(public_key, allocator)
	case ALG_RSASHA512:
		md = EVP_sha512()
		spki, ok = rsa_spki(public_key, allocator)

	case ALG_ECDSAP256SHA256:
		md = EVP_sha256()
		spki, ok = ec_spki(public_key, EC_P256_PREFIX, 64, allocator)
		if ok {
			sig, ok = ecdsa_signature_der(signature, 32, allocator)
		}
	case ALG_ECDSAP384SHA384:
		md = EVP_sha384()
		spki, ok = ec_spki(public_key, EC_P384_PREFIX, 96, allocator)
		if ok {
			sig, ok = ecdsa_signature_der(signature, 48, allocator)
		}

	// The Edwards curves hash internally, so no digest is named at init time.
	case ALG_ED25519:
		spki, ok = ec_spki(public_key, ED25519_PREFIX, 32, allocator)
		ok = ok && len(signature) == 64
	case ALG_ED448:
		spki, ok = ec_spki(public_key, ED448_PREFIX, 57, allocator)
		ok = ok && len(signature) == 114

	case:
		return .Unsupported
	}

	if !ok {
		return .Bad
	}

	ERR_clear_error()
	der := raw_data(spki)
	pkey := d2i_PUBKEY(nil, &der, c.long(len(spki)))
	if pkey == nil {
		return .Bad
	}
	defer EVP_PKEY_free(pkey)

	ctx := EVP_MD_CTX_new()
	if ctx == nil {
		return .Unsupported
	}
	defer EVP_MD_CTX_free(ctx)

	// A refusal here is a policy decision about the algorithm rather than a
	// verdict on this signature, so it must not be reported as a forgery.
	if EVP_DigestVerifyInit(ctx, nil, md, nil, pkey) != 1 {
		return .Unsupported
	}
	if EVP_DigestVerify(ctx, raw_data(sig), c.size_t(len(sig)), raw_data(data), c.size_t(len(data))) != 1 {
		return .Bad
	}
	return .Ok
}

// SubjectPublicKeyInfo prefixes for the fixed-size key formats: the algorithm
// identifier and the BIT STRING header, up to the point the raw key begins.
@(private)
EC_P256_PREFIX := []u8 {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
}

@(private)
EC_P384_PREFIX := []u8 {
	0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
}

@(private)
ED25519_PREFIX := []u8{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

@(private)
ED448_PREFIX := []u8{0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00}

@(private)
ec_spki :: proc(key: []u8, prefix: []u8, key_len: int, allocator: mem.Allocator) -> ([]u8, bool) {
	if len(key) != key_len {
		return nil, false
	}
	out := make([]u8, len(prefix) + key_len, allocator)
	copy(out, prefix)
	copy(out[len(prefix):], key)
	return out, true
}

/*
Wrap an RFC 3110 RSA public key as a DER SubjectPublicKeyInfo.

The DNSKEY form is a one- or three-byte exponent length, the exponent, then the
modulus running to the end of the field.
*/
@(private)
rsa_spki :: proc(key: []u8, allocator: mem.Allocator) -> ([]u8, bool) {
	if len(key) < 1 {
		return nil, false
	}
	explen := int(key[0])
	off := 1
	if explen == 0 {
		if len(key) < 3 {
			return nil, false
		}
		explen = int(key[1]) << 8 | int(key[2])
		off = 3
	}
	if explen == 0 || explen > MAX_EXPONENT_BYTES || off + explen >= len(key) {
		return nil, false
	}
	exponent := key[off:off + explen]
	modulus := key[off + explen:]
	if len(modulus) == 0 || len(modulus) > MAX_MODULUS_BYTES {
		return nil, false
	}

	body := make([dynamic]u8, 0, len(key) + 32, allocator)
	der_integer(&body, modulus)
	der_integer(&body, exponent)

	rsa_key := make([dynamic]u8, 0, len(body) + 8, allocator)
	der_tagged(&rsa_key, 0x30, body[:])

	// AlgorithmIdentifier { OID 1.2.840.113549.1.1.1, NULL }
	ALG_ID := []u8 {
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
	}
	bits := make([dynamic]u8, 0, len(rsa_key) + 1, allocator)
	append(&bits, 0) // no unused bits
	append(&bits, ..rsa_key[:])

	inner := make([dynamic]u8, 0, len(bits) + 24, allocator)
	append(&inner, ..ALG_ID)
	der_tagged(&inner, 0x03, bits[:])

	out := make([dynamic]u8, 0, len(inner) + 8, allocator)
	der_tagged(&out, 0x30, inner[:])
	return out[:], true
}

/*
Convert a DNSSEC ECDSA signature to the DER form OpenSSL expects.

RFC 6605 puts R and S on the wire as fixed-width integers back to back; the
verifier wants SEQUENCE { INTEGER r, INTEGER s }.
*/
@(private)
ecdsa_signature_der :: proc(sig: []u8, half: int, allocator: mem.Allocator) -> ([]u8, bool) {
	if len(sig) != half * 2 {
		return nil, false
	}
	body := make([dynamic]u8, 0, len(sig) + 8, allocator)
	der_integer(&body, sig[:half])
	der_integer(&body, sig[half:])

	out := make([dynamic]u8, 0, len(body) + 8, allocator)
	der_tagged(&out, 0x30, body[:])
	return out[:], true
}

@(private)
der_length :: proc(buf: ^[dynamic]u8, n: int) {
	switch {
	case n < 0x80:
		append(buf, u8(n))
	case n < 0x100:
		append(buf, 0x81, u8(n))
	case n < 0x1_0000:
		append(buf, 0x82, u8(n >> 8), u8(n))
	case:
		// Nothing built here comes near this, but a silently truncated length
		// would produce DER that says one thing and holds another.
		append(buf, 0x83, u8(n >> 16), u8(n >> 8), u8(n))
	}
}

@(private)
der_tagged :: proc(buf: ^[dynamic]u8, tag: u8, content: []u8) {
	append(buf, tag)
	der_length(buf, len(content))
	append(buf, ..content)
}

// DER integers are signed, so a leading zero byte is added when the top bit of
// the first octet is set, and redundant leading zeros are dropped first.
@(private)
der_integer :: proc(buf: ^[dynamic]u8, value: []u8) {
	i := 0
	for i + 1 < len(value) && value[i] == 0 {
		i += 1
	}
	body := value[i:]
	if len(body) == 0 {
		append(buf, 0x02, 0x01, 0x00)
		return
	}
	append(buf, 0x02)
	if body[0] & 0x80 != 0 {
		der_length(buf, len(body) + 1)
		append(buf, 0)
	} else {
		der_length(buf, len(body))
	}
	append(buf, ..body)
}
