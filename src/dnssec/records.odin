package dnssec

import "core:mem"
import "elodin:dns"

// Signing algorithms (IANA "DNS Security Algorithm Numbers").
ALG_RSASHA1 :: 5
ALG_RSASHA1_NSEC3 :: 7
ALG_RSASHA256 :: 8
ALG_RSASHA512 :: 10
ALG_ECDSAP256SHA256 :: 13
ALG_ECDSAP384SHA384 :: 14
ALG_ED25519 :: 15
ALG_ED448 :: 16

// DS digest algorithms.
DIGEST_SHA1 :: 1
DIGEST_SHA256 :: 2
DIGEST_SHA384 :: 4

// The only NSEC3 hash defined, and the only one likely ever to be.
NSEC3_HASH_SHA1 :: 1

DNSKEY_FLAG_ZONE :: 0x0100
DNSKEY_FLAG_REVOKE :: 0x0080
DNSKEY_FLAG_SEP :: 0x0001

NSEC3_FLAG_OPT_OUT :: 0x01

// A name cannot carry more labels than this, so nothing that walks labels needs
// to allocate.
MAX_LABELS :: 128

Parse_Error :: enum u8 {
	None,
	Short_Rdata,
	Bad_Name,
	Bad_Rdata,
}

Rrsig :: struct {
	type_covered: dns.Type,
	algorithm:    u8,
	labels:       u8,
	original_ttl: u32,
	expiration:   u32,
	inception:    u32,
	key_tag:      u16,
	signer:       string,
	signature:    []u8,
}

Dnskey :: struct {
	flags:      u16,
	protocol:   u8,
	algorithm:  u8,
	public_key: []u8,
	// The whole RDATA, which is what both the key tag and the DS digest run over.
	rdata:      []u8,
	tag:        u16,
}

Ds :: struct {
	key_tag:     u16,
	algorithm:   u8,
	digest_type: u8,
	digest:      []u8,
}

Nsec :: struct {
	next:  string,
	types: []u8,
}

Nsec3 :: struct {
	hash_algorithm: u8,
	flags:          u8,
	iterations:     u16,
	salt:           []u8,
	next_hash:      []u8,
	types:          []u8,
}

@(private)
Rd :: struct {
	buf: []u8,
	pos: int,
}

@(private)
rd_u8 :: proc(r: ^Rd) -> (v: u8, err: Parse_Error) {
	if r.pos + 1 > len(r.buf) {
		return 0, .Short_Rdata
	}
	v = r.buf[r.pos]
	r.pos += 1
	return
}

@(private)
rd_u16 :: proc(r: ^Rd) -> (v: u16, err: Parse_Error) {
	if r.pos + 2 > len(r.buf) {
		return 0, .Short_Rdata
	}
	v = u16(r.buf[r.pos]) << 8 | u16(r.buf[r.pos + 1])
	r.pos += 2
	return
}

@(private)
rd_u32 :: proc(r: ^Rd) -> (v: u32, err: Parse_Error) {
	if r.pos + 4 > len(r.buf) {
		return 0, .Short_Rdata
	}
	v =
		u32(r.buf[r.pos]) << 24 |
		u32(r.buf[r.pos + 1]) << 16 |
		u32(r.buf[r.pos + 2]) << 8 |
		u32(r.buf[r.pos + 3])
	r.pos += 4
	return
}

@(private)
rd_bytes :: proc(r: ^Rd, n: int) -> (v: []u8, err: Parse_Error) {
	if n < 0 || r.pos + n > len(r.buf) {
		return nil, .Short_Rdata
	}
	v = r.buf[r.pos:r.pos + n]
	r.pos += n
	return
}

/*
Read a domain name out of RDATA.

Compression is rejected rather than followed. RFC 4034 requires the names inside
DNSSEC RDATA to be uncompressed precisely so that everyone canonicalises them
the same way, and the decoded record hands us a copy of the RDATA with no
message left to point into.
*/
@(private)
rd_name :: proc(r: ^Rd, allocator: mem.Allocator) -> (name: string, err: Parse_Error) {
	pos := r.pos
	for {
		if pos >= len(r.buf) {
			return "", .Short_Rdata
		}
		l := r.buf[pos]
		if l & 0xc0 != 0 {
			return "", .Bad_Name
		}
		if l == 0 {
			pos += 1
			break
		}
		pos += 1 + int(l)
	}

	decoded, _, derr := dns.decode_name(r.buf[r.pos:pos], 0, allocator)
	if derr != .None {
		return "", .Bad_Name
	}
	r.pos = pos
	return decoded, .None
}

// The RDATA of a record the codec did not model natively, which is where every
// DNSSEC type lands.
raw_rdata :: proc(rec: dns.Record) -> (data: []u8, ok: bool) {
	v, is_raw := rec.data.(dns.Rdata_Raw)
	if !is_raw {
		return nil, false
	}
	return v.data, true
}

parse_rrsig :: proc(rdata: []u8, allocator := context.allocator) -> (sig: Rrsig, err: Parse_Error) {
	r := Rd{buf = rdata}
	sig.type_covered = dns.Type(rd_u16(&r) or_return)
	sig.algorithm = rd_u8(&r) or_return
	sig.labels = rd_u8(&r) or_return
	sig.original_ttl = rd_u32(&r) or_return
	sig.expiration = rd_u32(&r) or_return
	sig.inception = rd_u32(&r) or_return
	sig.key_tag = rd_u16(&r) or_return
	sig.signer = rd_name(&r, allocator) or_return
	sig.signature = rdata[r.pos:]
	if len(sig.signature) == 0 {
		return {}, .Short_Rdata
	}
	return
}

parse_dnskey :: proc(rdata: []u8) -> (key: Dnskey, err: Parse_Error) {
	r := Rd{buf = rdata}
	key.flags = rd_u16(&r) or_return
	key.protocol = rd_u8(&r) or_return
	key.algorithm = rd_u8(&r) or_return
	key.public_key = rdata[r.pos:]
	if len(key.public_key) == 0 {
		return {}, .Short_Rdata
	}
	key.rdata = rdata
	key.tag = key_tag(rdata)
	return
}

parse_ds :: proc(rdata: []u8) -> (ds: Ds, err: Parse_Error) {
	r := Rd{buf = rdata}
	ds.key_tag = rd_u16(&r) or_return
	ds.algorithm = rd_u8(&r) or_return
	ds.digest_type = rd_u8(&r) or_return
	ds.digest = rdata[r.pos:]
	if len(ds.digest) == 0 {
		return {}, .Short_Rdata
	}
	return
}

parse_nsec :: proc(rdata: []u8, allocator := context.allocator) -> (n: Nsec, err: Parse_Error) {
	r := Rd{buf = rdata}
	n.next = rd_name(&r, allocator) or_return
	n.types = rdata[r.pos:]
	return
}

parse_nsec3 :: proc(rdata: []u8) -> (n: Nsec3, err: Parse_Error) {
	r := Rd{buf = rdata}
	n.hash_algorithm = rd_u8(&r) or_return
	n.flags = rd_u8(&r) or_return
	n.iterations = rd_u16(&r) or_return
	salt_len := int(rd_u8(&r) or_return)
	n.salt = rd_bytes(&r, salt_len) or_return
	hash_len := int(rd_u8(&r) or_return)
	if hash_len == 0 {
		return {}, .Bad_Rdata
	}
	n.next_hash = rd_bytes(&r, hash_len) or_return
	n.types = rdata[r.pos:]
	return
}

/*
The DNSKEY key tag, RFC 4034 appendix B.

A fold of the RDATA into 16 bits. It is an index, not a checksum: two keys in a
zone may share a tag, so every key with a matching tag has to be tried.
*/
key_tag :: proc "contextless" (rdata: []u8) -> u16 {
	ac: u32
	for b, i in rdata {
		ac += (u32(b) << 8) if i & 1 == 0 else u32(b)
	}
	ac += (ac >> 16) & 0xffff
	return u16(ac & 0xffff)
}

// Whether a key may sign zone data at all: the zone bit set, the protocol field
// at its fixed value, and not revoked (RFC 5011).
key_usable :: proc "contextless" (key: Dnskey) -> bool {
	if key.flags & DNSKEY_FLAG_ZONE == 0 {
		return false
	}
	if key.flags & DNSKEY_FLAG_REVOKE != 0 {
		return false
	}
	return key.protocol == 3
}

/*
Is type `t` present in an NSEC or NSEC3 type bit map?

The map is a sequence of windows, each a window number, a length and that many
bytes of bits with the most significant bit first.
*/
bitmap_has :: proc "contextless" (bitmap: []u8, t: dns.Type) -> bool {
	window := u8(u16(t) >> 8)
	bit := int(u16(t) & 0xff)
	pos := 0
	for pos + 2 <= len(bitmap) {
		w := bitmap[pos]
		length := int(bitmap[pos + 1])
		pos += 2
		if length == 0 || length > 32 || pos + length > len(bitmap) {
			return false
		}
		if w == window {
			index := bit / 8
			if index >= length {
				return false
			}
			return bitmap[pos + index] & (0x80 >> u8(bit % 8)) != 0
		}
		pos += length
	}
	return false
}

/*
Serial-number comparison, RFC 1982.

RRSIG timestamps are seconds since the epoch in 32 bits, compared in a space
that wraps, so `a >= b` is a signed comparison of the difference rather than of
the values.
*/
@(private)
serial_ge :: proc "contextless" (a, b: u32) -> bool {
	return i32(a - b) >= 0
}

/*
How far ahead of this server's clock a signature's inception may be.

RFC 4035 section 5.3.1 judges both ends against "the validator's notion of the
current time", and a signer whose clock runs ahead of ours mints signatures
whose inception is in our future. Unbound allows an hour or more either side,
PowerDNS Recursor a minute on the inception only, BIND and Knot Resolver none.
Only the inception gets it here: a signature accepted before it starts is one
its signer published early, while one accepted after it lapses is a replay
window for a signature the zone has withdrawn. An hour is Unbound's floor.
*/
SIG_INCEPTION_SKEW :: 3600

// Where `now` falls against a signature's validity period.
Sig_Window :: enum u8 {
	Current,
	Expired,
	Not_Yet_Valid,
}

// Which side of its validity period `now` is on, inception skew allowed.
signature_window :: proc "contextless" (sig: Rrsig, now: u32) -> Sig_Window {
	switch {
	case !serial_ge(now + SIG_INCEPTION_SKEW, sig.inception):
		return .Not_Yet_Valid
	case !serial_ge(sig.expiration, now):
		return .Expired
	// The skew must not admit a window that ends before it starts. `now` is
	// then inside the skew, short of the inception itself.
	case !serial_ge(sig.expiration, sig.inception):
		return .Not_Yet_Valid
	}
	return .Current
}

// Is `now` inside the signature's validity period, inception skew allowed?
signature_current :: proc "contextless" (sig: Rrsig, now: u32) -> bool {
	return signature_window(sig, now) == .Current
}

/*
The longest an RRset this signature verified may be served or kept for.

RFC 4035 section 5.3.3: no longer than the Original TTL the signer set, nor past
the signature's expiration. The TTL fields beside the records are unsigned, so
these two are the only ones a forger cannot raise. Assumes `signature_current`.
*/
signed_ttl_ceiling :: proc "contextless" (sig: Rrsig, now: u32) -> u32 {
	return min(sig.original_ttl, sig_lapses(sig, now))
}

// Seconds before a signature `signature_current` accepted stops verifying.
sig_lapses :: proc "contextless" (sig: Rrsig, now: u32) -> u32 {
	return sig.expiration - now
}
