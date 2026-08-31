package dnssec

import "core:testing"
import "elodin:dns"

/*
The RDATA readers, the key flags and the clock.

Everything in this file runs on bytes an attacker chose. A DNSSEC record arrives
inside an answer from an upstream that may be lying, may be a machine on the
path, or may simply be broken, and the parsers here are the first code to touch
it. Their job is to refuse rather than to guess: a truncated record must fail,
never read past its end, and never come back holding a slice of somebody else's
memory.

The prefix sweeps below are the shape a fuzzer would find, written down so they
run every time. Each takes a well-formed record and hands the parser every
truncation of it, checking that nothing crashes and that anything short of a
complete fixed header is refused outright.
*/

// "example." on the wire.
@(private = "file")
EXAMPLE_WIRE := []u8{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}

@(private = "file")
sample_rrsig :: proc() -> []u8 {
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, 0, 1) // type covered: A
	append(&out, ALG_ECDSAP256SHA256)
	append(&out, 2) // labels
	append(&out, 0, 0, 0x0e, 0x10) // original TTL 3600
	append(&out, 0x6a, 0, 0, 0) // expiration
	append(&out, 0x69, 0, 0, 0) // inception
	append(&out, 0x12, 0x34) // key tag
	append(&out, ..EXAMPLE_WIRE)
	for i in 0 ..< 64 {
		append(&out, u8(i))
	}
	return out[:]
}

@(private = "file")
sample_dnskey :: proc() -> []u8 {
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, 0x01, 0x00) // flags: zone key
	append(&out, 3) // protocol
	append(&out, ALG_ECDSAP256SHA256)
	for i in 0 ..< 64 {
		append(&out, u8(i))
	}
	return out[:]
}

@(private = "file")
sample_ds :: proc() -> []u8 {
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, 0x12, 0x34) // key tag
	append(&out, ALG_ECDSAP256SHA256)
	append(&out, DIGEST_SHA256)
	for i in 0 ..< 32 {
		append(&out, u8(i))
	}
	return out[:]
}

@(private = "file")
sample_nsec3 :: proc() -> []u8 {
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, NSEC3_HASH_SHA1)
	append(&out, 0) // flags
	append(&out, 0, 12) // iterations
	append(&out, 4, 0xaa, 0xbb, 0xcc, 0xdd) // salt
	append(&out, 20) // next hash length
	for i in 0 ..< 20 {
		append(&out, u8(i))
	}
	append(&out, 0, 1, 0x40) // type bit map: A
	return out[:]
}

@(test)
test_rrsig_parses_and_refuses_every_short_header :: proc(t: ^testing.T) {
	full := sample_rrsig()
	sig, err := parse_rrsig(full, context.temp_allocator)
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, sig.type_covered, dns.Type.A)
	testing.expect_value(t, sig.algorithm, u8(ALG_ECDSAP256SHA256))
	testing.expect_value(t, sig.labels, u8(2))
	testing.expect_value(t, sig.original_ttl, u32(3600))
	testing.expect_value(t, sig.key_tag, u16(0x1234))
	testing.expect_value(t, sig.signer, "example.")
	testing.expect_value(t, len(sig.signature), 64)

	// The fixed header is 18 bytes, then the signer name, then at least one byte
	// of signature. Anything less has to be refused: an RRSIG with no signature
	// in it is not a signature, and treating the empty tail as one would hand
	// `verify_signature` a zero-length string to check.
	header := 18 + len(EXAMPLE_WIRE)
	for n in 0 ..= header {
		_, short := parse_rrsig(full[:n], context.temp_allocator)
		testing.expectf(t, short != .None, "a %d-byte RRSIG should not parse", n)
	}
	free_all(context.temp_allocator)
}

@(test)
test_rrsig_refuses_a_compressed_signer_name :: proc(t: ^testing.T) {
	/*
	RFC 4034 forbids compression inside DNSSEC RDATA, because everyone has to
	canonicalise the same bytes. By the time the RDATA reaches here the message
	it might have pointed into is gone, so a pointer cannot be followed even if
	we wanted to - and following one would mean signing over whatever it landed
	on.
	*/
	full := sample_rrsig()
	compressed := make([dynamic]u8, context.temp_allocator)
	append(&compressed, ..full[:18])
	append(&compressed, 0xc0, 0x0c) // a pointer where the signer name belongs
	append(&compressed, ..full[18 + len(EXAMPLE_WIRE):])
	_, err := parse_rrsig(compressed[:], context.temp_allocator)
	testing.expect_value(t, err, Parse_Error.Bad_Name)
	free_all(context.temp_allocator)
}

@(test)
test_dnskey_parses_and_refuses_a_key_of_no_bytes :: proc(t: ^testing.T) {
	full := sample_dnskey()
	key, err := parse_dnskey(full)
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, key.flags, u16(DNSKEY_FLAG_ZONE))
	testing.expect_value(t, key.protocol, u8(3))
	testing.expect_value(t, key.algorithm, u8(ALG_ECDSAP256SHA256))
	testing.expect_value(t, len(key.public_key), 64)
	testing.expect_value(t, key.tag, key_tag(full))

	for n in 0 ..= 4 {
		_, short := parse_dnskey(full[:n])
		testing.expectf(t, short != .None, "a %d-byte DNSKEY should not parse", n)
	}
	free_all(context.temp_allocator)
}

@(test)
test_ds_parses_and_refuses_a_digest_of_no_bytes :: proc(t: ^testing.T) {
	full := sample_ds()
	ds, err := parse_ds(full)
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, ds.key_tag, u16(0x1234))
	testing.expect_value(t, ds.digest_type, u8(DIGEST_SHA256))
	testing.expect_value(t, len(ds.digest), 32)

	for n in 0 ..= 4 {
		_, short := parse_ds(full[:n])
		testing.expectf(t, short != .None, "a %d-byte DS should not parse", n)
	}
	free_all(context.temp_allocator)
}

@(test)
test_nsec_parses_and_refuses_a_broken_next_name :: proc(t: ^testing.T) {
	rdata := make([dynamic]u8, context.temp_allocator)
	append(&rdata, ..EXAMPLE_WIRE)
	append(&rdata, 0, 1, 0x40) // type bit map: A

	n, err := parse_nsec(rdata[:], context.temp_allocator)
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, n.next, "example.")
	testing.expect(t, bitmap_has(n.types, .A), "the bit map should survive the parse")

	// A name whose last label runs off the end of the RDATA.
	truncated := []u8{7, 'e', 'x', 'a'}
	_, short := parse_nsec(truncated, context.temp_allocator)
	testing.expect_value(t, short, Parse_Error.Short_Rdata)

	// And a compressed one, which RFC 4034 forbids here as it does in RRSIG.
	_, compressed := parse_nsec([]u8{0xc0, 0x0c}, context.temp_allocator)
	testing.expect_value(t, compressed, Parse_Error.Bad_Name)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_parses_and_refuses_lengths_that_run_off_the_end :: proc(t: ^testing.T) {
	full := sample_nsec3()
	n, err := parse_nsec3(full)
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, n.hash_algorithm, u8(NSEC3_HASH_SHA1))
	testing.expect_value(t, n.iterations, u16(12))
	testing.expect_value(t, len(n.salt), 4)
	testing.expect_value(t, len(n.next_hash), 20)
	testing.expect(t, bitmap_has(n.types, .A), "the bit map should survive the parse")

	// A salt length longer than the record.
	lying_salt := []u8{NSEC3_HASH_SHA1, 0, 0, 12, 200, 0xaa, 0xbb}
	_, salt_err := parse_nsec3(lying_salt)
	testing.expect_value(t, salt_err, Parse_Error.Short_Rdata)

	// A next-hash length longer than the record.
	lying_hash := []u8{NSEC3_HASH_SHA1, 0, 0, 12, 0, 200, 0x01}
	_, hash_err := parse_nsec3(lying_hash)
	testing.expect_value(t, hash_err, Parse_Error.Short_Rdata)

	// A next hash of nothing at all, which would describe a span with no end.
	empty_hash := []u8{NSEC3_HASH_SHA1, 0, 0, 12, 0, 0}
	_, empty_err := parse_nsec3(empty_hash)
	testing.expect_value(t, empty_err, Parse_Error.Bad_Rdata)

	/*
	The fixed part runs to the end of the next hash, 30 bytes here. Every
	truncation of that must be refused. Past it the type bit map begins, and an
	NSEC3 with no types at all is legal - it is what an empty non-terminal
	publishes - so those prefixes parse. A bit map left half-written by the
	truncation is not rejected here but read as carrying nothing, which
	`bitmap_has` does without walking off the end.
	*/
	fixed := 30
	for n in 0 ..< fixed {
		_, short := parse_nsec3(full[:n])
		testing.expectf(t, short != .None, "a %d-byte NSEC3 should not parse", n)
	}
	for n in fixed ..= len(full) {
		partial, ok := parse_nsec3(full[:n])
		testing.expectf(t, ok == .None, "a %d-byte NSEC3 carries a whole fixed header", n)
		testing.expectf(t, len(partial.next_hash) == 20, "and a whole next hash at %d bytes", n)
		// Whatever is left of the bit map, reading it must stay in bounds.
		_ = bitmap_has(partial.types, .A)
	}
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_accepts_the_empty_salt :: proc(t: ^testing.T) {
	// RFC 9276 asks zones for no salt and no iterations, so the shape the
	// current advice produces is the one that must not be mistaken for
	// truncation.
	rdata := []u8{NSEC3_HASH_SHA1, 0, 0, 0, 0, 20}
	full := make([dynamic]u8, context.temp_allocator)
	append(&full, ..rdata)
	for i in 0 ..< 20 {
		append(&full, u8(i))
	}
	n, err := parse_nsec3(full[:])
	testing.expect_value(t, err, Parse_Error.None)
	testing.expect_value(t, len(n.salt), 0)
	testing.expect_value(t, n.iterations, u16(0))

	out: [20]u8
	testing.expect(t, nsec3_hash("example.", n.salt, n.iterations, out[:]), "an unsalted name still hashes")
	free_all(context.temp_allocator)
}

@(test)
test_key_usable_refuses_a_revoked_or_non_zone_key :: proc(t: ^testing.T) {
	/*
	RFC 4034 section 2.1.1 and RFC 5011 section 2.1. A key without the zone bit
	is not for signing zone data, a revoked key has been publicly withdrawn by
	its owner, and the protocol field has one legal value. Accepting any of them
	would let a key that is not allowed to sign this zone's records be used to
	verify them - and in the revoked case, would undo a key rollover the operator
	performed on purpose after a compromise.
	*/
	base := Dnskey {
		flags     = DNSKEY_FLAG_ZONE,
		protocol  = 3,
		algorithm = ALG_ECDSAP256SHA256,
	}
	testing.expect(t, key_usable(base), "an ordinary zone key is usable")

	sep := base
	sep.flags |= DNSKEY_FLAG_SEP
	testing.expect(t, key_usable(sep), "the secure-entry-point bit does not stop a key signing")

	revoked := base
	revoked.flags |= DNSKEY_FLAG_REVOKE
	testing.expect(t, !key_usable(revoked), "a revoked key must not verify anything")

	not_a_zone_key := base
	not_a_zone_key.flags &~= u16(DNSKEY_FLAG_ZONE)
	testing.expect(t, !key_usable(not_a_zone_key), "a key without the zone bit must not sign zone data")

	wrong_protocol := base
	wrong_protocol.protocol = 4
	testing.expect(t, !key_usable(wrong_protocol), "the protocol field has exactly one legal value")
	free_all(context.temp_allocator)
}

@(test)
test_bitmap_spans_several_windows_and_refuses_a_malformed_one :: proc(t: ^testing.T) {
	/*
	A type bit map is a run of windows, each numbered, and a type only counts if
	its own window is present. Reading a length field without bounding it is how
	a bit map walks off the end of the record it came in.
	*/

	// Window 0 carrying A (type 1), then window 1 carrying type 257: window
	// number 1, bit 1, so the same 0x40 one byte in.
	bitmap := []u8{0, 1, 0x40, 1, 1, 0x40}
	testing.expect(t, bitmap_has(bitmap, .A), "A sits in window 0")
	testing.expect(t, !bitmap_has(bitmap, .NS), "NS does not")
	testing.expect(t, bitmap_has(bitmap, dns.Type(257)), "type 257 sits in window 1")
	testing.expect(t, !bitmap_has(bitmap, dns.Type(256)), "type 256 does not")
	// A window this map does not carry at all.
	testing.expect(t, !bitmap_has(bitmap, dns.Type(700)), "an absent window means the type is absent")

	// A window claiming more bytes than the record holds.
	testing.expect(t, !bitmap_has([]u8{0, 32, 0x40}, .A), "a length past the end must not be read")
	// A window claiming more than the 32 bytes a window can hold.
	testing.expect(t, !bitmap_has([]u8{0, 33, 0x40}, .A), "a window cannot exceed 32 bytes")
	// A window of no bytes at all.
	testing.expect(t, !bitmap_has([]u8{0, 0}, .A), "an empty window carries nothing")
	// A header with no room for its own length byte.
	testing.expect(t, !bitmap_has([]u8{0}, .A), "a truncated header carries nothing")
	testing.expect(t, !bitmap_has(nil, .A), "an absent bit map carries nothing")
	free_all(context.temp_allocator)
}

@(test)
test_signature_validity_is_compared_in_the_wrapping_space :: proc(t: ^testing.T) {
	/*
	RRSIG timestamps are seconds since the epoch in 32 bits, and RFC 4034
	section 3.1.5 compares them with the serial arithmetic of RFC 1982 rather
	than as plain integers. That matters twice: at the boundaries, where a
	signature is valid on the inception and expiration seconds themselves, and
	in 2106, when the counter wraps and a signature whose window straddles the
	wrap has an expiration numerically smaller than its inception.
	*/
	sig := Rrsig {
		inception  = 1000,
		expiration = 2000,
	}
	testing.expect(t, signature_current(sig, 1500), "the middle of the window is current")
	testing.expect(t, signature_current(sig, 1000), "the inception second itself is current")
	testing.expect(t, signature_current(sig, 2000), "the expiration second itself is current")
	testing.expect(t, !signature_current(sig, 999), "a second before inception is not yet current")
	testing.expect(t, !signature_current(sig, 2001), "a second after expiration has lapsed")

	// A window that straddles the wrap: inception near the top of the counter,
	// expiration just past it.
	wrapping := Rrsig {
		inception  = 0xffff_ff00,
		expiration = 100,
	}
	testing.expect(t, signature_current(wrapping, 0xffff_ff80), "before the wrap is inside the window")
	testing.expect(t, signature_current(wrapping, 0), "the wrap itself is inside the window")
	testing.expect(t, signature_current(wrapping, 50), "after the wrap is inside the window")
	testing.expect(t, !signature_current(wrapping, 200), "past the expiration is outside it")
	testing.expect(t, !signature_current(wrapping, 0xffff_fe00), "before the inception is outside it")

	testing.expect(t, serial_ge(5, 5), "a serial is not less than itself")
	testing.expect(t, serial_ge(0, 0xffff_ffff), "zero comes after the top of the space")
	testing.expect(t, !serial_ge(0xffff_ffff, 0), "and the top does not come after zero")
	free_all(context.temp_allocator)
}
