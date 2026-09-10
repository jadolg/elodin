package itest

import "core:mem"

/*
RDATA for the parity mock's synthetic zone, one shape per record type.

The point of writing these by hand is the compression pointers. RFC 1035 section
4.1.4 lets a name inside RDATA point at an earlier name in the same message, and
the types that predate RFC 3597 use it; a resolver that copies such a blob into
a message laid out differently produces a record naming a host nobody asked
about. elodin expands those names on the way through
(`src/dns/rdata_raw.odin`), and the only way to know that still works is for an
upstream to keep sending them - so every type whose layout permits a pointer
gets one here.

The values are not meant to be plausible, only to be well formed and to have the
right shape: a signature that is not a signature still has to survive the trip
byte for byte.
*/

@(private)
pm_rdata :: proc(r: ^Pg_Rand, qtype: u16, allocator: mem.Allocator) -> []u8 {
	buf := make([dynamic]u8, 0, 64, allocator)

	switch qtype {
	case 1: // A
		return pm_bytes(r, 4, allocator)

	case 28: // AAAA
		return pm_bytes(r, 16, allocator)

	case 2, 12: // NS, PTR - compressible, so compressed
		return PM_PTR_Q

	case 5: // CNAME
		// A full name rather than a pointer at the question: a CNAME whose
		// target is its own owner is a loop, and the loop check is a different
		// test's business.
		return pm_name("target.parity.test.", allocator)

	case 39: // DNAME - same reasoning as CNAME
		return pm_name("elsewhere.parity.test.", allocator)

	case 6: // SOA
		append(&buf, ..pm_name("ns1.parity.test.", allocator))
		append(&buf, ..pm_name("hostmaster.parity.test.", allocator))
		pm_put32(&buf, 2026090801) // serial
		pm_put32(&buf, 7200) // refresh
		pm_put32(&buf, 3600) // retry
		pm_put32(&buf, 1209600) // expire
		pm_put32(&buf, 300) // minimum
		return buf[:]

	case 15, 18, 21, 36: // MX, AFSDB, RT, KX - {2, 0, 1}
		pm_put16(&buf, 10)
		append(&buf, ..PM_PTR_Q)
		return buf[:]

	case 14, 17: // MINFO, RP - {0, 0, 2}
		append(&buf, ..PM_PTR_Q)
		append(&buf, ..PM_PTR_Q)
		return buf[:]

	case 26: // PX - {2, 0, 2}
		pm_put16(&buf, 20)
		append(&buf, ..PM_PTR_Q)
		append(&buf, ..PM_PTR_Q)
		return buf[:]

	case 33: // SRV - {6, 0, 1}
		pm_put16(&buf, 1) // priority
		pm_put16(&buf, 10) // weight
		pm_put16(&buf, 443) // port
		append(&buf, ..PM_PTR_Q)
		return buf[:]

	case 35: // NAPTR - {4, 3, 1}
		pm_put16(&buf, 100) // order
		pm_put16(&buf, 10) // preference
		pm_char_string(&buf, "u")
		pm_char_string(&buf, "E2U+sip")
		pm_char_string(&buf, "!^.*$!sip:info@parity.test!")
		append(&buf, ..PM_PTR_Q)
		return buf[:]

	case 24: // SIG - {18, 0, 1}
		append(&buf, ..pm_bytes(r, 18, allocator))
		append(&buf, ..PM_PTR_Q)
		append(&buf, ..pm_bytes(r, 32, allocator))
		return buf[:]

	case 16, 99: // TXT, SPF
		// Empty, ordinary and full-length character-strings in one record. The
		// empty one is legal and the one a length-prefix walker gets wrong.
		pm_char_string(&buf, "")
		pm_char_string(&buf, "v=parity1 shape=txt")
		long := make([]u8, 255, allocator)
		for i in 0 ..< 255 {
			long[i] = 'x'
		}
		append(&buf, 255)
		append(&buf, ..long)
		return buf[:]

	case 13: // HINFO
		pm_char_string(&buf, "ODIN")
		pm_char_string(&buf, "parity")
		return buf[:]

	case 257: // CAA
		append(&buf, 0) // flags
		pm_char_string(&buf, "issue")
		append(&buf, "parity.test")
		return buf[:]

	case 64, 65: // SVCB, HTTPS
		return pm_svcb(r, allocator)

	case 52: // TLSA
		append(&buf, 3, 1, 1) // usage, selector, matching type
		append(&buf, ..pm_bytes(r, 32, allocator))
		return buf[:]

	case 44: // SSHFP
		append(&buf, 4, 2) // algorithm, fingerprint type
		append(&buf, ..pm_bytes(r, 32, allocator))
		return buf[:]

	case 43: // DS
		pm_put16(&buf, 12345) // key tag
		append(&buf, 13, 2) // algorithm, digest type
		append(&buf, ..pm_bytes(r, 32, allocator))
		return buf[:]

	case 48: // DNSKEY
		pm_put16(&buf, 257) // flags: zone key, secure entry point
		append(&buf, 3, 13) // protocol, algorithm
		append(&buf, ..pm_bytes(r, 64, allocator))
		return buf[:]

	case 46: // RRSIG
		pm_put16(&buf, 1) // type covered
		append(&buf, 13, 2) // algorithm, labels
		pm_put32(&buf, 3600) // original ttl
		pm_put32(&buf, 1788000000) // expiration
		pm_put32(&buf, 1785000000) // inception
		pm_put16(&buf, 12345) // key tag
		// RFC 4034 section 3.1.7: the signer's name is never compressed.
		append(&buf, ..pm_name("parity.test.", allocator))
		append(&buf, ..pm_bytes(r, 64, allocator))
		return buf[:]

	case 47: // NSEC
		append(&buf, ..pm_name("next.parity.test.", allocator))
		pm_type_bitmap(&buf)
		return buf[:]

	case 50: // NSEC3
		append(&buf, 1, 0) // hash algorithm, flags
		pm_put16(&buf, 10) // iterations
		append(&buf, 8)
		append(&buf, ..pm_bytes(r, 8, allocator)) // salt
		append(&buf, 20)
		append(&buf, ..pm_bytes(r, 20, allocator)) // next hashed owner
		pm_type_bitmap(&buf)
		return buf[:]

	case 51: // NSEC3PARAM
		append(&buf, 1, 0)
		pm_put16(&buf, 10)
		append(&buf, 8)
		append(&buf, ..pm_bytes(r, 8, allocator))
		return buf[:]

	case 29: // LOC
		append(&buf, 0, 0x12, 0x16, 0x13)
		append(&buf, ..pm_bytes(r, 12, allocator))
		return buf[:]

	case 256: // URI
		pm_put16(&buf, 10) // priority
		pm_put16(&buf, 1) // weight
		append(&buf, "https://parity.test/")
		return buf[:]

	case 108: // EUI48
		return pm_bytes(r, 6, allocator)

	case 61: // OPENPGPKEY
		return pm_bytes(r, 96, allocator)
	}

	// Everything unassigned or unmodelled: opaque bytes, which is precisely
	// what RFC 3597 section 2 says a resolver must carry without understanding.
	return pm_bytes(r, 16 + pg_int(r, 48), allocator)
}

/*
SVCB and HTTPS RDATA.

Its own proc because it is the one modern type whose RDATA is a list rather than
a record, and because RFC 9460 section 2.2 forbids compressing the TargetName -
so this is the type that must come back with a full name where the older ones
come back with an expanded pointer.
*/
@(private = "file")
pm_svcb :: proc(r: ^Pg_Rand, allocator: mem.Allocator) -> []u8 {
	buf := make([dynamic]u8, 0, 64, allocator)
	pm_put16(&buf, 1) // priority
	append(&buf, ..pm_name("svc.parity.test.", allocator))

	// alpn: two length-prefixed protocol ids inside the one parameter, which is
	// how the list is written (RFC 9460 section 7.1.1).
	pm_put16(&buf, 1)
	pm_put16(&buf, 6)
	append(&buf, 2, 'h', '3', 2, 'h', '2')

	// port
	pm_put16(&buf, 3)
	pm_put16(&buf, 2)
	pm_put16(&buf, 8443)

	// ipv4hint
	pm_put16(&buf, 4)
	pm_put16(&buf, 4)
	append(&buf, ..pm_bytes(r, 4, allocator))

	return buf[:]
}

@(private = "file")
pm_char_string :: proc(buf: ^[dynamic]u8, s: string) {
	append(buf, u8(len(s)))
	append(buf, s)
}

// An NSEC type bitmap covering window 0: A, NS, SOA, TXT, AAAA, RRSIG and NSEC.
@(private = "file")
pm_type_bitmap :: proc(buf: ^[dynamic]u8) {
	append(buf, 0) // window block 0
	append(buf, 6) // bitmap length
	// Bit n of byte b is type b*8 + n, counted from the high bit.
	append(buf, 0x62) // A (1), NS (2), SOA (6)
	append(buf, 0x00)
	append(buf, 0x80) // TXT (16)
	append(buf, 0x08) // AAAA (28)
	append(buf, 0x00)
	append(buf, 0x03) // RRSIG (46), NSEC (47)
}
