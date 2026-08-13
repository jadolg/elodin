package dns

import "core:mem"

/*
Expansion of the compressed domain names a few early RR types may carry inside
their RDATA.

RFC 1035 section 4.1.4 lets a name inside RDATA be a pointer to an earlier name
in the same message, and the types that predate RFC 3597 make full use of it: an
authoritative server compresses the hostname of an AFSDB, the mailbox of an RP or
MINFO, and the exchanger of an RT or PX against names it has already written.
This codec models only a handful of RR types and keeps the rest as `Rdata_Raw`,
so for the types below the pointer arrives as opaque bytes.

Those bytes only mean anything against the message they came in. The writer
copies a raw blob out at whatever offset the record lands at, and the pointer
then names whichever byte now sits at the offset it holds, which is how an
answer comes to name a host nobody asked about. RFC 3597 section 4 lets a
receiver expand compressed RDATA names instead of carrying them along, and that
is what happens here: the names are decoded against the message still in hand and
written back out in full, so the blob means the same thing wherever it is put
down afterwards. It also gives DNSSEC the uncompressed form RFC 4034 section 6.2
requires of canonical RDATA, which a pointer could never be turned into once the
message around it was gone.

Nothing else about the record changes, and a blob holding no pointer is copied
byte for byte, so the only records that come out different are the ones that
would otherwise have come out wrong.
*/

@(private)
Raw_Layout :: struct {
	fixed:   int,
	strings: int,
	names:   int,
}

/*
Where the domain names sit inside the RDATA of a type kept as raw bytes: some
fixed-width bytes, then some character-strings, then the names. Everything past
the last name is carried through untouched.

Only types whose RDATA may carry a domain name need an entry, and only those
whose layout is fixed enough to walk without knowing more than the type. A6 is
left out: where its name starts depends on a prefix length in its own RDATA, and
it has been formally obsolete since RFC 6563. An A6 record therefore still
forwards with its pointer intact, which is what it did before any of this
existed.

The types this decoder models natively - NS, CNAME, PTR, DNAME, MB, MG, MR,
NSAP-PTR, SOA, MX, SRV - are on the list too, because a record of one of them
still lands here when its RDATA fails to parse for some other reason. An MX whose
RDLENGTH counts one byte more than its two fields, a SOA whose serial is short, a
CNAME whose name will not decode: `decode_record` catches the failure and keeps
the bytes as `Rdata_Raw`, and the compressed name inside is then exactly as stale
as any other once the message it pointed into is gone.

Nearly the same table exists as `raw_layout` in src/dnssec/canonical.odin, which
walks these layouts to lowercase the names for canonical form. It cannot reach a
private helper in this package and this package must not depend on that one, so
the two are kept in step by hand. The lists are not quite the same list, though,
and a type added here only belongs there if RFC 4034 section 6.2 names it: this
one is "a name may be compressed in here", that one is "a name in here is
lowercased for a signature". NSAP-PTR is the difference today - a name this
decoder walks, and one no signer ever downcased.
*/
@(private)
raw_rdata_layout :: proc "contextless" (t: Type) -> (layout: Raw_Layout, ok: bool) {
	#partial switch t {
	case .NS, .CNAME, .PTR, .DNAME, .MB, .MG, .MR, .MD, .MF, .NXT, .NSAP_PTR:
		return {0, 0, 1}, true
	case .SOA, .MINFO, .RP:
		return {0, 0, 2}, true
	case .MX, .AFSDB, .RT, .KX:
		return {2, 0, 1}, true
	case .PX:
		return {2, 0, 2}, true
	case .NAPTR:
		return {4, 3, 1}, true
	case .SRV:
		return {6, 0, 1}, true
	case .SIG:
		return {18, 0, 1}, true
	}
	return {}, false
}

/*
Take a copy of the RDATA at `msg[start:end]`, expanding any compressed name in
it.

Never fails: RDATA that does not walk cleanly - too short for its own layout, a
name that will not decode or that runs past the end of the record, an expansion
that would not fit an RDLENGTH - is copied exactly as it arrived. That is the
decoder's standing posture for odd RDATA, and a record that cannot be understood
here may still be the answer somebody wanted.
*/
@(private)
decode_raw_rdata :: proc(msg: []u8, type: Type, start, end: int, allocator: mem.Allocator) -> Rdata_Raw {
	layout, known := raw_rdata_layout(type)
	// Walking costs an allocation, and the overwhelming majority of raw RDATA
	// has no pointer anywhere in it. Two set high bits are what a pointer starts
	// with, so their absence settles it; their presence only means the walk is
	// worth attempting, since the byte may equally be part of a signature or a
	// flags field.
	if known && holds_pointer_byte(msg[start:end]) {
		if expanded, ok := expand_rdata_names(msg, layout, start, end, allocator); ok {
			return Rdata_Raw{data = expanded}
		}
	}

	verbatim := make([]u8, end - start, allocator)
	copy(verbatim, msg[start:end])
	return Rdata_Raw{data = verbatim}
}

@(private)
holds_pointer_byte :: proc "contextless" (rdata: []u8) -> bool {
	for b in rdata {
		if b & 0xc0 == 0xc0 {
			return true
		}
	}
	return false
}

@(private)
expand_rdata_names :: proc(
	msg: []u8,
	layout: Raw_Layout,
	start, end: int,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	buf := make([dynamic]u8, 0, end - start + MAX_NAME_WIRE, allocator)
	defer if !ok {
		delete(buf)
	}

	pos := start
	if pos + layout.fixed > end {
		return nil, false
	}
	append(&buf, ..msg[pos:pos + layout.fixed])
	pos += layout.fixed

	for _ in 0 ..< layout.strings {
		if pos >= end {
			return nil, false
		}
		n := int(msg[pos])
		if pos + 1 + n > end {
			return nil, false
		}
		append(&buf, ..msg[pos:pos + 1 + n])
		pos += 1 + n
	}

	name_buf: [MAX_NAME_WIRE]u8
	for _ in 0 ..< layout.names {
		// `decode_name` reads the whole message, which is the point - a pointer
		// aims outside the record - but the name's own bytes have to lie inside
		// it. `next` is the first byte after the name in the record being
		// walked, so a name that overran the RDATA shows up as an end past it.
		name, next, derr := decode_name(msg, pos, allocator)
		if derr != .None {
			return nil, false
		}
		defer delete(name, allocator)
		if next > end {
			return nil, false
		}
		n, eerr := encode_name(name, name_buf[:])
		if eerr != .None {
			return nil, false
		}
		append(&buf, ..name_buf[:n])
		pos = next
	}

	append(&buf, ..msg[pos:end])
	if len(buf) > 0xffff {
		return nil, false
	}
	return buf[:], true
}

/*
Whether a raw blob still holds a compression pointer where a name belongs.

Answers only for the types whose layout is known, and only when the walk reaches
a name; a blob that does not add up is reported as clean because nothing here can
tell where its names were meant to start. That is the conservative direction: the
writer refuses what this returns true for, and refusing a record that was fine
would cost an answer for nothing.
*/
@(private)
raw_rdata_holds_pointer :: proc "contextless" (type: Type, rdata: []u8) -> bool {
	layout, known := raw_rdata_layout(type)
	if !known {
		return false
	}

	pos := layout.fixed
	if pos > len(rdata) {
		return false
	}
	for _ in 0 ..< layout.strings {
		if pos >= len(rdata) {
			return false
		}
		n := int(rdata[pos])
		if pos + 1 + n > len(rdata) {
			return false
		}
		pos += 1 + n
	}

	for _ in 0 ..< layout.names {
		for {
			if pos >= len(rdata) {
				return false
			}
			l := rdata[pos]
			if l & 0xc0 == 0xc0 {
				return true
			}
			if l & 0xc0 != 0 {
				// A reserved label type: not a pointer, and not something whose
				// length is known well enough to walk past.
				return false
			}
			pos += 1 + int(l)
			if l == 0 {
				break
			}
		}
	}
	return false
}
