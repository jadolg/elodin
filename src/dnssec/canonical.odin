package dnssec

import "core:mem"
import "core:slice"
import "elodin:dns"

/*
Canonical form and canonical ordering, RFC 4034 sections 6.1 and 6.2.

A signature is computed over a byte sequence the signer built from the zone's
own copy of the data, so a validator has to reconstruct exactly the same bytes:
owner names lowercased and uncompressed, RDATA in a fixed layout, the records of
an RRset sorted by their RDATA and duplicates removed.
*/

/*
Write `name` into `out` as lowercase, uncompressed wire bytes.

`out` must have room for a full name. Nothing is allocated: the presentation
form is folded into a stack buffer on the way past.
*/
canonical_name :: proc(name: string, out: []u8) -> (n: int, ok: bool) {
	buf: [dns.MAX_NAME_PRESENTATION]u8
	if len(name) > len(buf) {
		return 0, false
	}
	for i in 0 ..< len(name) {
		c := name[i]
		buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	m, err := dns.encode_name(string(buf[:len(name)]), out)
	return m, err == .None
}

@(private)
plain_name :: proc(name: string, out: []u8) -> (n: int, ok: bool) {
	m, err := dns.encode_name(name, out)
	return m, err == .None
}

// Labels in a presentation name, root excluded: "www.example.com." is 3.
label_count :: proc "contextless" (name: string) -> int {
	if name == "" || name == "." {
		return 0
	}
	n := 0
	i := 0
	for i < len(name) {
		if name[i] == '\\' {
			// Both escape forms (\X and \DDD) continue with characters that
			// cannot be an unescaped separator, so skipping two is enough.
			i += 2
			continue
		}
		if name[i] == '.' {
			n += 1
		}
		i += 1
	}
	return n
}

// Drop `count` labels from the front: ("a.b.c.", 1) is "b.c.".
name_drop_labels :: proc(name: string, count: int) -> string {
	out := name
	for _ in 0 ..< count {
		if out == "." || out == "" {
			return "."
		}
		out = dns.name_parent(out)
	}
	return out
}

// Is `child` at or below `parent`?
name_in_zone :: proc(child, parent: string) -> bool {
	if parent == "." {
		return true
	}
	cl, pl := label_count(child), label_count(parent)
	if cl < pl {
		return false
	}
	return dns.name_equal_fold(name_drop_labels(child, cl - pl), parent)
}

@(private)
split_labels :: proc "contextless" (wire: []u8, out: [][]u8) -> int {
	n := 0
	pos := 0
	for pos < len(wire) && n < len(out) {
		l := int(wire[pos])
		if l == 0 {
			break
		}
		if pos + 1 + l > len(wire) {
			break
		}
		out[n] = wire[pos + 1:pos + 1 + l]
		n += 1
		pos += 1 + l
	}
	return n
}

/*
Canonical DNS name order, RFC 4034 section 6.1.

Names sort as if their labels were read right to left, each label compared as a
lowercase unsigned octet string. It is the order NSEC chains are built in, so
"covered by" questions are answered with this and nothing else.
*/
name_compare :: proc(a, b: string) -> (order: int, ok: bool) {
	abuf, bbuf: [dns.MAX_NAME_WIRE]u8
	an, aok := canonical_name(a, abuf[:])
	bn, bok := canonical_name(b, bbuf[:])
	if !aok || !bok {
		// A name that will not encode has no place in the ordering, and
		// guessing one would let a span be read as covering something it does
		// not. The caller has to treat this as a proof that did not hold.
		return 0, false
	}

	al, bl: [MAX_LABELS][]u8
	ac := split_labels(abuf[:an], al[:])
	bc := split_labels(bbuf[:bn], bl[:])

	i, j := ac - 1, bc - 1
	for i >= 0 && j >= 0 {
		if c := mem.compare(al[i], bl[j]); c != 0 {
			return c, true
		}
		i -= 1
		j -= 1
	}
	if i >= 0 {
		return 1, true
	}
	if j >= 0 {
		return -1, true
	}
	return 0, true
}

/*
Types whose RDATA domain names are lowercased in canonical form.

The list is RFC 4034 section 6.2 with the correction from RFC 6840 section 5.1:
the next name in an NSEC record is left exactly as it was published, while the
signer name in an RRSIG is lowercased.
*/
@(private)
downcases_rdata_names :: proc "contextless" (t: dns.Type) -> bool {
	#partial switch t {
	case .NS, .MD, .MF, .CNAME, .SOA, .MB, .MG, .MR, .PTR, .MINFO, .MX, .RP,
	     .AFSDB, .RT, .SIG, .PX, .NXT, .NAPTR, .KX, .SRV, .DNAME, .A6, .RRSIG:
		return true
	}
	return false
}

/*
Where the domain names sit inside the RDATA of a type the codec keeps as raw
bytes: some fixed-width bytes, then some character-strings, then the names.
Everything after the last name is copied through untouched.

Only types on the lowercasing list above need an entry, and only those whose
layout is fixed enough to walk. A6 is left out: its layout depends on a prefix
length, and it has been formally obsolete since 2012. The types the codec models
natively are listed anyway: one of them still arrives as raw bytes when its RDATA
failed to parse, and a validation attempt on such a record should compare against
the same canonical form as any other.

The same table exists as `raw_rdata_layout` in src/dns/rdata_raw.odin, where the
decoder walks it to expand compressed names. That one is private to its package
and this one is private to this, so the two are kept in step by hand: a type
added to either belongs in both.
*/
@(private)
Raw_Layout :: struct {
	fixed:   int,
	strings: int,
	names:   int,
}

@(private)
raw_layout :: proc "contextless" (t: dns.Type) -> (layout: Raw_Layout, ok: bool) {
	#partial switch t {
	case .NS, .CNAME, .PTR, .DNAME, .MB, .MG, .MR, .MD, .MF, .NXT:
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
Copy raw RDATA, lowercasing the domain names it is known to contain.

Falls back to a verbatim copy when the layout does not parse — including when a
name turns out to be compressed, which cannot be expanded here because the
surrounding message is long gone. Such a record simply fails to validate, which
is the right outcome for RDATA that RFC 4034 forbade compressing in the first
place.

A compressed name should no longer reach that fallback: the decoder expands the
ones it can while the message is still in hand (see src/dns/rdata_raw.odin), so
what arrives here is the uncompressed form RFC 4034 section 6.2 asks for rather
than a canonical form no signer ever signed. What is left is RDATA nothing could
walk, and a validation failure is the honest answer for it.
*/
@(private)
write_downcased_raw :: proc(out: ^[dynamic]u8, type: dns.Type, rdata: []u8) {
	layout, known := raw_layout(type)
	if !known {
		append(out, ..rdata)
		return
	}

	mark := len(out^)
	pos := 0
	fail :: proc(out: ^[dynamic]u8, mark: int, rdata: []u8) {
		resize(out, mark)
		append(out, ..rdata)
	}

	if pos + layout.fixed > len(rdata) {
		fail(out, mark, rdata)
		return
	}
	append(out, ..rdata[pos:pos + layout.fixed])
	pos += layout.fixed

	for _ in 0 ..< layout.strings {
		if pos >= len(rdata) {
			fail(out, mark, rdata)
			return
		}
		n := int(rdata[pos])
		if pos + 1 + n > len(rdata) {
			fail(out, mark, rdata)
			return
		}
		append(out, ..rdata[pos:pos + 1 + n])
		pos += 1 + n
	}

	for _ in 0 ..< layout.names {
		for {
			if pos >= len(rdata) {
				fail(out, mark, rdata)
				return
			}
			l := rdata[pos]
			if l & 0xc0 != 0 {
				fail(out, mark, rdata)
				return
			}
			if l == 0 {
				pos += 1
				break
			}
			if pos + 1 + int(l) > len(rdata) {
				fail(out, mark, rdata)
				return
			}
			append(out, l)
			for c in rdata[pos + 1:pos + 1 + int(l)] {
				append(out, c + 32 if c >= 'A' && c <= 'Z' else c)
			}
			pos += 1 + int(l)
		}
		append(out, 0)
	}

	append(out, ..rdata[pos:])
}

@(private)
write_canonical_rdata :: proc(out: ^[dynamic]u8, rec: dns.Record) -> bool {
	buf: [dns.MAX_NAME_WIRE]u8
	down := downcases_rdata_names(rec.type)

	write_name :: proc(out: ^[dynamic]u8, buf: []u8, name: string, down: bool) -> bool {
		n, ok := 0, false
		if down {
			n, ok = canonical_name(name, buf)
		} else {
			n, ok = plain_name(name, buf)
		}
		if !ok {
			return false
		}
		append(out, ..buf[:n])
		return true
	}

	switch d in rec.data {
	case dns.Rdata_A:
		addr := d.addr
		append(out, ..addr[:])
	case dns.Rdata_AAAA:
		addr := d.addr
		append(out, ..addr[:])
	case dns.Rdata_Name:
		return write_name(out, buf[:], d.name, down)
	case dns.Rdata_SOA:
		if !write_name(out, buf[:], d.ns, down) || !write_name(out, buf[:], d.mbox, down) {
			return false
		}
		append(out, u8(d.serial >> 24), u8(d.serial >> 16), u8(d.serial >> 8), u8(d.serial))
		append(out, u8(d.refresh >> 24), u8(d.refresh >> 16), u8(d.refresh >> 8), u8(d.refresh))
		append(out, u8(d.retry >> 24), u8(d.retry >> 16), u8(d.retry >> 8), u8(d.retry))
		append(out, u8(d.expire >> 24), u8(d.expire >> 16), u8(d.expire >> 8), u8(d.expire))
		append(out, u8(d.minimum >> 24), u8(d.minimum >> 16), u8(d.minimum >> 8), u8(d.minimum))
	case dns.Rdata_MX:
		append(out, u8(d.preference >> 8), u8(d.preference))
		return write_name(out, buf[:], d.exchange, down)
	case dns.Rdata_TXT:
		for s in d.strings {
			if len(s) > 255 {
				return false
			}
			append(out, u8(len(s)))
			append(out, ..transmute([]u8)s)
		}
	case dns.Rdata_SRV:
		append(out, u8(d.priority >> 8), u8(d.priority))
		append(out, u8(d.weight >> 8), u8(d.weight))
		append(out, u8(d.port >> 8), u8(d.port))
		return write_name(out, buf[:], d.target, down)
	case dns.Rdata_CAA:
		append(out, d.flags)
		if len(d.tag) > 255 {
			return false
		}
		append(out, u8(len(d.tag)))
		append(out, ..transmute([]u8)d.tag)
		append(out, ..transmute([]u8)d.value)
	case dns.Rdata_SVCB:
		append(out, u8(d.priority >> 8), u8(d.priority))
		// SVCB is not on the lowercasing list, and its target is never compressed.
		if !write_name(out, buf[:], d.target, false) {
			return false
		}
		append(out, ..d.params)
	case dns.Rdata_OPT:
		// OPT is never covered by a signature.
		return false
	case dns.Rdata_Raw:
		write_downcased_raw(out, rec.type, d.data)
	case:
		return false
	}
	return true
}

/*
Build the byte sequence an RRSIG is computed over.

That is the signature's own RDATA up to but not including the signature itself,
followed by every record of the RRset in canonical form and canonical order.
`owner` is the name to sign under, which is the records' owner name except for a
wildcard expansion, where it is the wildcard the zone actually holds.
*/
signing_input :: proc(
	sig: Rrsig,
	owner: string,
	class: dns.Class,
	records: []dns.Record,
	allocator := context.temp_allocator,
) -> (
	data: []u8,
	ok: bool,
) {
	if len(records) == 0 {
		return nil, false
	}

	name_buf: [dns.MAX_NAME_WIRE]u8
	owner_len := canonical_name(owner, name_buf[:]) or_return
	owner_wire := name_buf[:owner_len]

	out := make([dynamic]u8, 0, 512, allocator)
	append(&out, u8(u16(sig.type_covered) >> 8), u8(u16(sig.type_covered)))
	append(&out, sig.algorithm, sig.labels)
	append(&out, u8(sig.original_ttl >> 24), u8(sig.original_ttl >> 16), u8(sig.original_ttl >> 8), u8(sig.original_ttl))
	append(&out, u8(sig.expiration >> 24), u8(sig.expiration >> 16), u8(sig.expiration >> 8), u8(sig.expiration))
	append(&out, u8(sig.inception >> 24), u8(sig.inception >> 16), u8(sig.inception >> 8), u8(sig.inception))
	append(&out, u8(sig.key_tag >> 8), u8(sig.key_tag))

	signer_buf: [dns.MAX_NAME_WIRE]u8
	signer_len := canonical_name(sig.signer, signer_buf[:]) or_return
	append(&out, ..signer_buf[:signer_len])

	// Each RDATA is rendered once, then the set is sorted and de-duplicated on
	// those bytes, which is what "canonical order" means for an RRset.
	rdatas := make([dynamic][]u8, 0, len(records), allocator)
	for rec in records {
		buf := make([dynamic]u8, 0, 64, allocator)
		if !write_canonical_rdata(&buf, rec) {
			return nil, false
		}
		if len(buf) > 0xffff {
			return nil, false
		}
		append(&rdatas, buf[:])
	}
	slice.sort_by(rdatas[:], proc(a, b: []u8) -> bool {
		return mem.compare(a, b) < 0
	})

	previous: []u8
	written := 0
	for rdata, i in rdatas {
		if i > 0 && mem.compare(previous, rdata) == 0 {
			continue
		}
		previous = rdata

		append(&out, ..owner_wire)
		append(&out, u8(u16(sig.type_covered) >> 8), u8(u16(sig.type_covered)))
		append(&out, u8(u16(class) >> 8), u8(u16(class)))
		append(&out, u8(sig.original_ttl >> 24), u8(sig.original_ttl >> 16), u8(sig.original_ttl >> 8), u8(sig.original_ttl))
		append(&out, u8(len(rdata) >> 8), u8(len(rdata)))
		append(&out, ..rdata)
		written += 1
	}
	if written == 0 {
		return nil, false
	}
	return out[:], true
}
