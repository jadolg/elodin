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

Nearly the same table exists as `raw_rdata_layout` in src/dns/rdata_raw.odin,
where the decoder walks it to expand compressed names. That one is private to its
package and this one is private to this, so the two are kept in step by hand -
but they are not quite the same list. That one asks whether a name in the RDATA
may have been compressed; this one asks whether a name in the RDATA is lowercased
for a signature, which only the types in RFC 4034 section 6.2 are. NSAP-PTR,
NSEC, TALINK, LP, DSYNC, IPSECKEY, AMTRELAY and HIP are walked there and
deliberately absent here: downcasing them would build a canonical form no signer
ever computed (RFC 6840 section 5.1 took NSEC off the RFC 4034 list). RRSIG is walked there and absent
here too, though on the list: no RRSIG set is itself signed, and the validator
canonicalizes the signer of the one it checks on its own.
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
One RRset's canonical RDATA, rendered once and reused for every signature tried
over it, and the buffer each attempt's signing input is built in.

Only the RRSIG's own RDATA, the owner a wildcard signature names and the
Original TTL differ from one signature over a set to the next; the sorted,
de-duplicated RDATA is the same every time. A render per attempt costs about one
and a half times the set's wire size per signature, so a 60 KB set and the
`MAX_VERIFICATIONS_PER_QUERY` signatures a zone may publish over it would cost
several MB of arena per query (issue #527). With one of these per RRset that is
the set once and the buffer once.

Zero-valued to start with, one per RRset: a scratch handed a different set
renders that one instead of reusing the first.
*/
Signing_Scratch :: struct {
	/*
	The question's allowances, or nil where nobody is counting. What the scratch
	takes is charged to its `spent`, against `dns.REQUEST_DECODE_BUDGET`, so a
	validation's renders count with what its readings already took. Past it
	`signing_input` refuses, `over_budget` says so, and the budget's `ran_out`
	names the reason for whichever loop stops on it.
	*/
	budget:      ^Budget,
	over_budget: bool,
	// The set `rdatas` was rendered from, or nil before the first: a set that
	// would not render is remembered too, so it is not attempted again per
	// signature.
	records:     []dns.Record,
	// Sorted and de-duplicated, slices into one buffer; nil if it would not render.
	rdatas:      [][]u8,
	// Their total length.
	rdata_bytes: int,
	out:         [dynamic]u8,
}

/*
Charge `n` bytes of arena to the request, and refuse once it is past its budget.
*/
@(private)
charge_scratch :: proc(scratch: ^Signing_Scratch, n: int) -> bool {
	if scratch.budget == nil || scratch.budget.spent == nil {
		return true
	}
	if !dns.request_charge(scratch.budget.spent, n) {
		scratch_refuse(scratch)
		return false
	}
	return !scratch_over_budget(scratch)
}

// Whether the request is past its budget, and if so the scratch refuses from
// here on, and says why in the budget.
@(private)
scratch_over_budget :: proc(scratch: ^Signing_Scratch) -> bool {
	if scratch.budget == nil || !dns.over_request_budget(scratch.budget.spent) {
		return false
	}
	scratch_refuse(scratch)
	return true
}

// Refuse from here on, and say why in the budget - over it, or refused a heavy
// slot, which the validator reports the same way (see `dns.request_charge`).
@(private)
scratch_refuse :: proc(scratch: ^Signing_Scratch) {
	scratch.over_budget = true
	scratch.budget.ran_out = READING_OVER_BUDGET
}

/*
Each RDATA rendered once into a single buffer, then the set sorted and
de-duplicated on those bytes, which is what "canonical order" means for an
RRset (RFC 4034 section 6.3).
*/
@(private)
render_rdatas :: proc(scratch: ^Signing_Scratch, records: []dns.Record, allocator: mem.Allocator) -> bool {
	scratch.records = records
	scratch.rdatas = nil
	scratch.rdata_bytes = 0
	/*
	Charged as it grows, and at twice the buffer's capacity: growth that cannot
	happen in place - past the end of an arena block - leaves every smaller copy
	behind, and those sum to less than the last. A set's canonical form can be
	many times its wire size, since names in RDATA arrive compressed and are
	rendered in full, so a request that runs out stops the render at the step
	that crossed rather than paying for the set and refusing after.

	The index arrays are charged before they are taken, and with the buffer's
	first capacity, so a request with nothing left renders nothing, as
	`dns.decode_message` reads nothing. Both are taken before the buffer, so the
	buffer is the last thing in the arena and grows in place.
	*/
	STORE_START :: 512
	if !charge_scratch(scratch, len(records) * (size_of(int) + size_of([]u8)) + 2 * STORE_START) {
		return false
	}
	ends := make([]int, len(records), allocator)
	rdatas := make([][]u8, len(records), allocator)
	store := make([dynamic]u8, 0, STORE_START, allocator)
	charged := 2 * STORE_START
	for rec, i in records {
		start := len(store)
		rendered := write_canonical_rdata(&store, rec) && len(store) - start <= 0xffff
		// Before the verdict: the arena has paid for this record either way.
		if 2 * cap(store) > charged {
			charge_scratch(scratch, 2 * cap(store) - charged) or_return
			charged = 2 * cap(store)
		}
		if !rendered {
			return false
		}
		ends[i] = len(store)
	}
	start := 0
	for end, i in ends {
		rdatas[i] = store[start:end]
		start = end
	}
	slice.sort_by(rdatas, proc(a, b: []u8) -> bool {
		return mem.compare(a, b) < 0
	})
	n := 0
	for rdata, i in rdatas {
		if i > 0 && mem.compare(rdatas[n - 1], rdata) == 0 {
			continue
		}
		rdatas[n] = rdata
		n += 1
		scratch.rdata_bytes += len(rdata)
	}
	scratch.rdatas = rdatas[:n]
	return true
}

/*
Build the byte sequence an RRSIG is computed over.

That is the signature's own RDATA up to but not including the signature itself,
followed by every record of the RRset in canonical form and canonical order.
`owner` is the name to sign under, which is the records' owner name except for a
wildcard expansion, where it is the wildcard the zone actually holds.

The result lives in `scratch` and is overwritten by the next call with it; see
`Signing_Scratch`. Without one, every call renders the set afresh.
*/
signing_input :: proc(
	sig: Rrsig,
	owner: string,
	class: dns.Class,
	records: []dns.Record,
	allocator := context.temp_allocator,
	scratch: ^Signing_Scratch = nil,
) -> (
	data: []u8,
	ok: bool,
) {
	if len(records) == 0 {
		return nil, false
	}
	local: Signing_Scratch
	s := scratch if scratch != nil else &local
	if s.over_budget {
		return nil, false
	}

	name_buf: [dns.MAX_NAME_WIRE]u8
	owner_len := canonical_name(owner, name_buf[:]) or_return
	owner_wire := name_buf[:owner_len]

	signer_buf: [dns.MAX_NAME_WIRE]u8
	signer_len := canonical_name(sig.signer, signer_buf[:]) or_return

	if raw_data(s.records) != raw_data(records) || len(s.records) != len(records) {
		render_rdatas(s, records, allocator)
	}
	if len(s.rdatas) == 0 || s.over_budget {
		return nil, false
	}

	framing := len(s.rdatas) * 10
	need := RRSIG_FIXED_PREFIX + signer_len + len(s.rdatas) * owner_len + framing + s.rdata_bytes
	if cap(s.out) < need {
		/*
		Sized for the longest signer and for the records' own owner, which no
		wildcard a signature names is longer than, so the signer and Labels
		fields a sender varies from one signature to the next do not make every
		attempt a fresh buffer. The presentation length plus one is never short
		of the wire length. Doubled past that, should a caller name some other
		owner.
		*/
		widest := RRSIG_FIXED_PREFIX + dns.MAX_NAME_WIRE + len(s.rdatas) * max(owner_len, len(records[0].name) + 1) + framing + s.rdata_bytes
		size := max(widest, 2 * cap(s.out))
		charge_scratch(s, size) or_return
		s.out = make([dynamic]u8, 0, size, allocator)
	}
	out := &s.out
	clear(out)
	append(out, u8(u16(sig.type_covered) >> 8), u8(u16(sig.type_covered)))
	append(out, sig.algorithm, sig.labels)
	append(out, u8(sig.original_ttl >> 24), u8(sig.original_ttl >> 16), u8(sig.original_ttl >> 8), u8(sig.original_ttl))
	append(out, u8(sig.expiration >> 24), u8(sig.expiration >> 16), u8(sig.expiration >> 8), u8(sig.expiration))
	append(out, u8(sig.inception >> 24), u8(sig.inception >> 16), u8(sig.inception >> 8), u8(sig.inception))
	append(out, u8(sig.key_tag >> 8), u8(sig.key_tag))
	append(out, ..signer_buf[:signer_len])

	for rdata in s.rdatas {
		append(out, ..owner_wire)
		append(out, u8(u16(sig.type_covered) >> 8), u8(u16(sig.type_covered)))
		append(out, u8(u16(class) >> 8), u8(u16(class)))
		append(out, u8(sig.original_ttl >> 24), u8(sig.original_ttl >> 16), u8(sig.original_ttl >> 8), u8(sig.original_ttl))
		append(out, u8(len(rdata) >> 8), u8(len(rdata)))
		append(out, ..rdata)
	}
	return out[:], true
}

// Type Covered, Algorithm, Labels, Original TTL, Expiration, Inception and Key
// Tag: the RRSIG RDATA ahead of the signer (RFC 4034 section 3.1).
@(private)
RRSIG_FIXED_PREFIX :: 18
