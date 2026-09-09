package itest

import "core:fmt"
import "core:mem"
import "core:slice"
import "core:strings"

/*
An independent reader for the DNS messages the parity check compares.

Deliberately does not import `elodin:dns`. The parity check asks whether elodin
handed the client what its upstream handed elodin, and a comparator built on the
codec under test cannot answer that: a decoder that loses an option, mis-walks an
RDATA or drops a record loses it identically on both sides of the comparison and
reports agreement. The same reasoning `fixtures.odin` gives for freezing captured
wire data as hex rather than generating it with our own encoder.

So this walks the bytes itself, and it is the only file in the suite that may.
What it produces is a canonical form - names expanded, sections as multisets,
rcode reassembled from both of the places it is written - in which two messages
that say the same thing compare equal however they were laid out.
*/

PW_MAX_NAME :: 255

/*
How many compression pointers one name may follow.

A cap alone does not stop a decompression loop, so pointers must also aim
strictly backwards (see `pw_read_name`); with that in place this only bounds the
work a deeply chained but legal name can cost.
*/
PW_MAX_JUMPS :: 64

Pw_Question :: struct {
	// Uncompressed wire form with the case exactly as it arrived. The case is
	// kept because echoing it unchanged is a property worth checking: it is
	// what a 0x20-randomising client uses to tell its own answer from a forgery.
	name:  []u8,
	type:  u16,
	class: u16,
}

Pw_Option :: struct {
	code: u16,
	data: []u8,
}

Pw_Opt :: struct {
	present:   bool,
	// An OPT record's owner name must be root (RFC 6891 section 6.1.2).
	root:      bool,
	udp_size:  u16,
	ext_rcode: u8,
	version:   u8,
	flags:     u16,
	options:   []Pw_Option,
	// The option list did not walk cleanly to the end of the RDATA. Reported
	// rather than smoothed over: an OPT whose list ends in the stump of a
	// fourth option header is exactly the shape that hides an option from one
	// reader and not from another.
	malformed: bool,
	// A second OPT record in the additional section, which RFC 6891 section
	// 6.1.1 forbids.
	duplicate: bool,
}

PW_DO :: 0x8000

Pw_RR :: struct {
	// Uncompressed wire form, case as it arrived.
	name:  []u8,
	type:  u16,
	class: u16,
	ttl:   u32,
	// RDATA with any compressed name inside it expanded, so a record means the
	// same thing wherever in a message it was written down. Case is preserved:
	// expansion is not downcasing, and a side that downcased a name in RDATA
	// should show up as a difference rather than be normalised into agreement.
	rdata: []u8,
}

Pw_Msg :: struct {
	ok:         bool,
	err:        string,
	size:       int,
	id:         u16,
	opcode:     u8,
	qr:         bool,
	aa:         bool,
	tc:         bool,
	rd:         bool,
	ra:         bool,
	ad:         bool,
	cd:         bool,
	// The three reserved header bits between RA and the rcode, which must be
	// zero and which nothing in the path may set.
	z:          u8,
	// The full twelve-bit rcode: the header's low four bits with the OPT
	// record's extended eight above them (RFC 6891 section 6.1.3). Reassembled
	// here because a server that forwards the low half and drops the high half
	// turns a BADVERS into a FORMERR, and only the joined value shows that.
	rcode:      u16,
	question:   []Pw_Question,
	answer:     []Pw_RR,
	authority:  []Pw_RR,
	// OPT removed; it is carried in `opt` instead, because it is message
	// metadata rather than a record and comparing it as one would report every
	// legitimate payload-size rewrite as a missing record.
	additional: []Pw_RR,
	opt:        Pw_Opt,
	// The counts the header declared, which is not always what the sections
	// turned out to hold.
	counts:     [4]u16,
}

/*
Walk a message into canonical form.

A message that does not walk comes back with `ok` false and `err` saying where
it stopped, which is itself a comparable fact: if one side parses and the other
does not, that is the finding.
*/
pw_parse :: proc(msg: []u8, allocator := context.temp_allocator) -> (out: Pw_Msg) {
	out.size = len(msg)
	if len(msg) < 12 {
		out.err = fmt.aprintf("short message: %d bytes", len(msg), allocator = allocator)
		return out
	}

	out.id = pw_u16(msg, 0)
	flags := pw_u16(msg, 2)
	out.qr = flags & 0x8000 != 0
	out.opcode = u8((flags >> 11) & 0xf)
	out.aa = flags & 0x0400 != 0
	out.tc = flags & 0x0200 != 0
	out.rd = flags & 0x0100 != 0
	out.ra = flags & 0x0080 != 0
	out.z = u8((flags >> 6) & 0x1)
	out.ad = flags & 0x0020 != 0
	out.cd = flags & 0x0010 != 0
	out.rcode = flags & 0x000f
	for i in 0 ..< 4 {
		out.counts[i] = pw_u16(msg, 4 + i * 2)
	}

	pos := 12
	questions := make([dynamic]Pw_Question, 0, int(out.counts[0]), allocator)
	for _ in 0 ..< int(out.counts[0]) {
		q: Pw_Question
		next: int
		name_ok: bool
		q.name, next, name_ok = pw_name(msg, pos, allocator)
		if !name_ok {
			out.err = fmt.aprintf("question name at %d does not decode", pos, allocator = allocator)
			return out
		}
		if next + 4 > len(msg) {
			out.err = fmt.aprintf("question at %d runs past the message", pos, allocator = allocator)
			return out
		}
		q.type = pw_u16(msg, next)
		q.class = pw_u16(msg, next + 2)
		append(&questions, q)
		pos = next + 4
	}
	out.question = questions[:]

	sections: [3][]Pw_RR
	for s in 0 ..< 3 {
		recs, next, sec_ok, why := pw_records(msg, pos, int(out.counts[s + 1]), allocator)
		if !sec_ok {
			out.err = why
			return out
		}
		sections[s] = recs
		pos = next
	}
	out.answer, out.authority = sections[0], sections[1]

	// The OPT record is lifted out of the additional section before anything
	// compares it, so a payload size the server is entitled to rewrite does not
	// read as one record replaced by another.
	kept := make([dynamic]Pw_RR, 0, len(sections[2]), allocator)
	for rec in sections[2] {
		if rec.type != 41 {
			append(&kept, rec)
			continue
		}
		if out.opt.present {
			out.opt.duplicate = true
			continue
		}
		out.opt = pw_opt(rec, allocator)
	}
	out.additional = kept[:]
	if out.opt.present {
		out.rcode |= u16(out.opt.ext_rcode) << 4
	}

	if pos != len(msg) {
		out.err = fmt.aprintf(
			"%d trailing bytes after the last record",
			len(msg) - pos,
			allocator = allocator,
		)
		return out
	}

	out.ok = true
	return out
}

@(private = "file")
pw_records :: proc(
	msg: []u8,
	start: int,
	count: int,
	allocator: mem.Allocator,
) -> (
	out: []Pw_RR,
	next: int,
	ok: bool,
	why: string,
) {
	recs := make([dynamic]Pw_RR, 0, count, allocator)
	pos := start
	for i in 0 ..< count {
		rec: Pw_RR
		after: int
		name_ok: bool
		rec.name, after, name_ok = pw_name(msg, pos, allocator)
		if !name_ok {
			return nil, 0, false, fmt.aprintf(
				"record %d: owner name at %d does not decode",
				i,
				pos,
				allocator = allocator,
			)
		}
		if after + 10 > len(msg) {
			return nil, 0, false, fmt.aprintf(
				"record %d: header runs past the message",
				i,
				allocator = allocator,
			)
		}
		rec.type = pw_u16(msg, after)
		rec.class = pw_u16(msg, after + 2)
		rec.ttl = pw_u32(msg, after + 4)
		rdlength := int(pw_u16(msg, after + 8))
		rd_start := after + 10
		if rd_start + rdlength > len(msg) {
			return nil, 0, false, fmt.aprintf(
				"record %d: rdlength %d runs past the message",
				i,
				rdlength,
				allocator = allocator,
			)
		}
		rec.rdata = pw_canonical_rdata(msg, rec.type, rd_start, rd_start + rdlength, allocator)
		append(&recs, rec)
		pos = rd_start + rdlength
	}
	return recs[:], pos, true, ""
}

/*
Read one name, following compression pointers, into uncompressed wire form.

`next` is the first byte after the name as it was written here, which for a
compressed name is two bytes on from where it started rather than wherever the
pointer led.
*/
pw_name :: proc(
	msg: []u8,
	start: int,
	allocator := context.temp_allocator,
) -> (
	name: []u8,
	next: int,
	ok: bool,
) {
	buf: [PW_MAX_NAME]u8
	n := 0
	pos := start
	jumps := 0
	next = -1

	for {
		if pos < 0 || pos >= len(msg) {
			return nil, 0, false
		}
		b := int(msg[pos])
		switch {
		case b & 0xc0 == 0xc0:
			if pos + 1 >= len(msg) {
				return nil, 0, false
			}
			target := ((b & 0x3f) << 8) | int(msg[pos + 1])
			if next < 0 {
				next = pos + 2
			}
			// Strictly backwards. A pointer that does not move towards the
			// start of the message is how a decompression loop is written, and
			// a jump budget alone would only make one expensive rather than
			// impossible.
			if target >= pos {
				return nil, 0, false
			}
			jumps += 1
			if jumps > PW_MAX_JUMPS {
				return nil, 0, false
			}
			pos = target

		case b & 0xc0 != 0:
			// 0x40 and 0x80 open label types nothing is allowed to send.
			return nil, 0, false

		case b == 0:
			if n + 1 > len(buf) {
				return nil, 0, false
			}
			buf[n] = 0
			n += 1
			if next < 0 {
				next = pos + 1
			}
			out := make([]u8, n, allocator)
			copy(out, buf[:n])
			return out, next, true

		case:
			if pos + 1 + b > len(msg) || n + 1 + b > len(buf) {
				return nil, 0, false
			}
			buf[n] = u8(b)
			copy(buf[n + 1:], msg[pos + 1:pos + 1 + b])
			n += 1 + b
			pos += 1 + b
		}
	}
}

/*
Where the domain names sit inside the RDATA of the types that may compress one.

The same layouts `src/dns/rdata_raw.odin` walks, and for the same reason: RFC
1035 section 4.1.4 lets these types point into the message around them, and a
blob holding a pointer means nothing once it has been copied somewhere else. Both
sides of a comparison are expanded here so that a message which carried a pointer
and a message which spelled the name out compare equal.

Kept in step with that table by hand. A type missing from this one would show up
as every record of it differing whenever either side re-encoded the message, so
the failure mode is noise rather than a silent pass.
*/
@(private = "file")
Pw_Layout :: struct {
	fixed:   int,
	strings: int,
	names:   int,
}

@(private = "file")
pw_layout :: proc(t: u16) -> (layout: Pw_Layout, ok: bool) {
	switch t {
	// NS, MD, MF, CNAME, MB, MG, MR, PTR, NSAP-PTR, NXT, DNAME
	case 2, 3, 4, 5, 7, 8, 9, 12, 23, 30, 39:
		return {0, 0, 1}, true
	// SOA, MINFO, RP
	case 6, 14, 17:
		return {0, 0, 2}, true
	// MX, AFSDB, RT, KX
	case 15, 18, 21, 36:
		return {2, 0, 1}, true
	// PX
	case 26:
		return {2, 0, 2}, true
	// NAPTR
	case 35:
		return {4, 3, 1}, true
	// SRV
	case 33:
		return {6, 0, 1}, true
	// SIG
	case 24:
		return {18, 0, 1}, true
	}
	return {}, false
}

/*
Copy the RDATA at `msg[start:end]`, expanding any compressed name in it.

Never fails. RDATA that does not walk - too short for its own layout, a name
that will not decode or that runs past the record - is copied exactly as it
arrived, which is what elodin's decoder does with the same bytes and what leaves
a record nobody here understands still comparable to itself.
*/
@(private = "file")
pw_canonical_rdata :: proc(
	msg: []u8,
	type: u16,
	start, end: int,
	allocator: mem.Allocator,
) -> []u8 {
	verbatim :: proc(msg: []u8, start, end: int, allocator: mem.Allocator) -> []u8 {
		out := make([]u8, end - start, allocator)
		copy(out, msg[start:end])
		return out
	}

	layout, known := pw_layout(type)
	if !known {
		return verbatim(msg, start, end, allocator)
	}

	buf := make([dynamic]u8, 0, end - start + PW_MAX_NAME, allocator)
	pos := start
	if pos + layout.fixed > end {
		return verbatim(msg, start, end, allocator)
	}
	append(&buf, ..msg[pos:pos + layout.fixed])
	pos += layout.fixed

	for _ in 0 ..< layout.strings {
		if pos >= end {
			return verbatim(msg, start, end, allocator)
		}
		n := int(msg[pos])
		if pos + 1 + n > end {
			return verbatim(msg, start, end, allocator)
		}
		append(&buf, ..msg[pos:pos + 1 + n])
		pos += 1 + n
	}

	for _ in 0 ..< layout.names {
		name, next, ok := pw_name(msg, pos, allocator)
		// A pointer may aim outside the record - that is the point of one - but
		// the name's own bytes have to lie inside it.
		if !ok || next > end {
			return verbatim(msg, start, end, allocator)
		}
		append(&buf, ..name)
		pos = next
	}

	append(&buf, ..msg[pos:end])
	if len(buf) > 0xffff {
		return verbatim(msg, start, end, allocator)
	}
	return buf[:]
}

@(private = "file")
pw_opt :: proc(rec: Pw_RR, allocator: mem.Allocator) -> (opt: Pw_Opt) {
	opt.present = true
	opt.root = len(rec.name) == 1 && rec.name[0] == 0
	opt.udp_size = rec.class
	opt.ext_rcode = u8(rec.ttl >> 24)
	opt.version = u8((rec.ttl >> 16) & 0xff)
	opt.flags = u16(rec.ttl & 0xffff)

	options := make([dynamic]Pw_Option, 0, 4, allocator)
	pos := 0
	for pos < len(rec.rdata) {
		if pos + 4 > len(rec.rdata) {
			opt.malformed = true
			break
		}
		code := pw_u16(rec.rdata, pos)
		length := int(pw_u16(rec.rdata, pos + 2))
		if pos + 4 + length > len(rec.rdata) {
			opt.malformed = true
			break
		}
		data := make([]u8, length, allocator)
		copy(data, rec.rdata[pos + 4:pos + 4 + length])
		append(&options, Pw_Option{code = code, data = data})
		pos += 4 + length
	}
	opt.options = options[:]
	return opt
}

/*
How many bytes this message's OPT record occupies on the wire.

Zero when it has none. A root owner name is one byte, then the type, the class
carrying the payload size, the four TTL bytes and the RDATA length - eleven
before the option list itself.
*/
pw_opt_wire_len :: proc(m: Pw_Msg) -> int {
	if !m.opt.present {
		return 0
	}
	n := 1 + 2 + 2 + 4 + 2
	for o in m.opt.options {
		n += 4 + len(o.data)
	}
	return n
}

pw_do :: proc(m: Pw_Msg) -> bool {
	return m.opt.present && m.opt.flags & PW_DO != 0
}

pw_find_option :: proc(m: Pw_Msg, code: u16) -> (data: []u8, found: bool) {
	for o in m.opt.options {
		if o.code == code {
			return o.data, true
		}
	}
	return nil, false
}

// --- rendering -------------------------------------------------------------

/*
A name as text, with anything outside the printable set escaped.

Only ever shown to a human reading a failure; comparisons work on the wire form,
so no two distinct names need to render distinctly for correctness. They do
anyway - the escaping is reversible - which is what makes a reported difference
worth acting on.
*/
pw_name_text :: proc(name: []u8, allocator := context.temp_allocator) -> string {
	if len(name) == 0 {
		return "<empty>"
	}
	sb := strings.builder_make(allocator)
	pos := 0
	for pos < len(name) {
		n := int(name[pos])
		if n == 0 {
			break
		}
		if pos + 1 + n > len(name) {
			strings.write_string(&sb, "<truncated>")
			break
		}
		for c in name[pos + 1:pos + 1 + n] {
			switch {
			case c == '.' || c == '\\':
				strings.write_byte(&sb, '\\')
				strings.write_byte(&sb, c)
			case c < 0x21 || c > 0x7e:
				fmt.sbprintf(&sb, "\\%03d", c)
			case:
				strings.write_byte(&sb, c)
			}
		}
		strings.write_byte(&sb, '.')
		pos += 1 + n
	}
	if strings.builder_len(sb) == 0 {
		return "."
	}
	return strings.to_string(sb)
}

/*
One record as a single comparable line, case and all.

Case is kept because losing it here would hide a real class of change: a
resolver that re-encodes a message compresses names against earlier ones, and
compression matches without regard to case (RFC 1035 section 4.1.4), so a name
can come back spelled in the case of whatever it was compressed against. That is
legal and it is still not what the upstream sent. `pw_rr_key_folded` is the same
line with the case taken out, and the comparison uses the two together: an exact
match is agreement, a folded-only match is a case change with a name, and no
match at all is a failure.
*/
pw_rr_key :: proc(rec: Pw_RR, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	fmt.sbprintf(
		&sb,
		"%s %d %d %d ",
		pw_name_text(rec.name, allocator),
		rec.class,
		rec.type,
		rec.ttl,
	)
	for b in rec.rdata {
		fmt.sbprintf(&sb, "%02x", b)
	}
	return strings.to_string(sb)
}

// The same line with the owner name and every name inside the RDATA lowercased.
pw_rr_key_folded :: proc(rec: Pw_RR, allocator := context.temp_allocator) -> string {
	folded := rec
	folded.name = make([]u8, len(rec.name), allocator)
	copy(folded.name, rec.name)
	pw_lower_name(folded.name)
	folded.rdata = pw_fold_rdata_names(rec.type, rec.rdata, allocator)
	return pw_rr_key(folded, allocator)
}

pw_rr_key_folded_no_ttl :: proc(rec: Pw_RR, allocator := context.temp_allocator) -> string {
	stripped := rec
	stripped.ttl = 0
	return pw_rr_key_folded(stripped, allocator)
}

/*
A copy of canonical RDATA with the domain names inside it lowercased.

Only the types `pw_layout` knows, which is the whole set that can have the
problem: a name can only come back in somebody else's case if it was compressed,
and only these types may compress one. Anything else is returned as it stands.
*/
@(private = "file")
pw_fold_rdata_names :: proc(type: u16, rdata: []u8, allocator: mem.Allocator) -> []u8 {
	layout, known := pw_layout(type)
	if !known {
		return rdata
	}
	out := make([]u8, len(rdata), allocator)
	copy(out, rdata)

	pos := layout.fixed
	if pos > len(out) {
		return out
	}
	for _ in 0 ..< layout.strings {
		if pos >= len(out) {
			return out
		}
		n := int(out[pos])
		if pos + 1 + n > len(out) {
			return out
		}
		pos += 1 + n
	}
	for _ in 0 ..< layout.names {
		if pos >= len(out) {
			return out
		}
		pw_lower_name(out[pos:])
		// Step over the name this just lowered. Canonical RDATA holds no
		// pointers, so the walk is label by label to the root.
		for pos < len(out) {
			n := int(out[pos])
			if n == 0 {
				pos += 1
				break
			}
			if pos + 1 + n > len(out) {
				return out
			}
			pos += 1 + n
		}
	}
	return out
}

// The same line without the TTL, for the comparisons that hold a TTL to a range
// rather than to a value.
pw_rr_key_no_ttl :: proc(rec: Pw_RR, allocator := context.temp_allocator) -> string {
	stripped := rec
	stripped.ttl = 0
	return pw_rr_key(stripped, allocator)
}

/*
Lowercase the label bytes of a wire-form name in place.

Only A-Z, per RFC 4034 section 6.2: a byte above 0x7f is not a letter to DNS,
whatever locale is in force.
*/
pw_lower_name :: proc(name: []u8) {
	pos := 0
	for pos < len(name) {
		n := int(name[pos])
		if n == 0 || pos + 1 + n > len(name) {
			return
		}
		for i in pos + 1 ..< pos + 1 + n {
			if name[i] >= 'A' && name[i] <= 'Z' {
				name[i] += 32
			}
		}
		pos += 1 + n
	}
}

pw_names_equal_fold :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

/*
A section as a sorted multiset of record lines, which is what makes two answers
that list the same records in a different order compare equal.

Folded, because the one caller is the live mode asking whether a resolver gave
the same answer twice, and two answers differing only in the case of a
compressed name are the same answer for that purpose.
*/
pw_section_keys :: proc(recs: []Pw_RR, allocator := context.temp_allocator) -> []string {
	keys := make([]string, len(recs), allocator)
	for rec, i in recs {
		keys[i] = pw_rr_key_folded(rec, allocator)
	}
	slice.sort(keys)
	return keys
}

@(private = "file")
pw_u16 :: proc(b: []u8, off: int) -> u16 {
	return u16(b[off]) << 8 | u16(b[off + 1])
}

@(private = "file")
pw_u32 :: proc(b: []u8, off: int) -> u32 {
	return u32(b[off]) << 24 | u32(b[off + 1]) << 16 | u32(b[off + 2]) << 8 | u32(b[off + 3])
}
