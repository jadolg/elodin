package dns

import "core:mem"

Decode_Error :: enum u8 {
	None,
	Short_Buffer,
	Bad_Pointer,
	Bad_Label,
	Name_Too_Long,
	Loop_Detected,
	Bad_Rdata,
	Truncated_Header,
}

Encode_Error :: enum u8 {
	None,
	Buffer_Too_Small,
	Bad_Escape,
	Bad_Name,
	Label_Too_Long,
	Name_Too_Long,
	Too_Large,
	Bad_Rdata,
}

@(private)
Reader :: struct {
	msg: []u8,
	pos: int,
}

@(private)
r_u8 :: proc(r: ^Reader) -> (v: u8, err: Decode_Error) {
	if r.pos + 1 > len(r.msg) {
		return 0, .Short_Buffer
	}
	v = r.msg[r.pos]
	r.pos += 1
	return
}

@(private)
r_u16 :: proc(r: ^Reader) -> (v: u16, err: Decode_Error) {
	if r.pos + 2 > len(r.msg) {
		return 0, .Short_Buffer
	}
	v = u16(r.msg[r.pos]) << 8 | u16(r.msg[r.pos + 1])
	r.pos += 2
	return
}

@(private)
r_u32 :: proc(r: ^Reader) -> (v: u32, err: Decode_Error) {
	if r.pos + 4 > len(r.msg) {
		return 0, .Short_Buffer
	}
	v =
		u32(r.msg[r.pos]) << 24 |
		u32(r.msg[r.pos + 1]) << 16 |
		u32(r.msg[r.pos + 2]) << 8 |
		u32(r.msg[r.pos + 3])
	r.pos += 4
	return
}

@(private)
r_bytes :: proc(r: ^Reader, n: int, allocator: mem.Allocator) -> (v: []u8, err: Decode_Error) {
	if n < 0 || r.pos + n > len(r.msg) {
		return nil, .Short_Buffer
	}
	v = make([]u8, n, allocator)
	copy(v, r.msg[r.pos:r.pos + n])
	r.pos += n
	return
}

@(private)
r_name :: proc(r: ^Reader, allocator: mem.Allocator) -> (name: string, err: Decode_Error) {
	next: int
	name, next, err = decode_name(r.msg, r.pos, allocator)
	if err != .None {
		return
	}
	r.pos = next
	return
}

// A <character-string>: one length byte followed by that many raw bytes.
@(private)
r_char_string :: proc(r: ^Reader, allocator: mem.Allocator) -> (s: string, err: Decode_Error) {
	n := r_u8(r) or_return
	b := r_bytes(r, int(n), allocator) or_return
	return string(b), .None
}

/*
Decode a complete DNS message.

Every string and slice in the result is allocated from `allocator`; callers that
serve a single query are expected to hand in an arena and drop it wholesale.
*/
decode_message :: proc(msg: []u8, allocator := context.allocator) -> (m: Message, err: Decode_Error) {
	if len(msg) < HEADER_SIZE {
		return {}, .Truncated_Header
	}
	r := Reader{msg = msg}

	m.id = r_u16(&r) or_return
	m.flags = transmute(Flags)(r_u16(&r) or_return)
	qdcount := r_u16(&r) or_return
	ancount := r_u16(&r) or_return
	nscount := r_u16(&r) or_return
	arcount := r_u16(&r) or_return

	// A record needs at least 11 bytes on the wire (root name + fixed fields),
	// a question at least 5. Reject counts that cannot possibly fit so a tiny
	// hostile datagram cannot make us allocate 64k records.
	remaining := len(msg) - HEADER_SIZE
	if int(qdcount) * 5 + (int(ancount) + int(nscount) + int(arcount)) * 11 > remaining {
		return {}, .Short_Buffer
	}

	if qdcount > 0 {
		qs := make([]Question, int(qdcount), allocator)
		for i in 0 ..< int(qdcount) {
			qs[i].name = r_name(&r, allocator) or_return
			qs[i].type = Type(r_u16(&r) or_return)
			qs[i].class = Class(r_u16(&r) or_return)
		}
		m.question = qs
	}

	m.answer = decode_records(&r, int(ancount), allocator) or_return
	m.authority = decode_records(&r, int(nscount), allocator) or_return
	m.additional = decode_records(&r, int(arcount), allocator) or_return
	return
}

@(private)
decode_records :: proc(r: ^Reader, count: int, allocator: mem.Allocator) -> (out: []Record, err: Decode_Error) {
	if count == 0 {
		return nil, .None
	}
	recs := make([]Record, count, allocator)
	for i in 0 ..< count {
		recs[i] = decode_record(r, allocator) or_return
	}
	return recs, .None
}

@(private)
decode_record :: proc(r: ^Reader, allocator: mem.Allocator) -> (rec: Record, err: Decode_Error) {
	rec.name = r_name(r, allocator) or_return
	rec.type = Type(r_u16(r) or_return)
	rec.class = Class(r_u16(r) or_return)
	rec.ttl = r_u32(r) or_return
	rdlength := int(r_u16(r) or_return)

	if r.pos + rdlength > len(r.msg) {
		return {}, .Short_Buffer
	}
	rdata_start := r.pos
	rdata_end := r.pos + rdlength

	rec.data, err = decode_rdata(r, rec.type, rdata_start, rdata_end, allocator)
	if err != .None {
		// Malformed or unrecognised RDATA is preserved rather than rejected, so
		// odd records still survive a forward. Compressed names in it are still
		// expanded where they can be: a type this decoder does model can fail on
		// something else entirely - a trailing byte, a length that disagrees -
		// and come through here with a perfectly good pointer inside it.
		rec.data = decode_raw_rdata(r.msg, rec.type, rdata_start, rdata_end, allocator)
		err = .None
	}
	r.pos = rdata_end
	return
}

@(private)
decode_rdata :: proc(
	r: ^Reader,
	type: Type,
	start, end: int,
	allocator: mem.Allocator,
) -> (
	data: Record_Data,
	err: Decode_Error,
) {
	r.pos = start
	n := end - start

	#partial switch type {
	case .A:
		if n != 4 {
			return nil, .Bad_Rdata
		}
		v: Rdata_A
		copy(v.addr[:], r.msg[start:end])
		return v, .None

	case .AAAA:
		if n != 16 {
			return nil, .Bad_Rdata
		}
		v: Rdata_AAAA
		copy(v.addr[:], r.msg[start:end])
		return v, .None

	case .NS, .CNAME, .PTR, .DNAME, .MB, .MG, .MR, .NSAP_PTR:
		name := r_name(r, allocator) or_return
		return Rdata_Name{name = name}, .None

	case .SOA:
		v: Rdata_SOA
		v.ns = r_name(r, allocator) or_return
		v.mbox = r_name(r, allocator) or_return
		v.serial = r_u32(r) or_return
		v.refresh = r_u32(r) or_return
		v.retry = r_u32(r) or_return
		v.expire = r_u32(r) or_return
		v.minimum = r_u32(r) or_return
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return v, .None

	case .MX:
		v: Rdata_MX
		v.preference = r_u16(r) or_return
		v.exchange = r_name(r, allocator) or_return
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return v, .None

	case .TXT, .SPF:
		parts := make([dynamic]string, 0, 2, allocator)
		for r.pos < end {
			s := r_char_string(r, allocator) or_return
			append(&parts, s)
		}
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return Rdata_TXT{strings = parts[:]}, .None

	case .SRV:
		v: Rdata_SRV
		v.priority = r_u16(r) or_return
		v.weight = r_u16(r) or_return
		v.port = r_u16(r) or_return
		v.target = r_name(r, allocator) or_return
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return v, .None

	case .CAA:
		v: Rdata_CAA
		v.flags = r_u8(r) or_return
		tag_len := int(r_u8(r) or_return)
		tag := r_bytes(r, tag_len, allocator) or_return
		v.tag = string(tag)
		if r.pos > end {
			return nil, .Bad_Rdata
		}
		val := r_bytes(r, end - r.pos, allocator) or_return
		v.value = string(val)
		return v, .None

	case .SVCB, .HTTPS:
		v: Rdata_SVCB
		v.priority = r_u16(r) or_return
		v.target = r_name(r, allocator) or_return
		if r.pos > end {
			return nil, .Bad_Rdata
		}
		v.params = r_bytes(r, end - r.pos, allocator) or_return
		return v, .None

	case .OPT:
		opts := make([dynamic]EDNS_Option, 0, 2, allocator)
		for r.pos + 4 <= end {
			code := r_u16(r) or_return
			olen := int(r_u16(r) or_return)
			if r.pos + olen > end {
				return nil, .Bad_Rdata
			}
			odata := r_bytes(r, olen, allocator) or_return
			append(&opts, EDNS_Option{code = code, data = odata})
		}
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return Rdata_OPT{options = opts[:]}, .None
	}

	return decode_raw_rdata(r.msg, type, start, end, allocator), .None
}

// Cheap header peek for paths that only need the ID or the QR bit and do not
// want to pay for a full parse.
peek_id :: proc(msg: []u8) -> (id: u16, ok: bool) {
	if len(msg) < 2 {
		return 0, false
	}
	return u16(msg[0]) << 8 | u16(msg[1]), true
}

set_id_in_place :: proc(msg: []u8, id: u16) {
	if len(msg) >= 2 {
		msg[0] = u8(id >> 8)
		msg[1] = u8(id)
	}
}

// Extracts the first question without decoding the rest of the message.
peek_question :: proc(msg: []u8, allocator := context.allocator) -> (q: Question, ok: bool) {
	if len(msg) < HEADER_SIZE {
		return {}, false
	}
	qdcount := u16(msg[4]) << 8 | u16(msg[5])
	if qdcount == 0 {
		return {}, false
	}
	r := Reader{msg = msg, pos = HEADER_SIZE}
	name, err := r_name(&r, allocator)
	if err != .None {
		return {}, false
	}
	t, terr := r_u16(&r)
	if terr != .None {
		return {}, false
	}
	c, cerr := r_u16(&r)
	if cerr != .None {
		return {}, false
	}
	return Question{name = name, type = Type(t), class = Class(c)}, true
}
