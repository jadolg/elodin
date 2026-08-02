package dns

find_opt :: proc(m: Message) -> (opt: Record, found: bool) {
	for rec in m.additional {
		if rec.type == .OPT {
			return rec, true
		}
	}
	return {}, false
}

// The requester's advertised UDP payload size. Without EDNS0 it is 512.
edns_udp_size :: proc(m: Message) -> u16 {
	opt, found := find_opt(m)
	if !found {
		return MAX_UDP_SIZE
	}
	size := u16(opt.class)
	return clamp(size, MAX_UDP_SIZE, 4096)
}

edns_present :: proc(m: Message) -> bool {
	_, found := find_opt(m)
	return found
}

// DO bit lives in the top bit of the OPT record's 32-bit TTL field.
edns_do :: proc(m: Message) -> bool {
	opt, found := find_opt(m)
	if !found {
		return false
	}
	return opt.ttl & 0x0000_8000 != 0
}

make_opt :: proc(udp_size: u16, do_bit: bool, ext_rcode: u8 = 0) -> Record {
	ttl := u32(ext_rcode) << 24
	if do_bit {
		ttl |= 0x0000_8000
	}
	return Record{name = ".", type = .OPT, class = Class(udp_size), ttl = ttl}
}

/*
Build a response skeleton mirroring `query`: same ID and question, QR set, RD
copied, RA set, and an OPT record echoed back when the query carried one.
*/
make_response :: proc(query: Message, rcode: Rcode, allocator := context.allocator) -> Message {
	resp: Message
	resp.id = query.id
	resp.flags.qr = true
	resp.flags.opcode = query.flags.opcode
	resp.flags.rd = query.flags.rd
	resp.flags.ra = true
	resp.flags.cd = query.flags.cd
	resp.flags.rcode = u8(rcode) & 0xf
	resp.question = query.question

	if _, found := find_opt(query); found {
		add := make([]Record, 1, allocator)
		add[0] = make_opt(edns_udp_size(query), edns_do(query), u8(u16(rcode) >> 4))
		resp.additional = add
	}
	return resp
}

/*
Encode a bare error response for a query we could not or would not answer.

Falls back to patching the request's own header in place when the query cannot
be parsed, which is the only way to answer a malformed datagram at all.
*/
error_response :: proc(
	query_bytes: []u8,
	query: Message,
	rcode: Rcode,
	allocator := context.allocator,
	max_size := MAX_UDP_SIZE,
) -> (
	out: []u8,
	ok: bool,
) {
	resp := make_response(query, rcode, allocator)
	bytes, _, err := encode_message(resp, allocator, max_size)
	if err == .None {
		return bytes, true
	}

	if len(query_bytes) < HEADER_SIZE {
		return nil, false
	}
	buf := make([]u8, HEADER_SIZE, allocator)
	copy(buf, query_bytes[:HEADER_SIZE])
	flags := transmute(Flags)(u16(buf[2]) << 8 | u16(buf[3]))
	flags.qr = true
	flags.ra = true
	flags.tc = false
	flags.rcode = u8(rcode) & 0xf
	fv := transmute(u16)flags
	buf[2] = u8(fv >> 8)
	buf[3] = u8(fv)
	// Drop every section count; the sections themselves are not copied.
	for i in 4 ..< HEADER_SIZE {
		buf[i] = 0
	}
	return buf, true
}

@(private)
skip_name :: proc(msg: []u8, pos: int) -> (next: int, ok: bool) {
	p := pos
	for {
		if p >= len(msg) {
			return 0, false
		}
		n := msg[p]
		switch n & 0xc0 {
		case 0x00:
			if n == 0 {
				return p + 1, true
			}
			p += 1 + int(n)
		case 0xc0:
			if p + 1 >= len(msg) {
				return 0, false
			}
			return p + 2, true
		case:
			return 0, false
		}
	}
}

/*
Locate every TTL field in a message.

Used by the cache, which stores upstream answers as untouched wire bytes and
rewrites the TTLs on each hit. That keeps the original name compression intact
instead of round-tripping through the decoder. OPT records are skipped: their
"TTL" is really the extended rcode and flags.
*/
scan_ttl_offsets :: proc(msg: []u8, allocator := context.allocator) -> (offsets: []int, ok: bool) {
	if len(msg) < HEADER_SIZE {
		return nil, false
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	total := int(u16(msg[6]) << 8 | u16(msg[7]))
	total += int(u16(msg[8]) << 8 | u16(msg[9]))
	total += int(u16(msg[10]) << 8 | u16(msg[11]))

	pos := HEADER_SIZE
	for _ in 0 ..< qdcount {
		pos = skip_name(msg, pos) or_return
		pos += 4
		if pos > len(msg) {
			return nil, false
		}
	}

	out := make([dynamic]int, 0, total, allocator)
	for _ in 0 ..< total {
		next, name_ok := skip_name(msg, pos)
		if !name_ok {
			delete(out)
			return nil, false
		}
		pos = next
		if pos + 10 > len(msg) {
			delete(out)
			return nil, false
		}
		rtype := Type(u16(msg[pos]) << 8 | u16(msg[pos + 1]))
		if rtype != .OPT {
			append(&out, pos + 4)
		}
		rdlength := int(u16(msg[pos + 8]) << 8 | u16(msg[pos + 9]))
		pos += 10 + rdlength
		if pos > len(msg) {
			delete(out)
			return nil, false
		}
	}
	return out[:], true
}

/*
The EDNS0 payload size a message advertises, read off the wire.

Answers the question a sender has to answer before it can size a receive buffer:
how large may the reply to this be? Returns MAX_UDP_SIZE when there is no OPT
record, or when the message cannot be walked — the 512 bytes RFC 1035 says a
responder must assume without being told otherwise.

Distinct from `edns_udp_size`, which clamps into the range this server is
willing to *send*; this reports what the message actually said.
*/
peek_udp_size :: proc(msg: []u8) -> u16 {
	if len(msg) < HEADER_SIZE {
		return MAX_UDP_SIZE
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	total := int(u16(msg[6]) << 8 | u16(msg[7]))
	total += int(u16(msg[8]) << 8 | u16(msg[9]))
	total += int(u16(msg[10]) << 8 | u16(msg[11]))

	pos := HEADER_SIZE
	for _ in 0 ..< qdcount {
		next, ok := skip_name(msg, pos)
		if !ok {
			return MAX_UDP_SIZE
		}
		pos = next + 4
		if pos > len(msg) {
			return MAX_UDP_SIZE
		}
	}
	for _ in 0 ..< total {
		next, ok := skip_name(msg, pos)
		if !ok {
			return MAX_UDP_SIZE
		}
		pos = next
		if pos + 10 > len(msg) {
			return MAX_UDP_SIZE
		}
		// OPT carries the payload size where every other type carries its class.
		if Type(u16(msg[pos]) << 8 | u16(msg[pos + 1])) == .OPT {
			return u16(msg[pos + 2]) << 8 | u16(msg[pos + 3])
		}
		rdlength := int(u16(msg[pos + 8]) << 8 | u16(msg[pos + 9]))
		pos += 10 + rdlength
		if pos > len(msg) {
			return MAX_UDP_SIZE
		}
	}
	return MAX_UDP_SIZE
}

read_ttls :: proc(msg: []u8, offsets: []int, allocator := context.allocator) -> []u32 {
	ttls := make([]u32, len(offsets), allocator)
	for off, i in offsets {
		ttls[i] =
			u32(msg[off]) << 24 |
			u32(msg[off + 1]) << 16 |
			u32(msg[off + 2]) << 8 |
			u32(msg[off + 3])
	}
	return ttls
}

// Rewrites each TTL to `original - elapsed`, floored at `floor_ttl`.
patch_ttls :: proc(msg: []u8, offsets: []int, originals: []u32, elapsed: u32, floor_ttl: u32 = 0) {
	for off, i in offsets {
		if off + 4 > len(msg) || i >= len(originals) {
			break
		}
		v := originals[i]
		v = v - elapsed if v > elapsed else floor_ttl
		if v < floor_ttl {
			v = floor_ttl
		}
		msg[off] = u8(v >> 24)
		msg[off + 1] = u8(v >> 16)
		msg[off + 2] = u8(v >> 8)
		msg[off + 3] = u8(v)
	}
}

min_ttl :: proc(ttls: []u32) -> (v: u32, ok: bool) {
	if len(ttls) == 0 {
		return 0, false
	}
	v = max(u32)
	for t in ttls {
		v = min(v, t)
	}
	return v, true
}

// TTL to cache a negative answer for: the SOA MINIMUM capped by the SOA TTL
// (RFC 2308). Falls back to `fallback` when no SOA is present.
negative_ttl :: proc(m: Message, fallback: u32) -> u32 {
	for rec in m.authority {
		if soa, is_soa := rec.data.(Rdata_SOA); is_soa {
			return min(soa.minimum, rec.ttl)
		}
	}
	return fallback
}

set_rcode :: proc(m: ^Message, rcode: Rcode) {
	m.flags.rcode = u8(rcode) & 0xf
}

rcode_of :: proc(m: Message) -> Rcode {
	base := u16(m.flags.rcode)
	if opt, found := find_opt(m); found {
		base |= u16(opt.ttl >> 24) << 4
	}
	return Rcode(base)
}

/*
Copy the question name's byte case from `query` into `resp`.

A cached answer may have been stored for a differently-cased spelling of the
same name. Clients that use 0x20 randomisation check that the echoed question
matches theirs byte for byte, so the stored copy is re-cased before it goes out.
Question names are never compressed, so both encodings have identical lengths.
*/
copy_question_case :: proc(resp: []u8, query: []u8) {
	if len(resp) < HEADER_SIZE || len(query) < HEADER_SIZE {
		return
	}
	if resp[4] == 0 && resp[5] == 0 {
		return
	}
	q_end, q_ok := skip_name(query, HEADER_SIZE)
	r_end, r_ok := skip_name(resp, HEADER_SIZE)
	if !q_ok || !r_ok {
		return
	}
	if q_end - HEADER_SIZE != r_end - HEADER_SIZE {
		return
	}
	copy(resp[HEADER_SIZE:r_end], query[HEADER_SIZE:q_end])
}

clone_message_bytes :: proc(src: []u8, allocator := context.allocator) -> []u8 {
	dst := make([]u8, len(src), allocator)
	copy(dst, src)
	return dst
}
