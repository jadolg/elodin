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

/*
The EDNS version the requestor asked in, from the second byte of the OPT
record's TTL.

RFC 6891 section 6.1.3 divides that 32-bit field into an extended rcode, this
version number, and sixteen flag bits of which DO is the top one. The three are
windows onto one number, and until this one was cut only the two at either end
of it were ever looked through - so a request asking in a version this server
does not implement was indistinguishable from one asking in version 0, and got
an answer in a version nobody had agreed on.

A message with no OPT record asked in no version at all, and zero is the right
answer for it: a requestor that never mentioned EDNS is asking for something
this server can answer, which is what a caller comparing against the version it
implements needs to hear.
*/
edns_version :: proc(m: Message) -> u8 {
	opt, found := find_opt(m)
	if !found {
		return 0
	}
	return u8(opt.ttl >> 16)
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

RA is answered per RFC 1035 section 4.1.1: whether this server supports
recursive service at all, not whether this particular query got any. A query
refused for arriving with RD=0 still gets RA=1 back - the same way BIND and
Unbound keep answering RA=1 to a query an ACL declines to recurse for. The
capability is on offer; this request just did not use it.
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
The smallest complete answer there is: the question back, with TC set.

Thirty-odd bytes for a query of the same size, so it is no use to anyone
reflecting traffic off this server, and it says the one thing a rate-limited
client needs to hear - ask again over TCP, where a handshake proves the address
the answer would go to. A datagram source cannot do that, which is the point.

Built from the query's own bytes rather than from a decoded message: this runs
on the read loop while a flood is in progress, and decoding is work the flood
would be paying us to do. The question is copied only if it is there and
uncompressed - a pointer in a question is not legal and not worth echoing - and
otherwise the answer is the header alone, which a client still reads as TC.
*/
truncated_response :: proc(query_bytes: []u8, allocator := context.allocator) -> (out: []u8, ok: bool) {
	if len(query_bytes) < HEADER_SIZE {
		return nil, false
	}

	end := HEADER_SIZE
	questions: u16 = 0
	if query_bytes[4] == 0 && query_bytes[5] == 1 {
		p := HEADER_SIZE
		for p < len(query_bytes) {
			n := int(query_bytes[p])
			if n & 0xc0 != 0 {
				// A pointer, or a reserved label type. Neither belongs here.
				p = -1
				break
			}
			p += 1 + n
			if n == 0 {
				break
			}
		}
		if p >= 0 && p + 4 <= len(query_bytes) {
			end = p + 4
			questions = 1
		}
	}

	buf := make([]u8, end, allocator)
	copy(buf, query_bytes[:end])
	flags := transmute(Flags)(u16(buf[2]) << 8 | u16(buf[3]))
	flags.qr = true
	flags.ra = true
	flags.tc = true
	// As in `error_response`: every bit here started as the client's, and AD
	// coming back set would read as this server vouching for something.
	flags.ad = false
	flags.rcode = 0
	fv := transmute(u16)flags
	buf[2] = u8(fv >> 8)
	buf[3] = u8(fv)
	buf[4], buf[5] = u8(questions >> 8), u8(questions)
	// No answer, authority or additional sections, so nothing counts them.
	for i in 6 ..< HEADER_SIZE {
		buf[i] = 0
	}
	return buf, true
}

/*
Encode a bare error response for a query we could not or would not answer.

Falls back to patching the request's own header when there is no decoded query
to build from, which is the only way to answer a malformed datagram at all.
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
	/*
	A query that did not decode arrives here as an empty message, and an empty
	message encodes perfectly well - into twelve bytes carrying id zero and no
	question. Taking that as success is what left the fallback below unreachable
	and sent malformed queries a reply their client had no way to recognise: a
	stub matches on the transaction ID, so what came back was dropped as
	unsolicited and the query waited out its full timeout.

	So the decision is made on whether there is anything to build from, not on
	whether the encoder objected.

	An extended rcode is the third thing there is to build from. Its top bits
	live in an OPT record and nowhere else, so the fallback below - twelve bytes
	and no additional section - cannot carry one: BADVERS would go back as
	NOERROR and BADCOOKIE as YXRRSET, which is a weaker answer than the refusal
	meant, and in BADVERS' case is this server agreeing to a version it cannot
	speak. A query that carries an OPT record is enough to answer from, whatever
	else it left out - `make_response` echoes that record and puts the top bits
	in it.
	*/
	usable := len(query.question) > 0 || query.id != 0 || (u16(rcode) > 0xf && edns_present(query))
	if usable {
		resp := make_response(query, rcode, allocator)
		bytes, _, err := encode_message(resp, allocator, max_size)
		if err == .None {
			return bytes, true
		}
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
	// Built out of the query's own header, so every bit in it started as the
	// client's. AD is the one that must not survive the round trip: coming back
	// set, it would read as this server vouching for a message it could not
	// even parse.
	flags.ad = false
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

	/*
	Counts that cannot possibly fit are refused before `total` is spent as a
	capacity: a question needs at least 5 bytes on the wire and a record at
	least 11 - a root name plus the fixed fields - which is the same arithmetic
	`decode_message` makes, for the same reason.

	Kept although every caller now reaches here behind a decode: `cache.put` is
	the only one, and `resolve_query` decodes a response before it offers it, so
	a datagram with impossible counts is turned away one step earlier. This
	guard was added when `cap_ttls` walked undecoded bytes through here and a
	17-byte reply claiming three sections of 65535 records made it allocate
	1.5 MB for a walk that then failed on the first name. `cap_ttls` allocates
	nothing and does its own walk now, so that route is gone - but the capacity
	is still spent on counts a caller supplies, and a guard that costs one
	comparison is not worth removing for a caller that might not always decode
	first.
	*/
	remaining := len(msg) - HEADER_SIZE
	if qdcount * 5 + total * 11 > remaining {
		return nil, false
	}

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

/*
The largest TTL a message may carry.

The field is 32 bits wide on the wire, but RFC 2181 section 8 narrows the value
to an unsigned 31-bit number: the top bit is not part of it. Doubles as the "no
ceiling" argument to `cap_ttls`, since no TTL that has been through `sane_ttl`
is above it.
*/
TTL_MAX :: u32(0x7fff_ffff)

/*
A TTL as this server is willing to read it, per RFC 2181 section 8:

	Implementations should treat TTL values received with the most significant
	bit set as if the entire value received was zero.

Zero rather than the low 31 bits, which is what the RFC asks for and is the only
reading that is safe to act on anyway. A sender that sets the top bit is either
getting the field wrong or nailing the record into every cache below it for the
life of the machine - 2^31 seconds is sixty-eight years - and nothing else in
the message tells the two apart. Zero says "use this for the query in hand and
come back", which is the right answer to both.

Applied where a TTL is acted on rather than in `decode_message`, which goes on
reporting the field as it stands: a decoded message is also what the DNSSEC
validator and the query log read, and those want to see what arrived.
*/
sane_ttl :: proc(v: u32) -> u32 {
	return 0 if v > TTL_MAX else v
}

/*
The TTL field at `off`, read and written as the four big-endian bytes it is.

One spelling of the pair, because four places move a TTL in and out of a message
in place - `read_ttls`, `cap_ttls`, `patch_ttls` and the cache's stale branch -
and arithmetic typed out four times is arithmetic that can be typed wrong once.

Neither bounds-checks. Every offset in play was established to be inside the
message before it was handed over - by `scan_ttl_offsets` for the cache's
callers, and by `cap_ttls`'s own walk for that one - so a check here would be
dead in every caller; Odin's own bounds checks stay on in release builds and
catch a caller that invents one.
*/
read_ttl_at :: proc(msg: []u8, off: int) -> u32 {
	return u32(msg[off]) << 24 | u32(msg[off + 1]) << 16 | u32(msg[off + 2]) << 8 | u32(msg[off + 3])
}

write_ttl_at :: proc(msg: []u8, off: int, v: u32) {
	msg[off] = u8(v >> 24)
	msg[off + 1] = u8(v >> 16)
	msg[off + 2] = u8(v >> 8)
	msg[off + 3] = u8(v)
}

read_ttls :: proc(msg: []u8, offsets: []int, allocator := context.allocator) -> []u32 {
	ttls := make([]u32, len(offsets), allocator)
	for off, i in offsets {
		ttls[i] = sane_ttl(read_ttl_at(msg, off))
	}
	return ttls
}

/*
Bound every TTL a message carries, on the wire, in place.

For the answers that never pass through the cache - a miss is forwarded to the
client from the upstream's own bytes, and with `cache.enabled: false` no answer
passes through it at all. The cache bounds the copies it serves by bounding what
it stores (see `cache.put`), and that leaves the copy the client gets on the very
miss that filled the entry, which is the one that carries the upstream's figure
untouched.

Best-effort, and deliberately so: every record this can read is bounded, and the
walk stops at the first one it cannot. It does not refuse the message, and it
reports nothing for a caller to act on.

Refusing was the first shape of this - a message that could not be walked got
SERVFAIL rather than being forwarded with the sender's own figures in it. What
that missed is which messages fail the walk. Records are laid out answer first,
so the section a client acts on is the section already bounded by the time any
later one goes wrong; what a whole-message refusal actually turned away was junk
in an authority or additional section, sections no TTL decision here depends on,
and it turned it into SERVFAIL for a name whose answer section was clean. That
is the same fail-closed-on-the-wrong-evidence `server.resolve_query` documents
at length for the chain walk, and it is settled the same way: hold the refusal to
the part that was actually read.

Nothing is given up by not refusing. A message this cannot fully walk is one
`scan_ttl_offsets` refuses too, so `cache.put` will not store it and no entry
ever pins the sender's figure; the exposure is the single forwarded copy, whose
answer section this bounded on the way past. An answer section this cannot walk
is one the client's own parser has to contend with, and where blocking is on
`resolve_query` refuses it a few lines below for reasons of its own.

Walks the message itself rather than taking offsets from the caller: the one
caller that has already scanned is the cache, and it has its own reason to hold
the offsets. Nothing is allocated here - the walk writes as it goes rather than
collecting offsets first - so a reply claiming three sections of 65535 records
costs the loop iterations it takes to fail on the first one and no memory at all.
*/
cap_ttls :: proc(msg: []u8, ceiling: u32) {
	if len(msg) < HEADER_SIZE {
		return
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	total := int(u16(msg[6]) << 8 | u16(msg[7]))
	total += int(u16(msg[8]) << 8 | u16(msg[9]))
	total += int(u16(msg[10]) << 8 | u16(msg[11]))

	pos := HEADER_SIZE
	for _ in 0 ..< qdcount {
		next, name_ok := skip_name(msg, pos)
		if !name_ok {
			return
		}
		pos = next + 4
		if pos > len(msg) {
			return
		}
	}
	for _ in 0 ..< total {
		next, name_ok := skip_name(msg, pos)
		if !name_ok {
			return
		}
		pos = next
		if pos + 10 > len(msg) {
			return
		}
		// OPT is skipped: its "TTL" is really the extended rcode and flags.
		if Type(u16(msg[pos]) << 8 | u16(msg[pos + 1])) != .OPT {
			write_ttl_at(msg, pos + 4, min(sane_ttl(read_ttl_at(msg, pos + 4)), ceiling))
		}
		rdlength := int(u16(msg[pos + 8]) << 8 | u16(msg[pos + 9]))
		pos += 10 + rdlength
		if pos > len(msg) {
			return
		}
	}
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
		write_ttl_at(msg, off, v)
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
