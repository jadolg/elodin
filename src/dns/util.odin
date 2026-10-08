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

// The DO bit is the top bit of the flags half of the OPT record's TTL field,
// the low sixteen bits.
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
windows onto one number. Reading only the two at either end of it would leave a
request asking in a version this server does not implement indistinguishable
from one asking in version 0, and it would get an answer in a version nobody had
agreed on.

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

	Callers are `cache.put`, which `resolve_query` reaches only with a response
	it has decoded, and `server.doh_max_age`, which scans the answer about to
	be sent. A 17-byte reply claiming three sections of 65535 records would
	otherwise allocate 1.5 MB for a walk that fails on the first name, and a
	guard that costs one comparison is not worth removing for a caller that
	might hand it bytes nothing has checked.
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

Only the additional section is looked in, for the reason `find_opt_span` gives:
that is where RFC 6891 section 6.1.1 puts the record, and it is the only section
`find_opt` and `find_opt_span` read, so a record of type OPT anywhere else is not
the message's EDNS record. A client can put one in its answer section for the
asking - and a reader that took it would be sizing a buffer, and picking the
figure a rewrite writes, off a record the writer never touches and the upstream
never reads.
*/
peek_udp_size :: proc(msg: []u8) -> u16 {
	if len(msg) < HEADER_SIZE {
		return MAX_UDP_SIZE
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	before := int(u16(msg[6]) << 8 | u16(msg[7]))
	before += int(u16(msg[8]) << 8 | u16(msg[9]))
	arcount := int(u16(msg[10]) << 8 | u16(msg[11]))

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
	for i in 0 ..< before + arcount {
		next, ok := skip_name(msg, pos)
		if !ok {
			return MAX_UDP_SIZE
		}
		pos = next
		if pos + 10 > len(msg) {
			return MAX_UDP_SIZE
		}
		// OPT carries the payload size where every other type carries its class.
		if i >= before && Type(u16(msg[pos]) << 8 | u16(msg[pos + 1])) == .OPT {
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
Whether a reply is a referral rather than an answer, read off the wire.

RFC 2308 section 2.2, type 4: NOERROR, nothing in the answer section, and name
servers in the authority section with no SOA beside them. That is a server
saying "ask them", which is what an authority that does not recurse sends in
reply to RD=1 (RFC 1034 section 4.3.1). It is not a NODATA - that is told apart,
in the RFC's own words, by the SOA being there or the NS not being - and a
client handed one reads "the name has no records of this type" (issue #410).

And the same after a CNAME, which is RFC 2308 section 2.1's own REFERRAL
RESPONSE example: `an.example. CNAME tripple.xx.` in the answer, `xx. NS` in
authority, no SOA. The chain stops at a name the server does not hold, and a
client handed it gets an alias and no address (issue #451). What makes it one
is where the NS sit: at or above the chain's target and not above the name
asked. An authority that includes its own apex NS beside a CNAME out of its
zone - BIND does, for `mail.corp. CNAME ghs.googlehosted.com.` - has answered
all it holds, and a stub that follows CNAMEs resolves that today; it is left
alone. Only CNAME, DNAME and their RRSIGs may stand in the answer: anything
else there is data, and the reply is an answer.

The RA bit is not read. A server that clears it on answers it does give exists,
and one that sets it over a referral has still not answered; what the reply
holds is the whole test.

The AA bit is, over an empty answer. A referral is sent from above the cut,
where the server is not the authority for the name asked (RFC 1035 section
4.1.1), so no server sets it on one; an authority that does set it over an
empty answer with only its own NS beside it is sending a NODATA without the
SOA, and that is its answer. Beside a CNAME it says nothing: the authority for
the alias sets it, and the target is still somebody else's.

The rcode is the composed one, so an extended rcode whose low nibble is zero is
not a NOERROR here. A message that cannot be walked is not a referral: what a
decode would refuse is refused where it is decoded.

The walk allocates nothing. Only a reply already of the partial shape - every
answer record an alias, NS and no SOA in authority - has its question, answer
and NS owners decoded, into scratch, to follow the chain. And only one no larger
than `MAX_ALIAS_REFERRAL_RECORDS` in either section: every judgement of a reply
reads this, several times per reply and once per chain-walk step, and none of
those readings is charged to the request's decode budget (issue #354). A reply
past it is left as the answer it claims to be, which it was before issue #451.
*/
peek_referral :: proc(msg: []u8) -> bool {
	if len(msg) < HEADER_SIZE {
		return false
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	ancount := int(u16(msg[6]) << 8 | u16(msg[7]))
	nscount := int(u16(msg[8]) << 8 | u16(msg[9]))
	// A header rcode other than zero composes to something other than NOERROR
	// whatever the OPT record adds, so only a zero one needs the walk below.
	if nscount == 0 || msg[3] & 0x0f != 0 || (ancount == 0 && msg[2] & 0x04 != 0) {
		return false
	}
	// The alias branch reads one question, and decodes nothing for any other.
	if ancount > 0 && (qdcount != 1 || ancount > MAX_ALIAS_REFERRAL_RECORDS || nscount > MAX_ALIAS_REFERRAL_RECORDS) {
		return false
	}

	pos := HEADER_SIZE
	for _ in 0 ..< qdcount {
		next, ok := skip_name(msg, pos)
		if !ok {
			return false
		}
		pos = next + 4
		if pos > len(msg) {
			return false
		}
	}
	// The answer first: an ordinary answer's first record ends this here.
	for _ in 0 ..< ancount {
		type, next, ok := skip_record(msg, pos)
		if !ok {
			return false
		}
		#partial switch type {
		case .CNAME, .DNAME, .RRSIG:
		case:
			return false
		}
		pos = next
	}
	// The rcode after the counts and the answer: composing it walks the whole
	// message for the OPT record.
	if peek_rcode(msg) != .No_Error {
		return false
	}
	ns := false
	authority_at := pos
	for _ in 0 ..< nscount {
		type, next, ok := skip_record(msg, pos)
		if !ok {
			return false
		}
		#partial switch type {
		case .SOA:
			return false
		case .NS:
			ns = true
		}
		pos = next
	}
	if !ns || ancount == 0 {
		return ns
	}
	return referred_past_alias(msg, authority_at, nscount)
}

// The resource record at `pos`: its type, and where the one after it starts.
@(private)
skip_record :: proc(msg: []u8, pos: int) -> (type: Type, next: int, ok: bool) {
	fixed, named := skip_name(msg, pos)
	if !named || fixed + 10 > len(msg) {
		return
	}
	next = fixed + 10 + int(u16(msg[fixed + 8]) << 8 | u16(msg[fixed + 9]))
	if next > len(msg) {
		return
	}
	return Type(u16(msg[fixed]) << 8 | u16(msg[fixed + 1])), next, true
}

// The most answer or authority records `peek_referral` follows a chain through:
// a chain as long as the validator follows (`dnssec.MAX_CNAME_CHAIN`), each link
// beside its RRSIG. It bounds both the decode and the walk, which is quadratic
// in the answer.
@(private)
MAX_ALIAS_REFERRAL_RECORDS :: 32

/*
Where the CNAME chain in a reply's answer section ends: the name a client that
follows it asks next. `aliased` is false where the chain goes nowhere - no CNAME
from the question's name, a loop back to it, or a question whose CNAME is the
data rather than a step (a CNAME, DNAME or RRSIG asked for, or ANY, which
matches the CNAME and is not followed: RFC 1034 section 4.3.2, step 3a) - and
where a link on it is unreadable, since then nobody here knows where it goes.

For `resolve_query`, which asks it of a reply `peek_referral` has already called
a referral past an alias, and so already bounded.
*/
peek_alias_target :: proc(msg: []u8) -> (target: string, aliased: bool) {
	_, target, aliased, _ = alias_chain(msg)
	return
}

/*
`unreadable` where a link on the chain was kept raw (`decode_record`): the chain
goes somewhere and nobody here can say where, so `aliased` is false beside it.
Every CNAME at an owner is looked at, not just the first, so where a second one
sits in the section does not decide whether the chain can be read.
*/
@(private)
alias_chain :: proc(msg: []u8) -> (asked, target: string, aliased, unreadable: bool) {
	decoded, err := decode_through_answer(msg, context.temp_allocator)
	if err != .None || len(decoded.question) != 1 {
		return
	}
	#partial switch decoded.question[0].type {
	case .CNAME, .DNAME, .RRSIG, .ANY:
		return
	}
	asked = decoded.question[0].name
	target = asked
	// One step per answer record at most, so a loop in the chain ends.
	for _ in decoded.answer {
		next := ""
		for rec in decoded.answer {
			if rec.type != .CNAME || !name_equal_fold(rec.name, target) {
				continue
			}
			alias, is_name := rec.data.(Rdata_Name)
			if !is_name {
				return asked, target, false, true
			}
			if next == "" {
				next = alias.name
			}
		}
		if next == "" {
			break
		}
		target = next
	}
	return asked, target, !name_equal_fold(target, asked), false
}

// The CNAME half of `peek_referral`: whether the authority's NS are for the
// chain's target rather than for the name asked. `authority_at` is where the
// authority section starts, which `peek_referral` has already walked.
@(private)
referred_past_alias :: proc(msg: []u8, authority_at, nscount: int) -> bool {
	asked, target, aliased, unreadable := alias_chain(msg)
	// Where the chain ends is unknown, so whether the NS are for it is too, and
	// "cannot tell" is not passed on as an answer (see `cloaked_chain_target`).
	if unreadable {
		return true
	}
	if !aliased {
		return false
	}
	pos := authority_at
	for _ in 0 ..< nscount {
		type, next, _ := skip_record(msg, pos)
		if type == .NS {
			zone, _, nerr := decode_name(msg, pos, context.temp_allocator)
			if nerr == .None && name_at_or_below(target, zone) && !name_at_or_below(asked, zone) {
				return true
			}
		}
		pos = next
	}
	return false
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
`resolve_query` refuses it later for reasons of its own.

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
// (RFC 2308), each read through `sane_ttl`. `has_soa` is false when the
// authority section holds no SOA.
negative_ttl :: proc(m: Message) -> (ttl: u32, has_soa: bool) {
	for rec in m.authority {
		if soa, is_soa := rec.data.(Rdata_SOA); is_soa {
			return min(sane_ttl(soa.minimum), sane_ttl(rec.ttl)), true
		}
	}
	return 0, false
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
