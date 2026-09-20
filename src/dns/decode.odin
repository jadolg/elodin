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
	Name_Budget,
	/*
	This request had already taken `REQUEST_DECODE_BUDGET` out of its arena.

	Apart from every other error here because it is not a statement about the
	message: the same bytes read on their own would have decoded, and what
	stopped them is this server's own accounting across the readings before it.
	A reader deciding whether a reply is malformed - the validator most of all,
	which would otherwise report a forgery - has to be able to tell the two
	apart.
	*/
	Request_Budget,
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

/*
What one decode of a message may spend expanding its names into.

Every name is cloned in escaped presentation form, so one 255-octet name of
unprintable bytes costs 1004 bytes, and a two-byte compression pointer buys a
fresh copy of the whole expansion. A record is only 16 wire bytes when its owner
and its RDATA name are both pointers, so a reply built entirely of those reaches
about 130 times its own length - 8.5 MB out of 64 KB - and the same message is
decoded again for the cache, for the UDP fit and for the validator.

A flat figure rather than a multiple of the message, for two reasons. It is the
absolute one that matters: what threatens the box is the megabytes a full-length
reply can reach, and a short message expanding to many times itself is many times
nothing. And a multiple would not survive this codebase's own rewrites - a
message is stripped of its RRSIGs and stored, and `encode_message` compresses
what it writes, so the same names can come back in half the bytes. The entry
would then be refused on every cache hit by a budget its own message had passed,
which is a branch `resolve` documents as unreachable.

640 KB is what one reading may spend. A record whose owner is a pointer is 16
wire bytes, so a full-length reply crosses it at around 160 presentation
characters of name per record - an RRset of four thousand records under one name
that long. Shorter replies reach it too, since what a name costs has nothing to
do with the two bytes that name it: 650 records under one 255-octet name of
unprintable octets is 10 KB of wire and the whole budget. Both are legal and
neither is anything a real server sends - a name is normally printable and a few
dozen characters, written out once for every record or two that carries it, and
a reply of a few hundred records costs a few tens of kilobytes of names.
*/
NAME_BUDGET :: 640 * 1024

/*
What one request may take out of its arena reading the messages it reads.

`NAME_BUDGET` is per reading, and a request is not one reading. A single query
reads the upstream's reply for the cache, reads it again when only the answer
section will parse, reads it a third time in `fit_response` when it passes the
client's limit, and the validator reads a reply of its own for every step of the
chain - `dnssec.MAX_LOOKUPS_PER_QUERY` of them. Thirty-five readings, each with
a budget of its own and none at all for what it allocates besides names, all
into the one arena that request is served from. Issue #354, measured over those
thirty-five readings:

	names, five kilobytes of pointers at one 255-octet name   23,989,840 B
	65,504 empty character-strings in one TXT record          36,686,720 B
	5,957 minimal records in one message                      18,554,196 B

Every byte of it, rather than the names alone. Names are the largest expansion a
message can ask for and the only one this decoder ever bounded, but they are not
the only one: a `<character-string>` may be zero bytes long and is a 16-byte
`string` either way, an EDNS option is four wire bytes and twenty-four in
memory, and a record is eleven wire bytes and about ninety. Those are a fixed
multiple of the message and so bounded per reading by the message's own
length - which is exactly the thing this budget exists to stop being the bound,
since the request chooses how many readings there are. One counter of what the
decoder took is simpler than a counter per kind of expansion and is the figure
that matters anyway: what threatens the box is the megabytes, whatever shape
they arrived in.

Eight megabytes. A heavy request of the ordinary kind is 1,356,752 bytes
measured - a full-length answer read the three times the answer path reads one,
plus a DNSKEY reply for each of the thirty-two steps a chain walk may take - so
this is about six times the worst honest traffic. It has to be several times the
per-reading figures rather than equal to them: `decode_answer` reads the same
reply twice on purpose, the whole message and then the answer section alone when
the whole will not parse, and a budget the first reading can empty takes the
second one with it, which refuses an answer this server had no opinion about.
A full-length reply built to spend everything a reading may is about 1.7 MB, so
the three readings of the answer path come to 5 MB and the chain still has room.

Against the pool rather than against one query is where the figure is worth
checking: `config` derives 16 to 128 workers and charges each
`WORKER_MEMORY_BYTES` of ordinary use, so a flood holding every worker inside a
request of this shape is 128 MB on the small box the issue was filed from, where
the three lines above were gigabytes. Lowering this is the lever if that is
still too much; what it costs is the headroom above, and what it must not go
under is the answer path's three readings.

A reading passed no counter keeps `NAME_BUDGET` alone and nothing else, which is
every caller outside a request: the fuzz target, the bootstrap resolver, the
tests.
*/
REQUEST_DECODE_BUDGET :: 8 * 1024 * 1024

@(private)
Reader :: struct {
	msg:        []u8,
	pos:        int,
	// Presentation bytes this message's names have been expanded into so far,
	// against `NAME_BUDGET`.
	name_bytes: int,
	/*
	What this request has taken out of the caller's allocator so far, against
	`REQUEST_DECODE_BUDGET`, or nil for a reading nobody is counting.

	Borrowed rather than owned: it outlives this decode and is charged by every
	other reading the same request makes.
	*/
	spent:      ^int,
}

/*
Charge `n` presentation bytes to the message's expansion budget.

Charged after the clone rather than before it, since what a name costs is not
known until it is decoded, so a name overshoots the budget by at most
`MAX_NAME_PRESENTATION` and nothing else is decoded once it is gone. RDATA
expansion overshoots by that much per name in the layout, since it reads them
one after another before anything checks again; its buffer is the one thing
charged ahead of itself, because that one is known before it is taken.
*/
@(private)
charge_name :: proc(r: ^Reader, n: int) -> Decode_Error {
	r.name_bytes += n
	if r.spent != nil {
		r.spent^ += n
	}
	return budget_spent(r)
}

/*
Which budget, if either, this reading has run past.

The request's is reported first where both are gone, because it is the one that
says something about what comes next: another reading of the same message has a
fresh `NAME_BUDGET` and will fail again the moment it charges anything, and a
caller offered the shorter reading as a second chance is better told there is no
second chance. It is also the error that must not be read as a statement about
the message - see `Request_Budget`.
*/
@(private)
budget_spent :: proc(r: ^Reader) -> Decode_Error {
	if r.spent != nil && r.spent^ > REQUEST_DECODE_BUDGET {
		return .Request_Budget
	}
	return .Name_Budget if r.name_bytes > NAME_BUDGET else .None
}

/*
Charge `n` bytes of the caller's allocator to the request, before taking them.

Everything this decoder allocates that is not a name: the question and record
arrays, the lists TXT and OPT hold, the RDATA it copies verbatim. Each of those
is a size the wire states and the decoder reads before it allocates, so unlike a
name it is charged ahead of itself and the reading is refused with nothing taken.

Only against the request's budget. A single reading of a single message is
already bounded in all of these by the message's own length - eleven wire bytes
per record, one per character-string - which is what `NAME_BUDGET` exists
because names are not. What was unbounded is the number of readings; see
`REQUEST_DECODE_BUDGET`.
*/
@(private)
charge_bytes :: proc(r: ^Reader, n: int) -> Decode_Error {
	if r.spent == nil {
		return .None
	}
	r.spent^ += n
	return .Request_Budget if r.spent^ > REQUEST_DECODE_BUDGET else .None
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
	charge_bytes(r, n) or_return
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
	if err = charge_name(r, len(name)); err != .None {
		// The one place a name is decoded and then not kept, so the one place
		// that has to hand it back. An allocator that takes things back is not
		// what this decoder is normally fed - a caller serving a query hands it
		// an arena and drops the lot - and a decode that fails anywhere leaves
		// everything before it unreachable for the same reason. That is the
		// contract rather than this procedure's business; dropping a name it
		// has in hand would be.
		delete(name, allocator)
		return "", err
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

`spent` is that caller's running total of what its request has taken out of
`allocator`, against `REQUEST_DECODE_BUDGET`. A caller serving one query from
one arena passes the same counter to every reading it makes, so what the arena
holds is bounded by the request rather than by the reading; one that leaves it
out gets `NAME_BUDGET` for this reading and no count across readings, which is
what every call site outside a request wants.
*/
decode_message :: proc(
	msg: []u8,
	allocator := context.allocator,
	spent: ^int = nil,
) -> (
	m: Message,
	err: Decode_Error,
) {
	return decode_sections(msg, false, spent, allocator)
}

/*
Decode as far as the answer section and stop there.

For a caller whose question is what the answer says: it gets that answer, or the
error that stopped it reading one, and is not told about a malformed record
sitting in a section it was never going to look at. `decode_message` refuses the
whole message for any of them, which is right when the whole message is what the
caller wanted and wrong when it makes a clean, walkable answer unreadable on the
strength of somebody's additional section.

The section counts are still sanity-checked against the message's length before
anything is allocated, so a caller that stops early is not a way around that.

`spent` is the request's counter, as in `decode_message`. This is the reading a
caller falls back to when the whole message would not parse, so both readings
charge the one counter and the arena holds what the request took rather than
twice what a reading may.
*/
decode_through_answer :: proc(
	msg: []u8,
	allocator := context.allocator,
	spent: ^int = nil,
) -> (
	m: Message,
	err: Decode_Error,
) {
	return decode_sections(msg, true, spent, allocator)
}

@(private)
decode_sections :: proc(
	msg: []u8,
	answer_only: bool,
	spent: ^int,
	allocator := context.allocator,
) -> (
	m: Message,
	err: Decode_Error,
) {
	if len(msg) < HEADER_SIZE {
		return {}, .Truncated_Header
	}
	/*
	A request with nothing left to spend reads nothing at all.

	Charging first and checking afterwards is how a name is paid for - what it
	costs is not known until it is decoded - but a reading that starts with the
	counter already gone would still expand a name to find that out, once per
	reading for every reading the request has left. Refusing here keeps the
	overshoot to the one reading that crossed the budget rather than to all of
	them.
	*/
	if spent != nil && spent^ > REQUEST_DECODE_BUDGET {
		return {}, .Request_Budget
	}
	r := Reader{msg = msg, spent = spent}

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
		charge_bytes(&r, size_of(Question) * int(qdcount)) or_return
		qs := make([]Question, int(qdcount), allocator)
		for i in 0 ..< int(qdcount) {
			qs[i].name = r_name(&r, allocator) or_return
			qs[i].type = Type(r_u16(&r) or_return)
			qs[i].class = Class(r_u16(&r) or_return)
		}
		m.question = qs
	}

	m.answer = decode_records(&r, int(ancount), allocator) or_return
	if answer_only {
		return
	}
	m.authority = decode_records(&r, int(nscount), allocator) or_return
	m.additional = decode_records(&r, int(arcount), allocator) or_return
	return
}

@(private)
decode_records :: proc(r: ^Reader, count: int, allocator: mem.Allocator) -> (out: []Record, err: Decode_Error) {
	if count == 0 {
		return nil, .None
	}
	charge_bytes(r, size_of(Record) * count) or_return
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
		// and come through here with a perfectly good pointer inside it. Such a
		// record charges its names to the budget twice, once for each attempt,
		// which is the right count: the first attempt's clones are in the arena
		// as surely as the second's.
		rec.data = decode_raw_rdata(r, rec.type, rdata_start, rdata_end, allocator)
		err = .None
	}
	/*
	A spent budget fails the message, whichever path above noticed.

	The raw path cannot say so itself: `decode_raw_rdata` never fails - a record
	of a type this decoder does not model is kept as bytes whatever is wrong
	with it - so when the budget stops it expanding a name it copies the RDATA
	verbatim and says nothing. That leaves a live compression pointer in an
	`Rdata_Raw`, which is the one thing `encode_message` refuses to write: the
	message would decode here and then fail to be built again, taking
	`fit_response` to an empty TC answer and `remove_edns_option` to no answer
	at all, for a reply this server had read.

	Asked after the fallback rather than before it so the modelled path lands
	here too - its own refusal would otherwise be swallowed by the retry the
	same way. Reachable only on a message's last record, since any record after
	it fails on its own owner name, and that is exactly the record an upstream
	would append.
	*/
	if err = budget_spent(r); err != .None {
		return {}, err
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
		/*
		Counted before anything is taken, so the list is allocated once at the
		size the wire asks for.

		These used to be collected into a `[dynamic]string` that started at two
		and doubled, and a caller serving a query hands this decoder an arena,
		which does not give back the buffers a doubling walks past. A
		<character-string> may be zero bytes long, so one length byte buys a
		16-byte `string` header - sixteen times its wire length on its own, and
		thirty-two with the doubling behind it, which is more than the budget
		above permits for the shapes it does bound. The count is on the wire
		either way: follow the length bytes and stop at the RDATA's end. Issue
		#351.

		An element running past the RDATA is refused here rather than half way
		through the read, which is the same refusal by a shorter route. The read
		reached `.Short_Buffer` or the end-of-RDATA check below, and either way
		`decode_record` keeps the record as raw bytes rather than rejecting the
		message - which it still does.
		*/
		count := 0
		for p := start; p < end; count += 1 {
			p += 1 + int(r.msg[p])
			if p > end {
				return nil, .Bad_Rdata
			}
		}
		charge_bytes(r, size_of(string) * count) or_return
		parts := make([]string, count, allocator)
		for i in 0 ..< count {
			parts[i] = r_char_string(r, allocator) or_return
		}
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return Rdata_TXT{strings = parts}, .None

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
		// Counted first, for the reason written at TXT above: an option is four
		// wire bytes at its smallest and twenty-four in memory, which the
		// doubling took to twelve times the wire.
		count := 0
		for p := start; p + 4 <= end; count += 1 {
			p += 4 + (int(r.msg[p + 2]) << 8 | int(r.msg[p + 3]))
			if p > end {
				return nil, .Bad_Rdata
			}
		}
		charge_bytes(r, size_of(EDNS_Option) * count) or_return
		opts := make([]EDNS_Option, count, allocator)
		for i in 0 ..< count {
			opts[i].code = r_u16(r) or_return
			olen := int(r_u16(r) or_return)
			opts[i].data = r_bytes(r, olen, allocator) or_return
		}
		if r.pos != end {
			return nil, .Bad_Rdata
		}
		return Rdata_OPT{options = opts}, .None
	}

	return decode_raw_rdata(r, type, start, end, allocator), .None
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
