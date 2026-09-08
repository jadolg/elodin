package dns

import "core:mem"
import "core:strings"

/*
Message writer with RFC 1035 name compression.

Note on Rdata_Raw: a raw blob is copied out at whatever offset the record lands
at, so a compression pointer inside one would name a byte of this message rather
than the one it was written against. Answers do reach this writer - a cookie
attached to a reply that carried no OPT record, an answer stripped of its DNSSEC
records for a client that did not ask for them, and one shrunk to a UDP limit are
all re-encoded - so what keeps that from corrupting them is the decoder, which
expands the compressed names inside raw RDATA as it reads them (see
src/dns/rdata_raw.odin). `w_record` refuses a blob that still holds one, on the
grounds that failing to answer is recoverable and answering wrongly is not.
*/
Writer :: struct {
	buf:       [dynamic]u8,
	comp:      map[string]u16,
	compress:  bool,
	allocator: mem.Allocator,
	// Scratch reused across names so encoding a message stays allocation-light.
	name_buf:  [MAX_NAME_WIRE]u8,
	fold_buf:  [MAX_NAME_WIRE]u8,
	offsets:   [dynamic]int,
}

writer_init :: proc(w: ^Writer, allocator := context.allocator, compress := true) {
	w.allocator = allocator
	w.compress = compress
	w.buf = make([dynamic]u8, 0, 512, allocator)
	w.offsets = make([dynamic]int, 0, 16, allocator)
	if compress {
		w.comp = make(map[string]u16, 32, allocator)
	}
}

writer_destroy :: proc(w: ^Writer) {
	delete(w.buf)
	writer_release_scratch(w)
}

/*
Release everything the writer allocated except its output buffer.

Split out because `encode_message` hands that buffer to its caller and has to let
go of the rest. The compression map's keys are cloned (see `w_name`), and the
map's own storage does not own them, so dropping the map alone would leave a
string per distinct name suffix behind.
*/
@(private)
writer_release_scratch :: proc(w: ^Writer) {
	delete(w.offsets)
	writer_free_comp_keys(w)
	delete(w.comp)
}

/*
Free the cloned key strings the compression map holds (see `w_name`).

The map's own storage does not own its keys, so both dropping the map
(`writer_release_scratch`) and clearing it to invalidate stale targets
(`encode_message`'s truncation path) have to free them first, or a string
per distinct name suffix leaks.
*/
@(private)
writer_free_comp_keys :: proc(w: ^Writer) {
	for key in w.comp {
		delete(key, w.allocator)
	}
}

@(private)
w_u8 :: proc(w: ^Writer, v: u8) {
	append(&w.buf, v)
}

@(private)
w_u16 :: proc(w: ^Writer, v: u16) {
	append(&w.buf, u8(v >> 8), u8(v))
}

@(private)
w_u32 :: proc(w: ^Writer, v: u32) {
	append(&w.buf, u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v))
}

@(private)
w_bytes :: proc(w: ^Writer, v: []u8) {
	append(&w.buf, ..v)
}

@(private)
w_char_string :: proc(w: ^Writer, s: string) -> Encode_Error {
	if len(s) > 255 {
		return .Too_Large
	}
	w_u8(w, u8(len(s)))
	w_bytes(w, transmute([]u8)s)
	return .None
}

@(private)
w_name :: proc(w: ^Writer, name: string, compress := true) -> Encode_Error {
	n := encode_name(name, w.name_buf[:], &w.offsets) or_return
	tmp := w.name_buf[:n]

	if !w.compress || !compress {
		w_bytes(w, tmp)
		return .None
	}

	base := len(w.buf)
	// The last entry is the root label; a 1-byte root beats a 2-byte pointer.
	for i in 0 ..< max(0, len(w.offsets) - 1) {
		off := w.offsets[i]
		suffix := tmp[off:n]
		for k in 0 ..< len(suffix) {
			c := suffix[k]
			w.fold_buf[k] = c + 32 if c >= 'A' && c <= 'Z' else c
		}
		key := string(w.fold_buf[:len(suffix)])

		if target, found := w.comp[key]; found {
			w_bytes(w, tmp[:off])
			w_u16(w, 0xc000 | target)
			return .None
		}
		if base + off < 0x4000 {
			w.comp[strings.clone(key, w.allocator)] = u16(base + off)
		}
	}

	w_bytes(w, tmp)
	return .None
}

// Types whose RDATA name may be compressed. Anything newer must not be
// (RFC 3597), so the writer emits those names in full.
@(private)
rdata_name_compressible :: proc "contextless" (t: Type) -> bool {
	#partial switch t {
	case .NS, .CNAME, .SOA, .PTR, .MX, .MINFO, .MB, .MG, .MR, .MD, .MF:
		return true
	}
	return false
}

@(private)
w_question :: proc(w: ^Writer, q: Question) -> Encode_Error {
	w_name(w, q.name) or_return
	w_u16(w, u16(q.type))
	w_u16(w, u16(q.class))
	return .None
}

@(private)
w_record :: proc(w: ^Writer, rec: Record) -> Encode_Error {
	w_name(w, rec.name, compress = rec.type != .OPT) or_return
	w_u16(w, u16(rec.type))
	w_u16(w, u16(rec.class))
	w_u32(w, rec.ttl)

	len_pos := len(w.buf)
	w_u16(w, 0)
	rdata_start := len(w.buf)

	compressible := rdata_name_compressible(rec.type)

	switch d in rec.data {
	case Rdata_A:
		addr := d.addr
		w_bytes(w, addr[:])
	case Rdata_AAAA:
		addr := d.addr
		w_bytes(w, addr[:])
	case Rdata_Name:
		w_name(w, d.name, compress = compressible) or_return
	case Rdata_SOA:
		w_name(w, d.ns, compress = compressible) or_return
		w_name(w, d.mbox, compress = compressible) or_return
		w_u32(w, d.serial)
		w_u32(w, d.refresh)
		w_u32(w, d.retry)
		w_u32(w, d.expire)
		w_u32(w, d.minimum)
	case Rdata_MX:
		w_u16(w, d.preference)
		w_name(w, d.exchange, compress = compressible) or_return
	case Rdata_TXT:
		if len(d.strings) == 0 {
			w_u8(w, 0)
		}
		for s in d.strings {
			w_char_string(w, s) or_return
		}
	case Rdata_SRV:
		w_u16(w, d.priority)
		w_u16(w, d.weight)
		w_u16(w, d.port)
		w_name(w, d.target, compress = false) or_return
	case Rdata_CAA:
		w_u8(w, d.flags)
		w_char_string(w, d.tag) or_return
		w_bytes(w, transmute([]u8)d.value)
	case Rdata_SVCB:
		w_u16(w, d.priority)
		w_name(w, d.target, compress = false) or_return
		w_bytes(w, d.params)
	case Rdata_OPT:
		for opt in d.options {
			w_u16(w, opt.code)
			w_u16(w, u16(len(opt.data)))
			w_bytes(w, opt.data)
		}
	case Rdata_Raw:
		/*
		The decoder expands these, so this only fires if something got past it:
		a compressible type with no entry in `raw_rdata_layout` to walk, a layout
		that stopped matching what senders write, a name the walk could not
		rebuild - a pointer aiming forwards, an expansion that will not fit a
		name - or a blob built somewhere other than a decode. Little of that
		should happen, which is why it is worth catching: a stale pointer is not
		visible in the answer, and the client has no way to know the name it was
		handed is the wrong one.

		Most callers degrade into something the client recovers from on its own:
		`fit_response` falls back to an empty answer with TC set and the client
		asks again over TCP, `ensure_edns_option` returns the answer without a
		cookie, and `strip_dnssec_records` forwards the bytes it started from.

		Two do not, and it is worth being plain about them. `remove_edns_option`
		is how a cookie is taken back out of a message, on the way to an upstream
		in src/server/resolver.odin and on the way back from one in
		src/upstream/cookie.odin, and both fail closed rather than let a cookie
		travel: the query is answered SERVFAIL and the reply is dropped for the
		group to re-ask. So a single record whose RDATA holds a pointer nothing
		could expand costs a cookie-using client that answer entirely. That is
		the trade taken here anyway - such a record is malformed in its own right
		by the time it reaches this, and a name pointing at bytes nobody chose is
		the worse thing to hand out - but it is a whole answer, not a degraded
		one.
		*/
		if raw_rdata_holds_pointer(rec.type, d.data) {
			return .Bad_Rdata
		}
		w_bytes(w, d.data)
	case:
		// nil rdata encodes as an empty RDATA section
	}

	rdlen := len(w.buf) - rdata_start
	if rdlen > 0xffff {
		return .Too_Large
	}
	w.buf[len_pos] = u8(rdlen >> 8)
	w.buf[len_pos + 1] = u8(rdlen)
	return .None
}

/*
The OPT record's own encoded length: a root owner name, the four fixed fields,
and four bytes of header per option carried.

Nothing about it depends on where in the message it lands - the owner name is
the root and its RDATA holds no name to compress - so this can be worked out
before a byte is written, which is what `encode_message` needs to keep room for
it behind a truncation.

`ok` is false wherever that arithmetic is not the record's, and the caller keeps
no room rather than the wrong amount:

  - a message with no OPT record in its additional section, which is the section
    `find_opt` reads and the only one an OPT record is the message's EDNS record
    in;
  - an owner name other than the root. RFC 6891 section 6.1.2 makes it the root
    and `w_record` writes it uncompressed, so a decoded reply that carries
    something else - the decoder reads the RDATA and never looks at the name -
    would cost as many bytes as the name is long. Reserving eleven for it is how
    the walk back below sheds records for a record that then does not fit
    anyway.
  - RDATA of another shape than an option list. Nothing builds one, and nothing
    here has to guess at what it encodes to.
*/
@(private)
opt_wire_len :: proc(m: Message) -> (n: int, ok: bool) {
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		if rec.name != "." {
			return 0, false
		}
		// The root name, TYPE, CLASS, TTL and RDLENGTH.
		n = 11
		if rdata, is_opt := rec.data.(Rdata_OPT); is_opt {
			for o in rdata.options {
				n += 4 + len(o.data)
			}
		} else if rec.data != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

/*
Whether the message's rcode has bits that live only in its OPT record's TTL.

RFC 6891 section 6.1.3 splits an rcode of 16 or more between the header's four
bits and that byte, so a message that loses the record states the low four on
their own - a different rcode, and one the client has no way to know is not the
one it was answered with.

Read through `find_opt`, so it is the same record the rest of this package calls
the message's own.
*/
@(private)
opt_holds_extended_rcode :: proc(m: Message) -> bool {
	opt, found := find_opt(m)
	return found && opt.ttl & 0xff00_0000 != 0
}

/*
Serialise a message, truncating at `max_size` if necessary.

TC says that answer or authority data was left out, which is what RFC 2181
section 9 makes it: the bit tells a client the records it asked for did not all
fit and to ask again over TCP. So a record dropped from those two sections sets
`truncated` and the TC bit, and a record dropped from the additional section
does not - a responder that could not fit a glue address or an OPT record behind
a complete answer has answered the question, and a client sent to TCP over it
gets the same records one round trip later.

The OPT record is re-appended after a cut so the client still sees our EDNS
parameters, and where a cut in the answer or authority section leaves no room
for it, records are dropped back until there is. That is the one place this
prefers the EDNS parameters to a record: the client is being told to ask again
over TCP either way, so the records behind the cut are bytes it will discard -
while the OPT record carries the payload size to ask again with, the upper bits
of the rcode, and any cookie or extended error written into it. An answer that would
otherwise be *complete* is never cut for it: there the record is left out
instead, which is `server.match_client_opt`'s reading of the same trade for an
OPT record it declines to mint.
*/
encode_message :: proc(
	m: Message,
	allocator := context.allocator,
	max_size := MAX_MESSAGE,
	compress := true,
) -> (
	out: []u8,
	truncated: bool,
	err: Encode_Error,
) {
	w: Writer
	writer_init(&w, allocator, compress)
	/*
	The scratch goes back whatever happens; the buffer only when it is not being
	returned. Every `or_return` below abandons a partly written message, and the
	allocator here defaults to `context.allocator` rather than to the per-request
	arena the server happens to pass, so neither can be left to a `free_all` that
	may never come.
	*/
	defer {
		if err != .None {
			delete(w.buf)
		}
		writer_release_scratch(&w)
	}

	append(&w.buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	for q in m.question {
		w_question(&w, q) or_return
	}
	if len(w.buf) > max_size {
		return nil, true, .Buffer_Too_Small
	}
	qdcount := u16(len(m.question))

	counts: [3]u16
	sections := [3][]Record{m.answer, m.authority, m.additional}

	/*
	Where the message stood after the last answer or authority record that still
	left room for the OPT record, so a truncation can drop back to it.

	One mark rather than a stack of them: the walk back only ever goes to the
	longest prefix of those two sections that the OPT record fits behind, which
	is this point by construction, whether that is one record short of the cut
	or the whole of both sections.

	-1 where there is no such point at all: a message whose question alone
	leaves no room for the record has nothing to gain by dropping records for it,
	and would come back empty and still without one.
	*/
	opt_len, keep_room := opt_wire_len(m)
	// Whether the OPT record is the only place part of this message's rcode is
	// written, which is what makes leaving it out a different answer rather
	// than a smaller one. See the walk back below.
	opt_required := opt_holds_extended_rcode(m)
	roomy_mark := -1
	roomy_counts: [3]u16
	if keep_room && len(w.buf) + opt_len <= max_size {
		roomy_mark = len(w.buf)
	}

	// Two different endings, and they are not the same answer: see above.
	additional_dropped := false
	opt_written := false

	outer: for section, si in sections {
		for rec in section {
			/*
			The additional section keeps the OPT record's room as it fills.

			The room the walk back below keeps behind a cut is no use if the
			records ahead of the OPT record spend it, and the OPT record is
			normally the last one in the section - so an answer whose glue ends
			eleven bytes short of the ceiling would leave a client that asked
			with EDNS no record at all: no payload size, no cookie, no extended
			error, and no cut to walk back from. A glue address is a hint the
			client can go and ask for; the record it negotiated is not.

			Only while the record would still fit at all. Where it is already
			past the ceiling nothing behind it can be dropped to help, and
			holding the room back would cost the section a record for nothing.
			*/
			ceiling := max_size
			if si == 2 && keep_room && !opt_written && rec.type != .OPT {
				if len(w.buf) + opt_len <= max_size {
					ceiling = max_size - opt_len
				}
			}

			mark := len(w.buf)
			w_record(&w, rec) or_return
			if len(w.buf) > ceiling {
				resize(&w.buf, mark)
				if si != 2 {
					truncated = true
					break outer
				}
				/*
				The additional section is filled as far as it goes rather than
				abandoned at the first record that will not fit. Nothing on the
				wire says a record was left out of it - which is the whole of
				what the split above is - so a client whose buffer had no room
				for one glue address would otherwise silently lose the records
				behind it that did fit, the OPT record it negotiated among them.

				Once, and then compression is off for the rest of the message.
				The targets recorded for the bytes just dropped are stale, so
				the map has to go - keys freed first, since its storage does not
				own them - and every record tried after that would otherwise
				clone a key per distinct suffix into an allocator that is a
				per-request arena, where the frees are no-ops. A reply carrying
				thousands of small additional records against a small ceiling
				would grow that arena by all of them for records none of which
				are sent. What it costs is the odd byte on the records behind
				the drop, which go out with their names in full.
				*/
				if !additional_dropped {
					additional_dropped = true
					writer_free_comp_keys(&w)
					clear(&w.comp)
					w.compress = false
				}
				continue
			}
			counts[si] += 1
			/*
			Asked of the record just written rather than of the one that
			overflowed: an OPT record already in the message is not one to append
			a second copy of below.

			And only in the additional section, which is the only one `find_opt`
			reads and the only one `opt_wire_len` measured. A client can put a
			record of type OPT in its question's answer section for the asking,
			and taking that for the message's EDNS record would shed answer
			records for room the re-add below then declines to use.
			*/
			if si == 2 && rec.type == .OPT {
				opt_written = true
			}
			if si < 2 && keep_room && len(w.buf) + opt_len <= max_size {
				roomy_mark = len(w.buf)
				roomy_counts = counts
			}
		}
	}

	/*
	The cut left the OPT record nowhere to go, so it goes back one or more
	records further.

	Two reasons to spend a record on that, and a complete answer is never cut
	for either of them without one. A truncation is dropping records and sending
	the client to TCP already, so the ones behind the cut are bytes it will
	discard - while the OPT record carries what it needs to ask again with.

	The other is a message whose rcode is 16 or more. Its top eight bits live in
	that record's TTL and nowhere else (RFC 6891 section 6.1.3), so a message
	that loses the record states a different rcode: BADVERS read as NOERROR over
	an empty answer section, which is a NODATA, and BADCOOKIE as YXRRSET. A
	record dropped to keep that honest sets TC like any other, so the client
	reads the rcode it was answered with and comes back over TCP for the records
	- rather than reading the wrong rcode and coming back for the same thing.
	*/
	if !opt_written && roomy_mark >= 0 && len(w.buf) + opt_len > max_size && (truncated || opt_required) {
		/*
		TC for what the walk back takes out of the answer or authority section,
		and for nothing else: it may have discarded additional records alone,
		and a complete answer is not one to send a client away from. Asked of
		the counts rather than assumed from the reason, since the rcode half of
		this runs over answers nothing has been dropped from.

		Not reachable as things stand - a non-OPT additional record is only
		written while it leaves the OPT record's room, so the record is written
		in the walk above and this never runs - which is a reason to derive the
		flag from what happened rather than to argue about which shapes reach
		it.
		*/
		if counts[0] != roomy_counts[0] || counts[1] != roomy_counts[1] {
			truncated = true
		}
		resize(&w.buf, roomy_mark)
		counts = roomy_counts
	}

	if truncated || additional_dropped {
		// Compression targets recorded for the dropped bytes are now stale, so
		// nothing more may be written that could reference them. OPT uses a
		// root name and no compressible RDATA, which keeps this safe. The keys
		// are cloned, so free them before `clear` drops the entries — otherwise
		// the later `writer_release_scratch` finds an empty map and one string
		// per distinct suffix leaks.
		writer_free_comp_keys(&w)
		clear(&w.comp)
		for rec in m.additional {
			if rec.type != .OPT {
				continue
			}
			// One already went out ahead of the record that overflowed, and a
			// message carrying two OPT records is one whose readers are
			// entitled to disagree about which of them is the message's.
			if opt_written {
				break
			}
			mark := len(w.buf)
			w.compress = false
			w_record(&w, rec) or_return
			if len(w.buf) > max_size {
				resize(&w.buf, mark)
				/*
				An rcode of 16 or more lives half in the header and half in this
				record's TTL (RFC 6891 section 6.1.3), so a message that loses
				the record goes out as a different rcode: BADVERS read as NOERROR
				over an empty answer section, which is a NODATA, and BADCOOKIE as
				YXRRSET. So that one is a truncation after all - the client is
				sent to TCP, where the record fits and the rcode it was actually
				answered with arrives.

				`server.match_client_opt` refuses to strip an OPT record from
				those same answers for the same reason, and `dns.error_response`
				will not fall back to a header for one. Not reachable through the
				server, where `response_limit` floors at 512 bytes and the
				largest composed-rcode reply it builds is under 300 - and this
				procedure is exported, so it is not resting on that.
				*/
				if rec.ttl & 0xff00_0000 != 0 {
					truncated = true
				}
			} else {
				counts[2] += 1
			}
			break
		}
	}

	flags := m.flags
	if truncated {
		flags.tc = true
	}
	fv := transmute(u16)flags

	w.buf[0] = u8(m.id >> 8)
	w.buf[1] = u8(m.id)
	w.buf[2] = u8(fv >> 8)
	w.buf[3] = u8(fv)
	w.buf[4] = u8(qdcount >> 8)
	w.buf[5] = u8(qdcount)
	w.buf[6] = u8(counts[0] >> 8)
	w.buf[7] = u8(counts[0])
	w.buf[8] = u8(counts[1] >> 8)
	w.buf[9] = u8(counts[1])
	w.buf[10] = u8(counts[2] >> 8)
	w.buf[11] = u8(counts[2])

	return w.buf[:], truncated, .None
}
