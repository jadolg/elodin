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
Serialise a message, truncating at `max_size` if necessary.

When records have to be dropped the TC bit is set and, if the additional section
carried an OPT record, that record is re-appended so the client still sees our
EDNS parameters.
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

	outer: for section, si in sections {
		for rec in section {
			mark := len(w.buf)
			w_record(&w, rec) or_return
			if len(w.buf) > max_size {
				resize(&w.buf, mark)
				truncated = true
				break outer
			}
			counts[si] += 1
		}
	}

	if truncated {
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
			mark := len(w.buf)
			w.compress = false
			w_record(&w, rec) or_return
			if len(w.buf) > max_size {
				resize(&w.buf, mark)
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
