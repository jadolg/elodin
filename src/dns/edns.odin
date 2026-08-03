package dns

import "core:mem"

/*
EDNS0 options, read off a decoded message and written back into an encoded one.

The writing half works on wire bytes rather than on a `Message` because that is
the shape answers have here: an upstream reply or a cache entry passes through
this server as the bytes it arrived as, and decoding one only to re-encode it
would throw away the name compression it came with. So an option is spliced into
the OPT record's RDATA where that is provably safe, and the message is rebuilt
only when it is not.
*/

find_edns_option :: proc(m: Message, code: EDNS_Option_Code) -> (data: []u8, found: bool) {
	opt, has_opt := find_opt(m)
	if !has_opt {
		return nil, false
	}
	rdata, is_opt := opt.data.(Rdata_OPT)
	if !is_opt {
		return nil, false
	}
	for o in rdata.options {
		if o.code == u16(code) {
			return o.data, true
		}
	}
	return nil, false
}

/*
Put `data` into the message's OPT record under `code`, replacing any option
already there.

Fails when the message has no OPT record - an EDNS option has nowhere to live
without one - or when it cannot be walked.
*/
set_edns_option :: proc(
	msg: []u8,
	code: EDNS_Option_Code,
	data: []u8,
	allocator := context.allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	return rewrite_edns_option(msg, u16(code), data, false, allocator)
}

/*
As `set_edns_option`, but for a message that may have no OPT record at all: one
advertising `udp_size` is added to hold the option.

Needed on the way out to a client, where the answer may have come from an
upstream that dropped EDNS on the floor. The client asked with an OPT record and
expects one back; refusing to answer at all because the upstream is old would be
the worse trade.
*/
ensure_edns_option :: proc(
	msg: []u8,
	code: EDNS_Option_Code,
	data: []u8,
	udp_size: u16,
	allocator := context.allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	if out, ok = rewrite_edns_option(msg, u16(code), data, false, allocator); ok {
		return out, true
	}

	m, derr := decode_message(msg, allocator)
	if derr != .None {
		return nil, false
	}
	if _, has_opt := find_opt(m); has_opt {
		// It has one and the rewrite still failed, so the message is not
		// something to hand back half-changed.
		return nil, false
	}

	options := make([]EDNS_Option, 1, allocator)
	options[0] = EDNS_Option {
		code = u16(code),
		data = data,
	}
	// DO stays clear: this answer reached us without signatures, and the bit
	// would say otherwise.
	opt := make_opt(udp_size, false)
	opt.data = Rdata_OPT{options = options}

	additional := make([dynamic]Record, 0, len(m.additional) + 1, allocator)
	append(&additional, ..m.additional)
	append(&additional, opt)
	m.additional = additional[:]

	encoded, _, eerr := encode_message(m, allocator, MAX_MESSAGE)
	if eerr != .None {
		return nil, false
	}
	return encoded, true
}

// Take `code` back out. A message that never carried it is returned unchanged.
remove_edns_option :: proc(
	msg: []u8,
	code: EDNS_Option_Code,
	allocator := context.allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	return rewrite_edns_option(msg, u16(code), nil, true, allocator)
}

/*
The full response code of an encoded message, extended bits included.

`Message.flags` carries only the low four; the other eight live in the OPT
record's TTL field, so a BADCOOKIE (23) reads as YXRRSET (7) to anything that
looks at the header alone. Returns the header's own value when there is no OPT
record or the message cannot be walked, which is what those eight bits mean when
nothing supplies them.
*/
peek_rcode :: proc(msg: []u8) -> Rcode {
	if len(msg) < HEADER_SIZE {
		return .No_Error
	}
	base := u16(msg[3] & 0xf)
	span, ok := find_opt_span(msg)
	if !ok {
		return Rcode(base)
	}
	// TTL sits between the class and RDLENGTH, so it ends four bytes back.
	return Rcode(base | u16(msg[span.rdlen_pos - 4]) << 4)
}

@(private)
Opt_Span :: struct {
	// Offset of the OPT record's RDLENGTH field, which has to be corrected
	// whenever the options behind it change size.
	rdlen_pos: int,
	rd_start:  int,
	rd_end:    int,
	// Nothing follows the OPT record, so bytes may be inserted into its RDATA
	// without moving anything a compression pointer could be aimed at.
	last:      bool,
}

@(private)
find_opt_span :: proc(msg: []u8) -> (span: Opt_Span, ok: bool) {
	if len(msg) < HEADER_SIZE {
		return {}, false
	}
	qdcount := int(u16(msg[4]) << 8 | u16(msg[5]))
	/*
	Only the additional section is looked in, because that is the only section
	`find_opt` looks in. A record of type OPT anywhere else is not the message's
	EDNS record and editing it would leave the reader and the writer working on
	different bytes - the option the reader sees left standing, and a record it
	never consults quietly rewritten. A client can put one in its answer section
	for the asking.
	*/
	before := int(u16(msg[6]) << 8 | u16(msg[7]))
	before += int(u16(msg[8]) << 8 | u16(msg[9]))
	arcount := int(u16(msg[10]) << 8 | u16(msg[11]))

	pos := HEADER_SIZE
	for _ in 0 ..< qdcount {
		pos = skip_name(msg, pos) or_return
		pos += 4
		if pos > len(msg) {
			return {}, false
		}
	}
	for i in 0 ..< before + arcount {
		pos = skip_name(msg, pos) or_return
		if pos + 10 > len(msg) {
			return {}, false
		}
		rtype := Type(u16(msg[pos]) << 8 | u16(msg[pos + 1]))
		rdlength := int(u16(msg[pos + 8]) << 8 | u16(msg[pos + 9]))
		rd_start := pos + 10
		rd_end := rd_start + rdlength
		if rd_end > len(msg) {
			return {}, false
		}
		if rtype == .OPT && i >= before {
			return Opt_Span {
					rdlen_pos = pos + 8,
					rd_start = rd_start,
					rd_end = rd_end,
					last = rd_end == len(msg),
				},
				true
		}
		pos = rd_end
	}
	return {}, false
}

@(private)
Option_Site :: struct {
	start: int,
	end:   int,
	found: bool,
	// The code appears more than once, which no option this server writes is
	// allowed to do. Rewriting only the first would leave the rest for a client
	// to read instead, so these are normalised by rebuilding the message.
	dupes: bool,
}

@(private)
scan_edns_option :: proc(msg: []u8, span: Opt_Span, code: u16) -> (site: Option_Site, ok: bool) {
	p := span.rd_start
	for p + 4 <= span.rd_end {
		olen := int(u16(msg[p + 2]) << 8 | u16(msg[p + 3]))
		end := p + 4 + olen
		if end > span.rd_end {
			return {}, false
		}
		if u16(msg[p]) << 8 | u16(msg[p + 1]) == code {
			if site.found {
				site.dupes = true
			} else {
				site = Option_Site {
					start = p,
					end   = end,
					found = true,
				}
			}
		}
		p = end
	}
	// A trailing byte or three is an option header cut short.
	if p != span.rd_end {
		return {}, false
	}
	return site, true
}

@(private)
rewrite_edns_option :: proc(
	msg: []u8,
	code: u16,
	data: []u8,
	remove: bool,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	if !remove && len(data) > 0xffff {
		return nil, false
	}

	span := find_opt_span(msg) or_return
	site := scan_edns_option(msg, span, code) or_return

	if remove && !site.found {
		return msg, true
	}
	if !span.last || site.dupes {
		return rebuild_edns_option(msg, code, data, remove, allocator)
	}

	cut_start := site.start if site.found else span.rd_end
	cut_end := site.end if site.found else span.rd_end
	written := 0 if remove else 4 + len(data)
	delta := written - (cut_end - cut_start)

	rdlen := span.rd_end - span.rd_start + delta
	if rdlen > 0xffff {
		return nil, false
	}

	out = make([]u8, len(msg) + delta, allocator)
	copy(out, msg[:cut_start])
	p := cut_start
	if !remove {
		out[p] = u8(code >> 8)
		out[p + 1] = u8(code)
		out[p + 2] = u8(len(data) >> 8)
		out[p + 3] = u8(len(data))
		copy(out[p + 4:], data)
		p += written
	}
	copy(out[p:], msg[cut_end:])

	out[span.rdlen_pos] = u8(rdlen >> 8)
	out[span.rdlen_pos + 1] = u8(rdlen)
	return out, true
}

// The slow path: decode, fix the option list, encode again.
@(private)
rebuild_edns_option :: proc(
	msg: []u8,
	code: u16,
	data: []u8,
	remove: bool,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	m, derr := decode_message(msg, allocator)
	if derr != .None {
		return nil, false
	}
	for &rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, _ := rec.data.(Rdata_OPT)
		options := make([dynamic]EDNS_Option, 0, len(rdata.options) + 1, allocator)
		written := false
		for o in rdata.options {
			if o.code == code {
				if remove || written {
					continue
				}
				append(&options, EDNS_Option{code = code, data = data})
				written = true
				continue
			}
			append(&options, o)
		}
		if !remove && !written {
			append(&options, EDNS_Option{code = code, data = data})
		}
		rec.data = Rdata_OPT{options = options[:]}

		encoded, _, eerr := encode_message(m, allocator, MAX_MESSAGE)
		if eerr != .None {
			return nil, false
		}
		return encoded, true
	}
	return nil, false
}
