package itest

import "core:mem"

/*
The deterministic upstream the parity check compares against.

Answers any question at all, from a zone synthesised out of a hash of the name
and type, so the generator never has to stay inside a list of names somebody
wrote down. The same question always produces the same answer, which is what
makes a failing seed reproducible.

Built byte by byte rather than with `elodin:dns`, for the reason
`parity_wire.odin` gives: an upstream that encoded its answers with the codec
under test would only ever hand elodin messages that codec already agrees with,
and the records worth worrying about are exactly the ones it does not model.

What the zone is for is coverage of shapes rather than realism. Every RR type
the suite can think of, a compressed name inside the RDATA of each type that may
carry one, character-strings that are empty and character-strings that are full,
TTLs at both ends of their range, unassigned types with opaque RDATA, answers
that fit a datagram and answers that cannot.
*/

@(private = "file")
PM_ZONE :: "parity.test."

// The server half of the cookie this mock issues. Fixed, so a test can tell it
// from one elodin minted.
@(private = "file")
PM_SERVER_COOKIE := []u8{0x9a, 0x11, 0x7e, 0x5e, 0x5e, 0x7e, 0x11, 0x9a}

/*
A response to `query`.

`over_tcp` selects between the whole answer and the truncated stub a datagram
gets when the whole answer would not fit what the query advertised - which is
what a real server does, and what puts elodin's own truncation path under the
comparison rather than around it.
*/
parity_synth_reply :: proc(
	query: []u8,
	over_tcp: bool,
	allocator := context.allocator,
) -> []u8 {
	name, qtype, qclass, q_end, ok := pm_question(query, allocator)
	if !ok {
		return pm_formerr(query, allocator)
	}

	seed := pm_hash(name, qtype)
	r := Pg_Rand{state = seed}
	shape := int(pg_next(&r) % 16)

	body := make([dynamic]u8, 0, 512, allocator)
	counts: [3]u16
	rcode := u16(0)
	aa := false

	// A class this zone does not serve is refused, the way a real server does.
	if qclass != 1 && qclass != 255 {
		rcode = 5
	} else {
		switch shape {
		case 0:
			rcode = 3
			counts[1] = pm_soa_authority(&body, &r, allocator)
		case 1:
			counts[1] = pm_soa_authority(&body, &r, allocator)
		case 2:
			counts[0] = pm_cname_chain(&body, &r, qtype, allocator)
		case 3:
			counts[0] = pm_answer(&body, &r, qtype, allocator)
			counts[1] = pm_ns_authority(&body, &r, allocator)
			counts[2] = pm_glue(&body, &r, allocator)
		case 4:
			counts[0] = pm_large_answer(&body, &r, qtype, allocator)
		case 5:
			aa = true
			counts[0] = pm_answer(&body, &r, qtype, allocator)
		case:
			counts[0] = pm_answer(&body, &r, qtype, allocator)
		}
	}

	// The OPT record goes last, after every other record has been written, so
	// the additional count is settled before it is bumped for this one.
	opt := pm_opt(query, &r, shape, allocator)
	if opt != nil {
		append(&body, ..opt)
		counts[2] += 1
	}

	reply := pm_assemble(query, q_end, body[:], counts, rcode, aa, allocator)

	// Truncation, decided against what the query said it could receive rather
	// than against a constant: a client that advertised 4096 gets 4096.
	if !over_tcp {
		limit := pm_advertised_size(query)
		if len(reply) > limit {
			/*
			The records go; the OPT record stays.

			A truncated answer is still an EDNS answer, and it still carries the
			cookie the exchange is running on - drop the OPT here and the
			resolver is handed a reply with no cookie to a query that had one,
			which it is right to throw away, and the retry over TCP it was being
			told to make never happens. Which is the same defect this check
			found in elodin's own encoder; a mock that repeated it would be
			testing the recovery path with a message no real server sends.
			*/
			counts_with_opt := [3]u16{0, 0, 0}
			body_with_opt := opt
			if opt != nil {
				counts_with_opt[2] = 1
			}
			stub := pm_assemble(
				query,
				q_end,
				body_with_opt,
				counts_with_opt,
				rcode,
				aa,
				allocator,
			)
			stub[2] |= 0x02
			return stub
		}
	}
	return reply
}

// --- message assembly ------------------------------------------------------

@(private = "file")
pm_assemble :: proc(
	query: []u8,
	q_end: int,
	body: []u8,
	counts: [3]u16,
	rcode: u16,
	aa: bool,
	allocator: mem.Allocator,
) -> []u8 {
	out := make([dynamic]u8, 0, q_end + len(body), allocator)
	// Header and question copied from the query, so the question comes back
	// exactly as it was asked - the case included, which is what a client
	// randomising it is relying on.
	append(&out, ..query[:q_end])

	flags := u16(0x8000) | u16(0x0080) // QR, RA
	if query[2] & 0x01 != 0 {
		flags |= 0x0100 // RD, echoed
	}
	if query[3] & 0x10 != 0 {
		flags |= 0x0010 // CD, echoed
	}
	if aa {
		flags |= 0x0400
	}
	flags |= rcode & 0xf

	out[2] = u8(flags >> 8)
	out[3] = u8(flags)
	pm_set16(out[:], 4, 1)
	pm_set16(out[:], 6, counts[0])
	pm_set16(out[:], 8, counts[1])
	pm_set16(out[:], 10, counts[2])

	append(&out, ..body)
	return out[:]
}

@(private = "file")
pm_formerr :: proc(query: []u8, allocator: mem.Allocator) -> []u8 {
	out := make([]u8, 12, allocator)
	copy(out, query[:min(len(query), 12)])
	out[2] = 0x80
	out[3] = 0x01
	for i in 4 ..< 12 {
		out[i] = 0
	}
	return out
}

/*
The question, as the mock needs it.

Its own walk rather than `pw_parse`'s, because a query is not a response and
most of what that returns does not exist here; and its own rather than
`elodin:dns`'s, for the reason at the top of the file.
*/
@(private = "file")
pm_question :: proc(
	query: []u8,
	allocator: mem.Allocator,
) -> (
	name: []u8,
	qtype, qclass: u16,
	q_end: int,
	ok: bool,
) {
	if len(query) < 12 {
		return nil, 0, 0, 0, false
	}
	if pm_u16(query, 4) != 1 {
		return nil, 0, 0, 0, false
	}
	n, next, name_ok := pw_name(query, 12, allocator)
	if !name_ok || next + 4 > len(query) {
		return nil, 0, 0, 0, false
	}
	pw_lower_name(n)
	return n, pm_u16(query, next), pm_u16(query, next + 2), next + 4, true
}

// What the query said it could receive: its EDNS payload size, or the 512 bytes
// a message without EDNS is held to (RFC 1035 section 4.2.1).
@(private = "file")
pm_advertised_size :: proc(query: []u8) -> int {
	m := pw_parse(query, context.temp_allocator)
	if !m.ok || !m.opt.present {
		return 512
	}
	// A payload size below the bare 512 is not a smaller limit; RFC 6891
	// section 6.2.5 says to treat it as 512.
	return max(int(m.opt.udp_size), 512)
}

// --- sections --------------------------------------------------------------

/*
Records of the type that was asked for.

The owner name is always the compression pointer to the question, which is what
a real server writes and what makes every answer here exercise the reader's
decompression rather than only the easy path.
*/
@(private = "file")
pm_answer :: proc(
	body: ^[dynamic]u8,
	r: ^Pg_Rand,
	qtype: u16,
	allocator: mem.Allocator,
) -> u16 {
	if qtype == 255 {
		// ANY: a spread, because an answer holding several types at once is
		// where a re-encode drops the one it has no structure for.
		pm_rr(body, PM_PTR_Q, 1, 1, 300, pm_rdata(r, 1, allocator), allocator)
		pm_rr(body, PM_PTR_Q, 28, 1, 300, pm_rdata(r, 28, allocator), allocator)
		pm_rr(body, PM_PTR_Q, 16, 1, 300, pm_rdata(r, 16, allocator), allocator)
		pm_rr(body, PM_PTR_Q, 15, 1, 300, pm_rdata(r, 15, allocator), allocator)
		return 4
	}
	count := u16(1 + pg_int(r, 3))
	for i in 0 ..< count {
		// TTLs at both ends: zero is legal and means "do not cache", and the
		// top of the range is where a signed-vs-unsigned slip shows up.
		ttl := u32(300)
		switch i {
		case 1:
			ttl = 0
		case 2:
			ttl = 0x7fffffff
		}
		pm_rr(body, PM_PTR_Q, qtype, 1, ttl, pm_rdata(r, qtype, allocator), allocator)
	}
	return count
}

// Enough records that the answer cannot fit a datagram, so the truncate-and-
// retry path is walked rather than assumed.
@(private = "file")
pm_large_answer :: proc(
	body: ^[dynamic]u8,
	r: ^Pg_Rand,
	qtype: u16,
	allocator: mem.Allocator,
) -> u16 {
	count := u16(40)
	for _ in 0 ..< count {
		pm_rr(body, PM_PTR_Q, qtype, 1, 3600, pm_rdata(r, qtype, allocator), allocator)
	}
	return count
}

@(private = "file")
pm_cname_chain :: proc(
	body: ^[dynamic]u8,
	r: ^Pg_Rand,
	qtype: u16,
	allocator: mem.Allocator,
) -> u16 {
	alias := pm_name("alias." + PM_ZONE, allocator)
	pm_rr(body, PM_PTR_Q, 5, 1, 600, alias, allocator)
	if qtype == 5 {
		return 1
	}
	pm_rr(body, alias, qtype, 1, 600, pm_rdata(r, qtype, allocator), allocator)
	return 2
}

@(private = "file")
pm_soa_authority :: proc(body: ^[dynamic]u8, r: ^Pg_Rand, allocator: mem.Allocator) -> u16 {
	pm_rr(body, pm_name(PM_ZONE, allocator), 6, 1, 900, pm_rdata(r, 6, allocator), allocator)
	return 1
}

@(private = "file")
pm_ns_authority :: proc(body: ^[dynamic]u8, r: ^Pg_Rand, allocator: mem.Allocator) -> u16 {
	pm_rr(
		body,
		pm_name(PM_ZONE, allocator),
		2,
		1,
		1800,
		pm_name("ns1." + PM_ZONE, allocator),
		allocator,
	)
	return 1
}

@(private = "file")
pm_glue :: proc(body: ^[dynamic]u8, r: ^Pg_Rand, allocator: mem.Allocator) -> u16 {
	ns := pm_name("ns1." + PM_ZONE, allocator)
	pm_rr(body, ns, 1, 1, 1800, pm_rdata(r, 1, allocator), allocator)
	pm_rr(body, ns, 28, 1, 1800, pm_rdata(r, 28, allocator), allocator)
	return 2
}

/*
The response's OPT record.

Present whenever the query carried one, which is what a server that speaks EDNS
does. The DO bit is echoed. What the options hold varies by shape: NSID names
the server that answered, and an unassigned code is there to ask whether an
option nothing in the path recognises still reaches the client.
*/
@(private = "file")
pm_opt :: proc(query: []u8, r: ^Pg_Rand, shape: int, allocator: mem.Allocator) -> []u8 {
	q := pw_parse(query, context.temp_allocator)
	if !q.ok || !q.opt.present {
		return nil
	}

	rdata := make([dynamic]u8, 0, 32, allocator)

	/*
	A cookie, when the query carried one.

	Written here rather than by `Mock.cookies`, which would build it with
	elodin's own encoder - and the question being asked is what happens to the
	*other* options when this server takes this cookie back out. An upstream
	whose OPT record was assembled by the codec under test could not ask it.
	*/
	// NSID names the server that answered. Always present, because it is the
	// plainest case of an option a forwarder has no business dropping: it is
	// information the client asked for by name.
	nsid := "parity-mock"
	pm_put16(&rdata, 3)
	pm_put16(&rdata, u16(len(nsid)))
	append(&rdata, nsid)

	if sent, has_cookie := pw_find_option(q, 10); has_cookie && len(sent) >= 8 {
		pm_put16(&rdata, 10)
		pm_put16(&rdata, 16)
		append(&rdata, ..sent[:8])
		append(&rdata, ..PM_SERVER_COOKIE)
	}

	if shape % 4 == 1 {
		// An option nothing in the path recognises, to ask whether a code with
		// no meaning to this server still reaches the client.
		pm_put16(&rdata, 65002)
		pm_put16(&rdata, 4)
		append(&rdata, 0xde, 0xad, 0xbe, 0xef)
	}

	/*
	An idle timeout for a connection this hop is not an end of.

	edns-tcp-keepalive is hop by hop, so an upstream's is meaningless to the
	client and must not reach it - `dns.strip_edns_options` is what stops it, on
	every transport and whether or not elodin writes one of its own. Sent as a
	number elodin would never write, so the two are told apart on the transports
	where both could be present: 1s against the 10s `parity_config` pins.

	Unconditional, because the leak it asks about is: the check that catches it
	(`pc_client_mintable`) is the one that goes quiet on exactly the answers
	elodin mints no keepalive into, and those are the answers this has to be in.
	*/
	pm_put16(&rdata, 11)
	pm_put16(&rdata, 2)
	append(&rdata, 0, 10)

	out := make([dynamic]u8, 0, 16 + len(rdata), allocator)
	append(&out, 0) // root owner name
	pm_put16(&out, 41)
	pm_put16(&out, 1232) // the payload size this mock can receive
	append(&out, 0, 0) // extended rcode, version
	pm_put16(&out, q.opt.flags & PW_DO)
	pm_put16(&out, u16(len(rdata)))
	append(&out, ..rdata[:])
	return out[:]
}

// --- records ---------------------------------------------------------------

// The two bytes that point at the question's name, which always starts at
// offset 12.
@(private)
PM_PTR_Q := []u8{0xc0, 0x0c}

@(private = "file")
pm_rr :: proc(
	body: ^[dynamic]u8,
	name: []u8,
	type, class: u16,
	ttl: u32,
	rdata: []u8,
	allocator: mem.Allocator,
) {
	append(body, ..name)
	pm_put16(body, type)
	pm_put16(body, class)
	pm_put32(body, ttl)
	pm_put16(body, u16(len(rdata)))
	append(body, ..rdata)
}

@(private)
pm_name :: proc(text: string, allocator: mem.Allocator) -> []u8 {
	out := make([]u8, len(text) + 1, allocator)
	pos := 0
	start := 0
	for i in 0 ..< len(text) {
		if text[i] != '.' {
			continue
		}
		out[pos] = u8(i - start)
		copy(out[pos + 1:], text[start:i])
		pos += 1 + (i - start)
		start = i + 1
	}
	out[pos] = 0
	return out[:pos + 1]
}

@(private)
pm_bytes :: proc(r: ^Pg_Rand, n: int, allocator: mem.Allocator) -> []u8 {
	out := make([]u8, n, allocator)
	for i in 0 ..< n {
		out[i] = u8(pg_next(r) & 0xff)
	}
	return out
}

@(private = "file")
pm_hash :: proc(name: []u8, qtype: u16) -> u64 {
	// FNV-1a, so the zone a name gets does not move when anything else here
	// changes.
	h := u64(0xcbf29ce484222325)
	for b in name {
		h = (h ~ u64(b)) * 0x100000001b3
	}
	h = (h ~ u64(qtype)) * 0x100000001b3
	return h
}

@(private = "file")
pm_u16 :: proc(b: []u8, off: int) -> u16 {
	return u16(b[off]) << 8 | u16(b[off + 1])
}

@(private = "file")
pm_set16 :: proc(b: []u8, off: int, v: u16) {
	b[off] = u8(v >> 8)
	b[off + 1] = u8(v)
}

@(private)
pm_put16 :: proc(buf: ^[dynamic]u8, v: u16) {
	append(buf, u8(v >> 8), u8(v))
}

@(private)
pm_put32 :: proc(buf: ^[dynamic]u8, v: u32) {
	append(buf, u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v))
}
