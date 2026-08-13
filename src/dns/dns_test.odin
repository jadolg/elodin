package dns

import "core:mem"
import "core:testing"

@(test)
test_name_roundtrip :: proc(t: ^testing.T) {
	names := []string{".", "com.", "www.example.com.", "a.b.c.d.e.f.", "xn--bcher-kva.de."}
	for name in names {
		buf: [MAX_NAME_WIRE]u8
		n, err := encode_name(name, buf[:])
		testing.expect_value(t, err, Encode_Error.None)

		got, next, derr := decode_name(buf[:n], 0, context.temp_allocator)
		testing.expect_value(t, derr, Decode_Error.None)
		testing.expect_value(t, next, n)
		testing.expect_value(t, got, name)
	}
	free_all(context.temp_allocator)
}

@(test)
test_name_escaping :: proc(t: ^testing.T) {
	// A label containing a literal dot and a space must survive intact.
	wire := []u8{5, 'a', '.', 'b', ' ', 'c', 3, 'c', 'o', 'm', 0}
	got, _, err := decode_name(wire, 0, context.temp_allocator)
	testing.expect_value(t, err, Decode_Error.None)
	testing.expect_value(t, got, "a\\046b\\032c.com.")

	buf: [MAX_NAME_WIRE]u8
	n, eerr := encode_name(got, buf[:])
	testing.expect_value(t, eerr, Encode_Error.None)
	testing.expect(t, mem.compare(buf[:n], wire) == 0, "re-encoded wire differs")
	free_all(context.temp_allocator)
}

@(test)
test_name_pointer_loop_rejected :: proc(t: ^testing.T) {
	// Pointer at offset 0 aiming at itself: must not hang.
	wire := []u8{0xc0, 0x00}
	_, _, err := decode_name(wire, 0, context.temp_allocator)
	testing.expect(t, err != .None, "self-referential pointer accepted")
	free_all(context.temp_allocator)
}

@(test)
test_query_roundtrip :: proc(t: ^testing.T) {
	q := Message {
		id       = 0x1234,
		question = []Question{{name = "www.example.com.", type = .A, class = .IN}},
	}
	q.flags.rd = true

	wire, trunc, err := encode_message(q, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, !trunc, "unexpected truncation")

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, got.id, u16(0x1234))
	testing.expect(t, got.flags.rd, "RD not preserved")
	testing.expect(t, !got.flags.qr, "QR should be clear")
	testing.expect_value(t, len(got.question), 1)
	testing.expect_value(t, got.question[0].name, "www.example.com.")
	testing.expect_value(t, got.question[0].type, Type.A)
	free_all(context.temp_allocator)
}

@(test)
test_answer_roundtrip_all_rdata :: proc(t: ^testing.T) {
	m := Message {
		id       = 7,
		question = []Question{{name = "example.com.", type = .ANY, class = .IN}},
		answer   = []Record {
			{name = "example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {93, 184, 216, 34}}},
			{
				name = "example.com.",
				type = .AAAA,
				class = .IN,
				ttl = 300,
				data = Rdata_AAAA{addr = {0x26, 0x06, 0x28, 0, 2, 0x20, 0, 1, 2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46},},
			},
			{name = "example.com.", type = .NS, class = .IN, ttl = 600, data = Rdata_Name{name = "a.iana-servers.net."}},
			{
				name = "example.com.",
				type = .MX,
				class = .IN,
				ttl = 600,
				data = Rdata_MX{preference = 10, exchange = "mail.example.com."},
			},
			{
				name = "example.com.",
				type = .TXT,
				class = .IN,
				ttl = 60,
				data = Rdata_TXT{strings = []string{"v=spf1 -all", "second"}},
			},
			{
				name = "_sip._tcp.example.com.",
				type = .SRV,
				class = .IN,
				ttl = 60,
				data = Rdata_SRV{priority = 1, weight = 2, port = 5060, target = "sip.example.com."},
			},
			{
				name = "example.com.",
				type = .CAA,
				class = .IN,
				ttl = 60,
				data = Rdata_CAA{flags = 0, tag = "issue", value = "letsencrypt.org"},
			},
			{
				name = "example.com.",
				type = .SVCB,
				class = .IN,
				ttl = 60,
				data = Rdata_SVCB{priority = 1, target = "svc.example.com.", params = []u8{0, 1, 0, 3, 2, 'h', '2'}},
			},
			{
				name = "example.com.",
				type = .DS,
				class = .IN,
				ttl = 60,
				data = Rdata_Raw{data = []u8{0x12, 0x34, 8, 2, 0xde, 0xad, 0xbe, 0xef}},
			},
		},
		authority = []Record {
			{
				name = "example.com.",
				type = .SOA,
				class = .IN,
				ttl = 3600,
				data = Rdata_SOA {
					ns = "ns.icann.org.",
					mbox = "noc.dns.icann.org.",
					serial = 2024010101,
					refresh = 7200,
					retry = 3600,
					expire = 1209600,
					minimum = 3600,
				},
			},
		},
	}
	m.flags.qr = true
	m.flags.ra = true

	wire, trunc, err := encode_message(m, context.temp_allocator, MAX_MESSAGE)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, !trunc, "unexpected truncation")

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, len(got.answer), len(m.answer))
	testing.expect_value(t, len(got.authority), 1)

	a := got.answer[0].data.(Rdata_A)
	testing.expect_value(t, a.addr[0], u8(93))

	ns := got.answer[2].data.(Rdata_Name)
	testing.expect_value(t, ns.name, "a.iana-servers.net.")

	mx := got.answer[3].data.(Rdata_MX)
	testing.expect_value(t, mx.preference, u16(10))
	testing.expect_value(t, mx.exchange, "mail.example.com.")

	txt := got.answer[4].data.(Rdata_TXT)
	testing.expect_value(t, len(txt.strings), 2)
	testing.expect_value(t, txt.strings[0], "v=spf1 -all")

	srv := got.answer[5].data.(Rdata_SRV)
	testing.expect_value(t, srv.port, u16(5060))
	testing.expect_value(t, srv.target, "sip.example.com.")

	caa := got.answer[6].data.(Rdata_CAA)
	testing.expect_value(t, caa.tag, "issue")
	testing.expect_value(t, caa.value, "letsencrypt.org")

	svcb := got.answer[7].data.(Rdata_SVCB)
	testing.expect_value(t, svcb.priority, u16(1))
	testing.expect_value(t, svcb.target, "svc.example.com.")

	ds := got.answer[8].data.(Rdata_Raw)
	testing.expect_value(t, len(ds.data), 8)

	soa := got.authority[0].data.(Rdata_SOA)
	testing.expect_value(t, soa.ns, "ns.icann.org.")
	testing.expect_value(t, soa.serial, u32(2024010101))

	free_all(context.temp_allocator)
}

@(test)
test_compression_is_used :: proc(t: ^testing.T) {
	m := Message {
		question = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer   = []Record {
			{name = "www.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {1, 2, 3, 4}}},
			{name = "www.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {5, 6, 7, 8}}},
		},
	}
	compressed, _, err := encode_message(m, context.temp_allocator, MAX_MESSAGE, compress = true)
	testing.expect_value(t, err, Encode_Error.None)
	plain, _, err2 := encode_message(m, context.temp_allocator, MAX_MESSAGE, compress = false)
	testing.expect_value(t, err2, Encode_Error.None)
	testing.expect(t, len(compressed) < len(plain), "compression did not shrink the message")

	got, derr := decode_message(compressed, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, got.answer[1].name, "www.example.com.")
	free_all(context.temp_allocator)
}

@(test)
test_truncation_sets_tc :: proc(t: ^testing.T) {
	answers := make([dynamic]Record, 0, 60, context.temp_allocator)
	for i in 0 ..< 60 {
		append(&answers, Record{name = "www.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {1, 2, 3, u8(i)}}})
	}
	m := Message {
		question = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer   = answers[:],
	}
	wire, trunc, err := encode_message(m, context.temp_allocator, MAX_UDP_SIZE)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, trunc, "expected truncation")
	testing.expect(t, len(wire) <= MAX_UDP_SIZE, "message exceeds the UDP limit")

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect(t, got.flags.tc, "TC bit not set")
	testing.expect(t, len(got.answer) < 60, "no records were dropped")
	testing.expect_value(t, len(got.question), 1)
	free_all(context.temp_allocator)
}

@(test)
test_edns_opt :: proc(t: ^testing.T) {
	q := Message {
		id         = 1,
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []Record{make_opt(1232, true)},
	}
	wire, _, err := encode_message(q, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, edns_udp_size(got), u16(1232))
	testing.expect(t, edns_do(got), "DO bit lost")
	free_all(context.temp_allocator)
}

@(test)
test_ttl_scan_and_patch :: proc(t: ^testing.T) {
	m := Message {
		id         = 9,
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		answer     = []Record {
			{name = "example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {1, 2, 3, 4}}},
			{name = "example.com.", type = .A, class = .IN, ttl = 100, data = Rdata_A{addr = {5, 6, 7, 8}}},
		},
		additional = []Record{make_opt(1232, false)},
	}
	m.flags.qr = true
	wire, _, err := encode_message(m, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	offsets, ok := scan_ttl_offsets(wire, context.temp_allocator)
	testing.expect(t, ok, "ttl scan failed")
	// The OPT record must not be counted.
	testing.expect_value(t, len(offsets), 2)

	originals := read_ttls(wire, offsets, context.temp_allocator)
	testing.expect_value(t, originals[0], u32(300))
	testing.expect_value(t, originals[1], u32(100))

	patch_ttls(wire, offsets, originals, 120, 0)
	got, derr := decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, got.answer[0].ttl, u32(180))
	testing.expect_value(t, got.answer[1].ttl, u32(0))
	// OPT flags survived untouched.
	testing.expect_value(t, edns_udp_size(got), u16(1232))
	free_all(context.temp_allocator)
}

@(test)
test_decode_rejects_absurd_counts :: proc(t: ^testing.T) {
	// Header claims 65535 answers in a 12-byte message.
	wire := []u8{0, 1, 0x81, 0x80, 0, 0, 0xff, 0xff, 0, 0, 0, 0}
	_, err := decode_message(wire, context.temp_allocator)
	testing.expect(t, err != .None, "absurd record count accepted")
	free_all(context.temp_allocator)
}

@(test)
test_peek_helpers :: proc(t: ^testing.T) {
	q := Message {
		id       = 0xabcd,
		question = []Question{{name = "block.me.", type = .AAAA, class = .IN}},
	}
	wire, _, err := encode_message(q, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	id, ok := peek_id(wire)
	testing.expect(t, ok, "peek_id failed")
	testing.expect_value(t, id, u16(0xabcd))

	pq, qok := peek_question(wire, context.temp_allocator)
	testing.expect(t, qok, "peek_question failed")
	testing.expect_value(t, pq.name, "block.me.")
	testing.expect_value(t, pq.type, Type.AAAA)

	set_id_in_place(wire, 0x0001)
	id2, _ := peek_id(wire)
	testing.expect_value(t, id2, u16(1))
	free_all(context.temp_allocator)
}

@(test)
test_name_helpers :: proc(t: ^testing.T) {
	testing.expect_value(t, name_parent("www.example.com."), "example.com.")
	testing.expect_value(t, name_parent("com."), ".")
	testing.expect_value(t, name_parent("."), ".")
	testing.expect(t, name_equal_fold("WWW.Example.COM.", "www.example.com."), "fold compare failed")
	testing.expect_value(t, name_trim_root("example.com."), "example.com")

	c := name_canonical("Example.COM", context.temp_allocator)
	testing.expect_value(t, c, "example.com.")
	free_all(context.temp_allocator)
}

/*
A record whose owner name cannot be walked aborts the scan after the offset list
has already been allocated. The list is the scanner's to release on the way out;
`scan_ttl_offsets` is called with the cache's own allocator, so anything left
behind there is a heap leak per malformed response.
*/
@(test)
test_scan_ttl_offsets_releases_on_bad_name :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	msg := [dynamic]u8{}
	defer delete(msg)
	// Header: one question, three answers.
	append(&msg, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0)
	// A well-formed question, so the scan gets past it and allocates the list.
	append(&msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	append(&msg, 0, 1, 0, 1)
	// The first answer's name: 0x40 is a reserved label type, which `skip_name`
	// refuses. Any byte with the top two bits 01 or 10 would do.
	append(&msg, 0x40)

	offsets, ok := scan_ttl_offsets(msg[:], allocator)
	testing.expect(t, !ok, "a reserved label type was accepted")
	testing.expect(t, offsets == nil, "a failed scan returned a list")

	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes leaked, allocated at %v", entry.size, entry.location)
	}
}

/*
`encode_message` hands the caller its output buffer and abandons everything else
the writer allocated: the label-offset list, the compression map, and a cloned
string per distinct name suffix recorded in it.

Nothing leaks in the server, where every caller threads a per-request arena
through and `free_all` reclaims the lot. But the allocator parameter defaults to
`context.allocator`, so a caller that takes the signature at its word - a test, a
tool, anything that does not know the arena convention - leaks per message
encoded, and there is nothing in the signature to warn it off.
*/
@(test)
test_encode_message_releases_its_writer :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	// Names sharing suffixes, so the compression map is populated and its keys
	// are actually cloned rather than the map staying empty.
	m := Message {
		id = 0x1234,
		question = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer = []Record {
			{
				name = "www.example.com.",
				type = .CNAME,
				class = .IN,
				ttl = 300,
				data = Rdata_Name{name = "host.example.com."},
			},
			{name = "host.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 1}}},
			{name = "mail.example.com.", type = .A, class = .IN, ttl = 300, data = Rdata_A{addr = {192, 0, 2, 2}}},
		},
	}
	m.flags.qr = true

	wire, _, err := encode_message(m, allocator)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect(t, len(wire) > 0, "nothing was encoded")

	// The buffer is the caller's, and is meant to be the only thing that is.
	delete(wire, allocator)

	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes left held, allocated at %v", entry.size, entry.location)
	}
	testing.expectf(t, len(track.bad_free_array) == 0, "%d bad frees", len(track.bad_free_array))
}

/*
An encode that gives up owes the same debt, and one more besides: the output
buffer it was part way through filling is abandoned rather than returned, so
nothing outside is left holding a reference to free.
*/
@(test)
test_encode_message_releases_its_writer_on_error :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	m := Message {
		id       = 0x1234,
		question = []Question{{name = "www.example.com.", type = .A, class = .IN}},
	}

	// Smaller than the header, so the question is written and then refused.
	wire, _, err := encode_message(m, allocator, 4)
	testing.expect(t, err != .None, "a message past max_size was accepted")
	testing.expect(t, wire == nil, "a refused encode still returned a buffer")

	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%d bytes left held, allocated at %v", entry.size, entry.location)
	}
	testing.expectf(t, len(track.bad_free_array) == 0, "%d bad frees", len(track.bad_free_array))
}

@(test)
test_peek_udp_size_reads_the_opt_record :: proc(t: ^testing.T) {
	// No OPT: the 512 bytes a responder has to assume without being told.
	bare := Message {
		id       = 1,
		question = []Question{{name = "example.com.", type = .A, class = .IN}},
	}
	bare_wire, _, bare_err := encode_message(bare, context.temp_allocator)
	testing.expect_value(t, bare_err, Encode_Error.None)
	testing.expect_value(t, peek_udp_size(bare_wire), u16(MAX_UDP_SIZE))

	// With one, whatever it actually says — unclamped, since the point is to
	// size a buffer for what the peer may send.
	for advertised in ([]u16{512, 1232, 4096, 8192, 65535}) {
		m := Message {
			id         = 1,
			question   = []Question{{name = "example.com.", type = .A, class = .IN}},
			additional = []Record{make_opt(advertised, true)},
		}
		wire, _, err := encode_message(m, context.temp_allocator)
		testing.expect_value(t, err, Encode_Error.None)
		testing.expect_value(t, peek_udp_size(wire), advertised)
	}

	// An OPT sitting behind other records in the additional section is still
	// found, and a message that will not walk falls back to the default.
	behind := Message {
		id         = 1,
		question   = []Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []Record {
			{name = "ns.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{addr = {192, 0, 2, 1}}},
			make_opt(2048, false),
		},
	}
	behind_wire, _, behind_err := encode_message(behind, context.temp_allocator)
	testing.expect_value(t, behind_err, Encode_Error.None)
	testing.expect_value(t, peek_udp_size(behind_wire), u16(2048))

	testing.expect_value(t, peek_udp_size({}), u16(MAX_UDP_SIZE))
	testing.expect_value(t, peek_udp_size(behind_wire[:HEADER_SIZE + 2]), u16(MAX_UDP_SIZE))

	free_all(context.temp_allocator)
}

/*
The truncated answer a rate-limited client gets.

It is built from the query's own bytes on the read loop, without decoding them,
so it is a parser of hostile input in its own right: what it must never do is
read past what arrived, and what it must always produce is something a client
recognises as an answer to its question with TC set.
*/
@(test)
test_truncated_response :: proc(t: ^testing.T) {
	query := Message {
		id       = 0xbeef,
		question = []Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, err := encode_message(query, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)

	out, ok := truncated_response(wire, context.temp_allocator)
	testing.expect(t, ok, "a well-formed query got no truncated answer")
	testing.expect(t, len(out) < 64, "the answer is meant to be too small to reflect")

	decoded, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expect_value(t, decoded.id, u16(0xbeef))
	testing.expect(t, decoded.flags.qr, "QR not set")
	testing.expect(t, decoded.flags.tc, "TC not set, which is the whole message")
	testing.expect(t, decoded.flags.ra, "RA not set")
	// RD comes back as the client sent it; AD never does.
	testing.expect(t, decoded.flags.rd, "RD not echoed")
	testing.expect(t, !decoded.flags.ad, "AD set on an answer that vouches for nothing")
	testing.expect_value(t, rcode_of(decoded), Rcode.No_Error)
	testing.expect_value(t, len(decoded.question), 1)
	testing.expect_value(t, decoded.question[0].name, "example.com.")
	testing.expect_value(t, len(decoded.answer), 0)
	testing.expect_value(t, len(decoded.additional), 0)

	/*
	Everything else is a header, which is still an answer: a client reads TC and
	comes back over TCP. What matters is that none of these walks off the end.
	*/
	Case :: struct {
		wire: []u8,
		ok:   bool,
		what: string,
	}

	short := wire[:HEADER_SIZE - 1]
	header_only := wire[:HEADER_SIZE]
	// qdcount says one, and the name never ends.
	unterminated := make([]u8, HEADER_SIZE + 3, context.temp_allocator)
	copy(unterminated, wire[:HEADER_SIZE])
	unterminated[HEADER_SIZE] = 8
	// qdcount says one, and the question is a compression pointer, which is
	// not legal in a question and not worth echoing.
	compressed := make([]u8, HEADER_SIZE + 6, context.temp_allocator)
	copy(compressed, wire[:HEADER_SIZE])
	compressed[HEADER_SIZE] = 0xc0
	compressed[HEADER_SIZE + 1] = 0x0c
	// A name that ends exactly at the end, with no type and class behind it.
	truncated_question := wire[:HEADER_SIZE + 13]

	CASES := []Case {
		{short, false, "shorter than a header"},
		{header_only, true, "a header and nothing else"},
		{unterminated, true, "a question whose name never ends"},
		{compressed, true, "a compressed question"},
		{truncated_question, true, "a question cut off before its type"},
		{{}, false, "nothing at all"},
	}

	for c in CASES {
		got, built := truncated_response(c.wire, context.temp_allocator)
		testing.expectf(t, built == c.ok, "%s: built=%v", c.what, built)
		if !built {
			continue
		}
		testing.expectf(t, len(got) >= HEADER_SIZE, "%s: %d bytes came back", c.what, len(got))
		testing.expectf(t, got[2] & 0x80 != 0, "%s: QR not set", c.what)
		testing.expectf(t, got[2] & 0x02 != 0, "%s: TC not set", c.what)
		// Nothing is claimed that is not there.
		questions := int(got[4]) << 8 | int(got[5])
		testing.expectf(t, questions == 0 || len(got) > HEADER_SIZE, "%s: a question claimed but not carried", c.what)
		for i in 6 ..< HEADER_SIZE {
			testing.expectf(t, got[i] == 0, "%s: section count at byte %d is not zero", c.what, i)
		}
	}
	free_all(context.temp_allocator)
}

/*
RA answers whether this server supports recursive service at all - RFC 1035
section 4.1.1 - not whether the query in hand asked for or got any. A query
that arrived with RD=0 still gets RA=1 back, the same way BIND and Unbound
keep answering RA=1 to a query an ACL declines to recurse for: the capability
is on offer regardless of what this one request did with it.

Covers all three paths that build a locally-made answer: `make_response` (the
decoded path), and the two that patch a header without decoding one,
`error_response`'s malformed-query fallback and `truncated_response`. Pinned
here because it is easy to reach for the opposite rule - tying RA to RD looks
tempting next to the RD=0 refusal in `resolve_query`, and was in fact tried
and reverted; this guards against trying it again.
*/
@(test)
test_ra_is_a_capability_flag_not_tied_to_rd :: proc(t: ^testing.T) {
	question := []Question{{name = "example.com.", type = .A, class = .IN}}

	recursive := Message {
		id       = 1,
		question = question,
	}
	recursive.flags.rd = true
	resp := make_response(recursive, .No_Error, context.temp_allocator)
	testing.expect(t, resp.flags.ra, "RA not set for a query that asked for recursion")

	non_recursive := Message {
		id       = 2,
		question = question,
	}
	non_recursive.flags.rd = false
	refused := make_response(non_recursive, .Refused, context.temp_allocator)
	testing.expect(t, refused.flags.ra, "RA not set for a query that did not ask for recursion")

	// The header-patching paths: built from a query's own bytes rather than a
	// decoded Message.
	rd_wire, _, rd_err := encode_message(recursive, context.temp_allocator)
	testing.expect_value(t, rd_err, Encode_Error.None)
	no_rd_wire, _, no_rd_err := encode_message(non_recursive, context.temp_allocator)
	testing.expect_value(t, no_rd_err, Encode_Error.None)

	// An unusable Message ({}) forces the fallback that patches the query's own
	// header rather than building from a decoded one - the path a malformed
	// datagram takes, which is the only way it ever reaches `error_response`.
	err_rd, err_rd_ok := error_response(rd_wire, Message{}, .Serv_Fail, context.temp_allocator)
	testing.expect(t, err_rd_ok, "error_response built nothing for an RD=1 query")
	testing.expect(t, err_rd[3] & 0x80 != 0, "RA not set in error_response for an RD=1 query")

	err_no_rd, err_no_rd_ok := error_response(no_rd_wire, Message{}, .Serv_Fail, context.temp_allocator)
	testing.expect(t, err_no_rd_ok, "error_response built nothing for an RD=0 query")
	testing.expect(t, err_no_rd[3] & 0x80 != 0, "RA not set in error_response for an RD=0 query")

	trunc_rd, trunc_rd_ok := truncated_response(rd_wire, context.temp_allocator)
	testing.expect(t, trunc_rd_ok, "truncated_response built nothing for an RD=1 query")
	testing.expect(t, trunc_rd[3] & 0x80 != 0, "RA not set in truncated_response for an RD=1 query")

	trunc_no_rd, trunc_no_rd_ok := truncated_response(no_rd_wire, context.temp_allocator)
	testing.expect(t, trunc_no_rd_ok, "truncated_response built nothing for an RD=0 query")
	testing.expect(t, trunc_no_rd[3] & 0x80 != 0, "RA not set in truncated_response for an RD=0 query")

	free_all(context.temp_allocator)
}

@(test)
test_name_length_counts_the_root_octet :: proc(t: ^testing.T) {
	/*
	RFC 1035 2.3.4 caps a domain name at 255 octets, and that figure counts
	the length octet in front of every label as well as the zero octet that
	terminates the name; RFC 2181 11 restates it. The decoder and the encoder
	have to draw the line in the same place. A name only the decoder accepts
	is one this server will read off the wire and can never write back out,
	because every path that would re-encode it refuses - so the boundary is
	pinned here from both sides, and the largest name that fits is made to
	survive a round trip through both halves.
	*/
	// Four 50-octet labels and one 49-octet label come to 4 * 51 + 50 = 254
	// octets of labels, which the root brings to exactly 255.
	longest := make([dynamic]u8, 0, 256, context.temp_allocator)
	for _ in 0 ..< 4 {
		append(&longest, 50)
		for _ in 0 ..< 50 {
			append(&longest, 'a')
		}
	}
	append(&longest, 49)
	for _ in 0 ..< 49 {
		append(&longest, 'a')
	}
	append(&longest, 0)
	testing.expect_value(t, len(longest), MAX_NAME_WIRE)

	name, next, err := decode_name(longest[:], 0, context.temp_allocator)
	testing.expect_value(t, err, Decode_Error.None)
	testing.expect_value(t, next, MAX_NAME_WIRE)

	buf: [MAX_NAME_WIRE]u8
	n, eerr := encode_name(name, buf[:])
	testing.expect_value(t, eerr, Encode_Error.None)
	testing.expect_value(t, n, MAX_NAME_WIRE)
	testing.expect(t, mem.compare(buf[:n], longest[:]) == 0, "the longest legal name did not re-encode to its own wire bytes")

	// One octet more: five 50-octet labels are 255 octets of labels on their
	// own, 256 once the root is counted.
	too_long := make([dynamic]u8, 0, 256, context.temp_allocator)
	for _ in 0 ..< 5 {
		append(&too_long, 50)
		for _ in 0 ..< 50 {
			append(&too_long, 'a')
		}
	}
	append(&too_long, 0)
	testing.expect_value(t, len(too_long), MAX_NAME_WIRE + 1)

	_, _, terr := decode_name(too_long[:], 0, context.temp_allocator)
	testing.expect_value(t, terr, Decode_Error.Name_Too_Long)

	// The encoder is the other side of that same line, and it is the side the
	// decoder was just made to agree with, so pin it too: the presentation form
	// of those same five labels has to come back Name_Too_Long rather than a
	// 256th octet.
	presentation := make([dynamic]u8, 0, 256, context.temp_allocator)
	for _ in 0 ..< 5 {
		for _ in 0 ..< 50 {
			append(&presentation, 'a')
		}
		append(&presentation, '.')
	}
	_, perr := encode_name(string(presentation[:]), buf[:])
	testing.expect_value(t, perr, Encode_Error.Name_Too_Long)
	free_all(context.temp_allocator)
}

/*
A message whose answers can carry a compression pointer inside their RDATA.

The question sits at offset 12 and the second answer is an NS record whose
target name starts at the returned offset, so a later record's RDATA has a real
name to point at - which is what an authoritative server does when it compresses
the hostname of an AFSDB or the mailbox of an RP against a name it has already
written.
*/
@(private = "file")
message_prefix :: proc(answers: int) -> (m: [dynamic]u8, ns_target: int) {
	m = make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&m, 0x12, 0x34, 0x80, 0x00, 0x00, 0x01, u8(answers >> 8), u8(answers), 0x00, 0x00, 0x00, 0x00)
	// Question: example.com. A IN, at offset 12.
	append(&m, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	append(&m, 0x00, 0x01, 0x00, 0x01)
	// Answer 1: a.example.com. TXT "abc", owner written out in full so the
	// re-encode has something of its own to compress.
	append(&m, 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	append(&m, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04)
	append(&m, 3, 'a', 'b', 'c')
	// Answer 2: example.com. NS ns1.example.com.
	append(&m, 0xc0, 0x0c)
	append(&m, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x06)
	ns_target = len(m)
	append(&m, 3, 'n', 's', '1', 0xc0, 0x0c)
	return
}

// An answer owned by example.com. carrying `rdata` verbatim.
@(private = "file")
append_answer :: proc(m: ^[dynamic]u8, type: Type, rdata: []u8) {
	append(m, 0xc0, 0x0c)
	append(m, u8(u16(type) >> 8), u8(u16(type)))
	append(m, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c)
	append(m, u8(len(rdata) >> 8), u8(len(rdata)))
	append(m, ..rdata)
}

@(private = "file")
raw_rdata_of :: proc(wire: []u8, type: Type) -> (data: []u8, ok: bool) {
	msg, err := decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	for rec in msg.answer {
		if rec.type != type {
			continue
		}
		raw, is_raw := rec.data.(Rdata_Raw)
		if !is_raw {
			return nil, false
		}
		return raw.data, true
	}
	return nil, false
}

/*
The hostname an AFSDB record names, read the way a client would: out of the
RDATA when it stands on its own, and by following the pointer into the message
it arrived in when it does not.

Reading it this way rather than comparing bytes lets the test state the property
a client cares about - the record still names the same host - so it holds
whichever representation the codec settles on.
*/
@(private = "file")
afsdb_host :: proc(wire: []u8) -> (name: string, ok: bool) {
	raw := raw_rdata_of(wire, .AFSDB) or_return
	if len(raw) < 3 {
		return "", false
	}
	if raw[2] & 0xc0 == 0xc0 {
		if len(raw) < 4 {
			return "", false
		}
		target := (int(raw[2]) & 0x3f) << 8 | int(raw[3])
		n, _, err := decode_name(wire, target, context.temp_allocator)
		return n, err == .None
	}
	n, _, err := decode_name(raw, 2, context.temp_allocator)
	return n, err == .None
}

/*
A compression pointer inside the RDATA of a type the codec keeps as raw bytes is
expanded when the message is decoded.

AFSDB is one of the types RFC 1035 name compression may legally reach into and
one this codec does not model, so its hostname arrives as a pointer into the
message that carried it. Such a pointer only means anything against the exact
bytes it came with; the moment the record is written into a message of our own it
names whatever now sits at that offset. Expanding at decode, which RFC 3597
section 4 allows a receiver to do, makes the blob mean the same thing wherever it
is later put down.
*/
@(test)
test_raw_rdata_pointer_expanded_at_decode :: proc(t: ^testing.T) {
	m, ns_target := message_prefix(3)
	append_answer(&m, .AFSDB, []u8{0x00, 0x01, 0xc0 | u8(ns_target >> 8), u8(ns_target)})

	raw, ok := raw_rdata_of(m[:], .AFSDB)
	testing.expect(t, ok, "no raw AFSDB record came back")
	expected := []u8{0x00, 0x01, 3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	testing.expect(t, mem.compare(raw, expected) == 0, "AFSDB rdata was not expanded")
	free_all(context.temp_allocator)
}

/*
Re-encoding an answer keeps the hostname its AFSDB record named.

An answer that has a cookie attached with no OPT record to rewrite, that is
stripped of DNSSEC records for a client which did not ask for them, or that is
shrunk to fit a UDP limit, goes out through the message writer rather than
straight from the upstream's bytes. Before the RDATA was expanded, the pointer
inside it survived into the new message and resolved against a byte that had
nothing to do with the name it was written for, so the client was handed a
plausible-looking answer naming the wrong host.
*/
@(test)
test_raw_rdata_pointer_survives_reencode :: proc(t: ^testing.T) {
	m, ns_target := message_prefix(3)
	append_answer(&m, .AFSDB, []u8{0x00, 0x01, 0xc0 | u8(ns_target >> 8), u8(ns_target)})

	before, before_ok := afsdb_host(m[:])
	testing.expect(t, before_ok, "the AFSDB hostname could not be read from the original")
	testing.expect_value(t, before, "ns1.example.com.")

	msg, derr := decode_message(m[:], context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	out, _, eerr := encode_message(msg, context.temp_allocator)
	testing.expect_value(t, eerr, Encode_Error.None)

	after, after_ok := afsdb_host(out)
	testing.expect(t, after_ok, "the AFSDB hostname could not be read after re-encoding")
	testing.expect_value(t, after, "ns1.example.com.")
	free_all(context.temp_allocator)
}

/*
A type this decoder does model is expanded too when its RDATA falls back to raw.

`decode_rdata` rejects an MX whose RDLENGTH counts a byte more than its two
fields, and `decode_record` then keeps the record as `Rdata_Raw` rather than
losing it. The exchanger inside is a perfectly good compressed name, so it has to
be expanded on the way through exactly as an AFSDB's would be: nothing downstream
can tell a raw MX from a raw AFSDB, and a stale pointer re-encoded into an answer
names whichever byte now sits at that offset.
*/
@(test)
test_raw_rdata_expands_a_modelled_type_that_failed_to_parse :: proc(t: ^testing.T) {
	m, ns_target := message_prefix(3)
	// preference, a compressed exchanger, and one byte more than the fields need.
	append_answer(&m, .MX, []u8{0x00, 0x0a, 0xc0 | u8(ns_target >> 8), u8(ns_target), 0x00})

	raw, ok := raw_rdata_of(m[:], .MX)
	testing.expect(t, ok, "the malformed MX did not come back as raw rdata")
	expected := []u8 {
		0x00, 0x0a,
		3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00,
	}
	testing.expect(t, mem.compare(raw, expected) == 0, "MX rdata was not expanded")

	// And it still names the same host once written into a message of our own.
	msg, derr := decode_message(m[:], context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	out, _, eerr := encode_message(msg, context.temp_allocator)
	testing.expect_value(t, eerr, Encode_Error.None)

	after, after_ok := raw_rdata_of(out, .MX)
	testing.expect(t, after_ok, "the MX record did not survive the re-encode")
	testing.expect(t, mem.compare(after, expected) == 0, "MX rdata changed meaning on re-encode")
	free_all(context.temp_allocator)
}

/*
A modelled type whose name cannot be expanded is refused by the writer.

A CNAME carrying a forward pointer does not decode, so the record falls back to
raw with the pointer still in it. Forwarding those two bytes is the dangerous
outcome: the pointer aims past the end of the message it arrived in, but a
message of our own may well be long enough for it to land on a real name, and the
client would be sent somewhere nobody named. Failing the encode leaves every
caller with an honest degradation instead.
*/
@(test)
test_encode_refuses_a_modelled_type_holding_a_pointer :: proc(t: ^testing.T) {
	m, _ := message_prefix(3)
	append_answer(&m, .CNAME, []u8{0xc0, 0xf0})

	raw, ok := raw_rdata_of(m[:], .CNAME)
	testing.expect(t, ok, "the undecodable CNAME did not come back as raw rdata")
	testing.expect(t, mem.compare(raw, []u8{0xc0, 0xf0}) == 0, "unwalkable CNAME rdata was altered")

	msg, derr := decode_message(m[:], context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	_, _, eerr := encode_message(msg, context.temp_allocator)
	testing.expect_value(t, eerr, Encode_Error.Bad_Rdata)
	free_all(context.temp_allocator)
}

/*
RDATA with nothing to expand comes back exactly as it arrived.

Expansion is only ever a rewrite of compression pointers, so a blob holding none
- the ordinary case, and the only case for the types RFC 3597 forbids
compressing at all - has to be handed on byte for byte. A type off the
compressible list is left alone whatever its bytes look like: a DNSKEY's key
material may well contain a 0xc0 byte, and reading that as a pointer would
corrupt the very records DNSSEC validation rests on.
*/
@(test)
test_raw_rdata_without_pointer_is_untouched :: proc(t: ^testing.T) {
	plain := []u8{0x00, 0x01, 3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	// Not on the compressible list, and these bytes would walk as a pointer if
	// anything were tempted to look.
	keyish := []u8{0x01, 0x00, 0x03, 0x08, 0xc0, 0x0c, 0xc0, 0x1a, 0xff, 0xff}

	m, _ := message_prefix(4)
	append_answer(&m, .AFSDB, plain)
	append_answer(&m, .DNSKEY, keyish)

	raw, ok := raw_rdata_of(m[:], .AFSDB)
	testing.expect(t, ok, "no raw AFSDB record came back")
	testing.expect(t, mem.compare(raw, plain) == 0, "uncompressed AFSDB rdata was altered")

	key, key_ok := raw_rdata_of(m[:], .DNSKEY)
	testing.expect(t, key_ok, "no raw DNSKEY record came back")
	testing.expect(t, mem.compare(key, keyish) == 0, "DNSKEY rdata was altered")
	free_all(context.temp_allocator)
}

/*
RDATA that cannot be walked is forwarded exactly as it arrived.

The decoder's standing posture is to keep odd RDATA rather than reject the
message around it, so a record whose layout does not add up has to come through
unchanged: it may still be the answer somebody wanted, and it is not this
server's place to decide otherwise. Both shapes here are ones a broken or
hostile sender can produce - a pointer cut short by the RDATA's own length, and a
pointer aiming forwards, which `decode_name` refuses because only a backward
pointer is guaranteed to terminate.
*/
@(test)
test_raw_rdata_that_cannot_be_walked_is_kept :: proc(t: ^testing.T) {
	cases := [][]u8{{0x00, 0x01, 0xc0}, {0x00, 0x01, 0xff, 0xff}}
	for rdata in cases {
		m, _ := message_prefix(3)
		append_answer(&m, .AFSDB, rdata)

		_, derr := decode_message(m[:], context.temp_allocator)
		testing.expect_value(t, derr, Decode_Error.None)

		raw, ok := raw_rdata_of(m[:], .AFSDB)
		testing.expect(t, ok, "no raw AFSDB record came back")
		testing.expect(t, mem.compare(raw, rdata) == 0, "unwalkable rdata was altered")
	}
	free_all(context.temp_allocator)
}

/*
Both names of a two-name RDATA are expanded.

RP carries a mailbox and the name of a TXT record, one after the other, and
MINFO and PX have the same shape. Expanding only the first would leave the second
pointing at a byte of the old message, which is the same corruption in a place
that is easier to miss, so the walk has to run to the end of the layout.
*/
@(test)
test_raw_rdata_expands_every_name :: proc(t: ^testing.T) {
	m, ns_target := message_prefix(3)
	append_answer(&m, .RP, []u8{0xc0, 0x0c, 0xc0 | u8(ns_target >> 8), u8(ns_target)})

	raw, ok := raw_rdata_of(m[:], .RP)
	testing.expect(t, ok, "no raw RP record came back")
	expected := []u8 {
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	}
	testing.expect(t, mem.compare(raw, expected) == 0, "RP rdata was not fully expanded")
	free_all(context.temp_allocator)
}

/*
The writer refuses raw RDATA that still holds a compression pointer.

Nothing the decoder produces should reach this point any more, which is the
reason to check: a type added to the compressible list without a layout to walk,
or a layout that stops matching what senders write, would otherwise surface as a
wrong answer served to a client rather than as a failure here. Every caller
degrades into something honest - an answer without a cookie, an answer truncated
so the client retries over TCP - which is worth having in place of a name
pointing at the wrong bytes. Types off the compressible list are not checked at
all, so a blob that merely happens to contain a 0xc0 byte still goes out.
*/
@(test)
test_encode_refuses_raw_rdata_holding_a_pointer :: proc(t: ^testing.T) {
	compressed := Message {
		id     = 1,
		answer = []Record {
			{
				name = "example.com.",
				type = .AFSDB,
				class = .IN,
				ttl = 60,
				data = Rdata_Raw{data = []u8{0x00, 0x01, 0xc0, 0x0c}},
			},
		},
	}
	_, _, err := encode_message(compressed, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.Bad_Rdata)

	opaque := Message {
		id     = 2,
		answer = []Record {
			{
				name = "example.com.",
				type = .DNSKEY,
				class = .IN,
				ttl = 60,
				data = Rdata_Raw{data = []u8{0x01, 0x00, 0x03, 0x08, 0xc0, 0x0c}},
			},
		},
	}
	_, _, opaque_err := encode_message(opaque, context.temp_allocator)
	testing.expect_value(t, opaque_err, Encode_Error.None)
	free_all(context.temp_allocator)
}
