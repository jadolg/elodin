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
