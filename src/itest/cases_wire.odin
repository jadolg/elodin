package itest

import "core:fmt"
import "elodin:dns"

/*
Wire-level coverage.

Every captured fixture is replayed through the server and compared byte for byte
with what the mock sent, ignoring only the transaction ID. That is the strongest
statement available about "answers all kinds of DNS requests": whatever a real
resolver produced reaches the client unaltered, including compression pointers,
DNSSEC records and types the codec has no case for.
*/

/*
A TXT record whose RDATA is nothing but length bytes of zero.

The shape from issue #351: a `<character-string>` may be zero bytes long, so one
wire byte is one whole string, and 65,000 of them are well formed and legal.
The decoder used to collect them into a doubling `[dynamic]string`, which under
the arena a request is served from cost 32 times the record's own length; it
counts them off the wire and allocates the list once now. What this checks is
that counting them did not change what comes back - the record has to survive the
trip byte for byte, and `fit_response` has to still be able to read it.
*/
@(private = "file")
EMPTY_STRINGS_COUNT :: 65000

@(private = "file")
empty_character_strings_answer :: proc(name: string, allocator := context.allocator) -> []u8 {
	strs := make([]string, EMPTY_STRINGS_COUNT, context.temp_allocator)
	m := dns.Message {
		question = []dns.Question{{name = name, type = .TXT, class = .IN}},
		answer = []dns.Record {
			{name = name, type = .TXT, class = .IN, ttl = 300, data = dns.Rdata_TXT{strings = strs}},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, truncated, err := dns.encode_message(m, allocator, dns.MAX_MESSAGE)
	if err != .None || truncated {
		return nil
	}
	return wire
}


/*
A reply whose names cost a whole reading's budget, out of a few kilobytes.

Issue #298's shape - MX records whose owner and exchange are both two-byte
pointers at one 255-octet name of unprintable octets - built onto the question
the client asked, so the upstream's answer matches the query that went out.

The point of it here is issue #354: the counter that bounds those expansions is
the request's now rather than each reading's, and a reply that spends what a
single reading may spend is still a reply this server forwards. That is the
failure mode a per-request budget invites - one made too tight refuses answers
nobody had a quarrel with - and the only way to see it is through the whole
server.
*/
@(private = "file")
name_bomb_answer :: proc(query: []u8, allocator := context.allocator) -> []u8 {
	long: [256]u8
	at := 0
	for l in ([]int{63, 63, 63, 61}) {
		long[at] = u8(l)
		at += 1
		for _ in 0 ..< l {
			long[at] = 0x01
			at += 1
		}
	}
	long[at] = 0
	at += 1
	// What it costs once escaped, read rather than written down.
	owner, _, derr := dns.decode_name(long[:at], 0, context.temp_allocator)
	if derr != .None {
		return nil
	}

	out := make([dynamic]u8, 0, 8192, allocator)
	append(&out, ..query)
	out[2] |= 0x80 // QR
	out[3] |= 0x80 // RA
	// The first record's owner is the long name itself, written out here for
	// every record after it to point at.
	long_at := u16(len(out))
	append(&out, ..long[:at])
	append(&out, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))
	append(&out, 0, 0, 0x0e, 0x10)
	append(&out, 0, 4, 0, 10)
	append(&out, 0xc0 | u8(long_at >> 8), u8(long_at))

	count := 1
	for count * 2 * len(owner) <= dns.NAME_BUDGET {
		append(&out, 0xc0 | u8(long_at >> 8), u8(long_at))
		append(&out, 0, u8(dns.Type.MX), 0, u8(dns.Class.IN))
		append(&out, 0, 0, 0x0e, 0x10)
		append(&out, 0, 4, 0, 10)
		append(&out, 0xc0 | u8(long_at >> 8), u8(long_at))
		count += 1
	}
	out[6], out[7] = u8(count >> 8), u8(count)
	return out[:]
}

@(private = "file")
config_passthrough :: proc(udp_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		udp_port,
		upstream_port,
	)
}

run_wire_cases :: proc(r: ^Runner) {
	start_case(r, "harness: a reply the helpers cannot decode fails the case")
	{
		/*
		Twelve bytes that parse as a header and cannot decode as a message: the
		header claims one answer record and the record is not there.

		Every helper used to report this as "the thing you asked about is
		absent", which is exactly what a negative assertion wants to hear, so a
		case could go green on bytes nothing read. A scratch runner collects the
		failures instead of this case taking them.
		*/
		bad := []u8{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0}

		scratch: Runner
		defer {
			for f in scratch.failures {
				delete(f)
			}
			delete(scratch.failures)
		}

		answer_has_type(&scratch, bad, u16(dns.Type.A))
		answer_addresses(&scratch, bad)
		first_cname_or_name(&scratch, bad)
		min_answer_ttl(&scratch, bad)
		find_cookie(&scratch, bad)
		find_padding(&scratch, bad)
		find_keepalive(&scratch, bad)
		check_eq_int(r, len(scratch.failures), 7, "helpers that refused an undecodable reply")

		// And the header reader, whose zero value reads as NOERROR. It fails the
		// case and still hands the zeros back, which is why a case that counts
		// what it reads needs a length guard of its own; assert both halves,
		// since the second is what `cases_queryid.odin` defends against.
		short := parse_header(&scratch, bad[:8])
		check_eq_int(r, len(scratch.failures), 8, "a reply too short for a header also fails")
		check(r, short == Header{}, "a header read from too few bytes is not zeroed")
	}
	end_case(r)

	upstream_port := next_port(r)
	mock := mock_make("wire", upstream_port)

	// Every fixture is registered, so one server serves them all.
	for f in FIXTURES {
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	}
	// Too large for any UDP reply, so the mock answers TC over UDP and serves
	// the record itself when elodin comes back over TCP - the way an upstream
	// with a big answer actually behaves.
	empty_strings := empty_character_strings_answer("manystrings.wire.test.")
	defer delete(empty_strings)
	if empty_strings == nil {
		skip_case(r, "wire", "cannot build the empty-character-string answer")
		return
	}
	mock_truncate_udp(mock, "manystrings.wire.test.", u16(dns.Type.TXT), empty_strings)

	bomb_query := build_query("namebomb.wire.test.", u16(dns.Type.MX), id = 0x5151, allocator = context.allocator)
	defer delete(bomb_query)
	name_bomb := name_bomb_answer(bomb_query)
	defer delete(name_bomb)
	if name_bomb == nil {
		skip_case(r, "wire", "cannot build the name-bomb answer")
		return
	}
	mock_reply(mock, "namebomb.wire.test.", u16(dns.Type.MX), name_bomb)

	if !mock_start(mock) {
		skip_case(r, "wire", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_passthrough(udp_port, upstream_port), udp_port = udp_port, tcp_port = udp_port})
	if !ok {
		skip_case(r, "wire", "server did not start")
		return
	}
	defer stop_server(&srv)

	for f in FIXTURES {
		expected := from_hex(f.response)

		// Large answers cannot come back over UDP without EDNS, so those
		// fixtures are checked on TCP where the framing has room.
		use_tcp := len(expected) > 512

		start_case(r, fmt.tprintf("wire: %s (%s, %d bytes%s)", f.key, f.qname, len(expected), ", tcp" if use_tcp else ""))
		{
			query := from_hex(f.query)
			// Use a distinct ID so ID rewriting is exercised.
			query[0], query[1] = 0x7a, 0x5c

			res := use_tcp ? query_tcp(udp_port, query) : query_udp(udp_port, query)
			if check(r, res.ok, "no response") {
				h := parse_header(r, res.wire)
				check(r, h.id == 0x7a5c, "transaction ID: got %04x, want 7a5c", h.id)
				check_eq_int(r, h.ancount, f.ancount, "answer count")
				check_eq_int(r, h.rcode, f.rcode, "rcode")

				/*
				Byte-for-byte, ignoring the ID we deliberately changed and the
				AD bit we deliberately do not pass on.

				This server is configured without DNSSEC, so it authenticated
				nothing and has no business repeating an upstream's claim that
				it did. The bit is checked on its own below; everything else
				still has to arrive exactly as the upstream sent it.
				*/
				want := expected
				want[3] &~= 0x20
				if check(r, len(res.wire) == len(expected), "length: got %d, want %d", len(res.wire), len(expected)) {
					check(
						r,
						bytes_equal(res.wire[2:], want[2:]),
						"payload differs from what the upstream sent",
					)
					check(
						r,
						res.wire[3] & 0x20 == 0,
						"the upstream's AD bit was forwarded by a server that validates nothing",
					)
				}

				// The decoder must also be able to read it back.
				_, derr := dns.decode_message(res.wire, context.temp_allocator)
				check(r, derr == .None, "the response does not decode: %v", derr)
			}
		}
		end_case(r)
	}

	start_case(r, "wire: a reply that spends a reading's name budget is still forwarded")
	{
		/*
		Issue #354: what one request may expand names into is now counted across
		every reading it makes rather than per reading. A reply that spends what
		a single reading is allowed is far under that, so it goes to the client
		as it always did - byte for byte, since nothing here reads its answer
		section and nothing rebuilds it.

		Over TCP because it is several kilobytes, and without EDNS: the same
		reply over UDP is `fit_response`'s problem, which `resolver.odin` argues
		on its own.
		*/
		res := query_tcp(udp_port, bomb_query)
		if check(r, res.ok, "no response to a reply that spends a name budget") {
			h := parse_header(r, res.wire)
			check(r, h.id == 0x5151, "transaction ID: got %04x, want 5151", h.id)
			check_eq_int(r, h.rcode, 0, "rcode")
			if check(
				r,
				len(res.wire) == len(name_bomb),
				"length: got %d, want %d",
				len(res.wire),
				len(name_bomb),
			) {
				want := name_bomb
				want[3] &~= 0x20
				check(r, bytes_equal(res.wire[2:], want[2:]), "payload differs from what the upstream sent")
			}
		}

		// And the server is still answering afterwards: the reply cost it a
		// bounded amount of arena and nothing that outlives the request.
		f := fixture("a")
		after := query_udp(udp_port, from_hex(f.query))
		check(r, after.ok, "the server stopped answering after a name bomb")
	}
	end_case(r)

	start_case(r, "wire: DNSSEC records survive with the DO bit set")
	{
		f := fixture("dnssec_a")
		query := from_hex(f.query)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, err == .None, "cannot decode") {
				found_rrsig := false
				for rec in msg.answer {
					if rec.type == .RRSIG {
						found_rrsig = true
					}
				}
				check(r, found_rrsig, "no RRSIG in the answer section")
				check(r, dns.edns_do(msg), "the DO bit was not preserved")
			}
		}
	}
	end_case(r)

	start_case(r, "edns: the client's OPT record is carried to the upstream")
	{
		// elodin forwards the query as it arrived, so EDNS parameters are
		// negotiated end to end rather than rewritten in the middle. What
		// matters is therefore what the upstream received.
		f := fixture("a")
		query := build_query(f.qname, f.qtype, edns_size = 1232, dnssec_ok = true)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			seen := mock_last_query(mock)
			if check(r, seen != nil, "the upstream saw no query") {
				msg, err := dns.decode_message(seen, context.temp_allocator)
				if check(r, err == .None, "the forwarded query does not decode") {
					check(r, dns.edns_present(msg), "the OPT record was dropped on the way upstream")
					check_eq_int(r, int(dns.edns_udp_size(msg)), 1232, "advertised buffer size")
					check(r, dns.edns_do(msg), "the DO bit was dropped on the way upstream")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "the query reaches the upstream with its case intact (0x20 clients)")
	{
		query := build_query("ExAmPle.CoM.", u16(dns.Type.A))
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			seen := mock_last_query(mock)
			if check(r, seen != nil, "the upstream saw no query") {
				// The question starts right after the 12-byte header and is
				// never compressed, so the bytes can be compared directly.
				check(
					r,
					len(seen) >= 25 && bytes_equal(seen[12:25], query[12:25]),
					"the question was not forwarded byte for byte",
				)
			}
		}
	}
	end_case(r)

	start_case(r, "malformed: a datagram shorter than a header gets no reply")
	{
		check(r, expect_no_udp_reply(udp_port, []u8{0x00, 0x01, 0x02}), "the server answered a runt datagram")
	}
	end_case(r)

	start_case(r, "malformed: a response sent to the listener is ignored")
	{
		// QR set: this is an answer, not a question, and must not be processed.
		reply := from_hex(fixture("a").response)
		check(r, expect_no_udp_reply(udp_port, reply), "the server answered a message with QR set")
	}
	end_case(r)

	start_case(r, "malformed: a truncated question yields FORMERR")
	{
		// A header claiming one question, with the name cut off mid-label.
		bad := []u8{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x'}
		res := query_udp(udp_port, bad)
		if check(r, res.ok, "no response to a truncated question") {
			h := parse_header(r, res.wire)
			check(r, h.rcode == int(dns.Rcode.Form_Err), "rcode %d, want FORMERR", h.rcode)
		}
	}
	end_case(r)

	start_case(r, "malformed: an unsupported opcode yields NOTIMP")
	{
		q := build_query("example.com.", u16(dns.Type.A))
		q[2] = (q[2] & 0x87) | (2 << 3) // opcode STATUS
		res := query_udp(udp_port, q)
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, h.rcode == int(dns.Rcode.Not_Impl), "rcode %d, want NOTIMP", h.rcode)
		}
	}
	end_case(r)

	start_case(r, "truncation: an oversized answer sets TC for a 512-byte client")
	{
		f := fixture("txt_big")
		// No EDNS, so the client is limited to 512 bytes.
		query := build_query(f.qname, f.qtype)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, h.tc, "the TC bit was not set")
			check(r, len(res.wire) <= 512, "response is %d bytes, over the 512 limit", len(res.wire))
			check_eq_int(r, h.qdcount, 1, "question count in a truncated reply")
		}
	}
	end_case(r)

	start_case(r, "truncation: the same answer fits over TCP")
	{
		f := fixture("txt_big")
		query := build_query(f.qname, f.qtype)
		res := query_tcp(udp_port, query)
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, !h.tc, "TC set on a TCP reply")
			check_eq_int(r, h.ancount, f.ancount, "answer count")
		}
	}
	end_case(r)

	start_case(r, fmt.tprintf("wire: a TXT record of %d empty character-strings survives over TCP", EMPTY_STRINGS_COUNT))
	{
		query := build_query("manystrings.wire.test.", u16(dns.Type.TXT))
		res := query_tcp(udp_port, query)
		if check(r, res.ok, "no response") {
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, err == .None, "the response does not decode: %v", err) {
				if check_eq_int(r, len(msg.answer), 1, "answer records") {
					txt, is_txt := msg.answer[0].data.(dns.Rdata_TXT)
					if check(r, is_txt, "the record came back as %v, not a TXT", msg.answer[0].data) {
						check_eq_int(r, len(txt.strings), EMPTY_STRINGS_COUNT, "character-strings")
						empty := true
						for s in txt.strings {
							if len(s) != 0 {
								empty = false
							}
						}
						check(r, empty, "a character-string came back with bytes in it")
					}
				}
			}
			// And byte for byte, since what the upstream sent is what a client
			// asking a passthrough server has to get.
			if check(r, len(res.wire) == len(empty_strings), "length: got %d, want %d", len(res.wire), len(empty_strings)) {
				check(r, bytes_equal(res.wire[2:], empty_strings[2:]), "payload differs from what the upstream sent")
			}
		}
	}
	end_case(r)

	start_case(r, "wire: the same record is truncated rather than refused for a 512-byte client")
	{
		// `fit_response` decodes the upstream's reply to cut it down, so this is
		// the counting pass on the path a request actually takes.
		query := build_query("manystrings.wire.test.", u16(dns.Type.TXT))
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, h.tc, "the TC bit was not set")
			check(r, len(res.wire) <= 512, "response is %d bytes, over the 512 limit", len(res.wire))
			check_eq_int(r, h.qdcount, 1, "question count in a truncated reply")
			check_eq_int(r, h.rcode, 0, "rcode")
		}
	}
	end_case(r)
}
