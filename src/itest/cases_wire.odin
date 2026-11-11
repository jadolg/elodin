package itest

import "core:fmt"
import "core:strings"
import "core:time"
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
	// RD echoed from the query, as an upstream does: the bit is the client's,
	// and the byte-for-byte check below would otherwise read it as a change.
	m.flags.rd = true
	m.flags.ra = true
	wire, truncated, err := dns.encode_message(m, allocator, dns.MAX_MESSAGE)
	if err != .None || truncated {
		return nil
	}
	return wire
}


/*
An SRV answer near 64 KiB whose re-encode does not fit a stream message.

Every owner and every target is a pointer at the question name, so each record
is 20 bytes as sent and 37 once the encoder writes the target in full, as it
writes every SRV target. The OPT record is followed by an A record, so taking
it out for a client that asked without EDNS has to decode and encode the whole
message again rather than cut bytes off the end.
*/
@(private = "file")
GROWING_QNAME :: "srvgrow.wire.test."
@(private = "file")
GROWING_SRVS :: 3200

@(private = "file")
growing_srv_answer :: proc(allocator := context.allocator) -> []u8 {
	buf := make([dynamic]u8, 0, 65535, allocator)
	append(&buf, 0, 0, 0x81, 0x80, 0, 1, u8(GROWING_SRVS >> 8), u8(GROWING_SRVS & 0xff), 0, 0, 0, 2)
	append(&buf, 7, 's', 'r', 'v', 'g', 'r', 'o', 'w', 4, 'w', 'i', 'r', 'e', 4, 't', 'e', 's', 't', 0, 0, 33, 0, 1)
	for _ in 0 ..< GROWING_SRVS {
		// owner, SRV IN, TTL 300, RDLENGTH 8, priority 1 weight 1 port 53, target
		append(&buf, 0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 1, 0x2c, 0, 8, 0, 1, 0, 1, 0, 53, 0xc0, 0x0c)
	}
	append(&buf, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
	append(&buf, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1)
	return buf[:]
}

/*
A reply whose names cost a whole reading's budget, out of a few kilobytes.

Issue #298's shape - MX records whose owner and exchange are both two-byte
pointers at one 255-octet name of unprintable octets - built onto the question
the client asked, so the upstream's answer matches the query that went out.

The point of it here is issue #354: what bounds those expansions is the
request's counter now rather than each reading's, and a reply that spends what a
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
FLAT_QNAME :: "flat.wire.test."

// An answer with no OPT record and no name compression, as an upstream that
// does neither sends one.
@(private = "file")
flat_answer :: proc(allocator := context.allocator) -> []u8 {
	m := dns.Message {
		question = []dns.Question{{name = FLAT_QNAME, type = .A, class = .IN}},
		answer   = []dns.Record {
			{name = FLAT_QNAME, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 7}}},
			{name = FLAT_QNAME, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 8}}},
		},
	}
	m.flags.qr = true
	m.flags.rd = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator, compress = false)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
HEADER_POINTER_QNAME :: "headptr.wire.test."

// The question, then one A record whose owner is the question's labels ended by
// a compression pointer to offset 11 - ARCOUNT's low byte, a zero octet while
// ARCOUNT is zero, so the owner reads as the question's name until it is not.
@(private = "file")
header_pointer_answer :: proc(allocator := context.allocator) -> []u8 {
	msg := make([dynamic]u8, allocator)
	append(&msg, 0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
	append(&msg, 7, 'h', 'e', 'a', 'd', 'p', 't', 'r', 4, 'w', 'i', 'r', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1)
	append(&msg, 7, 'h', 'e', 'a', 'd', 'p', 't', 'r', 4, 'w', 'i', 'r', 'e', 4, 't', 'e', 's', 't', 0xc0, 11)
	append(&msg, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9)
	return msg[:]
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
	growing := growing_srv_answer()
	defer delete(growing)
	mock_truncate_udp(mock, GROWING_QNAME, u16(dns.Type.SRV), growing)

	bomb_query := build_query("namebomb.wire.test.", u16(dns.Type.MX), id = 0x5151, allocator = context.allocator)
	defer delete(bomb_query)
	name_bomb := name_bomb_answer(bomb_query)
	defer delete(name_bomb)
	if name_bomb == nil {
		skip_case(r, "wire", "cannot build the name-bomb answer")
		return
	}
	mock_reply(mock, "namebomb.wire.test.", u16(dns.Type.MX), name_bomb)

	flat := flat_answer(context.allocator)
	defer delete(flat)
	if flat == nil {
		skip_case(r, "wire", "cannot build the uncompressed answer")
		return
	}
	mock_reply(mock, FLAT_QNAME, u16(dns.Type.A), flat)
	header_pointer := header_pointer_answer(context.allocator)
	defer delete(header_pointer)
	mock_reply(mock, HEADER_POINTER_QNAME, u16(dns.Type.A), header_pointer)

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

			// The clock either side of the exchange: elodin read it between the two.
			before := u32(time.time_to_unix(time.now()))
			res := use_tcp ? query_tcp(udp_port, query) : query_udp(udp_port, query)
			after := u32(time.time_to_unix(time.now()))
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
				/*
				And the TTLs a signed answer may not be told past its RRSIGs
				(RFC 4034 section 3.1.5, issue #165). Elodin read the clock
				somewhere between `before` and `after`, which can straddle a
				second while a fixture's signatures have fewer seconds left than
				its TTLs, so the payload matches the cap at one of the two.
				*/
				want_late := make([]u8, len(want), context.temp_allocator)
				copy(want_late, want)
				if left, signed := dns.signatures_lapse(want, before); signed {
					dns.cap_ttls(want, left)
					late, _ := dns.signatures_lapse(want_late, after)
					dns.cap_ttls(want_late, late)
				}
				if check(r, len(res.wire) == len(expected), "length: got %d, want %d", len(res.wire), len(expected)) {
					check(
						r,
						bytes_equal(res.wire[2:], want[2:]) || bytes_equal(res.wire[2:], want_late[2:]),
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
		Issue #354: what one request may take out of its arena is now counted
		across every reading it makes rather than per reading. A reply that
		spends what a single reading is allowed is far under that, so it goes to
		the client as it always did - byte for byte, since nothing here reads
		its answer section and nothing rebuilds it. The `manystrings` case above
		is the same statement for the other end of the expansion: a full-length
		TXT record of empty character-strings, which is a megabyte of `string`
		headers a reading, has to survive the trip too.

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

	start_case(r, "edns: the upstream is asked with an OPT record and the client's DO")
	{
		// elodin builds the query it forwards from the question, DO and CD
		// (issue #423), with an OPT record of its own. What matters is
		// therefore what the upstream received.
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

	start_case(r, "a 0x20 client reads its own case back, and the upstream is asked in the key's")
	{
		// Every client asking the name sends the upstream one message, so the
		// name goes out folded as the cache key folds it (issue #423), and the
		// answer's question is put back in the client's case.
		query := build_query("ExAmPle.CoM.", u16(dns.Type.A))
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			// The question starts right after the 12-byte header and is never
			// compressed, so the bytes can be compared directly.
			check(
				r,
				len(res.wire) >= 25 && bytes_equal(res.wire[12:25], query[12:25]),
				"the answer's question is not the client's byte for byte",
			)
			seen := mock_last_query(mock)
			if check(r, seen != nil, "the upstream saw no query") {
				check(
					r,
					len(seen) >= 25 && bytes_equal(seen[12:25], []u8{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}),
					"the question was not forwarded in lower case",
				)
			}
		}
	}
	end_case(r)

	start_case(r, "edns: an OPT record minted for an EDNS client is appended to the upstream's bytes")
	{
		/*
		Issue #598. An answer with no OPT record going back to a client that
		asked with one gets a record minted, and the record is written onto the
		end of the bytes: everything ahead of it is what the upstream sent. The
		upstream here writes its names in full, which a decode and re-encode
		compresses - shorter, and not the upstream's bytes. The same
		`match_client_opt` call serves a cache hit, so no EDNS client's hit pays
		for a decode.
		*/
		query := build_query(FLAT_QNAME, u16(dns.Type.A), edns_size = 1232)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			if check(r, len(res.wire) == len(flat) + 11, "length: got %d, want %d", len(res.wire), len(flat) + 11) {
				check(
					r,
					bytes_equal(res.wire[2:10], flat[2:10]) && bytes_equal(res.wire[12:len(flat)], flat[12:]),
					"the bytes ahead of the minted record are not the upstream's",
				)
				check_eq_int(r, int(res.wire[11]), int(flat[11]) + 1, "ARCOUNT")
			}
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, err == .None, "the response does not decode: %v", err) {
				check(r, dns.edns_present(msg), "no OPT record went back to an EDNS client")
			}
		}
	}
	end_case(r)

	start_case(r, "malformed: an upstream answer whose name points into the header is not read, and not cached")
	{
		/*
		Issue #605. The owner ends in a pointer to offset 11, ARCOUNT's low
		byte, so it reads as the question's name while ARCOUNT is zero and as
		another once an OPT record is appended for an EDNS client - a name the
		upstream can arrange for the client to read differently from any reading
		taken here.
		The decoder refuses the pointer, so the answer is one this server has
		not read: passed on as the upstream sent it, like any other reply that
		does not decode, and never stored. A readable answer beside it is
		stored, so the count is the cache's and not the mock's.
		*/
		cached_port := next_port(r)
		cached_cfg, _ := strings.replace(config_passthrough(cached_port, upstream_port), "cache: { enabled: false }", "cache: { enabled: true }", 1, context.temp_allocator)
		cached, started := start_server(r, Server_Options{config = cached_cfg, udp_port = cached_port, tcp_port = cached_port})
		if check(r, started, "the caching server did not start") {
			defer stop_server(&cached)
			asked := proc(r: ^Runner, port: int, mock: ^Mock, qname: string) -> int {
				before := mock_total(mock)
				for _ in 0 ..< 2 {
					res := query_udp(port, build_query(qname, u16(dns.Type.A), edns_size = 1232))
					check(r, res.ok, "no response for %s", qname)
				}
				return mock_total(mock) - before
			}
			check_eq_int(r, asked(r, cached_port, mock, FLAT_QNAME), 1, "upstream queries for a readable answer asked twice")
			check_eq_int(r, asked(r, cached_port, mock, HEADER_POINTER_QNAME), 2, "upstream queries for an answer pointing into the header asked twice")
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

	start_case(r, "malformed: an OPT record owned by a name other than root yields FORMERR")
	{
		// RFC 6891 section 6.1.2: the OPT record's NAME MUST be 0 (root). The
		// OPT is the last eleven bytes; its root owner becomes a pointer to the
		// question's name, which is one byte longer.
		f := fixture("a")
		q := build_query(f.qname, f.qtype, edns_size = 1232)
		bad := make([dynamic]u8, 0, len(q) + 1, context.temp_allocator)
		append(&bad, ..q[:len(q) - 11])
		append(&bad, 0xc0, 0x0c)
		append(&bad, ..q[len(q) - 10:])
		before := mock_total(mock)
		res := query_udp(udp_port, bad[:])
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, h.rcode == int(dns.Rcode.Form_Err), "rcode %d, want FORMERR", h.rcode)
			check_eq_int(r, mock_total(mock) - before, 0, "queries forwarded to the upstream")
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

	/*
	A client that asked without EDNS has the upstream's OPT record taken out,
	and here that means a rebuild that outgrows `MAX_MESSAGE`. Kept, the
	encoder's cut would reach the client with records dropped and TC set - over
	the TCP connection TC tells it to retry on. Refused, the answer is SERVFAIL
	(RFC 6891 section 6.1.1 still keeps the upstream's record from the client).
	*/
	start_case(r, "wire: an answer whose rebuild outgrows a stream message is not cut with TC")
	{
		query := build_query(GROWING_QNAME, u16(dns.Type.SRV))
		res := query_tcp(udp_port, query)
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, !h.tc, "the TC bit was set on a TCP answer of %d records", h.ancount)
			check(
				r,
				h.ancount == GROWING_SRVS || h.rcode == int(dns.Rcode.Serv_Fail),
				"got %d of %d records with rcode %d",
				h.ancount,
				GROWING_SRVS,
				h.rcode,
			)
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
