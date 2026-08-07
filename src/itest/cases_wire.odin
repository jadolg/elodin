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
	upstream_port := next_port(r)
	mock := mock_make("wire", upstream_port)

	// Every fixture is registered, so one server serves them all.
	for f in FIXTURES {
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	}
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
				h, _ := parse_header(res.wire)
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
			h, _ := parse_header(res.wire)
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
			h, _ := parse_header(res.wire)
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
			h, _ := parse_header(res.wire)
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
			h, _ := parse_header(res.wire)
			check(r, !h.tc, "TC set on a TCP reply")
			check_eq_int(r, h.ancount, f.ancount, "answer count")
		}
	}
	end_case(r)
}
