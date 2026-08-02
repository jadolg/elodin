package itest

import "core:fmt"
import "core:strings"
import "elodin:dns"

/*
Listener-side coverage: the four ways a client can reach elodin, plus the DoH
endpoint's HTTP behaviour.
*/

@(private = "file")
config_all_transports :: proc(r: ^Runner, port, dot_port, doh_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		port,
		port,
		dot_port,
		r.cert_file,
		r.key_file,
		doh_port,
		r.cert_file,
		r.key_file,
		upstream_port,
	)
}

run_transport_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	upstream_port := next_port(r)

	mock := mock_make("primary", upstream_port)
	mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
	if !mock_start(mock) {
		skip_case(r, "transports", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_all_transports(r, port, dot_port, doh_port, upstream_port),
			port = port,
			dot_port = dot_port,
			doh_port = doh_port,
		},
	)
	if !ok {
		skip_case(r, "transports", "server did not start")
		return
	}
	defer stop_server(&srv)

	// Heap, not scratch: end_case resets the temp allocator between cases and
	// this query is shared by all of them.
	query := build_query(fix.qname, fix.qtype, id = 0x1111, allocator = context.allocator)
	defer delete(query)

	// --- UDP ---
	start_case(r, "udp: forwards and returns the answer")
	{
		res := query_udp(port, query)
		if check(r, res.ok, "no response over UDP") {
			h, _ := parse_header(res.wire)
			check(r, h.id == 0x1111, "transaction ID not echoed: got %04x", h.id)
			check(r, h.qr, "QR bit not set")
			check(r, h.ra, "RA bit not set")
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
			addrs := answer_addresses(res.wire)
			check(r, len(addrs) == 2, "expected 2 addresses, got %d", len(addrs))
		}
	}
	end_case(r)

	// --- TCP ---
	start_case(r, "tcp: length-prefixed framing")
	{
		res := query_tcp(port, query)
		if check(r, res.ok, "no response over TCP") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
			check(r, h.id == 0x1111, "transaction ID not echoed")
		}
	}
	end_case(r)

	start_case(r, "tcp: several queries on one connection")
	{
		q1 := build_query(fix.qname, fix.qtype, id = 1)
		q2 := build_query(fix.qname, fix.qtype, id = 2)
		q3 := build_query(fix.qname, fix.qtype, id = 3)
		results := query_tcp_multi(port, [][]u8{q1, q2, q3})
		for res, i in results {
			if !check(r, res.ok, "query %d on the shared connection failed", i + 1) {
				break
			}
			h, _ := parse_header(res.wire)
			check(r, int(h.id) == i + 1, "query %d came back with ID %d", i + 1, h.id)
		}
	}
	end_case(r)

	// --- DoT ---
	start_case(r, "dot: answers over TLS")
	{
		res := query_dot(dot_port, query)
		if check(r, res.ok, "no response over DoT") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
			check(r, h.id == 0x1111, "transaction ID not echoed")
		}
	}
	end_case(r)

	// --- DoH ---
	start_case(r, "doh: POST application/dns-message")
	{
		res := doh_post(doh_port, "/dns-query", query)
		if check(r, res.ok, "no HTTP response") {
			check_eq_int(r, res.status, 200, "status")
			check(r, header_contains(res.headers, "content-type: application/dns-message"), "content type header missing")
			check(r, header_contains(res.headers, "cache-control: max-age="), "cache-control header missing")
			if check(r, len(res.body) >= dns.HEADER_SIZE, "body too short: %d bytes", len(res.body)) {
				h, _ := parse_header(res.body)
				check_eq_int(r, h.ancount, fix.ancount, "answer count")
				check(r, h.id == 0x1111, "transaction ID not echoed")
			}
		}
	}
	end_case(r)

	start_case(r, "doh: GET with unpadded base64url")
	{
		res := doh_get(doh_port, "/dns-query", query)
		if check(r, res.ok, "no HTTP response") {
			check_eq_int(r, res.status, 200, "status")
			if check(r, len(res.body) >= dns.HEADER_SIZE, "body too short") {
				h, _ := parse_header(res.body)
				check_eq_int(r, h.ancount, fix.ancount, "answer count")
			}
		}
	}
	end_case(r)

	start_case(r, "doh: keep-alive serves two queries per connection")
	{
		a, b := doh_post_twice(doh_port, "/dns-query", query)
		check(r, a.ok && a.status == 200, "first request failed (status %d)", a.status)
		check(r, b.ok && b.status == 200, "second request on the same connection failed (status %d)", b.status)
	}
	end_case(r)

	start_case(r, "doh: unknown path is 404")
	{
		res := doh_raw(doh_port, "GET /nope HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n")
		check(r, res.ok, "no HTTP response")
		check_eq_int(r, res.status, 404, "status")
	}
	end_case(r)

	start_case(r, "doh: unsupported method is 405")
	{
		res := doh_raw(doh_port, "PUT /dns-query HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n")
		check(r, res.ok, "no HTTP response")
		check_eq_int(r, res.status, 405, "status")
	}
	end_case(r)

	start_case(r, "doh: wrong content type is 415")
	{
		body := "not a dns message"
		req := fmt.tprintf(
			"POST /dns-query HTTP/1.1\r\nHost: elodin.local\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body),
			body,
		)
		res := doh_raw(doh_port, req)
		check(r, res.ok, "no HTTP response")
		check_eq_int(r, res.status, 415, "status")
	}
	end_case(r)

	start_case(r, "doh: GET without the dns parameter is 400")
	{
		res := doh_raw(doh_port, "GET /dns-query HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n")
		check(r, res.ok, "no HTTP response")
		check_eq_int(r, res.status, 400, "status")
	}
	end_case(r)

	start_case(r, "doh: malformed base64 in the dns parameter is 400")
	{
		res := doh_raw(
			doh_port,
			"GET /dns-query?dns=!!!!not-base64!!!! HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n",
		)
		check(r, res.ok, "no HTTP response")
		check_eq_int(r, res.status, 400, "status")
	}
	end_case(r)

	// --- local answers, no upstream involved ---
	start_case(r, "chaos: version.bind reports the build")
	{
		q := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
		res := query_udp(port, q)
		if check(r, res.ok, "no response") {
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, err == .None, "cannot decode the response") &&
			   check(r, len(msg.answer) == 1, "expected one answer") {
				txt, is_txt := msg.answer[0].data.(dns.Rdata_TXT)
				if check(r, is_txt, "answer is not TXT") {
					check(r, strings.has_prefix(txt.strings[0], "elodin "), "unexpected version text %q", txt.strings[0])
				}
			}
		}
	}
	end_case(r)

	start_case(r, "refuses zone transfers")
	{
		for qtype in ([]u16{252, 251}) { 	// AXFR, IXFR
			q := build_query("example.com.", qtype)
			res := query_udp(port, q)
			if check(r, res.ok, "no response for type %d", qtype) {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.Refused), "type %d: rcode %d, want REFUSED", qtype, h.rcode)
			}
		}
	}
	end_case(r)

	start_case(r, "refuses classes other than IN and CH")
	{
		q := build_query("example.com.", u16(dns.Type.A), class = 4) // HS
		res := query_udp(port, q)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.Refused), "rcode %d, want REFUSED", h.rcode)
		}
	}
	end_case(r)
}
