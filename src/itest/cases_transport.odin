package itest

import "core:encoding/base64"
import "core:fmt"
import "core:strings"
import "elodin:dns"

/*
Listener-side coverage: the four ways a client can reach elodin, plus the DoH
endpoint's HTTP behaviour.
*/

@(private = "file")
config_all_transports :: proc(r: ^Runner, udp_port, dot_port, doh_port, upstream_port: int) -> string {
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
		udp_port,
		udp_port,
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

	udp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_all_transports(r, udp_port, dot_port, doh_port, upstream_port),
			udp_port = udp_port,
			tcp_port = udp_port,
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
		res := query_udp(udp_port, query)
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
		res := query_tcp(udp_port, query)
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
		results := query_tcp_multi(udp_port, [][]u8{q1, q2, q3})
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

	/*
	The second request in the segment is a request, not spare bytes.

	Nothing asks a client to wait for the answer before sending the next question
	(RFC 9112 9.3), and keep-alive is what this endpoint advertises. Both arrive
	in the same read, so the second one is in the reader's buffer when the first
	is answered: dropped along with it, the client waits out `client_timeout` for
	an answer that was never going to come.

	Counted rather than read one reply at a time, for the reason
	`doh_raw_until_close` gives - two answers usually arrive in one record.
	*/
	start_case(r, "doh: two pipelined requests are both answered")
	{
		encoded, eerr := base64.encode(query, base64.ENC_URL_TABLE, context.temp_allocator)
		if eerr != nil {
			fail(r, "cannot encode the pipelined query")
		} else {
			req := fmt.tprintf(
				"POST /dns-query HTTP/1.1\r\nHost: elodin.local\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s" +
				"GET /dns-query?dns=%s HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n",
				len(query),
				string(query),
				strings.trim_right(encoded, "="),
			)
			data, read := doh_raw_until_close(doh_port, req)
			replies := strings.count(data, "HTTP/1.1 200") if read else 0
			check(r, replies == 2, "%d of the two pipelined requests were answered", replies)
		}
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

	/*
	The Apple .mobileconfig profile downloads, and carries the DoH URL built from
	the request's own Host.

	The whole point of the endpoint is that an iPhone reaches it over exactly this
	transport and gets back a file whose ServerURL names the host it used, so this
	asks for it as a device would - a GET, over the real DoH TLS connection - and
	checks the profile that comes back is the Apple content type and points at
	`https://<that host>/dns-query`, the managed-DNS payload iOS installs.
	*/
	start_case(r, "doh: the Apple profile downloads and names the request host")
	{
		res := doh_raw(
			doh_port,
			"GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: dns.test.local\r\nConnection: close\r\n\r\n",
		)
		if check(r, res.ok, "no HTTP response") {
			check_eq_int(r, res.status, 200, "status")
			check(
				r,
				header_contains(res.headers, "content-type: application/x-apple-aspen-config"),
				"not served as an Apple configuration profile",
			)
			body := string(res.body)
			check(
				r,
				strings.contains(body, "<string>https://dns.test.local/dns-query</string>"),
				"the profile does not carry the DoH URL built from the request Host",
			)
			check(
				r,
				strings.contains(body, "com.apple.dnsSettings.managed"),
				"the profile is missing the managed DNS payload",
			)
		}
	}
	end_case(r)

	start_case(r, "doh: the Apple profile path is GET-only")
	{
		res := doh_raw(
			doh_port,
			"POST /apple-doh.mobileconfig HTTP/1.1\r\nHost: dns.test.local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		)
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

	/*
	Content-Length is 1*DIGIT (RFC 9110 8.6) and repeats are invalid (RFC 9112
	6.3). Both of these are requests a front end sharing :443 with elodin - nginx,
	haproxy, Envoy - refuses or frames differently, and answering them is how a
	back end ends up disagreeing with the hop in front about where this request
	stops and the next one starts.

	The body below is the real query, correctly sized. Only the way the size is
	written is out of grammar, so an answer coming back means the length was
	acted on.
	*/
	start_case(r, "doh: a hexadecimal Content-Length is not a length")
	{
		req := fmt.tprintf(
			"POST /dns-query HTTP/1.1\r\nHost: elodin.local\r\nContent-Type: application/dns-message\r\nContent-Length: 0x%x\r\nConnection: close\r\n\r\n%s",
			len(query),
			string(query),
		)
		res := doh_raw(doh_port, req)
		check(r, !res.ok || res.status != 200, "a hexadecimal Content-Length was answered (status %d)", res.status)
	}
	end_case(r)

	/*
	Two Content-Lengths, the second of them zero, and a body that is itself a
	request.

	Taking the last of the pair, elodin frames this as a request with no body,
	answers it, and leaves the octets that follow unclaimed. Taking the first, it
	is one request with a body. Both readings are answers, and RFC 9112 6.3 asks
	for neither: the message is to be refused, because whichever way this hop
	resolves the pair, the hop in front may resolve it the other way and forward
	the remainder as a request of its own - on a connection it is pipelining for
	somebody else.

	So what is checked is that nothing at all comes back. A reply means a framing
	was chosen.
	*/
	start_case(r, "doh: a repeated Content-Length is refused rather than framed")
	{
		encoded, eerr := base64.encode(query, base64.ENC_URL_TABLE, context.temp_allocator)
		if eerr != nil {
			fail(r, "cannot encode the smuggled query")
		} else {
			smuggled := fmt.tprintf(
				"GET /dns-query?dns=%s HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\n\r\n",
				strings.trim_right(encoded, "="),
			)
			req := fmt.tprintf(
				"POST /dns-query HTTP/1.1\r\nHost: elodin.local\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n%s",
				len(smuggled),
				smuggled,
			)
			data, read := doh_raw_until_close(doh_port, req)
			replies := strings.count(data, "HTTP/1.1 ") if read else 0
			check(r, replies == 0, "%d reply(s) came back, so one of the two lengths was acted on", replies)
		}
	}
	end_case(r)

	/*
	The request line is three tokens and the third of them is a version this
	server speaks (RFC 9112 3 and 2.3), and an HTTP/1.1 request carries exactly
	one Host (RFC 9112 3.2).

	Same argument as the Content-Length cases above, on the other half of the
	request line. A front end sharing :443 with elodin reads the version and the
	authority as the grammar writes them - it refuses these, or reads a target or
	a host out of them that this hop did not - so what is checked is that the
	refusal happens here too, and that it says which half was wrong: 505 for a
	major version this endpoint does not speak, 400 for a line that is not three
	tokens - a third token that is not an HTTP-version at all included - and for
	the Host cases.

	`HTTP/1.0` is in the list because it is the one version below 1.1 that stays
	valid, Host and all: the field postdates it, so a 1.0 request without one is
	answered rather than refused.

	The last case carries a body the reader never gets to - the request line is
	refused before the headers that frame it - and checks that a status still comes
	back over the real listener. Whether the answer survives the close that follows
	it is timing, so it is `test_a_refusal_outlives_the_close_that_follows_it` that
	pins it: a client that reads as promptly as this one does has the answer before
	the close, and the case here would not notice its loss.
	*/
	start_case(r, "doh: the request line and Host are checked")
	{
		Case :: struct {
			request: string,
			status:  int,
			what:    string,
		}
		CASES := []Case {
			{"GET /nope JUNK\r\nHost: elodin.local\r\nConnection: close\r\n\r\n", 400, "a version that is not one"},
			{"GET /nope HTTP/2.0\r\nHost: elodin.local\r\nConnection: close\r\n\r\n", 505, "HTTP/2 without ALPN"},
			{"GET /nope HTTP/1.1 x\r\nHost: elodin.local\r\nConnection: close\r\n\r\n", 400, "a fourth token"},
			{"GET /nope\r\nHost: elodin.local\r\nConnection: close\r\n\r\n", 400, "two tokens"},
			{"GET /nope HTTP/1.1\r\nConnection: close\r\n\r\n", 400, "1.1 with no Host"},
			{
				"GET /nope HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nConnection: close\r\n\r\n",
				400,
				"two Hosts",
			},
			{"GET /nope HTTP/1.0\r\nConnection: close\r\n\r\n", 404, "1.0 without a Host, still served"},
		}
		for c in CASES {
			res := doh_raw(doh_port, c.request)
			if check(r, res.ok, "%s: no HTTP response", c.what) {
				check(r, res.status == c.status, "%s: status %d, want %d", c.what, res.status, c.status)
			}
		}

		// The refusal with a body behind it. 16 KiB is past the reader's first
		// read, so bytes of it are still unread when the connection closes.
		UNREAD :: 16 * 1024
		with_body := fmt.tprintf(
			"POST /nope JUNK\r\nHost: elodin.local\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			UNREAD,
			strings.repeat("x", UNREAD, context.temp_allocator),
		)
		res := doh_raw(doh_port, with_body)
		if check(r, res.ok, "a refusal with a body behind it: no HTTP response") {
			check(r, res.status == 400, "a refusal with a body behind it: status %d, want 400", res.status)
		}
	}
	end_case(r)

	// --- local answers, no upstream involved ---
	start_case(r, "chaos: version.bind reports the build")
	{
		q := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
		res := query_udp(udp_port, q)
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
			res := query_udp(udp_port, q)
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
		res := query_udp(udp_port, q)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.Refused), "rcode %d, want REFUSED", h.rcode)
		}
	}
	end_case(r)
}
