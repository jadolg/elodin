package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
DoH over HTTP/2.

Covers negotiation, both request forms, concurrency on one connection, the
framing details a browser exercises (CONTINUATION, flow control, DATA
splitting, RST_STREAM, PING) and the error paths.
*/

@(private = "file")
config_h2 :: proc(r: ^Runner, udp_port, doh_port, upstream_port: int, upstream_scheme := "") -> string {
	server := fmt.tprintf("\"%s127.0.0.1:%d\"", upstream_scheme, upstream_port)
	return fmt.tprintf(
		`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}
upstream:
  timeout: 5s
  servers: [%s]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		doh_port,
		r.cert_file,
		r.key_file,
		server,
	)
}

run_h2_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	upstream_port := next_port(r)
	mock := mock_make("h2", upstream_port)
	mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
	mock_synth_all(mock, {203, 0, 113, 5})
	if !mock_start(mock) {
		skip_case(r, "doh/h2", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_h2(r, udp_port, doh_port, upstream_port), udp_port = udp_port})
	if !ok {
		skip_case(r, "doh/h2", "server did not start")
		return
	}
	defer stop_server(&srv)

	query := build_query(fix.qname, fix.qtype, id = 0x2222, allocator = context.allocator)
	defer delete(query)

	start_case(r, "h2: ALPN selects h2 when the client offers it")
	{
		check_eq_str(r, h2_negotiated(doh_port), "h2", "negotiated protocol")
	}
	end_case(r)

	start_case(r, "h2: POST returns the answer")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query), "cannot send the request")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
				check_eq_str(r, h2_header_value(res, "content-type"), "application/dns-message", "content type")
				check(r, h2_header_value(res, "cache-control") != "", "no cache-control header")
				if check(r, len(res.body) >= dns.HEADER_SIZE, "body too short: %d", len(res.body)) {
					h, _ := parse_header(res.body)
					check_eq_int(r, h.ancount, fix.ancount, "answer count")
					check(r, h.id == 0x2222, "transaction ID not echoed: %04x", h.id)
				}
			}
		}
	}
	end_case(r)

	start_case(r, "h2: GET with unpadded base64url")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_get(c, 1, "/dns-query", query), "cannot send the request")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
				h, _ := parse_header(res.body)
				check_eq_int(r, h.ancount, fix.ancount, "answer count")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: Huffman-coded request headers are decoded")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query, huffman = true), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: a header block split across CONTINUATION is accepted")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query, split_headers = true), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
			}
		}
	}
	end_case(r)

	/*
	RFC 7541 6.3: a dynamic table size update may not exceed the limit the
	protocol set, which here is the 4096 of SETTINGS_HEADER_TABLE_SIZE. A larger
	one is a decoding error (4.2), and a decoding error on a connection whose
	HPACK state is now in doubt is a GOAWAY rather than a refused stream.

	An update *at* the limit is sent first, so what the case below shows is a
	size being refused rather than size updates being unwelcome.
	*/
	start_case(r, "h2: a dynamic table size update at the advertised limit is accepted")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query, table_update = 4096), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: a dynamic table size update past the advertised limit is refused")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query, table_update = 8192), "cannot send")
			// The connection ends, so this returns as soon as the read fails
			// rather than waiting out the timeout.
			_ = h2_collect(c, []u32{1}, 3 * time.Second)
			res, found := h2_stream(c, 1)
			answered := found && res.done && res.status == 200
			check(r, !answered, "a table twice the advertised size was accepted and the request served")
			check(r, c.goaway, "no GOAWAY for a header block that could not be decoded")
		}
	}
	end_case(r)

	start_case(r, "h2: concurrent streams are answered in parallel, not in turn")
	{
		// The mock delays every answer, so serial handling would cost the sum of
		// the delays and parallel handling only one of them.
		slow_port := next_port(r)
		slow := mock_make("h2-slow", slow_port)
		mock_delay_all(slow, 300 * time.Millisecond, nil)
		if !check(r, mock_start(slow), "cannot start the slow mock") {
			end_case(r)
			return
		}
		defer mock_stop(slow)

		slow_dns := next_port(r)
		slow_doh := next_port(r)
		slow_srv, sok := start_server(
			r,
			Server_Options{config = config_h2(r, slow_dns, slow_doh, slow_port), udp_port = slow_dns},
		)
		if check(r, sok, "the slow server did not start") {
			defer stop_server(&slow_srv)

			c, cok := h2_connect(slow_doh)
			if check(r, cok, "cannot open an h2 connection") {
				defer h2_close(c)

				started := time.now()
				ids := []u32{1, 3, 5, 7}
				for id, i in ids {
					q := build_query(fmt.tprintf("s%d.parallel.test.", i), u16(dns.Type.A), id = u16(id))
					check(r, h2_send_request(c, id, "POST", "/dns-query", q), "cannot send stream %d", id)
				}
				if check(r, h2_collect(c, ids), "not every stream completed") {
					elapsed := time.diff(started, time.now())
					for id in ids {
						res, _ := h2_stream(c, id)
						check(r, res.status == 200, "stream %d status %d", id, res.status)
					}
					// Four 300ms queries: serial would be about 1.2s.
					check(
						r,
						elapsed < 900 * time.Millisecond,
						"took %.0fms for four 300ms queries, so they were serialised",
						time.duration_milliseconds(elapsed),
					)
				}
			}
		}
	}
	end_case(r)

	start_case(r, "h2: the server waits for flow-control credit and then finishes")
	{
		// A tiny initial window forces the response body to be released in
		// pieces as WINDOW_UPDATEs arrive.
		c, cok := h2_connect(doh_port, H2_Settings{initial_window = 8})
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query), "cannot send")

			/*
			Wait for the server to actually stall on the 8-byte window before
			handing out more credit, rather than sleeping a fixed duration: on a
			slow or busy runner the response may still be in flight when a fixed
			sleep elapses, so the window updates land before the server has sent
			anything and the whole body goes out in one frame once credit
			exists - failing the case below for a timing reason that has nothing
			to do with flow control.

			The deadline below is not what actually bounds a stuck wait: each
			`h2_pump` call blocks inside `conn_read` for up to CLIENT_TIMEOUT
			before it can return and let the deadline be rechecked, so a server
			that never sends anything is caught after one CLIENT_TIMEOUT, not
			after this deadline. It has to sit above CLIENT_TIMEOUT or it would
			never be the thing that fires.
			*/
			stalled := false
			deadline := time.time_add(time.now(), CLIENT_TIMEOUT + 2 * time.Second)
			for time.diff(deadline, time.now()) < 0 {
				if res, found := h2_stream(c, 1); found && res.data_frames >= 1 {
					stalled = true
					break
				}
				if !h2_pump(c) {
					break
				}
			}
			check(r, stalled, "the server never sent a frame constrained by the 8-byte window")

			check(r, h2_send_window_update(c, 1, 65535), "cannot send a stream window update")
			check(r, h2_send_window_update(c, 0, 65535), "cannot send a connection window update")

			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
				if check(r, len(res.body) >= dns.HEADER_SIZE, "body too short: %d", len(res.body)) {
					h, _ := parse_header(res.body)
					check_eq_int(r, h.ancount, fix.ancount, "answer count")
				}
				check(r, res.data_frames > 1, "the body arrived in one frame despite an 8-byte window")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: PING is answered with an ACK")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_ping(c, {1, 2, 3, 4, 5, 6, 7, 8}), "cannot send a ping")
			// Pump alongside a real request so there is something to wait for.
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query), "cannot send")
			h2_collect(c, []u32{1})
			check(r, c.pings >= 1, "no PING ACK was received")
		}
	}
	end_case(r)

	start_case(r, "h2: a reset stream is dropped without disturbing the connection")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query), "cannot send stream 1")
			check(r, h2_send_rst(c, 1), "cannot reset stream 1")

			// The connection must still serve a later stream.
			check(r, h2_send_request(c, 3, "POST", "/dns-query", query), "cannot send stream 3")
			if check(r, h2_collect(c, []u32{3}), "stream 3 never completed after a reset") {
				res, _ := h2_stream(c, 3)
				check_eq_int(r, res.status, 200, "status on the stream after a reset")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: unknown path is 404")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/nope", query), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 404, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: unsupported method is 405")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "PUT", "/dns-query", query), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 405, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: wrong content type is 415")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", query, content_type = "text/plain"), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 415, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: GET without the dns parameter is 400")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "GET", "/dns-query", nil), "cannot send")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 400, "status")
			}
		}
	}
	end_case(r)

	start_case(r, "h2: a client offering only http/1.1 still gets HTTP/1.1")
	{
		res := doh_post(doh_port, "/dns-query", query)
		if check(r, res.ok, "no HTTP/1.1 response") {
			check_eq_int(r, res.status, 200, "status")
			h, _ := parse_header(res.body)
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
		}
	}
	end_case(r)
}

/*
A response larger than one DATA frame.

The upstream is reached over TCP so a big answer is not clipped by the 4096-byte
UDP receive path, and the mock returns a TXT set well over the 16 KiB default
frame size.
*/
run_h2_large_response_case :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("h2-large", upstream_port)
	big := build_large_txt_response("big.test.", 100, context.allocator)
	mock_reply(mock, "big.test.", u16(dns.Type.TXT), big)
	if !mock_start(mock) {
		skip_case(r, "h2: large response", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = config_h2(r, udp_port, doh_port, upstream_port, "tcp://"), udp_port = udp_port},
	)
	if !ok {
		skip_case(r, "h2: large response", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "h2: a response larger than one frame is split and reassembled")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			q := build_query("big.test.", u16(dns.Type.TXT), id = 0x33, edns_size = 4096)
			check(r, h2_send_request(c, 1, "POST", "/dns-query", q), "cannot send")
			if check(r, h2_collect(c, []u32{1}, 20 * time.Second), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
				check(r, len(res.body) > 16384, "response is only %d bytes, too small to split", len(res.body))
				check(r, res.data_frames > 1, "a %d-byte body arrived in one DATA frame", len(res.body))
				check_eq_int(r, len(res.body), len(big), "reassembled length")
				h, _ := parse_header(res.body)
				check(r, h.ancount == 100, "answer count: got %d, want 100", h.ancount)
			}
		}
	}
	end_case(r)
}

// A DNS response carrying `count` TXT records of 400 bytes each.
@(private = "file")
build_large_txt_response :: proc(name: string, count: int, allocator := context.allocator) -> []u8 {
	answers := make([]dns.Record, count, context.temp_allocator)
	for i in 0 ..< count {
		chunk := make([]u8, 400, context.temp_allocator)
		for j in 0 ..< len(chunk) {
			chunk[j] = u8('a' + (i + j) % 26)
		}
		strs := make([]string, 1, context.temp_allocator)
		strs[0] = string(chunk[:255])
		answers[i] = dns.Record {
			name  = name,
			type  = .TXT,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_TXT{strings = strs},
		}
	}
	m := dns.Message {
		question   = []dns.Question{{name = name, type = .TXT, class = .IN}},
		answer     = answers,
		additional = []dns.Record{dns.make_opt(4096, false)},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator, dns.MAX_MESSAGE)
	if err != .None {
		return nil
	}
	return wire
}
