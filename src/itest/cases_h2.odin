package itest

import "core:fmt"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "elodin:dns"
import "elodin:h2"
import "elodin:tlsx"

/*
DoH over HTTP/2.

Covers negotiation, both request forms, concurrency on one connection, the
framing details a browser exercises (CONTINUATION, flow control, DATA
splitting, RST_STREAM, PING) and the error paths.
*/

@(private = "file")
config_h2 :: proc(r: ^Runner, udp_port, doh_port, upstream_port: int, upstream_scheme := "") -> string {
	return base_config(
		udp_port,
		fmt.tprintf(`["%s127.0.0.1:%d"]`, upstream_scheme, upstream_port),
		log = "{ level: debug, queries: true }",
		timeout = "5s",
		listeners_extra = fmt.tprintf(
			"  doh: {{ enabled: true, address: \"127.0.0.1\", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}",
			doh_port,
			r.cert_file,
			r.key_file,
		),
	)
}

run_h2_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	upstream_port := next_port(r)
	mock := mock_make("h2", upstream_port)
	mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
	mock_synth_all(mock, {203, 0, 113, 5})
	if !mock_start_or_skip(r, mock, "doh/h2") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_h2(r, udp_port, doh_port, upstream_port),
			udp_port = udp_port,
			doh_port = doh_port,
		},
	)
	if !ok {
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
					h := parse_header(r, res.body)
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
				h := parse_header(r, res.body)
				check_eq_int(r, h.ancount, fix.ancount, "answer count")
			}
		}
	}
	end_case(r)

	/*
	The Apple .mobileconfig profile is served over HTTP/2 too, since that is the
	protocol a device negotiates. The URL inside it is built from the `:authority`
	pseudo-header - the client sends `elodin.local` - and the response carries the
	Apple content type rather than the DNS-message one. Signed over this transport
	as over the other one, and checked the same way; see the HTTP/1.1 case.
	*/
	start_case(r, "h2: the Apple profile downloads, signed")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_request(c, 1, "GET", "/apple-doh.mobileconfig", nil), "cannot send the request")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status")
				check_eq_str(
					r,
					h2_header_value(res, "content-type"),
					"application/x-apple-aspen-config",
					"content type",
				)
				payload, verified := cms_verify(r, res.body, r.cert_file)
				if check(r, verified, "the profile is not a signature openssl will verify") {
					check(
						r,
						strings.contains(payload, "<string>https://elodin.local/dns-query</string>"),
						"the signed profile does not carry the DoH URL built from :authority",
					)
				}
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

	start_case(r, "h2: Content-Type is the media type, whole and folded (#304)")
	{
		for c in DOH_CONTENT_TYPE_CASES {
			hc, cok := h2_connect(doh_port)
			if !check(r, cok, "cannot open an h2 connection") {
				break
			}
			check(r, h2_send_request(hc, 1, "POST", "/dns-query", query, content_type = c.content_type), "cannot send")
			if check(r, h2_collect(hc, []u32{1}), "%q: stream 1 never completed", c.content_type) {
				res, _ := h2_stream(hc, 1)
				check_eq_int(r, res.status, c.status, c.content_type)
			}
			h2_close(hc)
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
	RFC 9113 8.1: a request may end with a trailer section after its body. One
	that does is served, and the connection carries on; trailers that leave the
	stream open or carry a pseudo-header field make the request malformed, a
	stream error of type PROTOCOL_ERROR (8.1.1), and the connection still
	carries on (#457). Stream 3 on the same connection is what shows it did.
	*/
	{
		Trailer_Row :: struct {
			what:       string,
			trailers:   []H2_Field,
			end_stream: bool,
			served:     bool,
		}
		rows := []Trailer_Row {
			{"h2: a request that ends with trailers is served", {{"x-t", "1"}}, true, true},
			{"h2: trailers without END_STREAM reset the request", {{"x-t", "1"}}, false, false},
			{"h2: a pseudo-header in trailers resets the request", {{":path", "/"}}, true, false},
		}
		for row in rows {
			start_case(r, row.what)
			c, cok := h2_connect(doh_port)
			if check(r, cok, "cannot open an h2 connection") {
				check(r, h2_send_request(c, 1, "POST", "/dns-query", query, trailers = row.trailers, trailers_end_stream = row.end_stream), "cannot send")
				if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
					res, _ := h2_stream(c, 1)
					if row.served {
						check_eq_int(r, res.status, 200, "status")
						check(r, !res.reset, "stream 1 was reset")
					} else {
						check(r, res.reset && res.reset_code == .Protocol_Error, "stream 1: reset %v, code %v; want PROTOCOL_ERROR", res.reset, res.reset_code)
					}
				}
				check(r, h2_send_request(c, 3, "POST", "/dns-query", query), "cannot send stream 3")
				if check(r, h2_collect(c, []u32{3}), "stream 3 never completed after the trailers") {
					res, _ := h2_stream(c, 3)
					check_eq_int(r, res.status, 200, "stream 3 status")
				}
				check(r, !c.goaway, "GOAWAY %v for the trailers", c.goaway_code)
				h2_close(c)
			}
			end_case(r)
		}
	}

	/*
	RFC 9113 6.5.2 makes an ENABLE_PUSH other than 0 or 1 a PROTOCOL_ERROR, and
	5.1 makes a WINDOW_UPDATE or RST_STREAM on an idle stream one too. Stream 1
	is served before the frame, so a refusal is the frame's and not a connection
	that never worked; the accepted rows then serve stream 3, so a server that
	refused too much fails them. A row refused by its preface's ENABLE_PUSH
	writes nothing after it, not even the SETTINGS ACK: a write to the
	connection the server has closed draws a TCP reset, which can discard the
	GOAWAY before it is read.
	*/
	H2_Probe :: enum {
		None,
		Window_Update,
		Rst_Stream,
	}
	for tc in ([]struct {
			what:    string,
			push:    int,
			probe:   H2_Probe,
			stream:  u32,
			refused: bool,
		} {
			{"ENABLE_PUSH=2", 2, .None, 0, true},
			{"WINDOW_UPDATE on an idle stream", 0, .Window_Update, 5, true},
			{"RST_STREAM on an idle stream", 0, .Rst_Stream, 5, true},
			{"ENABLE_PUSH=1", 1, .None, 0, false},
			{"WINDOW_UPDATE on a closed stream", 0, .Window_Update, 1, false},
			{"RST_STREAM on a closed stream", 0, .Rst_Stream, 1, false},
		}) {
		start_case(r, fmt.tprintf("h2: %s is %s", tc.what, "a PROTOCOL_ERROR" if tc.refused else "accepted"))
		c, cok := h2_connect(doh_port, {enable_push = tc.push})
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			c.no_ack = tc.refused && tc.probe == .None
			if !c.no_ack {
				check(r, h2_send_request(c, 1, "POST", "/dns-query", query), "cannot send")
				// A reset counts as completed too, and is not being served.
				if check(r, h2_collect(c, []u32{1}, 3 * time.Second), "stream 1 never completed") {
					res, _ := h2_stream(c, 1)
					check_eq_int(r, res.status, 200, "status of stream 1 before the frame")
				}
			}
			switch tc.probe {
			case .None:
			case .Window_Update:
				check(r, h2_send_window_update(c, tc.stream, 1024), "cannot send a window update")
			case .Rst_Stream:
				check(r, h2_send_rst(c, tc.stream), "cannot send a reset")
			}
			if tc.refused {
				// The connection ends, so this returns as soon as the read fails.
				for start := time.tick_now(); !c.goaway && time.tick_since(start) < 3 * time.Second && h2_pump(c); {}
				check(r, c.goaway && c.goaway_code == .Protocol_Error, "goaway=%v (%v), want PROTOCOL_ERROR", c.goaway, c.goaway_code)
			} else {
				check(r, h2_send_request(c, 3, "POST", "/dns-query", query), "cannot send stream 3")
				if check(r, h2_collect(c, []u32{3}), "stream 3 never completed after the frame") {
					// A reset counts as completed too, and is not being served.
					res, _ := h2_stream(c, 3)
					check_eq_int(r, res.status, 200, "status of stream 3 after the frame")
				}
				check(r, !c.goaway, "GOAWAY (%v) for a frame the server must accept", c.goaway_code)
			}
		}
		end_case(r)
	}

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
		// Stopped whether or not it started: `mock_stop` frees a failed start too.
		slow_ok := mock_start(slow)
		defer mock_stop(slow)
		if check(r, slow_ok, "cannot start the slow mock") {
			slow_dns := next_port(r)
			slow_doh := next_port(r)
			slow_srv, sok := start_server(
				r,
				Server_Options {
					config = config_h2(r, slow_dns, slow_doh, slow_port),
					udp_port = slow_dns,
					doh_port = slow_doh,
				},
			)
			if sok {
				defer stop_server(&slow_srv)

				c, cok := h2_connect(slow_doh)
				if check(r, cok, "cannot open an h2 connection") {
					defer h2_close(c)

					started := time.tick_now()
					ids := []u32{1, 3, 5, 7}
					for id, i in ids {
						q := build_query(fmt.tprintf("s%d.parallel.test.", i), u16(dns.Type.A), id = u16(id))
						check(r, h2_send_request(c, id, "POST", "/dns-query", q), "cannot send stream %d", id)
					}
					if check(r, h2_collect(c, ids), "not every stream completed") {
						elapsed := time.tick_since(started)
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
			deadline := time.tick_add(time.tick_now(), CLIENT_TIMEOUT + 2 * time.Second)
			for time.tick_diff(time.tick_now(), deadline) > 0 {
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
					h := parse_header(r, res.body)
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

	/*
	RFC 9113 8.2 and 8.3: a request carrying a connection-specific field, or an
	uppercase field name, is malformed - a stream error of type PROTOCOL_ERROR,
	not something to answer. Driven over the real transport rather than only
	against `finish_headers` because the answer has to be an RST_STREAM that
	leaves the connection usable, and it is the connection that the streams
	after it depend on.
	*/
	start_case(r, "h2: a malformed request is reset and the connection carries on")
	{
		Case :: struct {
			what:  string,
			field: H2_Field,
		}
		cases := []Case {
			{"transfer-encoding", {"transfer-encoding", "chunked"}},
			{"connection", {"connection", "keep-alive"}},
			{"te other than trailers", {"te", "gzip"}},
			// A second one after the one every POST carries (#304).
			{"a repeated content-type", {"content-type", "application/dns-message"}},
			{"an uppercase field name", {"X-Smuggled", "1"}},
		}
		for tc in cases {
			c, cok := h2_connect(doh_port)
			if !check(r, cok, "cannot open an h2 connection for %s", tc.what) {
				continue
			}
			defer h2_close(c)

			check(
				r,
				h2_send_request(c, 1, "POST", "/dns-query", query, extra = []H2_Field{tc.field}),
				"cannot send the malformed request with %s",
				tc.what,
			)
			if check(r, h2_collect(c, []u32{1}), "stream 1 never ended for %s", tc.what) {
				res, _ := h2_stream(c, 1)
				check(r, res.reset, "%s was answered instead of reset", tc.what)
				check_eq_int(
					r,
					int(res.reset_code),
					int(h2.Error_Code.Protocol_Error),
					fmt.tprintf("reset code for a request with %s", tc.what),
				)
				check_eq_int(r, res.status, 0, fmt.tprintf("status for a request with %s", tc.what))
			}

			// The connection is the peer's, not the request's: a later stream on
			// it must still be served.
			check(r, !c.goaway, "a malformed request took the whole connection down for %s", tc.what)
			check(r, h2_send_request(c, 3, "POST", "/dns-query", query), "cannot send stream 3 after %s", tc.what)
			if check(r, h2_collect(c, []u32{3}), "stream 3 never completed after %s", tc.what) {
				res, _ := h2_stream(c, 3)
				check_eq_int(r, res.status, 200, fmt.tprintf("status on the stream after %s", tc.what))
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
			check(r, h2_send_request(c, 3, "PUT", "/apple-doh.mobileconfig", nil), "cannot send")
			check(r, h2_send_request(c, 5, "HEAD", "/dns-query", nil), "cannot send")
			if check(r, h2_collect(c, []u32{1, 3, 5}), "a stream never completed") {
				// RFC 9110 15.5.6: a 405 MUST carry Allow.
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 405, "status")
				check_eq_str(r, h2_header_value(res, "allow"), "GET, POST", "allow")
				res, _ = h2_stream(c, 3)
				check_eq_int(r, res.status, 405, "profile status")
				check_eq_str(r, h2_header_value(res, "allow"), "GET", "profile allow")
				// RFC 9110 9.3.2: a reply to HEAD carries no content.
				res, _ = h2_stream(c, 5)
				check_eq_int(r, res.status, 405, "HEAD status")
				check_eq_int(r, res.data_frames, 0, "DATA frames on the HEAD reply")
				// RFC 9110 8.6: no content-length unless it is what GET would send.
				check_eq_str(r, h2_header_value(res, "content-length"), "", "content-length on the HEAD reply")
				check_eq_str(r, h2_header_value(res, "allow"), "GET, POST", "allow on the HEAD reply")
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
			h := parse_header(r, res.body)
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
		}
	}
	end_case(r)

	/*
	Last, because it narrows `server.allow_from` past loopback for good. A held
	connection's next request is refused 403 and the connection ended with
	GOAWAY(NO_ERROR), as HTTP/1.1 closes it (#642). The status is read from the
	wire: an encoder that cannot spell a status sends 500.

	The request is followed by more than the server reads before it stops. A close
	with bytes unread is an RST, which RFC 1122 4.2.2.13 lets this end's kernel
	answer by discarding the 403 and the GOAWAY unless the server drained first.
	Linux hands over what it already holds, the server's close_notify included, so
	what is checked is what comes after that on the socket: the end of the stream,
	not a reset.
	*/
	start_case(r, "h2: a connection held across a reload that drops its network from allow_from gets 403, then GOAWAY")
	{
		c, cok := h2_connect(doh_port)
		if check(r, cok, "cannot open an h2 connection") {
			defer h2_close(c)
			check(r, h2_send_get(c, 1, "/dns-query", query), "cannot send the request")
			if check(r, h2_collect(c, []u32{1}), "stream 1 never completed") {
				res, _ := h2_stream(c, 1)
				check_eq_int(r, res.status, 200, "status before the reload")
			}
			narrowed := strings.concatenate(
				{config_h2(r, udp_port, doh_port, upstream_port), "server:\n  allow_from: [\"192.0.2.0/24\"]\n"},
				context.temp_allocator,
			)
			if check(r, reload_to(r, &srv, narrowed, "msg=reloaded"), "the reload was never logged") {
				NEEDLE :: "no longer admits"
				before := log_count(&srv, NEEDLE)
				// 68 KB of PINGs behind the request (five TLS records), in the same
				// write: more than one read takes, there before the server answers.
				pings := make([dynamic]u8, 0, 4000 * 17, context.temp_allocator)
				for _ in 0 ..< 4000 {
					h2.write_frame_header(&pings, 8, .Ping, 0, 0)
					append(&pings, 0, 0, 0, 0, 0, 0, 0, 0)
				}
				check(r, h2_send_request(c, 3, "POST", "/dns-query", query, then = pings[:]), "cannot send the request")
				check(r, wait_for_log_count(&srv, NEEDLE, before + 1, 5 * time.Second), "the refusal was never logged")
				for !c.goaway && h2_pump(c) {}
				res, found := h2_stream(c, 3)
				if check(r, found, "stream 3 was never answered") {
					check_eq_int(r, res.status, 403, "status after the reload")
				}
				check(r, c.goaway, "the refused connection was not sent GOAWAY")
				check(r, c.goaway_code == .No_Error, "GOAWAY code %v, want NO_ERROR", c.goaway_code)
				end := tlsx.Error.None
				for end == .None {
					rest: [4096]u8
					n, err := tlsx.read(c.conn.tls, rest[:])
					end = .Closed if err == .None && n == 0 else err
				}
				check(r, end == .Closed, "the refused connection ended with %v, not a close", end)
				// Past the close_notify the socket holds the FIN or the RST, whichever
				// the close sent; the socket is non-blocking under TLS, hence the poll.
				fd := posix.FD(c.conn.socket)
				pfd := posix.pollfd{fd = fd, events = {.IN}}
				if check(r, posix.poll(&pfd, 1, 5000) == 1, "the refused connection was never closed") {
					tail: [1]u8
					n := posix.recv(fd, &tail, 1, {})
					check(r, n == 0, "the refused connection ended with %d, %v, not a close", n, posix.errno())
				}
			}
		}
	}
	end_case(r)
}

/*
A response larger than one DATA frame.

The upstream is reached over TCP so a big answer is not clipped to the UDP size
the upstream query advertises, and the mock returns a TXT set well over the 16 KiB default
frame size.
*/
run_h2_large_response_case :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("h2-large", upstream_port)
	big := big_txt_answer("big.test.", 100, context.allocator)
	mock_reply(mock, "big.test.", u16(dns.Type.TXT), big)
	if !mock_start_or_skip(r, mock, "h2: large response") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_h2(r, udp_port, doh_port, upstream_port, "tcp://"),
			udp_port = udp_port,
			doh_port = doh_port,
		},
	)
	if !ok {
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
				h := parse_header(r, res.body)
				check(r, h.ancount == 100, "answer count: got %d, want 100", h.ancount)
			}
		}
	}
	end_case(r)
}
