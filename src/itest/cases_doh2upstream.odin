package itest

import "core:fmt"
import "core:net"
import "core:time"
import "elodin:dns"
import "elodin:h2"

/*
elodin as a DoH client: ALPN decides between HTTP/2 and HTTP/1.1 against the
upstream, exactly as it does the other way around for elodin's own DoH
listener (cases_h2.odin). See src/upstream/h2client.odin.
*/
// One DoH upstream on loopback, as an entry of `upstream.servers`.
@(private = "file")
doh_upstream :: proc(name: string, port: int) -> string {
	return fmt.tprintf(`{{ name: %s, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}`, name, port)
}

run_upstream_doh2_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	payload := from_hex(fix.response, context.allocator)

	// --- ALPN prefers h2 when the upstream offers it ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		// Stopped whether or not it started: `doh2_mock_stop` frees a failed start too.
		started := doh2_mock_start(mock, r.cert_file, r.key_file)
		defer doh2_mock_stop(mock)
		if !started {
			skip_case(r, "upstream: doh over h2", "cannot start the mock")
		} else {
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("doh2up", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: resolves a query over a DoH/h2 upstream")
				{
					if _, h, answered := ask(r, udp_port, fix.qname, fix.qtype); answered {
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check(r, h2_hits >= 1, "the upstream was not reached over h2")
					check_eq_int(r, h1_hits, 0, "fell back to http/1.1 against an h2-capable upstream")
				}
				end_case(r)

				start_case(r, "upstream: DoH/h2 connection is multiplexed across queries, not reopened")
				{
					before_h2, _ := doh2_mock_counts(mock)
					for i in 0 ..< 5 {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(500 + i)))
						check(r, res.ok, "no response on query %d", i)
					}
					after_h2, _ := doh2_mock_counts(mock)
					// Every query answered over h2, but on the one shared connection:
					// hits (streams) go up while the mock only ever accepts once.
					check_eq_int(r, after_h2 - before_h2, 5, "streams answered over h2")
				}
				end_case(r)
				stop_server(&srv)
			}
		}
	}

	// --- A server that starts to offer h2 is asked over h2 ---
	{
		upstream_port := next_port(r)
		old := doh2_mock_make(upstream_port, "/dns-query", payload)
		started := doh2_mock_start(old, r.cert_file, r.key_file, {"http/1.1"})
		if !started {
			doh2_mock_stop(old)
			skip_case(r, "upstream: doh protocol relearned", "cannot start the mock")
		} else {
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("relearn", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if !ok {
				doh2_mock_stop(old)
			} else {
				start_case(r, "upstream: a DoH server that starts to choose h2 is asked over h2, not sent HTTP/1.1")
				{
					_, _, first := ask(r, udp_port, fix.qname, fix.qtype)
					h2_before, h1_hits := doh2_mock_counts(old)
					check(r, first && h1_hits >= 1, "the premise: the http/1.1-only server was asked over http/1.1")
					check_eq_int(r, h2_before, 0, "the premise: the http/1.1-only server was asked over h2")
					// The same address, now preferring h2: what a move to another
					// server, or the server's own upgrade, looks like here.
					doh2_mock_stop(old)
					next := doh2_mock_make(upstream_port, "/dns-query", payload)
					defer doh2_mock_stop(next)
					if check(r, doh2_mock_start(next, r.cert_file, r.key_file), "cannot restart the mock with h2") {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 0x6915))
						if check(r, res.ok, "no response once the server chose h2") {
							check_eq_int(r, parse_header(r, res.wire).rcode, int(dns.Rcode.No_Error), "rcode once the server chose h2")
						}
						h2_hits, h1_after := doh2_mock_counts(next)
						check(r, h2_hits >= 1, "the server that chose h2 was not asked over h2")
						check_eq_int(r, h1_after, 0, "the server that chose h2 was sent HTTP/1.1")
					}
				}
				end_case(r)
				stop_server(&srv)
			}
		}
	}

	// --- ALPN falls back to http/1.1 against a resolver that lacks h2 ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		started := doh2_mock_start(mock, r.cert_file, r.key_file, {"http/1.1"})
		defer doh2_mock_stop(mock)
		if !started {
			skip_case(r, "upstream: doh h2 alpn fallback", "cannot start the mock")
		} else {
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("h1up", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: falls back to http/1.1 when the upstream does not offer h2")
				{
					if _, h, answered := ask(r, udp_port, fix.qname, fix.qtype); answered {
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check_eq_int(r, h2_hits, 0, "used h2 against an upstream that only offered http/1.1")
					check(r, h1_hits >= 1, "the upstream was not reached over http/1.1")
				}
				end_case(r)
				stop_server(&srv)
			}
		}
	}

	// --- a race member over HTTP/1.1 answering 503 with a body ---
	/*
	The race path takes replies from the heap and frees them only when they
	win, so a refused reply's body is the exchange's to release (#524). Under
	`mise run leakcheck` a body left behind is a report; here the case pins that
	the 503 path is the one taken and that the race rides through it.
	*/
	{
		down_port := next_port(r)
		up_port := next_port(r)
		down := doh2_mock_make(down_port, "/dns-query", payload)
		down.status = 503
		up := doh2_mock_make(up_port, "/dns-query", payload)
		// Both are stopped, started or not: the first may have started when the
		// second did not.
		down_ok, up_ok := doh2_mock_start(down, r.cert_file, r.key_file, {"http/1.1"}), doh2_mock_start(up, r.cert_file, r.key_file)
		defer doh2_mock_stop(down)
		defer doh2_mock_stop(up)
		if !down_ok || !up_ok {
			skip_case(r, "upstream: doh h1 503 in a race", "cannot start the mock")
		} else {
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s, %s]", doh_upstream("down", down_port), doh_upstream("up", up_port)), timeout = "5s", upstream_extra = "  strategy: race")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: a race rides through an HTTP/1.1 member answering 503 with a body")
				{
					for i in 0 ..< 3 {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(0x5240 + i)))
						if check(r, res.ok, "query %d: no response", i) {
							h := parse_header(r, res.wire)
							check_eq_int(r, h.ancount, fix.ancount, "answer count")
						}
					}
					// The race answers with the first member, so the 503 member's own
					// dial may still be under way when the last answer arrives.
					h1_hits := 0
					asked_by := time.tick_add(time.tick_now(), 5 * time.Second)
					for {
						_, h1_hits = doh2_mock_counts(down)
						if h1_hits >= 1 || time.tick_diff(time.tick_now(), asked_by) <= 0 {
							break
						}
						time.sleep(10 * time.Millisecond)
					}
					check(r, h1_hits >= 1, "the 503 member was never asked, so its body was never read")
				}
				end_case(r)
				stop_server(&srv)
			}
		}
	}

	// --- an HTTP/1.1 reply longer than a DNS message ---
	/*
	RFC 8484 6 holds application/dns-message to 65535 bytes, so a 96 KB reply is
	refused even though it echoes the query's header and question, rather than
	taken as the answer at twice its length per query (#525).
	*/
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		mock.pad = 98304
		started := doh2_mock_start(mock, r.cert_file, r.key_file, {"http/1.1"})
		defer doh2_mock_stop(mock)
		if !started {
			skip_case(r, "upstream: doh h1 oversized reply", "cannot start the mock")
		} else {
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("big", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: a DoH reply over HTTP/1.1 longer than a DNS message is refused")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 0x5250))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode")
					}
					_, h1_hits := doh2_mock_counts(mock)
					check(r, h1_hits >= 1, "the oversized member was never asked over HTTP/1.1")
				}
				end_case(r)
				stop_server(&srv)
			}
		}
	}

	// --- an h2 response that ends with trailers ---
	/*
	RFC 9113 8.1: a response may end with a trailer section, which carries no
	pseudo-header field; one that does is malformed, and a client MUST NOT
	accept it (8.1.1). So trailers on a 200 leave the answer standing, and a
	`:status` in them is no answer at all - here a 500 that a trailing 200 does
	not override (#457).
	*/
	{
		Trailer_Case :: struct {
			what:     string,
			head:     int,
			trailers: []h2.Header_Field,
			rcode:    int,
		}
		trailer_cases := []Trailer_Case {
			{"upstream: an h2 answer that ends with trailers is taken", 200, {{name = "x-t", value = "1"}}, int(dns.Rcode.No_Error)},
			{"upstream: a :status in an h2 answer's trailers is no answer", 500, {{name = ":status", value = "200"}}, int(dns.Rcode.Serv_Fail)},
		}
		for tc, i in trailer_cases {
			upstream_port := next_port(r)
			mock := doh2_mock_make(upstream_port, "/dns-query", payload)
			mock.trailer_head = tc.head
			mock.trailers = tc.trailers
			if !doh2_mock_start(mock, r.cert_file, r.key_file, {"h2"}) {
				skip_case(r, tc.what, "cannot start the mock")
				doh2_mock_stop(mock)
				continue
			}
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("trailers", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, tc.what)
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(0x5260 + i)))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.rcode, tc.rcode, "rcode")
					}
					h2_hits, _ := doh2_mock_counts(mock)
					check(r, h2_hits >= 1, "the upstream was not reached over h2")
				}
				end_case(r)
				stop_server(&srv)
			}
			doh2_mock_stop(mock)
		}
	}

	// --- an h2 response held to its content-length ---
	/*
	RFC 9113 8.1.1: a response whose `content-length` is not the sum of its
	DATA is malformed, and "Clients MUST NOT accept a malformed response". One
	that matches is the answer; one that does not is no answer at all.
	*/
	{
		Length_Case :: struct {
			what:   string,
			length: string,
			rcode:  int,
		}
		// Literals the mock's threads read after the case: on the heap, freed
		// once the mock is stopped.
		matching := fmt.aprint(len(payload))
		short := fmt.aprint(len(payload) + 100)
		defer delete(matching)
		defer delete(short)
		length_cases := []Length_Case {
			{"upstream: an h2 answer whose content-length matches is taken", matching, int(dns.Rcode.No_Error)},
			{"upstream: an h2 answer short of its content-length is no answer", short, int(dns.Rcode.Serv_Fail)},
		}
		for tc, i in length_cases {
			upstream_port := next_port(r)
			mock := doh2_mock_make(upstream_port, "/dns-query", payload)
			mock.content_length = tc.length
			if !doh2_mock_start(mock, r.cert_file, r.key_file, {"h2"}) {
				skip_case(r, tc.what, "cannot start the mock")
				doh2_mock_stop(mock)
				continue
			}
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("length", upstream_port)), timeout = "5s")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, tc.what)
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(0x5270 + i)))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.rcode, tc.rcode, "rcode")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check(r, h2_hits >= 1 && h1_hits == 0, "the upstream was reached over h2 %d times and http/1.1 %d", h2_hits, h1_hits)
				}
				end_case(r)
				stop_server(&srv)
			}
			doh2_mock_stop(mock)
		}
	}

	// --- an upstream answering 429 or 503 asks to be left alone ---
	/*
	RFC 6585 4 and RFC 9110 15.6.4: a 429 is the upstream refusing this server,
	a 503 one that cannot serve for now. Each is a kind of its own, not an
	`http_error`; the log names the status and the
	`Retry-After` it sent, and that parks it at once for as long as it asks (RFC
	9110 10.2.3), so the queries after the first are not sent to it (#258). Over
	both versions of the protocol, each with its own way of carrying the field.
	*/
	{
		Throttle_Case :: struct {
			what:   string,
			alpn:   []string,
			status: int,
			// The kind as the log names it, and as the metric labels it.
			kind:   string,
			label:  string,
		}
		throttle_cases := []Throttle_Case {
			{what = "upstream: an h2 DoH upstream answering 429 parks for its Retry-After", alpn = {"h2"}, status = 429, kind = "Throttled", label = "throttled"},
			{what = "upstream: an http/1.1 DoH upstream answering 503 parks for its Retry-After", alpn = {"http/1.1"}, status = 503, kind = "Unavailable", label = "unavailable"},
		}
		for tc, i in throttle_cases {
			upstream_port := next_port(r)
			mock := doh2_mock_make(upstream_port, "/dns-query", payload)
			mock.status = tc.status
			mock.retry_after = "120"
			if !doh2_mock_start(mock, r.cert_file, r.key_file, tc.alpn) {
				skip_case(r, tc.what, "cannot start the mock")
				doh2_mock_stop(mock)
				continue
			}
			udp_port := next_port(r)
			metrics_port := next_port(r)
			config := base_config(
				udp_port,
				fmt.tprintf("[%s]", doh_upstream("busy", upstream_port)),
				timeout = "5s",
				upstream_extra = "  attempts: 1",
				extra = fmt.tprintf("metrics: {{ enabled: true, address: 127.0.0.1, port: %d }}", metrics_port),
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, tc.what)
				{
					for q in 0 ..< 3 {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(0x5270 + 4 * i + q)))
						if check(r, res.ok, "query %d: no response", q) {
							h := parse_header(r, res.wire)
							check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode")
						}
					}
					check(
						r,
						wait_for_log(
							&srv,
							fmt.tprintf("upstream busy (HTTPS 127.0.0.1): %s, HTTP %d, Retry-After 2m0s, pausing it for 2m0s", tc.kind, tc.status),
							3 * time.Second,
						),
						"the refusal's line did not name the status, the Retry-After and the pause",
					)
					// Asked once: the refusal parked it, and `attempts: 1` gives up on a
					// group whose every member is parked rather than asking it again.
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check_eq_int(r, h2_hits + h1_hits, 1, "queries sent to an upstream that asked to be left alone")
					// Every refusal the mock sent, and nothing else: an absent kind is -1.
					page := metrics_page(metrics_port)
					check_eq_int(r, metric_value(page, fmt.tprintf(`elodin_upstream_failure_kind_total{{upstream="busy",error="%s"}}`, tc.label)), h2_hits + h1_hits, "refusals counted under their kind")
					check_eq_int(r, metric_value(page, `elodin_upstream_failure_kind_total{upstream="busy",error="http_error"}`), -1, "http_error failures")
					check_eq_int(r, metric_value(page, `elodin_upstream_up{upstream="busy"}`), 0, "up")
				}
				end_case(r)
				stop_server(&srv)
			}
			doh2_mock_stop(mock)
		}
	}

	// --- a DoH reply's Age is taken off its TTLs (RFC 8484 section 5.1) ---
	{
		age_payload := age_answer()
		defer delete(age_payload)
		Age_Case :: struct {
			what: string,
			alpn: []string,
		}
		age_cases := []Age_Case {
			{what = "upstream: an h2 DoH reply's Age is taken off its TTLs, forwarded and cached", alpn = {"h2"}},
			{what = "upstream: an http/1.1 DoH reply's Age is taken off its TTLs, forwarded and cached", alpn = {"http/1.1"}},
		}
		for tc, i in age_cases {
			upstream_port := next_port(r)
			mock := doh2_mock_make(upstream_port, "/dns-query", age_payload)
			// A literal: the mock's threads read it after `end_case` frees the
			// temporary allocator.
			mock.age = AGE_HEADER
			if age_payload == nil || !doh2_mock_start(mock, r.cert_file, r.key_file, tc.alpn) {
				skip_case(r, tc.what, "cannot start the mock")
				doh2_mock_stop(mock)
				continue
			}
			udp_port := next_port(r)
			config := base_config(udp_port, fmt.tprintf("[%s]", doh_upstream("aged", upstream_port)), timeout = "5s", cache = "{ enabled: true }")
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, tc.what)
				want := u32(AGE_TTL - AGE_SECONDS)
				for q in 0 ..< 2 {
					res := query_udp(udp_port, build_query(AGE_QNAME, u16(dns.Type.A), id = u16(0x5290 + 2 * i + q)))
					if !check(r, res.ok, "query %d: no response", q) {
						continue
					}
					msg, decoded := decode_reply(r, res.wire)
					if !decoded || !check(r, len(msg.answer) == 1, "query %d: %d answers", q, len(msg.answer)) {
						continue
					}
					// A cache hit counts down from there by the seconds it was held.
					ttl := msg.answer[0].ttl
					check(r, ttl <= want && ttl + 5 >= want, "query %d: TTL %d, want %d (%d less the Age %d)", q, ttl, want, AGE_TTL, AGE_SECONDS)
				}
				h2_hits, h1_hits := doh2_mock_counts(mock)
				check_eq_int(r, h2_hits + h1_hits, 1, "upstream queries")
				end_case(r)
				stop_server(&srv)
			}
			doh2_mock_stop(mock)
		}
	}

	// --- a mock that cannot bind its port can still be stopped ---
	/*
	Another run on the box holding the port is how a parity scenario's mock
	fails to start, and the scenario stops every mock it made, started or not.
	So a failed start keeps no handle it has already freed or closed: the stop
	would free the TLS context a second time, or close a number that may by
	then be another socket.
	*/
	{
		port := next_port(r)
		held, herr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
		// Both held from the start, so another run taking either is a skip
		// here rather than a failure partway through the case.
		held_udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, port)
		if herr != nil || uerr != nil {
			if held_udp != 0 {
				net.close(held_udp)
			}
			if herr == nil {
				net.close(held)
			}
			skip_case(r, "harness: a mock that cannot bind its port can still be stopped", "cannot hold the port")
		} else {
			start_case(r, "harness: a mock that cannot bind its port can still be stopped")
			mock := doh2_mock_make(port, "/dns-query", payload)
			check(r, !doh2_mock_start(mock, r.cert_file, r.key_file), "the doh mock started on a port already held")
			check(r, mock.tls_ctx == nil, "the failed start kept a TLS context it had freed")
			doh2_mock_stop(mock)
			dot := mock_make("held", port)
			check(r, !mock_start(dot, r.cert_file, r.key_file), "the dot mock started on a port already held")
			check(r, dot.tls_ctx == nil, "the failed start kept a TLS context a caller that skips the stop leaks")
			mock_stop(dot)
			// With the UDP port held, the bind fails first, and the socket it could
			// not bind is closed rather than left open.
			before, bok := open_descriptor_count()
			check(r, bok, "cannot count the open descriptors")
			udp_only := mock_make("held", port)
			check(r, !mock_start(udp_only), "the mock started on a UDP port already held")
			mock_stop(udp_only)
			after, aok := open_descriptor_count()
			check(r, aok && after == before, "the failed UDP bind left its socket open")
			// With the UDP port free, the plain mock binds it and then fails on TCP,
			// closing the UDP socket it already had.
			net.close(held_udp)
			plain := mock_make("held", port)
			check(r, !mock_start(plain), "the mock started on a port already held")
			check(r, plain.udp_socket == 0, "the failed start kept a UDP socket it had closed")
			mock_stop(plain)
			end_case(r)
			net.close(held)
		}
	}

	delete(payload)
}

@(private = "file")
AGE_QNAME :: "age.example."

@(private = "file")
AGE_TTL :: u32(600)

@(private = "file")
AGE_SECONDS :: u32(250)

@(private = "file")
AGE_HEADER :: "250"

// An answer to `AGE_QNAME` A at TTL `AGE_TTL`.
@(private = "file")
age_answer :: proc() -> []u8 {
	m := dns.Message {
		question = []dns.Question{{name = AGE_QNAME, type = .A, class = .IN}},
		answer   = []dns.Record{{name = AGE_QNAME, type = .A, class = .IN, ttl = AGE_TTL, data = dns.Rdata_A{addr = {10, 9, 9, 9}}}},
	}
	m.flags.qr = true
	m.flags.rd = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, context.allocator)
	if err != .None {
		return nil
	}
	return wire
}
