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
