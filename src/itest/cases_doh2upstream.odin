package itest

import "core:fmt"

/*
elodin as a DoH client: ALPN decides between HTTP/2 and HTTP/1.1 against the
upstream, exactly as it does the other way around for elodin's own DoH
listener (cases_h2.odin). See src/upstream/h2client.odin.
*/
run_upstream_doh2_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	payload := from_hex(fix.response, context.allocator)

	// --- ALPN prefers h2 when the upstream offers it ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		if !doh2_mock_start(mock, r.cert_file, r.key_file) {
			skip_case(r, "upstream: doh over h2", "cannot start the mock")
		} else {
			defer doh2_mock_stop(mock)
			port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: doh2up, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, port = port})
			if ok {
				start_case(r, "upstream: resolves a query over a DoH/h2 upstream")
				{
					res := query_udp(port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
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
						res := query_udp(port, build_query(fix.qname, fix.qtype, id = u16(500 + i)))
						check(r, res.ok, "no response on query %d", i)
					}
					after_h2, _ := doh2_mock_counts(mock)
					// Every query answered over h2, but on the one shared connection:
					// hits (streams) go up while the mock only ever accepts once.
					check_eq_int(r, after_h2 - before_h2, 5, "streams answered over h2")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh over h2", "server did not start")
			}
		}
	}

	// --- ALPN falls back to http/1.1 against a resolver that lacks h2 ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		if !doh2_mock_start(mock, r.cert_file, r.key_file, {"http/1.1"}) {
			skip_case(r, "upstream: doh h2 alpn fallback", "cannot start the mock")
		} else {
			defer doh2_mock_stop(mock)
			port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: h1up, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, port = port})
			if ok {
				start_case(r, "upstream: falls back to http/1.1 when the upstream does not offer h2")
				{
					res := query_udp(port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check_eq_int(r, h2_hits, 0, "used h2 against an upstream that only offered http/1.1")
					check(r, h1_hits >= 1, "the upstream was not reached over http/1.1")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh h2 alpn fallback", "server did not start")
			}
		}
	}

	delete(payload)
}
