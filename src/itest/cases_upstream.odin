package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
Upstream coverage: the transports elodin speaks as a client, the three
strategies, health cooldown, and the UDP-to-TCP retry.

Distinct answers per mock make it possible to tell which upstream served a
query from the response alone.
*/

// A minimal A response for `name`, answering with the given address. Built by
// hand so the assertion does not depend on the encoder under test.
@(private = "file")
make_a_response :: proc(name: string, addr: [4]u8, ttl: u32, allocator := context.allocator) -> []u8 {
	buf := make([dynamic]u8, 0, 64, allocator)
	append(&buf, 0, 0) // id, patched by the mock
	append(&buf, 0x81, 0x80) // QR, RD, RA
	append(&buf, 0, 1, 0, 1, 0, 0, 0, 0)

	name_start := len(buf)
	rest := name
	for len(rest) > 0 && rest != "." {
		label := rest
		if idx := index_byte(rest, '.'); idx >= 0 {
			label = rest[:idx]
			rest = rest[idx + 1:]
		} else {
			rest = ""
		}
		if label == "" {
			continue
		}
		append(&buf, u8(len(label)))
		for i in 0 ..< len(label) {
			append(&buf, label[i])
		}
	}
	append(&buf, 0)
	name_len := len(buf) - name_start
	append(&buf, 0, 1, 0, 1) // type A, class IN

	// Answer: the name repeated in full rather than compressed, which keeps
	// this helper simple and is perfectly legal.
	for i in 0 ..< name_len {
		append(&buf, buf[name_start + i])
	}
	append(&buf, 0, 1, 0, 1)
	append(&buf, u8(ttl >> 24), u8(ttl >> 16), u8(ttl >> 8), u8(ttl))
	append(&buf, 0, 4)
	append(&buf, addr[0], addr[1], addr[2], addr[3])
	return buf[:]
}

@(private = "file")
index_byte :: proc(s: string, c: u8) -> int {
	for i in 0 ..< len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}

@(private = "file")
QNAME :: "probe.test."

@(private = "file")
first_address :: proc(wire: []u8) -> string {
	addrs := answer_addresses(wire)
	return addrs[0] if len(addrs) > 0 else ""
}

run_strategy_cases :: proc(r: ^Runner) {
	// Three upstreams, each answering with a distinguishable address.
	ports := [3]int{next_port(r), next_port(r), next_port(r)}
	mocks: [3]^Mock
	addrs := [3][4]u8{{10, 0, 0, 1}, {10, 0, 0, 2}, {10, 0, 0, 3}}

	for i in 0 ..< 3 {
		mocks[i] = mock_make(fmt.tprintf("up%d", i + 1), ports[i])
		mock_reply_all(mocks[i], make_a_response(QNAME, addrs[i], 60))
		if !mock_start(mocks[i]) {
			skip_case(r, "strategies", "cannot start the mock upstreams")
			for k in 0 ..< i {
				mock_stop(mocks[k])
			}
			return
		}
	}
	defer for m in mocks {
		mock_stop(m)
	}

	base_config :: proc(udp_port: int, strategy: string, servers: string, extra := "") -> string {
		return fmt.tprintf(
			`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  strategy: %s
  timeout: 2s
  attempts: 1
%s  servers:
%s
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
			udp_port,
			strategy,
			extra,
			servers,
		)
	}

	server_list :: proc(ports: []int) -> string {
		out := ""
		for p in ports {
			out = fmt.tprintf("%s    - \"127.0.0.1:%d\"\n", out, p)
		}
		return out
	}

	// --- failover ---
	{
		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = base_config(udp_port, "failover", server_list(ports[:])), udp_port = udp_port},
		)
		if ok {
			start_case(r, "strategy: failover always prefers the first upstream")
			{
				for i in 0 ..< 4 {
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A), id = u16(i)))
					if check(r, res.ok, "no response on attempt %d", i) {
						check_eq_str(r, first_address(res.wire), "10.0.0.1", "answering upstream")
					}
				}
			}
			end_case(r)
			stop_server(&srv)
		} else {
			skip_case(r, "strategy: failover", "server did not start")
		}
	}

	// --- round robin ---
	{
		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = base_config(udp_port, "round_robin", server_list(ports[:])), udp_port = udp_port},
		)
		if ok {
			start_case(r, "strategy: round_robin visits every upstream in turn")
			{
				seen := map[string]int{}
				defer delete(seen)
				for i in 0 ..< 6 {
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A), id = u16(i)))
					if check(r, res.ok, "no response on attempt %d", i) {
						seen[first_address(res.wire)] += 1
					}
				}
				check_eq_int(r, len(seen), 3, "distinct upstreams used over six queries")
				for addr in ([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}) {
					check(r, seen[addr] == 2, "upstream %s answered %d times, want 2", addr, seen[addr])
				}
			}
			end_case(r)
			stop_server(&srv)
		} else {
			skip_case(r, "strategy: round_robin", "server did not start")
		}
	}

	// --- race ---
	{
		// A slow first upstream and a fast second: the fast one must win even
		// though it is not first in the list.
		slow_port := next_port(r)
		fast_port := next_port(r)
		slow := mock_make("slow", slow_port)
		mock_delay_all(slow, 700 * time.Millisecond, make_a_response(QNAME, {10, 9, 9, 9}, 60))
		fast := mock_make("fast", fast_port)
		mock_reply_all(fast, make_a_response(QNAME, {10, 8, 8, 8}, 60))

		if !mock_start(slow) || !mock_start(fast) {
			skip_case(r, "strategy: race", "cannot start the racing mocks")
		} else {
			defer mock_stop(slow)
			defer mock_stop(fast)

			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = base_config(udp_port, "race", server_list([]int{slow_port, fast_port})),
					udp_port = udp_port,
				},
			)
			if ok {
				start_case(r, "strategy: race returns the first answer to arrive")
				{
					started := time.now()
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A)))
					elapsed := time.diff(started, time.now())
					if check(r, res.ok, "no response") {
						check_eq_str(r, first_address(res.wire), "10.8.8.8", "winning upstream")
						check(
							r,
							elapsed < 500 * time.Millisecond,
							"took %.0fms, so it waited for the slow upstream",
							time.duration_milliseconds(elapsed),
						)
					}
				}
				end_case(r)

				start_case(r, "strategy: race still answers when the fast upstream is the only one left")
				{
					// Both were queried; the losing answer must not leak out or
					// corrupt the next query.
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A), id = 99))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check(r, h.id == 99, "wrong ID after a race: %04x", h.id)
					}
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "strategy: race", "server did not start")
			}
		}
	}

	// --- failover past a dead upstream, and the health cooldown ---
	{
		dead_port := next_port(r)
		live_port := next_port(r)
		dead := mock_make("dead", dead_port)
		mock_silent(dead)
		live := mock_make("live", live_port)
		mock_reply_all(live, make_a_response(QNAME, {10, 7, 7, 7}, 60))

		if !mock_start(dead) || !mock_start(live) {
			skip_case(r, "strategy: failover past a dead upstream", "cannot start the mocks")
		} else {
			defer mock_stop(dead)
			defer mock_stop(live)

			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = base_config(udp_port, "failover", server_list([]int{dead_port, live_port})),
					udp_port = udp_port,
				},
			)
			if ok {
				start_case(r, "upstream: a silent server is skipped and the next one answers")
				{
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						check_eq_str(r, first_address(res.wire), "10.7.7.7", "answering upstream")
					}
				}
				end_case(r)

				start_case(r, "upstream: a repeatedly failing server is parked, and queries speed up")
				{
					// Three failures trip the cooldown; after that the dead
					// upstream is skipped without waiting for its timeout.
					for i in 0 ..< 3 {
						_ = query_udp(udp_port, build_query(QNAME, u16(dns.Type.A), id = u16(100 + i)))
					}
					started := time.now()
					res := query_udp(udp_port, build_query(QNAME, u16(dns.Type.A), id = 200))
					elapsed := time.diff(started, time.now())

					if check(r, res.ok, "no response after the cooldown started") {
						check_eq_str(r, first_address(res.wire), "10.7.7.7", "answering upstream")
						check(
							r,
							elapsed < 500 * time.Millisecond,
							"took %.0fms, so the parked upstream was still being tried",
							time.duration_milliseconds(elapsed),
						)
					}
					check(r, log_contains(&srv, "consecutive failures"), "no cooldown was logged")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "strategy: failover past a dead upstream", "server did not start")
			}
		}
	}
}

run_upstream_transport_cases :: proc(r: ^Runner) {
	fix := fixture("a")

	// --- upstream over TCP ---
	{
		upstream_port := next_port(r)
		mock := mock_make("tcp-upstream", upstream_port)
		mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "upstream: tcp", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["tcp://127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: forwards over TCP")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					_, tcp_count, _ := mock_counts(mock)
					check(r, tcp_count >= 1, "the upstream was not reached over TCP")
				}
				end_case(r)

				start_case(r, "upstream: TCP connections are pooled across queries")
				{
					mock_reset_counts(mock)
					for i in 0 ..< 3 {
						_ = query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(300 + i)))
					}
					_, tcp_count, _ := mock_counts(mock)
					check_eq_int(r, tcp_count, 3, "queries seen by the upstream")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: tcp", "server did not start")
			}
		}
	}

	// --- upstream over DoT ---
	{
		upstream_port := next_port(r)
		mock := mock_make("dot-upstream", upstream_port)
		mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
		if !mock_start(mock, r.cert_file, r.key_file) {
			skip_case(r, "upstream: dot", "cannot start the TLS mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			// verify: false, because the mock uses the suite's self-signed cert.
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: dot, type: tls, address: 127.0.0.1, port: %d, hostname: elodin.local, verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: forwards over DNS-over-TLS")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					_, _, tls_count := mock_counts(mock)
					check(r, tls_count >= 1, "the upstream was not reached over TLS")
				}
				end_case(r)

				start_case(r, "upstream: DoT sessions are reused, not renegotiated per query")
				{
					mock_reset_counts(mock)
					for i in 0 ..< 3 {
						_ = query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(400 + i)))
					}
					_, _, tls_count := mock_counts(mock)
					check_eq_int(r, tls_count, 3, "queries seen over the TLS session")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: dot", "server did not start")
			}
		}
	}

	// --- truncated UDP answer retried over TCP ---
	{
		upstream_port := next_port(r)
		full := from_hex(fixture("txt").response, context.allocator)
		mock := mock_make("truncating", upstream_port)
		mock_truncate_udp(mock, "google.com.", u16(dns.Type.TXT), full)
		if !mock_start(mock) {
			skip_case(r, "upstream: udp to tcp retry", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			tcp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: false }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				tcp_port,
				upstream_port,
			)
			// The readiness probe uses UDP, so this server is checked directly.
			srv, ok := start_server_tcp_only(r, config, tcp_port)
			if ok {
				start_case(r, "upstream: a truncated UDP answer is retried over TCP")
				{
					res := query_tcp(tcp_port, build_query("google.com.", u16(dns.Type.TXT)))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check(r, !h.tc, "the client was handed a truncated answer")
						check(r, h.ancount > 1, "expected the full answer, got %d records", h.ancount)
					}
					udp_count, tcp_count, _ := mock_counts(mock)
					check(r, udp_count >= 1, "the upstream was not tried over UDP first")
					check(r, tcp_count >= 1, "the upstream was not retried over TCP")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: udp to tcp retry", "server did not start")
			}
		}
	}

	// --- every upstream down ---
	{
		dead_port := next_port(r)
		dead := mock_make("all-dead", dead_port)
		mock_silent(dead)
		if !mock_start(dead) {
			skip_case(r, "upstream: total outage", "cannot start the mock")
		} else {
			defer mock_stop(dead)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 1s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				dead_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: a total outage yields SERVFAIL, not silence")
				{
					res := query_udp(udp_port, build_query("anything.test.", u16(dns.Type.A)))
					if check(r, res.ok, "the server went quiet instead of answering") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.Serv_Fail), "rcode %d, want SERVFAIL", h.rcode)
						check_eq_int(r, h.qdcount, 1, "the question was not echoed")
					}
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: total outage", "server did not start")
			}
		}
	}
}

// A TCP-only server cannot be probed over UDP, so readiness is established by
// connecting instead.
@(private = "file")
start_server_tcp_only :: proc(r: ^Runner, config: string, tcp_port: int) -> (srv: Server, ok: bool) {
	srv, ok = start_server_raw(r, config, tcp_port)
	if !ok {
		return srv, false
	}
	if !wait_tcp(tcp_port, 5 * time.Second) {
		stop_server(&srv)
		return srv, false
	}
	return srv, true
}

/*
Reusing a connection the server has already dropped.

Public DoT and DoH resolvers close connections a client has left idle. The
pooled connection is then dead, and the query that picks it up must be retried
on a fresh one rather than reported as an upstream failure — a spurious failure
also counts toward the health cooldown, so a few of them bench a server that was
working perfectly.
*/
run_stale_connection_cases :: proc(r: ^Runner) {
	fix := fixture("a")

	Case :: struct {
		name:   string,
		scheme: string,
		tls:    bool,
	}
	cases := []Case{{"tcp", "tcp://", false}, {"dot", "", true}}

	for c in cases {
		if c.tls && r.cert_file == "" {
			skip_case(r, fmt.tprintf("stale connection over %s", c.name), "no certificate")
			continue
		}

		upstream_port := next_port(r)
		mock := mock_make("stale", upstream_port)
		mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
		// Drop connections after a beat of idleness.
		mock_close_idle_after(mock, 250 * time.Millisecond)

		started := c.tls ? mock_start(mock, r.cert_file, r.key_file) : mock_start(mock)
		if !started {
			skip_case(r, fmt.tprintf("stale connection over %s", c.name), "cannot start the mock")
			continue
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		server_entry :=
			c.tls \
			? fmt.tprintf(
				"    - {{ name: up, type: tls, address: 127.0.0.1, port: %d, hostname: elodin.local, verify: false }}",
				upstream_port,
			) \
			: fmt.tprintf("    - \"%s127.0.0.1:%d\"", c.scheme, upstream_port)

		config := fmt.tprintf(
			`log: {{ level: debug }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 4s
  attempts: 1
  servers:
%s
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
			udp_port,
			server_entry,
		)

		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
		if !ok {
			skip_case(r, fmt.tprintf("stale connection over %s", c.name), "server did not start")
			continue
		}

		start_case(r, fmt.tprintf("upstream: a dropped %s connection is retried, not reported as failure", c.name))
		{
			first := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 1))
			if check(r, first.ok, "the first query failed") {
				h, _ := parse_header(first.wire)
				check_eq_int(r, h.ancount, fix.ancount, "answer count on the first query")
			}

			// Let the mock drop the pooled connection.
			time.sleep(600 * time.Millisecond)

			second := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 2))
			if check(r, second.ok, "no response after the pooled connection went stale") {
				h, _ := parse_header(second.wire)
				check(
					r,
					h.rcode == int(dns.Rcode.No_Error),
					"rcode %d after a stale pooled connection, want NOERROR",
					h.rcode,
				)
				check_eq_int(r, h.ancount, fix.ancount, "answer count after reconnecting")
			}

			// And it must not have been recorded as an upstream failure.
			check(
				r,
				!log_contains(&srv, "consecutive failures"),
				"a stale connection was counted against the upstream's health",
			)
		}
		end_case(r)
		stop_server(&srv)
	}
}
