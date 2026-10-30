package itest

import "core:fmt"
import "core:net"
import "core:time"
import "elodin:dns"

/*
A `udp` upstream's TCP retry turns away what its connection cannot answer in
time, against the running binary (issue #551).

Every truncated answer is asked again on one pipelined connection (RFC 7766
section 6.2.2), so when the answers asked for outrun the answers that
connection carries a second, the queue on it grows past the timeout. A caller
that gives up leaves its answer on the stream, so from there the connection
carries answers nobody reads and nearly every query fails. The mock here is
that connection: its TCP side answers one query at a time, `SERVICE` apart,
and the client asks twice as fast as that.

What shows the excess is turned away rather than queued is the failure kind
that names it. A quick SERVFAIL would not: three timeouts in a row park the one
member, and the quick refusals after that are the cooldown's.
*/

@(private = "file")
SERVICE :: 50 * time.Millisecond
@(private = "file")
PACE :: 25 * time.Millisecond
@(private = "file")
QUERIES :: 80

run_tc_backlog_cases :: proc(r: ^Runner) {
	name :: "upstream: a backed-up TCP retry turns the excess away"
	upstream_port := next_port(r)
	mock := mock_make("backlog", upstream_port)
	// Every name, since the queries are for names of their own: the same name
	// asked again while it is in flight would join it rather than the queue.
	mock_truncate_udp(mock, "", 0, nil, SERVICE)
	if !mock_start(mock) {
		skip_case(r, name, "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	metrics_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 1s
  attempts: 1
  servers:
    - {{ name: slow, type: udp, address: 127.0.0.1, port: %d }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
metrics: {{ enabled: true, address: 127.0.0.1, port: %d }}
`,
		udp_port,
		upstream_port,
		metrics_port,
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, name, "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, name)
	answered := paced_big_queries(udp_port)
	check(r, answered > 0, "nothing was answered")
	backlogged := metric_value(
		string(http_request(metrics_port, "GET", "/metrics", context.temp_allocator).body),
		`elodin_upstream_failure_kind_total{upstream="slow",error="backlogged"}`,
	)
	check(r, backlogged > 0, "no failure was counted as backlogged: %d", backlogged)
	end_case(r)
}

/*
`QUERIES` truncated names, each its own, one every `PACE`, counting the answers
as they come.
*/
@(private = "file")
paced_big_queries :: proc(udp_port: int) -> (answered: int) {
	socket, err := net.make_unbound_udp_socket(.IP4)
	if err != nil {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 5 * time.Millisecond)
	endpoint := net.Endpoint{address = net.IP4_Loopback, port = udp_port}

	sent := 0
	start := time.tick_now()
	buf := make([]u8, 65535, context.temp_allocator)
	// Every reply is in by the last query plus the timeout; the slack is the
	// server's own.
	for time.tick_since(start) < QUERIES * PACE + 2 * time.Second {
		if sent < QUERIES && time.tick_since(start) >= time.Duration(sent) * PACE {
			query := build_query(fmt.tprintf("q%d.backlog.test.", sent), u16(dns.Type.A), id = u16(sent))
			_, _ = net.send_udp(socket, query, endpoint)
			sent += 1
		}
		n, _, rerr := net.recv_udp(socket, buf)
		if rerr != nil || n < dns.HEADER_SIZE {
			continue
		}
		if int(buf[0]) << 8 | int(buf[1]) < QUERIES && dns.Rcode(buf[3] & 0x0f) == .No_Error {
			answered += 1
		}
	}
	return
}
