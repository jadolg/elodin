package itest

import "core:fmt"
import "core:strings"
import "elodin:dns"

/*
How much of the connection table one client may hold, against the running
binary.

`server.max_connections` bounds how many stream connections exist at once for
the whole server, and on its own it says nothing about whose they are. Nothing
else counted them per client either: the response limiter charges *queries*, so
a client that opens connections and asks nothing on them spends no budget at
all, and `client_timeout` reclaiming an idle one after ten seconds is a delay
rather than a limit to somebody willing to open another. So one source could
hold every slot, and the clients who were locked out of the table were locked
out by a configuration that said nothing about it.

`server.max_connections_per_prefix` is the bound, and the two runs below are the
same four connections from one client against a server with it and against one
without. What they show is a share being enforced with the table nowhere near
full - which is the part a total limit cannot do, and the part an operator needs,
since a share reached at the same moment as the total would be no share at all.

The prefix is a /24 here as it is everywhere else in this server (see
`client_prefix`), and every client the suite has is on loopback, so the four
connections are one client whatever port they came from. What cannot be shown
from here is the other half of the property - that a client in *another* prefix
is still served out of what is left - because that needs a source address in a
second /24, which a test client on one machine cannot dial from. The unit tests
in `src/server/conns_test.odin` hold that half, and `bench/cmd/rrlexp`'s
`slowloris` arms measure it under load.
*/

// `metrics_port` is where the counters are read from: what the clients see is
// how many were answered, and what the server says is how many it refused, and
// the case wants both.
@(private = "file")
config_conn_limits :: proc(udp_port, tcp_port, metrics_port, upstream_port, max_conns, per_prefix: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
server:
  max_connections: %d
  max_connections_per_prefix: %d
  # A connection that is refused is closed on accept, and a connection that is
  # served holds its slot until its client goes away. Left at the shipped ten
  # seconds either way; nothing here waits on it.
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
metrics: {{ enabled: true, address: "127.0.0.1", port: %d }}
`,
		udp_port,
		tcp_port,
		max_conns,
		per_prefix,
		upstream_port,
		metrics_port,
	)
}

run_connection_limit_cases :: proc(r: ^Runner) {
	// Four connections against a table of six, so a refusal is never the table
	// running out: two of the six are still free when the third is turned away.
	CONNS :: 4
	TABLE :: 6
	SHARE :: 2

	upstream_port := next_port(r)
	mock := mock_make("connlimit", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 11})
	if !mock_start(mock) {
		skip_case(r, "connection limits", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	query := build_query("held.example.", u16(dns.Type.A), id = 1, allocator = context.allocator)
	defer delete(query)

	/*
	With no share configured, one client is served every connection it opens.

	This is the shape of the finding rather than a feature: four connections held
	open at once from one source, four of the server's slots occupied by it, and
	nothing that would have stopped it taking the other two as well.

	`max_connections_per_prefix` set to the table rather than left out, because
	left out it is derived as half - so the run with no cap has to ask for no cap.
	It is also the configuration an operator running one large NAT would write.
	*/
	start_case(r, "connections: without a share, one client is served every slot it asks for")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_conn_limits(udp_port, tcp_port, metrics_port, upstream_port, TABLE, TABLE),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "the uncapped server did not start") {
			defer stop_server(&srv)
			refused_before := conn_refused_count(metrics_port)
			answered, opened := tcp_hold_and_query(tcp_port, query, CONNS)
			check_eq_int(r, opened, CONNS, "connections the client could open")
			check_eq_int(r, answered, CONNS, "answers on connections held at once with no share configured")
			check_eq_int(
				r,
				conn_refused_count(metrics_port) - refused_before,
				0,
				"connections refused with no share configured",
			)
		}
	}
	end_case(r)

	/*
	With a share, the client is served its share and refused the rest.

	The counter is what says a refusal happened rather than an answer being lost:
	every connection past the share is counted as `conn_refused=`, the same
	counter a full table increments, and the two are told apart in the log line
	underneath. Read as a difference because the readiness probes are connections
	too, and one of them may still have been letting go of its slot.
	*/
	start_case(r, "connections: a client past its share is refused with the table not full")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_conn_limits(udp_port, tcp_port, metrics_port, upstream_port, TABLE, SHARE),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "the capped server did not start") {
			defer stop_server(&srv)
			refused_before := conn_refused_count(metrics_port)
			answered, opened := tcp_hold_and_query(tcp_port, query, CONNS)
			check_eq_int(r, opened, CONNS, "connections the client could open")
			check(
				r,
				answered <= SHARE,
				"%d of %d connections held at once were answered, past the share of %d",
				answered,
				CONNS,
				SHARE,
			)
			// And the share is a share rather than a wall: the client is still
			// served up to it. Anything less than one would be this server
			// refusing a client it has room for.
			check(r, answered >= 1, "a client was refused every connection, share of %d", SHARE)
			// Every connection that went unanswered was refused on purpose. An
			// answer lost to a timeout, or a connection dropped for some other
			// reason, would leave this short.
			check_eq_int(
				r,
				conn_refused_count(metrics_port) - refused_before,
				CONNS - answered,
				"connections refused past the share",
			)
			/*
			The table itself was not the bound, which is the whole claim.

			Read off the server rather than argued from the numbers above: a
			table of six that refused a third connection refused it over the
			share, and the same case against a table of two would prove nothing.
			*/
			page := metrics_page(metrics_port)
			check_eq_int(r, metric_value(page, "elodin_connections_max"), TABLE, "the table the server reports")
			check_eq_int(
				r,
				metric_value(page, "elodin_connections_max_per_prefix"),
				SHARE,
				"the share the server reports",
			)
			// And the operator is told which of the two figures refused it, once,
			// naming the setting that would change the outcome.
			check(
				r,
				log_contains(&srv, "server.max_connections_per_prefix"),
				"the refusal never named the setting behind it; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)

	/*
	The startup line, which is where the derived figure is readable at all.

	The default share is half the table and is worked out at load, so it appears
	in no configuration file: an operator whose client cannot connect has nowhere
	else to find out that one prefix may hold 256 of 512. A server that says
	nothing about it is a limit nobody can see.
	*/
	start_case(r, "connections: the share is reported at startup")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_conn_limits(udp_port, tcp_port, metrics_port, upstream_port, TABLE, SHARE),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			log := read_log(&srv)
			check(
				r,
				strings.contains(log, fmt.tprintf("at most %d at once", TABLE)) &&
				strings.contains(log, fmt.tprintf("may hold %d", SHARE)),
				"the connection limits were not reported at startup; log:\n%s",
				log,
			)
		}
	}
	end_case(r)
}

// The refusals the server has counted so far, or 0 before the endpoint answers -
// which is a baseline the case subtracts and not a figure it reports.
@(private = "file")
conn_refused_count :: proc(metrics_port: int) -> int {
	return max(metric_value(metrics_page(metrics_port), "elodin_connections_refused_total"), 0)
}

@(private = "file")
metrics_page :: proc(metrics_port: int) -> string {
	if !wait_http(metrics_port, "/metrics") {
		return ""
	}
	return string(http_request(metrics_port, "GET", "/metrics", context.temp_allocator).body)
}
