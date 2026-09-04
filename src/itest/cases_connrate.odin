package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
How fast one client may open connections, against the running binary.

The other half of `cases_conns.odin`. That file is about *occupancy* - how many of
`server.max_connections` one client may hold at once - and the gap it leaves is
what a client that holds nothing costs. Such a client dials, completes a TLS
handshake and hangs up: it asks no question, so neither response budget sees it,
and it holds one slot for the length of a handshake, so a table of 512 with a
share of 256 is never reached. Measured, that was 6,922 handshakes a second and
1.4 of four cores with `conn_refused` and `elodin_rate_limited_total` both at zero
(`bench/results/2026-09-03-handshake-floods.md`).

So opening a connection is charged to the prefix's own budget, alongside the
datagrams and the queries - see `Rate_Class` in `src/server/ratelimit.odin`. The
two runs below are the same burst of connections from one client against a server
with the limiter on and against one with it off, which is the shape of the finding
and the shape of the fix.

`responses_per_second` is pinned low so the burst reaches the budget in the time a
test can spend: at 4/s a prefix banks 8 connections, which 24 dials go through
several times over. What the case asserts is the counter rather than a division of
24 into served and refused, because the budget refills while the dials are going
out and the split depends on how fast the runner is.

Every client here is 127.0.0.1, so all of them are one prefix - the same
limitation `cases_conns.odin` has and for the same reason. That a *different*
prefix keeps its own arrivals is asserted in `src/server/ratelimit_test.odin`,
which can pick source addresses freely.
*/

@(private = "file")
config_conn_rate :: proc(udp_port, tcp_port, metrics_port, upstream_port: int, limiter: string) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
server:
  # A table far larger than the burst below, so nothing here is the connection
  # table filling up: a refusal has to be the arrival budget or the case proves
  # the wrong thing. Same for the share.
  max_connections: 256
  max_connections_per_prefix: 256
  rate_limit: {{ %s }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
metrics: {{ enabled: true, address: "127.0.0.1", port: %d }}
`,
		udp_port,
		tcp_port,
		limiter,
		upstream_port,
		metrics_port,
	)
}

// 24 dials against a prefix that banks 8 and accrues 4 a second: enough to be
// refused several times over however fast the runner gets through them.
@(private = "file")
CONN_RATE :: 4

@(private = "file")
DIALS :: 24

run_connection_rate_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("connrate", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 12})
	if !mock_start(mock) {
		skip_case(r, "connection rate", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	query := build_query("dialled.example.", u16(dns.Type.A), id = 1, allocator = context.allocator)
	defer delete(query)

	/*
	With the limiter off, one client is served every connection it opens.

	The shape of the finding rather than a feature: 24 connections in as many
	milliseconds from one source, every one accepted and given a thread, and no
	counter in this server moving for any of them. `rate_limit.enabled: false` is
	also what an operator who wants that back asks for, so the row is worth
	keeping green as well as worth reading.
	*/
	start_case(r, "connection rate: with the limiter off, every connection a client opens is served")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_conn_rate(udp_port, tcp_port, metrics_port, upstream_port, "enabled: false"),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "the unlimited server did not start") {
			defer stop_server(&srv)
			answered := dial_and_query(tcp_port, query, DIALS)
			check_eq_int(r, answered, DIALS, "connections answered with the limiter off")
			check_eq_int(r, conn_counters(metrics_port).rate_limited, 0, "connections the arrival budget refused")
		}
	}
	end_case(r)

	/*
	With the limiter on, the burst runs into the prefix's budget.

	The counter is what says a refusal happened rather than an answer being lost,
	and it is the counter the finding is about: `conn_refused` read zero right
	through a handshake flood, so a bound with nothing publishing it would leave
	an operator inferring this from latency complaints.

	`answered >= 1` as well, because a budget is a budget and not a wall: a
	client is served up to it. A row where nothing at all got through would be
	this server refusing a client it has room for.
	*/
	start_case(r, "connection rate: a client opening connections past its budget is refused and counted")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_conn_rate(
					udp_port,
					tcp_port,
					metrics_port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 0", CONN_RATE),
				),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "the limited server did not start") {
			defer stop_server(&srv)
			answered := dial_and_query(tcp_port, query, DIALS)
			check(r, answered >= 1, "a client was refused every one of %d connections", DIALS)
			check(r, answered < DIALS, "%d of %d connections were served, so the budget never bit", answered, DIALS)
			/*
			Every dial that went unanswered was refused by the arrival budget and
			by nothing else. A connection the table turned away, or an answer lost
			to a timeout, would leave this short - and a query refused by the
			*query* budget after its connection was accepted would too, which is
			the confusion the two counters exist to keep apart.
			*/
			counters := conn_counters(metrics_port)
			check_eq_int(r, counters.rate_limited, DIALS - answered, "connections the arrival budget refused")
			check_eq_int(r, counters.refused, 0, "connections refused for want of a slot")
			/*
			And the operator is told which setting refused it, once, by name.

			Waited for rather than read once: `conn_rate_check` charges the
			counter scraped above and only then hands `report_conn_rate_limit`
			the line, so a scrape that has seen the refusal is no ordering at all
			on the log file - see `wait_for_log`.

			The needle carries the words around the setting rather than the
			setting alone, because the setting alone is not this line:
			`report_rate_limited` names it too, for a *query* the budget
			refused. That one is debug-only and this case runs at info, so the
			short needle would pass today - and pass for the wrong reason the
			moment either of those changes, which is exactly the confusion the
			assertion above this one exists to rule out.
			*/
			check(
				r,
				wait_for_log(
					&srv,
					"is opening them faster than server.rate_limit.responses_per_second",
					5 * time.Second,
				),
				"the refusal never named the setting behind it; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)
}

/*
`n` connections, one query each, dial and close - which is what a client arriving
for every lookup does, and the cheapest way to reach the arrival budget from a
test.

Returns how many were answered. A connection the server closed on accept comes
back as a query that did not complete, which is what a refused client sees: there
is nothing to write a reason on.
*/
@(private = "file")
dial_and_query :: proc(tcp_port: int, query: []u8, n: int) -> int {
	answered := 0
	for _ in 0 ..< n {
		if query_tcp(tcp_port, query, context.temp_allocator).ok {
			answered += 1
		}
	}
	return answered
}

/*
The two connection counters, read off one scrape.

One page rather than one each, so the pair an assertion compares was taken at the
same instant and the case pays a single round trip.

`metric_value` answers -1 for a series that is not on the page - the endpoint
never came up, or the name changed - and that is passed through rather than
clamped to 0. Both rows above assert a zero, and a missing series read as a zero
is exactly the reading that would make those assertions pass for the wrong
reason: the limiter-off row is the only thing here that would notice
`elodin_connections_rate_limited_total` going away, and clamped it would go on
passing after the series was gone.
*/
@(private = "file")
Conn_Counters :: struct {
	rate_limited: int,
	refused:      int,
}

@(private = "file")
conn_counters :: proc(metrics_port: int) -> Conn_Counters {
	page := ""
	if wait_http(metrics_port, "/metrics") {
		page = string(http_request(metrics_port, "GET", "/metrics", context.temp_allocator).body)
	}
	return {
		rate_limited = metric_value(page, "elodin_connections_rate_limited_total"),
		refused = metric_value(page, "elodin_connections_refused_total"),
	}
}
