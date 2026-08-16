package itest

import "core:fmt"
import "elodin:dns"

/*
Response rate limiting, against the running binary.

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address said. That is what makes an open resolver an amplifier: a
small spoofed query buys the sender a large response aimed at somebody else. The
bound on it is a budget per destination prefix, and the two runs below are the
same flood against a server with that budget and against one without.

The last case is the same budget over TCP, where amplification is not what is
being bounded - a handshake settled where the client is - but the work behind an
answer is, and a client pipelining down one connection reaches it as fast as the
socket allows.
*/

// `tcp_port` of 0 leaves the stream listener off, which is what every case that
// is about datagrams wants: a listener nothing connects to would only be a port
// for the suite to collide on.
@(private = "file")
config_rate_limit :: proc(udp_port, upstream_port: int, limit: string, tcp_port := 0) -> string {
	tcp := "{ enabled: false }"
	if tcp_port > 0 {
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, tcp_port)
	}
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: %s
server:
  # Pinned rather than derived from whatever machine the suite is running on:
  # the flood below has to fit inside max_pending, which is workers * 8, for
  # the unlimited run to be the baseline it claims to be. Otherwise the case
  # measures this machine's shed threshold instead of the limiter.
  workers: 32
  upstream_workers: 8
  rate_limit: {{ %s }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: true, max_entries: 100 }}
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp,
		limit,
		upstream_port,
	)
}

run_rate_limit_cases :: proc(r: ^Runner) {
	QUERIES :: 200
	// Small enough that the burst is reached in a fraction of the run, and the
	// arithmetic below stays honest about what refills during it.
	RATE :: 20
	BURST :: RATE * 2

	upstream_port := next_port(r)
	mock := mock_make("ratelimit", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "rate limit", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	query := build_query("flood.example.", u16(dns.Type.A), id = 1, allocator = context.allocator)
	defer delete(query)

	/*
	Without a limit, every one of them is answered.

	This is the shape of the vulnerability rather than a feature being checked:
	one source, two hundred queries, two hundred answers, and nothing in the
	server that would have stopped the two hundredth from being aimed at a
	stranger.
	*/
	start_case(r, "rate limit: disabled, a flood from one source is answered in full")
	{
		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_rate_limit(udp_port, upstream_port, "enabled: false"), udp_port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := udp_flood(udp_port, query, QUERIES)
			check(
				r,
				res.answered >= QUERIES - 5,
				"only %d of %d answered with the limiter off, so the flood did not arrive",
				res.answered,
				QUERIES,
			)
			check_eq_int(r, res.truncated, 0, "truncated answers with the limiter off")
		}
	}
	end_case(r)

	start_case(r, "rate limit: a flood from one prefix is cut to the budget")
	{
		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					udp_port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 2", RATE),
				),
				udp_port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := udp_flood(udp_port, query, QUERIES)

			full := res.answered - res.truncated
			// The burst, plus whatever the second or so of draining refilled.
			ceiling := BURST + RATE * 2
			check(
				r,
				full <= ceiling,
				"%d full answers to %d queries, past the %d the budget allows",
				full,
				QUERIES,
				ceiling,
			)
			check(r, full > 0, "the budget answered nothing at all")

			// Every second query over the budget comes back truncated, which is
			// what lets a real client behind a busy NAT retry over TCP.
			check(r, res.truncated > 0, "nothing came back truncated, so a legitimate client would just stall")
			check(
				r,
				res.answered < QUERIES,
				"all %d were answered, so nothing was withheld",
				QUERIES,
			)
		}
	}
	end_case(r)

	/*
	The amplification the whole thing is about, measured rather than asserted in
	the abstract: what one flood costs the party whose address was on it.
	*/
	start_case(r, "rate limit: the bytes a flood can aim at one address are bounded")
	{
		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					udp_port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 2", RATE),
				),
				udp_port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			limited := udp_flood(udp_port, query, QUERIES)

			port2 := next_port(r)
			srv2, ok2 := start_server(
				r,
				Server_Options {
					config = config_rate_limit(port2, upstream_port, "enabled: false"),
					udp_port = port2,
				},
			)
			if check(r, ok2, "the unlimited server did not start") {
				defer stop_server(&srv2)
				unlimited := udp_flood(port2, query, QUERIES)
				check(
					r,
					limited.bytes * 2 < unlimited.bytes,
					"the same flood drew %d bytes limited against %d unlimited",
					limited.bytes,
					unlimited.bytes,
				)
			}
		}
	}
	end_case(r)

	/*
	The same flood down one TCP connection, which the limiter used not to see at
	all.

	`server.max_connections` bounds how many clients are here, not how fast one of
	them asks, so a client that pipelines - which RFC 7766 6.2.1.1 allows - had the
	upstream round trips and the cache churn of an unmetered flood for the price of
	one connection.

	Both runs are here rather than only the limited one, because the ceiling below is
	a bound only if the flood arrives: a run that answered forty queries because forty
	was all that got through the socket would pass it having tested nothing. The
	unlimited server answers all two hundred on the one connection.

	Nothing comes back truncated. There is nothing to truncate on a stream - the TC
	bit tells a client to ask again over TCP and it is already there - so the budget
	running out shows up as the connection ending, which is what stops the read.
	*/
	start_case(r, "rate limit: a flood pipelined over TCP is cut to the budget")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(udp_port, upstream_port, "enabled: false", tcp_port),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "the unlimited server did not start") {
			defer stop_server(&srv)
			unlimited := tcp_pipeline_flood(tcp_port, query, QUERIES)
			check(
				r,
				unlimited.answered >= QUERIES - 5,
				"only %d of %d answered with the limiter off, so the pipeline did not arrive",
				unlimited.answered,
				QUERIES,
			)
		}

		limited_udp_port := next_port(r)
		limited_tcp_port := next_port(r)
		srv2, ok2 := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					limited_udp_port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 2", RATE),
					limited_tcp_port,
				),
				udp_port = limited_udp_port,
				tcp_port = limited_tcp_port,
			},
		)
		if check(r, ok2, "the limited server did not start") {
			defer stop_server(&srv2)
			limited := tcp_pipeline_flood(limited_tcp_port, query, QUERIES)

			// The burst, plus whatever the second or so of draining refilled. The
			// readiness probes spend a little of it first, which only tightens this.
			ceiling := BURST + RATE * 2
			check(
				r,
				limited.answered <= ceiling,
				"%d answers to %d pipelined queries, past the %d the budget allows",
				limited.answered,
				QUERIES,
				ceiling,
			)
			check(r, limited.answered > 0, "the budget answered nothing at all")
			check_eq_int(r, limited.truncated, 0, "truncated answers on a connection")
		}
	}
	end_case(r)
}
