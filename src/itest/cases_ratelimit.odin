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
*/

@(private = "file")
config_rate_limit :: proc(port, upstream_port: int, limit: string) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
server:
  rate_limit: {{ %s }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: true, max_entries: 100 }}
blocking: {{ enabled: false }}
`,
		port,
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
		port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_rate_limit(port, upstream_port, "enabled: false"), port = port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := udp_flood(port, query, QUERIES)
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
		port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 2", RATE),
				),
				port = port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := udp_flood(port, query, QUERIES)

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
		port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					port,
					upstream_port,
					fmt.tprintf("enabled: true, responses_per_second: %d, slip: 2", RATE),
				),
				port = port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			limited := udp_flood(port, query, QUERIES)

			port2 := next_port(r)
			srv2, ok2 := start_server(
				r,
				Server_Options {
					config = config_rate_limit(port2, upstream_port, "enabled: false"),
					port = port2,
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
}
