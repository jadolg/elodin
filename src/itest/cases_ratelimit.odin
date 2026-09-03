package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
Response rate limiting, against the running binary.

A UDP query carries no proof of where it came from, so the answer goes wherever
the source address said. That is what makes an open resolver an amplifier: a
small spoofed query buys the sender a large response aimed at somebody else. The
bound on it is a budget per destination prefix, and the two runs below are the
same flood against a server with that budget and against one without.

Then the same limit over TCP, where amplification is not what is being bounded - a
handshake settled where the client is - but the work behind an answer is, and a
client pipelining down one connection reaches it as fast as the socket allows.

The last case is the line between the two: a prefix's datagrams and its connections
are charged to separate budgets, so a spoofed flood cannot close the connections of
the clients who live at the address it is naming. See the note at the top of
`src/server/ratelimit.odin`, which is where that decision is argued and where the
one-shared-budget version it replaced is written down.
*/

// `tcp_port` of 0 leaves the stream listener off, which is what every case that
// is about datagrams wants: a listener nothing connects to would only be a port
// for the suite to collide on.
@(private = "file")
config_rate_limit :: proc(
	udp_port, upstream_port: int,
	limit: string,
	tcp_port := 0,
	// `::` for the case that needs both families on one port; loopback otherwise,
	// so the rest of the suite binds no more than it is asking about.
	udp_address := "127.0.0.1",
) -> string {
	tcp := "{ enabled: false }"
	if tcp_port > 0 {
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, tcp_port)
	}
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "%s", port: %d }}
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
		udp_address,
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

			/*
			At most every second, and bounded by a budget rather than by the size
			of the flood: the truncated answers come out of a pool of their own at
			an eighth of the rate (`RRL_SLIP_SHARE`), so this flood of ten times
			the budget draws a handful of them and not the eighty-odd that one per
			two over-limit datagrams would be. That is the whole of what makes
			`responses_per_second` a description of what this server emits - see
			`bench/results/2026-09-03-rate-limit-bystander.md` for what it emitted
			without it.

			The ceiling is over-allowed on purpose: the pool's burst plus twice
			what the drain can refill, so the case fails on the uncharged
			behaviour and not on how long a loaded machine took to read its
			answers.
			*/
			SLIP_RATE :: RATE / 8
			slip_ceiling := SLIP_RATE * 2 + SLIP_RATE * 4
			check(
				r,
				res.truncated <= slip_ceiling,
				"%d of %d queries came back truncated, past the %d the slip's own budget allows",
				res.truncated,
				QUERIES,
				slip_ceiling,
			)
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
			/*
			And the answers that did come back were not taken away again. The
			connection is cut off with the rest of the pipeline still unread, and
			closing a socket in that state sends an RST, which has this client's
			kernel discard whatever of those answers it had not read yet - so the
			server drains before it closes. See `stream_linger`; `reset` is what
			says which kind of ending arrived.
			*/
			check(r, !limited.reset, "the connection was reset, so answers already sent were lost")
		}
	}
	end_case(r)

	/*
	A datagram flood does not close the prefix's connections.

	The budget is keyed on the query's source address, and on a datagram the sender
	writes that field. So when one budget served both transports, anybody able to
	send UDP could empty any prefix's budget - and every genuine TCP, DoT or DoH
	connection from that prefix then had its first query refused and its connection
	closed. This is that case from the outside: the datagram budget is spent dry and
	a TCP client at the same address asks anyway.

	One response a second, which is what makes the case say something rather than
	measure a refill. A shared budget stays empty for a whole second after the
	flood, and the TCP query lands well inside it; two budgets and the connection is
	answered out of its own, which the flood never touched.

	The UDP result is checked first, because what follows means nothing if the flood
	did not arrive: two hundred datagrams answered a handful of times is the budget
	having been spent.
	*/
	start_case(r, "rate limit: a datagram flood does not close the prefix's connections")
	{
		udp_port := next_port(r)
		tcp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_rate_limit(
					udp_port,
					upstream_port,
					"enabled: true, responses_per_second: 1, slip: 2",
					tcp_port,
				),
				udp_port = udp_port,
				tcp_port = tcp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)

			// A short drain, so the query below arrives while a shared budget would
			// still have been empty.
			res := udp_flood(udp_port, query, QUERIES, 250 * time.Millisecond)
			full := res.answered - res.truncated
			check(
				r,
				full <= 4,
				"%d full answers to %d datagrams at one a second, so the budget was not spent",
				full,
				QUERIES,
			)

			answer := query_tcp(tcp_port, query)
			defer delete(answer.wire)
			check(
				r,
				answer.ok,
				"a TCP query was refused after a datagram flood spent the prefix's UDP budget",
			)
		}
	}
	end_case(r)

	/*
	Both families of client on one wildcard listener, each with a budget of its own.

	An IPv4 client reaching a listener bound to `::` arrives as `::ffff:a.b.c.d`,
	which is zeroes in the four groups an IPv6 source is keyed on - so keyed as
	IPv6 it landed in the `::/64` bucket, the same one `::1` lands in, and the
	whole IPv4 side of the listener shared a budget with it. This is that from the
	outside, and it is the case that needs no spoofing to show: two real clients,
	two real families, one port, and the kernel filling in the source addresses.

	One response a second, for the reason the case above gives: a shared bucket
	stays empty for a whole second after the flood, so the IPv6 query landing
	microseconds later cannot be answered out of a refill. `wildcard_flood` sends
	it before draining anything, which is what puts it there.

	The IPv4 result is checked first: two hundred datagrams answered a handful of
	times is the flood having arrived and been cut to the budget, and without that
	the IPv6 answer below would only be saying the limiter was never reached.
	*/
	if !ipv6_loopback_available() {
		skip_case(r, "rate limit: a `::` listener tells the families apart", "no IPv6 loopback on this machine")
	} else {
		start_case(r, "rate limit: a `::` listener tells the families apart")
		{
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = config_rate_limit(
						udp_port,
						upstream_port,
						"enabled: true, responses_per_second: 1, slip: 0",
						udp_address = "::",
					),
					udp_port = udp_port,
				},
			)
			if check(r, ok, "server did not start") {
				defer stop_server(&srv)

				res := wildcard_flood(udp_port, query, QUERIES)
				check(r, res.v6_sent, "the IPv6 query did not go out, so nothing below was tested")
				check(
					r,
					res.v4_answered <= 4,
					"%d full answers to %d datagrams at one a second, so the budget was not spent",
					res.v4_answered,
					QUERIES,
				)
				check(
					r,
					res.v6_answered,
					"an IPv4 flood on a `::` listener spent the IPv6 client's budget: it got no answer at all",
				)
			}
		}
		end_case(r)
	}
}
