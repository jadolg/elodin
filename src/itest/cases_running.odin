package itest

import "core:fmt"
import "core:net"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
Waits overlap on one event loop, against the running binary (#547).

Every query runs on a fiber, and a fiber waiting on the network or on another
query parks while the loop runs the others. What a client can see of that is
that one loop - one thread - still overlaps queries that each wait on a slow
upstream, and the cases here run a single loop while something waits in each of
the places a query waits: an upstream round trip, a coalesced follower, a DoH
reply parked on the client's flow-control window, its racers, a stale refresh. A
wait that blocked the loop thread instead of parking would show as the other
queries arriving one round trip, or one write timeout, late.

The upstream answers after `DELAY`, and each bound sits half a delay past one
round trip: what a blocked wait costs is a whole round trip more, at least.
*/

@(private = "file")
DELAY :: 600 * time.Millisecond

@(private = "file")
WITHIN :: DELAY + DELAY / 2

@(private = "file")
config_running :: proc(r: ^Runner, udp_port, doh_port, upstream_port: int, server: string, readers := 1) -> string {
	doh := "doh: { enabled: false }"
	if doh_port > 0 {
		doh = fmt.tprintf(
			`doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
			doh_port,
			r.cert_file,
			r.key_file,
		)
	}
	return fmt.tprintf(
		`log: {{ level: info }}
server:
%s
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d, readers: %d }}
  tcp: {{ enabled: false }}
  %s
upstream:
  timeout: 5s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		server,
		udp_port,
		readers,
		doh,
		upstream_port,
	)
}

/*
Send every query at once, each from a socket of its own, and wait for them all.
How many were answered, and how long the last one took.
*/
@(private = "file")
udp_burst :: proc(udp_port: int, queries: [][]u8) -> (answered: int, elapsed: time.Duration) {
	sockets := make([]net.UDP_Socket, len(queries), context.temp_allocator)
	opened := make([]bool, len(queries), context.temp_allocator)
	defer for s, i in sockets {
		if opened[i] {
			net.close(s)
		}
	}
	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = udp_port,
	}
	start := time.tick_now()
	for q, i in queries {
		s, err := net.make_unbound_udp_socket(.IP4)
		if err != nil {
			continue
		}
		sockets[i] = s
		opened[i] = true
		_, _ = net.send_udp(s, q, endpoint)
	}
	deadline := time.tick_add(start, CLIENT_TIMEOUT)
	buf := make([]u8, 65535, context.temp_allocator)
	for s, i in sockets {
		if !opened[i] {
			continue
		}
		left := time.tick_diff(time.tick_now(), deadline)
		if left <= 0 {
			break
		}
		_ = net.set_option(s, .Receive_Timeout, left)
		n, _, rerr := net.recv_udp(s, buf)
		if rerr == nil && n >= dns.HEADER_SIZE {
			answered += 1
		}
	}
	return answered, time.tick_since(start)
}

@(private = "file")
burst_queries :: proc(prefix: string, n: int, first_id: u16) -> [][]u8 {
	queries := make([][]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		queries[i] = build_query(
			fmt.tprintf("%s%d.example.", prefix, i),
			u16(dns.Type.A),
			id = first_id + u16(i),
			allocator = context.temp_allocator,
		)
	}
	return queries
}

run_one_loop_cases :: proc(r: ^Runner, cert_ok: bool) {
	upstream_port := next_port(r)
	mock := mock_make("running", upstream_port)
	// No payload: an empty NOERROR for whatever was asked, so every name is
	// its own question and its own round trip.
	mock_delay_all(mock, DELAY, nil)
	if !mock_start(mock) {
		skip_case(r, "one loop", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r) if cert_ok else 0
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_running(
				r,
				udp_port,
				doh_port,
				upstream_port,
				"  client_timeout: 5s\n  rate_limit: { enabled: false }",
			),
			udp_port = udp_port,
			doh_port = doh_port,
			warmup = DELAY,
		},
	)
	if !ok {
		skip_case(r, "one loop", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "one loop: queries waiting on the upstream overlap")
	{
		check(
			r,
			log_contains(&srv, "loops=1"),
			"the sizing line does not report the one loop; log:\n%s",
			read_log(&srv),
		)
		answered, elapsed := udp_burst(udp_port, burst_queries("overlap", 8, 0x5100))
		check_eq_int(r, answered, 8, "queries answered")
		// One at a time would be eight round trips.
		check(
			r,
			elapsed < WITHIN,
			"8 queries against a %v upstream took %v on one loop: the round trips did not overlap",
			DELAY,
			elapsed,
		)
	}
	end_case(r)

	start_case(r, "one loop: a coalesced follower does not hold the loop")
	{
		/*
		One name three times, then four of their own. The first is the leader
		and waits on the upstream; the next two wait on the leader, which is
		the wait under test. Blocking, it keeps the four behind it until the
		leader lands, and they reach the upstream a round trip late.
		*/
		same := build_query("coalesced.example.", u16(dns.Type.A), id = 0x5200, allocator = context.temp_allocator)
		queries := make([dynamic][]u8, context.temp_allocator)
		for _ in 0 ..< 3 {
			append(&queries, same)
		}
		append(&queries, ..burst_queries("beside", 4, 0x5210))
		answered, elapsed := udp_burst(udp_port, queries[:])
		check_eq_int(r, answered, 7, "queries answered")
		check(
			r,
			elapsed < WITHIN,
			"took %v against a %v upstream: the queries behind the followers waited for the leader",
			elapsed,
			DELAY,
		)
	}
	end_case(r)

	if cert_ok {
		start_case(r, "one loop: a DoH reply parked on flow control does not hold the loop")
		{
			// A one-byte window: the reply's first DATA frame carries one byte
			// and the rest waits on credit this client never gives, up to the
			// write timeout (`client_timeout`, 5 s here).
			c, cok := h2_connect(doh_port, H2_Settings{initial_window = 1})
			if check(r, cok, "cannot open an h2 connection") {
				defer h2_close(c)
				q := build_query("parked.example.", u16(dns.Type.A), id = 0x5300, allocator = context.temp_allocator)
				check(r, h2_send_request(c, 1, "POST", "/dns-query", q), "cannot send")
				stalled := false
				deadline := time.tick_add(time.tick_now(), CLIENT_TIMEOUT)
				for time.tick_diff(time.tick_now(), deadline) > 0 {
					if res, found := h2_stream(c, 1); found && res.data_frames >= 1 {
						stalled = true
						break
					}
					if !h2_pump(c) {
						break
					}
				}
				if check(r, stalled, "the reply never started, so nothing is parked on the window") {
					answered, elapsed := udp_burst(udp_port, burst_queries("past-parked", 2, 0x5310))
					check_eq_int(r, answered, 2, "queries answered")
					check(
						r,
						elapsed < WITHIN,
						"took %v against a %v upstream while a DoH reply waited on flow control",
						elapsed,
						DELAY,
					)
				}
			}
		}
		end_case(r)
	}

	/*
	A query under `strategy: race` waits on its racers rather than on a socket,
	and the racers are fibers of the same loop.
	*/
	start_case(r, "one loop: a query waiting on its racers does not hold the loop")
	{
		second_port := next_port(r)
		second := mock_make("running-race", second_port)
		mock_delay_all(second, DELAY, nil)
		if check(r, mock_start(second), "cannot start the second mock upstream") {
			defer mock_stop(second)
			race_port := next_port(r)
			race_config, _ := strings.replace(
				config_running(
					r,
					race_port,
					0,
					upstream_port,
					"  rate_limit: { enabled: false }",
				),
				fmt.tprintf("  servers: [\"127.0.0.1:%d\"]", upstream_port),
				fmt.tprintf(
					"  strategy: race\n  servers: [\"127.0.0.1:%d\", \"127.0.0.1:%d\"]",
					upstream_port,
					second_port,
				),
				1,
				context.temp_allocator,
			)
			rsrv, rok := start_server(r, Server_Options{config = race_config, udp_port = race_port, warmup = DELAY})
			if check(r, rok, "server did not start") {
				defer stop_server(&rsrv)
				answered, elapsed := udp_burst(race_port, burst_queries("raced", 4, 0x5500))
				check_eq_int(r, answered, 4, "queries answered")
				check(
					r,
					elapsed < WITHIN,
					"4 raced queries against %v upstreams took %v on one loop",
					DELAY,
					elapsed,
				)
			}
		}
	}
	end_case(r)

	/*
	A client served from an expired entry waits up to `stale_timeout` for the
	refresh it started, and the refresh runs on this same loop. Blocking, the
	wait would leave the refresh unrun behind the very query waiting for it, and
	the client would get the stale answer at the timer rather than the fresh one
	a round trip in.
	*/
	start_case(r, "one loop: a client waiting on its stale refresh does not hold the loop")
	{
		qname := "stale-slot.example."
		stale_port := next_port(r)
		stale_mock := mock_make("running-stale", stale_port)
		mock_delay_all(stale_mock, 200 * time.Millisecond, make_a_response(qname, {203, 0, 113, 9}, 60, context.allocator))
		if check(r, mock_start(stale_mock), "cannot start the stale mock upstream") {
			defer mock_stop(stale_mock)
			udp := next_port(r)
			stale_config, _ := strings.replace(
				config_running(r, udp, 0, stale_port, "  rate_limit: { enabled: false }"),
				"cache: { enabled: false }",
				"cache: { enabled: true, max_entries: 100, max_ttl: 1, serve_stale: true, stale_timeout: 2s }",
				1,
				context.temp_allocator,
			)
			ssrv, sok := start_server(r, Server_Options{config = stale_config, udp_port = udp, warmup = DELAY})
			if check(r, sok, "server did not start") {
				defer stop_server(&ssrv)
				first := query_udp(udp, build_query(qname, u16(dns.Type.A), id = 0x5600), context.temp_allocator)
				if check(r, first.ok, "no answer to fill the cache") {
					// Past `max_ttl`, which the entry was stored under.
					time.sleep(1300 * time.Millisecond)
					begun := time.tick_now()
					second := query_udp(udp, build_query(qname, u16(dns.Type.A), id = 0x5601), context.temp_allocator)
					waited := time.tick_since(begun)
					check(r, second.ok, "no answer from the expired entry")
					check(
						r,
						waited < time.Second,
						"waited %v for a 200ms refresh: it ran only once the 2s stale timer let the slot go",
						waited,
					)
				}
			}
		}
	}
	end_case(r)

	/*
	What is in flight is not a thread count. One loop, and `max_pending` left to
	the machine, carries a burst of 500 misses at once, all on one thread.

	Read off the upstream rather than a clock: a mock of its own holds every
	reply until all 500 questions are waiting on it, which only a server with all
	of them in flight at once can bring about. One that ran fewer would leave the
	hold unreached and the burst unanswered.
	*/
	start_case(r, "one loop: carries a burst of 500 misses at once")
	{
		derived_mock := mock_make("running-derived", next_port(r))
		mock_delay_all(derived_mock, 0, nil)
		if check(r, mock_start(derived_mock), "cannot start the derived mock upstream") {
			defer mock_stop(derived_mock)
			derived_port := next_port(r)
			dsrv, dok := start_server(
				r,
				Server_Options {
					config = config_running(r, derived_port, 0, derived_mock.port, "  max_pending: 1024\n  rate_limit: { enabled: false }"),
					udp_port = derived_port,
					warmup = DELAY,
				},
			)
			if check(r, dok, "server did not start") {
				defer stop_server(&dsrv)
				mock_hold_until(derived_mock, 500)
				answered, _ := udp_burst(derived_port, burst_queries("derived", 500, 0x5400))
				check(r, mock_held(derived_mock) >= 500, "only %d of 500 misses reached the upstream at once", mock_held(derived_mock))
				check_eq_int(r, answered, 500, "queries answered")
			}
		}
	}
	end_case(r)
}
