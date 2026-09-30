package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
A name asked for near its expiry is refreshed before it expires (issue #468).

Without it the first query after a popular name's entry expires waits a whole
upstream round trip, which a monitoring probe asking at a steady rate sees as a
peak once in every TTL. Unbound's rule: a hit in the last tenth of the entry's
lifetime is answered from the cache, and the entry is refreshed behind it.

A five-second TTL puts the window in the last 500 ms, and `prefetch_min_ttl: 0`
lets an entry that short in. The query at 4.7 seconds lands in the window with
a margin either side. What says the refresh happened is the upstream's count:
one query from the prefetch while the entry is still fresh, then none from a
query past the old expiry, which the renewed entry answers.

Asked once over UDP, which a worker of the shared pool answers, and once over
TCP, which a connection's own thread answers: the refresh runs on the pool
either way, and both have to reach it.
*/
run_prefetch_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("prefetch", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 7}, ttl = 5)
	if !mock_start(mock) {
		skip_case(r, "prefetch", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	tcp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache:
  enabled: true
  max_entries: 100
  prefetch_min_ttl: 0
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp_port,
		upstream_port,
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, tcp_port = tcp_port})
	if !ok {
		skip_case(r, "prefetch", "server did not start")
		return
	}
	defer stop_server(&srv)

	Transport :: enum {
		UDP,
		TCP,
	}
	for transport in Transport {
		qname := fmt.tprintf("prefetch-%v.example.", transport)
		ask := proc(transport: Transport, udp_port, tcp_port: int, qname: string, id: u16) -> Query_Result {
			q := build_query(qname, u16(dns.Type.A), id = id)
			return query_udp(udp_port, q) if transport == .UDP else query_tcp(tcp_port, q)
		}
		start_case(r, fmt.tprintf("prefetch: a %v hit near expiry refreshes the entry behind it", transport))
		{
			mock_reset_counts(mock)
			first := ask(transport, udp_port, tcp_port, qname, 1)
			// Every time below is measured from here, the latest the entry can
			// have been stored, rather than slept end to end: a loaded box that
			// is slow at one step does not push the next past the expiry.
			filled := time.tick_now()
			if !check(r, first.ok, "no response to the query that filled the cache") {
				end_case(r)
				continue
			}
			check_eq_int(r, mock_total(mock), 1, "upstream queries to fill the cache")

			time.sleep(4700 * time.Millisecond - time.tick_since(filled))
			begun := time.tick_now()
			near := ask(transport, udp_port, tcp_port, qname, 2)
			waited := time.tick_since(begun)
			check(r, near.ok, "the hit near expiry went unanswered")
			check(r, waited < 300 * time.Millisecond, "the hit near expiry waited %v", waited)
			// The refresh is behind the client, so it is waited for - up to the
			// old expiry, after which a miss would put the same count on the wire.
			for mock_total(mock) < 2 && time.tick_since(filled) < 5 * time.Second {
				time.sleep(10 * time.Millisecond)
			}
			check_eq_int(r, mock_total(mock), 2, "upstream queries once the prefetch has run")

			// Past the first entry's expiry: only the renewed one can answer.
			time.sleep(5500 * time.Millisecond - time.tick_since(filled))
			after := ask(transport, udp_port, tcp_port, qname, 3)
			check(r, after.ok, "the query past the old expiry went unanswered")
			check_eq_int(r, mock_total(mock), 2, "upstream queries after the old expiry")
		}
		end_case(r)
	}
}
