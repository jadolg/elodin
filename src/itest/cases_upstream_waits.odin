package itest

import "core:fmt"
import "core:net"
import "core:time"
import "elodin:dns"

/*
Issue #623: misses held by a dead upstream fill `server.max_pending`, and then
the readers shed cache hits with them.

`max_pending` is 8, so 6 may wait on an upstream and 2 are kept for answers that
need none. The upstream goes silent after the cache is filled, with a
five-second timeout and one attempt, so every miss sent to it holds its place
for the rest of the cases. What says the places are taken is the mock having
been asked by six of them: a miss reaches the upstream only once it has one.
*/
run_upstream_wait_cases :: proc(r: ^Runner) {
	hit := "hit.waits.example."
	old := "old.waits.example."
	upstream_port := next_port(r)
	mock := mock_make("waits", upstream_port)
	mock_synth(mock, hit, u16(dns.Type.A), {203, 0, 113, 1}, ttl = 300)
	mock_synth(mock, old, u16(dns.Type.A), {203, 0, 113, 2}, ttl = 1)
	if !mock_start(mock) {
		skip_case(r, "upstream waits", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: error }}
server:
  max_pending: 8
  rate_limit: {{ enabled: false }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache:
  enabled: true
  max_entries: 100
  serve_stale: true
  stale_timeout: 3s
blocking: {{ enabled: false }}
`,
		udp_port,
		upstream_port,
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "upstream waits", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "upstream waits: a cache hit is answered while misses hold a silent upstream")
	{
		primed_hit := query_udp(udp_port, build_query(hit, u16(dns.Type.A), id = 1))
		primed_old := query_udp(udp_port, build_query(old, u16(dns.Type.A), id = 2))
		if !check(r, primed_hit.ok && primed_old.ok, "the cache was not filled") {
			end_case(r)
			return
		}
		// Past `old`'s one-second TTL, so `serve_stale` is all that keeps it.
		time.sleep(1200 * time.Millisecond)
		mock_go_silent(mock)
		mock_reset_counts(mock)

		flood, err := net.make_unbound_udp_socket(.IP4)
		if !check(r, err == nil, "no client socket") {
			end_case(r)
			return
		}
		defer net.close(flood)
		to := net.Endpoint{address = net.IP4_Loopback, port = udp_port}
		// Twice what may be in flight: without a bound of their own the misses
		// would take all eight.
		for i in 0 ..< 16 {
			_, _ = net.send_udp(flood, build_query(fmt.tprintf("miss%d.waits.example.", i), u16(dns.Type.A), id = u16(100 + i)), to)
		}
		for start := time.tick_now(); mock_total(mock) < 6 && time.tick_since(start) < 3 * time.Second; {
			time.sleep(10 * time.Millisecond)
		}
		check_eq_int(r, mock_total(mock), 6, "misses that reached the silent upstream")

		res := query_udp(udp_port, build_query(hit, u16(dns.Type.A), id = 3), timeout = time.Second)
		if check(r, res.ok, "the cache hit was shed with the misses") {
			check_eq_str(r, waits_address(r, res.wire), "203.0.113.1", "the cached answer")
		}

		// A miss past the bound is told SERVFAIL now, not held for the timeout.
		begun := time.tick_now()
		miss := query_udp(udp_port, build_query("late.waits.example.", u16(dns.Type.A), id = 4), timeout = time.Second)
		if check(r, miss.ok, "a miss past the bound went unanswered") {
			check(r, dns.peek_rcode(miss.wire) == .Serv_Fail, "a miss past the bound answered %v", dns.peek_rcode(miss.wire))
			check(r, time.tick_since(begun) < 500 * time.Millisecond, "a miss past the bound waited %v", time.tick_since(begun))
		}

		// And an expired entry goes out at once rather than after `stale_timeout`.
		begun = time.tick_now()
		stale := query_udp(udp_port, build_query(old, u16(dns.Type.A), id = 5), timeout = 2 * time.Second)
		if check(r, stale.ok, "the expired entry was shed with the misses") {
			check_eq_str(r, waits_address(r, stale.wire), "203.0.113.2", "the expired answer")
			check(r, time.tick_since(begun) < 500 * time.Millisecond, "the expired entry waited %v", time.tick_since(begun))
		}
		check_eq_int(r, mock_total(mock), 6, "queries that reached the silent upstream in all")
	}
	end_case(r)
}

@(private = "file")
waits_address :: proc(r: ^Runner, wire: []u8) -> string {
	addrs := answer_addresses(r, wire)
	return addrs[0] if len(addrs) > 0 else ""
}
