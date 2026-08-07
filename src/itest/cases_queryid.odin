package itest

import "core:fmt"
import "elodin:dns"

/*
The transaction ID elodin puts on a query it forwards.

RFC 5452 section 9.2. On a plain UDP upstream the ID and elodin's ephemeral
source port are the whole of what an off-path attacker has to guess for a forged
datagram to be taken as the upstream's answer - it already knows the upstream's
address and port, and it chose the question by asking for it. Forwarding the
client's own ID gives one of the two away to whoever sent the query, leaving the
port alone between an attacker and an answer cached for every client behind this
resolver.

Asserted here on the query as the upstream received it, through the binary that
ships, because that is the only place the number in question is observable.
*/

@(private = "file")
CLIENT_ID :: u16(0x4242)

// Enough forwards that a fixed or counting ID cannot pass by chance, few enough
// that 16-bit collisions stay unlikely.
@(private = "file")
FORWARDS :: 24

run_query_id_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("id-upstream", upstream_port)
	// Any name, so each query can ask a different one and still be answered.
	mock_synth_all(mock, {192, 0, 2, 9})
	if !mock_start(mock) {
		skip_case(r, "upstream: transaction ids", "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	// The cache is off so every query reaches the upstream, and cookies too:
	// they close this same hole by another route, and what is under test is the
	// ID on its own.
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["udp://127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
cookies: {{ enabled: false, upstream: false }}
`,
		udp_port,
		upstream_port,
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "upstream: transaction ids", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "upstream: a forwarded query does not carry the client's transaction id")
	{
		seen := make(map[u16]bool, FORWARDS, context.temp_allocator)
		reused := 0
		answered := 0

		for i in 0 ..< FORWARDS {
			// A different name each time, so nothing can be served from
			// anywhere but the upstream.
			qname := fmt.tprintf("id-%d.probe.test.", i)
			res := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = CLIENT_ID))
			if !check(r, res.ok, "no response to query %d", i) {
				break
			}
			answered += 1

			// The client is waiting on the ID it wrote.
			h, _ := parse_header(res.wire)
			check(r, h.id == CLIENT_ID, "the client got id %04x back, not its own %04x", h.id, CLIENT_ID)

			forwarded := mock_last_query(mock)
			if !check(r, forwarded != nil, "the upstream saw no query") {
				break
			}
			fh, fok := parse_header(forwarded)
			if !check(r, fok, "the forwarded query has no readable header") {
				break
			}
			if fh.id == CLIENT_ID {
				reused += 1
			}
			seen[fh.id] = true
		}

		check_eq_int(r, answered, FORWARDS, "queries answered")
		check_eq_int(r, reused, 0, "forwarded queries carrying the client's own id")
		/*
		Distinctness is the other half of it: one fresh ID reused for every
		query afterwards is as good as the client's to an attacker who has seen
		a single answer. 24 draws from 16 bits collide about 0.4% of the time,
		so one repeat is not a failure - several are.
		*/
		check(
			r,
			len(seen) >= answered - 2,
			"only %d distinct transaction ids across %d forwarded queries",
			len(seen),
			answered,
		)
	}
	end_case(r)
}
