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

// The ID the client puts on its first query; each one after takes the next.
@(private = "file")
FIRST_CLIENT_ID :: u16(0x4242)

// Enough forwards that a fixed, repeated, copied or counting ID cannot pass by
// chance, few enough that 16-bit collisions stay unlikely.
@(private = "file")
FORWARDS :: 24

/*
Forwards that carried their client's ID: a copying server's 24, and a random
draw's one time in 65,536 - three or more of 24 is C(24,3)/65536^3, under 1e-11,
where allowing none failed a correct server about once in 2,700 runs.
*/
@(private = "file")
COPIES_ALLOWED :: 2

/*
24 draws from 16 bits make about lambda = 276/65536 = 0.0042 colliding pairs.
Each lost ID is one more pair, or a triple: three lost - three pairs
(lambda^3/6 = 1.2e-8) or a triple and a pair (C(24,3)/65536^2 * lambda = 2e-9) -
is too likely to fail on. Four or more lost takes four pairs (lambda^4/24 =
1.3e-11) or a triple and two pairs (4.7e-7 * lambda^2/2 = 4e-12): under 1e-10
together. One fresh ID used for every query loses 23.
*/
@(private = "file")
REPEATS_ALLOWED :: 3

/*
Forwards whose ID is the one before it plus the same step as the one before
that: a counter's 22, by whatever step and in either direction, and a random
draw's one time in 65,536 - three or more of 22 is C(22,3)/65536^3, under 1e-11.
*/
@(private = "file")
STEADY_STEPS_ALLOWED :: 2

run_query_id_cases :: proc(r: ^Runner) {
	// Any name, so each query can ask a different one and still be answered.
	mock, upstream_port, started := synth_mock(r, "id-upstream", "upstream: transaction ids", {192, 0, 2, 9})
	if !started {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	// The cache is off so every query reaches the upstream, and cookies too:
	// they close this same hole by another route, and what is under test is the
	// ID on its own.
	config := base_config(
		udp_port,
		upstreams_at({upstream_port}, scheme = "udp://"),
		timeout = "3s",
		extra = "cookies: { enabled: false, upstream: false }",
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "upstream: a forwarded query does not carry the client's transaction id")
	{
		seen := make(map[u16]bool, FORWARDS, context.temp_allocator)
		copied := 0
		steady := 0
		previous, step: Maybe(u16)
		recorded := 0

		for i in 0 ..< FORWARDS {
			// A different name each time, so nothing can be served from
			// anywhere but the upstream.
			qname := fmt.tprintf("id-%d.probe.test.", i)
			client_id := FIRST_CLIENT_ID + u16(i)
			id, forwarded := forward_id(r, mock, udp_port, qname, client_id)
			if !forwarded {
				break
			}
			if id == client_id {
				copied += 1
			}
			if before, has := previous.?; has {
				if last, stepped := step.?; stepped && id - before == last {
					steady += 1
				}
				step = id - before
			}
			previous = id
			seen[id] = true
			recorded += 1
		}

		check_eq_int(r, recorded, FORWARDS, "forwarded queries recorded")
		check(r, copied <= COPIES_ALLOWED, "%d of %d forwarded queries carried the client's ID", copied, recorded)
		/*
		Distinctness is the other half of it: one fresh ID reused for every
		query afterwards is as good as the client's to an attacker who has seen
		a single answer, and a counter's next is as good as known.
		*/
		check(r, steady <= STEADY_STEPS_ALLOWED, "%d of %d forwarded queries stepped from the one before as it had from its own", steady, max(recorded - 2, 0))
		check(
			r,
			len(seen) >= recorded - REPEATS_ALLOWED,
			"only %d distinct transaction ids across %d forwarded queries",
			len(seen),
			recorded,
		)
	}
	end_case(r)
}

/*
Ask `qname` under `client_id` and return the ID the upstream saw, checking on
the way that the client got its own ID back and that the query the upstream
saw last is this one, not one before it. False, with the case failed,
when either is not so.
*/
@(private = "file")
forward_id :: proc(r: ^Runner, mock: ^Mock, udp_port: int, qname: string, client_id: u16) -> (id: u16, ok: bool) {
	res := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = client_id), allocator = context.temp_allocator)
	if !check(r, res.ok, "no response to %s", qname) {
		return
	}
	h := parse_header(r, res.wire)
	check(r, h.id == client_id, "the client got id %04x back, not its own %04x", h.id, client_id)
	msg, decoded := decode_reply(r, mock_last_query(mock))
	if !decoded {
		return
	}
	if !check(r, len(msg.question) == 1 && dns.name_equal_fold(msg.question[0].name, qname), "%s was not the last query the upstream saw: %v", qname, msg.question) {
		return
	}
	return msg.id, true
}
