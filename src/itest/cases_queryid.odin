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

// Enough forwards that a fixed, repeated or counting ID cannot pass by chance,
// few enough that 16-bit collisions stay unlikely.
@(private = "file")
FORWARDS :: 24

/*
What a forward that carried the client's ID is asked again with: a server
copying the ID copies these too, while one drawing at random draws a client's
ID one time in 65,536. Two asks, so a correct server fails only when its first
forward and both asks match - (24/65536)/65536^2, under 1e-13 - where needing
no forward to match at all failed it about once in 2,700 runs.
*/
@(private = "file")
OTHER_CLIENT_IDS :: [2]u16{0x2424, 0x5151}

/*
24 draws from 16 bits make about lambda = 276/65536 = 0.0042 colliding pairs.
What this allows for is a triple, three draws alike (C(24,3)/65536^2 = 4.7e-7):
that loses two IDs, and is why two lost is not a failure. Four or more lost
takes four pairs, about lambda^4/24 = 1.3e-11, or a triple and two pairs
(4.7e-7 * lambda^2/2), about 4e-12: under 1e-10 together. One fresh ID used for
every query loses 23.
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
		fmt.tprintf(`["udp://127.0.0.1:%d"]`, upstream_port),
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
			id, forwarded := forward_id(r, mock, udp_port, qname, CLIENT_ID)
			if !forwarded {
				break
			}
			if id == CLIENT_ID && copies_every_client_id(r, mock, udp_port, qname) {
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
		check(r, copied == 0, "%d of %d forwarded queries carried the client's ID, and the client's again when asked under others", copied, recorded)
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
saw last is this one, not one before it again. False, with the case failed,
when either is not so.
*/
@(private = "file")
forward_id :: proc(r: ^Runner, mock: ^Mock, udp_port: int, qname: string, client_id: u16) -> (id: u16, ok: bool) {
	res := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = client_id))
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

// Whether asking `qname` again under each of `OTHER_CLIENT_IDS` forwards that
// ID too: what a server copying the client's ID does, and a random one by a
// chance under 1e-9.
@(private = "file")
copies_every_client_id :: proc(r: ^Runner, mock: ^Mock, udp_port: int, qname: string) -> bool {
	for other in OTHER_CLIENT_IDS {
		id, forwarded := forward_id(r, mock, udp_port, qname, other)
		if !forwarded || id != other {
			return false
		}
	}
	return true
}
