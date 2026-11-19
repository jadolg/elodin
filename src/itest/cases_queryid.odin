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
How often a server drawing every ID at random may still be seen to do what a
broken one does, before the case says so. A random draw is the client's ID one
time in 65,536: requiring none of 24 to be failed a correct server about once
in 2,700 runs. Three or more is C(24,3)/65536^3, under 1e-11, while a server
that copies the ID copies it 24 times.
*/
@(private = "file")
REUSED_ALLOWED :: 2

/*
24 draws from 16 bits make about lambda = 276/65536 = 0.0042 colliding pairs.
Four or more IDs lost to collisions takes four pairs, about lambda^4/24 = 1.3e-11,
or a triple (C(24,3)/65536^2 = 4.7e-7) and two pairs (lambda^2/2), about 4e-12:
under 1e-10 together. One fresh ID used for every query loses 23. A reused
client ID is a draw like any other, so it counts here too: the two allowances
overlap rather than add.
*/
@(private = "file")
REPEATS_ALLOWED :: 3

/*
Forwards whose ID is the one before it plus one: a counter's 23, and a random
draw's one time in 65,536 - three or more of 23 is C(23,3)/65536^3, under 1e-11.
*/
@(private = "file")
SEQUENTIAL_ALLOWED :: 2

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
		reused := 0
		sequential := 0
		previous: Maybe(u16)
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
			h := parse_header(r, res.wire)
			check(r, h.id == CLIENT_ID, "the client got id %04x back, not its own %04x", h.id, CLIENT_ID)

			// Length, not just presence: `parse_header` hands back a zeroed
			// header for anything shorter, and every short query drawing the
			// same id 0 would report a collision that never happened.
			forwarded := mock_last_query(mock)
			if !check(r, len(forwarded) >= dns.HEADER_SIZE, "the upstream saw no readable query") {
				break
			}
			// The query the upstream saw last is this one, not the one before
			// it again: one answered without forwarding would count twice.
			msg, decoded := decode_reply(r, forwarded)
			if !decoded || !check(r, len(msg.question) == 1 && dns.name_equal_fold(msg.question[0].name, qname), "query %d was not the last one the upstream saw: %v", i, msg.question) {
				break
			}
			fh := parse_header(r, forwarded)
			if fh.id == CLIENT_ID {
				reused += 1
			}
			if before, has := previous.?; has && fh.id == before + 1 {
				sequential += 1
			}
			previous = fh.id
			seen[fh.id] = true
		}

		check_eq_int(r, answered, FORWARDS, "queries answered")
		check(r, reused <= REUSED_ALLOWED, "%d of %d forwarded queries carried the client's own id", reused, answered)
		/*
		Distinctness is the other half of it: one fresh ID reused for every
		query afterwards is as good as the client's to an attacker who has seen
		a single answer.
		*/
		check(r, sequential <= SEQUENTIAL_ALLOWED, "%d of %d forwarded queries took the ID after the one before", sequential, answered - 1)
		check(
			r,
			len(seen) >= answered - REPEATS_ALLOWED,
			"only %d distinct transaction ids across %d forwarded queries",
			len(seen),
			answered,
		)
	}
	end_case(r)
}
