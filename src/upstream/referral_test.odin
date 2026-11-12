package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "elodin:dns"

/*
Issue #410: a referral is not an answer to a recursive query (RFC 1034 section
4.3.1, RFC 2308 section 2.2 type 4). A member that does not recurse for a name
answers RD=1 with one, and the group has to go on to a member that does.
*/

// Answers every query with a referral: NOERROR, RA clear, no answer, the zone's
// NS in authority and no SOA - what a server that does not recurse sends.
@(private = "file")
Referral_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	hits:   int,
}

@(private = "file")
referral_loop :: proc(m: ^Referral_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		q, derr := dns.decode_message(buf[:n], context.temp_allocator)
		if derr != .None || len(q.question) != 1 {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		reply := dns.Message {
			id        = q.id,
			question  = q.question,
			authority = []dns.Record{{name = "example.com.", type = .NS, class = .IN, ttl = 3600, data = dns.Rdata_Name{"ns1.example.com."}}},
		}
		reply.flags.qr = true
		reply.flags.rd = q.flags.rd
		wire, _, _ := dns.encode_message(reply, context.temp_allocator)
		_, _ = net.send_udp(m.socket, wire, client)
		free_all(context.temp_allocator)
	}
}

// A normal recursive answer: the query echoed back with QR and RA set.
@(private = "file")
echo_loop :: proc(m: ^Referral_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		buf[2] |= 0x80
		buf[3] |= 0x80
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

@(test)
test_a_referral_is_not_taken_as_an_answer :: proc(t: ^testing.T) {
	referrer, answerer: Referral_Mock
	// Neither started means neither closed: a zero socket here is fd 0, which
	// under `odin test` is another test's.
	bad, bad_thread, bad_ok := start_udp_mock(t, &referrer, referral_loop, "referrer")
	if !bad_ok {
		return
	}
	defer stop_udp_mock(&referrer, bad_thread, bad)
	good, good_thread, good_ok := start_udp_mock(t, &answerer, echo_loop, "answerer")
	if !good_ok {
		return
	}
	defer stop_udp_mock(&answerer, good_thread, good)

	servers := []^Upstream{bad, good}
	g := failover_group(servers)
	query := dns.Message{id = 0x4104, question = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}}}
	query.flags.rd = true
	wire, _, _ := dns.encode_message(query, context.temp_allocator)

	// A client's own question.
	plain, plain_winner, plain_err := resolve_readable(&g, wire, context.allocator)
	testing.expect_value(t, plain_err, Error.None)
	testing.expect(t, plain_winner == good, "resolve_readable took the referral as the answer")
	delete(plain, context.allocator)

	// The chain walk's sweep.
	resp, winner, err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == good, "resolve_answerable took the referral as answerable")
	delete(resp, context.allocator)

	testing.expect(t, sync.atomic_load(&referrer.hits) >= 2, "the referring member was not asked first each time")
	testing.expect(t, sync.atomic_load(&answerer.hits) > 0, "the member that recurses was never asked")
	free_all(context.temp_allocator)
}
