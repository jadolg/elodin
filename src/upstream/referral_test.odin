package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
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

@(private = "file")
start_mock :: proc(t: ^testing.T, m: ^Referral_Mock, name: string, loop: proc(_: ^Referral_Mock)) -> (^Upstream, ^thread.Thread) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	testing.expectf(t, serr == nil, "bind: %v", serr)
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)
	bound, _ := net.bound_endpoint(socket)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "upstream: %v", uerr)
	return u, thread.create_and_start_with_poly_data(m, loop)
}

@(test)
test_a_referral_is_not_taken_as_an_answer :: proc(t: ^testing.T) {
	referrer, answerer: Referral_Mock
	bad, bad_thread := start_mock(t, &referrer, "referrer", referral_loop)
	good, good_thread := start_mock(t, &answerer, "answerer", echo_loop)
	defer {
		sync.atomic_store(&referrer.stop, true)
		sync.atomic_store(&answerer.stop, true)
		thread.join(bad_thread)
		thread.join(good_thread)
		thread.destroy(bad_thread)
		thread.destroy(good_thread)
		net.close(referrer.socket)
		net.close(answerer.socket)
		destroy(bad)
		destroy(good)
	}

	servers := []^Upstream{bad, good}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
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
