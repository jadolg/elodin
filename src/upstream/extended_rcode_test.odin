package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A reply whose rcode the client cannot read is not the group's last word.

`dns.peek_rcode` composes twelve bits - the header's four and eight more out of
the OPT record's TTL (RFC 6891 section 6.1.3) - where a stub reads the four. So
an extended rcode reaches the client as some other rcode, and BADVERS, whose low
nibble is zero, reaches it as NOERROR over an empty answer section: a NODATA.

`resolve` is right to hand a client's own question back whatever the first
upstream said - the rcode is the answer, and passing it on is honest - and that
reading holds for the rcodes a client can read. `resolve_readable` is the same
procedure for the ones it cannot: elodin only ever asks in EDNS version 0, which
every EDNS implementation is required to support, so a BADVERS in answer to one
is that upstream violating the protocol rather than a verdict about the name, and
the rest of the group is asked.

Two responders in configured order: the first answers BADVERS to everything, the
second NOERROR. `resolve` is expected to take the first at its word;
`resolve_readable` is expected to go on and find the second.
*/

@(private = "file")
QNAME :: "_25._tcp.mx.example."

@(private = "file")
QUERY_ID :: u16(0x3c3c)

@(private = "file")
Canned_Mock :: struct {
	socket:  net.UDP_Socket,
	// Encoded ahead of the thread starting, and never written to after: the
	// loop only reads it.
	reply:   []u8,
	stop:    bool,
	hits:    int,
	// The transaction ID of the last query this responder was sent, as an int
	// so it can be read back atomically.
	last_id: int,
}

@(private = "file")
canned_mock_loop :: proc(m: ^Canned_Mock) {
	buf: [1024]u8
	out: [1024]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil {
			// The receive timeout firing is how this loop notices `stop`.
			continue
		}
		if n < dns.HEADER_SIZE || len(m.reply) > len(out) {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		sync.atomic_store(&m.last_id, int(u16(buf[0]) << 8 | u16(buf[1])))
		copy(out[:], m.reply)
		// Echo the ID it was asked with, which is drawn fresh per exchange.
		out[0], out[1] = buf[0], buf[1]
		_, _ = net.send_udp(m.socket, out[:len(m.reply)], client)
	}
}

/*
A reply for `QNAME`, with `ext` as the upper eight bits of its rcode.

`make_opt` writes those into the OPT record's TTL, and the header's own nibble is
left at zero throughout - which is the case rather than a detail of the fixture:
rcode 16 is four zero bits in the header and a one in the extended byte.
*/
@(private = "file")
canned_reply :: proc(ext: u8) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .TLSA,
		class = .IN,
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false, ext)
	msg := dns.Message {
		question   = question,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
canned_query :: proc() -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .TLSA,
		class = .IN,
	}
	msg := dns.Message {
		id       = QUERY_ID,
		question = question,
	}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// Binds a responder that answers every query with `reply`, and hands back the
// upstream pointing at it.
@(private = "file")
start_canned_mock :: proc(
	t: ^testing.T,
	m: ^Canned_Mock,
	name: string,
	reply: []u8,
) -> (
	u: ^Upstream,
	responder: ^thread.Thread,
	ok: bool,
) {
	if !testing.expect(t, len(reply) > dns.HEADER_SIZE, "the fixture did not encode") {
		return nil, nil, false
	}
	m.reply = reply

	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return nil, nil, false
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return nil, nil, false
	}

	built, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
	)
	if uerr != .None {
		net.close(socket)
		testing.expectf(t, false, "cannot build the upstream: %v", uerr)
		return nil, nil, false
	}

	return built, thread.create_and_start_with_poly_data(m, canned_mock_loop), true
}

@(test)
test_a_reply_the_client_cannot_read_is_asked_elsewhere :: proc(t: ^testing.T) {
	broken := Canned_Mock{}
	answerer := Canned_Mock{}

	// 1 in the extended byte, nothing in the header's nibble: BADVERS, and the
	// reading a stub gives it is NOERROR.
	badvers := canned_reply(1)
	bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "badvers", badvers)
	if !bad_ok {
		return
	}
	defer {
		sync.atomic_store(&broken.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(broken.socket)
		destroy(bad)
	}

	good, good_thread, good_ok := start_canned_mock(t, &answerer, "answerer", canned_reply(0))
	if !good_ok {
		return
	}
	defer {
		sync.atomic_store(&answerer.stop, true)
		thread.join(good_thread)
		thread.destroy(good_thread)
		net.close(answerer.socket)
		destroy(good)
	}

	// The premise, read off the fixture rather than assumed: an rcode of 16
	// whose header half a client reads as NOERROR.
	testing.expect_value(t, dns.peek_rcode(badvers), dns.Rcode.Bad_Vers)
	testing.expect_value(t, badvers[3] & 0xf, u8(0))

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = bad
	servers[1] = good

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	// What `resolve` alone does, and what the guard in `resolve_query` would
	// otherwise be handed: the first reply, extended rcode and all.
	plain, plain_winner, plain_err := resolve(&g, wire, context.allocator)
	testing.expect_value(t, plain_err, Error.None)
	testing.expect_value(t, dns.peek_rcode(plain), dns.Rcode.Bad_Vers)
	testing.expect_value(t, plain_winner, bad)
	delete(plain, context.allocator)

	// And what a client's question gets now: the server that could answer it.
	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.No_Error)
	testing.expect_value(t, winner, good)
	testing.expect(t, sync.atomic_load(&answerer.hits) > 0, "the second upstream was never asked")
	delete(resp, context.allocator)

	/*
	The scratch arena is left for the runner to reset rather than reset here.

	`m.reply` points into it, and the responder threads are stopped and joined
	by the deferred blocks above - which run *after* the last statement of this
	procedure. Resetting the arena here would hand a live thread a slice into
	memory this frame had given back, and it is a read nothing would report:
	`ODIN_TEST_FAIL_ON_BAD_MEMORY` tracks `context.allocator`, and the temporary
	arena keeps its blocks mapped, so ASan sees nothing either.
	*/
}

/*
And where nobody in the group can manage a readable rcode, the first reply comes
back as it stands.

Deliberately: turning one reply into another is the caller's business, and
`resolve_query` is the caller that does it - it answers the client SERVFAIL. A
sweep that invented an error here would take the reply away from the one caller
that has to look at it, and would leave a group of one - the ordinary
arrangement - reporting a transport failure for a reply that arrived perfectly
well.
*/
@(test)
test_an_unreadable_reply_still_comes_back_when_nobody_else_can_answer :: proc(t: ^testing.T) {
	broken := Canned_Mock{}
	bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "badvers", canned_reply(1))
	if !bad_ok {
		return
	}
	defer {
		sync.atomic_store(&broken.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(broken.socket)
		destroy(bad)
	}

	servers := make([]^Upstream, 1, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = bad

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, winner, bad)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.Bad_Vers)
	// One query: the sweep skips the server that already spoke, and there is
	// nobody else, so a group of one costs exactly what it did before.
	testing.expect_value(t, sync.atomic_load(&broken.hits), 1)
	delete(resp, context.allocator)

	// The upstream answered, promptly, and is not marked down for it: those
	// eight bits are two bytes an on-path attacker can write into any reply it
	// can reach, and counting them as a failure would let one park a healthy
	// server from a forged packet per query.
	testing.expect(t, healthy(bad), "an upstream was parked over an rcode it answered with")

	/*
	The scratch arena is left for the runner to reset rather than reset here.

	`m.reply` points into it, and the responder threads are stopped and joined
	by the deferred blocks above - which run *after* the last statement of this
	procedure. Resetting the arena here would hand a live thread a slice into
	memory this frame had given back, and it is a read nothing would report:
	`ODIN_TEST_FAIL_ON_BAD_MEMORY` tracks `context.allocator`, and the temporary
	arena keeps its blocks mapped, so ASan sees nothing either.
	*/
}

/*
And the query the sweep sends carries a transaction ID of its own.

RFC 5452 section 9.2, and `cases_queryid.odin` states the rule this server keeps:
on a plain UDP upstream the ID and the source port are the whole of what an
off-path attacker has to guess. What makes it sharper here than on the ordinary
forward is that a *reply* is what triggers the sweep, so the server that sent the
first one picks the moment - an upstream that is hostile, or whose traffic an
attacker can read, answers unusably and thereby induces a second query for the
same name to another member of the group. Sent under the ID that upstream has
just seen, only the fresh source port would be left to guess, and a hit is an
answer this server caches for every client behind it.

Eight rounds, because a single comparison against a random 16-bit number is a
one-in-65536 flake either way. The ID the sweep uses has to differ from the
query's own in at least one of them; reuse fails all eight.
*/
@(test)
test_the_swept_query_carries_a_transaction_id_of_its_own :: proc(t: ^testing.T) {
	broken := Canned_Mock{}
	answerer := Canned_Mock{}

	bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "badvers", canned_reply(1))
	if !bad_ok {
		return
	}
	defer {
		sync.atomic_store(&broken.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(broken.socket)
		destroy(bad)
	}

	good, good_thread, good_ok := start_canned_mock(t, &answerer, "answerer", canned_reply(0))
	if !good_ok {
		return
	}
	defer {
		sync.atomic_store(&answerer.stop, true)
		thread.join(good_thread)
		thread.destroy(good_thread)
		net.close(answerer.socket)
		destroy(good)
	}

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = bad
	servers[1] = good

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	ROUNDS :: 8
	own := 0
	for _ in 0 ..< ROUNDS {
		resp, winner, err := resolve_readable(&g, wire, context.allocator)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, winner, good)
		delete(resp, context.allocator)

		// The first exchange is `resolve`'s and is left exactly as the caller
		// wrote it: `resolve_query` has already drawn the ID for that one.
		testing.expect_value(t, u16(sync.atomic_load(&broken.last_id)), QUERY_ID)
		if u16(sync.atomic_load(&answerer.last_id)) == QUERY_ID {
			own += 1
		}
	}

	testing.expectf(
		t,
		own < ROUNDS,
		"every one of %d swept queries went out under the client-facing query's own ID",
		ROUNDS,
	)

	/*
	The scratch arena is left for the runner to reset rather than reset here.

	`m.reply` points into it, and the responder threads are stopped and joined
	by the deferred blocks above - which run *after* the last statement of this
	procedure. Resetting the arena here would hand a live thread a slice into
	memory this frame had given back, and it is a read nothing would report:
	`ODIN_TEST_FAIL_ON_BAD_MEMORY` tracks `context.allocator`, and the temporary
	arena keeps its blocks mapped, so ASan sees nothing either.
	*/
}
