package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A reply the client's own question cannot use is not the group's last word.

Two kinds of those, and this file holds both: an rcode the client cannot read,
which is what the fixtures and the first tests are about, and a SERVFAIL or a
REFUSED, which it reads perfectly well and which says nothing about the name -
issue #309, at the end.

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
	// How long to sit on a query before answering it, for the member that is
	// slow rather than absent.
	delay:   time.Duration,
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
		if m.delay > 0 {
			time.sleep(m.delay)
		}
		copy(out[:], m.reply)
		// Echo the ID it was asked with, which is drawn fresh per exchange.
		out[0], out[1] = buf[0], buf[1]
		_, _ = net.send_udp(m.socket, out[:len(m.reply)], client)
	}
}

/*
A reply for `QNAME`, with `ext` as the upper eight bits of its rcode and `rcode`
as the header's own four.

`make_opt` writes the upper eight into the OPT record's TTL. The header's nibble
stays at zero for the extended-rcode cases, which is the case rather than a
detail of the fixture: rcode 16 is four zero bits in the header and a one in the
extended byte. The SERVFAIL and REFUSED cases are the other way round - nothing
extended, and the whole rcode in the header where a stub reads it.
*/
@(private = "file")
canned_reply :: proc(ext: u8, rcode := dns.Rcode.No_Error) -> []u8 {
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
	msg.flags.rcode = u8(rcode)
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

/*
And a SERVFAIL or a REFUSED is not the group's last word either.

Different reason, same conclusion. RFC 2308 section 7.1 reads SERVFAIL as the
server saying nothing about the name - it is a report about the server - and
REFUSED is the server declining to be asked at all. Neither is a verdict the
other members of a failover group cannot improve on, and every other resolver
treats them that way: dnsmasq retries and marks the sender, Unbound counts a
SERVFAIL from a forward address as a failure and takes the next one, BIND moves
to the next forwarder.

What made this issue #309 rather than a preference is where it lands. A group of
two exists so that one of them can be down; an upstream whose ACL changed, or
whose own recursion is down, answers REFUSED or SERVFAIL promptly and forever,
which never trips the health cooldown - that counts transport failures - and
before this every client query stopped at it while the member beside it held the
answer.

Health is still left alone, on purpose, and the assertion below says so: an
upstream that answers is not an upstream that has failed in the sense
`record_failure` tracks, and the sweep is what costs the group nothing to get
past it.
*/
@(test)
test_a_reply_the_clients_question_cannot_use_is_asked_elsewhere :: proc(t: ^testing.T) {
	for rcode in ([]dns.Rcode{.Serv_Fail, .Refused}) {
		broken := Canned_Mock{}
		answerer := Canned_Mock{}

		bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "broken", canned_reply(0, rcode))
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

		// The premise: `resolve` alone still takes the first member at its
		// word, which is what the client was handed before this.
		plain, plain_winner, plain_err := resolve(&g, wire, context.allocator)
		testing.expect_value(t, plain_err, Error.None)
		testing.expect_value(t, dns.peek_rcode(plain), rcode)
		testing.expect_value(t, plain_winner, bad)
		delete(plain, context.allocator)

		resp, winner, err := resolve_readable(&g, wire, context.allocator)
		testing.expect_value(t, err, Error.None)
		testing.expectf(
			t,
			dns.peek_rcode(resp) == .No_Error,
			"a client's question stopped at the member that answered %v",
			rcode,
		)
		testing.expect_value(t, winner, good)
		testing.expect(t, sync.atomic_load(&answerer.hits) > 0, "the second upstream was never asked")
		delete(resp, context.allocator)

		// It answered, promptly, and is not parked for it. SERVFAIL is a
		// legitimate answer to plenty of questions and the sweep is cheap; what
		// `record_failure` tracks is a server that has stopped replying.
		testing.expect(t, healthy(bad), "an upstream was parked over an rcode it answered with")

		// Which leaves the counter as the only trace it leaves, so the counter
		// is asserted: one reply of its own swept past, named against it rather
		// than against the member that answered.
		swept := stats_of(bad)
		testing.expect_value(t, swept.swept_rcode, u64(1))
		testing.expect_value(t, swept.failures, u64(0))
		testing.expect_value(t, stats_of(good).swept_rcode, u64(0))
	}
}

/*
Except where the reply says, in an extended error, that it is about the name
after all: those stand.

The exception `BOGUS_EDE_FIRST` is written on, and the case it protects is a
group whose members do not all validate - a validating resolver beside an ISP
box that does not - with elodin's own `dnssec.enabled: false`, where nothing
here is checking either. The first member finds a zone bogus and SERVFAILs it;
sweeping on would fetch the forgery from the member that never looked, and this
server would cache it and hand it to every client behind it. RFC 8914 is how the
first member says which of the two SERVFAILs it meant, and every validating
resolver attaches one.

The REFUSED half is the same shape for a different reason. 15, 16 and 17 -
blocked, censored, filtered - are a responder declining this *name* on policy,
which a filtering member of a group has to be able to say or its blocks are
fetched from the member beside it. 18, prohibited, is that responder declining
this *client*, which says nothing about the name and is exactly what the sweep
is for.

Eight replies, one per reading, and in both halves a reply carrying no extended
error at all makes no claim and is swept past - the case the tests above cover,
here for the contrast.
*/
@(test)
test_an_extended_error_that_names_the_reason_is_the_answer :: proc(t: ^testing.T) {
	Case :: struct {
		what:   string,
		rcode:  dns.Rcode,
		// -1 for a reply with no extended error in it at all.
		ede:    int,
		stands: bool,
	}
	cases := []Case {
		{"DNSSEC Bogus", .Serv_Fail, 6, true},
		{"NSEC Missing", .Serv_Fail, 12, true},
		{"No Reachable Authority", .Serv_Fail, 22, false},
		{"a SERVFAIL with no extended error", .Serv_Fail, -1, false},
		{"Blocked", .Refused, 15, true},
		{"Filtered", .Refused, 17, true},
		// The responder declining this client rather than this name, which is
		// the case the sweep exists for.
		{"Prohibited", .Refused, 18, false},
		{"a REFUSED with no extended error", .Refused, -1, false},
	}

	for c in cases {
		broken := Canned_Mock{}
		answerer := Canned_Mock{}

		bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "broken", ede_reply(c.rcode, c.ede))
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

		resp, winner, err := resolve_readable(&g, wire, context.allocator)
		testing.expect_value(t, err, Error.None)
		if c.stands {
			testing.expectf(
				t,
				winner == bad && dns.peek_rcode(resp) == c.rcode,
				"%s was swept past, so the client was answered from somewhere else",
				c.what,
			)
		} else {
			testing.expectf(
				t,
				winner == good && dns.peek_rcode(resp) == .No_Error,
				"%s ended the search with a member that could answer standing by",
				c.what,
			)
		}
		delete(resp, context.allocator)
	}
}

/*
A reply for `QNAME` with `rcode` in its header, carrying RFC 8914 extended error
`info`, or none at all where `info` is negative.

The option goes in after the message is encoded, the way one reaches a reply on
the wire: `set_edns_option` needs the OPT record `canned_reply` already writes.
*/
@(private = "file")
ede_reply :: proc(rcode: dns.Rcode, info: int) -> []u8 {
	wire := canned_reply(0, rcode)
	if info < 0 || len(wire) == 0 {
		return wire
	}
	// Info-code, and no text behind it: RFC 8914 section 2 makes the text
	// optional, and what this server reads is the code.
	data := make([]u8, 2, context.temp_allocator)
	data[0] = u8(u16(info) >> 8)
	data[1] = u8(info)
	out, ok := dns.set_edns_option(wire, .Ext_Error, data, context.temp_allocator)
	if !ok {
		return nil
	}
	return out
}

/*
And a group of one hands its SERVFAIL back untouched, at the cost of one query.

Which is the ordinary deployment, and the arrangement the parity suite runs: one
upstream, and every rcode it states is the client's answer. The sweep skips the
member that already spoke, so where there is nobody else it does nothing at all -
no second query, no invented error, the same bytes as before.
*/
@(test)
test_a_lone_upstreams_servfail_is_still_the_clients_answer :: proc(t: ^testing.T) {
	broken := Canned_Mock{}
	bad, bad_thread, bad_ok := start_canned_mock(t, &broken, "broken", canned_reply(0, .Serv_Fail))
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
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.Serv_Fail)
	testing.expect_value(t, sync.atomic_load(&broken.hits), 1)
	delete(resp, context.allocator)

	// And it is counted, though there was nobody to ask: the series is the
	// replies a group could not use, which is the figure that names the member
	// answering them. See `note_swept_rcode`.
	testing.expect_value(t, stats_of(bad).swept_rcode, u64(1))
}

/*
And the sweep does not spend a second timeout on a member this query already
failed to reach.

The cooldown does not cover it: `FAILURE_THRESHOLD` is three, so the first two
timeouts cost `g.timeout` each and leave the server `healthy`. A group of one
member that is not there and one that answers REFUSED is the shape - the first
is asked by `resolve` and times out, the second answers, and the reply is one the
sweep will not take. Before this the sweep asked the dead member again, and a
question that cost one timeout cost two.

A socket bound and closed gives an address nothing is listening on, which is a
timeout rather than a refusal on UDP. The timeout is 200ms and the assertion is
that the whole call comes in under three of them: the fixture cannot see a
skipped exchange, only the wait it would have cost.
*/
@(test)
test_the_sweep_does_not_wait_again_on_a_member_that_timed_out :: proc(t: ^testing.T) {
	dead_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the dead port: %v", derr) {
		return
	}
	dead_bound, berr := net.bound_endpoint(dead_socket)
	net.close(dead_socket)
	if !testing.expectf(t, berr == nil, "cannot read the dead port: %v", berr) {
		return
	}

	dead, uerr := make_upstream(
		config.Upstream_Spec {
			name = "dead",
			kind = .UDP,
			address = "127.0.0.1",
			port = dead_bound.port,
		},
		0,
		time.Second,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the dead upstream: %v", uerr) {
		return
	}
	defer destroy(dead)

	refusing := Canned_Mock{}
	ref, ref_thread, ref_ok := start_canned_mock(t, &refusing, "refusing", canned_reply(0, .Refused))
	if !ref_ok {
		return
	}
	defer {
		sync.atomic_store(&refusing.stop, true)
		thread.join(ref_thread)
		thread.destroy(ref_thread)
		net.close(refusing.socket)
		destroy(ref)
	}

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = dead
	servers[1] = ref

	TIMEOUT :: 200 * time.Millisecond
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	started := time.now()
	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	spent := time.since(started)

	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, winner, ref)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.Refused)
	delete(resp, context.allocator)

	// One timeout and a datagram, against a threshold of two: the exact signal
	// is the counter below, and this is the wall clock saying what it buys.
	testing.expectf(
		t,
		spent < 2 * TIMEOUT,
		"the query took %v, which is the dead member's timeout paid twice",
		spent,
	)

	// The REFUSED is counted against the member that sent it, as every reply
	// the group cannot use is, whether or not the sweep found anywhere to go.
	testing.expect_value(t, stats_of(ref).swept_rcode, u64(1))
}

/*
And a live spare standing behind a dead one is reached once the dead one parks.

The sweep stops at the first member it cannot reach, which is what keeps its
cost to one timeout however many members are left. The price is this group -
`[refuses, not there, has the answer]` - where the sweep stops at the middle
member and the client is handed the REFUSED it started with.

For three queries. Each of those exchanges is a real failure at the group's own
timeout, which is the point of not cutting it short: the dead member accrues
`FAILURE_THRESHOLD` and parks, the sweep skips a parked member, and the one
behind it answers. So the assertion is that the group heals itself inside the
threshold rather than that the first query is perfect.
*/
@(test)
test_a_live_spare_behind_a_dead_one_is_reached_once_the_dead_one_parks :: proc(t: ^testing.T) {
	refusing := Canned_Mock{}
	ref, ref_thread, ref_ok := start_canned_mock(t, &refusing, "refusing", canned_reply(0, .Refused))
	if !ref_ok {
		return
	}
	defer {
		sync.atomic_store(&refusing.stop, true)
		thread.join(ref_thread)
		thread.destroy(ref_thread)
		net.close(refusing.socket)
		destroy(ref)
	}

	answerer := Canned_Mock{}
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

	dead_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the dead port: %v", derr) {
		return
	}
	dead_bound, berr := net.bound_endpoint(dead_socket)
	net.close(dead_socket)
	if !testing.expectf(t, berr == nil, "cannot read the dead port: %v", berr) {
		return
	}
	dead, uerr := make_upstream(
		config.Upstream_Spec {
			name = "not-there",
			kind = .UDP,
			address = "127.0.0.1",
			port = dead_bound.port,
		},
		0,
		time.Second,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the dead upstream: %v", uerr) {
		return
	}
	defer destroy(dead)

	servers := make([]^Upstream, 3, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = ref
	servers[1] = dead
	servers[2] = good

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = 400 * time.Millisecond,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	/*
	One more query than the threshold: the first `FAILURE_THRESHOLD` of them
	pay a timeout at the dead member and are answered with the REFUSED, and the
	one after that finds it parked and reaches the member behind it.
	*/
	answered := false
	for i in 0 ..< FAILURE_THRESHOLD + 1 {
		resp, winner, err := resolve_readable(&g, wire, context.allocator)
		testing.expect_value(t, err, Error.None)
		if winner == good && dns.peek_rcode(resp) == .No_Error {
			answered = true
		} else {
			testing.expectf(
				t,
				winner == ref && dns.peek_rcode(resp) == .Refused,
				"query %d came back from neither the refusing member nor the one with the answer",
				i,
			)
		}
		delete(resp, context.allocator)
	}

	testing.expect(
		t,
		answered,
		"the member with the answer was never reached, so a dead spare in front of it stands forever",
	)
	testing.expect(t, !healthy(dead), "the dead member was never parked, so the sweep never gets past it")
}

/*
And however many members a group has left, the sweep spends one timeout on them.

The shape is a group of three whose first member answers REFUSED at once and
whose two spares are not there. Unbounded, that is a timeout per spare - at the
shipped five seconds, ten of them for a reply the group had in its first
millisecond, with a query worker held for the whole of it. Bounded, the first
spare is asked and the second is not, because by then the budget is gone.

The assertion is the wall clock, against a threshold between one timeout and
two: a fixture cannot see an exchange that was never made, only the wait it
would have cost. The dead ports are bound and closed, which on UDP is a timeout
rather than a refusal - `exchange_udp` does not connect its socket, so no ICMP
comes back.
*/
@(test)
test_the_sweep_spends_one_timeout_on_the_members_it_has_left :: proc(t: ^testing.T) {
	dead_upstream :: proc(t: ^testing.T, name: string) -> (^Upstream, bool) {
		socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, serr == nil, "cannot bind a dead port: %v", serr) {
			return nil, false
		}
		bound, berr := net.bound_endpoint(socket)
		net.close(socket)
		if !testing.expectf(t, berr == nil, "cannot read a dead port: %v", berr) {
			return nil, false
		}
		u, uerr := make_upstream(
			config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
			0,
			time.Second,
			context.allocator,
		)
		if !testing.expectf(t, uerr == .None, "cannot build %s: %v", name, uerr) {
			return nil, false
		}
		return u, true
	}

	refusing := Canned_Mock{}
	ref, ref_thread, ref_ok := start_canned_mock(t, &refusing, "refusing", canned_reply(0, .Refused))
	if !ref_ok {
		return
	}
	defer {
		sync.atomic_store(&refusing.stop, true)
		thread.join(ref_thread)
		thread.destroy(ref_thread)
		net.close(refusing.socket)
		destroy(ref)
	}

	first, first_ok := dead_upstream(t, "spare-one")
	if !first_ok {
		return
	}
	defer destroy(first)
	second, second_ok := dead_upstream(t, "spare-two")
	if !second_ok {
		return
	}
	defer destroy(second)

	servers := make([]^Upstream, 3, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = ref
	servers[1] = first
	servers[2] = second

	TIMEOUT :: 200 * time.Millisecond
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	started := time.now()
	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	spent := time.since(started)

	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, winner, ref)
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.Refused)
	delete(resp, context.allocator)

	testing.expectf(
		t,
		spent < 2 * TIMEOUT,
		"the sweep took %v, which is a timeout for every spare rather than one for the sweep",
		spent,
	)
}

/*
And a member the sweep asks is judged on the group's timeout, not on a smaller
one.

The rule that keeps this honest: `exchange` counts a timeout as a failure, and
three failures park a server for `COOLDOWN`. So a sweep that asked with anything
less than `g.timeout` would mark down a member for being asked impatiently -
answering well inside what its group allows - and three queries later the spare
this whole change exists to keep would be out of the group. Which is how the
first version of the bound was wrong: it divided the timeout between the members
it had left.

A member that answers at three quarters of the timeout, asked four times: the
assertion is that it is still in the group at the end, and that its answer is
what the client got.
*/
@(test)
test_a_slow_member_the_sweep_reaches_is_not_marked_down :: proc(t: ^testing.T) {
	refusing := Canned_Mock{}
	ref, ref_thread, ref_ok := start_canned_mock(t, &refusing, "refusing", canned_reply(0, .Refused))
	if !ref_ok {
		return
	}
	defer {
		sync.atomic_store(&refusing.stop, true)
		thread.join(ref_thread)
		thread.destroy(ref_thread)
		net.close(refusing.socket)
		destroy(ref)
	}

	TIMEOUT :: 400 * time.Millisecond
	slow := Canned_Mock {
		delay = 300 * time.Millisecond,
	}
	good, good_thread, good_ok := start_canned_mock(t, &slow, "slow", canned_reply(0))
	if !good_ok {
		return
	}
	defer {
		sync.atomic_store(&slow.stop, true)
		thread.join(good_thread)
		thread.destroy(good_thread)
		net.close(slow.socket)
		destroy(good)
	}

	servers := make([]^Upstream, 2, context.allocator)
	defer delete(servers, context.allocator)
	servers[0] = ref
	servers[1] = good

	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}

	wire := canned_query()
	testing.expect(t, len(wire) > dns.HEADER_SIZE, "the query did not encode")

	for i in 0 ..< FAILURE_THRESHOLD + 1 {
		resp, winner, err := resolve_readable(&g, wire, context.allocator)
		testing.expect_value(t, err, Error.None)
		testing.expectf(
			t,
			winner == good && dns.peek_rcode(resp) == .No_Error,
			"query %d did not reach the slow member, which answers inside the group's timeout",
			i,
		)
		delete(resp, context.allocator)
	}

	testing.expect(
		t,
		healthy(good),
		"the slow member was parked for answering inside the timeout its group allows",
	)
	testing.expect_value(t, stats_of(good).failures, u64(0))
}
