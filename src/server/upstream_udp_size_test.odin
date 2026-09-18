package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
The EDNS payload size this server advertises upstream is its own.

RFC 6891 section 6.2.5 makes that field a statement by whoever sends the
message: on a query it says how large a datagram the *sender* is prepared to
receive. Forwarded verbatim it says something about the client instead, and the
client is anonymous - so any of them can decide that the answers arriving at
this server should be 65000 bytes of fragmented UDP. The second fragment carries
neither port nor transaction ID, which is the precondition every fragment-based
poisoning of a forwarder rests on, and the poisoned reply is then cached and
served to everyone behind it.

So the two bytes are rewritten on the way out, to the DNS Flag Day 2020 figure
(RFC 9715) that dnsmasq, Unbound, BIND and dnsproxy all send. TC and the TCP
retry in `upstream/plain.odin` are what fetch an answer that no longer fits.

Asserted on the query the upstream received, because that is the only place the
number is observable - the same reasoning `extended_rcode_test.odin` gives for
the transaction ID and the extended rcode beside it.
*/

@(private = "file")
QNAME :: "www.example."

@(private = "file")
CLIENT_ID :: u16(0x5151)

@(private = "file")
Seen_Query :: struct {
	socket:   net.UDP_Socket,
	got:      bool,
	// The query as it arrived. Read after the thread is joined.
	seen:     [1024]u8,
	seen_len: int,
}

// Serve exactly one query with an answer built from it, and keep what arrived.
@(private = "file")
serve_one :: proc(x: ^Seen_Query) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE {
		return
	}
	x.got = true
	x.seen_len = copy(x.seen[:], buf[:n])

	reply := answer_reply()
	out: [4096]u8
	if len(reply) > len(out) {
		return
	}
	copy(out[:], reply)
	// Echo the ID it was asked with: the resolver draws a fresh one for every
	// query it forwards, so nothing here can know it in advance.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(reply)], remote)
}

// The client's question, advertising `advertised` bytes of room - or asking
// without EDNS at all, which has no field to advertise in and is held to 512.
@(private = "file")
client_query :: proc(advertised: u16, edns := true) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = CLIENT_ID,
		question = question,
	}
	msg.flags.rd = true
	if edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(advertised, false)
		msg.additional = additional
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
answer_reply :: proc() -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_A{addr = {192, 0, 2, 7}},
	}
	msg := dns.Message {
		question = question,
		answer   = answer,
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

// A forwarding server with nothing between the client and the upstream, and no
// validator: `dnssec_upstream_query` is not what rewrites the size here, and a
// query with CD=1 or a routed zone would not reach it even with one running.
@(private = "file")
forwarding_server :: proc(
	t: ^testing.T,
) -> (
	s: Server,
	cfg: ^config.Config,
	x: ^Seen_Query,
	ok: bool,
) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return {}, nil, nil, false
	}
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		net.close(socket)
		return {}, nil, nil, false
	}

	specs := make([]config.Upstream_Spec, 1, context.temp_allocator)
	specs[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg = new(config.Config, context.temp_allocator)
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	cfg.upstream.servers = specs

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		net.close(socket)
		return {}, nil, nil, false
	}
	x = new(Seen_Query, context.temp_allocator)
	x.socket = socket
	return Server{cfg = cfg, group = group}, cfg, x, true
}

// Forward one query and hand back the payload size the upstream was asked with.
@(private = "file")
forward_and_read_size :: proc(t: ^testing.T, query: []u8) -> (advertised: u16, ok: bool) {
	s, _, x, built := forwarding_server(t)
	if !built {
		return 0, false
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	mock := thread.create_and_start_with_poly_data(x, serve_one)
	out, outcome, answered := handle_query(&s, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return 0, false
	}
	// The exchange has to have worked, or the size below is the size of a query
	// that went nowhere.
	testing.expect(t, answered, "nothing came back at all")
	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)
	return dns.peek_udp_size(x.seen[:x.seen_len]), true
}

/*
The reproducer: a client advertising 65000, and what the upstream is told.

65000 is a figure no stub has any business sending and every stub is free to
send - `dig +bufsize` caps itself, so the report that found this used a raw
socket, and so does this by building the message directly.
*/
@(test)
test_a_clients_edns_payload_size_is_not_forwarded_upstream :: proc(t: ^testing.T) {
	query := client_query(65000)
	if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
		return
	}
	// The premise, read the same way the assertion below reads the forwarded
	// copy: the client really did ask for 65000.
	testing.expect_value(t, dns.peek_udp_size(query), u16(65000))

	advertised, ok := forward_and_read_size(t, query)
	if !ok {
		return
	}
	// The literal rather than `UPSTREAM_UDP_SIZE`: the figure is RFC 9715's and
	// a case reading the constant back would pass at any value the constant
	// took, including the 4096 this is here to have moved off.
	testing.expectf(
		t,
		advertised == 1232,
		"the upstream was told it could send %d bytes rather than the flag-day 1232",
		advertised,
	)

	free_all(context.temp_allocator)
}

/*
And a client that asked for less is not overruled upward.

The rewrite is a ceiling, not a number this server insists on: there is nothing
to gain from asking an upstream for more room than the answer going back to the
client may use, and a stub advertising 512 is often one behind a path that could
not carry more. 512 also happens to be what a query carrying no OPT record at
all is held to, and this is the same case reached with a field to read.
*/
@(test)
test_a_smaller_client_payload_size_is_left_alone :: proc(t: ^testing.T) {
	query := client_query(512)
	if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
		return
	}
	testing.expect_value(t, dns.peek_udp_size(query), u16(512))

	advertised, ok := forward_and_read_size(t, query)
	if !ok {
		return
	}
	testing.expectf(
		t,
		advertised == 512,
		"the upstream was told it could send %d bytes to answer a query that asked for 512",
		advertised,
	)

	free_all(context.temp_allocator)
}

/*
The validating path writes the same figure.

`dnssec_upstream_query` builds its own OPT record rather than passing the
client's on, so it never depended on the rewrite above - and before this it was
the one path that was safe, at 4096, which is still past the flag-day figure and
still fragments on an ordinary 1500-byte path.
*/
@(test)
test_the_validating_rewrite_advertises_the_flag_day_size :: proc(t: ^testing.T) {
	query := client_query(65000)
	msg, derr := dns.decode_message(query, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}

	wire, ok := dnssec_upstream_query(msg, context.temp_allocator)
	if !testing.expect(t, ok, "the validating rewrite did not encode") {
		return
	}
	testing.expectf(
		t,
		dns.peek_udp_size(wire) == 1232,
		"the validating path advertises %d bytes upstream rather than the flag-day 1232",
		dns.peek_udp_size(wire),
	)
	// And it is still the query it was: DO and CD set, the question intact.
	out, oerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, oerr, dns.Decode_Error.None)
	testing.expect(t, out.flags.cd, "the validating rewrite lost CD")
	testing.expect(t, dns.edns_do(out), "the validating rewrite lost DO")
	if testing.expect(t, len(out.question) == 1, "the validating rewrite lost the question") {
		testing.expect(t, dns.name_equal_fold(out.question[0].name, QNAME), "the question changed")
	}

	free_all(context.temp_allocator)
}

/*
And it cannot push the figure below 512 either.

RFC 6891 section 6.2.3 has a responder treat anything under 512 as 512, so a
smaller number buys a client nothing on the receiving end - but written out it is
the cap's lever pointed the other way: zero advertised, and every upstream answer
over 512 bytes comes back truncated and is re-fetched over TCP. One unsigned
datagram in, an upstream connection out, for as long as the client cares to send
them.

Zero rather than some other small number because it is the figure the lever is
worth most at, and because an OPT record is entitled to carry it: the field is
two bytes wide and nothing about the wire forbids it.
*/
@(test)
test_a_client_cannot_push_the_upstream_payload_size_below_512 :: proc(t: ^testing.T) {
	query := client_query(0, edns = true)
	if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
		return
	}
	// The premise: an OPT record really is there, advertising zero - not a query
	// that went out without one.
	testing.expect_value(t, dns.peek_udp_size(query), u16(0))
	msg, derr := dns.decode_message(query, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, dns.edns_present(msg), "the fixture lost its opt record")

	advertised, ok := forward_and_read_size(t, query)
	if !ok {
		return
	}
	testing.expectf(
		t,
		advertised == 512,
		"the upstream was told it could send %d bytes, which is the client's figure below the floor",
		advertised,
	)

	free_all(context.temp_allocator)
}

/*
And a client cannot carry a second payload size upstream in a section this
server does not read.

`find_opt`, `find_opt_span` and `edns_opt_readable` all read the additional
section alone - RFC 6891 section 6.1.1 is where the record belongs - and a client
may put a record of type OPT in its answer section for the asking. Two things
went wrong with that. `peek_udp_size` used to walk every section and return the
first record it met, so the decoy was what this rewrite and the receive buffer in
`upstream/plain.odin` both read while the real record went out saying whatever
the decoy said; that is fixed in the codec, and `dns.test_peek_udp_size_reads_the_opt_record`
holds it. And the decoy itself was forwarded, so an upstream reading the first
OPT *it* met - which is exactly what this server did until #325 - would answer
the client's 65000 whatever this server wrote in the record it does read.

The second is what this case is about, and the gate that already refuses the two
other EDNS shapes this server cannot account for is where it is settled: FORMERR,
and the query is not forwarded at all.
*/
@(test)
test_a_query_carrying_an_opt_outside_the_additional_section_is_refused :: proc(t: ^testing.T) {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.make_opt(65000, false)
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	msg := dns.Message {
		id         = CLIENT_ID,
		question   = question,
		answer     = answer,
		additional = additional,
	}
	msg.flags.rd = true
	query, _, werr := dns.encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, werr, dns.Encode_Error.None) {
		return
	}
	// The premise: the message carries both records, and the one the codec
	// reports is the one in the additional section.
	testing.expect_value(t, dns.peek_udp_size(query), u16(1232))
	if opt, had := dns.find_opt(msg); testing.expect(t, had, "the fixture lost its real opt record") {
		// An OPT record carries the payload size where every other type carries
		// its class.
		testing.expect_value(t, u16(opt.class), u16(1232))
	}

	s, _, x, built := forwarding_server(t)
	if !built {
		return
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	// No mock thread: nothing may be forwarded, and `mock_untouched` reads the
	// socket after the call has returned rather than racing it.
	out, outcome, answered := handle_query(&s, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, mock_untouched(x.socket), "the decoy was forwarded to the upstream")
	if !testing.expect(t, answered, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expectf(
		t,
		dns.peek_rcode(out) == .Form_Err,
		"the client was handed %v rather than FORMERR",
		dns.peek_rcode(out),
	)
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, decoded.id, CLIENT_ID)

	free_all(context.temp_allocator)
}
