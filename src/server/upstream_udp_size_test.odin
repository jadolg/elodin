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
// validator, so the query is the plain path's.
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

	group, gerr := upstream.make_group(cfg.upstream, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		net.close(socket)
		return {}, nil, nil, false
	}
	x = new(Seen_Query, context.temp_allocator)
	x.socket = socket
	return Server{cfg = cfg, group = group}, cfg, x, true
}

// Forward one query and hand back what the upstream was asked, and the answer.
@(private = "file")
forward_and_see :: proc(t: ^testing.T, query: []u8) -> (seen: []u8, out: []u8, ok: bool) {
	s, _, x, built := forwarding_server(t)
	if !built {
		return nil, nil, false
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	mock := thread.create_and_start_with_poly_data(x, serve_one)
	reply, outcome, answered := handle_query(&s, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return nil, nil, false
	}
	// The exchange has to have worked, or what was seen is a query that went
	// nowhere.
	testing.expect(t, answered, "nothing came back at all")
	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(reply), dns.Rcode.No_Error)
	seen = make([]u8, x.seen_len, context.temp_allocator)
	copy(seen, x.seen[:x.seen_len])
	return seen, reply, true
}

// Forward one query and hand back the payload size the upstream was asked with.
@(private = "file")
forward_and_read_size :: proc(t: ^testing.T, query: []u8) -> (advertised: u16, ok: bool) {
	seen, _ := forward_and_see(t, query) or_return
	return dns.peek_udp_size(seen), true
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
And a client that asked for less, or without EDNS at all, is asked for with the
same figure: it says what this server can receive (RFC 6891 section 6.2.5), and
the answer is fitted to the client on the way back as a cached one is. Asking
for 512 instead turns every answer over it into a TC=1 and a TCP retry upstream.
*/
@(test)
test_a_smaller_client_payload_size_is_asked_for_with_ours :: proc(t: ^testing.T) {
	for query in ([][]u8{client_query(512), client_query(0, edns = false)}) {
		if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
			return
		}
		advertised, ok := forward_and_read_size(t, query)
		if !ok {
			return
		}
		testing.expectf(t, advertised == 1232, "the upstream was told it could send %d bytes rather than 1232", advertised)
	}

	free_all(context.temp_allocator)
}

/*
The validating query writes the same figure, with DO and CD set and the
question intact.
*/
@(test)
test_the_validating_query_advertises_the_flag_day_size :: proc(t: ^testing.T) {
	wire, ok := upstream_query({name = QNAME, type = .A, class = .IN}, true, true, context.temp_allocator)
	if !testing.expect(t, ok, "the validating query did not encode") {
		return
	}
	testing.expectf(
		t,
		dns.peek_udp_size(wire) == 1232,
		"the validating path advertises %d bytes upstream rather than the flag-day 1232",
		dns.peek_udp_size(wire),
	)
	out, oerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, oerr, dns.Decode_Error.None)
	testing.expect(t, out.flags.cd, "the validating query lost CD")
	testing.expect(t, dns.edns_do(out), "the validating query lost DO")
	if testing.expect(t, len(out.question) == 1, "the validating query lost the question") {
		testing.expect(t, dns.name_equal_fold(out.question[0].name, QNAME), "the question changed")
	}

	free_all(context.temp_allocator)
}

/*
And it cannot push the figure down either.

Written out, a client's small figure would be a lever: zero advertised, and every
upstream answer over 512 bytes comes back truncated and is re-fetched over TCP.
One unsigned datagram in, an upstream connection out, for as long as the client
cares to send them.

Zero rather than some other small number because it is the figure the lever is
worth most at, and because an OPT record is entitled to carry it: the field is
two bytes wide and nothing about the wire forbids it.
*/
@(test)
test_a_client_cannot_push_the_upstream_payload_size_down :: proc(t: ^testing.T) {
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
		advertised == 1232,
		"the upstream was told it could send %d bytes, which is the client's figure rather than ours",
		advertised,
	)

	free_all(context.temp_allocator)
}

/*
And a client cannot carry a second payload size upstream in a section this
server does not read.

`find_opt`, `find_opt_span` and `edns_opt_readable` all read the additional
section alone - RFC 6891 section 6.1.1 is where the record belongs - and a client
may put a record of type OPT in its answer section for the asking. Two rules
hold against that. The size is read from the additional section's OPT record
alone, so the decoy is not what this rewrite and the receive buffer in
`upstream/plain.odin` read; `dns.test_peek_udp_size_reads_the_opt_record` holds
that in the codec. And the decoy itself is not forwarded, since an upstream
reading the first OPT *it* meets (#325) would answer the client's 65000 whatever
this server wrote in the record it does read.

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

/*
Two queries for one cache key reach the upstream as one message, bar the ID
(issue #423).

Each is as odd as the gates let through, and the two odd in different ways: one
without EDNS, in upper case, with TC, AA, AD and Z set and a record in its
authority section; the other with a 65000-byte OPT record carrying NSID, EXPIRE
and an unknown option and a reserved flag, a second additional record, and bytes
past the last record. The key is the question, DO and CD, which both share, so
the upstream is asked one question - and anything else of the client's that
reached it would be one client choosing what the next is answered with.
*/
@(test)
test_two_queries_for_one_key_reach_the_upstream_as_one_message :: proc(t: ^testing.T) {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = "WWW.Example.",
		type  = .A,
		class = .IN,
	}
	extra := make([]dns.Record, 1, context.temp_allocator)
	extra[0] = dns.Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {198, 51, 100, 1}},
	}
	plain := dns.Message {
		id        = CLIENT_ID,
		question  = question,
		authority = extra,
	}
	plain.flags.rd = true
	plain.flags.tc = true
	plain.flags.aa = true
	plain.flags.ad = true
	plain.flags.z = true
	first, _, ferr := dns.encode_message(plain, context.temp_allocator)
	if !testing.expect_value(t, ferr, dns.Encode_Error.None) {
		return
	}

	options := make([]dns.EDNS_Option, 3, context.temp_allocator)
	options[0] = {code = u16(dns.EDNS_Option_Code.NSID)}
	options[1] = {code = u16(dns.EDNS_Option_Code.Expire)}
	options[2] = {code = 65001, data = {1, 2, 3}}
	opt := dns.make_opt(65000, false)
	opt.ttl |= 0x0001 // a reserved OPT flag
	opt.data = dns.Rdata_OPT{options = options}
	lower := make([]dns.Question, 1, context.temp_allocator)
	lower[0] = {name = QNAME, type = .A, class = .IN}
	additional := make([]dns.Record, 2, context.temp_allocator)
	additional[0] = extra[0]
	additional[1] = opt
	edns := dns.Message {
		id         = CLIENT_ID + 1,
		question   = lower,
		additional = additional,
	}
	edns.flags.rd = true
	encoded, _, eerr := dns.encode_message(edns, context.temp_allocator)
	if !testing.expect_value(t, eerr, dns.Encode_Error.None) {
		return
	}
	second := make([]u8, len(encoded) + 3, context.temp_allocator)
	copy(second, encoded)

	// The premise: one key, two messages that differ past the ID.
	testing.expect(t, string(first[2:]) != string(second[2:]), "the fixtures are one message")

	seen_first, answer, ok := forward_and_see(t, first)
	if !ok {
		return
	}
	seen_second, _, ok2 := forward_and_see(t, second)
	if !ok2 {
		return
	}
	testing.expect(t, string(seen_first[2:]) == string(seen_second[2:]), "the upstream was asked two different messages for one key")

	// And the one message is the key's: the question in lower case, RD alone of
	// the flags, one OPT record of ours with no options, nothing else.
	asked, derr := dns.decode_message(seen_second, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	want := asked
	want.flags = {}
	want.flags.rd = true
	testing.expect_value(t, asked.flags, want.flags)
	testing.expect_value(t, len(asked.answer) + len(asked.authority), 0)
	if testing.expect_value(t, len(asked.question), 1) {
		testing.expect_value(t, asked.question[0].name, QNAME)
	}
	if testing.expect_value(t, len(asked.additional), 1) {
		testing.expect_value(t, asked.additional[0].ttl, u32(0))
		testing.expect_value(t, u16(asked.additional[0].class), u16(1232))
		rdata, is_opt := asked.additional[0].data.(dns.Rdata_OPT)
		if testing.expect(t, is_opt, "the one additional record is not an OPT record") {
			testing.expect_value(t, len(rdata.options), 0)
		}
	}

	// The client in upper case reads its own question back, byte for byte.
	end := dns.HEADER_SIZE + len("\x03WWW\x07Example\x00")
	testing.expect(t, string(answer[dns.HEADER_SIZE:end]) == string(first[dns.HEADER_SIZE:end]), "the answer's question lost the client's case")

	free_all(context.temp_allocator)
}
