package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
Whether an answer carries an OPT record at all, which is a fact about the
request and not about the answer.

RFC 6891 section 6.1.1: "An OPT RR MUST NOT be cached, forwarded, or stored in
or loaded from Zone Master Files." Answers pass through this server as the bytes
they arrived as, so an upstream's OPT record rides along in them - and
`cache.make_key` keys on the question plus DO and CD, which does not include
whether the client sent an OPT at all. One entry therefore answers clients on
both sides of that question, and whichever of the two filled it decided what the
other one got.

Both directions are wrong and they are wrong in different ways. A client that
never negotiated EDNS gets a record for an extension it did not ask about, which
is what the RFC forbids. A client that did negotiate it gets no record, so the
answer says nothing about the payload size this server can deliver -
`advertise_udp_size` has no field to write the ceiling into - and the guarantee
`udp_size_test.odin` pins has a hole in it for exactly as long as a non-EDNS
client asked first.

`match_client_opt` settles both on the way out. These cases go through
`handle_query` with the cache on, one per direction, and the forwarded path is
pinned beside them: the strip is not a cache-only concern, an upstream that
answers a query with an OPT record it never asked for reaches a client the same
way.
*/

@(private = "file")
QNAME :: "www.example.com."

@(private = "file")
CLIENT_ID :: u16(0x5151)

// The one address the mock answers with, so a mangled answer is a visible one.
@(private = "file")
ANSWER_ADDR := [4]u8{192, 0, 2, 7}

// Larger than the shipped ceiling, so the client's figure and this server's are
// never the same number.
@(private = "file")
CLIENT_ADVERTISED :: u16(4096)

@(private = "file")
client_query :: proc(edns: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = CLIENT_ID,
		question = questions,
	}
	msg.flags.rd = true

	if edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(CLIENT_ADVERTISED, false)
		msg.additional = additional
	}

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
The mock's answer, with an OPT record of its own or without one.

Which of the two a real upstream sends follows the query it was asked with, and
the query this server forwards carries the client's own OPT record or no OPT at
all - so the two shapes here are the two an upstream answers with, one per
client. The mock is told which rather than reading the query, so that a test can
name the shape it is pinning.
*/
@(private = "file")
mock_reply :: proc(edns: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
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
		data  = dns.Rdata_A{addr = ANSWER_ADDR},
	}

	msg := dns.Message {
		id       = CLIENT_ID,
		question = questions,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true

	if edns {
		// The upstream's own figure, which is neither the client's nor this
		// server's ceiling.
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(4096, false)
		msg.additional = additional
	}

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
Exchange :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	got:    bool,
}

@(private = "file")
serve_one :: proc(x: ^Exchange) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.got = true

	out: [4096]u8
	copy(out[:], x.reply)
	// Echo the ID it was asked with: the forwarded query carries one of ours.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
Harness :: struct {
	socket:  net.UDP_Socket,
	cfg:     config.Config,
	group:   ^upstream.Group,
	answers: ^cache.Cache,
	srv:     Server,
}

@(private = "file")
harness_start :: proc(t: ^testing.T, h: ^Harness, caching := true) -> bool {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return false
	}
	h.socket = socket
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return false
	}

	h.cfg = config.default_config()
	h.cfg.log.queries = false
	h.cfg.cache.enabled = caching
	h.cfg.blocking.enabled = false
	h.cfg.dnssec.enabled = false
	h.cfg.cookies.enabled = false
	h.cfg.upstream.strategy = .Failover
	h.cfg.upstream.attempts = 1
	h.cfg.upstream.timeout = 5 * time.Second

	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	h.cfg.upstream.servers = servers

	group, gerr := upstream.make_group(h.cfg.upstream, nil, context.allocator, false)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		return false
	}
	h.group = group

	h.answers = cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	h.srv = Server {
		cfg     = &h.cfg,
		group   = h.group,
		answers = h.answers,
	}
	return true
}

@(private = "file")
harness_stop :: proc(h: ^Harness) {
	cache.destroy(h.answers)
	upstream.destroy_group(h.group)
	net.close(h.socket)
}

// One query through the server with the mock upstream answering it in the shape
// `upstream_edns` names.
@(private = "file")
forward_once :: proc(
	t: ^testing.T,
	h: ^Harness,
	query: []u8,
	upstream_edns: bool,
) -> (
	out: []u8,
	ok: bool,
) {
	x := Exchange {
		socket = h.socket,
		reply  = mock_reply(upstream_edns),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one)
	response, outcome, served := handle_query(&h.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return nil, false
	}
	if !testing.expect(t, served, "the query went unanswered") {
		return nil, false
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)
	return response, true
}

// The answer still says what it said, whatever happened to its OPT record.
@(private = "file")
expect_the_answer_survived :: proc(t: ^testing.T, m: dns.Message, label: string) {
	if !testing.expectf(t, len(m.answer) == 1, "%s: the answer section holds %d records, not 1", label, len(m.answer)) {
		return
	}
	testing.expectf(t, m.answer[0].type == .A, "%s: the answer is a %v", label, m.answer[0].type)
	addr, is_a := m.answer[0].data.(dns.Rdata_A)
	if !testing.expectf(t, is_a, "%s: the answer's RDATA did not survive", label) {
		return
	}
	testing.expectf(t, addr.addr == ANSWER_ADDR, "%s: the address came back as %v", label, addr.addr)
	testing.expectf(t, m.id == CLIENT_ID, "%s: the answer carries ID %d", label, m.id)
	testing.expectf(t, len(m.question) == 1, "%s: the question did not come back", label)
}

/*
An EDNS client fills the entry; a client that sent no OPT record then hits it and
gets none back.

The direction with a line in the RFC against it: without this the second client
is handed the first one's OPT record, advertising a payload size it never asked
about, which a strict stub is entitled to read as a malformed reply.
*/
@(test)
test_a_cached_answer_gives_a_non_edns_client_no_opt :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	// The EDNS client's own answer carries an OPT record reporting the ceiling,
	// which is what the entry is then holding.
	filled, filled_ok := forward_once(t, &h, client_query(true), true)
	if !filled_ok {
		return
	}
	testing.expect_value(t, int(dns.peek_udp_size(filled)), config.DEFAULT_MAX_UDP_RESPONSE)

	hit, outcome, ok := handle_query(&h.srv, client_query(false), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the cached query went unanswered")
	testing.expect_value(t, outcome, Outcome.Cached)

	m, derr := dns.decode_message(hit, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(m), "a cached OPT record crossed to a client that sent none")
	expect_the_answer_survived(t, m, "the cached answer")

	free_all(context.temp_allocator)
}

/*
And the other way round: a non-EDNS client fills the entry, and the EDNS client
behind it is still told what this server can deliver.

This is the half that undercuts #106. `dns.set_edns_udp_size` reports false and
leaves the message alone when there is no OPT record to write into, which is
right for a client that asked without EDNS and wrong here - this client did ask
with EDNS, and would otherwise get an answer saying nothing about the payload
size purely because a non-EDNS client happened to ask first. A downstream
forwarder reading no OPT falls back to 512 and pays for the TC bits and TCP
retries #104 was about.
*/
@(test)
test_a_cached_answer_gives_an_edns_client_the_ceiling :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	// Filled by a client that sent no OPT record, so the upstream answered
	// without one and that is what the entry holds.
	filled, filled_ok := forward_once(t, &h, client_query(false), false)
	if !filled_ok {
		return
	}
	bare, bare_err := dns.decode_message(filled, context.temp_allocator)
	testing.expect_value(t, bare_err, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(bare), "the non-EDNS client was given an OPT record")

	hit, outcome, ok := handle_query(&h.srv, client_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the cached query went unanswered")
	testing.expect_value(t, outcome, Outcome.Cached)

	m, derr := dns.decode_message(hit, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, dns.edns_present(m), "an EDNS client got a cached answer with no OPT record") {
		testing.expect_value(t, int(dns.peek_udp_size(hit)), config.DEFAULT_MAX_UDP_RESPONSE)
		testing.expect(t, !dns.edns_do(m), "a minted OPT record claims DO over an unsigned answer")
	}
	expect_the_answer_survived(t, m, "the cached answer")

	free_all(context.temp_allocator)
}

/*
The strip is not a cache-only concern.

An upstream that answers with an OPT record the client never asked for is
forwarding one to that client too - the same sentence of RFC 6891, reached with
the cache off - so the rule is applied to the answer in hand rather than to where
it came from.
*/
@(test)
test_a_forwarded_answer_gives_a_non_edns_client_no_opt :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = false) {
		return
	}
	defer harness_stop(&h)

	out, ok := forward_once(t, &h, client_query(false), true)
	if !ok {
		return
	}

	m, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(m), "an upstream's OPT record reached a client that sent none")
	expect_the_answer_survived(t, m, "the forwarded answer")

	free_all(context.temp_allocator)
}
