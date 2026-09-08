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
What is written *inside* an answer's OPT record, which is this server's own
statement and not the upstream's.

`edns_presence_test.odin` pins whether a record goes back at all. This file pins
what the record that goes back says, which is the other half of RFC 6891 section
6.1.1 - "An OPT RR MUST NOT be cached, forwarded, or stored in or loaded from
Zone Master Files." An answer passes through this server as the bytes it arrived
as, so an upstream's OPT record rides along inside it: the options it wrote, the
EDNS version it answered in, and the flag bits it set.

Three things cross that way and none of them is about this client:

  - the options. NSID names the upstream instance that answered a question this
    client never asked, and the cache hands the same bytes to every client that
    hits the entry for as long as it lives.
  - the version. RFC 6891 section 6.1.3 makes VERSION the responder's own
    statement, and this server is the responder for the answer it sends. It
    refuses a *query* asking in a version it does not implement with BADVERS;
    passing an upstream's version on is that rule not held to by the server that
    holds requestors to it.
  - the DO bit. RFC 3225 section 3: "The DO bit of the query MUST be copied in
    the response." What arrives is the upstream's copy of the bit *this server*
    sent it, which is not the bit the client sent.

The options this server writes itself are a different thing and stay: an
extended DNS error explains a refusal to the client that caused it, and it is
attached before `match_client_opt` runs. `extended_rcode_test.odin` pins that
one reaching the client, and the strip here is confined to answers that came
from an upstream so that it keeps doing so.
*/

@(private = "file")
QNAME :: "contents.example.com."

@(private = "file")
CLIENT_ID :: u16(0x6262)

@(private = "file")
ANSWER_ADDR := [4]u8{192, 0, 2, 9}

/*
The NSID the mock upstream reports.

NSID is the sharpest of the options to pin because it has no reading at all as a
statement by this server: RFC 5001 makes it the identity of the instance that
answered, so a copy of it in an answer from here names a machine that never
spoke to this client.
*/
@(private = "file")
UPSTREAM_NSID :: "probe-upstream"

// The client's own advertised buffer, larger than the shipped ceiling so that
// its figure and this server's are never the same number.
@(private = "file")
CLIENT_ADVERTISED :: u16(4096)

/*
An OPT record built field by field rather than through `dns.make_opt`, which
states version 0 and takes no options - the two things every case here needs to
vary.

The TTL is the three windows onto one number RFC 6891 section 6.1.3 defines: the
extended rcode in the top byte, the version below it, and sixteen flag bits with
DO at the top of them. The extended rcode is left at zero throughout; an answer
carrying one never reaches the client at all (`unreadable_rcode_refusal`), and
`extended_rcode_test.odin` is where that is pinned.
*/
@(private = "file")
opt_record :: proc(udp_size: u16, version: u8, do_bit: bool, options: []dns.EDNS_Option) -> dns.Record {
	ttl := u32(version) << 16
	if do_bit {
		ttl |= 0x0000_8000
	}
	return dns.Record {
		name  = ".",
		type  = .OPT,
		class = dns.Class(udp_size),
		ttl   = ttl,
		data  = dns.Rdata_OPT{options = options},
	}
}

@(private = "file")
client_query :: proc(do_bit := false) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	// Version 0 and no options: the client asks in the one version this server
	// implements, and asks for nothing else.
	additional[0] = opt_record(CLIENT_ADVERTISED, 0, do_bit, nil)

	msg := dns.Message {
		id         = CLIENT_ID,
		question   = questions,
		additional = additional,
	}
	msg.flags.rd = true

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
The mock's answer, carrying an OPT record that says what a real upstream's says:
its own version, its own flag bits, and whatever options it chose to write.
*/
@(private = "file")
mock_reply :: proc(version: u8, do_bit: bool, options: []dns.EDNS_Option) -> []u8 {
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
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt_record(4096, version, do_bit, options)

	msg := dns.Message {
		id         = CLIENT_ID,
		question   = questions,
		answer     = answer,
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

// An upstream reply carrying nothing but an NSID, which is the measured case.
@(private = "file")
nsid_reply :: proc() -> []u8 {
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option {
		code = u16(dns.EDNS_Option_Code.NSID),
		data = transmute([]u8)string(UPSTREAM_NSID),
	}
	return mock_reply(0, false, options)
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

// One query through the server, with the mock answering it once.
@(private = "file")
forward_once :: proc(t: ^testing.T, h: ^Harness, query: []u8, reply: []u8) -> (out: []u8, ok: bool) {
	x := Exchange {
		socket = h.socket,
		reply  = reply,
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
	addr, is_a := m.answer[0].data.(dns.Rdata_A)
	if !testing.expectf(t, is_a, "%s: the answer's RDATA did not survive", label) {
		return
	}
	testing.expectf(t, addr.addr == ANSWER_ADDR, "%s: the address came back as %v", label, addr.addr)
	testing.expectf(t, m.id == CLIENT_ID, "%s: the answer carries ID %d", label, m.id)
	testing.expectf(t, len(m.question) == 1, "%s: the question did not come back", label)
}

// Every option the answer's OPT record carries, so a case can name what it found
// rather than only that it found something.
@(private = "file")
options_of :: proc(m: dns.Message) -> []dns.EDNS_Option {
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		return rdata.options
	}
	return nil
}

@(private = "file")
expect_no_upstream_options :: proc(t: ^testing.T, wire: []u8, label: string) -> (m: dns.Message, ok: bool) {
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "%s did not decode: %v", label, derr) {
		return {}, false
	}
	if !testing.expectf(t, dns.edns_present(decoded), "%s carries no OPT record", label) {
		return decoded, false
	}
	for o in options_of(decoded) {
		testing.expectf(
			t,
			false,
			"%s carries EDNS option %d (%q), which the upstream put there",
			label,
			o.code,
			string(o.data),
		)
	}
	return decoded, true
}

/*
An upstream's option does not reach the client that hits the entry it filled.

The measured case: the mock reports NSID `probe-upstream`, one EDNS client fills
the cache with the answer carrying it, and a second EDNS client hits the entry.
Without the strip the second client is told the identity of a machine that
answered a question it never asked - and is told it for as long as the entry
lives, which is a statement about one exchange repeated over every hit.
*/
@(test)
test_a_cached_answer_carries_no_option_the_upstream_sent :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	filled, filled_ok := forward_once(t, &h, client_query(), nsid_reply())
	if !filled_ok {
		return
	}
	// The forwarded copy first: the entry is filled from the same bytes, so a
	// leak here and a leak on the hit are the same leak seen twice.
	expect_no_upstream_options(t, filled, "the forwarded answer")

	hit, outcome, ok := handle_query(&h.srv, client_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "the cached query went unanswered")
	testing.expect_value(t, outcome, Outcome.Cached)

	m, decoded := expect_no_upstream_options(t, hit, "the cached answer")
	if decoded {
		expect_the_answer_survived(t, m, "the cached answer")
	}

	free_all(context.temp_allocator)
}

/*
And with the cache off, so the strip is a rule about the answer in hand rather
than about where it was kept.

An upstream that writes an option into a reply is writing it into the reply this
server forwards, whether or not anything stored it on the way past.
*/
@(test)
test_a_forwarded_answer_carries_no_option_the_upstream_sent :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = false) {
		return
	}
	defer harness_stop(&h)

	out, ok := forward_once(t, &h, client_query(), nsid_reply())
	if !ok {
		return
	}

	m, decoded := expect_no_upstream_options(t, out, "the forwarded answer")
	if decoded {
		expect_the_answer_survived(t, m, "the forwarded answer")
	}

	free_all(context.temp_allocator)
}

/*
The version and the DO bit are this server's, not the upstream's.

The mock answers in EDNS version 1 with DO set; the client asked in version 0
with DO clear. Both fields are the responder's own statement about the answer it
is sending - RFC 6891 section 6.1.3 for the version, RFC 3225 section 3 for the
bit, which "MUST be copied" from the query - and this server is the responder
here. Forwarded as they arrive, the client is answered in a version it did not
ask in and may not implement, by a server that refuses a *query* in that same
version one screen earlier.
*/
@(test)
test_a_forwarded_answer_states_version_0_and_the_clients_do_bit :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = false) {
		return
	}
	defer harness_stop(&h)

	reply := mock_reply(1, true, nil)
	// The premise, read off the fixture rather than assumed: without this the
	// case could pass against a mock that answered in version 0 all along.
	fixture, ferr := dns.decode_message(reply, context.temp_allocator)
	testing.expect_value(t, ferr, dns.Decode_Error.None)
	testing.expect_value(t, dns.edns_version(fixture), u8(1))
	testing.expect(t, dns.edns_do(fixture), "the fixture's DO bit is clear, so this case tests nothing")

	out, ok := forward_once(t, &h, client_query(do_bit = false), reply)
	if !ok {
		return
	}

	m, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, dns.edns_present(m), "the EDNS client got no OPT record back") {
		testing.expectf(
			t,
			dns.edns_version(m) == 0,
			"the answer states EDNS version %d, which the client did not ask in",
			dns.edns_version(m),
		)
		testing.expect(t, !dns.edns_do(m), "the answer claims DO over a client that asked without it")
	}
	expect_the_answer_survived(t, m, "the forwarded answer")

	free_all(context.temp_allocator)
}

/*
The other direction of the copy rule: a client that did set DO reads it back.

Clearing the bit outright would settle the case above too, and would be wrong
for the same reason passing the upstream's on is - the bit in a response is a
copy of the one in the query and nothing else.
*/
@(test)
test_a_forwarded_answer_copies_a_do_bit_the_client_set :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = false) {
		return
	}
	defer harness_stop(&h)

	// The upstream answers with DO clear, so the bit the client reads back can
	// only have come from its own query.
	out, ok := forward_once(t, &h, client_query(do_bit = true), mock_reply(0, false, nil))
	if !ok {
		return
	}

	m, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, dns.edns_present(m), "the EDNS client got no OPT record back") {
		testing.expect(t, dns.edns_do(m), "the client set DO and was answered with it clear")
	}
	expect_the_answer_survived(t, m, "the forwarded answer")

	free_all(context.temp_allocator)
}
