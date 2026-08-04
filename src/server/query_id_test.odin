package server

import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:upstream"

/*
The transaction ID a forwarded query carries is ours, not the client's.

RFC 5452 section 9.2. On a plain UDP upstream the ID is half of what stops an
off-path attacker from having a forged datagram accepted as the upstream's
answer: the source and destination addresses are known, the question is the one
the attacker asked for, and what is left to guess is our ephemeral source port
and the ID. Forwarding the client's own ID hands one of those two away to
whoever sent the query, and the search space collapses from about 2^31 to the
port alone.

Driven through `handle_query` against a real socket rather than against the
rewriting procedures directly, because the defect was not in any one of them:
each path builds the outgoing query correctly, and none of them was replacing
the ID. So all three are exercised here - a plain forward, the DNSSEC rewrite,
and the one that strips a client cookie - and what is asserted is what arrived
at the far end.
*/

// Enough draws that a fixed or counting ID cannot pass by chance, and few
// enough that 16-bit collisions stay unlikely.
@(private = "file")
DRAWS :: 32

// The ID the client asks with throughout. Any value does; this one is easy to
// spot in a failure message.
@(private = "file")
CLIENT_ID :: u16(0x4242)

@(private = "file")
Exchange :: struct {
	socket:       net.UDP_Socket,
	reply:        []u8,
	// The ID the query arrived with, and whether a query arrived at all.
	forwarded_id: u16,
	got:          bool,
}

/*
Serve exactly one query, recording the ID it came with.

One query per thread, joined by the caller before it looks at the result: there
is no shared state to guard, and a query that never arrives leaves `got` false
rather than hanging the suite - the socket carries a receive timeout.
*/
@(private = "file")
serve_one :: proc(x: ^Exchange) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.forwarded_id = u16(buf[0]) << 8 | u16(buf[1])
	x.got = true

	out: [4096]u8
	copy(out[:], x.reply)
	// Echo the ID it was asked with, so the reply is accepted as the answer to
	// it whatever that ID turns out to be.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
QNAME :: "www.example.com."

// The answer the mock upstream gives, for the question every case here asks.
@(private = "file")
mock_reply :: proc() -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_A{addr = {93, 184, 216, 34}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = QNAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = CLIENT_ID,
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

/*
A query as a client sends it.

`cookie` puts a COOKIE option in the OPT record, which is what sends the
forwarding path through `remove_edns_option` - one of the three ways the
outgoing buffer comes about.
*/
@(private = "file")
id_client_query :: proc(cookie := false) -> []u8 {
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

	if cookie {
		client_half := make([]u8, 8, context.temp_allocator)
		for i in 0 ..< len(client_half) {
			client_half[i] = u8(0xa0 + i)
		}
		options := make([]dns.EDNS_Option, 1, context.temp_allocator)
		options[0] = dns.EDNS_Option {
			code = u16(dns.EDNS_Option_Code.Cookie),
			data = client_half,
		}
		opt := dns.make_opt(1232, false)
		opt.data = dns.Rdata_OPT{options = options}

		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = opt
		msg.additional = additional
	}

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
A validator that can fetch nothing.

The verdict is not what these cases are about, and the chain for a name the mock
invented could not be built from anything it would answer. Refusing to fetch
makes the answer indeterminate straight away, which is the quick way to reach
the assertion: what went out on the wire before any of that happened.
*/
@(private = "file")
no_chain :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	return nil, false
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
harness_start :: proc(t: ^testing.T, h: ^Harness, validating := false) -> bool {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return false
	}
	h.socket = socket
	// A query that never comes must not stall the run; the upstream timeout
	// below is longer, so a real exchange is never cut short by this.
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return false
	}

	h.cfg = config.default_config()
	h.cfg.log.queries = false
	// Every query has to reach the upstream for the ID it carried to be seen.
	h.cfg.cache.enabled = false
	h.cfg.blocking.enabled = false
	h.cfg.dnssec.enabled = validating
	h.cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
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

	// Cookies towards the upstream are a separate mechanism and would add an
	// option to the outgoing query; they have nothing to do with the ID.
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
	if validating {
		h.srv.validator = dnssec.make_validator(no_chain, nil, dnssec.Options{})
	}
	return true
}

@(private = "file")
harness_stop :: proc(h: ^Harness) {
	if h.srv.validator != nil {
		dnssec.destroy_validator(h.srv.validator)
		h.srv.validator = nil
	}
	cache.destroy(h.answers)
	upstream.destroy_group(h.group)
	net.close(h.socket)
}

/*
Put one query through the server and report the ID the upstream saw.

The mock is started before the query and joined after it, rather than left
running: it reads the reply bytes out of this test's scratch arena.
*/
@(private = "file")
forward_once :: proc(
	t: ^testing.T,
	h: ^Harness,
	query: []u8,
) -> (
	forwarded_id: u16,
	response: []u8,
	outcome: Outcome,
	ok: bool,
) {
	x := Exchange {
		socket = h.socket,
		reply  = mock_reply(),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one)
	out, result, served := handle_query(&h.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return 0, nil, result, false
	}
	return x.forwarded_id, out, result, served
}

@(test)
test_forwarded_query_id_is_not_the_client_id :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	seen: map[u16]bool
	defer delete(seen)

	for i in 0 ..< DRAWS {
		query := id_client_query()
		forwarded_id, out, outcome, ok := forward_once(t, &h, query)
		if !ok {
			return
		}
		testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
		testing.expectf(
			t,
			forwarded_id != CLIENT_ID,
			"draw %d: the upstream was asked with the client's own transaction id %04x",
			i,
			forwarded_id,
		)
		seen[forwarded_id] = true

		// The client is waiting on the ID it wrote, so that is what comes back.
		id, id_ok := dns.peek_id(out)
		testing.expect(t, id_ok, "the response is too short to carry an id")
		testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	}

	/*
	Distinctness is what makes the ID worth anything: a single fresh value
	reused for every query afterwards is as good as the client's to an attacker
	who has seen one answer. 32 draws from 16 bits collide about 0.8% of the
	time, so a couple of repeats is not a failure - a handful is.
	*/
	testing.expectf(
		t,
		len(seen) >= DRAWS - 2,
		"only %d distinct transaction ids across %d queries",
		len(seen),
		DRAWS,
	)
	free_all(context.temp_allocator)
}

@(test)
test_forwarded_query_id_is_replaced_on_the_dnssec_path :: proc(t: ^testing.T) {
	// The DNSSEC rewrite re-encodes the client's message to set CD and DO, and
	// carried its ID across with everything else.
	h: Harness
	if !harness_start(t, &h, validating = true) {
		return
	}
	defer harness_stop(&h)

	forwarded_id, out, _, ok := forward_once(t, &h, id_client_query())
	if !ok {
		return
	}
	testing.expectf(
		t,
		forwarded_id != CLIENT_ID,
		"the rewritten query kept the client's transaction id %04x",
		forwarded_id,
	)
	/*
	And the client still hears its own ID back, on a path that answers from
	somewhere else entirely: the chain cannot be built, so this is the SERVFAIL
	that `dnssec_failure_response` composes rather than the upstream's answer
	with its ID corrected. A reply carrying the wrong ID is not a failure a
	client can see - it is dropped as unsolicited, and the query waits out its
	whole timeout instead.
	*/
	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	free_all(context.temp_allocator)
}

@(test)
test_forwarded_query_id_is_replaced_when_the_cookie_is_stripped :: proc(t: ^testing.T) {
	// A third buffer: the client's message with its COOKIE option taken out.
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	query := id_client_query(cookie = true)
	forwarded_id, out, outcome, ok := forward_once(t, &h, query)
	if !ok {
		return
	}
	testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
	testing.expectf(
		t,
		forwarded_id != CLIENT_ID,
		"the cookie-stripped query kept the client's transaction id %04x",
		forwarded_id,
	)
	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == CLIENT_ID, "the client got id %04x back, not its own %04x", id, CLIENT_ID)
	free_all(context.temp_allocator)
}
