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
edns-tcp-keepalive, RFC 7828, in both directions.

Two things are being pinned, and they are opposite halves of the same fact: the
option describes the connection between this client and this server, so it
belongs in the answer that goes back down that connection and nowhere else.

Downwards, the cases below hold the answer to the three conditions
`attach_keepalive` puts on it - the TCP transports and not the datagram or the
HTTP one, a client that asked and not one that did not, and a value that is
`server.client_timeout` rather than a constant that happens to match it today.

Upwards, one case watches a real upstream socket. A client's option relayed
untouched to a UDP upstream is this server sending the shape section 3.2.1
forbids outright, so what that case reads is the bytes that actually left.

Answered from a rewrite rule wherever no upstream is needed, the way
`padding_test.odin` does it: the option under test is then one this server minted
on its own, with nothing in the path that could have echoed it.
*/

@(private = "file")
KEPT :: "kept.example."

// The default `client_timeout` is ten seconds, which is a hundred units of the
// 100ms the TIMEOUT field is counted in (RFC 7828 section 3.1). Written as the
// arithmetic rather than as 100, so a changed default is a changed expectation
// and not a failing test.
@(private = "file")
DEFAULT_UNITS :: u16(10 * time.Second / (100 * time.Millisecond))

@(private = "file")
keepalive_server :: proc(cfg: ^config.Config) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false

	answers := make([]config.Rewrite_Answer, 1, context.temp_allocator)
	answers[0] = config.Rewrite_Answer {
		kind = .A,
		v4   = {192, 0, 2, 1},
	}
	rewrites := make([]config.Rewrite, 1, context.temp_allocator)
	rewrites[0] = config.Rewrite {
		domain  = KEPT,
		answers = answers,
		ttl     = 300,
	}
	cfg.rewrites = rewrites
	return Server{cfg = cfg}
}

/*
An A query for `name`, with an OPT record that carries a keepalive option when
`ask` is set.

The option is empty, which is the only shape a client may send it in: RFC 7828
section 3.1 gives OPTION-LENGTH "the value 0 if the TIMEOUT is omitted", and
section 3.2.1 has a client omit it - the timeout is the server's to state.
*/
@(private = "file")
keepalive_query :: proc(name: string, ask: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = .A,
		class = .IN,
	}

	opt := dns.make_opt(1232, false)
	if ask {
		options := make([]dns.EDNS_Option, 1, context.temp_allocator)
		options[0] = dns.EDNS_Option {
			code = u16(dns.EDNS_Option_Code.TCP_Keepalive),
			data = nil,
		}
		opt.data = dns.Rdata_OPT{options = options}
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt

	msg := dns.Message {
		id         = 0x2b2b,
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

// The TIMEOUT an answer states, as the two octets RFC 7828 section 3.1 defines
// them: unsigned, network byte order. `found` false covers both an answer with
// no such option and one whose option is the wrong length, which a client
// reading it would have to treat alike.
@(private = "file")
answer_keepalive :: proc(t: ^testing.T, wire: []u8) -> (units: u16, found: bool) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the answer does not decode: %v", err) {
		return 0, false
	}
	data, has := dns.find_edns_option(m, .TCP_Keepalive)
	if !has {
		return 0, false
	}
	if !testing.expectf(
		t,
		len(data) == 2,
		"the keepalive option is %d bytes, and a response carries two",
		len(data),
	) {
		return 0, false
	}
	return u16(data[0]) << 8 | u16(data[1]), true
}

@(private = "file")
answers_the_rewrite :: proc(t: ^testing.T, wire: []u8) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the answer does not decode: %v", err) {
		return
	}
	testing.expect_value(t, dns.peek_rcode(wire), dns.Rcode.No_Error)
	if !testing.expect_value(t, len(m.answer), 1) {
		return
	}
	a, is_a := m.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the answer lost its A record")
	testing.expect_value(t, a.addr, [4]u8{192, 0, 2, 1})
}

/*
A client on a connection that asks is told how long the connection will be held.

RFC 7828 section 3.3.2 is the rule the value has to satisfy - a server "MUST
specify the TIMEOUT value that is currently associated with the TCP session" -
and on these two transports that value is `server.client_timeout`, which
`stream_job` puts on the socket as its receive timeout.

Both transports, because DoT is TCP with a handshake in front of it and the
connection whose lifetime is at issue is the same one. It is also the transport
the option is worth the most on, that handshake being what a client re-pays
every time it guesses the idle timeout wrong.
*/
@(test)
test_a_connected_client_that_asks_is_told_the_idle_timeout :: proc(t: ^testing.T) {
	for proto in ([]Protocol{.TCP, .DoT}) {
		cfg: config.Config
		s := keepalive_server(&cfg)

		query := keepalive_query(KEPT, true)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, outcome, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", proto) {
			return
		}
		testing.expect_value(t, outcome, Outcome.Rewritten)

		units, found := answer_keepalive(t, out)
		if testing.expectf(t, found, "%v: the answer carries no keepalive option", proto) {
			testing.expectf(
				t,
				units == DEFAULT_UNITS,
				"%v: the answer states a %d00ms idle timeout and the socket holds one for %v",
				proto,
				units,
				cfg.server.client_timeout,
			)
		}

		// The option is bytes beside the answer, not bytes instead of it.
		answers_the_rewrite(t, out)
		free_all(context.temp_allocator)
	}
}

/*
And the number follows the setting rather than sitting beside it.

This is the half of section 3.3.2 a constant would pass the case above with. An
operator who shortens `client_timeout` to reclaim connections sooner has clients
still holding theirs for the old figure if the option does not move with it -
which is worse than never sending one, because now they have been told.
*/
@(test)
test_the_idle_timeout_sent_is_the_one_configured :: proc(t: ^testing.T) {
	Want :: struct {
		timeout: time.Duration,
		units:   u16,
	}
	cases := []Want {
		{2500 * time.Millisecond, 25},
		{45 * time.Second, 450},
		// Truncated rather than rounded: 1.999s of connection must not be
		// stated as 2s. See `keepalive_units`.
		{1999 * time.Millisecond, 19},
	}
	for c in cases {
		cfg: config.Config
		s := keepalive_server(&cfg)
		cfg.server.client_timeout = c.timeout

		query := keepalive_query(KEPT, true)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, _, ok := handle_query(&s, query, .DoT, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", c.timeout) {
			return
		}

		units, found := answer_keepalive(t, out)
		if testing.expectf(t, found, "%v: the answer carries no keepalive option", c.timeout) {
			testing.expectf(
				t,
				units == c.units,
				"a %v timeout was stated as %d00ms, not %d00ms",
				c.timeout,
				units,
				c.units,
			)
		}
		free_all(context.temp_allocator)
	}
}

/*
A timeout there is no honest way to state is left unstated.

A non-positive `client_timeout` is no receive timeout on the socket at all, and
the only value the two octets could carry for that is 0 - which section 3.4
defines as a request to close the connection as soon as possible, the exact
opposite of what that connection does. So the option is left off and the client
keeps its own idea of when to close, which is where it was before it asked.
*/
@(test)
test_a_timeout_that_cannot_be_stated_is_left_off :: proc(t: ^testing.T) {
	for timeout in ([]time.Duration{0, 50 * time.Millisecond}) {
		cfg: config.Config
		s := keepalive_server(&cfg)
		cfg.server.client_timeout = timeout

		query := keepalive_query(KEPT, true)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, _, ok := handle_query(&s, query, .DoT, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", timeout) {
			return
		}

		units, found := answer_keepalive(t, out)
		testing.expectf(
			t,
			!found,
			"a %v timeout was stated as %d00ms, which reads as close-at-once",
			timeout,
			units,
		)
		// Still an answer, and still the one the client asked for: the option
		// is what is missing, not the reply.
		answers_the_rewrite(t, out)
		free_all(context.temp_allocator)
	}
}

/*
A client that did not ask is told nothing.

Section 3.3.2 would permit the option in any answer to a query carrying an OPT
record, and this server takes the narrower reading `pad_answer` takes about
padding: an option a client did not ask for is bytes it did not budget for, and
a stub with no RFC 7828 in it gets nothing to skip past.
*/
@(test)
test_a_client_that_did_not_ask_is_told_nothing :: proc(t: ^testing.T) {
	for proto in ([]Protocol{.TCP, .DoT}) {
		cfg: config.Config
		s := keepalive_server(&cfg)

		query := keepalive_query(KEPT, false)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, _, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", proto) {
			return
		}

		_, found := answer_keepalive(t, out)
		testing.expectf(t, !found, "%v: an unasked-for keepalive option came back", proto)
		free_all(context.temp_allocator)
	}
}

/*
On UDP the option is ignored, which is a decision and not an accident.

RFC 7828 section 3.3.1: a server that receives the option over UDP "MUST ignore
the option". Ignore is the whole of it - not FORMERR, and not an answer that
states a timeout for a connection neither end has. A client that sends it there
is breaking section 3.2.1, and the remedy the RFC gives for that is to carry on
answering the question.

Pinned rather than left to fall out of the transport gate in `attach_keepalive`,
because the two are not the same statement: the gate could be loosened by
somebody adding a transport to it, and this case is what would then say so.

DoH goes with it, for a rule from the other document. RFC 8484 section 10:
"Extensions that are specific to the choice of transport, such as [RFC7828], are
not applicable to DoH." A DoH connection's lifetime is HTTP's to describe and is
not the DNS session's idle timeout, whatever the socket underneath it does.
*/
@(test)
test_the_option_is_ignored_where_it_does_not_apply :: proc(t: ^testing.T) {
	for proto in ([]Protocol{.UDP, .DoH}) {
		cfg: config.Config
		s := keepalive_server(&cfg)

		query := keepalive_query(KEPT, true)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, outcome, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", proto) {
			return
		}

		// Ignored, so the question is answered exactly as it would have been
		// without the option on it.
		testing.expect_value(t, outcome, Outcome.Rewritten)
		answers_the_rewrite(t, out)

		units, found := answer_keepalive(t, out)
		testing.expectf(
			t,
			!found,
			"%v: the answer states a %d00ms idle timeout for a session there is none of",
			proto,
			units,
		)
		free_all(context.temp_allocator)
	}
}

// --- the way upstream ------------------------------------------------------

@(private = "file")
Keepalive_Mock :: struct {
	socket:        net.UDP_Socket,
	saw_keepalive: bool,
	served:        bool,
}

@(private = "file")
serve_keepalive :: proc(x: ^Keepalive_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE {
		return
	}
	m, derr := dns.decode_message(buf[:n], context.temp_allocator)
	if derr != .None {
		return
	}
	/*
	Every OPT record is walked rather than the first one the strip edits, for
	the reason `ecs_test.odin` gives: a mock that looked only where the strip
	looks could not tell a query the strip cleaned from one still carrying the
	option somewhere the strip never reached.
	*/
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for o in rdata.options {
			if o.code == u16(dns.EDNS_Option_Code.TCP_Keepalive) {
				x.saw_keepalive = true
			}
		}
	}

	reply := keepalive_reply()
	if len(reply) == 0 || len(reply) > len(buf) {
		return
	}
	out: [4096]u8
	copy(out[:], reply)
	out[0], out[1] = buf[0], buf[1]
	_, serr := net.send_udp(x.socket, out[:len(reply)], remote)
	x.served = serr == nil
	free_all(context.temp_allocator)
}

@(private = "file")
keepalive_reply :: proc() -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name = FORWARDED,
		type = .A,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_A{addr = {198, 51, 100, 7}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = FORWARDED,
		type  = .A,
		class = .IN,
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	msg := dns.Message {
		question   = question,
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

// A name no rewrite answers, so the query reaches the socket the case is
// watching.
@(private = "file")
FORWARDED :: "forwarded.example."

/*
The client's keepalive option does not reach the upstream.

The offence is section 3.2.1: "DNS clients MUST NOT include the edns-tcp-keepalive
option in queries sent using UDP transport." Towards a UDP upstream the client
sending the query is elodin, so a client's option relayed untouched is this
server issuing exactly that - from a hop where the option was legal, onto one
where it is not, describing a connection the upstream is not an end of.

What the mock reads is the bytes that left rather than what this server meant to
send, which is the only reading that would have caught the option travelling
before this.
*/
@(test)
test_a_client_keepalive_does_not_reach_the_upstream :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	// Only a bound on a hang, and past the upstream timeout below rather than
	// under it: see the note on `MOCK_RECV_TIMEOUT`.
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return
	}

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	// No cookie towards the upstream: it would add an option of its own to the
	// outgoing query, which has nothing to do with the one under test.
	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	s := Server {
		cfg     = &cfg,
		group   = group,
		answers = answers,
	}

	x := Keepalive_Mock{socket = socket}
	mock := thread.create_and_start_with_poly_data(&x, serve_keepalive)
	// Asked over DoT, which is where a client has most reason to send the
	// option and where this server has an answer of its own for it. The strip
	// is not conditioned on the client's transport, and this is the transport
	// on which forgetting it would be least visible.
	out, outcome, ok := handle_query(
		&s,
		keepalive_query(FORWARDED, true),
		.DoT,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.served, "the mock upstream never answered")
	testing.expect(t, !x.saw_keepalive, "the client's keepalive option was forwarded to the upstream")

	testing.expect(t, ok, "the query produced nothing at all")
	testing.expect_value(t, outcome, Outcome.Forwarded)
	// And the client still gets this server's own answer to what it asked,
	// which is the half the strip does not take away.
	units, found := answer_keepalive(t, out)
	if testing.expect(t, found, "the forwarded answer carries no keepalive option") {
		testing.expect_value(t, units, DEFAULT_UNITS)
	}
	free_all(context.temp_allocator)
}

// --- the arithmetic --------------------------------------------------------

@(test)
test_the_keepalive_timeout_is_counted_in_hundredths_of_a_second :: proc(t: ^testing.T) {
	Want :: struct {
		timeout: time.Duration,
		units:   u16,
		ok:      bool,
	}
	cases := []Want {
		{10 * time.Second, 100, true},
		{100 * time.Millisecond, 1, true},
		{2500 * time.Millisecond, 25, true},
		// Truncated towards the shorter statement: a client told less asks
		// again early and keeps its connection, one told more spends a round
		// trip finding out the connection is gone.
		{1999 * time.Millisecond, 19, true},
		// Nothing to state: no idle timeout at all, or one that would floor to
		// the close-at-once value of section 3.4.
		{0, 0, false},
		{-1 * time.Second, 0, false},
		{99 * time.Millisecond, 0, false},
		// The field's own ceiling, a little under two hours.
		{time.Duration(max(u16)) * 100 * time.Millisecond, max(u16), true},
		{24 * time.Hour, max(u16), true},
	}
	for c in cases {
		units, ok := keepalive_units(c.timeout)
		testing.expectf(t, ok == c.ok, "%v: statable is %v, want %v", c.timeout, ok, c.ok)
		if c.ok {
			testing.expectf(t, units == c.units, "%v is %d units, want %d", c.timeout, units, c.units)
		}
	}
}
