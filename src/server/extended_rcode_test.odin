package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
An upstream reply whose rcode a client cannot read is not handed to the client.

`dns.peek_rcode` composes twelve bits - the header's four and eight more from the
OPT record's TTL (RFC 6891 section 6.1.3) - and a stub reads the four. BADVERS is
16, so its low nibble is zero: forwarded as it stands, the reply a client sees is
NOERROR over an empty answer section, which is a NODATA. The upstream said "not
in that EDNS version"; the client is told the name has no such record.

The question these ask is a `TLSA`, because that is where the difference costs
something. A DANE client told SERVFAIL retries or refuses to connect; one told
NODATA concludes the name has no TLSA record and connects without checking a
certificate - which is #271's downgrade reached without touching DNSSEC at all.
So these run with `dnssec.enabled: false`, where the validator that refuses the
same shape is not running and the guard in `resolve_query` is the whole of what
catches it.
*/

@(private = "file")
TLSA_NAME :: "_25._tcp.mx.example."

@(private = "file")
Canned_Exchange :: struct {
	socket:   net.UDP_Socket,
	reply:    []u8,
	got:      bool,
	// The query as it arrived, so a case can assert on what this server
	// actually forwarded rather than only on what came back. Read after the
	// thread is joined.
	seen:     [512]u8,
	seen_len: int,
}

/*
Serve exactly one query with a canned reply.

One query per thread, joined by the caller before it reads `got`: there is
nothing shared to guard, and a query that never arrives leaves `got` false
rather than hanging the suite - the socket carries a receive timeout.
*/
@(private = "file")
serve_one_canned :: proc(x: ^Canned_Exchange) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.got = true
	x.seen_len = copy(x.seen[:], buf[:n])

	out: [4096]u8
	copy(out[:], x.reply)
	// Echo the ID it was asked with. The resolver draws a fresh one for every
	// query it forwards, so nothing here can know it in advance.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

/*
The client's question. `edns` decides whether it offers an OPT record, which is
the only place a response can put an extended DNS error: a client that asked
without one has nowhere to be told why, and gets the bare refusal.
*/
@(private = "file")
tlsa_query :: proc(edns := true, ext: u8 = 0) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = TLSA_NAME,
		type  = .TLSA,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x7d1e,
		question = question,
	}
	msg.flags.rd = true
	if edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		// `ext` is the EXTENDED-RCODE byte, which RFC 6891 section 6.1.3 says a
		// request must leave at zero - so a non-zero one is a client doing
		// something it may not, which is the point of the case that passes one.
		additional[0] = dns.make_opt(1232, false, ext)
		msg.additional = additional
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// The info-code of the extended error a response carries (RFC 8914), or -1 if
// it has none.
@(private = "file")
extended_error_code :: proc(wire: []u8) -> int {
	code, _ := extended_error(wire)
	return code
}

// The info-code and the EXTRA-TEXT of the extended error a response carries,
// or -1 and "" if it has none.
@(private = "file")
extended_error :: proc(wire: []u8) -> (code: int, text: string) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return -1, ""
	}
	for rec in msg.additional {
		opt, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for option in opt.options {
			if option.code == u16(dns.EDNS_Option_Code.Ext_Error) && len(option.data) >= 2 {
				return int(option.data[0]) << 8 | int(option.data[1]), string(option.data[2:])
			}
		}
	}
	return -1, ""
}

/*
What an upstream that will not answer in the EDNS version it was asked in sends
back: the question, an OPT record, and nothing it looked up.

The header's own nibble is left at zero, which is not a detail of the fixture but
the whole of the case: rcode 16 is four zero bits in the header and a one in the
OPT record's extended byte, and the client reads the header. Both readers are
checked on the way in by every caller below, so a fixture that stopped carrying
an extended rcode - a codec that dropped the TTL, say - would fail rather than
quietly assert about an ordinary NOERROR.
*/
@(private = "file")
extended_rcode_reply :: proc(nibble: u8 = 0, ext: u8 = 1) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = TLSA_NAME,
		type  = .TLSA,
		class = .IN,
	}
	// The upper eight bits of the extended rcode live in the OPT record's TTL
	// (RFC 6891 section 6.1.3). The lowest of them on its own is BADVERS.
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, true, ext)
	msg := dns.Message {
		question   = question,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = nibble & 0xf
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// A plain rcode in the header and no OPT record at all: what a server that
// declines to answer sends, and the reply the client is owed as it stands.
@(private = "file")
plain_rcode_reply :: proc(rcode: dns.Rcode) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = TLSA_NAME,
		type  = .TLSA,
		class = .IN,
	}
	msg := dns.Message {
		question = question,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = u8(rcode) & 0xf
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// The certificate association a DANE client is asking for. Kept as raw RDATA
// because this codec models only a handful of RR types, and TLSA is not one of
// them; what matters here is that the answer section carries the record.
@(private = "file")
tlsa_answer_reply :: proc() -> []u8 {
	rdata := make([]u8, 7, context.temp_allocator)
	copy(rdata, []u8{3, 1, 1, 0xde, 0xad, 0xbe, 0xef})
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = TLSA_NAME,
		type  = .TLSA,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_Raw{data = rdata},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = TLSA_NAME,
		type  = .TLSA,
		class = .IN,
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

// Binds a mock upstream on the loopback and hands back its spec.
@(private = "file")
bind_mock :: proc(t: ^testing.T, name: string) -> (socket: net.UDP_Socket, spec: config.Upstream_Spec, ok: bool) {
	sock, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return {}, {}, false
	}
	// Only a bound on a hang, and past the upstream timeout below rather than
	// under it: see the note on `MOCK_RECV_TIMEOUT`.
	_ = net.set_option(sock, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(sock)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		net.close(sock)
		return {}, {}, false
	}
	return sock, config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port}, true
}

// A forwarding server with nothing between the client and the upstream: no
// cache to answer from or store into, no blocklist, and no validator - which is
// the arrangement this guard exists for.
@(private = "file")
forwarding_config :: proc(specs: []config.Upstream_Spec) -> config.Config {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	cfg.upstream.servers = specs
	return cfg
}

// The premise every case below rests on, asserted against the fixture rather
// than assumed: rcode 16 with a header a client reads as NOERROR.
@(private = "file")
expect_reads_as_noerror :: proc(t: ^testing.T, reply: []u8) -> bool {
	if !testing.expect(t, len(reply) > dns.HEADER_SIZE, "the fixture did not encode") {
		return false
	}
	if !testing.expect_value(t, dns.peek_rcode(reply), dns.Rcode.Bad_Vers) {
		return false
	}
	return testing.expectf(
		t,
		reply[3] & 0xf == 0,
		"the fixture's header nibble is %d, so nothing about this case is about a client reading it as NOERROR",
		reply[3] & 0xf,
	)
}

/*
The reproducer: one upstream, and it answers BADVERS.

There is nowhere else for the query to go, so what the client gets is this
server's own reading of the reply. SERVFAIL is the answer; NOERROR is the bug,
and it is checked through both readers because a client uses the header and this
server uses the composed value - a response that kept the extended half and lost
the header's would still be a NODATA to everything that receives it.
*/
@(test)
test_an_extended_rcode_is_not_forwarded_to_the_client :: proc(t: ^testing.T) {
	socket, spec, bound := bind_mock(t, "broken")
	if !bound {
		return
	}
	defer net.close(socket)

	specs := make([]config.Upstream_Spec, 1, context.temp_allocator)
	specs[0] = spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	reply := extended_rcode_reply()
	if !expect_reads_as_noerror(t, reply) {
		return
	}

	x := Canned_Exchange {
		socket = socket,
		reply  = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_canned)
	out, outcome, ok := handle_query(&s, tlsa_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}

	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expectf(
		t,
		dns.peek_rcode(out) == .Serv_Fail,
		"the client was handed %v rather than SERVFAIL",
		dns.peek_rcode(out),
	)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	// What a stub reads, and the whole of the harm: NOERROR over an empty answer
	// section is a name with no TLSA record.
	testing.expectf(
		t,
		decoded.flags.rcode != u8(dns.Rcode.No_Error),
		"the header reads as NOERROR over %d answers, which is a NODATA",
		len(decoded.answer),
	)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.Serv_Fail)
	testing.expect_value(t, len(decoded.answer), 0)
	testing.expect_value(t, decoded.id, u16(0x7d1e))

	/*
	And the client is told why, the way the rebinding guard and the validator
	explain their own refusals: RFC 8914 extended error 0, "Other", with the
	rcode in the text. There is no registered code for "the responder's rcode is
	not one you could read", and a nearer-sounding one - a network error, an
	unreachable authority - would say something untrue about an upstream that
	answered.
	*/
	testing.expect_value(t, extended_error_code(out), 0)

	counters := stats_of(&s)
	testing.expect_value(t, counters.failed, u64(1))
	testing.expect_value(t, counters.forwarded, u64(0))
	/*
	Counted as its own figure as well, which is what makes the once-at-warn line
	sound: the warning is said once per process and demoted to debug after, so a
	deployment whose upstream starts doing this has nothing but this counter to
	show for every query after the first. Same reasoning as `conn_refused`.
	*/
	testing.expect_value(t, counters.unreadable_rcode, u64(1))

	free_all(context.temp_allocator)
}

/*
And the same reply with a low nibble that says something else.

BADCOOKIE is 23, whose nibble is 7 - YXRRSET, an rcode that has no business in
an answer to a client's question and that a stub will nonetheless act on. The
case is here because the guard is written on the composed value rather than on
the one rcode whose nibble happens to be zero, and a guard that only caught
BADVERS would leave every other extended rcode reading as whatever its bottom
four bits spell.
*/
@(test)
test_an_extended_rcode_with_a_nonzero_nibble_is_not_forwarded_either :: proc(t: ^testing.T) {
	socket, spec, bound := bind_mock(t, "broken")
	if !bound {
		return
	}
	defer net.close(socket)

	specs := make([]config.Upstream_Spec, 1, context.temp_allocator)
	specs[0] = spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	// 16 | 7: an extended rcode this server has no reading for either, and one
	// whose header half is a rcode in its own right.
	reply := extended_rcode_reply(u8(dns.Rcode.YX_RRSet))
	if !testing.expect(t, len(reply) > dns.HEADER_SIZE, "the fixture did not encode") {
		return
	}
	testing.expectf(
		t,
		u16(dns.peek_rcode(reply)) == 16 | u16(dns.Rcode.YX_RRSet),
		"the fixture composed %v rather than an extended rcode over YXRRSET",
		dns.peek_rcode(reply),
	)

	x := Canned_Exchange {
		socket = socket,
		reply  = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_canned)
	// Asked without EDNS, which is the other half of this case: there is no OPT
	// record in the response to carry an extended error, and the refusal has to
	// go out as a plain SERVFAIL rather than not at all.
	out, outcome, ok := handle_query(
		&s,
		tlsa_query(edns = false),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expectf(
		t,
		dns.peek_rcode(out) == .Serv_Fail,
		"the client was handed %v rather than SERVFAIL",
		dns.peek_rcode(out),
	)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.Serv_Fail)
	testing.expect_value(t, decoded.id, u16(0x7d1e))
	testing.expect_value(t, len(decoded.answer), 0)
	testing.expect_value(t, extended_error_code(out), -1)

	free_all(context.temp_allocator)
}

/*
A group with somewhere else to go is asked, rather than answering SERVFAIL for
what one broken member said.

elodin only ever sends EDNS version 0, which every EDNS implementation is
required to support, so a BADVERS in answer to one is that server violating the
protocol rather than anything about the name. `resolve_readable` treats it as
the transport-level failure it is and sweeps the rest of the group, which is what
`resolve_answerable` already did for a chain lookup that got an rcode saying
nothing. The client gets the answer the second server had all along.
*/
@(test)
test_a_broken_upstream_is_asked_past_for_an_extended_rcode :: proc(t: ^testing.T) {
	broken_socket, broken_spec, broken_ok := bind_mock(t, "broken")
	if !broken_ok {
		return
	}
	defer net.close(broken_socket)
	good_socket, good_spec, good_ok := bind_mock(t, "good")
	if !good_ok {
		return
	}
	defer net.close(good_socket)

	specs := make([]config.Upstream_Spec, 2, context.temp_allocator)
	specs[0] = broken_spec
	specs[1] = good_spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	reply := extended_rcode_reply()
	if !expect_reads_as_noerror(t, reply) {
		return
	}

	broken := Canned_Exchange {
		socket = broken_socket,
		reply  = reply,
	}
	good := Canned_Exchange {
		socket = good_socket,
		reply  = tlsa_answer_reply(),
	}
	broken_mock := thread.create_and_start_with_poly_data(&broken, serve_one_canned)
	good_mock := thread.create_and_start_with_poly_data(&good, serve_one_canned)
	out, outcome, ok := handle_query(&s, tlsa_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(broken_mock)
	thread.join(good_mock)
	thread.destroy(broken_mock)
	thread.destroy(good_mock)

	testing.expect(t, broken.got, "the first upstream was never asked")
	testing.expect(t, good.got, "the second upstream was never asked, so the group was not swept")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}

	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, len(decoded.answer) == 1, "the client was not served the record the second upstream had") {
		testing.expect_value(t, decoded.answer[0].type, dns.Type.TLSA)
	}

	counters := stats_of(&s)
	testing.expect_value(t, counters.forwarded, u64(1))
	testing.expect_value(t, counters.failed, u64(0))

	free_all(context.temp_allocator)
}

/*
An rcode the client can read is still the client's answer, and still ends the
search.

This is the half that must not change. SERVFAIL is a reply, and for a client's
own question the rcode is the answer - `upstream.resolve_answerable`'s own
reading says so, and passing it on is honest. A guard that swept the group for
one would turn every declining upstream into a second query, and every ACL a
resolver applies to a client of ours into an answer fetched from somewhere that
does not apply it.

Two upstreams, and the second must be left alone: it is read after the call has
returned rather than raced, which is both exact and quick. See `mock_untouched`.
*/
@(test)
test_a_readable_rcode_is_still_the_clients_answer :: proc(t: ^testing.T) {
	first_socket, first_spec, first_ok := bind_mock(t, "declining")
	if !first_ok {
		return
	}
	defer net.close(first_socket)
	second_socket, second_spec, second_ok := bind_mock(t, "spare")
	if !second_ok {
		return
	}
	defer net.close(second_socket)

	specs := make([]config.Upstream_Spec, 2, context.temp_allocator)
	specs[0] = first_spec
	specs[1] = second_spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	x := Canned_Exchange {
		socket = first_socket,
		reply  = plain_rcode_reply(.Serv_Fail),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_canned)
	out, outcome, ok := handle_query(&s, tlsa_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the first upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}

	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Serv_Fail)
	testing.expect(t, mock_untouched(second_socket), "a readable rcode sent the group a second query")

	free_all(context.temp_allocator)
}

/*
And a composed rcode nothing has a name for still says what it was.

`Rcode` names 16 to 23; the field is eight bits wide, so 4080 of the 4096
composed values have no name at all, and Odin's `%v` renders one of those as a
`BAD ENUM VALUE` placeholder. The whole threat model here is an attacker
choosing the byte, so it would choose one of those - and the extended error's
info-code is 0, "Other", which means the text is the only thing it carries. A
placeholder there tells the client's operator nothing and tells this server's
operator nothing either, in the one line it gets before the rest are demoted to
debug.

Extended byte 2 with an empty nibble: composed rcode 32, unassigned, and what
the client has to be told is the number.
*/
@(test)
test_an_unnamed_extended_rcode_is_reported_as_a_number :: proc(t: ^testing.T) {
	socket, spec, bound := bind_mock(t, "broken")
	if !bound {
		return
	}
	defer net.close(socket)

	specs := make([]config.Upstream_Spec, 1, context.temp_allocator)
	specs[0] = spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	reply := extended_rcode_reply(ext = 2)
	if !testing.expect(t, len(reply) > dns.HEADER_SIZE, "the fixture did not encode") {
		return
	}
	// The premise: a composed rcode of 32, which is not a value `Rcode` names.
	testing.expect_value(t, u16(dns.peek_rcode(reply)), u16(32))
	if _, named := dns.rcode_name(dns.peek_rcode(reply)); named {
		testing.expect(t, false, "32 is a named rcode now, so this case no longer tests what it says")
		return
	}

	x := Canned_Exchange {
		socket = socket,
		reply  = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_canned)
	out, outcome, ok := handle_query(&s, tlsa_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Serv_Fail)

	code, text := extended_error(out)
	testing.expect_value(t, code, 0)
	testing.expectf(t, text == "upstream rcode RCODE32", "the client was told %q", text)

	free_all(context.temp_allocator)
}

/*
A client cannot make this server ask upstream in an rcode of its own.

RFC 6891 section 6.1.3 requires the OPT record's EXTENDED-RCODE byte to be zero
in a request, and the version gate reads the two bytes below it rather than this
one - so a client can set it and, forwarded verbatim, it reaches the upstream.
An upstream that echoes the query's OPT TTL rather than building its own answers
with a composed rcode of 16 or more for every query that client sends: the guard
above then refuses each of them, after sweeping the group for a reply that is
not. One client's byte, and every member of the group asked for it.

So the byte is cleared where the transaction ID is drawn. Asserted on the query
the upstream received, because that is the only place the number is observable -
the same reasoning `cases_queryid.odin` gives for the ID beside it.
*/
@(test)
test_a_clients_extended_rcode_byte_is_not_forwarded :: proc(t: ^testing.T) {
	socket, spec, bound := bind_mock(t, "echoing")
	if !bound {
		return
	}
	defer net.close(socket)

	specs := make([]config.Upstream_Spec, 1, context.temp_allocator)
	specs[0] = spec
	cfg := forwarding_config(specs)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s := Server{cfg = &cfg, group = group}

	// Extended byte 4 on the client's own query: composed rcode 64 to anything
	// that reads the OPT record, and nothing at all to the version gate.
	query := tlsa_query(ext = 4)
	if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
		return
	}
	testing.expect_value(t, u16(dns.peek_rcode(query)), u16(64))

	x := Canned_Exchange {
		socket = socket,
		reply  = tlsa_answer_reply(),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_canned)
	out, outcome, ok := handle_query(&s, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return
	}
	testing.expectf(
		t,
		dns.peek_rcode(x.seen[:x.seen_len]) == .No_Error,
		"the upstream was asked with composed rcode %d, which is the client's byte forwarded",
		u16(dns.peek_rcode(x.seen[:x.seen_len])),
	)
	// And the query is otherwise untouched: it still asks the same question and
	// still carries an OPT record for the upstream to answer into.
	seen, serr := dns.decode_message(x.seen[:x.seen_len], context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	if testing.expect(t, len(seen.question) == 1, "the forwarded query lost its question") {
		testing.expect(t, dns.name_equal_fold(seen.question[0].name, TLSA_NAME), "the forwarded question changed")
	}
	testing.expect_value(t, dns.edns_udp_size(seen), u16(1232))

	// And the client gets the answer rather than the SERVFAIL its own byte
	// would have earned it against an echoing upstream.
	if testing.expect(t, ok, "nothing came back at all") {
		testing.expect_value(t, outcome, Outcome.Forwarded)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)
	}

	free_all(context.temp_allocator)
}
