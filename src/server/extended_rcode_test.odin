package server

import "core:net"
import "core:testing"
import "core:thread"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
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
same shape is not running and `unreadable_rcode_refusal` is the whole of what
catches it.
*/

@(private = "file")
TLSA_NAME :: "_25._tcp.mx.example."

@(private = "file")
CLIENT_ID :: u16(0x7d1e)

/*
The client's question. `edns` decides whether it offers an OPT record, which is
the only place a response can put an extended DNS error: a client that asked
without one has nowhere to be told why, and gets the bare refusal.

`ext` is the EXTENDED-RCODE byte, which RFC 6891 section 6.1.3 says a request
must leave at zero - so a non-zero one is a client doing something it may not,
which is the point of the case that passes one.
*/
@(private = "file")
tlsa_query :: proc(edns := true, ext: u8 = 0, advertised: u16 = 1232) -> []u8 {
	opt: Maybe(dns.Record)
	if edns {
		opt = dns.make_opt(advertised, false, ext)
	}
	return test_query(TLSA_NAME, .TLSA, id = CLIENT_ID, opt = opt)
}

/*
An upstream's reply to the TLSA question: `nibble` in the header's rcode, and
`ext` - when there is one - as the extended byte of an OPT record.

With `ext`, it is what an upstream that will not answer in the EDNS version it
was asked in sends back: the question, an OPT record, and nothing it looked up.
The header's own nibble is then left at zero, which is not a detail of the
fixture but the whole of the case: rcode 16 is four zero bits in the header and
a one in the OPT record's extended byte (RFC 6891 section 6.1.3), and the client
reads the header. Both readers are checked on the way in by every caller below,
so a fixture that stopped carrying an extended rcode - a codec that dropped the
TTL, say - would fail rather than quietly assert about an ordinary NOERROR.

Without it, a plain rcode in the header and no OPT record at all: what a server
that declines to answer sends, and the reply the client is owed as it stands.

`answer` carries the certificate association a DANE client is asking for. Kept
as raw RDATA because this codec models only a handful of RR types, and TLSA is
not one of them; what matters here is that the answer section carries the record.
*/
@(private = "file")
tlsa_reply :: proc(nibble: u8 = 0, ext: Maybe(u8) = nil, answer := false) -> []u8 {
	question := [1]dns.Question{{name = TLSA_NAME, type = .TLSA, class = .IN}}
	msg := dns.Message {
		question = question[:],
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = nibble & 0xf
	if ext_byte, has := ext.?; has {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, true, ext_byte)
		msg.additional = additional
	}
	if answer {
		rdata := make([]u8, 7, context.temp_allocator)
		copy(rdata, []u8{3, 1, 1, 0xde, 0xad, 0xbe, 0xef})
		records := make([]dns.Record, 1, context.temp_allocator)
		records[0] = dns.Record {
			name  = TLSA_NAME,
			type  = .TLSA,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_Raw{data = rdata},
		}
		msg.answer = records
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		panic("the TLSA reply does not encode")
	}
	return wire
}

// The premise every case below rests on, asserted against the fixture rather
// than assumed: rcode 16 with a header a client reads as NOERROR.
@(private = "file")
expect_reads_as_noerror :: proc(t: ^testing.T, reply: []u8) -> bool {
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
A server whose group is one mock upstream per name, asked in that order. The
caller keeps the fixture where it declared it: `srv` points at `cfg`.
*/
@(private = "file")
Rcode_Fixture :: struct {
	sockets: [2]net.UDP_Socket,
	bound:   int,
	cfg:     config.Config,
	group:   ^upstream.Group,
	srv:     Server,
}

@(private = "file")
rcode_fixture_start :: proc(t: ^testing.T, f: ^Rcode_Fixture, names: ..string, loc := #caller_location) -> bool {
	assert(len(names) <= len(f.sockets))
	specs := make([]config.Upstream_Spec, len(names), context.temp_allocator)
	for name, i in names {
		socket, spec, ok := bind_mock(t, name, loc = loc)
		if !ok {
			rcode_fixture_stop(f)
			return false
		}
		f.sockets[i] = socket
		f.bound += 1
		specs[i] = spec
	}
	f.cfg = test_config(specs)
	group, gerr := upstream.make_group(f.cfg.upstream)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		rcode_fixture_stop(f)
		return false
	}
	f.group = group
	f.srv = Server {
		cfg   = &f.cfg,
		group = f.group,
	}
	return true
}

@(private = "file")
rcode_fixture_stop :: proc(f: ^Rcode_Fixture) {
	if f.group != nil {
		upstream.destroy_group(f.group)
		f.group = nil
	}
	for socket in f.sockets[:f.bound] {
		net.close(socket)
	}
	f.bound = 0
}

/*
One query through the fixture, the mock at each position answering the reply at
the same position. A nil reply starts no mock there, for a member that must be
left alone: it is read with `mock_untouched` once this has returned.
*/
@(private = "file")
rcode_ask :: proc(
	f: ^Rcode_Fixture,
	query: []u8,
	replies: ..[]u8,
) -> (
	out: []u8,
	outcome: Outcome,
	served: bool,
	mocks: [2]Canned_Mock,
) {
	threads: [2]^thread.Thread
	for reply, i in replies {
		if reply == nil {
			continue
		}
		mocks[i] = Canned_Mock {
			socket = f.sockets[i],
			reply  = reply,
		}
		threads[i] = thread.create_and_start_with_poly_data(&mocks[i], serve_canned)
	}
	out, outcome, served = handle_query(&f.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	for th in threads {
		if th != nil {
			thread.join(th)
			thread.destroy(th)
		}
	}
	return
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
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "broken") {
		return
	}
	defer rcode_fixture_stop(&f)

	reply := tlsa_reply(ext = 1)
	if !expect_reads_as_noerror(t, reply) {
		return
	}

	out, outcome, ok, mocks := rcode_ask(&f, tlsa_query(), reply)
	testing.expect(t, mocks[0].got, "the upstream was never asked")
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
	testing.expect_value(t, decoded.id, CLIENT_ID)

	/*
	And the client is told why, the way the rebinding guard and the validator
	explain their own refusals: RFC 8914 extended error 0, "Other", with the
	rcode in the text. There is no registered code for "the responder's rcode is
	not one you could read", and a nearer-sounding one - a network error, an
	unreachable authority - would say something untrue about an upstream that
	answered.
	*/
	code, _ := extended_error(out)
	testing.expect_value(t, code, 0)

	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.failed, u64(1))
	testing.expect_value(t, counters.forwarded, u64(0))
	/*
	Counted as its own figure as well, which is what makes the gated line
	sound: the warning is said once a window and demoted to debug between, so a
	deployment whose upstream starts doing this has nothing but this counter to
	show for every query the log holds back. Same reasoning as `conn_refused`.
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
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "broken") {
		return
	}
	defer rcode_fixture_stop(&f)

	// 16 | 7: an extended rcode this server has no reading for either, and one
	// whose header half is a rcode in its own right.
	reply := tlsa_reply(u8(dns.Rcode.YX_RRSet), ext = 1)
	testing.expectf(
		t,
		u16(dns.peek_rcode(reply)) == u16(dns.Rcode.Bad_Vers) | u16(dns.Rcode.YX_RRSet),
		"the fixture composed %v rather than an extended rcode over YXRRSET",
		dns.peek_rcode(reply),
	)

	// Asked without EDNS, which is the other half of this case: there is no OPT
	// record in the response to carry an extended error, and the refusal has to
	// go out as a plain SERVFAIL rather than not at all.
	out, outcome, ok, mocks := rcode_ask(&f, tlsa_query(edns = false), reply)
	testing.expect(t, mocks[0].got, "the upstream was never asked")
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
	testing.expect_value(t, decoded.id, CLIENT_ID)
	testing.expect_value(t, len(decoded.answer), 0)
	code, _ := extended_error(out)
	testing.expect_value(t, code, -1)

	free_all(context.temp_allocator)
}

/*
A group with somewhere else to go is asked, rather than answering SERVFAIL for
what one broken member said.

elodin only ever sends EDNS version 0, which every EDNS implementation is
required to support, so a BADVERS in answer to one is that server violating the
protocol rather than anything about the name. `resolve_readable` treats it as
the transport-level failure it is and sweeps the rest of the group, as
`resolve_answerable` does for a chain lookup that got an rcode saying nothing.
The client gets the answer the second server had all along.
*/
@(test)
test_a_broken_upstream_is_asked_past_for_an_extended_rcode :: proc(t: ^testing.T) {
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "broken", "good") {
		return
	}
	defer rcode_fixture_stop(&f)

	reply := tlsa_reply(ext = 1)
	if !expect_reads_as_noerror(t, reply) {
		return
	}

	out, outcome, ok, mocks := rcode_ask(&f, tlsa_query(), reply, tlsa_reply(answer = true))
	testing.expect(t, mocks[0].got, "the first upstream was never asked")
	testing.expect(t, mocks[1].got, "the second upstream was never asked, so the group was not swept")
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

	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.forwarded, u64(1))
	testing.expect_value(t, counters.failed, u64(0))

	free_all(context.temp_allocator)
}

/*
An rcode that states something about the name is still the client's answer, and
still ends the search.

This is the half that must not change. NXDOMAIN is a verdict about the name
rather than a report about the server, and for a client's own question the rcode
is the answer - `upstream.resolve_answerable`'s own reading says so, and passing
it on is honest. A guard that swept the group for one would turn every name a
zone does not hold into a second query to every other member, and every question
a resolver answers into a race between two of them.

SERVFAIL and REFUSED are the two that are not such a verdict, and issue #309 is
what the group does with them; `test_a_group_with_a_spare_is_asked_past_a_servfail`
below is that case. The cost written down there is REFUSED as an ACL: a member
that declines this question on policy has the member beside it asked, which is a
resolver upstream of ours applying a rule we then ask somewhere else about. That
is the trade the issue makes, and it is made for the deployment where two
upstreams are configured so that one of them can be broken.

Two upstreams, and the second must be left alone: it is read after the call has
returned rather than raced, which is both exact and quick. See `mock_untouched`.
*/
@(test)
test_a_readable_rcode_is_still_the_clients_answer :: proc(t: ^testing.T) {
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "declining", "spare") {
		return
	}
	defer rcode_fixture_stop(&f)

	query := tlsa_query()
	out, outcome, ok, mocks := rcode_ask(&f, query, tlsa_reply(u8(dns.Rcode.NX_Domain)))
	testing.expect(t, mocks[0].got, "the first upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}

	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.NX_Domain)
	testing.expect(t, mock_untouched(f.sockets[1], query), "a readable rcode sent the group a second query")

	free_all(context.temp_allocator)
}

/*
And where the first member SERVFAILs or REFUSEs, the client gets the answer the
member beside it had all along.

Issue #309, over the path a client's question actually takes. RFC 2308 section
7.1 reads SERVFAIL as the responder saying nothing about the name, and REFUSED as
it declining to be asked; neither is a statement the rest of a failover group
cannot improve on, and neither trips the health cooldown, which counts transport
failures - so a member in that state answers promptly and forever.

Counted as a forward rather than a failure, because that is what happened: a
question went to the group and an answer came back.
*/
@(test)
test_a_group_with_a_spare_is_asked_past_a_servfail :: proc(t: ^testing.T) {
	asked_past(t, .Serv_Fail)
	asked_past(t, .Refused)
}

@(private = "file")
asked_past :: proc(t: ^testing.T, rcode: dns.Rcode) {
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "broken", "good") {
		return
	}
	defer rcode_fixture_stop(&f)

	out, outcome, ok, mocks := rcode_ask(&f, tlsa_query(), tlsa_reply(u8(rcode)), tlsa_reply(answer = true))
	testing.expectf(t, mocks[0].got, "%v: the first upstream was never asked", rcode)
	testing.expectf(t, mocks[1].got, "a %v ended the search with a spare upstream standing by", rcode)
	if !testing.expectf(t, ok, "%v: nothing came back at all", rcode) {
		return
	}

	testing.expect_value(t, outcome, Outcome.Forwarded)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expectf(t, len(decoded.answer) == 1, "%v: the client was not served the record the second upstream had", rcode) {
		testing.expect_value(t, decoded.answer[0].type, dns.Type.TLSA)
	}

	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.forwarded, u64(1))
	testing.expect_value(t, counters.failed, u64(0))

	free_all(context.temp_allocator)
}

/*
And a composed rcode nothing has a name for still says what it was.

`Rcode` names 0 to 11 and 16 to 23; the field is eight bits wide, so 4076 of the
4096 composed values have no name at all, and Odin's `%v` renders one of those
as a `BAD ENUM VALUE` placeholder. The whole threat model here is an attacker
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
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "broken") {
		return
	}
	defer rcode_fixture_stop(&f)

	reply := tlsa_reply(ext = 2)
	// The premise: a composed rcode of 32, which is not a value `Rcode` names.
	testing.expect_value(t, u16(dns.peek_rcode(reply)), u16(32))
	if _, named := dns.rcode_name(dns.peek_rcode(reply)); named {
		testing.expect(t, false, "32 is a named rcode now, so this case no longer tests what it says")
		return
	}

	out, outcome, ok, mocks := rcode_ask(&f, tlsa_query(), reply)
	testing.expect(t, mocks[0].got, "the upstream was never asked")
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
	f: Rcode_Fixture
	if !rcode_fixture_start(t, &f, "echoing") {
		return
	}
	defer rcode_fixture_stop(&f)

	// Extended byte 4 on the client's own query: composed rcode 64 to anything
	// that reads the OPT record, and nothing at all to the version gate. And a
	// payload size of its own, so the forwarded figure below can only be ours.
	query := tlsa_query(ext = 4, advertised = 4096)
	if !testing.expect(t, len(query) > dns.HEADER_SIZE, "the query did not encode") {
		return
	}
	testing.expect_value(t, u16(dns.peek_rcode(query)), u16(64))
	testing.expect_value(t, dns.peek_udp_size(query), u16(4096))

	out, outcome, ok, mocks := rcode_ask(&f, query, tlsa_reply(answer = true))
	x := &mocks[0]
	if !testing.expect(t, x.got, "the upstream was never asked") {
		return
	}
	testing.expectf(
		t,
		dns.peek_rcode(x.seen[:x.seen_len]) == .No_Error,
		"the upstream was asked with composed rcode %d, which is the client's byte forwarded",
		u16(dns.peek_rcode(x.seen[:x.seen_len])),
	)
	// And the rest of the query, which `upstream_query` rebuilds, still asks the
	// same question and carries an OPT record for the upstream to answer into -
	// with this server's payload size rather than the client's.
	seen, serr := dns.decode_message(x.seen[:x.seen_len], context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	if testing.expect(t, len(seen.question) == 1, "the forwarded query lost its question") {
		testing.expect(t, dns.name_equal_fold(seen.question[0].name, TLSA_NAME), "the forwarded question changed")
	}
	testing.expect_value(t, dns.edns_udp_size(seen), u16(UPSTREAM_UDP_SIZE))

	// And the client gets the answer rather than the SERVFAIL its own byte
	// would have earned it against an echoing upstream.
	if testing.expect(t, ok, "nothing came back at all") {
		testing.expect_value(t, outcome, Outcome.Forwarded)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)
	}

	free_all(context.temp_allocator)
}

/*
Which extended error a DNSSEC refusal carries, and why the third one exists.

SERVFAIL is all a client gets when an answer cannot be authenticated, so the
extended error is the whole of what it is told about why. Three refusals reach
here and they want a client to do different things: a forged answer is a
forgery, an unreachable parent zone is worth retrying, and a zone whose NSEC3
records ask for more hashing than this server does is neither - it is this
resolver declining work over a number the zone chose, and RFC 8914 section 4.28
has a code that says exactly that.

Sending "no reachable authority" for it sends whoever is debugging the zone to
look at connectivity, which is the one thing that is fine.
*/
@(test)
test_a_dnssec_refusal_names_which_refusal_it_was :: proc(t: ^testing.T) {
	// With an OPT record, because an extended error has nowhere else to go:
	// `attach_extended_error` writes into the response's OPT, and a client that
	// did not send one gets the bare SERVFAIL and no reason at all.
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	query := dns.Message {
		id         = 0x1234,
		flags      = dns.Flags{rd = true},
		question   = {{name = "nx.n3test.", type = .A, class = .IN}},
		additional = additional,
	}
	cases := []struct {
		result: dnssec.Result,
		code:   int,
		what:   string,
	} {
		{{status = .Bogus, reason = "denial of existence not proven"}, EDE_DNSSEC_BOGUS, "a forgery"},
		// RFC 8914 sections 4.8 and 4.9: a forgery verdict that rests on a
		// signature's validity period says which side of it (issue #360).
		{
			{status = .Bogus, reason = "signature expired at 2026-07-03T10:00:00Z", lapsed = {window = .Expired}},
			EDE_SIGNATURE_EXPIRED,
			"a signature past its expiration",
		},
		{
			{status = .Bogus, reason = "signature not yet valid until 2026-08-03T10:00:00Z", lapsed = {window = .Not_Yet_Valid}},
			EDE_SIGNATURE_NOT_YET_VALID,
			"a signature short of its inception",
		},
		{{status = .Indeterminate, reason = "chain of trust unavailable"}, EDE_NO_REACHABLE_AUTHORITY, "a chain this server could not walk"},
		{
			{status = .Indeterminate, reason = dnssec.NSEC3_OVER_CEILING},
			EDE_UNSUPPORTED_NSEC3_ITERATIONS,
			"a zone asking for more hashing than this server does",
		},
		// No code of its own describes "this server would not spend more CPU on
		// your question", and 22 is what every other allowance in the validator
		// already sends - the signature budget, the lookup budget - so this
		// goes with them rather than inventing a distinction the rest of the
		// package does not make.
		{
			{status = .Indeterminate, reason = dnssec.NSEC3_BUDGET_SPENT},
			EDE_NO_REACHABLE_AUTHORITY,
			"an allowance of ours",
		},
		{
			{status = .Indeterminate, reason = "lookup budget spent"},
			EDE_NO_REACHABLE_AUTHORITY,
			"the allowance beside it, which answers the same way",
		},
	}
	for c in cases {
		wire, ok := dnssec_failure_response(query, c.result, context.temp_allocator, dns.MAX_MESSAGE)
		if !testing.expectf(t, ok, "the refusal for %s should encode", c.what) {
			continue
		}
		code, text := extended_error(wire)
		testing.expectf(t, code == c.code, "%s should carry extended error %d, got %d", c.what, c.code, code)
		testing.expectf(t, text == c.result.reason, "and the reason it was given: %q, got %q", c.result.reason, text)
	}
	free_all(context.temp_allocator)
}
