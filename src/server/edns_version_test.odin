package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
A request in an EDNS version this server does not implement is refused with
BADVERS.

RFC 6891 section 6.1.3: a responder that does not implement the VERSION level of
the request MUST respond with RCODE=BADVERS. Version 0 is the only one
implemented here, and the gate sits in `handle_query` ahead of `resolve_query` -
so what these pin is where it sits as much as what it answers. A request asking
in version 1 must not be rewritten, matched against a blocklist, answered from
the cache or forwarded, because every one of those answers would go back in a
version the two ends never agreed on.

No upstream is configured: `s.group` is left nil, so a query that reached the
forwarding step would panic rather than hang, which is what makes a mistake in
the gate's placement loud instead of a timeout.
*/

@(private = "file")
REWRITTEN :: "rewritten.example."

/*
The OPT record's TTL is an extended rcode, then VERSION, then sixteen flag bits.
`make_opt` writes the two ends of it, so the version is put there by hand - the
same way a client asking for one would, and the only way to build this query
without going through the reader under test.
*/
@(private = "file")
version_query :: proc(version: u8, edns := true, cookie: []u8 = nil, name := REWRITTEN) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x4321,
		question = questions,
	}
	msg.flags.rd = true

	if edns {
		opt := dns.make_opt(1232, false)
		opt.ttl |= u32(version) << 16
		if cookie != nil {
			options := make([]dns.EDNS_Option, 1, context.temp_allocator)
			options[0] = dns.EDNS_Option {
				code = u16(dns.EDNS_Option_Code.Cookie),
				data = cookie,
			}
			opt.data = dns.Rdata_OPT{options = options}
		}
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
A server that can answer `REWRITTEN` from its configuration and nothing else, so
a version this server does implement has somewhere to be answered from.

The rewrite and its answers are allocated rather than written as slice literals:
a literal lives in the frame that made it, and these have to outlive this call.
*/
@(private = "file")
rewriting_server :: proc(cfg: ^config.Config) -> Server {
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
		domain  = REWRITTEN,
		answers = answers,
		ttl     = 300,
	}
	cfg.rewrites = rewrites
	return Server{cfg = cfg}
}

@(private = "file")
response_cookie :: proc(wire: []u8) -> (data: []u8, found: bool) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(m, .Cookie)
}

@(test)
test_edns_version_above_zero_is_refused_with_badvers :: proc(t: ^testing.T) {
	cfg: config.Config
	s := rewriting_server(&cfg)

	out, outcome, ok := handle_query(&s, version_query(1), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "a request in EDNS version 1 went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Refused)

	/*
	Both readers, because rcode 16 is four zero bits in the header and a one in
	the OPT record's extended byte. A response that lost the extended half reads
	as NOERROR to whichever of the two the client happens to use, and NOERROR
	with no answers is not a refusal - it is this server agreeing to a version it
	cannot speak.
	*/
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Bad_Vers)

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.Bad_Vers)

	// The name has a rewrite waiting for it, so an empty answer section is the
	// gate having run before anything was looked up rather than a miss.
	testing.expect_value(t, len(decoded.answer), 0)

	// RFC 6891 section 6.1.3 has the response state the highest version this
	// responder implements, which is 0, rather than echo the one asked for.
	testing.expect_value(t, dns.edns_version(decoded), u8(0))

	free_all(context.temp_allocator)
}

/*
Version 0, and no EDNS at all, are left exactly as they were.

The whole cost of this gate falls on requests it must not touch: version 0 is
what every ordinary client asks in, and a request with no OPT record states no
version and is owed no refusal. A reader that mistook either for a version above
zero would refuse every query this server has ever been sent.
*/
@(test)
test_edns_version_zero_and_plain_queries_are_untouched :: proc(t: ^testing.T) {
	cfg: config.Config
	s := rewriting_server(&cfg)

	out, outcome, ok := handle_query(&s, version_query(0), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "a request in EDNS version 0 went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)

	plain, plain_outcome, plain_ok := handle_query(
		&s,
		version_query(0, edns = false),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	if !testing.expect(t, plain_ok, "a request without EDNS went unanswered") {
		return
	}
	testing.expect_value(t, plain_outcome, Outcome.Rewritten)
	testing.expect_value(t, dns.peek_rcode(plain), dns.Rcode.No_Error)

	free_all(context.temp_allocator)
}

/*
A refusal for the version still hands back the cookie the client asked for.

RFC 7873 puts no condition on that, and BADVERS is not an exception any more
than BADCOOKIE is: a client that gets no cookie back reads it as a server that
does not do cookies, and under `cookies.require` that reading would leave it
stuck. The gate is written to fall through to `attach_cookie` rather than to
return out of `handle_query`, and this is what says so.

It also pins that the cookie can be added without costing the answer its rcode.
`attach_cookie` splices the option into the OPT record's RDATA and leaves the
TTL where it is, which is where the extended half of a BADVERS lives - and the
one path that instead rebuilds the record, for an answer that arrived with no
EDNS at all, would rebuild it at rcode 0.
*/
@(test)
test_badvers_still_carries_a_cookie_back :: proc(t: ^testing.T) {
	cfg: config.Config
	s := rewriting_server(&cfg)
	cfg.cookies.enabled = true
	cfg.cookies.secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
	if !testing.expect(t, start_cookies(&s), "the cookie keeper would not start") {
		return
	}
	defer stop_cookies(&s)

	client_cookie := make([]u8, 8, context.temp_allocator)
	copy(client_cookie, []u8{0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57})

	out, outcome, ok := handle_query(
		&s,
		version_query(1, cookie = client_cookie),
		.UDP,
		"198.51.100.100:9999",
		context.temp_allocator,
	)
	if !testing.expect(t, ok, "a request in EDNS version 1 with a cookie went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Refused)

	_, found := response_cookie(out)
	testing.expect(t, found, "BADVERS came back without the cookie the client asked for")
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Bad_Vers)

	free_all(context.temp_allocator)
}
