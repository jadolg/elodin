package server

import "core:testing"
import "elodin:dns"

// One row of the table below: the question's type and class, and how it is
// answered.
@(private = "file")
Meta_Case :: struct {
	type:      dns.Type,
	class:     dns.Class,
	rcode:     dns.Rcode,
	ede:       int,
	forwarded: bool,
}

// Ask `h` the case's question and hold the answer to it: forwarded or answered
// here, with its rcode, and with its extended error when answered here.
@(private = "file")
expect_meta_answer :: proc(t: ^testing.T, h: ^Harness, c: Meta_Case) {
	query := test_query("example.com.", type = c.type, opt = dns.make_opt(1232, false), class = c.class if c.class != dns.Class(0) else .IN)
	out: []u8
	outcome: Outcome
	ok, asked: bool
	if c.forwarded {
		out, outcome, ok, asked = harness_ask(h, query, test_reply("example.com.", c.type))
	} else {
		out, outcome, ok = handle_query(&h.srv, query, .UDP, TEST_CLIENT, context.temp_allocator)
		asked = !mock_untouched(h.socket, query)
	}
	testing.expectf(t, asked == c.forwarded, "type %d: forwarded = %v", u16(c.type), asked)
	if !testing.expectf(t, ok, "type %d went unanswered", u16(c.type)) {
		return
	}
	msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "type %d: the answer does not decode: %v", u16(c.type), derr) {
		return
	}
	testing.expectf(t, dns.rcode_of(msg) == c.rcode, "type %d: rcode %v, want %v", u16(c.type), dns.rcode_of(msg), c.rcode)
	if c.forwarded {
		testing.expectf(t, outcome == .Forwarded, "type %d: outcome %v", u16(c.type), outcome)
		return
	}
	testing.expectf(t, outcome == .Refused, "type %d: outcome %v, want Refused", u16(c.type), outcome)
	testing.expectf(t, len(msg.question) == 1, "type %d: %d questions echoed", u16(c.type), len(msg.question))
	ede, why := extended_error(out)
	testing.expectf(t, ede == c.ede, "type %d: extended error %d (%q), want %d", u16(c.type), ede, why, c.ede)
}

/*
A question for a meta-type or a QTYPE this server will not forward is answered
here, without an upstream (RFC 6895 section 3.1 sets the 128-255 range apart).

- OPT, TKEY, TSIG and the meta range up to TSIG describe one message on one hop,
  so a question about them is FORMERR with extended error 30, "Invalid Query
  Type"; RFC 9824 section 3.5 makes that a MUST for NXNAME (128), and Unbound and
  BIND answer the whole range so.
- MAILA and MAILB are QTYPEs RFC 1035 defines and this server does not
  implement: NOTIMP, "does not support the requested kind of query" (RFC 1035
  section 4.1.1), as BIND answers.
- ANY is forwarded (RFC 8482), and an ordinary type above the range is too.
*/
@(test)
test_meta_qtypes_are_answered_without_forwarding :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)

	CASES := []Meta_Case {
		{type = .OPT, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = .NXNAME, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = dns.Type(200), rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = dns.Type(248), rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = .TKEY, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = .TSIG, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		// Whatever the class: RFC 9824 section 3.5's MUST is for any query.
		{type = .TSIG, class = .CH, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = .NXNAME, class = .HS, rcode = .Form_Err, ede = EDE_INVALID_QUERY_TYPE},
		{type = .MAILB, rcode = .Not_Impl, ede = -1},
		{type = .MAILA, rcode = .Not_Impl, ede = -1},
		{type = .AXFR, rcode = .Refused, ede = -1},
		{type = .ANY, rcode = .No_Error, forwarded = true},
		{type = dns.Type(127), rcode = .No_Error, forwarded = true},
		{type = .URI, rcode = .No_Error, forwarded = true},
	}

	for c in CASES {
		expect_meta_answer(t, &h, c)
	}
	free_all(context.temp_allocator)
}
