package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

@(private = "file")
TWO_QUESTIONS :: "two.qdcount.test."

// A QUERY asking two questions, with no OPT record or one in EDNS `version`.
@(private = "file")
two_question_query :: proc(t: ^testing.T, edns: bool, version: u8 = 0) -> (wire: []u8, ok: bool) {
	q := dns.Message {
		id       = 0x6930,
		question = []dns.Question{{name = TWO_QUESTIONS, type = .A, class = .IN}, {name = "other.qdcount.test.", type = .A, class = .IN}},
	}
	q.flags.rd = true
	if edns {
		opt := dns.make_opt(1232, false)
		opt.ttl |= u32(version) << 16
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = opt
		q.additional = additional
	}
	out, _, err := dns.encode_message(q, context.temp_allocator)
	return out, testing.expectf(t, err == .None, "cannot encode the query: %v", err)
}

/*
RFC 9619 section 4: "A DNS message with OPCODE = 0 and QDCOUNT > 1 MUST be
treated as an incorrectly formatted message. The value of the RCODE parameter in
the response message MUST be set to 1 (FORMERR)", and no message with OPCODE 0,
the response included, may carry more than one question. With or without EDNS,
and whatever version it asks in: the count is a property of the message, read
before its EDNS is (as Unbound's `worker_check_request` does).
*/
@(test)
test_two_questions_are_formerr_with_one_echoed :: proc(t: ^testing.T) {
	cfg: config.Config
	s := rewrite_server(&cfg, TWO_QUESTIONS)
	Row :: struct {
		what:    string,
		edns:    bool,
		version: u8,
	}
	for row in ([]Row{{what = "no EDNS"}, {what = "EDNS 0", edns = true}, {what = "EDNS 1", edns = true, version = 1}}) {
		query, built := two_question_query(t, row.edns, row.version)
		if !built {
			return
		}
		out, _, ok := handle_query(&s, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok && out != nil, "%s: no answer", row.what) {
			continue
		}
		msg, derr := dns.decode_message(out, context.temp_allocator)
		if !testing.expectf(t, derr == .None, "%s: the answer does not decode: %v", row.what, derr) {
			continue
		}
		testing.expectf(t, dns.rcode_of(msg) == .Form_Err, "%s: rcode %v, want FORMERR", row.what, dns.rcode_of(msg))
		testing.expectf(t, len(msg.question) <= 1, "%s: %d questions echoed", row.what, len(msg.question))
		testing.expectf(t, dns.edns_present(msg) == row.edns, "%s: EDNS in the answer %v", row.what, dns.edns_present(msg))
	}
	free_all(context.temp_allocator)
}
