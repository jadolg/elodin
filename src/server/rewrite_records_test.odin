package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
The record types a rewrite can answer with beyond an address and an alias.

What these pin is the step between the configuration and the wire: that each
kind reaches the encoder as the record it claims to be, with its fields in the
places the RFCs put them, and that a rule answering one type says "there is
none" for the others rather than answering with the wrong one.
*/

@(private = "file")
answers_of :: proc(list: ..config.Rewrite_Answer) -> []config.Rewrite_Answer {
	// See `reverse_test.odin`: a `[]T{...}` literal is a temporary in the
	// enclosing frame, so a rule set built from one and returned is a dangling
	// slice that reads as rules nobody wrote.
	out := make([]config.Rewrite_Answer, len(list), context.temp_allocator)
	copy(out, list)
	return out
}

@(private = "file")
strings_of :: proc(list: ..string) -> []string {
	out := make([]string, len(list), context.temp_allocator)
	copy(out, list)
	return out
}

// One rule for `mail.example.` carrying every kind at once, which is also the
// shape that says the kinds do not interfere with each other.
@(private = "file")
record_rules :: proc() -> []config.Rewrite {
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "mail.example.",
		answers = answers_of(
			{kind = .MX, preference = 10, name = "mx1.example."},
			{kind = .MX, preference = 20, name = "mx2.example."},
			{kind = .TXT, strings = strings_of("v=spf1 -all")},
			{kind = .SRV, priority = 0, weight = 5, port = 5060, name = "sip.example."},
			{kind = .A, v4 = {192, 0, 2, 10}},
		),
		ttl     = 222,
		ptr     = true,
	}
	return rules
}

@(private = "file")
ask :: proc(rules: []config.Rewrite, name: string, type: dns.Type) -> (dns.Message, Outcome, bool) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.rewrites = rules

	s := Server {
		cfg = &cfg,
	}
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	// RD=0, so a name the rules do not answer cannot reach the forwarding path -
	// there is no upstream here - and comes back Refused instead.
	query := dns.Message {
		id       = 0x51a0,
		question = questions,
	}
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if enc != .None {
		return {}, .Failed, false
	}
	out, outcome, ok := handle_query(&s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !ok {
		return {}, outcome, false
	}
	resp, derr := dns.decode_message(out, context.temp_allocator)
	if derr != .None {
		return {}, outcome, false
	}
	return resp, outcome, true
}

/*
Two MX records for one name, which is the ordinary shape of an MX answer: the
preference is what a sender sorts on, so a rule that could hold only one would
be a rule nobody with a backup mail server could use.
*/
@(test)
test_rewrite_answers_mx :: proc(t: ^testing.T) {
	resp, outcome, ok := ask(record_rules(), "mail.example.", .MX)
	if !testing.expect(t, ok, "the MX query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	if !testing.expect(t, len(resp.answer) == 2, "expected both MX records") {
		return
	}
	for rec, i in resp.answer {
		testing.expect_value(t, rec.type, dns.Type.MX)
		testing.expect_value(t, rec.ttl, u32(222))
		mx, is_mx := rec.data.(dns.Rdata_MX)
		if !testing.expect(t, is_mx, "the answer is not an MX record") {
			return
		}
		want_pref := u16(10) if i == 0 else u16(20)
		want_host := "mx1.example." if i == 0 else "mx2.example."
		testing.expect_value(t, mx.preference, want_pref)
		testing.expect_value(t, mx.exchange, want_host)
	}

	free_all(context.temp_allocator)
}

@(test)
test_rewrite_answers_txt :: proc(t: ^testing.T) {
	resp, _, ok := ask(record_rules(), "mail.example.", .TXT)
	if !testing.expect(t, ok, "the TXT query went unanswered") {
		return
	}
	if !testing.expect(t, len(resp.answer) == 1, "expected one TXT record") {
		return
	}
	testing.expect_value(t, resp.answer[0].type, dns.Type.TXT)
	txt, is_txt := resp.answer[0].data.(dns.Rdata_TXT)
	if !testing.expect(t, is_txt, "the answer is not a TXT record") {
		return
	}
	if testing.expect_value(t, len(txt.strings), 1) {
		testing.expect_value(t, txt.strings[0], "v=spf1 -all")
	}

	free_all(context.temp_allocator)
}

/*
The four fields of an SRV, in the order RFC 2782 gives them.

Pinned with four different numbers on purpose: priority, weight and port are
three u16s in a row, so a pair swapped anywhere between the config file and the
wire is invisible to a test that uses the same number twice.
*/
@(test)
test_rewrite_answers_srv :: proc(t: ^testing.T) {
	resp, _, ok := ask(record_rules(), "mail.example.", .SRV)
	if !testing.expect(t, ok, "the SRV query went unanswered") {
		return
	}
	if !testing.expect(t, len(resp.answer) == 1, "expected one SRV record") {
		return
	}
	testing.expect_value(t, resp.answer[0].type, dns.Type.SRV)
	srv, is_srv := resp.answer[0].data.(dns.Rdata_SRV)
	if !testing.expect(t, is_srv, "the answer is not an SRV record") {
		return
	}
	testing.expect_value(t, srv.priority, u16(0))
	testing.expect_value(t, srv.weight, u16(5))
	testing.expect_value(t, srv.port, u16(5060))
	testing.expect_value(t, srv.target, "sip.example.")

	free_all(context.temp_allocator)
}

/*
A type the rule has no record of is NODATA with an SOA, which is what
`apply_rewrite` already did for an address rule asked for an MX and is now the
answer in every direction.
*/
@(test)
test_rewrite_records_are_answered_by_type :: proc(t: ^testing.T) {
	resp, outcome, ok := ask(record_rules(), "mail.example.", .AAAA)
	if !testing.expect(t, ok, "the AAAA query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	testing.expect_value(t, resp.flags.rcode, u8(dns.Rcode.No_Error))
	testing.expect_value(t, len(resp.answer), 0)
	if testing.expect(t, len(resp.authority) == 1, "NODATA carries no SOA to cache it against") {
		testing.expect_value(t, resp.authority[0].type, dns.Type.SOA)
	}

	// And the A the same rule does carry is still answered, so it is the type
	// that decided this rather than the rule having been passed over.
	a_resp, _, a_ok := ask(record_rules(), "mail.example.", .A)
	if testing.expect(t, a_ok, "the A query went unanswered") {
		if testing.expect(t, len(a_resp.answer) == 1, "expected the A record") {
			testing.expect_value(t, a_resp.answer[0].type, dns.Type.A)
		}
	}

	free_all(context.temp_allocator)
}

// ANY is every record the rule holds, which is what the existing kinds already
// do and what a rule mixing types has to keep doing.
@(test)
test_rewrite_records_answer_any :: proc(t: ^testing.T) {
	resp, _, ok := ask(record_rules(), "mail.example.", .ANY)
	if !testing.expect(t, ok, "the ANY query went unanswered") {
		return
	}
	testing.expect_value(t, len(resp.answer), 5)

	free_all(context.temp_allocator)
}

/*
A rule that only adds records to a name leaves the rest of the name alone.

This is the difference between the kinds this commit adds and the ones that were
here before. An address, an alias and the sink each answer "what is this name",
so a rule holding one of them may say NODATA for the types it has no record of.
An `MX` does not: the ordinary reason to write one is a domain whose address is
somebody else's business, and `example.com` with two MX records is still a real
website. NODATA for its `A` would take that website away from every client
behind this server, with an SOA on the answer so they remembered it.

`Refused` is what falling through looks like in a test with no upstream and
RD=0, and it is the whole of the assertion: the rule declined to answer and the
query went on down the pipeline.
*/
@(test)
test_a_record_only_rule_leaves_other_types_alone :: proc(t: ^testing.T) {
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "example.com.",
		answers = answers_of(
			{kind = .MX, preference = 10, name = "mail.example.com."},
			{kind = .TXT, strings = strings_of("v=spf1 -all")},
		),
		ttl     = 300,
		ptr     = true,
	}

	_, forwarded, _ := ask(rules, "example.com.", .A)
	testing.expect_value(t, forwarded, Outcome.Refused)

	// The types it does hold are still answered here.
	resp, answered, ok := ask(rules, "example.com.", .MX)
	if testing.expect(t, ok, "the MX query went unanswered") {
		testing.expect_value(t, answered, Outcome.Rewritten)
		testing.expect_value(t, len(resp.answer), 1)
	}

	free_all(context.temp_allocator)
}

/*
The other side of it: one address in the rule and the old reading is back.

That is the line, and it is deliberate - an operator who wants the name wholly
answered here writes down where it points, which is what they were always
writing before these kinds existed.
*/
@(test)
test_an_address_in_the_rule_still_claims_the_whole_name :: proc(t: ^testing.T) {
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "example.com.",
		answers = answers_of(
			{kind = .MX, preference = 10, name = "mail.example.com."},
			{kind = .A, v4 = {192, 0, 2, 10}},
		),
		ttl     = 300,
		ptr     = true,
	}

	resp, outcome, ok := ask(rules, "example.com.", .AAAA)
	if !testing.expect(t, ok, "the AAAA query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	testing.expect_value(t, resp.flags.rcode, u8(dns.Rcode.No_Error))
	testing.expect_value(t, len(resp.answer), 0)
	testing.expect_value(t, len(resp.authority), 1)

	/*
	A CNAME and `block` say the same thing about a name, so each of them claims
	it too.

	A CNAME is alone in its rule because the loader will not let it share one
	(RFC 2181 section 10.1), which is the shape it has in any configuration that
	loads; `block` may sit beside a record, and does here.
	*/
	alias := make([]config.Rewrite, 1, context.temp_allocator)
	alias[0] = config.Rewrite {
		domain  = "other.example.",
		answers = answers_of({kind = .CNAME, name = "elsewhere.example."}),
		ttl     = 300,
		ptr     = true,
	}
	_, alias_outcome, _ := ask(alias, "other.example.", .AAAA)
	testing.expect_value(t, alias_outcome, Outcome.Rewritten)

	sunk := make([]config.Rewrite, 1, context.temp_allocator)
	sunk[0] = config.Rewrite {
		domain  = "sunk.example.",
		answers = answers_of({kind = .TXT, strings = strings_of("x")}, {kind = .Block}),
		ttl     = 300,
		ptr     = true,
	}
	// Counted as a rewrite rather than as a block, `apply_rewrite` being what
	// answered; the rcode is what says the name was sunk and not merely found to
	// have no AAAA.
	sunk_resp, sunk_outcome, sunk_ok := ask(sunk, "sunk.example.", .AAAA)
	testing.expect_value(t, sunk_outcome, Outcome.Rewritten)
	if testing.expect(t, sunk_ok, "the sunk name went unanswered") {
		testing.expect_value(t, sunk_resp.flags.rcode, u8(dns.Rcode.NX_Domain))
	}

	free_all(context.temp_allocator)
}

/*
A rule with an MX and nothing else claims no address, so it supplies no reverse
either - the PTR synthesis reads addresses out of `answers`, and there is none
here to read.
*/
@(test)
test_a_record_only_rule_supplies_no_reverse :: proc(t: ^testing.T) {
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "mail.example.",
		answers = answers_of({kind = .MX, preference = 10, name = "mx1.example."}),
		ttl     = 300,
		ptr     = true,
	}

	_, _, found := reverse_rewrite_target(rules, "50.1.168.192.in-addr.arpa.")
	testing.expect(t, !found, "a rule with no address can be the reverse of nothing")

	free_all(context.temp_allocator)
}
