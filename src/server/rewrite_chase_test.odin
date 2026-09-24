package server

import "core:fmt"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A CNAME rewrite is answered with its target's records, not with the alias
alone (issue #320).

glibc's `getanswer_r` and musl both give up on an answer to an A query that
holds nothing but a CNAME, so a rewrite that stops at the alias reads as "Name
or service not known" to every ordinary program while `dig` looks fine. RFC 1034
section 4.3.2 step 3.a restarts the lookup at the canonical name, and that is
what these hold the server to. None of them configures an upstream: a target
that is itself a rewrite is answered here, and the forwarding of one that is not
is the integration suite's business, against a mock that can say it was asked.
*/

// Allocated rather than written as a slice literal, which would live in the
// frame of `chase_rules` and not outlive it.
@(private = "file")
one_answer :: proc(a: config.Rewrite_Answer) -> []config.Rewrite_Answer {
	answers := make([]config.Rewrite_Answer, 1, context.temp_allocator)
	answers[0] = a
	return answers
}

@(private = "file")
chase_rules :: proc() -> []config.Rewrite {
	rules := make([]config.Rewrite, 7, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "old.lan.",
		answers = one_answer({kind = .CNAME, name = "nas.lan."}),
		ttl     = 60,
	}
	rules[1] = config.Rewrite {
		domain  = "nas.lan.",
		answers = one_answer({kind = .A, v4 = {192, 168, 1, 50}}),
		ttl     = 300,
	}
	// A loop the loader cannot see coming once wildcards are involved.
	rules[2] = config.Rewrite {
		domain  = "ping.lan.",
		answers = one_answer({kind = .CNAME, name = "pong.lan."}),
		ttl     = 60,
	}
	rules[3] = config.Rewrite {
		domain  = "pong.lan.",
		answers = one_answer({kind = .CNAME, name = "ping.lan."}),
		ttl     = 60,
	}
	rules[4] = config.Rewrite {
		domain  = "ext.lan.",
		answers = one_answer({kind = .CNAME, name = "target.example.com."}),
		ttl     = 60,
	}
	rules[5] = config.Rewrite {
		domain  = "refused.lan.",
		answers = one_answer({kind = .CNAME, name = "sunk.lan."}),
		ttl     = 60,
	}
	rules[6] = config.Rewrite {
		domain  = "sunk.lan.",
		answers = one_answer({kind = .Block}),
		ttl     = 60,
	}
	return rules
}

@(private = "file")
chase_ask :: proc(
	t: ^testing.T,
	name: string,
	type: dns.Type,
	rd := true,
	block := config.Block_Response.NX_Domain,
	rewritten: ^u64 = nil,
	rules: []config.Rewrite = nil,
) -> (
	resp: dns.Message,
	ok: bool,
) {
	cfg := new(config.Config, context.temp_allocator)
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.blocking.response = block
	cfg.rewrites = rules if rules != nil else chase_rules()
	s := Server {
		cfg = cfg,
	}

	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = type, class = .IN}
	query := dns.Message{id = 0x3200, question = questions}
	query.flags.rd = rd
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	out, outcome, answered := handle_query(&s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if rewritten != nil {
		rewritten^ = s.stats.rewritten
	}
	if !testing.expect(t, answered, "the rewrite went unanswered") {
		return {}, false
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)
	msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return {}, false
	}
	return msg, true
}

@(test)
test_a_cname_rewrite_to_a_rewritten_name_carries_its_address :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "old.lan.", .A)
	if !ok {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.No_Error)
	if !testing.expectf(t, len(resp.answer) == 2, "want the CNAME and the target's A, got %d records", len(resp.answer)) {
		return
	}
	alias, is_alias := resp.answer[0].data.(dns.Rdata_Name)
	testing.expect(t, is_alias && resp.answer[0].type == .CNAME, "the first record is not the CNAME")
	testing.expect_value(t, alias.name, "nas.lan.")
	testing.expect_value(t, resp.answer[0].ttl, u32(60))
	a, is_a := resp.answer[1].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the second record is not an A")
	testing.expect_value(t, resp.answer[1].name, "nas.lan.")
	testing.expect_value(t, a.addr, [4]u8{192, 168, 1, 50})
	testing.expect_value(t, resp.answer[1].ttl, u32(300))
	testing.expect(t, !resp.flags.ad, "a locally made chain claims to have been validated")
}

// Nothing of that type at the target is NODATA for the chain, with the target's
// SOA to cache the denial by - not a bare CNAME that looks like the whole story.
@(test)
test_a_cname_rewrite_with_nothing_of_the_type_at_its_target_is_nodata :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "old.lan.", .AAAA)
	if !ok {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.No_Error)
	testing.expect_value(t, len(resp.answer), 1)
	testing.expect_value(t, len(resp.authority), 1)
}

// A question for the CNAME itself, or for everything, is answered by the alias:
// both match it, so RFC 1034 has nothing to restart.
@(test)
test_a_cname_question_is_answered_by_the_alias_alone :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	for type in ([]dns.Type{.CNAME, .ANY}) {
		resp, ok := chase_ask(t, "old.lan.", type)
		if !ok {
			return
		}
		testing.expectf(t, len(resp.answer) == 1, "%v: want the CNAME alone, got %d records", type, len(resp.answer))
	}
}

// A rewrite loop ends at the first name it comes back to, with each alias once:
// RFC 2181 section 5 has no RRset repeat a record.
@(test)
test_a_rewrite_loop_ends_where_it_comes_back :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "ping.lan.", .A)
	if !ok {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.No_Error)
	testing.expectf(t, len(resp.answer) == 2, "want ping->pong and pong->ping, got %d records", len(resp.answer))
}

// And a chain of distinct names ends at the bound, however many rules it has.
@(test)
test_a_long_rewrite_chain_stops_at_the_bound :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	rules := make([]config.Rewrite, MAX_REWRITE_CHASE + 2, context.temp_allocator)
	for i in 0 ..< len(rules) {
		rules[i] = config.Rewrite {
			domain  = fmt.aprintf("c%d.lan.", i, allocator = context.temp_allocator),
			answers = one_answer({kind = .CNAME, name = fmt.aprintf("c%d.lan.", i + 1, allocator = context.temp_allocator)}),
			ttl     = 60,
		}
	}
	resp, ok := chase_ask(t, "c0.lan.", .A, rules = rules)
	if !ok {
		return
	}
	testing.expect_value(t, len(resp.answer), MAX_REWRITE_CHASE)
}

// RD=0 asks for nothing to be looked up elsewhere, and a target that is no rule
// of ours could only be looked up elsewhere: the alias alone is the answer, as
// it always was, and not the RD gate's refusal of the target.
@(test)
test_a_cname_rewrite_without_recursion_desired_is_the_alias_alone :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "ext.lan.", .A, rd = false)
	if !ok {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.No_Error)
	testing.expect_value(t, len(resp.answer), 1)
}

// Whoever refuses the target - this server's policy, or an upstream's ACL - is
// refusing the target and not the alias, which is answerable: the client gets
// the alias and meets the refusal only if it asks for the target itself.
@(test)
test_a_cname_rewrite_to_a_refused_target_is_the_alias_alone :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "refused.lan.", .A, block = .Refused)
	if !ok {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.No_Error)
	testing.expect_value(t, len(resp.answer), 1)
}

// A target answered but not readable back - the request's decode budget spent -
// is SERVFAIL behind the alias, not the bare alias a stub reads as not found.
@(test)
test_a_chased_target_that_cannot_be_read_back_is_servfail :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.rewrites = chase_rules()
	s := Server {
		cfg = &cfg,
	}
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = "old.lan.", type = .A, class = .IN}
	msg := dns.Message{id = 0x3201, question = questions}
	msg.flags.rd = true

	plain, matched, alias := apply_rewrite(&s, msg, questions[0], context.temp_allocator, 512)
	cname, is_alias := alias.?
	if !testing.expect(t, matched && is_alias, "old.lan. should be answered by its alias") {
		return
	}
	spent := dns.REQUEST_DECODE_BUDGET + 1
	out, _ := chase_rewrite_alias(
		&s,
		plain,
		cname,
		msg,
		.UDP,
		"127.0.0.1:5555",
		512,
		Cookie_Request{},
		time.now(),
		&spent,
		context.temp_allocator,
		false,
	)
	resp, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect_value(t, derr, dns.Decode_Error.None) {
		return
	}
	testing.expect_value(t, dns.Rcode(resp.flags.rcode), dns.Rcode.Serv_Fail)
	testing.expect_value(t, len(resp.answer), 1)
}

// One query is one answer in `elodin_answers_total`, however many links it
// took: a chain of rewrites is one rewrite, and an alias left alone by a
// refusal - which counts nowhere - is still counted as one.
@(test)
test_a_chased_rewrite_is_counted_once :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cases := []struct {
		name: string,
		rd:   bool,
	}{{"old.lan.", true}, {"ping.lan.", true}, {"ext.lan.", false}}
	for c in cases {
		rewritten: u64
		if _, ok := chase_ask(t, c.name, .A, rd = c.rd, rewritten = &rewritten); ok {
			testing.expectf(t, rewritten == 1, "%s: counted %d times", c.name, rewritten)
		}
	}
}
