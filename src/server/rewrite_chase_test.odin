package server

import "core:testing"
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
	rules := make([]config.Rewrite, 5, context.temp_allocator)
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
	return rules
}

@(private = "file")
chase_ask :: proc(t: ^testing.T, name: string, type: dns.Type, rd := true) -> (resp: dns.Message, ok: bool) {
	cfg := new(config.Config, context.temp_allocator)
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.rewrites = chase_rules()
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

// A rewrite loop ends, and ends with an answer rather than a worker lost to it.
@(test)
test_a_rewrite_loop_is_chased_a_bounded_number_of_times :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	resp, ok := chase_ask(t, "ping.lan.", .A)
	if !ok {
		return
	}
	testing.expectf(
		t,
		len(resp.answer) == MAX_REWRITE_CHASE + 1,
		"want %d CNAMEs, got %d records",
		MAX_REWRITE_CHASE + 1,
		len(resp.answer),
	)
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
