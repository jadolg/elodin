package server

import "core:fmt"
import "core:mem"
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
		time.tick_now(),
		&spent,
		context.temp_allocator,
		.Shared,
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

/*
Whichever allocation of the chase is refused, the answer is never the bare alias
(issue #620): that is the not-found a stub reads it as. It is the whole chain,
or SERVFAIL, or - with not even room for that - nothing.

Asked twice: once of a one-link chain, and once of one long enough that the
chain's list grows partway, so a link that fails to land is asked about too.
*/
@(test)
test_a_chase_that_runs_dry_is_never_the_bare_alias :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	chase_dry_sweep(t, chase_rules(), "old.lan.", 2)
	// With EDNS, so the answer's own OPT record is one of the refusals.
	chase_dry_sweep(t, chase_rules(), "old.lan.", 2, edns = true)

	long := make([]config.Rewrite, 7, context.temp_allocator)
	for i in 0 ..< 6 {
		long[i] = config.Rewrite {
			domain  = fmt.tprintf("a%d.lan.", i),
			answers = one_answer({kind = .CNAME, name = fmt.tprintf("a%d.lan.", i + 1)}),
			ttl     = 60,
		}
	}
	long[6] = config.Rewrite {
		domain  = "a6.lan.",
		answers = one_answer({kind = .A, v4 = {192, 168, 1, 60}}),
		ttl     = 60,
	}
	chase_dry_sweep(t, long, "a0.lan.", 7)

	// A target that is no rule, so it is asked of `resolve_query`, which the
	// special-use table answers NXDOMAIN without an upstream. Not NOERROR: the
	// chain alone is the bare alias.
	dead := make([]config.Rewrite, 1, context.temp_allocator)
	dead[0] = config.Rewrite {
		domain  = "dead.lan.",
		answers = one_answer({kind = .CNAME, name = "gone.invalid."}),
		ttl     = 60,
	}
	chase_dry_sweep(t, dead, "dead.lan.", 1, final = .NX_Domain)
}

@(private = "file")
chase_dry_sweep :: proc(
	t: ^testing.T,
	rules: []config.Rewrite,
	name: string,
	whole: int,
	edns := false,
	final := dns.Rcode.No_Error,
) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.rewrites = rules
	s := Server {
		cfg = &cfg,
	}
	questions := []dns.Question{{name = name, type = .A, class = .IN}}
	msg := dns.Message{id = 0x3202, question = questions}
	msg.flags.rd = true
	opt := []dns.Record{dns.make_opt(1232, false)}
	if edns {
		msg.additional = opt
	}
	plain, matched, alias := apply_rewrite(&s, msg, questions[0], context.temp_allocator, 512)
	cname, is_alias := alias.?
	if !testing.expectf(t, matched && is_alias, "%s should be answered by its alias", name) {
		return
	}
	servfails := 0
	// Runs as well as single refusals: a refused reservation is retried by the
	// append behind it, so an encode fails only when the grow is refused too.
	for run in ([]int{1, 3}) do for n := 1; ; n += 1 {
		f := Fail_Nth{fail_at = n, fail_for = run}
		one := mem.Allocator{procedure = fail_nth_proc, data = &f}
		spent := 0
		out, _ := chase_rewrite_alias(&s, plain, cname, msg, .UDP, "127.0.0.1:5555", 512, Cookie_Request{}, time.tick_now(), &spent, one, .Shared)
		if f.seen < n {
			break
		}
		if len(out) == 0 {
			continue
		}
		resp, derr := dns.decode_message(out, context.temp_allocator)
		if !testing.expect_value(t, derr, dns.Decode_Error.None) {
			return
		}
		rcode := dns.Rcode(resp.flags.rcode)
		if rcode == .Serv_Fail {
			servfails += 1
			continue
		}
		if !testing.expectf(t, rcode == final && len(resp.answer) == whole, "%s: refusing %d from allocation %d answered %v with %d records", name, run, n, rcode, len(resp.answer)) {
			return
		}
	}
	testing.expectf(t, servfails > 0, "%s: no refusal was answered SERVFAIL, so the guard went untested", name)
}

/*
A rewrite whose allocations run dry stays matched, and what it builds is the
whole alias or nothing: never a NODATA, never an `answers[0]` past the end, and
never unmatched, which would send the operator's name on to the upstreams.

Runs of refusals, since a refused reserve alone is retried by the append that
follows it.
*/
@(test)
test_a_rewrite_that_runs_dry_stays_matched :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.rewrites = chase_rules()
	s := Server {
		cfg = &cfg,
	}
	questions := []dns.Question{{name = "old.lan.", type = .A, class = .IN}}
	msg := dns.Message{id = 0x3203, question = questions}
	for run in ([]int{1, 2, 3, 8}) {
		for from := 1; ; from += 1 {
			f := Fail_Nth{fail_at = from, fail_for = run}
			dry := mem.Allocator{procedure = fail_nth_proc, data = &f}
			out, matched, _ := apply_rewrite(&s, msg, questions[0], dry, 512)
			if f.seen < from {
				break
			}
			if !testing.expectf(t, matched, "refusing %d from %d left the rule unmatched", run, from) {
				return
			}
			if len(out) == 0 {
				continue
			}
			resp, derr := dns.decode_message(out, context.temp_allocator)
			if !testing.expect_value(t, derr, dns.Decode_Error.None) {
				return
			}
			if !testing.expectf(t, len(resp.answer) == 1, "refusing %d from %d answered %d records", run, from, len(resp.answer)) {
				return
			}
		}
	}
}

/*
The reverse of a rewrite stays matched where its allocations run dry, as the
rewrite does: falling through would answer the address out of the special-use
table, which says it has no PTR.
*/
@(test)
test_a_reverse_rewrite_that_runs_dry_stays_matched :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg := config.default_config()
	cfg.log.queries = false
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = "nas.lan.",
		answers = one_answer({kind = .A, v4 = {192, 168, 1, 50}}),
		ttl     = 300,
		ptr     = true,
	}
	cfg.rewrites = rules
	s := Server {
		cfg = &cfg,
	}
	questions := []dns.Question{{name = "50.1.168.192.in-addr.arpa.", type = .PTR, class = .IN}}
	msg := dns.Message{id = 0x3204, question = questions}
	whole, whole_matched := apply_reverse_rewrite(&s, msg, questions[0], context.temp_allocator, 512)
	if !testing.expect(t, whole_matched && len(whole) > 0, "nas.lan.'s address should be answered by its PTR") {
		return
	}
	for run in ([]int{1, 3}) do for from := 1; ; from += 1 {
		f := Fail_Nth{fail_at = from, fail_for = run}
		dry := mem.Allocator{procedure = fail_nth_proc, data = &f}
		out, matched := apply_reverse_rewrite(&s, msg, questions[0], dry, 512)
		if f.seen < from {
			break
		}
		if !testing.expectf(t, matched, "refusing %d from %d left the PTR unmatched", run, from) {
			return
		}
		if len(out) > 0 && !testing.expectf(t, string(out) == string(whole), "refusing %d from %d built a different answer", run, from) {
			return
		}
	}
}
