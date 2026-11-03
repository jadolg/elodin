package server

import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
The stages of `resolve_query` run on their own against a `Query_State`, and
each hands on what it does not answer.

An ordinary RD=0 question: `answer_locally` has nothing for it and passes it
on with the question settled, and `answer_from_cache`, with no cache, refuses
it at the RD gate (RFC 1035 section 4.1.1) having settled the cache key on the
way. `resolve_query`, running the stages in order, hands back that refusal.
*/
@(test)
test_stages_hand_on_what_they_do_not_answer :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	s := Server {
		cfg = &cfg,
	}

	questions := []dns.Question{{name = "example.com.", type = .A, class = .IN}}
	msg := dns.Message {
		id       = 0x1234,
		question = questions,
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, err, dns.Encode_Error.None) {
		return
	}
	spent: int
	st := Query_State {
		s         = &s,
		query     = wire,
		msg       = msg,
		proto     = .UDP,
		client    = "127.0.0.1:5555",
		limit     = 512,
		started   = time.tick_now(),
		spent     = &spent,
		allocator = context.temp_allocator,
	}

	testing.expect(t, !answer_locally(&st), "a name nothing local claims was answered locally")
	testing.expect_value(t, st.q.name, "example.com.")
	testing.expect(t, answer_from_cache(&st), "an RD=0 miss was handed on towards an upstream")
	testing.expect(t, st.key != "", "the cache stage did not settle the key")
	testing.expect(t, st.ok, "the RD gate's refusal was not built")
	testing.expect_value(t, st.outcome, Outcome.Refused)
	testing.expect_value(t, dns.peek_rcode(st.response), dns.Rcode.Refused)

	got := resolve_query(&s, wire, msg, .UDP, "127.0.0.1:5555", 512, {}, time.tick_now(), &spent, context.temp_allocator)
	testing.expect(t, got.ok, "resolve_query built no answer")
	testing.expect_value(t, got.outcome, Outcome.Refused)

	free_all(context.temp_allocator)
}
