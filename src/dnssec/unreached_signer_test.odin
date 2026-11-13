package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

// The captured chain, with lookup number `fail_at` unanswered: an upstream that
// lost one reply.
@(private = "file")
Losing_Upstream :: struct {
	fail_at: int,
	seen:    int,
}

@(private = "file")
losing_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> ([]u8, bool) {
	u := (^Losing_Upstream)(ctx)
	u.seen += 1
	if u.seen == u.fail_at {
		return nil, false
	}
	return fixture_answer(FIXTURES, name, type, allocator)
}

/*
A signature whose signer's walk lost a reply is untried, not refuted: where the
walk to the owner then holds up and nothing else verifies, the set is
`Indeterminate` for the walk that stopped, never `Bogus` (#636). Every lookup of
the walk lost in turn.
*/
@(test)
test_a_lost_chain_reply_is_not_a_forgery :: proc(t: ^testing.T) {
	wire := unhex(fixture("example_a").wire, context.allocator)
	defer delete(wire)
	lost := 0
	for n := 1; ; n += 1 {
		u := Losing_Upstream {
			fail_at = n,
		}
		v := make_validator(losing_query, &u, Options{})
		result := validate(v, "www.example.com.", .A, wire, fixture_now())
		destroy_validator(v)
		free_all(context.temp_allocator)
		if u.seen < n {
			testing.expectf(t, result.status == .Secure, "%v (%s) with no reply lost", result.status, result.reason)
			break
		}
		lost += 1
		testing.expectf(
			t,
			result.status == .Secure || result.status == .Indeterminate && result.reason == CHAIN_UNAVAILABLE,
			"lookup %d lost: %v (%s)",
			n,
			result.status,
			result.reason,
		)
	}
	testing.expect(t, lost > 0, "the walk asked nobody")
}
