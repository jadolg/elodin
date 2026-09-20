package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #354: the chain walk reads a reply per step into the request's arena, and
`dns.NAME_BUDGET` bounded each of those readings on its own.

The counter is the request's now, so a walk can run out of it - and what it
reports then must be the truth, which is that this server stopped reading. The
alternative is an accusation: a zone reported forged because the question it
belongs to had already expanded its allowance of names, at a moment an attacker
with a signed zone chooses by answering the chain expensively.
*/

// A reply with a name in it, so that a counter already past its budget is
// noticed on the first charge. Nothing about it is malformed.
@(private = "file")
ordinary_reply :: proc(name: string, type: dns.Type) -> []u8 {
	m := dns.Message {
		id       = 0x3c3c,
		question = []dns.Question{{name = name, type = type, class = .IN}},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("the fixture does not encode")
	}
	return wire
}

@(private = "file")
spent_counter :: proc() -> int {
	return dns.REQUEST_NAME_BUDGET + 1
}

/*
A response this server had no allowance left to read is undecided, not forged.

`Bogus` reaches the client as SERVFAIL with EDE 6, which says the records were
checked and found false. Nothing was checked here.
*/
@(test)
test_a_response_past_the_request_name_budget_is_not_called_a_forgery :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	names := spent_counter()
	result := validate(
		v,
		"www.example.com.",
		.A,
		ordinary_reply("www.example.com.", .A),
		time.unix(FIXTURE_TIME, 0),
		context.temp_allocator,
		names = &names,
	)
	testing.expect_value(t, result.status, Status.Indeterminate)
	testing.expect_value(t, result.reason, NAMES_OVER_BUDGET)
	testing.expect_value(t, up.calls, 0)
	free_all(context.temp_allocator)
}

/*
And neither is a step of the chain.

The upstream answers the DS lookup perfectly well; the request simply has
nothing left to expand the reply's names into. `zone_step` used to read any
decode failure as a broken delegation, which under this counter would report a
forgery for every zone the walk reached after the allowance ran out.
*/
@(test)
test_a_chain_step_past_the_request_name_budget_stops_the_walk :: proc(t: ^testing.T) {
	up := Answering_Upstream{}
	v := make_validator(answering_query, &up, Options{})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, now)

	names := spent_counter()
	budget := query_budget(v)
	budget.names = &names
	status, _, _ := zone_trust(v, &budget, "www.example.com.", now, context.temp_allocator)

	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect_value(t, budget.walk_stopped, NAMES_OVER_BUDGET)
	testing.expectf(t, up.calls > 0, "the walk stopped before it asked anybody anything")
	free_all(context.temp_allocator)
}

/*
The same walk, with the request's allowance intact, still reads what it is sent.

The counter is only a bound, and a test that passes because nothing was ever
read would pass with the walk broken. Here the reply is the same one - an empty
answer the parent never signed - and the step is `Bogus` for what it says rather
than `Indeterminate` for what this server declined to read.
*/
@(test)
test_a_chain_step_within_the_request_name_budget_reads_the_reply :: proc(t: ^testing.T) {
	up := Answering_Upstream{}
	v := make_validator(answering_query, &up, Options{})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, now)

	names := 0
	budget := query_budget(v)
	budget.names = &names
	status, _, _ := zone_trust(v, &budget, "www.example.com.", now, context.temp_allocator)

	testing.expect_value(t, status, Status.Bogus)
	testing.expectf(t, names > 0, "the walk read a reply and charged the request nothing")
	free_all(context.temp_allocator)
}

// An upstream that answers every lookup with a reply about the name it was
// asked, and counts them.
@(private = "file")
Answering_Upstream :: struct {
	calls: int,
}

@(private = "file")
answering_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	u := cast(^Answering_Upstream)ctx
	u.calls += 1
	return ordinary_reply(name, type), true
}

@(private = "file")
Counting_Upstream :: struct {
	calls: int,
}

@(private = "file")
counting_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	u := cast(^Counting_Upstream)ctx
	u.calls += 1
	return nil, false
}
