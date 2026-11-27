package upstream

import "core:sync"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #245: `resolve_proving` sweeps past an answerable reply that is not the
one its caller holds out for. A routed apex's `DS` is the caller - one member's
NXDOMAIN beside another's NODATA proof - and a sweep that stops at the first
answerable reply leaves which of the two the client gets to the member the
group reaches.
*/

// Starts one member per rcode, in order. `stop_mock_set` tears down whatever
// started.
@(private = "file")
start_fixed :: proc(t: ^testing.T, fg: ^Mock_Set(3), rcodes: []dns.Rcode) -> bool {
	for rcode, i in rcodes {
		fg.mocks[i].rcode = u8(rcode) & 0xf
	}
	return start_mock_set(t, fg, "member", count = len(rcodes))
}

@(private = "file")
fixed_query :: proc() -> []u8 {
	query := dns.Message{id = 0x0245, question = []dns.Question{{name = "corp.example.", type = .DS, class = .IN}}}
	query.flags.rd = true
	wire, _, _ := dns.encode_message(query, context.temp_allocator)
	return wire
}

// One exchange with each member, so that each is known to be answering: the
// sweep holds out for a proof only from those (see `answering`).
@(private = "file")
warm :: proc(t: ^testing.T, fg: ^Mock_Set(3)) {
	for u in fg.servers[:fg.live] {
		resp, err := exchange(u, fixed_query(), time.Second, context.allocator)
		testing.expectf(t, err == .None, "warming %s: %v", u.spec.name, err)
		delete(resp, context.allocator)
	}
	for &m in fg.mocks[:fg.live] {
		sync.atomic_store(&m.hits, 0)
	}
}

// The proof as these tests have it: a NOERROR.
@(private = "file")
proves_noerror :: proc(response: []u8, _: rawptr) -> bool {
	return dns.peek_rcode(response) == .No_Error
}

@(private = "file")
proves_nothing :: proc(_: []u8, _: rawptr) -> bool {
	return false
}

@(test)
test_an_answerable_reply_that_is_not_the_proof_does_not_end_the_sweep :: proc(t: ^testing.T) {
	fg: Mock_Set(3)
	defer stop_mock_set(&fg)
	if !start_fixed(t, &fg, {.NX_Domain, .No_Error}) {
		return
	}
	warm(t, &fg)
	g := failover_group(fg.servers[:2])
	wire := fixed_query()

	// The premise: `resolve_answerable`, which takes any answerable reply,
	// stops at the NXDOMAIN.
	first, first_winner, first_err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, first_err, Error.None)
	testing.expect(t, first_winner == fg.servers[0], "resolve_answerable did not stop at the NXDOMAIN")
	testing.expect_value(t, sync.atomic_load(&fg.mocks[1].hits), 0)
	delete(first, context.allocator)

	resp, winner, err := resolve_proving(&g, wire, proves_noerror, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[1], "the sweep stopped short of the member holding the proof")
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.No_Error)
	delete(resp, context.allocator)
	// A disagreement, not a member failing its group: nothing is counted.
	testing.expect_value(t, fg.servers[0].stats.swept_rcode, 0)
	free_all(context.temp_allocator)
}

@(test)
test_a_proof_from_the_first_member_sweeps_nobody :: proc(t: ^testing.T) {
	fg: Mock_Set(3)
	defer stop_mock_set(&fg)
	if !start_fixed(t, &fg, {.No_Error, .NX_Domain}) {
		return
	}
	g := failover_group(fg.servers[:2])
	resp, winner, err := resolve_proving(&g, fixed_query(), proves_noerror, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[0], "the first member's proof was not taken")
	testing.expect_value(t, sync.atomic_load(&fg.mocks[1].hits), 0)
	delete(resp, context.allocator)
	free_all(context.temp_allocator)
}

/*
And where nobody proves anything, the first answerable reply stands - not the
first reply, which `resolve_answerable` would have swept past, and not a later
answerable one, which would make the answer turn on the group's order past it.
*/
@(test)
test_a_sweep_with_no_proof_keeps_the_first_answerable_reply :: proc(t: ^testing.T) {
	fg: Mock_Set(3)
	defer stop_mock_set(&fg)
	if !start_fixed(t, &fg, {.Serv_Fail, .NX_Domain, .No_Error}) {
		return
	}
	warm(t, &fg)
	g := failover_group(fg.servers[:3])
	resp, winner, err := resolve_proving(&g, fixed_query(), proves_nothing, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[1], "the first answerable reply did not stand")
	testing.expect_value(t, dns.peek_rcode(resp), dns.Rcode.NX_Domain)
	testing.expect(t, sync.atomic_load(&fg.mocks[2].hits) > 0, "the sweep stopped before the last member")
	// The SERVFAIL is what sent the group looking, and is counted as always.
	testing.expect_value(t, fg.servers[0].stats.swept_rcode, 1)
	delete(resp, context.allocator)
	free_all(context.temp_allocator)
}

/*
And the member whose reply sent the group looking is not asked again, even once
a later member's answerable reply has taken its place in hand: under
`round_robin` it can sit after that member in `g.servers`.
*/
@(test)
test_the_member_that_sent_the_group_looking_is_not_asked_again :: proc(t: ^testing.T) {
	fg: Mock_Set(3)
	defer stop_mock_set(&fg)
	if !start_fixed(t, &fg, {.NX_Domain, .Serv_Fail}) {
		return
	}
	warm(t, &fg)
	g := Group {
		servers   = fg.servers[:2],
		strategy  = .Round_Robin,
		timeout   = time.Second,
		attempts  = 1,
		cursor    = 1,
		allocator = context.allocator,
	}
	resp, winner, err := resolve_proving(&g, fixed_query(), proves_noerror, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[0], "the NXDOMAIN did not take the SERVFAIL's place")
	testing.expect_value(t, sync.atomic_load(&fg.mocks[1].hits), 1)
	delete(resp, context.allocator)
	free_all(context.temp_allocator)
}

/*
And a member not known to be answering is not held out for: with an answer
already in hand, waiting `g.timeout` on a dead spare costs a client that has
one. Neither a member never yet asked nor one whose last exchange failed.
*/
@(test)
test_a_member_not_known_to_be_answering_is_not_held_out_for :: proc(t: ^testing.T) {
	fg: Mock_Set(3)
	defer stop_mock_set(&fg)
	if !start_fixed(t, &fg, {.NX_Domain, .No_Error}) {
		return
	}
	g := failover_group(fg.servers[:2])

	// Never asked: a failover spare, or a fresh start.
	resp, winner, err := resolve_proving(&g, fixed_query(), proves_noerror, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[0], "the NXDOMAIN in hand did not stand")
	testing.expect_value(t, sync.atomic_load(&fg.mocks[1].hits), 0)
	delete(resp, context.allocator)

	// Answered once, then failed: the member is still `healthy`, short of the
	// three failures that park it, and still not held out for.
	warm(t, &fg)
	record_failure(fg.servers[1], .Timeout)
	testing.expect(t, healthy(fg.servers[1]), "one failure parked the member")
	resp, winner, err = resolve_proving(&g, fixed_query(), proves_noerror, nil, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == fg.servers[0], "the NXDOMAIN in hand did not stand")
	testing.expect_value(t, sync.atomic_load(&fg.mocks[1].hits), 0)
	delete(resp, context.allocator)
	free_all(context.temp_allocator)
}
