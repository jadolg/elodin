package upstream

import "core:fmt"
import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A failover or round-robin query waits out a bounded budget, not every member for
every attempt (issue #327).

`resolve_sequential` used to loop `attempts` rounds over every member at the
full timeout each: two black-holed members at the shipped five seconds and two
attempts held a query worker for twenty seconds, four times what a stub waits,
and a client repeating such names could empty the pool.
*/

@(private = "file")
DEADLINE_TIMEOUT :: 200 * time.Millisecond

// Answers every query by echoing it back as a response after `delay`, or reads
// it and says nothing when `mute` is set. Counts what it was asked either way.
@(private = "file")
Echo_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	mute:   bool,
	delay:  time.Duration,
	// The header rcode of the echo, NOERROR unless set.
	rcode:  u8,
	hits:   int,
}

@(private = "file")
echo_mock_loop :: proc(m: ^Echo_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		if m.mute {
			continue
		}
		if m.delay > 0 {
			time.sleep(m.delay)
		}
		buf[2] |= 0x80
		buf[3] = 0x80 | (buf[3] & 0x70) | (m.rcode & 0xf)
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

@(private = "file")
start_echo_mock :: proc(t: ^testing.T, m: ^Echo_Mock, name: string) -> (u: ^Upstream, worker: ^thread.Thread, ok: bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind a loopback responder: %v", serr) {
		return nil, nil, false
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the responder's port: %v", berr) {
		net.close(socket)
		return nil, nil, false
	}
	built, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		DEADLINE_TIMEOUT,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		net.close(socket)
		return nil, nil, false
	}
	return built, thread.create_and_start_with_poly_data(m, echo_mock_loop), true
}

@(private = "file")
stop_echo_mock :: proc(m: ^Echo_Mock, u: ^Upstream, worker: ^thread.Thread) {
	sync.atomic_store(&m.stop, true)
	thread.join(worker)
	thread.destroy(worker)
	net.close(m.socket)
	destroy(u)
}

@(private = "file")
deadline_query :: proc() -> []u8 {
	msg := dns.Message {
		id       = 0x3270,
		question = []dns.Question{{name = "hole.example.test.", type = .A, class = .IN}},
	}
	msg.flags.rd = true
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	return wire
}

/*
Two members that never answer and a third that would be asked next: the query
gives up once two timeouts have been waited, rather than after every member
twice over (six timeouts here), and the third is never reached.
*/
@(test)
test_a_failover_query_waits_out_two_timeouts_and_no_more :: proc(t: ^testing.T) {
	mocks: [3]Echo_Mock
	ups: [3]^Upstream
	workers: [3]^thread.Thread
	for i in 0 ..< 3 {
		mocks[i].mute = true
		ok: bool
		ups[i], workers[i], ok = start_echo_mock(t, &mocks[i], "hole")
		if !ok {
			return
		}
	}
	defer for i in 0 ..< 3 {
		stop_echo_mock(&mocks[i], ups[i], workers[i])
	}

	g := Group {
		servers   = ups[:],
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 2,
		allocator = context.allocator,
	}
	started := time.tick_now()
	resp, _, err := resolve(&g, deadline_query(), context.allocator)
	spent := time.tick_since(started)
	delete(resp, context.allocator)

	testing.expect(t, err != .None, "a group of silent members produced an answer")
	testing.expect(t, sync.atomic_load(&mocks[0].hits) == 1 && sync.atomic_load(&mocks[1].hits) == 1, "the first two members were not each asked once")
	testing.expectf(t, sync.atomic_load(&mocks[2].hits) == 0, "a third member was asked after two timeouts had gone")
	// Under three timeouts, the design's worst case, so a loaded runner has a
	// whole timeout of slack; the unbounded loop waited six.
	testing.expectf(t, spent < 3 * DEADLINE_TIMEOUT, "the query waited %v, where the budget is two timeouts of %v", spent, DEADLINE_TIMEOUT)
	free_all(context.temp_allocator)
}

/*
And the budget costs failover nothing: a dead first member still hands over to
the second within the query, and the second is given its whole timeout - it
answers after most of one here, which a share of what was left would have cut
off and counted as a failure against it.
*/
@(test)
test_a_dead_first_member_still_fails_over_to_a_slow_second :: proc(t: ^testing.T) {
	dead, slow: Echo_Mock
	dead.mute = true
	slow.delay = DEADLINE_TIMEOUT * 7 / 10
	du, dw, dok := start_echo_mock(t, &dead, "dead")
	if !dok {
		return
	}
	defer stop_echo_mock(&dead, du, dw)
	su, sw, sok := start_echo_mock(t, &slow, "slow")
	if !sok {
		return
	}
	defer stop_echo_mock(&slow, su, sw)

	servers := []^Upstream{du, su}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 2,
		allocator = context.allocator,
	}
	resp, winner, err := resolve(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == su, "the answer did not come from the second member")
	free_all(context.temp_allocator)
}

/*
What is bounded is waiting, not attempts. Members whose hostname cannot be
resolved fail before sending anything and cost nothing, so three of them, then
a dead member, still leave the budget room to reach the live one behind: a
bound on attempts would have stopped at the unresolvable ones on every query,
which is issue #309's failure and one that never heals.
*/
@(test)
test_members_that_fail_for_free_do_not_spend_the_budget :: proc(t: ^testing.T) {
	stuck: [3]^Upstream
	for i in 0 ..< 3 {
		// No bootstrap servers and an RFC 2606 name: `bootstrap_resolve` gives
		// up without a query.
		u, uerr := make_upstream(
			config.Upstream_Spec{name = "unresolvable", kind = .UDP, address = "upstream.invalid", port = 53},
			0,
			DEADLINE_TIMEOUT,
			context.allocator,
		)
		if !testing.expectf(t, uerr == .None, "cannot build the unresolvable upstream: %v", uerr) {
			return
		}
		stuck[i] = u
	}
	defer for u in stuck {
		destroy(u)
	}
	dead, slow: Echo_Mock
	dead.mute = true
	slow.delay = DEADLINE_TIMEOUT * 7 / 10
	du, dw, dok := start_echo_mock(t, &dead, "dead")
	if !dok {
		return
	}
	defer stop_echo_mock(&dead, du, dw)
	su, sw, sok := start_echo_mock(t, &slow, "slow")
	if !sok {
		return
	}
	defer stop_echo_mock(&slow, su, sw)

	servers := []^Upstream{stuck[0], stuck[1], stuck[2], du, su}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}
	resp, winner, err := resolve(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == su, "the live member behind the free failures and one dead member was not reached")
	free_all(context.temp_allocator)
}


/*
A later round asks a parked member before asking again one this query has just
seen fail. With two timeouts to spend, the order is who gets asked: one member
gone quiet and a parked one that has come back would otherwise spend the second
timeout on the quiet one again, and the client would get SERVFAIL from a group
holding a live member.
*/
@(test)
test_a_retry_round_asks_a_parked_member_before_a_failed_one :: proc(t: ^testing.T) {
	quiet, back: Echo_Mock
	quiet.mute = true
	qu, qw, qok := start_echo_mock(t, &quiet, "quiet")
	if !qok {
		return
	}
	defer stop_echo_mock(&quiet, qu, qw)
	bu, bw, bok := start_echo_mock(t, &back, "back")
	if !bok {
		return
	}
	defer stop_echo_mock(&back, bu, bw)
	// Parked by what it did a moment ago, and answering again now.
	bu.failures = FAILURE_THRESHOLD
	bu.down_until = time.time_add(time.now(), COOLDOWN)

	servers := []^Upstream{qu, bu}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 2,
		allocator = context.allocator,
	}
	resp, winner, err := resolve(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == bu, "the parked member that came back was not asked")
	testing.expect_value(t, sync.atomic_load(&quiet.hits), 1)
	free_all(context.temp_allocator)
}


/*
And the order is by what this query did, not by what the member's health says
by the time the retry round starts. A quiet member one failure short of the
threshold parks on this query's own timeout, so reading `healthy` again would
put it among the parked members and ask it a second time ahead of the one that
came back, spending the second timeout on it and never reaching the other.
*/
@(test)
test_a_member_parked_by_this_query_is_not_asked_again_first :: proc(t: ^testing.T) {
	quiet, back: Echo_Mock
	quiet.mute = true
	qu, qw, qok := start_echo_mock(t, &quiet, "quiet")
	if !qok {
		return
	}
	defer stop_echo_mock(&quiet, qu, qw)
	bu, bw, bok := start_echo_mock(t, &back, "back")
	if !bok {
		return
	}
	defer stop_echo_mock(&back, bu, bw)
	qu.failures = FAILURE_THRESHOLD - 1
	bu.failures = FAILURE_THRESHOLD
	bu.down_until = time.time_add(time.now(), COOLDOWN)

	servers := []^Upstream{qu, bu}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 2,
		allocator = context.allocator,
	}
	resp, winner, err := resolve(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == bu, "the parked member that came back was not asked")
	testing.expect_value(t, sync.atomic_load(&quiet.hits), 1)
	free_all(context.temp_allocator)
}

// An upstream named by hostname whose bootstrap resolver echoes the lookup back
// with no answer after `delay`, so every exchange on it fails `Not_Resolved`
// having waited two lookups (A and AAAA) for nothing.
@(private = "file")
slow_unresolvable :: proc(t: ^testing.T, bu: ^Upstream) -> ^Upstream {
	// Kept by the upstream, so not a literal on this frame.
	bootstrap := make([]string, 1, context.temp_allocator)
	bootstrap[0] = fmt.tprintf("127.0.0.1:%d", bu.endpoint.port)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "unresolvable", kind = .UDP, address = "slow-bootstrap.example.test", port = 53, bootstrap = bootstrap},
		0,
		DEADLINE_TIMEOUT,
		context.allocator,
	)
	testing.expectf(t, uerr == .None, "cannot build the unresolvable upstream: %v", uerr)
	return u
}

/*
A hostname the bootstrap takes time to fail on is charged, and parks.

Both halves, because each is the other's reason. Charged, or a bootstrap
resolver gone quiet makes the wait unbounded again; parked, or the member that
is charged for it every query takes the whole budget on every query and the
live member behind it is never reached - the two ways review of #327 went.

Here the member costs 1.2 timeouts and a dead one behind it one more, which is
the budget, so the live member is not reached while the first is still in the
group. After `FAILURE_THRESHOLD` such queries both have parked and it is.
*/
@(test)
test_a_slow_unresolvable_member_is_charged_and_parks :: proc(t: ^testing.T) {
	boot, dead, live: Echo_Mock
	boot.delay = DEADLINE_TIMEOUT * 6 / 10
	dead.mute = true
	bu, bw, bok := start_echo_mock(t, &boot, "bootstrap")
	if !bok {
		return
	}
	defer stop_echo_mock(&boot, bu, bw)
	du, dw, dok := start_echo_mock(t, &dead, "dead")
	if !dok {
		return
	}
	defer stop_echo_mock(&dead, du, dw)
	lu, lw, lok := start_echo_mock(t, &live, "live")
	if !lok {
		return
	}
	defer stop_echo_mock(&live, lu, lw)
	stuck := slow_unresolvable(t, bu)
	defer destroy(stuck)

	servers := []^Upstream{stuck, du, lu}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}
	for i in 0 ..< FAILURE_THRESHOLD {
		resp, _, err := resolve(&g, deadline_query(), context.allocator)
		delete(resp, context.allocator)
		testing.expectf(t, err != .None, "query %d answered while the slow member was still in the group", i + 1)
	}
	testing.expect_value(t, sync.atomic_load(&live.hits), 0)
	testing.expect(t, !healthy(stuck), "the unresolvable member did not park")

	resp, winner, err := resolve(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == lu, "the live member was not reached once the others had parked")
	free_all(context.temp_allocator)
}

/*
And the same in the sweep, whose budget is one timeout: the slow member takes
it until it parks, and the member behind it answers from then on.
*/
@(test)
test_the_sweep_charges_a_slow_unresolvable_member_until_it_parks :: proc(t: ^testing.T) {
	boot, refusing, live: Echo_Mock
	boot.delay = DEADLINE_TIMEOUT * 6 / 10
	refusing.rcode = u8(dns.Rcode.Refused)
	bu, bw, bok := start_echo_mock(t, &boot, "bootstrap")
	if !bok {
		return
	}
	defer stop_echo_mock(&boot, bu, bw)
	ru, rw, rok := start_echo_mock(t, &refusing, "refusing")
	if !rok {
		return
	}
	defer stop_echo_mock(&refusing, ru, rw)
	lu, lw, lok := start_echo_mock(t, &live, "live")
	if !lok {
		return
	}
	defer stop_echo_mock(&live, lu, lw)
	stuck := slow_unresolvable(t, bu)
	defer destroy(stuck)

	servers := []^Upstream{ru, stuck, lu}
	g := Group {
		servers   = servers,
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 1,
		allocator = context.allocator,
	}
	// `resolve` asks only the refusing member; the sweep then meets the slow
	// one, whose 1.2 timeouts are past the sweep's one.
	for i in 0 ..< FAILURE_THRESHOLD {
		resp, winner, _ := resolve_readable(&g, deadline_query(), context.allocator)
		delete(resp, context.allocator)
		testing.expectf(t, winner != lu, "sweep %d reached the live member past the slow one's wait", i + 1)
	}
	testing.expect(t, !healthy(stuck), "the unresolvable member did not park")

	resp, winner, err := resolve_readable(&g, deadline_query(), context.allocator)
	defer delete(resp, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == lu, "the sweep did not reach the live member once the slow one had parked")
	free_all(context.temp_allocator)
}

/*
The sweep spends what is left of the query's two timeouts, not a timeout of its
own on top of them (issue #426). A is silent (one timeout); B recurses for 0.9
of one and says SERVFAIL, which `resolve` hands back at 1.9. What is left is a
tenth of a timeout: C is asked, since the budget is checked after an exchange
rather than before, and its slow SERVFAIL ends the sweep at 2.8. D, silent, is
never reached - with a fresh timeout for the sweep it was, and the query waited
3.8 timeouts, twenty seconds as elodin ships.
*/
@(test)
test_the_sweep_spends_what_is_left_of_the_query_budget :: proc(t: ^testing.T) {
	mocks: [4]Echo_Mock
	mocks[0].mute = true
	mocks[1].rcode = u8(dns.Rcode.Serv_Fail)
	mocks[1].delay = DEADLINE_TIMEOUT * 9 / 10
	mocks[2].rcode = u8(dns.Rcode.Serv_Fail)
	mocks[2].delay = DEADLINE_TIMEOUT * 9 / 10
	mocks[3].mute = true
	ups: [4]^Upstream
	workers: [4]^thread.Thread
	for i in 0 ..< 4 {
		ok: bool
		ups[i], workers[i], ok = start_echo_mock(t, &mocks[i], fmt.tprintf("m%d", i))
		if !ok {
			return
		}
	}
	defer for i in 0 ..< 4 {
		stop_echo_mock(&mocks[i], ups[i], workers[i])
	}

	g := Group {
		servers   = ups[:],
		strategy  = .Failover,
		timeout   = DEADLINE_TIMEOUT,
		attempts  = 2,
		allocator = context.allocator,
	}
	// Both callers, since both are the one sweep: a client's question and a
	// chain lookup. Each call gets a budget of its own.
	for insisting, i in ([]proc(_: ^Group, _: []u8, _: mem.Allocator) -> ([]u8, ^Upstream, Error){resolve_readable, resolve_answerable}) {
		before := sync.atomic_load(&mocks[3].hits)
		started := time.tick_now()
		resp, winner, err := insisting(&g, deadline_query(), context.allocator)
		spent := time.tick_since(started)
		delete(resp, context.allocator)

		testing.expect_value(t, err, Error.None)
		testing.expectf(t, winner == ups[1], "call %d: the first SERVFAIL did not stand", i)
		testing.expectf(t, sync.atomic_load(&mocks[2].hits) == i + 1, "call %d: the sweep did not ask the member under the line", i)
		testing.expectf(t, sync.atomic_load(&mocks[3].hits) == before, "call %d: a fourth member was asked after the query's budget had gone", i)
		// Under three timeouts, the design's worst case: two, and the exchange
		// that crosses the line. A fresh budget for the sweep waited 3.8.
		testing.expectf(t, spent < 3 * DEADLINE_TIMEOUT, "call %d: the query waited %v, where the budget is two timeouts of %v", i, spent, DEADLINE_TIMEOUT)
	}
	free_all(context.temp_allocator)
}
