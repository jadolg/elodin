package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
Issue #245: `resolve_proving` sweeps past an answerable reply that is not the
one its caller holds out for. A routed apex's `DS` is the caller - one member's
NXDOMAIN beside another's NODATA proof - and a sweep that stops at the first
answerable reply leaves which of the two the client gets to the member the
group reaches.
*/

// Answers every query with `rcode` and nothing else.
@(private = "file")
Fixed_Mock :: struct {
	socket: net.UDP_Socket,
	rcode:  u8,
	stop:   bool,
	hits:   int,
}

@(private = "file")
fixed_loop :: proc(m: ^Fixed_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		buf[2] |= 0x80
		buf[3] = 0x80 | m.rcode
		_, _ = net.send_udp(m.socket, buf[:n], client)
	}
}

@(private = "file")
NAMES := [3]string{"first", "second", "third"}

@(private = "file")
Fixed_Group :: struct {
	mocks:   [3]Fixed_Mock,
	servers: [3]^Upstream,
	threads: [3]^thread.Thread,
	started: int,
}

// Starts one member per rcode, in order. Whatever started is torn down by
// `stop_fixed`, which is safe to call on a partial start: a zero socket here is
// fd 0, another test's under `odin test`, so only what was bound is closed.
@(private = "file")
start_fixed :: proc(t: ^testing.T, fg: ^Fixed_Group, rcodes: []dns.Rcode) -> bool {
	for rcode, i in rcodes {
		m := &fg.mocks[i]
		m.rcode = u8(rcode) & 0xf
		socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, serr == nil, "bind: %v", serr) {
			return false
		}
		bound, berr := net.bound_endpoint(socket)
		if !testing.expectf(t, berr == nil, "cannot read the responder's port: %v", berr) {
			net.close(socket)
			return false
		}
		u, uerr := make_upstream(
			config.Upstream_Spec{name = NAMES[i], kind = .UDP, address = "127.0.0.1", port = bound.port},
			0,
			time.Second,
			context.allocator,
		)
		if !testing.expectf(t, uerr == .None, "upstream: %v", uerr) {
			net.close(socket)
			return false
		}
		m.socket = socket
		set_socket_timeouts(socket, 50 * time.Millisecond)
		fg.servers[i] = u
		fg.threads[i] = thread.create_and_start_with_poly_data(m, fixed_loop)
		fg.started = i + 1
	}
	return true
}

@(private = "file")
stop_fixed :: proc(fg: ^Fixed_Group) {
	for i in 0 ..< fg.started {
		sync.atomic_store(&fg.mocks[i].stop, true)
		thread.join(fg.threads[i])
		thread.destroy(fg.threads[i])
		net.close(fg.mocks[i].socket)
		destroy(fg.servers[i])
	}
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
warm :: proc(t: ^testing.T, fg: ^Fixed_Group) {
	for u in fg.servers[:fg.started] {
		resp, err := exchange(u, fixed_query(), time.Second, context.allocator)
		testing.expectf(t, err == .None, "warming %s: %v", u.spec.name, err)
		delete(resp, context.allocator)
	}
	for &m in fg.mocks[:fg.started] {
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
	fg: Fixed_Group
	defer stop_fixed(&fg)
	if !start_fixed(t, &fg, {.NX_Domain, .No_Error}) {
		return
	}
	warm(t, &fg)
	g := Group {
		servers   = fg.servers[:2],
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
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
	fg: Fixed_Group
	defer stop_fixed(&fg)
	if !start_fixed(t, &fg, {.No_Error, .NX_Domain}) {
		return
	}
	g := Group {
		servers   = fg.servers[:2],
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
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
	fg: Fixed_Group
	defer stop_fixed(&fg)
	if !start_fixed(t, &fg, {.Serv_Fail, .NX_Domain, .No_Error}) {
		return
	}
	warm(t, &fg)
	g := Group {
		servers   = fg.servers[:3],
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
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
And a member not known to be answering is not held out for: with an answer
already in hand, waiting `g.timeout` on a dead spare costs a client that has
one. Neither a member never yet asked nor one whose last exchange failed.
*/
@(test)
test_a_member_not_known_to_be_answering_is_not_held_out_for :: proc(t: ^testing.T) {
	fg: Fixed_Group
	defer stop_fixed(&fg)
	if !start_fixed(t, &fg, {.NX_Domain, .No_Error}) {
		return
	}
	g := Group {
		servers   = fg.servers[:2],
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}

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
