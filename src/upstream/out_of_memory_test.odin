package upstream

import "base:runtime"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"
import "elodin:tlsx"

/*
Issue #620: a query this server cannot allocate the buffers for is not sent, and
says so as `Out_Of_Memory` rather than trapping on an empty slice. Neither the
copy `pipe_query` takes nor the frame `pipe_write` builds touches the connection
first, so the connection is left as it was.
*/
@(test)
test_a_pipelined_query_that_cannot_be_copied_or_framed_is_not_sent :: proc(t: ^testing.T) {
	query := make([]u8, 32)
	defer delete(query)
	deadline := time.tick_add(time.tick_now(), time.Second)

	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	_, copy_err := pipe_query(nil, nil, query, deadline, temp)
	write_err := pipe_write(nil, query, deadline)
	context.temp_allocator = temp

	testing.expect_value(t, copy_err, Error.Out_Of_Memory)
	testing.expect_value(t, write_err, Error.Out_Of_Memory)
}

// Charged as `Backlogged` is: not at all, since it says nothing about the upstream.
@(test)
test_a_failure_of_this_server_s_own_is_not_charged_to_the_upstream :: proc(t: ^testing.T) {
	testing.expect(t, !charges_member(.Out_Of_Memory, false), "this server's memory was charged to the upstream")
	testing.expect(t, !charges_member(.Backlogged, false))
	testing.expect(t, !charges_member(.Timeout, true))
	testing.expect(t, charges_member(.Timeout, false))
	testing.expect(t, charges_member(.IO_Error, false))
}

/*
A reply's question is checked against the query's even where the temp allocator
has run dry: a failed read of the query's question is not a query without one,
or any reply carrying the right ID would be taken for the answer.
*/
@(test)
test_a_reply_read_without_memory_is_not_matched :: proc(t: ^testing.T) {
	asked := [1]dns.Question{{name = "example.com.", type = .A, class = .IN}}
	other := [1]dns.Question{{name = "attacker.test.", type = .A, class = .IN}}
	query, _, qerr := dns.encode_message(dns.Message{id = 0x1234, question = asked[:]})
	defer delete(query)
	reply, _, rerr := dns.encode_message(dns.Message{id = 0x1234, flags = {qr = true}, question = other[:]})
	defer delete(reply)
	testing.expect_value(t, qerr, dns.Encode_Error.None)
	testing.expect_value(t, rerr, dns.Encode_Error.None)
	testing.expect(t, !response_matches(query, reply), "the fixture's question mismatch went unseen")

	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	matched := response_matches(query, reply)
	context.temp_allocator = temp

	testing.expect(t, !matched, "a reply for another name was matched once the question could not be read")

	// Nor is a genuine one refused for it, which would charge the upstream as a
	// `Bad_Response` for this server's memory.
	ours, _, oerr := dns.encode_message(dns.Message{id = 0x1234, flags = {qr = true}, question = asked[:]})
	defer delete(ours)
	testing.expect_value(t, oerr, dns.Encode_Error.None)
	context.temp_allocator = mem.nil_allocator()
	genuine := response_matches(query, ours)
	context.temp_allocator = temp
	testing.expect(t, genuine, "the upstream's own reply was refused for want of memory")
}

// Nor is a reply this server has no memory to copy taken for an empty answer.
@(test)
test_a_reply_that_cannot_be_copied_is_not_an_empty_answer :: proc(t: ^testing.T) {
	query := []u8{0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reply := []u8{0xab, 0xcd, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	out, err := pipe_reply_copy(reply, query, mem.nil_allocator())
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect_value(t, len(out), 0)

	copied, copy_err := pipe_reply_copy(reply, query, context.temp_allocator)
	defer free_all(context.temp_allocator)
	testing.expect_value(t, copy_err, Error.None)
	if testing.expect_value(t, len(copied), len(reply)) {
		testing.expect_value(t, copied[0], 0x12)
		testing.expect_value(t, copied[2], 0x80)
	}
}

// Fails `fail_for` requests from its `fail_at`th on and hands every other to
// `backing`. The dns, dnssec and server packages keep their own copies: test
// files cannot be shared across packages.
@(private)
Fail_Nth :: struct {
	backing:  mem.Allocator,
	seen:     int,
	fail_at:  int,
	fail_for: int,
}

@(private)
fail_nth_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	f := cast(^Fail_Nth)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		f.seen += 1
		if f.seen >= f.fail_at && f.seen < f.fail_at + f.fail_for {
			return nil, .Out_Of_Memory
		}
	}
	return f.backing.procedure(f.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

@(private)
fail_nth :: proc(f: ^Fail_Nth) -> mem.Allocator {
	return {procedure = fail_nth_proc, data = f}
}

// A query with an OPT record, so a cookie and padding have somewhere to go, on
// the heap: the tests run with the temp allocator refusing. The caller frees it.
@(private = "file")
oom_query :: proc(t: ^testing.T) -> (wire: []u8, ok: bool) {
	msg := dns.Message {
		id         = 0x0636,
		question   = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(1232, false)},
	}
	msg.flags.rd = true
	err: dns.Encode_Error
	wire, _, err = dns.encode_message(msg, context.allocator)
	return wire, testing.expect_value(t, err, dns.Encode_Error.None)
}

// Whether a datagram is waiting on `socket`, read without blocking: a query
// sent to it over loopback is there by the time the send returns.
@(private = "file")
datagram_waiting :: proc(t: ^testing.T, socket: net.UDP_Socket) -> bool {
	if berr := net.set_blocking(socket, false); !testing.expect_value(t, berr, nil) {
		return false
	}
	buf: [dns.MAX_UDP_SIZE]u8
	_, _, err := net.recv_udp(socket, buf[:])
	return err == nil
}

/*
A UDP query this server has no room to read the answer to is not sent, with or
without a cookie: refused the reply buffer, or the copy that carries the cookie.
Sent, it would wait out the timeout and be charged to the upstream; sent without
its cookie, it would go out with the protection RFC 7873 gives it taken off.
*/
@(test)
test_a_udp_query_without_room_is_not_sent :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	for cookies in ([]bool{false, true}) {
		bound: net.Endpoint
		socket, bound_ok := net.UDP_Socket{}, false
		if socket, bound, bound_ok = bind_loopback_udp(t); !bound_ok {
			return
		}
		defer net.close(socket)
		u, uerr := make_upstream(
			config.Upstream_Spec{name = "dry", kind = .UDP, address = "127.0.0.1", port = bound.port},
			0,
			time.Second,
			context.allocator,
			cookies = cookies,
		)
		if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
			return
		}
		defer destroy(u)

		// The first allocation alone: the cookie's copy where there is one, the
		// reply buffer where not.
		f := Fail_Nth{backing = context.temp_allocator, fail_at = 1, fail_for = 1}
		temp := context.temp_allocator
		context.temp_allocator = fail_nth(&f)
		_, err := exchange(u, query, 300 * time.Millisecond, temp)
		context.temp_allocator = temp
		testing.expectf(t, err == .Out_Of_Memory, "cookies %v: %v", cookies, err)
		testing.expectf(t, !datagram_waiting(t, socket), "cookies %v: the query was sent", cookies)
		testing.expectf(t, u.failures == 0, "cookies %v: this server's memory was charged to the upstream", cookies)

		// With its memory, the same exchange reaches the socket.
		_, asked_err := exchange(u, query, 50 * time.Millisecond, temp)
		testing.expectf(t, asked_err == .Timeout, "cookies %v: %v from a socket that never answers", cookies, asked_err)
		testing.expectf(t, datagram_waiting(t, socket), "cookies %v: the query never reached the socket", cookies)
		free_all(context.temp_allocator)
	}
}

// Nor is a UDP answer this server has no memory to copy out taken for an empty
// one, which reads as a NOERROR the client is sent.
@(test)
test_a_udp_answer_that_cannot_be_copied_is_not_an_empty_answer :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	m: Echo_Mock
	u, worker, ok := start_udp_mock(t, &m, echo_mock_loop, "echo")
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)
	defer free_all(context.temp_allocator)

	deadline := time.tick_add(time.tick_now(), time.Second)
	out, err := exchange_udp(u, query, time.Second, deadline, mem.nil_allocator())
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect_value(t, len(out), 0)

	deadline = time.tick_add(time.tick_now(), time.Second)
	answer, answer_err := exchange_udp(u, query, time.Second, deadline, context.temp_allocator)
	testing.expect_value(t, answer_err, Error.None)
	testing.expect_value(t, len(answer), len(query))
	testing.expect_value(t, sync.atomic_load(&m.hits), 2)
}

/*
A DoH query without room for its body, or a TLS one without room for its
padding, is not sent. Unpadded, its length would name it on the encrypted
transport (RFC 8467 section 4.1). The port refuses, so a query that reached the
dial fails there instead.
*/
@(test)
test_an_encrypted_query_without_room_is_not_sent :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	closed, held := closed_port(t)
	if !held {
		return
	}
	defer release_port(closed)
	for kind in ([]config.Upstream_Kind{.TLS, .HTTPS}) {
		u, uerr := make_upstream(
			config.Upstream_Spec{name = "dry", kind = kind, address = "127.0.0.1", port = closed.port, hostname = "localhost", path = "/dns-query"},
			0,
			time.Second,
			context.allocator,
		)
		if !testing.expectf(t, uerr == .None, "%v: cannot build the upstream: %v", kind, uerr) {
			return
		}
		defer destroy(u)

		f := Fail_Nth{backing = context.temp_allocator, fail_at = 1, fail_for = 1}
		temp := context.temp_allocator
		context.temp_allocator = fail_nth(&f)
		_, err := exchange(u, query, time.Second, temp)
		context.temp_allocator = temp
		testing.expectf(t, err == .Out_Of_Memory, "%v: %v", kind, err)
		// Past the padding, which is refused first: the body's own copy.
		if kind == .HTTPS {
			context.temp_allocator = mem.nil_allocator()
			_, body_err := exchange_doh(u, query, time.Second, time.tick_add(time.tick_now(), time.Second), temp)
			context.temp_allocator = temp
			testing.expect_value(t, body_err, Error.Out_Of_Memory)
		}

		_, dialled := exchange(u, query, time.Second, temp)
		testing.expectf(t, dialled == .Dial_Failed, "%v: %v from a port that refuses", kind, dialled)
		free_all(context.temp_allocator)
	}
}

// A sweep with no room for its fresh-ID copy asks nobody: sent empty, the
// query would fail at the member and be charged to it.
@(test)
test_a_sweep_query_without_room_is_not_built :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	_, dry_ok := sweep_query(query)
	context.temp_allocator = temp
	testing.expect(t, !dry_ok, "a sweep query was built with no memory")

	out, ok := sweep_query(query)
	defer free_all(context.temp_allocator)
	testing.expect(t, ok, "a sweep query was not built")
	testing.expect_value(t, len(out), len(query))
}

/*
A group with no room for what it keeps about the members it asks - the rounds
of a failover, the candidates and shared state of a race - asks none of them and
says it was this server's memory, rather than trapping on an empty slice.
*/
@(test)
test_a_group_without_room_asks_nobody :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	a, a_socket, a_ok := silent_upstream(t, "a")
	if !a_ok {
		return
	}
	defer {destroy(a); net.close(a_socket)}
	b, b_socket, b_ok := silent_upstream(t, "b")
	if !b_ok {
		return
	}
	defer {destroy(b); net.close(b_socket)}
	servers := []^Upstream{a, b}

	// A run of two: the race's list refused its room and then a member's
	// append, which would leave it racing the other alone.
	for strategy in ([]config.Strategy{.Failover, .Race}) {
		g := failover_group(servers, 50 * time.Millisecond)
		g.strategy = strategy
		f := Fail_Nth{backing = context.temp_allocator, fail_at = 1, fail_for = 2}
		temp := context.temp_allocator
		context.temp_allocator = fail_nth(&f)
		_, _, err := resolve(&g, query, temp)
		context.temp_allocator = temp
		testing.expectf(t, err == .Out_Of_Memory, "%v: %v", strategy, err)
	}

	// The race's shared state is on the heap, a racer outliving the caller's
	// arena: the state, the query's copy and the jobs.
	g := failover_group(servers, 50 * time.Millisecond)
	g.strategy = .Race
	for n in 1 ..= 3 {
		f := Fail_Nth{backing = context.allocator, fail_at = n, fail_for = 1}
		heap := context.allocator
		context.allocator = fail_nth(&f)
		_, _, err := resolve_race(&g, query, time.Second, context.temp_allocator)
		context.allocator = heap
		testing.expectf(t, err == .Out_Of_Memory, "heap allocation %d refused: %v", n, err)
		testing.expectf(t, f.seen >= n, "heap allocation %d refused, of %d", n, f.seen)
	}
	testing.expect(t, !datagram_waiting(t, a_socket) && !datagram_waiting(t, b_socket), "a member was asked")
	free_all(context.temp_allocator)
}

/*
A pipelined reply the connection has no room for cannot be read past, so the
connection goes, and its waiters hear it was this server's memory: delivered
empty, the stream would read the reply's bytes as the next length.
*/
@(test)
test_a_pipelined_reply_without_room_ends_the_connection :: proc(t: ^testing.T) {
	for dry in ([]bool{true, false}) {
		pair: [2]linux.Fd
		if serr := linux.socketpair(.UNIX, .STREAM, .HOPOPT, &pair); !testing.expect_value(t, serr, linux.Errno.NONE) {
			return
		}
		defer {linux.close(pair[0]); linux.close(pair[1])}
		reply: [2 + dns.HEADER_SIZE]u8
		reply[1], reply[2], reply[3], reply[4] = dns.HEADER_SIZE, 0x06, 0x36, 0x80
		if n, werr := linux.write(pair[1], reply[:]); !testing.expectf(t, werr == .NONE && n == len(reply), "cannot write the reply: %v", werr) {
			return
		}
		c := new(Pipe_Conn)
		defer free(c)
		c.stream.socket = net.TCP_Socket(pair[0])
		c.timeout = time.Second
		c.allocator = mem.nil_allocator() if dry else context.allocator
		err := pipe_read_one(c, time.Second)
		testing.expect_value(t, err, Error.Out_Of_Memory if dry else Error.None)
		testing.expect_value(t, c.replies, 0 if dry else 1)
	}
}

/*
Idle connections the sweep has no room to list are still closed, every one of
them: taken off the pool without it, they would be held open for the life of
the process.
*/
@(test)
test_idle_connections_without_room_are_still_closed :: proc(t: ^testing.T) {
	u, uerr := make_upstream(config.Upstream_Spec{name = "idle", kind = .TCP, address = "127.0.0.1", port = 53}, 2, time.Second, context.allocator)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		return
	}
	defer destroy(u)
	for _ in 0 ..< 2 {
		fd, serr := linux.socket(.INET, .STREAM, {.CLOEXEC}, .TCP)
		if !testing.expect_value(t, serr, linux.Errno.NONE) {
			return
		}
		put_idle(u, Stream{socket = net.TCP_Socket(fd)})
	}
	if !testing.expect_value(t, len(u.idle), 2) {
		return
	}
	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	closed := close_idle(u, all = true)
	context.temp_allocator = temp
	testing.expect_value(t, closed, 2)
	testing.expect_value(t, len(u.idle), 0)
}

/*
An upstream's hostname this server has no memory to look up is `Out_Of_Memory`
and not charged to the member, where one the bootstrap servers did not resolve
is `Not_Resolved` and is.
*/
@(test)
test_a_bootstrap_lookup_without_memory_is_not_charged :: proc(t: ^testing.T) {
	query, built := oom_query(t)
	if !built {
		return
	}
	defer delete(query)
	socket, bound, bound_ok := bind_loopback_udp(t)
	if !bound_ok {
		return
	}
	defer net.close(socket)
	// Built with no bootstrap servers, so construction does not wait on the
	// silent one; it is handed over afterwards.
	u, uerr := make_upstream(config.Upstream_Spec{name = "hostname", kind = .UDP, address = "dns.example.test", port = 53}, 0, time.Second, context.allocator)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		return
	}
	defer destroy(u)
	bootstrap := []string{net.endpoint_to_string(bound, context.temp_allocator)}
	u.spec.bootstrap = bootstrap
	defer u.spec.bootstrap = nil
	defer free_all(context.temp_allocator)

	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	_, err := exchange(u, query, 300 * time.Millisecond, temp)
	context.temp_allocator = temp
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect_value(t, u.failures, 0)
	testing.expect(t, !datagram_waiting(t, socket), "the bootstrap server was asked")

	_, unresolved := exchange(u, query, 50 * time.Millisecond, temp)
	testing.expect_value(t, unresolved, Error.Not_Resolved)
	testing.expect_value(t, u.failures, 1)
	testing.expect(t, datagram_waiting(t, socket), "the bootstrap server was never asked")
}

/*
A reply's cookie this server has no memory to strip is `Out_Of_Memory`: the
reply is still not handed on with the cookie in it, and the upstream is not
blamed with a `Bad_Response` for it.
*/
@(test)
test_a_cookie_strip_without_memory_is_not_the_upstreams :: proc(t: ^testing.T) {
	u := Upstream {
		spec = config.Upstream_Spec{name = "strip", kind = .UDP},
	}
	option := [COOKIE_CLIENT_LEN + 8]u8{}
	msg := dns.Message {
		id         = 0x0636,
		flags      = {qr = true},
		question   = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(1232, false)},
	}
	plain, _, perr := dns.encode_message(msg, context.allocator)
	if !testing.expect_value(t, perr, dns.Encode_Error.None) {
		return
	}
	defer delete(plain)
	for dry in ([]bool{true, false}) {
		with, attached := dns.set_edns_option(plain, .Cookie, option[:], context.allocator)
		if !testing.expect(t, attached, "the fixture's cookie was not attached") {
			return
		}
		temp := context.temp_allocator
		context.temp_allocator = mem.nil_allocator() if dry else temp
		out, err := strip_cookie(&u, with, mem.nil_allocator() if dry else context.allocator)
		context.temp_allocator = temp
		if dry {
			testing.expect_value(t, err, Error.Out_Of_Memory)
			// Handed back to nobody: the strip frees what it was given.
			testing.expect_value(t, len(out), 0)
			delete(with)
		} else {
			testing.expect_value(t, err, Error.None)
			_, carried := reply_cookie(out)
			testing.expect(t, !carried, "the cookie was left in")
			delete(out)
		}
	}
}

/*
An h2 connection there is no room to build is this server's failing, whichever
part was refused: nothing is half built, and the connection struct is not kept
without its client.
*/
@(test)
test_an_h2_connection_without_room_is_not_built :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "dry", kind = .HTTPS, address = "127.0.0.1", port = 443, hostname = "localhost", path = "/dns-query"},
		0,
		time.Second,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		return
	}
	defer destroy(u)
	heap := u.allocator
	// The connection, then its client: neither writes anything, so the stream
	// is never touched.
	for at in 1 ..= 2 {
		f := Fail_Nth {
			backing  = mem.tracking_allocator(&track),
			fail_at  = at,
			fail_for = 1,
		}
		u.allocator = fail_nth(&f)
		hc := make_h2_conn(u, Stream{})
		u.allocator = heap
		testing.expectf(t, hc == nil, "built with allocation %d refused", at)
		testing.expectf(t, f.seen == at, "allocation %d refused after %d", at, f.seen)
	}
	testing.expectf(t, len(track.allocation_map) == 0, "%d allocations kept", len(track.allocation_map))
}

@(private = "file")
H2_Dial_Peer :: struct {
	listener: net.TCP_Socket,
	ctx:      ^tlsx.Context,
	// What each connection's handshake chose, and how its reading ended.
	alpn:     [2]string,
	ended:    [2]tlsx.Error,
}

@(private = "file")
h2_dial_peer_run :: proc(p: ^H2_Dial_Peer) {
	for i in 0 ..< len(p.alpn) {
		socket, _, aerr := net.accept_tcp(p.listener)
		if aerr != nil {
			return
		}
		if net.set_option(socket, .Receive_Timeout, 3 * time.Second) != nil {
			net.close(socket)
			return
		}
		conn, terr := tlsx.server_accept(p.ctx, socket)
		if terr != .None {
			net.close(socket)
			return
		}
		// The test's thread frees it, which tracks a heap of its own.
		p.alpn[i] = strings.clone(tlsx.alpn_protocol(conn), runtime.heap_allocator())
		buf: [1024]u8
		for {
			if _, err := tlsx.read(conn, buf[:]); err != .None {
				p.ended[i] = err
				break
			}
		}
		tlsx.close(conn)
	}
}

/*
A dial that negotiated h2 and then had no room for the connection reports
`Out_Of_Memory` and closes the stream it dialled, rather than keep a connection
nothing reads; the next query dials afresh.
*/
@(test)
test_an_h2_dial_without_room_is_closed :: proc(t: ^testing.T) {
	fx, fixture_ok := dot_fixture(t)
	if !fixture_ok {
		return
	}
	defer dot_fixture_destroy(&fx)
	sctx, serr := tlsx.server_context(dot_cert_path, dot_key_path, []string{"h2"})
	if !testing.expectf(t, serr == .None, "server_context: %v", serr) {
		return
	}
	defer tlsx.context_destroy(sctx)
	cctx, cerr := tlsx.client_context(false, "", []string{"h2"})
	if !testing.expectf(t, cerr == .None, "client_context: %v", cerr) {
		return
	}

	p := H2_Dial_Peer {
		listener = fx.listener,
		ctx      = sctx,
	}
	peer := thread.create_and_start_with_poly_data(&p, h2_dial_peer_run)
	if !testing.expect(t, peer != nil, "cannot start the peer") {
		tlsx.context_destroy(cctx)
		return
	}
	defer {
		thread.join(peer)
		thread.destroy(peer)
		delete(p.alpn[0], runtime.heap_allocator())
		delete(p.alpn[1], runtime.heap_allocator())
	}
	// Dialled twice below; on an early return, the peer is woken from its accept.
	dials := 0
	defer if dials < len(p.alpn) {
		net.shutdown(fx.listener, .Both)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "dry", kind = .HTTPS, address = "127.0.0.1", port = fx.bound.port, hostname = "localhost", path = "/dns-query"},
		0,
		2 * time.Second,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		tlsx.context_destroy(cctx)
		return
	}
	// One that takes the self-signed certificate; `destroy` frees it.
	tlsx.context_destroy(u.tls_ctx)
	u.tls_ctx = cctx

	heap := u.allocator
	f := Fail_Nth {
		backing  = heap,
		fail_at  = 1,
		fail_for = 1,
	}
	u.allocator = fail_nth(&f)
	_, is_h2, err := get_h2_conn(u, 2 * time.Second, 2 * time.Second)
	u.allocator = heap
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect(t, !is_h2 && u.h2 == nil, "a connection without room was kept")
	testing.expect_value(t, f.seen, 1)

	conn, again, aerr := get_h2_conn(u, 2 * time.Second, 2 * time.Second)
	testing.expectf(t, aerr == .None && again, "with room: %v", aerr)
	if again {
		h2.client_unref(conn)
	}
	dials = 2
	// Ends the second connection's read, so the peer is done by the join.
	destroy(u)
	thread.join(peer)

	// The premise: the refused dial is the one that negotiated h2, and its
	// stream was closed (close_notify) rather than left open.
	testing.expectf(t, p.alpn[0] == "h2" && p.alpn[1] == "h2", "negotiated %v", p.alpn)
	testing.expect_value(t, p.ended[0], tlsx.Error.Closed)
}
