package itest

import "core:fmt"
import "core:net"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:server"

/*
Pipelined queries on one TCP or DoT connection are answered as each is ready,
not in the order they were asked (RFC 7766 sections 6.2.1.1 and 7; issue #666).

The mock holds every upstream reply until a count of them is waiting, so which
queries are outstanding is decided by the case and not by a clock: a cache hit
pipelined behind a held miss can only come back first if the two were in flight
together.
*/

@(private = "file")
HIT :: "hit.pipeline.test."
@(private = "file")
SLOW :: "slow.pipeline.test."
@(private = "file")
HIT_ID :: 0xffff
// Long enough past `client_timeout` below that the server's idle wait ends
// while the answer to `SLOW` is still on its way.
@(private = "file")
SLOW_DELAY :: 3 * time.Second
@(private = "file")
PIPELINE_CLIENT_TIMEOUT :: "1s"
@(private = "file")
HOLD_WAIT :: 5 * time.Second

run_pipeline_cases :: proc(r: ^Runner) {
	group :: "pipelining"
	upstream_port := next_port(r)
	mock := mock_make(group, upstream_port)
	mock_synth(mock, HIT, u16(dns.Type.A), {192, 0, 2, 1})
	mock_delay(mock, SLOW, u16(dns.Type.A), SLOW_DELAY, nil)
	// Every other name waits on the hold; with none set it is answered at once.
	mock_delay_all(mock, 0, nil)
	if !mock_start_or_skip(r, mock, group) {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	tcp_port := next_port(r)
	dot_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = pipeline_config(r, udp_port, tcp_port, dot_port, upstream_port),
			udp_port = udp_port,
			tcp_port = tcp_port,
			dot_port = dot_port,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "pipelining: the name the cases ask as a hit is cached")
	warm := query_udp(udp_port, build_query(HIT, u16(dns.Type.A)), context.temp_allocator)
	if check(r, warm.ok, "the warming query was not answered") {
		check_eq_int(r, parse_header(r, warm.wire).ancount, 1, "answers to the warming query")
	}
	end_case(r)

	start_case(r, "tcp: a cache hit pipelined behind a held miss is answered first")
	if conn, dialled := dial_tcp(tcp_port); check(r, dialled, "cannot connect over tcp") {
		defer net.close(conn.socket)
		hit_before_miss(r, &conn, mock, udp_port, "tcp")
	}
	end_case(r)

	start_case(r, "dot: a cache hit pipelined behind a held miss is answered first")
	if conn, dialled := dial_tls(dot_port); check(r, dialled, "cannot connect over dot") {
		defer close_tls(&conn)
		hit_before_miss(r, &conn, mock, udp_port, "dot")
	}
	end_case(r)

	start_case(r, "tcp: past the queries one connection may have in flight, the next waits for a place")
	if conn, dialled := dial_tcp(tcp_port); check(r, dialled, "cannot connect over tcp") {
		defer net.close(conn.socket)
		hit_waits_past_the_bound(r, &conn, mock, udp_port)
	}
	end_case(r)

	start_case(r, "tcp: a connection waiting on an answer longer than client_timeout is kept")
	if conn, dialled := dial_tcp(tcp_port); check(r, dialled, "cannot connect over tcp") {
		defer net.close(conn.socket)
		slow := stream_query(&conn, build_query(SLOW, u16(dns.Type.A), id = 1), context.temp_allocator)
		if check(r, slow.ok, "the slow query was not answered") {
			check_eq_int(r, parse_header(r, slow.wire).rcode, int(dns.Rcode.No_Error), "rcode of the slow answer")
			// Asked once the answer is in: within the idle wait that starts there.
			next := stream_query(&conn, build_query(HIT, u16(dns.Type.A), id = 2), context.temp_allocator)
			check(r, next.ok, "the connection was closed after an answer that outlasted client_timeout")
		}
	}
	end_case(r)

	/*
	The idle wait is waited out again only between messages. A message whose
	first byte is in when the wait ends is held to the deadline it started,
	which nothing extends (RFC 7766 section 6.2.3): the connection ends once
	the slow answer is out. What follows the part already sent is laid out so
	that a server reading on would find a whole query in it, and answer.
	*/
	{
		follow := build_query(HIT, u16(dns.Type.A), id = 3)
		start_case(r, "tcp: a length prefix half read when the idle wait ends is not waited for again")
		rest := make([dynamic]u8, context.temp_allocator)
		append(&rest, u8(len(follow)))
		append(&rest, ..follow)
		// Sent once the reader is waiting on an empty buffer, so the byte starts
		// the message's deadline rather than lying in the read-ahead.
		part_read_past_the_wait(r, tcp_port, mock, {0}, rest[:], separately = true)
		end_case(r)

		start_case(r, "tcp: a message past the read-ahead whose body is not in when the idle wait ends is not waited for again")
		// Read past the read-ahead, so its prefix is consumed before the body is
		// waited for; the body opens with a whole framed query.
		BIG :: server.STREAM_READ_AHEAD + 88
		body := make([]u8, BIG, context.temp_allocator)
		framed := frame_all({follow})
		copy(body, framed)
		part_read_past_the_wait(r, tcp_port, mock, {u8(BIG >> 8), u8(BIG & 0xff)}, body)
		end_case(r)
	}
}

/*
Ask `SLOW` and send `part` behind it - in the same write, or `separately` once the
query has reached the upstream - wait out its answer, which the mock delays past
`client_timeout`, and then send `rest`: the connection has to be over by then,
`rest` unanswered.
*/
@(private = "file")
part_read_past_the_wait :: proc(r: ^Runner, tcp_port: int, mock: ^Mock, part, rest: []u8, separately := false) {
	conn, dialled := dial_tcp(tcp_port)
	if !check(r, dialled, "cannot connect over tcp") {
		return
	}
	defer net.close(conn.socket)
	asked := mock_total(mock)
	first := make([dynamic]u8, context.temp_allocator)
	append(&first, ..frame_all({build_query(SLOW, u16(dns.Type.A), id = 1)}))
	if !separately {
		append(&first, ..part)
	}
	if !check(r, conn_write(&conn, first[:]), "the slow query was not sent") {
		return
	}
	if separately {
		reached := mock_wait_until(mock, asked_more_than, asked, HOLD_WAIT)
		if !check(r, reached, "the slow query never reached the upstream") || !check(r, conn_write(&conn, part), "the part was not sent") {
			return
		}
	}
	slow := stream_read_answer(&conn, context.temp_allocator)
	if !check(r, slow.ok, "the slow query was not answered") {
		return
	}
	check_eq_int(r, int(parse_header(r, slow.wire).id), 1, "id of the slow answer")
	// Refused is the connection already over, which is the outcome asked for. A
	// write the kernel takes says nothing either way; the read below does.
	if !conn_write(&conn, rest) {
		return
	}
	after := stream_read_answer(&conn, context.temp_allocator)
	check(r, !after.ok, "the rest was read as a query of its own and answered")
}

@(private = "file")
pipeline_config :: proc(r: ^Runner, udp_port, tcp_port, dot_port, upstream_port: int, extra := "") -> string {
	return base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "5s",
		upstream_extra = "  attempts: 1",
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, tcp_port),
		cache = "{ enabled: true }",
		listeners_extra = fmt.tprintf(
			`  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}`,
			dot_port,
			r.cert_file,
			r.key_file,
		),
		extra = fmt.tprintf("server:\n  client_timeout: %s\n%s", PIPELINE_CLIENT_TIMEOUT, extra),
	)
}

// `queries`, each behind its length prefix, in one buffer for one write.
@(private = "file")
frame_all :: proc(queries: [][]u8) -> []u8 {
	out := make([dynamic]u8, 0, 64 * len(queries), context.temp_allocator)
	for q in queries {
		append(&out, u8(len(q) >> 8), u8(len(q)))
		append(&out, ..q)
	}
	return out[:]
}

// Wait until the mock holds `want` replies, true when it did within `HOLD_WAIT`.
@(private = "file")
wait_held :: proc(mock: ^Mock, want: int) -> bool {
	return mock_wait_until(mock, proc(m: ^Mock, want: int) -> bool {return sync.atomic_load(&m.held) >= want}, want, HOLD_WAIT)
}

// Queries the mock has received over any transport; under `m.mu`.
@(private = "file")
asked_more_than :: proc(m: ^Mock, count: int) -> bool {
	return m.udp_queries + m.tcp_queries + m.tls_queries > count
}

/*
Release the hold by asking one more held name over UDP, which takes the count the
hold waits for to its end.
*/
@(private = "file")
release_hold :: proc(r: ^Runner, udp_port: int, tag: string) -> bool {
	name := fmt.tprintf("release-%s.pipeline.test.", tag)
	return check(r, query_udp(udp_port, build_query(name, u16(dns.Type.A)), context.temp_allocator).ok, "the query releasing the hold was not answered")
}

/*
Ask a held miss and then a cache hit on one connection in one write. The hit has
to come back while the miss is still held - which the hold makes certain, since
nothing releases it until the hit is read - and the miss once released.
*/
@(private = "file")
hit_before_miss :: proc(r: ^Runner, c: ^Test_Conn, mock: ^Mock, udp_port: int, tag: string) {
	MISS_ID :: 1
	held := mock_held(mock)
	mock_hold_until(mock, held + 2)
	miss := build_query(fmt.tprintf("miss-%s.pipeline.test.", tag), u16(dns.Type.A), id = MISS_ID)
	hit := build_query(HIT, u16(dns.Type.A), id = HIT_ID)
	if !check(r, conn_write(c, frame_all({miss, hit})), "the two queries were not sent") {
		return
	}

	first := stream_read_answer(c, context.temp_allocator)
	if !check(r, first.ok, "no answer arrived") {
		return
	}
	check_eq_int(r, int(parse_header(r, first.wire).id), HIT_ID, "id of the first answer (the hit)")
	// The premise: the miss went upstream and is held there, so it was in flight
	// beside the hit rather than answered from somewhere else.
	if !check(r, wait_held(mock, held + 1), "the miss never reached the upstream: %s", mock_hold_report(mock)) {
		return
	}
	if !release_hold(r, udp_port, tag) {
		return
	}
	second := stream_read_answer(c, context.temp_allocator)
	if check(r, second.ok, "the miss was not answered once released") {
		h := parse_header(r, second.wire)
		check_eq_int(r, int(h.id), MISS_ID, "id of the second answer (the miss)")
		check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode of the miss")
	}
}

/*
Fill the connection's places with held misses and pipeline a hit behind them. The
hit cannot be answered until one of the misses is, since the reader takes no
query past `server.STREAM_MAX_IN_FLIGHT`; one place more and it would come back
first, as in `hit_before_miss`.
*/
@(private = "file")
hit_waits_past_the_bound :: proc(r: ^Runner, c: ^Test_Conn, mock: ^Mock, udp_port: int) {
	BOUND :: server.STREAM_MAX_IN_FLIGHT
	held := mock_held(mock)
	mock_hold_until(mock, held + BOUND + 1)
	queries: [BOUND + 1][]u8
	for i in 0 ..< BOUND {
		queries[i] = build_query(fmt.tprintf("bound-%d.pipeline.test.", i), u16(dns.Type.A), id = u16(i))
	}
	queries[BOUND] = build_query(HIT, u16(dns.Type.A), id = HIT_ID)
	if !check(r, conn_write(c, frame_all(queries[:])), "the queries were not sent") {
		return
	}
	// The premise: every place the connection has is in flight at once.
	if !check(r, wait_held(mock, held + BOUND), "the misses were not all in flight at once: %s", mock_hold_report(mock)) {
		return
	}
	if !release_hold(r, udp_port, "bound") {
		return
	}

	hit_at := -1
	seen: [BOUND]bool
	for i in 0 ..= BOUND {
		answer := stream_read_answer(c, context.temp_allocator)
		if !check(r, answer.ok, "answer %d of %d did not arrive", i + 1, BOUND + 1) {
			return
		}
		id := int(parse_header(r, answer.wire).id)
		switch {
		case id == HIT_ID:
			hit_at = i
		case id < BOUND && !seen[id]:
			seen[id] = true
		case:
			fail(r, "answer %d has id %d, not one asked or asked twice", i + 1, id)
			return
		}
	}
	check(r, hit_at > 0, "the hit was answer %d, ahead of every held miss: more than %d were in flight", hit_at + 1, BOUND)
}

/*
With `server.max_pending` full, a connection's next query waits for the
connection's own place and is answered there, after the query holding it: it is
neither dropped nor answered beside it.

`max_pending` is one, so the connection's second query takes the only counted
place and its third finds none.
*/
run_pipeline_pending_cases :: proc(r: ^Runner) {
	group :: "pipelining: max_pending"
	upstream_port := next_port(r)
	mock := mock_make("pipeline-pending", upstream_port)
	mock_synth(mock, HIT, u16(dns.Type.A), {192, 0, 2, 1})
	mock_delay_all(mock, 0, nil)
	if !mock_start_or_skip(r, mock, group) {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	tcp_port := next_port(r)
	dot_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = pipeline_config(r, udp_port, tcp_port, dot_port, upstream_port, extra = "  max_pending: 1"),
			udp_port = udp_port,
			tcp_port = tcp_port,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "tcp: with max_pending full, a pipelined query waits for the connection's own place")
	defer end_case(r)
	warm := query_tcp(tcp_port, build_query(HIT, u16(dns.Type.A)), context.temp_allocator)
	if !check(r, warm.ok, "the warming query was not answered") {
		return
	}
	conn, dialled := dial_tcp(tcp_port)
	if !check(r, dialled, "cannot connect over tcp") {
		return
	}
	defer net.close(conn.socket)

	OWN_ID :: 1
	COUNTED_ID :: 2
	held := mock_held(mock)
	mock_hold_until(mock, held + 3)
	own := build_query("own.pipeline.test.", u16(dns.Type.A), id = OWN_ID)
	counted := build_query("counted.pipeline.test.", u16(dns.Type.A), id = COUNTED_ID)
	hit := build_query(HIT, u16(dns.Type.A), id = HIT_ID)
	if !check(r, conn_write(&conn, frame_all({own, counted, hit})), "the queries were not sent") {
		return
	}
	// The premise: both misses are in flight, the second in the one counted place.
	if !check(r, wait_held(mock, held + 2), "the two misses were not in flight at once: %s", mock_hold_report(mock)) {
		return
	}
	// Released over a connection of its own, whose own place is free: a datagram
	// would find `max_pending` full and be shed.
	release, released := dial_tcp(tcp_port)
	if !check(r, released, "cannot connect to release the hold") {
		return
	}
	defer net.close(release.socket)
	if !check(r, stream_query(&release, build_query("release-pending.pipeline.test.", u16(dns.Type.A)), context.temp_allocator).ok, "the query releasing the hold was not answered") {
		return
	}

	own_at, hit_at := -1, -1
	for i in 0 ..< 3 {
		answer := stream_read_answer(&conn, context.temp_allocator)
		if !check(r, answer.ok, "answer %d of 3 did not arrive", i + 1) {
			return
		}
		h := parse_header(r, answer.wire)
		check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode")
		switch h.id {
		case OWN_ID:
			own_at = i
		case HIT_ID:
			hit_at = i
		}
	}
	check(r, own_at >= 0 && hit_at > own_at, "the hit was answer %d and the own place's miss %d: the hit did not wait for that place", hit_at + 1, own_at + 1)
}
