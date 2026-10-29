package upstream

import "core:net"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A connection, not dialled, whose quickest reply took `floor` and whose last
`PIPE_BACKLOG_SAMPLES` replies took `waited` each, the newest just now. With a
probe already on it, so the gate decides alone. Its socket is no descriptor at
all, so a write that should have been refused fails rather than landing on
another test's: a zero handle under `odin test` is somebody else's socket.
*/
@(private = "file")
Backlogged :: struct {
	c:     ^Pipe_Conn,
	probe: Pipe_Waiter,
}

@(private = "file")
make_backlogged :: proc(b: ^Backlogged, waited: time.Duration, floor := 10 * time.Millisecond) {
	c := new(Pipe_Conn)
	c.stream.socket = net.TCP_Socket(-1)
	c.timeout = time.Second
	c.last = time.now()
	c.refs = 1
	c.waiters = make(map[u16]^Pipe_Waiter)
	pipe_note_wait(c, floor, true)
	for _ in 0 ..< PIPE_BACKLOG_SAMPLES {
		pipe_note_wait(c, waited, true)
	}
	c.waiters[1] = &b.probe
	c.backlog.probe, c.backlog.probe_id = &b.probe, 1
	b.c = c
}

@(private = "file")
free_conn :: proc(c: ^Pipe_Conn) {
	delete(c.waiters)
	free(c)
}

/*
The gate (issue #551): shut only when every one of the last
`PIPE_BACKLOG_SAMPLES` replies waited at least half of what the query has left
beyond the connection's floor, and the newest of them is fresh.
*/
@(test)
test_a_backlog_is_judged_on_every_recent_reply :: proc(t: ^testing.T) {
	left := time.Second
	floor := 10 * time.Millisecond

	b: Backlogged
	make_backlogged(&b, floor + left / 2, floor)
	defer free_conn(b.c)
	testing.expect(t, pipe_backlogged(b.c, left), "every reply queued half of what was left, and the gate stayed open")
	// Half of what is left, not a fixed figure: a caller with more time to
	// spend can wait behind the same queue.
	testing.expect(t, !pipe_backlogged(b.c, 2 * left + time.Millisecond), "a caller with time to wait behind the queue was turned away")
	// Out of time altogether: it goes on, and fails as the timeout it is
	// rather than as a refusal nothing charges.
	testing.expect(t, !pipe_backlogged(b.c, 0), "a query with no time left was refused rather than timed out")
	testing.expect(t, !pipe_backlogged(b.c, -time.Millisecond), "a query past its deadline was refused rather than timed out")

	// One quick reply among them is a slow name answered out of order rather
	// than a queue every message waits behind (RFC 7766 section 7).
	pipe_note_wait(b.c, floor, true)
	testing.expect(t, !pipe_backlogged(b.c, left), "one slow name shut the gate")

	// Replies older than the connection's timeout describe a queue long gone.
	s: Backlogged
	make_backlogged(&s, left, floor)
	defer free_conn(s.c)
	s.c.backlog.at = time.tick_add(time.tick_now(), -s.c.timeout)
	testing.expect(t, !pipe_backlogged(s.c, left), "a stale backlog shut the gate")

	// Fewer slow replies than the window are not a queue.
	f := new(Pipe_Conn)
	defer free_conn(f)
	f.timeout = time.Second
	f.waiters = make(map[u16]^Pipe_Waiter)
	for _ in 0 ..< PIPE_BACKLOG_SAMPLES - 1 {
		pipe_note_wait(f, left, true)
	}
	testing.expect(t, !pipe_backlogged(f, left), "a short run of slow replies was taken for a queue")
}

/*
A path that is far away, or a server that is slow, waits as long with nobody
queued: the floor is that wait, and only what is above it is a queue.
*/
@(test)
test_a_long_round_trip_is_not_a_queue :: proc(t: ^testing.T) {
	b: Backlogged
	make_backlogged(&b, 600 * time.Millisecond, 600 * time.Millisecond)
	defer free_conn(b.c)
	testing.expect(t, !pipe_backlogged(b.c, time.Second), "a steady 600 ms round trip was taken for a queue")
}

/*
A shut gate lets one query through at a time, so a quick reply can open it
again: without one, a run of slow names would shut every quick query out for
as long as any of them was on the connection.
*/
@(test)
test_a_shut_gate_lets_one_probe_through :: proc(t: ^testing.T) {
	left := time.Second
	b: Backlogged
	make_backlogged(&b, time.Second)
	defer free_conn(b.c)
	c := b.c

	// The probe from `make_backlogged` is still on it.
	w1, w2: Pipe_Waiter
	testing.expect(t, !pipe_admit(c, &w1, 7, left), "a second query got past a shut gate with a probe on it")

	// The probe has gone, answered or not: the next query is the probe.
	delete_key(&c.waiters, 1)
	testing.expect(t, pipe_admit(c, &w1, 7, left), "nothing was let through a shut gate with no probe on it")
	c.waiters[7] = &w1
	testing.expect(t, !pipe_admit(c, &w2, 8, left), "two probes were let through at once")

	// Its answer came back quickly: the gate opens for everyone.
	delete_key(&c.waiters, 7)
	pipe_note_wait(c, 20 * time.Millisecond, true)
	testing.expect(t, pipe_admit(c, &w2, 8, left), "a quick probe did not open the gate")
	c.waiters[8] = &w2
	w3: Pipe_Waiter
	testing.expect(t, pipe_admit(c, &w3, 9, left), "an open gate held a query back behind a probe")
}

/*
What a reply is sampled as. One for a caller still waiting has waited since it
was asked, and may lower the floor; one for a caller that gave up waited
longer than that caller had, which the connection's timeout stands for, and
says nothing about the floor.
*/
@(test)
test_a_reply_nobody_waits_for_counts_as_the_whole_timeout :: proc(t: ^testing.T) {
	c := new(Pipe_Conn)
	defer free_conn(c)
	c.timeout = 3 * time.Second
	c.allocator = context.allocator
	c.waiters = make(map[u16]^Pipe_Waiter)

	orphan := make([]u8, dns.HEADER_SIZE)
	orphan[0], orphan[1] = 0x12, 0x34
	pipe_deliver(c, orphan)
	newest := (c.backlog.next + PIPE_BACKLOG_SAMPLES - 1) % PIPE_BACKLOG_SAMPLES
	testing.expect_value(t, c.backlog.waited[newest], c.timeout)
	testing.expect_value(t, c.backlog.floor, time.Duration(0))

	w := Pipe_Waiter {
		asked = time.tick_add(time.tick_now(), -200 * time.Millisecond),
	}
	c.waiters[0x55] = &w
	mine := make([]u8, dns.HEADER_SIZE)
	mine[0], mine[1] = 0x00, 0x55
	pipe_deliver(c, mine)
	newest = (c.backlog.next + PIPE_BACKLOG_SAMPLES - 1) % PIPE_BACKLOG_SAMPLES
	got := c.backlog.waited[newest]
	testing.expectf(t, got >= 200 * time.Millisecond && got < c.timeout, "a waiter's reply was sampled as %v", got)
	testing.expect_value(t, c.backlog.floor, got)
	if w.reply != nil {
		delete(w.reply)
	}
}

/*
Turned away through the whole exchange, at once, without a byte written, and
without moving the upstream towards its cooldown: a congested path is not a
server that is down, and a `udp` member's datagram answers still arrive.
*/
@(test)
test_a_backlogged_connection_refuses_fast_and_does_not_park_the_upstream :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "backlogged", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	b: Backlogged
	make_backlogged(&b, time.Second)
	u.pipe = b.c
	defer {
		u.pipe = nil
		destroy(u)
		free_conn(b.c)
	}

	query := dns.Message {
		id       = 0x4242,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if !testing.expectf(t, enc == .None, "cannot encode: %v", enc) {
		return
	}

	for _ in 0 ..< 2 * FAILURE_THRESHOLD {
		before := time.tick_now()
		_, err := exchange(u, wire, time.Second, context.temp_allocator)
		testing.expect_value(t, err, Error.Backlogged)
		took := time.tick_since(before)
		testing.expectf(t, took < 100 * time.Millisecond, "the refusal took %v", took)
	}
	testing.expect(t, healthy(u), "refusals parked the upstream")
	testing.expect_value(t, stats_of(u).failure_kinds[.Backlogged], u64(2 * FAILURE_THRESHOLD))
	testing.expect_value(t, len(b.c.waiters), 1)
	free_all(context.temp_allocator)
}
