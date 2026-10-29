package upstream

import "core:net"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A connection, not dialled, with one query outstanding and its last replies
having waited `waited` each, the newest just now. Its socket is no descriptor
at all, so a write that should have been refused fails rather than landing on
another test's: a zero handle under `odin test` is somebody else's socket.
*/
@(private = "file")
backlogged_conn :: proc(waited: time.Duration) -> ^Pipe_Conn {
	c := new(Pipe_Conn)
	c.stream.socket = net.TCP_Socket(-1)
	c.timeout = time.Second
	c.last = time.now()
	c.refs = 1
	c.waiters = make(map[u16]^Pipe_Waiter)
	c.waiters[1] = nil
	for _ in 0 ..< PIPE_BACKLOG_SAMPLES {
		pipe_note_wait(c, waited)
	}
	return c
}

@(private = "file")
free_conn :: proc(c: ^Pipe_Conn) {
	delete(c.waiters)
	free(c)
}

/*
The guard itself (issue #551): a query is turned away only when every one of
the last `PIPE_BACKLOG_SAMPLES` replies waited at least half of what it has
left, something is outstanding, and the newest of them is fresh.
*/
@(test)
test_a_backlog_is_judged_on_every_recent_reply :: proc(t: ^testing.T) {
	left := time.Second

	c := backlogged_conn(left / 2)
	defer free_conn(c)
	testing.expect(t, pipe_backlogged(c, left), "every reply waited half of what was left, and the query was let on")
	// The bound is half of what is left, not a fixed figure: a caller with more
	// time to spend can wait behind the same queue.
	testing.expect(t, !pipe_backlogged(c, 2 * left + time.Millisecond), "a caller with time to wait behind the queue was turned away")

	// One fast reply among them is a slow name answered out of order rather
	// than a queue every message waits behind (RFC 7766 section 7).
	pipe_note_wait(c, time.Millisecond)
	testing.expect(t, !pipe_backlogged(c, left), "one slow name turned the next query away")

	// Nothing outstanding: no queue to wait behind, and this query is the
	// probe that says whether the queue has gone.
	d := backlogged_conn(left)
	defer free_conn(d)
	clear(&d.waiters)
	testing.expect(t, !pipe_backlogged(d, left), "the probe on an empty connection was turned away")

	// Replies older than the connection's timeout describe a queue long gone.
	e := backlogged_conn(left)
	defer free_conn(e)
	e.backlog.at = time.tick_add(time.tick_now(), -e.timeout)
	testing.expect(t, !pipe_backlogged(e, left), "a stale backlog turned a query away")

	// Fewer replies than the window are not enough to call it a queue.
	f := backlogged_conn(left)
	defer free_conn(f)
	f.backlog.taken = PIPE_BACKLOG_SAMPLES - 1
	testing.expect(t, !pipe_backlogged(f, left), "a short run of slow replies was taken for a queue")
}

/*
What a reply is sampled as. One for a caller still waiting has waited since it
was asked; one for a caller that gave up waited longer than that caller had,
which the connection's timeout stands for - and those are most of what a
connection carries once its queue is longer than the timeout.
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
	testing.expect_value(t, c.backlog.taken, 2)
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
	c := backlogged_conn(time.Second)
	u.pipe = c
	defer {
		u.pipe = nil
		destroy(u)
		free_conn(c)
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
	testing.expect_value(t, len(c.waiters), 1)
	free_all(context.temp_allocator)
}
