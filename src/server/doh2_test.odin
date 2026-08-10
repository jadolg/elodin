package server

import "base:runtime"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:h2"
import "elodin:pool"

/*
A scripted peer: hands `input` to the connection a read at a time and keeps
everything the connection writes back.

`await` holds the peer open until the answer has been written. `h2.serve` marks
the connection closed on its way out, and a closed connection refuses writes -
so a peer that leaves the moment its request is sent would silence a handler
still running on a pool worker, which is not what a real one does.
*/
@(private = "file")
Script :: struct {
	input:  []u8,
	read:   int,
	await:  string,
	mu:     sync.Mutex,
	output: [dynamic]u8,
}

@(private = "file")
script_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	s := cast(^Script)user
	if s.read >= len(s.input) {
		deadline := time.time_add(time.now(), 2 * time.Second)
		for time.diff(time.now(), deadline) > 0 {
			sync.mutex_lock(&s.mu)
			answered := strings.contains(string(s.output[:]), s.await)
			sync.mutex_unlock(&s.mu)
			if answered {
				break
			}
			time.sleep(time.Millisecond)
		}
		// Out of script: the peer has gone, which is what ends `h2.serve`.
		return 0, false
	}
	n = min(len(buf), len(s.input) - s.read)
	copy(buf, s.input[s.read:s.read + n])
	s.read += n
	return n, true
}

@(private = "file")
script_write :: proc(user: rawptr, buf: []u8) -> bool {
	s := cast(^Script)user
	sync.mutex_lock(&s.mu)
	defer sync.mutex_unlock(&s.mu)
	append(&s.output, ..buf)
	return true
}

@(private = "file")
write_frame :: proc(out: ^[dynamic]u8, length: int, type: u8, flags: u8, stream_id: u32) {
	append(
		out,
		u8(length >> 16),
		u8(length >> 8),
		u8(length),
		type,
		flags,
		u8(stream_id >> 24),
		u8(stream_id >> 16),
		u8(stream_id >> 8),
		u8(stream_id),
	)
}

// HPACK literal without indexing, new name - the encoding that needs no table
// state, so the block can be built here without an encoder.
@(private = "file")
write_field :: proc(out: ^[dynamic]u8, name, value: string) {
	append(out, 0x00)
	append(out, u8(len(name)))
	append(out, ..transmute([]u8)name)
	append(out, u8(len(value)))
	append(out, ..transmute([]u8)value)
}

// Everything a client sends for one complete GET: the preface, the SETTINGS it
// opens with, and a single HEADERS frame carrying the whole request.
@(private = "file")
one_get_request :: proc(path: string) -> [dynamic]u8 {
	block := make([dynamic]u8, 0, 128, context.allocator)
	defer delete(block)
	write_field(&block, ":method", "GET")
	write_field(&block, ":scheme", "https")
	write_field(&block, ":authority", "dns.example")
	write_field(&block, ":path", path)

	out := make([dynamic]u8, 0, 256, context.allocator)
	append(&out, ..transmute([]u8)string(h2.PREFACE))
	write_frame(&out, 0, 0x4, 0, 0)
	// END_STREAM | END_HEADERS: a complete request in one frame.
	write_frame(&out, len(block), 0x1, 0x5, 1)
	append(&out, ..block[:])
	return out
}

// Whether any DATA frame went out, which is what says a response carried a
// body: a body is the flow-controlled part, and the only part that can park the
// thread writing it.
@(private = "file")
wrote_a_body :: proc(out: []u8) -> bool {
	pos := 0
	for pos + 9 <= len(out) {
		length := int(out[pos]) << 16 | int(out[pos + 1]) << 8 | int(out[pos + 2])
		if out[pos + 3] == 0x0 && length > 0 {
			return true
		}
		pos += 9 + length
	}
	return false
}

@(private = "file")
Gate :: struct {
	open: bool,
}

@(private = "file")
gate_job :: proc(data: rawptr) {
	g := cast(^Gate)data
	for !sync.atomic_load(&g.open) {
		time.sleep(time.Millisecond)
	}
}

@(private = "file")
Result :: struct {
	// Everything the connection wrote. The caller owns it.
	output:  [dynamic]u8,
	dropped: u64,
	// Requests that reached the pool, the job occupying it not counted.
	queued:  int,
}

/*
Serve one GET for `path` over a whole HTTP/2 connection and report what came of
it.

`occupy` fills the worker with a job that will not finish, which is what puts
the backlog at the limit. The pool is one worker throughout, so `max_pending` of
1 and an occupied worker is a full backlog.
*/
@(private = "file")
serve_one :: proc(cfg: ^config.Config, path: string, await: string, occupy: bool) -> Result {
	handler_pool := pool.make_pool(1)
	s := Server {
		cfg          = cfg,
		handler_pool = handler_pool,
	}

	gate := Gate{}
	if occupy {
		pool.submit(handler_pool, gate_job, &gate)
	}

	input := one_get_request(path)
	defer delete(input)

	script := Script {
		input  = input[:],
		await  = await,
		output = make([dynamic]u8, 0, 256, context.allocator),
	}

	ctx := H2_Context {
		server = &s,
		client = "127.0.0.1",
		path   = cfg.listeners.doh.path,
	}
	io := h2.IO {
		user  = &script,
		read  = script_read,
		write = script_write,
	}
	hc := h2.make_conn(io, h2_handler, &ctx)
	h2.serve(hc)

	// Read before the gate opens: once the worker is free the pool drains, and
	// a job that was queued would no longer be pending to find.
	queued := pool.pending(handler_pool)
	if occupy {
		queued -= 1
	}

	sync.atomic_store(&gate.open, true)
	h2.conn_wait_idle(hc)
	h2.conn_unref(hc)
	pool.destroy(handler_pool)

	return Result{output = script.output, dropped = sync.atomic_load(&s.stats.dropped), queued = queued}
}

/*
DoH over HTTP/2 must shed against `max_pending` like every other queued query.

It is the only transport that hands its work to the shared worker pool instead
of answering on its own connection thread, so it is the one that can fill that
pool - up to `max_connections` x `MAX_CONCURRENT` streams - while the operator's
backlog limit sheds UDP at a few hundred.

The query is a bare DNS header with no question, which the endpoint answers
FORMERR without reaching the cache, the filters or an upstream group - none of
which are wired up here. A shed request never gets that far, but a regression
that queues it again should fail this test rather than crash it.
*/
@(test)
test_doh2_sheds_when_the_pool_backlog_is_full :: proc(t: ^testing.T) {
	/*
	A queued job is allocated on the connection thread and released on a pool
	worker, and in the server both run under the default heap allocator. The
	test runner hands this proc a per-test tracking allocator instead, which
	would make that pairing a free through an allocator that never made the
	block.
	*/
	context.allocator = runtime.heap_allocator()

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	cfg.server.max_pending = 1
	cfg.cache.enabled = false
	cfg.blocking.enabled = false

	// A bare 12-byte DNS header, base64url with no padding.
	got := serve_one(&cfg, "/dns-query?dns=AAAAAAAAAAAAAAAA", "", occupy = true)
	defer delete(got.output)

	testing.expectf(t, got.queued == 0, "%d requests were queued past max_pending", got.queued)

	// The status is the whole answer: a shed carries no body, so that it cannot
	// park this thread on flow control. See `h2_shed`.
	testing.expect(
		t,
		strings.contains(string(got.output[:]), "503"),
		"the shed request was not answered 503 (nothing was shed)",
	)
	testing.expect(
		t,
		!wrote_a_body(got.output[:]),
		"the shed answer carried a body, which can park the reader on flow control",
	)
	testing.expect_value(t, got.dropped, u64(1))
}

// The shed is a limit, not a policy: with the pool idle the same request goes to
// a worker and is answered there.
@(test)
test_doh2_queues_while_the_pool_has_room :: proc(t: ^testing.T) {
	// See the note in the test above.
	context.allocator = runtime.heap_allocator()

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	cfg.server.max_pending = 8

	got := serve_one(&cfg, "/not-the-endpoint", "not found", occupy = false)
	defer delete(got.output)

	answer := string(got.output[:])
	// The 404 status is a static-table index rather than three digits on the
	// wire; its body is what shows plainly.
	testing.expect(
		t,
		strings.contains(answer, "not found"),
		"the request was not answered by a worker",
	)
	testing.expect(t, !strings.contains(answer, "503"), "an idle pool shed a request")
	// Also what says `wrote_a_body` can tell: this answer has one.
	testing.expect(t, wrote_a_body(got.output[:]), "the 404 went out without its body")
	testing.expect_value(t, got.dropped, u64(0))
}

/*
`dropped` counts queries the server refused, not streams it turned away.

A request for some other path is shed like any other once the backlog is full -
it would have taken a worker to answer - but it was never going to reach the
resolver, so counting it would have a scanner on the DoH port inflating the
figure an operator reads as "this server cannot keep up".
*/
@(test)
test_doh2_shed_counts_only_queries :: proc(t: ^testing.T) {
	// See the note in the first test.
	context.allocator = runtime.heap_allocator()

	cfg := config.default_config()
	cfg.listeners.doh.path = "/dns-query"
	cfg.server.max_pending = 1

	got := serve_one(&cfg, "/not-the-endpoint", "", occupy = true)
	defer delete(got.output)

	testing.expectf(t, got.queued == 0, "%d requests were queued past max_pending", got.queued)
	testing.expect(
		t,
		strings.contains(string(got.output[:]), "503"),
		"the request was not shed",
	)
	testing.expect_value(t, got.dropped, u64(0))
}
