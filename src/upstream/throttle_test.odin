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
import "elodin:h2"
import "elodin:logx"
import "elodin:loop"

/*
Run one DoH exchange over HTTP/1.1 against `reply`, and charge the upstream
for it as `exchange` would. Hands back the kind, how long a `Retry-After` has
the upstream left alone for, and whether it is still asked first.
*/
@(private)
throttle_on_h1_reply :: proc(t: ^testing.T, reply: string, allocator := context.temp_allocator) -> (err: Error, window: time.Duration, up: bool, ok: bool) {
	query := []u8{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		return
	}
	// A run that never dials still ends: the mock gives up on `accept`.
	if serr := net.set_option(listener, .Receive_Timeout, 3 * time.Second); !testing.expectf(t, serr == nil, "cannot bound the accept: %v", serr) {
		return
	}
	m := Http_Mock {
		listener = listener,
		reply    = reply,
	}
	server := thread.create_and_start_with_poly_data(&m, http_mock_once)
	defer {
		thread.join(server)
		thread.destroy(server)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec {
			name = "throttling",
			kind = .TCP,
			address = "127.0.0.1",
			port = bound.port,
			hostname = "doh.invalid",
			path = "/dns-query",
		},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	resp: []u8
	resp, err = exchange_doh_h1(u, query, query, time.tick_add(loop.tick_now(), 2 * time.Second), allocator)
	if !testing.expectf(t, resp == nil && err != .None, "a refusal came back as an answer: %v", err) {
		return
	}
	record_failure(u, err)
	return err, max(-loop.moment_since(u.throttled_until), 0), healthy(u), true
}

/*
A 429 is the upstream refusing this server and a 503 one that cannot serve for
now, not a broken reply: each is a kind of its own (#258). One that carries a
`Retry-After`, in either form RFC 9110 10.2.3
allows, parks the upstream at once for that long, never less than `COOLDOWN`
nor more than `MAX_RETRY_AFTER`. One without, or whose value does not parse, or
a `Retry-After` on anything else or on an interim response, parks nothing.
*/
@(test)
test_a_throttled_doh_h1_reply_parks_for_its_retry_after :: proc(t: ^testing.T) {
	Row :: struct {
		what:   string,
		reply:  string,
		err:    Error,
		window: time.Duration,
	}
	at, built := time.time_to_datetime(time.time_add(loop.now(), 4 * time.Minute))
	if !testing.expect(t, built, "cannot read the clock as a date") {
		return
	}
	in_four_minutes := h2.format_http_date(at, context.temp_allocator)
	rows := []Row {
		{
			what = "429 asking for two minutes",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = 2 * time.Minute,
		},
		{
			what = "503 asking for four minutes by date",
			reply = fmt.tprintf("HTTP/1.1 503 Service Unavailable\r\nRetry-After: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", in_four_minutes),
			err = .Unavailable,
			window = 4 * time.Minute,
		},
		{
			what = "503 with a maintenance page and no Retry-After",
			reply = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\nConnection: close\r\n\r\nmaintenance",
			err = .Unavailable,
			window = 0,
		},
		{
			what = "429 asking for less than the cooldown",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = COOLDOWN,
		},
		{
			what = "429 asking for longer than the bound",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 99999999999\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = MAX_RETRY_AFTER,
		},
		{
			what = "429 whose Retry-After is not one",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: soon\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = 0,
		},
		{
			what = "429 whose body is past a DNS message",
			reply = fmt.tprintf("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", dns.MAX_MESSAGE + 1),
			err = .Throttled,
			window = 2 * time.Minute,
		},
		{
			what = "429 whose body breaks off",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 50\r\nConnection: close\r\n\r\n0123456789",
			err = .Throttled,
			window = 2 * time.Minute,
		},
		{
			what = "429 whose framing the reader refuses",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
			err = .HTTP_Error,
			window = 0,
		},
		{
			what = "503 whose head is cut off after its status line",
			reply = "HTTP/1.1 503 Service Unavailable\r\nRetry-",
			err = .IO_Error,
			window = 0,
		},
		{
			what = "429 asking twice, the first longer",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nRetry-After: 15\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = 2 * time.Minute,
		},
		{
			what = "Retry-After on an interim response only",
			reply = "HTTP/1.1 103 Early Hints\r\nRetry-After: 120\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = 0,
		},
		{
			what = "Retry-After on a 500",
			reply = "HTTP/1.1 500 Internal Server Error\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .HTTP_Error,
			window = 0,
		},
	}
	for row in rows {
		err, window, up, ok := throttle_on_h1_reply(t, row.reply)
		if !ok {
			continue
		}
		testing.expectf(t, err == row.err, "%s: %v, want %v", row.what, err, row.err)
		// A date has whole seconds, and both clocks moved on a little since.
		testing.expectf(
			t,
			window <= row.window && window > row.window - 2 * time.Second,
			"%s: left alone for %v, want %v",
			row.what,
			window,
			row.window,
		)
		// One failure parks nothing; only the wait does.
		testing.expectf(t, up == (row.window == 0), "%s: asked first %v with a window of %v", row.what, up, window)
	}
	free_all(context.temp_allocator)
}

/*
`Retry-After` is read only on a status that asks the client to wait. A 200
carrying one, which some CDNs send, is not parsed at all.
*/
@(test)
test_retry_after_is_read_only_where_the_status_asks_to_wait :: proc(t: ^testing.T) {
	Row :: struct {
		reply: string,
		want:  u32,
	}
	rows := []Row {
		{reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 120},
		{reply = "HTTP/1.1 200 OK\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
	}
	for row in rows {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)
		resp, err, ok := exchange_against(t, row.reply, &track)
		if !ok {
			continue
		}
		testing.expectf(t, err == .None, "%q: %v", row.reply[:12], err)
		testing.expectf(t, resp.retry_after == row.want, "%q: Retry-After read as %d, want %d", row.reply[:12], resp.retry_after, row.want)
		if len(resp.body) > 0 {
			delete(resp.body, mem.tracking_allocator(&track))
		}
	}
}

/*
A `Retry-After` stops the next queries going to the upstream, even one that
answers some of them (RFC 9110 10.2.3): a token bucket answering one query in
three is still asked to be left alone. An answer to a query sent before the
refusal does not lift what it asked for; an answer to one sent after it does,
since the server is taking queries again.
*/
@(test)
test_only_an_answer_sent_after_the_refusal_lifts_a_retry_after :: proc(t: ^testing.T) {
	u: Upstream
	before := loop.tick_now()
	note_throttled(&u, .Throttled, 429, 300)
	record_failure(&u, .Throttled)
	testing.expect(t, !healthy(&u), "asked to wait 300s, the upstream is still asked first")
	record_success(&u, time.Millisecond, sent = before)
	testing.expect(t, !healthy(&u), "an answer to a query sent before the refusal lifted it")
	testing.expect(t, !answering(&u), "a member asked to be left alone is counted as answering")
	wait := -loop.moment_since(u.throttled_until)
	testing.expectf(t, wait > 5 * time.Minute - time.Second && wait <= 5 * time.Minute, "left alone for %v, want 5m", wait)

	record_success(&u, time.Millisecond, sent = loop.tick_now())
	testing.expect(t, healthy(&u), "an answer to a query sent after the refusal did not lift it")
	testing.expect(t, answering(&u), "a member answering again is not counted as answering")
}

/*
Through a group: a member parked by a `Retry-After` is still asked when the
group has nobody else (`attempts: 2`, round 2), and its answer ends the window,
so a lone upstream that throttled once is not shown down for the rest of it.
*/
@(test)
test_a_parked_member_that_answers_its_group_is_back :: proc(t: ^testing.T) {
	m: Echo_Mock
	u, worker, ok := start_udp_mock(t, &m, echo_mock_loop, "throttled", time.Second)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)
	note_throttled(u, .Throttled, 429, 300)
	if !testing.expect(t, !healthy(u), "the Retry-After did not park the member") {
		return
	}
	msg := dns.Message{id = 0x3271, question = []dns.Question{{name = "throttled.example.test.", type = .A, class = .IN}}}
	msg.flags.rd = true
	query, _, encoded := dns.encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, encoded, dns.Encode_Error.None) {
		return
	}
	ups := []^Upstream{u}
	g := failover_group(ups, time.Second, attempts = 2)
	resp, _, err := resolve(&g, query, context.allocator)
	delete(resp, context.allocator)
	testing.expectf(t, err == .None, "the parked member's answer did not come back: %v", err)
	testing.expect_value(t, sync.atomic_load(&m.hits), 1)
	testing.expect(t, healthy(u), "a member that answered is still parked by the Retry-After")
	free_all(context.temp_allocator)
}

/*
A `Retry-After` is its own window, not a length lent to the next run of failures:
timeouts after it park the upstream for `COOLDOWN`, as any timeouts do.
*/
@(test)
test_a_retry_after_does_not_lengthen_a_later_cooldown :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, .Throttled, 429, 300)
	record_failure(&u, .Throttled)
	record_failure(&u, .Timeout)
	record_failure(&u, .Timeout)
	testing.expect_value(t, u.failures, FAILURE_THRESHOLD)
	cooldown := -loop.moment_since(u.down_until)
	testing.expectf(t, cooldown <= COOLDOWN && cooldown > COOLDOWN - time.Second, "a timeout run parked for %v", cooldown)
}

/*
Replies arriving together each ask for their own wait, and the longest stands:
neither a later 503 that says nothing nor a later 429 asking for less cuts short
what an earlier one asked for.
*/
@(test)
test_a_later_shorter_retry_after_does_not_cut_a_longer_one :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, .Throttled, 429, 120)
	note_throttled(&u, .Unavailable, 503, 0)
	wait := -loop.moment_since(u.throttled_until)
	testing.expectf(t, wait <= 2 * time.Minute && wait > 2 * time.Minute - time.Second, "asked to wait %v after a 120s and a bare 503", wait)

	v: Upstream
	note_throttled(&v, .Throttled, 429, 300)
	note_throttled(&v, .Throttled, 429, 120)
	wait = -loop.moment_since(v.throttled_until)
	testing.expectf(t, wait <= 5 * time.Minute && wait > 5 * time.Minute - time.Second, "asked to wait %v after a 300s and a 120s", wait)
}

/*
The same over HTTP/2, where the status and the field come in an HPACK block: a
429 is `Throttled` and its `retry-after` reaches the upstream, and one on an
interim response does not.
*/
@(test)
test_a_throttled_doh_h2_reply_carries_its_retry_after :: proc(t: ^testing.T) {
	Row :: struct {
		what:    string,
		interim: bool,
		status:  string,
		// A second `retry-after` after the first, asking for fifteen seconds.
		twice:   bool,
		// Bytes of body after the header block.
		body:    int,
		// The stream reset after the header block, or left open with nothing more.
		reset:   bool,
		stall:   bool,
		// Or the connection closed after it.
		hang_up: bool,
		// A second `:status` after the fields, which RFC 9113 8.3 makes malformed.
		malformed: bool,
		wait:    time.Duration,
		err:     Error,
	}
	rows := []Row {
		{what = "429 asking for two minutes", status = "429", wait = 2 * time.Minute, err = .Throttled},
		{what = "503 asking for two minutes", status = "503", wait = 2 * time.Minute, err = .Unavailable},
		{what = "429 asking twice, the first longer", status = "429", twice = true, wait = 2 * time.Minute, err = .Throttled},
		{what = "429 whose body is past a DNS message", status = "429", body = dns.MAX_MESSAGE + 1, wait = 2 * time.Minute, err = .Throttled},
		{what = "429 reset after its head", status = "429", reset = true, wait = 2 * time.Minute, err = .Throttled},
		{what = "503 whose body never comes", status = "503", stall = true, wait = 2 * time.Minute, err = .Unavailable},
		{what = "500 reset after its head", status = "500", reset = true, wait = 0, err = .HTTP_Error},
		{what = "429 whose connection closes after its head", status = "429", hang_up = true, wait = 2 * time.Minute, err = .Throttled},
		{what = "a malformed 429", status = "429", malformed = true, wait = 0, err = .HTTP_Error},
		{what = "a 103 asking, then a 429", interim = true, status = "429", wait = 0, err = .Throttled},
		{what = "500 asking for two minutes", status = "500", wait = 0, err = .HTTP_Error},
	}
	for row in rows {
		head := make([dynamic]u8, 0, 64, context.temp_allocator)
		interim: [dynamic]u8
		if row.interim {
			interim = make([dynamic]u8, 0, 64, context.temp_allocator)
			h2.encode_header(&interim, ":status", "103")
			h2.encode_header(&interim, "retry-after", "120")
			h2.encode_header(&head, ":status", row.status)
		} else {
			h2.encode_header(&head, ":status", row.status)
			h2.encode_header(&head, "retry-after", "120")
			if row.twice {
				h2.encode_header(&head, "retry-after", "15")
			}
			if row.malformed {
				h2.encode_header(&head, ":status", "200")
			}
		}
		err, wait := exchange_with_head(t, interim[:], head[:], row.body, reset = row.reset, stall = row.stall, hang_up = row.hang_up)
		testing.expectf(t, err == row.err, "%s: %v, want %v", row.what, err, row.err)
		testing.expectf(t, wait <= row.wait && wait > row.wait - time.Second, "%s: asked to wait %v, want %v", row.what, wait, row.wait)
	}
	free_all(context.temp_allocator)
}

/*
A refusal is one event and asks its kind's gate once: `note_throttled` writes
the line with the reply's own status and `Retry-After`, and `record_failure`,
counting the same event a moment later, does not ask again. Asked twice, the
second would count the event as held and could take the line for itself.
*/
@(test)
test_a_refusal_asks_its_kinds_gate_once :: proc(t: ^testing.T) {
	for kind in ([]Error{.Throttled, .Unavailable}) {
		u: Upstream
		note_throttled(&u, kind, 429 if kind == .Throttled else 503, 120)
		record_failure(&u, kind)
		testing.expectf(t, logx.gate_shut(&u.reported[kind], loop.tick_now()._nsec), "%v: the refusal did not pass its gate", kind)
		testing.expectf(t, sync.atomic_load(&u.reported[kind].held) == 0, "%v: one refusal was counted as held", kind)
		testing.expect_value(t, u.stats.failure_kinds[kind], 1)
	}
}

/*
An answer between refusals closes each window, so a token bucket can open one
per answer. The line that says so is the kind's, behind its gate, so five
refusals write one line and count four as held, however often windows open.
*/
@(test)
test_reopened_windows_share_one_gate :: proc(t: ^testing.T) {
	u: Upstream
	for _ in 0 ..< 5 {
		note_throttled(&u, .Throttled, 429, 30)
		if !testing.expect(t, !healthy(&u), "the refusal did not open a window") {
			return
		}
		record_success(&u, time.Millisecond, sent = loop.tick_now())
		if !testing.expect(t, healthy(&u), "the answer did not close the window") {
			return
		}
	}
	testing.expect_value(t, sync.atomic_load(&u.reported[.Throttled].held), 4)
}

/*
Refusals noted out of the order of their moments keep the later one: a refusal
that read its moment before another, and recorded it after, would otherwise move
`refused_at` back, and an answer to a query sent between the two would lift the
later refusal's window. The test holds the upstream's lock while a refusal is
under way, and records one an hour later in the meantime.
*/
@(test)
test_an_earlier_refusal_does_not_move_refused_at_back :: proc(t: ^testing.T) {
	u: Upstream
	sync.mutex_lock(&u.mu)
	a := thread.create_and_start_with_poly_data(&u, proc(u: ^Upstream) {
		note_throttled(u, .Throttled, 429, 300)
	})
	later := time.tick_add(loop.tick_now(), time.Hour)
	u.refused_at = later
	sync.mutex_unlock(&u.mu)
	thread.join(a)
	thread.destroy(a)
	testing.expectf(t, time.tick_diff(later, u.refused_at) >= 0, "refused_at moved back by %v", time.tick_diff(u.refused_at, later))
}
