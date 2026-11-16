package upstream

import "core:fmt"
import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"
import "elodin:loop"

/*
Run one DoH exchange over HTTP/1.1 against `reply`, and charge the upstream
for it as `exchange` would. Hands back the kind, how long a `Retry-After` has
the upstream left alone for, and whether it is still asked first.
*/
@(private = "file")
throttle_on_h1_reply :: proc(t: ^testing.T, reply: string) -> (err: Error, window: time.Duration, up: bool, ok: bool) {
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
	resp, err = exchange_doh_h1(u, query, query, time.tick_add(loop.tick_now(), 2 * time.Second), context.temp_allocator)
	if !testing.expectf(t, resp == nil && err != .None, "a refusal came back as an answer: %v", err) {
		return
	}
	record_failure(u, err)
	return err, max(-loop.moment_since(u.throttled_until), 0), healthy(u), true
}

/*
A 429 or a 503 is the upstream refusing this server, not failing: it is its own
kind (#258). One that carries a `Retry-After`, in either form RFC 9110 10.2.3
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
	at, built := time.time_to_datetime(time.time_add(loop.now(), 5 * time.Minute))
	if !testing.expect(t, built, "cannot read the clock as a date") {
		return
	}
	in_five_minutes := h2.format_http_date(at, context.temp_allocator)
	rows := []Row {
		{
			what = "429 asking for two minutes",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = 2 * time.Minute,
		},
		{
			what = "503 asking for five minutes by date",
			reply = fmt.tprintf("HTTP/1.1 503 Service Unavailable\r\nRetry-After: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", in_five_minutes),
			err = .Throttled,
			window = 5 * time.Minute,
		},
		{
			what = "503 with a maintenance page and no Retry-After",
			reply = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\nConnection: close\r\n\r\nmaintenance",
			err = .Throttled,
			window = 0,
		},
		{
			what = "429 asking for less than the cooldown",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			window = COOLDOWN,
		},
		{
			what = "429 asking for years",
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
three is still asked to be left alone, and an answer to a query sent before the
refusal does not lift what the refusal asked for.
*/
@(test)
test_an_answer_does_not_lift_a_retry_after :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, 429, 300)
	record_failure(&u, .Throttled)
	testing.expect(t, !healthy(&u), "asked to wait 300s, the upstream is still asked first")
	record_success(&u, time.Millisecond)
	testing.expect(t, !healthy(&u), "an answer lifted what a Retry-After asked for")
	testing.expect(t, !answering(&u), "a member asked to be left alone is counted as answering")
	wait := -loop.moment_since(u.throttled_until)
	testing.expectf(t, wait > 5 * time.Minute - time.Second && wait <= 5 * time.Minute, "left alone for %v, want 5m", wait)
}

/*
A `Retry-After` is its own window, not a length lent to the next run of failures:
timeouts after it park the upstream for `COOLDOWN`, as any timeouts do.
*/
@(test)
test_a_retry_after_does_not_lengthen_a_later_cooldown :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, 429, 3600)
	record_failure(&u, .Throttled)
	record_failure(&u, .Timeout)
	record_failure(&u, .Timeout)
	testing.expect_value(t, u.failures, FAILURE_THRESHOLD)
	cooldown := -loop.moment_since(u.down_until)
	testing.expectf(t, cooldown <= COOLDOWN && cooldown > COOLDOWN - time.Second, "a timeout run parked for %v", cooldown)
}

/*
Replies arriving together each ask for their own wait, and the longest stands:
a later 503 that says nothing does not cut short what a 429 asked for. The line
about the kind names one reply, status and `Retry-After` together, rather than
the last status beside the longest wait.
*/
@(test)
test_a_later_shorter_retry_after_does_not_cut_a_longer_one :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, 429, 120)
	note_throttled(&u, 503, 0)
	wait := -loop.moment_since(u.throttled_until)
	testing.expectf(t, wait <= 2 * time.Minute && wait > 2 * time.Minute - time.Second, "asked to wait %v after a 120s and a bare 503", wait)
	testing.expect_value(t, u.throttled_status, 503)
	testing.expect_value(t, u.throttled_retry, 0)

	// Nor does a later one asking for less.
	v: Upstream
	note_throttled(&v, 429, 300)
	note_throttled(&v, 429, 120)
	wait = -loop.moment_since(v.throttled_until)
	testing.expectf(t, wait <= 5 * time.Minute && wait > 5 * time.Minute - time.Second, "asked to wait %v after a 300s and a 120s", wait)
	testing.expect_value(t, v.throttled_retry, 120)
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
		wait:    time.Duration,
		err:     Error,
	}
	rows := []Row {
		{what = "429 asking for two minutes", status = "429", wait = 2 * time.Minute, err = .Throttled},
		{what = "503 asking for two minutes", status = "503", wait = 2 * time.Minute, err = .Throttled},
		{what = "429 asking twice, the first longer", status = "429", twice = true, wait = 2 * time.Minute, err = .Throttled},
		{what = "429 whose body is past a DNS message", status = "429", body = dns.MAX_MESSAGE + 1, wait = 2 * time.Minute, err = .Throttled},
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
		}
		err, wait := exchange_with_head(t, interim[:], head[:], row.body)
		testing.expectf(t, err == row.err, "%s: %v, want %v", row.what, err, row.err)
		testing.expectf(t, wait <= row.wait && wait > row.wait - time.Second, "%s: asked to wait %v, want %v", row.what, wait, row.wait)
	}
	free_all(context.temp_allocator)
}
