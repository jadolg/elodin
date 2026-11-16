package upstream

import "core:fmt"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"
import "elodin:loop"

/*
Run one DoH exchange over HTTP/1.1 against `reply`, then charge the upstream
what `exchange` would for it, `FAILURE_THRESHOLD` times over, and hand back the
kind and how long that parked the upstream for.
*/
@(private = "file")
park_on_h1_reply :: proc(t: ^testing.T, reply: string) -> (err: Error, cooldown: time.Duration, ok: bool) {
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
	for _ in 0 ..< FAILURE_THRESHOLD {
		record_failure(u, err)
	}
	// The premise: the run parked it, so the cooldown is the one it was given.
	if !testing.expect(t, !healthy(u), "the upstream was not parked") {
		return
	}
	return err, -loop.moment_since(u.down_until), true
}

// RFC 9110 5.6.7's IMF-fixdate for `at`.
@(private = "file")
imf_fixdate :: proc(at: time.Time) -> string {
	days := [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	months := [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	y, mo, d := time.date(at)
	h, mi, s := time.clock_from_time(at)
	return fmt.tprintf("%s, %02d %s %04d %02d:%02d:%02d GMT", days[int(time.weekday(at))], d, months[int(mo) - 1], y, h, mi, s)
}

/*
A 429 or a 503 is the upstream refusing this server, not failing: it is its own
kind (#258), and the cooldown it earns is as long as its `Retry-After` asks -
in either of the forms RFC 9110 10.2.3 allows - and never shorter than
`COOLDOWN`, nor longer than `MAX_RETRY_AFTER`. A `Retry-After` on anything else,
on an interim response, or that does not parse, asks for nothing.
*/
@(test)
test_a_throttled_doh_h1_reply_parks_for_its_retry_after :: proc(t: ^testing.T) {
	Row :: struct {
		what:     string,
		reply:    string,
		err:      Error,
		cooldown: time.Duration,
	}
	in_five_minutes := imf_fixdate(time.time_add(loop.now(), 5 * time.Minute))
	rows := []Row {
		{
			what = "429 asking for two minutes",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = 2 * time.Minute,
		},
		{
			what = "503 asking for five minutes by date",
			reply = fmt.tprintf("HTTP/1.1 503 Service Unavailable\r\nRetry-After: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", in_five_minutes),
			err = .Throttled,
			cooldown = 5 * time.Minute,
		},
		{
			what = "503 with a maintenance page and no Retry-After",
			reply = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\nConnection: close\r\n\r\nmaintenance",
			err = .Throttled,
			cooldown = COOLDOWN,
		},
		{
			what = "429 asking for less than the cooldown",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = COOLDOWN,
		},
		{
			what = "429 asking for years",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 99999999999\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = MAX_RETRY_AFTER,
		},
		{
			what = "429 whose Retry-After is not one",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: soon\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = COOLDOWN,
		},
		{
			what = "429 whose body is past a DNS message",
			reply = fmt.tprintf("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", dns.MAX_MESSAGE + 1),
			err = .Throttled,
			cooldown = 2 * time.Minute,
		},
		{
			what = "429 asking twice, the first longer",
			reply = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = 2 * time.Minute,
		},
		{
			what = "Retry-After on an interim response only",
			reply = "HTTP/1.1 103 Early Hints\r\nRetry-After: 120\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .Throttled,
			cooldown = COOLDOWN,
		},
		{
			what = "Retry-After on a 500",
			reply = "HTTP/1.1 500 Internal Server Error\r\nRetry-After: 120\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			err = .HTTP_Error,
			cooldown = COOLDOWN,
		},
	}
	for row in rows {
		err, cooldown, ok := park_on_h1_reply(t, row.reply)
		if !ok {
			continue
		}
		testing.expectf(t, err == row.err, "%s: %v, want %v", row.what, err, row.err)
		// A date has whole seconds, and both clocks moved on a little since.
		testing.expectf(
			t,
			cooldown <= row.cooldown && cooldown > row.cooldown - 2 * time.Second,
			"%s: parked for %v, want %v",
			row.what,
			cooldown,
			row.cooldown,
		)
	}
	free_all(context.temp_allocator)
}

/*
An answer ends what a `Retry-After` asked for: a run of other failures after it
parks the upstream for `COOLDOWN`, not for a wait the server has since shown it
no longer wanted.
*/
@(test)
test_an_answer_forgets_a_retry_after :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, 429, 120)
	testing.expectf(t, -loop.moment_since(u.throttled_until) > COOLDOWN, "the Retry-After was not noted: %v", -loop.moment_since(u.throttled_until))
	record_success(&u, time.Millisecond)
	for _ in 0 ..< FAILURE_THRESHOLD {
		record_failure(&u, .Timeout)
	}
	cooldown := -loop.moment_since(u.down_until)
	testing.expectf(t, cooldown <= COOLDOWN && cooldown > COOLDOWN - time.Second, "parked for %v after an answer", cooldown)
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
		// A second `retry-after` after the first, asking for five seconds.
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
				h2.encode_header(&head, "retry-after", "5")
			}
		}
		err, wait := exchange_with_head(t, interim[:], head[:], row.body)
		testing.expectf(t, err == row.err, "%s: %v, want %v", row.what, err, row.err)
		testing.expectf(t, wait <= row.wait && wait > row.wait - time.Second, "%s: asked to wait %v, want %v", row.what, wait, row.wait)
	}
	free_all(context.temp_allocator)
}

/*
Replies arriving together each ask for their own wait, and the longest stands:
a later 503 that says nothing does not cut short what a 429 asked for.
*/
@(test)
test_a_later_shorter_retry_after_does_not_cut_a_longer_one :: proc(t: ^testing.T) {
	u: Upstream
	note_throttled(&u, 429, 120)
	note_throttled(&u, 503, 0)
	wait := -loop.moment_since(u.throttled_until)
	testing.expectf(t, wait <= 2 * time.Minute && wait > 2 * time.Minute - time.Second, "asked to wait %v after a 120s and a bare 503", wait)
	testing.expect_value(t, u.throttled_status, 503)
}
