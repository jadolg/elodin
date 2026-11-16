package h2

import "core:mem"
import "core:testing"
import dt "core:time/datetime"

/*
RFC 9110 10.2.3 and 5.6.7: `Retry-After` is delay-seconds or an HTTP-date in
any of its three forms, measured from a fixed `now` so every row's answer is
exact.
*/
@(test)
test_retry_after_reads_every_form_rfc_9110_allows :: proc(t: ^testing.T) {
	now, err := dt.components_to_datetime(1994, 11, 6, 8, 49, 37)
	if !testing.expectf(t, err == .None, "cannot build the reference time: %v", err) {
		return
	}
	Row :: struct {
		value:   string,
		ok:      bool,
		seconds: u32,
	}
	rows := []Row {
		{value = "0", ok = true, seconds = 0},
		{value = "120", ok = true, seconds = 120},
		{value = "0000120", ok = true, seconds = 120},
		{value = "4294967295", ok = true, seconds = max(u32)},
		// Past a u32 it saturates rather than wrapping to a short wait.
		{value = "4294967296", ok = true, seconds = max(u32)},
		{value = "99999999999999999999999999", ok = true, seconds = max(u32)},
		// Not `1*DIGIT`: what `strconv` would read anyway.
		{value = "", ok = false},
		{value = "+5", ok = false},
		{value = "-5", ok = false},
		{value = "1_0", ok = false},
		{value = "0x10", ok = false},
		// OWS is the field value's own (RFC 9110 5.5), as for a Content-Length.
		{value = "5 ", ok = true, seconds = 5},
		{value = "5.0", ok = false},
		// IMF-fixdate, two minutes on; a date already past is no wait at all.
		{value = "Sun, 06 Nov 1994 08:51:37 GMT", ok = true, seconds = 120},
		{value = "Sun, 06 Nov 1994 08:49:37 GMT", ok = true, seconds = 0},
		{value = "Sat, 05 Nov 1994 08:49:37 GMT", ok = true, seconds = 0},
		{value = "Mon, 07 Nov 1994 08:49:37 GMT", ok = true, seconds = 86_400},
		// The leap second the grammar allows is the next minute's first.
		{value = "Sun, 06 Nov 1994 08:50:60 GMT", ok = true, seconds = 83},
		// Except where the next minute is a year no HTTP-date can write.
		{value = "Fri, 31 Dec 9999 23:59:60 GMT", ok = false},
		// Far enough out that the wait passes a `u32` of seconds.
		{value = "Fri, 31 Dec 9999 23:59:59 GMT", ok = true, seconds = max(u32)},
		// The obsolete RFC 850 form, and its two-digit year read by RFC 9110
		// 5.6.7: 94 is 1994, and 31 is 2031, 37 years on, rather than 1931.
		{value = "Sunday, 06-Nov-94 08:51:37 GMT", ok = true, seconds = 120},
		{value = "Monday, 06-Nov-45 08:51:37 GMT", ok = true, seconds = 0},
		// Nine leap days between.
		{value = "Thursday, 06-Nov-31 08:49:37 GMT", ok = true, seconds = (37 * 365 + 9) * 86_400},
		// asctime, with a one-digit day padded by a space or a zero.
		{value = "Sun Nov  6 08:51:37 1994", ok = true, seconds = 120},
		{value = "Sun Nov 06 08:51:37 1994", ok = true, seconds = 120},
		// Names are case-sensitive, and each form is held to its own shape.
		{value = "sun, 06 Nov 1994 08:51:37 GMT", ok = false},
		{value = "Sun, 06 nov 1994 08:51:37 GMT", ok = false},
		{value = "Sun, 06 Nov 1994 08:51:37 UTC", ok = false},
		{value = "Sun, 06 Nov 1994 08-51-37 GMT", ok = false},
		{value = "Sun, 6 Nov 1994 08:51:37 GMT ", ok = false},
		{value = "Sunday, 06 Nov 1994 08:51:37 GMT", ok = false},
		{value = "Sun, 06-Nov-94 08:51:37 GMT", ok = false},
		{value = "Funday, 06-Nov-94 08:51:37 GMT", ok = false},
		{value = "Sun Nov  6 08:51:37 94  ", ok = false},
		{value = "Sun Nov 6  08:51:37 1994", ok = false},
		// A date the calendar does not have.
		{value = "Thu, 30 Feb 1995 08:51:37 GMT", ok = false},
		{value = "Sun, 06 Nov 1994 24:00:00 GMT", ok = false},
		{value = "Sun, 06 Nov 1994 08:61:00 GMT", ok = false},
		{value = "Sun, 06 Nov 1994 08:51:61 GMT", ok = false},
	}
	for row in rows {
		seconds, ok := parse_retry_after(row.value, now)
		testing.expectf(t, ok == row.ok, "%q: ok %v, want %v", row.value, ok, row.ok)
		if ok && row.ok {
			testing.expectf(t, seconds == row.seconds, "%q: %d seconds, want %d", row.value, seconds, row.seconds)
		}
	}
}

/*
RFC 9110 5.6.7 from the other side: in 2026 a two-digit 94 is not 2094, 68 years
on, but 1994, so the wait it names is already over; and 76, 50 years on, is not
more than 50 and stays 2076.
*/
@(test)
test_an_rfc_850_year_more_than_50_years_on_is_last_centurys :: proc(t: ^testing.T) {
	now, err := dt.components_to_datetime(2026, 11, 16, 0, 0, 0)
	if !testing.expectf(t, err == .None, "cannot build the reference time: %v", err) {
		return
	}
	seconds, ok := parse_retry_after("Sunday, 06-Nov-94 08:51:37 GMT", now)
	testing.expect(t, ok, "an rfc850-date was refused")
	testing.expect_value(t, seconds, 0)

	seconds, ok = parse_retry_after("Monday, 16-Nov-76 00:00:00 GMT", now)
	testing.expect(t, ok, "an rfc850-date was refused")
	// Thirteen leap days between.
	testing.expect_value(t, seconds, (50 * 365 + 13) * 86_400)

	// Near the end of the calendar the window would reach past year 9999, which
	// no HTTP-date can name: 23 read in 9999 is not 10023.
	late, late_err := dt.components_to_datetime(9999, 6, 15, 0, 0, 0)
	if !testing.expectf(t, late_err == .None, "cannot build the reference time: %v", late_err) {
		return
	}
	_, ok = parse_retry_after("Sunday, 09-Nov-23 08:49:37 GMT", late)
	testing.expect(t, !ok, "an RFC 850 year was read past 9999")
}

/*
The form a sender generates reads back as the moment it was made from, with
the day name worked out from the date: 16 November 2026 is a Monday.
*/
@(test)
test_a_formatted_http_date_reads_back :: proc(t: ^testing.T) {
	at, err := dt.components_to_datetime(2026, 11, 16, 14, 41, 3)
	if !testing.expectf(t, err == .None, "cannot build the date: %v", err) {
		return
	}
	text := format_http_date(at, context.temp_allocator)
	testing.expect_value(t, text, "Mon, 16 Nov 2026 14:41:03 GMT")
	back, ok := parse_http_date(text, at)
	testing.expect(t, ok, "the formatted date did not parse")
	testing.expect_value(t, back, at)
	free_all(context.temp_allocator)
}

/*
The client reads `retry-after` only on a status `status_asks_to_wait` names,
and the first one: a 200 that carries one, as some CDNs send, costs no clock
read and no parse.
*/
@(test)
test_client_reads_retry_after_only_where_the_status_asks_to_wait :: proc(t: ^testing.T) {
	Row :: struct {
		status: string,
		want:   u32,
	}
	rows := []Row{{status = "429", want = 120}, {status = "503", want = 120}, {status = "200", want = 0}}
	for row in rows {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)
		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", row.status)
		encode_header(&block, "retry-after", "120")
		encode_header(&block, "retry-after", "15")
		clear(&c.header_scratch)
		append(&c.header_scratch, ..block[:])
		ok := client_finish_headers(c, 1)
		testing.expectf(t, ok, "%s: the header block was refused", row.status)
		testing.expectf(t, s.status == parse_status(row.status), "%s: status read as %d", row.status, s.status)
		testing.expectf(t, s.retry_after == row.want, "%s: retry-after read as %d, want %d", row.status, s.retry_after, row.want)
		client_stream_destroy(c, s)
		delete_key(&c.streams, u32(1))
		client_done(t, c, &track, "client retry-after", &log)
		free_all(context.temp_allocator)
	}
}
