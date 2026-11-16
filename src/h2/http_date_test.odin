package h2

import "core:testing"
import "core:time"

/*
RFC 9110 10.2.3 and 5.6.7: `Retry-After` is delay-seconds or an HTTP-date in
any of its three forms, measured from a fixed `now` so every row's answer is
exact.
*/
@(test)
test_retry_after_reads_every_form_rfc_9110_allows :: proc(t: ^testing.T) {
	now, built := time.components_to_time(1994, 11, 6, 8, 49, 37)
	if !testing.expect(t, built, "cannot build the reference time") {
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
		{value = "5 ", ok = false},
		{value = "5.0", ok = false},
		// IMF-fixdate, two minutes on; a date already past is no wait at all.
		{value = "Sun, 06 Nov 1994 08:51:37 GMT", ok = true, seconds = 120},
		{value = "Sun, 06 Nov 1994 08:49:37 GMT", ok = true, seconds = 0},
		{value = "Sat, 05 Nov 1994 08:49:37 GMT", ok = true, seconds = 0},
		{value = "Mon, 07 Nov 1994 08:49:37 GMT", ok = true, seconds = 86_400},
		// The leap second the grammar allows is the next minute's first.
		{value = "Sun, 06 Nov 1994 08:50:60 GMT", ok = true, seconds = 83},
		// Far enough out to overflow a nanosecond `time.Time`, still bounded.
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
	now, built := time.components_to_time(2026, 11, 16, 0, 0, 0)
	if !testing.expect(t, built, "cannot build the reference time") {
		return
	}
	seconds, ok := parse_retry_after("Sunday, 06-Nov-94 08:51:37 GMT", now)
	testing.expect(t, ok, "an rfc850-date was refused")
	testing.expect_value(t, seconds, 0)

	seconds, ok = parse_retry_after("Monday, 16-Nov-76 00:00:00 GMT", now)
	testing.expect(t, ok, "an rfc850-date was refused")
	// Thirteen leap days between.
	testing.expect_value(t, seconds, (50 * 365 + 13) * 86_400)
}
