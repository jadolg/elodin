package h2

import "core:fmt"
import "core:time"
import dt "core:time/datetime"
import "elodin:loop"

/*
Whether a response with this status is the server declining the request for
now, so that its `Retry-After` says how long to wait: 429 Too Many Requests
(RFC 6585 4) and 503 Service Unavailable (RFC 9110 15.6.4).
*/
status_asks_to_wait :: proc(status: int) -> bool {
	return status == 429 || status == 503
}

/*
A `Retry-After` field value as the response with `status` means it: its seconds
when `status_asks_to_wait`, and zero otherwise or where it does not parse. Both
HTTP clients read the field through this, the first of it in the final
response's section.
*/
retry_after_of :: proc(status: int, value: string) -> u32 {
	if !status_asks_to_wait(status) {
		return 0
	}
	if seconds, ok := retry_after_now(value); ok {
		return seconds
	}
	return 0
}

/*
`parse_retry_after` against the wall clock as it reads now, which is when the
response carrying `value` was received. The one place either HTTP client reads
that clock, and only for a date: an HTTP-date names an instant on it (RFC 9110
5.6.7), where delay-seconds needs no clock at all.
*/
@(private = "file")
retry_after_now :: proc(value: string) -> (seconds: u32, ok: bool) {
	if s, is_delay := delay_seconds(value); is_delay {
		return s, true
	}
	now := time.time_to_datetime(loop.now()) or_return // wall-clock: an HTTP-date is an instant on it
	return date_retry_after(value, now)
}

/*
RFC 9110 10.2.3: a `Retry-After` value, `HTTP-date / delay-seconds`, as the
whole seconds from `now` it names. `now` is when the response was received,
which delay-seconds counts from.

A date already past is zero, and a wait past what a `u32` holds comes back as
`max(u32)`, so a caller's own bound sees it and nothing wraps on the way. A value
that is neither form is refused.
*/
parse_retry_after :: proc(value: string, now: dt.DateTime) -> (seconds: u32, ok: bool) {
	if s, is_delay := delay_seconds(value); is_delay {
		return s, true
	}
	return date_retry_after(value, now)
}

// The HTTP-date half of `parse_retry_after`.
@(private = "file")
date_retry_after :: proc(value: string, now: dt.DateTime) -> (seconds: u32, ok: bool) {
	at := parse_http_date(value, now) or_return
	delta, err := dt.sub(at, now)
	if err != .None {
		return 0, false
	}
	// Days are bounded by year 9999 against year 1, so this does not overflow.
	total := delta.days * 86_400 + delta.seconds
	return u32(clamp(total, 0, i64(max(u32)))), true
}

/*
RFC 9110 10.2.3: `delay-seconds = 1*DIGIT`, saturating at `max(u32)`. The same
digits-only reading as a `Content-Length`, which takes no sign, base prefix or
separator, and OWS around it, which is the field value's own (RFC 9110 5.5).
*/
@(private = "file")
delay_seconds :: proc(value: string) -> (seconds: u32, ok: bool) {
	n := parse_content_length(value, int(max(u32))) or_return
	return u32(min(n, int(max(u32)))), true
}

/*
RFC 9110 5.6.7: an `HTTP-date`, in any of the three forms a recipient MUST
accept - IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), the obsolete RFC 850 form
(`Sunday, 06-Nov-94 08:49:37 GMT`) and asctime (`Sun Nov  6 08:49:37 1994`) -
as a calendar moment in UTC.

The names are case-sensitive, as the grammar's `%s` strings are. The day name is
held to the list and not to the date, which the RFC does not ask a recipient to
check. A second of 60 is the leap second the grammar allows, read as the first
second of the next minute. A moment past year 9999, which four digits of
year cannot hold, is refused. `now` decides the century of the RFC 850 form's two
digit year.
*/
parse_http_date :: proc(value: string, now: dt.DateTime) -> (moment: dt.DateTime, ok: bool) {
	year, month, day: i64
	clock: string
	switch {
	case len(value) == len("Sun, 06 Nov 1994 08:49:37 GMT") && value[3] == ',':
		// IMF-fixdate: day-name "," SP 2DIGIT SP month SP 4DIGIT SP time SP "GMT"
		if !day_name_is(value[:3], false) || !spaced(value, 4, 7, 11, 16, 25) || value[26:] != "GMT" {
			return
		}
		day = digits(value[5:7]) or_return
		month = month_number(value[8:11]) or_return
		year = digits(value[12:16]) or_return
		clock = value[17:25]
	case len(value) == len("Sun Nov  6 08:49:37 1994"):
		// asctime-date: day-name SP month SP ( 2DIGIT / ( SP DIGIT ) ) SP time SP 4DIGIT
		if !day_name_is(value[:3], false) || !spaced(value, 3, 7, 10, 19) {
			return
		}
		month = month_number(value[4:7]) or_return
		day = digits(value[9:10] if value[8] == ' ' else value[8:10]) or_return
		clock = value[11:19]
		year = digits(value[20:]) or_return
	case:
		// rfc850-date: day-name-l "," SP 2DIGIT "-" month "-" 2DIGIT SP time SP "GMT"
		REST :: len(", 06-Nov-94 08:49:37 GMT")
		if len(value) <= REST {
			return
		}
		name, rest := value[:len(value) - REST], value[len(value) - REST:]
		if !day_name_is(name, true) || rest[:2] != ", " || rest[4] != '-' || rest[8] != '-' || !spaced(rest, 11, 20) || rest[21:] != "GMT" {
			return
		}
		day = digits(rest[2:4]) or_return
		month = month_number(rest[5:8]) or_return
		yy := digits(rest[9:11]) or_return
		/*
		RFC 9110 5.6.7: a two-digit year that would put the date more than 50
		years in the future is the most recent past year with those digits, so
		it is read as the one year with those digits from 49 years back to 50
		on. Judged by year, which is as fine as two digits can be read.
		*/
		year = now.year / 100 * 100 + yy
		if year > now.year + 50 {
			year -= 100
		} else if year < now.year - 49 {
			year += 100
		}
		clock = rest[12:20]
	}
	if clock[2] != ':' || clock[5] != ':' {
		return
	}
	hour := digits(clock[0:2]) or_return
	minute := digits(clock[3:5]) or_return
	second := digits(clock[6:8]) or_return
	leap := second == 60
	if leap {
		second = 59
	}
	m, err := dt.components_to_datetime(year, month, day, hour, minute, second)
	if err != .None {
		return
	}
	if leap {
		m, err = dt.add(m, dt.Delta{seconds = 1})
		if err != .None {
			return
		}
	}
	// Past 9999 is a moment no HTTP-date can write: the leap second of its last
	// minute, or an RFC 850 year read into the next century.
	if m.year > 9999 {
		return
	}
	return m, true
}

/*
`at` as an RFC 9110 5.6.7 IMF-fixdate, the form a sender generates. `at` is a
valid date in years 0 to 9999, which is what the four digits hold.
*/
format_http_date :: proc(at: dt.DateTime, allocator := context.allocator) -> string {
	ordinal, _ := dt.date_to_ordinal(at.date)
	day_names, month_names := DAY_NAMES, MONTH_NAMES
	return fmt.aprintf(
		"%s, %02d %s %04d %02d:%02d:%02d GMT",
		day_names[int(dt.day_of_week(ordinal))],
		at.day,
		month_names[at.month - 1],
		at.year,
		at.hour,
		at.minute,
		at.second,
		allocator = allocator,
	)
}

// RFC 9110 5.6.7's `day-name`, indexed by `time.Weekday` and `datetime.Weekday`.
DAY_NAMES :: [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// RFC 9110 5.6.7's `month`, January first.
MONTH_NAMES :: [12]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

@(private = "file")
DAY_NAMES_LONG :: [7]string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

@(private = "file")
day_name_is :: proc(s: string, long: bool) -> bool {
	names := DAY_NAMES_LONG if long else DAY_NAMES
	for n in names {
		if s == n {
			return true
		}
	}
	return false
}

@(private = "file")
month_number :: proc(s: string) -> (month: i64, ok: bool) {
	names := MONTH_NAMES
	for n, i in names {
		if s == n {
			return i64(i + 1), true
		}
	}
	return 0, false
}

// A fixed-width run of digits, which no field here has more than four of.
@(private = "file")
digits :: proc(s: string) -> (v: i64, ok: bool) {
	for i in 0 ..< len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v * 10 + i64(s[i] - '0')
	}
	return v, len(s) > 0
}

// Whether `s` has a space at each of `at`.
@(private = "file")
spaced :: proc(s: string, at: ..int) -> bool {
	for i in at {
		if s[i] != ' ' {
			return false
		}
	}
	return true
}
