package fuzz_retry_after

import dt "core:time/datetime"
import "elodin:fuzz/harness"
import "elodin:h2"

/*
The `Retry-After` reader a DoH upstream's 429 or 503 writes into: delay-seconds
and the three HTTP-date forms. The input is the field value.

What is checked, against oracles of the target's own:
  - delay-seconds is read exactly, saturating at `max(u32)`, whatever `now` is;
  - a date read back through `h2.format_http_date` is the same moment;
  - an RFC 850 date's year ends in its two digits and lies from 49 years
    before `now` to 50 after (RFC 9110 5.6.7);
  - a date's wait is measured from `now`: a day earlier, it is a day longer.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	value := string(data[:size])
	digits := len(value) > 0
	want: u64
	for i in 0 ..< len(value) {
		if value[i] < '0' || value[i] > '9' {
			digits = false
			break
		}
		want = min(want * 10 + u64(value[i] - '0'), u64(max(u32)))
	}

	// Mid-year, so a day earlier is the same year and the RFC 850 window
	// does not move between the two.
	nows := [3][6]i64{{1970, 6, 15, 0, 0, 0}, {2025, 6, 15, 12, 0, 0}, {9999, 6, 15, 23, 59, 59}}
	for c in nows {
		now, nerr := dt.components_to_datetime(c[0], c[1], c[2], c[3], c[4], c[5])
		day_before, berr := dt.add(now, dt.Delta{days = -1})
		if nerr != .None || berr != .None {
			panic("cannot build the reference times")
		}
		seconds, ok := h2.parse_retry_after(value, now)
		if digits {
			if !ok || u64(seconds) != want {
				panic("delay-seconds was misread")
			}
			continue
		}
		if !ok {
			continue
		}
		at, dated := h2.parse_http_date(value, now)
		if !dated {
			panic("a Retry-After that is no number and no date was read")
		}
		back, again := h2.parse_http_date(h2.format_http_date(at, context.temp_allocator), now)
		if !again || back != at {
			panic("a date did not read back as itself")
		}
		if rfc850(value) {
			yy := i64(value[len(value) - 15] - '0') * 10 + i64(value[len(value) - 14] - '0')
			if at.year %% 100 != yy || at.year < now.year - 49 || at.year > now.year + 50 {
				panic("an RFC 850 year was read into the wrong century")
			}
			continue
		}
		earlier, earlier_ok := h2.parse_retry_after(value, day_before)
		if !earlier_ok {
			panic("a date read at one moment was refused a day before it")
		}
		if seconds > 0 && earlier < max(u32) && earlier - seconds != 86_400 {
			panic("a date's wait is not measured from now")
		}
	}
	return 0
}

// Whether `value` has the RFC 850 shape at its end: `-yy hh:mm:ss GMT`.
@(private = "file")
rfc850 :: proc(value: string) -> bool {
	return len(value) > 21 && value[len(value) - 16] == '-'
}
