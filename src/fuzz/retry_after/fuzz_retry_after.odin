package fuzz_retry_after

import "core:time"
import "elodin:fuzz/harness"
import "elodin:h2"

/*
The `Retry-After` reader a DoH upstream's 429 or 503 writes into: delay-seconds
and the three HTTP-date forms. The input is the field value. What is checked is
what `note_throttled` leans on: a number of seconds is read exactly, saturating
rather than wrapping, and a date names a wait no longer than a `u32` holds
whichever side of it the clock stands.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	value := string(data[:size])
	// Either end of the range a `time.Time` holds, and a moment in 2025.
	nows := [3]time.Time{{_nsec = min(i64)}, {_nsec = max(i64)}, {_nsec = 1_763_251_200 * i64(time.Second)}}
	for now in nows {
		seconds, ok := h2.parse_retry_after(value, now)
		digits := len(value) > 0
		want: u128
		for i in 0 ..< len(value) {
			if value[i] < '0' || value[i] > '9' {
				digits = false
				break
			}
			want = min(want * 10 + u128(value[i] - '0'), u128(max(u32)) + 1)
		}
		if digits && (!ok || u128(seconds) != min(want, u128(max(u32)))) {
			panic("delay-seconds was misread")
		}
		if ok && !digits {
			if _, dated := h2.parse_http_date(value, now); !dated {
				panic("a value that is no date was read as one")
			}
		}
	}
	return 0
}
