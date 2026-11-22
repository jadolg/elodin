package dns

import "core:testing"

/*
Every lifetime drawn is the RFC 7873 section 7.1 default less at most
`COOKIE_SECRET_JITTER` percent, and the draws differ: two hundred equal draws
from a range of more than 34 000 values would happen by chance with a
probability far below 1e-9.
*/
@(test)
test_a_cookie_secret_lifetime_carries_jitter :: proc(t: ^testing.T) {
	shortest := u32(COOKIE_SECRET_LIFETIME * (100 - COOKIE_SECRET_JITTER) / 100)
	first := cookie_secret_lifetime()
	varied := false
	for _ in 0 ..< 200 {
		got := cookie_secret_lifetime()
		testing.expectf(t, got >= shortest && got <= COOKIE_SECRET_LIFETIME, "a lifetime of %d s is outside [%d, %d]", got, shortest, COOKIE_SECRET_LIFETIME)
		varied ||= got != first
	}
	testing.expect(t, varied, "every lifetime drawn was the same")
}
