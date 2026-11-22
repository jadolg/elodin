package dns

import "core:crypto"

/*
How long a cookie secret is used for, in seconds, before it is replaced (RFC
7873 section 7.1).

The RFC's default lifetime of one day, less a random share of up to
`COOKIE_SECRET_JITTER` percent of it: "pseudorandom jitter in the range of plus
zero to minus at least 40%", so that rollovers are neither synchronised nor
predictable. Drawn afresh for every rollover, and never above the section's
26-hour SHOULD NOT.
*/
cookie_secret_lifetime :: proc() -> u32 {
	b: [4]u8
	crypto.rand_bytes(b[:])
	r := u64(b[0]) << 24 | u64(b[1]) << 16 | u64(b[2]) << 8 | u64(b[3])
	return COOKIE_SECRET_LIFETIME - u32(r * COOKIE_SECRET_LIFETIME * COOKIE_SECRET_JITTER / 100 >> 32)
}

COOKIE_SECRET_LIFETIME :: 86_400
COOKIE_SECRET_JITTER :: 40
