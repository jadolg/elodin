package config

import "core:strings"
import "core:testing"

// The smallest file that loads; a test builds on it with `+`.
@(private)
MINIMAL :: "upstream:\n  servers: [1.1.1.1]\n"

// The root's KSK-2017 digest, and the DS record that anchors it.
@(private)
ROOT_DIGEST :: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
@(private)
ROOT_ANCHOR :: ". IN DS 20326 8 2 " + ROOT_DIGEST

// Loads `src`, failing the test with its refusals when it does not load.
@(private)
expect_loads :: proc(t: ^testing.T, src: string, loc := #caller_location) -> (cfg: Config, ok: bool) {
	err: Maybe(Load_Error)
	cfg, err = load_string(src, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "refused: %v, from:\n%s", e.messages, src, loc = loc)
		return {}, false
	}
	return cfg, true
}

/*
Whether loading `src` is refused with a message holding every one of `wanted`
(starting with each, given `prefix`, or equal to it, given `exact`);
`count`, when not 0, is how many refusals there are in all. `tls_files` is
`load_string`'s.
*/
@(private)
expect_refused :: proc(
	t: ^testing.T,
	src: string,
	wanted: ..string,
	prefix := false,
	exact := false,
	count := 0,
	tls_files := true,
	loc := #caller_location,
) -> bool {
	_, err := load_string(src, context.temp_allocator, tls_files = tls_files)
	e, has := err.?
	if !testing.expectf(t, has, "accepted, wanted a refusal naming %v, from:\n%s", wanted, src, loc = loc) {
		return false
	}
	if count != 0 && !testing.expectf(t, len(e.messages) == count, "wanted %d refusals, one naming %v: %v", count, wanted, e.messages, loc = loc) {
		return false
	}
	matched: for m in e.messages {
		for w in wanted {
			names := m == w if exact else (strings.has_prefix(m, w) if prefix else strings.contains(m, w))
			if !names {
				continue matched
			}
		}
		return true
	}
	testing.expectf(t, false, "no refusal names %v: %v, from:\n%s", wanted, e.messages, src, loc = loc)
	return false
}
