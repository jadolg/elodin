package config

import "core:strings"
import "core:testing"

// The smallest file that loads; a test builds on it with `+`.
@(private)
MINIMAL :: "upstream:\n  servers: [1.1.1.1]\n"

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
(or starting with each, given `prefix`); `exactly_one` also wants that message
to be the only one.
*/
@(private)
expect_refused :: proc(
	t: ^testing.T,
	src: string,
	wanted: ..string,
	prefix := false,
	exactly_one := false,
	loc := #caller_location,
) -> bool {
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if !testing.expectf(t, has, "accepted, wanted a refusal naming %v, from:\n%s", wanted, src, loc = loc) {
		return false
	}
	if exactly_one && !testing.expectf(t, len(e.messages) == 1, "wanted one refusal naming %v: %v", wanted, e.messages, loc = loc) {
		return false
	}
	matched: for m in e.messages {
		for w in wanted {
			if !(strings.has_prefix(m, w) if prefix else strings.contains(m, w)) {
				continue matched
			}
		}
		return true
	}
	testing.expectf(t, false, "no refusal names %v: %v, from:\n%s", wanted, e.messages, src, loc = loc)
	return false
}
