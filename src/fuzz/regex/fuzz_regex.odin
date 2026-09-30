package fuzz_regex

import "core:strings"
import "elodin:filter"
import "elodin:fuzz/harness"

/*
The RE2 subset `filter` reads a `/regex/` rule in, and the tree it hands Odin's
compiler: the input is the pattern, whole, so every byte reaches the parser
rather than the list reader in front of it. What is kept is matched against
the input's first line and a few names, which drives the program through the
VM, the subject spelling and the scratch a match runs in.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	text := string(data[:size])
	block := filter.set_make()
	defer filter.set_destroy(block)
	allow := filter.set_make()
	defer filter.set_destroy(allow)

	if filter.parse_rule(block, allow, strings.concatenate({"/", text, "/"})) != 1 {
		return 0
	}
	e := filter.engine_make()
	defer filter.engine_destroy(e)
	filter.engine_swap(e, block, allow)
	name := text
	if i := strings.index_byte(text, '\n'); i >= 0 {
		name = text[:i]
	}
	for n in ([]string{name, "ads.example.com.", "a\\046b(c).x\\032y.", "0-_9.z."}) {
		_ = filter.engine_match(e, n)
	}
	// The sets are the deferred destroys' to free, not the engine's.
	filter.engine_swap(e, nil, nil)
	return 0
}
