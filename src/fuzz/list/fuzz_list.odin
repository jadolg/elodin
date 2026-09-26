package fuzz_list

import "elodin:filter"
import "elodin:fuzz/harness"

/*
The blocklist parsers, which read whatever a remote list host serves. The first
byte picks the format, so each line parser gets inputs of its own rather than
only the ones `detect_format` sends it; the rest is the list, and is also read
as a single `blocking.rules` entry.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	if size == 0 {
		return 0
	}
	format := filter.Format(data[0] % (u8(max(filter.Format)) + 1))
	text := string(data[1:size])

	block := filter.set_make()
	defer filter.set_destroy(block)
	allow := filter.set_make()
	defer filter.set_destroy(allow)

	_ = filter.parse_list(block, allow, text, format)
	_ = filter.parse_rule(block, allow, text)
	return 0
}
