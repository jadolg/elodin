package fuzz_list

import "core:strings"
import "elodin:dns"
import "elodin:filter"
import "elodin:fuzz/harness"

/*
The blocklist parsers, which read whatever a remote list host serves. The first
byte picks the format, so each line parser gets inputs of its own rather than
only the ones `detect_format` sends it; the rest is the list, and is also read
as a single `blocking.rules` entry. The sets are then matched against the list's
own first line, which drives any regex rule it held through the VM and the
scratch buffer a match runs in.
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
	// No memory for a set is no input's doing.
	if block == nil || allow == nil {
		return 0
	}

	_ = filter.parse_list(block, allow, text, format)
	_ = filter.parse_rule(block, allow, text)

	e := filter.engine_make()
	defer filter.engine_destroy(e)
	filter.engine_swap(e, block, allow)
	name := text
	if i := strings.index_byte(text, '\n'); i >= 0 {
		name = text[:i]
	}
	// The format byte's spare bits pick one query type, and the rest reach
	// past 63, so a `$dnstype` rule is matched for types it names and types it
	// does not, whichever end of the range they are at.
	typed_only: bool
	for qtype in ([]dns.Type{dns.Type(data[0] >> 2), .HTTPS, .CAA, dns.Type(65535)}) {
		_ = filter.engine_match(e, name, qtype, &typed_only)
	}
	// The sets are the deferred destroys' to free, not the engine's.
	filter.engine_swap(e, nil, nil)
	return 0
}
