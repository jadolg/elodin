package fuzz_dns

import "elodin:dns"
import "elodin:fuzz/harness"

// Every query and every upstream answer arrives through this one entry point,
// so it is the single most exposed parser in the binary.
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	_, _ = dns.decode_message(data[:size])
	// Reached from the UDP read loop for a rate-limited query, on the bytes as
	// they arrived and without decoding them first, so it is its own parser of
	// hostile input and gets its own turn here.
	_, _ = dns.truncated_response(data[:size])
	return 0
}
