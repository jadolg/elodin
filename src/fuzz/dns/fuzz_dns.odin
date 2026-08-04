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
	return 0
}
