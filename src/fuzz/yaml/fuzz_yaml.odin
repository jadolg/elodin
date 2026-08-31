package fuzz_yaml

import "elodin:fuzz/harness"
import "elodin:yaml"

// yaml.parse takes a string, so the buffer is cast rather than validated —
// invalid UTF-8 is exactly the kind of input the parser needs to survive, since
// it reads the configuration file at load. Downloaded blocklists do not come
// through here: they go to `filter.parse_list`, which has no target of its own.
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	_, _ = yaml.parse(string(data[:size]))
	return 0
}
