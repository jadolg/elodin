package fuzz_h2

import "elodin:fuzz/harness"
import "elodin:h2"

// A fresh Dynamic_Table per input: HPACK indexes are only valid relative to
// the table state built up over a connection, and a table reused across
// libFuzzer iterations would make crashes depend on run order instead of on
// the input alone.
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	table: h2.Dynamic_Table
	h2.dynamic_table_init(&table, 4096)

	_, _ = h2.decode(&table, data[:size])
	return 0
}
