package fuzz_doh

import "base:runtime"
import "elodin:fuzz/harness"
import "elodin:server"

/*
The HTTP/1.1 request parser every DoH client writes into: the request line, the
header loop with its refused framings, Content-Length, and the body, over as many
pipelined requests as the input holds. The input is what the client sent before
closing.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	socket, peer, ok := harness.feed(data[:size])
	if !ok {
		return 0
	}
	defer harness.unfeed(socket, peer)

	// The reader's buffer on the heap, as it is in `serve_doh`, rather than the
	// harness's arena, which never frees: a view into it held across a read that
	// grows it, or a compaction that shrinks it, is a use after free ASan can only
	// see where there is a free. The wrapper deletes the buffer itself.
	context.allocator = runtime.heap_allocator()
	server.fuzz_http_requests(server.Conn{socket = socket})
	return 0
}

// libFuzzer's start-up hook: see `harness.check_max_len`.
@(export, link_name = "LLVMFuzzerInitialize")
fuzz_init :: proc "c" (argc: ^i32, argv: ^[^]cstring) -> i32 {
	context = runtime.default_context()
	harness.check_max_len(argv^[:argc^])
	return 0
}
