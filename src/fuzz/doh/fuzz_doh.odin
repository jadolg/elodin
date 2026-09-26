package fuzz_doh

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

	server.fuzz_http_requests(server.Conn{socket = socket})
	return 0
}
