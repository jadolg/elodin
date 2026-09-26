package fuzz_http

import "elodin:fuzz/harness"
import "elodin:upstream"

/*
The HTTP/1.1 response reader, which every blocklist host and every DoH upstream
without h2 writes into: the status line, the header loop, and the chunked,
Content-Length and read-to-close bodies. The input is the whole response as the
server sent it, followed by its close.
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

	stream := upstream.Stream {
		socket = socket,
	}
	_, _ = upstream.http_exchange(&stream, upstream.Http_Request{method = "GET", path = "/", host = "fuzz"})
	return 0
}
