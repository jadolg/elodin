package fuzz_http

import "base:runtime"
import "core:mem"
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

	/*
	The reader's buffer comes from `context.temp_allocator`, whose arena never
	frees a block it outgrows, so a line held across a read that grows the buffer -
	the use after free `reader_line` warns about - reads memory that is still there
	and ASan says nothing. On the heap the outgrown block is freed; the tracker is
	how everything the exchange took is handed back afterwards. Scoped to the block
	so `teardown` sees the thread's own temp allocator again.
	*/
	{
		heap := runtime.heap_allocator()
		scratch: mem.Tracking_Allocator
		mem.tracking_allocator_init(&scratch, heap)
		defer {
			for _, e in scratch.allocation_map {
				free(e.memory, heap)
			}
			mem.tracking_allocator_destroy(&scratch)
		}
		context.temp_allocator = mem.tracking_allocator(&scratch)

		stream := upstream.Stream {
			socket = socket,
		}
		_, _ = upstream.http_exchange(&stream, upstream.Http_Request{method = "GET", path = "/", host = "fuzz"})
	}
	return 0
}
