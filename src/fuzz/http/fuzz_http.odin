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

Read twice: with the list fetcher's body limit, which no input reaches, and with
one at half the input, so each framing's refusal at `max_body` - the limit a
DoH reply is held to (#525) - is reached as well as its success. The two reads
also take the body the two ways callers do: handed over, and copied out.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	for max_body in ([]int{upstream.MAX_HTTP_BODY, int(size) / 2}) {
		exchange(data[:size], max_body)
	}
	return 0
}

@(private = "file")
exchange :: proc(data: []u8, max_body: int) {
	socket, peer, ok := harness.feed(data)
	if !ok {
		return
	}
	defer harness.unfeed(socket, peer)

	/*
	Scratch goes to the heap through a tracker: its arena never frees a block it
	outgrows, so a use after free of anything read through it would read memory
	that is still there and ASan would say nothing. The tracker is how it is all
	handed back afterwards. The reader's own buffer comes from `context.allocator`,
	which `setup` makes an arena and which would hide the same mistakes, so here it
	is the untracked heap: ASan sees a line held across a read that grows the
	buffer, and LeakSanitizer a buffer the exchange forgets to free. Scoped to the
	block so `teardown` sees the thread's own allocators again.
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
		context.allocator = heap

		stream := upstream.Stream {
			socket = socket,
		}
		/*
		At the list limit the body is in the reader's own allocator, as a list's
		is, so `reader_take` hands the buffer over and LeakSanitizer sees a body
		that still owns it; at the DoH limit it is in scratch, as a DoH reply's
		per-request allocator is, so it is copied out. Either way `read_chunked`
		grows it chunk by chunk and deletes it on every error.
		*/
		body_allocator := heap if max_body == upstream.MAX_HTTP_BODY else context.temp_allocator
		resp, _ := upstream.http_exchange(
			&stream,
			upstream.Http_Request{method = "GET", path = "/", host = "fuzz"},
			body_allocator,
			max_body = max_body,
		)
		if body_allocator == heap {
			delete(resp.body, heap)
		}
	}
}

// libFuzzer's start-up hook: see `harness.check_max_len`.
@(export, link_name = "LLVMFuzzerInitialize")
fuzz_init :: proc "c" (argc: ^i32, argv: ^[^]cstring) -> i32 {
	context = runtime.default_context()
	harness.check_max_len(argv^[:argc^])
	return 0
}
