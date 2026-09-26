package fuzz_h2conn

import "base:runtime"
import "elodin:fuzz/harness"
import "elodin:h2"

/*
The h2 frame layer and stream state machine, on both ends: the server a DoH
client talks to, and the client an h2 DoH upstream answers. `fuzz_h2` covers
HPACK alone; this is everything around it - frame headers, padding, SETTINGS,
WINDOW_UPDATE, RST_STREAM, CONTINUATION, and the stream table they move.

The first byte picks the side and the rest is what the peer sends. The server's
connection preface is supplied here rather than left for the fuzzer to find,
since a single wrong byte in it ends the connection before any frame is read.

The connection is on the heap rather than the harness's arena, which never
frees: the open bugs in this code are about streams outliving their owner, and
ASan only sees a use after free where there is a free.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	if size == 0 {
		return 0
	}
	input := Input {
		data = data[1:size],
	}
	io := h2.IO {
		user  = &input,
		read  = read_input,
		write = discard,
	}
	heap := runtime.heap_allocator()

	if data[0] & 1 == 0 {
		input.preface = h2.PREFACE
		c := h2.make_conn(io, answer, nil, heap)
		// A peer that grants no window is answered at once rather than waited on
		// for a real connection's write timeout.
		c.write_timeout = 0
		h2.serve(c)
		h2.conn_wait_idle(c)
		h2.conn_unref(c)
	} else {
		c := h2.client_make(io, heap)
		h2.client_serve(c)
		h2.client_unref(c)
	}
	return 0
}

Input :: struct {
	preface: string,
	data:    []u8,
}

read_input :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	input := (^Input)(user)
	if len(input.preface) > 0 {
		n = copy(buf, input.preface)
		input.preface = input.preface[n:]
		return n, true
	}
	if len(input.data) == 0 {
		return 0, false
	}
	n = copy(buf, input.data)
	input.data = input.data[n:]
	return n, true
}

discard :: proc(user: rawptr, buf: []u8) -> bool {
	return true
}

// Answered inline with a body, so the write path and its flow control are driven
// by whatever the input granted.
answer :: proc(c: ^h2.Conn, req: ^h2.Request) {
	body: [100]u8
	h2.respond(c, req.stream_id, h2.Response{status = 200, body = body[:]})
	h2.request_destroy(c, req)
}
