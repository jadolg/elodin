package h2

import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import "elodin:loop"

/*
What a refused allocation does to a connection, client and server alike: the
frame, the stream or the connection fails, and nothing short goes on the wire or
into HPACK state. Swept with runs of refusals, not only a dry arena, since an
arena that runs dry fails every later allocation too and one check then covers
for a missing other.
*/

// Refuses `fail_for` requests from its `fail_at`th on and hands every other to
// `backing`. src/server/out_of_memory_test.odin keeps its own copy: test files
// cannot be shared across packages.
@(private)
Fail_Nth :: struct {
	backing:  mem.Allocator,
	seen:     int,
	fail_at:  int,
	fail_for: int,
}

@(private)
fail_nth :: proc(f: ^Fail_Nth) -> mem.Allocator {
	return {procedure = fail_nth_proc, data = f}
}

// Refuses `fail_for` requests from the `fail_at`th after this call on.
@(private)
arm :: proc(f: ^Fail_Nth, fail_at, fail_for: int) {
	f.seen = 0
	f.fail_at = fail_at
	f.fail_for = fail_for
}

// Whether a refusal fell inside the armed run: past it, a sweep has refused
// every allocation once.
@(private)
refused_any :: proc(f: ^Fail_Nth) -> bool {
	return f.seen >= f.fail_at
}

@(private)
fail_nth_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	f := cast(^Fail_Nth)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		f.seen += 1
		if f.seen >= f.fail_at && f.seen < f.fail_at + f.fail_for {
			return nil, .Out_Of_Memory
		}
	}
	return f.backing.procedure(f.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

// The runs of refusals each sweep is made with.
@(private)
RUNS :: [?]int{1, 2, 8}

// More allocations than any one sweep step makes, so a sweep that never gets
// past them fails rather than looping.
@(private)
MAX_SWEEP :: 64

@(private = "file")
read_with :: proc(wire: []u8, temp: mem.Allocator) -> (h: Frame_Header, payload: []u8, refuse: Maybe(Error_Code), ok: bool, unread: int) {
	w := Wire {
		bytes = wire,
	}
	context.temp_allocator = temp
	h, payload, refuse, ok = read_frame(IO{user = &w, read = wire_read}, 0)
	return h, payload, refuse, ok, len(wire) - w.pos
}

/*
A frame whose payload there is no room for is not read: reported read with an
empty payload, its bytes would be left on the wire for the next frame header to
be parsed out of. INTERNAL_ERROR, since the peer did nothing wrong (RFC 9113 7).
*/
@(test)
test_a_frame_with_no_room_for_its_payload_is_not_read :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	wire := [FRAME_HEADER_SIZE + 8]u8{0, 0, 8, u8(Frame_Type.Ping), 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}

	f := Fail_Nth {
		backing = context.temp_allocator,
	}
	h, payload, refuse, ok, unread := read_with(wire[:], fail_nth(&f))
	testing.expectf(t, ok && refuse == nil, "a PING with room for it was not read: %v", refuse)
	testing.expect_value(t, h.type, Frame_Type.Ping)
	testing.expectf(t, string(payload) == string(wire[FRAME_HEADER_SIZE:]), "payload %v", payload)
	testing.expect_value(t, unread, 0)

	arm(&f, 1, 1)
	dry_h, dry_payload, dry_refuse, dry_ok, dry_unread := read_with(wire[:], fail_nth(&f))
	testing.expectf(t, !dry_ok && dry_payload == nil, "a %v without room for its payload was read, %d bytes left", dry_h.type, dry_unread)
	code, bad := dry_refuse.?
	testing.expectf(t, bad && code == .Internal_Error, "drew %v", dry_refuse)
}

/*
Every frame this end writes, byte for byte. DATA and HEADERS are built whole or
not at all: a frame cut short would put the rest of the connection out of step.
The rest need no memory; see `test_control_frames_need_no_room`.
*/
@(test)
test_a_frame_with_no_room_is_not_built :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	ping := [8]u8{1, 2, 3, 4, 5, 6, 7, 8}
	chunk := []u8{'a', 'b', 'c'}
	settings := [?]Setting_Value{{.Enable_Push, 0}}
	rst := rst_stream_frame(5, .Cancel)
	goaway := goaway_frame(7, .Internal_Error)
	ack := ping_ack_frame(ping[:])
	settings_ack := settings_ack_frame()
	window := window_update_frame(0x10000)
	opening_buf: [len("PRI ") + 2 * FRAME_HEADER_SIZE + SETTING_SIZE * len(settings) + 4]u8
	opening := opening_frames(opening_buf[:], "PRI ", settings[:])
	// RFC 9113 4.1: length (3), type, flags, stream (4), then the payload.
	fixed := []struct {
		name:  string,
		frame: []u8,
		want:  string,
	} {
		{"RST_STREAM", rst[:], "00000403000000000500000008"},
		{"GOAWAY", goaway[:], "0000080700000000000000000700000002"},
		{"PING ACK", ack[:], "0000080601000000000102030405060708"},
		{"SETTINGS ACK", settings_ack[:], "000000040100000000"},
		{"WINDOW_UPDATE", window[:], "00000408000000000000010000"},
		// "PRI ", SETTINGS ENABLE_PUSH=0, WINDOW_UPDATE of RECV_WINDOW - DEFAULT_WINDOW.
		{"opening", opening, "50524920" + "000006040000000000" + "000200000000" + "000004080000000000" + "000f0001"},
	}
	for c in fixed {
		want := from_hex(c.want)
		testing.expectf(t, want != nil && string(c.frame) == string(want), "%s built as %x", c.name, c.frame)
	}

	for end_stream in ([]bool{true, false}) {
		f := Fail_Nth {
			backing = context.temp_allocator,
		}
		data, headers, refused_data, refused_headers: []u8
		{
			context.temp_allocator = fail_nth(&f)
			data = data_frame(1, chunk, end_stream = end_stream)
			headers = headers_frame(3, chunk, end_stream = end_stream)
			arm(&f, 1, 1)
			refused_data = data_frame(1, chunk, end_stream = end_stream)
			arm(&f, 1, 1)
			refused_headers = headers_frame(3, chunk, end_stream = end_stream)
		}
		want_data := from_hex("000003000100000001616263" if end_stream else "000003000000000001616263")
		want_headers := from_hex("000003010500000003616263" if end_stream else "000003010400000003616263")
		testing.expectf(t, string(data) == string(want_data), "DATA built as %x", data)
		testing.expectf(t, string(headers) == string(want_headers), "HEADERS built as %x", headers)
		testing.expectf(t, refused_data == nil && refused_headers == nil, "built without room: %x, %x", refused_data, refused_headers)
	}
}

/*
A CONTINUATION the open header block has no room for fails the connection: a
block decoded without it would leave HPACK out of step with the peer's encoder.
*/
@(test)
test_a_continuation_with_no_room_is_not_added :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	f := Fail_Nth {
		backing = context.temp_allocator,
	}
	block := make([dynamic]u8, 0, 0, fail_nth(&f))
	payload := []u8{0x82, 0x86}
	h := Frame_Header {
		length    = len(payload),
		type      = .Continuation,
		flags     = FLAG_END_HEADERS,
		stream_id = 1,
	}
	on := u32(1)
	frames := 0

	arm(&f, 1, 1)
	complete, refuse := continue_header_block(&on, &frames, &block, h, payload)
	code, bad := refuse.?
	testing.expectf(t, !complete && bad && code == .Internal_Error, "complete %v, drew %v", complete, refuse)
	testing.expect_value(t, len(block), 0)
	testing.expect_value(t, on, u32(1))

	complete, refuse = continue_header_block(&on, &frames, &block, h, payload)
	testing.expectf(t, complete && refuse == nil, "with room: complete %v, drew %v", complete, refuse)
	testing.expectf(t, string(block[:]) == string(payload), "block %x", block[:])
}

/*
RFC 7541 2.2 has the decoder's dynamic table follow the encoder's entry for
entry. An entry this end has no room to store fails the block, and leaves the
table as it was: stored short, it would be a different size from the peer's, and
the two tables would evict differently from then on. Swept over the name, the
value and the growth of the entry list.
*/
@(test)
test_an_entry_the_table_has_no_room_for_fails_the_block :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	// A literal with incremental indexing, new name "x-a", value "b".
	block := []u8{0x40, 3, 'x', '-', 'a', 1, 'b'}

	refusals := 0
	for run in RUNS {
		for at in 1 ..= MAX_SWEEP {
			f := Fail_Nth {
				backing = allocator,
			}
			table: Dynamic_Table
			// Built with no room for its entry list, so the add has to grow it.
			arm(&f, 1, 1)
			dynamic_table_init(&table, DEFAULT_HEADER_TABLE_SIZE, fail_nth(&f))
			testing.expect_value(t, cap(table.entries), 0)

			arm(&f, at, run)
			headers, err := decode(&table, block, context.temp_allocator)
			if refused_any(&f) {
				refusals += 1
				testing.expectf(t, err == .Out_Of_Memory, "run %d at %d: %v", run, at, err)
				// A refused name asks for nothing more.
				testing.expectf(t, at != 1 || f.seen == 1, "run %d: %d allocations after the name was refused", run, f.seen)
				testing.expectf(t, table.size == 0 && len(table.entries) == 0, "run %d at %d: table holds %d", run, at, table.size)
			} else {
				testing.expectf(t, err == .None, "with room: %v", err)
				testing.expect_value(t, table.size, len("x-a") + len("b") + 32)
				testing.expectf(t, len(headers) == 1 && headers[0].name == "x-a" && headers[0].value == "b", "decoded %v", headers)
			}
			dynamic_table_destroy(&table)
			if !refused_any(&f) {
				break
			}
		}
	}
	// The name, the value and the list's growth, in each run.
	testing.expectf(t, refusals >= 3 * len(RUNS), "%d refusals", refusals)
	expect_no_leaks(t, &track, "table entry without room")
}

/*
A header list this end has no room for is not decoded: a field cloned short
would come back as an empty name or value, and one dropped would be missing from
a list that reads as whole. Swept over a plain block and a Huffman-coded one
(RFC 7541 C.3.1 and C.4.1), into an allocator of their own.
*/
@(test)
test_a_header_list_with_no_room_is_not_decoded :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	want := []Header_Field {
		{":method", "GET"},
		{":scheme", "http"},
		{":path", "/"},
		{":authority", "www.example.com"},
	}
	for hex in ([]string{REQUEST_BLOCK, "828684418cf1e3c2e5f23a6ba0ab90f4ff"}) {
		block := from_hex(hex)
		if !testing.expectf(t, block != nil, "cannot read %s", hex) {
			return
		}
		refusals := 0
		for run in RUNS {
			for at in 1 ..= MAX_SWEEP {
				table: Dynamic_Table
				dynamic_table_init(&table, DEFAULT_HEADER_TABLE_SIZE)
				f := Fail_Nth {
					backing = context.temp_allocator,
				}
				arm(&f, at, run)
				headers, err := decode(&table, block, fail_nth(&f))
				dynamic_table_destroy(&table)
				if refused_any(&f) {
					refusals += 1
					testing.expectf(t, err == .Out_Of_Memory, "%s run %d at %d: %v", hex, run, at, err)
					continue
				}
				testing.expectf(t, err == .None, "%s with room: %v", hex, err)
				testing.expect_value(t, len(headers), len(want))
				for w, i in want {
					if i < len(headers) {
						testing.expectf(t, headers[i] == w, "%s field %d is %v", hex, i, headers[i])
					}
				}
				break
			}
		}
		testing.expectf(t, refusals >= len(want), "%s: %d refusals", hex, refusals)
	}
}

// Counts the requests a connection hands over, and those that arrived whole:
// REQUEST_BLOCK's four fields as sent.
@(private = "file")
Seen_Requests :: struct {
	dispatched: int,
	whole:      int,
}

@(private = "file")
check_request :: proc(conn: ^Conn, req: ^Request) {
	seen := cast(^Seen_Requests)conn.user
	seen.dispatched += 1
	if req.method == "GET" && req.scheme == "http" && req.path == "/" && req.authority == "www.example.com" {
		seen.whole += 1
	}
	request_destroy(conn, req)
}

// What became of a request on a connection refused memory along the way.
@(private = "file")
Outcome :: enum {
	// Served, whole.
	Served,
	// Ended with GOAWAY(INTERNAL_ERROR).
	Connection_Ended,
	// Reset with REFUSED_STREAM, the connection carrying on.
	Stream_Refused,
	// No connection: no room for the connection itself.
	Not_Made,
	// Anything else: served short, or failed some other way.
	Wrong,
}

/*
One request on a fresh connection. Each of `setup`, `heap` and `temp` is a
refusal to arm, {at, run}: the connection's allocator while it is made, then
while the request is read, and the temp arena while it is read. `end_headers`
false holds the block for a CONTINUATION that never comes, so it is served when
its block was kept whole. `refused` is whether the `heap` or `temp` run refused
anything.
*/
@(private = "file")
serve_one :: proc(
	t: ^testing.T,
	allocator: mem.Allocator,
	setup: [2]int,
	heap: [2]int,
	temp: [2]int,
	end_headers := true,
) -> (
	outcome: Outcome,
	refused: bool,
) {
	block := request_block()
	hf := Fail_Nth {
		backing = allocator,
	}
	tf := Fail_Nth {
		backing = context.temp_allocator,
	}
	log: Frame_Log
	log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	defer delete(log.frames)
	seen: Seen_Requests

	arm(&hf, setup[0], setup[1])
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, check_request, &seen, fail_nth(&hf))
	if c == nil {
		return .Not_Made, false
	}
	defer conn_unref(c)
	clear(&log.frames)

	arm(&hf, heap[0], heap[1])
	arm(&tf, temp[0], temp[1])
	flags := u8(FLAG_END_STREAM) | (u8(FLAG_END_HEADERS) if end_headers else 0)
	ok: bool
	{
		context.temp_allocator = fail_nth(&tf)
		ok = handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = flags, stream_id = 1}, block)
	}
	refused = heap[1] > 0 && refused_any(&hf) || temp[1] > 0 && refused_any(&tf)
	_, open := c.streams[1]
	switch {
	// Or with nothing written, where the GOAWAY or RST_STREAM had no room either.
	// Stream 1 was never acted on, so the GOAWAY leaves the client free to
	// retry it (RFC 9113 6.8).
	case !ok && seen.dispatched == 0 && (log.goaway_code == .Internal_Error && log.goaway_last == 0 || len(log.frames) == 0):
		return .Connection_Ended, refused
	case ok && log.rst_code == .Refused_Stream && !open && seen.dispatched == 0:
		return .Stream_Refused, refused
	case ok && end_headers && seen.dispatched == 1 && seen.whole == 1:
		return .Served, refused
	case ok && !end_headers && open && string(c.header_block[:]) == string(block):
		return .Served, refused
	}
	testing.expectf(t, false, "ok %v, GOAWAY %v, RST %v, open %v, %d dispatched, %d whole", ok, log.goaway_code, log.rst_code, open, seen.dispatched, seen.whole)
	return .Wrong, refused
}

/*
A request the server has no room for is refused, never served short: its stream
or its HPACK state is the connection's (GOAWAY(INTERNAL_ERROR)), its fields are
the stream's (REFUSED_STREAM, which RFC 9113 8.7 lets the client retry). Swept
over the connection's allocator - with the connection itself built short of its
stream table, so opening a stream has to grow it - and over the temp arena the
header list is decoded into.
*/
@(test)
test_a_request_without_room_is_refused_not_served_short :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)

	counts: [Outcome]int
	for end_headers in ([]bool{true, false}) {
		// Nothing refused, then the connection's own allocations one at a time.
		for setup_at in 0 ..= 4 {
			setup := [2]int{setup_at, 1 if setup_at > 0 else 0}
			for run in RUNS {
				for at in 1 ..= MAX_SWEEP {
					outcome, refused := serve_one(t, allocator, setup, {at, run}, {}, end_headers = end_headers)
					counts[outcome] += 1
					if outcome == .Not_Made {
						// The connection's first allocation is itself.
						testing.expect_value(t, setup_at, 1)
						break
					}
					if !refused {
						testing.expectf(t, outcome == .Served, "with room: %v", outcome)
						break
					}
				}
			}
		}
		for run in RUNS {
			for at in 1 ..= MAX_SWEEP {
				outcome, refused := serve_one(t, allocator, {}, {}, {at, run}, end_headers = end_headers)
				counts[outcome] += 1
				if !refused {
					testing.expectf(t, outcome == .Served, "with room: %v", outcome)
					break
				}
			}
		}
	}
	testing.expectf(t, counts[.Wrong] == 0, "%v", counts)
	testing.expectf(t, counts[.Connection_Ended] > 0 && counts[.Stream_Refused] > 0 && counts[.Not_Made] > 0, "%v", counts)
	expect_no_leaks(t, &track, "request without room")
}

/*
A request body there is no room for is refused as one over the connection's
budget is: REFUSED_STREAM, the stream retired, its connection credit returned
(RFC 9113 6.9.1), and the connection carrying on.
*/
@(test)
test_a_request_body_without_room_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	block := request_block()
	body := make([]u8, CREDIT_BATCH, context.temp_allocator)

	for refuse in ([]bool{false, true}) {
		f := Fail_Nth {
			backing = allocator,
		}
		log: Frame_Log
		log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
		seen: Seen_Requests
		c := make_conn(IO{user = &log, read = no_read, write = log_write}, check_request, &seen, fail_nth(&f))
		if !testing.expect(t, c != nil, "cannot make the connection") {
			delete(log.frames)
			return
		}
		headers_ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)
		testing.expect(t, headers_ok, "the request's headers were refused")
		if refuse {
			arm(&f, 1, 1)
		}
		ok := handle_data(c, Frame_Header{length = len(body), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, body)
		testing.expectf(t, ok, "refuse %v: the connection ended", refuse)
		_, open := c.streams[1]
		if refuse {
			testing.expect_value(t, log.rst_code, Error_Code.Refused_Stream)
			testing.expect(t, !open, "the refused stream is still held")
			testing.expect_value(t, seen.dispatched, 0)
			testing.expect_value(t, c.request_bytes, 0)
		} else {
			testing.expect_value(t, seen.whole, 1)
			testing.expect(t, !saw_frame(&log, .Rst_Stream), "a body with room was reset")
		}
		testing.expect_value(t, log.credit, CREDIT_BATCH)
		conn_unref(c)
		delete(log.frames)
	}
	expect_no_leaks(t, &track, "request body without room")
}

// Takes the request and answers nothing, leaving its stream for the test to.
@(private = "file")
drop_request :: proc(conn: ^Conn, req: ^Request) {
	request_destroy(conn, req)
}

// The frames a response wrote, in order.
@(private = "file")
written_frames :: proc(h: ^Serve_Harness) -> (frames: [dynamic]Frame_Header, ok: bool) {
	frames = make([dynamic]Frame_Header, 0, 4, context.allocator)
	pos := 0
	for pos < len(h.written) {
		fh := parse_frame_header(h.written[pos:]) or_return
		if pos + FRAME_HEADER_SIZE + fh.length > len(h.written) {
			return
		}
		append(&frames, fh)
		pos += FRAME_HEADER_SIZE + fh.length
	}
	return frames, true
}

/*
A response this end has no room to build is reset with INTERNAL_ERROR rather
than cut short (RFC 9113 7): whatever it wrote is whole frames, the ones it
would have written with room, and a response that stops early ends with that
reset. Swept over the temp arena the frames are built in.
*/
@(test)
test_a_response_without_room_is_reset_not_cut_short :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	block := request_block()
	body := make([]u8, 2 * DEFAULT_MAX_FRAME, context.temp_allocator)
	resp := Response {
		status       = 200,
		content_type = "application/dns-message",
		body         = body,
	}

	reference: [dynamic]Frame_Header
	defer delete(reference)
	resets := 0
	for run in RUNS {
		for at in 0 ..= MAX_SWEEP {
			h := Serve_Harness {
				written = make([dynamic]u8, 0, 64, allocator),
			}
			c := make_conn(IO{user = &h, read = no_read, write = serve_harness_write}, drop_request, nil, allocator)
			if !testing.expect(t, c != nil, "cannot make the connection") {
				delete(h.written)
				return
			}
			opened := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, block)
			if !testing.expect(t, opened, "cannot open the stream") {
				conn_unref(c)
				delete(h.written)
				return
			}
			clear(&h.written)
			f := Fail_Nth {
				backing = context.temp_allocator,
			}
			arm(&f, at, run if at > 0 else 0)
			sent: bool
			{
				context.temp_allocator = fail_nth(&f)
				sent = respond(c, 1, resp)
			}
			frames, parsed := written_frames(&h)
			testing.expectf(t, parsed, "run %d at %d: a frame was cut short", run, at)
			// Only DATA written spends the window (RFC 9113 6.9.1).
			spent := 0
			for fh in frames {
				spent += fh.length if fh.type == .Data else 0
			}
			testing.expectf(t, c.send_window == DEFAULT_WINDOW - spent, "run %d at %d: window %d after %d bytes of DATA", run, at, c.send_window, spent)
			if at == 0 {
				testing.expect(t, sent, "a response with room was not sent")
				if len(reference) == 0 {
					append(&reference, ..frames[:])
				}
			} else if refused_any(&f) {
				testing.expectf(t, !sent, "run %d at %d: reported sent", run, at)
				n := len(frames)
				reset := n > 0 && frames[n - 1].type == .Rst_Stream
				if reset {
					resets += 1
					n -= 1
					// The last frame, so its code ends what was written.
					code := Error_Code(read_u32(h.written[len(h.written) - 4:]))
					testing.expectf(t, code == .Internal_Error, "run %d at %d: reset with %v", run, at, code)
				}
				// A single refusal leaves room for the reset.
				testing.expectf(t, reset || run > 1, "run %d at %d: stopped without a reset", run, at)
				testing.expectf(t, n < len(reference), "run %d at %d: %d frames of %d and refused", run, at, n, len(reference))
				for i in 0 ..< min(n, len(reference)) {
					testing.expectf(t, frames[i] == reference[i], "run %d at %d: frame %d is %v, not %v", run, at, i, frames[i], reference[i])
				}
			}
			delete(frames)
			conn_unref(c)
			delete(h.written)
			if at > 0 && !refused_any(&f) {
				break
			}
		}
	}
	// HEADERS and two DATA frames, so a reset after none, one and two of them.
	testing.expectf(t, len(reference) == 3, "%v", reference)
	testing.expectf(t, resets >= 3, "%d resets", resets)
	expect_no_leaks(t, &track, "response without room")
}

// A client with no room for itself is not made. Its preface needs no memory;
// see `test_control_frames_need_no_room`.
@(test)
test_a_client_without_room_is_not_made :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	log: Frame_Log
	log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	io := IO {
		user  = &log,
		read  = no_read,
		write = log_write,
	}
	f := Fail_Nth {
		backing = allocator,
	}
	arm(&f, 1, 1)
	testing.expect(t, client_make(io, fail_nth(&f)) == nil, "a client with no room for itself was made")
	testing.expect_value(t, len(log.frames), 0)

	c := client_make(io, fail_nth(&f))
	if !testing.expect(t, c != nil, "a client with room was not made") {
		delete(log.frames)
		return
	}
	testing.expect(t, !client_closed(c), "a client with room is closed")
	testing.expect(t, saw_frame(&log, .Settings), "no SETTINGS")
	client_unref(c)
	delete(log.frames)
	expect_no_leaks(t, &track, "client without room")
}

/*
A response the client has no room for fails as this end's, never as a short
answer: the connection ends with GOAWAY(INTERNAL_ERROR) where its header block
or HPACK state could not be kept, and the stream with RST_STREAM(INTERNAL_ERROR)
where its body could not, the connection carrying on. Either way it is marked
`dry`, which `client_request` reports as `Out_Of_Memory`. Swept over the
client's allocator, with the client built short of its header scratch so the
block has to grow it, and over the temp arena.
*/
@(test)
test_a_response_without_room_fails_as_this_ends :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)

	// :status 200, and a literal with incremental indexing for the table to keep.
	block := []u8{0x88, 0x40, 3, 'x', '-', 'a', 1, 'b'}
	// Past the stream's buffer, so the body has to grow it.
	body := make([]u8, 64, context.temp_allocator)
	for &b, i in body {
		b = u8(i)
	}
	refusals: [2]int
	for sweep_temp in ([]bool{false, true}) {
		for run in RUNS {
			for at in 1 ..= MAX_SWEEP {
				hf := Fail_Nth {
					backing = allocator,
				}
				tf := Fail_Nth {
					backing = context.temp_allocator,
				}
				log: Frame_Log
				log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
				// The header scratch is the client's third allocation.
				arm(&hf, 3, 1)
				c := client_make(IO{user = &log, read = no_read, write = log_write}, fail_nth(&hf))
				if !testing.expect(t, c != nil && cap(c.header_scratch) == 0, "cannot make a client short of its scratch") {
					delete(log.frames)
					return
				}
				clear(&log.frames)
				s := open_test_stream(c, 1, allocator)
				// The stream's body grows into the client's allocator.
				delete(s.body)
				s.body = make([dynamic]u8, 0, 0, fail_nth(&hf))

				arm(&hf, 0, 0)
				arm(&tf, 0, 0)
				if sweep_temp {
					arm(&tf, at, run)
				} else {
					arm(&hf, at, run)
				}
				headers_ok, data_ok: bool
				{
					context.temp_allocator = fail_nth(&tf)
					headers_ok = client_handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)
					if headers_ok {
						data_ok = client_handle_data(c, Frame_Header{length = len(body), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, body)
					}
				}
				refused := refused_any(&tf) if sweep_temp else refused_any(&hf)
				switch {
				// Or with nothing written, where the GOAWAY had no room either.
				case !headers_ok:
					testing.expectf(t, c.dry && (log.goaway_code == .Internal_Error || len(log.frames) == 0), "run %d at %d: GOAWAY %v, dry %v", run, at, log.goaway_code, c.dry)
				case !s.done:
					testing.expectf(t, data_ok && s.reset && s.dry, "run %d at %d: ok %v, reset %v, dry %v", run, at, data_ok, s.reset, s.dry)
					testing.expectf(t, log.rst_code == .Internal_Error || sweep_temp, "run %d at %d: RST %v", run, at, log.rst_code)
				case:
					testing.expectf(t, s.status == 200 && string(s.body[:]) == string(body) && !s.dry && !c.dry, "run %d at %d: status %d, %d body bytes", run, at, s.status, len(s.body))
				}
				if refused {
					testing.expectf(t, !headers_ok || !s.done, "run %d at %d: refused, and answered all the same", run, at)
					refusals[int(sweep_temp)] += 1
				}
				client_stream_destroy(c, s)
				delete_key(&c.streams, u32(1))
				client_unref(c)
				delete(log.frames)
				if !refused {
					break
				}
			}
		}
	}
	testing.expectf(t, refusals[0] > 0 && refusals[1] > 0, "%v refusals", refusals)
	expect_no_leaks(t, &track, "response without room")
}

/*
A Frame_Log that also counts HEADERS written for a stream `c` is not tracking,
whose answer the reader would have nowhere to put. Written under `c.mu`, which
`client_request` holds across its HEADERS write.
*/
@(private = "file")
Tracked_Log :: struct {
	log:       Frame_Log,
	c:         ^Client,
	untracked: int,
}

@(private = "file")
tracked_write :: proc(user: rawptr, buf: []u8) -> bool {
	w := cast(^Tracked_Log)user
	if h, ok := parse_frame_header(buf); ok && h.type == .Headers && w.c != nil {
		if _, found := w.c.streams[h.stream_id]; !found {
			w.untracked += 1
		}
	}
	return log_write(&w.log, buf)
}

/*
A request the client has no room for is `Out_Of_Memory`, and nothing short of it
goes out: HEADERS whole or not at all, and a body cut off by a DATA frame not
built is reset with INTERNAL_ERROR rather than left for the peer to wait on.
Timed out at once with room, so the frames a whole request writes are known.
Swept over the temp arena and the client's allocator, with the client built
short of its stream table so opening a stream has to grow it.
*/
@(test)
test_a_request_without_room_is_not_sent_short :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	body := make([]u8, 2 * DEFAULT_MAX_FRAME, context.temp_allocator)
	req := Client_Request {
		method       = "POST",
		scheme       = "https",
		authority    = "mock.invalid",
		path         = "/dns-query",
		content_type = "application/dns-message",
		body         = body,
	}

	reference: [dynamic]Frame_Header
	defer delete(reference)
	refusals := [2]int{}
	for sweep_temp in ([]bool{false, true}) {
		for run in RUNS {
			for at in 0 ..= MAX_SWEEP {
				hf := Fail_Nth {
					backing = allocator,
				}
				tf := Fail_Nth {
					backing = context.temp_allocator,
				}
				w: Tracked_Log
				log := &w.log
				log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
				// The stream table is the client's second allocation.
				arm(&hf, 2, 1)
				c := client_make(IO{user = &w, read = no_read, write = tracked_write}, fail_nth(&hf))
				if !testing.expect(t, c != nil, "cannot make the client") {
					delete(log.frames)
					return
				}
				w.c = c
				clear(&log.frames)
				arm(&hf, 0, 0)
				if at > 0 {
					arm(&tf if sweep_temp else &hf, at, run)
				}
				err: Client_Error
				{
					context.temp_allocator = fail_nth(&tf)
					_, err = client_request(c, req, 0, allocator)
				}
				refused := at > 0 && (refused_any(&tf) if sweep_temp else refused_any(&hf))
				n := len(log.frames)
				if at == 0 {
					testing.expect_value(t, err, Client_Error.Timeout)
					if len(reference) == 0 {
						append(&reference, ..log.frames[:])
					}
				} else if refused {
					refusals[int(sweep_temp)] += 1
					testing.expectf(t, err == .Out_Of_Memory || err == .Timeout, "run %d at %d: %v", run, at, err)
					if n > 0 && log.frames[n - 1].type == .Rst_Stream {
						n -= 1
						testing.expectf(t, log.rst_code == .Internal_Error || err == .Timeout, "run %d at %d: RST %v", run, at, log.rst_code)
					}
					// A refusal the request could do without times out whole, as with
					// room; one it could not is this end's, and cuts it short.
					if err == .Out_Of_Memory {
						testing.expectf(t, n < len(reference) - 1, "run %d at %d: %d frames, and refused", run, at, n)
					} else {
						testing.expectf(t, n == len(reference) - 1, "run %d at %d: %d frames, timed out", run, at, n)
					}
				}
				for i in 0 ..< min(n, len(reference)) {
					testing.expectf(t, log.frames[i] == reference[i], "run %d at %d: frame %d is %v, not %v", run, at, i, log.frames[i], reference[i])
				}
				testing.expectf(t, w.untracked == 0, "run %d at %d: %d HEADERS for a stream the client does not track", run, at, w.untracked)
				// Only DATA written spends the window (RFC 9113 6.9.1).
				spent := 0
				for fh in log.frames {
					spent += fh.length if fh.type == .Data else 0
				}
				testing.expectf(t, c.send_window == DEFAULT_WINDOW - spent, "run %d at %d: window %d after %d bytes of DATA", run, at, c.send_window, spent)
				client_unref(c)
				delete(log.frames)
				if at > 0 && !refused {
					break
				}
			}
		}
	}
	// HEADERS, two DATA frames, and the timeout's RST_STREAM(CANCEL).
	testing.expectf(t, len(reference) == 4, "%v", reference)
	testing.expectf(t, refusals[0] > 0 && refusals[1] > 0, "%v refusals", refusals)
	expect_no_leaks(t, &track, "request without room")
}

/*
HPACK state this end could not keep ends the connection as this end's failing,
INTERNAL_ERROR, on both ends; a block the peer got wrong is still its
COMPRESSION_ERROR (RFC 9113 4.3).
*/
@(test)
test_hpack_state_without_room_ends_the_connection_as_this_ends :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	// A literal with incremental indexing, new name "x-a", value "b".
	good := []u8{0x88, 0x40, 3, 'x', '-', 'a', 1, 'b'}
	// Index 70: nothing in the dynamic table yet.
	bad := []u8{0xc6}
	for c in ([]struct {
			block: []u8,
			dry:   bool,
			want:  Error_Code,
		}{{good, true, .Internal_Error}, {bad, false, .Compression_Error}}) {
		f := Fail_Nth {
			backing = allocator,
		}
		if c.dry {
			arm(&f, 1, 1)
		}
		h := Frame_Header {
			length    = len(c.block),
			type      = .Headers,
			flags     = FLAG_END_HEADERS | FLAG_END_STREAM,
			stream_id = 1,
		}

		slog: Frame_Log
		sc := logged_conn(&slog, drop_request, allocator)
		sc.decoder.allocator = fail_nth(&f)
		testing.expectf(t, !handle_headers(sc, h, c.block), "server: %v kept the connection", c.want)
		testing.expect_value(t, slog.goaway_code, c.want)
		// A request this end had no room to decode was not acted on, and may be
		// retried (RFC 9113 6.8); one the peer got wrong is its own.
		testing.expect_value(t, slog.goaway_last, u32(0) if c.dry else 1)
		sc.decoder.allocator = allocator
		conn_done(t, sc, &track, "server HPACK", &slog)

		if c.dry {
			arm(&f, 1, 1)
		}
		clog: Frame_Log
		cc := logged_client(&clog, allocator)
		s := open_test_stream(cc, 1, allocator)
		cc.decoder.allocator = fail_nth(&f)
		testing.expectf(t, !client_handle_headers(cc, h, c.block), "client: %v kept the connection", c.want)
		testing.expect_value(t, clog.goaway_code, c.want)
		testing.expect_value(t, cc.dry, c.dry)
		cc.decoder.allocator = allocator
		client_stream_destroy(cc, s)
		delete_key(&cc.streams, u32(1))
		client_done(t, cc, &track, "client HPACK", &clog)
	}
}

/*
The frames that keep a connection going - its opening SETTINGS, the ACKs, the
connection WINDOW_UPDATE, RST_STREAM and GOAWAY - need no memory, client and
server alike: they are what tells the peer a stream or connection is over, so
one that could not be built would leave the peer waiting, short of window for
good (RFC 9113 6.9.1), or seeing the connection end with no reason given.
*/
@(test)
test_control_frames_need_no_room :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	ping := [8]u8{1, 2, 3, 4, 5, 6, 7, 8}
	f := Fail_Nth {
		backing  = context.temp_allocator,
		fail_at  = 1,
		fail_for = max(int) / 2,
	}
	slog, clog: Frame_Log
	slog.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	clog.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	sc := make_conn(IO{user = &slog, read = no_read, write = log_write}, drop_request, nil, allocator)
	cc: ^Client
	server_ok, client_ok: [5]bool
	{
		context.temp_allocator = fail_nth(&f)
		server_ok = {
			send_initial_settings(sc),
			handle_frame(sc, Frame_Header{length = 8, type = .Ping}, ping[:]),
			handle_frame(sc, Frame_Header{type = .Settings}, nil),
			give_connection_credit(sc, CREDIT_BATCH),
			rst_stream(sc, 1, .Internal_Error),
		}
		goaway(sc, .Internal_Error)
		cc = client_make(IO{user = &clog, read = no_read, write = log_write}, allocator)
		clog.credit = 0
		client_ok = {
			!client_closed(cc),
			client_handle_frame(cc, Frame_Header{length = 8, type = .Ping}, ping[:]),
			client_handle_frame(cc, Frame_Header{type = .Settings}, nil),
			client_give_connection_credit(cc, CREDIT_BATCH),
			client_rst_stream(cc, 1, .Internal_Error),
		}
		client_goaway(cc, .Internal_Error)
	}
	// Not refused and recovered from: never asked for.
	testing.expectf(t, f.seen == 0, "%d allocations asked for", f.seen)
	testing.expectf(t, server_ok == {true, true, true, true, true}, "server: %v", server_ok)
	testing.expectf(t, client_ok == {true, true, true, true, true}, "client: %v", client_ok)
	for log, i in ([]^Frame_Log{&slog, &clog}) {
		end := "server" if i == 0 else "client"
		testing.expectf(t, count_frames(log, .Settings) == 2, "%s: %d SETTINGS", end, count_frames(log, .Settings))
		testing.expectf(t, saw_frame(log, .Ping), "%s: no PING ACK", end)
		testing.expectf(t, count_frames(log, .Window_Update) == 2, "%s: %d WINDOW_UPDATE", end, count_frames(log, .Window_Update))
		testing.expectf(t, log.credit == (RECV_WINDOW - DEFAULT_WINDOW) + CREDIT_BATCH || i == 1, "%s: credit %d", end, log.credit)
		testing.expectf(t, log.rst_code == .Internal_Error && log.goaway_code == .Internal_Error, "%s: RST %v, GOAWAY %v", end, log.rst_code, log.goaway_code)
	}
	testing.expect_value(t, clog.credit, CREDIT_BATCH)
	delete(clog.frames)
	client_unref(cc)
	conn_done(t, sc, &track, "control frames", &slog)
}

/*
A CONTINUATION the server has no room to add ends the connection with
GOAWAY(INTERNAL_ERROR), and leaves the request it was continuing free to retry
(RFC 9113 6.8): nothing acted on it, though a stream the handler was given
before it is named. With room, the block completes and the request is served.
*/
@(test)
test_a_header_block_continued_without_room_can_be_retried :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	block := request_block()
	half := len(block) / 2
	for refuse in ([]bool{false, true}) {
		f := Fail_Nth {
			backing = allocator,
		}
		log: Frame_Log
		log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
		seen: Seen_Requests
		c := make_conn(IO{user = &log, read = no_read, write = log_write}, check_request, &seen, fail_nth(&f))
		if !testing.expect(t, c != nil, "cannot make the connection") {
			delete(log.frames)
			return
		}
		served := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, block)
		testing.expect(t, served && seen.whole == 1, "the first request was not served")
		opened := handle_headers(c, Frame_Header{length = half, type = .Headers, flags = FLAG_END_STREAM, stream_id = 3}, block[:half])
		testing.expect(t, opened, "the block was not opened")
		if refuse {
			// The held block grows to take the rest.
			arm(&f, 1, 1)
		}
		rest := block[half:]
		ok := handle_continuation(c, Frame_Header{length = len(rest), type = .Continuation, flags = FLAG_END_HEADERS, stream_id = 3}, rest)
		if refuse {
			testing.expect(t, !ok && refused_any(&f), "a CONTINUATION without room was added")
			testing.expect_value(t, log.goaway_code, Error_Code.Internal_Error)
			testing.expect_value(t, log.goaway_last, u32(1))
		} else {
			testing.expect(t, ok, "a CONTINUATION with room was refused")
			testing.expect_value(t, seen.whole, 2)
		}
		conn_unref(c)
		delete(log.frames)
	}
	expect_no_leaks(t, &track, "continuation without room")
}

/*
A frame the server has no room to read ends the connection with
GOAWAY(INTERNAL_ERROR) and leaves the request it belonged to free to retry
(RFC 9113 6.8): here a CONTINUATION, whose payload `read_frame` is the first to
need room for, so the refusal lands before the block it would continue. Swept
over the temp arena `serve` reads frames into.
*/
@(test)
test_a_frame_the_server_has_no_room_to_read_leaves_its_request_retryable :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	block := request_block()
	half := len(block) / 2
	// Not in the temp arena, which `serve` frees after every frame.
	input := make([dynamic]u8, 0, 128, allocator)
	// The preface ends with the client's SETTINGS (RFC 9113 3.4).
	append(&input, PREFACE)
	write_frame_header(&input, 0, .Settings, 0, 0)
	write_frame_header(&input, half, .Headers, FLAG_END_STREAM, 1)
	append(&input, ..block[:half])
	write_frame_header(&input, len(block) - half, .Continuation, FLAG_END_HEADERS, 1)
	append(&input, ..block[half:])

	ended := 0
	for run in RUNS {
		for at in 1 ..= MAX_SWEEP {
			h := Serve_Harness {
				in_data = input[:],
				written = make([dynamic]u8, 0, 64, allocator),
			}
			seen: Seen_Requests
			c := make_conn(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, check_request, &seen, allocator)
			if !testing.expect(t, c != nil, "cannot make the connection") {
				delete(h.written)
				delete(input)
				return
			}
			f := Fail_Nth {
				backing = context.temp_allocator,
			}
			arm(&f, at, run)
			{
				context.temp_allocator = fail_nth(&f)
				serve(c)
			}
			refused := refused_any(&f)
			conn_unref(c)
			delete(h.written)
			if !refused {
				testing.expectf(t, seen.whole == 1, "with room: %d served, GOAWAY %v %v, %d allocations", seen.whole, h.saw_goaway, h.code, f.seen)
				break
			}
			if h.saw_goaway && h.code == .Internal_Error {
				ended += 1
				testing.expectf(t, h.last == 0, "run %d at %d: GOAWAY names stream %d, which nothing acted on", run, at, h.last)
			}
			testing.expect_value(t, seen.dispatched, 0)
		}
	}
	testing.expectf(t, ended > 0, "no refusal ended the connection")
	delete(input)
	expect_no_leaks(t, &track, "frame without room to read")
}

// A fragment the block has no room for leaves none of it behind, though the
// block had spare room for part of it.
@(test)
test_a_fragment_without_room_leaves_no_part_of_it :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	f := Fail_Nth {
		backing = context.temp_allocator,
	}
	block := make([dynamic]u8, 0, 4, fail_nth(&f))
	append(&block, 1, 2)
	arm(&f, 1, 1)
	testing.expect(t, !append_whole(&block, []u8{3, 4, 5, 6, 7, 8}), "a fragment without room was taken")
	testing.expectf(t, string(block[:]) == "\x01\x02", "block holds %v", block[:])
	testing.expect(t, append_whole(&block, []u8{3, 4, 5, 6, 7, 8}), "a fragment with room was refused")
	testing.expectf(t, string(block[:]) == "\x01\x02\x03\x04\x05\x06\x07\x08", "block holds %v", block[:])
}

@(private = "file")
Gated_Response :: struct {
	c:         ^Conn,
	stream_id: u32,
	gate:      ^Gate,
	sent:      bool,
}

@(private = "file")
run_gated_response :: proc(r: ^Gated_Response) {
	// Assigned outside any block, which would undo it at its end.
	if r.gate != nil {
		r.gate.backing = context.temp_allocator
	}
	context.temp_allocator = mem.Allocator{procedure = gate_proc, data = r.gate} if r.gate != nil else context.temp_allocator
	body := [3]u8{1, 2, 3}
	r.sent = respond(r.c, r.stream_id, Response{status = 200, body = body[:]})
	free_all(context.temp_allocator)
}

/*
Connection credit a response took for a DATA frame it had no room to build goes
back, and the responses waiting for credit are woken to it, whether or not the
stream is still there to reset: left parked, one would wait out its write
timeout beside credit it could use.
*/
@(test)
test_credit_a_response_had_no_room_to_send_wakes_the_next :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	defer free_all(context.temp_allocator)
	sig: Frame_Signal
	c := make_conn(IO{user = &sig, read = no_read, write = signal_write}, drop_request, nil, allocator)
	if !testing.expect(t, c != nil, "cannot make the connection") {
		return
	}
	block := request_block()
	for id in ([]u32{1, 3}) {
		opened := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = id}, block)
		testing.expectf(t, opened, "stream %d was not opened", id)
	}
	// Room on the connection for one three-byte body.
	c.send_window = 3

	// The first response's third temp allocation is its DATA frame: the header
	// block and the HEADERS frame come before it.
	gate := Gate {
		block_at = 3,
	}
	first := Gated_Response {
		c         = c,
		stream_id = 1,
		gate      = &gate,
	}
	ft := thread.create_and_start_with_poly_data(&first, run_gated_response)
	if !testing.expect(t, ft != nil && sync.sema_wait_with_timeout(&gate.reached, 5 * time.Second), "the first response never built its DATA frame") {
		sync.sema_post(&gate.release)
		if ft != nil {
			thread.join(ft)
			thread.destroy(ft)
		}
		conn_unref(c)
		return
	}
	// The peer resets it meanwhile, so nothing is left to reset.
	close_stream(c, 1)
	second := Gated_Response {
		c         = c,
		stream_id = 3,
	}
	st := thread.create_and_start_with_poly_data(&second, run_gated_response)
	waiting := st != nil && wait_for_waiter(&c.cond)
	testing.expect(t, waiting, "the second response is not waiting for credit")
	sync.sema_post(&gate.release)

	// Well inside the write timeout.
	sent := waiting && sync.sema_wait_with_timeout(&sig.data, 2 * time.Second)
	testing.expect(t, sent, "the second response never sent its body")
	if !sent {
		// Ends the second response's wait.
		loop.lock(&c.mu)
		c.closed = true
		loop.cond_broadcast(&c.cond)
		loop.unlock(&c.mu)
	}
	thread.join(ft)
	thread.destroy(ft)
	if st != nil {
		thread.join(st)
		thread.destroy(st)
	}
	testing.expect(t, !first.sent, "the first response was reported sent")
	testing.expect_value(t, c.send_window, 0)
	conn_unref(c)
	expect_no_leaks(t, &track, "response credit passed on")
}
