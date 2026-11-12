package h2

import "core:testing"

// Bytes for `read_frame` to read, as the wire would hand them over.
@(private = "file")
Wire :: struct {
	bytes: []u8,
	pos:   int,
}

@(private = "file")
wire_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	w := cast(^Wire)user
	n = copy(buf, w.bytes[w.pos:])
	w.pos += n
	return n, n > 0
}

@(private = "file")
frame_bytes :: proc(type: Frame_Type, flags: u8, stream_id: u32, payload: []u8) -> []u8 {
	out := make([dynamic]u8, 0, FRAME_HEADER_SIZE + len(payload), context.temp_allocator)
	write_frame_header(&out, len(payload), type, flags, stream_id)
	append(&out, ..payload)
	return out[:]
}

/*
RFC 9113 6.10: a header block left open by HEADERS without END_HEADERS takes
nothing but CONTINUATION frames on its own stream, a connection error of type
PROTOCOL_ERROR otherwise. Checked as the frame is read, for client and server
alike, so any frame type is turned away there, not only the ones whose own
handler would notice.
*/
@(test)
test_an_open_header_block_takes_only_its_continuation :: proc(t: ^testing.T) {
	ping := [8]u8{}
	cases := []struct {
		name:  string,
		frame: []u8,
		ok:    bool,
	}{
		{"its CONTINUATION", frame_bytes(.Continuation, 0, 1, nil), true},
		{"a CONTINUATION on another stream", frame_bytes(.Continuation, 0, 3, nil), false},
		{"a PING", frame_bytes(.Ping, 0, 0, ping[:]), false},
		{"HEADERS on another stream", frame_bytes(.Headers, FLAG_END_HEADERS, 3, nil), false},
		{"DATA on its stream", frame_bytes(.Data, 0, 1, nil), false},
	}
	for c in cases {
		w := Wire {
			bytes = c.frame,
		}
		_, _, refuse, ok := read_frame(IO{user = &w, read = wire_read}, 1)
		testing.expectf(t, ok == c.ok, "%s read as ok=%v", c.name, ok)
		if !c.ok {
			code, bad := refuse.?
			testing.expectf(t, bad && code == .Protocol_Error, "%s drew %v", c.name, refuse)
		}
	}
	free_all(context.temp_allocator)
}

// The stream check `continue_header_block` makes for itself, behind the one
// `read_frame` makes first: a CONTINUATION with no block open, or for another
// stream's, is a PROTOCOL_ERROR, and the block is left as it was.
@(test)
test_a_continuation_for_no_open_block_is_refused :: proc(t: ^testing.T) {
	block := make([dynamic]u8, 0, 16, context.temp_allocator)
	frames := 0
	for c in ([]struct {
			on, stream: u32,
		}{{0, 1}, {1, 3}}) {
		on := c.on
		complete, refuse := continue_header_block(&on, &frames, &block, Frame_Header{type = .Continuation, flags = FLAG_END_HEADERS, stream_id = c.stream}, []u8{1})
		code, bad := refuse.?
		testing.expectf(t, bad && code == .Protocol_Error, "on %d, stream %d drew %v", c.on, c.stream, refuse)
		testing.expect(t, !complete, "a refused CONTINUATION completed the block")
		testing.expect_value(t, on, c.on)
	}
	testing.expect_value(t, len(block), 0)
	free_all(context.temp_allocator)
}

// RFC 9113 6.2 and the MAX_HEADER_LIST bound, as HEADERS is read on either end.
@(test)
test_a_headers_fragment_is_held_to_its_framing_and_the_list_bound :: proc(t: ^testing.T) {
	big := make([]u8, MAX_HEADER_LIST + 1, context.temp_allocator)
	cases := []struct {
		name:    string,
		payload: []u8,
		flags:   u8,
		code:    Error_Code,
		ok:      bool,
	}{
		{"a plain fragment", []u8{1, 2}, 0, .No_Error, true},
		{"padding longer than the frame", []u8{5, 1}, FLAG_PADDED, .Protocol_Error, false},
		{"a priority section cut short", []u8{1, 2, 3}, FLAG_PRIORITY, .Protocol_Error, false},
		{"a fragment past MAX_HEADER_LIST", big, 0, .Compression_Error, false},
		{"a fragment at MAX_HEADER_LIST", big[1:], 0, .No_Error, true},
	}
	for c in cases {
		_, code, ok := header_fragment(c.payload, c.flags)
		testing.expectf(t, ok == c.ok && code == c.code, "%s: ok=%v code=%v", c.name, ok, code)
	}
	free_all(context.temp_allocator)
}

// RFC 9113 6.5.2: the SETTINGS values neither end may accept.
@(test)
test_setting_values_out_of_range_are_refused :: proc(t: ^testing.T) {
	cases := []struct {
		id:    Setting,
		value: u32,
		code:  Error_Code,
		bad:   bool,
	}{
		{.Max_Frame_Size, DEFAULT_MAX_FRAME - 1, .Protocol_Error, true},
		{.Max_Frame_Size, DEFAULT_MAX_FRAME, .No_Error, false},
		{.Max_Frame_Size, 16777215, .No_Error, false},
		{.Max_Frame_Size, 16777216, .Protocol_Error, true},
		{.Initial_Window_Size, MAX_WINDOW, .No_Error, false},
		{.Initial_Window_Size, MAX_WINDOW + 1, .Flow_Control_Error, true},
		{.Header_Table_Size, max(u32), .No_Error, false},
	}
	for c in cases {
		code, bad := setting_error(c.id, c.value)
		testing.expectf(t, bad == c.bad && code == c.code, "%v = %d: bad=%v code=%v", c.id, c.value, bad, code)
	}
}

// RFC 9113 6.9: a WINDOW_UPDATE is four bytes, the top bit reserved, and an
// increment of zero is an error.
@(test)
test_a_window_update_payload_is_checked :: proc(t: ^testing.T) {
	cases := []struct {
		payload:   []u8,
		increment: int,
		code:      Error_Code,
	}{
		{{0, 0, 0, 1}, 1, .No_Error},
		{{0x80, 0, 0, 1}, 1, .No_Error},
		{{0x7f, 0xff, 0xff, 0xff}, MAX_WINDOW, .No_Error},
		{{0, 0, 0, 0}, 0, .Protocol_Error},
		{{0x80, 0, 0, 0}, 0, .Protocol_Error},
		{{0, 0, 1}, 0, .Frame_Size_Error},
		{{0, 0, 0, 1, 0}, 0, .Frame_Size_Error},
	}
	for c in cases {
		increment, code, ok := window_increment(c.payload)
		testing.expectf(t, increment == c.increment && code == c.code && ok == (c.code == .No_Error), "%v: %d %v %v", c.payload, increment, code, ok)
	}
}

// A DATA frame takes no more than either window and the peer's frame size, and
// both windows pay for it; with either spent, nothing is taken.
@(test)
test_send_credit_is_the_smallest_bound_and_charged_to_both_windows :: proc(t: ^testing.T) {
	cases := []struct {
		conn, stream, frame, remaining, chunk: int,
	}{
		{100, 100, 100, 50, 50},
		{30, 100, 100, 50, 30},
		{100, 20, 100, 50, 20},
		{100, 100, 10, 50, 10},
		{0, 100, 100, 50, 0},
		{100, -5, 100, 50, 0},
	}
	for c in cases {
		conn, stream := c.conn, c.stream
		chunk := take_send_credit(&conn, &stream, c.frame, c.remaining)
		testing.expectf(t, chunk == c.chunk, "%v took %d", c, chunk)
		testing.expectf(t, conn == c.conn - chunk && stream == c.stream - chunk, "%v left %d and %d", c, conn, stream)
	}
}
