package h2

import "core:encoding/hex"
import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

/*
HPACK tests built on the worked examples in RFC 7541 appendix C, so the codec is
checked against the specification's own vectors rather than against itself.
*/

@(private = "file")
from_hex :: proc(s: string) -> []u8 {
	out, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	if !ok {
		return nil
	}
	return out
}

@(test)
test_huffman_rfc_examples :: proc(t: ^testing.T) {
	// C.4.1, C.4.2, C.4.3: Huffman-coded strings from the request examples.
	Case :: struct {
		encoded: string,
		want:    string,
	}
	cases := []Case {
		{"f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"},
		{"a8eb10649cbf", "no-cache"},
		{"25a849e95ba97d7f", "custom-key"},
		{"25a849e95bb8e8b4bf", "custom-value"},
		// C.6.1: a Huffman-coded date header value.
		{"d07abe941054d444a8200595040b8166e082a62d1bff", "Mon, 21 Oct 2013 20:13:21 GMT"},
	}
	for c in cases {
		got, err := huffman_decode(from_hex(c.encoded), context.temp_allocator)
		testing.expectf(t, err == .None, "%q failed to decode: %v", c.want, err)
		testing.expect_value(t, got, c.want)
	}
	free_all(context.temp_allocator)
}

@(test)
test_huffman_rejects_bad_padding :: proc(t: ^testing.T) {
	// Padding must be the EOS prefix, all ones. A zero bit tail is invalid.
	_, err := huffman_decode([]u8{0xf1, 0x00}, context.temp_allocator)
	testing.expect(t, err != .None, "zero padding was accepted")

	// Padding longer than seven bits is invalid too.
	_, err2 := huffman_decode([]u8{0xff, 0xff, 0xff, 0xff}, context.temp_allocator)
	testing.expect(t, err2 != .None, "over-long padding was accepted")
	free_all(context.temp_allocator)
}

@(test)
test_decode_rfc_c31_literal_with_indexing :: proc(t: ^testing.T) {
	// C.3.1: a full request header set, literals plus indexed fields.
	table: Dynamic_Table
	dynamic_table_init(&table, 4096, context.temp_allocator)

	block := from_hex("828684410f7777772e6578616d706c652e636f6d")
	headers, err := decode(&table, block, context.temp_allocator)
	testing.expectf(t, err == .None, "decode failed: %v", err)
	testing.expect_value(t, len(headers), 4)
	testing.expect_value(t, headers[0].name, ":method")
	testing.expect_value(t, headers[0].value, "GET")
	testing.expect_value(t, headers[1].name, ":scheme")
	testing.expect_value(t, headers[1].value, "http")
	testing.expect_value(t, headers[2].name, ":path")
	testing.expect_value(t, headers[2].value, "/")
	testing.expect_value(t, headers[3].name, ":authority")
	testing.expect_value(t, headers[3].value, "www.example.com")

	// The literal was added to the dynamic table, at a cost of 57 bytes.
	testing.expect_value(t, table.size, 57)
	free_all(context.temp_allocator)
}

@(test)
test_decode_rfc_c4_huffman_request_sequence :: proc(t: ^testing.T) {
	// C.4: the same three requests as C.3 but Huffman coded, decoded on one
	// connection so the dynamic table carries across them.
	table: Dynamic_Table
	dynamic_table_init(&table, 4096, context.temp_allocator)

	first, e1 := decode(&table, from_hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"), context.temp_allocator)
	testing.expectf(t, e1 == .None, "first request failed: %v", e1)
	testing.expect_value(t, len(first), 4)
	testing.expect_value(t, first[3].value, "www.example.com")

	second, e2 := decode(&table, from_hex("828684be5886a8eb10649cbf"), context.temp_allocator)
	testing.expectf(t, e2 == .None, "second request failed: %v", e2)
	testing.expect_value(t, len(second), 5)
	// Index 62 refers back to the authority stored by the first request.
	testing.expect_value(t, second[3].name, ":authority")
	testing.expect_value(t, second[3].value, "www.example.com")
	testing.expect_value(t, second[4].name, "cache-control")
	testing.expect_value(t, second[4].value, "no-cache")

	third, e3 := decode(
		&table,
		from_hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"),
		context.temp_allocator,
	)
	testing.expectf(t, e3 == .None, "third request failed: %v", e3)
	testing.expect_value(t, len(third), 5)
	testing.expect_value(t, third[4].name, "custom-key")
	testing.expect_value(t, third[4].value, "custom-value")
	free_all(context.temp_allocator)
}

@(test)
test_dynamic_table_eviction :: proc(t: ^testing.T) {
	// A table only big enough for one of these entries evicts as it fills.
	table: Dynamic_Table
	dynamic_table_init(&table, 64, context.temp_allocator)

	dynamic_table_add(&table, "aaaa", "bbbb")
	testing.expect_value(t, len(table.entries), 1)
	dynamic_table_add(&table, "cccc", "dddd")
	testing.expect_value(t, len(table.entries), 1)
	// Newest first.
	testing.expect_value(t, table.entries[0].name, "cccc")

	// An entry larger than the table clears it and is not stored.
	big: [128]u8
	for i in 0 ..< len(big) {
		big[i] = 'x'
	}
	dynamic_table_add(&table, string(big[:]), "v")
	testing.expect_value(t, len(table.entries), 0)
	testing.expect_value(t, table.size, 0)
	free_all(context.temp_allocator)
}

@(test)
test_integer_continuation :: proc(t: ^testing.T) {
	// RFC 7541 C.1.2: 1337 with a 5-bit prefix is 31, 154, 10.
	r := Bit_Reader {
		buf = []u8{31, 154, 10},
	}
	v, err := read_integer(&r, 5)
	testing.expectf(t, err == .None, "decode failed: %v", err)
	testing.expect_value(t, v, 1337)

	// And the same value round-trips through the encoder.
	out := make([dynamic]u8, 0, 8, context.temp_allocator)
	write_integer(&out, 5, 1337, 0x00)
	testing.expect_value(t, len(out), 3)
	testing.expect_value(t, out[0], u8(31))
	testing.expect_value(t, out[1], u8(154))
	testing.expect_value(t, out[2], u8(10))
	free_all(context.temp_allocator)
}

@(test)
test_encoder_round_trips_through_decoder :: proc(t: ^testing.T) {
	out := make([dynamic]u8, 0, 128, context.temp_allocator)
	encode_header(&out, ":status", "200")
	encode_header(&out, "content-type", "application/dns-message")
	encode_header(&out, "cache-control", "max-age=42")
	encode_header(&out, "server", "elodin")

	table: Dynamic_Table
	dynamic_table_init(&table, 4096, context.temp_allocator)
	headers, err := decode(&table, out[:], context.temp_allocator)
	testing.expectf(t, err == .None, "decode failed: %v", err)
	testing.expect_value(t, len(headers), 4)
	testing.expect_value(t, headers[0].name, ":status")
	testing.expect_value(t, headers[0].value, "200")
	testing.expect_value(t, headers[1].value, "application/dns-message")
	testing.expect_value(t, headers[2].value, "max-age=42")
	testing.expect_value(t, headers[3].value, "elodin")

	// ":status: 200" is static entry 8, so it costs a single byte.
	testing.expect_value(t, out[0], u8(0x88))
	free_all(context.temp_allocator)
}

@(test)
test_decode_rejects_bad_index :: proc(t: ^testing.T) {
	table: Dynamic_Table
	dynamic_table_init(&table, 4096, context.temp_allocator)
	// Index 62 with an empty dynamic table refers to nothing.
	_, err := decode(&table, []u8{0xbe}, context.temp_allocator)
	testing.expect(t, err != .None, "an out-of-range index was accepted")
	free_all(context.temp_allocator)
}

@(test)
test_frame_header_round_trip :: proc(t: ^testing.T) {
	out := make([dynamic]u8, 0, 16, context.temp_allocator)
	write_frame_header(&out, 1234, .Headers, FLAG_END_HEADERS | FLAG_END_STREAM, 0x7fffffff)

	h, ok := parse_frame_header(out[:])
	testing.expect(t, ok, "parse failed")
	testing.expect_value(t, h.length, 1234)
	testing.expect_value(t, h.type, Frame_Type.Headers)
	testing.expect_value(t, h.flags, u8(FLAG_END_HEADERS | FLAG_END_STREAM))
	testing.expect_value(t, h.stream_id, u32(0x7fffffff))

	// The reserved top bit must be masked off on receipt.
	out[5] |= 0x80
	h2, _ := parse_frame_header(out[:])
	testing.expect_value(t, h2.stream_id, u32(0x7fffffff))
	free_all(context.temp_allocator)
}

/*
The three tests below run against a tracking allocator rather than the temp
allocator the rest of the file uses, because what they check is that a failed or
abandoned request releases what it allocated. A leak here is reachable by any
peer that can open a connection, so it is worth asserting on directly.
*/

@(private = "file")
expect_no_leaks :: proc(t: ^testing.T, track: ^mem.Tracking_Allocator, what: string) {
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%s: %d bytes leaked, allocated at %v", what, entry.size, entry.location)
	}
	testing.expectf(t, len(track.bad_free_array) == 0, "%s: %d bad frees", what, len(track.bad_free_array))
}

@(test)
test_decode_error_releases_partial_list :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	table: Dynamic_Table
	dynamic_table_init(&table, 4096, allocator)

	// Two valid indexed fields (:method GET, :scheme http) and then index 62,
	// which refers to a dynamic table that is still empty. The two fields are
	// already decoded and cloned by the time the third is rejected.
	_, err := decode(&table, []u8{0x82, 0x86, 0xbe}, allocator)
	testing.expect(t, err != .None, "an out-of-range index was accepted")

	dynamic_table_destroy(&table)
	expect_no_leaks(t, &track, "decode error")
}

@(private = "file")
discard_write :: proc(user: rawptr, buf: []u8) -> bool {
	return true
}

@(private = "file")
no_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	return 0, false
}

@(private = "file")
ignore_request :: proc(conn: ^Conn, req: ^Request) {
}

// RFC 7541 C.3.1: GET http / www.example.com, four fields.
@(private = "file")
REQUEST_BLOCK :: "828684410f7777772e6578616d706c652e636f6d"

@(test)
test_teardown_releases_parked_request :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	// HEADERS without END_STREAM: the request is complete but its body is not,
	// so it is parked on the stream and no handler ever takes ownership of it.
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)
	testing.expect(t, ok, "handle_headers failed")

	s, found := c.streams[1]
	testing.expect(t, found, "stream 1 was not created")
	testing.expect(t, s.pending != nil, "no request was parked on the stream")

	// The peer goes away here, which is all it takes.
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "parked request")
}

@(test)
test_oversized_body_drops_the_stream :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)

	body := make([]u8, MAX_BODY + 1, context.temp_allocator)
	ok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, ok, "handle_data failed")

	// Refused, and gone: a stream left in the map would hold its body and one of
	// MAX_CONCURRENT slots for as long as the connection lasted.
	_, still_open := c.streams[1]
	testing.expect(t, !still_open, "the reset stream is still in the table")

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "oversized body")
}

/*
RFC 9113 6.1: DATA is only ever sent on a stream, never on the connection
control stream, so one arriving with stream_id 0 is a connection error of
type PROTOCOL_ERROR. `handle_headers` already checks this; `handle_data` did
not, and fell through to look up a stream that can never be in the map.
*/
@(test)
test_data_on_stream_zero_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, ignore_request, nil, allocator)

	body := []u8{'x'}
	ok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 0}, body)
	testing.expect(t, !ok, "DATA on stream 0 was accepted")

	saw_goaway := false
	for f in log.frames {
		if f.type == .Goaway {
			saw_goaway = true
		}
	}
	testing.expect(t, saw_goaway, "no GOAWAY was sent for DATA on stream 0")

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data on stream zero")
}

/*
RFC 9113 5.1: a stream id past the highest one this connection has ever opened
is idle, and DATA is not among the frames idle accepts - a connection error of
type PROTOCOL_ERROR, the same as stream 0. `handle_data` instead found nothing
in the stream table and fell through the ordinary not-found path, handing back
a connection WINDOW_UPDATE for a stream id that was never opened.
*/
@(test)
test_data_on_an_idle_stream_is_rejected :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, ignore_request, nil, allocator)

	body := []u8{'x'}
	ok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 3}, body)
	testing.expect(t, !ok, "DATA on an idle stream was accepted")

	saw_goaway := false
	for f in log.frames {
		if f.type == .Goaway {
			saw_goaway = true
		}
	}
	testing.expect(t, saw_goaway, "no GOAWAY was sent for DATA on an idle stream")

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data on an idle stream")
}

/*
RFC 9113 5.1: once a stream is half-closed (remote), the peer has said it is
done sending, and anything but WINDOW_UPDATE, PRIORITY, or RST_STREAM from it
is a stream error of type STREAM_CLOSED. `handle_data` instead appended
straight to `s.body`, silently accepting a body that was already complete.
*/
@(test)
test_data_after_end_stream_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, destroying_handler, nil, allocator)

	// END_STREAM on the HEADERS dispatches straight away and marks the stream
	// half-closed (remote); the handler frees the request but leaves the
	// stream itself for whoever answers it.
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1},
		block,
	)
	testing.expect(t, ok, "handle_headers failed")

	clear(&log.frames)
	body := []u8{'x'}
	dok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, dok, "DATA after END_STREAM should be a stream error, not a connection error")

	s, still_open := c.streams[1]
	testing.expect(t, still_open, "a stream still owned by its handler was retired out from under it")
	if still_open {
		testing.expect_value(t, len(s.body), 0)
	}

	saw_rst := false
	saw_credit := false
	for f in log.frames {
		if f.type == .Rst_Stream && f.stream_id == 1 {
			saw_rst = true
		}
		if f.type == .Window_Update && f.stream_id == 0 {
			saw_credit = true
		}
	}
	testing.expect(t, saw_rst, "no RST_STREAM was sent for DATA after END_STREAM")
	testing.expect(t, saw_credit, "the connection window was not replenished for a frame that was refused")

	/*
	A peer that keeps sending after the first violation must not draw a fresh
	RST_STREAM every time - that is a cheap way to make this end write two
	frames under `c.mu` per frame it sends. `cancelled`, set on the first
	violation above, is what keeps the second one quiet.
	*/
	clear(&log.frames)
	dok2 := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, dok2, "a repeat violation should still be a stream error, not a connection error")
	for f in log.frames {
		testing.expectf(t, f.type != .Rst_Stream, "a second RST_STREAM was sent for a stream already marked cancelled")
	}

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data after end stream")
}

/*
RFC 9113 5.1 puts closed in the same bucket as half-closed (remote): once the
peer has reset a stream, only WINDOW_UPDATE, PRIORITY, and RST_STREAM are
still allowed from it. A dispatched stream stays in `c.streams` after an
inbound RST_STREAM - `respond` is what retires it - so `handle_data` could
still find it and, before this fix, would append to its body and hand back a
stream-level WINDOW_UPDATE for a stream the peer had already walked away
from. Answering with an RST_STREAM of our own would loop (RFC 9113 5.4.2),
so this checks its absence rather than its presence.
*/
@(test)
test_data_on_a_peer_reset_stream_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, destroying_handler, nil, allocator)

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1},
		block,
	)
	testing.expect(t, ok, "handle_headers failed")

	rst := []u8{0, 0, 0, 8} // CANCEL
	rok := handle_frame(c, Frame_Header{length = len(rst), type = .Rst_Stream, stream_id = 1}, rst)
	testing.expect(t, rok, "handle_frame failed")

	live, open := c.streams[1]
	testing.expect(t, open, "a dispatched stream was retired out from under its handler")
	if open {
		testing.expect_value(t, live.state, Stream_State.Closed)
	}

	clear(&log.frames)
	body := []u8{'x'}
	dok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)
	testing.expect(t, dok, "DATA on a peer-reset stream should be a stream error, not a connection error")

	if s, still_open := c.streams[1]; still_open {
		testing.expect_value(t, len(s.body), 0)
	}

	saw_credit := false
	for f in log.frames {
		testing.expectf(t, f.type != .Rst_Stream, "an RST_STREAM was sent answering a stream the peer had already reset")
		if f.type == .Window_Update && f.stream_id == 0 {
			saw_credit = true
		}
	}
	testing.expect(t, saw_credit, "the connection window was not replenished for a frame that was refused")

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data on a peer-reset stream")
}

@(test)
test_padding_and_priority_stripping :: proc(t: ^testing.T) {
	// PADDED: first byte is the pad length, that many bytes come off the end.
	padded := []u8{2, 'h', 'i', 0, 0}
	body, ok := strip_padding(padded, FLAG_PADDED)
	testing.expect(t, ok, "strip_padding failed")
	testing.expect_value(t, string(body), "hi")

	// A pad length that overruns the payload is rejected.
	_, bad := strip_padding([]u8{9, 'h'}, FLAG_PADDED)
	testing.expect(t, !bad, "over-long padding was accepted")

	// PRIORITY prepends five bytes.
	prio := []u8{0, 0, 0, 1, 16, 'o', 'k'}
	rest, pok := strip_priority(prio, FLAG_PRIORITY)
	testing.expect(t, pok, "strip_priority failed")
	testing.expect_value(t, string(rest), "ok")
}

// ---------------------------------------------------------------------------
// A stream freed while the reader thread is between locks
// ---------------------------------------------------------------------------

@(private = "file")
Close_Hook :: struct {
	conn:      ^Conn,
	stream_id: u32,
	armed:     bool,
	fired:     bool,
	closed:    ^Stream,
}

/*
Stands in for a handler thread completing `respond` inside the window
`handle_data` leaves open between releasing `c.mu` after appending the body and
re-acquiring it to record the stream's final state.

`handle_data` reaches here through the WINDOW_UPDATE it writes for the bytes it
just consumed, which is where the real race lands: `write_all` holds `c.mu` for
the length of this call, so a `respond` running on a handler-pool worker would
be parked on that mutex right here and would take it the moment this returns.
Retiring the stream inline reproduces that ordering without asking the scheduler
to produce it.

`close_stream` would free the stream here, and a write through the reader
thread's stale pointer is then a use-after-free. The stream is only unhooked
from the map rather than released, so that the write has somewhere defined to
land and the test can assert on it instead of depending on the allocator to
reuse the block or on a sanitiser to be watching.
*/
@(private = "file")
close_on_write :: proc(user: rawptr, buf: []u8) -> bool {
	h := cast(^Close_Hook)user
	if h == nil || !h.armed || h.fired {
		return true
	}
	h.fired = true

	s, found := h.conn.streams[h.stream_id]
	if !found {
		return true
	}
	delete_key(&h.conn.streams, h.stream_id)
	s.state = .Closed
	h.closed = s
	return true
}

@(private = "file")
destroying_handler :: proc(conn: ^Conn, req: ^Request) {
	request_destroy(conn, req)
}

@(test)
test_data_frame_cannot_touch_a_closed_stream :: proc(t: ^testing.T) {
	/*
	A DATA frame arriving for a stream must not write through a pointer the
	reader thread picked up before it released the lock, whoever retired the
	stream in between - here, nothing so far has dispatched a handler for it,
	so the request is still parked; `test_data_after_end_stream_is_refused`
	covers the same race for a stream a handler already owns.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	hook := Close_Hook{}
	c := make_conn(IO{user = &hook, read = no_read, write = close_on_write}, destroying_handler, nil, allocator)
	hook.conn = c
	hook.stream_id = 1

	/*
	No END_STREAM on the HEADERS: the request parks on the stream rather than
	dispatching, so the DATA below is the first frame to see this stream and
	`already_ended` (server.odin) is false for it - it still takes the append
	path all the way to the WINDOW_UPDATE write the hook rides in on. HEADERS
	with END_STREAM would dispatch immediately and leave nothing for this DATA
	to reach but the now-`already_ended` short-circuit, which returns before
	ever writing a WINDOW_UPDATE.
	*/
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)
	testing.expect(t, ok, "handle_headers failed")

	hook.armed = true
	body := []u8{'x'}
	handle_data(c, Frame_Header{length = len(body), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, body)

	testing.expect(t, hook.fired, "the close hook never ran, so nothing was reproduced")
	testing.expect(t, hook.closed != nil, "the stream was not retired")

	/*
	The stream was retired while `handle_data` was between locks. In the real
	sequence it has also been freed by now, so any write here is a write to
	released memory.
	*/
	testing.expect_value(t, hook.closed.state, Stream_State.Closed)
	_, back_in_map := c.streams[1]
	testing.expect(t, !back_in_map, "the retired stream was put back in the table")

	stream_destroy(c, hook.closed)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data after close")
}

// ---------------------------------------------------------------------------
// Bounds on what one peer can make a connection hold or wait for
// ---------------------------------------------------------------------------

/*
A dynamic table size update may not exceed the size this end advertised.

RFC 7541 6.3: "The new maximum size MUST be lower than or equal to the limit
determined by the protocol using HPACK", and 4.2 makes a larger value a
decoding error. The limit here is 4096 - what `dynamic_table_init` is given on
both the server and the client connection, and what SETTINGS_HEADER_TABLE_SIZE
states.

What the decoder enforced instead was 65536, a constant of its own with no
relation to the number the table was built with. The two are supposed to be the
same number.

Not all of that 65536 was reachable: `read_integer` refuses any value past
MAX_HEADER_LIST, so an update above 32 KiB was already a decoding error by
another route, and what a peer could actually take was eight times the size
this end agreed to rather than sixteen. Both boundaries are here, each with the
error that turns it away, so which one does the work is on the record.
*/
@(test)
test_dynamic_table_update_is_bounded_by_the_advertised_limit :: proc(t: ^testing.T) {
	LIMIT :: 4096

	Case :: struct {
		size:     int,
		accepted: bool,
		err:      Hpack_Error,
		what:     string,
	}

	CASES := []Case {
		{0, true, .None, "down to nothing"},
		{512, true, .None, "under the limit"},
		{LIMIT, true, .None, "exactly the limit"},
		{LIMIT + 1, false, .Bad_Update, "one byte past the limit"},
		{8192, false, .Bad_Update, "twice the limit"},
		{MAX_HEADER_LIST, false, .Bad_Update, "the largest update that gets this far"},
		// Past what `read_integer` will read at all, whatever it is for.
		{MAX_HEADER_LIST + 1, false, .Too_Large, "past the integer cap"},
		{65536, false, .Too_Large, "the old local cap"},
	}

	for c in CASES {
		table: Dynamic_Table
		dynamic_table_init(&table, LIMIT, context.temp_allocator)

		block := make([dynamic]u8, 0, 16, context.temp_allocator)
		write_integer(&block, 5, c.size, 0x20)
		// A real field behind the update, so what is measured is a block a peer
		// would actually send rather than a lone update.
		append(&block, 0x82) // indexed: :method GET

		headers, err := decode(&table, block[:], context.temp_allocator)
		if c.accepted {
			testing.expectf(t, err == .None, "an update %s was refused: %v", c.what, err)
			testing.expectf(t, table.max_size == c.size, "%s: the table is %d, expected %d", c.what, table.max_size, c.size)
			testing.expectf(t, len(headers) == 1, "%s: %d headers decoded", c.what, len(headers))
		} else {
			testing.expectf(t, err == c.err, "an update %s gave %v, expected %v", c.what, err, c.err)
			testing.expectf(
				t,
				table.max_size == LIMIT,
				"%s: the table was resized to %d anyway",
				c.what,
				table.max_size,
			)
		}
		free_all(context.temp_allocator)
	}
}

@(test)
test_continuation_flood_is_refused :: proc(t: ^testing.T) {
	/*
	A header block arrives across as many CONTINUATION frames as the peer cares
	to send, and neither HEADERS nor CONTINUATION is flow-controlled, so nothing
	slows one down. HPACK's own limit is no help: `decode` does not run until
	END_HEADERS arrives, and a peer bent on this never sends it.

	So the block has to be bounded as it accumulates.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	// END_HEADERS clear, so the block stays open.
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = 0, stream_id = 1}, block)
	testing.expect(t, ok, "handle_headers failed")

	chunk := make([]u8, DEFAULT_MAX_FRAME, context.temp_allocator)
	refused := false
	for _ in 0 ..< 64 {
		if !handle_continuation(
			c,
			Frame_Header{length = len(chunk), type = .Continuation, flags = 0, stream_id = 1},
			chunk,
		) {
			refused = true
			break
		}
	}
	testing.expect(t, refused, "a header block was allowed to grow without limit")

	if s, found := c.streams[1]; found {
		testing.expectf(
			t,
			len(s.header_block) <= MAX_HEADER_LIST,
			"the block reached %d bytes, past the %d limit",
			len(s.header_block),
			MAX_HEADER_LIST,
		)
	}

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "continuation flood")
}

/*
The same flood with nothing in the frames.

A byte cap is no cap at all against a peer that sends no bytes: an empty
CONTINUATION never advances `len(s.header_block)`, so the block stays open and
the frames keep coming. Nothing accrues, which is why this is small, but the
reader thread reads and dispatches nine-byte frames for as long as the peer
cares to send them and the block it is waiting on never ends.

So the frames are counted as well as measured.
*/
@(test)
test_empty_continuation_flood_is_refused :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = 0, stream_id = 1}, block)
	testing.expect(t, ok, "handle_headers failed")

	// Far more than the cap, and far fewer than a peer would need to send to
	// make this worth doing.
	sent := 0
	refused := false
	for _ in 0 ..< 10000 {
		sent += 1
		if !handle_continuation(c, Frame_Header{length = 0, type = .Continuation, stream_id = 1}, nil) {
			refused = true
			break
		}
	}
	testing.expectf(t, refused, "%d empty CONTINUATION frames were all accepted", sent)

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "empty continuation flood")
}

/*
A stream the peer resets before its body arrives.

Nothing else will ever retire it. `respond` is what normally does, and it runs
only for a stream a handler was given; one parked between its headers and a body
that never came has no handler to answer it. Left in the table it holds its
parked request - a header list apiece - and one of MAX_CONCURRENT slots for as
long as the connection lasts.
*/
@(test)
test_reset_stream_is_retired :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	// END_HEADERS without END_STREAM: the request is parked awaiting a body, so
	// no handler owns it.
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1},
		block,
	)
	testing.expect(t, ok, "handle_headers failed")

	s, found := c.streams[1]
	testing.expect(t, found, "stream 1 was not created")
	testing.expect(t, s.pending != nil, "no request was parked on the stream")

	rst := []u8{0, 0, 0, 8} // CANCEL
	rok := handle_frame(c, Frame_Header{length = len(rst), type = .Rst_Stream, stream_id = 1}, rst)
	testing.expect(t, rok, "handle_frame(RST_STREAM) failed")

	_, still_open := c.streams[1]
	testing.expect(t, !still_open, "the reset stream is still in the table")

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "reset stream")
}

/*
The consequence of not retiring them, which is what makes it worth more than a
leak: two frames per stream and the connection stops accepting new ones.
*/
@(test)
test_reset_streams_do_not_exhaust_concurrency :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)

	rst := []u8{0, 0, 0, 8} // CANCEL
	for i in 0 ..< MAX_CONCURRENT {
		block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
		id := u32(1 + 2 * i)
		handle_headers(
			c,
			Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = id},
			block,
		)
		handle_frame(c, Frame_Header{length = len(rst), type = .Rst_Stream, stream_id = id}, rst)
	}

	testing.expectf(t, len(c.streams) == 0, "%d reset streams are still held on the connection", len(c.streams))

	// So the next one is still accepted rather than refused.
	fresh, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	next := u32(1 + 2 * MAX_CONCURRENT)
	handle_headers(
		c,
		Frame_Header{length = len(fresh), type = .Headers, flags = FLAG_END_HEADERS, stream_id = next},
		fresh,
	)
	_, accepted := c.streams[next]
	testing.expect(t, accepted, "a fresh stream was refused after MAX_CONCURRENT resets")

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "reset stream flood")
}

/*
A stream that already has a handler is the other half of the same rule.

`respond` is what retires that one, and it has to find the stream still there to
see that the peer cancelled and skip the answer. Retiring it here instead would
leave `respond` writing a response for a stream the peer has finished with, and
the handler's own `close_stream` with nothing to close.
*/
@(test)
test_reset_stream_with_a_handler_is_left_for_it :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, destroying_handler, nil, allocator)

	// END_STREAM dispatches straight away, so a handler owns this one.
	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1},
		block,
	)
	testing.expect(t, ok, "handle_headers failed")

	rst := []u8{0, 0, 0, 8} // CANCEL
	handle_frame(c, Frame_Header{length = len(rst), type = .Rst_Stream, stream_id = 1}, rst)

	live, open := c.streams[1]
	testing.expect(t, open, "a dispatched stream was retired out from under its handler")
	if open {
		testing.expect(t, live.cancelled, "the stream was not marked cancelled")
	}

	// The handler answers late, and must find the cancellation rather than write.
	clear(&log.frames)
	respond(c, 1, Response{status = 200, content_type = "application/dns-message", body = []u8{1, 2, 3, 4}})
	testing.expectf(t, len(log.frames) == 0, "respond wrote %d frames for a cancelled stream", len(log.frames))

	_, after := c.streams[1]
	testing.expect(t, !after, "respond did not retire the cancelled stream")

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "reset with handler")
}

@(private = "file")
Respond_Ctx :: struct {
	conn: ^Conn,
	done: bool,
}

@(private = "file")
respond_worker :: proc(r: ^Respond_Ctx) {
	body := []u8{1, 2, 3, 4}
	respond(r.conn, 1, Response{status = 200, content_type = "application/dns-message", body = body})
	sync.atomic_store(&r.done, true)
}

@(test)
test_response_gives_up_when_no_window_is_granted :: proc(t: ^testing.T) {
	/*
	A client that advertises a zero window and then says nothing leaves the
	handler answering it parked on flow control. Nothing else marks the
	connection dead - its reader is perfectly healthy - so the wait had no end
	to it, and one connection could pin a worker per stream, up to
	MAX_CONCURRENT of them.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, destroying_handler, nil, allocator)
	// The peer grants nothing, so no stream ever has room for a DATA frame.
	c.peer_initial_window = 0
	c.write_timeout = 200 * time.Millisecond

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	ok := handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1},
		block,
	)
	testing.expect(t, ok, "handle_headers failed")

	r := Respond_Ctx {
		conn = c,
	}
	worker := thread.create_and_start_with_poly_data(&r, respond_worker)

	// Generously past the timeout above, and still far short of forever.
	deadline := time.time_add(time.now(), 5 * time.Second)
	for !sync.atomic_load(&r.done) && time.diff(time.now(), deadline) > 0 {
		time.sleep(10 * time.Millisecond)
	}
	finished := sync.atomic_load(&r.done)
	testing.expect(t, finished, "respond never gave up waiting for a window that was never granted")

	if !finished {
		// Release it so the suite can finish rather than hang on the join.
		sync.mutex_lock(&c.mu)
		c.closed = true
		sync.cond_broadcast(&c.cond)
		sync.mutex_unlock(&c.mu)
	}
	thread.join(worker)
	thread.destroy(worker)

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "no window granted")
}

// ---------------------------------------------------------------------------
// Flow-control credit for bytes we refused
// ---------------------------------------------------------------------------

@(private = "file")
Frame_Log :: struct {
	frames: [dynamic]Frame_Header,
}

@(private = "file")
log_write :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Frame_Log)user
	if log == nil {
		return true
	}
	pos := 0
	for pos + FRAME_HEADER_SIZE <= len(buf) {
		h, ok := parse_frame_header(buf[pos:])
		if !ok {
			break
		}
		append(&log.frames, h)
		pos += FRAME_HEADER_SIZE + h.length
	}
	return true
}

@(private = "file")
saw_connection_window_update :: proc(log: ^Frame_Log) -> bool {
	for f in log.frames {
		if f.type == .Window_Update && f.stream_id == 0 {
			return true
		}
	}
	return false
}

@(test)
test_oversized_body_returns_connection_credit :: proc(t: ^testing.T) {
	/*
	A body past the limit is refused and its stream dropped, but the bytes were
	still read off the connection and still count against the connection's
	receive window. That window is shared by every stream, and nothing ever
	replenishes it on its own, so skipping the WINDOW_UPDATE here costs the
	connection that much room permanently. Enough of them and the peer is no
	longer allowed to send anything at all.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, ignore_request, nil, allocator)

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)

	clear(&log.frames)
	body := make([]u8, MAX_BODY + 1, context.temp_allocator)
	handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = 1}, body)

	testing.expect(
		t,
		saw_connection_window_update(&log),
		"the connection window was not replenished for a body that was refused",
	)

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "oversized body credit")
}

/*
A SETTINGS_INITIAL_WINDOW_SIZE change adjusts every open stream's send window,
and the result of that adjustment has to be checked as well as the value itself.

RFC 9113 section 6.9.2 makes a flow-control window pushed past 2^31-1 a
connection error of type FLOW_CONTROL_ERROR. `handle_window_update` checks for
exactly that, and this path applied its delta and looked at nothing, so the two
routes to the same window disagreed about the same limit. The guard that is
there only refuses a settings *value* over the maximum, which does not stop the
accumulated window from getting there a byte at a time.
*/
@(test)
test_settings_window_change_is_bounded :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, ignore_request, nil, allocator)

	block, _ := hex.decode(transmute([]u8)string(REQUEST_BLOCK), context.temp_allocator)
	handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)

	// Exactly the maximum is allowed, and is where a peer parks a stream before
	// nudging it over with a settings change.
	grant := []u8{0x7f, 0xff, 0x00, 0x00} // MAX_WINDOW - DEFAULT_WINDOW
	granted := handle_window_update(c, Frame_Header{length = len(grant), type = .Window_Update, stream_id = 1}, grant)
	testing.expect(t, granted, "a window update to exactly the maximum was refused")
	if s, found := c.streams[1]; found {
		testing.expect_value(t, s.send_window, MAX_WINDOW)
	}

	clear(&log.frames)
	// One byte more of initial window is one byte too many.
	settings := []u8{0, u8(Setting.Initial_Window_Size), 0, 1, 0, 0} // 65536
	accepted := handle_settings(c, Frame_Header{length = len(settings), type = .Settings, stream_id = 0}, settings)
	testing.expect(t, !accepted, "a settings change past the maximum window was accepted")

	saw_goaway := false
	for f in log.frames {
		if f.type == .Goaway {
			saw_goaway = true
		}
	}
	testing.expect(t, saw_goaway, "no GOAWAY was sent for a flow-control violation")

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "settings window overflow")
}

// ---------------------------------------------------------------------------
// Frame size bound
// ---------------------------------------------------------------------------

// Feeds `serve` a scripted byte stream and records the code of any GOAWAY the
// connection writes back, so the frame loop can be driven end to end.
@(private = "file")
Serve_Harness :: struct {
	in_data:    []u8,
	in_pos:     int,
	// Every byte written, so a frame split across writes is still parsed whole.
	written:    [dynamic]u8,
	saw_goaway: bool,
	code:       Error_Code,
}

@(private = "file")
serve_harness_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	h := cast(^Serve_Harness)user
	if h.in_pos >= len(h.in_data) {
		return 0, false
	}
	n = copy(buf, h.in_data[h.in_pos:])
	h.in_pos += n
	return n, true
}

// Accumulates writes and scans complete frames from the whole buffer, so a
// GOAWAY that lands across two writes is still seen once its tail arrives
// rather than dropped with the mid-frame tail of a single call.
@(private = "file")
serve_harness_write :: proc(user: rawptr, buf: []u8) -> bool {
	h := cast(^Serve_Harness)user
	append(&h.written, ..buf)
	pos := 0
	for pos + FRAME_HEADER_SIZE <= len(h.written) {
		fh, ok := parse_frame_header(h.written[pos:])
		if !ok {
			break
		}
		// The frame's body has not all arrived yet; wait for the write that
		// carries the rest.
		if pos + FRAME_HEADER_SIZE + fh.length > len(h.written) {
			break
		}
		if fh.type == .Goaway {
			body := h.written[pos + FRAME_HEADER_SIZE:]
			if len(body) >= 8 {
				h.saw_goaway = true
				h.code = Error_Code(read_u32(body[4:]))
			}
		}
		pos += FRAME_HEADER_SIZE + fh.length
	}
	return true
}

@(test)
test_frame_larger_than_advertised_max_is_refused :: proc(t: ^testing.T) {
	/*
	The frame loop advertises the RFC 9113 6.5.2 default MAX_FRAME_SIZE (16384)
	by never sending one, yet the bound it enforced was the receive window, 64x
	that. A peer told one size and allowed another was refused only above 1 MB,
	so any frame in between was accepted while the peer had been promised it
	would not be.
	*/
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	// Preface, then a frame header claiming a payload one byte over the
	// advertised maximum - well under the old receive-window bound.
	input := make([dynamic]u8, 0, len(PREFACE) + FRAME_HEADER_SIZE, context.temp_allocator)
	append(&input, ..transmute([]u8)string(PREFACE))
	write_frame_header(&input, DEFAULT_MAX_FRAME + 1, .Data, 0, 1)

	h := Serve_Harness {
		in_data = input[:],
		written = make([dynamic]u8, 0, 64, allocator),
	}
	c := make_conn(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, ignore_request, nil, allocator)
	serve(c)

	testing.expect(t, h.saw_goaway, "an oversized frame was accepted without a GOAWAY")
	testing.expect_value(t, h.code, Error_Code.Frame_Size_Error)

	delete(h.written)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "oversized frame")
}

// ---------------------------------------------------------------------------
// A stream refused for being over the concurrency limit
// ---------------------------------------------------------------------------

// Fills every concurrency slot with a bare stream, so the next HEADERS the
// connection sees is over MAX_CONCURRENT and refused. `last_stream_id` is left
// at the highest id used, as opening those streams for real would have, so a
// refused stream after it still has to advance the id on its own.
@(private = "file")
fill_concurrency :: proc(c: ^Conn, allocator: mem.Allocator) {
	for i in 0 ..< MAX_CONCURRENT {
		s := new(Stream, allocator)
		s.id = u32(1 + 2 * i)
		c.streams[s.id] = s
		c.last_stream_id = s.id
	}
}

/*
RFC 9113 5.1.1: a refused stream's field block must still be decoded, or the
per-connection HPACK decoder desynchronises from the peer's encoder for good.

A literal with incremental indexing on the refused stream adds an entry to the
peer's dynamic table; skipping the decode leaves ours without it, so every later
block that references it decodes against the wrong table.
*/
@(test)
test_refused_stream_still_decodes_its_header_block :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)
	fill_concurrency(c, allocator)

	// Literal with incremental indexing, new name "x" with value "y": added to
	// the dynamic table at index 62.
	refused_block := []u8{0x40, 0x01, 'x', 0x01, 'y'}
	refused_id := u32(1 + 2 * MAX_CONCURRENT)
	ok := handle_headers(
		c,
		Frame_Header{length = len(refused_block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = refused_id},
		refused_block,
	)
	testing.expect(t, ok, "handle_headers on a refused stream failed")

	// Refused: it holds no slot.
	_, held := c.streams[refused_id]
	testing.expect(t, !held, "a refused stream was left in the table")

	// last_stream_id advanced, so the peer cannot reuse the id.
	testing.expect_value(t, c.last_stream_id, refused_id)

	// The block's dynamic-table side effect was applied.
	testing.expectf(t, len(c.decoder.entries) == 1, "the refused block was not decoded: %d entries", len(c.decoder.entries))
	if len(c.decoder.entries) == 1 {
		testing.expect_value(t, c.decoder.entries[0].name, "x")
		testing.expect_value(t, c.decoder.entries[0].value, "y")
	}

	// Free a slot and send a stream that references index 62. With the decoder in
	// step it decodes; desynchronised it is Bad_Index and a COMPRESSION_ERROR.
	close_stream(c, 1)
	next_block := []u8{0xbe}
	next_id := refused_id + 2
	nok := handle_headers(
		c,
		Frame_Header{length = len(next_block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = next_id},
		next_block,
	)
	testing.expect(t, nok, "a later block referencing the refused entry failed to decode")
	_, accepted := c.streams[next_id]
	testing.expect(t, accepted, "the following stream was not accepted")

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "refused stream decode")
}

/*
A refused HEADERS whose END_HEADERS is clear opens a CONTINUATION sequence like
any other. Without `continuation_on` set on the refused path, the CONTINUATION
that follows fails the `continuation_on != stream_id` guard and GOAWAYs the whole
connection - so a client merely at its stream limit loses every in-flight stream.
*/
@(test)
test_refused_stream_accepts_its_continuation :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	c := make_conn(IO{read = no_read, write = discard_write}, ignore_request, nil, allocator)
	fill_concurrency(c, allocator)

	// The literal split across HEADERS (END_HEADERS clear) and a CONTINUATION.
	refused_id := u32(1 + 2 * MAX_CONCURRENT)
	head := []u8{0x40, 0x01, 'x'}
	ok := handle_headers(
		c,
		Frame_Header{length = len(head), type = .Headers, flags = 0, stream_id = refused_id},
		head,
	)
	testing.expect(t, ok, "handle_headers on a refused stream failed")
	testing.expect_value(t, c.continuation_on, refused_id)

	tail := []u8{0x01, 'y'}
	cok := handle_continuation(
		c,
		Frame_Header{length = len(tail), type = .Continuation, flags = FLAG_END_HEADERS, stream_id = refused_id},
		tail,
	)
	testing.expect(t, cok, "the CONTINUATION of a refused stream was rejected")
	testing.expect_value(t, c.continuation_on, u32(0))

	// The whole block was decoded, so the decoder stayed in step.
	testing.expectf(t, len(c.decoder.entries) == 1, "the refused block was not decoded: %d entries", len(c.decoder.entries))

	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "refused stream continuation")
}

/*
DATA the peer had already put on the wire for a stream we refused arrives after
it is gone from the table. It is not tracked, so nothing buffers it; the bytes
still counted against the shared receive window, so their credit is returned
with a connection-level WINDOW_UPDATE rather than silently dropped.
*/
@(test)
test_data_on_a_refused_stream_returns_connection_credit :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)

	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 8, allocator),
	}
	c := make_conn(IO{user = &log, read = no_read, write = log_write}, ignore_request, nil, allocator)
	fill_concurrency(c, allocator)

	refused_id := u32(1 + 2 * MAX_CONCURRENT)
	block := []u8{0x40, 0x01, 'x', 0x01, 'y'}
	handle_headers(
		c,
		Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = refused_id},
		block,
	)
	_, held := c.streams[refused_id]
	testing.expect(t, !held, "a refused stream was left in the table")

	clear(&log.frames)
	body := []u8{1, 2, 3, 4}
	ok := handle_data(c, Frame_Header{length = len(body), type = .Data, stream_id = refused_id}, body)
	testing.expect(t, ok, "DATA on a refused stream was not handled gracefully")
	testing.expect(
		t,
		saw_connection_window_update(&log),
		"the connection window was not replenished for DATA on a refused stream",
	)

	delete(log.frames)
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, &track, "data on a refused stream")
}
