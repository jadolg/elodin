package h2

import "core:encoding/hex"
import "core:mem"
import "core:testing"

/*
Fixtures shared by the server and client tests: a tracking allocator for the
leak checks, an IO that logs the frames written, and the request block most
server tests open a stream with.
*/

// Starts tracking into `track`. The tracker is destroyed at the end of the
// caller's scope; `expect_no_leaks` is still the caller's to place.
@(private, deferred_in = untrack_allocations)
track_allocations :: proc(track: ^mem.Tracking_Allocator) -> mem.Allocator {
	mem.tracking_allocator_init(track, context.allocator)
	return mem.tracking_allocator(track)
}

@(private)
untrack_allocations :: proc(track: ^mem.Tracking_Allocator) {
	mem.tracking_allocator_destroy(track)
}

@(private)
expect_no_leaks :: proc(t: ^testing.T, track: ^mem.Tracking_Allocator, what: string, loc := #caller_location) {
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "%s: %d bytes leaked, allocated at %v", what, entry.size, entry.location, loc = loc)
	}
	testing.expectf(t, len(track.bad_free_array) == 0, "%s: %d bad frees", what, len(track.bad_free_array), loc = loc)
}

@(private)
from_hex :: proc(s: string) -> []u8 {
	out, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	if !ok {
		return nil
	}
	return out
}

// RFC 7541 C.3.1: GET http / www.example.com, four fields.
@(private)
REQUEST_BLOCK :: "828684410f7777772e6578616d706c652e636f6d"

@(private)
request_block :: proc() -> []u8 {
	return from_hex(REQUEST_BLOCK)
}

@(private)
no_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	return 0, false
}

@(private)
discard_write :: proc(user: rawptr, buf: []u8) -> bool {
	return true
}

@(private)
Frame_Log :: struct {
	frames:      [dynamic]Frame_Header,
	// Sum of the connection WINDOW_UPDATE increments written.
	credit:      int,
	// Error code of the last GOAWAY written.
	goaway_code: Error_Code,
	// Error code of the last RST_STREAM written.
	rst_code:    Error_Code,
}

// Logs every frame written. A client's preface is not a frame, and is skipped
// when it leads the buffer.
@(private)
log_write :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Frame_Log)user
	if log == nil {
		return true
	}
	pos := 0
	if len(buf) >= len(PREFACE) && string(buf[:len(PREFACE)]) == PREFACE {
		pos = len(PREFACE)
	}
	for pos + FRAME_HEADER_SIZE <= len(buf) {
		h, ok := parse_frame_header(buf[pos:])
		if !ok {
			break
		}
		append(&log.frames, h)
		if h.type == .Window_Update && h.stream_id == 0 && h.length == 4 && pos + FRAME_HEADER_SIZE + 4 <= len(buf) {
			log.credit += int(read_u32(buf[pos + FRAME_HEADER_SIZE:]))
		}
		if h.type == .Goaway && pos + FRAME_HEADER_SIZE + 8 <= len(buf) {
			log.goaway_code = Error_Code(read_u32(buf[pos + FRAME_HEADER_SIZE + 4:]))
		}
		if h.type == .Rst_Stream && pos + FRAME_HEADER_SIZE + 4 <= len(buf) {
			log.rst_code = Error_Code(read_u32(buf[pos + FRAME_HEADER_SIZE:]))
		}
		pos += FRAME_HEADER_SIZE + h.length
	}
	return true
}

// Frames of `type` written, on `stream_id` or on any stream.
@(private)
count_frames :: proc(log: ^Frame_Log, type: Frame_Type, stream_id: Maybe(u32) = nil) -> int {
	n := 0
	id, one := stream_id.?
	for f in log.frames {
		if f.type == type && (!one || f.stream_id == id) {
			n += 1
		}
	}
	return n
}

@(private)
saw_frame :: proc(log: ^Frame_Log, type: Frame_Type, stream_id: Maybe(u32) = nil) -> bool {
	return count_frames(log, type, stream_id) > 0
}

// A server connection on `handler` whose writes go to `log`.
@(private)
logged_conn :: proc(log: ^Frame_Log, handler: Handler, allocator: mem.Allocator) -> ^Conn {
	log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	return make_conn(IO{user = log, read = no_read, write = log_write}, handler, nil, allocator)
}

// A client whose writes go to `log`. Nothing is ever read.
@(private)
logged_client :: proc(log: ^Frame_Log, allocator := context.allocator) -> ^Client {
	log.frames = make([dynamic]Frame_Header, 0, 8, allocator)
	return client_make(IO{user = log, read = no_read, write = log_write}, allocator)
}

// Ends a tracked server test: the log, the connection, then the leak check.
@(private)
conn_done :: proc(t: ^testing.T, c: ^Conn, track: ^mem.Tracking_Allocator, what: string, log: ^Frame_Log = nil, loc := #caller_location) {
	if log != nil {
		delete(log.frames)
	}
	conn_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, track, what, loc)
}

// Ends a tracked client test: the log, the client, then the leak check.
@(private)
client_done :: proc(t: ^testing.T, c: ^Client, track: ^mem.Tracking_Allocator, what: string, log: ^Frame_Log = nil, loc := #caller_location) {
	if log != nil {
		delete(log.frames)
	}
	client_unref(c)
	free_all(context.temp_allocator)
	expect_no_leaks(t, track, what, loc)
}
