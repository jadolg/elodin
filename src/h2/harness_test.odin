package h2

import "core:mem"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

import "elodin:loop"
import "elodin:testkit"

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

// RFC 7541 C.3.1: GET http / www.example.com, four fields.
@(private)
REQUEST_BLOCK :: "828684410f7777772e6578616d706c652e636f6d"

@(private)
request_block :: proc() -> []u8 {
	return testkit.unhex(REQUEST_BLOCK)
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
	// Error code and last stream id of the last GOAWAY written.
	goaway_code: Error_Code,
	goaway_last: u32,
	// Error code of the last RST_STREAM written.
	rst_code:    Error_Code,
	// Posted for each HEADERS written, for a test on another thread to wait on.
	headers:     sync.Sema,
}

// The whole frame at `pos^` in `buf` and its body, moving `pos` past it; false at
// the end, or at a frame whose body has not all arrived.
@(private)
next_frame :: proc(buf: []u8, pos: ^int) -> (h: Frame_Header, body: []u8, ok: bool) {
	if pos^ + FRAME_HEADER_SIZE > len(buf) {
		return
	}
	h = parse_frame_header(buf[pos^:]) or_return
	end := pos^ + FRAME_HEADER_SIZE + h.length
	if end > len(buf) {
		return h, nil, false
	}
	body = buf[pos^ + FRAME_HEADER_SIZE:end]
	pos^ = end
	return h, body, true
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
	for h, body in next_frame(buf, &pos) {
		append(&log.frames, h)
		if h.type == .Headers {
			sync.sema_post(&log.headers)
		}
		if h.type == .Window_Update && h.stream_id == 0 && len(body) == 4 {
			log.credit += int(read_u32(body))
		}
		if h.type == .Goaway && len(body) >= 8 {
			log.goaway_code = Error_Code(read_u32(body[4:]))
			log.goaway_last = read_u32(body)
		}
		if h.type == .Rst_Stream && len(body) >= 4 {
			log.rst_code = Error_Code(read_u32(body))
		}
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

@(test)
test_count_frames_keeps_to_the_stream_asked_for :: proc(t: ^testing.T) {
	log := Frame_Log {
		frames = make([dynamic]Frame_Header, 0, 4, context.temp_allocator),
	}
	append(&log.frames, Frame_Header{type = .Rst_Stream, stream_id = 1})
	append(&log.frames, Frame_Header{type = .Rst_Stream, stream_id = 3})
	append(&log.frames, Frame_Header{type = .Data, stream_id = 3})
	testing.expect_value(t, count_frames(&log, .Rst_Stream), 2)
	testing.expect_value(t, count_frames(&log, .Rst_Stream, 1), 1)
	testing.expect_value(t, count_frames(&log, .Rst_Stream, 5), 0)
	testing.expect_value(t, count_frames(&log, .Data, 1), 0)
	free_all(context.temp_allocator)
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

@(private)
Header_Log :: struct {
	block: [dynamic]u8,
}

// Keeps the header block of the first HEADERS frame written.
@(private)
log_headers :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Header_Log)user
	pos := 0
	if len(buf) >= len(PREFACE) && string(buf[:len(PREFACE)]) == PREFACE {
		pos = len(PREFACE)
	}
	for h, body in next_frame(buf, &pos) {
		if h.type == .Headers && len(log.block) == 0 {
			append(&log.block, ..body)
		}
	}
	return true
}

// The value of `name` in the logged header block; "" when it is absent.
@(private)
logged_field :: proc(log: ^Header_Log, name: string) -> (value: string, err: Hpack_Error) {
	table: Dynamic_Table
	dynamic_table_init(&table, DEFAULT_HEADER_TABLE_SIZE, context.temp_allocator)
	headers := decode(&table, log.block[:], context.temp_allocator) or_return
	for f in headers {
		if f.name == name {
			return f.value, .None
		}
	}
	return "", .None
}

// Ends a tracked server test: the log, the connection, then the leak check.
@(private)
conn_done :: proc(t: ^testing.T, c: ^Conn, track: ^mem.Tracking_Allocator, what: string, log: ^Frame_Log = nil, loc := #caller_location) {
	if log != nil {
		delete(log.frames)
	}
	conn_unref(c)
	free_all(context.temp_allocator)
	testkit.expect_no_leaks(t, track, what, loc = loc)
}

// Ends a tracked client test: the log, the client, then the leak check.
@(private)
client_done :: proc(t: ^testing.T, c: ^Client, track: ^mem.Tracking_Allocator, what: string, log: ^Frame_Log = nil, loc := #caller_location) {
	if log != nil {
		delete(log.frames)
	}
	client_unref(c)
	free_all(context.temp_allocator)
	testkit.expect_no_leaks(t, track, what, loc = loc)
}

/*
Waits for `n` waiters to be parked on `c`: a thread in `cond_wait` is on its
list from before it lets its lock go until it is woken. False after five
seconds.
*/
@(private)
wait_for_waiter :: proc(c: ^loop.Cond, n := 1) -> bool {
	deadline := time.tick_add(time.tick_now(), 5 * time.Second)
	for time.tick_diff(time.tick_now(), deadline) > 0 {
		sync.mutex_lock(&c.mu)
		parked := 0
		for w := c.waiters.head; w != nil; w = w.next {
			parked += 1
		}
		sync.mutex_unlock(&c.mu)
		if parked >= n {
			return true
		}
		time.sleep(time.Millisecond) // lint:allow the poll's interval; the deadline above bounds it, and a waiter parking posts nothing
	}
	return false
}

// Bytes for `read_frame` to read, as the wire would hand them over.
@(private)
Wire :: struct {
	bytes: []u8,
	pos:   int,
}

@(private)
wire_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	w := cast(^Wire)user
	n = copy(buf, w.bytes[w.pos:])
	w.pos += n
	return n, n > 0
}

// Feeds `serve` a scripted byte stream and records the code of any GOAWAY the
// connection writes back, so the frame loop can be driven end to end.
@(private)
Serve_Harness :: struct {
	in_data:    []u8,
	in_pos:     int,
	// Every byte written, so a frame split across writes is still parsed whole.
	written:    [dynamic]u8,
	saw_goaway: bool,
	code:       Error_Code,
	// The last GOAWAY's last stream id.
	last:       u32,
	// Whatever a test's own write hook needs.
	user:       rawptr,
}

@(private)
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
@(private)
serve_harness_write :: proc(user: rawptr, buf: []u8) -> bool {
	h := cast(^Serve_Harness)user
	append(&h.written, ..buf)
	// A frame whose body has not all arrived ends the scan; the write that
	// carries the rest scans it again.
	pos := 0
	for fh, body in next_frame(h.written[:], &pos) {
		if fh.type == .Goaway && len(body) >= 8 {
			h.saw_goaway = true
			h.code = Error_Code(read_u32(body[4:]))
			h.last = read_u32(body)
		}
	}
	return true
}

/*
Records what a connection wrote back and how many requests reached the handler,
which together say whether a header list was served or turned away.
*/
@(private)
Request_Log :: struct {
	rsts:       int,
	rst_code:   Error_Code,
	goaway:     bool,
	dispatched: int,
	// The last dispatched request's, cloned onto the temporary allocator.
	authority:  string,
	body:       string,
}

@(private)
request_log_write :: proc(user: rawptr, buf: []u8) -> bool {
	log := cast(^Request_Log)user
	if log == nil {
		return true
	}
	pos := 0
	for h, body in next_frame(buf, &pos) {
		#partial switch h.type {
		case .Rst_Stream:
			if len(body) >= 4 {
				log.rsts += 1
				log.rst_code = Error_Code(read_u32(body))
			}
		case .Goaway:
			log.goaway = true
		}
	}
	return true
}

@(private)
counting_handler :: proc(conn: ^Conn, req: ^Request) {
	log := cast(^Request_Log)conn.user
	if log != nil {
		log.dispatched += 1
		log.authority = strings.clone(req.authority, context.temp_allocator)
		log.body = strings.clone(string(req.body), context.temp_allocator)
	}
	request_destroy(conn, req)
}

/*
A stream this end opened as `id`, with its body and window as client_request
would leave them.
*/
@(private)
open_test_stream :: proc(c: ^Client, id: u32, allocator: mem.Allocator) -> ^Client_Stream {
	s := new(Client_Stream, allocator)
	s.id = id
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 8, allocator)
	c.streams[id] = s
	c.next_stream_id = id + 2
	return s
}

// Posts `headers` and `data` as each kind of frame goes out, for a test on
// another thread to wait on.
@(private)
Frame_Signal :: struct {
	headers: sync.Sema,
	data:    sync.Sema,
}

@(private)
signal_write :: proc(user: rawptr, buf: []u8) -> bool {
	sig := cast(^Frame_Signal)user
	if h, ok := parse_frame_header(buf); ok {
		#partial switch h.type {
		case .Headers:
			sync.sema_post(&sig.headers)
		case .Data:
			sync.sema_post(&sig.data)
		}
	}
	return true
}

// Hands every request to `backing`, but holds the `block_at`th until `release`
// is posted, and then refuses it, posting `reached` first.
@(private)
Gate :: struct {
	backing:  mem.Allocator,
	seen:     int,
	block_at: int,
	reached:  sync.Sema,
	release:  sync.Sema,
}

@(private)
gate_proc :: proc(
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
	g := cast(^Gate)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		g.seen += 1
		if g.seen == g.block_at {
			sync.sema_post(&g.reached)
			sync.sema_wait(&g.release)
			return nil, .Out_Of_Memory
		}
	}
	return g.backing.procedure(g.backing.data, mode, size, alignment, old_memory, old_size, loc)
}

// One frame, header and payload, in the temp allocator.
@(private)
frame_bytes :: proc(type: Frame_Type, flags: u8, stream_id: u32, payload: []u8) -> []u8 {
	out := make([dynamic]u8, 0, FRAME_HEADER_SIZE + len(payload), context.temp_allocator)
	write_frame_header(&out, len(payload), type, flags, stream_id)
	append(&out, ..payload)
	return out[:]
}

// Marks `c` closed and wakes every response parked on it, as a connection going
// away does, so a test's join cannot hang on a wait it already failed.
@(private)
close_conn :: proc(c: ^Conn) {
	loop.lock(&c.mu)
	c.closed = true
	loop.cond_broadcast(&c.cond)
	loop.unlock(&c.mu)
}

// A handler that releases its request and leaves the stream unanswered.
@(private)
destroying_handler :: proc(conn: ^Conn, req: ^Request) {
	request_destroy(conn, req)
}

// A handler that does nothing with its request.
@(private)
ignore_request :: proc(conn: ^Conn, req: ^Request) {
}

// x-t: 1, a literal with incremental indexing: it becomes dynamic index 62, so
// a decoder that skipped it falls out of step with the peer's encoder.
// RST_STREAM's payload for CANCEL.
@(private)
RST_CANCEL :: [4]u8{0, 0, 0, u8(Error_Code.Cancel)}

@(private)
TRAILER :: [?]u8{0x40, 0x03, 'x', '-', 't', 0x01, '1'}
