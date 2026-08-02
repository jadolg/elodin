package h2

import "core:mem"
import "core:strings"
import "core:sync"

/*
A server-side HTTP/2 connection, scoped to what a DoH endpoint needs.

Requests are delivered to a handler which may answer inline or hand the work to
another thread and call `respond` later; the connection is reference counted so
a late responder cannot outlive it. Writes are serialised, so responses may be
produced concurrently and interleave on the wire in any order — which is the
point of running HTTP/2 at all, since a browser resolving a name sends its A and
AAAA queries at the same time.

Not implemented, because a DoH endpoint never needs them: server push (refused
in SETTINGS), stream priority (parsed and ignored, as RFC 9113 permits), and
the extended CONNECT protocol.
*/

// Transport, so this package does not depend on the TLS layer.
IO :: struct {
	user:  rawptr,
	read:  proc(user: rawptr, buf: []u8) -> (n: int, ok: bool),
	write: proc(user: rawptr, buf: []u8) -> bool,
}

Request :: struct {
	stream_id:    u32,
	method:       string,
	path:         string,
	authority:    string,
	scheme:       string,
	content_type: string,
	accept:       string,
	body:         []u8,
	// Scratch owning every string and slice above; released with the stream.
	allocator:    mem.Allocator,
}

Response :: struct {
	status:        int,
	content_type:  string,
	cache_control: string,
	body:          []u8,
}

Handler :: #type proc(conn: ^Conn, req: ^Request)

MAX_CONCURRENT :: 128
// Advertised receive window. Generous, so a client streaming request bodies is
// never throttled by us; DoH bodies are tiny anyway.
RECV_WINDOW :: 1 << 20

Stream_State :: enum u8 {
	Open,
	Half_Closed_Remote,
	Closed,
}

Stream :: struct {
	id:           u32,
	state:        Stream_State,
	header_block: [dynamic]u8,
	body:         [dynamic]u8,
	end_stream:   bool,
	// Set when the peer resets the stream, so a response in flight is dropped.
	cancelled:    bool,
	send_window:  int,
	// Request parked between its headers and the end of its body.
	pending:      ^Request,
}

Conn :: struct {
	io:              IO,
	handler:         Handler,
	user:            rawptr,

	mu:              sync.Mutex,
	cond:            sync.Cond,
	refs:            int,
	closed:          bool,

	// Peer settings that govern what we may send.
	peer_max_frame:  int,
	peer_initial_window: int,
	send_window:     int,

	decoder:         Dynamic_Table,
	streams:         map[u32]^Stream,
	last_stream_id:  u32,
	goaway_sent:     bool,

	allocator:       mem.Allocator,
	// Scratch for a header block spanning CONTINUATION frames.
	continuation_on: u32,
}

make_conn :: proc(io: IO, handler: Handler, user: rawptr, allocator := context.allocator) -> ^Conn {
	c := new(Conn, allocator)
	c.io = io
	c.handler = handler
	c.user = user
	c.allocator = allocator
	c.refs = 1
	c.peer_max_frame = DEFAULT_MAX_FRAME
	c.peer_initial_window = DEFAULT_WINDOW
	c.send_window = DEFAULT_WINDOW
	c.streams = make(map[u32]^Stream, 16, allocator)
	dynamic_table_init(&c.decoder, 4096, allocator)
	return c
}

// Take a reference before handing the connection to another thread.
conn_ref :: proc(c: ^Conn) {
	sync.mutex_lock(&c.mu)
	c.refs += 1
	sync.mutex_unlock(&c.mu)
}

conn_unref :: proc(c: ^Conn) {
	sync.mutex_lock(&c.mu)
	c.refs -= 1
	last := c.refs == 0
	// Wakes anyone in conn_wait_idle.
	sync.cond_broadcast(&c.cond)
	sync.mutex_unlock(&c.mu)
	if !last {
		return
	}

	for _, s in c.streams {
		stream_destroy(c, s)
	}
	delete(c.streams)
	dynamic_table_destroy(&c.decoder)
	free(c, c.allocator)
}

@(private)
stream_destroy :: proc(c: ^Conn, s: ^Stream) {
	// A request parked between its headers and a body that never arrived is
	// owned by the stream, not by a handler; only a dispatched one is released
	// by whoever answered it.
	request_destroy(c, s.pending)
	delete(s.header_block)
	delete(s.body)
	free(s, c.allocator)
}

/*
Block until every handler has finished, leaving only the caller's reference.

Serving code calls this after `serve` returns and before dropping its own
reference, so a handler still running on another thread cannot reach for a
transport its owner has already torn down. Handlers waiting on flow control are
released by the close that `serve` performs on its way out, so this cannot wait
indefinitely on a dead peer.
*/
conn_wait_idle :: proc(c: ^Conn) {
	sync.mutex_lock(&c.mu)
	for c.refs > 1 {
		sync.cond_wait(&c.cond, &c.mu)
	}
	sync.mutex_unlock(&c.mu)
}

/*
Run the connection until the peer goes away or the protocol is violated.

Returns once no more frames will be read. In-flight handlers may still be
running; they hold their own references.
*/
serve :: proc(c: ^Conn) {
	defer {
		sync.mutex_lock(&c.mu)
		c.closed = true
		sync.cond_broadcast(&c.cond)
		sync.mutex_unlock(&c.mu)
	}

	if !read_preface(c) {
		return
	}
	if !send_initial_settings(c) {
		return
	}

	header: [FRAME_HEADER_SIZE]u8
	for {
		if !read_exact(c, header[:]) {
			return
		}
		h, ok := parse_frame_header(header[:])
		if !ok {
			return
		}
		if h.length > RECV_WINDOW {
			goaway(c, .Frame_Size_Error)
			return
		}

		payload: []u8
		if h.length > 0 {
			payload = make([]u8, h.length, context.temp_allocator)
			if !read_exact(c, payload) {
				return
			}
		}

		// A header block may not be interrupted by frames for other streams.
		if c.continuation_on != 0 && (h.type != .Continuation || h.stream_id != c.continuation_on) {
			goaway(c, .Protocol_Error)
			return
		}

		if !handle_frame(c, h, payload) {
			return
		}
		free_all(context.temp_allocator)
	}
}

@(private)
read_preface :: proc(c: ^Conn) -> bool {
	buf: [len(PREFACE)]u8
	if !read_exact(c, buf[:]) {
		return false
	}
	return string(buf[:]) == PREFACE
}

@(private)
read_exact :: proc(c: ^Conn, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, ok := c.io.read(c.io.user, buf[got:])
		if !ok || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

@(private)
write_all :: proc(c: ^Conn, buf: []u8) -> bool {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	if c.closed {
		return false
	}
	return c.io.write(c.io.user, buf)
}

@(private)
send_initial_settings :: proc(c: ^Conn) -> bool {
	out := make([dynamic]u8, 0, 64, context.temp_allocator)
	// SETTINGS_ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE.
	write_frame_header(&out, 18, .Settings, 0, 0)
	append(&out, 0, u8(Setting.Enable_Push))
	append_u32(&out, 0)
	append(&out, 0, u8(Setting.Max_Concurrent_Streams))
	append_u32(&out, MAX_CONCURRENT)
	append(&out, 0, u8(Setting.Initial_Window_Size))
	append_u32(&out, RECV_WINDOW)

	// Raise the connection-level receive window to match.
	write_frame_header(&out, 4, .Window_Update, 0, 0)
	append_u32(&out, RECV_WINDOW - DEFAULT_WINDOW)
	return write_all(c, out[:])
}

@(private)
handle_frame :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	#partial switch h.type {
	case .Settings:
		return handle_settings(c, h, payload)

	case .Ping:
		if h.stream_id != 0 || len(payload) != 8 {
			goaway(c, .Protocol_Error)
			return false
		}
		if h.flags & FLAG_ACK != 0 {
			return true
		}
		out := make([dynamic]u8, 0, 17, context.temp_allocator)
		write_frame_header(&out, 8, .Ping, FLAG_ACK, 0)
		append(&out, ..payload)
		return write_all(c, out[:])

	case .Window_Update:
		return handle_window_update(c, h, payload)

	case .Headers:
		return handle_headers(c, h, payload)

	case .Continuation:
		return handle_continuation(c, h, payload)

	case .Data:
		return handle_data(c, h, payload)

	case .Rst_Stream:
		sync.mutex_lock(&c.mu)
		if s, found := c.streams[h.stream_id]; found {
			s.cancelled = true
			s.state = .Closed
		}
		sync.mutex_unlock(&c.mu)
		return true

	case .Priority:
		// Parsed and ignored: RFC 9113 deprecates the scheme and a resolver has
		// nothing useful to do with it.
		return true

	case .Goaway:
		return false

	case .Push_Promise:
		// A client may not push.
		goaway(c, .Protocol_Error)
		return false
	}
	// Unknown frame types must be ignored (RFC 9113 section 4.1).
	return true
}

@(private)
handle_settings :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if h.flags & FLAG_ACK != 0 {
		return len(payload) == 0
	}
	if h.stream_id != 0 || len(payload) % 6 != 0 {
		goaway(c, .Protocol_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	for i := 0; i + 6 <= len(payload); i += 6 {
		id := Setting(read_u16(payload[i:]))
		value := read_u32(payload[i + 2:])
		#partial switch id {
		case .Max_Frame_Size:
			if value < DEFAULT_MAX_FRAME || value > 16777215 {
				sync.mutex_unlock(&c.mu)
				goaway(c, .Protocol_Error)
				return false
			}
			c.peer_max_frame = int(value)
		case .Initial_Window_Size:
			if value > MAX_WINDOW {
				sync.mutex_unlock(&c.mu)
				goaway(c, .Flow_Control_Error)
				return false
			}
			// A change retroactively adjusts every open stream's window.
			delta := int(value) - c.peer_initial_window
			c.peer_initial_window = int(value)
			for _, s in c.streams {
				s.send_window += delta
			}
			sync.cond_broadcast(&c.cond)
		}
	}
	sync.mutex_unlock(&c.mu)

	out := make([dynamic]u8, 0, FRAME_HEADER_SIZE, context.temp_allocator)
	write_frame_header(&out, 0, .Settings, FLAG_ACK, 0)
	return write_all(c, out[:])
}

@(private)
handle_window_update :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if len(payload) != 4 {
		goaway(c, .Frame_Size_Error)
		return false
	}
	increment := int(read_u32(payload) & 0x7fff_ffff)
	if increment == 0 {
		goaway(c, .Protocol_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	overflow := false
	if h.stream_id == 0 {
		c.send_window += increment
		overflow = c.send_window > MAX_WINDOW
	} else if s, found := c.streams[h.stream_id]; found {
		s.send_window += increment
		overflow = s.send_window > MAX_WINDOW
	}
	sync.cond_broadcast(&c.cond)
	sync.mutex_unlock(&c.mu)

	if overflow {
		goaway(c, .Flow_Control_Error)
		return false
	}
	return true
}

@(private)
handle_headers :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if h.stream_id == 0 || h.stream_id % 2 == 0 {
		goaway(c, .Protocol_Error)
		return false
	}

	body, ok := strip_padding(payload, h.flags)
	if !ok {
		goaway(c, .Protocol_Error)
		return false
	}
	block, pok := strip_priority(body, h.flags)
	if !pok {
		goaway(c, .Protocol_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	if h.stream_id <= c.last_stream_id {
		sync.mutex_unlock(&c.mu)
		goaway(c, .Protocol_Error)
		return false
	}
	if len(c.streams) >= MAX_CONCURRENT {
		sync.mutex_unlock(&c.mu)
		return rst_stream(c, h.stream_id, .Refused_Stream)
	}
	c.last_stream_id = h.stream_id

	s := new(Stream, c.allocator)
	s.id = h.stream_id
	s.state = .Open
	s.send_window = c.peer_initial_window
	s.header_block = make([dynamic]u8, 0, len(block), c.allocator)
	s.body = make([dynamic]u8, 0, 512, c.allocator)
	append(&s.header_block, ..block)
	s.end_stream = h.flags & FLAG_END_STREAM != 0
	c.streams[h.stream_id] = s
	sync.mutex_unlock(&c.mu)

	if h.flags & FLAG_END_HEADERS == 0 {
		c.continuation_on = h.stream_id
		return true
	}
	return finish_headers(c, s)
}

@(private)
handle_continuation :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if c.continuation_on != h.stream_id {
		goaway(c, .Protocol_Error)
		return false
	}
	sync.mutex_lock(&c.mu)
	s, found := c.streams[h.stream_id]
	if found {
		append(&s.header_block, ..payload)
	}
	sync.mutex_unlock(&c.mu)
	if !found {
		goaway(c, .Protocol_Error)
		return false
	}

	if h.flags & FLAG_END_HEADERS == 0 {
		return true
	}
	c.continuation_on = 0
	return finish_headers(c, s)
}

/*
Decode a completed header block and, if the request is already complete,
dispatch it.

HPACK state is per connection and order-dependent, so the block must be decoded
here on the reader thread even when the request body has yet to arrive.
*/
@(private)
finish_headers :: proc(c: ^Conn, s: ^Stream) -> bool {
	headers, err := decode(&c.decoder, s.header_block[:], c.allocator)
	if err != .None {
		goaway(c, .Compression_Error)
		return false
	}
	// The block is decoded; keep only the fields.
	clear(&s.header_block)

	req := new(Request, c.allocator)
	req.stream_id = s.id
	req.allocator = c.allocator
	// A repeated field would otherwise orphan the value it replaces, which a
	// peer could exploit to make the connection hold memory without limit.
	take :: proc(dst: ^string, value: string, allocator: mem.Allocator) {
		if dst^ != "" {
			delete(value, allocator)
			return
		}
		dst^ = value
	}

	for f in headers {
		switch f.name {
		case ":method":
			take(&req.method, f.value, c.allocator)
		case ":path":
			take(&req.path, f.value, c.allocator)
		case ":authority":
			take(&req.authority, f.value, c.allocator)
		case ":scheme":
			take(&req.scheme, f.value, c.allocator)
		case "content-type":
			take(&req.content_type, f.value, c.allocator)
		case "accept":
			take(&req.accept, f.value, c.allocator)
		case:
			delete(f.value, c.allocator)
		}
		delete(f.name, c.allocator)
	}
	delete(headers, c.allocator)

	sync.mutex_lock(&c.mu)
	s.state = .Half_Closed_Remote if s.end_stream else .Open
	complete := s.end_stream
	sync.mutex_unlock(&c.mu)

	if !complete {
		// Park the request until the body arrives.
		s.pending = req
		return true
	}
	return dispatch(c, s, req)
}

@(private)
handle_data :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	data, ok := strip_padding(payload, h.flags)
	if !ok {
		goaway(c, .Protocol_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	s, found := c.streams[h.stream_id]
	if found {
		// Checked before appending, so an oversized body is refused rather than
		// buffered first.
		if len(s.body) + len(data) > MAX_BODY {
			sync.mutex_unlock(&c.mu)
			sent := rst_stream(c, h.stream_id, .Enhance_Your_Calm)
			// The stream is over. Without this it would hold its body, its parked
			// request and one of MAX_CONCURRENT slots until the connection went.
			close_stream(c, h.stream_id)
			return sent
		}
		append(&s.body, ..data)
	}
	sync.mutex_unlock(&c.mu)

	// Give the credit straight back; we buffer whole requests anyway.
	if len(payload) > 0 {
		out := make([dynamic]u8, 0, 26, context.temp_allocator)
		write_frame_header(&out, 4, .Window_Update, 0, 0)
		append_u32(&out, u32(len(payload)))
		if found && h.flags & FLAG_END_STREAM == 0 {
			write_frame_header(&out, 4, .Window_Update, 0, h.stream_id)
			append_u32(&out, u32(len(payload)))
		}
		if !write_all(c, out[:]) {
			return false
		}
	}

	if !found || h.flags & FLAG_END_STREAM == 0 {
		return true
	}

	sync.mutex_lock(&c.mu)
	s.state = .Half_Closed_Remote
	req := s.pending
	s.pending = nil
	sync.mutex_unlock(&c.mu)

	if req == nil {
		// DATA before HEADERS completed.
		goaway(c, .Protocol_Error)
		return false
	}
	return dispatch(c, s, req)
}

@(private)
dispatch :: proc(c: ^Conn, s: ^Stream, req: ^Request) -> bool {
	if len(s.body) > 0 {
		body := make([]u8, len(s.body), c.allocator)
		copy(body, s.body[:])
		req.body = body
	}
	c.handler(c, req)
	return true
}

// Release a request once its handler is finished with it.
request_destroy :: proc(c: ^Conn, req: ^Request) {
	if req == nil {
		return
	}
	delete(req.method, req.allocator)
	delete(req.path, req.allocator)
	delete(req.authority, req.allocator)
	delete(req.scheme, req.allocator)
	delete(req.content_type, req.allocator)
	delete(req.accept, req.allocator)
	if req.body != nil {
		delete(req.body, req.allocator)
	}
	free(req, req.allocator)
}

MAX_BODY :: 64 * 1024

@(private)
rst_stream :: proc(c: ^Conn, stream_id: u32, code: Error_Code) -> bool {
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	write_frame_header(&out, 4, .Rst_Stream, 0, stream_id)
	append_u32(&out, u32(code))
	return write_all(c, out[:])
}

@(private)
goaway :: proc(c: ^Conn, code: Error_Code) {
	sync.mutex_lock(&c.mu)
	if c.goaway_sent {
		sync.mutex_unlock(&c.mu)
		return
	}
	c.goaway_sent = true
	last := c.last_stream_id
	sync.mutex_unlock(&c.mu)

	out := make([dynamic]u8, 0, 17, context.temp_allocator)
	write_frame_header(&out, 8, .Goaway, 0, 0)
	append_u32(&out, last)
	append_u32(&out, u32(code))
	_ = write_all(c, out[:])
}

/*
Send a response and close the stream.

Safe to call from any thread. Blocks while the peer's flow-control window has no
room, waking when a WINDOW_UPDATE arrives or the connection closes.
*/
respond :: proc(c: ^Conn, stream_id: u32, resp: Response) -> bool {
	sync.mutex_lock(&c.mu)
	s, found := c.streams[stream_id]
	cancelled := found && s.cancelled
	sync.mutex_unlock(&c.mu)
	if cancelled {
		close_stream(c, stream_id)
		return true
	}

	block := make([dynamic]u8, 0, 128, context.temp_allocator)
	encode_header(&block, ":status", status_text(resp.status))
	if resp.content_type != "" {
		encode_header(&block, "content-type", resp.content_type)
	}
	if resp.cache_control != "" {
		encode_header(&block, "cache-control", resp.cache_control)
	}
	encode_header(&block, "content-length", int_to_string(len(resp.body), context.temp_allocator))
	encode_header(&block, "server", "elodin")

	out := make([dynamic]u8, 0, len(block) + 32, context.temp_allocator)
	end_stream := u8(FLAG_END_STREAM) if len(resp.body) == 0 else 0
	write_frame_header(&out, len(block), .Headers, FLAG_END_HEADERS | end_stream, stream_id)
	append(&out, ..block[:])
	if !write_all(c, out[:]) {
		close_stream(c, stream_id)
		return false
	}

	if len(resp.body) > 0 {
		if !write_body(c, stream_id, resp.body) {
			close_stream(c, stream_id)
			return false
		}
	}
	close_stream(c, stream_id)
	return true
}

/*
Write a response body, honouring flow control and the peer's frame size limit.
*/
@(private)
write_body :: proc(c: ^Conn, stream_id: u32, body: []u8) -> bool {
	sent := 0
	for sent < len(body) {
		remaining := len(body) - sent

		sync.mutex_lock(&c.mu)
		chunk := 0
		for {
			if c.closed {
				sync.mutex_unlock(&c.mu)
				return false
			}
			s, found := c.streams[stream_id]
			if !found || s.cancelled {
				sync.mutex_unlock(&c.mu)
				return true
			}
			available := min(c.send_window, s.send_window)
			available = min(available, c.peer_max_frame)
			available = min(available, remaining)
			if available > 0 {
				chunk = available
				c.send_window -= chunk
				s.send_window -= chunk
				break
			}
			// No credit; a WINDOW_UPDATE or a close will wake us.
			sync.cond_wait(&c.cond, &c.mu)
		}
		sync.mutex_unlock(&c.mu)

		last := sent + chunk >= len(body)
		out := make([dynamic]u8, 0, chunk + FRAME_HEADER_SIZE, context.temp_allocator)
		write_frame_header(&out, chunk, .Data, u8(FLAG_END_STREAM) if last else 0, stream_id)
		append(&out, ..body[sent:sent + chunk])
		if !write_all(c, out[:]) {
			return false
		}
		sent += chunk
	}
	return true
}

@(private)
close_stream :: proc(c: ^Conn, stream_id: u32) {
	sync.mutex_lock(&c.mu)
	s, found := c.streams[stream_id]
	if found {
		delete_key(&c.streams, stream_id)
	}
	sync.mutex_unlock(&c.mu)
	if found {
		stream_destroy(c, s)
	}
}

@(private)
status_text :: proc(status: int) -> string {
	switch status {
	case 200:
		return "200"
	case 400:
		return "400"
	case 404:
		return "404"
	case 405:
		return "405"
	case 413:
		return "413"
	case 415:
		return "415"
	case 500:
		return "500"
	}
	return "500"
}

@(private)
int_to_string :: proc(v: int, allocator: mem.Allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_int(&b, v)
	return strings.to_string(b)
}
