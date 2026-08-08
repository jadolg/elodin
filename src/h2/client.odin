package h2

import "core:mem"
import "core:sync"
import "core:time"

/*
A multiplexed HTTP/2 client connection (RFC 9113), for talking to upstream DoH
servers.

One connection is shared by every concurrent caller: `client_request` opens a
new stream, writes it, and blocks until that stream's response arrives, while
a single background reader (`client_serve`, meant to run on its own thread)
demultiplexes frames for every open stream at once. That is the point of
running HTTP/2 on the upstream side rather than the HTTP/1.1
request-per-connection pool the plain client uses: concurrent DNS queries to
the same resolver share one TCP connection instead of tying up one each.

Not implemented, because a DNS client never needs them: server push (refused
via SETTINGS_ENABLE_PUSH=0; a peer that sends one anyway is treated as a
protocol violation) and splitting our own header blocks across CONTINUATION
frames (a DoH request is a handful of short headers, always one frame). A
response's headers may still arrive split, and that direction is handled.
*/

Client :: struct {
	io: IO,

	mu:     sync.Mutex,
	cond:   sync.Cond,
	refs:   int,
	closed: bool,

	next_stream_id:      u32,
	peer_max_frame:      int,
	peer_initial_window: int,
	send_window:         int,

	decoder:             Dynamic_Table,
	streams:             map[u32]^Client_Stream,
	// Scratch for a response header block spanning CONTINUATION frames. Only
	// the reader goroutine touches this, so it needs no lock.
	header_scratch:      [dynamic]u8,
	continuation_on:     u32,
	// How many CONTINUATION frames have arrived for the block currently open.
	continuation_frames: int,

	allocator: mem.Allocator,
}

Client_Stream :: struct {
	id:          u32,
	status:      int,
	body:        [dynamic]u8,
	end_stream:  bool,
	// Set once the response is complete (headers with END_STREAM, or the DATA
	// frame that carries it).
	done:        bool,
	// Set when the peer resets the stream.
	reset:       bool,
	send_window: int,
}

Client_Request :: struct {
	method:       string,
	scheme:       string,
	authority:    string,
	path:         string,
	content_type: string,
	accept:       string,
	body:         []u8,
}

Client_Response :: struct {
	status: int,
	body:   []u8,
}

Client_Error :: enum u8 {
	None,
	// The connection is dead: a read/write failure, GOAWAY, or a protocol
	// violation. The caller should dial a fresh connection.
	Closed,
	// The peer reset our stream.
	Reset,
	Timeout,
}

// Advertised receive window: generous, so we are never the reason a DoH
// response stalls. Answers are tiny; this covers many of them arriving at
// once across every multiplexed stream.
CLIENT_RECV_WINDOW :: 1 << 20
// Bound on one response body. The h2 package does not depend on the dns
// package, so DNS's own message size limit is restated here.
CLIENT_MAX_BODY :: 64 * 1024

client_make :: proc(io: IO, allocator := context.allocator) -> ^Client {
	c := new(Client, allocator)
	c.io = io
	c.allocator = allocator
	c.refs = 1
	c.next_stream_id = 1
	c.peer_max_frame = DEFAULT_MAX_FRAME
	c.peer_initial_window = DEFAULT_WINDOW
	c.send_window = DEFAULT_WINDOW
	c.streams = make(map[u32]^Client_Stream, 16, allocator)
	c.header_scratch = make([dynamic]u8, 0, 256, allocator)
	dynamic_table_init(&c.decoder, DEFAULT_HEADER_TABLE_SIZE, allocator)

	// Sent here rather than from client_serve so it happens before this
	// procedure returns: client_serve only starts once the caller has spawned
	// it on its own thread, by which point a concurrent client_request could
	// otherwise have already written a HEADERS frame as the connection's first
	// bytes, corrupting the preface.
	if !client_send_preface(c) {
		c.closed = true
	}
	return c
}

// Take a reference before handing the connection to another caller.
// `client_request` takes its own for the length of the call, so this is only
// needed by code that keeps a pointer to `c` around between calls.
client_ref :: proc(c: ^Client) {
	sync.mutex_lock(&c.mu)
	c.refs += 1
	sync.mutex_unlock(&c.mu)
}

client_unref :: proc(c: ^Client) {
	sync.mutex_lock(&c.mu)
	c.refs -= 1
	last := c.refs == 0
	sync.mutex_unlock(&c.mu)
	if !last {
		return
	}
	for _, s in c.streams {
		client_stream_destroy(c, s)
	}
	delete(c.streams)
	delete(c.header_scratch)
	dynamic_table_destroy(&c.decoder)
	free(c, c.allocator)
}

@(private)
client_stream_destroy :: proc(c: ^Client, s: ^Client_Stream) {
	delete(s.body)
	free(s, c.allocator)
}

// Whether the connection is known dead. Callers check this before reusing a
// cached connection and dial a fresh one instead of reusing this one.
client_closed :: proc(c: ^Client) -> bool {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	return c.closed
}

/*
Run the connection until the peer goes away or the protocol is violated.

Meant to run on its own thread, started by the caller right after
`client_make` (which has already sent the preface). Returns once no more
frames will be read; callers blocked in `client_request` are released by the
close this performs on its way out.
*/
client_serve :: proc(c: ^Client) {
	defer {
		sync.mutex_lock(&c.mu)
		c.closed = true
		sync.cond_broadcast(&c.cond)
		sync.mutex_unlock(&c.mu)
	}

	header: [FRAME_HEADER_SIZE]u8
	for {
		if !client_read_exact(c, header[:]) {
			return
		}
		h, ok := parse_frame_header(header[:])
		if !ok {
			return
		}
		// Bounded at the frame size we advertise, not at the receive window: we
		// send no SETTINGS_MAX_FRAME_SIZE, so an upstream is held to the RFC 9113
		// 6.5.2 default (16384). The window still caps how much of a response we
		// buffer; this caps a single frame off the wire.
		if h.length > DEFAULT_MAX_FRAME {
			client_goaway(c, .Frame_Size_Error)
			return
		}

		payload: []u8
		if h.length > 0 {
			payload = make([]u8, h.length, context.temp_allocator)
			if !client_read_exact(c, payload) {
				return
			}
		}

		// A response header block may not be interrupted by frames for other
		// streams.
		if c.continuation_on != 0 && (h.type != .Continuation || h.stream_id != c.continuation_on) {
			client_goaway(c, .Protocol_Error)
			return
		}

		if !client_handle_frame(c, h, payload) {
			return
		}
		free_all(context.temp_allocator)
	}
}

@(private)
client_read_exact :: proc(c: ^Client, buf: []u8) -> bool {
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
client_write_all :: proc(c: ^Client, buf: []u8) -> bool {
	sync.mutex_lock(&c.mu)
	defer sync.mutex_unlock(&c.mu)
	if c.closed {
		return false
	}
	return c.io.write(c.io.user, buf)
}

@(private)
client_send_preface :: proc(c: ^Client) -> bool {
	out := make([dynamic]u8, 0, len(PREFACE) + 32, context.temp_allocator)
	append(&out, ..transmute([]u8)string(PREFACE))

	// SETTINGS_ENABLE_PUSH=0: a DNS client has no use for server push, and
	// disabling it up front turns a PUSH_PROMISE we then see into a clear
	// protocol violation rather than something to handle.
	// SETTINGS_INITIAL_WINDOW_SIZE raised to match the connection window
	// below, so the peer is never throttled sending us a response.
	// SETTINGS_HEADER_TABLE_SIZE states the size this end's decoder was built
	// with, which is the ceiling `decode` holds an upstream's table size
	// updates to.
	write_frame_header(&out, 24, .Settings, 0, 0)
	append(&out, 0, u8(Setting.Header_Table_Size))
	append_u32(&out, DEFAULT_HEADER_TABLE_SIZE)
	append(&out, 0, u8(Setting.Enable_Push))
	append_u32(&out, 0)
	append(&out, 0, u8(Setting.Initial_Window_Size))
	append_u32(&out, CLIENT_RECV_WINDOW)
	// So an upstream is told the header bound rather than discovering it as a
	// connection error.
	append(&out, 0, u8(Setting.Max_Header_List_Size))
	append_u32(&out, MAX_HEADER_LIST)

	write_frame_header(&out, 4, .Window_Update, 0, 0)
	append_u32(&out, CLIENT_RECV_WINDOW - DEFAULT_WINDOW)
	return client_write_all(c, out[:])
}

@(private)
client_handle_frame :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	#partial switch h.type {
	case .Settings:
		return client_handle_settings(c, h, payload)

	case .Ping:
		if h.stream_id != 0 || len(payload) != 8 {
			client_goaway(c, .Protocol_Error)
			return false
		}
		if h.flags & FLAG_ACK != 0 {
			return true
		}
		out := make([dynamic]u8, 0, 17, context.temp_allocator)
		write_frame_header(&out, 8, .Ping, FLAG_ACK, 0)
		append(&out, ..payload)
		return client_write_all(c, out[:])

	case .Window_Update:
		return client_handle_window_update(c, h, payload)

	case .Headers:
		return client_handle_headers(c, h, payload)

	case .Continuation:
		return client_handle_continuation(c, h, payload)

	case .Data:
		return client_handle_data(c, h, payload)

	case .Rst_Stream:
		if len(payload) != 4 {
			client_goaway(c, .Frame_Size_Error)
			return false
		}
		sync.mutex_lock(&c.mu)
		if s, found := c.streams[h.stream_id]; found {
			s.reset = true
			sync.cond_broadcast(&c.cond)
		}
		sync.mutex_unlock(&c.mu)
		return true

	case .Priority:
		// Parsed and ignored: RFC 9113 deprecates the scheme and a DNS client
		// has nothing useful to do with it.
		return true

	case .Goaway:
		return false

	case .Push_Promise:
		client_goaway(c, .Protocol_Error)
		return false
	}
	// Unknown frame types must be ignored (RFC 9113 section 4.1).
	return true
}

@(private)
client_handle_settings :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	if h.flags & FLAG_ACK != 0 {
		return len(payload) == 0
	}
	if h.stream_id != 0 || len(payload) % 6 != 0 {
		client_goaway(c, .Protocol_Error)
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
				client_goaway(c, .Protocol_Error)
				return false
			}
			c.peer_max_frame = int(value)
		case .Initial_Window_Size:
			if value > MAX_WINDOW {
				sync.mutex_unlock(&c.mu)
				client_goaway(c, .Flow_Control_Error)
				return false
			}
			// A change retroactively adjusts every open stream's window; see the
			// server's handle_settings for why the result needs checking too.
			delta := int(value) - c.peer_initial_window
			c.peer_initial_window = int(value)
			overflow := false
			for _, s in c.streams {
				s.send_window += delta
				overflow ||= s.send_window > MAX_WINDOW
			}
			sync.cond_broadcast(&c.cond)
			if overflow {
				sync.mutex_unlock(&c.mu)
				client_goaway(c, .Flow_Control_Error)
				return false
			}
		}
	}
	sync.mutex_unlock(&c.mu)

	out := make([dynamic]u8, 0, FRAME_HEADER_SIZE, context.temp_allocator)
	write_frame_header(&out, 0, .Settings, FLAG_ACK, 0)
	return client_write_all(c, out[:])
}

@(private)
client_handle_window_update :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	if len(payload) != 4 {
		client_goaway(c, .Frame_Size_Error)
		return false
	}
	increment := int(read_u32(payload) & 0x7fff_ffff)
	if increment == 0 {
		client_goaway(c, .Protocol_Error)
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
		client_goaway(c, .Flow_Control_Error)
		return false
	}
	return true
}

@(private)
client_handle_headers :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	body, ok := strip_padding(payload, h.flags)
	if !ok {
		client_goaway(c, .Protocol_Error)
		return false
	}
	block, pok := strip_priority(body, h.flags)
	if !pok {
		client_goaway(c, .Protocol_Error)
		return false
	}
	if len(block) > MAX_HEADER_LIST {
		client_goaway(c, .Compression_Error)
		return false
	}

	clear(&c.header_scratch)
	append(&c.header_scratch, ..block)

	sync.mutex_lock(&c.mu)
	if s, found := c.streams[h.stream_id]; found {
		s.end_stream = h.flags & FLAG_END_STREAM != 0
	}
	sync.mutex_unlock(&c.mu)

	if h.flags & FLAG_END_HEADERS == 0 {
		c.continuation_on = h.stream_id
		c.continuation_frames = 0
		return true
	}
	return client_finish_headers(c, h.stream_id)
}

@(private)
client_handle_continuation :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	if c.continuation_on != h.stream_id {
		client_goaway(c, .Protocol_Error)
		return false
	}
	/*
	Bounded as it accumulates, for the same reason as the server side: neither
	HEADERS nor CONTINUATION is flow-controlled, and HPACK's own limit lives in
	`decode`, which never runs for a block whose END_HEADERS never arrives. An
	upstream that sent these without end would otherwise grow this without end.

	Counted as well, because a size cap is no cap against frames that carry
	nothing: an empty CONTINUATION advances neither the block nor this check,
	and holds the reader on a block that never ends.
	*/
	c.continuation_frames += 1
	if c.continuation_frames > MAX_CONTINUATION_FRAMES {
		client_goaway(c, .Enhance_Your_Calm)
		return false
	}
	if len(c.header_scratch) + len(payload) > MAX_HEADER_LIST {
		client_goaway(c, .Compression_Error)
		return false
	}
	append(&c.header_scratch, ..payload)

	if h.flags & FLAG_END_HEADERS == 0 {
		return true
	}
	c.continuation_on = 0
	return client_finish_headers(c, h.stream_id)
}

/*
The `:status` value, which RFC 9113 8.3.2 says is exactly three digits.

`strconv.parse_int` with its default base read more than that: `0x1` came back
as 1, `0b11001000` as 200, `1_0` as 10, and a fourth digit was accepted rather
than noticed. A peer's word for how its answer went then differs here from what
it says anywhere else, which is a poor thing to hang a `== 200` on. Anything
that is not three digits is not a status, and 0 is how a missing one is already
reported.
*/
@(private)
parse_status :: proc(value: string) -> int {
	if len(value) != 3 {
		return 0
	}
	v := 0
	for c in transmute([]u8)value {
		if c < '0' || c > '9' {
			return 0
		}
		v = v * 10 + int(c - '0')
	}
	return v
}

/*
Decode a completed response header block and, if the stream is still tracked,
record its status and completion.

HPACK state is per connection and order-dependent, so the block is decoded
here regardless of whether anyone is still waiting on it — a stream we gave up
on locally (a timeout) must not desynchronise the decoder from the peer's
encoder, or every header block after it would fail to decode too.
*/
@(private)
client_finish_headers :: proc(c: ^Client, stream_id: u32) -> bool {
	headers, err := decode(&c.decoder, c.header_scratch[:], c.allocator)
	clear(&c.header_scratch)
	if err != .None {
		client_goaway(c, .Compression_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	s, found := c.streams[stream_id]
	if found {
		for f in headers {
			if f.name == ":status" {
				s.status = parse_status(f.value)
			}
		}
		if s.end_stream {
			s.done = true
			sync.cond_broadcast(&c.cond)
		}
	}
	sync.mutex_unlock(&c.mu)

	for f in headers {
		delete(f.name, c.allocator)
		delete(f.value, c.allocator)
	}
	delete(headers, c.allocator)
	return true
}

@(private)
client_handle_data :: proc(c: ^Client, h: Frame_Header, payload: []u8) -> bool {
	data, ok := strip_padding(payload, h.flags)
	if !ok {
		client_goaway(c, .Protocol_Error)
		return false
	}

	sync.mutex_lock(&c.mu)
	s, found := c.streams[h.stream_id]
	oversized := false
	if found {
		if len(s.body) + len(data) > CLIENT_MAX_BODY {
			oversized = true
			s.reset = true
		} else {
			append(&s.body, ..data)
		}
	}
	if oversized {
		sync.cond_broadcast(&c.cond)
	}
	sync.mutex_unlock(&c.mu)

	if oversized {
		/*
		The stream is over as far as we are concerned; no point reading more of
		a body we have already discarded. The connection is a different matter -
		these bytes came off it and count against a receive window shared by
		every stream on it, so the credit goes back even though the stream-level
		update does not.
		*/
		if !client_rst_stream(c, h.stream_id, .Enhance_Your_Calm) {
			return false
		}
		return client_give_connection_credit(c, len(payload))
	}

	// Give the credit straight back; we buffer whole responses anyway.
	if len(payload) > 0 {
		out := make([dynamic]u8, 0, 26, context.temp_allocator)
		write_frame_header(&out, 4, .Window_Update, 0, 0)
		append_u32(&out, u32(len(payload)))
		if found && h.flags & FLAG_END_STREAM == 0 {
			write_frame_header(&out, 4, .Window_Update, 0, h.stream_id)
			append_u32(&out, u32(len(payload)))
		}
		if !client_write_all(c, out[:]) {
			return false
		}
	}

	if !found || h.flags & FLAG_END_STREAM == 0 {
		return true
	}

	/*
	Looked up again rather than reusing the pointer from the top of this
	procedure. The lock was released in between, and a caller that gives up on
	its stream - a timeout, or a reset - frees it in the deferred cleanup of
	`client_request`, so the earlier pointer may refer to memory that is gone
	by now. A response landing at the same moment the caller stops waiting for
	it is all this needs.
	*/
	sync.mutex_lock(&c.mu)
	live, still_open := c.streams[h.stream_id]
	if !still_open {
		sync.mutex_unlock(&c.mu)
		return true
	}
	live.done = true
	sync.cond_broadcast(&c.cond)
	sync.mutex_unlock(&c.mu)
	return true
}

// Hand back connection-level receive window for bytes already read, whatever
// became of the stream they belonged to.
@(private)
client_give_connection_credit :: proc(c: ^Client, n: int) -> bool {
	if n <= 0 {
		return true
	}
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	write_frame_header(&out, 4, .Window_Update, 0, 0)
	append_u32(&out, u32(n))
	return client_write_all(c, out[:])
}

@(private)
client_rst_stream :: proc(c: ^Client, stream_id: u32, code: Error_Code) -> bool {
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	write_frame_header(&out, 4, .Rst_Stream, 0, stream_id)
	append_u32(&out, u32(code))
	return client_write_all(c, out[:])
}

@(private)
client_goaway :: proc(c: ^Client, code: Error_Code) {
	out := make([dynamic]u8, 0, 17, context.temp_allocator)
	write_frame_header(&out, 8, .Goaway, 0, 0)
	// Streams are always client-initiated and push is refused, so we never
	// process a peer-initiated stream; the last-stream-id field is vestigial.
	append_u32(&out, 0)
	append_u32(&out, u32(code))
	_ = client_write_all(c, out[:])
}

/*
Send one request and wait for its response.

Opens a new stream on `c`, writes it, and blocks until the response completes,
the connection dies, or `timeout` passes. Safe to call from many threads at
once — that concurrency is the reason this client exists rather than the
HTTP/1.1 request-per-connection pool.
*/
client_request :: proc(
	c: ^Client,
	req: Client_Request,
	timeout: time.Duration,
	allocator := context.allocator,
) -> (
	resp: Client_Response,
	err: Client_Error,
) {
	// Built before any lock is taken: it does not depend on the stream id.
	block := make([dynamic]u8, 0, 128, context.temp_allocator)
	encode_header(&block, ":method", req.method)
	encode_header(&block, ":scheme", req.scheme)
	encode_header(&block, ":authority", req.authority)
	encode_header(&block, ":path", req.path)
	if req.content_type != "" {
		encode_header(&block, "content-type", req.content_type)
	}
	if req.accept != "" {
		encode_header(&block, "accept", req.accept)
	}
	end_stream: u8 = FLAG_END_STREAM if len(req.body) == 0 else 0

	sync.mutex_lock(&c.mu)
	if c.closed {
		sync.mutex_unlock(&c.mu)
		return {}, .Closed
	}
	c.refs += 1
	stream_id := c.next_stream_id
	c.next_stream_id += 2
	s := new(Client_Stream, c.allocator)
	s.id = stream_id
	s.send_window = c.peer_initial_window
	s.body = make([dynamic]u8, 0, 512, c.allocator)
	c.streams[stream_id] = s

	/*
	The HEADERS write happens in the same critical section as the id
	allocation above, rather than going through client_write_all after
	releasing the lock. RFC 9113 requires a peer to see stream ids used in
	increasing order; releasing the lock between assigning stream_id and
	writing its HEADERS frame would let a second caller — assigned a higher
	id — win the race to the socket, and the peer sees that as a protocol
	violation and kills the whole connection out from under every stream on
	it, not just the two that raced.
	*/
	out := make([dynamic]u8, 0, len(block) + FRAME_HEADER_SIZE, context.temp_allocator)
	write_frame_header(&out, len(block), .Headers, FLAG_END_HEADERS | end_stream, stream_id)
	append(&out, ..block[:])
	sent := c.io.write(c.io.user, out[:])
	sync.mutex_unlock(&c.mu)

	/*
	The stream is released under the lock, not after it. The reader thread
	looks streams up while holding `c.mu` and acts on what it finds; freeing
	one outside the lock would let this cleanup run between that lookup and
	the use, leaving the reader writing into memory already handed back.
	`client_unref` takes the lock itself, so it stays outside.
	*/
	defer {
		sync.mutex_lock(&c.mu)
		delete_key(&c.streams, stream_id)
		client_stream_destroy(c, s)
		sync.mutex_unlock(&c.mu)
		client_unref(c)
	}

	deadline := time.time_add(time.now(), timeout)

	if !sent || (len(req.body) > 0 && !client_send_body(c, s, req.body, deadline)) {
		sync.mutex_lock(&c.mu)
		dead := c.closed
		sync.mutex_unlock(&c.mu)
		return {}, .Closed if dead else .Timeout
	}

	sync.mutex_lock(&c.mu)
	for !s.done && !s.reset && !c.closed {
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			sync.mutex_unlock(&c.mu)
			client_rst_stream(c, stream_id, .Cancel)
			return {}, .Timeout
		}
		sync.cond_wait_with_timeout(&c.cond, &c.mu, remaining)
	}

	switch {
	case s.reset:
		sync.mutex_unlock(&c.mu)
		return {}, .Reset
	case c.closed && !s.done:
		sync.mutex_unlock(&c.mu)
		return {}, .Closed
	}

	status := s.status
	body := make([]u8, len(s.body), allocator)
	copy(body, s.body[:])
	sync.mutex_unlock(&c.mu)
	return Client_Response{status = status, body = body}, .None
}

// Write a request body, honouring flow control and the peer's frame size
// limit. Mirrors the server's response-body writer (h2/server.odin), bounded
// additionally by the caller's deadline since nothing else here would notice
// a peer that simply never grants window.
@(private)
client_send_body :: proc(c: ^Client, s: ^Client_Stream, body: []u8, deadline: time.Time) -> bool {
	sent := 0
	for sent < len(body) {
		remaining := len(body) - sent

		sync.mutex_lock(&c.mu)
		chunk := 0
		for {
			if c.closed || s.reset {
				sync.mutex_unlock(&c.mu)
				return false
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
			left := time.diff(time.now(), deadline)
			if left <= 0 {
				sync.mutex_unlock(&c.mu)
				return false
			}
			sync.cond_wait_with_timeout(&c.cond, &c.mu, left)
		}
		sync.mutex_unlock(&c.mu)

		last := sent + chunk >= len(body)
		out := make([dynamic]u8, 0, chunk + FRAME_HEADER_SIZE, context.temp_allocator)
		write_frame_header(&out, chunk, .Data, u8(FLAG_END_STREAM) if last else 0, s.id)
		append(&out, ..body[sent:sent + chunk])
		if !client_write_all(c, out[:]) {
			return false
		}
		sent += chunk
	}
	return true
}
