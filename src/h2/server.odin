package h2

import "core:mem"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:loop"
import "elodin:netx"

/*
A server-side HTTP/2 connection, scoped to what a DoH endpoint needs.

Requests are delivered to a handler which may answer inline or hand the work to
another fiber and call `respond` later; the connection is reference counted so
a late responder cannot outlive it. Writes are serialised, so responses may be
produced concurrently and interleave on the wire in any order — which is the
point of running HTTP/2 at all, since a browser resolving a name sends its A and
AAAA queries at the same time.

Not implemented, because a DoH endpoint never needs them: server push (refused
in SETTINGS), stream priority (parsed and ignored, as RFC 9113 permits), and
the extended CONNECT protocol.
*/

/*
Transport, so this package does not depend on the TLS layer.

`begin` is called where a read that has to complete as a whole starts - the
preface, a frame header, a frame payload - and is what lets the transport bound
one of those as a whole rather than bounding each read of it. Without it a peer
trickling a byte at a time restarts the transport's wait with every byte and is
never given up on, which on a DoH server is a connection and its fiber held for
nothing before any stream exists. Optional: a transport with nothing to bound
leaves it nil.

`starts_frame` is false for a frame's payload, which is the rest of a frame whose
header has already been read, and true for everything else: a transport that
decides to stop reading should decide it where a frame starts, not between the
halves of one it has already begun to take.

Both halves of this package call it, though only the server has a transport that
sets one today. A hook that fired on one path and not the other would hand a
client transport that set it a bound it never got, which is the failure it exists
to prevent.
*/
IO :: struct {
	user:  rawptr,
	read:  proc(user: rawptr, buf: []u8) -> (n: int, ok: bool),
	write: proc(user: rawptr, buf: []u8) -> bool,
	begin: proc(user: rawptr, starts_frame: bool),
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
	// The methods the target supports, which RFC 9110 15.5.6 requires on a 405.
	allow:         string,
	// A reply to HEAD: no content (RFC 9110 9.3.2), and no content-length,
	// which RFC 9110 8.6 allows only when it is what GET would have sent.
	head:          bool,
	body:          []u8,
}

Handler :: #type proc(conn: ^Conn, req: ^Request)

MAX_CONCURRENT :: 128
/*
Streams one connection may hold in its table, open or not.

Two counts, because the peer and this end disagree about a stream that is
over for the peer - it reset it, or its END_STREAM has gone out - but whose
handler is still running: the peer is right to count it closed and open
another (RFC 9113 5.1.2), while the slot here is only freed once the handler
lets go. So a stream is admitted while the peer has fewer than MAX_CONCURRENT
open by its own count (Conn.closed_held marks the difference), and never past
this many held. Every refusal is charged to MAX_CONTROL_FRAMES_PER_SECOND:
- A client within the limit it was told is never refused on the first count,
  so a well-behaved one replacing cancelled queries costs nothing and is not
  dropped.
- Charging only on the peer's count would leave a free RST_STREAM per HEADERS
  for as long as a peer kept MAX_CONCURRENT reset queries running; this cap is
  what stops that, and a peer past it is refused on the budget like any other.
The work behind the extra slots is bounded where it is started, by the server's
max_pending, and their bytes by MAX_CONN_REQUEST.
*/
MAX_HELD_STREAMS :: 2 * MAX_CONCURRENT
// See Conn.closed_stream_rst_budget.
MAX_CLOSED_STREAM_RST :: 16
// See Conn.reset_ids: the most resets it remembers that can land within a
// moment - a full control window either side of the second rolling over.
RESET_IDS :: 2 * MAX_CONTROL_FRAMES_PER_SECOND
/*
PINGs, non-ACK SETTINGS and stream errors (a malformed or refused request) a
peer may cause per second, each of which draws a frame back. Writes here are
synchronous, so there is no outbound queue for a flood to grow (the actual
CVE-2019-9512 / 9515); this only stops a peer turning a connection slot into a
1:1 echo for as long as it keeps sending. (Go's net/http2 bounds the queue
instead, at 10000 unwritten control frames, which a peer that reads its replies
never reaches.) A real client sends a handful per connection, and never a
malformed request or one past the MAX_CONCURRENT it was told (see
MAX_HELD_STREAMS), so 100 a second leaves ample room.
*/
MAX_CONTROL_FRAMES_PER_SECOND :: 100
/*
How long a response may wait for the peer to open its flow-control window.

A client that advertises a zero window and then goes quiet is otherwise
indistinguishable from a slow one, and waiting on it forever hands over a
query in flight per stream. Long enough that a genuinely slow reader is not cut
off, short enough that a deliberate one cannot accumulate them.
*/
DEFAULT_WRITE_TIMEOUT :: 10 * time.Second
// Advertised receive window. Generous, so a client streaming request bodies is
// never throttled by us; DoH bodies are tiny anyway. Well past MAX_BODY, so a
// stream is never given more than this and only the connection window needs
// replenishing. Padding spends the window without growing the body, so a
// stream is also reset once half the window has gone (Stream.received), rather
// than left to stall with none.
RECV_WINDOW :: 1 << 20
// Connection credit is owed until this much has built up, so a peer sending
// 1-byte DATA frames does not draw a WINDOW_UPDATE back for each one. Far
// below RECV_WINDOW, so the peer never waits on it.
CREDIT_BATCH :: 16 * 1024

Stream_State :: enum u8 {
	Open,
	Half_Closed_Remote,
	Closed,
}

Stream :: struct {
	id:           u32,
	state:        Stream_State,
	body:         [dynamic]u8,
	end_stream:   bool,
	// Set when the peer resets the stream, so a response in flight is dropped.
	cancelled:    bool,
	// Set when the stream is over the concurrency limit: its block is still
	// decoded to keep HPACK in step, then the stream is reset without being
	// served. See `handle_headers`.
	refused:      bool,
	send_window:  int,
	// Request parked between its headers and the end of its body.
	pending:      ^Request,
	/*
	Whether a handler has been given this stream, which decides who retires it.

	A dispatched stream is `respond`'s to close, and it has to still be in the
	table when that runs so the cancellation above is seen and the answer
	skipped. One that was never dispatched has nobody to do that, so a reset
	has to close it there and then or nothing ever will.
	*/
	dispatched:   bool,
	// What this stream has added to Conn.request_bytes, given back when it goes.
	charged:      int,
	// DATA payload taken on this stream, padding included: what it has spent of
	// its flow-control window. See RECV_WINDOW.
	received:     int,
}

Conn :: struct {
	io:                  IO,
	handler:             Handler,
	user:                rawptr,

	mu:                  loop.Mutex,
	cond:                loop.Cond,
	refs:                int,
	closed:              bool,

	// Peer settings that govern what we may send.
	peer_max_frame:      int,
	peer_initial_window: int,
	send_window:         int,

	decoder:        Dynamic_Table,
	streams:        map[u32]^Stream,
	last_stream_id: u32,
	goaway_sent:    bool,
	/*
	How many more DATA frames for a stream that was opened and has since
	closed still draw a courteous RST_STREAM(STREAM_CLOSED), rather than just
	their connection credit back in silence. Bounded so a peer that keeps a
	stream id alive purely to make this end answer it forever cannot turn a
	handful of genuinely in-flight frames - the case RFC 9113 5.1 asks for
	tolerance on - into an unbounded run of extra writes; see `handle_data`.
	*/
	closed_stream_rst_budget: int,
	/*
	Streams this end reset and retired while the peer was still sending on
	them, the oldest overwritten first; see `close_stream`. RFC 9113 5.1 has
	frames that follow our own RST_STREAM ignored, since the peer may have sent
	them before the reset reached it - and the stream is gone from `streams` by
	then, so this is what still knows (#390).

	Only those resets: one on a stream the peer had already ended or reset
	leaves nothing legitimately in flight, and remembering it would let a peer
	that drew one have its next header block taken quietly.

	Every reset remembered goes through `stream_error`, which spends
	MAX_CONTROL_FRAMES_PER_SECOND (the server's own budget has no `earned`
	credit to stretch it). The window is fixed, so a full one either side of
	it rolling over can land together; RESET_IDS holds both, so a slot lasts at
	least a second at the fastest a peer can reset. In flight means sent before
	our reset arrived - a round trip, which is well inside that on any link a
	resolver serves. On one slower than a second, an id overwritten early has
	DATA on it fall back to `closed_stream_rst_budget` and trailers on it to
	the connection error every other reused id gets.

	An id is struck off once the peer ends or resets the stream, or its
	trailers arrive: nothing more can be in flight on it after that.
	*/
	reset_ids:                [RESET_IDS]u32,
	reset_next:               int,
	// Request bytes held by this connection's streams; see MAX_CONN_REQUEST.
	request_bytes:            int,

	allocator:           mem.Allocator,
	/*
	A header block open across CONTINUATION frames, held here rather than on
	its stream: nothing may come between a HEADERS and its CONTINUATION frames
	(RFC 9113 6.10), so there is one at a time, and a block on a stream past
	taking one still has to be decoded after a handler may have retired the
	stream. Freed once decoded; a block whole in its HEADERS frame is decoded
	from the frame and never held. `block_stream` is the stream it opens or
	ends, nil for one decoded only to keep HPACK in step; see `handle_headers`.
	*/
	header_block:        [dynamic]u8,
	block_stream:        ^Stream,
	// The stream whose header block is open across CONTINUATION frames, or 0.
	continuation_on:     u32,
	// How many of them have arrived for the block currently open.
	continuation_frames: int,
	// How long a response may wait for the peer to grant flow-control credit
	// before the stream is given up on.
	write_timeout:       time.Duration,
	// Answered control frames and stream errors; see Control_Budget.
	control:             Control_Budget,
	// Connection credit not yet returned; see CREDIT_BATCH. Reader only.
	credit_owed:         int,
	// Streams in `streams` marked Closed, which the peer no longer counts; see
	// MAX_HELD_STREAMS and set_state.
	closed_held:         int,
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
	c.closed_stream_rst_budget = MAX_CLOSED_STREAM_RST
	c.write_timeout = DEFAULT_WRITE_TIMEOUT
	dynamic_table_init(&c.decoder, DEFAULT_HEADER_TABLE_SIZE, allocator)
	return c
}

// Take a reference before handing the connection to another thread.
conn_ref :: proc(c: ^Conn) {
	loop.lock(&c.mu)
	c.refs += 1
	loop.unlock(&c.mu)
}

conn_unref :: proc(c: ^Conn) {
	loop.lock(&c.mu)
	c.refs -= 1
	last := c.refs == 0
	// Wakes anyone in conn_wait_idle.
	loop.cond_broadcast(&c.cond)
	loop.unlock(&c.mu)
	if !last {
		return
	}

	for _, s in c.streams {
		stream_destroy(c, s)
	}
	delete(c.streams)
	delete(c.header_block)
	dynamic_table_destroy(&c.decoder)
	free(c, c.allocator)
}

@(private)
stream_destroy :: proc(c: ^Conn, s: ^Stream) {
	// A request parked between its headers and a body that never arrived is
	// owned by the stream, not by a handler; only a dispatched one is released
	// by whoever answered it.
	request_destroy(c, s.pending)
	c.request_bytes -= s.charged
	delete(s.body)
	free(s, c.allocator)
}

/*
Wait until every handler has finished, leaving only the caller's reference.

Serving code calls this after `serve` returns and before dropping its own
reference, so a handler still running on another fiber cannot reach for a
transport its owner has already torn down. Handlers waiting on flow control are
released by the close that `serve` performs on its way out, and give up on their
own deadline in any case, so this cannot wait indefinitely on a peer that has
stopped reading.
*/
conn_wait_idle :: proc(c: ^Conn) {
	loop.lock(&c.mu)
	for c.refs > 1 {
		loop.cond_wait(&c.cond, &c.mu)
	}
	loop.unlock(&c.mu)
}

/*
Run the connection until the peer goes away or the protocol is violated.

Returns once no more frames will be read. In-flight handlers may still be
running; they hold their own references.
*/
serve :: proc(c: ^Conn) {
	defer {
		loop.lock(&c.mu)
		c.closed = true
		loop.cond_broadcast(&c.cond)
		loop.unlock(&c.mu)
	}

	if !read_preface(c) {
		return
	}
	if !send_initial_settings(c) {
		return
	}

	header: [FRAME_HEADER_SIZE]u8
	// A peer that keeps the socket readable never lets this reader park, and the
	// handlers it starts on the same loop would wait behind it: counted per frame
	// as well as per socket call, since `IO` need not be a socket (the tests',
	// read from memory). See `loop.take_turn`.
	for {
		loop.take_turn()
		if !read_exact(c, header[:]) {
			return
		}
		h, ok := parse_frame_header(header[:])
		if !ok {
			return
		}
		// Bounded at the frame size we advertise, not at the receive window. We
		// never send SETTINGS_MAX_FRAME_SIZE, so the peer is held to the RFC 9113
		// 6.5.2 default (16384); accepting 64x that (RECV_WINDOW) would allow a
		// frame the peer was told to keep smaller. The window still caps the body
		// a stream may buffer; this caps a single frame off the wire.
		if h.length > DEFAULT_MAX_FRAME {
			goaway(c, .Frame_Size_Error)
			return
		}

		payload: []u8
		if h.length > 0 {
			payload = make([]u8, h.length, context.temp_allocator)
			if !read_exact(c, payload, starts_frame = false) {
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
read_exact :: proc(c: ^Conn, buf: []u8, starts_frame := true) -> bool {
	// One whole thing off the wire starts here: everything this package reads it
	// reads through this, so this is the one place that has to say so. See `IO`.
	if c.io.begin != nil {
		c.io.begin(c.io.user, starts_frame)
	}
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
	loop.lock(&c.mu)
	defer loop.unlock(&c.mu)
	if c.closed {
		return false
	}
	return c.io.write(c.io.user, buf)
}

@(private)
send_initial_settings :: proc(c: ^Conn) -> bool {
	out := make([dynamic]u8, 0, 64, context.temp_allocator)
	// SETTINGS_HEADER_TABLE_SIZE, ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS,
	// INITIAL_WINDOW_SIZE and MAX_HEADER_LIST_SIZE - the bounds stated rather
	// than left for a peer to discover as a connection error. The table size is
	// the RFC 9113 6.5.2 default, which would apply anyway; sending it puts the
	// number `decode` holds a peer to on the wire where the peer can read it.
	write_frame_header(&out, 30, .Settings, 0, 0)
	append(&out, 0, u8(Setting.Header_Table_Size))
	append_u32(&out, DEFAULT_HEADER_TABLE_SIZE)
	append(&out, 0, u8(Setting.Enable_Push))
	append_u32(&out, 0)
	append(&out, 0, u8(Setting.Max_Concurrent_Streams))
	append_u32(&out, MAX_CONCURRENT)
	append(&out, 0, u8(Setting.Initial_Window_Size))
	append_u32(&out, RECV_WINDOW)
	append(&out, 0, u8(Setting.Max_Header_List_Size))
	append_u32(&out, MAX_HEADER_LIST)

	// Raise the connection-level receive window to match.
	write_frame_header(&out, 4, .Window_Update, 0, 0)
	append_u32(&out, RECV_WINDOW - DEFAULT_WINDOW)
	return write_all(c, out[:])
}

@(private)
handle_frame :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if (h.type == .Ping || h.type == .Settings) && h.flags & FLAG_ACK == 0 && !spend_control_budget(c) {
		return false
	}
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
		if h.stream_id == 0 || len(payload) != 4 {
			goaway(c, .Protocol_Error if h.stream_id == 0 else .Frame_Size_Error)
			return false
		}
		loop.lock(&c.mu)
		if stream_is_idle(c, h.stream_id) {
			loop.unlock(&c.mu)
			goaway(c, .Protocol_Error)
			return false
		}
		orphaned := false
		if s, found := c.streams[h.stream_id]; found {
			s.cancelled = true
			set_state(c, s, .Closed)
			// Nobody is coming for this one. See `Stream.dispatched`.
			orphaned = !s.dispatched
			// Wakes a handler parked in write_body's no-credit wait; without this
			// it sleeps out the full write_timeout on a stream already known
			// dead. Inside `found`, unlike the already_ended path in handle_data:
			// there is no stream here for an unmatched id to have parked anyone
			// on, so broadcasting for one would only wake every other handler on
			// the connection to recheck a state that has not changed for them.
			loop.cond_broadcast(&c.cond)
		} else {
			// Over for the peer too, so nothing more is in flight on it.
			was_reset_here(c, h.stream_id, forget = true)
		}
		loop.unlock(&c.mu)
		if orphaned {
			close_stream(c, h.stream_id)
		}
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

/*
Frames a peer drew out of this end, held to MAX_CONTROL_FRAMES_PER_SECOND plus
whatever it has earned: `frames` counts the second starting at `window`, and
`earned` is frames paid for by work this end asked for (the client's answers;
the server earns nothing). One per connection; reader only.

`earned` is not reset with the window. A PING may trail the answer that paid
for it by any lag, across a second boundary, and a busy pooled connection
answers far more than the budget a second, so credit that expired with the
window would drop exactly that connection. It is not capped either: it only
grows by answering this end's own requests, one frame each, so what a peer can
bank is a 1:1 echo of queries already sent, never a rate it raises itself.
*/
Control_Budget :: struct {
	frames: int,
	window: time.Tick,
	earned: int,
}

// Charges one frame; false once this second's budget is spent.
@(private)
control_budget_spend :: proc(b: ^Control_Budget) -> bool {
	if b.earned > 0 {
		b.earned -= 1
		return true
	}
	now := loop.tick_now()
	// A zero window is long past, so the first frame opens one.
	if time.tick_diff(b.window, now) >= time.Second {
		b.window = now
		b.frames = 0
	}
	b.frames += 1
	return b.frames <= MAX_CONTROL_FRAMES_PER_SECOND
}

// Credits one frame, for work the peer did that this end asked for.
@(private)
control_budget_refund :: proc(b: ^Control_Budget) {
	b.earned += 1
}

// Charges one frame against MAX_CONTROL_FRAMES_PER_SECOND. Past it, the peer is
// sent GOAWAY(ENHANCE_YOUR_CALM) and false says to drop the connection.
@(private)
spend_control_budget :: proc(c: ^Conn) -> bool {
	if !control_budget_spend(&c.control) {
		goaway(c, .Enhance_Your_Calm)
		return false
	}
	return true
}

/*
Every change to a stream's state once it is in the table goes through here, so
Conn.closed_held stays the number of held streams marked Closed. Closed is
terminal (RFC 9113 5.1): a write that would reopen one is dropped rather than
left to undercount, which would loosen admission for the rest of the
connection. Caller holds c.mu.
*/
@(private)
set_state :: proc(c: ^Conn, s: ^Stream, state: Stream_State) {
	if s.state == .Closed {
		return
	}
	if state == .Closed {
		c.closed_held += 1
	}
	s.state = state
}

/*
RFC 9113 5.1: a stream id past the highest the peer has opened is idle, and so
is any even one, which only a push could open and this end never pushes. Idle
accepts only HEADERS and PRIORITY; anything else on one is a connection error
of type PROTOCOL_ERROR. Caller holds c.mu; stream 0 is the connection, not a
stream, and is the caller's to rule out.
*/
@(private)
stream_is_idle :: proc(c: ^Conn, stream_id: u32) -> bool {
	return stream_id > c.last_stream_id || stream_id % 2 == 0
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

	loop.lock(&c.mu)
	for i := 0; i + 6 <= len(payload); i += 6 {
		id := Setting(read_u16(payload[i:]))
		value := read_u32(payload[i + 2:])
		#partial switch id {
		case .Enable_Push:
			// RFC 9113 6.5.2: anything but 0 or 1 is a PROTOCOL_ERROR. This
			// end never pushes, so a legal value changes nothing.
			if value > 1 {
				loop.unlock(&c.mu)
				goaway(c, .Protocol_Error)
				return false
			}
		case .Max_Frame_Size:
			if value < DEFAULT_MAX_FRAME || value > 16777215 {
				loop.unlock(&c.mu)
				goaway(c, .Protocol_Error)
				return false
			}
			c.peer_max_frame = int(value)
		case .Initial_Window_Size:
			if value > MAX_WINDOW {
				loop.unlock(&c.mu)
				goaway(c, .Flow_Control_Error)
				return false
			}
			/*
			A change retroactively adjusts every open stream's window, and a
			stream carried past the maximum by that adjustment is the same
			connection error as one carried there by a WINDOW_UPDATE (RFC 9113
			section 6.9.2). The check above only refuses a settings *value* over
			the maximum, which does not stop an already-raised window from being
			nudged over it.
			*/
			delta := int(value) - c.peer_initial_window
			c.peer_initial_window = int(value)
			overflow := false
			for _, s in c.streams {
				s.send_window += delta
				overflow ||= s.send_window > MAX_WINDOW
			}
			loop.cond_broadcast(&c.cond)
			if overflow {
				loop.unlock(&c.mu)
				goaway(c, .Flow_Control_Error)
				return false
			}
		}
	}
	loop.unlock(&c.mu)

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

	loop.lock(&c.mu)
	if h.stream_id != 0 && stream_is_idle(c, h.stream_id) {
		loop.unlock(&c.mu)
		goaway(c, .Protocol_Error)
		return false
	}
	overflow := false
	if h.stream_id == 0 {
		c.send_window += increment
		overflow = c.send_window > MAX_WINDOW
	} else if s, found := c.streams[h.stream_id]; found {
		s.send_window += increment
		overflow = s.send_window > MAX_WINDOW
	}
	loop.cond_broadcast(&c.cond)
	loop.unlock(&c.mu)

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
	if len(block) > MAX_HEADER_LIST {
		goaway(c, .Compression_Error)
		return false
	}

	loop.lock(&c.mu)
	c.block_stream = nil
	stream_closed, past_taking := false, false
	if h.stream_id <= c.last_stream_id {
		s, found := c.streams[h.stream_id]
		switch {
		case found && s.state == .Open && s.pending != nil:
			/*
			RFC 9113 8.1: a request may end with a trailer section, a block on
			the stream it opened, after the body. Nothing is done with the fields,
			but the block is decoded, checked and only then ends the request; see
			`finish_trailers`. A parked request has no handler, so nothing but
			this reader can retire the stream while the block is open.
			*/
			s.end_stream = h.flags & FLAG_END_STREAM != 0
			c.block_stream = s
		case found:
			/*
			RFC 9113 5.1: the peer has ended this stream, or one end has reset it,
			so it takes no more blocks: a stream error of type STREAM_CLOSED,
			answered once and skipped on one the peer reset itself (5.4.2), as
			DATA is in `handle_data`. The stream stays its handler's to retire,
			so the block is decoded on its own. A block draws no reply after the
			first but still costs a decode, so each is charged to
			MAX_CONTROL_FRAMES_PER_SECOND: a peer repeating them on a stream a
			slow handler holds is held to the rate any other is.
			*/
			stream_closed = mark_stream_closed(c, s)
			past_taking = true
		case was_reset_here(c, h.stream_id, forget = true) && h.flags & FLAG_END_STREAM != 0:
		/*
		A stream this end reset and retired while the peer was still sending
		(Conn.reset_ids): trailers the peer sent before it saw that reset are in
		flight, which RFC 9113 5.1 has ignored, not punished (#390). Decoded on
		its own, then dropped. Once: trailers end the stream, so the id is
		struck off, and a second block is a connection error again.
		*/
		case:
			// Already in use or closed, which is a connection error. Trailers end
			// the stream (RFC 9113 8.1); a block that does not is an id reused.
			loop.unlock(&c.mu)
			goaway(c, .Protocol_Error)
			return false
		}
	} else {
		c.last_stream_id = h.stream_id

		/*
		A stream over the concurrency limit is refused, but not here. HPACK
		state is per connection and order-dependent, so the block must still be
		decoded to keep the decoder in step with the peer's encoder - RFC 9113
		4.3 makes a block left undecoded a COMPRESSION_ERROR, whatever the
		stream's fate. The stream is carried like any other through the block
		(and its CONTINUATION frames), then reset in `finish_headers` instead of
		served. Advancing `last_stream_id` above and setting `continuation_on`
		below both happen on this path exactly as on the accepted one.
		*/
		// See MAX_HELD_STREAMS.
		refused := len(c.streams) - c.closed_held >= MAX_CONCURRENT || len(c.streams) >= MAX_HELD_STREAMS

		s := new(Stream, c.allocator)
		s.id = h.stream_id
		s.state = .Open
		s.refused = refused
		s.send_window = c.peer_initial_window
		// Nothing allocated until DATA arrives, where `handle_data` charges it.
		s.body = make([dynamic]u8, 0, 0, c.allocator)
		s.end_stream = h.flags & FLAG_END_STREAM != 0
		c.streams[h.stream_id] = s
		c.block_stream = s
	}
	loop.unlock(&c.mu)

	if stream_closed && !stream_error(c, h.stream_id, .Stream_Closed) {
		return false
	}
	if past_taking && !stream_closed && !spend_control_budget(c) {
		return false
	}
	if h.flags & FLAG_END_HEADERS == 0 {
		// Held for the CONTINUATION frames that bring the rest of it.
		delete(c.header_block)
		c.header_block = make([dynamic]u8, 0, len(block), c.allocator)
		append(&c.header_block, ..block)
		c.continuation_on = h.stream_id
		c.continuation_frames = 0
		return true
	}
	return finish_headers(c, c.block_stream, block)
}

@(private)
handle_continuation :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	// RFC 9113 6.10: only behind a HEADERS without END_HEADERS, on its stream;
	// with no block open, `continuation_on` is 0, which is no stream either.
	if c.continuation_on == 0 || c.continuation_on != h.stream_id {
		goaway(c, .Protocol_Error)
		return false
	}
	/*
	Counted as well as measured.

	The size cap below is no cap against frames that carry nothing: an empty
	CONTINUATION never advances `len(c.header_block)`, so a peer sending them
	holds the block open and this reader reading nine-byte frames for as long as
	it likes. Nothing accrues, which is why the cap is generous - a legitimate
	block is MAX_HEADER_LIST at the outside and arrives in a handful of frames,
	so anything near this many is a peer with something else in mind.
	*/
	c.continuation_frames += 1
	if c.continuation_frames > MAX_CONTINUATION_FRAMES {
		goaway(c, .Enhance_Your_Calm)
		return false
	}
	/*
	Bounded as it accumulates, not once it is whole. Neither HEADERS nor
	CONTINUATION is flow-controlled, so nothing slows a peer sending these, and
	HPACK's own limit lives in `decode` - which never runs for a block whose
	END_HEADERS never arrives. Without a cap here one connection can make us
	hold as much as it cares to send.
	*/
	if len(c.header_block) + len(payload) > MAX_HEADER_LIST {
		goaway(c, .Compression_Error)
		return false
	}
	append(&c.header_block, ..payload)

	if h.flags & FLAG_END_HEADERS == 0 {
		return true
	}
	c.continuation_on = 0
	return finish_headers(c, c.block_stream, c.header_block[:])
}

/*
Whether a decoded request header list is malformed under RFC 9113 8.2 and 8.3.

One pass over the list, no allocation. `finish_headers` keeps six fields and
drops the rest, so without this the checks the specification asks for would be
made against the six that survived - and a `transfer-encoding` this end never
looks at would be dropped in silence rather than refused.

Silence is safe only for as long as elodin is the last hop. It terminates every
request it accepts and reflects no field onward, so none of this is a smuggling
primitive here today; it becomes one the moment another hop sits in front of or
behind this endpoint, an h2-to-h1 front end that downgrades a request carrying
`transfer-encoding` being the classic h2.TE desync. The HTTP/1.1 side of this
codebase already refuses the same shapes, and the two should not disagree about
what a request is.
*/
@(private)
request_is_malformed :: proc(headers: []Header_Field) -> bool {
	method, scheme, path, authority: string
	have_method, have_scheme, have_path, have_authority: bool
	// Set by the first ordinary field, which is where the pseudo-headers end.
	seen_regular: bool
	have_content_type: bool
	host: string
	have_host: bool

	for f in headers {
		if len(f.name) == 0 {
			return true
		}

		if f.name[0] == ':' {
			// An ordinary field's value is `field_is_malformed`'s to check.
			if !field_value_is_valid(f.value) {
				return true
			}
			// 8.3: every pseudo-header comes before the ordinary fields.
			if seen_regular {
				return true
			}
			/*
			A repeat is malformed, and it is worth being explicit about why the
			check is here rather than left to `take`. That procedure keeps the
			first value and frees the rest, which is right for memory and wrong
			for the protocol: two `:path` fields would be answered from the
			first, and a hop that resolved the same request the other way round
			would answer from the second.
			*/
			switch f.name {
			case ":method":
				if have_method {
					return true
				}
				have_method, method = true, f.value
			case ":scheme":
				if have_scheme {
					return true
				}
				have_scheme, scheme = true, f.value
			case ":path":
				if have_path {
					return true
				}
				have_path, path = true, f.value
			case ":authority":
				if have_authority {
					return true
				}
				have_authority, authority = true, f.value
			case:
				// 8.3 again: a request has those four and no others. `:protocol`
				// lands here too, which is the answer this end wants - extended
				// CONNECT is not implemented.
				return true
			}
			continue
		}

		seen_regular = true
		if field_is_malformed(f) {
			return true
		}
		switch f.name {
		case "host":
			// 8.3.1 lets a request carry `Host` in place of `:authority`, and an
			// h2-to-h1 hop writes it out as the one it gets: the same rule (#438).
			// Once only, as on HTTP/1.1, and checked against `:authority` below.
			if have_host || !authority_is_valid(f.value) {
				return true
			}
			have_host, host = true, f.value
		case "content-type":
			/*
			RFC 9110 5.3: a singleton field, and a recipient may treat a repeat
			as an error. The `:path` argument above applies: `take` keeps the
			first non-empty value, a hop in front may have judged another, and
			the media type is what decides whether the body is taken for a DNS
			message. Counted here, so an empty first one is a repeat too.
			*/
			if have_content_type {
				return true
			}
			have_content_type = true
		}
	}

	/*
	`:authority` is the target of CONNECT's request line and the `Host` of every
	other request's, so it is held to what a host may hold, for the reason
	given for `:path` below (#438) - see `authority_is_valid`.
	*/
	if !authority_is_valid(authority) {
		return true
	}
	// 8.3.1: a Host naming another entity than `:authority` is malformed. This
	// end routes by `:authority`, a hop behind it may route by `host`. ASCII
	// case is the only normalising done, so `a:443` and `a` are refused as two
	// entities: stricter than the RFC asks, and nothing sends both that way.
	if have_host && have_authority && !dns.name_equal_fold(host, authority) {
		return true
	}
	/*
	8.5: CONNECT carries `:authority` and neither `:scheme` nor `:path`. Not
	implemented here, but a conformant one still has to be recognised as
	conformant - turning it away is the handler's job, and not this procedure's
	under the name of malformed. It carries no `:path`, so what the handler
	matches it against is the empty one and what it answers is a 404.
	*/
	if method == "CONNECT" {
		return !have_authority || have_scheme || have_path
	}

	// 8.3.1: the three every other request must carry.
	if !have_method || !have_scheme || !have_path {
		return true
	}
	/*
	One valid value each, which 8.3.1 asks for and which an empty string is not:
	`:method` is a token and `:scheme` is a scheme, and neither grammar admits
	nothing at all. `:scheme` is worth more than tidiness here - it is what
	selects the `:path` checks below, so an empty one carried any `:path` at all
	straight past them.

	And a token, not merely something (RFC 9110 9.1): `GE(T`, `GET\x0b` and
	`POST\t/allowed` were requests, and the last is a request line that an
	h2-to-h1 hop writes out for a lenient reader to split on the tab (#438).
	The HTTP/1.1 side refuses the same methods. `:path` is held to what a
	request target may hold for the same reason.
	*/
	if !is_token(method) || len(scheme) == 0 || !target_is_valid(path) {
		return true
	}
	/*
	And what `:path` may hold: for http and https it is origin-form, non-empty
	and rooted, with asterisk-form reserved to OPTIONS. Any other scheme's path
	is not this specification's to constrain, and is nothing this endpoint would
	match in any case.

	An absent `:path` is refused above rather than left to arrive as "", which
	would fail the comparison in `build_h2_response` and 404 - safe by accident
	rather than by check, and only for as long as that comparison is what the
	path is used for.

	Folded, because RFC 3986 section 3.1 makes scheme names case-insensitive and
	8.3.1 puts no case restriction on `:scheme` - it is an ordinary field value,
	not a token a receiver may fold on the sender's behalf. Compared as it
	arrives, `HTTPS` names a scheme this specification is silent about and so
	carried any `:path` past these checks, which is the empty-`:scheme` hole
	again with a capital letter in place of nothing at all.

	And a scheme at all first: RFC 3986 3.1 writes it in ASCII letters, digits,
	`+`, `-` and `.`, beginning with a letter. Anything else names no scheme and
	would carry any `:path` past these checks as surely as an empty one did. And
	folded in ASCII only: `strings.equal_fold` folds Unicode, where the long s
	(U+017F) is an `s`, so `http\u017f` read as https (#432).
	*/
	if !netx.is_scheme(scheme) {
		return true
	}
	if dns.name_equal_fold(scheme, "http") || dns.name_equal_fold(scheme, "https") {
		if path == "*" {
			return method != "OPTIONS"
		}
		if len(path) == 0 || path[0] != '/' {
			return true
		}
	}
	return false
}

/*
What makes an ordinary field malformed wherever it is, in a request's header
section or its trailers: a name or value RFC 9113 8.2.1 refuses, or one of the
connection-specific fields 8.2.2 does, which have no meaning in HTTP/2, where
the connection is shared by every stream on it.
*/
@(private)
field_is_malformed :: proc(f: Header_Field) -> bool {
	if !field_name_is_valid(f.name) || !field_value_is_valid(f.value) {
		return true
	}
	switch f.name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	case "te":
		// The one exception 8.2.2 makes, and only for this value.
		return f.value != "trailers"
	}
	return false
}

/*
RFC 9113 8.1: a trailer section ends its stream and carries no pseudo-header
field, and 8.2 refuses in it what it refuses anywhere; a section that breaks
either is malformed, a request's or a response's. A pseudo-header's name is no
token, so `field_is_malformed` refuses those too.
*/
@(private)
trailers_are_malformed :: proc(trailers: []Header_Field, end_stream: bool) -> bool {
	if !end_stream {
		return true
	}
	for f in trailers {
		if field_is_malformed(f) {
			return true
		}
	}
	return false
}

/*
RFC 9110 5.6.2: a token, which is what a field name is on either version of the
protocol. ASCII only, so a name outside it cannot be one a Unicode case fold in
some other hop reads as a field this one knows by another spelling.
*/
is_token :: proc(s: string) -> bool {
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9':
			continue
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	// 1*tchar: nothing at all is not a token.
	return len(s) > 0
}

/*
RFC 9112 3.2 and RFC 3986 2: a request target is visible ASCII and nothing
else. No SP, HTAB, VT or FF, which a lenient hop is entitled to split a request
line on (RFC 9112 3), no other control, and no byte outside ASCII, which a URI
cannot hold unencoded. Emptiness is left to the caller, which knows what an
empty target means on its version.
*/
target_is_valid :: proc(s: string) -> bool {
	for i in 0 ..< len(s) {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

/*
RFC 9110 7.2 and RFC 3986 3.2: a host, `uri-host [":" port]`, is a target that
holds no userinfo (which RFC 9113 8.3.1 forbids in `:authority` by name), no
path, query or fragment, and no backslash, which WHATWG parsers read as a `/`.
Each of those is a Host that a hop routing by it parses its own way:
`a.example@b.example` is `b.example` to one reader and `a.example` to another.
Empty is left to the caller, as for `target_is_valid`.
*/
authority_is_valid :: proc(s: string) -> bool {
	return target_is_valid(s) && strings.index_any(s, "@/\\?#") < 0
}

/*
RFC 9110 5.6.1: whether the comma-separated list `value` holds `token`, compared
without regard to ASCII case. `Connection: keep-alive, close` is a close, which
a single-token compare missed (#437); each element loses its OWS and nothing
more, and empty elements match nothing. For lists of tokens only, such as
`Connection`: a comma inside a quoted-string is split on like any other.
*/
list_has_token :: proc(value, token: string) -> bool {
	rest := value
	for element in strings.split_iterator(&rest, ",") {
		if dns.name_equal_fold(trim_ows(element), token) {
			return true
		}
	}
	return false
}

/*
`value` with `OWS` taken off either end and nothing else.

`OWS` is spaces and tabs (RFC 9110 5.6.3), which is all a recipient may take off
a field value. `strings.trim_space` takes more: it is Unicode-aware, so it also
takes a non-breaking space off the end, which would make `close\u00a0` a close. A hop
in front reads the field as the grammar writes it and refuses the message rather
than trimming it, so trimming one here is this hop reading a value the front end
never saw.
*/
trim_ows :: proc(value: string) -> string {
	return strings.trim(value, " \t")
}

/*
An HTTP/1 `Content-Length` value, which is `1*DIGIT` (RFC 9110 8.6) and nothing
else, with `OWS` around it. One parser for the DoH server and the HTTP client,
since both carry the same request-smuggling hardening and two that disagree are
the bug.

`strconv.parse_int` with its default base reads a good deal more: the base comes
from a prefix, so `0x10` is 16 and `0b1010` is 10; `_` between digits is
skipped; a leading sign is allowed; and the accumulator wraps in silence, so
`18446744073709551620` comes back as 4 and a range check downstream sees nothing
wrong. On the server that is CL.CL request smuggling behind a front end that
reads the field as the RFC writes it; on the client it leaves a kept-alive
connection reading from the middle of a body.

A value past `limit` comes back as `limit + 1`, so nothing wraps on the way to
the caller's range check, and its digits are still all checked: too large and
not a length at all are different refusals.
*/
parse_content_length :: proc(value: string, limit: int) -> (length: int, ok: bool) {
	// A step is taken only from `length <= limit`, so it stays under
	// `limit * 10 + 9`, which this keeps inside an int.
	assert(limit >= 0 && limit < max(int) / 10)
	digits := trim_ows(value)
	if len(digits) == 0 {
		return 0, false
	}
	for i in 0 ..< len(digits) {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if length <= limit {
			length = min(length * 10 + int(c - '0'), limit + 1)
		}
	}
	return length, true
}

/*
An HTTP/1 `HTTP-version`: `HTTP/` `DIGIT` `.` `DIGIT`, case-sensitively, and
nothing on either side of it (RFC 9112 2.3) - the request line's third token, or
the first eight bytes of a status line.
*/
http1_version :: proc(s: string) -> (major, minor: u8, ok: bool) {
	if len(s) != 8 || !strings.has_prefix(s, "HTTP/") || s[6] != '.' {
		return
	}
	if s[5] < '0' || s[5] > '9' || s[7] < '0' || s[7] > '9' {
		return
	}
	return s[5] - '0', s[7] - '0', true
}

/*
RFC 9113 8.2.1: a field name is an RFC 9110 token, and lowercase. Uppercase is
not folded on receipt but malformed, so that two hops cannot disagree about
which of `Transfer-Encoding` and `transfer-encoding` they were sent.
*/
@(private)
field_name_is_valid :: proc(name: string) -> bool {
	for i in 0 ..< len(name) {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return false
		}
	}
	return is_token(name)
}

/*
RFC 9113 8.2.1 again: a field value holds no NUL, CR or LF, and neither begins
nor ends with whitespace. The three characters are what an HTTP/1.1 hop would
read as the end of the field, or of the message, so a value carrying one is how
a request smuggled through this end would be written.
*/
field_value_is_valid :: proc(value: string) -> bool {
	if len(value) > 0 {
		first, last := value[0], value[len(value) - 1]
		if first == ' ' || first == '\t' || last == ' ' || last == '\t' {
			return false
		}
	}
	for i in 0 ..< len(value) {
		switch value[i] {
		case 0, '\n', '\r':
			return false
		}
	}
	return true
}

/*
Decode a completed header block and, if the request is already complete,
dispatch it.

HPACK state is per connection and order-dependent, so the block must be decoded
here on the reader even when the request body has yet to arrive.
*/
@(private)
finish_headers :: proc(c: ^Conn, s: ^Stream, block: []u8) -> bool {
	/*
	Into the reader's per-frame arena, which `serve` resets after this frame:
	up to MAX_HEADER_COUNT fields are decoded and a request keeps six of them,
	so those six are cloned out below (`take`) and the rest go with the arena
	rather than one heap allocation and free apiece.
	*/
	headers, err := decode(&c.decoder, block, context.temp_allocator)
	// The block is decoded; keep only the fields. Freed rather than cleared, or
	// a connection keeps up to MAX_HEADER_LIST of buffer for as long as it lasts
	// (#303).
	delete(c.header_block)
	c.header_block = nil
	c.block_stream = nil
	if err != .None {
		goaway(c, .Compression_Error)
		return false
	}

	// A block decoded only for its HPACK side effects; see `handle_headers`.
	if s == nil {
		return true
	}
	// A refused stream has had its HPACK side effects applied by the decode
	// above, which is the whole reason it was carried this far. Reset it and let
	// it go without ever handing it to a handler.
	if s.refused {
		sent := stream_error(c, s.id, .Refused_Stream)
		close_stream(c, s.id, peer_sending = !s.end_stream)
		return sent
	}
	// Only a request parked for its body has one, so this block is its trailers.
	if s.pending != nil {
		return finish_trailers(c, s, headers)
	}

	/*
	RFC 9113 8.1.1 makes a malformed request a stream error of type
	PROTOCOL_ERROR: the stream is reset and the connection carries on, so the
	streams around it are not punished for one peer's bad request. Checked here
	rather than in the DoH handler because none of it is about DNS - it is what
	the HTTP/2 layer promises the layers above it about the request it hands
	over, and the field that would break the promise is dropped by the loop
	below before anyone above could see it.
	*/
	if request_is_malformed(headers) {
		sent := stream_error(c, s.id, .Protocol_Error)
		close_stream(c, s.id, peer_sending = !s.end_stream)
		return sent
	}

	req := new(Request, c.allocator)
	req.stream_id = s.id
	req.allocator = c.allocator
	// The first of a repeated field is the one kept, and only it is cloned, so
	// a peer repeating one holds no more of the connection's memory than one.
	take :: proc(dst: ^string, value: string, allocator: mem.Allocator) {
		if dst^ != "" {
			return
		}
		dst^ = strings.clone(value, allocator)
	}

	for f in headers {
		switch f.name {
		case ":method":
			take(&req.method, f.value, c.allocator)
		case ":path":
			take(&req.path, f.value, c.allocator)
		case ":authority", "host":
			// 8.3.1: `host` stands in for an absent `:authority`. Both present
			// means they agree (`request_is_malformed`), and the pseudo-header,
			// coming first, is the one kept.
			take(&req.authority, f.value, c.allocator)
		case ":scheme":
			take(&req.scheme, f.value, c.allocator)
		case "content-type":
			take(&req.content_type, f.value, c.allocator)
		case "accept":
			take(&req.accept, f.value, c.allocator)
		}
	}

	// Charged like body bytes: a stream parked for its body holds its fields as
	// long as it holds the body, and a :path near MAX_HEADER_LIST on every
	// stream pins as much as the bodies MAX_CONN_REQUEST exists to bound.
	fields := len(req.method) + len(req.path) + len(req.authority) + len(req.scheme) + len(req.content_type) + len(req.accept)
	loop.lock(&c.mu)
	over := c.request_bytes + fields > MAX_CONN_REQUEST
	if !over {
		s.charged = fields
		c.request_bytes += fields
		set_state(c, s, .Half_Closed_Remote if s.end_stream else .Open)
	}
	complete := s.end_stream
	loop.unlock(&c.mu)
	if over {
		request_destroy(c, req)
		sent := stream_error(c, s.id, .Refused_Stream)
		close_stream(c, s.id, peer_sending = !s.end_stream)
		return sent
	}

	if !complete {
		// Park the request until the body arrives.
		s.pending = req
		return true
	}
	return dispatch(c, s, req)
}

/*
End a parked request with its trailers. RFC 9113 8.1: they carry END_STREAM and
no pseudo-header field, and a request whose do not is malformed - as is one
whose trailers carry a field 8.2 refuses anywhere - which 8.1.1 makes a stream
error of type PROTOCOL_ERROR. The fields themselves are dropped: nothing this
end serves reads a trailer.
*/
@(private)
finish_trailers :: proc(c: ^Conn, s: ^Stream, trailers: []Header_Field) -> bool {
	if trailers_are_malformed(trailers, s.end_stream) {
		sent := stream_error(c, s.id, .Protocol_Error)
		close_stream(c, s.id, peer_sending = !s.end_stream)
		return sent
	}
	// Parked, so no handler holds it and the pointer is still good.
	loop.lock(&c.mu)
	set_state(c, s, .Half_Closed_Remote)
	req := s.pending
	s.pending = nil
	loop.unlock(&c.mu)
	return dispatch(c, s, req)
}

@(private)
handle_data :: proc(c: ^Conn, h: Frame_Header, payload: []u8) -> bool {
	if h.stream_id == 0 {
		goaway(c, .Protocol_Error)
		return false
	}

	data, ok := strip_padding(payload, h.flags)
	if !ok {
		goaway(c, .Protocol_Error)
		return false
	}

	loop.lock(&c.mu)
	/*
	RFC 9113 5.1: a stream id past the highest one this connection has ever
	opened is idle, and idle only accepts HEADERS or PRIORITY - DATA on one
	is a connection error of type PROTOCOL_ERROR, the same as stream 0. Left
	unchecked, a peer can drive an unbounded run of connection WINDOW_UPDATE
	writes with DATA on stream ids that were never opened.

	An even id is idle too, whatever `last_stream_id` is: `handle_headers`
	rejects one outright, so this server can never have opened one, and
	without this half a DATA frame on one below `last_stream_id` would fall
	through to the closed-stream path instead - a connection error misanswered
	as a stream error, and one that spent the closed-stream budget doing it.
	*/
	if stream_is_idle(c, h.stream_id) {
		loop.unlock(&c.mu)
		goaway(c, .Protocol_Error)
		return false
	}
	s, found := c.streams[h.stream_id]
	/*
	The idle check above already ruled out a stream id past `last_stream_id`,
	so `!found` here can only mean one that was opened and has since closed -
	RFC 9113 5.1 answers that with a stream error of type STREAM_CLOSED.
	Budgeted rather than answered every time, unlike the two cases below that
	cap their own RST_STREAM through `cancelled`: this stream is already gone,
	so there is nothing here to hold a one-shot flag on. RFC 9113 5.1 also
	asks endpoints to tolerate frames that were genuinely in flight when a
	stream closed, and a peer that just keeps a dead id around otherwise draws
	an unbounded run of RST_STREAM writes out of this end. Once the budget is
spent, this falls back to returning the credit with no RST: silently
ignored.

	A stream this end reset while the peer was still sending is not asked
	about at all: RFC 9113 5.1 has frames that follow our own RST_STREAM
	ignored, and these are the in-flight case, not a violation - a body behind
	a refused HEADERS, or the rest of one over MAX_BODY (#390). See
	Conn.reset_ids.
	*/
	// Ended by the peer, so nothing more is in flight on it; see handle_headers.
	reset_here := !found && was_reset_here(c, h.stream_id, forget = h.flags & FLAG_END_STREAM != 0)
	send_closed_rst := !found && !reset_here && c.closed_stream_rst_budget > 0
	if send_closed_rst {
		c.closed_stream_rst_budget -= 1
	}
	/*
	RFC 9113 5.1: half-closed (remote) and closed both allow WINDOW_UPDATE,
	PRIORITY, and RST_STREAM from the peer and nothing else. A stream in
	either state already has, or is getting, a handler's full attention - so
	this is refused rather than retired: retiring it here would race whoever
	answers it.

	`cancelled` already gates `respond` and `write_body` (set there by an
	inbound RST_STREAM), so setting it here too - under the same lock that
	makes the check, not after - narrows the race between this and a handler
	mid-`respond` without a second flag, though it does not close it: `respond`
	and `write_body` both read `cancelled`, drop the lock, and only then write,
	so a handler that reads it as false just before this runs can still write
	one HEADERS frame after the RST_STREAM this sends. `cancelled` is already
	true by the time that RST_STREAM goes out, so `write_body`'s first
	per-chunk check catches it before any DATA follows - only the HEADERS frame
	can escape. Closing that outright would mean holding `c.mu` across a
	blocking write, which is the worse trade. Setting `cancelled` here also
	means a stream the peer already reset draws no RST_STREAM of ours in
	answer, since it is already true by the time DATA gets here - avoiding the
	loop RFC 9113 5.4.2 warns against - and a peer that repeats the violation
	on a stream we reset first just draws its credit back without a second one.
	*/
	already_ended := found && (s.state == .Half_Closed_Remote || s.state == .Closed)
	need_rst := already_ended && mark_stream_closed(c, s)
	if found && !already_ended {
		// Checked before appending, so an oversized body is refused rather than
		// buffered first. Over the connection's share rather than the stream's,
		// nothing of it reached a handler, so the client may retry it (RFC 9113
		// 8.7).
		//
		// Charged by capacity, not length: left to `append`, a 64 KiB body in
		// 16 KiB frames grows a 116 KiB buffer. Grown here instead, doubling but
		// never past MAX_BODY, so what is charged is what is allocated.
		need := len(s.body) + len(data)
		s.received += len(payload)
		// The second bound is on the window, not the body: see RECV_WINDOW.
		oversized := need > MAX_BODY || s.received > RECV_WINDOW / 2
		grow := 0
		if need > cap(s.body) {
			grow = min(max(need, 2 * cap(s.body)), MAX_BODY) - cap(s.body)
		}
		if oversized || c.request_bytes + grow > MAX_CONN_REQUEST {
			loop.unlock(&c.mu)
			// No handler behind this reset either, so it is budgeted like a refused
			// HEADERS: see stream_error.
			sent := stream_error(c, h.stream_id, oversized ? .Enhance_Your_Calm : .Refused_Stream)
			// The stream is over. Without this it would hold its body, its parked
			// request and one of MAX_HELD_STREAMS slots until the connection went.
			close_stream(c, h.stream_id, peer_sending = h.flags & FLAG_END_STREAM == 0)
			/*
			The stream is finished with, but the connection is not. These bytes
			came off it and count against a receive window every stream shares,
			and nothing replenishes that on its own - so refusing the body
			without returning the credit costs the connection that much room for
			good.
			*/
			return sent && give_connection_credit(c, len(payload))
		}
		reserve(&s.body, cap(s.body) + grow)
		append(&s.body, ..data)
		s.charged += grow
		c.request_bytes += grow
	}
	loop.unlock(&c.mu)

	if already_ended {
		sent := true
		if need_rst {
			// Budgeted: the stream was just marked closed above, so the peer may open
			// a replacement at once and repeat this for a reset per HEADERS.
			sent = stream_error(c, h.stream_id, .Stream_Closed)
		}
		return sent && give_connection_credit(c, len(payload))
	}

	if send_closed_rst {
		sent := rst_stream(c, h.stream_id, .Stream_Closed)
		return sent && give_connection_credit(c, len(payload))
	}

	// Give the credit back; we buffer whole requests anyway. The stream's own
	// window needs none: see RECV_WINDOW.
	if !give_connection_credit(c, len(payload)) {
		return false
	}

	if !found || h.flags & FLAG_END_STREAM == 0 {
		return true
	}

	/*
	Looked up again rather than reusing the pointer from the top of this
	procedure. The lock was released in between, and a handler answering this
	stream retires it through `close_stream`, which frees it - so the earlier
	pointer may by now refer to memory that is gone. A peer is free to send
	DATA on a stream it has already ended, which is all it takes to be here at
	the same moment as the handler.
	*/
	loop.lock(&c.mu)
	live, still_open := c.streams[h.stream_id]
	if !still_open {
		loop.unlock(&c.mu)
		return true
	}
	set_state(c, live, .Half_Closed_Remote)
	req := live.pending
	live.pending = nil
	loop.unlock(&c.mu)

	if req == nil {
		// DATA before HEADERS completed.
		goaway(c, .Protocol_Error)
		return false
	}
	// Safe to use outside the lock: a parked request means no handler has been
	// given this stream yet, so nothing else is in a position to retire it.
	return dispatch(c, live, req)
}

/*
A frame the peer may not send on `s` any more, a stream it has ended or one end
has reset (RFC 9113 5.1): the stream is cancelled, and Closed since it is reset
for the peer too (see MAX_HELD_STREAMS), but stays its handler's to retire.
Returns whether a STREAM_CLOSED is still owed: not on a stream already
cancelled, so one the peer reset draws none (5.4.2) and a repeat draws no
second. Caller holds c.mu.
*/
@(private)
mark_stream_closed :: proc(c: ^Conn, s: ^Stream) -> (need_rst: bool) {
	need_rst = !s.cancelled
	s.cancelled = true
	set_state(c, s, .Closed)
	// Wakes a handler parked in write_body's no-credit wait; without this it
	// sleeps out the full write_timeout on a stream already known dead.
	loop.cond_broadcast(&c.cond)
	return
}

@(private)
dispatch :: proc(c: ^Conn, s: ^Stream, req: ^Request) -> bool {
	// Handed over rather than copied, so it is held once; the stream keeps the
	// charge until it goes. Both use c.allocator.
	if len(s.body) > 0 {
		req.body = s.body[:]
		s.body = nil
	}
	// Marked before the handler runs, not after: it may answer inline and retire
	// the stream, and a reset arriving for an answered stream must not be read
	// as one nobody was ever given.
	loop.lock(&c.mu)
	s.dispatched = true
	loop.unlock(&c.mu)
	c.handler(c, req)
	// A handler can end the connection too, through `shutdown`, and nothing is
	// read past a GOAWAY this end has sent. Asked here, once per request, rather
	// than once per frame in `serve`: the handler runs inline on the reader.
	loop.lock(&c.mu)
	defer loop.unlock(&c.mu)
	return !c.goaway_sent
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

// A DNS message, which RFC 8484 6 holds to 65535 bytes; restated as
// CLIENT_MAX_BODY is, and `server` asserts it agrees with `dns.MAX_MESSAGE`.
MAX_BODY :: 65535
/*
Request bytes - decoded header fields and body - one connection may hold across
all its streams at once.

MAX_BODY alone bounds a stream, not a connection: connection credit goes back
as DATA arrives, and receive windows are not enforced against a peer anyway, so
MAX_CONCURRENT streams each parked at MAX_BODY pinned 8 MiB a connection
(#303), and a long :path on each does as much without any body. Charged as the
fields are decoded and the body buffered, released only when the stream is
destroyed, so a request handed to a handler still counts until it is answered.
Two maximal requests at once, where real DoH queries are a few hundred bytes. A
stream that would take the connection past it is refused with REFUSED_STREAM,
which a client may retry (RFC 9113 8.7).
*/
MAX_CONN_REQUEST :: 2 * (MAX_BODY + MAX_HEADER_LIST)

// Owe connection-level receive window for bytes that have been read off the
// wire, whatever became of the stream they belonged to, and hand it back once
// CREDIT_BATCH has built up.
@(private)
give_connection_credit :: proc(c: ^Conn, n: int) -> bool {
	frame := owe_connection_credit(&c.credit_owed, n)
	return frame == nil || write_all(c, frame)
}

// Adds `n` to `owed` and, once CREDIT_BATCH has built up, returns the
// connection WINDOW_UPDATE that pays it all back; nil until then. Server and
// client alike.
@(private)
owe_connection_credit :: proc(owed: ^int, n: int) -> []u8 {
	owed^ += n
	if owed^ < CREDIT_BATCH {
		return nil
	}
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	write_frame_header(&out, 4, .Window_Update, 0, 0)
	append_u32(&out, u32(owed^))
	owed^ = 0
	return out[:]
}

// A RST_STREAM the peer drew without a handler behind it, charged against
// MAX_CONTROL_FRAMES_PER_SECOND like a PING.
@(private)
stream_error :: proc(c: ^Conn, stream_id: u32, code: Error_Code) -> bool {
	if !spend_control_budget(c) {
		return false
	}
	return rst_stream(c, stream_id, code)
}

@(private)
rst_stream :: proc(c: ^Conn, stream_id: u32, code: Error_Code) -> bool {
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	write_frame_header(&out, 4, .Rst_Stream, 0, stream_id)
	append_u32(&out, u32(code))
	return write_all(c, out[:])
}

// Whether `stream_id` is in Conn.reset_ids, struck off as well with `forget`.
// Caller holds `c.mu`.
@(private)
was_reset_here :: proc(c: ^Conn, stream_id: u32, forget := false) -> bool {
	// 0 marks an empty slot.
	if stream_id == 0 {
		return false
	}
	for &id in c.reset_ids {
		if id == stream_id {
			if forget {
				id = 0
			}
			return true
		}
	}
	return false
}

@(private)
goaway :: proc(c: ^Conn, code: Error_Code) {
	loop.lock(&c.mu)
	if c.goaway_sent {
		loop.unlock(&c.mu)
		return
	}
	c.goaway_sent = true
	last := c.last_stream_id
	loop.unlock(&c.mu)

	out := make([dynamic]u8, 0, 17, context.temp_allocator)
	write_frame_header(&out, 8, .Goaway, 0, 0)
	append_u32(&out, last)
	append_u32(&out, u32(code))
	_ = write_all(c, out[:])
}

/*
End the connection from a handler: GOAWAY(NO_ERROR), which RFC 9113 6.8 says an
endpoint SHOULD send before closing. Called inline, from the handler `dispatch`
runs on the reader, `serve` reads nothing after it; `dispatch` is where that is
checked, so from a fiber of the handler's own it takes effect only at the next
request the reader dispatches. Streams already started are not waited for: once
`serve` returns their writes are refused. 6.8 says such streams "might still
complete", which does not oblige them to, and the peer is told only that they may
have been processed.
*/
shutdown :: proc(c: ^Conn) {
	goaway(c, .No_Error)
}

/*
Send a response and close the stream.

Safe to call from any thread. Blocks while the peer's flow-control window has no
room, waking when a WINDOW_UPDATE arrives or the connection closes.
*/
respond :: proc(c: ^Conn, stream_id: u32, resp: Response) -> bool {
	resp := resp
	if resp.head {
		resp.body = nil
	}
	loop.lock(&c.mu)
	s, found := c.streams[stream_id]
	cancelled := found && s.cancelled
	if found && len(resp.body) == 0 {
		// Its END_STREAM rides on the HEADERS below; see MAX_HELD_STREAMS.
		set_state(c, s, .Closed)
	}
	loop.unlock(&c.mu)
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
	if resp.allow != "" {
		encode_header(&block, "allow", resp.allow)
	}
	if !resp.head {
		encode_header(&block, "content-length", int_to_string(len(resp.body), context.temp_allocator))
	}
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
	// On the tick clock: a step of the wall clock must not cut every pending
	// write off at once, nor hold a fiber for the length of the step.
	deadline := time.tick_add(loop.tick_now(), c.write_timeout)
	sent := 0
	for sent < len(body) {
		remaining := len(body) - sent

		loop.lock(&c.mu)
		chunk := 0
		for {
			if c.closed {
				loop.unlock(&c.mu)
				return false
			}
			s, found := c.streams[stream_id]
			if !found || s.cancelled {
				loop.unlock(&c.mu)
				return true
			}
			available := min(c.send_window, s.send_window)
			available = min(available, c.peer_max_frame)
			available = min(available, remaining)
			if available > 0 {
				chunk = available
				c.send_window -= chunk
				s.send_window -= chunk
				if chunk == remaining {
					// This chunk carries END_STREAM; see MAX_HELD_STREAMS.
					set_state(c, s, .Closed)
				}
				break
			}
			/*
			No credit. A WINDOW_UPDATE or a close will wake us; the deadline is
			what handles the peer that sends neither. Its reader stays perfectly
			healthy, so nothing else would ever mark this connection dead, and
			the wait would keep the query and its fiber for as long as the peer
			felt like holding it.
			*/
			left := time.tick_diff(loop.tick_now(), deadline)
			if left <= 0 {
				// Marked here, under the same lock, for the same reason
				// handle_data's already_ended path marks it before sending its
				// own RST_STREAM: a DATA frame landing in the gap between this
				// and respond's close_stream must find a stream already known
				// dead, not send a second RST_STREAM onto one this end just reset.
				s.cancelled = true
				set_state(c, s, .Closed)
				loop.cond_broadcast(&c.cond)
				loop.unlock(&c.mu)
				rst_stream(c, stream_id, .Cancel)
				return false
			}
			loop.cond_wait_with_timeout(&c.cond, &c.mu, left)
		}
		loop.unlock(&c.mu)

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

/*
Retire a stream and release it.

The free happens under the lock, not after it. The reader looks streams
up while holding `c.mu` and acts on what it finds; releasing one outside the
lock would let this run between that lookup and the use, leaving the reader
writing into memory that has already gone back to the allocator. Nothing here
does I/O or takes another lock, so holding `c.mu` across it costs nothing.
*/
@(private)
close_stream :: proc(c: ^Conn, stream_id: u32, peer_sending := false) {
	loop.lock(&c.mu)
	defer loop.unlock(&c.mu)
	s, found := c.streams[stream_id]
	if !found {
		return
	}
	// Reset by this end with the peer still sending: see Conn.reset_ids.
	if peer_sending {
		c.reset_ids[c.reset_next] = stream_id
		c.reset_next = (c.reset_next + 1) % len(c.reset_ids)
	}
	delete_key(&c.streams, stream_id)
	if s.state == .Closed {
		c.closed_held -= 1
	}
	stream_destroy(c, s)
}

/*
The `:status` value as HPACK wants it: the code's three digits (RFC 9113 8.3.2).

Converted rather than looked up, so that no status a caller sends can be missing
from a table. RFC 9110 15 puts every valid code in 100 to 599, and `respond`
sends a final response, which 15.2 says a 1xx is not (RFC 9113 8.6 forbids 101
outright). Anything outside 200 to 599 is a caller's mistake - a Response left at
its zero status - and goes out as 500 rather than as a field no client can use.
*/
@(private)
status_text :: proc(status: int) -> string {
	if status < 200 || status > 599 {
		return "500"
	}
	return int_to_string(status, context.temp_allocator)
}

@(private)
int_to_string :: proc(v: int, allocator: mem.Allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_int(&b, v)
	return strings.to_string(b)
}
