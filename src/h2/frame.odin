package h2

import "elodin:dns"
import "elodin:loop"

/*
HTTP/2 framing (RFC 9113 section 4 and 6).
*/

// The 24-byte client connection preface.
PREFACE :: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_HEADER_SIZE :: 9
DEFAULT_MAX_FRAME :: 16384
DEFAULT_WINDOW :: 65535
MAX_WINDOW :: 2147483647

/*
The receive window this end advertises, on the connection and on each stream,
client and server alike. Generous, so a peer is never throttled sending to us,
and DNS messages are tiny anyway. Well past MAX_BODY, so a stream is never given
more than this and only the connection window needs replenishing. Padding spends
the window without growing the body, so a stream is also reset once half the
window has gone (Stream.received, Client_Stream.received), rather than left to
stall with none.
*/
RECV_WINDOW :: 1 << 20
// Bound on one request or response body: a DNS message, which RFC 8484 6 holds
// to 65535 bytes.
MAX_BODY :: dns.MAX_MESSAGE
// The largest SETTINGS_MAX_FRAME_SIZE a peer may advertise (RFC 9113 6.5.2).
MAX_FRAME_SIZE_LIMIT :: (1 << 24) - 1

Frame_Type :: enum u8 {
	Data          = 0x0,
	Headers       = 0x1,
	Priority      = 0x2,
	Rst_Stream    = 0x3,
	Settings      = 0x4,
	Push_Promise  = 0x5,
	Ping          = 0x6,
	Goaway        = 0x7,
	Window_Update = 0x8,
	Continuation  = 0x9,
}

// Flag bits. Their meaning depends on the frame type, so they are named after
// the frames that use them.
FLAG_ACK :: 0x1
FLAG_END_STREAM :: 0x1
FLAG_END_HEADERS :: 0x4
FLAG_PADDED :: 0x8
FLAG_PRIORITY :: 0x20

Setting :: enum u16 {
	Header_Table_Size      = 0x1,
	Enable_Push            = 0x2,
	Max_Concurrent_Streams = 0x3,
	Initial_Window_Size    = 0x4,
	Max_Frame_Size         = 0x5,
	Max_Header_List_Size   = 0x6,
}

Error_Code :: enum u32 {
	No_Error            = 0x0,
	Protocol_Error      = 0x1,
	Internal_Error      = 0x2,
	Flow_Control_Error  = 0x3,
	Settings_Timeout    = 0x4,
	Stream_Closed       = 0x5,
	Frame_Size_Error    = 0x6,
	Refused_Stream      = 0x7,
	Cancel              = 0x8,
	Compression_Error   = 0x9,
	Connect_Error       = 0xa,
	Enhance_Your_Calm   = 0xb,
	Inadequate_Security = 0xc,
	Http_1_1_Required   = 0xd,
}

Frame_Header :: struct {
	length:    int,
	type:      Frame_Type,
	flags:     u8,
	stream_id: u32,
}

parse_frame_header :: proc(buf: []u8) -> (h: Frame_Header, ok: bool) {
	if len(buf) < FRAME_HEADER_SIZE {
		return {}, false
	}
	h.length = int(buf[0]) << 16 | int(buf[1]) << 8 | int(buf[2])
	h.type = Frame_Type(buf[3])
	h.flags = buf[4]
	// The top bit is reserved and must be ignored on receipt.
	h.stream_id =
		(u32(buf[5]) & 0x7f) << 24 | u32(buf[6]) << 16 | u32(buf[7]) << 8 | u32(buf[8])
	return h, true
}

write_frame_header :: proc(out: ^[dynamic]u8, length: int, type: Frame_Type, flags: u8, stream_id: u32) {
	h: [FRAME_HEADER_SIZE]u8
	put_frame_header(h[:], length, type, flags, stream_id)
	append(out, ..h[:])
}

append_u32 :: proc(out: ^[dynamic]u8, v: u32) {
	b: [4]u8
	put_u32(b[:], v)
	append(out, ..b[:])
}

// A frame header into the first FRAME_HEADER_SIZE bytes of `out`.
@(private)
put_frame_header :: proc(out: []u8, length: int, type: Frame_Type, flags: u8, stream_id: u32) {
	out[0], out[1], out[2] = u8(length >> 16), u8(length >> 8), u8(length)
	out[3], out[4] = u8(type), flags
	put_u32(out[5:], stream_id & 0x7fff_ffff)
}

// `v` into the first four bytes of `out`, in network byte order.
@(private)
put_u32 :: proc(out: []u8, v: u32) {
	out[0], out[1], out[2], out[3] = u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v)
}

read_u32 :: proc(b: []u8) -> u32 {
	if len(b) < 4 {
		return 0
	}
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}

read_u16 :: proc(b: []u8) -> u16 {
	if len(b) < 2 {
		return 0
	}
	return u16(b[0]) << 8 | u16(b[1])
}

/*
Strip padding from a DATA or HEADERS payload.

When PADDED is set the first byte is the pad length, and that many bytes are
removed from the end. A pad length that does not leave room is a connection
error (RFC 9113 section 6.1).
*/
strip_padding :: proc(payload: []u8, flags: u8) -> (out: []u8, ok: bool) {
	if flags & FLAG_PADDED == 0 {
		return payload, true
	}
	if len(payload) < 1 {
		return nil, false
	}
	pad := int(payload[0])
	if 1 + pad > len(payload) {
		return nil, false
	}
	return payload[1:len(payload) - pad], true
}

// HEADERS carries an optional 5-byte priority section before the block.
strip_priority :: proc(payload: []u8, flags: u8) -> (out: []u8, ok: bool) {
	if flags & FLAG_PRIORITY == 0 {
		return payload, true
	}
	if len(payload) < 5 {
		return nil, false
	}
	return payload[5:], true
}

/*
Fill `buf` from the transport, client and server alike. One whole thing off the
wire starts here: everything this package reads it reads through this, so this
is the one place that has to say so. See `IO`.
*/
@(private)
io_read_exact :: proc(io: IO, buf: []u8, starts_frame := true) -> bool {
	if io.begin != nil {
		io.begin(io.user, starts_frame)
	}
	got := 0
	for got < len(buf) {
		n, ok := io.read(io.user, buf[got:])
		if !ok || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

/*
One write to the transport under `mu`, so frames from concurrent writers do not
interleave; refused once `closed` is set. Refused as well for an empty `buf`,
which is what a frame builder returns where it had no room: every frame carries
at least its header, so nothing is ever a write of nothing.
*/
@(private)
io_write_locked :: proc(io: IO, mu: ^loop.Mutex, closed: ^bool, buf: []u8) -> bool {
	if len(buf) == 0 {
		return false
	}
	loop.lock(mu)
	defer loop.unlock(mu)
	if closed^ {
		return false
	}
	return io.write(io.user, buf)
}

/*
The next frame off the wire, client and server alike, its payload in
`context.temp_allocator`. False once nothing more can be read; `refuse` set as well is the GOAWAY code
the caller sends before it stops. A payload there is no room for is
INTERNAL_ERROR: its bytes are still on the wire, and the next frame header cannot
be found without reading them.

Bounded at the frame size this end advertises, not at the receive window:
neither end sends SETTINGS_MAX_FRAME_SIZE, so the peer is held to the RFC 9113
6.5.2 default (16384), and accepting 64x that (RECV_WINDOW) would allow a frame
the peer was told to keep smaller. The window still caps the body a stream may
buffer; this caps a single frame off the wire.

A header block may not be interrupted by frames for other streams (RFC 9113
6.10): `continuation_on` is the stream whose block is open, 0 for none.

A peer that keeps the socket readable never lets the reader park, and the work
it starts on the same loop would wait behind it: counted per frame as well as
per socket call, since `IO` need not be a socket (the tests', read from memory).
See `loop.take_turn`.
*/
@(private)
read_frame :: proc(
	io: IO,
	continuation_on: u32,
) -> (
	h: Frame_Header,
	payload: []u8,
	refuse: Maybe(Error_Code),
	ok: bool,
) {
	loop.take_turn()
	header: [FRAME_HEADER_SIZE]u8
	if !io_read_exact(io, header[:]) {
		return
	}
	h = parse_frame_header(header[:]) or_return
	if h.length > DEFAULT_MAX_FRAME {
		return h, nil, .Frame_Size_Error, false
	}
	if h.length > 0 {
		room: bool
		payload, room = dns.alloc_slice([]u8, h.length, context.temp_allocator)
		if !room {
			return h, nil, .Internal_Error, false
		}
		if !io_read_exact(io, payload, starts_frame = false) {
			return h, nil, nil, false
		}
	}
	if continuation_on != 0 && (h.type != .Continuation || h.stream_id != continuation_on) {
		return h, nil, .Protocol_Error, false
	}
	return h, payload, nil, true
}

/*
A SETTINGS entry whose value is out of range for both ends: the GOAWAY code it
draws (RFC 9113 6.5.2). Enable_Push is checked by each end, since the rule
differs for a client and a server.
*/
@(private)
setting_error :: proc(id: Setting, value: u32) -> (code: Error_Code, bad: bool) {
	#partial switch id {
	case .Max_Frame_Size:
		if value < DEFAULT_MAX_FRAME || value > MAX_FRAME_SIZE_LIMIT {
			return .Protocol_Error, true
		}
	case .Initial_Window_Size:
		if value > MAX_WINDOW {
			return .Flow_Control_Error, true
		}
	}
	return .No_Error, false
}

/*
Apply a new SETTINGS_INITIAL_WINDOW_SIZE: it retroactively adjusts every open
stream's send window, and a stream carried past the maximum by that adjustment
is the same connection error, FLOW_CONTROL_ERROR, as one carried there by a
WINDOW_UPDATE (RFC 9113 6.9.2). `setting_error` only refuses a settings *value*
over the maximum, which does not stop an already-raised window from being nudged
over it. True on that overflow. Caller holds the lock over `streams`.
*/
@(private)
apply_initial_window :: proc(peer_initial: ^int, value: u32, streams: map[u32]^$S) -> (overflow: bool) {
	delta := int(value) - peer_initial^
	peer_initial^ = int(value)
	for _, s in streams {
		s.send_window += delta
		overflow ||= s.send_window > MAX_WINDOW
	}
	return
}

// A WINDOW_UPDATE payload's increment, or the GOAWAY code a malformed one draws
// (RFC 9113 6.9): FRAME_SIZE_ERROR for a length other than 4, PROTOCOL_ERROR for
// a zero increment. The reserved top bit is ignored.
@(private)
window_increment :: proc(payload: []u8) -> (increment: int, code: Error_Code, ok: bool) {
	if len(payload) != 4 {
		return 0, .Frame_Size_Error, false
	}
	increment = int(read_u32(payload) & 0x7fff_ffff)
	if increment == 0 {
		return 0, .Protocol_Error, false
	}
	return increment, .No_Error, true
}

/*
The header block fragment a HEADERS payload carries, padding and priority
stripped, or the GOAWAY code it draws: PROTOCOL_ERROR for padding or priority
that does not fit (RFC 9113 6.2), COMPRESSION_ERROR for a fragment already
past MAX_HEADER_LIST.
*/
@(private)
header_fragment :: proc(payload: []u8, flags: u8) -> (block: []u8, code: Error_Code, ok: bool) {
	body, pok := strip_padding(payload, flags)
	if !pok {
		return nil, .Protocol_Error, false
	}
	block, pok = strip_priority(body, flags)
	if !pok {
		return nil, .Protocol_Error, false
	}
	if len(block) > MAX_HEADER_LIST {
		return nil, .Compression_Error, false
	}
	return block, .No_Error, true
}

/*
The GOAWAY code a header block that does not decode draws, client and server
alike: COMPRESSION_ERROR for the peer's block (RFC 9113 4.3), and INTERNAL_ERROR
where this end had no room to decode it, which is no fault of the peer's (RFC
9113 7).
*/
@(private)
hpack_goaway_code :: proc(err: Hpack_Error) -> Error_Code {
	return .Internal_Error if err == .Out_Of_Memory else .Compression_Error
}

/*
Add a CONTINUATION frame to the header block open on `on^`, client and server
alike. `complete` once END_HEADERS closes it, which clears `on^`; `refuse` is
the GOAWAY code a frame that may not continue it draws, and INTERNAL_ERROR where
the block has no room for it: a block decoded short would leave HPACK out of
step with the peer's encoder.

RFC 9113 6.10: only behind a HEADERS without END_HEADERS, on its stream; with
no block open, `on^` is 0, which is no stream either.

Counted as well as measured. The size cap is no cap against frames that carry
nothing: an empty CONTINUATION never grows the block, so a peer sending them
holds the block open and the reader reading nine-byte frames for as long as it
likes. Nothing accrues, which is why the count is generous - a legitimate block
is MAX_HEADER_LIST at the outside and arrives in a handful of frames, so
anything near MAX_CONTINUATION_FRAMES is a peer with something else in mind.

Bounded as it accumulates, not once it is whole. Neither HEADERS nor
CONTINUATION is flow-controlled, so nothing slows a peer sending these, and
HPACK's own limit lives in `decode` - which never runs for a block whose
END_HEADERS never arrives. Without a cap here one connection can make this end
hold as much as it cares to send.
*/
@(private)
continue_header_block :: proc(
	on: ^u32,
	frames: ^int,
	block: ^[dynamic]u8,
	h: Frame_Header,
	payload: []u8,
) -> (
	complete: bool,
	refuse: Maybe(Error_Code),
) {
	if on^ == 0 || on^ != h.stream_id {
		return false, .Protocol_Error
	}
	frames^ += 1
	if frames^ > MAX_CONTINUATION_FRAMES {
		return false, .Enhance_Your_Calm
	}
	if len(block^) + len(payload) > MAX_HEADER_LIST {
		return false, .Compression_Error
	}
	if !append_whole(block, payload) {
		return false, .Internal_Error
	}
	if h.flags & FLAG_END_HEADERS == 0 {
		return false, nil
	}
	on^ = 0
	return true, nil
}

/*
The DATA payload flow control lets go now, at most `remaining`: the smaller of
the connection and stream send windows and the peer's frame size, charged to
both windows. 0 when either window is spent, and nothing is charged. Caller
holds the lock over both windows.
*/
@(private)
take_send_credit :: proc(conn_window, stream_window: ^int, peer_max_frame, remaining: int) -> (chunk: int) {
	chunk = min(conn_window^, stream_window^, peer_max_frame, remaining)
	if chunk <= 0 {
		return 0
	}
	conn_window^ -= chunk
	stream_window^ -= chunk
	return chunk
}

// Appends `bytes` to `out`, or leaves it as it was and returns false where it
// has no room.
@(private)
append_whole :: proc(out: ^[dynamic]u8, bytes: []u8) -> bool {
	before := len(out^)
	append(out, ..bytes)
	return len(out^) == before + len(bytes)
}

/*
DATA and HEADERS, the frames this end writes that carry a payload of any size,
are built in `context.temp_allocator`, reserved whole, or nil where there is no
room; `io_write_locked` refuses nil, so a frame not built is a write that
failed, never a short frame on the wire.
*/
@(private)
build_frame :: proc(type: Frame_Type, flags: u8, stream_id: u32, payload: []u8) -> []u8 {
	out, ok := dns.alloc_list([dynamic]u8, FRAME_HEADER_SIZE + len(payload), context.temp_allocator)
	if !ok {
		return nil
	}
	write_frame_header(&out, len(payload), type, flags, stream_id)
	append(&out, ..payload)
	return out[:]
}

@(private)
data_frame :: proc(stream_id: u32, chunk: []u8, end_stream: bool) -> []u8 {
	return build_frame(.Data, u8(FLAG_END_STREAM) if end_stream else 0, stream_id, chunk)
}

@(private)
headers_frame :: proc(stream_id: u32, block: []u8, end_stream: bool) -> []u8 {
	return build_frame(.Headers, FLAG_END_HEADERS | (u8(FLAG_END_STREAM) if end_stream else 0), stream_id, block)
}

/*
The frames that end a stream or connection, acknowledge the peer's, or return
its window: fixed in size, so built on the stack and never short of memory. One
that could not be built would leave the peer waiting on a stream, short of
window for good, or seeing the connection end with no reason given.
*/

@(private)
rst_stream_frame :: proc(stream_id: u32, code: Error_Code) -> (f: [FRAME_HEADER_SIZE + 4]u8) {
	put_frame_header(f[:], 4, .Rst_Stream, 0, stream_id)
	put_u32(f[FRAME_HEADER_SIZE:], u32(code))
	return
}

@(private)
goaway_frame :: proc(last_stream_id: u32, code: Error_Code) -> (f: [FRAME_HEADER_SIZE + 8]u8) {
	put_frame_header(f[:], 8, .Goaway, 0, 0)
	put_u32(f[FRAME_HEADER_SIZE:], last_stream_id & 0x7fff_ffff)
	put_u32(f[FRAME_HEADER_SIZE + 4:], u32(code))
	return
}

// `payload` is the PING's eight bytes, which the caller has checked.
@(private)
ping_ack_frame :: proc(payload: []u8) -> (f: [FRAME_HEADER_SIZE + 8]u8) {
	put_frame_header(f[:], 8, .Ping, FLAG_ACK, 0)
	copy(f[FRAME_HEADER_SIZE:], payload)
	return
}

@(private)
settings_ack_frame :: proc() -> (f: [FRAME_HEADER_SIZE]u8) {
	put_frame_header(f[:], 0, .Settings, FLAG_ACK, 0)
	return
}

@(private)
window_update_frame :: proc(increment: int) -> (f: [FRAME_HEADER_SIZE + 4]u8) {
	put_frame_header(f[:], 4, .Window_Update, 0, 0)
	put_u32(f[FRAME_HEADER_SIZE:], u32(increment))
	return
}

@(private)
Setting_Value :: struct {
	id:    Setting,
	value: u32,
}

// The bytes one SETTINGS entry takes (RFC 9113 6.5.1).
@(private)
SETTING_SIZE :: 6

/*
What each end opens a connection with, into `buf`: `prefix` (the client's
preface, or nothing), a SETTINGS frame of `settings`, and the WINDOW_UPDATE that
raises the connection's receive window from DEFAULT_WINDOW to RECV_WINDOW.
Returns the bytes written; `buf` has room for `len(prefix) + 2 *
FRAME_HEADER_SIZE + SETTING_SIZE * len(settings) + 4`.
*/
@(private)
opening_frames :: proc(buf: []u8, prefix: string, settings: []Setting_Value) -> []u8 {
	n := copy(buf, prefix)
	put_frame_header(buf[n:], SETTING_SIZE * len(settings), .Settings, 0, 0)
	n += FRAME_HEADER_SIZE
	for st in settings {
		buf[n], buf[n + 1] = u8(u16(st.id) >> 8), u8(st.id)
		put_u32(buf[n + 2:], st.value)
		n += SETTING_SIZE
	}
	put_frame_header(buf[n:], 4, .Window_Update, 0, 0)
	put_u32(buf[n + FRAME_HEADER_SIZE:], RECV_WINDOW - DEFAULT_WINDOW)
	return buf[:n + FRAME_HEADER_SIZE + 4]
}
