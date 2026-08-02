package h2

/*
HTTP/2 framing (RFC 9113 section 4 and 6).
*/

// The 24-byte client connection preface.
PREFACE :: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_HEADER_SIZE :: 9
DEFAULT_MAX_FRAME :: 16384
DEFAULT_WINDOW :: 65535
MAX_WINDOW :: 2147483647

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
	append(out, u8(length >> 16), u8(length >> 8), u8(length))
	append(out, u8(type), flags)
	append(out, u8(stream_id >> 24) & 0x7f, u8(stream_id >> 16), u8(stream_id >> 8), u8(stream_id))
}

append_u32 :: proc(out: ^[dynamic]u8, v: u32) {
	append(out, u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v))
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
