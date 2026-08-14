package itest

import "core:encoding/base64"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:time"
import "elodin:h2"
import "elodin:tlsx"

/*
A minimal HTTP/2 client for the integration tests.

Frames are built by hand so the server's framing is checked against something
other than itself. Request headers are HPACK literals, optionally Huffman
coded, which exercises the server's decoder on both paths. Response headers go
through the h2 package's decoder — interoperability with a foreign HPACK
implementation is covered separately by the curl-based checks in the README.
*/

H2_Stream_Result :: struct {
	status:      int,
	body:        []u8,
	headers:     []h2.Header_Field,
	data_frames: int,
	done:        bool,
	reset:       bool,
	// The code the server put in the first RST_STREAM, which is what says why
	// the stream was refused rather than merely that it was.
	reset_code:  h2.Error_Code,
}

// A request field beyond the four pseudo-headers every request carries.
H2_Field :: struct {
	name:  string,
	value: string,
}

H2_Client :: struct {
	conn:      Test_Conn,
	read_buf:  [dynamic]u8,
	decoder:   h2.Dynamic_Table,
	results:   map[u32]^H2_Stream_Result,
	pings:     int,
	goaway:    bool,
	allocator: mem.Allocator,
}

H2_Settings :: struct {
	initial_window: int,
	max_frame:      int,
}

h2_connect :: proc(port: int, settings: H2_Settings = {}, allocator := context.temp_allocator) -> (c: ^H2_Client, ok: bool) {
	conn, dialed := dial_tls(port, []string{"h2"})
	if !dialed {
		return nil, false
	}

	c = new(H2_Client, allocator)
	c.conn = conn
	c.allocator = allocator
	c.read_buf = make([dynamic]u8, 0, 16384, allocator)
	c.results = make(map[u32]^H2_Stream_Result, 8, allocator)
	h2.dynamic_table_init(&c.decoder, 4096, allocator)

	if !conn_write(&c.conn, transmute([]u8)string(h2.PREFACE)) {
		return nil, false
	}

	payload := make([dynamic]u8, 0, 12, allocator)
	if settings.initial_window > 0 {
		append(&payload, 0, u8(h2.Setting.Initial_Window_Size))
		h2.append_u32(&payload, u32(settings.initial_window))
	}
	if settings.max_frame > 0 {
		append(&payload, 0, u8(h2.Setting.Max_Frame_Size))
		h2.append_u32(&payload, u32(settings.max_frame))
	}
	out := make([dynamic]u8, 0, 32, allocator)
	h2.write_frame_header(&out, len(payload), .Settings, 0, 0)
	append(&out, ..payload[:])
	if !conn_write(&c.conn, out[:]) {
		return nil, false
	}
	return c, true
}

h2_close :: proc(c: ^H2_Client) {
	if c == nil {
		return
	}
	close_tls(&c.conn)
}

// Confirms the server picked h2 during the handshake.
h2_negotiated :: proc(port: int) -> string {
	conn, ok := dial_tls(port, []string{"h2", "http/1.1"})
	if !ok {
		return ""
	}
	defer close_tls(&conn)
	return strings.clone(tlsx.alpn_protocol(conn.tls), context.temp_allocator)
}

@(private)
h2_literal :: proc(out: ^[dynamic]u8, name, value: string, huffman: bool) {
	// Literal header field without indexing, new name.
	append(out, 0x00)
	h2_write_string(out, name, huffman)
	h2_write_string(out, value, huffman)
}

@(private)
h2_write_string :: proc(out: ^[dynamic]u8, s: string, huffman: bool) {
	if !huffman {
		h2_write_integer(out, 7, len(s), 0x00)
		append(out, ..transmute([]u8)s)
		return
	}
	encoded := h2_huffman_encode(s, context.temp_allocator)
	h2_write_integer(out, 7, len(encoded), 0x80)
	append(out, ..encoded)
}

@(private)
h2_write_integer :: proc(out: ^[dynamic]u8, prefix_bits: uint, value: int, flags: u8) {
	mask := int(1 << prefix_bits) - 1
	if value < mask {
		append(out, flags | u8(value))
		return
	}
	append(out, flags | u8(mask))
	v := value - mask
	for v >= 0x80 {
		append(out, u8(v & 0x7f) | 0x80)
		v >>= 7
	}
	append(out, u8(v))
}

// Huffman encoder, used only to drive the server's decoder.
@(private)
h2_huffman_encode :: proc(s: string, allocator := context.temp_allocator) -> []u8 {
	out := make([dynamic]u8, 0, len(s), allocator)
	acc: u64 = 0
	bits: uint = 0
	for i in 0 ..< len(s) {
		sym := int(s[i])
		acc = (acc << uint(h2.HUFFMAN_LEN[sym])) | u64(h2.HUFFMAN_CODE[sym])
		bits += uint(h2.HUFFMAN_LEN[sym])
		for bits >= 8 {
			bits -= 8
			append(&out, u8((acc >> bits) & 0xff))
		}
	}
	if bits > 0 {
		// Pad with the EOS prefix, which is all ones.
		pad := 8 - bits
		acc = (acc << pad) | ((1 << pad) - 1)
		append(&out, u8(acc & 0xff))
	}
	return out[:]
}

/*
Send a request. `split_headers` sends the block as HEADERS plus a CONTINUATION
frame, which browsers do for large header sets.
*/
h2_send_request :: proc(
	c: ^H2_Client,
	stream_id: u32,
	method, path: string,
	body: []u8,
	content_type := "application/dns-message",
	huffman := false,
	split_headers := false,
	// A dynamic table size update at the head of the block, where HPACK
	// requires one to be. Negative sends none.
	table_update := -1,
	// Sent after the fields above, so a check can put a field of its own on a
	// request that is otherwise ordinary.
	extra: []H2_Field = nil,
) -> bool {
	block := make([dynamic]u8, 0, 128, context.temp_allocator)
	if table_update >= 0 {
		h2_write_integer(&block, 5, table_update, 0x20)
	}
	h2_literal(&block, ":method", method, huffman)
	h2_literal(&block, ":scheme", "https", huffman)
	h2_literal(&block, ":authority", "elodin.local", huffman)
	h2_literal(&block, ":path", path, huffman)
	if method == "POST" && content_type != "" {
		h2_literal(&block, "content-type", content_type, huffman)
	}
	h2_literal(&block, "accept", "application/dns-message", huffman)
	for f in extra {
		h2_literal(&block, f.name, f.value, huffman)
	}

	end_stream: u8 = h2.FLAG_END_STREAM if len(body) == 0 else 0
	out := make([dynamic]u8, 0, len(block) + 32, context.temp_allocator)

	if split_headers && len(block) > 4 {
		half := len(block) / 2
		h2.write_frame_header(&out, half, .Headers, end_stream, stream_id)
		append(&out, ..block[:half])
		h2.write_frame_header(&out, len(block) - half, .Continuation, h2.FLAG_END_HEADERS, stream_id)
		append(&out, ..block[half:])
	} else {
		h2.write_frame_header(&out, len(block), .Headers, h2.FLAG_END_HEADERS | end_stream, stream_id)
		append(&out, ..block[:])
	}

	if len(body) > 0 {
		h2.write_frame_header(&out, len(body), .Data, h2.FLAG_END_STREAM, stream_id)
		append(&out, ..body)
	}
	return conn_write(&c.conn, out[:])
}

h2_send_get :: proc(c: ^H2_Client, stream_id: u32, path: string, query: []u8, huffman := false) -> bool {
	encoded, err := base64.encode(query, base64.ENC_URL_TABLE, context.temp_allocator)
	if err != nil {
		return false
	}
	target := strings.concatenate({path, "?dns=", strings.trim_right(encoded, "=")}, context.temp_allocator)
	return h2_send_request(c, stream_id, "GET", target, nil, huffman = huffman)
}

h2_send_rst :: proc(c: ^H2_Client, stream_id: u32) -> bool {
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	h2.write_frame_header(&out, 4, .Rst_Stream, 0, stream_id)
	h2.append_u32(&out, u32(h2.Error_Code.Cancel))
	return conn_write(&c.conn, out[:])
}

h2_send_ping :: proc(c: ^H2_Client, payload: [8]u8) -> bool {
	out := make([dynamic]u8, 0, 17, context.temp_allocator)
	h2.write_frame_header(&out, 8, .Ping, 0, 0)
	data := payload
	append(&out, ..data[:])
	return conn_write(&c.conn, out[:])
}

h2_send_window_update :: proc(c: ^H2_Client, stream_id: u32, increment: int) -> bool {
	out := make([dynamic]u8, 0, 13, context.temp_allocator)
	h2.write_frame_header(&out, 4, .Window_Update, 0, stream_id)
	h2.append_u32(&out, u32(increment))
	return conn_write(&c.conn, out[:])
}

/*
Read frames until every stream in `wanted` has ended, or the deadline passes.
*/
h2_collect :: proc(c: ^H2_Client, wanted: []u32, timeout := 10 * time.Second) -> bool {
	deadline := time.time_add(time.now(), timeout)

	for time.diff(deadline, time.now()) < 0 {
		if h2_all_done(c, wanted) {
			return true
		}
		if !h2_pump(c) {
			return h2_all_done(c, wanted)
		}
	}
	return h2_all_done(c, wanted)
}

@(private)
h2_all_done :: proc(c: ^H2_Client, wanted: []u32) -> bool {
	for id in wanted {
		r, found := c.results[id]
		if !found || !(r.done || r.reset) {
			return false
		}
	}
	return true
}

// Read once, then consume every complete frame in the buffer.
@(private)
h2_pump :: proc(c: ^H2_Client) -> bool {
	chunk: [16384]u8
	n, ok := conn_read(&c.conn, chunk[:])
	if !ok {
		return false
	}
	append(&c.read_buf, ..chunk[:n])

	for {
		if len(c.read_buf) < h2.FRAME_HEADER_SIZE {
			return true
		}
		header, hok := h2.parse_frame_header(c.read_buf[:])
		if !hok {
			return false
		}
		total := h2.FRAME_HEADER_SIZE + header.length
		if len(c.read_buf) < total {
			return true
		}
		payload := c.read_buf[h2.FRAME_HEADER_SIZE:total]

		if !h2_handle(c, header, payload) {
			return false
		}
		remaining := len(c.read_buf) - total
		copy(c.read_buf[:remaining], c.read_buf[total:])
		resize(&c.read_buf, remaining)
	}
}

@(private)
h2_result :: proc(c: ^H2_Client, stream_id: u32) -> ^H2_Stream_Result {
	if r, found := c.results[stream_id]; found {
		return r
	}
	r := new(H2_Stream_Result, c.allocator)
	c.results[stream_id] = r
	return r
}

@(private)
h2_handle :: proc(c: ^H2_Client, header: h2.Frame_Header, payload: []u8) -> bool {
	#partial switch header.type {
	case .Settings:
		if header.flags & h2.FLAG_ACK == 0 {
			out := make([dynamic]u8, 0, h2.FRAME_HEADER_SIZE, context.temp_allocator)
			h2.write_frame_header(&out, 0, .Settings, h2.FLAG_ACK, 0)
			return conn_write(&c.conn, out[:])
		}

	case .Ping:
		if header.flags & h2.FLAG_ACK != 0 {
			c.pings += 1
		}

	case .Goaway:
		c.goaway = true

	case .Rst_Stream:
		r := h2_result(c, header.stream_id)
		// The first code and not the last, because a stream can be reset twice
		// over and only the first reset says why it died. A malformed POST
		// draws PROTOCOL_ERROR from `finish_headers`, and the DATA frame that
		// was already on the wire behind it - the HEADERS carried no
		// END_STREAM - then finds the stream retired and draws a second
		// RST_STREAM carrying STREAM_CLOSED. Both are the server behaving
		// correctly, and which of them a check would have read depended on
		// whether the two arrived in the same `h2_pump` read. `r.reset` is
		// what tells one from the other, so it is read here and set after.
		if !r.reset && len(payload) >= 4 {
			r.reset_code = h2.Error_Code(h2.read_u32(payload))
		}
		r.reset = true

	case .Headers:
		block, ok := h2.strip_padding(payload, header.flags)
		if !ok {
			return false
		}
		block2, pok := h2.strip_priority(block, header.flags)
		if !pok {
			return false
		}
		fields, err := h2.decode(&c.decoder, block2, c.allocator)
		if err != .None {
			return false
		}
		r := h2_result(c, header.stream_id)
		r.headers = fields
		for f in fields {
			if f.name == ":status" {
				r.status = strconv.parse_int(f.value) or_else 0
			}
		}
		if header.flags & h2.FLAG_END_STREAM != 0 {
			r.done = true
		}

	case .Data:
		data, ok := h2.strip_padding(payload, header.flags)
		if !ok {
			return false
		}
		r := h2_result(c, header.stream_id)
		grown := make([]u8, len(r.body) + len(data), c.allocator)
		copy(grown, r.body)
		copy(grown[len(r.body):], data)
		r.body = grown
		r.data_frames += 1
		if header.flags & h2.FLAG_END_STREAM != 0 {
			r.done = true
		}
	}
	return true
}

h2_stream :: proc(c: ^H2_Client, stream_id: u32) -> (r: ^H2_Stream_Result, ok: bool) {
	res, found := c.results[stream_id]
	return res, found
}

h2_header_value :: proc(r: ^H2_Stream_Result, name: string) -> string {
	if r == nil {
		return ""
	}
	for f in r.headers {
		if f.name == name {
			return f.value
		}
	}
	return ""
}
