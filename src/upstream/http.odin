package upstream

import "core:mem"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:time"
import "elodin:logx"
import "elodin:tlsx"

/*
A small HTTP/1.1 client.

It exists to serve two callers: blocklist downloads, which have no HTTP/2
server to talk to, and DoH upstream queries (RFC 8484) against a resolver that
ALPN showed does not speak h2 — see h2client.odin for the one that does.
*/

// Either half of a connection: plain TCP or TLS-wrapped.
Stream :: struct {
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
}

stream_read :: proc(s: ^Stream, buf: []u8) -> (n: int, err: Error) {
	if s.tls != nil {
		got, terr := tlsx.read(s.tls, buf)
		if terr == .Closed {
			return 0, .None
		}
		if terr != .None {
			return 0, .IO_Error
		}
		return got, .None
	}
	got, nerr := net.recv_tcp(s.socket, buf)
	if nerr != nil {
		return 0, .IO_Error
	}
	return got, .None
}

stream_write :: proc(s: ^Stream, buf: []u8) -> Error {
	if s.tls != nil {
		if _, err := tlsx.write(s.tls, buf); err != .None {
			return .IO_Error
		}
		return .None
	}
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(s.socket, buf[sent:])
		if err != nil || n <= 0 {
			return .IO_Error
		}
		sent += n
	}
	return .None
}

stream_close :: proc(s: ^Stream) {
	if s.tls != nil {
		tlsx.close(s.tls)
		s.tls = nil
		return
	}
	net.close(s.socket)
}

@(private)
Buf_Reader :: struct {
	stream: ^Stream,
	buf:    [dynamic]u8,
	pos:    int,
}

@(private)
reader_fill :: proc(r: ^Buf_Reader) -> Error {
	chunk: [8192]u8
	n, err := stream_read(r.stream, chunk[:])
	if err != .None {
		return err
	}
	if n == 0 {
		return .IO_Error
	}
	append(&r.buf, ..chunk[:n])
	return .None
}

// Read up to and including the next CRLF, returning the line without it.
@(private)
reader_line :: proc(r: ^Buf_Reader) -> (line: string, err: Error) {
	for {
		if idx := index_crlf(r.buf[r.pos:]); idx >= 0 {
			start := r.pos
			r.pos += idx + 2
			return string(r.buf[start:start + idx]), .None
		}
		if len(r.buf) > 64 * 1024 {
			return "", .HTTP_Error
		}
		reader_fill(r) or_return
	}
}

@(private)
index_crlf :: proc(b: []u8) -> int {
	for i in 0 ..< max(0, len(b) - 1) {
		if b[i] == '\r' && b[i + 1] == '\n' {
			return i
		}
	}
	return -1
}

@(private)
reader_exact :: proc(r: ^Buf_Reader, n: int) -> (data: []u8, err: Error) {
	// A count no read can satisfy. Falling through would step the cursor
	// backwards and return a slice ending before it starts, which a release
	// build compiles without the bounds check that catches it here.
	if n < 0 {
		return nil, .HTTP_Error
	}
	for len(r.buf) - r.pos < n {
		reader_fill(r) or_return
	}
	start := r.pos
	r.pos += n
	return r.buf[start:start + n], .None
}

// Read until the peer closes, for responses with no length information.
@(private)
reader_to_end :: proc(r: ^Buf_Reader) -> []u8 {
	for {
		if err := reader_fill(r); err != .None {
			break
		}
	}
	return r.buf[r.pos:]
}

Http_Response :: struct {
	status:   int,
	body:     []u8,
	location: string,
	// Whether the server agreed to keep the connection open.
	keep_alive: bool,
}

Http_Request :: struct {
	method:       string,
	path:         string,
	host:         string,
	body:         []u8,
	content_type: string,
	accept:       string,
	// Extra headers, already formatted as "Name: value" without CRLF.
	extra:        []string,
}

MAX_HTTP_BODY :: 64 * 1024 * 1024

/*
Perform one request/response exchange on `stream`.

The returned body is allocated from `allocator`; everything else borrows from
scratch memory and must be copied if it needs to outlive the call.
*/
http_exchange :: proc(
	stream: ^Stream,
	req: Http_Request,
	allocator := context.allocator,
) -> (
	resp: Http_Response,
	err: Error,
) {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, req.method)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, req.path)
	strings.write_string(&b, " HTTP/1.1\r\nHost: ")
	strings.write_string(&b, req.host)
	strings.write_string(&b, "\r\nUser-Agent: elodin\r\nConnection: keep-alive\r\n")
	if req.accept != "" {
		strings.write_string(&b, "Accept: ")
		strings.write_string(&b, req.accept)
		strings.write_string(&b, "\r\n")
	}
	if len(req.body) > 0 {
		if req.content_type != "" {
			strings.write_string(&b, "Content-Type: ")
			strings.write_string(&b, req.content_type)
			strings.write_string(&b, "\r\n")
		}
		strings.write_string(&b, "Content-Length: ")
		strings.write_int(&b, len(req.body))
		strings.write_string(&b, "\r\n")
	}
	for h in req.extra {
		strings.write_string(&b, h)
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "\r\n")

	stream_write(stream, transmute([]u8)strings.to_string(b)) or_return
	if len(req.body) > 0 {
		stream_write(stream, req.body) or_return
	}

	r := Buf_Reader {
		stream = stream,
		buf    = make([dynamic]u8, 0, 8192, context.temp_allocator),
	}

	status_line := reader_line(&r) or_return
	resp.status = parse_status(status_line) or_return
	resp.keep_alive = true

	content_length := -1
	chunked := false
	for {
		line := reader_line(&r) or_return
		if line == "" {
			break
		}
		name, value, ok := split_header(line)
		if !ok {
			continue
		}
		switch {
		case strings.equal_fold(name, "content-length"):
			v, vok := strconv.parse_int(strings.trim_space(value))
			if vok {
				content_length = v
			}
		case strings.equal_fold(name, "transfer-encoding"):
			chunked = strings.contains(strings.to_lower(value, context.temp_allocator), "chunked")
		case strings.equal_fold(name, "connection"):
			if strings.equal_fold(strings.trim_space(value), "close") {
				resp.keep_alive = false
			}
		case strings.equal_fold(name, "location"):
			// Scratch, as the doc comment above promises: only the body is the
			// caller's to free. Taking the first of a repeated header rather than
			// the last also stops a server orphaning a string per copy.
			if resp.location == "" {
				resp.location = strings.clone(strings.trim_space(value), context.temp_allocator)
			}
		}
	}

	switch {
	case chunked:
		resp.body = read_chunked(&r, allocator) or_return
	case content_length == 0:
		resp.body = nil
	case content_length > 0:
		if content_length > MAX_HTTP_BODY {
			return resp, .Too_Large
		}
		data := reader_exact(&r, content_length) or_return
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
	case:
		// No framing information: the body ends when the connection does.
		data := reader_to_end(&r)
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
		resp.keep_alive = false
	}
	return resp, .None
}

@(private)
parse_status :: proc(line: string) -> (status: int, err: Error) {
	if !strings.has_prefix(line, "HTTP/") {
		return 0, .HTTP_Error
	}
	space := strings.index_byte(line, ' ')
	if space < 0 || space + 4 > len(line) {
		return 0, .HTTP_Error
	}
	v, ok := strconv.parse_int(line[space + 1:space + 4])
	if !ok {
		return 0, .HTTP_Error
	}
	return v, .None
}

@(private)
split_header :: proc(line: string) -> (name, value: string, ok: bool) {
	idx := strings.index_byte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return line[:idx], strings.trim_space(line[idx + 1:]), true
}

@(private)
read_chunked :: proc(r: ^Buf_Reader, allocator: mem.Allocator) -> (body: []u8, err: Error) {
	out := make([dynamic]u8, 0, 8192, allocator)
	// A body assembled only in part is of no use to anyone, and every `or_return`
	// below is a way to end up holding one.
	defer if err != .None {
		delete(out)
	}
	for {
		line := reader_line(r) or_return
		// A chunk size may carry extensions after a ';'.
		size_text := line
		if idx := strings.index_byte(line, ';'); idx >= 0 {
			size_text = line[:idx]
		}
		/*
		`strconv.parse_u64_of_base` has no overflow check: it wraps and still
		reports success. A header longer than a u64 therefore parses as some
		unrelated number — zero among them, which would be read as the end of
		the body — so the length is settled here, where sixteen significant hex
		digits is exactly what fits.
		*/
		digits := strings.trim_space(size_text)
		for len(digits) > 1 && digits[0] == '0' {
			digits = digits[1:]
		}
		if len(digits) == 0 || len(digits) > 16 {
			return nil, .HTTP_Error
		}
		size, ok := strconv.parse_u64_of_base(digits, 16)
		if !ok {
			return nil, .HTTP_Error
		}
		if size == 0 {
			// Trailers, then the final CRLF.
			for {
				trailer := reader_line(r) or_return
				if trailer == "" {
					break
				}
			}
			break
		}
		// Bounded before it is narrowed. A size past the body limit is refused
		// whatever it is, so the `int` below is always a number this build can
		// hold and the sum below it cannot overflow.
		if size > u64(MAX_HTTP_BODY) || len(out) + int(size) > MAX_HTTP_BODY {
			return nil, .Too_Large
		}
		data := reader_exact(r, int(size)) or_return
		append(&out, ..data)
		reader_line(r) or_return
	}
	return out[:], .None
}

/*
Open a stream to `endpoint`, optionally wrapping it in TLS.

`tls_ctx` is nil for plain HTTP. `hostname` is used for SNI and certificate
verification.
*/
open_stream :: proc(
	endpoint: net.Endpoint,
	tls_ctx: ^tlsx.Context,
	hostname: string,
	timeout: time.Duration,
) -> (
	stream: Stream,
	err: Error,
) {
	socket := dial_tcp_timeout(endpoint, timeout) or_return
	set_socket_timeouts(socket, timeout)
	_ = net.set_option(socket, .TCP_Nodelay, true)

	if tls_ctx == nil {
		return Stream{socket = socket}, .None
	}
	conn, terr := tlsx.client_connect(tls_ctx, socket, hostname)
	if terr != .None {
		logx.debugf(
			"TLS handshake with %q failed: %s",
			hostname,
			tlsx.describe_error(terr, context.temp_allocator),
		)
		net.close(socket)
		return {}, .Verify_Failed if terr == .Verify_Failed else .TLS_Failed
	}
	return Stream{socket = socket, tls = conn}, .None
}
