package upstream

import "core:mem"
import "core:net"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:h2"
import "elodin:logx"
import "elodin:loop"
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
		// A read that ran out of time is a timeout on either half, as in
		// `pipe_read_full`: `IO_Error` says the peer broke, not that it was slow.
		if terr != .None {
			return 0, roundtrip_failure(terr)
		}
		return got, .None
	}
	got, nerr := loop.recv_tcp(s.socket, buf)
	if nerr != nil {
		// SO_RCVTIMEO expiring is EAGAIN, which core:net calls .Would_Block.
		if nerr == .Timeout || nerr == .Would_Block {
			return 0, .Timeout
		}
		return 0, .IO_Error
	}
	return got, .None
}

/*
`deadline`, when set, bounds the write, and `idle` any one write under it, as
`reader_fill` does for reads: on TLS the whole call waits for what is left, as
`tlsx.write` holds a call to one timeout. On a plain socket it is
the timeout on each `send` - core:net retries a short one with a fresh wait - so
it bounds only a write that fits the socket buffer, which is what the plain-HTTP
caller sends: a list download's GET. DoH is HTTPS only.
*/
stream_write :: proc(s: ^Stream, buf: []u8, deadline := time.Tick{}, idle := time.Duration(0)) -> Error {
	if wait, bounded := next_wait(deadline, idle); bounded {
		if wait <= 0 {
			return .Timeout
		}
		stream_set_write_timeout(s, wait)
	}
	if s.tls != nil {
		if _, err := tlsx.write(s.tls, buf); err != .None {
			return roundtrip_failure(err)
		}
		return .None
	}
	sent := 0
	for sent < len(buf) {
		n, err := loop.send_tcp(s.socket, buf[sent:])
		if err == .Timeout || err == .Would_Block {
			return .Timeout
		}
		if err != nil || n <= 0 {
			return .IO_Error
		}
		sent += n
	}
	return .None
}

/*
How long the next read may wait, on whichever half the stream reads through.
Never less than a millisecond: a zero `SO_RCVTIMEO` is no timeout at all.
*/
stream_set_read_timeout :: proc(s: ^Stream, timeout: time.Duration) {
	bounded := max(timeout, time.Millisecond)
	if s.tls != nil {
		tlsx.set_read_timeout(s.tls, bounded)
		return
	}
	_ = net.set_option(s.socket, .Receive_Timeout, bounded)
}

// The same for the next write.
stream_set_write_timeout :: proc(s: ^Stream, timeout: time.Duration) {
	bounded := max(timeout, time.Millisecond)
	if s.tls != nil {
		tlsx.set_write_timeout(s.tls, bounded)
		return
	}
	_ = net.set_option(s.socket, .Send_Timeout, bounded)
}

stream_close :: proc(s: ^Stream) {
	if s.tls != nil {
		tlsx.close(s.tls)
		s.tls = nil
		return
	}
	net.close(s.socket)
}

/*
Not `core:bufio`: every read here is held to the exchange's deadline, through
`stream_set_read_timeout`, and a line ends at CRLF with a bare CR or LF in it
refused (RFC 9112 2.2), where `bufio.reader_read_string` splits on a bare LF.
*/
@(private)
Buf_Reader :: struct {
	stream:   ^Stream,
	buf:      [dynamic]u8,
	pos:      int,
	// When the whole exchange must be over, and how long any one read may
	// wait; either may be zero for no such bound, and with both zero the
	// timeouts already on the socket apply. See `reader_fill`.
	deadline: time.Tick,
	idle:     time.Duration,
	// The peer has closed: what `reader_to_end` waits for, and the only thing
	// that ends a body with no framing.
	closed:   bool,
	// Some of the response has arrived, whether or not `buf` still holds it.
	received: bool,
}

/*
Read once more from the stream into `buf`. `unread`, when given, is how many
bytes past the cursor the caller is waiting for, so the buffer grows to hold
exactly that rather than doubling past it.
*/
@(private)
reader_fill :: proc(r: ^Buf_Reader, unread := 0) -> Error {
	/*
	A timeout per read bounds a silent peer and nothing else: a peer sending a
	line just inside it, again and again, held the exchange for as long as the
	field limit and the body limit let it (#445). So each read waits for what
	is left of the deadline at most.
	*/
	if wait, bounded := next_wait(r.deadline, r.idle); bounded {
		if wait <= 0 {
			return .Timeout
		}
		stream_set_read_timeout(r.stream, wait)
	}
	chunk: [8192]u8
	// What has been read past is dropped rather than grown over, or a chunked
	// body would be held twice: here, and in the body its chunks are copied to.
	// A view into `buf` lasts only until the next read, so nothing points here.
	if r.pos > 0 && len(r.buf) + len(chunk) > cap(r.buf) {
		kept := copy(r.buf[:], r.buf[r.pos:])
		resize(&r.buf, kept)
		r.pos = 0
	}
	// No more than a waiting read needs once the buffer is full, so the buffer
	// grown for it holds what arrives: bytes the peer sent behind it would grow
	// the whole thing again. Room already there is filled, or what follows a
	// chunk would take a read of its own.
	size := len(chunk)
	if unread > 0 {
		size = clamp(max(unread - (len(r.buf) - r.pos), cap(r.buf) - len(r.buf)), 1, len(chunk))
	}
	n, err := stream_read(r.stream, chunk[:size])
	if err != .None {
		return err
	}
	/*
	Nothing read and no error is the peer having closed.

	`Peer_Closed` only when it closed without having said anything at all,
	which on a pooled connection is routine - it is what `Connection:
	keep-alive` costs when the server's idle timer is shorter than ours - and
	is the one thing `record_failure` must not read as an outage. Once a byte
	of the response has arrived the same close is a reply cut in half, which is
	the server breaking and has to be counted as one, which is what `received`
	answers.

	`reader_to_end` reaches here for the opposite reason, as the close that
	ends a body with no length, and discards whichever of the two it gets.
	*/
	if n == 0 {
		r.closed = true
		return .Peer_Closed if !r.received else .IO_Error
	}
	r.received = true
	// Doubled as bytes arrive, but never past what a waiting read needs - the
	// drop above runs on any read that could grow `buf`, so the cursor is at
	// zero here and that is `unread`.
	// Not reserved to `unread` outright: a length the peer declares and never
	// sends must not cost more than twice what it did send.
	if need := len(r.buf) + n; need > cap(r.buf) {
		grow := max(2 * cap(r.buf), need)
		if unread > 0 {
			grow = min(grow, max(unread, need))
		}
		reserve(&r.buf, grow)
	}
	// Bytes taken off the socket cannot be put back: dropped, the response
	// would go on with a gap in it rather than fail.
	if _, aerr := append(&r.buf, ..chunk[:n]); aerr != nil {
		return .Too_Large
	}
	return .None
}

/*
How long the next read or write may wait: what is left of `deadline`, or `idle`
if that is shorter. `bounded` is false with neither set, and the timeouts
already on the socket apply; a `wait` of zero or less is the deadline passed.
*/
@(private)
next_wait :: proc(deadline: time.Tick, idle: time.Duration) -> (wait: time.Duration, bounded: bool) {
	if deadline == {} {
		return idle, idle > 0
	}
	left := time.tick_diff(time.tick_now(), deadline)
	if idle > 0 && idle < left {
		return idle, true
	}
	return left, true
}

/*
Read up to and including the next CRLF, returning the line without it.

The result is a view into `r.buf`, which a later read may shift down over the
bytes already consumed, or past its capacity move to a different block. So a
line is good until the next read and no longer: `http_exchange` finishes with
each one inside the iteration that produced it, and clones the one thing it
keeps. Anything added here that holds a line across a read has to copy it first.
*/
@(private)
reader_line :: proc(r: ^Buf_Reader) -> (line: string, err: Error) {
	for {
		if idx := index_crlf(r.buf[r.pos:]); idx >= 0 {
			start := r.pos
			r.pos += idx + 2
			line = string(r.buf[start:start + idx])
			/*
			A bare CR or LF, or a NUL, is refused (RFC 9112 2.2, RFC 9110 5.5),
			as the server's `http_line` does (#432). Kept, `Connection:
			keep-alive\nConnection: close` was one field with no `close` in it
			where a peer taking the LF for a line end sent two (#437).
			*/
			for i in 0 ..< len(line) {
				if line[i] == '\r' || line[i] == '\n' || line[i] == 0 {
					return "", .HTTP_Error
				}
			}
			return line, .None
		}
		if len(r.buf) - r.pos > 64 * 1024 {
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
	// backwards and return a slice ending before it starts; the bounds check
	// behind that is a crash a peer can reach, so refuse it as an error here.
	if n < 0 {
		return nil, .HTTP_Error
	}
	for len(r.buf) - r.pos < n {
		reader_fill(r, n) or_return
	}
	start := r.pos
	r.pos += n
	return r.buf[start:start + n], .None
}

/*
Read until the peer closes, for responses with no length information.

Bounded by `limit`, like every other framing path: the header scan stops at 64
KB, and both the chunked and the Content-Length readers check the exchange's
`max_body`.
This one has nothing to check against, so without `limit` a peer that never
sent a length - by omitting both headers, or by sending a Content-Length that is
not a length - would decide on its own how much of our memory to take.
*/
@(private)
reader_to_end :: proc(r: ^Buf_Reader, limit: int) -> (data: []u8, err: Error) {
	for {
		// Checked before the next read rather than after, so the buffer is never
		// grown past the limit it is about to be refused for.
		if len(r.buf) - r.pos > limit {
			return nil, .Too_Large
		}
		/*
		The close is the end of the body, and nothing else is. Any failed read
		ended it: a deadline or a read timeout cut it short and the part that
		had arrived came back as the whole, with no error - for a list, a
		partial copy written over the good cached one (#445).
		*/
		if ferr := reader_fill(r, limit + 1); ferr != .None {
			if r.closed {
				break
			}
			return nil, ferr
		}
	}
	return r.buf[r.pos:], .None
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

// What `http_exchange` takes for a body unless told otherwise: a blocklist. A
// DoH reply is a DNS message and passes `dns.MAX_MESSAGE` instead (#525).
MAX_HTTP_BODY :: 64 * 1024 * 1024

/*
How many header fields — or trailer fields, which are read by the same loop —
one exchange may carry. Interim (1xx) responses draw on the headers' budget,
each one costing a field on top of its own, so a budget per response would let a
run of interim responses go on a hundred times as long. Trailers have a budget
of their own.

`reader_line` bounds a line at 64 KB but says nothing about how many lines
follow, so a peer sending short fields forever was answered for as long as it
kept the socket open. A hundred is well past what any list host or DoH resolver
sends; the largest seen in practice is around twenty.
*/
MAX_HTTP_HEADERS :: 100

/*
Perform one request/response exchange on `stream`.

The returned body is allocated from `allocator`; everything else borrows from
scratch memory and must be copied if it needs to outlive the call. The response
is read through a buffer from `context.allocator`, freed before returning, so
that has to be an allocator that frees: in an arena, every block the buffer
outgrew would stay.

`deadline`, when set, bounds the request's writes and the reading of the whole
response, and `idle` any one read or write under it; see `stream_write` and
`reader_fill`. Without one, only the timeouts already on
the stream apply, and those are per read.

`max_body` is the most the body may be, in every framing, and so the most
`allocator` is asked to hold for it; the reader's buffer holds the fields as
well. A longer body is `Too_Large`, and a declared length past it is refused
before any of the body is read.
*/
http_exchange :: proc(
	stream: ^Stream,
	req: Http_Request,
	allocator := context.allocator,
	deadline := time.Tick{},
	idle := time.Duration(0),
	max_body := MAX_HTTP_BODY,
) -> (
	resp: Http_Response,
	err: Error,
) {
	/*
	The path and host go into the request line and `Host` verbatim, so a byte
	there the request line cannot hold is a request of this client's making that
	a server reads some other way - or, given a CR LF, one carrying fields
	nobody meant to send. Checked here, where every request line is written: a
	list url comes from config, and a redirect's from whoever answered (#438).
	*/
	if !h2.target_is_valid(req.path) || !h2.authority_is_valid(req.host) {
		return {}, .HTTP_Error
	}
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

	stream_write(stream, transmute([]u8)strings.to_string(b), deadline, idle) or_return
	if len(req.body) > 0 {
		stream_write(stream, req.body, deadline, idle) or_return
	}

	// On the heap rather than in scratch, which keeps every block the buffer
	// outgrows until the caller's `free_all` - for a blocklist refresh, every
	// list's download until the last one has loaded.
	r := Buf_Reader {
		stream   = stream,
		buf      = make([dynamic]u8, 0, 8192),
		deadline = deadline,
		idle     = idle,
	}
	defer delete(r.buf)

	/*
	Interim (1xx) responses come first and are passed over: their fields are
	read under the same rules, then dropped, and the next status line is the
	response's own (RFC 9110 15.2). Each one counts against the field limit,
	or a peer could send them forever (#442).
	*/
	http_1_0: bool
	content_length: int
	chunked: bool
	headers := 0
	// A close announced by any response of the exchange, interim ones included,
	// holds for the connection: keeping it costs a dial at most.
	resp.keep_alive = true
	for {
		status_line := reader_line(&r) or_return
		resp.status, http_1_0 = parse_status(status_line) or_return
		// HTTP/1.0 closes unless it says otherwise (RFC 9112 9.3), and saying so
		// is not worth honouring for one saved dial: only 1.1 and later are pooled.
		if http_1_0 {
			resp.keep_alive = false
		}
		// A 101 is an answer to an upgrade this client never asks for.
		if resp.status == 101 {
			return resp, .HTTP_Error
		}
		content_length = -1
		chunked = false
		for {
			line := reader_line(&r) or_return
			if line == "" {
				break
			}
			headers += 1
			if headers > MAX_HTTP_HEADERS {
				return resp, .HTTP_Error
			}
			name, value, ok := split_header(line)
			if !ok {
				return resp, .HTTP_Error
			}
			switch {
			/*
			Names and the `close` option compare without regard to ASCII case and no
			other: `strings.equal_fold` folds Unicode, where the long s (U+017F) is
			an `s`, so `Tran\u017ffer-Encoding` framed the body as chunked (#432).
			*/
			case dns.name_equal_fold(name, "content-length"):
				// RFC 9112 6.3: more than one of these and the message is invalid,
				// agreeing or not.
				if content_length >= 0 {
					return resp, .HTTP_Error
				}
				v, cl_ok := h2.parse_content_length(value, max_body)
				// A value that is not a length is refused here rather than left to
				// fall past the `== 0` and `> 0` cases below onto the read-to-end
				// path, which is not what the peer asked for.
				if !cl_ok {
					return resp, .HTTP_Error
				}
				// Past `max_body` it reads as `max_body + 1`, and is refused below
				// once the status says a body follows: a 304's is its
				// representation's length, and a 1xx's is refused for framing.
				content_length = v
			case dns.name_equal_fold(name, "transfer-encoding"):
				/*
				`chunked` alone, once, or the response is refused (#437). This
				client asks for no codings, so any other is one it cannot undo -
				`chunked, gzip` framed as chunks handed the gzip on as the answer -
				and RFC 9112 6.1 forbids chunked anywhere but last, or twice. Read
				as a substring, `xchunked` took chunk framing out of a plain body.
				*/
				if chunked || !dns.name_equal_fold(value, "chunked") {
					return resp, .HTTP_Error
				}
				chunked = true
			case dns.name_equal_fold(name, "connection"):
				// A list of options (RFC 9110 7.6.1): `keep-alive, close` closes.
				if h2.list_has_token(value, "close") {
					resp.keep_alive = false
				}
			case dns.name_equal_fold(name, "location"):
				// Scratch, as the doc comment above promises: only the body is the
				// caller's to free. Taking the first of a repeated header rather than
				// the last also stops a server orphaning a string per copy.
				// An interim response's Location is not the answer's.
				if resp.location == "" && resp.status >= 200 {
					resp.location = strings.clone(value, context.temp_allocator)
				}
			}
		}
		if resp.status >= 200 {
			break
		}
		/*
		A 1xx may not frame a body (RFC 9110 8.6, RFC 9112 6.1). Passed over,
		one that did had what it framed read as the answer - a 200 of the peer's
		choosing - with the real one left on the connection for the next query.
		*/
		if chunked || content_length >= 0 {
			return resp, .HTTP_Error
		}
		headers += 1
		if headers > MAX_HTTP_HEADERS {
			return resp, .HTTP_Error
		}
	}

	/*
	RFC 9112 6.1: an HTTP/1.0 message with a Transfer-Encoding has faulty
	framing. Alongside a Content-Length the chunks win (6.3), but where the
	other framing would have ended is not a place to read another response
	from, so the connection goes no further.
	*/
	if chunked && http_1_0 {
		return resp, .HTTP_Error
	}
	if chunked && content_length >= 0 {
		resp.keep_alive = false
	}

	switch {
	case resp.status == 204 || resp.status == 304:
		// No body, whatever the fields say (RFC 9112 6.3): read by them, a 204
		// on a kept-alive connection waited for a close that never came (#442).
		// A 204 may not frame a body (RFC 9110 8.6, 6.1); one that does may have
		// sent it, and the next response would be read from inside it. A 304's
		// framing fields describe its representation, and nothing follows it.
		// No caller pools after a non-200 today; this is for the one that does.
		if resp.status == 204 && (chunked || content_length >= 0) {
			resp.keep_alive = false
		}
	case chunked:
		resp.body = read_chunked(&r, allocator, max_body) or_return
	case content_length == 0:
		resp.body = nil
	case content_length > max_body:
		// Before a byte of the body is read.
		return resp, .Too_Large
	case content_length > 0:
		data := reader_exact(&r, content_length) or_return
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
	case:
		// No framing information: the body ends when the connection does.
		data := reader_to_end(&r, max_body) or_return
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
		resp.keep_alive = false
	}
	return resp, .None
}

/*
The status line: `HTTP/1.<DIGIT> SP 3DIGIT`, then optionally a space and a
reason phrase (RFC 9112 4), and whether its version is 1.0.

Not parsed with `strconv`'s detected base, which would read `HTTP/1.1 0x1 OK`
as 1 and `1_0` as 10. The three characters are also checked for what follows
them, since `HTTP/1.1 2000 OK` is not a status line at all and would otherwise
read as 200. And the version is held to `HTTP/1.<DIGIT>`: with only the `HTTP/`
prefix checked, `HTTP/1.1x` would be a version, one this client would go on to
pool as 1.1 (#437).
*/
@(private)
parse_status :: proc(line: string) -> (status: int, http_1_0: bool, err: Error) {
	V :: len("HTTP/1.1")
	if len(line) < V + 4 || line[V] != ' ' {
		return 0, false, .HTTP_Error
	}
	// Major version 1 is the only one spoken on this wire (RFC 9112 2.3).
	if major, _, ok := h2.http1_version(line[:V]); !ok || major != 1 {
		return 0, false, .HTTP_Error
	}
	// A reason phrase is optional, but if anything follows the code it is the
	// space in front of one.
	if len(line) > V + 4 && line[V + 4] != ' ' {
		return 0, false, .HTTP_Error
	}
	// Three digits or 0, which the range check below refuses.
	v := h2.parse_status(line[V + 1:V + 4])
	// RFC 9110 15: a status is 100 to 599. Below that it is not even an interim
	// response to pass over, which is what `099` was read as (#442).
	if v < 100 || v > 599 {
		return 0, false, .HTTP_Error
	}
	return v, line[:V] == "HTTP/1.0", .None
}

@(private)
split_header :: proc(line: string) -> (name, value: string, ok: bool) {
	/*
	A line starting with whitespace is obs-fold (RFC 9112 5.2), and whitespace
	before the colon makes no field name (5.1). Skipped, either one hid a field
	the unfolded or trimmed reading has: `Transfer-Encoding: chunked` then
	` , gzip` framed a gzip body as chunks (#437). Refused by the caller, as is
	a line with no name at all.
	*/
	idx := strings.index_byte(line, ':')
	if idx <= 0 || line[0] == ' ' || line[0] == '\t' || line[idx - 1] == ' ' || line[idx - 1] == '\t' {
		return "", "", false
	}
	return line[:idx], h2.trim_ows(line[idx + 1:]), true
}

@(private)
read_chunked :: proc(r: ^Buf_Reader, allocator: mem.Allocator, limit: int) -> (body: []u8, err: Error) {
	// Never more than `limit` from the start, as never more than it on the way.
	out := make([dynamic]u8, 0, min(8192, limit), allocator)
	// A body assembled only in part is of no use to anyone, and every `or_return`
	// below is a way to end up holding one.
	defer if err != .None {
		delete(out)
	}
	for {
		line := reader_line(r) or_return
		/*
		`1*HEXDIG`, then optionally BWS and a `;` extension (RFC 9112 7.1.1).
		The BWS is spaces and tabs and only in front of the `;`: trimmed off
		both ends regardless, ` 5` and `5 ` were chunk sizes (#437).
		*/
		digits := line
		if idx := strings.index_byte(line, ';'); idx >= 0 {
			digits = strings.trim_right(line[:idx], " \t")
		}
		/*
		Parsed here rather than by `strconv.parse_u64_of_base`, which takes a
		sign and skips `_` - so `+5` and `0_5` were five - and has no overflow
		check: a size longer than a u64 wrapped to some unrelated number, zero
		among them, which would be read as the end of the body. Sixteen
		significant hex digits is exactly what fits.
		*/
		for len(digits) > 1 && digits[0] == '0' {
			digits = digits[1:]
		}
		if len(digits) == 0 || len(digits) > 16 {
			return nil, .HTTP_Error
		}
		size: u64
		for i in 0 ..< len(digits) {
			c := digits[i]
			switch c {
			case '0' ..= '9':
				size = size << 4 | u64(c - '0')
			case 'a' ..= 'f':
				size = size << 4 | u64(c - 'a' + 10)
			case 'A' ..= 'F':
				size = size << 4 | u64(c - 'A' + 10)
			case:
				return nil, .HTTP_Error
			}
		}
		if size == 0 {
			// Trailers, then the final CRLF. Counted like the headers they are.
			trailers := 0
			for {
				trailer := reader_line(r) or_return
				if trailer == "" {
					break
				}
				trailers += 1
				if trailers > MAX_HTTP_HEADERS {
					return nil, .HTTP_Error
				}
			}
			break
		}
		// Bounded before it is narrowed. A size past the body limit is refused
		// whatever it is, so the `int` below is always a number this build can
		// hold and the sum below it cannot overflow.
		if size > u64(limit) || len(out) + int(size) > limit {
			return nil, .Too_Large
		}
		data := reader_exact(r, int(size)) or_return
		// Doubled, but never past `limit`: `append` grows by more than twice,
		// which would hold a body just under the limit in more than it allows.
		if need := len(out) + len(data); need > cap(out) {
			reserve(&out, min(max(2 * cap(out), need), limit))
		}
		append(&out, ..data)
		// The data ends in CRLF and nothing else (RFC 9112 7.1). Thrown away,
		// the line let `helloEXTRA` read as `hello` on a connection kept for
		// the next response (#437).
		if tail := reader_line(r) or_return; tail != "" {
			return nil, .HTTP_Error
		}
	}
	// The caller holds the body for as long as it needs it - a list, through
	// parsing - so not in the capacity its doubling left behind.
	if cap(out) > len(out) {
		shrink(&out)
	}
	return out[:], .None
}

/*
Open a stream to `endpoint`, optionally wrapping it in TLS.

`tls_ctx` is nil for plain HTTP. `hostname` is used for SNI and certificate
verification. `name` names the upstream in the log when there is one to name;
the bootstrap resolver has none.

A handshake the transport killed - a peer that reset the connection partway
through - is retried once on a new socket. Some resolvers do this to a share of
connections while the very next attempt goes through: Quad9 reset roughly a
fifth of the handshakes offered to it from one network, and a single retry
recovered two thirds of those. Left alone they accumulate into the consecutive
failure count and park an upstream that answers perfectly well.

Only that case is retried. A certificate that did not check out will not check
out on a second look, and a handshake that ran out of time has already spent the
caller's budget - retrying it would spend it twice. A reset comes back
immediately, so the retry costs a round trip.

The same reset can also surface before the handshake starts: `dial_tcp_timeout`
reports `Dial_Reset` when the peer closed before this side finished connecting,
which is retried on the same terms.

`timeout` is one deadline over all of it - both dials, both handshakes - so each
step is given what the ones before it left, and a peer slow to accept, slow to
shake hands, or resetting the first attempt just short of the deadline costs the
caller its budget once rather than once per step (#346). The socket leaves
carrying whatever is left; every caller sets its own timeouts on the stream
before using it.
*/
// Whether `open_stream` makes its one retry: only from the first attempt, and only
// inside the deadline. Out of time, the first attempt's failure is the one
// reported, not a `Timeout` that hides it. `now` is passed in so a test can put
// it either side of the deadline.
@(private)
retry_due :: proc(timeout: time.Duration, deadline, now: time.Tick, attempt: int) -> bool {
	return attempt == 0 && (timeout <= 0 || time.tick_diff(now, deadline) > 0)
}

/*
What is left of `open_stream`'s deadline at `now`.

Zero is no deadline, and stays zero. No configuration reaches it - the loader
refuses an `upstream.timeout` under a millisecond (#499) - and a positive timeout
never decays into it: what is left is floored at a millisecond, since a deadline
met to the nanosecond, or one already gone, would otherwise hand the socket a
zero, which is no timeout at all. `now` is passed in so a test can put it on
the deadline exactly.
*/
@(private)
stream_time_left :: proc(timeout: time.Duration, deadline, now: time.Tick) -> time.Duration {
	return timeout if timeout <= 0 else max(time.tick_diff(now, deadline), time.Millisecond)
}

open_stream :: proc(
	endpoint: net.Endpoint,
	tls_ctx: ^tlsx.Context,
	hostname: string,
	timeout: time.Duration,
	u: ^Upstream = nil,
) -> (
	stream: Stream,
	err: Error,
) {
	deadline := time.tick_add(time.tick_now(), timeout)
	for attempt in 0 ..< 2 {
		socket, derr := dial_tcp_timeout(endpoint, stream_time_left(timeout, deadline, time.tick_now()))
		if derr != .None {
			if derr != .Dial_Reset || !retry_due(timeout, deadline, time.tick_now(), attempt) {
				return {}, derr
			}
			continue
		}
		// The handshake's deadline is the socket's receive timeout - see
		// `tlsx.handshake_loop` - so this is what bounds it. A dial that used the
		// last of the budget still gets one bounded attempt: `stream_time_left`
		// floors what is left at a millisecond.
		set_socket_timeouts(socket, stream_time_left(timeout, deadline, time.tick_now()))
		_ = net.set_option(socket, .TCP_Nodelay, true)

		if tls_ctx == nil {
			return Stream{socket = socket}, .None
		}
		conn, terr := tlsx.client_connect(tls_ctx, socket, hostname)
		if terr == .None {
			return Stream{socket = socket, tls = conn}, .None
		}
		// OpenSSL keeps its reason on a per-thread queue, so it has to be read
		// here rather than at the point the error surfaces.
		detail := tlsx.describe_error(terr, context.temp_allocator)
		net.close(socket)
		if terr == .Closed && retry_due(timeout, deadline, time.tick_now(), attempt) {
			logx.debugf("TLS handshake with %q failed: %s, retrying once", hostname, detail)
			continue
		}
		ferr := handshake_failure(terr)
		// Said once a window per upstream per kind, and at `debug` between: the
		// reason is the whole diagnosis of a failing DoT or DoH upstream and
		// `Error` has nowhere to carry it, so an operator who never sees this
		// line has `TLS_Failed` and nothing else to go on.
		if loud, held := handshake_failure_due(u, ferr); loud {
			logx.warnf_held(held, "upstream %s: TLS handshake with %q failed: %s", u.spec.name, hostname, detail)
		} else if u != nil {
			logx.debugf("upstream %s: TLS handshake with %q failed: %s", u.spec.name, hostname, detail)
		} else {
			logx.debugf("TLS handshake with %q failed: %s", hostname, detail)
		}
		return {}, ferr
	}
	return {}, .TLS_Failed
}
