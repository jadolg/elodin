package upstream

import "core:mem"
import "core:net"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:h2"
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
		// A read that ran out of time is a timeout on either half, as in
		// `pipe_read_full`: `IO_Error` says the peer broke, not that it was slow.
		if terr != .None {
			return 0, roundtrip_failure(terr)
		}
		return got, .None
	}
	got, nerr := net.recv_tcp(s.socket, buf)
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
		n, err := net.send_tcp(s.socket, buf[sent:])
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
}

@(private)
reader_fill :: proc(r: ^Buf_Reader) -> Error {
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
	n, err := stream_read(r.stream, chunk[:])
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
	the server breaking and has to be counted as one; `r.buf` is per exchange,
	so its being empty is exactly that question.

	`reader_to_end` reaches here for the opposite reason, as the close that
	ends a body with no length, and discards whichever of the two it gets.
	*/
	if n == 0 {
		r.closed = true
		return .Peer_Closed if len(r.buf) == 0 else .IO_Error
	}
	append(&r.buf, ..chunk[:n])
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

The result is a view into `r.buf`, which every later read may grow — and past
its capacity that means a different block. So a line is good until the next read
and no longer: `http_exchange` finishes with each one inside the iteration that
produced it, and clones the one thing it keeps. Anything added here that holds a
line across a read has to copy it first.
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
		reader_fill(r) or_return
	}
	start := r.pos
	r.pos += n
	return r.buf[start:start + n], .None
}

/*
Read until the peer closes, for responses with no length information.

Bounded by `limit`, like every other framing path: the header scan stops at 64
KB, and both the chunked and the Content-Length readers check MAX_HTTP_BODY.
This one had nothing to check against, so a peer that never sent a length - by
omitting both headers, or by sending a Content-Length that is not a length -
decided on its own how much of our memory to take.
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
		if ferr := reader_fill(r); ferr != .None {
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

MAX_HTTP_BODY :: 64 * 1024 * 1024

/*
How many header fields — or trailer fields, which are read by the same loop —
one exchange may carry. Interim (1xx) responses draw on the headers' budget,
each one costing a field on top of its own: the reader keeps every line it has
read for the whole exchange, so a budget per response would let a run of interim
responses hold a hundred times as much. Trailers have a budget of their own.

`reader_line` bounds a line at 64 KB but says nothing about how many lines
follow, so a peer sending short fields forever was answered for as long as it
kept the socket open. A hundred is well past what any list host or DoH resolver
sends; the largest seen in practice is around twenty.
*/
MAX_HTTP_HEADERS :: 100

/*
Perform one request/response exchange on `stream`.

The returned body is allocated from `allocator`; everything else borrows from
scratch memory and must be copied if it needs to outlive the call.

`deadline`, when set, bounds the request's writes and the reading of the whole
response, and `idle` any one read or write under it; see `stream_write` and
`reader_fill`. Without one, only the timeouts already on
the stream apply, and those are per read.
*/
http_exchange :: proc(
	stream: ^Stream,
	req: Http_Request,
	allocator := context.allocator,
	deadline := time.Tick{},
	idle := time.Duration(0),
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

	stream_write(stream, transmute([]u8)strings.to_string(b), deadline, idle) or_return
	if len(req.body) > 0 {
		stream_write(stream, req.body, deadline, idle) or_return
	}

	r := Buf_Reader {
		stream   = stream,
		buf      = make([dynamic]u8, 0, 8192, context.temp_allocator),
		deadline = deadline,
		idle     = idle,
	}

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
				v, cl_err := parse_content_length(value)
				// A value that is not a length is refused here rather than left to
				// fall past the `== 0` and `> 0` cases below onto the read-to-end
				// path, which is not what the peer asked for.
				if cl_err != .None {
					return resp, cl_err
				}
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
		resp.body = read_chunked(&r, allocator) or_return
	case content_length == 0:
		resp.body = nil
	case content_length > 0:
		// Already bounded where the header was read.
		data := reader_exact(&r, content_length) or_return
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
	case:
		// No framing information: the body ends when the connection does.
		data := reader_to_end(&r, MAX_HTTP_BODY) or_return
		out := make([]u8, len(data), allocator)
		copy(out, data)
		resp.body = out
		resp.keep_alive = false
	}
	return resp, .None
}

/*
Parse a `Content-Length` value, which is `1*DIGIT` (RFC 9110 8.6) and nothing
else.

`strconv.parse_int` with its default base reads a good deal more than that: the
base comes from a prefix, so `0x10` is 16 and `0b1010` is 10; `_` between digits
is skipped; a leading sign is allowed; and the accumulator wraps in silence, so
a value past 64 bits arrives as something small enough for any range check that
follows. What is on the other end of this parser is a blocklist host or a DoH
upstream, over a connection this client keeps alive and reuses, so a length read
differently from the way it was sent leaves the reader standing in the middle of
a body with the next response starting from wherever that landed.

The server side of the field is in `server/doh.odin`, where the same laxity is a
request-smuggling primitive rather than a desync with oneself.

The limit is applied digit by digit, so nothing can wrap on the way to it. What
may surround the digits is `OWS` - spaces and tabs, RFC 9110 5.6.3 - and that is
all this takes off, `split_header` having already trimmed the field value.
*/
@(private)
parse_content_length :: proc(value: string) -> (length: int, err: Error) {
	digits := strings.trim_right(strings.trim_left(value, " \t"), " \t")
	if len(digits) == 0 {
		return 0, .HTTP_Error
	}
	v := 0
	for i in 0 ..< len(digits) {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, .HTTP_Error
		}
		v = v * 10 + int(c - '0')
		if v > MAX_HTTP_BODY {
			return 0, .Too_Large
		}
	}
	return v, .None
}

/*
The status line: `HTTP/1.<DIGIT> SP 3DIGIT`, then optionally a space and a
reason phrase (RFC 9112 4), and whether its version is 1.0.

Parsed with a detected base the code was rather more: `HTTP/1.1 0x1 OK` came back
as 1, `1_0` as 10. The three characters were also taken without asking what
followed them, so `HTTP/1.1 2000 OK` - not a status line at all - read as 200.
And with only the `HTTP/` prefix checked, `HTTP/1.1x` was a version, one this
client went on to pool as 1.1 (#437).
*/
@(private)
parse_status :: proc(line: string) -> (status: int, http_1_0: bool, err: Error) {
	V :: len("HTTP/1.1")
	if len(line) < V + 4 || !strings.has_prefix(line, "HTTP/") || line[V] != ' ' {
		return 0, false, .HTTP_Error
	}
	// Major version 1 is the only one spoken on this wire (RFC 9112 2.3).
	if line[5] != '1' || line[6] != '.' || line[7] < '0' || line[7] > '9' {
		return 0, false, .HTTP_Error
	}
	// A reason phrase is optional, but if anything follows the code it is the
	// space in front of one.
	if len(line) > V + 4 && line[V + 4] != ' ' {
		return 0, false, .HTTP_Error
	}
	v := 0
	for c in transmute([]u8)line[V + 1:V + 4] {
		if c < '0' || c > '9' {
			return 0, false, .HTTP_Error
		}
		v = v * 10 + int(c - '0')
	}
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
	// `OWS` off the value and nothing more (RFC 9110 5.6.3): `strings.trim_space`
	// also takes a non-breaking space, which made `close\u00a0` a close.
	return line[:idx], strings.trim(line[idx + 1:], " \t"), true
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
		if size > u64(MAX_HTTP_BODY) || len(out) + int(size) > MAX_HTTP_BODY {
			return nil, .Too_Large
		}
		data := reader_exact(r, int(size)) or_return
		append(&out, ..data)
		// The data ends in CRLF and nothing else (RFC 9112 7.1). Thrown away,
		// the line let `helloEXTRA` read as `hello` on a connection kept for
		// the next response (#437).
		if tail := reader_line(r) or_return; tail != "" {
			return nil, .HTTP_Error
		}
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
*/
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
	for attempt in 0 ..< 2 {
		socket, derr := dial_tcp_timeout(endpoint, timeout)
		if derr != .None {
			if derr != .Dial_Reset || attempt == 1 {
				return {}, derr
			}
			continue
		}
		set_socket_timeouts(socket, timeout)
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
		if terr == .Closed && attempt == 0 {
			logx.debugf("TLS handshake with %q failed: %s, retrying once", hostname, detail)
			continue
		}
		ferr := handshake_failure(terr)
		// Said once per upstream per kind, and at `debug` after that: the
		// reason is the whole diagnosis of a failing DoT or DoH upstream and
		// `Error` has nowhere to carry it, so an operator who never sees this
		// line has `TLS_Failed` and nothing else to go on.
		if first_failure_of_kind(u, ferr) {
			logx.warnf("upstream %s: TLS handshake with %q failed: %s", u.spec.name, hostname, detail)
		} else if u != nil {
			logx.debugf("upstream %s: TLS handshake with %q failed: %s", u.spec.name, hostname, detail)
		} else {
			logx.debugf("TLS handshake with %q failed: %s", hostname, detail)
		}
		return {}, ferr
	}
	return {}, .TLS_Failed
}
