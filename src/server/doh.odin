package server

import "core:encoding/base64"
import "core:strings"
import "elodin:dns"
import "elodin:logx"

/*
The DoH endpoint (RFC 8484) over HTTP/1.1.

Both defined request forms are accepted:

  POST <path>            body is the raw DNS message
  GET  <path>?dns=<b64>  base64url-encoded DNS message, no padding

HTTP/2 is not implemented. The TLS layer advertises only "http/1.1" via ALPN, so
an HTTP/2-only client fails during the handshake instead of after it.
*/

DOH_CONTENT_TYPE :: "application/dns-message"
MAX_HEADER_BYTES :: 16 * 1024
MAX_DOH_BODY :: 64 * 1024

/*
What the connection's read buffer starts at, and what it is put back to between
requests.

It grows to hold whatever the largest request on the connection needed - a body
at `MAX_DOH_BODY` takes it to 128 KiB, since a dynamic array doubles - and since
the buffer now lives as long as the connection rather than as long as one
request, that is capacity a client can raise once and leave raised for as long as
it keeps the connection open, whatever it sends afterwards. At
`server.max_connections`, connections that each did that hold tens of megabytes
between them for nothing. One oversized request is not a reason to keep an
oversized buffer, so `http_compact` hands the excess back.
*/
HTTP_BUF_SIZE :: 4096

@(private)
Http_Request_In :: struct {
	method:       string,
	path:         string,
	query:        string,
	body:         []u8,
	keep_alive:   bool,
	content_type: string,
}

@(private)
Http_Reader :: struct {
	conn: Conn,
	buf:  [dynamic]u8,
	pos:  int,
}

@(private)
http_fill :: proc(r: ^Http_Reader) -> bool {
	chunk: [4096]u8
	n, ok := conn_read(r.conn, chunk[:])
	if !ok {
		return false
	}
	append(&r.buf, ..chunk[:n])
	return true
}

@(private)
http_line :: proc(r: ^Http_Reader) -> (line: string, ok: bool) {
	for {
		region := r.buf[r.pos:]
		for i in 0 ..< max(0, len(region) - 1) {
			if region[i] == '\r' && region[i + 1] == '\n' {
				start := r.pos
				r.pos += i + 2
				return string(r.buf[start:start + i]), true
			}
		}
		if len(r.buf) > MAX_HEADER_BYTES {
			return "", false
		}
		if !http_fill(r) {
			return "", false
		}
	}
}

/*
Drop what has been read and move what has not to the front.

`r.pos` is where the request just read ended, and anything past it is the start
of the next one - so it has to survive into the next round, and the header limit
`http_line` applies has to be measured from where that request begins rather
than from whatever came before it. `remove_range` moves the tail down; the move
is a `memmove`, so a tail longer than the gap it moves into is fine.
*/
@(private)
http_compact :: proc(r: ^Http_Reader) {
	if r.pos > 0 {
		remove_range(&r.buf, 0, r.pos)
		r.pos = 0
	}
	// The tail is what the next request has sent so far, so anything past
	// `HTTP_BUF_SIZE` is capacity this connection has no use for. Left alone
	// while the tail is larger than that: the next round compacts again, and
	// giving it up here would only mean growing back for the request it belongs
	// to.
	if cap(r.buf) > HTTP_BUF_SIZE && len(r.buf) <= HTTP_BUF_SIZE {
		_, _ = shrink(&r.buf, HTTP_BUF_SIZE)
	}
}

@(private)
http_exact :: proc(r: ^Http_Reader, n: int) -> (data: []u8, ok: bool) {
	for len(r.buf) - r.pos < n {
		if !http_fill(r) {
			return nil, false
		}
	}
	start := r.pos
	r.pos += n
	return r.buf[start:start + n], true
}

/*
Parse a `Content-Length` value, which is `1*DIGIT` and nothing else.

RFC 9110 8.6 writes the field that way, and `strconv.parse_int` with its default
base does not read it that way. It takes the base from a prefix, so `0x10` is
16, `0b1010` is 10 and `0o20` is 16; it skips `_` between digits, so `1_0` is
10; it allows a leading sign; and it wraps without reporting it, so
`18446744073709551620` comes back as 4 and a range check downstream sees nothing
wrong with the answer.

None of that is academic here. Sharing :443 with a web server, or terminating
TLS at nginx, haproxy or Envoy, is an ordinary way to run DoH, and a front end
parses this field as the RFC writes it: it rejects the message, or reads a
different length out of it. Two hops that disagree about where a request ends is
the whole of CL.CL request smuggling - what this server takes for the tail of a
body, the front end takes for the start of the next request, and attributes to
whoever's connection it is pipelining onto. `transfer-encoding` is refused
outright where the headers are read, which closes the TE.CL half of the same
problem.

The limit is applied digit by digit rather than to the total, so there is
nothing for an overlong value to wrap in on the way to being checked.

`value` is the field value as it arrived. What may surround the digits is `OWS`
- spaces and tabs, RFC 9110 5.6.3 - and that is all this takes off.
*/
@(private)
parse_content_length :: proc(value: string) -> (length: int, ok: bool) {
	digits := strings.trim_right(strings.trim_left(value, " \t"), " \t")
	if len(digits) == 0 {
		return 0, false
	}
	v := 0
	for i in 0 ..< len(digits) {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v * 10 + int(c - '0')
		if v > MAX_DOH_BODY {
			return 0, false
		}
	}
	return v, true
}

/*
Read one request off `r`.

Everything kept in the result is copied out of the reader's buffer rather than
pointed into it. `http_line` and `http_exact` return views, and every read after
one of them may grow that buffer - which, past its capacity, means a different
block. The arena behind `context.temp_allocator` happens to carry the old
contents forward and hold onto the block until `free_all`, so views into it kept
reading correctly, but nothing here should depend on which allocator it was
handed. The copies live in the same scratch space and go the same way.
*/
@(private)
read_http_request :: proc(r: ^Http_Reader) -> (req: Http_Request_In, ok: bool) {
	hold :: proc(s: string) -> string {
		return strings.clone(s, context.temp_allocator)
	}
	line := http_line(r) or_return

	// "METHOD path HTTP/1.1"
	first := strings.index_byte(line, ' ')
	if first <= 0 {
		return {}, false
	}
	rest := line[first + 1:]
	second := strings.index_byte(rest, ' ')
	if second <= 0 {
		return {}, false
	}
	req.method = hold(line[:first])
	target := rest[:second]
	version := rest[second + 1:]
	req.keep_alive = version != "HTTP/1.0"

	if q := strings.index_byte(target, '?'); q >= 0 {
		req.path = hold(target[:q])
		req.query = hold(target[q + 1:])
	} else {
		req.path = hold(target)
	}

	// -1 rather than 0, so a second Content-Length can be told from the first.
	content_length := -1
	for {
		header := http_line(r) or_return
		if header == "" {
			break
		}
		/*
		A field line this server cannot read is a field line it must not skip.

		Both of these are ways to write a Content-Length that elodin does not see
		and a hop in front might: a line beginning with whitespace is an obs-fold
		continuation of the one before it (RFC 9112 5.2), and whitespace before
		the colon is not a field name (RFC 9112 5.1). Read here as "no header of
		that name", either one leaves the body unread while the front end that
		unfolded or trimmed it forwards a body length elodin never applied - the
		remainder becomes the next request on the connection. Both RFCs ask a
		server to reject rather than guess, and nothing that speaks DoH sends
		either.
		*/
		if header[0] == ' ' || header[0] == '\t' {
			return {}, false
		}
		colon := strings.index_byte(header, ':')
		if colon <= 0 {
			return {}, false
		}
		if header[colon - 1] == ' ' || header[colon - 1] == '\t' {
			return {}, false
		}
		name := header[:colon]
		value := strings.trim_space(header[colon + 1:])
		switch {
		case strings.equal_fold(name, "content-length"):
			// RFC 9112 6.3: a message with more than one of these is invalid,
			// whether or not they agree, because the hop in front is entitled to
			// resolve the pair differently from the way this one would.
			if content_length >= 0 {
				return {}, false
			}
			// The field value as it arrived, not `value`: `strings.trim_space`
			// takes a non-breaking space off the end, which is not OWS and not
			// something a front end would overlook.
			v, vok := parse_content_length(header[colon + 1:])
			if !vok {
				return {}, false
			}
			content_length = v
		case strings.equal_fold(name, "connection"):
			if strings.equal_fold(value, "close") {
				req.keep_alive = false
			}
		case strings.equal_fold(name, "content-type"):
			req.content_type = hold(value)
		case strings.equal_fold(name, "transfer-encoding"):
			// Chunked request bodies are not accepted; DoH clients send a
			// Content-Length.
			return {}, false
		}
	}

	if content_length > 0 {
		body := http_exact(r, content_length) or_return
		owned := make([]u8, len(body), context.temp_allocator)
		copy(owned, body)
		req.body = owned
	}
	return req, true
}

@(private)
serve_doh :: proc(s: ^Server, conn: Conn, client: string) {
	path := s.cfg.listeners.doh.path

	/*
	One reader for the connection rather than one per request.

	A client may send the next request without waiting for the answer to this
	one (RFC 9112 9.3), and `Connection: keep-alive` is what this endpoint
	advertises, so a conforming client can do it. Those bytes come off the socket
	along with the request being parsed and sit in `r.buf` past its end: a reader
	built inside the loop throws them away with itself, and the next request is
	either lost whole - the client waits for an answer until `client_timeout`
	closes the connection - or, when only part of it had arrived, resumed from its
	middle, which parses as a garbage request line and ends the connection.

	The buffer is therefore not from `context.temp_allocator`: that arena is reset
	after every request, and what is left over belongs to the next one. It does
	not accumulate either - see `HTTP_BUF_SIZE`.
	*/
	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE),
	}
	defer delete(r.buf)

	for {
		req, ok := read_http_request(&r)
		if !ok {
			free_all(context.temp_allocator)
			return
		}
		// Before the answer, so that what the reader carries into the next round
		// is the next request and nothing before it.
		http_compact(&r)

		keep_alive := req.keep_alive
		handled := serve_doh_request(s, conn, req, path, client)
		free_all(context.temp_allocator)
		if !handled || !keep_alive {
			return
		}
	}
}

@(private)
serve_doh_request :: proc(s: ^Server, conn: Conn, req: Http_Request_In, path: string, client: string) -> bool {
	if req.path != path {
		return send_http_error(conn, "doh", 404, "not found", req.keep_alive)
	}

	query: []u8
	switch {
	case req.method == "POST":
		if req.content_type != "" && !strings.has_prefix(req.content_type, DOH_CONTENT_TYPE) {
			return send_http_error(conn, "doh", 415, "unsupported media type", req.keep_alive)
		}
		query = req.body
	case req.method == "GET":
		encoded, found := query_param(req.query, "dns")
		if !found {
			return send_http_error(conn, "doh", 400, "missing dns parameter", req.keep_alive)
		}
		decoded, dok := decode_dns_param(encoded)
		if !dok || len(decoded) == 0 {
			return send_http_error(conn, "doh", 400, "malformed dns parameter", req.keep_alive)
		}
		query = decoded
	case:
		return send_http_error(conn, "doh", 405, "method not allowed", req.keep_alive)
	}

	if len(query) < dns.HEADER_SIZE {
		return send_http_error(conn, "doh", 400, "message too short", req.keep_alive)
	}

	response, _, ok := handle_query(s, query, .DoH, client, context.temp_allocator)
	if !ok || len(response) == 0 {
		return send_http_error(conn, "doh", 500, "no response", req.keep_alive)
	}

	// Cache-Control mirrors the smallest TTL so intermediaries expire the
	// answer at the same time the DNS data does.
	max_age := doh_max_age(response)

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: ")
	strings.write_string(&b, DOH_CONTENT_TYPE)
	strings.write_string(&b, "\r\nContent-Length: ")
	strings.write_int(&b, len(response))
	strings.write_string(&b, "\r\nCache-Control: max-age=")
	strings.write_int(&b, int(max_age))
	strings.write_string(&b, "\r\nDate: ")
	strings.write_string(&b, now_http_date(context.temp_allocator))
	strings.write_string(&b, "\r\nServer: elodin/")
	strings.write_string(&b, VERSION)
	strings.write_string(&b, "\r\nConnection: ")
	strings.write_string(&b, "keep-alive" if req.keep_alive else "close")
	strings.write_string(&b, "\r\n\r\n")

	head := strings.to_string(b)
	if !conn_write_all(conn, transmute([]u8)head) {
		return false
	}
	return conn_write_all(conn, response)
}

/*
Decode the `dns` GET parameter.

RFC 8484 specifies base64url with the padding removed, which the decoder still
wants, so it is put back before decoding.
*/
@(private)
decode_dns_param :: proc(encoded: string) -> (data: []u8, ok: bool) {
	padded := encoded
	if rem := len(encoded) % 4; rem != 0 {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, encoded)
		for _ in 0 ..< 4 - rem {
			strings.write_byte(&b, '=')
		}
		padded = strings.to_string(b)
	}
	decoded, err := base64.decode(padded, base64.DEC_URL_TABLE, nil, context.temp_allocator)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

@(private)
doh_max_age :: proc(response: []u8) -> u32 {
	offsets, ok := dns.scan_ttl_offsets(response, context.temp_allocator)
	if !ok || len(offsets) == 0 {
		return 0
	}
	ttls := dns.read_ttls(response, offsets, context.temp_allocator)
	v, has := dns.min_ttl(ttls)
	return v if has else 0
}

@(private)
query_param :: proc(query: string, name: string) -> (value: string, found: bool) {
	rest := query
	for len(rest) > 0 {
		pair := rest
		if idx := strings.index_byte(rest, '&'); idx >= 0 {
			pair = rest[:idx]
			rest = rest[idx + 1:]
		} else {
			rest = ""
		}
		eq := strings.index_byte(pair, '=')
		if eq < 0 {
			continue
		}
		if pair[:eq] == name {
			return pair[eq + 1:], true
		}
	}
	return "", false
}

// `who` names the endpoint in the debug line. Both HTTP endpoints this server
// has - DoH and the metrics one - refuse requests the same way, and a log line
// that named only one of them would send an operator to the wrong port.
@(private)
send_http_error :: proc(conn: Conn, who: string, status: int, message: string, keep_alive: bool) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 ")
	strings.write_int(&b, status)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, message)
	strings.write_string(&b, "\r\nContent-Type: text/plain\r\nContent-Length: ")
	strings.write_int(&b, len(message) + 1)
	strings.write_string(&b, "\r\nConnection: ")
	strings.write_string(&b, "keep-alive" if keep_alive else "close")
	strings.write_string(&b, "\r\n\r\n")
	strings.write_string(&b, message)
	strings.write_byte(&b, '\n')

	logx.debugf("%s: replying %d %s", who, status, message)
	return conn_write_all(conn, transmute([]u8)strings.to_string(b)) && keep_alive
}
