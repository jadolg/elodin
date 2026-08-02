package server

import "core:encoding/base64"
import "core:strconv"
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

	content_length := 0
	for {
		header := http_line(r) or_return
		if header == "" {
			break
		}
		colon := strings.index_byte(header, ':')
		if colon <= 0 {
			continue
		}
		name := header[:colon]
		value := strings.trim_space(header[colon + 1:])
		switch {
		case strings.equal_fold(name, "content-length"):
			v, vok := strconv.parse_int(value)
			if !vok || v < 0 || v > MAX_DOH_BODY {
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

	for {
		r := Http_Reader {
			conn = conn,
			buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
		}
		req, ok := read_http_request(&r)
		if !ok {
			free_all(context.temp_allocator)
			return
		}

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
		return send_http_error(conn, 404, "not found", req.keep_alive)
	}

	query: []u8
	switch {
	case req.method == "POST":
		if req.content_type != "" && !strings.has_prefix(req.content_type, DOH_CONTENT_TYPE) {
			return send_http_error(conn, 415, "unsupported media type", req.keep_alive)
		}
		query = req.body
	case req.method == "GET":
		encoded, found := query_param(req.query, "dns")
		if !found {
			return send_http_error(conn, 400, "missing dns parameter", req.keep_alive)
		}
		decoded, dok := decode_dns_param(encoded)
		if !dok || len(decoded) == 0 {
			return send_http_error(conn, 400, "malformed dns parameter", req.keep_alive)
		}
		query = decoded
	case:
		return send_http_error(conn, 405, "method not allowed", req.keep_alive)
	}

	if len(query) < dns.HEADER_SIZE {
		return send_http_error(conn, 400, "message too short", req.keep_alive)
	}

	response, _, ok := handle_query(s, query, .DoH, client, context.temp_allocator)
	if !ok || len(response) == 0 {
		return send_http_error(conn, 500, "no response", req.keep_alive)
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

@(private)
send_http_error :: proc(conn: Conn, status: int, message: string, keep_alive: bool) -> bool {
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

	logx.debugf("doh: replying %d %s", status, message)
	return conn_write_all(conn, transmute([]u8)strings.to_string(b)) && keep_alive
}
