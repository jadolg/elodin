package server

import "core:encoding/base64"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
The DoH endpoint (RFC 8484) over HTTP/1.1.

Both defined request forms are accepted:

  POST <path>            body is the raw DNS message
  GET  <path>?dns=<b64>  base64url-encoded DNS message, no padding

HTTP/2 is served elsewhere. The listener advertises "h2" and "http/1.1" via ALPN
and hands an "h2" connection to `serve_doh2`, so this reader only ever sees a
client that selected HTTP/1.1 - which is why an `HTTP/2.0` request line here is
refused rather than upgraded.
*/

DOH_CONTENT_TYPE :: "application/dns-message"
MAX_HEADER_BYTES :: 16 * 1024
MAX_DOH_BODY :: 64 * 1024

/*
How much of a refused request `http_linger` reads and throws away before the
connection closes on it, how long it waits for any one read, and how long the
whole of it may take.

The size is a request this endpoint would have read in full anyway - the header
limit plus the largest body it accepts - so draining one costs no more than
serving one would have.

The idle wait applies per read. `HTTP_LINGER_BODY_IDLE` is what every drain here
passes, because every refusal that drains is one `read_http_request` handed back,
decided on the request line or on a repeated `Host` - before the body those
headers declared has been read. What is unread there is not something the client
has already put on the wire but a body still on its way, and over any distance
the next segment of it is a round trip away rather than in the queue: a wait of
only the time a queued byte takes to arrive drains the first congestion window,
gives up on a body that is still coming, and closes over the remainder, which is
the RST this drain exists to avoid and leaves the client reading ECONNRESET
instead of the 400. So it is a round trip's worth. It is provokable - a request
line this reader will not read costs a client no more than a query does - which
is why it is a quarter of a second rather than a second, that being the bound
`stream_linger` accepts against the same abuse.

Passed by the caller rather than defaulted, though there is one value to pass, so
that a path added later has to answer where its unread bytes are rather than
inherit an answer. The 429 in `serve_doh_request` is the path that used to have
the other one, and it drains nothing now: it keeps the connection, and where the
client asked for `Connection: close` the request it refused was read in full, so
neither case leaves the close anything to trip over.

The deadline bounds the drain as a whole, which the idle wait alone does not. A
client sending a byte inside every wait stays inside all of them for as long as it
likes, so a drain counted only in bytes and idle time would be somewhere to sit
and hold a slot for hours; past the deadline the close goes ahead. See
`stream_linger`, which is bounded the same way.
*/
HTTP_LINGER_BYTES :: MAX_HEADER_BYTES + MAX_DOH_BODY
HTTP_LINGER_TIMEOUT :: 1 * time.Second
HTTP_LINGER_BODY_IDLE :: 250 * time.Millisecond

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
	// The Host header, used only to build the DoH URL the .mobileconfig endpoint
	// hands back. An HTTP/1.1 request that sent no Host at all is refused before
	// it gets here, so this is empty only on an HTTP/1.0 request, which predates
	// the field, or where the field arrived with an empty value - which is a Host
	// the client sent and `valid_mobileconfig_host` still has to turn away.
	host:         string,
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
`value` with `OWS` taken off either end and nothing else.

`OWS` is spaces and tabs (RFC 9110 5.6.3), which is all a recipient may take off
a field value. `strings.trim_space` takes more: it is Unicode-aware, so it also
takes a non-breaking space off the end. A hop in front reads the field as the
grammar writes it and refuses the message rather than trimming it, so trimming
one here is this hop reading a value the front end never saw.
*/
@(private)
trim_ows :: proc(value: string) -> string {
	return strings.trim_right(strings.trim_left(value, " \t"), " \t")
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
	digits := trim_ows(value)
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
What to answer a request line's third token with: 0 for a version this endpoint
speaks, and otherwise the status the RFC asks for.

Two refusals live here, and 505 is the narrower of the two. RFC 9110 15.6.6 has
it mean the *major version* of the request is one this server does not support,
which is something a client can act on: ask again in a version both hops speak.
A token that is not an HTTP-version at all is not that. RFC 9112 2.3 writes the
version as `HTTP/` `DIGIT` `.` `DIGIT`, case-sensitively, with no room for
anything on either side of it, and a request line carrying anything else is an
invalid request line, which 3 answers with a 400.

Answering 505 to all of them tells a client to change a version that was never
the problem - `GET / JUNK`, `GET / http/1.1` and `GET / HTTP/1.10` are malformed
request lines, not unsupported versions - and a client whose retry logic acts on
a 505 by asking again in HTTP/1.0 is answered 505 again, forever.

A minor version above 1 is not refused: 2.3 has a recipient treat one as the
highest minor version it speaks, and nothing in HTTP/1.x changes framing between
minor versions. Another major version is, ALPN having already routed HTTP/2
elsewhere - see the note at the top of this file.
*/
@(private)
http_version_status :: proc(version: string) -> int {
	is_digit :: proc(c: u8) -> bool {
		return c >= '0' && c <= '9'
	}
	// `HTTP/` `DIGIT` `.` `DIGIT` is eight bytes, and the token is all of them.
	if len(version) != 8 || !strings.has_prefix(version, "HTTP/") {
		return 400
	}
	if !is_digit(version[5]) || version[6] != '.' || !is_digit(version[7]) {
		return 400
	}
	// The major version, which is all a 505 is about.
	if version[5] != '1' {
		return 505
	}
	return 0
}

/*
Read one request off `r`.

`status` says what the caller is to answer a request this refuses with, and 0
says to answer nothing and close. What decides between the two is whether this
hop and the hop in front agree on where the message ends, not how far into the
request the refusal happened. Nothing is answered where the framing is what was
wrong - an unreadable `Content-Length`, a folded field line, a chunked body:
those are requests the two hops may cut in different places, and a reply on a
connection whose next byte this server cannot place would be a reply the front
end may attribute to the next request on it.

The rest are framed the way both hops read them, so the refusals the RFC asks
for are safe to send: a request line is either read whole or not read at all, and
a missing or repeated `Host` - refused with the headers only half read - has no
bearing on where the body ends. Each of those closes the connection after
answering, and drains what the client had already sent before it does, so that
the answer is not lost to the RST that closing on unread bytes would send - see
`http_linger`.

Everything kept in the result is copied out of the reader's buffer rather than
pointed into it. `http_line` and `http_exact` return views, and every read after
one of them may grow that buffer - which, past its capacity, means a different
block. The arena behind `context.temp_allocator` happens to carry the old
contents forward and hold onto the block until `free_all`, so views into it kept
reading correctly, but nothing here should depend on which allocator it was
handed. The copies live in the same scratch space and go the same way.
*/
@(private)
read_http_request :: proc(r: ^Http_Reader) -> (req: Http_Request_In, status: int, ok: bool) {
	hold :: proc(s: string) -> string {
		return strings.clone(s, context.temp_allocator)
	}
	line := http_line(r) or_return

	// "METHOD SP request-target SP HTTP-version", three tokens and nothing else
	// (RFC 9112 3).
	first := strings.index_byte(line, ' ')
	if first <= 0 {
		return {}, 400, false
	}
	rest := line[first + 1:]
	second := strings.index_byte(rest, ' ')
	if second <= 0 {
		return {}, 400, false
	}
	target := rest[:second]
	version := rest[second + 1:]
	/*
	`second` is the first space in `rest`, so what follows the target - any
	further space included - is all in `version`. Checked rather than taken for
	one: read as "not HTTP/1.0, so 1.1 with keep-alive", `GET / JUNK` was a
	request, and so was `GET / HTTP/1.1 trailing-garbage`.

	Both are the disagreement `parse_content_length` above is written against, on
	the other half of the request line. A front end sharing :443 with elodin, or
	terminating TLS in front of it, reads the request line as the grammar writes
	it: it refuses the message, or - given a fourth token - takes the target to be
	something other than what this hop took it for.

	A fourth token, or a missing third one, is a line that is not three tokens,
	which RFC 9112 3 answers with a 400. What a third token that is not
	`HTTP/1.<DIGIT>` is answered with depends on the way it fails - a version this
	server does not speak is not the same refusal as a token that is not a version
	at all, see `http_version_status`.
	*/
	if len(version) == 0 || strings.index_byte(version, ' ') >= 0 {
		return {}, 400, false
	}
	if vstatus := http_version_status(version); vstatus != 0 {
		return {}, vstatus, false
	}
	req.method = hold(line[:first])
	http_1_0 := version == "HTTP/1.0"
	req.keep_alive = !http_1_0

	if q := strings.index_byte(target, '?'); q >= 0 {
		req.path = hold(target[:q])
		req.query = hold(target[q + 1:])
	} else {
		req.path = hold(target)
	}

	// -1 rather than 0, so a second Content-Length can be told from the first.
	content_length := -1
	// Counted rather than flagged off `req.host`: an empty Host is a field the
	// client sent, and a second one has to be told from it.
	hosts := 0
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
			return {}, 0, false
		}
		colon := strings.index_byte(header, ':')
		if colon <= 0 {
			return {}, 0, false
		}
		if header[colon - 1] == ' ' || header[colon - 1] == '\t' {
			return {}, 0, false
		}
		name := header[:colon]
		value := strings.trim_space(header[colon + 1:])
		switch {
		case strings.equal_fold(name, "content-length"):
			// RFC 9112 6.3: a message with more than one of these is invalid,
			// whether or not they agree, because the hop in front is entitled to
			// resolve the pair differently from the way this one would.
			if content_length >= 0 {
				return {}, 0, false
			}
			// The field value as it arrived, not `value`: `strings.trim_space`
			// takes a non-breaking space off the end, which is not OWS and not
			// something a front end would overlook.
			v, vok := parse_content_length(header[colon + 1:])
			if !vok {
				return {}, 0, false
			}
			content_length = v
		case strings.equal_fold(name, "connection"):
			if strings.equal_fold(value, "close") {
				req.keep_alive = false
			}
		case strings.equal_fold(name, "content-type"):
			req.content_type = hold(value)
		case strings.equal_fold(name, "host"):
			/*
			RFC 9112 3.2: a request carrying more than one Host is a 400, whether
			or not the two agree - the same argument a repeated Content-Length
			gets. The loop kept the last one it saw, and the .mobileconfig
			endpoint builds a URL out of it: given two, the profile a device
			installs names whichever of them this hop happened to keep, which is
			not necessarily the one the front end routed the request by.
			*/
			hosts += 1
			if hosts > 1 {
				return {}, 400, false
			}
			// The field value as it arrived with `OWS` off it, not `value`: the
			// authority is the other field a front end routes by, so the argument
			// `parse_content_length` is handed the raw value for holds here too -
			// a `Host` a front end refuses for the non-breaking space on the end
			// of it must not become a host this hop trimmed into a valid one and
			// wrote into a .mobileconfig.
			req.host = hold(trim_ows(header[colon + 1:]))
		case strings.equal_fold(name, "transfer-encoding"):
			// Chunked request bodies are not accepted; DoH clients send a
			// Content-Length.
			return {}, 0, false
		}
	}

	// RFC 9112 3.2 again: Host carries the authority for an origin-form target,
	// so an HTTP/1.1 request without one is a 400. HTTP/1.0 predates the field
	// and is allowed to leave it out.
	if hosts == 0 && !http_1_0 {
		return {}, 400, false
	}

	if content_length > 0 {
		body := http_exact(r, content_length) or_return
		owned := make([]u8, len(body), context.temp_allocator)
		copy(owned, body)
		req.body = owned
	}
	return req, 0, true
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
		req, status, ok := read_http_request(&r)
		if !ok {
			// The connection ends either way: `keep_alive` is false, so nothing
			// further is read off a connection whose next byte this server cannot
			// place. A `status` of 0 is a request that is not answered at all -
			// see `read_http_request`.
			if status != 0 {
				_ = send_http_error(conn, "doh", status, http_refusal_message(status), false)
				// The refused request may have declared a body that was never read,
				// and the close below would take the answer with it. That body may
				// also still be arriving, which is what picks the longer of the two
				// idle waits - see `HTTP_LINGER_BODY_IDLE`.
				http_linger(conn, HTTP_LINGER_BODY_IDLE)
			}
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
	mc_path := s.cfg.listeners.doh.mobileconfig_path
	if mc_path != "" && req.path == mc_path {
		return serve_doh_mobileconfig(conn, req, path)
	}
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

	/*
	Charged here rather than where the request is read, so that what is charged is
	a query: a 404 from a scanner, a .mobileconfig download and a request this
	endpoint refuses on its framing are none of them responses to a question, and
	none of them reach the resolver, the cache or an upstream. The budget is
	denominated in the ones that do.

	429 rather than the bare close the length-prefixed transports get, RFC 6585 4
	being written for exactly this: over HTTP a status is something a client can
	read and act on. No `Retry-After` with it, though the RFC allows one: the field
	counts whole seconds, and at the default 500 a second the budget has a token
	back in two milliseconds, so the smallest value it can carry would send a client
	away for hundreds of times the wait there actually is.

	The client's own `keep_alive`, so the refusal leaves the connection where it
	found it - which is where this parts company with `serve_dns_stream`, and joins
	`h2_rate_limited`. Ending it charged this server a TLS handshake for every
	question a flooding client asked and the client nothing: it reconnects and asks
	again, and the accept path signs another key exchange. Measured against the
	shipped default in `bench/results/2026-09-03-rate-limit-bystander.md`, one
	unspoofed client offering 6,123 queries a second over HTTP/1.1 opened 56,249
	connections in twelve seconds and cost 1.33 cores - 236 us per refusal, where
	the same flood over HTTP/2, refused on a connection that survives, cost 10.5 us
	and four connections. The limiter working exactly as designed was what bought
	the attacker the handshakes, which made a public endpoint's own defence the
	cheapest way to load it. Keeping the connection costs 7.9 us and 64 connections
	on the same arm - `bench/results/2026-09-03-doh1-refusal-keeps-the-connection.md`.

	Nothing is drained here for the same reason nothing is drained after an answer:
	the drain exists to keep a close from turning into an RST that discards the
	status along with it (see `http_linger`), and on a kept connection there is no
	close. What a pipelining client sent ahead is the next request, which is read
	and refused in its turn. The one close left on this path is the client's own -
	an HTTP/1.0 request, or one carrying `Connection: close` - and that one needs no
	drain either: the request was read in full, body and all, so a client that meant
	the field it sent has nothing left in the receive queue for the close to trip
	over.

	Nor is the connection ended after some count of refusals. A client that ignores
	429 indefinitely is not worth serving, but disconnecting it is not what stops it
	- it is what it wants, since the reconnection costs this end a signature and
	that end a socket - and a connection held is bounded already, by
	`client_timeout` between requests and by `max_connections` across them. A
	flooder occupies the same one slot either way.
	*/
	if !stream_rate_check(s.limiter, conn.peer, time.tick_now()) {
		report_rate_limited(client, .DoH, !req.keep_alive)
		return send_http_error(conn, "doh", 429, "too many requests", req.keep_alive)
	}

	response, _, ok := handle_query(s, query, .DoH, client, context.temp_allocator)
	if !ok || len(response) == 0 {
		return send_http_error(conn, "doh", 500, "no response", req.keep_alive)
	}

	// Cache-Control mirrors the smallest TTL so intermediaries expire the
	// answer at the same time the DNS data does - the bounded TTL, see
	// `doh_max_age`.
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
Serve the Apple .mobileconfig profile that points a device at this DoH endpoint.

A GET, since a device downloads it by navigating to the URL; anything else is a
405. The URL inside it is built from the request's own `Host` header, so a
client that sends none - or one this server could not have a certificate for -
gets a 400 rather than a profile naming a host that does not resolve. `doh_path`
is `listeners.doh.path`, which is what the profile has the device query.
*/
@(private)
serve_doh_mobileconfig :: proc(conn: Conn, req: Http_Request_In, doh_path: string) -> bool {
	if req.method != "GET" {
		return send_http_error(conn, "doh", 405, "method not allowed", req.keep_alive)
	}
	if !valid_mobileconfig_host(req.host) {
		return send_http_error(conn, "doh", 400, "missing or invalid Host header", req.keep_alive)
	}

	profile := build_doh_mobileconfig(req.host, doh_path, context.temp_allocator)

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: ")
	strings.write_string(&b, DOH_MOBILECONFIG_CONTENT_TYPE)
	strings.write_string(&b, "\r\nContent-Length: ")
	strings.write_int(&b, len(profile))
	strings.write_string(&b, "\r\nContent-Disposition: attachment; filename=\"elodin-doh.mobileconfig\"")
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
	return conn_write_all(conn, transmute([]u8)profile)
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

/*
The `Cache-Control: max-age` for a response, read back off its own TTLs.

Reads the answer as it is about to be sent, which is the answer after
`handle_query` has bounded its TTLs: RFC 2181 section 8 applied and
`cache.max_ttl` on top of it, whether the bytes came out of the cache or
straight from an upstream. So the header cannot outlive the DNS data it is
mirroring, and a hostile TTL cannot be laundered through it into every HTTP
cache between here and the client - which recomputing the figure from what the
upstream sent would do. `read_ttls` applies section 8 again on the way past,
which costs nothing and means this holds for any caller that reaches it with
bytes from somewhere else.
*/
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

/*
The reason phrase for a status `read_http_request` refused a request with.

`send_http_error` writes the message it is given as both the reason phrase and
the body, and the reader hands back a status rather than a phrase - which
endpoint is being refused for, and in what words, is not its business. Both
callers of the reader map it here so the two answer alike.
*/
@(private)
http_refusal_message :: proc(status: int) -> string {
	if status == 505 {
		return "http version not supported"
	}
	return "bad request"
}

/*
Read and throw away what the client had already sent, so that the refusal just
written to it is not lost to the close that follows.

A refused request is answered and the connection then closes, and the request that
earned the refusal may carry bytes this server never read: `read_http_request`
turns down a bad request line before reading the headers that would say how long
the body is, and a repeated `Host` before the end of them. Closing a socket whose
receive queue still holds bytes does not send a FIN but an RST (RFC 1122
4.2.2.13), and an RST arriving at a client that has not read yet has its kernel
discard what is already in its receive buffer - so the status this endpoint went
to the trouble of writing is thrown away and the client sees a connection reset,
which is the bare closed connection the status was there to replace.

Discarded rather than parsed: `keep_alive` is false on every path that gets here,
so nothing further on this connection is answered and what these bytes say does
not matter. A client that stops short of what it declared, that keeps sending past
`HTTP_LINGER_BYTES`, or that trickles for longer than `HTTP_LINGER_TIMEOUT`, ends
the drain on the idle wait, the limit or the deadline rather than holding the
thread.

`idle` is the per-read wait, and the caller chooses it because the caller is what
knows whether the bytes that are left are already here or still arriving. Every
caller has a body outstanding today and so passes `HTTP_LINGER_BODY_IDLE`; it is
passed rather than defaulted so that a path added later has to answer the question
rather than inherit an answer.
*/
@(private)
http_linger :: proc(conn: Conn, idle: time.Duration) {
	// Not `net.set_option`: over DoH the connection is a TLS one, where the socket
	// option stopped applying at the handshake - see `conn_set_read_timeout`.
	conn_set_read_timeout(conn, idle)
	start := time.tick_now()
	chunk: [4096]u8
	discarded := 0
	for discarded < HTTP_LINGER_BYTES && time.tick_since(start) < HTTP_LINGER_TIMEOUT {
		n, ok := conn_read(conn, chunk[:])
		if !ok {
			return
		}
		discarded += n
	}
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
