package server

import "core:encoding/base64"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:cache"
import "elodin:dns"
import "elodin:h2"
import "elodin:logx"
import "elodin:loop"
import "elodin:tlsx"

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
// The Allow of a 405 (RFC 9110 15.5.6): RFC 8484 4.1 defines GET and POST.
DOH_METHODS :: "GET, POST"
MAX_HEADER_BYTES :: 16 * 1024
// RFC 8484 6: application/dns-message is at most 65535 bytes.
MAX_DOH_BODY :: dns.MAX_MESSAGE

/*
Whether a POST's Content-Type names the DoH media type, for both HTTP/1.1 and
HTTP/2.

RFC 9110 8.3.1: the type and subtype are case-insensitive, and parameters follow
a `;`. So it is the media type before any parameters, compared whole and without
regard to case - not a prefix, which would let `application/dns-messageZZZZ`
through, and not a case-sensitive one, which would refuse
`Application/DNS-Message`. The fold is ASCII only: `strings.equal_fold` folds
Unicode, and would take the long s (U+017F) in `application/dns-mes\u017fage` for
an `s`. A missing Content-Type is accepted.
*/
doh_content_type_ok :: proc(value: string) -> bool {
	if value == "" {
		return true
	}
	media := value
	if semi := strings.index_byte(media, ';'); semi >= 0 {
		media = media[:semi]
	}
	return dns.name_equal_fold(h2.trim_ows(media), DOH_CONTENT_TYPE)
}

/*
How much of a refused request `http_linger` reads and throws away before the
connection closes on it, how long it waits for any one read, and how long the
whole of it may take.

The size is a request this endpoint would have read in full anyway - the header
limit plus the largest body it accepts - so draining one costs no more than
serving one would have.

The idle wait applies per read. `HTTP_LINGER_BODY_IDLE` is what every refusal's
drain passes, because every refusal is one `read_http_request` handed back,
decided on the request line, on the header block - a `Host`, a repeated
`Content-Type`, a `Content-Length` over the limit - or partway through a chunked
body, before the rest of the body has been read. What is unread there is not something the client has
already put on the wire but a body still on its way, and over any distance the
next segment of it is a round trip away rather than in the queue: a wait of
only the time a queued byte takes to arrive drains the first congestion window,
gives up on a body that is still coming, and closes over the remainder, which is
the RST this drain exists to avoid and leaves the client reading ECONNRESET
instead of the refusal. So it is a round trip's worth. It is provokable - a request
line this reader will not read costs a client no more than a query does - which
is why it is a quarter of a second rather than a second, that being the bound
`stream_linger` accepts against the same abuse.

Passed by the caller rather than defaulted, so that a path added later has to
answer where its unread bytes are rather than inherit an answer. The close
after a chunked request that was answered passes `STREAM_LINGER_IDLE`: the
body was read whole, and what is unread is what the client had already
pipelined behind it. The 429 in `serve_doh_request` is the one path that drains
nothing: it keeps the connection, and where the
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
the buffer lives as long as the connection rather than as long as one request,
that is capacity a client can raise once and leave raised for as long as
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
	// A view into `Http_Reader.buf`, unlike the fields above: it ends at the
	// next `http_compact`, so callers compact only once they are done with it.
	body:         []u8,
	keep_alive:   bool,
	// The close after it is this server's choice and not the client's (a
	// chunked body): what the client pipelined behind it is drained first.
	closing:      bool,
	content_type: string,
	// The Host header, or for an absolute-form target the target's authority,
	// which RFC 9112 3.2.2 has stand in for it; used only to build the DoH URL
	// the .mobileconfig endpoint hands back. An HTTP/1.1 request that sent no
	// Host at all is refused before it gets here, so this is empty only on an
	// HTTP/1.0 request, which predates the field, or where the field arrived
	// with an empty value - which is a Host the client sent and
	// `valid_mobileconfig_host` still has to turn away.
	host:         string,
}

@(private)
Http_Reader :: struct {
	conn:   Conn,
	buf:    [dynamic]u8,
	pos:    int,
	/*
	What the request being read may take, taken fresh per request by the caller's
	loop - see `Read_Budget`, and `serve_dns_stream` where the same budget bounds
	one DNS message.

	A request line, its headers and its body are as many reads as the client cares
	to split them into, and the per-read wait is restarted by each one: without a
	bound across the whole of them a client trickling a byte at a time holds this
	connection, and one of `max_connections`, for as long as it likes while no
	request ever completes.
	*/
	budget: Read_Budget,
}

@(private)
http_fill :: proc(r: ^Http_Reader) -> bool {
	/*
	Straight into the buffer's free capacity, not through a chunk on the stack: the
	read between requests is where an idle connection parks, and a 4 KiB chunk
	there is a page the parked fiber keeps resident for as long as the client
	keeps the connection (#596). Grown by doubling once full, as `append` grows it.
	A read takes at most `HTTP_BUF_SIZE`, so a header that never ends is refused
	within one such read past `MAX_HEADER_BYTES`.
	*/
	have := len(r.buf)
	if have == cap(r.buf) && reserve(&r.buf, max(2 * cap(r.buf), HTTP_BUF_SIZE)) != nil {
		return false
	}
	_ = non_zero_resize(&r.buf, have + min(cap(r.buf) - have, HTTP_BUF_SIZE))
	n, ok := conn_read_budgeted(r.conn, r.buf[have:], &r.budget)
	_ = resize(&r.buf, have + (n if ok else 0))
	return ok
}

/*
One line, up to CRLF.

A bare LF, a bare CR or a NUL before it refuses the request (#432), and says so
with `malformed`, which the caller answers with a 400. RFC 9112 2.2 lets a
recipient take a bare LF for a line end, so a hop in front may read
`X: a\nTransfer-Encoding: chunked` as two fields where this one would read one,
and frame the body by chunks where this one framed it by Content-Length. The
same goes for the request line, and a bare CR or NUL is what some hops split on
or cut at. Nothing that speaks DoH sends any of them, and HTTP/2 already refuses
them in a value (`field_value_is_valid`).

`from` is where the bytes `MAX_HEADER_BYTES` bounds start: the request, for its
header block, or the line, for a chunk's. A line past it, or a read that fails,
is `ok` false and not `malformed`.

Every byte before the first CRLF is looked at on the pass that finds it, so a
byte is judged once it has a successor to be read against.
*/
@(private)
http_line :: proc(r: ^Http_Reader, from := 0) -> (line: string, ok: bool, malformed: bool) {
	for {
		region := r.buf[r.pos:]
		for i in 0 ..< max(0, len(region) - 1) {
			switch region[i] {
			case '\r':
				if region[i + 1] != '\n' {
					return "", false, true
				}
				start := r.pos
				r.pos += i + 2
				return string(r.buf[start:start + i]), true, false
			case '\n', 0:
				return "", false, true
			}
		}
		if len(r.buf) - from > MAX_HEADER_BYTES {
			return "", false, false
		}
		if !http_fill(r) {
			return "", false, false
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
	major, _, ok := h2.http1_version(version)
	if !ok {
		return 400
	}
	// The major version, which is all a 505 is about.
	if major != 1 {
		return 505
	}
	return 0
}

/*
Read one request off `r`.

`status` says what the caller is to answer a request this refuses with, and 0
says to answer nothing and close: a read that failed, or a header block past
`MAX_HEADER_BYTES`, where there is no whole request to answer. Every other
refusal is answered and the connection then closes, which is what RFC 9112
asks for the requests whose framing is in doubt - a `Transfer-Encoding` whose
final coding is not chunked or a `Content-Length` that is invalid or repeated
(6.3), an obs-fold (5.2), whitespace before a field's colon (5.1) - and what
makes answering them safe: nothing more is read on the connection, so there is
no next request for a front end and this hop to cut in different places. The
caller drains what the client had already sent before it closes, so that the
answer is not lost to the RST that closing on unread bytes would send - see
`http_linger`.

A refusal after the request line is read hands back the method alone, so that
the refusal to a HEAD can go without content (RFC 9110 9.3.2).

Everything kept in the result but the body is copied out of the reader's buffer
rather than pointed into it. `http_line` and `http_exact` return views, and every
read after one of them may grow that buffer - which, past its capacity, means a
different block. The arena behind `context.temp_allocator` happens to carry the
old contents forward and hold onto the block until `free_all`, so views into it
would read correctly, but nothing here should depend on which allocator it was
handed. The copies live in the same scratch space and go the same way.
*/
@(private)
read_http_request :: proc(r: ^Http_Reader) -> (req: Http_Request_In, status: int, ok: bool) {
	// A field this server has no room to keep ends the request unanswered,
	// rather than reading as an empty one the client sent.
	held := true
	authority, absolute, http_1_0, lstatus, lok := read_request_line(r, &req, &held)
	if !lok {
		return {method = req.method}, lstatus, false
	}
	refused := Http_Request_In {
		method = req.method,
	}
	f, fstatus, fok := read_field_lines(r, &req, http_1_0, &held)
	if !fok {
		return refused, fstatus, false
	}

	// Before the body is waited for: a request this server cannot keep is not
	// answered whatever follows.
	if !held {
		return {}, 0, false
	}
	if absolute {
		req.host = authority
	}
	chunked, framing_status := request_framing(f, http_1_0)
	if framing_status != 0 {
		return refused, framing_status, false
	}

	if (f.content_length > 0 || chunked) && f.expect_continue {
		/*
		RFC 9110 10.1.1: a server "MUST NOT wait for the content before sending
		the 100 (Continue) response". Everything this reader refuses on the
		header block is answered above with a final status instead; what is left
		is decided on the body, so it gets the 100 - unless the body is already
		here, which 10.1.1 lets a server leave unanswered.
		*/
		here := len(r.buf) - r.pos
		if (chunked && here == 0) || (!chunked && here < f.content_length) {
			if !conn_write_all(r.conn, transmute([]u8)string(HTTP_CONTINUE)) {
				return {}, 0, false
			}
		}
	}

	if chunked {
		body, bstatus, bok := read_chunked_body(r)
		if !bok {
			return refused, bstatus, false
		}
		req.body = body
		req.closing = true
		/*
		Closed after it is answered: the chunked framing this hop read is one a
		front end may have cut differently, and closing leaves it no next request
		on this connection to attribute anything to. RFC 9112 9.6 lets a server
		close after any response.
		*/
		req.keep_alive = false
	} else if f.content_length > 0 {
		// A view, where everything above is a copy: the body is the last thing
		// read, so nothing grows the buffer under it before the caller's
		// `http_compact`, which is what ends it.
		req.body = http_exact(r, f.content_length) or_return
	}
	return req, 0, true
}

/*
A copy of `s` in the scratch space; `held` goes false, for good, once one cannot
be made whole.
*/
@(private)
http_hold :: proc(s: string, held: ^bool) -> string {
	out, err := strings.clone(s, context.temp_allocator)
	held^ &&= err == nil && len(out) == len(s)
	return out
}

/*
Read the request line into `req`: its method, path and query, and whether it
keeps the connection alive. `authority` is an absolute-form target's, which
stands in for `Host`. `status` is the refusal when `ok` is false, as
`read_http_request` gives it.
*/
@(private)
read_request_line :: proc(r: ^Http_Reader, req: ^Http_Request_In, held: ^bool) -> (authority: string, absolute, http_1_0: bool, status: int, ok: bool) {
	line, lok, lbad := http_line(r)
	if !lok {
		return "", false, false, 400 if lbad else 0, false
	}

	// "METHOD SP request-target SP HTTP-version", three tokens and nothing else
	// (RFC 9112 3).
	first := strings.index_byte(line, ' ')
	if first <= 0 {
		return "", false, false, 400, false
	}
	rest := line[first + 1:]
	second := strings.index_byte(rest, ' ')
	if second <= 0 {
		return "", false, false, 400, false
	}
	target := rest[:second]
	version := rest[second + 1:]
	/*
	`second` is the first space in `rest`, so what follows the target - any
	further space included - is all in `version`. Checked rather than taken for
	one: read as "not HTTP/1.0, so 1.1 with keep-alive", `GET / JUNK` would be a
	request, and so would `GET / HTTP/1.1 trailing-garbage`.

	Both are the disagreement `h2.parse_content_length` is written against, on
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
		return "", false, false, 400, false
	}
	if vstatus := http_version_status(version); vstatus != 0 {
		return "", false, false, vstatus, false
	}
	/*
	The method is a token (RFC 9110 9.1) and the target visible ASCII (RFC 9112
	3.2). SP is the only separator this reader splits on, but RFC 9112 3 lets a
	recipient split on HTAB, VT, FF or a bare CR as well, so a byte of those in
	either half is a request line two hops read differently:
	`POST\t/allowed /dns-query HTTP/1.1` would be a POST to `/dns-query` here and
	a request for `/allowed` to a front end that split on the tab (#438). Bare CR
	never gets this far - see `http_line`.
	*/
	if !h2.is_token(line[:first]) || !h2.target_is_valid(target) {
		return "", false, false, 400, false
	}
	req.method = http_hold(line[:first], held)
	http_1_0 = version == "HTTP/1.0"
	req.keep_alive = !http_1_0

	/*
	RFC 9112 3.2.2: a server "MUST accept the absolute-form", and takes the
	host from it rather than from `Host` (3.2). Its authority is held to what
	`Host` is, userinfo included (RFC 9110 4.2.4), and what follows it is the
	origin-form target the rest of this reads.
	*/
	authority, absolute = absolute_form_authority(target)
	if absolute {
		if authority == "" || !h2.authority_is_valid(authority) {
			return "", false, false, 400, false
		}
		target = target[strings.index(target, "//") + 2 + len(authority):]
		// A copy now: `authority` is a view into the request line, and the
		// header lines read next may move the buffer it points into.
		authority = http_hold(authority, held)
	}
	path := target
	if q := strings.index_byte(target, '?'); q >= 0 {
		path = target[:q]
		req.query = http_hold(target[q + 1:], held)
	}
	// An absolute-form target with no path names the root (RFC 9110 4.2.3).
	req.path = http_hold(path if path != "" || !absolute else "/", held)
	return authority, absolute, http_1_0, 0, true
}

// What `read_field_lines` reads from a header block, beyond what it puts in the request.
@(private)
Http_Fields :: struct {
	// -1 for none, so a second Content-Length can be told from the first.
	content_length:  int,
	// Counted rather than flagged off `req.host`: an empty Host is a field the
	// client sent, and a second one has to be told from it.
	hosts:           int,
	content_types:   int,
	codings:         Transfer_Codings,
	// Field lines, apart from the codings they hold: one with none is a
	// Transfer-Encoding all the same to a hop that reads it as framing.
	te_fields:       int,
	expect_continue: bool,
	/*
	A 400 earned by a field's value is answered only once the block is read, as
	the 413 is, so that every field line is still judged as one: a field line
	that cannot be read is answered at once.
	*/
	malformed:       bool,
}

/*
Read the header block's field lines up to the empty one, keeping Host,
Content-Type and `Connection: close` in `req`. `status` is the refusal when `ok`
is false, a field line that cannot be read, as `read_http_request` gives it.
*/
@(private)
read_field_lines :: proc(r: ^Http_Reader, req: ^Http_Request_In, http_1_0: bool, held: ^bool) -> (f: Http_Fields, status: int, ok: bool) {
	f.content_length = -1
	for {
		header, hok, hbad := http_line(r)
		if !hok {
			return f, 400 if hbad else 0, false
		}
		if header == "" {
			break
		}
		name, value, field := h2.split_field_line(header)
		/*
		And a name is a token (RFC 9110 5.1), compared without regard to ASCII
		case and no other. `strings.equal_fold` folds Unicode, where the long s
		(U+017F) is an `s`, so `Hoſt` would count as Host; and a name outside
		the token grammar, once folded ASCII only, would be skipped here while
		a hop that folds the other way reads `Tranſfer-Encoding` as framing
		(#432). Refused, as the shapes `split_field_line` refuses are.
		*/
		if !field || !h2.is_token(name) {
			return f, 400, false
		}
		keep_field(&f, req, name, value, http_1_0, held)
	}
	return f, 0, true
}

// Keep what `read_http_request` reads from one field: in `req`, or in `f`.
@(private)
keep_field :: proc(f: ^Http_Fields, req: ^Http_Request_In, name, value: string, http_1_0: bool, held: ^bool) {
	switch {
	case dns.name_equal_fold(name, "content-length"):
		// RFC 9112 6.3: more than one of these, whether or not they agree,
		// or one that is not a length is an invalid message, since the hop
		// in front is entitled to resolve them differently from this one.
		// Too large is not refused here but after the headers: see
		// `request_framing`.
		v, vok := h2.parse_content_length(value, MAX_DOH_BODY)
		if f.content_length >= 0 || !vok {
			f.malformed = true
			return
		}
		f.content_length = v
	case dns.name_equal_fold(name, "connection"):
		if h2.list_has_token(value, "close") {
			req.keep_alive = false
		}
	case dns.name_equal_fold(name, "content-type"):
		// RFC 9110 5.3: a singleton field, and the loop keeps the last of a
		// repeat while a hop in front may judge the first. So a repeat is a
		// 400, as Host's is, rather than a media type picked for the check.
		f.content_types += 1
		if f.content_types > 1 {
			f.malformed = true
			return
		}
		req.content_type = http_hold(value, held)
	case dns.name_equal_fold(name, "host"):
		/*
		RFC 9112 3.2: a request carrying more than one Host is a 400, whether
		or not the two agree - the same argument a repeated Content-Length
		gets. The loop kept the last one it saw, and the .mobileconfig
		endpoint builds a URL out of it: given two, the profile a device
		installs names whichever of them this hop happened to keep, which is
		not necessarily the one the front end routed the request by.
		*/
		f.hosts += 1
		// And an invalid one is a 400 too (RFC 9112 3.2): held to what a
		// host may hold, as `:authority` is on HTTP/2 (#438).
		if f.hosts > 1 || !h2.authority_is_valid(value) {
			f.malformed = true
			return
		}
		req.host = http_hold(value, held)
	case dns.name_equal_fold(name, "transfer-encoding"):
		f.te_fields += 1
		if !transfer_codings_add(&f.codings, value) {
			f.malformed = true
		}
	case dns.name_equal_fold(name, "expect"):
		// RFC 9110 10.1.1: ignored on HTTP/1.0, and any other expectation
		// is one a server may ignore.
		f.expect_continue ||= !http_1_0 && h2.list_has_token(value, "100-continue")
	}
}

/*
Whether the body is chunked, from the fields `read_field_lines` read, and the
status to refuse the request with: 0 for none.
*/
@(private)
request_framing :: proc(f: Http_Fields, http_1_0: bool) -> (chunked: bool, status: int) {
	// RFC 9112 3.2 again: Host carries the authority, so an HTTP/1.1 request
	// without one is a 400 even where the target carries it too. HTTP/1.0
	// predates the field and is allowed to leave it out.
	if f.malformed || (f.hosts == 0 && !http_1_0) {
		return false, 400
	}

	if f.te_fields > 0 {
		switch {
		/*
		RFC 9112 6.1: an HTTP/1.0 message with a Transfer-Encoding is one whose
		framing is faulty, and a request with both it and a Content-Length is
		one a server may reject; this one does, since the pair is the shape
		request smuggling takes. 6.3: a final coding other than chunked, or a
		field with no coding at all, leaves the length unknowable, which is a
		400; chunked twice is a coding no sender may apply.
		*/
		case http_1_0, f.content_length >= 0, !f.codings.final_chunked, f.codings.chunked > 1:
			return false, 400
		// 6.1: a coding this server does not understand (it decodes chunked
		// alone) is a 501.
		case f.codings.count > 1:
			return false, 501
		}
		chunked = true
	}

	/*
	RFC 9110 15.5.14: a body larger than the server will process is a 413. Digits
	frame the request the same way to every hop - `parse_content_length` has
	checked all of them, and too many is no ambiguity about where it ends - so this
	is safe to answer, as everything above is. The body is not read, and the caller
	closes after the answer.
	*/
	if f.content_length > MAX_DOH_BODY {
		return false, 413
	}
	return chunked, 0
}

// The interim response RFC 9110 10.1.1 has a server send to `Expect: 100-continue`.
@(private)
HTTP_CONTINUE :: "HTTP/1.1 100 Continue\r\n\r\n"

/*
The authority of an absolute-form request target (RFC 9112 3.2.2), for an
`http` or `https` URI, the scheme compared without regard to ASCII case. Empty
when the target has none; `absolute` false for an origin-form target or another
scheme, which then reads as a path no endpoint serves.
*/
@(private)
absolute_form_authority :: proc(target: string) -> (authority: string, absolute: bool) {
	rest: string
	switch {
	case len(target) >= 7 && dns.name_equal_fold(target[:7], "http://"):
		rest = target[7:]
	case len(target) >= 8 && dns.name_equal_fold(target[:8], "https://"):
		rest = target[8:]
	case:
		return "", false
	}
	end := strings.index_any(rest, "/?")
	return rest if end < 0 else rest[:end], true
}

/*
What the `Transfer-Encoding` field lines of a request say, as one list (RFC 9110
5.3): how many codings, how many of them are chunked, and whether the last is.
*/
@(private)
Transfer_Codings :: struct {
	count:         int,
	chunked:       int,
	final_chunked: bool,
}

/*
Add a `Transfer-Encoding` value's codings to `t`. False for a value that is not
a list of codings (RFC 9112 7: a token, then parameters), or chunked with a
parameter, which it has none of.
*/
@(private)
transfer_codings_add :: proc(t: ^Transfer_Codings, value: string) -> bool {
	rest := value
	for len(rest) > 0 {
		// The next element, up to a comma that is not inside a quoted-string
		// (RFC 9110 5.6.1, 5.6.4): a parameter's value may hold one.
		at := 0
		for at < len(rest) && rest[at] != ',' {
			if rest[at] == '"' {
				q := h2.quoted_string_prefix(rest[at:])
				if q == 0 {
					return false
				}
				at += q
			} else {
				at += 1
			}
		}
		element := rest[:at]
		rest = rest[min(at + 1, len(rest)):]
		coding := h2.trim_ows(element)
		// RFC 9110 5.6.1: empty elements of a list are ignored.
		if coding == "" {
			continue
		}
		name := coding
		params := false
		if semi := strings.index_byte(coding, ';'); semi >= 0 {
			name = h2.trim_ows(coding[:semi])
			params = true
			// RFC 9112 7: each a token, "=", and a token or quoted-string.
			if !h2.params_are_valid(coding[semi:], value_optional = false) {
				return false
			}
		}
		if !h2.is_token(name) {
			return false
		}
		t.count += 1
		t.final_chunked = dns.name_equal_fold(name, "chunked")
		if t.final_chunked {
			t.chunked += 1
			if params {
				return false
			}
		}
	}
	return true
}

/*
Read a chunked body (RFC 9112 7.1) and hand back the content, de-chunked in
place in the reader's buffer: a view that ends at the caller's `http_compact`,
as a Content-Length body's does.

`status` is the answer to a body this refuses: 413 for content past
`MAX_DOH_BODY`, 400 for a chunk that does not read as one or framing past
`MAX_HEADER_BYTES` all told, and 0 for a read that failed. Chunk lines are read
by `h2.parse_chunk_line`; trailer fields are read as field lines and dropped
(7.1.2), nothing this endpoint serves reading one.
*/
@(private)
read_chunked_body :: proc(r: ^Http_Reader) -> (body: []u8, status: int, ok: bool) {
	start := r.pos
	end := start
	for {
		/*
		Measured from the end of the content moved down so far: what lies past
		it is framing - chunk lines and CRLFs - or not yet read, and it stays
		in the buffer until the caller compacts it. Bounded all told, or a
		stream of one-byte chunks with long extensions holds the content's
		limit in data and as much again, many times over, in framing.
		*/
		line, lok, lbad := http_line(r, from = end)
		if !lok {
			return nil, chunk_line_status(r, end, lbad), false
		}
		size, chunk := h2.parse_chunk_line(line, MAX_DOH_BODY)
		if !chunk {
			return nil, 400, false
		}
		if size == 0 {
			break
		}
		if end - start + size > MAX_DOH_BODY {
			return nil, 413, false
		}
		// Indices, not views: a read may move the buffer.
		at := r.pos
		_ = http_exact(r, size + 2) or_return
		if r.buf[at + size] != '\r' || r.buf[at + size + 1] != '\n' {
			return nil, 400, false
		}
		copy(r.buf[end:], r.buf[at:at + size])
		end += size
	}
	// The trailer section: field lines up to an empty one, held to what a
	// header block's lines are, and inside the same bound as the chunk lines.
	for {
		line, lok, lbad := http_line(r, from = end)
		if !lok {
			return nil, chunk_line_status(r, end, lbad), false
		}
		// `http_line` holds a line it has to wait for to the bound; what was
		// already in the buffer, chunk lines included, is held to it here,
		// before the body is handed back.
		if r.pos - end > MAX_HEADER_BYTES {
			return nil, 400, false
		}
		if line == "" {
			break
		}
		colon := strings.index_byte(line, ':')
		if colon <= 0 || !h2.is_token(line[:colon]) {
			return nil, 400, false
		}
	}
	return r.buf[start:end], 0, true
}

/*
The answer to a chunk or trailer line `http_line` refused: 400 for a malformed
one or for framing past `MAX_HEADER_BYTES`, measured from `end` as the lines
are, and 0 for a read that failed.
*/
@(private)
chunk_line_status :: proc(r: ^Http_Reader, end: int, malformed: bool) -> int {
	return 400 if malformed || len(r.buf) - end > MAX_HEADER_BYTES else 0
}

/*
Read requests off `conn` the way `serve_doh` does, and answer none of them: the
interim 100 `read_http_request` itself writes to an `Expect: 100-continue` is
all that goes back.

For the fuzz target, which lives in a package of its own and cannot reach the
reader: every request line, header loop and body this server would read, one
after another as a client pipelining them sends them, with the `dns` parameter
of each decoded as a GET would. Nothing else calls it.
*/
fuzz_http_requests :: proc(conn: Conn) {
	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE),
	}
	defer delete(r.buf)
	for {
		req, _, ok := read_http_request(&r)
		if !ok {
			return
		}
		if param, found := query_param(req.query, "dns"); found {
			_, _ = decode_dns_param(param)
		}
		http_compact(&r)
		// As `serve_doh` does between requests, so nothing the next one reads can
		// lean on this one's scratch.
		free_all(context.temp_allocator)
		// And, as there, nothing is read past a request that ends the connection.
		if !req.keep_alive {
			return
		}
	}
}

@(private)
serve_doh :: proc(s: ^Server, conn: Conn, client: string) {
	path := startup_config(s).listeners.doh.path

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

	last_question := loop.tick_now()
	// A client pipelining requests the cache answers never lets this fiber park;
	// its reads and writes step aside between them (`loop.take_turn`).
	for {
		// Nothing to free: the round before this one reset the arena on its way out.
		if doh_question_overdue(s, last_question, loop.tick_now()) {
			return
		}
		// Per request, so a connection kept alive between requests waits the whole
		// of `client_timeout` for the next one to start and the request that then
		// starts gets the whole of it too.
		r.budget = Read_Budget {
			idle = client_timeout(s),
		}

		req, status, ok := read_http_request(&r)
		if !ok {
			// The connection ends either way: `keep_alive` is false, so nothing
			// further is read off a connection whose next byte this server cannot
			// place.
			refuse_http_request(conn, "doh", status, req.method)
			free_all(context.temp_allocator)
			return
		}
		keep_alive := req.keep_alive
		closing := req.closing
		asked := false
		handled := serve_doh_request(s, conn, req, path, client, &asked)
		// After the answer, since `req.body` is a view into the reader's buffer,
		// and before the next round, so that what the reader carries into it is
		// the next request and nothing before it.
		http_compact(&r)
		free_all(context.temp_allocator)
		// Once it is answered rather than when it was charged, as a TCP client's
		// idle wait starts once its answer is written: the time the question takes
		// is not time the connection asked nothing.
		if asked {
			last_question = loop.tick_now()
		}
		if !handled || !keep_alive {
			// A close the client did not ask for may come with a request it
			// already pipelined, unread here, and closing on unread bytes sends
			// an RST that takes the answer with it: see `http_linger`.
			if closing {
				http_linger(conn, STREAM_LINGER_IDLE)
			}
			return
		}
	}
}

/*
Whether a DoH connection, over either HTTP version, has gone too long without
asking a question to be kept any longer (#344).

The per-message budget bounds how long one request or one frame may take, and not
how long a connection may live, and over HTTP those come apart. A request for
another path is answered 404 and keeps its connection, and an h2 SETTINGS or PING
is read and the loop goes round again - and none of them is charged to
`stream_rate_check`, which bills questions. A peer sending one inside every idle
wait would hold a connection, a fiber and one of `max_connections` forever for
nothing. The length-prefixed transports do not have the gap: a TCP or DoT client
keeps its connection only by completing DNS messages, and every one is charged.

So this is that rule, put in terms HTTP can keep: a connection must ask a question
- the thing the limiter charges - within twice `client_timeout`, or it is let go.
Twice because that is the longest a TCP client may go between messages it is
charged for: the idle wait for the next one to start, and the deadline that start
begins. A browser asking questions is never near it, and one holding an idle DoH
connection with nothing on it is closed by the idle wait long before it. What it
ends is a connection kept alive only by requests that cost the peer nothing.

Checked where each request or frame is about to be read, so a connection is held
past the figure by at most the one read it was waiting on - which the per-message
budget bounds - and never indefinitely.

The loader refuses a `client_timeout` under a millisecond; a non-positive one in a
`Config` built elsewhere is no idle wait at all, and this adds none.
*/
@(private)
doh_question_overdue :: proc(s: ^Server, last_question: time.Tick, now: time.Tick) -> bool {
	limit := client_timeout(s)
	// Less the limit rather than against twice it, which overflows for a
	// `client_timeout` past 146 years - refused by the loader, not by a `Config`
	// built elsewhere - into a negative bound that closes every connection
	// before its first request.
	return limit > 0 && time.tick_diff(last_question, now) - limit > limit
}

@(private)
serve_doh_request :: proc(
	s: ^Server,
	conn: Conn,
	req: Http_Request_In,
	path: string,
	client: string,
	// Set where the request is charged, which is what makes it a question. See
	// `doh_question_overdue`.
	asked: ^bool,
) -> bool {
	// Before every path, the profile and the 404s included: the accept loop
	// gives a source outside the list nothing at all, and a reload that removed
	// a held connection's network leaves it in the same place. Closed after the
	// answer, as the accept loop would have.
	head := req.method == "HEAD"
	if !stream_source_allowed(s, conn.peer, .DoH) {
		written := send_http_error(conn, "doh", 403, "forbidden", false, head = head)
		// What the client pipelined behind this request is unread, and the close
		// would take the 403 back with it - see `http_linger`.
		http_linger(conn, STREAM_LINGER_IDLE)
		return written
	}
	mc_path := startup_config(s).listeners.doh.mobileconfig_path
	if mc_path != "" && req.path == mc_path {
		profile, status, why, ok := doh_profile(s, req.method, req.host, "missing or invalid Host header")
		if !ok {
			allow := MOBILECONFIG_METHODS if status == 405 else ""
			return send_http_error(conn, "doh", status, why, req.keep_alive, allow, head)
		}
		return send_http_ok(
			s,
			conn,
			DOH_MOBILECONFIG_CONTENT_TYPE,
			profile,
			req.keep_alive,
			"Content-Disposition",
			PROFILE_DISPOSITION,
		)
	}
	if req.path != path {
		return send_http_error(conn, "doh", 404, "not found", req.keep_alive, head = head)
	}

	query, status, why, is_query := doh_query_message(req.method, req.content_type, req.body, req.query)
	if !is_query {
		if why == DOH_NOT_A_QUERY {
			sync.atomic_add(&s.stats.dropped, 1)
		}
		return send_http_error(conn, "doh", status, why, req.keep_alive, DOH_METHODS if status == 405 else "", head)
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
	asked^ = true
	if !stream_admits(s, conn.peer) {
		report_rate_limited(client, .DoH, !req.keep_alive)
		return send_http_error(conn, "doh", 429, "too many requests", req.keep_alive)
	}

	// HTTP/1.1, which answers on the connection's own fiber rather than on one
	// of its own. Cache-Control mirrors the smallest TTL, or a
	// denial's SOA figure, so intermediaries expire the answer at the same time
	// the DNS data does - the bounded TTL, see `doh_max_age`.
	max_age: u32
	// Answered on the connection's fiber, outside `max_pending`; see `handle_query`'s `pool`.
	response, _, ok := handle_query(s, query, .DoH, client, context.temp_allocator, pool = .Connection, max_age = &max_age)
	if !ok || len(response) == 0 {
		return send_http_error(conn, "doh", 500, "no response", req.keep_alive)
	}
	return send_http_ok(
		s,
		conn,
		DOH_CONTENT_TYPE,
		response,
		req.keep_alive,
		"Cache-Control",
		doh_cache_control(max_age),
	)
}

// Why a DoH request carrying a response (QR set) is a 400; counted as dropped
// by whichever version answers it, as `handle_query` counts the others.
DOH_NOT_A_QUERY :: "not a query"

/*
The DNS message a request to the DoH endpoint is asking about, over either HTTP
version, or the status and reason that say it was not asking about one.

It decides both whether a request is charged and what it asks: `serve_doh_request`
charges once it passes, and over HTTP/2 `h2_charged` asks it on the reader fiber
before `build_h2_response` asks it again for the message. One check for every
caller, because two that disagreed would spend a budget on a 400, or let the same
400 through for free.

`query` is the request target's query string, which carries the GET form's
`dns` parameter (RFC 8484 4.1).
*/
@(private)
doh_query_message :: proc(
	method: string,
	content_type: string,
	body: []u8,
	query: string,
) -> (
	message: []u8,
	status: int,
	why: string,
	ok: bool,
) {
	switch method {
	case "POST":
		if !doh_content_type_ok(content_type) {
			return nil, 415, "unsupported media type", false
		}
		message = body
	case "GET":
		encoded, found := query_param(query, "dns")
		if !found {
			return nil, 400, "missing dns parameter", false
		}
		decoded, dok := decode_dns_param(encoded)
		if !dok || len(decoded) == 0 {
			return nil, 400, "malformed dns parameter", false
		}
		message = decoded
	case:
		return nil, 405, "method not allowed", false
	}

	if len(message) < dns.HEADER_SIZE {
		return nil, 400, "message too short", false
	}
	// The client's error, so 400 (RFC 9110 section 15.5.1) rather than the 500
	// `handle_query` dropping it would give; see there.
	if dns.peek_is_response(message) {
		return nil, 400, DOH_NOT_A_QUERY, false
	}
	return message, 0, "", true
}

// The profile is a download whichever HTTP version asked for it (RFC 6266).
PROFILE_DISPOSITION :: `attachment; filename="elodin-doh.mobileconfig"`

/*
The Apple .mobileconfig profile that points a device at this DoH endpoint, over
either HTTP version, or the status and reason that turn the request away.

A GET, since a device downloads it by navigating to the URL; anything else is a
405. The URL inside it is built from `host` - the request's `Host`, or its
`:authority` over HTTP/2 - so a request that carries none, or one this server
could not have a certificate for, gets a 400 rather than a profile naming a host
that does not resolve. `bad_host` is that 400's reason, naming the field the way
the request's own HTTP version spells it. The path the profile has the device
query is `listeners.doh.path`, which the signer was built with; nothing here has
to be told it a second time.

What comes back is signed with the listener's own certificate, so the device
reports a profile it can verify rather than an unsigned one. `profile.odin` owns
the deciding; two of the three answers it can give are refusals, and both are
refusals this endpoint could not have made before there was a signature to make
them about.
*/
@(private)
doh_profile :: proc(
	s: ^Server,
	method: string,
	host: string,
	bad_host: string,
) -> (
	profile: []u8,
	status: int,
	why: string,
	ok: bool,
) {
	if method != "GET" {
		return nil, 405, "method not allowed", false
	}
	// Cheap syntax first: a Host with a byte no authority may contain is turned
	// away without the certificate being consulted about it.
	if !valid_mobileconfig_host(host) {
		return nil, 400, bad_host, false
	}
	signed, verdict := profile_for_host(s.profiles, host, tlsx.unix_now(), context.temp_allocator)
	switch verdict {
	case .Unknown_Host:
		return nil, 400, "not a host and port this server serves", false
	case .Unavailable:
		return nil, 503, "profile signing unavailable", false
	case .OK:
	}
	return signed, 0, "", true
}

// The `Cache-Control` value for an answer `doh_max_age` gave `max_age`, over
// either HTTP version.
@(private)
doh_cache_control :: proc(max_age: u32) -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "max-age=")
	strings.write_int(&b, int(max_age))
	return strings.to_string(b)
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
The `Cache-Control: max-age` for a response: the smallest TTL it carries, and
for a denial no more than its SOA says.

Reads the answer as it is about to be sent, which is the answer after
`handle_query` has bounded its TTLs: `dns.sane_ttl` applied and
`cache.max_ttl` (or `dns.TTL_CAP`) on top of it, whether the bytes came out of the cache or
straight from an upstream. So the header cannot outlive the DNS data it is
mirroring, and a hostile TTL cannot be laundered through it into every HTTP
cache between here and the client - which recomputing the figure from what the
upstream sent would do. `sane_ttl` applies again on the way past,
which costs nothing and means this holds for any caller that reaches it with
bytes from somewhere else.

A denial is bounded by RFC 8484 section 5.1: with no answer records and a SOA
in authority, the freshness lifetime "MUST NOT be greater than the MINIMUM
field from that SOA record" - which the smallest TTL alone does not bound,
since the SOA record's own TTL is usually the larger of the two. NODATA after a
CNAME is a denial too (RFC 2308 section 2.2), and one without a SOA gets no
freshness at all, as `cache.put` keeps none: the CNAME's own TTL would
otherwise have every HTTP cache in the path hold the NODATA for up to
`cache.max_ttl`.

One decode, charged to `spent`, the request's counter, like every other
reading it makes. A response that will not decode - or that this request can no
longer afford to read - gets no freshness: nothing here can say it is not a
denial, and `cache.put` keeps nothing it read only in part either.
*/
@(private)
doh_max_age :: proc(response: []u8, allocator := context.temp_allocator, spent: ^int = nil) -> u32 {
	msg, err := dns.decode_message(response, allocator, spent)
	if err != .None {
		return 0
	}
	v: u32 = max(u32)
	has := false
	for section in ([][]dns.Record{msg.answer, msg.authority, msg.additional}) {
		for r in section {
			// An OPT record's TTL field is extended rcode and flags.
			if r.type != .OPT {
				v, has = min(v, dns.sane_ttl(r.ttl)), true
			}
		}
	}
	if !has {
		return 0
	}
	if cache.denial(msg) {
		soa, has_soa := dns.negative_ttl(msg)
		v = min(v, soa) if has_soa else 0
	}
	return v
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
	switch status {
	case 413:
		return "content too large"
	case 501:
		return "not implemented"
	case 505:
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
the body is, and a bad header block or a body over the limit before reading the
body. Closing a socket whose receive queue still holds bytes does not send
a FIN but an RST (RFC 1122 4.2.2.13), and an RST arriving at a client that has
not read yet has its kernel discard what is already in its receive buffer - so
the status this endpoint went to the trouble of writing is thrown away and the
client sees a connection reset, which is the bare closed connection the status
was there to replace.

Discarded rather than parsed: `keep_alive` is false on every path that gets here,
so nothing further on this connection is answered and what these bytes say does
not matter. A client that stops short of what it declared, that keeps sending past
`HTTP_LINGER_BYTES`, or that trickles for longer than `HTTP_LINGER_TIMEOUT`, ends
the drain on the idle wait, the limit or the deadline rather than holding the
connection's fiber.

`idle` is the per-read wait, and the caller chooses it because the caller is what
knows whether the bytes that are left are already here or still arriving. A
refused request whose body may still be arriving passes `HTTP_LINGER_BODY_IDLE`;
the allow-list refusal, behind which there is only what the client had already
pipelined, passes `STREAM_LINGER_IDLE`. It is passed rather than defaulted so
that a path added later has to answer the question rather than inherit an answer.
*/
@(private)
http_linger :: proc(conn: Conn, idle: time.Duration) {
	conn_linger(conn, idle, HTTP_LINGER_TIMEOUT, HTTP_LINGER_BYTES)
}

/*
Answer a request `read_http_request` refused with the status it handed back,
then drain what the client sent before the close takes the answer with it. A
`status` of 0 is a request answered with nothing - see `read_http_request` - and
nothing is drained for it either.

Both HTTP endpoints refuse this way, the connection closing after: `who` names
the one in the debug line, and a refusal to a HEAD goes without content (RFC 9110
9.3.2). The refused request may have declared a body that was never read and may
still be arriving, which is what picks the longer of the two idle waits - see
`HTTP_LINGER_BODY_IDLE`.
*/
@(private)
refuse_http_request :: proc(conn: Conn, who: string, status: int, method: string) {
	if status == 0 {
		return
	}
	_ = send_http_error(conn, who, status, http_refusal_message(status), false, head = method == "HEAD")
	http_linger(conn, HTTP_LINGER_BODY_IDLE)
}

/*
The `Server` field's value under `server.identity: version`: the build on an
HTTP/1.1 200, and the product alone on every HTTP/2 response.
*/
@(private)
SERVER_FIELD :: PRODUCT + "/" + VERSION
@(private)
H2_SERVER_FIELD :: PRODUCT

/*
The `Server` field an HTTP/1.1 200 carries: `SERVER_FIELD` under
`server.identity: version`, and "" - no field - under any other setting,
which RFC 9110 section 10.2.4 allows. A text the operator chose for the CHAOS
names is not a `product` token, and is not put in a header field.
*/
@(private)
server_field :: proc(s: ^Server) -> string {
	pin_scope(s)
	return SERVER_FIELD if live(s).cfg.server.identity == .Version else ""
}

/*
A 200 carrying `body`, and the one field beside the common ones that each answer
has its own reason for: Cache-Control on a DoH answer and on the metrics page,
Content-Disposition on the profile. `Server` is sent as
`server_field` says. A reply to `head` is its fields alone (RFC
9112 6.3), carrying the Content-Length GET would have (RFC 9110 8.6).
*/
@(private)
send_http_ok :: proc(
	s: ^Server,
	conn: Conn,
	content_type: string,
	body: []u8,
	keep_alive: bool,
	field: string,
	value: string,
	head := false,
) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: ")
	strings.write_string(&b, content_type)
	strings.write_string(&b, "\r\nContent-Length: ")
	strings.write_int(&b, len(body))
	strings.write_string(&b, "\r\n")
	strings.write_string(&b, field)
	strings.write_string(&b, ": ")
	strings.write_string(&b, value)
	strings.write_string(&b, "\r\nDate: ")
	strings.write_string(&b, now_http_date(context.temp_allocator))
	if server := server_field(s); server != "" {
		strings.write_string(&b, "\r\nServer: ")
		strings.write_string(&b, server)
	}
	strings.write_string(&b, "\r\nConnection: ")
	strings.write_string(&b, "keep-alive" if keep_alive else "close")
	strings.write_string(&b, "\r\n\r\n")
	if !conn_write_all(conn, transmute([]u8)strings.to_string(b)) {
		return false
	}
	return head || conn_write_all(conn, body)
}

// `who` names the endpoint in the debug line. Both HTTP endpoints this server
// has - DoH and the metrics one - refuse requests the same way, and a log line
// that named only one of them would send an operator to the wrong port. `allow`
// is the target's methods, which RFC 9110 15.5.6 requires on a 405. A reply to
// `head` is its fields alone (RFC 9112 6.3): text after them would be read as
// the start of the next reply on the connection. It carries no Content-Length
// either, which RFC 9110 8.6 allows only when it is what GET would have sent.
// Every refusal carries a Date, which RFC 9110 6.6.1 requires on a 4xx from a
// server with a clock, and allows on a 5xx.
@(private)
send_http_error :: proc(
	conn: Conn,
	who: string,
	status: int,
	message: string,
	keep_alive: bool,
	allow := "",
	head := false,
) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 ")
	strings.write_int(&b, status)
	strings.write_byte(&b, ' ')
	strings.write_string(&b, message)
	strings.write_string(&b, "\r\nContent-Type: text/plain")
	if !head {
		strings.write_string(&b, "\r\nContent-Length: ")
		strings.write_int(&b, len(message) + 1)
	}
	strings.write_string(&b, "\r\nDate: ")
	strings.write_string(&b, now_http_date(context.temp_allocator))
	strings.write_string(&b, "\r\nConnection: ")
	strings.write_string(&b, "keep-alive" if keep_alive else "close")
	if allow != "" {
		strings.write_string(&b, "\r\nAllow: ")
		strings.write_string(&b, allow)
	}
	strings.write_string(&b, "\r\n\r\n")
	if !head {
		strings.write_string(&b, message)
		strings.write_byte(&b, '\n')
	}

	logx.debugf("%s: replying %d %s", who, status, message)
	return conn_write_all(conn, transmute([]u8)strings.to_string(b)) && keep_alive
}
