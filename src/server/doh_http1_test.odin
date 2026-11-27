package server

import "core:fmt"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
The HTTP/1.1 grammar a DoH request is read under (RFC 9112): the request line,
the field lines and their values, the framing of the body, and the fields of
the response written back.
*/

/*
Hand `raw` to `read_http_request` over a loopback socket.

The sender closes as soon as its bytes are away. A reader that asks for more
than what was sent therefore reaches the end of the connection instead of
blocking, which is what a body shorter than its declared length has to look
like here.

`status` is what the reader asks the caller to answer a refused request with,
and `ok` is whether the loopback pair itself came up - not whether the request
parsed, which is `parsed`.
*/
@(private = "file")
read_request_over_loopback :: proc(
	t: ^testing.T,
	raw: string,
	what: string,
) -> (
	req: Http_Request_In,
	status: int,
	parsed, ok: bool,
) {
	// A few hundred bytes, so the whole request fits in the socket buffer and
	// this side never has to interleave sending with the reading below.
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		testing.expectf(t, false, "%s: no loopback connection", what)
		return {}, 0, false, false
	}
	defer net.close(accepted)
	_, serr := net.send_tcp(client, transmute([]u8)raw)
	net.close(client)
	if !testing.expectf(t, serr == nil, "%s: cannot send the request: %v", what, serr) {
		return {}, 0, false, false
	}
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}

	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE, context.temp_allocator),
	}
	req, status, parsed = read_http_request(&r)
	return req, status, parsed, true
}

@(private = "file")
HOST :: "Host: dns.example\r\n"

@(private = "file")
TWO_HOSTS :: "Host: a.example\r\nHost: b.example\r\n"

@(private = "file")
Request_Line_Case :: struct {
	line:       string, // the request line, without its CRLF
	host:       string, // the Host field lines, if any, each with its CRLF
	status:     int, // 0 for a request that parses
	keep_alive: bool, // what the version asks for, when it parses
	what:       string,
}

// `test_request_line_is_three_tokens_with_a_known_version`'s cases.
@(private = "file")
REQUEST_LINE_CASES :: [?]Request_Line_Case {
	{"GET /dns-query HTTP/1.1", HOST, 0, true, "an ordinary 1.1 request line"},
	{"GET /dns-query HTTP/1.0", HOST, 0, false, "1.0, which keep-alive is not assumed for"},
	// RFC 9112 3.2 asks for Host on HTTP/1.1; 1.0 predates the field.
	{"GET /dns-query HTTP/1.0", "", 0, false, "1.0 without a Host, which is allowed"},
	{"GET /dns-query HTTP/1.9", HOST, 0, true, "a minor version this major version allows"},
	// 505 is for a major version this server does not speak; a token that is
	// not a version at all is a malformed request line, which is a 400.
	{"GET /dns-query HTTP/2.0", HOST, 505, false, "a major version this endpoint does not speak"},
	{"GET /dns-query HTTP/0.9", HOST, 505, false, "a major version below this one"},
	{"GET /dns-query JUNK", HOST, 400, false, "a version that is not one"},
	{"GET /dns-query HTTP/1.10", HOST, 400, false, "a two-digit minor version, which is not the grammar"},
	{"GET /dns-query http/1.1", HOST, 400, false, "a lowercase version name"},
	{"GET /dns-query HTTP/1.1\t", HOST, 400, false, "a tab on the end of an otherwise good version"},
	{"GET /dns-query HTTP/11", HOST, 400, false, "a version with no dot in it"},
	{"GET /dns-query HTTP/1.x", HOST, 400, false, "a minor version that is not a digit"},
	{"GET /dns-query HTTP/x.1", HOST, 400, false, "a major version that is not a digit"},
	{"GET /dns-query HTTP/1.1 x", HOST, 400, false, "a fourth token"},
	{"GET /dns-query HTTP/1.1 ", HOST, 400, false, "a trailing space"},
	{"GET /dns-query ", HOST, 400, false, "no version at all"},
	{"GET  HTTP/1.1", HOST, 400, false, "an empty target"},
	{" /dns-query HTTP/1.1", HOST, 400, false, "an empty method"},
	// RFC 9112 3 lets a recipient split on HTAB, VT, FF or a bare CR as well
	// as SP, so a method that is not a token is a request line a lenient hop
	// reads as another one: `POST\t/allowed` routed there by `/allowed` (#438).
	{"POST\t/allowed /dns-query HTTP/1.1", HOST, 400, false, "a tab inside the method"},
	{"GET\x0b /dns-query HTTP/1.1", HOST, 400, false, "a VT on the end of the method"},
	{"GET\x0c /dns-query HTTP/1.1", HOST, 400, false, "an FF on the end of the method"},
	{"GE(T /dns-query HTTP/1.1", HOST, 400, false, "a method with a delimiter in it"},
	{"G\u00c9T /dns-query HTTP/1.1", HOST, 400, false, "a method outside ASCII"},
	// And the target is the other half of the same split.
	{"GET /allowed\t/dns-query HTTP/1.1", HOST, 400, false, "a tab inside the target"},
	{"GET /dns-query\x0bHTTP/1.1 HTTP/1.1", HOST, 400, false, "a VT inside the target"},
	{"GET /dns-query\x7f HTTP/1.1", HOST, 400, false, "a DEL inside the target"},
	{"GET /dns-query?dns=\u00c9 HTTP/1.1", HOST, 400, false, "a target outside ASCII"},
	{"M-SEARCH /dns-query HTTP/1.1", HOST, 0, true, "a method that is an unusual token"},
	{"GET /dns-query", HOST, 400, false, "two tokens"},
	{"GET /dns-query HTTP/1.1", "", 400, false, "1.1 with no Host"},
	{"GET /dns-query HTTP/1.1", HOST + HOST, 400, false, "identical repeats of Host"},
	{"GET /dns-query HTTP/1.1", TWO_HOSTS, 400, false, "conflicting repeats of Host"},
	{"GET /dns-query HTTP/1.0", TWO_HOSTS, 400, false, "repeats of Host on 1.0 as well"},
	// RFC 9112 3.2: an invalid Host is a 400, and `:authority` is refused
	// the same way on HTTP/2 (#438).
	{"GET /dns-query HTTP/1.1", "Host: dns example\r\n", 400, false, "a Host with a space in it"},
	{"GET /dns-query HTTP/1.1", "Host: dns\texample\r\n", 400, false, "a Host with a tab in it"},
	{"GET /dns-query HTTP/1.1", "Host: dns.ex\u00e4mple\r\n", 400, false, "a Host outside ASCII"},
	{"GET /dns-query HTTP/1.1", "Host: [::1]:443\r\n", 0, true, "a Host that is an IPv6 authority"},
	// uri-host [":" port] holds none of userinfo, a path, a query or a
	// fragment, and a hop that routes by Host parses each of them its own way.
	{"GET /dns-query HTTP/1.1", "Host: a.example@b.example\r\n", 400, false, "a Host with userinfo"},
	{"GET /dns-query HTTP/1.1", "Host: a.example/x\r\n", 400, false, "a Host with a path"},
	{"GET /dns-query HTTP/1.1", "Host: a.example\\x\r\n", 400, false, "a Host with a backslash"},
	{"GET /dns-query HTTP/1.1", "Host: a.example?x\r\n", 400, false, "a Host with a query"},
	{"GET /dns-query HTTP/1.1", "Host: a.example#x\r\n", 400, false, "a Host with a fragment"},
}

/*
A request line is three tokens, and the third of them is a version this server
speaks.

RFC 9112 3 writes it as `method SP request-target SP HTTP-version` with nothing
around it, and 2.3 writes the version as `HTTP/1.<DIGIT>` here. A reader that
split on the first two spaces and never looked at the third token would take
anything there: `JUNK` would be read as a version, and so would
`HTTP/1.1 trailing-garbage`, because everything after the target - further
spaces included - would land in it.

Both are the disagreement the `Content-Length` cases below are about, on the
other half of the request line. A front end sharing :443 with elodin, or
terminating TLS in front of it, reads the version as the grammar writes it: it
refuses the message, or - for `HTTP/1.1 x` - takes the target to be `/` on a
request this hop was willing to answer. `Host` is the same argument again: RFC
9112 3.2 makes it mandatory on HTTP/1.1 and a repeat invalid, for the reason a
repeated `Content-Length` is.

Which refusal each one gets is checked too, because the two are not
interchangeable: 505 says the *major version* is unsupported (RFC 9110 15.6.6),
which a client acts on by asking again in another version, and every other failure
here is a malformed request line, which RFC 9112 3 answers with a 400. A `JUNK`
answered 505 sends a client off to change something that was never wrong.

`status` is what the caller answers with, and 0 is "answer nothing, close" - the
framing cases keep that, an answer on a connection whose next byte this server
cannot place being worse than a close.
*/
@(test)
test_request_line_is_three_tokens_with_a_known_version :: proc(t: ^testing.T) {
	for c in REQUEST_LINE_CASES {
		ok := expect_request_line(t, c)
		free_all(context.temp_allocator)
		if !ok {
			return
		}
	}
}

// Read `c`'s request line over loopback and expect its verdict; false when the
// loopback pair would not come up.
@(private = "file")
expect_request_line :: proc(t: ^testing.T, c: Request_Line_Case) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, c.line)
	strings.write_string(&b, "\r\n")
	strings.write_string(&b, c.host)
	strings.write_string(&b, "\r\n")

	req, status, parsed, ok := read_request_over_loopback(t, strings.to_string(b), c.what)
	if !ok {
		return false
	}
	if c.status == 0 {
		testing.expectf(t, parsed, "%s was refused with a %d", c.what, status)
		if parsed {
			testing.expectf(
				t,
				req.keep_alive == c.keep_alive,
				"%s: keep_alive came back as %v, expected %v",
				c.what,
				req.keep_alive,
				c.keep_alive,
			)
		}
	} else {
		testing.expectf(t, !parsed, "%s was accepted, as %q", c.what, req.path)
		testing.expectf(t, status == c.status, "%s: answered %d, expected %d", c.what, status, c.status)
	}
	return true
}

@(private = "file")
Content_Length_Case :: struct {
	headers:  string, // between the request line and the blank line
	body:     string,
	accepted: bool,
	what:     string,
}

// `test_content_length_is_strict_decimal`'s cases.
@(private = "file")
CONTENT_LENGTH_CASES :: [?]Content_Length_Case {
	{"Content-Length: 4\r\n", "abcd", true, "a plain decimal length"},
	{"Content-Length: 004\r\n", "abcd", true, "leading zeroes, still 1*DIGIT"},
	{"Content-Length: 0x4\r\n", "abcd", false, "hexadecimal"},
	{"Content-Length: 0b100\r\n", "abcd", false, "binary"},
	{"Content-Length: 0o4\r\n", "abcd", false, "octal"},
	{"Content-Length: 0z4\r\n", "abcd", false, "base twelve, which the prefix table also has"},
	{"Content-Length: 1_0\r\n", "abcdefghij", false, "a digit separator"},
	{"Content-Length: +4\r\n", "abcd", false, "a signed length"},
	{"Content-Length: -4\r\n", "abcd", false, "a negative length"},
	{"Content-Length: \r\n", "", false, "an empty length"},
	{"Content-Length: 4 5\r\n", "abcd", false, "two lengths in one field"},
	{"Content-Length: 4\r\nContent-Length: 0\r\n", "abcd", false, "conflicting repeats"},
	{"Content-Length: 4\r\nContent-Length: 4\r\n", "abcd", false, "identical repeats"},
	{"Content-Length:\t4\t\r\n", "abcd", true, "tabs around the digits, which is OWS"},
	/*
	Three ways to write a length this reader does not recognise as one while
	a hop in front may: a non-breaking space is not OWS but is whitespace to
	`strings.trim_space`; a folded line is a continuation of the one above it
	(RFC 9112 5.2); and space before the colon is not a field name (RFC 9112
	5.1). Skipped rather than refused, each leaves the body unread and the
	next request starting in the middle of it.
	*/
	{"Content-Length: 4\u00a0\r\n", "abcd", false, "a non-breaking space after the digits"},
	{"X-Fold: one\r\n Content-Length: 4\r\n", "abcd", false, "a folded continuation line"},
	{"Content-Length : 4\r\n", "abcd", false, "space before the colon"},
	{"Content-Length\t: 4\r\n", "abcd", false, "a tab before the colon"},
	{"just-some-garbage\r\n", "", false, "a field line with no colon at all"},
}

/*
`Content-Length` is `1*DIGIT` (RFC 9110 8.6) and nothing else.

A lenient parser reads a good deal more than that - `strconv.parse_int` with its
default base takes the base from a prefix, so `0x10` would be 16 and `0b1010`
10; skips `_` between digits, so `1_0` would be 10; allows a leading sign; and
wraps the accumulator without reporting it, so `18446744073709551620` would be 4
and the range check that follows would see nothing wrong with it.

Every one of those is a length elodin would act on and a front end would not.
Sharing :443 with a web server, or terminating TLS at nginx, haproxy or Envoy,
is an ordinary way to run DoH, and those parse the field as the RFC writes it -
so they reject the message or take a different length from it. Two hops that
disagree about where one request ends is the whole of CL.CL request smuggling:
what elodin reads as the tail of a body, the front end reads as the start of
the next request, and attributes to whoever's connection it is pipelining onto.

Repeats are refused for the same reason (RFC 9112 6.3): keeping the last one
seen is a choice nothing says a proxy in front makes the same way.
*/
@(test)
test_content_length_is_strict_decimal :: proc(t: ^testing.T) {
	for c in CONTENT_LENGTH_CASES {
		ok := expect_content_length(t, c)
		free_all(context.temp_allocator)
		if !ok {
			return
		}
	}
}

// Read a POST carrying `c`'s fields and body over loopback and expect its
// verdict; false when the loopback pair would not come up.
@(private = "file")
expect_content_length :: proc(t: ^testing.T, c: Content_Length_Case) -> bool {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(&b, "Content-Type: application/dns-message\r\n")
	strings.write_string(&b, c.headers)
	strings.write_string(&b, "\r\n")
	strings.write_string(&b, c.body)

	req, status, parsed, ok := read_request_over_loopback(t, strings.to_string(b), c.what)
	if !ok {
		return false
	}
	if c.accepted {
		testing.expectf(t, parsed, "%s was rejected", c.what)
		if parsed {
			testing.expectf(
				t,
				string(req.body) == c.body,
				"%s: body came back as %q, expected %q",
				c.what,
				string(req.body),
				c.body,
			)
		}
	} else {
		testing.expectf(
			t,
			!parsed,
			"%s was accepted, with a %d byte body; a front end would frame this request differently",
			c.what,
			len(req.body),
		)
		// RFC 9112 5.1, 5.2 and 6.3: each is answered with a 400, and the
		// connection then closes.
		testing.expectf(t, status == 400, "%s: answered %d, want 400", c.what, status)
	}
return true
}

/*
A `Content-Length` that is well formed but over `MAX_DOH_BODY` is a 413 (RFC 9110
15.5.14), and one that is unreadable or repeated is a 400 (RFC 9112 6.3).

The 413 waits for the end of the header block, so that a `Transfer-Encoding`,
a second `Content-Length` or a field line that cannot be read after it is
answered for what it is: a 400.
*/
@(test)
test_content_length_over_the_limit_is_a_413 :: proc(t: ^testing.T) {
	Case :: struct {
		method:  string,
		host:    string,
		headers: string, // after Host and before the blank line
		status:  int,
		what:    string,
	}

	HOST :: "Host: dns.example\r\n"
	OVER :: "Content-Length: 100000\r\n"
	// On the stack: the loop below frees the temp allocator after every case.
	just_over_buf: [64]u8
	just_over := fmt.bprintf(just_over_buf[:], "Content-Length: %d\r\n", MAX_DOH_BODY + 1)

	CASES := []Case {
		{"POST", HOST, OVER, 413, "a length well past the limit"},
		{"POST", HOST, just_over, 413, "one byte past the limit"},
		// 2^64 + 4, which a wrapping parser reads as 4: still digits, still too large.
		{"POST", HOST, "Content-Length: 18446744073709551620\r\n", 413, "a length past 64 bits"},
		{"HEAD", HOST, OVER, 413, "a HEAD, which keeps its method for the reply"},
		{"POST", HOST, "Content-Length: 0x100000\r\n", 400, "an over-limit length that is not decimal"},
		{"POST", HOST, OVER + "Transfer-Encoding: chunked\r\n", 400, "chunked framing after it"},
		{"POST", HOST, OVER + "Content-Length: 4\r\n", 400, "a second Content-Length after it"},
		{"POST", HOST, OVER + "X-Fold: one\r\n two\r\n", 400, "a folded line after it"},
		{"POST", "", OVER, 400, "1.1 with no Host, which is malformed before it is large"},
		{"POST", HOST + HOST, OVER, 400, "a repeated Host, which is malformed before it is large"},
		// A malformed header block is a 400 whatever framing comes with it.
		{"POST", HOST + HOST, "Transfer-Encoding: chunked\r\n", 400, "a repeated Host, then chunked framing"},
		{"POST", "Host: a b\r\n", "Content-Length: 4\r\nContent-Length: 5\r\n", 400, "an invalid Host, then two lengths"},
		{"POST", HOST, "Content-Type: a/b\r\nContent-Type: c/d\r\nTransfer-Encoding: chunked\r\n", 400, "a repeated Content-Type, then chunked framing"},
	}

	for c in CASES {
		raw := fmt.tprintf("%s /dns-query HTTP/1.1\r\n%s%s\r\n", c.method, c.host, c.headers)
		req, status, parsed, ok := read_request_over_loopback(t, raw, c.what)
		if !ok {
			return
		}
		testing.expectf(t, !parsed, "%s was accepted", c.what)
		testing.expectf(t, status == c.status, "%s: answered %d, expected %d", c.what, status, c.status)
		if c.status == 413 {
			testing.expectf(t, req.method == c.method, "%s: method came back as %q", c.what, req.method)
		}
		free_all(context.temp_allocator)
	}
	testing.expect_value(t, http_refusal_message(413), "content too large")
}

/*
The 200 every HTTP answer here goes out as - a DoH answer, the profile and the
metrics page - in one order of fields, with the one field each adds between
Content-Length and Date, and to a HEAD the fields alone with GET's
Content-Length (RFC 9110 9.3.2, 8.6).
*/
@(test)
test_a_200_writes_its_fields_in_one_order :: proc(t: ^testing.T) {
	Case :: struct {
		content_type, field, value, body: string,
		keep_alive, head:                 bool,
		want:                             string,
	}
	cases := []Case {
		{
			content_type = DOH_CONTENT_TYPE,
			field = "Cache-Control",
			value = "max-age=300",
			body = "abc",
			keep_alive = true,
			head = false,
			want = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\nCache-Control: max-age=300\r\nDate: D\r\nServer: elodin/" + VERSION + "\r\nConnection: keep-alive\r\n\r\nabc",
		},
		{
			content_type = "text/plain",
			field = "Cache-Control",
			value = "no-store",
			body = "page",
			keep_alive = false,
			head = true,
			want = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nCache-Control: no-store\r\nDate: D\r\nServer: elodin/" + VERSION + "\r\nConnection: close\r\n\r\n",
		},
	}
	cfg: config.Config
	s := local_server(&cfg)
	for c in cases {
		client, accepted, paired := loopback_tcp_pair(t)
		if !paired {
			return
		}
		defer net.close(client)
		written := send_http_ok(&s, Conn{socket = accepted}, c.content_type, transmute([]u8)c.body, c.keep_alive, c.field, c.value, head = c.head)
		net.close(accepted)
		testing.expect(t, written, "the 200 was not written")

		got, rerr := read_until_close(client, 3 * time.Second)
		testing.expectf(t, rerr == nil, "head=%v: the read did not end at the close: %v", c.head, rerr)
		got = mask_date(got)
		testing.expectf(t, got == c.want, "head=%v:\n got %q\nwant %q", c.head, got, c.want)
	}
}

// `reply` with its Date field's value replaced by `D`: the date is the clock's,
// and `http_date` has a test of its own.
@(private = "file")
mask_date :: proc(reply: string) -> string {
	at := strings.index(reply, "\r\nDate: ")
	if at < 0 {
		return reply
	}
	end := strings.index(reply[at + 2:], "\r\n")
	if end < 0 {
		return reply
	}
	return strings.concatenate({reply[:at], "\r\nDate: D", reply[at + 2 + end:]}, context.temp_allocator)
}

/*
A refusal - from DoH or the metrics endpoint - in one order of fields, with a
Date (RFC 9110 6.6.1) on a GET and a HEAD alike, and to a HEAD the fields alone.
*/
@(test)
test_a_refusal_writes_its_fields_in_one_order :: proc(t: ^testing.T) {
	Case :: struct {
		status:           int,
		message, allow:   string,
		keep_alive, head: bool,
		want:             string,
	}
	cases := []Case {
		{status = 404, message = "not found", keep_alive = true, want = "HTTP/1.1 404 not found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nDate: D\r\nConnection: keep-alive\r\n\r\nnot found\n"},
		{status = 405, message = "method not allowed", allow = "GET, HEAD", head = true, want = "HTTP/1.1 405 method not allowed\r\nContent-Type: text/plain\r\nDate: D\r\nConnection: close\r\nAllow: GET, HEAD\r\n\r\n"},
	}
	for c in cases {
		client, accepted, paired := loopback_tcp_pair(t)
		if !paired {
			return
		}
		defer net.close(client)
		// What it returns is whether the connection stays open.
		kept := send_http_error(Conn{socket = accepted}, "doh", c.status, c.message, c.keep_alive, allow = c.allow, head = c.head)
		net.close(accepted)
		testing.expectf(t, kept == c.keep_alive, "status %d: kept %v, want %v", c.status, kept, c.keep_alive)
		got, err := read_until_close(client, 3 * time.Second)
		testing.expectf(t, err == nil, "the refusal was not read: %v", err)
		testing.expectf(t, mask_date(got) == c.want, "status %d:\n got %q\nwant %q", c.status, mask_date(got), c.want)
	}
	free_all(context.temp_allocator)
}

/*
A POST's Content-Type is judged by its media type, whole and without regard to
ASCII case (RFC 9110 8.3.1), by the check both HTTP versions share. A prefix
match would let `application/dns-message-bogus` in and a case-sensitive one
would turn `Application/DNS-Message` away (#304); a Unicode fold would take the
long s (U+017F) for an `s`.
*/
@(test)
test_doh_content_type_is_the_media_type_folded :: proc(t: ^testing.T) {
	Case :: struct {
		content_type: string,
		accepted:     bool,
	}
	CASES := []Case {
		{"", true},
		{"application/dns-message", true},
		{"Application/DNS-Message", true},
		{"APPLICATION/DNS-MESSAGE", true},
		{"application/dns-message; charset=utf-8", true},
		{"application/dns-message ;q=1", true},
		{"application/dns-message-bogus", false},
		{"application/dns-messageZZZZ", false},
		{"application/dns-message2", false},
		{"application/dns-mes\u017fage", false},
		{"application/dns", false},
		{"application/dns-messag", false},
		{"text/plain", false},
		{";application/dns-message", false},
	}
	body := make([]u8, dns.HEADER_SIZE, context.temp_allocator)
	for c in CASES {
		_, status, _, ok := doh_query_message("POST", c.content_type, body, "")
		testing.expectf(t, ok == c.accepted, "%q: accepted %v, want %v", c.content_type, ok, c.accepted)
		if !c.accepted {
			testing.expectf(t, status == 415, "%q: status %d, want 415", c.content_type, status)
		}
	}
}

// A repeated Content-Type is a 400 on HTTP/1.1: a reader keeping the last of the
// two could disagree with a hop in front that judged the first.
// An empty first one counts too: the counter is not the stored value.
@(test)
test_doh_repeated_content_type_is_refused :: proc(t: ^testing.T) {
	for first in ([]string{"text/plain", ""}) {
		raw := fmt.tprintf(
			"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nContent-Type: %s\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\nabcd",
			first,
		)
		_, status, parsed, ok := read_request_over_loopback(t, raw, "a repeated Content-Type")
		if !ok {
			return
		}
		testing.expectf(t, !parsed, "a repeated Content-Type after %q was accepted", first)
		testing.expect_value(t, status, 400)
		free_all(context.temp_allocator)
	}
}

/*
The HTTP/1.1 reader hands the predicate the Content-Type with only OWS off it.
`strings.trim_space` also takes a non-breaking space, a vertical tab or a form
feed off the end - none of them OWS - so trimmed with it, a type a front end
judged with one of those on it would become `application/dns-message` here,
while HTTP/2 keeps the character and refuses it.
*/
@(test)
test_doh_content_type_keeps_what_is_not_ows :: proc(t: ^testing.T) {
	Case :: struct {
		value:    string,
		accepted: bool,
	}
	CASES := []Case {
		{"application/dns-message", true},
		{"\tApplication/DNS-Message \t", true},
		{"application/dns-message\u00a0", false},
		{"\u00a0application/dns-message", false},
		{"application/dns-message\x0b", false},
		{"application/dns-message\x0c", false},
	}
	for c in CASES {
		raw := fmt.tprintf(
			"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nContent-Type: %s\r\nContent-Length: 4\r\n\r\nabcd",
			c.value,
		)
		req, _, parsed, ok := read_request_over_loopback(t, raw, c.value)
		if !ok {
			return
		}
		if testing.expectf(t, parsed, "%q: the request was not read", c.value) {
			got := doh_content_type_ok(req.content_type)
			testing.expectf(t, got == c.accepted, "%q: read as %q, accepted %v, want %v", c.value, req.content_type, got, c.accepted)
		}
		free_all(context.temp_allocator)
	}
}

/*
A field name is a token (RFC 9110 5.1), and names and the `close` option compare
without regard to ASCII case only (#432). `strings.equal_fold` folds Unicode, so
with it `Ho\u017ft` - the long s, U+017F - would count as Host and `clo\u017fe`
would close the connection, and a name outside the token grammar would be read
at all: a hop that folds the same way reads `Tran\u017ffer-Encoding` as chunked
framing while this one, folding ASCII only, does not. So such a line is refused,
and a value keeps whatever is not OWS.
*/
@(test)
test_doh_field_names_are_ascii_tokens :: proc(t: ^testing.T) {
	Case :: struct {
		headers:    string, // between the request line and Content-Length
		accepted:   bool,
		keep_alive: bool,
		host:       string,
		what:       string,
	}
	CASES := []Case {
		{headers = "Host: dns.example\r\n", accepted = true, keep_alive = true, host = "dns.example", what = "a plain Host"},
		{headers = "HOST: dns.example\r\n", accepted = true, keep_alive = true, host = "dns.example", what = "an uppercase Host"},
		{headers = "Ho\u017ft: dns.example\r\n", accepted = false, keep_alive = false, host = "", what = "a Host spelled with a long s"},
		{headers = "Host: dns.example\r\nHo\u017ft: evil.example\r\n", accepted = false, keep_alive = false, host = "", what = "a long-s Host after a real one"},
		{headers = "Host: dns.example\r\nTran\u017ffer-Encoding: chunked\r\n", accepted = false, keep_alive = false, host = "", what = "Transfer-Encoding with a long s"},
		{headers = "Host: dns.example\r\nX(y): 1\r\n", accepted = false, keep_alive = false, host = "", what = "a name with a delimiter"},
		{headers = "Host: dns.example\r\nX-Caf\u00e9: 1\r\n", accepted = false, keep_alive = false, host = "", what = "a name with a non-ASCII letter"},
		{headers = "Host: dns.example\r\nConnection: close\r\n", accepted = true, keep_alive = false, host = "dns.example", what = "Connection: close"},
		{headers = "Host: dns.example\r\nConnection: CLOSE\r\n", accepted = true, keep_alive = false, host = "dns.example", what = "Connection: CLOSE"},
		{headers = "Host: dns.example\r\nConnection: clo\u017fe\r\n", accepted = true, keep_alive = true, host = "dns.example", what = "close spelled with a long s"},
		{headers = "Host: dns.example\r\nConnection: close\u00a0\r\n", accepted = true, keep_alive = true, host = "dns.example", what = "close with a non-breaking space"},
		{headers = "Host: dns.example\r\nConnection:\tclose \r\n", accepted = true, keep_alive = false, host = "dns.example", what = "close with OWS around it"},
	}
	for c in CASES {
		raw := fmt.tprintf(
			"POST /dns-query HTTP/1.1\r\n%sContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\nabcd",
			c.headers,
		)
		req, _, parsed, ok := read_request_over_loopback(t, raw, c.what)
		if !ok {
			return
		}
		testing.expectf(t, parsed == c.accepted, "%s: read %v, want %v", c.what, parsed, c.accepted)
		if parsed && c.accepted {
			testing.expectf(t, req.keep_alive == c.keep_alive, "%s: keep-alive %v, want %v", c.what, req.keep_alive, c.keep_alive)
			testing.expectf(t, req.host == c.host, "%s: host %q, want %q", c.what, req.host, c.host)
		}
		free_all(context.temp_allocator)
	}
}

/*
A line ends at CRLF and nowhere else, and holds no bare LF, bare CR or NUL. RFC
9112 2.2 lets a recipient take a bare LF for a line end, so a hop in front may
read `X: a\nTransfer-Encoding: chunked` as two fields where this one read one -
framing by chunks where elodin framed by Content-Length. A value holding one of
these was already malformed over HTTP/2 (`field_value_is_valid`).
*/
@(test)
test_doh_lines_hold_no_bare_line_ends :: proc(t: ^testing.T) {
	Case :: struct {
		raw:  string,
		what: string,
	}
	BODY :: "Content-Type: application/dns-message\r\nContent-Length: 4\r\n\r\nabcd"
	CASES := []Case {
		{"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX: a\nTransfer-Encoding: chunked\r\n" + BODY, "a bare LF in a value"},
		{"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX: a\rTransfer-Encoding: chunked\r\n" + BODY, "a bare CR in a value"},
		{"POST /dns-query HTTP/1.1\r\nHost: dns.example\r\nX: a\x00b\r\n" + BODY, "a NUL in a value"},
		{"POST /dns-query\nTransfer-Encoding:chunked HTTP/1.1\r\nHost: dns.example\r\n" + BODY, "a bare LF in the request line"},
		{"POST /dns-query HTTP/1.1\r\nHost: dns.example\n\r\n" + BODY, "a bare LF before CRLF"},
	}
	for c in CASES {
		_, _, parsed, ok := read_request_over_loopback(t, c.raw, c.what)
		if !ok {
			return
		}
		testing.expectf(t, !parsed, "%s was read as a request", c.what)
		free_all(context.temp_allocator)
	}
	// And the ordinary request still is.
	_, _, parsed, ok := read_request_over_loopback(t, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n" + BODY, "a plain request")
	if ok {
		testing.expect(t, parsed, "a plain request was refused")
	}
}

/*
`Connection` is a list of options (RFC 9110 7.6.1), and a client that puts
`close` anywhere in it wants no second request on this connection. Read as one
token, `close, TE` would be kept open until `client_timeout`, holding one of
`max_connections` for nothing (#437). An option that merely contains the letters
is not `close`.
*/
@(test)
test_doh_request_connection_is_a_list :: proc(t: ^testing.T) {
	Case :: struct {
		connection: string,
		keep_alive: bool,
	}
	CASES := []Case {
		{"Connection: close\r\n", false},
		{"Connection: close, TE\r\n", false},
		{"Connection: TE,close\r\n", false},
		{"Connection: keep-alive ,\tCLOSE\r\n", false},
		{"Connection: TE\r\nConnection: close\r\n", false},
		{"Connection: closed\r\n", true},
		{"Connection: xclose, TE\r\n", true},
		{"Connection: ,\r\n", true},
	}
	for c in CASES {
		raw := fmt.tprintf("GET /dns-query HTTP/1.1\r\nHost: dns.example\r\n%s\r\n", c.connection)
		req, status, parsed, ok := read_request_over_loopback(t, raw, c.connection)
		if !ok {
			return
		}
		testing.expectf(t, parsed, "%q was refused with a %d", c.connection, status)
		testing.expectf(t, req.keep_alive == c.keep_alive, "%q: keep_alive %v, want %v", c.connection, req.keep_alive, c.keep_alive)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
CHUNKED :: "Transfer-Encoding: chunked\r\n"

@(private = "file")
Chunked_Case :: struct {
	what:    string,
	version: string,
	headers: string, // after Host and before the blank line
	body:    string,
	status:  int, // 0 for a request read
	want:    string,
}

// `test_a_chunked_request_body_is_read`'s cases, but for the one whose size is
// worked out from `MAX_DOH_BODY`.
@(private = "file")
CHUNKED_CASES :: [?]Chunked_Case {
	{"one chunk", "HTTP/1.1", CHUNKED, "4\r\nabcd\r\n0\r\n\r\n", 0, "abcd"},
	{"two chunks, an extension and a trailer", "HTTP/1.1", CHUNKED, "2;x=y\r\nab\r\n2 ;z\r\ncd\r\n0\r\nX-T: v\r\n\r\n", 0, "abcd"},
	{"an upper-case size", "HTTP/1.1", CHUNKED, "A\r\n0123456789\r\n0\r\n\r\n", 0, "0123456789"},
	{"the coding name in another case, split over two lines", "HTTP/1.1", "Transfer-Encoding: \r\nTransfer-Encoding: CHUNKED\r\n", "1\r\nz\r\n0\r\n\r\n", 0, "z"},
	{"an empty body", "HTTP/1.1", CHUNKED, "0\r\n\r\n", 0, ""},
	{"a final coding other than chunked", "HTTP/1.1", "Transfer-Encoding: chunked, gzip\r\n", "", 400, ""},
	{"gzip alone", "HTTP/1.1", "Transfer-Encoding: gzip\r\n", "", 400, ""},
	{"chunked twice", "HTTP/1.1", "Transfer-Encoding: chunked, chunked\r\n", "", 400, ""},
	{"chunked with a parameter", "HTTP/1.1", "Transfer-Encoding: chunked;q=1\r\n", "", 400, ""},
	{"a coding that is not a token", "HTTP/1.1", "Transfer-Encoding: chun ked\r\n", "", 400, ""},
	{"a coding that is not a token, before chunked", "HTTP/1.1", "Transfer-Encoding: g zip, chunked\r\n", "", 400, ""},
	{"a coding this server does not decode before chunked", "HTTP/1.1", "Transfer-Encoding: gzip, chunked\r\n", "", 501, ""},
	{"the same over two field lines", "HTTP/1.1", "Transfer-Encoding: gzip\r\n" + CHUNKED, "", 501, ""},
	{"a Content-Length beside it", "HTTP/1.1", CHUNKED + "Content-Length: 4\r\n", "", 400, ""},
	{"HTTP/1.0", "HTTP/1.0", CHUNKED, "4\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"a size that is not hex", "HTTP/1.1", CHUNKED, "g\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"a size with no digits", "HTTP/1.1", CHUNKED, ";x\r\n\r\n0\r\n\r\n", 400, ""},
	{"junk after the size", "HTTP/1.1", CHUNKED, "4 x\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"no CRLF after the data", "HTTP/1.1", CHUNKED, "4\r\nabcdX\r\n0\r\n\r\n", 400, ""},
	// Two bytes that are not CRLF, with a last chunk right after them.
	{"other bytes where the CRLF goes", "HTTP/1.1", CHUNKED, "4\r\nabcdXY0\r\n\r\n", 400, ""},
	{"a trailer that is not a field line", "HTTP/1.1", CHUNKED, "4\r\nabcd\r\n0\r\nno colon\r\n\r\n", 400, ""},
	{"a size with more digits than any limit", "HTTP/1.1", CHUNKED, "10000000000000000000004\r\n", 413, ""},
	// RFC 9112 7.1.1's extension grammar.
	{"an extension with a quoted value", "HTTP/1.1", CHUNKED, "4 ; a = \"q\\\"x\" ; b\r\nabcd\r\n0\r\n\r\n", 0, "abcd"},
	{"whitespace after the size and no extension", "HTTP/1.1", CHUNKED, "4 \r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"an extension name that is not a token", "HTTP/1.1", CHUNKED, "4;\x7f\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"an extension with an empty value", "HTTP/1.1", CHUNKED, "4;a=\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"an unterminated quoted value", "HTTP/1.1", CHUNKED, "4;a=\"q\r\nabcd\r\n0\r\n\r\n", 400, ""},
	{"whitespace after an extension", "HTTP/1.1", CHUNKED, "4;a \r\nabcd\r\n0\r\n\r\n", 400, ""},
	// A Transfer-Encoding with no coding in it is framing all the same.
	{"an empty Transfer-Encoding beside a Content-Length", "HTTP/1.1", "Transfer-Encoding: \r\nContent-Length: 4\r\n", "abcd", 400, ""},
	// RFC 9112 7: a transfer-parameter is token "=" token / quoted-string.
	{"a malformed parameter on a coding ahead of chunked", "HTTP/1.1", "Transfer-Encoding: gzip;;=, chunked\r\n", "", 400, ""},
	{"a parameter with no value", "HTTP/1.1", "Transfer-Encoding: gzip;level, chunked\r\n", "", 400, ""},
	{"well-formed parameters ahead of chunked", "HTTP/1.1", "Transfer-Encoding: gzip; level = 9 ;q=\"x y\", chunked\r\n", "", 501, ""},
	// A comma inside a quoted parameter value does not end the coding.
	{"a quoted parameter holding a comma", "HTTP/1.1", "Transfer-Encoding: gzip;x=\"a,b\", chunked\r\n", "", 501, ""},
	{"an unterminated quoted parameter", "HTTP/1.1", "Transfer-Encoding: gzip;x=\"a, chunked\r\n", "", 400, ""},
	{"a Transfer-Encoding of commas", "HTTP/1.1", "Transfer-Encoding: , ,\r\n", "", 400, ""},
}

/*
RFC 9112 6.1: "A recipient MUST be able to parse the chunked transfer coding".
A chunked body is read and de-chunked, whatever its chunk sizes, extensions and
trailers, and the connection closes after it is answered; a body whose framing
is in doubt is a 400, one past `MAX_DOH_BODY` a 413, and a coding this server
does not understand a 501.
*/
@(test)
test_a_chunked_request_body_is_read :: proc(t: ^testing.T) {
	for c in CHUNKED_CASES {
		ok := expect_chunked(t, c)
		free_all(context.temp_allocator)
		if !ok {
			return
		}
	}
	// On the stack: the case frees the temp allocator behind it.
	over_buf: [32]u8
	over := fmt.bprintf(over_buf[:], "%x\r\n", MAX_DOH_BODY + 1)
	if !expect_chunked(t, {"a chunk past the limit", "HTTP/1.1", CHUNKED, over, 413, ""}) {
		return
	}
	free_all(context.temp_allocator)
	expect_chunked_framing_bounded(t)
	free_all(context.temp_allocator)
}

// Read a POST in `c`'s version carrying its fields and chunked body over
// loopback and expect its verdict; false when the loopback pair would not come up.
@(private = "file")
expect_chunked :: proc(t: ^testing.T, c: Chunked_Case) -> bool {
	raw := fmt.tprintf("POST /dns-query %s\r\nHost: dns.example\r\n%s\r\n%s", c.version, c.headers, c.body)
	req, status, parsed, ok := read_request_over_loopback(t, raw, c.what)
	if !ok {
		return false
	}
	if c.status == 0 {
		if testing.expectf(t, parsed, "%s was refused with %d", c.what, status) {
			testing.expectf(t, string(req.body) == c.want, "%s: body %q, want %q", c.what, string(req.body), c.want)
			testing.expectf(t, !req.keep_alive, "%s: the connection is kept open after a chunked body", c.what)
		}
	} else {
		testing.expectf(t, !parsed, "%s was accepted", c.what)
		testing.expectf(t, status == c.status, "%s: answered %d, want %d", c.what, status, c.status)
	}
return true
}

// The bounds a chunked body is held to across its chunks: the content's
// together, and the framing's together with its trailers.
@(private = "file")
expect_chunked_framing_bounded :: proc(t: ^testing.T) {
	// Two chunks under the limit each that are over it together.
	half := MAX_DOH_BODY / 2 + 1
	b := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n%s\r\n%x\r\n", CHUNKED, half)
	for _ in 0 ..< half {
		strings.write_byte(&b, 'a')
	}
	fmt.sbprintf(&b, "\r\n%x\r\n", half)
	_, status, parsed, ok := read_request_over_loopback(t, strings.to_string(b), "two chunks over the limit together")
	if ok {
		testing.expect(t, !parsed, "two chunks over the limit together were accepted")
		testing.expect_value(t, status, 413)
	}
	testing.expect_value(t, http_refusal_message(501), "not implemented")

	/*
	The chunk lines stay in the buffer until it is compacted, so they are
	bounded together as well as one by one: one-byte chunks with long
	extensions, each line well inside `MAX_HEADER_BYTES`, are refused once
	their framing is past it, with the content far inside its own limit.
	*/
	long := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&long, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n%s\r\n", CHUNKED)
	ext := strings.repeat("a", 1000, context.temp_allocator)
	for _ in 0 ..< MAX_HEADER_BYTES / 1000 + 2 {
		fmt.sbprintf(&long, "1;%s\r\nx\r\n", ext)
	}
	strings.write_string(&long, "0\r\n\r\n")
	_, lstatus, lparsed, lok := read_request_over_loopback(t, strings.to_string(long), "framing past the limit")
	if lok {
		testing.expect(t, !lparsed, "a body whose framing is past the limit was accepted")
		testing.expect_value(t, lstatus, 400)
	}
	// One line past it is a 400 as well, answered rather than closed on, and
	// the trailers count with the chunk lines rather than starting afresh.
	half_ext := strings.repeat("a", MAX_HEADER_BYTES / 2 + 100, context.temp_allocator)
	whole_ext := strings.repeat("a", MAX_HEADER_BYTES + 10, context.temp_allocator)
	for c in ([][2]string {
			{"one chunk line past the limit", fmt.tprintf("1;%s\r\nx\r\n0\r\n\r\n", whole_ext)},
			{"chunk lines and trailers past it together", fmt.tprintf("1;%s\r\nx\r\n0\r\nX-T: %s\r\n\r\n", half_ext, half_ext)},
		}) {
		raw := fmt.tprintf("POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n%s\r\n%s", CHUNKED, c[1])
		_, ostatus, oparsed, ook := read_request_over_loopback(t, raw, c[0])
		if ook {
			testing.expectf(t, !oparsed, "%s was accepted", c[0])
			testing.expectf(t, ostatus == 400, "%s: answered %d, want 400", c[0], ostatus)
		}
	}
}

/*
The close after a chunked request's answer is this server's choice, so what the
client pipelined behind it is drained before the close: closing on unread bytes
sends an RST, and the client's kernel drops the answer it had not read yet.
The request behind it is longer than one read, so bytes are left for the close.
*/
@(test)
test_the_close_after_a_chunked_request_keeps_its_answer :: proc(t: ^testing.T) {
	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "POST /not-served HTTP/1.1\r\nHost: dns.example\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n")
	strings.write_string(&b, "GET /not-served HTTP/1.1\r\nHost: dns.example\r\nX-Pad: ")
	for _ in 0 ..< 2 * HTTP_BUF_SIZE {
		strings.write_byte(&b, 'p')
	}
	strings.write_string(&b, "\r\n\r\n")
	if _, serr := net.send_tcp(client, b.buf[:]); !testing.expectf(t, serr == nil, "cannot send the requests: %v", serr) {
		net.close(accepted)
		return
	}
	// The drain ends on the end of the data rather than on its timeout.
	testing.expect(t, net.shutdown(client, .Send) == nil, "cannot end the stream")
	if !set_wait(t, client, .Receive_Timeout, 3 * time.Second) {
		net.close(accepted)
		return
	}

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	serve_doh(&s, Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}}, "test")
	// The listener's close, which is what an RST would come from.
	net.close(accepted)

	reply := make([dynamic]u8, 0, 4096, context.temp_allocator)
	for len(reply) < 4096 {
		chunk: [512]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if !testing.expectf(t, rerr == nil, "the answer did not survive the close: %v", rerr) {
			return
		}
		if n == 0 {
			break
		}
		append(&reply, ..chunk[:n])
	}
	testing.expectf(t, strings.count(string(reply[:]), "HTTP/1.1 ") == 1 && strings.has_prefix(string(reply[:]), "HTTP/1.1 404 "), "the client read %q, want one 404", string(reply[:min(len(reply), 60)]))
	free_all(context.temp_allocator)
}

/*
RFC 9112 3.2.2: a server "MUST accept the absolute-form", and takes the host
from the target rather than from `Host` (3.2), which a 1.1 request still has to
carry. An authority with userinfo, or none, is a 400.
*/
@(test)
test_an_absolute_form_target_is_accepted :: proc(t: ^testing.T) {
	Case :: struct {
		what:   string,
		target: string,
		host:   string,
		status: int,
		path:   string,
		query:  string,
		want:   string, // the host kept
	}
	CASES := []Case {
		{"https", "https://dns.example/dns-query?dns=AAAB", "Host: other.example\r\n", 0, "/dns-query", "dns=AAAB", "dns.example"},
		{"http, the scheme in another case", "HTTP://dns.example:8443/dns-query", "Host: dns.example:8443\r\n", 0, "/dns-query", "", "dns.example:8443"},
		{"no path", "https://dns.example", "Host: dns.example\r\n", 0, "/", "", "dns.example"},
		{"a query and no path", "https://dns.example?dns=AAAB", "Host: dns.example\r\n", 0, "/", "dns=AAAB", "dns.example"},
		{"origin-form", "/dns-query?dns=AAAB", "Host: dns.example\r\n", 0, "/dns-query", "dns=AAAB", "dns.example"},
		{"userinfo", "https://user@dns.example/dns-query", "Host: dns.example\r\n", 400, "", "", ""},
		{"no authority", "https:///dns-query", "Host: dns.example\r\n", 400, "", "", ""},
		{"no Host field", "https://dns.example/dns-query", "", 400, "", "", ""},
	}
	for c in CASES {
		raw := fmt.tprintf("GET %s HTTP/1.1\r\n%s\r\n", c.target, c.host)
		req, status, parsed, ok := read_request_over_loopback(t, raw, c.what)
		if !ok {
			return
		}
		if c.status == 0 {
			if testing.expectf(t, parsed, "%s was refused with %d", c.what, status) {
				testing.expectf(t, req.path == c.path, "%s: path %q, want %q", c.what, req.path, c.path)
				testing.expectf(t, req.query == c.query, "%s: query %q, want %q", c.what, req.query, c.query)
				testing.expectf(t, req.host == c.want, "%s: host %q, want %q", c.what, req.host, c.want)
			}
		} else {
			testing.expectf(t, !parsed, "%s was accepted", c.what)
			testing.expectf(t, status == c.status, "%s: answered %d, want %d", c.what, status, c.status)
		}
		free_all(context.temp_allocator)
	}
}

// A line that ends in a bare LF or holds a bare CR is answered with a 400, not
// closed on (RFC 9112 2.2).
@(test)
test_a_line_with_a_bare_cr_or_lf_is_a_400 :: proc(t: ^testing.T) {
	CASES := [][2]string {
		{"a bare LF after the request line", "GET /dns-query HTTP/1.1\nHost: dns.example\r\n\r\n"},
		{"a bare CR in a field line", "GET /dns-query HTTP/1.1\r\nHost: dns.example\r\nX-A: b\rc\r\n\r\n"},
		{"a NUL in a field line", "GET /dns-query HTTP/1.1\r\nHost: dns.example\r\nX-A: b\x00c\r\n\r\n"},
	}
	for c in CASES {
		_, status, parsed, ok := read_request_over_loopback(t, c[1], c[0])
		if !ok {
			return
		}
		testing.expectf(t, !parsed, "%s was accepted", c[0])
		testing.expectf(t, status == 400, "%s: answered %d, want 400", c[0], status)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
Continue_Reader :: struct {
	r:      Http_Reader,
	req:    Http_Request_In,
	status: int,
	parsed: bool,
}

@(private = "file")
Continue_Case :: struct {
	what:     string,
	version:  string,
	early:    bool, // the body sent with the header block
	chunked:  bool,
	continue_: bool,
}

// `test_expect_100_continue_is_answered_before_the_body`'s HTTP/1.1 cases.
@(private = "file")
CONTINUE_CASES :: [?]Continue_Case {
	{what = "a Content-Length body", version = "HTTP/1.1", early = false, chunked = false, continue_ = true},
	{what = "a chunked body", version = "HTTP/1.1", early = false, chunked = true, continue_ = true},
	{what = "a body already sent", version = "HTTP/1.1", early = true, chunked = false, continue_ = false},
}

/*
RFC 9110 10.1.1: a server "MUST NOT wait for the content before sending the 100
(Continue) response". The header block alone gets a 100 back; the body sent
after it is then read. HTTP/1.0 is not answered one, and neither is a request
whose body is already here.
*/
@(test)
test_expect_100_continue_is_answered_before_the_body :: proc(t: ^testing.T) {
	for c in CONTINUE_CASES {
		ok := expect_continue(t, c)
		free_all(context.temp_allocator)
		if !ok {
			return
		}
	}
	expect_no_continue_on_1_0(t)
}

// Send `c`'s header block with `Expect: 100-continue`, the body after it unless
// it is early, and expect the 100 only where `c` says; false when the
// connection or the reader would not start.
@(private = "file")
expect_continue :: proc(t: ^testing.T, c: Continue_Case) -> bool {
	client, accepted, paired := loopback_tcp_pair(t)
	if !testing.expectf(t, paired, "%s: no loopback connection", c.what) {
		return false
	}
	body := "4\r\nabcd\r\n0\r\n\r\n" if c.chunked else "abcd"
	framing := "Transfer-Encoding: chunked\r\n" if c.chunked else "Content-Length: 4\r\n"
	head := fmt.tprintf("POST /dns-query %s\r\nHost: dns.example\r\n%sExpect: 100-continue\r\n\r\n%s", c.version, framing, body if c.early else "")
	_, serr := net.send_tcp(client, transmute([]u8)head)
	sent := testing.expectf(t, serr == nil, "%s: cannot send the header block: %v", c.what, serr)
	if !sent || !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) || !set_wait(t, client, .Receive_Timeout, 3 * time.Second) {
		net.close(client)
		net.close(accepted)
		return false
	}

	cr := Continue_Reader {
		r = Http_Reader {
			conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
			buf = make([dynamic]u8, 0, HTTP_BUF_SIZE),
		},
	}
	reader := thread.create_and_start_with_poly_data(&cr, proc(cr: ^Continue_Reader) {
		cr.req, cr.status, cr.parsed = read_http_request(&cr.r)
	})
	if !testing.expectf(t, reader != nil, "%s: cannot start the reader", c.what) {
		delete(cr.r.buf)
		net.close(client)
		net.close(accepted)
		return false
	}
	if c.continue_ {
		// The 100, read before the body goes: what the reader wrote with
		// nothing to wait for.
		got: [len(HTTP_CONTINUE)]u8
		n, rerr := net.recv_tcp(client, got[:])
		testing.expectf(t, rerr == nil && string(got[:n]) == HTTP_CONTINUE, "%s: got %q (%v), want the 100", c.what, string(got[:n]), rerr)
	}
	if !c.early {
		_, berr := net.send_tcp(client, transmute([]u8)body)
		testing.expectf(t, berr == nil, "%s: cannot send the body: %v", c.what, berr)
	}
	thread.join(reader)
	thread.destroy(reader)
	if testing.expectf(t, cr.parsed, "%s was refused with %d", c.what, cr.status) {
		testing.expectf(t, string(cr.req.body) == "abcd", "%s: body %q", c.what, string(cr.req.body))
	}
	if !c.continue_ {
		// Nothing was written: the reader is done, so a 100 it sent would
		// be waiting to be read.
		expect_nothing_written(t, client, accepted, c.what)
	} else {
		net.close(accepted)
	}
	net.close(client)
	delete(cr.r.buf)
return true
}

// The HTTP/1.0 half of `test_expect_100_continue_is_answered_before_the_body`.
@(private = "file")
expect_no_continue_on_1_0 :: proc(t: ^testing.T) {
	/*
	HTTP/1.0 gets no 100 (10.1.1: "MUST ignore" the expectation there). The
	header block alone is sent and the sending side shut, so the reader reaches
	the body and ends there on the end of the stream: a 100 it wrote on the
	way would be waiting to be read.
	*/
	client, accepted, paired := loopback_tcp_pair(t)
	if !testing.expect(t, paired, "HTTP/1.0: no loopback connection") {
		return
	}
	defer net.close(client)
	head := "POST /dns-query HTTP/1.0\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n"
	_, serr := net.send_tcp(client, transmute([]u8)head)
	testing.expectf(t, serr == nil, "HTTP/1.0: cannot send the header block: %v", serr)
	testing.expect(t, net.shutdown(client, .Send) == nil, "HTTP/1.0: cannot end the stream")
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) || !set_wait(t, client, .Receive_Timeout, 3 * time.Second) {
		net.close(accepted)
		return
	}
	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf = make([dynamic]u8, 0, HTTP_BUF_SIZE),
	}
	defer delete(r.buf)
	_, status, parsed := read_http_request(&r)
	// The premise: it read the header block and then waited for the body.
	testing.expect(t, !parsed && status == 0, "HTTP/1.0: the reader did not end at the body")
	expect_nothing_written(t, client, accepted, "HTTP/1.0")
	free_all(context.temp_allocator)
}

// Close `accepted` and expect `client` to read the end of the stream and
// nothing before it.
@(private = "file")
expect_nothing_written :: proc(t: ^testing.T, client, accepted: net.TCP_Socket, what: string) {
	net.close(accepted)
	stray: [64]u8
	// The end of the stream, not an error: anything else is no evidence
	// either way.
	n, rerr := net.recv_tcp(client, stray[:])
	testing.expectf(t, rerr == nil && n == 0, "%s: %q was written (%v), want nothing", what, string(stray[:n]), rerr)
}

/*
An absolute-form target's authority is kept as a copy taken when the request
line is read: a view into it would point into the buffer the header lines read
after it may move. Enough header lines to grow the buffer, read through an
allocator that poisons what it frees, so a stale view reads as garbage.
*/
@(test)
test_an_absolute_form_host_survives_the_buffer_growing :: proc(t: ^testing.T) {
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	strings.write_string(&b, "GET https://dns.example/dns-query?dns=AAAB HTTP/1.1\r\nHost: dns.example\r\n")
	for i in 0 ..< 3 * HTTP_BUF_SIZE / 100 {
		fmt.sbprintf(&b, "X-Pad-%d: %s\r\n", i, strings.repeat("p", 90, context.temp_allocator))
	}
	strings.write_string(&b, "\r\n")

	client, accepted, paired := loopback_tcp_pair(t)
	if !paired {
		return
	}
	defer net.close(client)
	defer net.close(accepted)
	_, serr := net.send_tcp(client, b.buf[:])
	if !testing.expectf(t, serr == nil, "cannot send the request: %v", serr) {
		return
	}
	testing.expect(t, net.shutdown(client, .Send) == nil, "cannot end the stream")
	if !set_wait(t, accepted, .Receive_Timeout, 3 * time.Second) {
		return
	}

	arena: virtual.Arena
	if aerr := virtual.arena_init_growing(&arena); !testing.expectf(t, aerr == nil, "cannot create an arena: %v", aerr) {
		return
	}
	defer virtual.arena_destroy(&arena)
	poison := Poisoning_Allocator {
		backing = virtual.arena_allocator(&arena),
	}
	saved := context.temp_allocator
	context.temp_allocator = poisoning_allocator(&poison)
	defer context.temp_allocator = saved

	r := Http_Reader {
		conn = Conn{socket = accepted, peer = net.Endpoint{address = net.IP4_Loopback, port = 1}},
		buf  = make([dynamic]u8, 0, HTTP_BUF_SIZE, context.temp_allocator),
	}
	req, status, parsed := read_http_request(&r)
	// The premise: the buffer did grow past its first block.
	testing.expectf(t, cap(r.buf) > HTTP_BUF_SIZE, "the buffer never grew (cap %d)", cap(r.buf))
	if testing.expectf(t, parsed, "refused with %d", status) {
		testing.expect_value(t, req.host, "dns.example")
		testing.expect_value(t, req.path, "/dns-query")
	}
}
