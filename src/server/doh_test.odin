package server

import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"

/*
The DoH reader hands back views into a buffer it goes on appending to.

`http_line` returns a slice of `Http_Reader.buf`, and `read_http_request` keeps
several of those - the method, the path, the query string, the content type -
while it reads the headers and then the body. Every one of those reads can grow
the buffer past its capacity, and a grown buffer is a different block.

That the fields still read correctly today is a property of the arena behind
`context.temp_allocator`, which copies the old contents forward and does not
reclaim the block until `free_all`. Nothing in the reader depends on that, or
says so, and any other allocator invalidates the lot.
*/

// Delegates everything, and scribbles over a block before letting go of it.
// A correct reader never notices; one holding a view into a released block
// reads 0xDD.
@(private = "file")
Poisoning_Allocator :: struct {
	backing: mem.Allocator,
}

@(private = "file")
poisoning_proc :: proc(
	allocator_data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	p := cast(^Poisoning_Allocator)allocator_data
	b := p.backing

	#partial switch mode {
	case .Resize, .Resize_Non_Zeroed:
		// Done by hand rather than passed through, so the old block can be
		// scribbled on after its contents have been carried over.
		fresh, err := b.procedure(b.data, .Alloc, size, alignment, nil, 0, location)
		if err != nil {
			return nil, err
		}
		if old_memory != nil && old_size > 0 {
			copy(fresh, (cast([^]u8)old_memory)[:min(old_size, size)])
			mem.set(old_memory, 0xDD, old_size)
			_, _ = b.procedure(b.data, .Free, 0, 0, old_memory, old_size, location)
		}
		return fresh, nil

	case .Free:
		if old_memory != nil && old_size > 0 {
			mem.set(old_memory, 0xDD, old_size)
		}
	}
	return b.procedure(b.data, mode, size, alignment, old_memory, old_size, location)
}

@(private = "file")
poisoning_allocator :: proc(p: ^Poisoning_Allocator) -> mem.Allocator {
	return mem.Allocator{procedure = poisoning_proc, data = p}
}

@(private = "file")
Sender :: struct {
	endpoint: net.Endpoint,
	request:  string,
}

@(private = "file")
send_request :: proc(s: ^Sender) {
	socket, err := net.dial_tcp_from_endpoint(s.endpoint)
	if err != nil {
		return
	}
	defer net.close(socket)
	sent := 0
	raw := transmute([]u8)s.request
	for sent < len(raw) {
		n, serr := net.send_tcp(socket, raw[sent:])
		if serr != nil || n <= 0 {
			return
		}
		sent += n
	}
	// Held open until the reader has had its turn; closing here would race the
	// body read.
	time.sleep(250 * time.Millisecond)
}

/*
A request whose headers outgrow the reader's buffer must still parse.

The buffer starts at 4096 bytes, and MAX_HEADER_BYTES allows four times that,
so a request with a few kilobytes of headers - which any client is free to send
- grows it after the request line has already been sliced up.
*/
@(test)
test_doh_request_survives_a_buffer_that_grows :: proc(t: ^testing.T) {
	// Not from the temp allocator: it is about to be replaced, and this is
	// scaffolding rather than anything under test.
	b := strings.builder_make(context.allocator)
	defer strings.builder_destroy(&b)
	strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
	strings.write_string(&b, "Content-Type: application/dns-message\r\n")
	// Enough padding to take the buffer past its initial capacity, well inside
	// what MAX_HEADER_BYTES permits.
	for i in 0 ..< 60 {
		strings.write_string(&b, "X-Padding-")
		strings.write_int(&b, i)
		strings.write_string(&b, ": ")
		for _ in 0 ..< 100 {
			strings.write_byte(&b, 'p')
		}
		strings.write_string(&b, "\r\n")
	}
	strings.write_string(&b, "Content-Length: 4\r\n\r\nabcd")
	request := strings.to_string(b)

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	sender := Sender {
		endpoint = bound,
		request  = request,
	}
	client := thread.create_and_start_with_poly_data(&sender, send_request)
	defer {
		thread.join(client)
		thread.destroy(client)
	}

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	// Backed by an arena of its own, so the copies the reader is about to make
	// go away with it rather than showing up as leaks in the memory report.
	arena: virtual.Arena
	if aerr2 := virtual.arena_init_growing(&arena); aerr2 != nil {
		testing.expectf(t, false, "cannot create an arena: %v", aerr2)
		return
	}
	defer virtual.arena_destroy(&arena)
	poison := Poisoning_Allocator {
		backing = virtual.arena_allocator(&arena),
	}
	// The reader's buffer comes from `context.temp_allocator`; swapped for one
	// that will not quietly keep a released block readable.
	saved := context.temp_allocator
	context.temp_allocator = poisoning_allocator(&poison)
	defer context.temp_allocator = saved

	r := Http_Reader {
		conn = Conn{socket = accepted},
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	defer delete(r.buf)

	req, ok := read_http_request(&r)
	testing.expect(t, ok, "the request did not parse")
	if !ok {
		return
	}
	testing.expect_value(t, req.method, "POST")
	testing.expect_value(t, req.path, "/dns-query")
	testing.expect_value(t, req.content_type, "application/dns-message")
	testing.expect_value(t, string(req.body), "abcd")
}

/*
Hand `raw` to `read_http_request` over a loopback socket.

The sender closes as soon as its bytes are away. A reader that asks for more
than what was sent therefore reaches the end of the connection instead of
blocking, which is what a body shorter than its declared length has to look
like here.
*/
@(private = "file")
read_request_over_loopback :: proc(t: ^testing.T, raw: string, what: string) -> (req: Http_Request_In, parsed, ok: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "%s: cannot listen on loopback: %v", what, lerr)
		return {}, false, false
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "%s: cannot read the bound port: %v", what, berr)
		return {}, false, false
	}

	// A few hundred bytes, so the whole request fits in the socket buffer and
	// this side never has to interleave sending with the reading below.
	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "%s: cannot dial the listener: %v", what, derr)
		return {}, false, false
	}
	sent := 0
	bytes := transmute([]u8)raw
	for sent < len(bytes) {
		n, serr := net.send_tcp(client, bytes[sent:])
		if serr != nil || n <= 0 {
			net.close(client)
			testing.expectf(t, false, "%s: cannot send the request: %v", what, serr)
			return {}, false, false
		}
		sent += n
	}
	net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "%s: nothing connected: %v", what, aerr)
		return {}, false, false
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 3 * time.Second)

	r := Http_Reader {
		conn = Conn{socket = accepted},
		buf  = make([dynamic]u8, 0, 4096, context.temp_allocator),
	}
	req, parsed = read_http_request(&r)
	return req, parsed, true
}

/*
`Content-Length` is `1*DIGIT` (RFC 9110 8.6) and nothing else.

Read with `strconv.parse_int` and its default base, it is a good deal more than
that: the base is taken from a prefix, so `0x10` is 16 and `0b1010` is 10; `_`
between digits is skipped, so `1_0` is 10; a leading sign is allowed; and the
accumulator wraps without reporting it, so `18446744073709551620` is 4 and the
range check that follows sees nothing wrong with it.

Every one of those is a length elodin would act on and a front end would not.
Sharing :443 with a web server, or terminating TLS at nginx, haproxy or Envoy,
is an ordinary way to run DoH, and those parse the field as the RFC writes it -
so they reject the message or take a different length from it. Two hops that
disagree about where one request ends is the whole of CL.CL request smuggling:
what elodin reads as the tail of a body, the front end reads as the start of
the next request, and attributes to whoever's connection it is pipelining onto.

Repeats are refused for the same reason (RFC 9112 6.3). The loop kept the last
one it saw, and nothing says a proxy in front resolves the same way.
*/
@(test)
test_content_length_is_strict_decimal :: proc(t: ^testing.T) {
	Case :: struct {
		headers:  string, // between the request line and the blank line
		body:     string,
		accepted: bool,
		what:     string,
	}

	CASES := []Case {
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
		// 2^64 + 4: the accumulator wraps to 4 and the range check is happy.
		{"Content-Length: 18446744073709551620\r\n", "abcd", false, "a length past 64 bits"},
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
		{"Content-Length: 4 \r\n", "abcd", false, "a non-breaking space after the digits"},
		{"X-Fold: one\r\n Content-Length: 4\r\n", "abcd", false, "a folded continuation line"},
		{"Content-Length : 4\r\n", "abcd", false, "space before the colon"},
		{"Content-Length\t: 4\r\n", "abcd", false, "a tab before the colon"},
		{"just-some-garbage\r\n", "", false, "a field line with no colon at all"},
	}

	for c in CASES {
		b := strings.builder_make(context.temp_allocator)
		strings.write_string(&b, "POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n")
		strings.write_string(&b, "Content-Type: application/dns-message\r\n")
		strings.write_string(&b, c.headers)
		strings.write_string(&b, "\r\n")
		strings.write_string(&b, c.body)

		req, parsed, ok := read_request_over_loopback(t, strings.to_string(b), c.what)
		if !ok {
			return
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
		}
		free_all(context.temp_allocator)
	}
}
