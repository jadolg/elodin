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
