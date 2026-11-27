package h2

import "core:mem"
import "core:testing"

// A POST's header block, with `content-length` fields as given.
@(private = "file")
post_block :: proc(lengths: ..string) -> []u8 {
	block := make([dynamic]u8, 0, 128, context.temp_allocator)
	encode_header(&block, ":method", "POST")
	encode_header(&block, ":scheme", "https")
	encode_header(&block, ":authority", "dns.example")
	encode_header(&block, ":path", "/dns-query")
	encode_header(&block, "content-type", "application/dns-message")
	for l in lengths {
		encode_header(&block, "content-length", l)
	}
	return block[:]
}

/*
RFC 9113 8.1.1: a request whose `content-length` does not equal the sum of its
DATA, or that carries a repeated or non-numeric one, is malformed - a stream
error of type PROTOCOL_ERROR, and no handler is given it. One that matches is
served, wherever its content ends: on the HEADERS, on DATA, or with trailers.
*/
@(test)
test_a_request_is_held_to_its_content_length :: proc(t: ^testing.T) {
	Case :: struct {
		what:     string,
		lengths:  []string,
		// DATA payloads, the last carrying END_STREAM; none puts END_STREAM on
		// the HEADERS.
		data:     []string,
		trailers: bool,
		served:   bool,
	}
	cases := []Case {
		{what = "a length its DATA adds up to", lengths = {"3"}, data = {"a", "bc"}, trailers = false, served = true},
		{what = "one its DATA falls short of", lengths = {"100"}, data = {"abc"}, trailers = false, served = false},
		{what = "one its DATA runs past", lengths = {"2"}, data = {"abc"}, trailers = false, served = false},
		{what = "zero, with no DATA", lengths = {"0"}, data = nil, trailers = false, served = true},
		{what = "five, with no DATA", lengths = {"5"}, data = nil, trailers = false, served = false},
		{what = "a match ended by trailers", lengths = {"3"}, data = {"abc"}, trailers = true, served = true},
		{what = "a mismatch ended by trailers", lengths = {"4"}, data = {"abc"}, trailers = true, served = false},
		{what = "two equal lengths", lengths = {"3", "3"}, data = {"abc"}, trailers = false, served = false},
		{what = "a length that is not digits", lengths = {"0x3"}, data = {"abc"}, trailers = false, served = false},
		{what = "no length at all", lengths = nil, data = {"abc"}, trailers = false, served = true},
	}
	for row in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Request_Log
		c := make_conn(IO{user = &log, read = no_read, write = request_log_write}, counting_handler, &log, allocator)

		block := post_block(..row.lengths)
		flags: u8 = FLAG_END_HEADERS
		if len(row.data) == 0 && !row.trailers {
			flags |= FLAG_END_STREAM
		}
		ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = flags, stream_id = 1}, block)
		for d, i in row.data {
			last := i == len(row.data) - 1 && !row.trailers
			ok = ok && handle_data(c, Frame_Header{length = len(d), type = .Data, flags = u8(FLAG_END_STREAM) if last else 0, stream_id = 1}, transmute([]u8)d)
		}
		if row.trailers {
			trailer := TRAILER
			ok = ok && handle_headers(c, Frame_Header{length = len(trailer), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, trailer[:])
		}
		testing.expectf(t, ok, "%s: the connection was dropped", row.what)
		testing.expectf(t, !log.goaway, "%s: a GOAWAY, for what is a stream error", row.what)
		if row.served {
			testing.expectf(t, log.dispatched == 1 && log.rsts == 0, "%s: dispatched %d, %d resets; want it served", row.what, log.dispatched, log.rsts)
		} else {
			testing.expectf(t, log.dispatched == 0, "%s: dispatched to a handler", row.what)
			testing.expectf(t, log.rsts == 1 && log.rst_code == .Protocol_Error, "%s: %d resets (%v), want one PROTOCOL_ERROR", row.what, log.rsts, log.rst_code)
		}
		conn_done(t, c, &track, row.what)
	}
}

/*
RFC 9113 8.1.1: "Clients MUST NOT accept a malformed response", and one whose
`content-length` its DATA does not add up to is one. A response that defines no
content - to a HEAD, or a 204 or 304 - is not held to it.
*/
@(test)
test_a_response_is_held_to_its_content_length :: proc(t: ^testing.T) {
	Case :: struct {
		what:     string,
		status:   string,
		lengths:  []string,
		data:     []string,
		head:     bool,
		accepted: bool,
	}
	cases := []Case {
		{what = "a length its DATA adds up to", status = "200", lengths = {"3"}, data = {"a", "bc"}, head = false, accepted = true},
		{what = "one its DATA falls short of", status = "200", lengths = {"100"}, data = {"abc"}, head = false, accepted = false},
		{what = "one its DATA runs past", status = "200", lengths = {"2"}, data = {"abc"}, head = false, accepted = false},
		{what = "one with no DATA", status = "200", lengths = {"7"}, data = nil, head = false, accepted = false},
		{what = "two equal lengths", status = "200", lengths = {"3", "3"}, data = {"abc"}, head = false, accepted = false},
		{what = "a length that is not digits", status = "200", lengths = {"three"}, data = {"abc"}, head = false, accepted = false},
		// Not digits, with no DATA for the length it does not have to differ
		// from: refused for its form alone.
		{what = "a length that is not digits, and no DATA", status = "200", lengths = {"x"}, data = nil, head = false, accepted = false},
		{what = "a reply to HEAD", status = "200", lengths = {"100"}, data = nil, head = true, accepted = true},
		{what = "a 204", status = "204", lengths = {"100"}, data = nil, head = false, accepted = true},
		{what = "a 304", status = "304", lengths = {"100"}, data = nil, head = false, accepted = true},
		{what = "no length at all", status = "200", lengths = nil, data = {"abc"}, head = false, accepted = true},
	}
	for row in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)
		s.head = row.head

		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", row.status)
		for l in row.lengths {
			encode_header(&block, "content-length", l)
		}
		flags: u8 = FLAG_END_HEADERS
		if len(row.data) == 0 {
			flags |= FLAG_END_STREAM
		}
		ok := client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = flags, stream_id = 1}, block[:])
		for d, i in row.data {
			last := i == len(row.data) - 1
			ok = ok && client_handle_frame(c, Frame_Header{length = len(d), type = .Data, flags = u8(FLAG_END_STREAM) if last else 0, stream_id = 1}, transmute([]u8)d)
		}
		testing.expectf(t, ok, "%s: the connection was dropped", row.what)
		if row.accepted {
			testing.expectf(t, s.done && !s.reset, "%s: done %v, reset %v; want it accepted", row.what, s.done, s.reset)
		} else {
			testing.expectf(t, s.reset && !s.done, "%s: done %v, reset %v; want it failed", row.what, s.done, s.reset)
			testing.expectf(t, saw_frame(&log, .Rst_Stream, 1) && log.rst_code == .Protocol_Error, "%s: no RST_STREAM(PROTOCOL_ERROR)", row.what)
		}
		delete_key(&c.streams, 1)
		client_stream_destroy(c, s)
		client_done(t, c, &track, row.what, &log)
	}

	/*
	A refusal whose body misses its length fails the stream and keeps its head:
	a 503's `retry-after` is still what the server asked for, as under failed
	trailers. A head that is itself malformed has none to keep.
	*/
	Head_Case :: struct {
		what:      string,
		length:    string,
		data:      string,
		malformed: bool,
	}
	for row in ([]Head_Case {
			{"a 503 short of its length", "100", "0123456789", false},
			{"a 503 past its length", "2", "0123456789", false},
			{"a 503 with a length that is not digits", "x", "0123456789", true},
		}) {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)
		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", "503")
		encode_header(&block, "retry-after", "30")
		encode_header(&block, "content-length", row.length)
		ok := client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = len(row.data), type = .Data, flags = FLAG_END_STREAM, stream_id = 1}, transmute([]u8)row.data)
		testing.expectf(t, ok, "%s: the connection was dropped", row.what)
		testing.expectf(t, s.reset && !s.done, "%s: done %v, reset %v; want it failed", row.what, s.done, s.reset)
		testing.expectf(t, s.malformed == row.malformed, "%s: malformed %v, want %v", row.what, s.malformed, row.malformed)
		if !row.malformed {
			testing.expectf(t, s.status == 503 && s.retry_after == 30, "%s: head %d, retry-after %d, want 503 and 30 kept", row.what, s.status, s.retry_after)
		}
		delete_key(&c.streams, 1)
		client_stream_destroy(c, s)
		client_done(t, c, &track, row.what, &log)
	}
}

/*
DATA that runs past the declared `content-length` makes the message malformed
then and there (RFC 9113 8.1.1), so it is reset at once rather than buffered to
an END_STREAM that may never come - at both ends.
*/
@(test)
test_data_past_the_content_length_is_refused_at_once :: proc(t: ^testing.T) {
	{
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Request_Log
		c := make_conn(IO{user = &log, read = no_read, write = request_log_write}, counting_handler, &log, allocator)
		block := post_block("2")
		ok := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block)
		ok = ok && handle_data(c, Frame_Header{length = 3, type = .Data, stream_id = 1}, transmute([]u8)string("abc"))
		testing.expect(t, ok, "server: the connection was dropped")
		testing.expectf(t, log.rsts == 1 && log.rst_code == .Protocol_Error, "server: %d resets (%v) before the stream ended, want one PROTOCOL_ERROR", log.rsts, log.rst_code)
		testing.expect_value(t, log.dispatched, 0)
		conn_done(t, c, &track, "server")
	}
	{
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)
		block := make([dynamic]u8, 0, 64, context.temp_allocator)
		encode_header(&block, ":status", "200")
		encode_header(&block, "content-length", "2")
		ok := client_handle_frame(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS, stream_id = 1}, block[:])
		ok = ok && client_handle_frame(c, Frame_Header{length = 3, type = .Data, stream_id = 1}, transmute([]u8)string("abc"))
		testing.expect(t, ok, "client: the connection was dropped")
		testing.expectf(t, s.reset && !s.done, "client: done %v, reset %v before the stream ended; want it failed", s.done, s.reset)
		testing.expect(t, saw_frame(&log, .Rst_Stream, 1) && log.rst_code == .Protocol_Error, "client: no RST_STREAM(PROTOCOL_ERROR)")
		delete_key(&c.streams, 1)
		client_stream_destroy(c, s)
		client_done(t, c, &track, "client", &log)
	}
}
