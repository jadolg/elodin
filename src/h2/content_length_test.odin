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
		{"a length its DATA adds up to", {"3"}, {"a", "bc"}, false, true},
		{"one its DATA falls short of", {"100"}, {"abc"}, false, false},
		{"one its DATA runs past", {"2"}, {"abc"}, false, false},
		{"zero, with no DATA", {"0"}, nil, false, true},
		{"five, with no DATA", {"5"}, nil, false, false},
		{"a match ended by trailers", {"3"}, {"abc"}, true, true},
		{"a mismatch ended by trailers", {"4"}, {"abc"}, true, false},
		{"two equal lengths", {"3", "3"}, {"abc"}, false, false},
		{"a length that is not digits", {"0x3"}, {"abc"}, false, false},
		{"no length at all", nil, {"abc"}, false, true},
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
		{"a length its DATA adds up to", "200", {"3"}, {"a", "bc"}, false, true},
		{"one its DATA falls short of", "200", {"100"}, {"abc"}, false, false},
		{"one its DATA runs past", "200", {"2"}, {"abc"}, false, false},
		{"one with no DATA", "200", {"7"}, nil, false, false},
		{"two equal lengths", "200", {"3", "3"}, {"abc"}, false, false},
		{"a length that is not digits", "200", {"three"}, {"abc"}, false, false},
		// Not digits, with no DATA for the length it does not have to differ
		// from: refused for its form alone.
		{"a length that is not digits, and no DATA", "200", {"x"}, nil, false, false},
		{"a reply to HEAD", "200", {"100"}, nil, true, true},
		{"a 204", "204", {"100"}, nil, false, true},
		{"a 304", "304", {"100"}, nil, false, true},
		{"no length at all", "200", nil, {"abc"}, false, true},
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
			testing.expectf(t, s.reset && !s.done && s.malformed, "%s: done %v, reset %v, malformed %v; want it failed", row.what, s.done, s.reset, s.malformed)
			testing.expectf(t, saw_frame(&log, .Rst_Stream, 1) && log.rst_code == .Protocol_Error, "%s: no RST_STREAM(PROTOCOL_ERROR)", row.what)
		}
		delete(s.body)
		delete_key(&c.streams, 1)
		free(s, allocator)
		client_done(t, c, &track, row.what, &log)
	}
}
