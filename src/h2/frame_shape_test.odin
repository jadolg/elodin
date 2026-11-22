package h2

import "core:mem"
import "core:testing"

/*
RFC 9113 sections 6.3, 6.5 and 6.7: the error a PING, SETTINGS or PRIORITY
frame of the wrong shape draws, from the server and the client alike.
*/
@(private = "file")
Shape_Case :: struct {
	name:    string,
	h:       Frame_Header,
	// Written back: a GOAWAY with this code, or none (`.No_Error`), and
	// whether the connection carries on.
	goaway:  Error_Code,
	carries: bool,
}

@(private = "file")
SHAPE_CASES := []Shape_Case {
	{name = "PING of 7 bytes", h = {length = 7, type = .Ping}, goaway = .Frame_Size_Error},
	{name = "PING on a stream", h = {length = 8, type = .Ping, stream_id = 1}, goaway = .Protocol_Error},
	{name = "SETTINGS of 5 bytes", h = {length = 5, type = .Settings}, goaway = .Frame_Size_Error},
	{name = "SETTINGS ACK with a payload", h = {length = 6, type = .Settings, flags = FLAG_ACK}, goaway = .Frame_Size_Error},
	{name = "SETTINGS ACK on a stream", h = {type = .Settings, flags = FLAG_ACK, stream_id = 1}, goaway = .Protocol_Error},
	{name = "SETTINGS on a stream", h = {length = 6, type = .Settings, stream_id = 1}, goaway = .Protocol_Error},
	{name = "PRIORITY on stream 0", h = {length = 5, type = .Priority}, goaway = .Protocol_Error},
	// A stream error in 6.3, made a connection error as 5.4 allows.
	{name = "PRIORITY of 4 bytes", h = {length = 4, type = .Priority, stream_id = 1}, goaway = .Frame_Size_Error},
	// The shapes that are right, so the cases above fail for their shape.
	{name = "PRIORITY of 5 bytes", h = {length = 5, type = .Priority, stream_id = 1}, carries = true},
	{name = "SETTINGS ACK, empty", h = {type = .Settings, flags = FLAG_ACK}, carries = true},
	{name = "PING of 8 bytes", h = {length = 8, type = .Ping}, carries = true},
}

// A zeroed payload of the case's length, as `read_frame` would hand over.
@(private = "file")
shape_payload :: proc(h: Frame_Header) -> []u8 {
	buf := make([]u8, h.length, context.temp_allocator)
	if h.type == .Settings && h.length >= SETTING_SIZE {
		// A known setting with a legal value, so only the shape is wrong.
		buf[1] = u8(Setting.Max_Concurrent_Streams)
	}
	return buf
}

@(private = "file")
check_shape :: proc(t: ^testing.T, end: string, row: Shape_Case, carried: bool, log: ^Frame_Log) {
	testing.expectf(t, carried == row.carries, "%s, %s: the connection carried on: %v, want %v", end, row.name, carried, row.carries)
	if row.goaway != .No_Error {
		if testing.expectf(t, saw_frame(log, .Goaway), "%s, %s: no GOAWAY", end, row.name) {
			testing.expectf(t, log.goaway_code == row.goaway, "%s, %s: GOAWAY %v, want %v", end, row.name, log.goaway_code, row.goaway)
		}
	} else {
		testing.expectf(t, !saw_frame(log, .Goaway), "%s, %s: a GOAWAY (%v) for a frame of the right shape", end, row.name, log.goaway_code)
	}
	testing.expectf(t, !saw_frame(log, .Rst_Stream), "%s, %s: a RST_STREAM", end, row.name)
}

@(test)
test_a_frame_of_the_wrong_shape_draws_the_error_its_section_names :: proc(t: ^testing.T) {
	for row in SHAPE_CASES {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_conn(&log, ignore_request, allocator)
		carried := handle_frame(c, row.h, shape_payload(row.h))
		check_shape(t, "server", row, carried, &log)
		conn_done(t, c, &track, row.name, &log)

		ctrack: mem.Tracking_Allocator
		callocator := track_allocations(&ctrack)
		clog: Frame_Log
		cc := logged_client(&clog, callocator)
		ccarried := client_handle_frame(cc, row.h, shape_payload(row.h))
		check_shape(t, "client", row, ccarried, &clog)
		client_done(t, cc, &ctrack, row.name, &clog)
	}
}

@(private = "file")
pings_written :: proc(written: []u8) -> (n: int) {
	pos := 0
	for pos + FRAME_HEADER_SIZE <= len(written) {
		fh, ok := parse_frame_header(written[pos:])
		if !ok {
			break
		}
		if fh.type == .Ping {
			n += 1
		}
		pos += FRAME_HEADER_SIZE + fh.length
	}
	return n
}

/*
RFC 9113 section 3.4: the client's preface "MUST be followed by a SETTINGS
frame", and an invalid preface is a connection error of type PROTOCOL_ERROR. A
PING ahead of the SETTINGS is not answered; after it, it is.
*/
@(test)
test_the_server_holds_the_preface_to_a_settings_frame :: proc(t: ^testing.T) {
	Case :: struct {
		name:     string,
		first:    Frame_Header,
		answered: bool,
	}
	cases := []Case {
		{"PING first", {length = 8, type = .Ping}, false},
		{"SETTINGS ACK first", {type = .Settings, flags = FLAG_ACK}, false},
		{"SETTINGS first", {type = .Settings}, true},
	}
	for row in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		// Not the temp arena, which `serve` frees after every frame.
		input := make([dynamic]u8, 0, len(PREFACE) + 2 * FRAME_HEADER_SIZE + 8, allocator)
		append(&input, ..transmute([]u8)string(PREFACE))
		write_frame_header(&input, row.first.length, row.first.type, row.first.flags, row.first.stream_id)
		for _ in 0 ..< row.first.length {
			append(&input, 0)
		}
		// A PING after it, answered only once the preface is whole.
		write_frame_header(&input, 8, .Ping, 0, 0)
		append(&input, 1, 2, 3, 4, 5, 6, 7, 8)
		h := Serve_Harness {
			in_data = input[:],
			written = make([dynamic]u8, 0, 128, allocator),
		}
		c := make_conn(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, ignore_request, nil, allocator)
		serve(c)
		if row.answered {
			testing.expectf(t, pings_written(h.written[:]) == 1, "%s: the PING after the preface was not answered", row.name)
			testing.expectf(t, !h.saw_goaway, "%s: a GOAWAY (%v) after a whole preface", row.name, h.code)
		} else {
			testing.expectf(t, pings_written(h.written[:]) == 0, "%s: a PING was answered ahead of the client's SETTINGS", row.name)
			testing.expectf(t, h.saw_goaway && h.code == .Protocol_Error, "%s: GOAWAY %v (sent: %v), want PROTOCOL_ERROR", row.name, h.code, h.saw_goaway)
		}
		delete(h.written)
		delete(input)
		conn_done(t, c, &track, row.name)
	}
}

// The server's preface is a SETTINGS frame too, and the client holds it to one.
@(test)
test_the_client_holds_the_server_preface_to_a_settings_frame :: proc(t: ^testing.T) {
	Case :: struct {
		name:   string,
		first:  Frame_Header,
		refuse: bool,
	}
	cases := []Case {
		{"PING first", {length = 8, type = .Ping}, true},
		{"SETTINGS ACK first", {type = .Settings, flags = FLAG_ACK}, true},
		{"SETTINGS first", {type = .Settings}, false},
	}
	for row in cases {
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		// Not the temp arena, which `client_serve` frees after every frame.
		input := make([dynamic]u8, 0, FRAME_HEADER_SIZE + 8, allocator)
		write_frame_header(&input, row.first.length, row.first.type, row.first.flags, row.first.stream_id)
		for _ in 0 ..< row.first.length {
			append(&input, 0)
		}
		h := Serve_Harness {
			in_data = input[:],
			written = make([dynamic]u8, 0, 128, allocator),
		}
		log := Frame_Log {
			frames = make([dynamic]Frame_Header, 0, 8, allocator),
		}
		h.user = &log
		c := client_make(IO{user = &h, read = serve_harness_read, write = client_harness_write}, allocator)
		client_serve(c)
		if row.refuse {
			if testing.expectf(t, saw_frame(&log, .Goaway), "%s: no GOAWAY", row.name) {
				testing.expectf(t, log.goaway_code == .Protocol_Error, "%s: GOAWAY %v, want PROTOCOL_ERROR", row.name, log.goaway_code)
			}
		} else {
			testing.expectf(t, !saw_frame(&log, .Goaway), "%s: a GOAWAY (%v) after a SETTINGS preface", row.name, log.goaway_code)
		}
		delete(log.frames)
		delete(h.written)
		delete(input)
		client_unref(c)
		free_all(context.temp_allocator)
		expect_no_leaks(t, &track, row.name)
	}
}

/*
RFC 7541 section 4.2: a dynamic table size update "MUST occur at the beginning"
of a header block. After a field it is a decoding error, which the connection
turns into COMPRESSION_ERROR; at the start it is applied.
*/
@(test)
test_a_table_size_update_is_held_to_the_start_of_a_block :: proc(t: ^testing.T) {
	late: Dynamic_Table
	dynamic_table_init(&late, DEFAULT_HEADER_TABLE_SIZE, context.temp_allocator)
	// :method GET (static index 2), then an update to 0.
	_, late_err := decode(&late, []u8{0x82, 0x20}, context.temp_allocator)
	testing.expect_value(t, late_err, Hpack_Error.Bad_Update)

	early: Dynamic_Table
	dynamic_table_init(&early, DEFAULT_HEADER_TABLE_SIZE, context.temp_allocator)
	fields, early_err := decode(&early, []u8{0x20, 0x82}, context.temp_allocator)
	testing.expect_value(t, early_err, Hpack_Error.None)
	testing.expect_value(t, len(fields), 1)
	testing.expect_value(t, early.max_size, 0)
	free_all(context.temp_allocator)
}

// The client's writes, into the `Frame_Log` the harness carries: `log_write`
// steps over the client's preface, which is not a frame.
@(private = "file")
client_harness_write :: proc(user: rawptr, buf: []u8) -> bool {
	h := cast(^Serve_Harness)user
	return log_write(h.user, buf)
}
