package h2

import "core:mem"
import "core:slice"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:loop"

// A GOAWAY payload: the last stream id and `code`.
@(private = "file")
goaway_payload :: proc(last: u32, code := Error_Code.No_Error) -> []u8 {
	p := make([]u8, GOAWAY_FIXED_SIZE, context.temp_allocator)
	put_u32(p, last)
	put_u32(p[4:], u32(code))
	return p
}

// How many PING ACKs `written` holds: what a reader still reading answers.
@(private = "file")
ping_acks :: proc(written: []u8) -> int {
	n, pos := 0, 0
	for pos + FRAME_HEADER_SIZE <= len(written) {
		h, ok := parse_frame_header(written[pos:])
		if !ok {
			break
		}
		if h.type == .Ping && h.flags & FLAG_ACK != 0 {
			n += 1
		}
		pos += FRAME_HEADER_SIZE + h.length
	}
	return n
}

/*
RFC 9113 6.8: a client's GOAWAY does not cancel the requests it already sent.
The stream dispatched before it is still answered, the connection keeps being
read, and this end's GOAWAY(NO_ERROR), naming that stream, follows the answer.
*/
@(test)
test_a_peer_goaway_lets_the_open_stream_be_answered :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	log: Frame_Log
	c := logged_conn(&log, destroying_handler, allocator)

	block := request_block()
	opened := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, block)
	testing.expect(t, opened, "handle_headers failed")
	payload := goaway_payload(0)
	reading := handle_frame(c, Frame_Header{length = len(payload), type = .Goaway}, payload)
	testing.expect(t, reading, "the connection stopped being read with a stream still to answer")
	testing.expect(t, !saw_frame(&log, .Goaway), "a GOAWAY went out before the open stream was answered")

	answered := respond(c, 1, Response{status = 200, content_type = "application/dns-message", body = []u8{1, 2, 3, 4}})
	testing.expect(t, answered, "the answer to the open stream was not written")
	testing.expect(t, saw_frame(&log, .Headers, 1) && saw_frame(&log, .Data, 1), "the open stream's answer did not go out")
	testing.expect(t, len(log.frames) > 0 && log.frames[len(log.frames) - 1].type == .Goaway, "no GOAWAY followed the last answer")
	testing.expect_value(t, log.goaway_code, Error_Code.No_Error)
	testing.expect_value(t, log.goaway_last, 1)

	conn_done(t, c, &track, "peer goaway, one stream open", &log)
}

// With nothing open, the peer's GOAWAY is answered with this end's at once.
@(test)
test_a_peer_goaway_on_an_idle_connection_is_answered_at_once :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	log: Frame_Log
	c := logged_conn(&log, destroying_handler, allocator)

	payload := goaway_payload(0)
	reading := handle_frame(c, Frame_Header{length = len(payload), type = .Goaway}, payload)
	testing.expect(t, !reading, "an idle connection was still read after the peer's GOAWAY")
	testing.expect(t, saw_frame(&log, .Goaway), "no GOAWAY answered the peer's")
	testing.expect_value(t, log.goaway_code, Error_Code.No_Error)

	conn_done(t, c, &track, "peer goaway, idle", &log)
}

/*
`serve` reads nothing past a GOAWAY this end has sent, even when the frame that
drained the connection was not a request: here the peer resets the one stream
left, and the PING behind it is never answered.
*/
@(test)
test_serve_stops_reading_after_the_goaway_a_drain_sends :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	block := request_block()
	input := make([dynamic]u8, 0, 256, context.temp_allocator)
	append(&input, ..transmute([]u8)string(PREFACE))
	append(&input, ..frame_bytes(.Settings, 0, 0, nil))
	append(&input, ..frame_bytes(.Headers, FLAG_END_HEADERS, 1, block))
	append(&input, ..frame_bytes(.Goaway, 0, 0, goaway_payload(0)))
	cancel := []u8{0, 0, 0, u8(Error_Code.Cancel)}
	append(&input, ..frame_bytes(.Rst_Stream, 0, 1, cancel))
	append(&input, ..frame_bytes(.Ping, 0, 0, make([]u8, 8, context.temp_allocator)))

	// Off the temp allocator, which the reader frees after every frame.
	script := slice.clone(input[:])
	defer delete(script)
	h := Serve_Harness {
		in_data = script,
		written = make([dynamic]u8, 0, 256, allocator),
	}
	c := make_conn(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, destroying_handler, nil, allocator)
	serve(c)

	testing.expect(t, h.saw_goaway, "the drained connection sent no GOAWAY")
	testing.expect_value(t, h.code, Error_Code.No_Error)
	testing.expect_value(t, h.last, 1)
	testing.expectf(t, ping_acks(h.written[:]) == 0, "%d PINGs were answered after this end's GOAWAY", ping_acks(h.written[:]))

	delete(h.written)
	conn_done(t, c, &track, "serve after drain")
}

/*
RFC 9113 6.8 on the client: a stream above the GOAWAY's last stream id was not
processed and fails as `Refused`; one at or below it is read to its end. Then
the client says GOAWAY(NO_ERROR) and stops reading - the PING behind the answer
is never answered.
*/
@(test)
test_a_server_goaway_lets_streams_it_names_finish :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	input := make([dynamic]u8, 0, 256, context.temp_allocator)
	append(&input, ..frame_bytes(.Settings, 0, 0, nil))
	append(&input, ..frame_bytes(.Goaway, 0, 0, goaway_payload(1)))
	// `:status: 200`, static table index 8.
	append(&input, ..frame_bytes(.Headers, FLAG_END_HEADERS, 1, []u8{0x88}))
	append(&input, ..frame_bytes(.Data, FLAG_END_STREAM, 1, []u8{'o', 'k'}))
	append(&input, ..frame_bytes(.Ping, 0, 0, make([]u8, 8, context.temp_allocator)))

	// Off the temp allocator, which the reader frees after every frame.
	script := slice.clone(input[:])
	defer delete(script)
	h := Serve_Harness {
		in_data = script,
		written = make([dynamic]u8, 0, 256, allocator),
	}
	c := client_make(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, allocator)
	// The preface is not a frame, and the harness reads frames from the start.
	clear(&h.written)
	named := open_test_stream(c, 1, allocator)
	above := open_test_stream(c, 3, allocator)
	client_serve(c)

	testing.expect(t, named.done && string(named.body[:]) == "ok", "the stream the GOAWAY named did not finish")
	testing.expect(t, above.reset && above.refused, "the stream above the GOAWAY's last id was not refused")
	testing.expect(t, client_going_away(c), "the connection does not say it is going away")
	testing.expect(t, h.saw_goaway, "the client sent no GOAWAY once the named stream finished")
	testing.expect_value(t, h.code, Error_Code.No_Error)
	testing.expectf(t, ping_acks(h.written[:]) == 0, "%d PINGs were answered after the drain", ping_acks(h.written[:]))

	delete_key(&c.streams, 1)
	delete_key(&c.streams, 3)
	client_stream_destroy(c, named)
	client_stream_destroy(c, above)
	delete(h.written)
	client_done(t, c, &track, "server goaway")
}

// No new request goes on a connection the peer has sent GOAWAY on: it fails
// as `Closed` at once, so the caller dials afresh.
@(test)
test_no_request_goes_out_after_a_server_goaway :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	log: Frame_Log
	c := logged_client(&log, allocator)

	payload := goaway_payload(0)
	testing.expect(t, client_handle_frame(c, Frame_Header{length = len(payload), type = .Goaway}, payload), "the GOAWAY was refused")
	clear(&log.frames)
	_, err := client_request(c, Client_Request{method = "GET", scheme = "https", authority = "a.example", path = "/dns-query"}, 50 * time.Millisecond)
	testing.expect_value(t, err, Client_Error.Closed)
	testing.expect(t, !saw_frame(&log, .Headers), "a request went out after the peer's GOAWAY")

	client_done(t, c, &track, "request after goaway", &log)
}

// The serve harness, with an answer to stream 1 sent - as from the handler's
// own fiber - the moment the reader asks for the bytes at `answer_at`.
@(private = "file")
Answering_Harness :: struct {
	using h:   Serve_Harness,
	conn:      ^Conn,
	answer_at: int,
	answered:  bool,
}

@(private = "file")
answering_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	a := cast(^Answering_Harness)user
	if !a.answered && a.in_pos == a.answer_at {
		a.answered = true
		respond(a.conn, 1, Response{status = 200, body = []u8{1}})
	}
	return serve_harness_read(&a.h, buf)
}

@(private = "file")
answering_write :: proc(user: rawptr, buf: []u8) -> bool {
	return serve_harness_write(&(cast(^Answering_Harness)user).h, buf)
}

/*
A drain whose GOAWAY goes out from a handler's own fiber while the reader waits
for its next frame: that frame is not acted on. The HEADERS of a stream above
the GOAWAY's last stream id is not dispatched, and the PING behind it is not
answered.
*/
@(test)
test_serve_acts_on_no_frame_read_after_a_goaway_sent_from_another_fiber :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	block := request_block()
	input := make([dynamic]u8, 0, 256, context.temp_allocator)
	append(&input, ..transmute([]u8)string(PREFACE))
	append(&input, ..frame_bytes(.Settings, 0, 0, nil))
	append(&input, ..frame_bytes(.Headers, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block))
	append(&input, ..frame_bytes(.Goaway, 0, 0, goaway_payload(0)))
	answer_at := len(input)
	append(&input, ..frame_bytes(.Headers, FLAG_END_HEADERS | FLAG_END_STREAM, 3, block))
	append(&input, ..frame_bytes(.Ping, 0, 0, make([]u8, 8, context.temp_allocator)))
	script := slice.clone(input[:])
	defer delete(script)

	log: Request_Log
	a := Answering_Harness {
		h = {in_data = script, written = make([dynamic]u8, 0, 256, allocator)},
		answer_at = answer_at,
	}
	c := make_conn(IO{user = &a, read = answering_read, write = answering_write}, counting_handler, &log, allocator)
	// Stream 1 is left to the "fiber": the handler counts it and answers nothing.
	a.conn = c
	serve(c)

	testing.expect(t, a.answered, "the premise: stream 1 was answered while the reader waited")
	testing.expect(t, a.saw_goaway && a.code == .No_Error && a.last == 1, "the drain sent no GOAWAY(NO_ERROR) naming stream 1")
	testing.expect_value(t, log.dispatched, 1)
	testing.expectf(t, ping_acks(a.written[:]) == 0, "%d PINGs were answered after this end's GOAWAY", ping_acks(a.written[:]))

	delete(a.written)
	conn_done(t, c, &track, "goaway from another fiber")
}

/*
RFC 9113 6.8: a GOAWAY with an error code is the peer closing on a failure, not
draining. Each end answers it and ends the connection at once, open streams or
not, so the client's requests fail as `Closed` and are asked again elsewhere.
*/
@(test)
test_a_goaway_with_an_error_code_ends_the_connection_at_once :: proc(t: ^testing.T) {
	{
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_conn(&log, destroying_handler, allocator)
		block := request_block()
		opened := handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 1}, block)
		testing.expect(t, opened, "handle_headers failed")
		payload := goaway_payload(1, .Protocol_Error)
		reading := handle_frame(c, Frame_Header{length = len(payload), type = .Goaway}, payload)
		testing.expect(t, !reading, "the server kept reading after a GOAWAY with an error code")
		testing.expect(t, saw_frame(&log, .Goaway) && log.goaway_code == .No_Error, "the server did not answer the GOAWAY")
		conn_done(t, c, &track, "server, error goaway", &log)
	}
	{
		track: mem.Tracking_Allocator
		allocator := track_allocations(&track)
		log: Frame_Log
		c := logged_client(&log, allocator)
		s := open_test_stream(c, 1, allocator)
		payload := goaway_payload(1, .Protocol_Error)
		reading := client_handle_frame(c, Frame_Header{length = len(payload), type = .Goaway}, payload)
		testing.expect(t, !reading, "the client kept reading after a GOAWAY with an error code")
		testing.expect(t, !client_going_away(c), "a GOAWAY with an error code was taken for a drain")
		delete_key(&c.streams, 1)
		client_stream_destroy(c, s)
		client_done(t, c, &track, "client, error goaway", &log)
	}
}

/*
A stream read before another fiber claimed this end's drain GOAWAY, and above
the last stream id it names, is not given to a handler: the client was told it
was not processed and will ask for it again (RFC 9113 6.8).
*/
@(test)
test_a_stream_past_this_ends_goaway_is_not_dispatched :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)
	log: Request_Log
	c := make_conn(IO{read = no_read, write = discard_write}, counting_handler, &log, allocator)
	// As `goaway_claim_locked` leaves it, naming stream 1.
	loop.lock(&c.mu)
	_, claimed := goaway_claim_locked(c, .No_Error)
	c.goaway_last = 1
	c.goaway_writing = false
	loop.unlock(&c.mu)
	testing.expect(t, claimed, "the premise: the GOAWAY was claimed")

	block := request_block()
	handle_headers(c, Frame_Header{length = len(block), type = .Headers, flags = FLAG_END_HEADERS | FLAG_END_STREAM, stream_id = 3}, block)
	testing.expect_value(t, log.dispatched, 0)
	_, kept := c.streams[3]
	testing.expect(t, !kept, "the refused stream was left in the table")
	conn_done(t, c, &track, "stream past goaway")
}

@(private = "file")
Late_Goaway :: struct {
	conn: ^Conn,
	ok:   bool,
}

// Writes the GOAWAY claimed before `serve` began closing, once `serve` waits on it.
@(private = "file")
write_late_goaway :: proc(l: ^Late_Goaway) {
	l.ok = wait_for_waiter(&l.conn.cond)
	frame := goaway_frame(1, .No_Error)
	goaway_write(l.conn, frame[:])
}

/*
A drain GOAWAY claimed on a handler's fiber is written even when `serve` is
already on its way out: its close waits for the write rather than refusing it.
*/
@(test)
test_serve_waits_for_a_goaway_claimed_elsewhere_before_closing :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	allocator := track_allocations(&track)

	input := make([dynamic]u8, 0, 64, context.temp_allocator)
	append(&input, ..transmute([]u8)string(PREFACE))
	append(&input, ..frame_bytes(.Settings, 0, 0, nil))
	script := slice.clone(input[:])
	defer delete(script)
	h := Serve_Harness {
		in_data = script,
		written = make([dynamic]u8, 0, 128, allocator),
	}
	c := make_conn(IO{user = &h, read = serve_harness_read, write = serve_harness_write}, ignore_request, nil, allocator)
	c.write_timeout = 5 * time.Second
	loop.lock(&c.mu)
	_, claimed := goaway_claim_locked(c, .No_Error)
	loop.unlock(&c.mu)
	testing.expect(t, claimed, "the premise: the GOAWAY was claimed")

	l := Late_Goaway {
		conn = c,
	}
	writer := thread.create_and_start_with_poly_data(&l, write_late_goaway)
	serve(c)
	thread.join(writer)
	thread.destroy(writer)

	testing.expect(t, l.ok, "serve did not wait for the claimed GOAWAY")
	testing.expect(t, h.saw_goaway && h.code == .No_Error, "the claimed GOAWAY was refused by the close")
	delete(h.written)
	conn_done(t, c, &track, "goaway claimed elsewhere")
}
