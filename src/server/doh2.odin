package server

import "core:strings"
import "core:sync"
import "elodin:dns"
import "elodin:h2"
import "elodin:logx"
import "elodin:pool"
import "elodin:tlsx"

/*
The DoH endpoint over HTTP/2 (RFC 8484 with RFC 9113 transport).

This is the path browsers take: Firefox and Chrome will only speak HTTP/2 to a
DoH resolver. It accepts the same two request forms as the HTTP/1.1 endpoint,
POST with an application/dns-message body and GET with a base64url `dns`
parameter.

Each request is handed to the query worker pool rather than answered on the
connection's reader thread, so the two lookups a browser issues for one name run
at the same time instead of one behind the other. Responses are written back
under the connection's write lock and may complete in any order.

Being the only transport that queues its work, it is also the only one that has
to shed: past `server.max_pending` a request is answered 503 here instead of
joining a backlog it would sit out. See `h2_handler`.
*/

@(private)
H2_Context :: struct {
	server: ^Server,
	conn:   ^tlsx.Conn,
	client: string,
	path:   string,
}

@(private)
H2_Job :: struct {
	ctx:       ^H2_Context,
	h2conn:    ^h2.Conn,
	req:       ^h2.Request,
}

@(private)
h2_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	ctx := cast(^H2_Context)user
	got, err := tlsx.read(ctx.conn, buf)
	return got, err == .None && got > 0
}

@(private)
h2_write :: proc(user: rawptr, buf: []u8) -> bool {
	ctx := cast(^H2_Context)user
	_, err := tlsx.write(ctx.conn, buf)
	return err == .None
}

@(private)
serve_doh2 :: proc(s: ^Server, conn: ^tlsx.Conn, client: string) {
	ctx := H2_Context {
		server = s,
		conn   = conn,
		client = client,
		path   = s.cfg.listeners.doh.path,
	}

	io := h2.IO {
		user  = &ctx,
		read  = h2_read,
		write = h2_write,
	}
	hc := h2.make_conn(io, h2_handler, &ctx)
	// A response waits no longer for flow-control credit than the connection
	// waits for anything else, so a client that stops reading cannot hold a
	// query worker past its welcome.
	hc.write_timeout = s.cfg.server.client_timeout

	h2.serve(hc)
	// `ctx` and the TLS connection live in this frame, so every handler must be
	// finished with them before it returns.
	h2.conn_wait_idle(hc)
	h2.conn_unref(hc)
}

@(private)
h2_handler :: proc(hc: ^h2.Conn, req: ^h2.Request) {
	ctx := cast(^H2_Context)hc.user

	job := new(H2_Job)
	job.ctx = ctx
	job.h2conn = hc
	job.req = req

	// The job outlives this call, so it needs its own reference; the pool may
	// still be running it after the reader thread has gone.
	h2.conn_ref(hc)
	/*
	Shed rather than queue once the backlog is past what the workers can work
	through, the same bound the UDP read loop applies before it queues.

	This is the only transport that hands its work to the pool - the others
	answer on their own connection thread, so `max_connections` is what bounds
	them. Without this the operator's backlog limit sheds UDP at a few hundred
	while HTTP/2 queues up to `max_connections` x `MAX_CONCURRENT` streams, each
	holding its buffered body, in front of it.

	`try_submit` rather than `pending` and then `submit`: there is a reader
	thread per connection here, and a gap between the two is one all of them can
	pass through at once.
	*/
	switch pool.try_submit(
		ctx.server.handler_pool,
		h2_job,
		job,
		ctx.server.cfg.server.max_pending,
	) {
	case .Accepted:
	case .Full:
		h2.conn_unref(hc)
		free(job)
		h2_shed(ctx, hc, req)
	case .Stopped:
		// Shutting down: answer inline rather than dropping the stream.
		h2_answer(job)
	}
}

/*
Turn one request away, on the connection's reader thread.

Answered rather than dropped: unlike a datagram, the stream is a client sitting
on an open connection, and a status tells it to come back later instead of
leaving it to time out.

Answered with no body, which is the part that matters. A body goes out through
`h2.write_body`, which parks on flow-control credit until the write timeout when
the client is not reading - and this is the thread that would have read the
WINDOW_UPDATE releasing it. Parking here stops the connection reading anything,
including the WINDOW_UPDATEs that release pool workers already writing to it, so
a shed that can stall the reader deepens the overload it exists to relieve.
HEADERS are not flow-controlled, so a status on its own cannot park.

Nothing is freed here beyond the request: this runs on the arena `h2.serve` is
still working through, which is also why it is not reached through `h2_job`.
*/
@(private)
h2_shed :: proc(ctx: ^H2_Context, hc: ^h2.Conn, req: ^h2.Request) {
	// Counted as a query the server dropped only when it was going to be one. A
	// request for some other path was never going to reach the resolver, and
	// `dropped` counts refused queries rather than turned-away streams.
	endpoint, _ := h2_split_path(req.path)
	if endpoint == ctx.path {
		sync.atomic_add(&ctx.server.stats.dropped, 1)
	}
	/*
	Logged whatever the path, which the counter above is not: dropped= is a
	figure about queries, and this is the line that says a 503 came from the
	backlog rather than from a broken endpoint. Without it a shed off the DoH
	path leaves no trace anywhere at all.

	Nothing is released after it: `h2.serve` resets this arena between frames,
	which is the same reason `h2_error` can format on this thread.
	*/
	logx.debugf(
		"doh/h2: shedding a request from %s, server.max_pending (%d) is reached",
		ctx.client,
		ctx.server.cfg.server.max_pending,
	)
	h2.respond(hc, req.stream_id, h2.Response{status = 503})
	h2.request_destroy(hc, req)
}

@(private)
h2_job :: proc(data: rawptr) {
	// On a pool worker the arena is ours for the length of the job.
	defer free_all(context.temp_allocator)
	h2_answer(data)
}

/*
Answer one request.

Split from `h2_job` because the shutdown path above runs it inline on the
connection's reader thread, whose arena holds the frame `h2.serve` is still
working through — resetting it there would free the ground from under it.
*/
@(private)
h2_answer :: proc(data: rawptr) {
	job := cast(^H2_Job)data
	hc := job.h2conn
	req := job.req
	ctx := job.ctx
	defer {
		h2.request_destroy(hc, req)
		h2.conn_unref(hc)
		free(job)
	}

	resp, ok := build_h2_response(ctx, req)
	if !ok {
		return
	}
	h2.respond(hc, req.stream_id, resp)
}

@(private)
build_h2_response :: proc(ctx: ^H2_Context, req: ^h2.Request) -> (resp: h2.Response, ok: bool) {
	path, query := h2_split_path(req.path)
	if path != ctx.path {
		return h2_error(404, "not found"), true
	}

	message: []u8
	switch req.method {
	case "POST":
		if req.content_type != "" && !strings.has_prefix(req.content_type, DOH_CONTENT_TYPE) {
			return h2_error(415, "unsupported media type"), true
		}
		message = req.body
	case "GET":
		encoded, found := query_param(query, "dns")
		if !found {
			return h2_error(400, "missing dns parameter"), true
		}
		decoded, dok := decode_dns_param(encoded)
		if !dok || len(decoded) == 0 {
			return h2_error(400, "malformed dns parameter"), true
		}
		message = decoded
	case:
		return h2_error(405, "method not allowed"), true
	}

	if len(message) < dns.HEADER_SIZE {
		return h2_error(400, "message too short"), true
	}

	answer, _, handled := handle_query(ctx.server, message, .DoH, ctx.client, context.temp_allocator)
	if !handled || len(answer) == 0 {
		return h2_error(500, "no response"), true
	}

	return h2.Response {
			status = 200,
			content_type = DOH_CONTENT_TYPE,
			cache_control = h2_cache_control(answer),
			body = answer,
		},
		true
}

// The :path pseudo-header carries the query string too.
@(private)
h2_split_path :: proc(path: string) -> (endpoint: string, query: string) {
	if idx := strings.index_byte(path, '?'); idx >= 0 {
		return path[:idx], path[idx + 1:]
	}
	return path, ""
}

@(private)
h2_cache_control :: proc(response: []u8) -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "max-age=")
	strings.write_int(&b, int(doh_max_age(response)))
	return strings.to_string(b)
}

@(private)
h2_error :: proc(status: int, message: string) -> h2.Response {
	logx.debugf("doh/h2: replying %d %s", status, message)
	body := make([]u8, len(message) + 1, context.temp_allocator)
	copy(body, transmute([]u8)message)
	body[len(message)] = '\n'
	return h2.Response{status = status, content_type = "text/plain", body = body}
}
