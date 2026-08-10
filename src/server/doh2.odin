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

	/*
	Shed rather than queue once the backlog is past what the workers can work
	through, the same bound the UDP read loop applies before it queues.

	This is the only transport that hands its work to the pool - the others
	answer on their own connection thread, so `max_connections` is what bounds
	them. Without this check the operator's backlog limit sheds UDP at a few
	hundred while HTTP/2 queues up to `max_connections` x `MAX_CONCURRENT`
	streams, each holding its buffered body, in front of it.

	Answered rather than dropped: unlike a datagram, the stream is a client
	sitting on an open connection, and 503 tells it to come back later instead
	of leaving it to time out. The answer is built on the reader thread and must
	not reset its arena - `h2.serve` is still working through the frame that
	brought us here - which is why this does not go through `h2_job`.
	*/
	if limit := ctx.server.cfg.server.max_pending; limit > 0 {
		if pool.pending(ctx.server.handler_pool) >= limit {
			sync.atomic_add(&ctx.server.stats.dropped, 1)
			h2.respond(hc, req.stream_id, h2_error(503, "server too busy"))
			h2.request_destroy(hc, req)
			return
		}
	}

	job := new(H2_Job)
	job.ctx = ctx
	job.h2conn = hc
	job.req = req

	// The job outlives this call, so it needs its own reference; the pool may
	// still be running it after the reader thread has gone.
	h2.conn_ref(hc)
	if !pool.submit(ctx.server.handler_pool, h2_job, job) {
		// Shutting down: answer inline rather than dropping the stream.
		h2_answer(job)
	}
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
	// The :path pseudo-header carries the query string too.
	path := req.path
	query := ""
	if idx := strings.index_byte(path, '?'); idx >= 0 {
		query = path[idx + 1:]
		path = path[:idx]
	}

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
