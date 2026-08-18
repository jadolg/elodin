package server

import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
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
	// The endpoint `client` was formatted from, which is what the rate limiter
	// needs: a prefix cannot be hashed back out of the printed form. See `Conn`,
	// where the other stream transports carry the same thing.
	peer:   net.Endpoint,
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
serve_doh2 :: proc(s: ^Server, conn: ^tlsx.Conn, client: string, peer: net.Endpoint) {
	ctx := H2_Context {
		server = s,
		conn   = conn,
		client = client,
		peer   = peer,
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
	Charged before the request is queued, which is the order the UDP loop charges
	in and for the same reason: a request that is not going to be answered is work
	not worth doing, and queueing is work.

	Only requests that are questions, as `h2_shed`'s counter is: the budget is
	denominated in answers to questions, and a .mobileconfig download, a scanner's
	404 and a POST that names the wrong content type are none of them one - see the
	note in `serve_doh_request`, which charges at the same point for the same
	reason. `h2_charged` is what says which is which.

	The limiter is looked at before `h2_charged` is asked, rather than left to
	`stream_rate_check` to shrug off: deciding whether a request is a query means
	decoding a GET's `dns` parameter, and with the budget switched off that is a
	base64 decode per request, on the connection's reader thread, for an answer
	nothing then reads.
	*/
	if ctx.server.limiter != nil &&
	   h2_charged(ctx, req) &&
	   !stream_rate_check(ctx.server.limiter, ctx.peer, time.tick_now()) {
		h2_rate_limited(ctx, hc, req)
		return
	}

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

/*
Turn one request away for being over the response budget.

The shape is `h2_shed`'s and for the same reasons: on the connection's reader
thread, a status and no body. A body goes out through `h2.write_body`, which parks
on flow-control credit that this thread is the one that would read the
WINDOW_UPDATE for - and this path is reached by precisely the client that is
sending faster than it is being answered, so a refusal that can stall the reader
would deepen what it exists to relieve.

Not counted here. `stream_rate_check` has already counted it as limited=, which
is the figure that says the budget is what turned the request away; dropped= is
about queries this server could not keep up with, and `h2_shed` is where that is
counted.

The stream is refused rather than the connection closed, which is where this
parts company with the other three transports. There is no way to say "this
connection is over its budget" in HTTP/2 short of GOAWAY, and one over-limit
stream is not a reason to take the requests in flight beside it down as well: a
browser has a handful open on one connection, and they were not all sent by
whatever is flooding. A client that keeps asking keeps being answered 429, which
costs it a stream and this server a HEADERS frame.
*/
@(private)
h2_rate_limited :: proc(ctx: ^H2_Context, hc: ^h2.Conn, req: ^h2.Request) {
	// Nothing is released after the line, as in `h2_shed`: `h2.serve` resets this
	// arena between frames.
	logx.debugf(
		"doh/h2: refusing a request from %s, its prefix is over server.rate_limit.responses_per_second",
		ctx.client,
	)
	h2.respond(hc, req.stream_id, h2.Response{status = 429})
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

/*
Whether this request is one the response budget is denominated in.

Answered on the connection's reader thread, because that is where the charge is,
and answerable there because none of it is a lookup: the endpoint is a string
compare and the rest is the request as it arrived. Without it the budget was spent
by anything at all addressed to the DNS path - a POST with the wrong content type,
a `dns` parameter that is not base64, twelve bytes short of a header - none of
which reach the resolver, the cache or an upstream, and all of which could
therefore starve the clients sharing their prefix while costing this server
nothing it needed a budget for. The HTTP/1.1 endpoint has always charged after
these same checks; this is that, one thread earlier.
*/
@(private)
h2_charged :: proc(ctx: ^H2_Context, req: ^h2.Request) -> bool {
	endpoint, _ := h2_split_path(req.path)
	if endpoint != ctx.path {
		return false
	}
	_, _, _, is_query := h2_query_message(req)
	return is_query
}

/*
The DNS message a request to the DoH endpoint is asking about, or the status that
says it was not asking about one.

Split out of `build_h2_response` because `h2_charged` needs the question it
answers - is this a query? - a thread before the message itself is wanted, and
the two must agree: a request charged here and refused there would spend a budget
on a 400, and one refused here and charged there would let the same 400 through
for free.

Called twice per query as a result, once for the verdict and once for the
message. What the second call costs is a base64 decode of a `:path` that HPACK's
`MAX_HEADER_LIST` already bounds at 32 KiB, which is cheaper than the alternative:
the decode lands in `context.temp_allocator`, and on the reader thread that is the
arena `h2.serve` resets between frames, so carrying it across to the worker would
mean copying every message out to the heap - a cost on every query, to save a
decode on the ones a browser sends by GET.
*/
@(private)
h2_query_message :: proc(
	req: ^h2.Request,
) -> (
	message: []u8,
	status: int,
	why: string,
	ok: bool,
) {
	_, query := h2_split_path(req.path)
	switch req.method {
	case "POST":
		if req.content_type != "" && !strings.has_prefix(req.content_type, DOH_CONTENT_TYPE) {
			return nil, 415, "unsupported media type", false
		}
		message = req.body
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
	return message, 0, "", true
}

@(private)
build_h2_response :: proc(ctx: ^H2_Context, req: ^h2.Request) -> (resp: h2.Response, ok: bool) {
	path, _ := h2_split_path(req.path)

	mc_path := ctx.server.cfg.listeners.doh.mobileconfig_path
	if mc_path != "" && path == mc_path {
		return build_h2_mobileconfig(ctx, req)
	}
	if path != ctx.path {
		return h2_error(404, "not found"), true
	}

	// The status is built here rather than by the check, so that the refusal is
	// logged and formatted once - on the worker, by the call that wants the message
	// - and not again by `h2_charged` on the reader thread.
	message, status, why, is_query := h2_query_message(req)
	if !is_query {
		return h2_error(status, why), true
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

/*
Answer the .mobileconfig endpoint over HTTP/2.

The HTTP/1.1 endpoint's twin: a GET returns the Apple profile, the URL inside it
built from the request's `:authority` - the HTTP/2 spelling of `Host` - so a
stream carrying none, or one for a host this server has no certificate for, is
turned away rather than handed a profile that names an unreachable host.
*/
@(private)
build_h2_mobileconfig :: proc(ctx: ^H2_Context, req: ^h2.Request) -> (resp: h2.Response, ok: bool) {
	if req.method != "GET" {
		return h2_error(405, "method not allowed"), true
	}
	if !valid_mobileconfig_host(req.authority) {
		return h2_error(400, "missing or invalid :authority"), true
	}
	profile := build_doh_mobileconfig(req.authority, ctx.path, context.temp_allocator)
	return h2.Response {
			status = 200,
			content_type = DOH_MOBILECONFIG_CONTENT_TYPE,
			body = transmute([]u8)profile,
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
