package server

import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:h2"
import "elodin:logx"
import "elodin:tlsx"

/*
The DoH endpoint over HTTP/2 (RFC 8484 with RFC 9113 transport).

This is the path browsers take: Firefox and Chrome will only speak HTTP/2 to a
DoH resolver. It accepts the same two request forms as the HTTP/1.1 endpoint,
POST with an application/dns-message body and GET with a base64url `dns`
parameter.

Each request is answered on a fiber of its own rather than on the connection's
reader fiber, so the two lookups a browser issues for one name run at the same
time instead of one behind the other. Responses are written back under the
connection's write lock and may complete in any order.

Being the only stream transport that starts a query of its own per request, it is
also the only one that has to shed: past `server.max_pending` a request is
answered 503 here instead of adding to the queries the server is already behind
on. See `h2_handler`.
*/

@(private)
H2_Context :: struct {
	server:        ^Server,
	conn:          ^tlsx.Conn,
	client:        string,
	// The endpoint `client` was formatted from, which is what the rate limiter
	// needs: a prefix cannot be hashed back out of the printed form. See `Conn`,
	// where the other stream transports carry the same thing.
	peer:          net.Endpoint,
	path:          string,
	/*
	What the frame being read may take, reset by `h2_begin` where each one starts.

	The other transports bound a message this way and this one needs it for the
	same reason - see `Read_Budget`. An h2 connection is long-lived by design and
	nothing here shortens that: the wait for the next frame to start is still the
	whole of `client_timeout`, as it was when the socket option was the only bound.
	What it ends is the peer that trickles one byte inside every wait and so is
	never waited out at all, which before any stream exists - over the preface, or
	a frame header - held a connection with no request ever made.

	It is what one frame may take and not what one connection may. A peer that
	keeps completing frames would keep its connection, and a frame is not charged
	to `stream_rate_check` the way a DNS message is: SETTINGS, PING and an unknown
	type are no request at all. How long a connection may go without asking a
	question is `last_question`'s bound, and `doh_question_overdue` says why.
	*/
	budget:        Read_Budget,
	/*
	When this connection last asked a question or had one answered - or opened,
	before it has - for `doh_question_overdue`. Stamped once more when the answer
	is written, as over HTTP/1.1: the time a question takes is not time the
	connection asked nothing. The requests' fibers write it too, hence atomic.
	*/
	last_question: time.Tick,
	// Questions started on fibers of their own and not yet answered. A connection
	// waiting on one is not asking nothing, however slow the upstream.
	pending:       int,
}

@(private)
H2_Job :: struct {
	ctx:       ^H2_Context,
	h2conn:    ^h2.Conn,
	req:       ^h2.Request,
	// Counted in `H2_Context.pending`, and stamps `last_question` once answered.
	asked:     bool,
}

// Called by `h2.read_exact` where the preface, a frame header or a frame payload
// starts; `h2_read` then spends this budget across however many reads the peer
// splits that into.
@(private)
h2_begin :: proc(user: rawptr, starts_frame: bool) {
	ctx := cast(^H2_Context)user
	ctx.budget = Read_Budget {
		idle = client_timeout(ctx.server),
	}
	// A deadline that has already passed is a budget with nothing left, so the
	// read this begins fails and `h2.serve` ends the connection. Only where a
	// frame starts: a payload whose header is already read may be the question
	// that would have kept the connection, and cutting it there loses it.
	// `pending` first: the request's fiber stamps before it lets go of it.
	if !starts_frame || sync.atomic_load(&ctx.pending) != 0 {
		return
	}
	now := time.tick_now()
	if doh_question_overdue(ctx.server, {sync.atomic_load(&ctx.last_question._nsec)}, now) {
		ctx.budget.deadline = now
	}
}

@(private)
h2_read :: proc(user: rawptr, buf: []u8) -> (n: int, ok: bool) {
	ctx := cast(^H2_Context)user
	return conn_read_budgeted(Conn{tls = ctx.conn, peer = ctx.peer}, buf, &ctx.budget)
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
		server        = s,
		conn          = conn,
		client        = client,
		peer          = peer,
		path          = startup_config(s).listeners.doh.path,
		last_question = time.tick_now(),
	}

	io := h2.IO {
		user  = &ctx,
		read  = h2_read,
		write = h2_write,
		begin = h2_begin,
	}
	hc := h2.make_conn(io, h2_handler, &ctx)
	// A response waits no longer for flow-control credit than the connection
	// waits for anything else, so a client that stops reading cannot hold a
	// query in flight past its welcome.
	hc.write_timeout = client_timeout(s)

	h2.serve(hc)
	// `ctx` and the TLS connection live in this frame, so every handler must be
	// finished with them before it returns.
	h2.conn_wait_idle(hc)
	h2.conn_unref(hc)
}

@(private)
h2_handler :: proc(hc: ^h2.Conn, req: ^h2.Request) {
	ctx := cast(^H2_Context)hc.user

	// The access list in effect, which a reload may have narrowed since this
	// connection was accepted; see `stream_source_allowed`.
	if !stream_source_allowed(ctx.server, ctx.peer, .DoH) {
		h2.respond(hc, req.stream_id, h2.Response{status = 403})
		h2.request_destroy(hc, req)
		return
	}

	/*
	Charged before the request's query is started, which is the order the UDP
	loop charges in and for the same reason: a request that is not going to be
	answered is work not worth doing, and starting it is work.

	Only requests that are questions, as `h2_shed`'s counter is: the budget is
	denominated in answers to questions, and a .mobileconfig download, a scanner's
	404 and a POST that names the wrong content type are none of them one - see the
	note in `serve_doh_request`, which charges at the same point for the same
	reason. `h2_charged` is what says which is which.

	The limiter is looked at before `h2_charged` is asked, rather than left to
	`stream_rate_check` to shrug off: deciding whether a request is a query means
	decoding a GET's `dns` parameter, and with the budget switched off that is a
	base64 decode per request, on the connection's reader fiber, for an answer
	nothing then reads.

	A question is also what keeps the connection - see `doh_question_overdue` -
	and with no limiter every request counts as one. Nothing is charged for
	anything then, so a 404 holds a connection no more cheaply than a query does,
	and telling them apart would be the base64 decode the note above avoids.
	*/
	now := time.tick_now()
	asked, limited: bool
	max_pending: int
	{
		/*
		Pinned for the charge and the in-flight bound, and let go before anything
		below writes to the client. A 429 or a 503 is a HEADERS frame written on
		this fiber, which waits on a client that is not reading for up to the
		write timeout, and a generation pinned across that wait is one a reload
		cannot release - for as long as the client keeps it up.
		*/
		pin_scope(ctx.server)
		limiter := live(ctx.server).limiter
		asked = limiter == nil || h2_charged(ctx, req)
		if asked {
			sync.atomic_store(&ctx.last_question._nsec, now._nsec)
		}
		limited = limiter != nil && asked && !stream_rate_check(limiter, ctx.peer, now)
		max_pending = live(ctx.server).cfg.server.max_pending
	}
	if limited {
		h2_rate_limited(ctx, hc, req)
		return
	}

	job := new(H2_Job)
	job.ctx = ctx
	job.h2conn = hc
	job.req = req
	job.asked = asked
	if asked {
		sync.atomic_add(&ctx.pending, 1)
	}

	// The job outlives this call, so it needs its own reference; its fiber may
	// still be running it after the reader has gone.
	h2.conn_ref(hc)
	/*
	Shed rather than start once `max_pending` queries are in flight, the same
	bound the UDP read loop applies before it starts one.

	This is the only stream transport that starts a query of its own per request
	- the others answer on their connection's own fiber, one at a time, so
	`max_connections` is what bounds them. Without this the operator's bound
	sheds UDP at a few hundred while HTTP/2 runs up to `max_connections` x
	`MAX_HELD_STREAMS` queries, each holding its buffered body, beside it.

	`submit_query` decides and counts in one step: there is a reader per
	connection here, on every loop, and a check followed by a start is a gap all
	of them can pass through at once.
	*/
	switch submit_query(ctx.server, h2_job, job, max_pending) {
	case .Accepted:
	case .Full:
		if asked {
			sync.atomic_sub(&ctx.pending, 1)
		}
		h2.conn_unref(hc)
		free(job)
		h2_shed(ctx, hc, req, max_pending)
	case .Stopped:
		if can_detach(ctx.server) {
			/*
			A server with loops stops its connections before its loops, so what
			refused this start is a stack that could not be mapped. Shed, as at
			`max_pending`: answered here instead, the reader would stop reading
			for an upstream round trip, and a body past the client's window would
			park on a WINDOW_UPDATE only this reader could read.
			*/
			if asked {
				sync.atomic_sub(&ctx.pending, 1)
			}
			h2.conn_unref(hc)
			free(job)
			h2_shed(ctx, hc, req, max_pending, spawn_failed = true)
			report_query_spawn_failure(.DoH)
			return
		}
		// No loop to start it on - a `Server` built as a literal, driven from a
		// test's own thread: answered inline, on the connection's own fiber, as a
		// query `max_pending` does not count, and so one of the connections' for
		// the chain-walk bound too.
		h2_answer(job, .Connection)
	}
}

/*
Turn one request away, on the connection's reader fiber.

Answered rather than dropped: unlike a datagram, the stream is a client sitting
on an open connection, and a status tells it to come back later instead of
leaving it to time out.

Answered with no body, which is the part that matters. A body goes out through
`h2.write_body`, which parks on flow-control credit until the write timeout when
the client is not reading - and this is the fiber that would have read the
WINDOW_UPDATE releasing it. Parking here stops the connection reading anything,
including the WINDOW_UPDATEs that release the requests already writing to it, so
a shed that can stall the reader deepens the overload it exists to relieve.
HEADERS are not flow-controlled, so a status on its own cannot park.

Nothing is freed here beyond the request: this runs on the arena `h2.serve` is
still working through, which is also why it is not reached through `h2_job`.
*/
@(private)
h2_shed :: proc(
	ctx: ^H2_Context,
	hc: ^h2.Conn,
	req: ^h2.Request,
	max_pending: int,
	// Whether the bound was not what refused it: a stack that could not be
	// mapped, which raising `max_pending` would only make more of.
	spawn_failed := false,
) {
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
	in-flight bound, or from a stack the OS would not map, rather than from a
	broken endpoint - and which, since the two want opposite remedies. Without it
	a shed off the DoH path leaves no trace anywhere at all.

	Nothing is released after it: `h2.serve` resets this arena between frames,
	which is the same reason `h2_error` can format on this fiber.
	*/
	if spawn_failed {
		logx.debugf(
			"doh/h2: shedding a request from %s, the OS would not map a stack for it; check the memory limits and vm.max_map_count",
			ctx.client,
		)
	} else {
		logx.debugf(
			"doh/h2: shedding a request from %s, server.max_pending (%d) is reached",
			ctx.client,
			max_pending,
		)
	}
	h2.respond(hc, req.stream_id, h2.Response{status = 503})
	h2.request_destroy(hc, req)
}

/*
Turn one request away for being over the response budget.

The shape is `h2_shed`'s and for the same reasons: on the connection's reader
fiber, a status and no body. A body goes out through `h2.write_body`, which parks
on flow-control credit that this fiber is the one that would read the
WINDOW_UPDATE for - and this path is reached by precisely the client that is
sending faster than it is being answered, so a refusal that can stall the reader
would deepen what it exists to relieve.

Not counted here. `stream_rate_check` has already counted it as limited=, which
is the figure that says the budget is what turned the request away; dropped= is
about queries this server could not keep up with, and `h2_shed` is where that is
counted.

The stream is refused rather than the connection closed, which is where this
parts company with the length-prefixed transports. There is no way to say "this
connection is over its budget" in HTTP/2 short of GOAWAY, and one over-limit
stream is not a reason to take the requests in flight beside it down as well: a
browser has a handful open on one connection, and they were not all sent by
whatever is flooding. A client that keeps asking keeps being answered 429, which
costs it a stream and this server a HEADERS frame. `serve_doh_request` keeps its
connection for the second half of that reason, having been measured paying a TLS
handshake per refusal for the want of it.
*/
@(private)
h2_rate_limited :: proc(ctx: ^H2_Context, hc: ^h2.Conn, req: ^h2.Request) {
	// Nothing is released after the line, as in `h2_shed`: `h2.serve` resets this
	// arena between frames.
	//
	// The setting is named with the same caveat `report_rate_limited` carries:
	// with `server.rate_limit.overrides` in the file, the figure that refused
	// this client is the top-level one only where no entry names its network.
	logx.debugf(
		"doh/h2: refusing a request from %s, its prefix is over server.rate_limit.responses_per_second - or, where server.rate_limit.overrides names this client's network, over that entry's figure",
		ctx.client,
	)
	h2.respond(hc, req.stream_id, h2.Response{status = 429})
	h2.request_destroy(hc, req)
}

@(private)
h2_job :: proc(data: rawptr) {
	s := (^H2_Job)(data).ctx.server
	// The fiber's own scratch, and the query's count, both for exactly this job.
	defer {
		free_all(context.temp_allocator)
		query_done(s)
	}
	h2_answer(data)
}

/*
Answer one request.

Split from `h2_job` because the shutdown path above runs it inline on the
connection's reader fiber, whose scratch holds the frame `h2.serve` is still
working through — resetting it there would free the ground from under it.
*/
@(private)
h2_answer :: proc(data: rawptr, pool := dnssec.Walk_Pool.Shared) {
	job := cast(^H2_Job)data
	hc := job.h2conn
	req := job.req
	ctx := job.ctx
	defer {
		// Before the reference goes: `ctx` lives only as long as the connection.
		if job.asked {
			sync.atomic_store(&ctx.last_question._nsec, time.tick_now()._nsec)
			sync.atomic_sub(&ctx.pending, 1)
		}
		h2.request_destroy(hc, req)
		h2.conn_unref(hc)
		free(job)
	}

	resp, ok := build_h2_response(ctx, req, pool)
	if !ok {
		return
	}
	resp.head = req.method == "HEAD"
	// A body waits on the client's flow-control credit, up to the write timeout,
	// parked: a client that stops reading holds this query in flight and its
	// fiber, and nothing else.
	h2.respond(hc, req.stream_id, resp)
}

/*
Whether this request is one the response budget is denominated in.

Answered on the connection's reader fiber, because that is where the charge is,
and answerable there because none of it is a lookup: the endpoint is a string
compare and the rest is the request as it arrived. Without it the budget was spent
by anything at all addressed to the DNS path - a POST with the wrong content type,
a `dns` parameter that is not base64, twelve bytes short of a header - none of
which reach the resolver, the cache or an upstream, and all of which could
therefore starve the clients sharing their prefix while costing this server
nothing it needed a budget for. The HTTP/1.1 endpoint has always charged after
these same checks; this is that, one fiber earlier.
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
answers - is this a query? - a fiber before the message itself is wanted, and
the two must agree: a request charged here and refused there would spend a budget
on a 400, and one refused here and charged there would let the same 400 through
for free.

Called twice per query as a result, once for the verdict and once for the
message. What the second call costs is a base64 decode of a `:path` that HPACK's
`MAX_HEADER_LIST` already bounds at 32 KiB, which is cheaper than the alternative:
the decode lands in `context.temp_allocator`, and on the reader fiber that is the
scratch `h2.serve` resets between frames, so carrying it across to the request's
fiber would
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
		if !doh_content_type_ok(req.content_type) {
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
build_h2_response :: proc(
	ctx: ^H2_Context,
	req: ^h2.Request,
	// Which queries this one is among; see `handle_query`'s `pool`.
	pool := dnssec.Walk_Pool.Shared,
) -> (
	resp: h2.Response,
	ok: bool,
) {
	path, _ := h2_split_path(req.path)

	mc_path := startup_config(ctx.server).listeners.doh.mobileconfig_path
	if mc_path != "" && path == mc_path {
		return build_h2_mobileconfig(ctx, req)
	}
	if path != ctx.path {
		return h2_error(404, "not found"), true
	}

	// The status is built here rather than by the check, so that the refusal is
	// logged and formatted once - on the request's fiber, by the call that wants
	// the message - and not again by `h2_charged` on the reader fiber.
	message, status, why, is_query := h2_query_message(req)
	if !is_query {
		return h2_error(status, why, DOH_METHODS if status == 405 else ""), true
	}

	max_age: u32
	answer, _, handled := handle_query(
		ctx.server,
		message,
		.DoH,
		ctx.client,
		context.temp_allocator,
		pool = pool,
		max_age = &max_age,
	)
	if !handled || len(answer) == 0 {
		return h2_error(500, "no response"), true
	}

	return h2.Response {
			status = 200,
			content_type = DOH_CONTENT_TYPE,
			cache_control = h2_cache_control(max_age),
			body = answer,
		},
		true
}

/*
Answer the .mobileconfig endpoint over HTTP/2.

The HTTP/1.1 endpoint's twin: a GET returns the Apple profile, the URL inside it
built from the request's `:authority` - the HTTP/2 spelling of `Host` - so a
stream carrying none, or one for a host this server has no certificate for, is
turned away rather than handed a profile that names an unreachable host. The
profile is signed, and refused rather than served unsigned; see
`serve_doh_mobileconfig`, whose answers this mirrors.
*/
@(private)
build_h2_mobileconfig :: proc(ctx: ^H2_Context, req: ^h2.Request) -> (resp: h2.Response, ok: bool) {
	if req.method != "GET" {
		return h2_error(405, "method not allowed", MOBILECONFIG_METHODS), true
	}
	if !valid_mobileconfig_host(req.authority) {
		return h2_error(400, "missing or invalid :authority"), true
	}
	profile, status := profile_for_host(
		ctx.server.profiles,
		req.authority,
		tlsx.unix_now(),
		context.temp_allocator,
	)
	switch status {
	case .Unknown_Host:
		return h2_error(400, "not a host and port this server serves"), true
	case .Unavailable:
		return h2_error(503, "profile signing unavailable"), true
	case .OK:
	}
	return h2.Response {
			status = 200,
			content_type = DOH_MOBILECONFIG_CONTENT_TYPE,
			body = profile,
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
h2_cache_control :: proc(max_age: u32) -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "max-age=")
	strings.write_int(&b, int(max_age))
	return strings.to_string(b)
}

@(private)
h2_error :: proc(status: int, message: string, allow := "") -> h2.Response {
	logx.debugf("doh/h2: replying %d %s", status, message)
	body := make([]u8, len(message) + 1, context.temp_allocator)
	copy(body, transmute([]u8)message)
	body[len(message)] = '\n'
	return h2.Response{status = status, content_type = "text/plain", allow = allow, body = body}
}
