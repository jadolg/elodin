package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"
import "elodin:logx"
import "elodin:tlsx"

Error :: enum u8 {
	None,
	Not_Resolved,
	Dial_Failed,
	Timeout,
	IO_Error,
	Bad_Response,
	TLS_Failed,
	// The peer's certificate did not check out, as distinct from a handshake
	// that failed outright. Worth separating: one is a configuration or trust
	// problem, the other is usually the network.
	Verify_Failed,
	HTTP_Error,
	Too_Large,
	Unhealthy,
}

@(private)
Idle_Conn :: struct {
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
	since:  time.Time,
}

// Which protocol an HTTPS upstream turned out to speak, discovered from ALPN
// on the first connection and then treated as sticky.
@(private)
Protocol :: enum u8 {
	Unknown,
	H1,
	H2,
}

/*
A shared HTTP/2 connection plus what owns it.

`stopping` exists because closing a socket does not reliably wake a thread
already blocked in a read on it (the same reason itest/mock.odin polls rather
than relying on close to interrupt a loop): the reader thread's socket carries
a short receive timeout so it wakes on its own and can notice this flag,
bounding teardown instead of depending on the close below to cut its read
short.
*/
@(private)
H2_Conn :: struct {
	stream:   Stream,
	client:   ^h2.Client,
	thread:   ^thread.Thread,
	stopping: bool,
}

Upstream :: struct {
	spec:         config.Upstream_Spec,
	endpoint:     net.Endpoint,
	resolved:     bool,
	tls_ctx:      ^tlsx.Context,

	mu:           sync.Mutex,
	idle:         [dynamic]Idle_Conn,
	max_idle:     int,
	idle_timeout: time.Duration,

	// HTTPS only. `proto` is set once ALPN has settled it and never changes
	// back; `h2_cond` and `connecting` make concurrent first callers share one
	// handshake instead of each racing to open their own.
	proto:      Protocol,
	h2_cond:    sync.Cond,
	connecting: bool,
	h2:         ^H2_Conn,

	// Consecutive failures; a run of them parks the upstream for a cooldown so
	// a dead server stops costing every query a full timeout.
	failures:     u32,
	down_until:   time.Time,

	stats:        Stats,
	allocator:    mem.Allocator,
}

Stats :: struct {
	queries:  u64,
	failures: u64,
	latency_ns_total: u64,
}

// After this many consecutive failures an upstream is skipped for COOLDOWN.
FAILURE_THRESHOLD :: 3
COOLDOWN :: 10 * time.Second

make_upstream :: proc(
	spec: config.Upstream_Spec,
	max_idle: int,
	idle_timeout: time.Duration,
	allocator := context.allocator,
) -> (
	u: ^Upstream,
	err: Error,
) {
	u = new(Upstream, allocator)
	u.spec = spec
	u.allocator = allocator
	u.max_idle = max(max_idle, 0)
	u.idle_timeout = idle_timeout
	u.idle = make([dynamic]Idle_Conn, 0, max(max_idle, 1), allocator)

	#partial switch spec.kind {
	case .TLS:
		ctx, terr := tlsx.client_context(spec.verify, "", nil, allocator)
		if terr != .None {
			logx.errorf("upstream %s: cannot create TLS context: %s", spec.name, tlsx.describe_error(terr, context.temp_allocator))
			return nil, .TLS_Failed
		}
		u.tls_ctx = ctx
	case .HTTPS:
		// h2 first: preferring it is what lets a resolver that only accepts
		// HTTP/2 be used at all, and ALPN falls back to http/1.1 for the ones
		// that do not offer h2.
		ctx, terr := tlsx.client_context(spec.verify, "", []string{"h2", "http/1.1"}, allocator)
		if terr != .None {
			logx.errorf("upstream %s: cannot create TLS context: %s", spec.name, tlsx.describe_error(terr, context.temp_allocator))
			return nil, .TLS_Failed
		}
		u.tls_ctx = ctx
	}

	resolve_endpoint(u)
	return u, .None
}

destroy :: proc(u: ^Upstream) {
	if u == nil {
		return
	}
	close_idle(u, all = true)
	delete(u.idle)
	teardown_h2(u)
	tlsx.context_destroy(u.tls_ctx)
	free(u, u.allocator)
}

/*
Work out the address to dial.

An IP literal is used as-is. A hostname is resolved through the configured
bootstrap resolvers rather than the system resolver, because on a machine where
elodin *is* the system resolver, asking it to resolve its own upstream would
deadlock at boot.
*/
@(private)
resolve_endpoint :: proc(u: ^Upstream) -> bool {
	if addr := net.parse_address(u.spec.address); addr != nil {
		u.endpoint = net.Endpoint {
			address = addr,
			port    = u.spec.port,
		}
		u.resolved = true
		return true
	}

	addr, ok := bootstrap_resolve(u.spec.bootstrap, u.spec.address)
	if !ok {
		logx.warnf("upstream %s: cannot resolve %q via bootstrap resolvers", u.spec.name, u.spec.address)
		u.resolved = false
		return false
	}
	u.endpoint = net.Endpoint {
		address = addr,
		port    = u.spec.port,
	}
	u.resolved = true
	logx.debugf("upstream %s: resolved %s to %s", u.spec.name, u.spec.address, net.address_to_string(addr, context.temp_allocator))
	return true
}

healthy :: proc(u: ^Upstream) -> bool {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	if u.failures < FAILURE_THRESHOLD {
		return true
	}
	return time.diff(u.down_until, time.now()) >= 0
}

@(private)
record_success :: proc(u: ^Upstream, elapsed: time.Duration) {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.failures = 0
	u.stats.queries += 1
	u.stats.latency_ns_total += u64(elapsed)
}

@(private)
record_failure :: proc(u: ^Upstream) {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.failures += 1
	u.stats.queries += 1
	u.stats.failures += 1
	if u.failures == FAILURE_THRESHOLD {
		u.down_until = time.time_add(time.now(), COOLDOWN)
		logx.warnf("upstream %s: %d consecutive failures, pausing it for %v", u.spec.name, u.failures, COOLDOWN)
	} else if u.failures > FAILURE_THRESHOLD {
		u.down_until = time.time_add(time.now(), COOLDOWN)
	}
}

stats_of :: proc(u: ^Upstream) -> Stats {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	return u.stats
}

/*
Send one query and return the response bytes.

`query` is the client's message verbatim; the caller owns the transaction ID and
is responsible for restoring it on the way back out. The returned buffer belongs
to `allocator`.
*/
exchange :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator := context.allocator,
) -> (
	response: []u8,
	err: Error,
) {
	if !u.resolved && !resolve_endpoint(u) {
		return nil, .Not_Resolved
	}

	start := time.now()
	switch u.spec.kind {
	case .UDP:
		response, err = exchange_udp(u, query, timeout, allocator)
	case .TCP:
		response, err = exchange_tcp(u, query, timeout, allocator)
	case .TLS:
		response, err = exchange_dot(u, query, timeout, allocator)
	case .HTTPS:
		response, err = exchange_doh(u, query, timeout, allocator)
	}

	if err != .None {
		record_failure(u)
		return nil, err
	}
	record_success(u, time.diff(start, time.now()))
	return response, .None
}

// Confirm a reply belongs to the query we sent: matching ID, the QR bit set, and
// the same question. Without this an off-path packet could be taken as an answer.
@(private)
response_matches :: proc(query, response: []u8) -> bool {
	if len(response) < dns.HEADER_SIZE || len(query) < dns.HEADER_SIZE {
		return false
	}
	if response[0] != query[0] || response[1] != query[1] {
		return false
	}
	if response[2] & 0x80 == 0 {
		return false
	}

	qq, qok := dns.peek_question(query, context.temp_allocator)
	if !qok {
		// A query with no question (a bare NOTIFY, say) has nothing to compare.
		return true
	}
	rq, rok := dns.peek_question(response, context.temp_allocator)
	if !rok {
		return false
	}
	return qq.type == rq.type && qq.class == rq.class && dns.name_equal_fold(qq.name, rq.name)
}

@(private)
take_idle :: proc(u: ^Upstream) -> (conn: Idle_Conn, ok: bool) {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)

	now := time.now()
	for len(u.idle) > 0 {
		conn = pop(&u.idle)
		if time.diff(conn.since, now) < u.idle_timeout {
			return conn, true
		}
		close_conn(conn)
	}
	return {}, false
}

@(private)
put_idle :: proc(u: ^Upstream, conn: Idle_Conn) {
	sync.mutex_lock(&u.mu)
	if len(u.idle) >= u.max_idle {
		sync.mutex_unlock(&u.mu)
		close_conn(conn)
		return
	}
	c := conn
	c.since = time.now()
	append(&u.idle, c)
	sync.mutex_unlock(&u.mu)
}

@(private)
close_conn :: proc(conn: Idle_Conn) {
	if conn.tls != nil {
		tlsx.close(conn.tls)
		return
	}
	net.close(conn.socket)
}

// Drop idle connections, either the expired ones or every one of them.
close_idle :: proc(u: ^Upstream, all := false) -> (closed: int) {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)

	now := time.now()
	kept := make([dynamic]Idle_Conn, 0, len(u.idle), context.temp_allocator)
	for conn in u.idle {
		if all || time.diff(conn.since, now) >= u.idle_timeout {
			close_conn(conn)
			closed += 1
		} else {
			append(&kept, conn)
		}
	}
	clear(&u.idle)
	for conn in kept {
		append(&u.idle, conn)
	}
	return
}
