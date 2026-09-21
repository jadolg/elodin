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
	// The peer reset the connection before the handshake even began - a dial
	// that never really failed so much as landed on a socket the other side
	// had already decided to drop. Kept distinct from `Dial_Failed` so it can
	// be retried the same way a reset mid-handshake is.
	Dial_Reset,
	Timeout,
	IO_Error,
	/*
	The peer closed or reset a connection without answering on it.

	Kept apart from `IO_Error` because it is not evidence the server is down,
	and `record_failure` reads it that way. Every DNS-over-TCP peer recycles
	connections - both of the public resolvers this was measured against close
	an idle one inside fifteen seconds - so a query landing on one that has
	just been recycled is ordinary operation, not an outage. Counting it
	towards the health cooldown parks a server that is answering perfectly
	well, and with it every query that would have gone there.

	What still counts is everything that says the server itself is not
	reachable or not answering: a dial that failed, a handshake that failed, a
	connection that went quiet until the timeout.
	*/
	Peer_Closed,
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
	// HTTP/1.1 only, which is the one transport left that can do nothing but
	// one request per connection at a time. See `pipe` below for the rest.
	idle:         [dynamic]Idle_Conn,
	max_idle:     int,
	idle_timeout: time.Duration,
	// The shortest idle gap after which this upstream was found to have hung
	// up, or zero while it never has; see `note_idle_death`. Under `mu`.
	idle_died:    time.Duration,
	// When that figure was last learned, so it can be forgotten and learned
	// again; see `pipe_relearn_idle_locked`. Under `mu`.
	idle_learned: time.Time,
	// Consecutive exchanges that ended in `Peer_Closed` after the retry had
	// also been hung up on; see `record_failure`. Under `mu`.
	closed_run:   int,

	// `conn_cond` and `connecting` make concurrent first callers share one
	// handshake instead of each racing to open their own. Used by both shared
	// connections below, which no upstream has at once - `spec.kind` picks one.
	conn_cond:  sync.Cond,
	connecting: bool,

	// HTTPS only. `proto` is set once ALPN has settled it and never changes
	// back.
	proto:      Protocol,
	h2:         ^H2_Conn,

	// The one connection everything this upstream sends over a stream is
	// pipelined onto: `tcp` and `tls` throughout, and a `udp` upstream's retry
	// of a truncated answer. See pipeline.odin.
	pipe:       ^Pipe_Conn,
	// Queries that connection may carry at once, from
	// `PIPELINE_MAX_OUTSTANDING`. Per upstream rather than a constant read
	// where it is used, so a test can reach the overflow path without the
	// hundreds of threads the shipped figure would need - and so it has
	// somewhere to come from should it ever be derived from the worker counts.
	max_outstanding: int,

	// Whether queries to this server carry a DNS cookie. The client half is
	// fixed at construction; the server half is learned and lives under `mu`.
	cookies:      bool,
	cookie:       Cookie,

	// Consecutive failures; a run of them parks the upstream for a cooldown so
	// a dead server stops costing every query a full timeout.
	failures:     u32,
	down_until:   time.Time,
	// Which kinds of failure this upstream has already been reported for, so
	// each one is said once at `warn` and left to `debug` after that; see
	// `record_failure`.
	reported:     bit_set[Error],

	stats:        Stats,
	allocator:    mem.Allocator,
}

Stats :: struct {
	queries:  u64,
	failures: u64,
	latency_ns_total: u64,
	// Replies from this server that the caller could not pass on because their
	// rcode is not one a client can read; see `note_unreadable_rcode`.
	unreadable_rcode: u64,
	// Replies from this server that another member of its group answered
	// instead; see `note_swept_rcode`.
	swept_rcode:      u64,
	/*
	The same failures as `failures`, split by what went wrong.

	`failures` alone says an upstream is failing and never which way, and the
	log cannot fill the gap: a kind is warned about once per process, so an
	operator reading a window of it sees whichever kinds happened to be new in
	that window and nothing about the rate of any of them. Which kind
	dominates is the whole diagnosis - a `Timeout` and a `TLS_Failed` against
	the same server are different problems with different fixes - so it is
	kept here, where a scrape can carry it continuously.

	Indexed by `Error`, so it sums to `failures` by construction rather than
	by a second call site remembering to keep the two in step.
	*/
	failure_kinds:    [Error]u64,
}

// After this many consecutive failures an upstream is skipped for COOLDOWN.
FAILURE_THRESHOLD :: 3
COOLDOWN :: 10 * time.Second

make_upstream :: proc(
	spec: config.Upstream_Spec,
	max_idle: int,
	idle_timeout: time.Duration,
	allocator := context.allocator,
	cookies := false,
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
	u.max_outstanding = PIPELINE_MAX_OUTSTANDING
	u.cookies = cookies
	init_cookie(u)

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
	u.closed_run = 0
	u.stats.queries += 1
	u.stats.latency_ns_total += u64(elapsed)
}

/*
Whether this is the first failure of its kind for this upstream.

`true` exactly once per upstream per member of `Error`, so a caller with
something to say about a failure says it once however often the failure comes
back. The caller holds `u.mu`; `first_failure_of_kind` is the same question
asked from outside the lock.
*/
@(private)
note_failure_kind :: proc(u: ^Upstream, err: Error) -> bool {
	if err in u.reported {
		return false
	}
	u.reported += {err}
	return true
}

/*
The same, for the transports that know more about a failure than its kind.

A TLS handshake carries a reason string that `Error` has no room for, and it is
worth more than the enum is: "certificate has expired" and "no application
protocol" are different problems that both arrive here as `TLS_Failed`. Asked
where the reason is still in hand, so the one line this failure gets is the one
with the reason on it and `record_failure` stays quiet about it afterwards.
*/
@(private)
first_failure_of_kind :: proc(u: ^Upstream, err: Error) -> bool {
	if u == nil {
		return false
	}
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	return note_failure_kind(u, err)
}

/*
Count one failed exchange, and say why the first time each kind happens.

The `warn` is once per upstream per kind of failure rather than per exchange:
an upstream that intermittently fails never reaches the threshold below, so
before this the only trace it left was a `debug` line nobody has on and a
counter nobody is scraping - which is how a member of a group can be failing
every few queries, with the rest of the group covering for it, and nothing in
the log says so. Once per kind bounds the output at the size of `Error` for
the life of the process, whatever the query rate does, and a recurrence is
still on the `debug` line `exchange` writes for every one.
*/
@(private)
record_failure :: proc(u: ^Upstream, err: Error) {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.stats.queries += 1
	u.stats.failures += 1
	u.stats.failure_kinds[err] += 1
	if note_failure_kind(u, err) {
		logx.warnf("upstream %s (%v %s): %v", u.spec.name, u.spec.kind, u.spec.address, err)
	}
	/*
	A recycled connection is not a reason to bench the server.

	`Peer_Closed` is the peer hanging up without answering, and this query has
	already been asked again on a connection of its own by the time it gets
	here - so what reaches this line is a second connection closed as well, on
	an upstream that may still be answering everything else. Every DNS-over-TCP
	server recycles connections; letting that trip the cooldown takes a working
	upstream out of service for `COOLDOWN` and sends every query in that window
	somewhere else, which is a far larger outage than the one query that failed.

	Measured on the instance this came from: three of these in a row happened
	often enough to park the preferred upstream roughly every two and a half
	minutes, while it was answering 97% of what it was asked.

	The trade, stated plainly: hang-ups cost a failover each instead of the
	upstream being skipped for ten seconds, and only a sustained run of them
	parks it - see the block below for where the exemption stops. That is the
	same bargain `note_unreadable_rcode` makes, and the figure that names such a
	server is `elodin_upstream_failure_kind_total{error="peer_closed"}` - which
	is why it has a kind of its own. Health is still tripped at once by
	everything that says the server is unreachable or silent: a failed dial, a
	failed handshake, a timeout.
	*/
	if err == .Peer_Closed {
		u.closed_run += 1
		/*
		Except when that is all the server ever does.

		A run of these is no longer one recycled connection: what reaches this
		line already had its retry on a connection of its own hung up on too,
		so `FAILURE_THRESHOLD` of them in a row is a server closing everything
		it accepts. Left exempt it would never be parked, and - because the
		retry dials - it would be asked for two connections per query for as
		long as it kept doing it, which is the opposite of kind to the peer
		whose limit on connections started this.

		So the exemption is for a run rather than forever, and past it these
		count like any other failure: the upstream is parked `FAILURE_THRESHOLD`
		further hang-ups later, and a single success anywhere in between clears
		the run. A resolver recycling an idle connection never gets near it -
		one hang-up costs a retry that works, and never reaches here at all.
		*/
		if u.closed_run < FAILURE_THRESHOLD {
			return
		}
	} else {
		u.closed_run = 0
	}
	u.failures += 1
	if u.failures >= FAILURE_THRESHOLD {
		u.down_until = time.time_add(time.now(), COOLDOWN)
		// A server that stopped sending cookies is a server whose every reply is
		// now discarded for the want of one, and that arrives here looking like
		// any other outage. Let the cooldown decide what it does rather than
		// hold it to what it used to do.
		forget_cookie(u)
	}
	if u.failures == FAILURE_THRESHOLD {
		logx.warnf(
			"upstream %s: %d consecutive failures (last: %v), pausing it for %v",
			u.spec.name,
			u.failures,
			err,
			COOLDOWN,
		)
	}
}

/*
Count a reply from `u` whose rcode the caller could not hand to a client.

Kept per upstream because that is the question the count has to answer. The line
the server logs for one of these is said once per process and demoted to debug
after it - the bytes behind it being ones an on-path attacker can write - so
without a figure carrying the name, an operator whose group has one broken
member has no way to tell which of them it is.

Health is deliberately untouched, for the reason `resolve_insisting` gives: a
reply like this arriving is not evidence the server is down, and treating it as
such would let a forged packet per query park every member of the group. So this
is the *only* trace such a server leaves in the numbers: `failures` stays where
it was and `healthy` goes on reporting it up.

Not counted by this package, which has no opinion about what a client can read -
`resolve_readable` sweeps past such a reply but a chain lookup may go on to use
one. The caller that refuses it is the caller that counts it.

Which means it names the server whose reply was refused, and only that one. A
sweep that found every member answering unreadably discarded the rest without
counting them, so a group with two broken members shows one of them - the first
asked - and the count is of refusals rather than of replies. That is the figure
the caller has to explain: one query, one refusal, one server to look at. The
second member surfaces the next time it is the one asked first.
*/
note_unreadable_rcode :: proc(u: ^Upstream) {
	if u == nil {
		return
	}
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.stats.unreadable_rcode += 1
}

/*
Count a reply from `u` that another member of its group answered instead.

The trace a swept member leaves, and the only one. `resolve_insisting` sweeps
past a SERVFAIL, a REFUSED or an unreadable rcode without touching health - the
server replied, and parking it over what it replied is what `note_unreadable_rcode`
argues against - so `failures` stays at zero, `healthy` goes on reporting it up,
and the client's query is answered and counted as forwarded. An upstream that
has stopped being able to answer anything is then invisible in every other
figure, while the group behind it quietly runs at two exchanges per query.

Counted by this package rather than by the caller, unlike `unreadable_rcode`:
the sweep is where the decision is made and where the member that was passed
over is known. It names that member and not the one that answered, which is the
question an operator has - which of these should I go and look at.

One per reply the group could not use, which is the figure to read it as, and
not the number of extra exchanges it caused: a group of four counts one for a
sweep that asks three of them, and a lone upstream counts one for a reply there
was nobody else to improve on. That last case is deliberate rather than
tolerated - the arrangement that most needs naming is a member REFUSING
everything beside a member in its cooldown, where the sweep finds nowhere to go
and every client query breaks while `failures` and `up` both look healthy. What
the sweep spends is a different question, and `elodin_upstream_queries_total`
per member already answers it.

Not confined to the rcodes a client's own question refuses, either.
`resolve_insisting` is shared with the chain lookups, where `answerable` will
take only NOERROR and NXDOMAIN, so a FORMERR or a NOTIMP to a `DS` lookup lands
here too.
*/
note_swept_rcode :: proc(u: ^Upstream) {
	if u == nil {
		return
	}
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.stats.swept_rcode += 1
}

/*
What a kind of failure is called on the metrics endpoint.

Spelled out rather than taken from `%v`, because these are label values an
operator's dashboards and alerting rules match on. Deriving them from the enum
would make renaming a member - an ordinary refactor with no outward meaning -
silently rename a label and break every query using it, with nothing in this
package to say so.
*/
error_label :: proc(e: Error) -> string {
	switch e {
	case .None:
		return "none"
	case .Not_Resolved:
		return "not_resolved"
	case .Dial_Failed:
		return "dial_failed"
	case .Dial_Reset:
		return "dial_reset"
	case .Timeout:
		return "timeout"
	case .IO_Error:
		return "io_error"
	case .Peer_Closed:
		return "peer_closed"
	case .Bad_Response:
		return "bad_response"
	case .TLS_Failed:
		return "tls_failed"
	case .Verify_Failed:
		return "verify_failed"
	case .HTTP_Error:
		return "http_error"
	case .Too_Large:
		return "too_large"
	case .Unhealthy:
		return "unhealthy"
	}
	return "unknown"
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
	// Never both: a cookie is for the transports with nothing authenticating
	// the peer, padding for the transports where a length is the only thing
	// left showing. `cookies_wanted` and `padding_wanted` name disjoint kinds.
	switch {
	case cookies_wanted(u):
		response, err = exchange_with_cookie(u, query, timeout, allocator)
	case padding_wanted(u):
		response, err = exchange_padded(u, query, timeout, allocator)
	case:
		response, err = send(u, query, timeout, allocator)
	}

	if err != .None {
		record_failure(u, err)
		logx.debugf(
			"upstream %s (%v %s:%d) failed after %v: %v",
			u.spec.name,
			u.spec.kind,
			u.spec.address,
			u.spec.port,
			time.diff(start, time.now()),
			err,
		)
		return nil, err
	}
	record_success(u, time.diff(start, time.now()))
	return response, .None
}

// One round trip over whichever transport this upstream speaks.
@(private)
send :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	switch u.spec.kind {
	case .UDP:
		return exchange_udp(u, query, timeout, allocator)
	case .TCP, .TLS:
		return exchange_pipelined(u, query, timeout, allocator)
	case .HTTPS:
		return exchange_doh(u, query, timeout, allocator)
	}
	return nil, .Bad_Response
}

/*
Whether a reply is one to act on: it answers the query we sent, and it carries
our cookie if it carries one at all.

Split from `response_matches` because the cookie needs the upstream's state and
the bootstrap resolver has no upstream to hand.
*/
@(private)
response_accepted :: proc(u: ^Upstream, query, response: []u8) -> bool {
	if !response_matches(query, response) {
		return false
	}
	return cookie_matches(u, query, response)
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

	pipe_relearn_idle_locked(u)
	closed += close_pipe(u, all)

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
