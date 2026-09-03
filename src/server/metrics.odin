package server

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:cache"
import "elodin:filter"
import "elodin:logx"
import "elodin:metrics"
import "elodin:pool"
import "elodin:upstream"

/*
The Prometheus endpoint: one socket, one thread, and no share of anything a
query needs.

Off unless `metrics.enabled` is set. What it publishes is what the process was
counting anyway - every number here is an atomic the query path increments for
the `msg=stats` log line, or a figure `/proc` keeps about this process - so a
scrape adds no work to answering a query and turning the endpoint off removes
none. There is no timing histogram and no per-name label for that reason: both
would mean measuring on the path being measured.

The isolation is structural rather than a promise. This listener is served
inline on its own accept loop:

  - It never submits to a worker pool, so a scrape cannot queue behind, or
    ahead of, a query.
  - It never spawns a thread per connection, so nothing reaching this port can
    spend the budget `server.max_connections` keeps for clients.
  - It answers one request per connection and closes, so a scraper holding a
    connection open cannot keep the loop from the next scrape.

The cost of that last point is that two scrapers arrive one after the other
rather than at once. A scrape is a few hundred microseconds of formatting, and
the alternative - a thread per scraper - is the resource this endpoint is meant
not to spend.
*/

@(private)
Metrics_Context :: struct {
	server:    ^Server,
	listeners: ^Listeners,
}

/*
How long a scrape may take to send its request or read its answer.

Short on purpose, and the reason the single-threaded loop above is safe: the
worst a peer on this port can do is hold the endpoint for this long. It is not
`server.client_timeout`, which is sized for a DNS client on a slow link; a
scraper is a local process or a sidecar, and one that cannot finish a request
inside five seconds is one whose scrape has already timed out at its end.
*/
@(private)
METRICS_TIMEOUT :: 5 * time.Second

// A scrape is a request line and a handful of short headers.
@(private)
METRICS_REQUEST_BUF :: 2048

@(private)
start_metrics :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.metrics
	endpoint, ok := parse_bind(cfg.address, cfg.port)
	if !ok {
		logx.errorf("metrics.address: %q is not a valid bind address", cfg.address)
		return false
	}
	sock, err := net.listen_tcp(endpoint)
	if err != nil {
		report_bind_failure("metrics", cfg.address, cfg.port, err)
		return false
	}
	// So the accept loop wakes up now and then and can see `stop`.
	_ = net.set_option(sock, .Receive_Timeout, LISTENER_POLL)
	l.metrics_socket = sock
	l.metrics_open = true

	ctx := new(Metrics_Context)
	ctx.server = s
	ctx.listeners = l
	if conn_spawn(&l.conns, ctx, metrics_accept_loop, counted = false) != .Started {
		logx.errorf("metrics: cannot start the accept loop")
		// Nothing was ever handed it, so it is ours to release.
		free(ctx)
		return false
	}
	l.metrics_loop_ctx = ctx

	logx.infof("serving metrics on %s:%d%s", cfg.address, cfg.port, cfg.path)
	/*
	Said once, at the volume it deserves.

	Nothing on this endpoint is a secret in the way an answer is, but together
	the numbers describe a network: how much it queries, how much of that is
	blocked, which upstreams are reachable, how close the process is to its
	connection limit. There is no authentication in front of them, so a bind
	beyond loopback is a decision, and an operator who reached it by copying an
	address from the DNS listeners above should read this line.
	*/
	if !is_loopback(endpoint.address) {
		logx.warnf(
			"metrics.address is %s rather than a loopback address: the endpoint is served to anything that can reach it, without authentication",
			cfg.address,
		)
	}
	return true
}

@(private)
metrics_accept_loop :: proc(data: rawptr) {
	ctx := cast(^Metrics_Context)data
	l := ctx.listeners

	for !sync.atomic_load(&l.stop) {
		client_socket, client, err := net.accept_tcp(l.metrics_socket)
		if err != nil {
			if sync.atomic_load(&l.stop) {
				break
			}
			continue
		}
		serve_metrics(ctx.server, l, client_socket, client)
		net.close(client_socket)
		// This loop is the one place that never resets the arena otherwise, and
		// the rendered page is the largest thing in it.
		free_all(context.temp_allocator)
	}
	// `ctx` is not released here; `destroy_listeners` has it, for the reason
	// the DNS loops give.
}

@(private)
serve_metrics :: proc(s: ^Server, l: ^Listeners, socket: net.TCP_Socket, client: net.Endpoint) {
	_ = net.set_option(socket, .Receive_Timeout, METRICS_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, METRICS_TIMEOUT)

	// `peer` is filled in although nothing here charges the rate limiter, so that
	// it is not a zero endpoint waiting for something that does: `prefix_key` maps
	// an address it cannot read to one bucket, which would put every scrape in the
	// prefix of nobody.
	conn := Conn {
		socket = socket,
		peer   = client,
	}
	r := Http_Reader {
		conn = conn,
		buf  = make([dynamic]u8, 0, METRICS_REQUEST_BUF, context.temp_allocator),
	}
	req, status, ok := read_http_request(&r)
	if !ok {
		logx.debugf("metrics: unreadable request from %v", client)
		// A scraper is a program, and one whose request line this endpoint will
		// not read is one whose author has something to fix: the status says
		// which half of it was wrong instead of leaving a bare closed connection
		// to be read as the endpoint being down. 0 is a request that is not
		// answered at all - see `read_http_request`.
		if status != 0 {
			_ = send_http_error(conn, "metrics", status, http_refusal_message(status), false)
			// The refused request may have declared a body that was never read, and
			// the close in the accept loop would take the answer with it. The body
			// may not have finished arriving either, which is the longer of the two
			// idle waits - see `HTTP_LINGER_BODY_IDLE`.
			http_linger(conn, HTTP_LINGER_BODY_IDLE)
		}
		return
	}

	/*
	`req.keep_alive` is not consulted anywhere below: every answer says
	`Connection: close` and the caller closes the socket, whatever the client
	asked for. A keep-alive honoured on a single-threaded loop is a scraper
	deciding how long the next scrape waits - see the note at the top of this
	file.
	*/
	if req.path != s.cfg.metrics.path {
		_ = send_http_error(conn, "metrics", 404, "not found", false)
		return
	}
	if req.method != "GET" && req.method != "HEAD" {
		_ = send_http_error(conn, "metrics", 405, "method not allowed", false)
		return
	}

	body := render_metrics(s, l, context.temp_allocator)

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "HTTP/1.1 200 OK\r\nContent-Type: ")
	strings.write_string(&b, metrics.CONTENT_TYPE)
	strings.write_string(&b, "\r\nContent-Length: ")
	strings.write_int(&b, len(body))
	// Nothing here may be cached: a scraper that re-read a stored copy would
	// draw a flat line over a server that had stopped answering.
	strings.write_string(&b, "\r\nCache-Control: no-store\r\nDate: ")
	strings.write_string(&b, now_http_date(context.temp_allocator))
	strings.write_string(&b, "\r\nServer: elodin/")
	strings.write_string(&b, VERSION)
	strings.write_string(&b, "\r\nConnection: close\r\n\r\n")

	if !conn_write_all(conn, transmute([]u8)strings.to_string(b)) {
		return
	}
	// A HEAD answer carries the headers the body would have had and no body.
	if req.method == "HEAD" {
		return
	}
	_ = conn_write_all(conn, transmute([]u8)body)
}

/*
Render everything this process knows about itself, in the exposition format.

Read straight from the live counters rather than from a snapshot taken on a
timer: a scrape is the snapshot. Each counter is read on its own, so two of them
can be a query apart - which is what every Prometheus exporter does, and what
`rate()` over a counter is already tolerant of.
*/
render_metrics :: proc(s: ^Server, l: ^Listeners, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)

	metrics.family(&b, "elodin_build_info", .Gauge, "The version of the running binary, as a label.")
	metrics.sample(&b, "elodin_build_info", u64(1), metrics.Label{"version", VERSION})

	metrics.scalar(
		&b,
		"elodin_uptime_seconds",
		.Gauge,
		"Seconds since this process finished starting up.",
		time.duration_seconds(time.since(s.started)),
	)

	st := stats_of(s)

	metrics.scalar(
		&b,
		"elodin_queries_total",
		.Counter,
		"Queries accepted from clients, whatever became of them.",
		st.queries,
	)

	/*
	The same words the `msg=query` log line uses in its `outcome=` field, so
	that a PromQL query and a Loki query about the same event are written the
	same way.

	These do not add up to `elodin_queries_total`. A query the backlog or the
	allow list turned away never reached an outcome, and one answered from a
	local zone is not among these either; the difference is the `dropped` and
	`refused` counters below. Of the local answers only the reserved-name table
	is counted at all, in `elodin_special_use_total` below - a stopped `.onion`
	query being the one an operator watches for - while the CHAOS replies and the
	DDR probe are answered here and counted nowhere.

	An answer withheld by the rebinding guard is in none of these either, though
	the query log calls it `outcome=blocked`. `blocked` here is what the sink
	lists did to names clients asked for, which is a number meant to be large and
	is what a dashboard graphs as such; a rebind refusal is either an attack or a
	split horizon nobody exempted, and adding a handful of those into a figure in
	the tens of thousands would hide both. `elodin_rebind_refused_total` below is
	where it is counted. Same reasoning, and the same shape, as `outcome=refused
	detail=rd` not adding to `elodin_queries_refused_total`.
	*/
	metrics.family(&b, "elodin_answers_total", .Counter, "Queries by how they were answered.")
	metrics.sample(&b, "elodin_answers_total", st.forwarded, metrics.Label{"outcome", "forwarded"})
	metrics.sample(&b, "elodin_answers_total", st.cached, metrics.Label{"outcome", "cached"})
	metrics.sample(&b, "elodin_answers_total", st.blocked, metrics.Label{"outcome", "blocked"})
	metrics.sample(&b, "elodin_answers_total", st.rewritten, metrics.Label{"outcome", "rewritten"})
	metrics.sample(&b, "elodin_answers_total", st.failed, metrics.Label{"outcome", "failed"})

	metrics.scalar(
		&b,
		"elodin_queries_dropped_total",
		.Counter,
		"Queries turned away before any work was done, because the backlog was full or the source could not be answered.",
		st.dropped,
	)
	metrics.scalar(
		&b,
		"elodin_queries_refused_total",
		.Counter,
		"Datagrams and connections turned away by server.allow_from.",
		st.refused,
	)

	metrics.scalar(
		&b,
		"elodin_connections_refused_total",
		.Counter,
		"Connections turned away for want of a slot: server.max_connections was full, or the client's prefix already held its share of it.",
		st.conn_refused,
	)
	metrics.scalar(
		&b,
		"elodin_connections_failed_total",
		.Counter,
		"Connections turned away because the OS would not start a thread for one.",
		st.conn_failed,
	)
	metrics.scalar(
		&b,
		"elodin_connections_active",
		.Gauge,
		"Client connections being served on a thread of their own.",
		i64(active_connections(&l.conns)),
	)
	metrics.scalar(
		&b,
		"elodin_connections_max",
		.Gauge,
		"What server.max_connections allows.",
		i64(s.cfg.server.max_connections),
	)
	// Published beside the total because `_active` against `_max` alone cannot
	// say whether a server refusing connections is full or is refusing one
	// client that has filled its own share - which are different problems with
	// different settings behind them.
	metrics.scalar(
		&b,
		"elodin_connections_max_per_prefix",
		.Gauge,
		"How many of server.max_connections one client prefix (/24, /64) may hold; equal to the total when there is no such cap.",
		i64(s.cfg.server.max_connections_per_prefix),
	)

	limited, slipped := rate_limit_stats(s.limiter)
	metrics.scalar(
		&b,
		"elodin_rate_limited_total",
		.Counter,
		"Queries the rate limiter withheld an answer from.",
		limited,
	)
	metrics.scalar(
		&b,
		"elodin_rate_limit_slipped_total",
		.Counter,
		"Rate-limited queries answered truncated instead of dropped, to send a real client to TCP.",
		slipped,
	)

	metrics.scalar(
		&b,
		"elodin_rebind_refused_total",
		.Counter,
		"Answers withheld because a public name was pointed into private address space.",
		st.rebind,
	)

	metrics.scalar(
		&b,
		"elodin_special_use_total",
		.Counter,
		"Queries answered from the reserved-name table instead of being forwarded.",
		st.special_use,
	)

	metrics.family(&b, "elodin_dnssec_answers_total", .Counter, "Answers by what validation made of them.")
	metrics.sample(&b, "elodin_dnssec_answers_total", st.secure, metrics.Label{"result", "secure"})
	metrics.sample(&b, "elodin_dnssec_answers_total", st.bogus, metrics.Label{"result", "bogus"})

	render_udp_metrics(&b, l)

	render_cache_metrics(&b, s)
	render_filter_metrics(&b, s)
	render_upstream_metrics(&b, s)
	render_pool_metrics(&b, s)
	render_process_metrics(&b, s.started)

	return strings.to_string(b)
}

/*
The UDP readers: what each one took off its socket, and what the kernel threw
away before it could.

Two series that only mean something beside each other. `received` is this
process counting; `drops` is the kernel counting datagrams that never reached a
read, which is the one loss no counter on the query path can see - a query
dropped in the receive queue looks exactly like a query nobody sent. An operator
watching a client complain about timeouts while `elodin_queries_total` looks
healthy is looking for this number.

Labelled per reader rather than summed because the imbalance is the diagnosis.
The kernel picks a reader by hashing the datagram's 4-tuple, so a flood from one
source port is one reader's problem and ordinary traffic spreads over all of
them: one reader carrying everything, or dropping while the others do not, says
which of the two is happening.

The drops family is omitted entirely when `/proc` could not be read or a
socket's line was not found in it, rather than published as zeros - the same
reasoning as the process family below. A flat zero for "nothing was dropped" and
a flat zero for "this cannot be measured here" are indistinguishable in a graph
and differ completely in what they are worth.
*/
@(private)
render_udp_metrics :: proc(b: ^strings.Builder, l: ^Listeners) {
	if len(l.udp) == 0 {
		return
	}
	metrics.family(b, "elodin_udp_datagrams_total", .Counter, "Datagrams read off each UDP reader's socket.")
	for &reader, i in l.udp {
		metrics.sample(
			b,
			"elodin_udp_datagrams_total",
			sync.atomic_load(&reader.received),
			metrics.Label{"reader", reader_label(i)},
		)
	}

	drops, measured := udp_reader_drops(l)
	if !measured {
		return
	}
	metrics.family(
		b,
		"elodin_udp_receive_drops_total",
		.Counter,
		"Datagrams the kernel dropped on each reader's receive queue before they could be read.",
	)
	for n, i in drops {
		metrics.sample(b, "elodin_udp_receive_drops_total", n, metrics.Label{"reader", reader_label(i)})
	}
}

/*
The reader index as a label value.

Formatted into the temporary arena, which the metrics loop resets after every
scrape - the same arena the rendered page itself is built in. The label is
copied into the builder by `metrics.sample` before it returns, so nothing here
outlives the reset.
*/
@(private)
reader_label :: proc(i: int) -> string {
	return fmt.tprintf("%d", i)
}

/*
The cache families are written whether or not there is a cache.

A missing series and a zero read the same way in a graph and not at all the same
way in an alert: `absent()` fires on the first and never on the second. With
caching off these are zeros that say so, which is the honest answer to "how many
entries does the cache hold".
*/
@(private)
render_cache_metrics :: proc(b: ^strings.Builder, s: ^Server) {
	cs := cache.stats(s.answers)
	metrics.scalar(b, "elodin_cache_entries", .Gauge, "Answers held in the cache.", i64(cache.len_entries(s.answers)))
	metrics.scalar(b, "elodin_cache_bytes", .Gauge, "Bytes the cached answers occupy.", i64(cache.bytes_used(s.answers)))
	metrics.scalar(b, "elodin_cache_hits_total", .Counter, "Lookups answered from the cache.", cs.hits)
	metrics.scalar(b, "elodin_cache_misses_total", .Counter, "Lookups the cache could not answer.", cs.misses)
	metrics.scalar(
		b,
		"elodin_cache_withheld_total",
		.Counter,
		"Answers the cache handed over - a fresh hit or a stale lend - that the resolver then refused instead of serving.",
		cs.withheld,
	)
	/*
	The one series that shows `cache.serve_stale` working.

	A stale lookup is counted a miss - the cache did not answer it, the query went
	to an upstream - and the answer that comes back when that upstream fails is
	counted a cached query one package away, in `elodin_answers_total`. Neither
	says the data was expired, and the only other trace the failure behind it
	leaves is `elodin_upstream_failures_total`, which every exchange that fails
	raises, including the ones a second upstream or a retry went on to cover.
	Without this an operator watching an outage covered by expired data sees only
	the absence of the traffic that stopped.

	Counted where the answer reaches a client rather than where an upstream
	fails, so an expired entry served to an RD=0 query - which is answered from
	what this server already knows, without asking anybody - is in here too.
	*/
	metrics.scalar(
		b,
		"elodin_cache_stale_total",
		.Counter,
		"Expired answers served because no fresh one could be got.",
		cs.stale,
	)
	metrics.scalar(
		b,
		"elodin_cache_evictions_total",
		.Counter,
		"Entries dropped to stay inside max_entries or max_bytes.",
		cs.evictions,
	)
}

@(private)
render_filter_metrics :: proc(b: ^strings.Builder, s: ^Server) {
	// A running server always has an engine, whether or not blocking is on;
	// this is for the tests, which build a `Server` with only the parts they
	// are asking about.
	if s.filters == nil {
		return
	}
	fs := filter.engine_stats(s.filters)
	metrics.family(b, "elodin_filter_rules", .Gauge, "Rules loaded, by which set they are in.")
	metrics.sample(b, "elodin_filter_rules", i64(fs.block_rules), metrics.Label{"list", "block"})
	metrics.sample(b, "elodin_filter_rules", i64(fs.allow_rules), metrics.Label{"list", "allow"})
}

/*
Per-upstream, labelled by the name in the configuration.

The name is the one label here whose bytes come from a file rather than from
this source, which is what the escaping in `metrics.write_label_value` is for.

Every upstream this server has, the routed ones included: an operator watching
whether their domain controller is answering wants the same four series for it
that they get for the public resolvers, and a route that is failing is exactly
the thing that goes unnoticed otherwise, since it affects only the internal
names.

A name that appears in more than one group is emitted once, with the groups'
figures added together. Two samples with identical label sets in one family is
malformed exposition, and Prometheus rejects the whole scrape for it - so the
one arrangement that would silently break the endpoint is the ordinary one of
listing the router in `upstream.servers` and in a route for its own zone.

Added rather than the first one kept, which is the difference between a merged
view and a missing one. The two entries are separate `Upstream` values with
separate counters and separate failure cooldowns, so keeping the first would
report the default group's traffic under a name the route is also using and
leave the route's queries, failures and latency out of the endpoint entirely -
which is exactly the "a failing route goes unnoticed" case above, rebuilt by
the de-duplication meant to serve it. `up` is the same reasoning in gauge form:
the name is up while any of the upstreams wearing it is usable, so an operator
sees zero only once the server really has nowhere to send those names.
*/
@(private)
render_upstream_metrics :: proc(b: ^strings.Builder, s: ^Server) {
	if s.group == nil && len(s.routes) == 0 {
		return
	}

	// One series per configured name, gathered once and walked four times, so
	// the de-duplication happens in one place rather than in each family below.
	Series :: struct {
		name:     string,
		queries:  u64,
		failures: u64,
		latency:  u64,
		up:       bool,
	}
	all := make([dynamic]Series, 0, 8, context.temp_allocator)
	at := make(map[string]int, context.temp_allocator)
	add :: proc(all: ^[dynamic]Series, at: ^map[string]int, g: ^upstream.Group) {
		if g == nil {
			return
		}
		for u in g.servers {
			us := upstream.stats_of(u)
			live := upstream.healthy(u)
			if i, found := at[u.spec.name]; found {
				all[i].queries += us.queries
				all[i].failures += us.failures
				all[i].latency += us.latency_ns_total
				if live {
					all[i].up = true
				}
				continue
			}
			at[u.spec.name] = len(all^)
			append(
				all,
				Series {
					name = u.spec.name,
					queries = us.queries,
					failures = us.failures,
					latency = us.latency_ns_total,
					up = live,
				},
			)
		}
	}
	add(&all, &at, s.group)
	for route in s.routes {
		add(&all, &at, route.group)
	}

	metrics.family(b, "elodin_upstream_queries_total", .Counter, "Queries sent to each upstream.")
	for u in all {
		metrics.sample(b, "elodin_upstream_queries_total", u.queries, metrics.Label{"upstream", u.name})
	}

	metrics.family(b, "elodin_upstream_failures_total", .Counter, "Exchanges with each upstream that did not produce a usable answer.")
	for u in all {
		metrics.sample(b, "elodin_upstream_failures_total", u.failures, metrics.Label{"upstream", u.name})
	}

	/*
	Seconds spent waiting on each upstream, as a running total.

	A total rather than an average, because an average since start stops moving:
	divided by the query counter beside it under `rate()`, this gives the mean
	round trip over whatever window the query asks for, which is what an
	operator comparing two upstreams wants.
	*/
	metrics.family(b, "elodin_upstream_latency_seconds_total", .Counter, "Cumulative round-trip time to each upstream.")
	for u in all {
		metrics.sample(
			b,
			"elodin_upstream_latency_seconds_total",
			f64(u.latency) / f64(time.Second),
			metrics.Label{"upstream", u.name},
		)
	}

	metrics.family(b, "elodin_upstream_up", .Gauge, "1 while an upstream is being used, 0 while it is in its failure cooldown.")
	for u in all {
		metrics.sample(b, "elodin_upstream_up", u64(1) if u.up else u64(0), metrics.Label{"upstream", u.name})
	}
}

/*
The worker pools.

`pending` is the one number here that says whether this server is keeping up:
queries queue there when every worker is inside an upstream round trip, and a
figure that does not come back to zero is `server.workers` set too low - the
same condition `elodin_queries_dropped_total` starts counting once the backlog
is full.
*/
@(private)
render_pool_metrics :: proc(b: ^strings.Builder, s: ^Server) {
	if s.handler_pool == nil || s.race_pool == nil {
		return
	}
	metrics.family(b, "elodin_pool_workers", .Gauge, "Worker threads in each pool.")
	metrics.sample(b, "elodin_pool_workers", i64(pool.worker_count(s.handler_pool)), metrics.Label{"pool", "query"})
	metrics.sample(b, "elodin_pool_workers", i64(pool.worker_count(s.race_pool)), metrics.Label{"pool", "upstream"})

	metrics.family(b, "elodin_pool_pending", .Gauge, "Jobs waiting for a worker in each pool.")
	metrics.sample(b, "elodin_pool_pending", i64(pool.pending(s.handler_pool)), metrics.Label{"pool", "query"})
	metrics.sample(b, "elodin_pool_pending", i64(pool.pending(s.race_pool)), metrics.Label{"pool", "upstream"})
}

/*
CPU, memory and descriptors, under the names every Prometheus client library
uses for them.

Left out entirely when `/proc` could not be read, rather than published as
zeros: a process using no CPU and no memory is not a thing, and a dashboard
showing it flat is worse than one showing a gap where the data is missing.
*/
@(private)
render_process_metrics :: proc(b: ^strings.Builder, started: time.Time) {
	/*
	Taken from when this process began serving rather than from `/proc`.

	Prometheus's own clients derive it from the kernel's boot time plus the
	process's start ticks, which is exact and needs `/proc/stat` - a file whose
	interrupt line runs to several kilobytes on an ordinary host, for one number
	near the end of it. The difference between the two answers is the few
	milliseconds this process spent loading its configuration, and nothing
	`process_start_time_seconds` is used for - "has it restarted", "how long has
	it been up" - can tell them apart.
	*/
	metrics.scalar(
		b,
		"process_start_time_seconds",
		.Gauge,
		"Unix time at which this process began serving.",
		f64(time.time_to_unix_nano(started)) / f64(time.Second),
	)

	p := metrics.process_stats()
	if !p.ok {
		return
	}
	metrics.scalar(
		b,
		"process_cpu_seconds_total",
		.Counter,
		"Total user and system CPU time spent, in seconds.",
		p.cpu_seconds,
	)
	metrics.scalar(b, "process_resident_memory_bytes", .Gauge, "Resident memory size, in bytes.", p.resident_bytes)
	metrics.scalar(b, "process_virtual_memory_bytes", .Gauge, "Virtual memory size, in bytes.", p.virtual_bytes)
	metrics.scalar(b, "process_threads", .Gauge, "Threads in this process.", p.threads)
	if p.open_fds >= 0 {
		metrics.scalar(b, "process_open_fds", .Gauge, "Open file descriptors.", p.open_fds)
	}
	if p.max_fds > 0 {
		metrics.scalar(b, "process_max_fds", .Gauge, "Maximum number of open file descriptors.", p.max_fds)
	}
}
