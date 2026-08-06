package server

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"
import "elodin:pool"
import "elodin:tlsx"

Listeners :: struct {
	udp_socket: net.UDP_Socket,
	// What the UDP socket actually bound, read once: `plausible_source` needs
	// it for every datagram, and asking the kernel each time is a syscall per
	// query for an answer that cannot change.
	udp_bound:  net.Endpoint,
	tcp_socket: net.TCP_Socket,
	dot_socket: net.TCP_Socket,
	doh_socket: net.TCP_Socket,
	udp_open:   bool,
	tcp_open:   bool,
	dot_open:   bool,
	doh_open:   bool,
	dot_ctx:    ^tlsx.Context,
	doh_ctx:    ^tlsx.Context,
	conns:      Conn_Manager,
	stop:       bool,
	/*
	What the read and accept loops were given, held here rather than by the
	loops themselves.

	A loop hands its context to every job it queues and every connection thread
	it starts, and those outlive it: a queued query still runs while the pool
	drains, and a connection thread sits in a client read for as long as its
	timeout allows. A loop that released its own context on the way out would
	pull the ground from under both. `destroy_listeners` releases them instead,
	once there is nothing left that could be holding one.
	*/
	udp_loop_ctx:    ^Udp_Context,
	stream_loop_ctx: [dynamic]^Stream_Context,
}

/*
How long a loop may sit in a blocking call before it gets a chance to notice
that it has been told to stop.

Closing a socket does not reliably wake a thread already blocked reading or
accepting on it - the same reason `upstream/h2client.odin` polls rather than
trusting close to cut a read short - so the loops carry a timeout and come up
for air instead. Without it `conn_manager_shutdown` joins a thread that is
never going to return. One wakeup a second per listener costs nothing next to
the queries going through them.
*/
@(private)
LISTENER_POLL :: time.Second

@(private)
parse_bind :: proc(address: string, port: int) -> (endpoint: net.Endpoint, ok: bool) {
	addr := net.parse_address(address)
	if addr == nil {
		return {}, false
	}
	return net.Endpoint{address = addr, port = port}, true
}

/*
Explain a bind failure in terms of what to do about it.

The two that actually happen are a privileged port without the capability to
use it, and something already listening — usually the system resolver.
*/
@(private)
report_bind_failure :: proc(name: string, address: string, port: int, err: net.Network_Error) {
	logx.errorf("listeners.%s: cannot bind %s:%d (%v)", name, address, port, err)

	#partial switch e in err {
	case net.Bind_Error:
		#partial switch e {
		case .Insufficient_Permissions_For_Address:
			logx.errorf(
				"  ports below 1024 need privileges: either grant them once with",
			)
			logx.errorf("    sudo setcap 'cap_net_bind_service=+ep' ./bin/elodin")
			logx.errorf("  or use a high port, as examples/dev.yaml does")
		case .Address_In_Use:
			logx.errorf("  something is already listening there; on most systems that is systemd-resolved:")
			logx.errorf("    sudo systemctl stop systemd-resolved")
		}
	}
}

start_listeners :: proc(s: ^Server, l: ^Listeners) -> bool {
	conn_manager_init(&l.conns, s.cfg.server.max_connections)

	if s.cfg.listeners.udp.enabled {
		if !start_udp(s, l) {
			return false
		}
	}
	if s.cfg.listeners.tcp.enabled {
		if !start_tcp(s, l) {
			return false
		}
	}
	if s.cfg.listeners.dot.enabled {
		if !start_dot(s, l) {
			return false
		}
	}
	if s.cfg.listeners.doh.enabled {
		if !start_doh(s, l) {
			return false
		}
	}
	return true
}

stop_listeners :: proc(l: ^Listeners) {
	sync.atomic_store(&l.stop, true)
	if l.udp_open {
		net.close(l.udp_socket)
	}
	if l.tcp_open {
		net.close(l.tcp_socket)
	}
	if l.dot_open {
		net.close(l.dot_socket)
	}
	if l.doh_open {
		net.close(l.doh_socket)
	}
	conn_manager_shutdown(&l.conns)
	tlsx.context_destroy(l.dot_ctx)
	tlsx.context_destroy(l.doh_ctx)
}

/*
Release what the loops were given.

Separate from `stop_listeners` because stopping is not the same as being
finished with: a query queued before the sockets closed still runs while the
worker pool drains, and it reads the context of the loop that queued it. The
caller drains the pools between the two.
*/
destroy_listeners :: proc(l: ^Listeners) {
	if l.udp_loop_ctx != nil {
		free(l.udp_loop_ctx)
		l.udp_loop_ctx = nil
	}
	for ctx in l.stream_loop_ctx {
		free(ctx)
	}
	delete(l.stream_loop_ctx)
	l.stream_loop_ctx = nil
}

// --- UDP ------------------------------------------------------------------

@(private)
Udp_Context :: struct {
	server:    ^Server,
	listeners: ^Listeners,
}

@(private)
Udp_Job :: struct {
	ctx:    ^Udp_Context,
	data:   []u8,
	client: net.Endpoint,
}

@(private)
start_udp :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.udp
	endpoint, ok := parse_bind(cfg.address, cfg.port)
	if !ok {
		logx.errorf("listeners.udp: %q is not a valid bind address", cfg.address)
		return false
	}
	socket, err := net.make_bound_udp_socket(endpoint.address, endpoint.port)
	if err != nil {
		report_bind_failure("udp", cfg.address, cfg.port, err)
		return false
	}
	// A large receive buffer absorbs query bursts that arrive while every
	// worker is busy.
	_ = net.set_option(socket, .Receive_Buffer_Size, 1 << 20)
	// So the read loop below wakes up now and then and can see `stop`.
	_ = net.set_option(socket, .Receive_Timeout, LISTENER_POLL)

	l.udp_socket = socket
	l.udp_open = true
	if bound, berr := net.bound_endpoint(socket); berr == nil {
		l.udp_bound = bound
	}

	ctx := new(Udp_Context)
	ctx.server = s
	ctx.listeners = l
	if !conn_spawn(&l.conns, ctx, udp_loop, counted = false) {
		logx.errorf("listeners.udp: cannot start the read loop")
		// Nothing was ever handed it, so it is ours to release.
		free(ctx)
		return false
	}
	l.udp_loop_ctx = ctx
	logx.infof("listening for DNS on %s:%d/udp", cfg.address, cfg.port)
	return true
}

@(private)
udp_loop :: proc(data: rawptr) {
	ctx := cast(^Udp_Context)data
	l := ctx.listeners
	buf := make([]u8, 65535)
	defer delete(buf)

	for !sync.atomic_load(&l.stop) {
		n, client, err := net.recv_udp(l.udp_socket, buf)
		if err != nil {
			if sync.atomic_load(&l.stop) {
				break
			}
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}

		/*
		Before the message is parsed, before the limiter and before the queue:
		a source this server does not answer should cost a prefix compare and
		nothing else.

		Dropped rather than refused. A REFUSED is a datagram sent to whatever
		address the query claimed, which is a reflection of its own - small, but
		free to whoever asked for it - and the source on a datagram is not
		evidence of anything. The stream listeners, where a handshake has
		established who is there, close the connection instead.

		Not charged to the rate limiter, though the limiter is the next thing
		here. That budget is kept per /24, so a denied source in the same /24 as
		an allowed one would be spending its neighbour's: charging refusals
		would turn a narrowed allow list into a way to have the clients beside
		it dropped. Nothing is sent, so there is nothing a response budget is
		bounding.
		*/
		if !config.source_allowed(ctx.server.cfg.server.allow_from, client.address) {
			sync.atomic_add(&ctx.server.stats.refused, 1)
			report_refusal(client, "udp")
			continue
		}

		if !plausible_source(l, client) {
			sync.atomic_add(&ctx.server.stats.dropped, 1)
			continue
		}

		/*
		Charged before the work rather than after the answer.

		A response this server will not send is a query it need not resolve, and
		under a flood the upstream round trips and the cache churn are as much of
		the damage as the traffic. It costs a strictly conservative limiter: the
		reply that never gets built is charged for anyway, and a query that turns
		out to be answerable from cache costs the same as one that is not.
		*/
		switch rate_check(ctx.server.limiter, client, time.tick_now()) {
		case .Allow:
		case .Truncate:
			if tc, built := dns.truncated_response(buf[:n], context.temp_allocator); built {
				_, _ = net.send_udp(l.udp_socket, tc, client)
			}
			free_all(context.temp_allocator)
			continue
		case .Drop:
			continue
		}

		// Shed rather than queue once the backlog is past what the workers can
		// work through. A query added here would be answered long after its
		// client stopped waiting, and the effort spent on it is taken from
		// queries that could still have been answered in time.
		if limit := ctx.server.cfg.server.max_pending; limit > 0 {
			if pool.pending(ctx.server.handler_pool) >= limit {
				sync.atomic_add(&ctx.server.stats.dropped, 1)
				continue
			}
		}

		job := new(Udp_Job)
		job.ctx = ctx
		job.client = client
		job.data = make([]u8, n)
		copy(job.data, buf[:n])

		if !pool.submit(ctx.server.handler_pool, udp_job, job) {
			delete(job.data)
			free(job)
			break
		}
	}
	// `ctx` is not released here: jobs queued above still hold it, and they run
	// on while the pool drains. `destroy_listeners` has it.
}

/*
Say which client `server.allow_from` turned away, once, and then quietly.

A refused source is told nothing: over UDP because a REFUSED is a reflection of
its own, and over the stream transports because the connection is closed before
anything can be written on it. That is the right behaviour toward the client and
it leaves the operator with a resolver that has silently stopped serving
somebody - a default that denies has to be able to say who it denied, or the
first symptom of a network nobody added is a client that "just stopped working"
with nothing to grep for.

So the first refusal since start is a `warn` naming the source and the setting,
and every one after it is `debug`. The counter in the stats line carries the
rest: this is here to point at the setting once, not to log a flood.

Costs one atomic load per refused datagram while debug is off, which is the case
that matters - the caller is an attacker's send loop, and formatting an address
for every packet it sends is a thing to be made to do only on purpose.
*/
@(private)
refusal_reported: bool

@(private)
report_refusal :: proc(client: net.Endpoint, transport: string) {
	if sync.atomic_load(&refusal_reported) && !logx.enabled(.Debug) {
		return
	}
	/*
	The line itself is what has to be paid for, and it is paid for here.

	`logx` formats through `fmt.tprintf`, so a line costs a few hundred bytes of
	the calling thread's temp arena - and the two callers are the UDP read loop
	and the accept loops, neither of which resets one. The read loop's arena is
	not the one a query is answered from; that belongs to the worker the job is
	handed to. The accept loop's is untouched from start to shutdown. At `debug`,
	where every refusal is logged, that would be an arena a refused source grows
	for as long as it keeps sending - which is the level an operator turns on to
	find out why their clients are being refused, so it is the level this must
	not misbehave at.

	Released where the garbage is made rather than at the call sites, and safe
	because both of them hold nothing in the temp allocator across this: the
	check runs before a datagram is parsed and before a connection is queued.
	*/
	defer free_all(context.temp_allocator)

	// The stack rather than that arena: an address is a fixed few dozen bytes,
	// and the less of a refused packet's cost goes through an allocator the
	// better.
	buf: [64]u8
	builder := strings.builder_from_bytes(buf[:])
	who := net.endpoint_to_string(client, &builder)

	if sync.atomic_exchange(&refusal_reported, true) {
		logx.debugf("%s: refused a query from %s, which is not in server.allow_from", transport, who)
		return
	}
	logx.warnf(
		"%s: refused a query from %s: it is not in server.allow_from, so nothing was sent back",
		transport,
		who,
	)
	logx.warnf(
		"  add its network to server.allow_from if that client should be served; refusals are counted as refused= in the stats line, and further ones are logged at debug level",
	)
}

/*
Whether a datagram's source could be a client waiting for an answer.

Two things it cannot be, both free to check and both well established:

Port 0 is not a port anything receives on. A query that says it came from one is
either a probe or a packet built by hand, and answering it sends a datagram to a
port the kernel will not deliver.

Our own listening endpoint is the other. A datagram spoofed as coming from the
address and port this server is answering on makes it talk to itself - every
answer arriving as a new query, forever, at whatever rate the loop sustains. A
source port equal to ours from a loopback address is the same thing under a
wildcard bind, where our own datagrams come from whichever local address the
route picked rather than the 0.0.0.0 we asked for.

The same shape aimed at *another* resolver is what a loop between two servers
would be, and this is not what stops that: a client's source port is essentially
never 53, but "essentially never" has counted some real forwarders, so refusing
every datagram from port 53 would refuse them too. What stops it is that neither
end answers an answer - `handle_query` drops anything with QR set before it
looks at the question - so the exchange is one datagram each way rather than a
loop, and the rate limiter bounds even that.
*/
@(private)
plausible_source :: proc(l: ^Listeners, client: net.Endpoint) -> bool {
	if client.port == 0 {
		return false
	}
	bound := l.udp_bound
	if bound.port == 0 || client.port != bound.port {
		return true
	}
	// Bound to a concrete address, and the source claims to be it.
	if addresses_equal(client.address, bound.address) {
		return false
	}
	// Bound to the wildcard, where the source of our own datagrams is whichever
	// local address the route picked rather than the address we bound.
	return !is_loopback(client.address)
}

@(private)
addresses_equal :: proc(a, b: net.Address) -> bool {
	switch x in a {
	case net.IP4_Address:
		y, ok := b.(net.IP4_Address)
		return ok && x == y
	case net.IP6_Address:
		y, ok := b.(net.IP6_Address)
		return ok && x == y
	}
	return false
}

@(private)
is_loopback :: proc(a: net.Address) -> bool {
	switch x in a {
	case net.IP4_Address:
		return x[0] == 127
	case net.IP6_Address:
		return x == net.IP6_Loopback
	}
	return false
}

@(private)
udp_job :: proc(data: rawptr) {
	job := cast(^Udp_Job)data
	defer {
		delete(job.data)
		free(job)
		free_all(context.temp_allocator)
	}

	s := job.ctx.server
	client := net.endpoint_to_string(job.client, context.temp_allocator)
	response, _, ok := handle_query(s, job.data, .UDP, client, context.temp_allocator)
	if !ok || len(response) == 0 {
		return
	}
	_, _ = net.send_udp(job.ctx.listeners.udp_socket, response, job.client)
}

// --- TCP and DoT ----------------------------------------------------------

@(private)
Stream_Context :: struct {
	server:    ^Server,
	listeners: ^Listeners,
	proto:     Protocol,
}

@(private)
Stream_Job :: struct {
	ctx:    ^Stream_Context,
	socket: net.TCP_Socket,
	client: net.Endpoint,
}

@(private)
start_stream_listener :: proc(
	s: ^Server,
	l: ^Listeners,
	cfg: config.Listener,
	proto: Protocol,
	socket: ^net.TCP_Socket,
	open: ^bool,
) -> bool {
	name := proto_name(proto)
	endpoint, ok := parse_bind(cfg.address, cfg.port)
	if !ok {
		logx.errorf("listeners.%s: %q is not a valid bind address", name, cfg.address)
		return false
	}
	sock, err := net.listen_tcp(endpoint)
	if err != nil {
		report_bind_failure(name, cfg.address, cfg.port, err)
		return false
	}
	// So the accept loop below wakes up now and then and can see `stop`.
	_ = net.set_option(sock, .Receive_Timeout, LISTENER_POLL)
	socket^ = sock
	open^ = true

	ctx := new(Stream_Context)
	ctx.server = s
	ctx.listeners = l
	ctx.proto = proto
	if !conn_spawn(&l.conns, ctx, accept_loop, counted = false) {
		logx.errorf("listeners.%s: cannot start the accept loop", name)
		// Nothing was ever handed it, so it is ours to release.
		free(ctx)
		return false
	}
	append(&l.stream_loop_ctx, ctx)
	return true
}

@(private)
start_tcp :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.tcp
	if !start_stream_listener(s, l, cfg, .TCP, &l.tcp_socket, &l.tcp_open) {
		return false
	}
	logx.infof("listening for DNS on %s:%d/tcp", cfg.address, cfg.port)
	return true
}

@(private)
DOT_ALPN := []string{"dot"}

// h2 first: browsers will only use a DoH resolver over HTTP/2, and ALPN picks
// by server preference. A client that offers neither gets a clean handshake
// failure rather than a connection that then talks past us.
@(private)
DOH_ALPN := []string{"h2", "http/1.1"}

@(private)
start_dot :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.dot
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, DOT_ALPN)
	if err != .None {
		logx.errorf("listeners.dot: %s", tlsx.describe_error(err, context.temp_allocator))
		return false
	}
	l.dot_ctx = ctx
	if !start_stream_listener(s, l, cfg, .DoT, &l.dot_socket, &l.dot_open) {
		return false
	}
	logx.infof("listening for DNS-over-TLS on %s:%d", cfg.address, cfg.port)
	return true
}

@(private)
start_doh :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.doh
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, DOH_ALPN)
	if err != .None {
		logx.errorf("listeners.doh: %s", tlsx.describe_error(err, context.temp_allocator))
		return false
	}
	l.doh_ctx = ctx
	if !start_stream_listener(s, l, cfg, .DoH, &l.doh_socket, &l.doh_open) {
		return false
	}
	logx.infof("listening for DNS-over-HTTPS on %s:%d%s", cfg.address, cfg.port, cfg.path)
	return true
}

/*
Re-read the certificate and key files and switch the DoT/DoH listeners over to
what they now contain, without touching the sockets or any connection already
accepted.

A new `SSL_CTX` is built first and swapped in only once it is known good, so a
certificate that fails to load - the wrong key, a typo'd path - leaves the
listener serving what it already had rather than falling over. The context an
open connection's `SSL` holds stays valid after the swap: OpenSSL reference
counts an `SSL_CTX` from `SSL_new` on, so freeing the displaced one here only
releases it once the last connection still using it closes.

Called from the maintenance loop on SIGHUP, one listener at a time; nothing
else running concurrently writes `dot_ctx` or `doh_ctx`, but `accept_loop`'s
connection threads read them for every new connection, hence the atomic swap.
*/
reload_tls :: proc(s: ^Server, l: ^Listeners) -> bool {
	ok := true
	if l.dot_open {
		if !reload_tls_ctx(&l.dot_ctx, s.cfg.listeners.dot, DOT_ALPN, "dot") {
			ok = false
		}
	}
	if l.doh_open {
		if !reload_tls_ctx(&l.doh_ctx, s.cfg.listeners.doh, DOH_ALPN, "doh") {
			ok = false
		}
	}
	return ok
}

@(private)
reload_tls_ctx :: proc(slot: ^^tlsx.Context, cfg: config.Listener, alpn: []string, name: string) -> bool {
	fresh, err := tlsx.server_context(cfg.cert_file, cfg.key_file, alpn)
	if err != .None {
		logx.errorf(
			"listeners.%s: keeping the certificate already in use, %s and %s did not load: %s",
			name,
			cfg.cert_file,
			cfg.key_file,
			tlsx.describe_error(err, context.temp_allocator),
		)
		return false
	}
	old := sync.atomic_exchange(slot, fresh)
	tlsx.context_destroy(old)
	logx.infof("listeners.%s: reloaded the certificate from %s", name, cfg.cert_file)
	return true
}

@(private)
listening_socket :: proc(l: ^Listeners, proto: Protocol) -> net.TCP_Socket {
	switch proto {
	case .TCP:
		return l.tcp_socket
	case .DoT:
		return l.dot_socket
	case .DoH:
		return l.doh_socket
	case .UDP:
	}
	return l.tcp_socket
}

@(private)
accept_loop :: proc(data: rawptr) {
	ctx := cast(^Stream_Context)data
	l := ctx.listeners
	listener := listening_socket(l, ctx.proto)

	for !sync.atomic_load(&l.stop) {
		client_socket, client, err := net.accept_tcp(listener)
		if err != nil {
			if sync.atomic_load(&l.stop) {
				break
			}
			continue
		}

		/*
		Closed here rather than handed a thread that would answer REFUSED.

		A refusal a client can read is the friendlier of the two, and it is what
		BIND and Unbound send - but it has to be written on a connection, and a
		connection is a thread out of `max_connections` plus, for DoT and DoH, a
		TLS handshake. That would make the allow list a way to exhaust the
		connection limit rather than a defence: a source we have already decided
		not to serve would cost more than one we do. Closing on accept costs a
		prefix compare and a close, and a client whose network is not in the
		list sees the connection go rather than a reason, which is why the log
		has to carry one - see `report_refusal`.
		*/
		if !config.source_allowed(ctx.server.cfg.server.allow_from, client.address) {
			sync.atomic_add(&ctx.server.stats.refused, 1)
			report_refusal(client, proto_name(ctx.proto))
			net.close(client_socket)
			continue
		}

		job := new(Stream_Job)
		job.ctx = ctx
		job.socket = client_socket
		job.client = client

		if !conn_spawn(&l.conns, job, stream_job) {
			logx.warnf("%s: refusing a connection, the limit of %d is reached", proto_name(ctx.proto), l.conns.limit)
			net.close(client_socket)
			free(job)
			// The line above was formatted out of this thread's temp arena, and
			// this loop is the one place that never resets it - a peer opening
			// connections past the limit would otherwise grow it for as long as
			// it kept trying. Nothing here outlives the iteration.
			free_all(context.temp_allocator)
		}
	}
	// `ctx` is not released here: every connection thread started above holds
	// it for as long as its client keeps the connection open, and this loop
	// exits first. `destroy_listeners` has it.
}

@(private)
stream_job :: proc(data: rawptr) {
	job := cast(^Stream_Job)data
	defer {
		free(job)
		free_all(context.temp_allocator)
	}

	s := job.ctx.server
	timeout := s.cfg.server.client_timeout
	_ = net.set_option(job.socket, .Receive_Timeout, timeout)
	_ = net.set_option(job.socket, .Send_Timeout, timeout)
	_ = net.set_option(job.socket, .TCP_Nodelay, true)

	// The connection handlers below reset the temp allocator after every query,
	// so the client label must not live there: it is used for the lifetime of
	// the connection. A stack buffer owned by this frame outlives all of them.
	client_buf: [64]u8
	client_builder := strings.builder_from_bytes(client_buf[:])
	client := net.endpoint_to_string(job.client, &client_builder)

	switch job.ctx.proto {
	case .TCP:
		defer net.close(job.socket)
		serve_dns_stream(s, {socket = job.socket}, .TCP, client)
	case .DoT:
		// Read once, under the atomic that `reload_tls` swaps: a reload landing
		// mid-accept must not hand this connection a half-updated context.
		ctx := sync.atomic_load(&job.ctx.listeners.dot_ctx)
		conn, err := tlsx.server_accept(ctx, job.socket)
		if err != .None {
			logx.debugf("dot: handshake with %s failed: %v", client, err)
			net.close(job.socket)
			return
		}
		defer tlsx.close(conn)
		serve_dns_stream(s, {socket = job.socket, tls = conn}, .DoT, client)
	case .DoH:
		ctx := sync.atomic_load(&job.ctx.listeners.doh_ctx)
		conn, err := tlsx.server_accept(ctx, job.socket)
		if err != .None {
			logx.debugf("doh: handshake with %s failed: %v", client, err)
			net.close(job.socket)
			return
		}
		defer tlsx.close(conn)
		if tlsx.alpn_protocol(conn) == "h2" {
			serve_doh2(s, conn, client)
		} else {
			serve_doh(s, {socket = job.socket, tls = conn}, client)
		}
	case .UDP:
	// not reachable: UDP has no accept loop
	}
}

/*
Serve DNS messages on a stream, framed with the two-byte length prefix.

Queries on one connection are answered in order. Pipelining clients are rare
enough that the extra machinery to answer out of order is not worth the
complexity here.
*/
@(private)
serve_dns_stream :: proc(s: ^Server, conn: Conn, proto: Protocol, client: string) {
	for {
		length_buf: [2]u8
		if !conn_read_full(conn, length_buf[:]) {
			return
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}

		query := make([]u8, length, context.temp_allocator)
		if !conn_read_full(conn, query) {
			return
		}

		response, _, ok := handle_query(s, query, proto, client, context.temp_allocator)
		if !ok || len(response) == 0 {
			free_all(context.temp_allocator)
			continue
		}

		framed := make([]u8, 2 + len(response), context.temp_allocator)
		framed[0] = u8(len(response) >> 8)
		framed[1] = u8(len(response))
		copy(framed[2:], response)
		if !conn_write_all(conn, framed) {
			return
		}
		free_all(context.temp_allocator)
	}
}

// A stream that may or may not be wrapped in TLS.
Conn :: struct {
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
}

@(private)
conn_read :: proc(c: Conn, buf: []u8) -> (n: int, ok: bool) {
	if c.tls != nil {
		got, err := tlsx.read(c.tls, buf)
		return got, err == .None && got > 0
	}
	got, err := net.recv_tcp(c.socket, buf)
	return got, err == nil && got > 0
}

@(private)
conn_read_full :: proc(c: Conn, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, ok := conn_read(c, buf[got:])
		if !ok {
			return false
		}
		got += n
	}
	return true
}

@(private)
conn_write_all :: proc(c: Conn, buf: []u8) -> bool {
	if c.tls != nil {
		_, err := tlsx.write(c.tls, buf)
		return err == .None
	}
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(c.socket, buf[sent:])
		if err != nil || n <= 0 {
			return false
		}
		sent += n
	}
	return true
}

@(private)
now_http_date :: proc(allocator := context.allocator) -> string {
	// RFC 1123 date for the Date header. Callers only need something valid.
	now := time.now()
	y, m, d := time.date(now)
	h, mi, sec := time.clock_from_time(now)
	return fmt.aprintf(
		"%s, %02d %s %04d %02d:%02d:%02d GMT",
		"Mon",
		d,
		month_name(int(m)),
		y,
		h,
		mi,
		sec,
		allocator = allocator,
	)
}

@(private)
month_name :: proc(m: int) -> string {
	names := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	if m >= 1 && m <= 12 {
		return names[m - 1]
	}
	return "Jan"
}
