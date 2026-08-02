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
}

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

	l.udp_socket = socket
	l.udp_open = true

	ctx := new(Udp_Context)
	ctx.server = s
	ctx.listeners = l
	if !conn_spawn(&l.conns, ctx, udp_loop, counted = false) {
		logx.errorf("listeners.udp: cannot start the read loop")
		// No loop to hand it to, so it is ours to release.
		free(ctx)
		return false
	}
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
	free(ctx)
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
	socket^ = sock
	open^ = true

	ctx := new(Stream_Context)
	ctx.server = s
	ctx.listeners = l
	ctx.proto = proto
	if !conn_spawn(&l.conns, ctx, accept_loop, counted = false) {
		logx.errorf("listeners.%s: cannot start the accept loop", name)
		// No loop to hand it to, so it is ours to release.
		free(ctx)
		return false
	}
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
start_dot :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.dot
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, []string{"dot"})
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
	// h2 first: browsers will only use a DoH resolver over HTTP/2, and ALPN
	// picks by server preference. A client that offers neither gets a clean
	// handshake failure rather than a connection that then talks past us.
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, []string{"h2", "http/1.1"})
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

		job := new(Stream_Job)
		job.ctx = ctx
		job.socket = client_socket
		job.client = client

		if !conn_spawn(&l.conns, job, stream_job) {
			logx.warnf("%s: refusing a connection, the limit of %d is reached", proto_name(ctx.proto), l.conns.limit)
			net.close(client_socket)
			free(job)
		}
	}
	free(ctx)
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
		conn, err := tlsx.server_accept(job.ctx.listeners.dot_ctx, job.socket)
		if err != .None {
			logx.debugf("dot: handshake with %s failed: %v", client, err)
			net.close(job.socket)
			return
		}
		defer tlsx.close(conn)
		serve_dns_stream(s, {socket = job.socket, tls = conn}, .DoT, client)
	case .DoH:
		conn, err := tlsx.server_accept(job.ctx.listeners.doh_ctx, job.socket)
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
