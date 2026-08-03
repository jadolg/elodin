package itest

import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
A scriptable upstream resolver for the integration tests.

Pointing elodin at real public resolvers would make the suite slow, flaky and
dependent on someone else's uptime. This mock answers on UDP, TCP and optionally
TLS from a table of rules, so every behaviour under test — a timeout, a
truncated UDP reply, a delayed answer — is produced on demand instead of waited
for.
*/

Mock_Behaviour :: enum u8 {
	// Reply with `payload`, transaction ID patched to match the query.
	Reply,
	// Never answer. Used to exercise timeouts and failover.
	Silent,
	// Wait `delay` before replying. Used to exercise racing.
	Delayed,
	// Reply with TC=1 and no records over UDP, in full over TCP. This is what
	// a real resolver does when an answer will not fit in a datagram.
	Truncate_UDP,
	// Reply with the given rcode and no records.
	Rcode_Only,
	// Synthesise an A answer for whatever name was asked, using `addr`.
	// A fixed payload cannot be used as a catch-all: elodin checks that a
	// reply's question matches the query it sent, so a canned answer for one
	// name is correctly rejected when a different name was asked.
	Synth_A,
}

Mock_Cookies :: enum u8 {
	// Ignore COOKIE options entirely, the way a server that predates RFC 7873
	// would.
	Off,
	// Echo the client cookie with a server cookie behind it.
	Echo,
	// The same, but refuse to answer anything until the query shows the server
	// cookie this mock issued.
	Require,
}

Mock_Rule :: struct {
	// Empty matches any name; otherwise compared case-insensitively with the
	// trailing dot included.
	qname:     string,
	// 0 matches any type.
	qtype:     u16,
	behaviour: Mock_Behaviour,
	payload:   []u8,
	delay:     time.Duration,
	rcode:     dns.Rcode,
	addr:      [4]u8,
	ttl:       u32,
}

Mock :: struct {
	name:        string,
	port:        int,
	rules:       [dynamic]Mock_Rule,
	// Answer used when no rule matches.
	fallback:    Mock_Rule,

	udp_socket:  net.UDP_Socket,
	tcp_socket:  net.TCP_Socket,
	tls_ctx:     ^tlsx.Context,
	threads:     [dynamic]^thread.Thread,
	stop:        bool,

	// When set, a connection is closed after this much idle time, the way a
	// public DoT resolver drops connections a client has stopped using.
	idle_close:  time.Duration,

	// How this mock treats DNS cookies (RFC 7873).
	cookies:     Mock_Cookies,
	// Echo back a client cookie that is not the one the query carried, which is
	// what an off-path forgery would have to do.
	forge_cookie: bool,

	mu:          sync.Mutex,
	udp_queries: int,
	tcp_queries: int,
	tls_queries: int,
	// The most recent query as it arrived, so tests can assert on what elodin
	// actually forwarded rather than only on what came back.
	last_query:  []u8,
}

mock_make :: proc(name: string, port: int) -> ^Mock {
	m := new(Mock)
	m.name = name
	m.port = port
	m.rules = make([dynamic]Mock_Rule, 0, 8)
	m.threads = make([dynamic]^thread.Thread, 0, 4)
	m.fallback = Mock_Rule {
		behaviour = .Rcode_Only,
		rcode     = .NX_Domain,
	}
	return m
}

mock_reply :: proc(m: ^Mock, qname: string, qtype: u16, payload: []u8) {
	append(&m.rules, Mock_Rule{qname = qname, qtype = qtype, behaviour = .Reply, payload = payload})
}

mock_silent :: proc(m: ^Mock) {
	m.fallback = Mock_Rule {
		behaviour = .Silent,
	}
}

mock_delay_all :: proc(m: ^Mock, delay: time.Duration, payload: []u8) {
	m.fallback = Mock_Rule {
		behaviour = .Delayed,
		delay     = delay,
		payload   = payload,
	}
}

mock_reply_all :: proc(m: ^Mock, payload: []u8) {
	m.fallback = Mock_Rule {
		behaviour = .Reply,
		payload   = payload,
	}
}

// Answer any name with an A record pointing at `addr`.
mock_synth_all :: proc(m: ^Mock, addr: [4]u8, ttl: u32 = 60) {
	m.fallback = Mock_Rule {
		behaviour = .Synth_A,
		addr      = addr,
		ttl       = ttl,
	}
}

mock_synth :: proc(m: ^Mock, qname: string, qtype: u16, addr: [4]u8, ttl: u32 = 60) {
	append(
		&m.rules,
		Mock_Rule{qname = qname, qtype = qtype, behaviour = .Synth_A, addr = addr, ttl = ttl},
	)
}

mock_truncate_udp :: proc(m: ^Mock, qname: string, qtype: u16, payload: []u8) {
	append(&m.rules, Mock_Rule{qname = qname, qtype = qtype, behaviour = .Truncate_UDP, payload = payload})
}

mock_counts :: proc(m: ^Mock) -> (udp, tcp, tls: int) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	return m.udp_queries, m.tcp_queries, m.tls_queries
}

mock_total :: proc(m: ^Mock) -> int {
	u, t, s := mock_counts(m)
	return u + t + s
}

mock_reset_counts :: proc(m: ^Mock) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	m.udp_queries, m.tcp_queries, m.tls_queries = 0, 0, 0
}

// Close connections that have been idle this long, so a pooled connection goes
// stale exactly as it would against a real server.
mock_close_idle_after :: proc(m: ^Mock, d: time.Duration) {
	m.idle_close = d
}

// A copy of the last query the mock received, or nil if it has had none.
mock_last_query :: proc(m: ^Mock, allocator := context.temp_allocator) -> []u8 {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	if m.last_query == nil {
		return nil
	}
	out := make([]u8, len(m.last_query), allocator)
	copy(out, m.last_query)
	return out
}

@(private)
record_query :: proc(m: ^Mock, query: []u8) {
	// Called with m.mu already held.
	if m.last_query != nil {
		delete(m.last_query)
	}
	m.last_query = make([]u8, len(query))
	copy(m.last_query, query)
}

/*
How long a blocking recv or accept waits before looping.

Closing a socket does not wake a thread already blocked in recvfrom() or
accept() on Linux, so shutdown would deadlock waiting to join them. A receive
timeout gives every loop a regular chance to notice the stop flag.
*/
POLL_INTERVAL :: 200 * time.Millisecond

// `cert_file`/`key_file` turn on a TLS listener on the same port for DoT.
mock_start :: proc(m: ^Mock, cert_file := "", key_file := "") -> bool {
	if cert_file != "" {
		ctx, err := tlsx.server_context(cert_file, key_file, []string{"dot"})
		if err != .None {
			return false
		}
		m.tls_ctx = ctx

		sock, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = m.port})
		if lerr != nil {
			return false
		}
		m.tcp_socket = sock
		_ = net.set_option(sock, .Receive_Timeout, POLL_INTERVAL)
		append(&m.threads, thread.create_and_start_with_poly_data(m, mock_tls_loop))
		return true
	}

	udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, m.port)
	if uerr != nil {
		return false
	}
	m.udp_socket = udp
	_ = net.set_option(udp, .Receive_Timeout, POLL_INTERVAL)

	tcp, terr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = m.port})
	if terr != nil {
		net.close(udp)
		return false
	}
	m.tcp_socket = tcp
	_ = net.set_option(tcp, .Receive_Timeout, POLL_INTERVAL)

	append(&m.threads, thread.create_and_start_with_poly_data(m, mock_udp_loop))
	append(&m.threads, thread.create_and_start_with_poly_data(m, mock_tcp_loop))
	return true
}

mock_stop :: proc(m: ^Mock) {
	sync.atomic_store(&m.stop, true)
	if m.udp_socket != 0 {
		net.close(m.udp_socket)
	}
	if m.tcp_socket != 0 {
		net.close(m.tcp_socket)
	}

	// Connection threads add themselves to the list while running, so take it
	// under the lock and join the snapshot; anything started after this point
	// sees the stop flag immediately.
	for {
		sync.mutex_lock(&m.mu)
		pending := m.threads
		m.threads = make([dynamic]^thread.Thread, 0, 4)
		sync.mutex_unlock(&m.mu)

		if len(pending) == 0 {
			delete(pending)
			break
		}
		for t in pending {
			thread.join(t)
			thread.destroy(t)
		}
		delete(pending)
	}

	delete(m.threads)
	delete(m.rules)
	if m.last_query != nil {
		delete(m.last_query)
	}
	tlsx.context_destroy(m.tls_ctx)
	free(m)
}

@(private = "file")
match_rule :: proc(m: ^Mock, query: []u8) -> Mock_Rule {
	q, ok := dns.peek_question(query, context.temp_allocator)
	if !ok {
		return m.fallback
	}
	for rule in m.rules {
		if rule.qname != "" && !dns.name_equal_fold(rule.qname, q.name) {
			continue
		}
		if rule.qtype != 0 && rule.qtype != u16(q.type) {
			continue
		}
		return rule
	}
	return m.fallback
}

/*
Turn a matched rule into the bytes to send back.

`ok` is false when the rule says to stay quiet. `over_tcp` selects the full
answer for a Truncate_UDP rule.
*/
@(private = "file")
build_reply :: proc(
	m: ^Mock,
	query: []u8,
	rule: Mock_Rule,
	over_tcp: bool,
	allocator := context.allocator,
) -> (
	reply: []u8,
	ok: bool,
) {
	if m.cookies == .Off {
		return build_answer(m, query, rule, over_tcp, allocator)
	}
	sent, has_cookie := query_cookie(query)
	if !has_cookie {
		// A client that sends no cookie gets none back (RFC 7873 section 5.2.1).
		return build_answer(m, query, rule, over_tcp, allocator)
	}
	// Nothing but the cookie is looked at until the cookie is right.
	if m.cookies == .Require && !cookie_is_ours(m, sent) {
		return with_cookie(m, sent, build_rcode_reply(query, .Bad_Cookie, allocator), allocator), true
	}
	answer := build_answer(m, query, rule, over_tcp, allocator) or_return
	return with_cookie(m, sent, answer, allocator), true
}

// The server cookie this mock hands out; fixed, so a test can recognise it.
@(private = "file")
MOCK_SERVER_COOKIE := []u8{0xc0, 0x0c, 0x1e, 0x5e, 0x5e, 0x1e, 0x0c, 0xc0}

@(private = "file")
query_cookie :: proc(query: []u8) -> (cookie: []u8, found: bool) {
	msg, err := dns.decode_message(query, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(msg, .Cookie)
}

@(private = "file")
cookie_is_ours :: proc(m: ^Mock, sent: []u8) -> bool {
	if len(sent) != 8 + len(MOCK_SERVER_COOKIE) {
		return false
	}
	for b, i in MOCK_SERVER_COOKIE {
		if sent[8 + i] != b {
			return false
		}
	}
	return true
}

// Echo the client half back with this mock's server cookie behind it.
@(private = "file")
with_cookie :: proc(m: ^Mock, sent: []u8, reply: []u8, allocator := context.allocator) -> []u8 {
	option := make([]u8, 8 + len(MOCK_SERVER_COOKIE), context.temp_allocator)
	copy(option[:8], sent[:min(8, len(sent))])
	copy(option[8:], MOCK_SERVER_COOKIE)
	if m.forge_cookie {
		option[0] ~= 0xff
	}
	out, ok := dns.ensure_edns_option(reply, .Cookie, option, 1232, allocator)
	if !ok {
		return reply
	}
	return out
}

@(private = "file")
build_answer :: proc(
	m: ^Mock,
	query: []u8,
	rule: Mock_Rule,
	over_tcp: bool,
	allocator := context.allocator,
) -> (
	reply: []u8,
	ok: bool,
) {
	switch rule.behaviour {
	case .Silent:
		return nil, false

	case .Delayed:
		time.sleep(rule.delay)
		if rule.payload == nil {
			return build_rcode_reply(query, .No_Error, allocator), true
		}
		out := clone_with_id(rule.payload, query, allocator)
		return out, true

	case .Reply:
		if rule.payload == nil {
			return build_rcode_reply(query, .No_Error, allocator), true
		}
		return clone_with_id(rule.payload, query, allocator), true

	case .Rcode_Only:
		return build_rcode_reply(query, rule.rcode, allocator), true

	case .Synth_A:
		return build_synth_a(query, rule.addr, rule.ttl, allocator), true

	case .Truncate_UDP:
		if over_tcp {
			return clone_with_id(rule.payload, query, allocator), true
		}
		out := build_rcode_reply(query, .No_Error, allocator)
		// Set TC on the header we just produced.
		out[2] |= 0x02
		return out, true
	}
	return nil, false
}

@(private = "file")
clone_with_id :: proc(payload: []u8, query: []u8, allocator := context.allocator) -> []u8 {
	out := make([]u8, len(payload), allocator)
	copy(out, payload)
	if len(query) >= 2 && len(out) >= 2 {
		out[0], out[1] = query[0], query[1]
	}
	return out
}

// An A answer for whatever name the query asked about.
@(private = "file")
build_synth_a :: proc(query: []u8, addr: [4]u8, ttl: u32, allocator := context.allocator) -> []u8 {
	msg, err := dns.decode_message(query, context.temp_allocator)
	if err != .None || len(msg.question) == 0 {
		return build_rcode_reply(query, .Serv_Fail, allocator)
	}
	q := msg.question[0]

	resp := dns.make_response(msg, .No_Error, context.temp_allocator)
	if q.type == .A || q.type == .ANY {
		answers := make([]dns.Record, 1, context.temp_allocator)
		answers[0] = dns.Record {
			name  = q.name,
			type  = .A,
			class = .IN,
			ttl   = ttl,
			data  = dns.Rdata_A{addr = addr},
		}
		resp.answer = answers
	}
	wire, _, enc_err := dns.encode_message(resp, allocator)
	if enc_err != .None {
		return build_rcode_reply(query, .Serv_Fail, allocator)
	}
	return wire
}

// A minimal response echoing the question, for rules that carry no payload.
@(private = "file")
build_rcode_reply :: proc(query: []u8, rcode: dns.Rcode, allocator := context.allocator) -> []u8 {
	msg, err := dns.decode_message(query, context.temp_allocator)
	if err != .None {
		out := make([]u8, dns.HEADER_SIZE, allocator)
		copy(out, query[:min(len(query), dns.HEADER_SIZE)])
		out[2] = 0x81
		out[3] = u8(rcode) & 0xf
		for i in 4 ..< dns.HEADER_SIZE {
			out[i] = 0
		}
		return out
	}
	resp := dns.make_response(msg, rcode, context.temp_allocator)
	wire, _, enc_err := dns.encode_message(resp, allocator)
	if enc_err != .None {
		out := make([]u8, dns.HEADER_SIZE, allocator)
		return out
	}
	return wire
}

@(private = "file")
mock_udp_loop :: proc(m: ^Mock) {
	buf := make([]u8, 65535)
	defer delete(buf)

	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.udp_socket, buf)
		if err != nil {
			// Either the poll interval elapsed or the socket was closed; both
			// are handled by looping and re-testing the stop flag.
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		sync.mutex_lock(&m.mu)
		m.udp_queries += 1
		record_query(m, buf[:n])
		sync.mutex_unlock(&m.mu)

		rule := match_rule(m, buf[:n])
		if rule.behaviour == .Delayed {
			job := new(Delayed_Reply)
			job.mock = m
			job.client = client
			job.rule = rule
			job.query = make([]u8, n)
			copy(job.query, buf[:n])

			t := thread.create_and_start_with_poly_data(job, delayed_udp_reply)
			sync.mutex_lock(&m.mu)
			append(&m.threads, t)
			sync.mutex_unlock(&m.mu)
			free_all(context.temp_allocator)
			continue
		}

		reply, ok := build_reply(m, buf[:n], rule, false, context.temp_allocator)
		if ok {
			_, _ = net.send_udp(m.udp_socket, reply, client)
		}
		free_all(context.temp_allocator)
	}
}

// A delayed reply must not hold up the read loop, or concurrent queries would
// be serialised by the mock rather than by whatever is under test.
@(private = "file")
Delayed_Reply :: struct {
	mock:   ^Mock,
	client: net.Endpoint,
	query:  []u8,
	rule:   Mock_Rule,
}

@(private = "file")
delayed_udp_reply :: proc(job: ^Delayed_Reply) {
	m := job.mock
	reply, ok := build_reply(m, job.query, job.rule, false, context.temp_allocator)
	if ok && !sync.atomic_load(&m.stop) {
		_, _ = net.send_udp(m.udp_socket, reply, job.client)
	}
	delete(job.query)
	free(job)
	free_all(context.temp_allocator)
}

@(private = "file")
Mock_Conn :: struct {
	mock:   ^Mock,
	socket: net.TCP_Socket,
	tls:    bool,
}

@(private = "file")
mock_tcp_loop :: proc(m: ^Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, err := net.accept_tcp(m.tcp_socket)
		if err != nil {
			continue
		}
		_ = net.set_option(client, .Receive_Timeout, POLL_INTERVAL)
		conn := new(Mock_Conn)
		conn.mock = m
		conn.socket = client
		t := thread.create_and_start_with_poly_data(conn, mock_tcp_conn)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
mock_tls_loop :: proc(m: ^Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, err := net.accept_tcp(m.tcp_socket)
		if err != nil {
			continue
		}
		_ = net.set_option(client, .Receive_Timeout, POLL_INTERVAL)
		conn := new(Mock_Conn)
		conn.mock = m
		conn.socket = client
		conn.tls = true
		t := thread.create_and_start_with_poly_data(conn, mock_tcp_conn)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
mock_tcp_conn :: proc(conn: ^Mock_Conn) {
	m := conn.mock
	defer free(conn)

	tls_conn: ^tlsx.Conn
	if conn.tls {
		c, err := tlsx.server_accept(m.tls_ctx, conn.socket)
		if err != .None {
			net.close(conn.socket)
			return
		}
		tls_conn = c
	}
	// Cleanup is deferred at function scope on purpose. An Odin `defer` fires
	// when its enclosing block ends, so putting these inside the branches above
	// would tear the connection down before it was ever read from.
	defer {
		if tls_conn != nil {
			tlsx.close(tls_conn)
		} else {
			net.close(conn.socket)
		}
	}

	// The socket carries a short receive timeout so shutdown can interrupt it.
	// An idle connection must survive that: elodin pools upstream connections
	// and expects to reuse one minutes later, so a timeout only means "nothing
	// yet", and the loop keeps waiting until the peer actually goes away.
	read_full :: proc(conn: ^Mock_Conn, tls: ^tlsx.Conn, buf: []u8, deadline: time.Time) -> bool {
		got := 0
		for got < len(buf) {
			if sync.atomic_load(&conn.mock.stop) {
				return false
			}
			if conn.mock.idle_close > 0 && time.diff(deadline, time.now()) > 0 {
				return false
			}
			n: int
			if tls != nil {
				v, err := tlsx.read(tls, buf[got:])
				if err == .Timeout {
					continue
				}
				if err != .None || v <= 0 {
					return false
				}
				n = v
			} else {
				v, err := net.recv_tcp(conn.socket, buf[got:])
				if err == .Timeout {
					continue
				}
				if err != nil {
					return false
				}
				if v <= 0 {
					return false
				}
				n = v
			}
			got += n
		}
		return true
	}

	for !sync.atomic_load(&m.stop) {
		deadline := time.time_add(time.now(), m.idle_close)
		length_buf: [2]u8
		if !read_full(conn, tls_conn, length_buf[:], deadline) {
			return
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}
		query := make([]u8, length, context.temp_allocator)
		if !read_full(conn, tls_conn, query, time.time_add(time.now(), 5 * time.Second)) {
			return
		}

		sync.mutex_lock(&m.mu)
		if conn.tls {
			m.tls_queries += 1
		} else {
			m.tcp_queries += 1
		}
		record_query(m, query)
		sync.mutex_unlock(&m.mu)

		rule := match_rule(m, query)
		reply, ok := build_reply(m, query, rule, true, context.temp_allocator)
		if !ok {
			free_all(context.temp_allocator)
			continue
		}

		framed := make([]u8, 2 + len(reply), context.temp_allocator)
		framed[0] = u8(len(reply) >> 8)
		framed[1] = u8(len(reply))
		copy(framed[2:], reply)

		if tls_conn != nil {
			if _, err := tlsx.write(tls_conn, framed); err != .None {
				return
			}
		} else {
			sent := 0
			for sent < len(framed) {
				n, err := net.send_tcp(conn.socket, framed[sent:])
				if err != nil || n <= 0 {
					return
				}
				sent += n
			}
		}
		free_all(context.temp_allocator)
	}
}
