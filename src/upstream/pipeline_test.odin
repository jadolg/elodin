package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
A TCP responder that answers nothing until two queries have arrived on one
connection, and then answers them in the order it was not asked.

Both halves are the point. It accepts exactly one connection and reads a second
query before writing anything, so a client that will not put a second query on
a connection it is already waiting on can never be answered - which is what
RFC 7766 section 6.2.1.1 asks a client not to do. It then replies to the second
query first, because section 7 recommends servers answer out of order and a
demultiplexer that assumed FIFO would take the wrong reply for the wrong
caller.

The connection is left open after both replies: a client that pipelines has
both answers already, and one that does not has nothing left to wait for.
*/
@(private = "file")
Pipe_Mock :: struct {
	listener: net.TCP_Socket,
	// Transaction IDs as they arrived on the wire, in order.
	ids:      [2]u16,
	// How many queries the one accepted connection carried.
	got:      int,
	conns:    int,
	stop:     bool,
}

@(private = "file")
pipe_mock_loop :: proc(m: ^Pipe_Mock) {
	client, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	sync.atomic_add(&m.conns, 1)
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 200 * time.Millisecond)

	// Read both queries before answering either.
	queries: [2][]u8
	for i in 0 ..< 2 {
		length_buf: [2]u8
		if !pipe_mock_read(m, client, length_buf[:]) {
			return
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}
		q := make([]u8, length, context.allocator)
		if !pipe_mock_read(m, client, q) {
			delete(q)
			return
		}
		queries[i] = q
		m.ids[i] = u16(q[0]) << 8 | u16(q[1])
		sync.atomic_add(&m.got, 1)
	}
	defer {
		delete(queries[0])
		delete(queries[1])
	}

	// Second first: out of order, as RFC 7766 section 7 lets a server answer.
	for i in 0 ..< 2 {
		q := queries[1 - i]
		framed := make([]u8, 2 + len(q), context.allocator)
		defer delete(framed)
		framed[0] = u8(len(q) >> 8)
		framed[1] = u8(len(q))
		copy(framed[2:], q)
		// The query echoed back with QR set is everything `response_matches`
		// asks for, and keeps an encoder out of this responder.
		framed[4] |= 0x80
		if write_all_tcp(client, framed) != .None {
			return
		}
	}

	// Hold the connection open until the test is done with it.
	for !sync.atomic_load(&m.stop) {
		time.sleep(10 * time.Millisecond)
	}
}

@(private = "file")
pipe_mock_read :: proc(m: ^Pipe_Mock, socket: net.TCP_Socket, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		if sync.atomic_load(&m.stop) {
			return false
		}
		n, err := net.recv_tcp(socket, buf[got:])
		if err == .Timeout || err == .Would_Block {
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

@(private = "file")
Pipe_Leg :: struct {
	u:       ^Upstream,
	name:    string,
	// The transaction ID the caller put on its query, which is the one the
	// answer has to come back carrying.
	id:      u16,
	timeout: time.Duration,
	err:     Error,
	reply_id: u16,
	// Whether the answer that came back answers this leg's question and not
	// the other leg's. Decided here rather than handed back, because the name
	// would be a string on this thread's allocator.
	own_question: bool,
}

@(private = "file")
pipe_leg :: proc(leg: ^Pipe_Leg) {
	query := dns.Message {
		id       = leg.id,
		question = []dns.Question{{name = leg.name, type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.allocator)
	if enc != .None {
		leg.err = .Bad_Response
		return
	}
	defer delete(wire)

	timeout := leg.timeout if leg.timeout > 0 else 3 * time.Second
	resp, err := exchange(leg.u, wire, timeout, context.allocator)
	leg.err = err
	if err != .None {
		return
	}
	// Read off and released here rather than handed back: this runs on a
	// thread of its own, and the test's allocator is not this one's.
	defer delete(resp)
	leg.reply_id = u16(resp[0]) << 8 | u16(resp[1])
	if q, ok := dns.peek_question(resp, context.temp_allocator); ok {
		leg.own_question = dns.name_equal_fold(q.name, leg.name)
	}
	free_all(context.temp_allocator)
}

/*
Two concurrent queries to a TCP upstream go out on one connection.

The responder above cannot answer at all unless they do, so this fails as two
timeouts against a client that holds a connection for one query at a time -
which is both what RFC 7766 section 6.2.2 tells a client not to do and, against
a resolver that rate-limits new connections, where a share of its queries go.

What the answers have to survive is checked alongside: they arrive in the order
opposite to the one they were asked in, so each has to be matched to its caller
rather than to whoever is next in line; the two queries carry distinct IDs on
the wire, since one connection cannot demultiplex two of the same; and each
answer comes back under the ID its caller wrote, which is the contract
`exchange` has with everything above it.
*/
@(test)
test_tcp_pipelines_onto_one_connection :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}

	m := Pipe_Mock {
		listener = listener,
	}
	_ = net.set_option(listener, .Receive_Timeout, 200 * time.Millisecond)
	responder := thread.create_and_start_with_poly_data(&m, pipe_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec {
			name = "pipe",
			kind = .TCP,
			address = "127.0.0.1",
			port = bound.port,
		},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	// The same transaction ID on both, so the distinct IDs the responder sees
	// can only have come from this package.
	legs := [2]Pipe_Leg {
		{u = u, name = "one.invalid.", id = 0x1234},
		{u = u, name = "two.invalid.", id = 0x1234},
	}
	threads: [2]^thread.Thread
	for i in 0 ..< 2 {
		threads[i] = thread.create_and_start_with_poly_data(&legs[i], pipe_leg)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	testing.expectf(t, sync.atomic_load(&m.conns) == 1, "the responder accepted %d connections, expected 1", sync.atomic_load(&m.conns))
	testing.expectf(t, sync.atomic_load(&m.got) == 2, "one connection carried %d queries, expected 2", sync.atomic_load(&m.got))
	testing.expectf(t, m.ids[0] != m.ids[1], "both queries went out under transaction id 0x%04x", m.ids[0])

	for leg, i in legs {
		testing.expectf(t, leg.err == .None, "leg %d (%s) failed: %v", i, leg.name, leg.err)
		if leg.err != .None {
			continue
		}
		testing.expectf(
			t,
			leg.reply_id == leg.id,
			"leg %d came back under id 0x%04x, expected the caller's 0x%04x",
			i,
			leg.reply_id,
			leg.id,
		)
		testing.expectf(t, leg.own_question, "leg %d was answered somebody else's question", i)
	}
}

/*
A responder that accepts every connection, reads every query and answers none.

The shape of an upstream that has stopped answering while its TCP stack has
not, which is the case `PIPELINE_MAX_OUTSTANDING` exists for.
*/
@(private = "file")
Silent_Mock :: struct {
	listener: net.TCP_Socket,
	conns:    int,
	stop:     bool,
	threads:  [dynamic]^thread.Thread,
	mu:       sync.Mutex,
}

@(private = "file")
silent_mock_loop :: proc(m: ^Silent_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, aerr := net.accept_tcp(m.listener)
		if aerr != nil {
			continue
		}
		sync.atomic_add(&m.conns, 1)
		_ = net.set_option(client, .Receive_Timeout, 50 * time.Millisecond)
		conn := new(Silent_Conn)
		conn.mock = m
		conn.socket = client
		t := thread.create_and_start_with_poly_data(conn, silent_conn_loop)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
Silent_Conn :: struct {
	mock:   ^Silent_Mock,
	socket: net.TCP_Socket,
}

// Drain whatever arrives, so the queries are read and never answered rather
// than left to fill a socket buffer.
@(private = "file")
silent_conn_loop :: proc(conn: ^Silent_Conn) {
	defer free(conn)
	defer net.close(conn.socket)
	buf: [4096]u8
	for !sync.atomic_load(&conn.mock.stop) {
		n, err := net.recv_tcp(conn.socket, buf[:])
		if err == .Timeout || err == .Would_Block {
			continue
		}
		if err != nil || n <= 0 {
			return
		}
	}
}

/*
Past `PIPELINE_MAX_OUTSTANDING` a caller opens a connection of its own.

The bound is what keeps an upstream that has stopped answering from costing an
unbounded queue of waiters on one connection. What it must not do is shut the
callers past it out: they get a connection of their own, so a stalled upstream
slows them down rather than failing them for want of a slot. Checked with a
responder that answers nothing, since that is the only way to hold 64 queries
outstanding at once, and what the extra callers prove is that the mock saw a
second connection - which under the shared path alone it never would.
*/
@(test)
test_a_full_connection_does_not_shut_callers_out :: proc(t: ^testing.T) {
	LEGS :: PIPELINE_MAX_OUTSTANDING + 4

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	m := Silent_Mock {
		listener = listener,
		threads  = make([dynamic]^thread.Thread, 0, LEGS),
	}
	acceptor := thread.create_and_start_with_poly_data(&m, silent_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(acceptor)
		thread.destroy(acceptor)
		for th in m.threads {
			thread.join(th)
			thread.destroy(th)
		}
		delete(m.threads)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "full", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	legs := make([]Pipe_Leg, LEGS)
	defer delete(legs)
	threads := make([]^thread.Thread, LEGS)
	defer delete(threads)
	for i in 0 ..< LEGS {
		legs[i] = Pipe_Leg {
			u       = u,
			name    = "full.invalid.",
			id      = 0x4242,
			timeout = 700 * time.Millisecond,
		}
		threads[i] = thread.create_and_start_with_poly_data(&legs[i], pipe_leg)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	testing.expectf(
		t,
		sync.atomic_load(&m.conns) >= 2,
		"%d callers past the bound of %d all queued onto one connection",
		LEGS - PIPELINE_MAX_OUTSTANDING,
		PIPELINE_MAX_OUTSTANDING,
	)
	for leg, i in legs {
		testing.expectf(t, leg.err == .Timeout, "leg %d ended as %v, expected a timeout", i, leg.err)
	}
}

/*
A responder that reads two queries, waits, and then answers only the second.

The first caller is left to run out of time while the second's answer is still
coming, which is what puts the reading in the hands of a caller that is about
to give up.
*/
@(private = "file")
Handoff_Mock :: struct {
	listener: net.TCP_Socket,
	delay:    time.Duration,
	stop:     bool,
}

@(private = "file")
handoff_mock_loop :: proc(m: ^Handoff_Mock) {
	client, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 200 * time.Millisecond)

	second: []u8
	defer delete(second)
	for i in 0 ..< 2 {
		length_buf: [2]u8
		got := 0
		for got < 2 {
			n, err := net.recv_tcp(client, length_buf[got:])
			if err == .Timeout || err == .Would_Block {
				if sync.atomic_load(&m.stop) {
					return
				}
				continue
			}
			if err != nil || n <= 0 {
				return
			}
			got += n
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}
		q := make([]u8, length)
		got = 0
		for got < length {
			n, err := net.recv_tcp(client, q[got:])
			if err == .Timeout || err == .Would_Block {
				continue
			}
			if err != nil || n <= 0 {
				delete(q)
				return
			}
			got += n
		}
		if i == 1 {
			second = q
		} else {
			delete(q)
		}
	}

	time.sleep(m.delay)
	framed := make([]u8, 2 + len(second))
	defer delete(framed)
	framed[0] = u8(len(second) >> 8)
	framed[1] = u8(len(second))
	copy(framed[2:], second)
	framed[4] |= 0x80
	_ = write_all_tcp(client, framed)

	for !sync.atomic_load(&m.stop) {
		time.sleep(10 * time.Millisecond)
	}
}

/*
A caller that gives up hands the reading on rather than taking it with it.

Whoever is reading the shared socket is a caller like any other, so it has a
deadline of its own and will reach it while other callers are still waiting.
What it must not do is leave, because the others are parked on the condition
and nothing else will read their replies off the wire - they would each sit
until their own deadline with the answer already in the socket, which turns one
slow query into everybody's timeout.

The margin is what makes this a check rather than a coincidence: the answer is
on the wire at `DELAY` and the waiter's own deadline is an order of magnitude
past it, so a run that only notices when its own wait expires is unmistakable.
*/
@(test)
test_a_caller_that_gives_up_hands_on_the_reading :: proc(t: ^testing.T) {
	DELAY :: 400 * time.Millisecond
	// Long enough that returning at the deadline instead of at the answer is
	// not something a loaded box could produce.
	PATIENT :: 8 * time.Second
	LIMIT :: 3 * time.Second

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 200 * time.Millisecond)

	m := Handoff_Mock {
		listener = listener,
		delay    = DELAY,
	}
	responder := thread.create_and_start_with_poly_data(&m, handoff_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "handoff", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	// The impatient one first, and given a head start, so it is the one that
	// takes on the reading and the one that then walks away from it.
	quitter := Pipe_Leg {
		u       = u,
		name    = "quitter.invalid.",
		id      = 0x1111,
		timeout = DELAY / 2,
	}
	patient := Pipe_Leg {
		u       = u,
		name    = "patient.invalid.",
		id      = 0x2222,
		timeout = PATIENT,
	}
	first := thread.create_and_start_with_poly_data(&quitter, pipe_leg)
	time.sleep(50 * time.Millisecond)
	start := time.now()
	second := thread.create_and_start_with_poly_data(&patient, pipe_leg)
	for th in ([]^thread.Thread{first, second}) {
		thread.join(th)
		thread.destroy(th)
	}
	took := time.diff(start, time.now())

	testing.expectf(t, quitter.err == .Timeout, "the impatient caller ended as %v, expected a timeout", quitter.err)
	testing.expectf(t, patient.err == .None, "the patient caller failed: %v", patient.err)
	testing.expectf(t, patient.own_question, "the patient caller was answered somebody else's question")
	testing.expectf(t, took < LIMIT, "the patient caller waited %v for an answer that was on the wire at %v", took, DELAY)
}

/*
A responder that wedges its first connection and answers normally on its
second.

The first connection is read from and never answered, and it is never closed
either - the shape a NAT or a stateful firewall leaves behind when it evicts an
idle mapping, or an upstream that reboots without getting a FIN out. Nothing on
this side of the wire is told anything: the writes still succeed into the send
buffer and the reads simply never come back.
*/
@(private = "file")
Wedge_Mock :: struct {
	listener: net.TCP_Socket,
	conns:    int,
	// Connections before this one are read from and never answered. 2 wedges
	// the first and answers on every one after it.
	answer_from: int,
	// Queries this mock will answer in total, across every connection, or -1
	// for as many as it is asked. 1 is a server that answers once and then
	// stops for good, whatever it is dialled on.
	budget:   int,
	answered: int,
	stop:     bool,
	threads:  [dynamic]^thread.Thread,
	mu:       sync.Mutex,
}

@(private = "file")
Wedge_Conn :: struct {
	mock:   ^Wedge_Mock,
	socket: net.TCP_Socket,
	// The first connection is the wedged one.
	answer: bool,
}

@(private = "file")
wedge_mock_loop :: proc(m: ^Wedge_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, aerr := net.accept_tcp(m.listener)
		if aerr != nil {
			continue
		}
		n := sync.atomic_add(&m.conns, 1) + 1
		_ = net.set_option(client, .Receive_Timeout, 50 * time.Millisecond)
		conn := new(Wedge_Conn)
		conn.mock = m
		conn.socket = client
		conn.answer = n >= m.answer_from
		t := thread.create_and_start_with_poly_data(conn, wedge_conn_loop)
		sync.mutex_lock(&m.mu)
		append(&m.threads, t)
		sync.mutex_unlock(&m.mu)
	}
}

@(private = "file")
wedge_conn_loop :: proc(conn: ^Wedge_Conn) {
	defer free(conn)
	defer net.close(conn.socket)
	for !sync.atomic_load(&conn.mock.stop) {
		length_buf: [2]u8
		if !wedge_read(conn, length_buf[:]) {
			return
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}
		q := make([]u8, length, context.allocator)
		defer delete(q)
		if !wedge_read(conn, q) {
			return
		}
		if !conn.answer || !wedge_may_answer(conn.mock) {
			// Read and dropped, with the connection left open.
			continue
		}
		framed := make([]u8, 2 + len(q), context.allocator)
		defer delete(framed)
		framed[0] = length_buf[0]
		framed[1] = length_buf[1]
		copy(framed[2:], q)
		framed[4] |= 0x80
		if write_all_tcp(conn.socket, framed) != .None {
			return
		}
	}
}

// Whether this mock has an answer left to give, under `Wedge_Mock.budget`.
@(private = "file")
wedge_may_answer :: proc(m: ^Wedge_Mock) -> bool {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	if m.budget < 0 {
		return true
	}
	if m.answered >= m.budget {
		return false
	}
	m.answered += 1
	return true
}

@(private = "file")
wedge_read :: proc(conn: ^Wedge_Conn, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		if sync.atomic_load(&conn.mock.stop) {
			return false
		}
		n, err := net.recv_tcp(conn.socket, buf[got:])
		if err == .Timeout || err == .Would_Block {
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

/*
A connection that has stopped answering is dropped, not kept and reused.

The pooled path this replaced recovered from it on the very next query: any
failed round trip closed the socket, so the query after a silent upstream
dialled a fresh connection and got an answer. A shared connection must not be
torn down over one slow query - that would take every other query in flight
with it - but it must still be torn down when it is the *connection* that has
stopped, and the two are told apart by whether anything at all came back on it
while this caller was waiting.

Without that, nothing here ever closes the connection: the writes go on
succeeding into the send buffer, every read times out, and the idle reaper
cannot help because a connection under steady traffic is never idle. The
upstream stays wedged on one useless socket until the kernel gives up on the
unacked data, which on Linux is about fifteen minutes.
*/
@(test)
test_a_connection_that_stopped_answering_is_dropped :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	m := Wedge_Mock {
		listener    = listener,
		answer_from = 2,
		budget      = -1,
		threads     = make([dynamic]^thread.Thread, 0, 4),
	}
	acceptor := thread.create_and_start_with_poly_data(&m, wedge_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(acceptor)
		thread.destroy(acceptor)
		for th in m.threads {
			thread.join(th)
			thread.destroy(th)
		}
		delete(m.threads)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "wedged", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	// One query onto the connection that will never answer, then one after it.
	// The second is the whole test: it has to reach the second connection.
	wedged := Pipe_Leg {
		u       = u,
		name    = "wedged.invalid.",
		id      = 0x3333,
		timeout = 400 * time.Millisecond,
	}
	first := thread.create_and_start_with_poly_data(&wedged, pipe_leg)
	thread.join(first)
	thread.destroy(first)

	after := Pipe_Leg {
		u       = u,
		name    = "after.invalid.",
		id      = 0x4444,
		timeout = 2 * time.Second,
	}
	second := thread.create_and_start_with_poly_data(&after, pipe_leg)
	thread.join(second)
	thread.destroy(second)

	testing.expectf(t, wedged.err == .Timeout, "the query to the wedged connection ended as %v", wedged.err)
	testing.expectf(t, after.err == .None, "the query after it failed: %v", after.err)
	testing.expectf(t, after.own_question, "the query after it was answered somebody else's question")
	testing.expectf(
		t,
		sync.atomic_load(&m.conns) == 2,
		"the responder saw %d connections, expected the wedged one to be dropped and a second dialled",
		sync.atomic_load(&m.conns),
	)
}

/*
A responder that answers one query normally, then splits the next answer.

The split is the point: the two-byte length prefix goes out well before the
message it counts. A reader that picks up the prefix has committed the
connection's framing to finishing that message, whatever it had left of its own
deadline when it started.
*/
@(private = "file")
Split_Mock :: struct {
	listener:    net.TCP_Socket,
	// After the warm-up: when the length prefix goes out, and when the body
	// behind it follows.
	prefix_at:   time.Duration,
	body_at:     time.Duration,
	/*
	Split the two-byte length prefix as well, one byte at each moment.

	A server would not normally write it in two pieces, but a segment boundary
	falling between the two bytes puts it on the wire that way, and the reader
	cannot tell the difference. Worth its own case because one byte of a prefix
	commits the framing exactly as a half-read body does.
	*/
	split_prefix: bool,
	stop:        bool,
}

@(private = "file")
split_mock_loop :: proc(m: ^Split_Mock) {
	client, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 50 * time.Millisecond)

	// The warm-up query, answered at once: it is what establishes the shared
	// connection, so the connection is the one a later caller finds rather than
	// one that caller dialled itself.
	warm, warm_ok := split_read_query(m, client)
	if !warm_ok {
		return
	}
	defer delete(warm)
	if !split_write(client, warm, whole = true, m = m) {
		return
	}

	// Then the two pipelined queries. The second is the one answered.
	first, first_ok := split_read_query(m, client)
	if !first_ok {
		return
	}
	defer delete(first)
	second, second_ok := split_read_query(m, client)
	if !second_ok {
		return
	}
	defer delete(second)

	start := time.now()
	time.sleep(m.prefix_at)
	prefix := [2]u8{u8(len(second) >> 8), u8(len(second))}
	early := prefix[:1] if m.split_prefix else prefix[:]
	if write_all_tcp(client, early) != .None {
		return
	}
	// Measured from the start so the gap is the one configured rather than the
	// sum of two sleeps.
	time.sleep(m.body_at - time.diff(start, time.now()))
	if m.split_prefix {
		if write_all_tcp(client, prefix[1:]) != .None {
			return
		}
	}
	body := make([]u8, len(second), context.allocator)
	defer delete(body)
	copy(body, second)
	body[2] |= 0x80
	_ = write_all_tcp(client, body)

	for !sync.atomic_load(&m.stop) {
		time.sleep(10 * time.Millisecond)
	}
}

@(private = "file")
split_read_query :: proc(m: ^Split_Mock, client: net.TCP_Socket) -> (query: []u8, ok: bool) {
	length_buf: [2]u8
	if !split_read(m, client, length_buf[:]) {
		return nil, false
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
		return nil, false
	}
	query = make([]u8, length, context.allocator)
	if !split_read(m, client, query) {
		delete(query)
		return nil, false
	}
	return query, true
}

@(private = "file")
split_read :: proc(m: ^Split_Mock, client: net.TCP_Socket, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		if sync.atomic_load(&m.stop) {
			return false
		}
		n, err := net.recv_tcp(client, buf[got:])
		if err == .Timeout || err == .Would_Block {
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		got += n
	}
	return true
}

@(private = "file")
split_write :: proc(client: net.TCP_Socket, query: []u8, whole: bool, m: ^Split_Mock) -> bool {
	framed := make([]u8, 2 + len(query), context.allocator)
	defer delete(framed)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)
	framed[4] |= 0x80
	return write_all_tcp(client, framed) == .None
}

/*
A message half read is finished on the connection's own budget, not the
reader's.

Whoever reads the socket is a caller like any other, and the ordinary case for
taking the reading on is a waiter that woke with a sliver of its deadline left
- which is exactly why the read timeout has a floor. Such a reader that catches
the length prefix of an answer whose body is still arriving has committed the
framing: it cannot stop there. Giving the body what is left of that caller's
deadline is how one nearly-expired reader plus one answer split across segments
tears down the shared connection and fails every query on it - the connection
churn this is all meant to stop, arriving by another route.

The warm-up query is not decoration: it is what makes the connection one the
callers below found rather than one of them dialled, which is the ordinary
state of a shared connection and the only state in which the budgets differ.
*/
@(test)
test_a_half_read_message_is_finished_on_the_connections_budget :: proc(t: ^testing.T) {
	for split_prefix in ([]bool{false, true}) {
		half_read_case(t, split_prefix)
	}
}

/*
One run of the above: `split_prefix` chooses whether what the impatient reader
catches is the whole length prefix or the first byte of it.

Both are the same rule and the same failure. The bound starts at the first byte
consumed, not at the second: a reader holding one byte of a length it cannot
read yet has committed the connection's framing just as surely as one holding a
header without its records.
*/
@(private = "file")
half_read_case :: proc(t: ^testing.T, split_prefix: bool) {
	PREFIX_AT :: 300 * time.Millisecond
	BODY_AT :: 1200 * time.Millisecond
	// Past PREFIX_AT, so this caller is in the body read when its own deadline
	// arrives, and well under BODY_AT.
	IMPATIENT :: 600 * time.Millisecond
	PATIENT :: 6 * time.Second

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	m := Split_Mock {
		listener     = listener,
		prefix_at    = PREFIX_AT,
		body_at      = BODY_AT,
		split_prefix = split_prefix,
	}
	responder := thread.create_and_start_with_poly_data(&m, split_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "split", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	warm := Pipe_Leg {
		u       = u,
		name    = "warm.invalid.",
		id      = 0x5555,
		timeout = PATIENT,
	}
	warmup := thread.create_and_start_with_poly_data(&warm, pipe_leg)
	thread.join(warmup)
	thread.destroy(warmup)
	if warm.err != .None {
		testing.expectf(t, false, "the warm-up query failed: %v", warm.err)
		return
	}

	quitter := Pipe_Leg {
		u       = u,
		name    = "quitter.invalid.",
		id      = 0x6666,
		timeout = IMPATIENT,
	}
	patient := Pipe_Leg {
		u       = u,
		name    = "patient.invalid.",
		id      = 0x7777,
		timeout = PATIENT,
	}
	first := thread.create_and_start_with_poly_data(&quitter, pipe_leg)
	time.sleep(50 * time.Millisecond)
	second := thread.create_and_start_with_poly_data(&patient, pipe_leg)
	for th in ([]^thread.Thread{first, second}) {
		thread.join(th)
		thread.destroy(th)
	}

	what := "a split length prefix" if split_prefix else "a body behind its prefix"
	testing.expectf(t, quitter.err == .Timeout, "%s: the impatient caller ended as %v, expected a timeout", what, quitter.err)
	testing.expectf(t, patient.err == .None, "%s: the patient caller failed: %v", what, patient.err)
	testing.expectf(t, patient.own_question, "%s: the patient caller was answered somebody else's question", what)
}

/*
A responder that accepts connections and never speaks, so a TLS handshake on
one runs to its deadline.

The blackhole a dial has to survive, made locally: the peer is there, the
connect succeeds and the ClientHello goes out, and nothing comes back.
*/
@(private = "file")
Mute_Mock :: struct {
	listener: net.TCP_Socket,
	stop:     bool,
	held:     [dynamic]net.TCP_Socket,
	mu:       sync.Mutex,
}

@(private = "file")
mute_mock_loop :: proc(m: ^Mute_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, aerr := net.accept_tcp(m.listener)
		if aerr != nil {
			continue
		}
		sync.mutex_lock(&m.mu)
		append(&m.held, client)
		sync.mutex_unlock(&m.mu)
	}
	sync.mutex_lock(&m.mu)
	for s in m.held {
		net.close(s)
	}
	sync.mutex_unlock(&m.mu)
}

/*
A caller waiting for somebody else's dial is bounded by its own deadline.

Sharing one connection means sharing one handshake, which is the whole point:
a burst of concurrent first queries must not each open - and then all but one
discard - a connection of its own. But a dial against a blackholed upstream
takes the full timeout and fails, and the caller that was waiting for it must
not then start a dial of its own with the next one waiting behind that. Four
callers with a five second timeout would be twenty seconds, and each of them
would be holding an upstream worker for four times the budget it was given.

What this holds is the budget: every caller is back inside its own timeout,
whatever the caller in front of it did.
*/
@(test)
test_waiting_for_a_dial_is_bounded_by_the_callers_own_timeout :: proc(t: ^testing.T) {
	LEGS :: 4
	BUDGET :: 400 * time.Millisecond
	/*
	Two dials' worth, which is the bound: a caller that breaks out of the
	queue with a sliver of its deadline left still dials on the full timeout,
	so one dial can follow another, but the caller behind *that* is past its
	deadline and never starts a third. Four in a row, which is what this is
	looking for, is twice this.
	*/
	LIMIT :: 3 * BUDGET

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	m := Mute_Mock {
		listener = listener,
		held     = make([dynamic]net.TCP_Socket, 0, LEGS),
	}
	acceptor := thread.create_and_start_with_poly_data(&m, mute_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(acceptor)
		thread.destroy(acceptor)
		delete(m.held)
		net.close(listener)
	}

	// TLS, because a handshake is a dial with a read in it: a plain connect to
	// a listener that is accepting returns at once, and what has to be bounded
	// here is a dial that does not.
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "mute", kind = .TLS, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	legs: [LEGS]Pipe_Leg
	threads: [LEGS]^thread.Thread
	start := time.now()
	for i in 0 ..< LEGS {
		legs[i] = Pipe_Leg {
			u       = u,
			name    = "mute.invalid.",
			id      = 0x8888,
			timeout = BUDGET,
		}
		threads[i] = thread.create_and_start_with_poly_data(&legs[i], pipe_leg)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	took := time.diff(start, time.now())

	for leg, i in legs {
		testing.expectf(t, leg.err != .None, "leg %d was answered by a responder that never speaks", i)
	}
	testing.expectf(
		t,
		took < LIMIT,
		"%d callers took %v against a budget of %v each; they dialled one after another",
		LEGS,
		took,
		BUDGET,
	)
}


/*
One `send` costs one timeout, not one per stage it happens to pass through.

Waiting for somebody else's dial, dialling, asking, and then the retry of a
connection found dead are four stages, and each one used to start its own clock
from whatever it was handed. An upstream that answers once and then goes quiet
walks a query through the worst of them: the query on the established
connection runs out its timeout, that marks the connection dead - which is what
makes a server that vanished recoverable at all - and the retry then dialled
and asked again on a fresh budget. Twice the timeout for a query whose caller
stopped waiting after one, with an upstream worker held for all of it and
`attempts` above this ready to multiply it.

The recovery does not depend on that retry and this does not remove it: what
the retry is for is a connection found dead *before* any time was spent on it,
where the budget is still whole. `test_a_connection_that_stopped_answering_is_dropped`
holds the other half - the next query dials afresh - and needs no budget at all
to do it.
*/
@(test)
test_one_send_costs_one_timeout :: proc(t: ^testing.T) {
	BUDGET :: 500 * time.Millisecond
	// One timeout and room for scheduling; two is what this is looking for.
	LIMIT :: 8 * BUDGET / 5

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		net.close(listener)
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	// Answers on any connection, but only once: the first query establishes the
	// shared connection and every query after it is met with silence, on that
	// connection and on any the retry dials.
	m := Wedge_Mock {
		listener    = listener,
		answer_from = 1,
		budget      = 1,
		threads     = make([dynamic]^thread.Thread, 0, 4),
	}
	acceptor := thread.create_and_start_with_poly_data(&m, wedge_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(acceptor)
		thread.destroy(acceptor)
		for th in m.threads {
			thread.join(th)
			thread.destroy(th)
		}
		delete(m.threads)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "once", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	warm := Pipe_Leg {
		u       = u,
		name    = "warm.invalid.",
		id      = 0x9999,
		timeout = BUDGET,
	}
	warmup := thread.create_and_start_with_poly_data(&warm, pipe_leg)
	thread.join(warmup)
	thread.destroy(warmup)
	if warm.err != .None {
		testing.expectf(t, false, "the warm-up query failed: %v", warm.err)
		return
	}

	// On the established connection, which is now silent.
	quiet := Pipe_Leg {
		u       = u,
		name    = "quiet.invalid.",
		id      = 0xaaaa,
		timeout = BUDGET,
	}
	start := time.now()
	second := thread.create_and_start_with_poly_data(&quiet, pipe_leg)
	thread.join(second)
	thread.destroy(second)
	took := time.diff(start, time.now())

	testing.expectf(t, quiet.err == .Timeout, "the query to the quiet connection ended as %v", quiet.err)
	testing.expectf(
		t,
		took < LIMIT,
		"one send took %v against a timeout of %v; its stages each started a clock of their own",
		took,
		BUDGET,
	)
}
