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
	// The upstream's own figure rather than the shipped one, which sits above
	// every number of callers the server can put in `exchange` at once and
	// would need hundreds of threads to reach. What is under test is the
	// branch, not the constant.
	BOUND :: 8
	LEGS :: BOUND + 4

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
	u.max_outstanding = BOUND

	/*
	The first wave fills the connection, and the rest go after it has settled.

	`get_pipe` reads the outstanding count under `u.mu` but a caller does not
	register until `pipe_query` takes `c.mu`, so the check and the reservation
	are not one step: callers released together can all see room and all take
	it. Harmless in itself - the overshoot is bounded by the number of callers,
	which is what the figure was bounding - but it would make this test's
	question ("did anyone past the bound get a connection of their own?") one
	the code does not actually promise. Letting the first wave register first
	asks the question the branch exists to answer instead of racing it.
	*/
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
		if i == BOUND - 1 {
			time.sleep(150 * time.Millisecond)
		}
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	testing.expectf(
		t,
		sync.atomic_load(&m.conns) >= 2,
		"%d callers past the bound of %d all queued onto one connection",
		LEGS - BOUND,
		BOUND,
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

	/*
	Queries onto the connection that will never answer until it has been given
	up on, then one after that.

	`PIPE_SILENT_TIMEOUTS` of them, because one lone timeout is a slow answer
	rather than a dead connection and this is deliberately not acted on until
	it has happened twice with nothing in between. The query after them is the
	whole test: it has to reach a second connection.
	*/
	wedged: [PIPE_SILENT_TIMEOUTS]Pipe_Leg
	for i in 0 ..< PIPE_SILENT_TIMEOUTS {
		wedged[i] = Pipe_Leg {
			u       = u,
			name    = "wedged.invalid.",
			id      = 0x3333,
			timeout = 400 * time.Millisecond,
		}
		th := thread.create_and_start_with_poly_data(&wedged[i], pipe_leg)
		thread.join(th)
		thread.destroy(th)
	}

	after := Pipe_Leg {
		u       = u,
		name    = "after.invalid.",
		id      = 0x4444,
		timeout = 2 * time.Second,
	}
	second := thread.create_and_start_with_poly_data(&after, pipe_leg)
	thread.join(second)
	thread.destroy(second)

	for leg, i in wedged {
		testing.expectf(t, leg.err == .Timeout, "query %d to the wedged connection ended as %v", i, leg.err)
	}
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
	/*
	Comfortably inside `PIPE_FRAMING_GRACE` of the prefix, since that grace is
	what the reader gets once it has committed the framing with little of its
	own deadline left. Past `IMPATIENT` all the same, which is what makes this
	a body that arrives after its reader has given up.
	*/
	BODY_AT :: 900 * time.Millisecond
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
	One dial's worth and a little, because every stage is handed the same
	deadline: the caller that dials spends the budget, and the ones queued
	behind it are past their own deadlines by the time it fails and never
	start a second.

	The window this sits in is worth naming, since a limit that catches
	nothing is worse than no limit. Four callers dialling one after another,
	which is what the queue used to cost, is four budgets. A single caller
	coming out of the queue and dialling on the full timeout rather than on
	what it had left - the narrower regression - is two. Measured, this lands
	a little over one.
	*/
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

Written against the property rather than against any one line that upholds it,
and three do: `pipe_query` takes the deadline rather than minting one,
`get_pipe` refuses to stage anything once it has passed, and
`exchange_pipelined` returns ahead of the redial. Removing any one of them
leaves the other two holding, and this test green - which is the point of
stating it this way. It goes red when the last of them goes.
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

	/*
	On the established connection, which is now silent. All but the last of
	these only count towards `PIPE_SILENT_TIMEOUTS`; the last is the one that
	marks the connection dead, and so the only one that could go on to retry.
	It is the one worth a clock.
	*/
	for _ in 0 ..< PIPE_SILENT_TIMEOUTS - 1 {
		warming := Pipe_Leg {
			u       = u,
			name    = "quiet.invalid.",
			id      = 0xaaaa,
			timeout = BUDGET,
		}
		th := thread.create_and_start_with_poly_data(&warming, pipe_leg)
		thread.join(th)
		thread.destroy(th)
	}

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

/*
A responder that answers one query, then sends a length a byte at a time and
never the message behind it.

The shape that tells one budget from two: the second byte arrives late enough
to consume most of a budget and early enough to be inside it, so a reader that
starts a fresh clock for what follows waits nearly twice as long as one that
does not.
*/
@(private = "file")
Stall_Mock :: struct {
	listener:  net.TCP_Socket,
	// When the first byte of the length prefix goes out, measured from the
	// query arriving. Late enough and the reader picks it up with little of
	// its own deadline left, which is the case a budget for finishing the
	// message has to be bounded against.
	first_at:  time.Duration,
	// When the second byte follows the first, or 0 for never.
	second_at: time.Duration,
	stop:      bool,
}

@(private = "file")
stall_mock_loop :: proc(m: ^Stall_Mock) {
	client, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 50 * time.Millisecond)

	// The warm-up, answered whole: it is what establishes the shared
	// connection and fixes the budget a half-read message is finished on.
	warm, warm_ok := stall_read_query(m, client)
	if !warm_ok {
		return
	}
	defer delete(warm)
	framed := make([]u8, 2 + len(warm), context.allocator)
	defer delete(framed)
	framed[0] = u8(len(warm) >> 8)
	framed[1] = u8(len(warm))
	copy(framed[2:], warm)
	framed[4] |= 0x80
	if write_all_tcp(client, framed) != .None {
		return
	}

	// Then one length, in two pieces, with nothing behind it.
	next, next_ok := stall_read_query(m, client)
	if !next_ok {
		return
	}
	defer delete(next)
	prefix := [2]u8{u8(len(next) >> 8), u8(len(next))}
	time.sleep(m.first_at)
	if write_all_tcp(client, prefix[:1]) != .None {
		return
	}
	if m.second_at > 0 {
		time.sleep(m.second_at)
		_ = write_all_tcp(client, prefix[1:])
	}

	for !sync.atomic_load(&m.stop) {
		time.sleep(10 * time.Millisecond)
	}
}

@(private = "file")
stall_read_query :: proc(m: ^Stall_Mock, client: net.TCP_Socket) -> (query: []u8, ok: bool) {
	length_buf: [2]u8
	if !stall_read(m, client, length_buf[:]) {
		return nil, false
	}
	length := int(length_buf[0]) << 8 | int(length_buf[1])
	if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
		return nil, false
	}
	query = make([]u8, length, context.allocator)
	if !stall_read(m, client, query) {
		delete(query)
		return nil, false
	}
	return query, true
}

@(private = "file")
stall_read :: proc(m: ^Stall_Mock, client: net.TCP_Socket, buf: []u8) -> bool {
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

/*
A message half read gets one budget, not one per read it takes.

The connection's budget is what a peer may spend on a message it has already
started - one message, so one clock. Started again for each read, a peer that
dribbles can hold the reader for as many budgets as it cares to split the
message into, which is the compounding `exchange_pipelined` gives every stage
one deadline to prevent, arriving a level further down. The reader is past its
own deadline throughout, holding a worker the caller above stopped waiting for.

Two pieces is enough to show it and is the smallest case there is: a length
byte, a pause most of a budget long, the second byte, and then nothing. One
clock expires while the body is awaited; two carry on into a second budget.
*/
@(test)
test_a_half_read_message_gets_one_budget :: proc(t: ^testing.T) {
	BUDGET :: 600 * time.Millisecond
	// Most of a budget, so the second byte lands well inside the first clock
	// and leaves little of it for what follows.
	SECOND_AT :: 400 * time.Millisecond
	// One budget and a margin. Two clocks is SECOND_AT + BUDGET, a full
	// quarter-second above this.
	LIMIT :: 8 * BUDGET / 6

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

	m := Stall_Mock {
		listener  = listener,
		second_at = SECOND_AT,
	}
	responder := thread.create_and_start_with_poly_data(&m, stall_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "stall", kind = .TCP, address = "127.0.0.1", port = bound.port},
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
		id      = 0xbbbb,
		timeout = BUDGET,
	}
	warmup := thread.create_and_start_with_poly_data(&warm, pipe_leg)
	thread.join(warmup)
	thread.destroy(warmup)
	if warm.err != .None {
		testing.expectf(t, false, "the warm-up query failed: %v", warm.err)
		return
	}

	stalled := Pipe_Leg {
		u       = u,
		name    = "stalled.invalid.",
		id      = 0xcccc,
		timeout = BUDGET,
	}
	start := time.now()
	th := thread.create_and_start_with_poly_data(&stalled, pipe_leg)
	thread.join(th)
	thread.destroy(th)
	took := time.diff(start, time.now())

	testing.expectf(t, stalled.err != .None, "a message that never arrived was answered")
	testing.expectf(
		t,
		took < LIMIT,
		"a half-read message held the reader %v on a budget of %v; each read started a clock of its own",
		took,
		BUDGET,
	)
}


/*
A reader that took the socket on late is still back inside a bounded overrun.

The budget for finishing a half-read message is the connection's rather than
the reader's, and that is deliberate: a reader with a sliver of its deadline
left must not abandon a message it has committed the framing to, because doing
so costs every other caller on the connection its answer. But the connection's
budget is the whole configured timeout, so granting it wholesale to a reader
that is already at its deadline is how one `send` comes to cost two - which is
the compounding `exchange_pipelined` gives every stage one deadline to prevent.

Both are right, and neither is the rule. What a peer may spend finishing a
message it has begun is not what a query may spend being answered: the first is
a transmission on an established connection and the second is a resolution.
`PIPE_FRAMING_GRACE` is the first of those, and the reader gets whichever of
its own remaining time and that grace is larger - so a reader with time to
spare overruns by nothing at all, and one at its deadline overruns by the
grace rather than by a whole timeout.
*/
@(test)
test_a_late_reader_overruns_by_the_grace_not_the_timeout :: proc(t: ^testing.T) {
	BUDGET :: 2 * time.Second
	// Most of the budget, so what is left when the reader commits the framing
	// is well under the grace and the grace is what it gets.
	FIRST_AT :: 3 * BUDGET / 4
	/*
	The overrun this permits is one grace on top of the budget. The regression
	it is written against is a whole second budget - FIRST_AT + BUDGET, half a
	second above this - which is what granting the connection's timeout to a
	reader that is already out of time costs.
	*/
	LIMIT :: FIRST_AT + PIPE_FRAMING_GRACE + BUDGET / 4

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

	// One byte of a length, late, and nothing behind it ever.
	m := Stall_Mock {
		listener = listener,
		first_at = FIRST_AT,
	}
	responder := thread.create_and_start_with_poly_data(&m, stall_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "late", kind = .TCP, address = "127.0.0.1", port = bound.port},
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
		id      = 0xdddd,
		timeout = BUDGET,
	}
	warmup := thread.create_and_start_with_poly_data(&warm, pipe_leg)
	thread.join(warmup)
	thread.destroy(warmup)
	if warm.err != .None {
		testing.expectf(t, false, "the warm-up query failed: %v", warm.err)
		return
	}

	late := Pipe_Leg {
		u       = u,
		name    = "late.invalid.",
		id      = 0xeeee,
		timeout = BUDGET,
	}
	start := time.now()
	th := thread.create_and_start_with_poly_data(&late, pipe_leg)
	thread.join(th)
	thread.destroy(th)
	took := time.diff(start, time.now())

	testing.expectf(t, late.err != .None, "a message that never arrived was answered")
	testing.expectf(
		t,
		took < LIMIT,
		"a reader that committed the framing with %v left held on for %v against a budget of %v",
		BUDGET - FIRST_AT,
		took,
		BUDGET,
	)
}

/*
A write that put nothing on the wire leaves the connection where it found it.

The read path has said this from the start: a read that only ran out of time
consumed nothing, so the stream is still in frame and what happened is one
caller's timeout rather than everybody's failure. The write has to say the
same, and for a sharper reason - the caller this bites is one that arrived with
its deadline already gone, and the connection it would take down is one every
other query in flight is using. A burst coming out of the dial queue is exactly
that: `get_pipe` lets a caller through on a nanosecond, and the first of them
to reach the write would destroy the connection that was just dialled for the
rest of them, which is the churn this whole change exists to remove.

Driven through the internals rather than through `exchange`, because what has
to be observed is the connection's state and not the query's answer.
*/
@(test)
test_a_write_that_sent_nothing_leaves_the_connection_alone :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the listener's port: %v", berr)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	// Nothing has to answer: the write is what is under test, and it never
	// gets as far as needing a reply.
	m := Mute_Mock {
		listener = listener,
		held     = make([dynamic]net.TCP_Socket, 0, 2),
	}
	acceptor := thread.create_and_start_with_poly_data(&m, mute_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(acceptor)
		thread.destroy(acceptor)
		delete(m.held)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "spent", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if uerr != .None {
		testing.expectf(t, false, "cannot make the upstream: %v", uerr)
		return
	}
	defer destroy(u)

	c, derr := dial_pipe(u, 5 * time.Second, 5 * time.Second)
	if derr != .None {
		testing.expectf(t, false, "cannot dial: %v", derr)
		return
	}
	defer _ = pipe_unref(c)

	query := dns.Message {
		id       = 0x3c3c,
		question = []dns.Question{{name = "spent.invalid.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.allocator)
	if enc != .None {
		testing.expectf(t, false, "cannot encode the query: %v", enc)
		return
	}
	defer delete(wire)

	// A deadline that has already passed, which is what a caller coming out of
	// the dial queue on a sliver arrives with.
	werr := pipe_write(c, wire, time.tick_now())
	_, dead := pipe_dead(c)

	testing.expectf(t, werr == .Timeout, "a write with no budget left reported %v", werr)
	testing.expectf(t, !dead, "a write that put nothing on the wire took the connection down with it")
}

/*
A server that recycles its connection costs nobody an answer.

Every DNS-over-TCP server hangs up on a connection eventually - the two public
resolvers this was written for do it inside fifteen seconds of idleness - so a
query landing on one that has just been recycled is ordinary operation. The
retry in `exchange_pipelined` is what makes it invisible, and it used to have a
hole in it: a connection this query had dialled itself was the one case not
retried, on the reading that a brand new connection failing means the server is
broken. A peer that limits how often a source may connect refuses a new
connection just as readily, and then the query that paid for the dial was the
only one with no second chance.

The mock answers one query, hangs up, and answers everything after that on the
next connection. What is asserted is that nothing about this reached the
caller or the upstream's health.
*/
@(private = "file")
Recycle_Mock :: struct {
	listener: net.TCP_Socket,
	// Queries answered before the first connection is closed.
	before:   int,
	conns:    int,
	served:   int,
	stop:     bool,
}

@(private = "file")
recycle_mock_loop :: proc(m: ^Recycle_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, aerr := net.accept_tcp(m.listener)
		if aerr != nil {
			if aerr == .Timeout || aerr == .Would_Block {
				continue
			}
			return
		}
		n := sync.atomic_add(&m.conns, 1)
		_ = net.set_option(client, .Receive_Timeout, 200 * time.Millisecond)
		// The first connection answers `before` queries and hangs up; later
		// ones stay put, which is what the retry has to find.
		budget := m.before if n == 0 else max(int)
		// The query is read before the hang-up rather than left in the receive
		// buffer, because `close` with unread data sends an RST and an RST is
		// `IO_Error` where a FIN is `Peer_Closed`. The connection being
		// recycled is the orderly one, and it is the one under test.
		for i := 0; ; i += 1 {
			length_buf: [2]u8
			if !recycle_read(m, client, length_buf[:]) {
				break
			}
			ln := int(length_buf[0]) << 8 | int(length_buf[1])
			if ln < dns.HEADER_SIZE || ln > 4096 {
				break
			}
			q := make([]u8, ln, context.temp_allocator)
			if !recycle_read(m, client, q) {
				break
			}
			if i >= budget {
				break
			}
			out := make([]u8, 2 + ln, context.temp_allocator)
			out[0], out[1] = length_buf[0], length_buf[1]
			copy(out[2:], q)
			out[4] |= 0x80
			if _, werr := net.send_tcp(client, out); werr != nil {
				break
			}
			sync.atomic_add(&m.served, 1)
		}
		net.close(client)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
recycle_read :: proc(m: ^Recycle_Mock, socket: net.TCP_Socket, buf: []u8) -> bool {
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

@(test)
test_a_recycled_connection_costs_no_answer_and_no_health :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		net.close(listener)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 200 * time.Millisecond)

	m := Recycle_Mock {
		listener = listener,
		// Nothing at all on the first connection: accepted, then dropped. So
		// the query that dialled it is the one that has to survive, which is
		// the case the retry used to skip.
		before   = 0,
	}
	responder := thread.create_and_start_with_poly_data(&m, recycle_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "recycler", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x4242,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if !testing.expectf(t, enc == .None, "cannot encode: %v", enc) {
		return
	}

	// This query dials, is hung up on without an answer, and must still come
	// back with one from the connection it dials next.
	_, e1 := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, e1 == .None, "the query that dialled was not retried: %v", e1)

	// And the connection it settled on carries the ones after it.
	_, e2 := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, e2 == .None, "the exchange after the retry failed: %v", e2)

	testing.expect(t, sync.atomic_load(&m.conns) >= 2, "the upstream never redialled")
	// The point of the whole thing: the recycle is not an upstream failure, so
	// it reaches neither the health counter nor the endpoint.
	st := stats_of(u)
	testing.expect_value(t, st.failures, 0)
	testing.expect(t, healthy(u), "a recycled connection put the upstream in its cooldown")
	free_all(context.temp_allocator)
}

/*
A peer hanging up does not bench the server.

`FAILURE_THRESHOLD` of these in a row used to park an upstream for `COOLDOWN`
and send every query in that window somewhere else - an outage far larger than
the one query that failed, on a server that was answering everything else. The
count still reaches the endpoint, because a server that really does close every
connection has to be nameable; what it no longer reaches is health.
*/
@(test)
test_a_hang_up_is_counted_but_does_not_park_the_upstream :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "closer", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	// Short of the run that says the server closes everything: each of these
	// is one recycled connection, and a success clears the count between them.
	for _ in 0 ..< 20 {
		for _ in 0 ..< FAILURE_THRESHOLD - 1 {
			record_failure(u, .Peer_Closed)
		}
		record_success(u, time.Millisecond)
	}
	testing.expect(t, healthy(u), "hang-ups parked an upstream that is still answering")

	st := stats_of(u)
	testing.expect_value(t, st.failures, u64(20 * (FAILURE_THRESHOLD - 1)))
	testing.expect_value(t, st.failure_kinds[.Peer_Closed], u64(20 * (FAILURE_THRESHOLD - 1)))

	// And what does say the server is unreachable still parks it at once.
	for _ in 0 ..< FAILURE_THRESHOLD {
		record_failure(u, .Dial_Failed)
	}
	testing.expect(t, !healthy(u), "a run of failed dials left the upstream up")
	free_all(context.temp_allocator)
}

/*
A server that closes everything it accepts is parked after all.

The exemption above is for a run, not forever. What reaches `record_failure` as
`Peer_Closed` has already had its retry hung up on too, so a run of them is no
longer a recycled connection but a server refusing to carry a query - and left
exempt it would never be parked while being asked for two connections per query
for as long as it kept it up, against the sort of peer that rate-limits exactly
that.
*/
@(test)
test_a_server_that_closes_everything_is_parked_eventually :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "shutter", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	// The first `FAILURE_THRESHOLD - 1` are exempt and each one past them
	// counts like any other failure, so the cooldown lands `FAILURE_THRESHOLD`
	// after that - `2 * FAILURE_THRESHOLD - 1` in all, not at once and not
	// never.
	for _ in 0 ..< 2 * FAILURE_THRESHOLD - 2 {
		record_failure(u, .Peer_Closed)
	}
	testing.expect(t, healthy(u), "a run of hang-ups parked the upstream too early")

	record_failure(u, .Peer_Closed)
	testing.expect(t, !healthy(u), "a server closing every connection was never parked")
	free_all(context.temp_allocator)
}

/*
The idle ceiling comes down to what the peer will actually hold.

Neither public resolver advertises edns-tcp-keepalive, so being hung up on is
the only way to learn the figure, and the shipped thirty seconds is longer than
either of them keeps a connection.
*/
/*
The locked accessor, under the lock, as `close_pipe` and `get_pipe` take it.

Here rather than beside `pipe_idle_ceiling_locked` because production has no
use for an unlocked one: an accessor that takes `u.mu` a second time inside a
sweep already holding it is the deadlock these tests exist under, and leaving
one in the package for the tests' sake leaves it there to be reached for.
*/
@(private = "file")
idle_ceiling :: proc(u: ^Upstream) -> time.Duration {
	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	return pipe_idle_ceiling_locked(u)
}

@(test)
test_the_idle_ceiling_is_learned_from_being_hung_up_on :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "learner", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	testing.expect_value(t, idle_ceiling(u), 30 * time.Second)

	// Hung up on after 12s idle: reap at three quarters of that from now on.
	note_idle_death(u, 12 * time.Second)
	testing.expect_value(t, idle_ceiling(u), 9 * time.Second)

	// A longer gap says nothing new - the peer was already known to hang up
	// sooner than that.
	note_idle_death(u, 20 * time.Second)
	testing.expect_value(t, idle_ceiling(u), 9 * time.Second)

	// A shorter one does.
	note_idle_death(u, 8 * time.Second)
	testing.expect_value(t, idle_ceiling(u), 6 * time.Second)

	// Below the floor it is the peer refusing this connection rather than a
	// timer, and following it would have the reaper outrunning the queries.
	note_idle_death(u, 100 * time.Millisecond)
	testing.expect_value(t, idle_ceiling(u), 6 * time.Second)

	// The configured value is still a ceiling, never raised by what is learned.
	v, verr := make_upstream(
		config.Upstream_Spec{name = "short", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		3 * time.Second,
	)
	if !testing.expectf(t, verr == .None, "cannot make the upstream: %v", verr) {
		return
	}
	defer destroy(v)
	note_idle_death(v, 20 * time.Second)
	testing.expect_value(t, idle_ceiling(v), 3 * time.Second)
	free_all(context.temp_allocator)
}

/*
Grooming an upstream that has a connection must come back.

`close_idle` holds `u.mu` for the whole sweep and `close_pipe` runs inside it,
so everything `close_pipe` reaches has to be the `_locked` half. The idle
ceiling is read there, and reading it through the unlocked accessor takes
`u.mu` a second time - which on a mutex that is not reentrant is the
maintenance loop wedged forever, holding the lock every query to this upstream
also needs. Cheap to assert because the failure is a hang rather than a value:
if this returns at all, the sweep did not take its own lock twice.
*/
@(test)
test_grooming_a_live_connection_returns :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		net.close(listener)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 200 * time.Millisecond)

	// Answers everything, so the sweep below finds a connection rather than
	// the nil the deadlock hides behind.
	m := Recycle_Mock {
		listener = listener,
		before   = max(int),
	}
	responder := thread.create_and_start_with_poly_data(&m, recycle_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "groomed", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x5151,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if !testing.expectf(t, enc == .None, "cannot encode: %v", enc) {
		return
	}
	_, e := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	if !testing.expectf(t, e == .None, "the exchange failed: %v", e) {
		return
	}

	// What the maintenance loop calls on every tick, for every upstream.
	closed := close_idle(u)
	testing.expectf(t, closed == 0, "a connection in use was swept: %v", closed)
	free_all(context.temp_allocator)
}

/*
A slow server does not teach an idle timeout.

`note_idle_death` is the record of a peer *hanging up*, and what it learns is
one-way, so every other way a connection can die ratchets the ceiling down for
the life of the process and never back up. A timeout is the case to keep out:
it says the peer took the query and went quiet, which is the opposite evidence
- the connection was still there. Left in, two slow names on a quiet forwarder
walk the ceiling down to `PIPE_IDLE_FLOOR` and the reaper then dials a fresh
connection for almost every query, against the upstream whose limit on how
often a source may connect is what this all started with.
*/
@(test)
test_a_timeout_does_not_teach_an_idle_ceiling :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		net.close(listener)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 50 * time.Millisecond)

	m := Silent_Mock {
		listener = listener,
		threads  = make([dynamic]^thread.Thread, 0, 2),
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
		config.Upstream_Spec{name = "slowpoke", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x6262,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if !testing.expectf(t, enc == .None, "cannot encode: %v", enc) {
		return
	}

	// The first lone timeout only counts; it leaves the connection up, and
	// moves `last` forward so the gap below is measured from here.
	_, e1 := exchange(u, wire, 200 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, e1 == .Timeout, "the silent server answered: %v", e1)

	// Past `PIPE_IDLE_FLOOR`, so this is a gap the ceiling would believe if a
	// timeout were allowed to teach it.
	time.sleep(PIPE_IDLE_FLOOR + 300 * time.Millisecond)

	// `PIPE_SILENT_TIMEOUTS` reached: this one takes the connection down, on a
	// timeout rather than a hang-up.
	_, e2 := exchange(u, wire, 200 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, e2 == .Timeout, "the silent server answered: %v", e2)

	testing.expect_value(t, idle_ceiling(u), 30 * time.Second)
	free_all(context.temp_allocator)
}

/*
A learned idle timeout is forgotten so it can be learned again.

What `note_idle_death` learns only ever comes down, so a hang-up that was
nothing to do with an idle timer - a restart, a drain, a deploy - is remembered
as if it were, and with the ceiling already low the gap it is observed at can
take what is learned to `PIPE_IDLE_FLOOR`. Left there it would outlive the
cause by the uptime of the process, dialling afresh for nearly every query on a
quiet forwarder. `close_idle` drops it once it is `PIPE_IDLE_RELEARN` old.
*/
@(test)
test_a_learned_idle_ceiling_is_forgotten_and_learned_again :: proc(t: ^testing.T) {
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "restarter", kind = .TCP, address = "127.0.0.1", port = 5353},
		0,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	note_idle_death(u, 4 * time.Second)
	testing.expect_value(t, idle_ceiling(u), 3 * time.Second)

	// A sweep while it is still fresh leaves it alone; otherwise the figure
	// would be thrown away before it was ever used.
	_ = close_idle(u)
	testing.expect_value(t, idle_ceiling(u), 3 * time.Second)

	// Aged past the window, the way the maintenance loop would find it an hour
	// on. Poked rather than waited for, which is the only part of this a test
	// cannot have for real.
	sync.mutex_lock(&u.mu)
	u.idle_learned = time.time_add(u.idle_learned, -(PIPE_IDLE_RELEARN + time.Second))
	sync.mutex_unlock(&u.mu)

	_ = close_idle(u)
	testing.expect_value(t, idle_ceiling(u), 30 * time.Second)

	// And it learns again from there rather than being stuck at the old floor.
	note_idle_death(u, 20 * time.Second)
	testing.expect_value(t, idle_ceiling(u), 15 * time.Second)
	free_all(context.temp_allocator)
}

/*
A reply cut in half is not a hang-up on the pipelined path either.

`pipe_read_full` reports EOF as `Peer_Closed` wherever it happens, and the
first byte of the length prefix is the only place that means what the name
says: from there on the message is committed and a close is a reply that
cannot be used. Passed through, a server truncating every response was retried
each time, exempt from the cooldown for a run, and taught `note_idle_death` an
idle ceiling - all for an error that says nothing about connection reuse.

The mock reads the whole query before answering, so the close is the orderly
one: it promises a reply of the length it was asked about and sends half.
*/
@(private = "file")
Truncate_Mock :: struct {
	listener: net.TCP_Socket,
	conns:    int,
	stop:     bool,
}

@(private = "file")
truncate_mock_loop :: proc(m: ^Truncate_Mock) {
	for !sync.atomic_load(&m.stop) {
		client, _, aerr := net.accept_tcp(m.listener)
		if aerr != nil {
			if aerr == .Timeout || aerr == .Would_Block {
				continue
			}
			return
		}
		sync.atomic_add(&m.conns, 1)
		_ = net.set_option(client, .Receive_Timeout, 200 * time.Millisecond)
		truncate_serve(m, client)
		net.close(client)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
truncate_serve :: proc(m: ^Truncate_Mock, client: net.TCP_Socket) {
	length_buf: [2]u8
	if !truncate_read(m, client, length_buf[:]) {
		return
	}
	ln := int(length_buf[0]) << 8 | int(length_buf[1])
	if ln < dns.HEADER_SIZE || ln > 4096 {
		return
	}
	q := make([]u8, ln, context.temp_allocator)
	if !truncate_read(m, client, q) {
		return
	}
	// The length prefix of a whole reply, and half of the reply. Half rather
	// than none, because none is the hang-up this is meant not to be.
	half := min(max(ln / 2, dns.HEADER_SIZE), ln - 1)
	out := make([]u8, 2 + half, context.temp_allocator)
	out[0], out[1] = length_buf[0], length_buf[1]
	copy(out[2:], q[:half])
	out[4] |= 0x80
	_, _ = net.send_tcp(client, out)
}

@(private = "file")
truncate_read :: proc(m: ^Truncate_Mock, socket: net.TCP_Socket, buf: []u8) -> bool {
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

@(test)
test_a_truncated_pipelined_reply_is_not_a_hang_up :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		net.close(listener)
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 200 * time.Millisecond)

	m := Truncate_Mock {
		listener = listener,
	}
	responder := thread.create_and_start_with_poly_data(&m, truncate_mock_loop)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(responder)
		thread.destroy(responder)
		net.close(listener)
	}

	u, uerr := make_upstream(
		config.Upstream_Spec{name = "truncator", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)

	query := dns.Message {
		id       = 0x5151,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	if !testing.expectf(t, enc == .None, "cannot encode: %v", enc) {
		return
	}

	_, err := exchange(u, wire, 2 * time.Second, context.temp_allocator)
	testing.expectf(t, err == .IO_Error, "a truncated reply was reported as %v", err)
	testing.expect(t, sync.atomic_load(&m.conns) >= 1, "the upstream never connected")
	free_all(context.temp_allocator)
}
