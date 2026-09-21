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
