package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:loop"
import "elodin:testkit"

/*
A cookie-aware responder on loopback.

Scripted rather than canned, because what is under test is a conversation: the
first query has no server cookie to show, the reply carries one, and the next
query has to come back with it.
*/
@(private = "file")
Cookie_Mock :: struct {
	socket:     net.UDP_Socket,
	stop:       bool,
	server:     [8]u8,
	// Echo a client cookie that is not the one the query carried, the way an
	// off-path forgery would have to.
	forge:      bool,
	// Answer BADCOOKIE until a query turns up carrying the server cookie.
	demand:     bool,
	// Answer BADCOOKIE to every query, server cookie or not: an anycast node
	// whose secret is not the one that issued it (RFC 7873 section 5.3).
	always_bad: bool,
	// Give each reply a server cookie of its own: the last byte of `server` is
	// the reply's count, the way a node with a rotating secret would.
	rotate:     bool,
	/*
	Stop putting a COOKIE option in replies once this many have carried one.

	Leaving the option off is the cheaper thing for an off-path forgery to do
	than reproduce a cookie it has never seen. `nil` keeps sending them, and 0
	plays a server that does not implement cookies at all.
	*/
	drop_after: Maybe(int),
	// Reply with a server cookie shorter than the eight bytes RFC 7873 allows.
	short:      bool,
	// Answer only this many queries; `nil` answers every one.
	answer:     Maybe(int),

	mu:         sync.Mutex,
	queries:    int,
	last_query: [512]u8,
	last_len:   int,
}

@(private = "file")
cookie_mock_loop :: proc(m: ^Cookie_Mock) {
	buf: [1500]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}

		sync.mutex_lock(&m.mu)
		m.queries += 1
		count := m.queries
		m.last_len = copy(m.last_query[:], buf[:n])
		sync.mutex_unlock(&m.mu)

		if limit, capped := m.answer.?; capped && count > limit {
			continue
		}
		reply, ok := cookie_mock_reply(m, buf[:n], count)
		if ok {
			_, _ = net.send_udp(m.socket, reply, client)
		}
		free_all(context.temp_allocator)
	}
}

@(private = "file")
cookie_mock_reply :: proc(m: ^Cookie_Mock, query: []u8, count: int) -> (reply: []u8, ok: bool) {
	msg, derr := dns.decode_message(query, context.temp_allocator)
	if derr != .None {
		return nil, false
	}
	sent, has_cookie := dns.find_edns_option(msg, .Cookie)

	rcode := dns.Rcode.No_Error
	if (m.demand && len(sent) < COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN) || m.always_bad {
		rcode = .Bad_Cookie
	}
	resp := dns.make_response(msg, rcode, context.temp_allocator)
	wire, _, eerr := dns.encode_message(resp, context.temp_allocator)
	if eerr != .None {
		return nil, false
	}
	if !has_cookie {
		return wire, true
	}
	if limit, capped := m.drop_after.?; capped && count > limit {
		return wire, true
	}

	option: [COOKIE_CLIENT_LEN + len(m.server)]u8
	copy(option[:COOKIE_CLIENT_LEN], sent[:min(COOKIE_CLIENT_LEN, len(sent))])
	if m.forge {
		option[0] ~= 0xff
	}
	copy(option[COOKIE_CLIENT_LEN:], m.server[:])
	if m.rotate {
		option[len(option) - 1] = u8(count)
	}
	// A server cookie shorter than any RFC 7873 section 4 allows.
	written := option[:COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN / 2] if m.short else option[:]
	out, set_ok := dns.set_edns_option(wire, .Cookie, written, context.temp_allocator)
	if !set_ok {
		return wire, true
	}
	return out, true
}

@(private = "file")
start_cookie_mock :: proc(t: ^testing.T, m: ^Cookie_Mock) -> (u: ^Upstream, worker: ^thread.Thread, ok: bool) {
	return start_udp_mock(t, m, cookie_mock_loop, cookies = true)
}

@(private = "file")
edns_query :: proc(name: string, with_opt := true) -> []u8 {
	q := dns.Message {
		id       = 0x2A2A,
		question = []dns.Question{{name = name, type = .A, class = .IN}},
	}
	q.flags.rd = true
	if with_opt {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, false)
		q.additional = additional
	}
	wire, _, _ := dns.encode_message(q, context.temp_allocator)
	return wire
}

@(private = "file")
seen_cookie :: proc(m: ^Cookie_Mock) -> (cookie: []u8, found: bool) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	msg, err := dns.decode_message(m.last_query[:m.last_len], context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(msg, .Cookie)
}

/*
The first query has only a client cookie to offer; the answer teaches us a
server cookie, and the next query carries it.
*/
@(test)
test_upstream_cookie_is_sent_and_learned :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	first, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "first exchange failed: %v", err)

	asked, had := seen_cookie(&m)
	if testing.expect(t, had, "the query carried no cookie") {
		testing.expect_value(t, len(asked), COOKIE_CLIENT_LEN)
	}

	// What comes back must not carry the cookie onwards: it belongs to this
	// server and that upstream, and the answer goes into a shared cache.
	if first != nil {
		reply, rerr := dns.decode_message(first, context.temp_allocator)
		testing.expect_value(t, rerr, dns.Decode_Error.None)
		_, leaked := dns.find_edns_option(reply, .Cookie)
		testing.expect(t, !leaked, "the upstream's cookie was passed on")
	}

	_, err2 := exchange(u, edns_query("example.org."), time.Second, context.temp_allocator)
	testing.expectf(t, err2 == .None, "second exchange failed: %v", err2)

	again, had_again := seen_cookie(&m)
	if testing.expect(t, had_again, "the second query carried no cookie") {
		testing.expect_value(t, len(again), COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN)
		testing.expect(t, mem.compare(again[COOKIE_CLIENT_LEN:], m.server[:]) == 0, "the server cookie was not sent back")
		testing.expect(t, mem.compare(again[:COOKIE_CLIENT_LEN], asked) == 0, "the client cookie changed between queries")
	}
	free_all(context.temp_allocator)
}

/*
Stripping the server cookie must not orphan the reply it was stripped from.

`exchange_with_cookie` allocates the reply as it arrived in the caller's
allocator, then hands back a *different* buffer with the cookie taken out. On
the arena paths the discarded first buffer is reclaimed for free, but on the
Race strategy the allocator is the process heap and nothing else ever frees
it — so every forwarded query whose upstream echoes a cookie would leak one
buffer for the life of the process. Freeing the one buffer the caller is given
back must leave the heap empty.
*/
@(test)
test_upstream_cookie_strip_leaves_no_orphan_on_heap :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	// Stand in for the heap the race workers hand down, so a buffer left behind
	// shows up as a live allocation rather than being swallowed by an arena.
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	heap := mem.tracking_allocator(&track)

	// The reply carries a cookie, so the exchange takes the strip path: it
	// allocates the reply as sent and again the copy with the cookie removed.
	response, err := exchange(u, edns_query("example.com."), time.Second, heap)
	testing.expectf(t, err == .None, "the exchange failed: %v", err)
	testing.expect(t, response != nil, "the exchange returned nothing")

	// The stripped reply is the caller's to free. Once it is gone, nothing the
	// exchange put on the heap may remain.
	delete(response, heap)
	testkit.expect_no_leaks(t, &track, "the exchange's heap")
	free_all(context.temp_allocator)
}

/*
A reply echoing someone else's client cookie is what a forgery looks like, and
it is passed over rather than answered - the genuine reply may still arrive.
*/
@(test)
test_upstream_cookie_forged_reply_is_ignored :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
		forge  = true,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	_, err := exchange(u, edns_query("example.com."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err == .Bad_Response, "a forged reply was accepted (%v)", err)

	// It really did answer; the reply was rejected rather than never sent.
	sync.mutex_lock(&m.mu)
	seen := m.queries
	sync.mutex_unlock(&m.mu)
	testing.expect(t, seen > 0, "the responder never saw the query")
	free_all(context.temp_allocator)
}

/*
Once a server has issued a cookie, a reply from it without one is a forgery.

Otherwise the check is one an attacker opts out of: leaving the COOKIE option off
costs it nothing and puts the reply back to being accepted on the transaction ID
and the source port alone. RFC 7873 section 5.3 - "If the client is expecting the
response to contain a COOKIE option and it is missing, the response MUST be
discarded."
*/
@(test)
test_upstream_cookie_missing_from_reply_is_ignored :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server     = {1, 2, 3, 4, 5, 6, 7, 8},
		drop_after = 1,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	// The first reply carries one, so from here on this server is known to do
	// cookies and a reply without one has to be turned away.
	_, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the first exchange failed: %v", err)

	_, err2 := exchange(u, edns_query("example.org."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err2 == .Bad_Response, "a reply with the cookie left off was accepted (%v)", err2)

	sync.mutex_lock(&m.mu)
	seen := m.queries
	sync.mutex_unlock(&m.mu)
	testing.expect(t, seen > 1, "the responder never saw the second query")
	free_all(context.temp_allocator)
}

// A server cookie shorter than eight bytes is not a legal COOKIE option, and
// RFC 7873 section 5.3 has the client discard the reply rather than read past it.
@(test)
test_upstream_cookie_illegal_length_is_ignored :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
		short  = true,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	_, err := exchange(u, edns_query("example.com."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err == .Bad_Response, "a reply with an illegal cookie length was accepted (%v)", err)
	free_all(context.temp_allocator)
}

// A server that never sent one is a server that does not do cookies, and RFC
// 7873 has the exchange carry on without.
@(test)
test_upstream_cookie_absent_server_is_tolerated :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server     = {1, 2, 3, 4, 5, 6, 7, 8},
		drop_after = 0,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	for name in ([]string{"example.com.", "example.org."}) {
		_, err := exchange(u, edns_query(name), time.Second, context.temp_allocator)
		testing.expectf(t, err == .None, "%s: a cookie-less server was refused: %v", name, err)
	}
	free_all(context.temp_allocator)
}

// BADCOOKIE carries the cookie to come back with, so the question is asked again.
@(test)
test_upstream_cookie_badcookie_is_retried :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {9, 9, 9, 9, 9, 9, 9, 9},
		demand = true,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	response, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the retry did not produce an answer: %v", err)
	if response != nil {
		testing.expect_value(t, dns.peek_rcode(response), dns.Rcode.No_Error)
	}

	sync.mutex_lock(&m.mu)
	seen := m.queries
	sync.mutex_unlock(&m.mu)
	testing.expect_value(t, seen, 2)
	free_all(context.temp_allocator)
}

/*
And the retry shares the exchange's deadline rather than starting one of its own
(issue #449): every wait, the first query's and the retry's, runs to the one the
exchange took on entry. Read off the waits rather than judged by how long the
exchange took (issue #556), so the server answers both at once and nothing here
waits the timeout out.
*/
@(test)
test_upstream_cookie_retry_shares_the_exchange_timeout :: proc(t: ^testing.T) {
	TIMEOUT :: 2 * time.Second
	m := Cookie_Mock {
		server = {9, 9, 9, 9, 9, 9, 9, 9},
		demand = true,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	udp_waits_reset()
	started := time.tick_now()
	_, err := exchange(u, edns_query("example.com."), TIMEOUT, context.temp_allocator)
	testing.expectf(t, err == .None, "the retry did not produce an answer: %v", err)

	sync.mutex_lock(&m.mu)
	seen := m.queries
	sync.mutex_unlock(&m.mu)
	testing.expect_value(t, seen, 2)
	// A send and at least one read for each query.
	expect_udp_waits_share(t, started, TIMEOUT, 4)
	free_all(context.temp_allocator)
}

// A retry nothing answers ends as the exchange's timeout, on the exchange's
// deadline: what #449 first checked, with the reply never sent rather than late.
@(test)
test_upstream_cookie_retry_left_unanswered_times_out :: proc(t: ^testing.T) {
	// Waited out in full, and long enough that the BADCOOKIE is in well before it.
	TIMEOUT :: 500 * time.Millisecond
	m := Cookie_Mock {
		server = {9, 9, 9, 9, 9, 9, 9, 9},
		demand = true,
		answer = 1,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	udp_waits_reset()
	started := time.tick_now()
	_, err := exchange(u, edns_query("example.com."), TIMEOUT, context.temp_allocator)
	testing.expect_value(t, err, Error.Timeout)
	// The retry's send is the third wait, so four show it went out without
	// reading a count the mock may not have reached yet.
	expect_udp_waits_share(t, started, TIMEOUT, 4)
	free_all(context.temp_allocator)
}

/*
A query with no OPT record gets no cookie: adding one would negotiate EDNS on
behalf of a client that never asked, and change what may come back.
*/
@(test)
test_upstream_cookie_needs_an_opt_record :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)

	_, err := exchange(u, edns_query("example.com.", with_opt = false), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the exchange failed: %v", err)

	_, had := seen_cookie(&m)
	testing.expect(t, !had, "a cookie was added to a query with no OPT record")
	free_all(context.temp_allocator)
}

@(test)
test_upstream_cookie_only_for_plain_transports :: proc(t: ^testing.T) {
	kinds := []config.Upstream_Kind{.UDP, .TCP, .TLS, .HTTPS}
	// DoT and DoH authenticate the server with a certificate, which settles
	// more than a cookie would.
	want := []bool{true, true, false, false}
	for kind, i in kinds {
		u := Upstream {
			spec    = config.Upstream_Spec{kind = kind},
			cookies = true,
		}
		testing.expectf(t, cookies_wanted(&u) == want[i], "%v: cookies_wanted is not %v", kind, want[i])

		off := Upstream {
			spec = config.Upstream_Spec{kind = kind},
		}
		testing.expectf(t, !cookies_wanted(&off), "%v: cookies sent with the setting off", kind)
	}
}

// One client cookie per upstream, so it cannot be used to recognise this
// resolver from one server to the next (RFC 9018 section 3).
@(test)
test_upstream_cookie_differs_per_upstream :: proc(t: ^testing.T) {
	spec := config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = 53,
	}
	a, aerr := make_upstream(spec, 0, time.Second, context.allocator, cookies = true)
	b, berr := make_upstream(spec, 0, time.Second, context.allocator, cookies = true)
	if aerr != .None || berr != .None {
		testing.expect(t, false, "cannot build the upstreams")
		return
	}
	defer destroy(a)
	defer destroy(b)

	testing.expect(t, mem.compare(a.cookie.client[:], b.cookie.client[:]) != 0, "two upstreams share a client cookie")
	zero: [COOKIE_CLIENT_LEN]u8
	testing.expect(t, mem.compare(a.cookie.client[:], zero[:]) != 0, "the client cookie was never drawn")
}

/*
A BADCOOKIE answered by a retry this server has no memory to attach the new
cookie to is this server's failure, not the upstream's: whichever allocation of
the conversation is refused, the exchange never comes back `Bad_Response`.
*/
@(test)
test_a_cookie_retry_without_memory_is_not_a_bad_response :: proc(t: ^testing.T) {
	refused := 0
	for n := 1; ; n += 1 {
		m := Cookie_Mock {
			server = {1, 2, 3, 4, 5, 6, 7, 8},
			demand = true,
		}
		u, worker, ok := start_cookie_mock(t, &m)
		if !ok {
			return
		}
		defer stop_udp_mock(&m, worker, u)
		query := edns_query("retry.example.")
		f := testkit.Fail_Nth{backing = context.temp_allocator, fail_at = n, fail_for = 1}
		temp := context.temp_allocator
		context.temp_allocator = testkit.fail_nth(&f)
		_, err := exchange(u, query, time.Second, temp)
		context.temp_allocator = temp
		free_all(context.temp_allocator)
		if f.seen < n {
			testing.expect_value(t, err, Error.None)
			sync.mutex_lock(&m.mu)
			testing.expectf(t, m.queries == 2, "%d queries, where the BADCOOKIE and its retry were expected", m.queries)
			sync.mutex_unlock(&m.mu)
			break
		}
		refused += 1
		testing.expectf(t, err != .Bad_Response, "allocation %d refused: the upstream was blamed with %v", n, err)
	}
	testing.expect(t, refused > 0, "the exchange allocated nothing to refuse")
}

/*
A TCP responder that accepts one connection and answers each framed query on it
(RFC 7766 section 8) with `server` as its server cookie, BADCOOKIE when `bad`,
until the client hangs up or a read times out.
*/
@(private = "file")
Tcp_Answerer :: struct {
	listener: net.TCP_Socket,
	server:   [8]u8,
	bad:      bool,
	answered: int,
	mu:       sync.Mutex,
	// The server half of the cookie on the last query answered.
	seen:     [8]u8,
}

@(private = "file")
tcp_answerer_serve :: proc(m: ^Tcp_Answerer) {
	conn, _, aerr := net.accept_tcp(m.listener)
	if aerr != nil {
		return
	}
	defer net.close(conn)
	if net.set_option(conn, .Receive_Timeout, 2 * time.Second) != nil {
		return
	}
	answer := Cookie_Mock {
		server     = m.server,
		always_bad = m.bad,
	}
	for {
		defer free_all(context.temp_allocator)
		size: [2]u8
		if read_full_tcp(conn, size[:]) != .None {
			return
		}
		query := make([]u8, int(size[0]) << 8 | int(size[1]), context.temp_allocator)
		if read_full_tcp(conn, query) != .None {
			return
		}
		wire, ok := cookie_mock_reply(&answer, query, 1)
		if !ok {
			return
		}
		framed := frame_tcp(wire)
		// Before the send: the client reads these as soon as it has the reply.
		msg, derr := dns.decode_message(query, context.temp_allocator)
		if derr != .None {
			return
		}
		if sent, found := dns.find_edns_option(msg, .Cookie); found && len(sent) == COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN {
			sync.mutex_lock(&m.mu)
			copy(m.seen[:], sent[COOKIE_CLIENT_LEN:])
			sync.mutex_unlock(&m.mu)
		}
		sync.atomic_add(&m.answered, 1)
		if _, serr := net.send_tcp(conn, framed); serr != nil {
			return
		}
	}
}

// A loopback TCP listener on `port`, any free one for zero, with a bounded
// accept and an answerer serving it; `bound` is the port it holds.
@(private = "file")
start_tcp_answerer :: proc(t: ^testing.T, m: ^Tcp_Answerer, port: int) -> (server: ^thread.Thread, bound: int, ok: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
	if !testing.expectf(t, lerr == nil, "cannot listen on TCP %d: %v", port, lerr) {
		return nil, 0, false
	}
	if !testing.expect(t, net.set_option(listener, .Receive_Timeout, 2 * time.Second) == nil, "cannot bound the accept") {
		net.close(listener)
		return nil, 0, false
	}
	endpoint, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port bound: %v", berr) {
		net.close(listener)
		return nil, 0, false
	}
	m.listener = listener
	server = thread.create_and_start_with_poly_data(m, tcp_answerer_serve)
	if !testing.expect(t, server != nil, "cannot start the TCP responder") {
		net.close(listener)
		return nil, 0, false
	}
	return server, endpoint.port, true
}

// The upstream first: closing its connection ends the answerer's read.
@(private = "file")
stop_tcp_answerer :: proc(m: ^Tcp_Answerer, server: ^thread.Thread, u: ^Upstream) {
	destroy(u)
	thread.join(server)
	thread.destroy(server)
	net.close(m.listener)
}

/*
RFC 7873 section 5.3: "If the reply to a retried request with a fresh Server
Cookie is BADCOOKIE, the client SHOULD retry using TCP as the transport". A UDP
member that answers BADCOOKIE to the retry as well is asked once more over TCP,
on the same exchange, with the server cookie that refusal carried, and that
answer is the exchange's.
*/
@(test)
test_a_second_badcookie_is_asked_again_over_tcp :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server     = {9, 9, 9, 9, 9, 9, 9, 9},
		always_bad = true,
		rotate     = true,
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker)
	tcp := Tcp_Answerer {
		server = m.server,
	}
	server, _, started := start_tcp_answerer(t, &tcp, u.spec.port)
	if !started {
		destroy(u)
		return
	}
	defer stop_tcp_answerer(&tcp, server, u)

	response, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "a second BADCOOKIE ended the exchange: %v", err)
	if response != nil {
		testing.expect_value(t, dns.peek_rcode(response), dns.Rcode.No_Error)
	}
	sync.mutex_lock(&m.mu)
	seen := m.queries
	sync.mutex_unlock(&m.mu)
	testing.expectf(t, seen == 2, "%d UDP queries, want the first and its retry", seen)
	testing.expectf(t, sync.atomic_load(&tcp.answered) == 1, "%d TCP answers, want the one retry", sync.atomic_load(&tcp.answered))
	// The cookie the second refusal carried, not the one it refused.
	sync.mutex_lock(&tcp.mu)
	carried := tcp.seen
	sync.mutex_unlock(&tcp.mu)
	testing.expectf(t, carried == [8]u8{9, 9, 9, 9, 9, 9, 9, 2}, "the TCP ask carried server cookie %v", carried)
	free_all(context.temp_allocator)
}

/*
A TCP member already speaks the transport RFC 7873 section 5.3 falls back to:
BADCOOKIE to the query and to its retry with the fresh cookie fails the exchange
as `Bad_Response`, with no third ask.
*/
@(test)
test_a_tcp_member_refusing_twice_is_not_asked_a_third_time :: proc(t: ^testing.T) {
	tcp := Tcp_Answerer {
		server = {9, 9, 9, 9, 9, 9, 9, 9},
		bad    = true,
	}
	server, port, started := start_tcp_answerer(t, &tcp, 0)
	if !started {
		return
	}
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "refusing", kind = .TCP, address = "127.0.0.1", port = port},
		0,
		time.Second,
		cookies = true,
	)
	defer stop_tcp_answerer(&tcp, server, u)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}

	_, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expect_value(t, err, Error.Bad_Response)
	testing.expectf(t, sync.atomic_load(&tcp.answered) == 2, "%d TCP answers, want the query and its retry", sync.atomic_load(&tcp.answered))
	free_all(context.temp_allocator)
}

/*
The client cookie is drawn afresh once its lifetime is up (RFC 7873 section
7.1): the exchange after that goes out with a new client cookie and without the
server cookie bound to the old one, and the next rollover is a lifetime away,
less the jitter.
*/
@(test)
test_the_client_cookie_rolls_over :: proc(t: ^testing.T) {
	m := Cookie_Mock {
		server = {1, 2, 3, 4, 5, 6, 7, 8},
	}
	u, worker, ok := start_cookie_mock(t, &m)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, worker, u)
	lifetime := time.Duration(dns.COOKIE_SECRET_LIFETIME) * time.Second
	shortest := lifetime * (100 - dns.COOKIE_SECRET_JITTER) / 100

	sync.mutex_lock(&u.mu)
	first_roll := time.Duration(u.cookie.roll_at - loop.moment_now())
	sync.mutex_unlock(&u.mu)
	testing.expectf(t, first_roll >= shortest - time.Minute && first_roll <= lifetime, "the first rollover is %v away", first_roll)

	for name in ([]string{"example.com.", "example.org."}) {
		_, err := exchange(u, edns_query(name), time.Second, context.temp_allocator)
		testing.expectf(t, err == .None, "exchange for %s failed: %v", name, err)
	}
	before, had := seen_cookie(&m)
	if !testing.expect(t, had && len(before) == COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN, "the premise: a server cookie was learned and sent") {
		return
	}
	old: [COOKIE_CLIENT_LEN]u8
	copy(old[:], before[:COOKIE_CLIENT_LEN])

	sync.mutex_lock(&u.mu)
	u.cookie.roll_at = loop.moment_add(loop.moment_now(), -time.Second)
	sync.mutex_unlock(&u.mu)
	_, err := exchange(u, edns_query("example.net."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the exchange after the rollover failed: %v", err)

	after, had_after := seen_cookie(&m)
	if testing.expect(t, had_after, "the query after the rollover carried no cookie") {
		testing.expectf(t, len(after) == COOKIE_CLIENT_LEN, "the query after the rollover carried %d bytes of cookie, want the client cookie alone", len(after))
		testing.expect(t, mem.compare(after[:COOKIE_CLIENT_LEN], old[:]) != 0, "the client cookie did not roll over")
	}
	sync.mutex_lock(&u.mu)
	next := time.Duration(u.cookie.roll_at - loop.moment_now())
	sync.mutex_unlock(&u.mu)
	testing.expectf(t, next >= shortest - time.Minute && next <= lifetime, "the next rollover is %v away", next)
	free_all(context.temp_allocator)
}

/*
A rollover holds replies to the queries already out to the cookie they owe for
as long as any of them may wait, not only as long as the query that happened to
roll it over (whose budget may be the shortest), and the retries inside one
exchange do not roll it over: they answer a refusal with the server cookie it
carried.
*/
@(test)
test_a_rollover_covers_every_query_out :: proc(t: ^testing.T) {
	u, uerr := make_upstream(config.Upstream_Spec{name = "rolled", kind = .UDP, address = "127.0.0.1", port = 9}, 0, time.Second, cookies = true)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)
	sync.mutex_lock(&u.mu)
	u.cookie.server_len = copy(u.cookie.server[:], []u8{1, 2, 3, 4, 5, 6, 7, 8})
	sync.mutex_unlock(&u.mu)

	_, long_ok, long_dry := attach_cookie(u, edns_query("example.com."), time.Minute, context.temp_allocator)
	if !testing.expectf(t, long_ok, "the premise: the long query took a cookie (out of memory: %v)", long_dry) {
		return
	}
	sync.mutex_lock(&u.mu)
	u.cookie.roll_at = loop.moment_add(loop.moment_now(), -time.Second)
	old := u.cookie.client
	sync.mutex_unlock(&u.mu)

	_, kept_ok, kept_dry := attach_cookie(u, edns_query("example.org."), time.Second, context.temp_allocator, roll = false)
	testing.expectf(t, kept_ok, "the retry took no cookie (out of memory: %v)", kept_dry)
	sync.mutex_lock(&u.mu)
	kept := u.cookie.client == old && u.cookie.server_len == COOKIE_SERVER_MIN
	sync.mutex_unlock(&u.mu)
	testing.expect(t, kept, "a retry rolled the cookie over")

	_, short_ok, short_dry := attach_cookie(u, edns_query("example.net."), time.Second, context.temp_allocator)
	testing.expectf(t, short_ok, "the short query took no cookie (out of memory: %v)", short_dry)
	sync.mutex_lock(&u.mu)
	rolled := u.cookie.client != old
	window := time.Duration(u.cookie.renewed_until - loop.moment_now())
	sync.mutex_unlock(&u.mu)
	if testing.expect(t, rolled, "the premise: the short query rolled the cookie over") {
		testing.expectf(t, window > 30 * time.Second, "replies are held to their cookie for %v, short of the long query's minute", window)
	}
	free_all(context.temp_allocator)
}
