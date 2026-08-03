package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

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
	/*
	Stop putting a COOKIE option in replies once this many have carried one.

	Leaving the option off is the cheaper thing for an off-path forgery to do
	than reproduce a cookie it has never seen. `nil` keeps sending them, and 0
	plays a server that does not implement cookies at all.
	*/
	drop_after: Maybe(int),
	// Reply with a server cookie shorter than the eight bytes RFC 7873 allows.
	short:      bool,

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
	if m.demand && len(sent) < 16 {
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

	option: [16]u8
	copy(option[:8], sent[:min(8, len(sent))])
	if m.forge {
		option[0] ~= 0xff
	}
	copy(option[8:], m.server[:])
	written := option[:12] if m.short else option[:]
	out, set_ok := dns.set_edns_option(wire, .Cookie, written, context.temp_allocator)
	if !set_ok {
		return wire, true
	}
	return out, true
}

@(private = "file")
start_cookie_mock :: proc(t: ^testing.T, m: ^Cookie_Mock) -> (u: ^Upstream, worker: ^thread.Thread, ok: bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind a loopback responder: %v", serr)
		return nil, nil, false
	}
	m.socket = socket
	// Without this the responder would sit in recv_udp and never see `stop`.
	set_socket_timeouts(socket, 50 * time.Millisecond)

	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		net.close(socket)
		testing.expectf(t, false, "cannot read the responder's port: %v", berr)
		return nil, nil, false
	}

	worker = thread.create_and_start_with_poly_data(m, cookie_mock_loop)
	built, uerr := make_upstream(
		config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
		cookies = true,
	)
	if uerr != .None {
		sync.atomic_store(&m.stop, true)
		thread.join(worker)
		thread.destroy(worker)
		net.close(socket)
		testing.expectf(t, false, "cannot build the upstream: %v", uerr)
		return nil, nil, false
	}
	return built, worker, true
}

@(private = "file")
stop_cookie_mock :: proc(m: ^Cookie_Mock, u: ^Upstream, worker: ^thread.Thread) {
	sync.atomic_store(&m.stop, true)
	thread.join(worker)
	thread.destroy(worker)
	net.close(m.socket)
	destroy(u)
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
	defer stop_cookie_mock(&m, u, worker)

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
		testing.expect_value(t, len(again), COOKIE_CLIENT_LEN + 8)
		testing.expect(t, mem.compare(again[8:], m.server[:]) == 0, "the server cookie was not sent back")
		testing.expect(t, mem.compare(again[:8], asked) == 0, "the client cookie changed between queries")
	}
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
	defer stop_cookie_mock(&m, u, worker)

	_, err := exchange(u, edns_query("example.com."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err == .Timeout, "a forged reply was accepted (%v)", err)

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
	defer stop_cookie_mock(&m, u, worker)

	// The first reply carries one, so from here on this server is known to do
	// cookies and a reply without one has to be turned away.
	_, err := exchange(u, edns_query("example.com."), time.Second, context.temp_allocator)
	testing.expectf(t, err == .None, "the first exchange failed: %v", err)

	_, err2 := exchange(u, edns_query("example.org."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err2 == .Timeout, "a reply with the cookie left off was accepted (%v)", err2)

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
	defer stop_cookie_mock(&m, u, worker)

	_, err := exchange(u, edns_query("example.com."), 300 * time.Millisecond, context.temp_allocator)
	testing.expectf(t, err == .Timeout, "a reply with an illegal cookie length was accepted (%v)", err)
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
	defer stop_cookie_mock(&m, u, worker)

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
	defer stop_cookie_mock(&m, u, worker)

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
	defer stop_cookie_mock(&m, u, worker)

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
