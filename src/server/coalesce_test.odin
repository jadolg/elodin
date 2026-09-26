package server

import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
Issue #311: identical questions that arrive while the first is still out are one
upstream exchange, not one each.

Driven through `handle_query` from several threads at once against a mock that
counts what reaches it, since the count at the far end is the whole claim.
*/

@(private = "file")
CLIENTS :: 8

@(private = "file")
QNAME :: "slow.example.test."

@(private = "file")
HOLD_LIMIT :: 2 * time.Second

@(private = "file")
Mock :: struct {
	socket:   net.UDP_Socket,
	ttl:      u32,
	// Hold the first query until this many followers are waiting on it, read
	// from the server's own table, so no client can arrive after the answer.
	hold_for: int,
	srv:      ^Server,
	// Never answer: the upstream is down for the leader and its followers.
	silent:   bool,
	// Lose the first query only, as a datagram on a bad path is lost.
	drop_first: bool,
	// The rcode the first query is answered with; every later one is NOERROR.
	first:    dns.Rcode,
	queries:  int,
}

@(private = "file")
waiting_on :: proc(s: ^Server) -> int {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	n := 0
	for f in s.inflight.slots {
		if f != nil {
			n += f.waiters
		}
	}
	return n
}

// Count every query until the socket goes quiet, answering each one unless told
// not to.
@(private = "file")
serve_mock :: proc(m: ^Mock) {
	buf: [4096]u8
	for {
		n, remote, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			return
		}
		m.queries += 1
		if m.queries == 1 {
			// Quiet for longer than the leader can take to give up, so a
			// follower that forwards after it is still counted.
			_ = net.set_option(m.socket, .Receive_Timeout, m.srv.cfg.upstream.timeout + time.Second)
			// Bounded under the upstream timeout, so that without coalescing
			// every client is still answered and it is the count that fails.
			for start := time.tick_now(); waiting_on(m.srv) < m.hold_for; {
				if time.tick_since(start) > HOLD_LIMIT {
					break
				}
				time.sleep(time.Millisecond)
			}
		}
		if m.silent || (m.drop_first && m.queries == 1) {
			continue
		}
		reply := coalesce_reply(buf[0], buf[1], m.ttl, m.first if m.queries == 1 else .No_Error)
		_, _ = net.send_udp(m.socket, reply, remote)
	}
}

@(private = "file")
coalesce_reply :: proc(hi, lo: u8, ttl: u32, rcode: dns.Rcode) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = ttl,
		data  = dns.Rdata_A{addr = {192, 0, 2, 7}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = QNAME, type = .A, class = .IN}
	msg := dns.Message {
		id       = u16(hi) << 8 | u16(lo),
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = u8(rcode)
	if rcode != .No_Error {
		msg.answer = nil
	}
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	return wire
}

@(private = "file")
Client :: struct {
	srv:   ^Server,
	id:    u16,
	rcode: dns.Rcode,
	addr:  [4]u8,
	ok:    bool,
}

@(private = "file")
ask :: proc(c: ^Client) {
	defer free_all(context.temp_allocator)
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = QNAME, type = .A, class = .IN}
	msg := dns.Message {
		id       = c.id,
		question = question,
	}
	msg.flags.rd = true
	query, _, _ := dns.encode_message(msg, context.temp_allocator)
	out, _, served := handle_query(c.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !served {
		return
	}
	reply, err := dns.decode_message(out, context.temp_allocator)
	if err != .None || reply.id != c.id {
		return
	}
	c.rcode = dns.Rcode(reply.flags.rcode)
	if len(reply.answer) == 1 {
		if a, is_a := reply.answer[0].data.(dns.Rdata_A); is_a {
			c.addr = a.addr
		}
	}
	c.ok = true
}

/*
Everything a case needs: a mock on a loopback socket, a server pointed at it,
and `CLIENTS` threads asking the same question at once. Returns how many queries
the mock saw.
*/
@(private = "file")
run_burst :: proc(
	t: ^testing.T,
	clients: ^[CLIENTS]Client,
	ttl: u32 = 300,
	silent := false,
	timeout := 4 * time.Second,
	first := dns.Rcode.No_Error,
	drop_first := false,
) -> int {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return -1
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return -1
	}

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = timeout
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers
	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return -1
	}
	defer upstream.destroy_group(group)
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	srv := Server {
		cfg     = &cfg,
		group   = group,
		answers = answers,
	}

	m := Mock {
		socket   = socket,
		ttl      = ttl,
		hold_for = CLIENTS - 1,
		srv      = &srv,
		silent   = silent,
		first    = first,
		drop_first = drop_first,
	}
	mock := thread.create_and_start_with_poly_data(&m, serve_mock)
	threads: [CLIENTS]^thread.Thread
	for i in 0 ..< CLIENTS {
		clients[i] = Client {
			srv = &srv,
			id  = u16(0x1000 + i),
		}
		threads[i] = thread.create_and_start_with_poly_data(&clients[i], ask)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	thread.join(mock)
	thread.destroy(mock)
	return m.queries
}

@(test)
test_identical_inflight_queries_are_one_upstream_exchange :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients)
	testing.expectf(t, queries == 1, "the upstream saw %d queries for %d identical clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .No_Error, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
		testing.expectf(t, c.addr == {192, 0, 2, 7}, "client %d was answered %v", i, c.addr)
	}
}

/*
An answer the cache will not keep is shared all the same: a zero TTL forbids
holding it for a later question, not handing it to the ones already waiting on
it.
*/
@(test)
test_an_uncacheable_answer_is_shared_with_the_queries_waiting_on_it :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, ttl = 0)
	testing.expectf(t, queries == 1, "the upstream saw %d queries for %d identical clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.addr == {192, 0, 2, 7}, "client %d: ok=%v answer %v", i, c.ok, c.addr)
	}
}

/*
An upstream that gave the leader nothing is asked once more, by one of the
followers on behalf of the rest, and then not again: every follower waiting out
the same timeout for the same nothing would hold a worker twice as long as the
leader did.
*/
@(test)
test_followers_of_a_failed_exchange_ask_once_more_and_no_further :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, silent = true, timeout = 1 * time.Second)
	testing.expectf(t, queries == 2, "the upstream saw %d queries for %d identical clients, want 2", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
Once more because the leader's failure may have been the leader's alone - one
lost datagram, or a message the upstream would not read - and that must not be
every waiting client's SERVFAIL.
*/
@(test)
test_a_leader_whose_query_was_lost_does_not_fail_its_followers :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, drop_first = true, timeout = 1 * time.Second)
	testing.expectf(t, queries == 2, "the upstream saw %d queries for %d identical clients, want 2", queries, CLIENTS)
	failed, answered := 0, 0
	for c in clients {
		if c.ok && c.rcode == .Serv_Fail {
			failed += 1
		} else if c.ok && c.rcode == .No_Error && c.addr == {192, 0, 2, 7} {
			answered += 1
		}
	}
	testing.expectf(t, failed == 1 && answered == CLIENTS - 1, "%d clients failed and %d were answered, want 1 and %d", failed, answered, CLIENTS - 1)
}

/*
But not a FORMERR. That rcode is the upstream reading the leader's message, and
the message carries more than the key does - a client's own records in a section
a query leaves empty, which some upstreams answer FORMERR - so a follower that
asked well formed is not handed the refusal of a query it did not send.
*/
@(test)
test_a_formerr_to_the_leader_is_not_shared :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	run_burst(t, &clients, first = .Form_Err)
	refused, answered := 0, 0
	for c in clients {
		if c.ok && c.rcode == .Form_Err {
			refused += 1
		} else if c.ok && c.rcode == .No_Error && c.addr == {192, 0, 2, 7} {
			answered += 1
		}
	}
	testing.expectf(t, refused == 1 && answered == CLIENTS - 1, "%d clients got the leader's FORMERR and %d an answer, want 1 and %d", refused, answered, CLIENTS - 1)
}

// A follower whose leader never lands stops waiting at its patience, and the
// leader is then free to land with nobody left to wait for.
@(test)
test_a_follower_stops_waiting_at_its_patience :: proc(t: ^testing.T) {
	s: Server
	lead: Flight
	f, leading := flight_join(&s, "k", &lead)
	testing.expect(t, f == &lead && leading, "the first query did not lead")
	other: Flight
	joined, second_leads := flight_join(&s, "k", &other)
	testing.expect(t, joined == &lead && !second_leads, "the second query did not follow")

	start := time.tick_now()
	answer, _, failed, landed := flight_follow(&s, joined, 50 * time.Millisecond, context.temp_allocator)
	waited := time.tick_since(start)
	testing.expect(t, !landed && !failed && answer == nil, "a flight that never landed was read as landed")
	testing.expectf(t, waited >= 50 * time.Millisecond && waited < 2 * time.Second, "waited %v for 50ms of patience", waited)
	testing.expect_value(t, lead.waiters, 0)
	flight_land(&s, &lead)
	testing.expect(t, s.inflight.slots[0] == nil, "the landed flight is still in the table")
}

// A full table turns nobody away: the query forwards on its own.
@(test)
test_a_full_flight_table_forwards_without_joining :: proc(t: ^testing.T) {
	s: Server
	flights: [INFLIGHT_SLOTS]Flight
	keys: [INFLIGHT_SLOTS]string
	for i in 0 ..< INFLIGHT_SLOTS {
		keys[i] = fmt.tprintf("k%d", i)
		_, leading := flight_join(&s, keys[i], &flights[i])
		testing.expect(t, leading, "a free slot was not taken")
	}
	extra: Flight
	f, leading := flight_join(&s, "one more", &extra)
	testing.expect(t, f == nil && !leading, "a full table handed out a flight")
	for i in 0 ..< INFLIGHT_SLOTS {
		flight_land(&s, &flights[i])
	}
}
