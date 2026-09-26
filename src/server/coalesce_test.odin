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
import "elodin:dnssec"
import "elodin:filter"
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
	socket:     net.UDP_Socket,
	ttl:        u32,
	// Hold the first query until this many followers are waiting on it, read
	// from the server's own table, so no client can arrive after the answer.
	hold_for:   int,
	srv:        ^Server,
	// Never answer: the upstream is down for the leader and its followers.
	silent:     bool,
	// Lose the first query only, as a datagram on a bad path is lost.
	drop_first: bool,
	// The rcode the first query is answered with; every later one is NOERROR.
	first:      dns.Rcode,
	// Answer the question with a CNAME into `TRACKER` rather than an address.
	cloak:      bool,
	// Answer any other question - a chain lookup - with an empty NOERROR,
	// uncounted: a zone that published no keys, which is a Bogus verdict.
	others:     bool,
	queries:    int,
	lookups:    int,
}

@(private = "file")
TRACKER :: "tracker.evil.test."

// Whether this query is the client's question rather than one of the
// validator's own.
@(private = "file")
asks_qname :: proc(query: []u8) -> bool {
	want: [dns.MAX_NAME_WIRE + 4]u8
	n, err := dns.encode_name(QNAME, want[:])
	if err != .None {
		return false
	}
	want[n], want[n + 1], want[n + 2], want[n + 3] = 0, u8(dns.Type.A), 0, u8(dns.Class.IN)
	return len(query) >= dns.HEADER_SIZE + n + 4 && string(query[dns.HEADER_SIZE:][:n + 4]) == string(want[:n + 4])
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

@(private = "file")
flight_open :: proc(s: ^Server) -> bool {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	for f in s.inflight.slots {
		if f != nil {
			return true
		}
	}
	return false
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
		if m.others && !asks_qname(buf[:n]) {
			m.lookups += 1
			buf[2] |= 0x80 // QR
			buf[3] |= 0x80 // RA
			_, _ = net.send_udp(m.socket, buf[:n], remote)
			continue
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
		reply := coalesce_reply(buf[0], buf[1], m.ttl, m.first if m.queries == 1 else .No_Error, m.cloak)
		_, _ = net.send_udp(m.socket, reply, remote)
	}
}

@(private = "file")
coalesce_reply :: proc(hi, lo: u8, ttl: u32, rcode: dns.Rcode, cloak := false) -> []u8 {
	answer := make([]dns.Record, 2 if cloak else 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = QNAME,
		type  = .A,
		class = .IN,
		ttl   = ttl,
		data  = dns.Rdata_A{addr = {192, 0, 2, 7}},
	}
	if cloak {
		answer[0] = dns.Record {
			name  = QNAME,
			type  = .CNAME,
			class = .IN,
			ttl   = ttl,
			data  = dns.Rdata_Name{name = TRACKER},
		}
		answer[1] = dns.Record {
			name  = TRACKER,
			type  = .A,
			class = .IN,
			ttl   = ttl,
			data  = dns.Rdata_A{addr = {192, 0, 2, 7}},
		}
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
	// Ask with an OPT record at `UPSTREAM_UDP_SIZE`, or without one as an old
	// stub does, which is a different message to the upstream.
	edns:  bool,
	rcode:   dns.Rcode,
	addr:    [4]u8,
	outcome: Outcome,
	ok:      bool,
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
	if c.edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(UPSTREAM_UDP_SIZE, false)
		msg.additional = additional
	}
	query, _, _ := dns.encode_message(msg, context.temp_allocator)
	out, outcome, served := handle_query(c.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	c.outcome = outcome
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
	attempts := 1,
	edns := true,
	// Client 0 asks as `edns` says and leads; the rest ask the other way and
	// follow it, so the leader's message is not theirs.
	mixed := false,
	cache_on := true,
	// A real validator, which the mock's empty key sets turn into a Bogus
	// verdict for the unsigned answer.
	validating := false,
	// Blocking on, with `TRACKER` listed and the answer a CNAME into it.
	cloak := false,
	// How many of the validator's own lookups reached the mock.
	lookups: ^int = nil,
	// How many followers the mock holds the first query for, and how many
	// clients ask at all.
	hold_for := CLIENTS - 1,
	clients_asking := CLIENTS,
	// The server's counters once the burst is over.
	stats: ^Stats = nil,
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
	cfg.blocking.enabled = cloak
	cfg.cache.enabled = cache_on
	cfg.dnssec.enabled = validating
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = attempts
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
	if validating {
		srv.validator = dnssec.make_validator(validator_query, &srv, dnssec.Options{})
	}
	defer if srv.validator != nil {
		dnssec.destroy_validator(srv.validator)
	}
	engine: ^filter.Engine
	if cloak {
		engine = filter.engine_make()
		block := filter.set_make()
		filter.set_add(block, "tracker.evil.test", {.Apex, .Subdomains})
		filter.engine_swap(engine, block, filter.set_make())
		srv.filters = engine
	}
	defer if engine != nil {
		filter.engine_destroy(engine)
	}

	m := Mock {
		socket     = socket,
		ttl        = ttl,
		hold_for   = hold_for,
		srv        = &srv,
		silent     = silent,
		first      = first,
		drop_first = drop_first,
		cloak      = cloak,
		others     = validating,
	}
	mock := thread.create_and_start_with_poly_data(&m, serve_mock)
	threads: [CLIENTS]^thread.Thread
	for i in 0 ..< clients_asking {
		clients[i] = Client {
			srv  = &srv,
			id   = u16(0x1000 + i),
			edns = edns if !mixed || i == 0 else !edns,
		}
		threads[i] = thread.create_and_start_with_poly_data(&clients[i], ask)
		// Let the leader register before anybody else asks.
		for start := time.tick_now(); mixed && i == 0 && !flight_open(&srv); {
			if time.tick_since(start) > HOLD_LIMIT {
				break
			}
			time.sleep(time.Millisecond)
		}
	}
	for th in threads[:clients_asking] {
		thread.join(th)
		thread.destroy(th)
	}
	thread.join(mock)
	thread.destroy(mock)
	if stats != nil {
		stats^ = srv.stats
	}
	if lookups != nil {
		lookups^ = m.lookups
	}
	return m.queries
}

@(test)
test_identical_inflight_queries_are_one_upstream_exchange :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	st: Stats
	queries := run_burst(t, &clients, stats = &st)
	testing.expectf(t, queries == 1, "the upstream saw %d queries for %d identical clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .No_Error, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
		testing.expectf(t, c.addr == {192, 0, 2, 7}, "client %d was answered %v", i, c.addr)
	}
	// The followers are counted as coalesced, and nobody else is.
	testing.expect_value(t, st.coalesced, u64(CLIENTS - 1))
	testing.expect_value(t, st.forwarded, u64(1))
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
And an upstream that gave the leader nothing is not asked again by every query
that was waiting on it: the group has already tried every server for every
attempt, and each follower would wait out the same timeout for the same nothing,
holding a worker twice as long as the leader did.
*/
@(test)
test_followers_of_a_failed_exchange_do_not_ask_again :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, silent = true, timeout = 3 * time.Second)
	testing.expectf(t, queries == 1, "the upstream saw %d queries for %d identical clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
A lost datagram is the group's to retry, and the followers are answered by the
retry: nothing about sharing the leader's exchange makes one lost packet every
waiting client's SERVFAIL.
*/
@(test)
test_a_lost_datagram_is_retried_for_the_followers_too :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, drop_first = true, timeout = 1 * time.Second, attempts = 2)
	testing.expectf(t, queries == 2, "the upstream saw %d queries for %d identical clients, want 2", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.addr == {192, 0, 2, 7}, "client %d: ok=%v rcode=%v answer %v", i, c.ok, c.rcode, c.addr)
	}
}

/*
A leader whose message was not theirs - an old stub's, with no OPT record - may
have failed over those bytes rather than the question, so its followers ask for
themselves rather than take its failure.
*/
@(test)
test_followers_of_another_message_ask_for_themselves :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, drop_first = true, timeout = 1 * time.Second, edns = false, mixed = true)
	testing.expectf(t, queries == CLIENTS, "the upstream saw %d queries for %d clients, want %d", queries, CLIENTS, CLIENTS)
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
And the other way round: an EDNS leader's failure or FORMERR is the upstream
reading its message, which the followers' own, without EDNS, are not.
*/
@(test)
test_a_leaders_failure_is_not_handed_to_other_messages :: proc(t: ^testing.T) {
	down: [CLIENTS]Client
	queries := run_burst(t, &down, silent = true, timeout = 1 * time.Second, mixed = true)
	testing.expectf(t, queries == CLIENTS, "down: the upstream saw %d queries, want %d", queries, CLIENTS)

	refused: [CLIENTS]Client
	run_burst(t, &refused, first = .Form_Err, mixed = true)
	testing.expectf(t, refused[0].rcode == .Form_Err, "the leader was answered %v, want its FORMERR", refused[0].rcode)
	for c, i in refused[1:] {
		testing.expectf(t, c.ok && c.addr == {192, 0, 2, 7}, "follower %d: ok=%v rcode=%v", i + 1, c.ok, c.rcode)
	}
}

/*
And an rcode is shared or not on the same terms. From a leader whose message was
the follower's, a FORMERR or a REFUSED is the upstream's word on that message;
from one whose was not, it may be a refusal of bytes no follower sent, and only
the rcodes the cache itself keeps are handed on.
*/
@(test)
test_a_refusal_is_shared_only_between_identical_messages :: proc(t: ^testing.T) {
	count :: proc(clients: [CLIENTS]Client, rcode: dns.Rcode) -> (refused, answered: int) {
		for c in clients {
			if c.ok && c.rcode == rcode {
				refused += 1
			} else if c.ok && c.rcode == .No_Error && c.addr == {192, 0, 2, 7} {
				answered += 1
			}
		}
		return
	}

	for rcode in ([]dns.Rcode{.Form_Err, .Refused}) {
		own: [CLIENTS]Client
		run_burst(t, &own, first = rcode, edns = false, mixed = true)
		refused, answered := count(own, rcode)
		testing.expectf(t, refused == 1 && answered == CLIENTS - 1, "%v without EDNS: %d clients got the leader's refusal and %d an answer, want 1 and %d", rcode, refused, answered, CLIENTS - 1)
	}

	shared: [CLIENTS]Client
	queries := run_burst(t, &shared, first = .Form_Err)
	refused, _ := count(shared, .Form_Err)
	testing.expectf(t, queries == 1 && refused == CLIENTS, "with EDNS, %d queries and %d FORMERRs, want 1 and %d", queries, refused, CLIENTS)
}

// A follower whose leader never lands stops waiting at its patience, and the
// leader is then free to land with nobody left to wait for.
@(test)
test_a_follower_stops_waiting_at_its_patience :: proc(t: ^testing.T) {
	s: Server
	lead: Flight
	f, _ := flight_join(&s, "k", &lead)
	testing.expect(t, f == &lead, "the first query did not lead")
	other: Flight
	joined, _ := flight_join(&s, "k", &other)
	testing.expect(t, joined == &lead, "the second query did not follow")

	start := time.tick_now()
	result, landed, _ := flight_follow(&s, joined, 50 * time.Millisecond, context.temp_allocator)
	waited := time.tick_since(start)
	testing.expect(t, !landed && !result.failed && result.answer == nil, "a flight that never landed was read as landed")
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
		f, _ := flight_join(&s, keys[i], &flights[i])
		testing.expect(t, f == &flights[i], "a free slot was not taken")
	}
	extra: Flight
	f, _ := flight_join(&s, "one more", &extra)
	testing.expect(t, f == nil, "a full table handed out a flight")
	for i in 0 ..< INFLIGHT_SLOTS {
		flight_land(&s, &flights[i])
	}
}

/*
A follower is told whether its outgoing message was the leader's, bar the ID -
which is what decides whether anything but an answer is handed to it - and the
spelling of the name, or a header bit the key does not carry, is a difference.
*/
@(test)
test_a_follower_is_told_whether_its_message_was_the_leaders :: proc(t: ^testing.T) {
	message :: proc(id: u16, name: string, ad := false) -> []u8 {
		msg := dns.Message {
			id         = id,
			question   = []dns.Question{{name = name, type = .A, class = .IN}},
			additional = []dns.Record{dns.make_opt(UPSTREAM_UDP_SIZE, false)},
		}
		msg.flags.rd = true
		msg.flags.ad = ad
		wire, _, _ := dns.encode_message(msg, context.temp_allocator)
		return wire
	}
	follow :: proc(leader, follower: []u8) -> bool {
		s: Server
		lead: Flight
		_, _ = flight_join(&s, "k", &lead)
		lead.forwarded = leader
		other: Flight
		joined, _ := flight_join(&s, "k", &other)
		// Landed from another thread, which is what a follower waits for.
		landing := thread.create_and_start_with_poly_data2(&s, &lead, flight_land)
		_, landed, same := flight_follow(&s, joined, 5 * time.Second, context.temp_allocator, false, follower)
		thread.join(landing)
		thread.destroy(landing)
		return landed && same
	}
	leader := message(1, QNAME)
	testing.expect(t, follow(leader, message(2, QNAME)), "the same message under another ID was not the same")
	testing.expect(t, !follow(leader, message(1, "Slow.Example.Test.")), "another spelling of the name was the same")
	testing.expect(t, !follow(leader, message(1, QNAME, ad = true)), "another AD bit was the same")
	testing.expect(t, !follow(leader, nil), "no message was the same")
}

// Followers on the shared pool stop at the ceiling, and the count comes back
// down as they leave.
@(test)
test_followers_on_the_shared_pool_stop_at_the_ceiling :: proc(t: ^testing.T) {
	s: Server
	lead: Flight
	first, _ := flight_join(&s, "k", &lead, shared = true, ceiling = 2)
	testing.expect(t, first == &lead, "the first query did not lead")
	a, b, c: Flight
	fa, ca := flight_join(&s, "k", &a, shared = true, ceiling = 2)
	fb, cb := flight_join(&s, "k", &b, shared = true, ceiling = 2)
	fc, _ := flight_join(&s, "k", &c, shared = true, ceiling = 2)
	testing.expect(t, fa == &lead && fb == &lead, "a follower under the ceiling was turned away")
	testing.expect(t, fc == nil, "a follower past the ceiling was let in")
	// A connection's own thread is not the pool's to protect.
	d: Flight
	fd, cd := flight_join(&s, "k", &d, shared = false, ceiling = 2)
	testing.expect(t, fd == &lead && !cd, "a follower off the shared pool was turned away or counted")

	_, _, _ = flight_follow(&s, fa, 0, context.temp_allocator, ca)
	testing.expect_value(t, s.inflight.followers, 1)
	fe, ce := flight_join(&s, "k", &c, shared = true, ceiling = 2)
	testing.expect(t, fe == &lead, "the slot a follower left was not free again")
	_, _, _ = flight_follow(&s, fb, 0, context.temp_allocator, cb)
	_, _, _ = flight_follow(&s, fe, 0, context.temp_allocator, ce)
	_, _, _ = flight_follow(&s, fd, 0, context.temp_allocator, cd)
	testing.expect_value(t, s.inflight.followers, 0)
	flight_land(&s, &lead)
}

/*
With the cache off, nothing was ever shared between two clients' messages, and
coalescing does not start: only a follower whose message was the leader's takes
its answer.
*/
@(test)
test_with_the_cache_off_only_identical_messages_share_an_answer :: proc(t: ^testing.T) {
	alike: [CLIENTS]Client
	queries := run_burst(t, &alike, cache_on = false)
	testing.expectf(t, queries == 1, "identical: the upstream saw %d queries, want 1", queries)
	apart: [CLIENTS]Client
	queries = run_burst(t, &apart, cache_on = false, mixed = true)
	testing.expectf(t, queries == CLIENTS, "different: the upstream saw %d queries, want %d", queries, CLIENTS)
	for c, i in apart {
		testing.expectf(t, c.ok && c.addr == {192, 0, 2, 7}, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
Issue #425. A leader that stored a verdict leaves its followers to find it in the
cache: each is refused from the verdict, and none of them asks the upstream or
walks the chain again.
*/
@(test)
test_followers_of_a_bogus_leader_are_refused_from_its_verdict :: proc(t: ^testing.T) {
	// What one query's walk costs, so the burst can be held to it.
	single: [CLIENTS]Client
	one_walk: int
	run_burst(t, &single, validating = true, lookups = &one_walk, hold_for = 0, clients_asking = 1)
	testing.expectf(t, single[0].ok && single[0].rcode == .Serv_Fail, "a lone query: ok=%v rcode=%v", single[0].ok, single[0].rcode)
	testing.expect(t, one_walk > 0, "the validator never asked for the chain, so the answer was not validated")

	clients: [CLIENTS]Client
	walked: int
	queries := run_burst(t, &clients, validating = true, lookups = &walked)
	testing.expectf(t, queries == 1, "the upstream saw the question %d times for %d clients, want 1", queries, CLIENTS)
	testing.expectf(t, walked == one_walk, "the chain was asked for %d times, want one walk's %d", walked, one_walk)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

@(test)
test_followers_of_a_cloaked_leader_are_blocked_from_its_verdict :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, cloak = true)
	testing.expectf(t, queries == 1, "the upstream saw the question %d times for %d clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.outcome == .Blocked, "client %d: ok=%v outcome=%v", i, c.ok, c.outcome)
	}
}
