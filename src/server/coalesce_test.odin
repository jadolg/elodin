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
import "elodin:loop"
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
	// Set once every client has been joined: the loop drains what is left in
	// the socket and returns at its next quiet poll.
	stop:       bool,
}

@(private = "file")
TRACKER :: "tracker.evil.test."

// Whether this query is the client's question rather than one of the
// validator's own.
@(private = "file")
asks_qname :: proc(query: []u8) -> bool {
	q, ok := dns.peek_question(query, context.temp_allocator)
	return ok && dns.name_equal_fold(q.name, QNAME) && q.type == .A
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

/*
`flight_land` for `from`, with `to` leading its key's next flight from the same
moment, so the followers going round again follow `to` rather than lead.
*/
@(private = "file")
land_into :: proc(s: ^Server, from, to: ^Flight) {
	sync.mutex_lock(&s.inflight.mu)
	defer sync.mutex_unlock(&s.inflight.mu)
	to^ = Flight {
		key  = from.key,
		slot = from.slot,
	}
	s.inflight.slots[from.slot] = to
	from.landed = true
	loop.cond_broadcast(&from.cond)
	for from.waiters > 0 {
		loop.cond_wait(&from.cond, &s.inflight.mu)
	}
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

// Count every query until told to stop, answering each one unless told not to.
@(private = "file")
serve_mock :: proc(m: ^Mock) {
	buf: [4096]u8
	for {
		n, remote, err := net.recv_udp(m.socket, buf[:])
		if err != nil {
			// A quiet poll: the only point the loop looks at `stop`, so whatever
			// was already sent is counted before it returns.
			if sync.atomic_load(&m.stop) {
				return
			}
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		if !asks_qname(buf[:n]) {
			// The validator's own lookup, or another case's stray: counted as a
			// query, a stray would fail a burst on a name it never asked.
			if m.others {
				m.lookups += 1
				buf[2] |= 0x80 // QR
				buf[3] |= 0x80 // RA
				_, _ = net.send_udp(m.socket, buf[:n], remote)
			}
			continue
		}
		m.queries += 1
		if m.queries == 1 {
			// Bounded under the upstream timeout, so that without coalescing
			// every client is still answered and it is the count that fails.
			_ = wait_until(proc(data: rawptr) -> bool {
					m := (^Mock)(data)
					return waiting_on(m.srv) >= m.hold_for
				}, m, HOLD_LIMIT)
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
	answer: [2]dns.Record
	n := 1
	answer[0] = a_record(QNAME, {192, 0, 2, 7}, ttl)
	if cloak {
		answer[0] = cname_record(QNAME, TRACKER, ttl)
		answer[1] = a_record(TRACKER, {192, 0, 2, 7}, ttl)
		n = 2
	}
	if rcode != .No_Error {
		n = 0
	}
	wire := test_reply(QNAME, .A, ..answer[:n], rcode = rcode)
	wire[0], wire[1] = hi, lo
	return wire
}

@(private = "file")
Client :: struct {
	srv:     ^Server,
	id:      u16,
	// Ask with an OPT record at `UPSTREAM_UDP_SIZE`, or without one as an old
	// stub does - the same message to the upstream (issue #423).
	edns:    bool,
	rcode:   dns.Rcode,
	addr:    [4]u8,
	outcome: Outcome,
	ok:      bool,
	// How long `handle_query` held this client.
	took:    time.Duration,
}

@(private = "file")
ask :: proc(c: ^Client) {
	defer free_all(context.temp_allocator)
	opt: Maybe(dns.Record)
	if c.edns {
		opt = dns.make_opt(UPSTREAM_UDP_SIZE, false)
	}
	query := test_query(QNAME, id = c.id, opt = opt)
	started := time.tick_now()
	out, outcome, served := handle_query(c.srv, query, .UDP, "127.0.0.1:5555", context.temp_allocator)
	c.took = time.tick_since(started)
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
	// follow it.
	mixed := false,
	/*
	Lead the burst by hand with a message no client sends, which a reload that
	changed the DNSSEC settings between a leader and its followers is the one way
	to reach, and land it with `first` for an answer - or with nothing, `silent`.
	*/
	other_message := false,
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
	// The cache's counters once the burst is over.
	cache_stats: ^cache.Stats = nil,
	// The server's counters once the burst is over.
	stats: ^Stats = nil,
	// Lead the burst by hand and land it with this verdict stored, which the
	// cache does not hold: evicted between the leader's store and its
	// followers' reads.
	evicted: Stored_Verdict = .None,
	// And lead the exchange its followers go round for by hand too, landing it
	// the same way.
	evicted_twice := false,
	// How long the hand-made leader holds its followers before it lands.
	land_after: time.Duration = 0,
) -> int {
	// Short, because it is how the mock's loop gets to look at `stop`.
	socket, spec, bound := bind_mock(t, wait = 100 * time.Millisecond)
	if !bound {
		return -1
	}
	defer net.close(socket)

	cfg := test_config(loopback_upstream(spec.port))
	cfg.blocking.enabled = cloak
	cfg.cache.enabled = cache_on
	cfg.dnssec.enabled = validating
	cfg.upstream.attempts = attempts
	cfg.upstream.timeout = timeout
	group, gerr := upstream.make_group(cfg.upstream, context.allocator)
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
	key_buf: [cache.KEY_MAX]u8
	leaders: [2]Flight
	leading := false
	if evicted != .None || other_message {
		key := cache.make_key(key_buf[:], QNAME, .A, .IN, false, false)
		joined, _ := flight_join(&srv, key, &leaders[0])
		leading = testing.expect(t, joined == &leaders[0], "the hand-made leader did not get the flight")
	}
	if other_message {
		leaders[0].forwarded = []u8{0, 0, 0xff}
		if silent {
			leaders[0].failed = true
		} else {
			leaders[0].answer = coalesce_reply(0, 0, ttl, first)
		}
	}
	threads: [CLIENTS]^thread.Thread
	for i in 0 ..< clients_asking {
		clients[i] = Client {
			srv  = &srv,
			id   = u16(0x1000 + i),
			edns = edns if !mixed || i == 0 else !edns,
		}
		threads[i] = thread.create_and_start_with_poly_data(&clients[i], ask)
		// Let the leader register before anybody else asks.
		if mixed && i == 0 {
			_ = wait_until(proc(data: rawptr) -> bool {
					return flight_open((^Server)(data))
				}, &srv, HOLD_LIMIT)
		}
	}
	for round in 0 ..< (2 if evicted_twice else 1) {
		if !leading {
			break
		}
		Waiting :: struct {
			srv:   ^Server,
			count: int,
		}
		w := Waiting{&srv, clients_asking}
		_ = wait_until(proc(data: rawptr) -> bool {
				w := (^Waiting)(data)
				return waiting_on(w.srv) >= w.count
			}, &w, HOLD_LIMIT)
		testing.expect_value(t, waiting_on(&srv), clients_asking)
		time.sleep(land_after)
		leaders[round].stored = evicted
		if evicted_twice && round == 0 {
			land_into(&srv, &leaders[0], &leaders[1])
		} else {
			flight_land(&srv, &leaders[round])
		}
	}
	for th in threads[:clients_asking] {
		thread.join(th)
		thread.destroy(th)
	}
	sync.atomic_store(&m.stop, true)
	thread.join(mock)
	thread.destroy(mock)
	// Every place taken among the queries waiting on an upstream - leaders,
	// followers, the validator's walks - is given back (issue #623).
	testing.expect_value(t, srv.upstream_waits, 0)
	if stats != nil {
		stats^ = srv.stats
	}
	if lookups != nil {
		lookups^ = m.lookups
	}
	if cache_stats != nil {
		cache_stats^ = cache.stats(answers)
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
keeping its client waiting twice as long as the leader did.
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
Clients that ask one question differently - an old stub without EDNS behind an
EDNS leader - send the upstream one message (issue #423), so the followers take
the leader's failure rather than each wait out the same nothing again.
*/
@(test)
test_followers_that_asked_another_way_share_the_leaders_failure :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, silent = true, timeout = 1 * time.Second, mixed = true)
	testing.expectf(t, queries == 1, "the upstream saw %d queries for %d clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
A leader whose message was not theirs may have failed over those bytes rather
than the question, so its followers ask for themselves rather than take its
failure.
*/
@(test)
test_followers_of_another_message_ask_for_themselves :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, other_message = true, silent = true, timeout = 1 * time.Second, hold_for = 0, land_after = 50 * time.Millisecond)
	testing.expectf(t, queries == CLIENTS, "the upstream saw %d queries for %d clients, want %d", queries, CLIENTS, CLIENTS)
}

/*
A follower's wait on the leader is its question's first exchange, and spends its
deadline (issue #439). One whose message was not the leader's forwards on its
own once the leader lands with nothing, and asks with what the wait left, so
against a silent upstream it is done within one more timeout of the leader, the
exchange that crosses the line. A fresh deadline would wait the leader's two
timeouts and then two more of its own.
*/
@(test)
test_a_follower_forwards_on_what_its_wait_left_of_the_deadline :: proc(t: ^testing.T) {
	TIMEOUT :: 400 * time.Millisecond
	clients: [CLIENTS]Client
	run_burst(t, &clients, silent = true, timeout = TIMEOUT, attempts = 2, other_message = true, hold_for = 0, land_after = 2 * TIMEOUT)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
		// The leader's two timeouts and the one that crosses the line, with
		// slack; a fresh deadline for the follower would take four.
		testing.expectf(t, c.took < 7 * TIMEOUT / 2, "client %d waited %v, where its deadline is two timeouts of %v", i, c.took, TIMEOUT)
	}
}

/*
An rcode is shared or not on the same terms. From a leader whose message was the
follower's - which clients asking with and without EDNS both are - a FORMERR
or a REFUSED is the upstream's word on that message; from one whose was not, it
may be a refusal of bytes no follower sent, and only the rcodes the cache itself
keeps are handed on.
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
		mixed: [CLIENTS]Client
		queries := run_burst(t, &mixed, first = rcode, edns = false, mixed = true)
		refused, _ := count(mixed, rcode)
		testing.expectf(t, queries == 1 && refused == CLIENTS, "%v asked both ways: %d queries and %d refusals, want 1 and %d", rcode, queries, refused, CLIENTS)

		other: [CLIENTS]Client
		queries = run_burst(t, &other, first = rcode, other_message = true, hold_for = 0, land_after = 50 * time.Millisecond)
		// The mock answers the first query to reach it with `rcode` too: one
		// follower's own, not the leader's handed on.
		answered: int
		refused, answered = count(other, rcode)
		testing.expectf(t, queries == CLIENTS && refused == 1 && answered == CLIENTS - 1, "%v for another message: %d queries, %d refusals and %d answers, want %d, 1 and %d", rcode, queries, refused, answered, CLIENTS, CLIENTS - 1)
	}
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
	testing.expect(t, s.inflight.slots[lead.slot] == nil, "the landed flight is still in the table")
}

/*
Distinct questions in flight at once each lead a flight of their own, well past
the few hundred a 20 ms upstream keeps in flight at tens of thousands of misses a
second, and each still gathers its followers (#612).
*/
@(test)
test_a_thousand_distinct_misses_each_lead :: proc(t: ^testing.T) {
	N :: 1000
	s: Server
	// A fixed seed: under a drawn one, about one run in ten thousand fills a window.
	s.inflight.seed = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	s.inflight.seeded.done = true
	flights := make([]Flight, N)
	defer delete(flights)
	keys := make([]string, N)
	defer {
		for k in keys {
			delete(k)
		}
		delete(keys)
	}
	led := 0
	for i in 0 ..< N {
		keys[i] = fmt.aprintf("k%d", i)
		if f, _ := flight_join(&s, keys[i], &flights[i]); f == &flights[i] {
			led += 1
		}
	}
	testing.expectf(t, led == N, "%d of %d distinct misses led a flight", led, N)
	follower: Flight
	f, _ := flight_join(&s, keys[N - 1], &follower)
	testing.expect(t, f == &flights[N - 1], "a miss for a key in flight did not follow it")
	if f == &flights[N - 1] {
		flights[N - 1].waiters -= 1
	}
	for i in 0 ..< N {
		if flights[i].key != "" {
			flight_land(&s, &flights[i])
		}
	}
}

/*
A key looks no further than `INFLIGHT_PROBE` slots from its hash, and a full
window turns nobody away: the query forwards on its own, and a key whose window
has room still leads. Keys picked to share a window under a seed the test sets,
which a client cannot know.
*/
@(test)
test_a_full_flight_window_forwards_without_joining :: proc(t: ^testing.T) {
	s: Server
	s.inflight.seed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	s.inflight.seeded.done = true
	home :: proc(s: ^Server, key: string) -> int {
		return flight_home(&s.inflight, key)
	}
	keys: [dynamic]string
	defer {
		for k in keys {
			delete(k)
		}
		delete(keys)
	}
	elsewhere := ""
	target := home(&s, "k0")
	for i := 0; (len(keys) <= INFLIGHT_PROBE || elsewhere == "") && i < 10_000_000; i += 1 {
		k := fmt.aprintf("k%d", i)
		h := home(&s, k)
		if h == target && len(keys) <= INFLIGHT_PROBE {
			append(&keys, k)
		} else if elsewhere == "" && (h + INFLIGHT_SLOTS - target) % INFLIGHT_SLOTS > 2 * INFLIGHT_PROBE {
			elsewhere = k
		} else {
			delete(k)
		}
	}
	if !testing.expectf(t, len(keys) == INFLIGHT_PROBE + 1 && elsewhere != "", "found %d keys for one window", len(keys)) {
		delete(elsewhere)
		return
	}
	defer delete(elsewhere)
	flights: [INFLIGHT_PROBE + 1]Flight
	for i in 0 ..< INFLIGHT_PROBE {
		f, _ := flight_join(&s, keys[i], &flights[i])
		testing.expect(t, f == &flights[i], "a free slot in the window was not taken")
	}
	f, _ := flight_join(&s, keys[INFLIGHT_PROBE], &flights[INFLIGHT_PROBE])
	testing.expect(t, f == nil, "a full window handed out a flight")
	other: Flight
	g, _ := flight_join(&s, elsewhere, &other)
	testing.expect(t, g == &other, "a key with room in its own window did not lead")
	flight_land(&s, &other)
	for i in 0 ..< INFLIGHT_PROBE {
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
		wire, _, err := dns.encode_message(msg, context.temp_allocator)
		if err != .None {
			panic("the message does not encode")
		}
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
		_, landed, same := flight_follow(&s, joined, 5 * time.Second, context.temp_allocator, counted = false, forwarded = follower)
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

// A quarter of `max_pending`, the queries a follower's place is counted among.
@(test)
test_the_follower_ceiling_is_a_quarter_of_max_pending :: proc(t: ^testing.T) {
	cfg: config.Config
	cfg.server.max_pending = 16
	cfg.server.max_connections = 48
	s := Server{cfg = &cfg}
	testing.expect_value(t, follower_ceiling(&s), 4)
	cfg.server.max_pending = 0
	testing.expect_value(t, follower_ceiling(&s), 0)
}

/*
Followers counted in `max_pending` stop at the ceiling, and the count comes back
down as they leave. A query on a connection follows uncounted: `max_connections`
bounds those, and counting them here would let a client holding connections fill
the ceiling and leave every datagram for a hot name to forward on its own.
*/
@(test)
test_counted_followers_stop_at_the_ceiling :: proc(t: ^testing.T) {
	s: Server
	lead: Flight
	first, _ := flight_join(&s, "k", &lead, counted_query = true, ceiling = 2)
	testing.expect(t, first == &lead, "the first query did not lead")
	a, b, c: Flight
	fa, ca := flight_join(&s, "k", &a, counted_query = true, ceiling = 2)
	fb, cb := flight_join(&s, "k", &b, counted_query = true, ceiling = 2)
	fc, _ := flight_join(&s, "k", &c, counted_query = true, ceiling = 2)
	testing.expect(t, fa == &lead && fb == &lead, "a follower under the ceiling was turned away")
	testing.expect(t, fc == nil, "a follower past the ceiling was let in")
	d: Flight
	fd, cd := flight_join(&s, "k", &d, counted_query = false, ceiling = 2)
	testing.expect(t, fd == &lead && !cd, "a follower on a connection was turned away or counted")

	_, _, _ = flight_follow(&s, fa, 0, context.temp_allocator, ca)
	testing.expect_value(t, s.inflight.followers, 1)
	fe, ce := flight_join(&s, "k", &c, counted_query = true, ceiling = 2)
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
its answer - which clients asking with and without EDNS both are.
*/
@(test)
test_with_the_cache_off_only_identical_messages_share_an_answer :: proc(t: ^testing.T) {
	alike: [CLIENTS]Client
	queries := run_burst(t, &alike, cache_on = false, mixed = true)
	testing.expectf(t, queries == 1, "identical: the upstream saw %d queries, want 1", queries)
	apart: [CLIENTS]Client
	queries = run_burst(t, &apart, cache_on = false, other_message = true, hold_for = 0, land_after = 50 * time.Millisecond)
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
	st: Stats
	cs: cache.Stats
	queries := run_burst(t, &clients, validating = true, lookups = &walked, stats = &st, cache_stats = &cs)
	testing.expectf(t, queries == 1, "the upstream saw the question %d times for %d clients, want 1", queries, CLIENTS)
	testing.expectf(t, walked == one_walk, "the chain was asked for %d times, want one walk's %d", walked, one_walk)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .Serv_Fail, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
	// One miss a client, taken on the way in; the verdict is read as a probe,
	// which counts nothing, and the followers are what was coalesced.
	testing.expect_value(t, cs.misses, u64(CLIENTS))
	testing.expect_value(t, cs.hits, u64(0))
	testing.expect_value(t, st.coalesced, u64(CLIENTS - 1))
}

@(test)
test_followers_of_a_cloaked_leader_are_blocked_from_its_verdict :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	st: Stats
	cs: cache.Stats
	queries := run_burst(t, &clients, cloak = true, stats = &st, cache_stats = &cs)
	testing.expectf(t, queries == 1, "the upstream saw the question %d times for %d clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.outcome == .Blocked, "client %d: ok=%v outcome=%v", i, c.ok, c.outcome)
	}
	// A miss each on the way in, and a counted hit - then withheld - for each
	// follower that read the refusal.
	testing.expect_value(t, cs.misses, u64(CLIENTS))
	testing.expect_value(t, cs.hits, u64(CLIENTS - 1))
	testing.expect_value(t, cs.withheld, u64(CLIENTS - 1))
	testing.expect_value(t, st.coalesced, u64(CLIENTS - 1))
}

/*
A leader's stored verdict gone by the time its followers read it - evicted from
a cache at its bounds - sends them back to the flight table once, where one
leads the next exchange and the rest follow it, rather than every one of them
forwarding on its own (issue #428).
*/
@(test)
test_followers_of_an_evicted_verdict_rejoin_the_flight :: proc(t: ^testing.T) {
	for verdict in ([]Stored_Verdict{.Bogus, .Cloak}) {
		clients: [CLIENTS]Client
		queries := run_burst(t, &clients, evicted = verdict)
		testing.expectf(t, queries == 1, "%v: the upstream saw the question %d times for %d clients, want 1", verdict, queries, CLIENTS)
		for c, i in clients {
			testing.expectf(t, c.ok && c.rcode == .No_Error, "%v: client %d: ok=%v rcode=%v", verdict, i, c.ok, c.rcode)
		}
	}
}

/*
A follower going round leads with a deadline of its own from that moment, not
with what its first wait left (issue #428): one that waited out its deadline on
the evicted leader would otherwise lead on nothing, ask nobody, and hand that
failure to every query following it.

The hand-made leader lands two timeouts and a little after the last follower
joined, so every follower's deadline - armed before its join - has passed, and
well inside their patience of four: the clients may start up to about two
timeouts apart before the first one gives up.
*/
@(test)
test_a_follower_going_round_leads_on_a_deadline_of_its_own :: proc(t: ^testing.T) {
	TIMEOUT :: 250 * time.Millisecond
	clients: [CLIENTS]Client
	queries := run_burst(t, &clients, timeout = TIMEOUT, evicted = .Bogus, land_after = 2 * TIMEOUT + 20 * time.Millisecond)
	testing.expectf(t, queries == 1, "the upstream saw the question %d times for %d clients, want 1", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .No_Error, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
Once only: a second leader's verdict gone as fast as the first's is a cache that
holds nothing, and each follower forwards on its own rather than going round
again (issue #428).
*/
@(test)
test_followers_rejoin_an_evicted_verdict_once_only :: proc(t: ^testing.T) {
	clients: [CLIENTS]Client
	// Nobody follows the forwards at the end, so the mock holds none of them.
	queries := run_burst(t, &clients, evicted = .Bogus, evicted_twice = true, hold_for = 0)
	testing.expectf(t, queries == CLIENTS, "the upstream saw the question %d times for %d clients, want one each", queries, CLIENTS)
	for c, i in clients {
		testing.expectf(t, c.ok && c.rcode == .No_Error, "client %d: ok=%v rcode=%v", i, c.ok, c.rcode)
	}
}

/*
A follower waits on its leader for what is left of its own deadline and one
exchange more, not for as long as an unbounded forward would take (issue #446).

The deadline is armed before the join (#439), so a leader still out past it and
the one exchange it may finish is stuck on something other than its upstreams -
and the follower, when its patience runs out, forwards on a deadline already
spent and asks nobody. Any wait past that point holds the follower for nothing.
The leader here never lands; with two servers and two attempts a patience sized
for an unbounded forward would be ten timeouts, where the follower's deadline is
two.
*/
@(test)
test_a_follower_waits_no_longer_than_its_deadline_allows :: proc(t: ^testing.T) {
	TIMEOUT :: 100 * time.Millisecond
	sockets: [2]net.UDP_Socket
	bound := 0
	defer for socket in sockets[:bound] {
		net.close(socket)
	}
	servers := make([]config.Upstream_Spec, 2, context.temp_allocator)
	for i in 0 ..< 2 {
		socket, spec, ok := bind_mock(t, "silent")
		if !ok {
			return
		}
		sockets[i] = socket
		bound += 1
		servers[i] = spec
	}
	cfg := test_config(servers)
	cfg.upstream.attempts = 2
	cfg.upstream.timeout = TIMEOUT
	group, gerr := upstream.make_group(cfg.upstream, context.allocator)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	srv := Server {
		cfg   = &cfg,
		group = group,
	}

	// The leader: in the table under the follower's key, and never landing
	// until the follower has given up on it.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], QNAME, .A, .IN, false, false)
	leader: Flight
	if joined, _ := flight_join(&srv, key, &leader); !testing.expect(t, joined == &leader, "the leader did not get the flight") {
		return
	}
	defer flight_land(&srv, &leader)

	started := time.tick_now()
	out, _, ok := handle_query(&srv, test_query(QNAME, id = 0x4460), .UDP, "127.0.0.1:5555", context.temp_allocator)
	took := time.tick_since(started)

	testing.expect(t, ok, "the follower got no answer at all")
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.Serv_Fail)
	// Its two timeouts of deadline and two for the leader's crossing exchange,
	// with slack; a patience sized for an unbounded forward would wait ten.
	testing.expectf(t, took < 6 * TIMEOUT, "the follower waited %v on a leader, where its deadline is %v", took, 2 * TIMEOUT)
	// And it forwarded on nothing: the deadline was spent on the wait.
	for socket in sockets {
		testing.expect(t, mock_untouched(socket), "the follower asked an upstream after its deadline")
	}
	free_all(context.temp_allocator)
}

@(private = "file")
Late_Leader :: struct {
	srv:    ^Server,
	flight: ^Flight,
	answer: []u8,
	at:     time.Tick,
}

// Lands the leader's flight with `answer` at `at`, as a leader whose crossing
// exchange came back just past the deadline would.
@(private = "file")
land_late :: proc(l: ^Late_Leader) {
	for time.tick_diff(time.tick_now(), l.at) > 0 {
		time.sleep(time.Millisecond)
	}
	l.flight.answer = l.answer
	flight_land(l.srv, l.flight)
}

/*
And not shorter than that: a leader landing inside the two timeouts past the
deadline - the exchange that crossed the line, retried over TCP, finishing -
still serves its follower, which otherwise gives up at its deadline and has
nobody left to ask.
*/
@(test)
test_a_follower_still_takes_an_answer_landing_just_past_its_deadline :: proc(t: ^testing.T) {
	TIMEOUT :: 400 * time.Millisecond
	socket, spec, bound := bind_mock(t, "silent")
	if !bound {
		return
	}
	defer net.close(socket)
	cfg := test_config(loopback_upstream(spec.port, "silent"))
	cfg.cache.enabled = true
	cfg.upstream.timeout = TIMEOUT
	group, gerr := upstream.make_group(cfg.upstream, context.allocator)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	srv := Server {
		cfg     = &cfg,
		group   = group,
		answers = answers,
	}

	answer := test_reply(QNAME, .A, a_record(QNAME, {192, 0, 2, 46}, ttl = 300))

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], QNAME, .A, .IN, false, false)
	leader: Flight
	if joined, _ := flight_join(&srv, key, &leader); !testing.expect(t, joined == &leader, "the leader did not get the flight") {
		return
	}
	// A timeout and a half past the follower's deadline of two - a UDP reply
	// that crossed the line truncated and was asked again over TCP - give or
	// take the moment between this and its join.
	late := Late_Leader{srv = &srv, flight = &leader, answer = answer, at = time.tick_add(time.tick_now(), 7 * TIMEOUT / 2)}
	lander := thread.create_and_start_with_poly_data(&late, land_late)

	out, outcome, ok := handle_query(&srv, test_query(QNAME, id = 0x4462), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(lander)
	thread.destroy(lander)

	testing.expect(t, ok, "the follower got no answer at all")
	testing.expect_value(t, outcome, Outcome.Cached)
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.No_Error)
	testing.expect_value(t, len(decoded.answer), 1)
	free_all(context.temp_allocator)
}
