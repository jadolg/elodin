package server

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:upstream"

/*
An answer `cache.put` refuses still supersedes the expired copy (issue #419).

The upstream has spoken: a TTL-0 answer is the zone saying "do not cache this"
(RFC 1035 section 3.2.1, RFC 2181 section 8), and a denial without a SOA is one
RFC 2308 section 5 says not to cache - but both are answers, and the expired
bytes no longer stand for anything. Left in place, every later query whose
upstream is slower than `stale_timeout` is lent those bytes again, for the rest
of the day `serve_stale` keeps them, while the upstream answers the whole time.

A failure is the other side: SERVFAIL and REFUSED are what RFC 8767 keeps the
copy for, so they leave it where it was.

Both roads a refresh takes: detached on the pool, answering after the client was
lent the copy, and on the client's own thread where there is no loop.
*/
@(private = "file")
Superseded_Case :: struct {
	name:   string,
	reply:  []u8,
	// Whether the expired entry is still there once the reply has landed.
	kept:   bool,
	// A name on the block list, so the reply is refused by the CNAME walk
	// and reaches the cache through the cloaking store instead.
	block:  string,
	// Rebinding protection on, so the reply is refused by that guard and
	// never reaches the cache at all.
	rebind: bool,
}

// The question and `answer`, under `rcode`.
@(private = "file")
superseded_reply :: proc(rcode: dns.Rcode, answer: ..dns.Record) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = STALE_NAME, type = .A, class = .IN}
	records := make([]dns.Record, len(answer), context.temp_allocator)
	copy(records, answer)
	msg := dns.Message{question = question, answer = records}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	dns.set_rcode(&msg, rcode)
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
superseded_a :: proc(name: string, addr: [4]u8, ttl: u32) -> dns.Record {
	return dns.Record{name = name, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = addr}}
}

// `wire` with one additional record whose RDLENGTH runs past the end, so only
// the sections up to the answer decode.
@(private = "file")
superseded_junk :: proc(wire: []u8) -> []u8 {
	junk := make([dynamic]u8, 0, len(wire) + 11, context.temp_allocator)
	append(&junk, ..wire)
	junk[11] = 1 // ARCOUNT
	append(&junk, 0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 32) // root, TXT, IN, TTL 0, RDLENGTH 32
	return junk[:]
}

// An RRSIG over the A record whose expiration passed an hour ago.
@(private = "file")
superseded_lapsed_rrsig :: proc() -> dns.Record {
	expiration := u32(time.time_to_unix(time.now())) - 3600
	data := make([]u8, 23, context.temp_allocator)
	data[0], data[1], data[2], data[3] = 0, 1, 8, 2 // covers A, RSASHA256, 2 labels
	dns.write_ttl_at(data, 4, 300)
	dns.write_ttl_at(data, 8, expiration)
	dns.write_ttl_at(data, 12, expiration - 30 * 86400)
	// Key tag, the root as signer, and a signature nothing checks.
	copy(data[16:], []u8{0x12, 0x34, 0, 0xde, 0xad, 0xbe, 0xef})
	return dns.Record{name = STALE_NAME, type = .RRSIG, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = data}}
}

@(private = "file")
superseded_cases :: proc() -> []Superseded_Case {
	tracker :: "tracker.evil.example."
	chain := dns.Record{name = STALE_NAME, type = .CNAME, class = .IN, data = dns.Rdata_Name{name = tracker}}
	cases := make([]Superseded_Case, 14, context.temp_allocator)
	cases[0] = {"a TTL-0 answer", superseded_reply(.No_Error, superseded_a(STALE_NAME, LIVE_ADDR, 0)), false, "", false}
	cases[1] = {"a NODATA without a SOA", superseded_reply(.No_Error), false, "", false}
	cases[2] = {"an NXDOMAIN without a SOA", superseded_reply(.NX_Domain), false, "", false}
	cases[3] = {"a SERVFAIL", superseded_reply(.Serv_Fail), true, "", false}
	cases[4] = {"a REFUSED", superseded_reply(.Refused), true, "", false}
	cases[5] = {
		"a TTL-0 chain to a listed name",
		superseded_reply(.No_Error, chain, superseded_a(tracker, LIVE_ADDR, 0)),
		false,
		"tracker.evil.example",
		false,
	}
	cases[6] = {"a private address", superseded_reply(.No_Error, superseded_a(STALE_NAME, {10, 0, 0, 1}, 300)), false, "", true}
	// RFC 2308 section 2.1: a name error carries the chain and nothing else, so
	// this one contradicts itself and is no answer to supersede anything with.
	cases[7] = {"an NXDOMAIN carrying an address", superseded_reply(.NX_Domain, superseded_a(STALE_NAME, LIVE_ADDR, 300)), true, "", false}
	cases[8] = {"an NXDOMAIN carrying a private address", superseded_reply(.NX_Domain, superseded_a(STALE_NAME, {10, 0, 0, 1}, 300)), true, "", true}
	// Neither is read in full, which is no answer to supersede anything with.
	cases[9] = {"a TTL-0 answer with junk after it", superseded_junk(superseded_reply(.No_Error, superseded_a(STALE_NAME, LIVE_ADDR, 0))), true, "", false}
	cases[10] = {"a private address with junk after it", superseded_junk(superseded_reply(.No_Error, superseded_a(STALE_NAME, {10, 0, 0, 1}, 300))), true, "", true}
	// RFC 4034 section 3.1.5: not to be used, so no answer either.
	cases[11] = {
		"a private address whose signature lapsed",
		superseded_reply(.No_Error, superseded_a(STALE_NAME, {10, 0, 0, 1}, 300), superseded_lapsed_rrsig()),
		true,
		"",
		true,
	}
	// An answer section with nothing at the question name answers nothing
	// that was asked, which the cache reads as a denial and rebind refuses.
	cases[12] = {"a NOERROR about another name", superseded_reply(.No_Error, superseded_a("other.example.", LIVE_ADDR, 300)), true, "", false}
	cases[13] = {"a private address at another name", superseded_reply(.No_Error, superseded_a("other.example.", {10, 0, 0, 1}, 300)), true, "", true}
	return cases
}

@(private = "file")
run_superseded :: proc(t: ^testing.T, c: Superseded_Case, detached: bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return
	}

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	s := stale_server(&cfg, answers, nil)
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 5 * time.Second
	cfg.cache.stale_timeout = 100 * time.Millisecond
	cfg.upstream.servers = blackhole_servers(bound.port)

	group, gerr := upstream.make_group(cfg.upstream, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s.group = group
	if c.block != "" {
		engine := filter.engine_make()
		block := filter.set_make()
		filter.set_add(block, c.block, {.Apex, .Subdomains})
		filter.engine_swap(engine, block, filter.set_make())
		cfg.blocking.enabled = true
		s.filters = engine
	}
	cfg.rebind.enabled = c.rebind
	defer if s.filters != nil {
		filter.engine_destroy(s.filters)
	}
	workers: Test_Loop
	if detached {
		start_test_loop(&workers)
		s.loops = workers.loops[:]
	}
	defer stop_test_loop(&workers)

	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	// On the detached road the reply waits for the client to have been lent
	// the copy, so it reaches the cache alone; prompt where the client waits.
	lent: sync.Sema
	x := Stale_Exchange {
		socket = socket,
		reply  = c.reply,
		hold   = &lent if detached else nil,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	_, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	sync.sema_post(&lent)
	thread.join(mock)
	thread.destroy(mock)
	testing.expectf(t, ok, "%s: nothing came back", c.name)
	testing.expectf(t, x.got, "%s: the upstream was never asked", c.name)
	if !detached && (c.block != "" || c.rebind) {
		testing.expectf(t, outcome == .Blocked, "%s: the reply was not refused (%v)", c.name, outcome)
	}
	if detached {
		testing.expectf(t, outcome == .Cached, "%s: the client was not lent the copy (%v)", c.name, outcome)
		// Joined, not slept on: the store happens on the refresh's way out.
		stop_test_loop(&workers)
		s.loops = nil
	}

	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	_, hit, found := cache.get(answers, key, context.temp_allocator)
	if c.kept {
		testing.expectf(t, found && hit.stale, "%s (detached=%v): the expired copy was dropped", c.name, detached)
	} else {
		testing.expectf(t, !found, "%s (detached=%v): the expired copy outlived the upstream's answer", c.name, detached)
	}
}

@(test)
test_a_late_refused_answer_supersedes_the_stale_copy :: proc(t: ^testing.T) {
	for c in superseded_cases() {
		run_superseded(t, c, detached = true)
	}
	free_all(context.temp_allocator)
}

@(test)
test_a_refused_answer_supersedes_the_stale_copy_without_a_pool :: proc(t: ^testing.T) {
	for c in superseded_cases() {
		run_superseded(t, c, detached = false)
	}
	free_all(context.temp_allocator)
}

@(private = "file")
Tcp_Superseded :: struct {
	listener: net.TCP_Socket,
	reply:    []u8,
	got:      bool,
}

// Answer one query over TCP, with the TC bit set on the reply.
@(private = "file")
serve_one_truncated :: proc(x: ^Tcp_Superseded) {
	conn, _, aerr := net.accept_tcp(x.listener)
	if aerr != nil {
		return
	}
	defer net.close(conn)
	_ = net.set_option(conn, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	length: [2]u8
	if n, err := net.recv_tcp(conn, length[:]); err != nil || n != 2 {
		return
	}
	buf: [512]u8
	want := int(length[0]) << 8 | int(length[1])
	got := 0
	for got < want && want <= len(buf) {
		n, err := net.recv_tcp(conn, buf[got:want])
		if err != nil || n == 0 {
			return
		}
		got += n
	}
	if got < dns.HEADER_SIZE {
		return
	}
	x.got = true
	out: [514]u8
	out[0], out[1] = u8(len(x.reply) >> 8), u8(len(x.reply))
	copy(out[2:], x.reply)
	out[2], out[3] = buf[0], buf[1]
	out[4] |= 0x02 // TC
	_, _ = net.send_tcp(conn, out[:2 + len(x.reply)])
}


/*
A truncated reply is not the answer, so the expired copy stays.

RFC 2181 section 9 has a truncated response retried rather than used, and
`cache.put` turns it away; a server that sets TC over TCP has not answered the
question either. Over TCP because a TC over UDP is retried there and never
reaches the store. Both roads a reply takes to drop the copy: the store, and
the rebinding guard, which refuses a private address before the store is
reached.
*/
@(test)
test_a_truncated_reply_keeps_the_stale_copy :: proc(t: ^testing.T) {
	run_truncated(t, superseded_reply(.No_Error, superseded_a(STALE_NAME, LIVE_ADDR, 0)), false)
	run_truncated(t, superseded_reply(.No_Error, superseded_a(STALE_NAME, {10, 0, 0, 1}, 300)), true)
	free_all(context.temp_allocator)
}

@(private = "file")
run_truncated :: proc(t: ^testing.T, reply: []u8, rebind: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	// Bounds the accept, so a resolver that never connects fails the test
	// rather than hanging the join.
	_ = net.set_option(listener, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, _ := net.bound_endpoint(listener)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	s := stale_server(&cfg, answers, nil)
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 5 * time.Second
	cfg.rebind.enabled = rebind
	servers := blackhole_servers(bound.port)
	servers[0].kind = .TCP
	cfg.upstream.servers = servers
	group, gerr := upstream.make_group(cfg.upstream, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s.group = group
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	x := Tcp_Superseded {
		listener = listener,
		reply    = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_truncated)
	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	testing.expectf(t, x.got, "rebind=%v: the upstream was never asked", rebind)
	// The premise: the TC reply reached the guard, or the client and so the store.
	if rebind {
		testing.expectf(t, outcome == .Blocked, "the truncated private address was not refused (%v)", outcome)
	} else if testing.expect(t, ok && len(out) >= dns.HEADER_SIZE, "nothing came back") {
		testing.expect(t, out[2] & 0x02 != 0, "the reply that came back was not truncated")
	}

	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	_, hit, found := cache.get(answers, key, context.temp_allocator)
	testing.expectf(t, found && hit.stale, "rebind=%v: a truncated reply dropped the expired copy", rebind)
}
