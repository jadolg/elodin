package upstream

import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:loop"

// A bootstrap server answering A for any name with `addr` and `ttl`, or nothing
// while `silent`. Fields other than `socket` and `stop` are under `mu`.
@(private = "file")
Ttl_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	mu:     sync.Mutex,
	addr:   [4]u8,
	ttl:    u32,
	silent: bool,
	asked:  int,
	// Held before each answer, so lookups overlap.
	delay:  time.Duration,
	// A second A record, when set, in an order that turns with every answer.
	also:   [4]u8,
	// When set, the A records hang off a CNAME with this TTL.
	cname:  u32,
	// When set, an A record owned by a name off the chain, first in the answer.
	stray:  [4]u8,
	// The CNAME after the records it leads to rather than before.
	cname_last: bool,
	// When set, AAAA is answered with it; A is answered with nothing while
	// `no_a`.
	addr6:  [16]u8,
	no_a:   bool,
	// A is answered SERVFAIL: a failure to say, not an answer.
	servfail_a: bool,
}

@(private = "file")
ttl_mock_loop :: proc(m: ^Ttl_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		defer free_all(context.temp_allocator)
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		msg, derr := dns.decode_message(buf[:n], context.temp_allocator)
		if derr != .None || len(msg.question) != 1 {
			continue
		}
		sync.mutex_lock(&m.mu)
		m.asked += 1
		silent, addr, ttl, delay, also, cname, stray, cname_last, turn := m.silent, m.addr, m.ttl, m.delay, m.also, m.cname, m.stray, m.cname_last, m.asked % 2 == 0
		addr6, no_a, servfail_a := m.addr6, m.no_a, m.servfail_a
		sync.mutex_unlock(&m.mu)
		if silent {
			continue
		}
		if delay > 0 {
			time.sleep(delay) // lint:allow stands in for a slow bootstrap server; nothing is ordered on it
		}
		resp := dns.make_response(msg, .Serv_Fail if servfail_a && msg.question[0].type == .A else .No_Error, context.temp_allocator)
		q := msg.question[0]
		if q.type == .AAAA && addr6 != {} {
			answer := make([]dns.Record, 1, context.temp_allocator)
			answer[0] = dns.Record{name = q.name, type = .AAAA, class = .IN, ttl = ttl, data = dns.Rdata_AAAA{addr = addr6}}
			resp.answer = answer
		}
		if q.type == .A && !no_a && !servfail_a {
			answer := make([dynamic]dns.Record, context.temp_allocator)
			if stray != {} {
				append(&answer, dns.Record{name = "stray.invalid.", type = .A, class = .IN, ttl = 1, data = dns.Rdata_A{addr = stray}})
			}
			owner := q.name
			if cname != 0 {
				owner = "target.invalid."
				if !cname_last {
					append(&answer, dns.Record{name = q.name, type = .CNAME, class = .IN, ttl = cname, data = dns.Rdata_Name{name = owner}})
				}
			}
			first, second := addr, also
			if also != {} && turn {
				first, second = also, addr
			}
			append(&answer, dns.Record{name = owner, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = first}})
			if also != {} {
				append(&answer, dns.Record{name = owner, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = second}})
			}
			if cname != 0 && cname_last {
				append(&answer, dns.Record{name = q.name, type = .CNAME, class = .IN, ttl = cname, data = dns.Rdata_Name{name = owner}})
			}
			resp.answer = answer[:]
		}
		wire, _, eerr := dns.encode_message(resp, context.temp_allocator)
		if eerr != .None {
			continue
		}
		_, _ = net.send_udp(m.socket, wire, client) // lint:allow an answer lost here fails the lookup the test checks
	}
}

@(private = "file")
ttl_mock_set :: proc(m: ^Ttl_Mock, addr: [4]u8, silent := false) {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	m.addr, m.silent = addr, silent
}

@(private = "file")
ttl_mock_asked :: proc(m: ^Ttl_Mock) -> int {
	sync.mutex_lock(&m.mu)
	defer sync.mutex_unlock(&m.mu)
	return m.asked
}

// Let the address an upstream holds, and the bootstrap cache's entry for it, run
// out, as their TTL would.
@(private = "file")
expire_address :: proc(u: ^Upstream, key: string) {
	past := loop.moment_add(loop.moment_now(), -time.Second)
	sync.atomic_store(&u.expires, past)
	sync.mutex_lock(&bootstrap_cache.mu)
	defer sync.mutex_unlock(&bootstrap_cache.mu)
	if entry, found := &bootstrap_cache.entries[key]; found {
		entry.expires = past
	}
}

@(private = "file")
address_of :: proc(u: ^Upstream) -> net.Address {
	ep, _, err := endpoint_of(u)
	return ep.address if err == .None else nil
}

// How far `expires` is from now, as a duration.
@(private = "file")
expires_in :: proc(u: ^Upstream) -> time.Duration {
	return -loop.moment_since(sync.atomic_load(&u.expires))
}

/*
RFC 1035 section 3.2.1: a record's TTL is how long it "may be cached before the
source of the information should again be consulted". Read as RFC 2181
section 8 asks, within `BOOTSTRAP_MIN_TTL` and `BOOTSTRAP_TTL`.
*/
@(test)
test_a_bootstrap_answer_is_held_for_its_ttl_within_bounds :: proc(t: ^testing.T) {
	Row :: struct {
		ttl:  u32,
		want: time.Duration,
	}
	rows := []Row {
		{ttl = 0, want = BOOTSTRAP_MIN_TTL},
		{ttl = 1, want = BOOTSTRAP_MIN_TTL},
		{ttl = 300, want = 300 * time.Second},
		{ttl = u32(BOOTSTRAP_TTL / time.Second) + 1, want = BOOTSTRAP_TTL},
		// The top bit set reads as zero (RFC 2181 section 8), not as 68 years.
		{ttl = 0x8000_012c, want = BOOTSTRAP_MIN_TTL},
	}
	for row in rows {
		testing.expectf(t, bootstrap_ttl(row.ttl) == row.want, "TTL %d is held %v, want %v", row.ttl, bootstrap_ttl(row.ttl), row.want)
	}
}

/*
An upstream named by hostname holds its address for the TTL it was answered
with, and the exchange that finds it past asks the bootstrap servers again. An
address that moves is dialled from then on, and the shared connection to the
old one is let go. A bootstrap that does not answer the refresh leaves the
address held, and the exchange goes on to it.
*/
@(test)
test_an_upstream_hostname_is_asked_again_once_its_ttl_is_past :: proc(t: ^testing.T) {
	// The bootstrap cache is package-global; see `bootstrap_cache_owner`.
	sync.mutex_lock(&bootstrap_cache_owner)
	defer sync.mutex_unlock(&bootstrap_cache_owner)
	defer bootstrap_destroy()

	m := Ttl_Mock {
		addr = {127, 0, 0, 2},
		ttl  = 300,
	}
	bound, responder, ok := serve_udp_mock(t, &m, ttl_mock_loop)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, responder)

	HOST :: "moving.invalid"
	bootstrap := []string{net.endpoint_to_string(bound, context.temp_allocator)}
	// A port nothing listens on at either address, so an exchange fails fast
	// and what it dialled is all that matters.
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "moving", kind = .TCP, address = HOST, port = bound.port, bootstrap = bootstrap},
		0,
		time.Second,
		cookies = true,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)
	if !testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 2}), "the hostname did not resolve at startup") {
		return
	}
	left := expires_in(u)
	testing.expectf(t, left > 299 * time.Second && left <= 300 * time.Second, "the address is held %v, where its TTL is 300s", left)

	wire, _, eerr := dns.encode_message(
		dns.Message{id = 0x6910, question = []dns.Question{{name = "example.com.", type = .A, class = .IN}}},
		context.temp_allocator,
	)
	if !testing.expectf(t, eerr == .None, "cannot encode the query: %v", eerr) {
		return
	}

	// Within the TTL the address held is dialled, and nobody is asked.
	ttl_mock_set(&m, {127, 0, 0, 3})
	_, _ = exchange(u, wire, time.Second, context.temp_allocator) // lint:allow the member is a port nothing listens on; what it dialled is checked
	testing.expect_value(t, ttl_mock_asked(&m), 1)
	testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 2}), "the address moved within its TTL")

	// Past it, the next exchange asks again and dials the new address.
	expire_address(u, HOST + ".")
	_, _ = exchange(u, wire, time.Second, context.temp_allocator) // lint:allow as above
	testing.expect_value(t, ttl_mock_asked(&m), 2)
	testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 3}), "the address was not asked for again past its TTL")

	// A lookup that finds the address moved starts a new epoch, so the
	// connections to the old one are not reached for again (see
	// `test_a_connection_from_before_a_move_is_not_used_again`); one that finds
	// it where it was does not.
	for moved in ([]bool{false, true}) {
		sync.mutex_lock(&u.mu)
		epoch := u.epoch
		// A server cookie learned from the address held.
		u.cookie.server_len = 8
		client := u.cookie.client
		u.proto = .H1
		sync.mutex_unlock(&u.mu)
		ttl_mock_set(&m, {127, 0, 0, 5} if moved else {127, 0, 0, 3})
		expire_address(u, HOST + ".")
		testing.expect_value(t, resolve_endpoint(u, refresh = true), Error.None)
		sync.mutex_lock(&u.mu)
		next := u.epoch != epoch
		sync.mutex_unlock(&u.mu)
		testing.expectf(t, next == moved, "moved %v: a new epoch %v", moved, next)
		// RFC 7873 section 5.1, RFC 9018 section 3: cookies are per server
		// address, so a move starts afresh.
		sync.mutex_lock(&u.mu)
		forgot, redrawn := u.cookie.server_len == 0, u.cookie.client != client
		relearn := u.proto == .Unknown
		sync.mutex_unlock(&u.mu)
		testing.expectf(t, relearn == moved, "moved %v: the protocol is to be learned again %v", moved, relearn)
		testing.expectf(t, forgot == moved && redrawn == moved, "moved %v: server cookie forgotten %v, client cookie drawn afresh %v", moved, forgot, redrawn)
	}
	testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 5}), "the moved address was not published")

	// A bootstrap gone quiet: the address held is kept, the exchange is not
	// failed as unresolved, and the next ask waits `BOOTSTRAP_MIN_TTL`.
	ttl_mock_set(&m, {127, 0, 0, 4}, silent = true)
	expire_address(u, HOST + ".")
	_, err := exchange(u, wire, time.Second, context.temp_allocator)
	testing.expect(t, err != .Not_Resolved, "a failed refresh left the member unresolved")
	testing.expect(t, ttl_mock_asked(&m) > 4, "the bootstrap was not asked past the TTL")
	testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 5}), "a failed refresh lost the address held")
	left = expires_in(u)
	testing.expectf(t, left > 0 && left <= BOOTSTRAP_MIN_TTL, "a failed refresh is asked again in %v", left)
	testing.expect(t, sync.atomic_load(&u.refresh_failing), "a failed refresh was not marked, so the next would warn again")
	// A lookup that fails while the time to ask again is still ahead, as one
	// racing a refresh that succeeded does, leaves that time where it is.
	before := sync.atomic_load(&u.expires)
	testing.expect_value(t, resolve_endpoint(u, time.tick_add(time.tick_now(), 100 * time.Millisecond), refresh = true), Error.None)
	testing.expect(t, sync.atomic_load(&u.expires) == before, "a failed lookup moved a time to ask again that was still ahead")
	// One that succeeds ends the run, so the next failure warns again.
	ttl_mock_set(&m, {127, 0, 0, 5})
	expire_address(u, HOST + ".")
	testing.expect_value(t, resolve_endpoint(u, refresh = true), Error.None)
	testing.expect(t, !sync.atomic_load(&u.refresh_failing), "a refresh that succeeded left the run of failures marked")
	free_all(context.temp_allocator)
}

@(private = "file")
Refresher :: struct {
	u:    ^Upstream,
	wire: []u8,
}

@(private = "file")
refresher_worker :: proc(r: ^Refresher) {
	_, _ = exchange(r.u, r.wire, time.Second, context.temp_allocator) // lint:allow the member is a port nothing listens on; the lookups are counted
	free_all(context.temp_allocator)
}

/*
Exchanges that arrive together past the TTL send one lookup to the bootstrap
servers, not one each: the rest dial the address held meanwhile.
*/
@(test)
test_one_exchange_refreshes_an_expired_address :: proc(t: ^testing.T) {
	sync.mutex_lock(&bootstrap_cache_owner)
	defer sync.mutex_unlock(&bootstrap_cache_owner)
	defer bootstrap_destroy()

	m := Ttl_Mock {
		addr = {127, 0, 0, 2},
		ttl  = 300,
	}
	bound, responder, ok := serve_udp_mock(t, &m, ttl_mock_loop)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, responder)

	HOST :: "crowded.invalid"
	bootstrap := []string{net.endpoint_to_string(bound, context.temp_allocator)}
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "crowded", kind = .TCP, address = HOST, port = bound.port, bootstrap = bootstrap},
		0,
		time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)
	if !testing.expect_value(t, ttl_mock_asked(&m), 1) {
		return
	}
	wire, _, eerr := dns.encode_message(
		dns.Message{id = 0x6911, question = []dns.Question{{name = "example.com.", type = .A, class = .IN}}},
		context.allocator,
	)
	if !testing.expectf(t, eerr == .None, "cannot encode the query: %v", eerr) {
		return
	}
	defer delete(wire)

	sync.mutex_lock(&m.mu)
	m.addr, m.delay = {127, 0, 0, 3}, 100 * time.Millisecond
	sync.mutex_unlock(&m.mu)
	expire_address(u, HOST + ".")
	r := Refresher {
		u    = u,
		wire = wire,
	}
	workers: [8]^thread.Thread
	for &w in workers {
		w = thread.create_and_start_with_poly_data(&r, refresher_worker)
	}
	for w in workers {
		if w != nil {
			thread.join(w)
			thread.destroy(w)
		}
	}
	testing.expect_value(t, ttl_mock_asked(&m), 2)
	testing.expect(t, address_of(u) == net.Address(net.IP4_Address{127, 0, 0, 3}), "the address was not refreshed")
	testing.expect(t, !sync.atomic_load(&u.refreshing), "the refresh was left marked in progress")
}

/*
A connection dialled before the address moved is not used again: the shared
pipelined one is not handed out, and an HTTP/1.1 one coming back from a query
is closed rather than pooled. One dialled since is.
*/
@(test)
test_a_connection_from_before_a_move_is_not_used_again :: proc(t: ^testing.T) {
	u, uerr := make_upstream(config.Upstream_Spec{name = "moved", kind = .TCP, address = "127.0.0.1", port = 9}, 4, time.Hour)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)

	// Ready: used just now, nothing waiting. One reference is the upstream's,
	// one the test's.
	c := new(Pipe_Conn)
	defer free(c)
	c.stream.socket = net.TCP_Socket(-1)
	c.timeout = time.Hour
	c.last = loop.moment_now()
	c.refs = 2
	sync.mutex_lock(&u.mu)
	u.pipe = c
	sync.mutex_unlock(&u.mu)
	got, err := get_pipe(u, time.Second, time.tick_add(time.tick_now(), 100 * time.Millisecond))
	if testing.expectf(t, got == c && err == .None, "the premise: a current connection is handed out (%v)", err) {
		pipe_unref(got)
	}

	sync.mutex_lock(&u.mu)
	u.epoch += 1
	sync.mutex_unlock(&u.mu)
	got, err = get_pipe(u, time.Second, time.tick_add(time.tick_now(), 100 * time.Millisecond))
	testing.expect(t, got != c, "a connection to the old address was handed out")
	if got != nil && got != c {
		pipe_unref(got)
	}
	sync.mutex_lock(&u.mu)
	kept := u.pipe == c
	if kept {
		u.pipe = nil
	}
	sync.mutex_unlock(&u.mu)
	testing.expect(t, !kept, "the connection to the old address stayed shared")
	testing.expect_value(t, sync.atomic_load(&c.refs), 1)

	for current in ([]bool{false, true}) {
		socket, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
		if !testing.expectf(t, lerr == nil, "cannot open a socket: %v", lerr) {
			return
		}
		put_idle(u, Stream{socket = socket, epoch = u.epoch if current else u.epoch - 1})
		sync.mutex_lock(&u.mu)
		pooled := len(u.idle)
		sync.mutex_unlock(&u.mu)
		testing.expectf(t, pooled == (1 if current else 0), "current %v: %d pooled", current, pooled)
	}
	// And one pooled before a move is not taken after it.
	sync.mutex_lock(&u.mu)
	u.epoch += 1
	sync.mutex_unlock(&u.mu)
	_, taken := take_idle(u)
	testing.expect(t, !taken, "a pooled connection to the old address was taken")
	sync.mutex_lock(&u.mu)
	left := len(u.idle)
	sync.mutex_unlock(&u.mu)
	testing.expect_value(t, left, 0)
}

/*
A server that turns the order of an RRset with each answer does not make the
address look moved: the lowest is taken every time. Only records on the chain
from the name asked count, so a lower address under another owner is passed
over. The address is held for the shortest TTL on the chain, the CNAME that
leads to it included, not the stray record's.
*/
@(test)
test_a_bootstrap_answer_is_read_the_same_whatever_its_order :: proc(t: ^testing.T) {
	m := Ttl_Mock {
		addr  = {127, 0, 0, 9},
		also  = {127, 0, 0, 7},
		ttl   = 3600,
		cname = 30,
		stray = {10, 0, 0, 1},
	}
	bound, responder, ok := serve_udp_mock(t, &m, ttl_mock_loop)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, responder)
	server := net.endpoint_to_string(bound, context.temp_allocator)
	// The last answer puts the CNAME after the records it leads to.
	for i in 0 ..< 3 {
		sync.mutex_lock(&m.mu)
		m.cname_last = i == 2
		sync.mutex_unlock(&m.mu)
		addr, held, _, err := bootstrap_query(server, "turning.invalid", .A, time.tick_add(time.tick_now(), time.Second))
		testing.expectf(t, err == .None && addr == net.Address(net.IP4_Address{127, 0, 0, 7}), "answer %d: got %v (%v)", i, addr, err)
		testing.expectf(t, held == 30 * time.Second, "answer %d: held %v, where the CNAME's TTL is 30s", i, held)
	}
	testing.expect_value(t, ttl_mock_asked(&m), 3)

	// A refresh that holds an address the answer still gives keeps it, lowest
	// or not; one the answer no longer gives is let go for the lowest.
	held_addr := net.Address(net.IP4_Address{127, 0, 0, 9})
	addr, _, _, err := bootstrap_query(server, "turning.invalid", .A, time.tick_add(time.tick_now(), time.Second), held_addr)
	testing.expectf(t, err == .None && addr == held_addr, "an address still in the answer was let go for %v (%v)", addr, err)
	gone := net.Address(net.IP4_Address{127, 0, 0, 8})
	addr, _, _, err = bootstrap_query(server, "turning.invalid", .A, time.tick_add(time.tick_now(), time.Second), gone)
	testing.expectf(t, err == .None && addr == net.Address(net.IP4_Address{127, 0, 0, 7}), "an address gone from the answer was kept: %v (%v)", addr, err)
	free_all(context.temp_allocator)
}

/*
A refresh is held to `REFRESH_SHARE` of the exchange: with the bootstrap gone
quiet, the query still goes to the address held and is answered within its
timeout.
*/
@(test)
test_a_quiet_bootstrap_does_not_cost_a_query_its_answer :: proc(t: ^testing.T) {
	sync.mutex_lock(&bootstrap_cache_owner)
	defer sync.mutex_unlock(&bootstrap_cache_owner)
	defer bootstrap_destroy()

	// The member answers A for anything, which is all the query needs.
	member := Ttl_Mock {
		addr = {192, 0, 2, 1},
		ttl  = 60,
	}
	member_bound, member_thread, member_ok := serve_udp_mock(t, &member, ttl_mock_loop)
	if !member_ok {
		return
	}
	defer stop_udp_mock(&member, member_thread)
	boot := Ttl_Mock {
		addr = {127, 0, 0, 1},
		ttl  = 300,
	}
	boot_bound, boot_thread, boot_ok := serve_udp_mock(t, &boot, ttl_mock_loop)
	if !boot_ok {
		return
	}
	defer stop_udp_mock(&boot, boot_thread)

	HOST :: "quiet-bootstrap.invalid"
	TIMEOUT :: time.Second
	bootstrap := []string{net.endpoint_to_string(boot_bound, context.temp_allocator)}
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "quiet", kind = .UDP, address = HOST, port = member_bound.port, bootstrap = bootstrap},
		0,
		TIMEOUT,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)
	wire, _, eerr := dns.encode_message(
		dns.Message{id = 0x6913, question = []dns.Question{{name = "example.com.", type = .A, class = .IN}}},
		context.temp_allocator,
	)
	if !testing.expectf(t, eerr == .None, "cannot encode the query: %v", eerr) {
		return
	}

	ttl_mock_set(&boot, {127, 0, 0, 1}, silent = true)
	expire_address(u, HOST + ".")
	started := time.tick_now()
	response, err := exchange(u, wire, TIMEOUT, context.temp_allocator)
	took := time.tick_since(started)
	testing.expectf(t, err == .None && response != nil, "the query failed on a quiet bootstrap: %v", err)
	testing.expect(t, ttl_mock_asked(&boot) > 1, "the premise: the bootstrap was asked again")
	testing.expectf(t, took < TIMEOUT / 2, "the query took %v, where the refresh may spend %v", took, TIMEOUT / REFRESH_SHARE)
	free_all(context.temp_allocator)
}

// A query carrying an OPT record, with this upstream's cookie attached.
@(private = "file")
cookied_query :: proc(t: ^testing.T, u: ^Upstream) -> (query: []u8, ok: bool) {
	q := dns.Message {
		id       = 0x6914,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	q.additional = additional
	wire, _, eerr := dns.encode_message(q, context.temp_allocator)
	if !testing.expectf(t, eerr == .None, "cannot encode the query: %v", eerr) {
		return nil, false
	}
	attached, attach_ok, dry := attach_cookie(u, wire, context.temp_allocator)
	return attached, testing.expectf(t, attach_ok, "cannot attach the cookie (out of memory: %v)", dry)
}

// A reply to `query` echoing `client`, with a server cookie behind it.
@(private = "file")
cookied_reply :: proc(t: ^testing.T, query: []u8, client: [COOKIE_CLIENT_LEN]u8) -> (reply: []u8, ok: bool) {
	msg, derr := dns.decode_message(query, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "cannot decode the query: %v", derr) {
		return nil, false
	}
	wire, _, eerr := dns.encode_message(dns.make_response(msg, .No_Error, context.temp_allocator), context.temp_allocator)
	if !testing.expectf(t, eerr == .None, "cannot encode the reply: %v", eerr) {
		return nil, false
	}
	option: [16]u8
	echoed := client
	copy(option[:COOKIE_CLIENT_LEN], echoed[:])
	option[8], option[15] = 0x5e, 0x5e
	out, set_ok := dns.set_edns_option(wire, .Cookie, option[:], context.temp_allocator)
	return out, testing.expect(t, set_ok, "cannot set the reply's cookie")
}

/*
A move draws a fresh client cookie and forgets the server cookie while queries
sent with the old ones are still out. Their replies echo the old client cookie
and are taken (the cookie checked is the one the query carried), but the server
cookie they carry is the old address's and is not learned; and one that comes
back without a cookie is refused, as the server cookie the query carried owes
one.
*/
@(test)
test_replies_to_queries_from_before_a_move_keep_their_cookie :: proc(t: ^testing.T) {
	u, uerr := make_upstream(config.Upstream_Spec{name = "cookied", kind = .UDP, address = "127.0.0.1", port = 9}, 0, time.Second, cookies = true)
	if !testing.expectf(t, uerr == .None, "cannot build the member: %v", uerr) {
		return
	}
	defer destroy(u)
	sync.mutex_lock(&u.mu)
	u.cookie.server_len = copy(u.cookie.server[:], []u8{1, 2, 3, 4, 5, 6, 7, 8})
	old := u.cookie.client
	sync.mutex_unlock(&u.mu)
	query, qok := cookied_query(t, u)
	if !qok {
		return
	}
	// The move: the literal changes, which a refresh publishes.
	delete(u.spec.address, u.allocator)
	u.spec.address = strings.clone("127.0.0.2", u.allocator)
	testing.expect_value(t, resolve_endpoint(u, refresh = true, in_flight = time.Minute), Error.None)
	sync.mutex_lock(&u.mu)
	redrawn, forgot := u.cookie.client != old, u.cookie.server_len == 0
	sync.mutex_unlock(&u.mu)
	if !testing.expect(t, redrawn && forgot, "the premise: the move drew the cookies afresh") {
		return
	}
	bare, _, bare_err := dns.encode_message(dns.Message{id = 0x6914, flags = {qr = true}, question = []dns.Question{{name = "example.com.", type = .A, class = .IN}}}, context.temp_allocator)
	if testing.expectf(t, bare_err == .None, "cannot encode the reply: %v", bare_err) {
		testing.expect(t, !cookie_matches(u, query, bare), "a cookie-less reply to a query that carried a server cookie was taken")
		// A second move before any cookie is learned keeps that open.
		delete(u.spec.address, u.allocator)
		u.spec.address = strings.clone("127.0.0.3", u.allocator)
		testing.expect_value(t, resolve_endpoint(u, refresh = true, in_flight = time.Minute), Error.None)
		testing.expect(t, !cookie_matches(u, query, bare), "a second move let a cookie-less reply through")
		// Past the time any query from before the move could still wait, the
		// query is not walked for it any more.
		sync.mutex_lock(&u.mu)
		u.cookie.moved_until = loop.moment_add(loop.moment_now(), -time.Second)
		sync.mutex_unlock(&u.mu)
		testing.expect(t, cookie_matches(u, query, bare), "the window after a move did not close")
	}
	reply, rok := cookied_reply(t, query, old)
	if !rok {
		return
	}
	testing.expect(t, cookie_matches(u, query, reply), "the reply to a query sent before the move was refused")
	learn_cookie(u, reply)
	sync.mutex_lock(&u.mu)
	learned := u.cookie.server_len
	sync.mutex_unlock(&u.mu)
	testing.expect_value(t, learned, 0)

	// The premise for both: a reply echoing the cookie held now is learned.
	sync.mutex_lock(&u.mu)
	current := u.cookie.client
	sync.mutex_unlock(&u.mu)
	fresh, fok := cookied_reply(t, query, current)
	if !fok {
		return
	}
	learn_cookie(u, fresh)
	sync.mutex_lock(&u.mu)
	learned = u.cookie.server_len
	sync.mutex_unlock(&u.mu)
	testing.expect_value(t, learned, 8)
	free_all(context.temp_allocator)
}

/*
A refresh asks for the family of the address it holds first. A bootstrap that
fails to answer A (SERVFAIL) does not move an IPv4 member to IPv6; one that
answers that the name has no A any more (NOERROR, no address) does. A first
lookup goes on to AAAA either way.
*/
@(test)
test_a_refresh_keeps_to_the_family_it_holds :: proc(t: ^testing.T) {
	sync.mutex_lock(&bootstrap_cache_owner)
	defer sync.mutex_unlock(&bootstrap_cache_owner)
	defer bootstrap_destroy()

	m := Ttl_Mock {
		ttl   = 300,
		addr6 = {0 = 0x20, 1 = 0x01, 2 = 0x0d, 3 = 0xb8, 15 = 1},
		servfail_a = true,
	}
	bound, responder, ok := serve_udp_mock(t, &m, ttl_mock_loop)
	if !ok {
		return
	}
	defer stop_udp_mock(&m, responder)
	servers := []string{net.endpoint_to_string(bound, context.temp_allocator)}
	deadline := time.tick_add(time.tick_now(), time.Second)

	_, _, err := bootstrap_resolve(servers, "failing.invalid", deadline, net.IP4_Address{127, 0, 0, 1})
	testing.expect_value(t, err, Error.Not_Resolved)
	sync.mutex_lock(&m.mu)
	m.servfail_a, m.no_a = false, true
	sync.mutex_unlock(&m.mu)
	gone_addr, _, gone_err := bootstrap_resolve(servers, "gone.invalid", deadline, net.IP4_Address{127, 0, 0, 1})
	_, gone_v6 := gone_addr.(net.IP6_Address)
	testing.expectf(t, gone_err == .None && gone_v6, "a name with no A any more kept its refresh on A: %v (%v)", gone_addr, gone_err)
	addr, _, first_err := bootstrap_resolve(servers, "family.invalid", deadline)
	_, v6 := addr.(net.IP6_Address)
	testing.expectf(t, first_err == .None && v6, "a first lookup did not go on to AAAA: %v (%v)", addr, first_err)

	// An entry about to lapse is still held for the floor by whoever finds it.
	sync.mutex_lock(&bootstrap_cache.mu)
	if entry, found := &bootstrap_cache.entries["family.invalid."]; found {
		entry.expires = loop.moment_add(loop.moment_now(), time.Millisecond)
	}
	sync.mutex_unlock(&bootstrap_cache.mu)
	_, held, held_err := bootstrap_resolve(servers, "family.invalid", deadline)
	testing.expectf(t, held_err == .None && held >= BOOTSTRAP_MIN_TTL, "a cached address was held %v (%v)", held, held_err)
	free_all(context.temp_allocator)
}
