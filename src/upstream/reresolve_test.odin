package upstream

import "core:net"
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
		silent, addr, ttl, delay := m.silent, m.addr, m.ttl, m.delay
		sync.mutex_unlock(&m.mu)
		if silent {
			continue
		}
		if delay > 0 {
			time.sleep(delay) // lint:allow stands in for a slow bootstrap server; nothing is ordered on it
		}
		resp := dns.make_response(msg, .No_Error, context.temp_allocator)
		q := msg.question[0]
		if q.type == .A {
			answer := make([]dns.Record, 1, context.temp_allocator)
			answer[0] = dns.Record{name = q.name, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = addr}}
			resp.answer = answer
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
	ep, err := endpoint_of(u)
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

	// A lookup that finds the address moved lets go of the shared connection
	// to the old one; one that finds it where it was keeps it. Asked directly,
	// since an exchange would dial past the stand-in connection. One reference
	// is the test's, so the drop leaves it for the test to free.
	c := new(Pipe_Conn)
	defer free(c)
	c.refs = 2
	for moved in ([]bool{false, true}) {
		sync.mutex_lock(&u.mu)
		u.pipe = c
		sync.mutex_unlock(&u.mu)
		ttl_mock_set(&m, {127, 0, 0, 5} if moved else {127, 0, 0, 3})
		expire_address(u, HOST + ".")
		testing.expect_value(t, resolve_endpoint(u), Error.None)
		sync.mutex_lock(&u.mu)
		kept := u.pipe == c
		u.pipe = nil
		sync.mutex_unlock(&u.mu)
		testing.expectf(t, kept != moved, "moved %v: the connection was kept %v", moved, kept)
	}
	testing.expect_value(t, sync.atomic_load(&c.refs), 1)
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
