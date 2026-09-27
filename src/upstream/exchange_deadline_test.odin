package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
One `exchange` spends one timeout, whatever it has to do inside (issue #449).

The question's deadline, the group's budget and a follower's patience all allow
for one exchange crossing their line, and each is only as good as that exchange
being bounded. Three stages inside it started a timeout of their own: resolving
a hostname through the bootstrap servers, a truncated UDP reply's retry over
TCP, and a cookie retry after BADCOOKIE (in cookie_test.odin).
*/

@(private = "file")
X_TIMEOUT :: 200 * time.Millisecond

// Answers over UDP with TC set after `delay`, and over TCP - once - after
// `delay` again, so an exchange that gives the retry a timeout of its own gets
// its answer, and one that shares the timeout does not.
@(private = "file")
Truncating_Mock :: struct {
	udp:      net.UDP_Socket,
	listener: net.TCP_Socket,
	delay:    time.Duration,
	stop:     bool,
}

@(private = "file")
truncating_udp_loop :: proc(m: ^Truncating_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.udp, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		time.sleep(m.delay)
		buf[2] |= 0x80 | 0x02 // QR, TC
		_, _ = net.send_udp(m.udp, buf[:n], client)
	}
}

@(private = "file")
truncating_tcp_once :: proc(m: ^Truncating_Mock) {
	client, _, err := net.accept_tcp(m.listener)
	if err != nil {
		return
	}
	defer net.close(client)
	length: [2]u8
	if read_full_tcp(client, length[:]) != .None {
		return
	}
	n := int(length[0]) << 8 | int(length[1])
	query: [512]u8
	if n < dns.HEADER_SIZE || n > len(query) || read_full_tcp(client, query[:n]) != .None {
		return
	}
	time.sleep(m.delay)
	out: [2 + 512]u8
	out[0], out[1] = length[0], length[1]
	copy(out[2:], query[:n])
	out[4] |= 0x80 // QR
	_ = write_all_tcp(client, out[:2 + n])
}

@(test)
test_a_truncated_replys_tcp_retry_shares_the_exchange_timeout :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	bound, _ := net.bound_endpoint(listener)
	_ = net.set_option(listener, .Receive_Timeout, 10 * X_TIMEOUT)
	udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, bound.port)
	if !testing.expectf(t, uerr == nil, "cannot bind udp/%d: %v", bound.port, uerr) {
		net.close(listener)
		return
	}
	set_socket_timeouts(udp, 50 * time.Millisecond)
	m := Truncating_Mock {
		udp      = udp,
		listener = listener,
		delay    = X_TIMEOUT * 7 / 10,
	}
	udp_thread := thread.create_and_start_with_poly_data(&m, truncating_udp_loop)
	tcp_thread := thread.create_and_start_with_poly_data(&m, truncating_tcp_once)
	u, berr := make_upstream(
		config.Upstream_Spec{name = "truncating", kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		X_TIMEOUT,
		context.allocator,
	)
	defer {
		if u != nil {
			destroy(u)
		}
		sync.atomic_store(&m.stop, true)
		// Wakes the accept if the retry never came.
		net.close(listener)
		thread.join(udp_thread)
		thread.destroy(udp_thread)
		thread.join(tcp_thread)
		thread.destroy(tcp_thread)
		net.close(udp)
	}
	if !testing.expectf(t, berr == .None, "cannot build the upstream: %v", berr) {
		return
	}

	query := dns.Message {
		id         = 0x4490,
		question   = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
		additional = []dns.Record{dns.make_opt(1232, false)},
	}
	query.flags.rd = true
	wire, _, _ := dns.encode_message(query, context.temp_allocator)
	started := time.tick_now()
	resp, xerr := exchange(u, wire, X_TIMEOUT, context.temp_allocator)
	spent := time.tick_since(started)

	// The TC arrived at 0.7 of the timeout, leaving 0.3 for a retry the server
	// answers after 0.7: a retry on its own clock answered at 1.4.
	testing.expectf(t, xerr != .None, "the retry was answered on a timeout of its own (%d bytes)", len(resp))
	testing.expectf(t, spent < X_TIMEOUT * 5 / 4, "the exchange waited %v, where its timeout is %v", spent, X_TIMEOUT)
	// And the connection the retry dialled keeps the upstream's own timeout,
	// not the sliver this exchange had left: it is every later query's too.
	sync.mutex_lock(&u.mu)
	c := u.pipe
	kept := c.timeout if c != nil else 0
	sync.mutex_unlock(&u.mu)
	testing.expectf(t, c == nil || kept == X_TIMEOUT, "the retry's connection was dialled with %v, where the upstream's timeout is %v", kept, X_TIMEOUT)
	free_all(context.temp_allocator)
}

@(test)
test_bootstrap_resolution_shares_the_exchange_timeout :: proc(t: ^testing.T) {
	// Bound and never read: queries queue in the kernel and nothing answers.
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the bootstrap mock: %v", serr) {
		return
	}
	defer net.close(socket)
	bound, _ := net.bound_endpoint(socket)

	// Built with no bootstrap servers, so construction fails to resolve at once
	// rather than waiting out the silent one; it is handed over afterwards, the
	// state of a hostname upstream that did not resolve at startup.
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "hostname", kind = .UDP, address = "dns.example.test", port = 53},
		0,
		X_TIMEOUT,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "cannot build the upstream: %v", uerr) {
		return
	}
	defer destroy(u)
	testing.expect(t, !u.resolved, "a hostname resolved with no bootstrap servers")
	bootstrap := []string{net.endpoint_to_string(bound, context.temp_allocator)}
	u.spec.bootstrap = bootstrap

	query := dns.Message{id = 0x4491, question = []dns.Question{{name = "example.com.", type = .A, class = .IN}}}
	wire, _, _ := dns.encode_message(query, context.temp_allocator)
	started := time.tick_now()
	_, xerr := exchange(u, wire, X_TIMEOUT, context.temp_allocator)
	spent := time.tick_since(started)

	testing.expect_value(t, xerr, Error.Not_Resolved)
	// Each bootstrap query had `BOOTSTRAP_TIMEOUT` of its own - three seconds,
	// for A and again for AAAA - before the exchange's timeout even began.
	testing.expectf(t, spent < X_TIMEOUT * 5 / 4, "the exchange waited %v, where its timeout is %v", spent, X_TIMEOUT)
	u.spec.bootstrap = nil
	free_all(context.temp_allocator)
}

/*
Sharing the exchange's timeout must not cost the rest of the bootstrap list: a
dead first server given all that is left - three seconds for A out of the
default five, and the rest for AAAA - leaves the second unasked, and a hostname
that did not resolve at startup then never resolves while the first is down.
Nothing answers here, so nothing reaches the package-global cache that other
tests read; what is checked is that the second server was asked at all.
*/
@(test)
test_a_dead_bootstrap_server_leaves_time_for_the_next :: proc(t: ^testing.T) {
	first, ferr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, ferr == nil, "cannot bind the first bootstrap mock: %v", ferr) {
		return
	}
	defer net.close(first)
	second, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the second bootstrap mock: %v", serr) {
		return
	}
	defer net.close(second)
	a, _ := net.bound_endpoint(first)
	b, _ := net.bound_endpoint(second)
	servers := []string {
		net.endpoint_to_string(a, context.temp_allocator),
		net.endpoint_to_string(b, context.temp_allocator),
	}

	_, ok := bootstrap_resolve(servers, "failover.example.test", time.tick_add(time.tick_now(), X_TIMEOUT))
	testing.expect(t, !ok, "resolved with nothing answering")

	set_socket_timeouts(second, 10 * time.Millisecond)
	buf: [512]u8
	n, _, _ := net.recv_udp(second, buf[:])
	testing.expect(t, n > 0, "the second bootstrap server was never asked")
	free_all(context.temp_allocator)
}
