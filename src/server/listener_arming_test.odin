package server

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Bound listeners read nothing until `arm_listeners` (#681): no reader, accept
loop or metrics thread runs, while the kernel queues what arrives. Once armed,
the datagram and the connection that waited are served.
*/
@(test)
test_a_bound_listener_reads_nothing_until_armed :: proc(t: ^testing.T) {
	READERS :: 2
	cfg := udp_listener_config(READERS)
	cfg.server.max_pending = 8
	cfg.listeners.tcp = {
		enabled = true,
		address = "127.0.0.1",
		port    = 0,
	}
	cfg.metrics.enabled = true
	cfg.metrics.address = "127.0.0.1"
	cfg.metrics.port = 0

	tl: Test_Loop
	if !testing.expect(t, start_test_loop(&tl), "no loop") {
		return
	}
	s := Server {
		cfg   = &cfg,
		loops = tl.loops[:],
	}
	l: Listeners
	started := start_listeners(&s, &l)
	defer {
		stop_listeners(&l)
		stop_metrics(&l)
		stop_test_loop(&tl)
		destroy_listeners(&l)
	}
	if !testing.expect(t, started, "could not bind the listeners") {
		return
	}
	sync.mutex_lock(&l.conns.mu)
	before := len(l.conns.entries)
	sync.mutex_unlock(&l.conns.mu)
	testing.expectf(t, before == 0, "%d read or accept loops run before arming", before)
	testing.expect(t, l.metrics_thread == nil, "the metrics endpoint is served before arming")

	client, cerr := net.make_unbound_udp_socket(.IP4)
	if !testing.expectf(t, cerr == nil, "no client socket: %v", cerr) {
		return
	}
	defer net.close(client)
	if err := net.set_option(client, .Receive_Timeout, 5 * time.Second); !testing.expectf(t, err == nil, "cannot set a receive timeout: %v", err) {
		return
	}
	// A header and no question, answered FORMERR without a lookup.
	query: [dns.HEADER_SIZE]u8
	query[1] = 0x42
	if _, err := net.send_udp(client, query[:], l.udp_bound); !testing.expectf(t, err == nil, "cannot send: %v", err) {
		return
	}
	tcp_at, berr := net.bound_endpoint(l.tcp_socket)
	if !testing.expectf(t, berr == nil, "cannot read the TCP port: %v", berr) {
		return
	}
	stream, derr := net.dial_tcp(tcp_at)
	if !testing.expectf(t, derr == nil, "cannot connect before arming: %v", derr) {
		return
	}
	defer net.close(stream)

	// The premise: the datagram is waiting in a reader's socket. The kernel
	// picks the socket, so any of them.
	Bound :: struct {
		l: ^Listeners,
	}
	bound := Bound{&l}
	queued := wait_until(proc(data: rawptr) -> bool {
			for reader in (^Bound)(data).l.udp {
				if unread_bytes(linux.Fd(reader.socket)) > 0 {
					return true
				}
			}
			return false
		}, &bound, 5 * time.Second)
	if !testing.expect(t, queued, "the datagram is not waiting in a reader's socket: read before arming") {
		return
	}

	if !testing.expect(t, arm_listeners(&s, &l), "could not arm the listeners") {
		return
	}
	testing.expect_value(t, sync.atomic_load(&l.conns.permanent), READERS + 1)
	testing.expect(t, l.metrics_thread != nil, "the metrics endpoint is not served once armed")

	answer: [dns.MAX_UDP_SIZE]u8
	n, _, rerr := net.recv_udp(client, answer[:])
	if testing.expectf(t, rerr == nil && n >= dns.HEADER_SIZE, "the queued datagram was not answered once armed: n=%d %v", n, rerr) {
		testing.expect_value(t, answer[1], query[1])
	}
	accepted := wait_until(proc(data: rawptr) -> bool {
			cm := &(^Bound)(data).l.conns
			sync.mutex_lock(&cm.mu)
			defer sync.mutex_unlock(&cm.mu)
			return len(cm.entries) > cm.permanent
		}, &bound, 5 * time.Second)
	testing.expect(t, accepted, "the queued connection was not accepted once armed")
}
