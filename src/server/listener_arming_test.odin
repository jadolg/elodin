package server

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
Bound listeners read nothing until `arm_listeners` (#681): no reader, accept
loop or metrics thread runs, while the kernel queues what arrives. Once armed,
the datagram and the connection that waited are served.
*/
@(test)
test_a_bound_listener_reads_nothing_until_armed :: proc(t: ^testing.T) {
	READERS :: 2
	cfg := arming_config(READERS)

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

	// A header and no question, answered FORMERR without a lookup.
	query: [dns.HEADER_SIZE]u8
	query[1] = 0x42
	client, sent := send_to_listener(t, &l, query[:])
	if !sent {
		return
	}
	defer net.close(client)
	stream, dialled := dial_listener(t, &l)
	if !dialled {
		return
	}
	defer net.close(stream)

	// The premise: the datagram is waiting in a reader's socket. The kernel
	// picks the socket, so any of them.
	if !testing.expect(t, wait_until(queued_in_a_reader, &l, 5 * time.Second), "the datagram is not waiting in a reader's socket: read before arming") {
		return
	}

	if !testing.expect(t, arm_listeners(&s, &l), "could not arm the listeners") {
		return
	}
	testing.expect_value(t, sync.atomic_load(&l.conns.permanent), READERS + 1)
	testing.expect(t, l.metrics_thread != nil, "the metrics endpoint is not served once armed")

	expect_answered(t, client, query[:])
	testing.expect(t, wait_until(accepted_one, &l, 5 * time.Second), "the queued connection was not accepted once armed")
}

// A UDP listener with `readers` readers, a TCP listener and the metrics
// endpoint, all on loopback ports of the kernel's choosing.
@(private = "file")
arming_config :: proc(readers: int) -> config.Config {
	cfg := udp_listener_config(readers)
	cfg.server.max_pending = 8
	cfg.listeners.tcp = {
		enabled = true,
		address = "127.0.0.1",
		port    = 0,
	}
	cfg.metrics.enabled = true
	cfg.metrics.address = "127.0.0.1"
	cfg.metrics.port = 0
	return cfg
}

// A UDP client, reading for up to five seconds, that has sent `query` to `l`'s
// UDP listener. On false there is nothing to close.
@(private = "file")
send_to_listener :: proc(t: ^testing.T, l: ^Listeners, query: []u8) -> (client: net.UDP_Socket, ok: bool) {
	c, cerr := net.make_unbound_udp_socket(.IP4)
	if !testing.expectf(t, cerr == nil, "no client socket: %v", cerr) {
		return {}, false
	}
	if err := net.set_option(c, .Receive_Timeout, 5 * time.Second); !testing.expectf(t, err == nil, "cannot set a receive timeout: %v", err) {
		net.close(c)
		return {}, false
	}
	if _, err := net.send_udp(c, query, l.udp_bound); !testing.expectf(t, err == nil, "cannot send: %v", err) {
		net.close(c)
		return {}, false
	}
	return c, true
}

// A connection to `l`'s TCP listener. On false there is nothing to close.
@(private = "file")
dial_listener :: proc(t: ^testing.T, l: ^Listeners) -> (stream: net.TCP_Socket, ok: bool) {
	tcp_at, berr := net.bound_endpoint(l.tcp_socket)
	if !testing.expectf(t, berr == nil, "cannot read the TCP port: %v", berr) {
		return {}, false
	}
	dialled, derr := net.dial_tcp(tcp_at)
	if !testing.expectf(t, derr == nil, "cannot connect before arming: %v", derr) {
		return {}, false
	}
	return dialled, true
}

// That `client` reads an answer to `query`, by its ID.
@(private = "file")
expect_answered :: proc(t: ^testing.T, client: net.UDP_Socket, query: []u8) {
	answer: [dns.MAX_UDP_SIZE]u8
	n, _, rerr := net.recv_udp(client, answer[:])
	if testing.expectf(t, rerr == nil && n >= dns.HEADER_SIZE, "the queued datagram was not answered once armed: n=%d %v", n, rerr) {
		testing.expect_value(t, answer[1], query[1])
	}
}

// Whether a datagram waits unread in any of the `^Listeners` readers' sockets.
@(private = "file")
queued_in_a_reader :: proc(data: rawptr) -> bool {
	for reader in (^Listeners)(data).udp {
		if unread_bytes(linux.Fd(reader.socket)) > 0 {
			return true
		}
	}
	return false
}

// Whether the `^Listeners` hold a connection beside their permanent loops.
@(private = "file")
accepted_one :: proc(data: rawptr) -> bool {
	cm := &(^Listeners)(data).conns
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)
	return len(cm.entries) > cm.permanent
}
