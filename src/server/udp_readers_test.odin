package server

import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"
import "elodin:pool"

/*
Several readers, one port.

The whole of what `SO_REUSEPORT` buys this server: every reader has a socket, a
receive queue and a thread of its own, so the rate at which datagrams can be
taken off the wire scales with cores instead of being one of them. Before this
the port was held by a single socket, and a second bind of it - which is what a
second reader is - was refused with `Address_In_Use`.
*/

@(private = "file")
READERS :: 4

// Datagrams sent, from a source port each. Enough that the kernel's 4-tuple
// hash landing all of them on one reader is not something that happens: it is
// `READERS * (1 - 1/READERS)^SOURCES`, which is about one run in twenty
// million here.
@(private = "file")
SOURCES :: 64

@(private = "file")
fixture :: proc(cfg: ^config.Config, readers: int) {
	cfg^ = config.default_config()
	cfg.listeners.udp = config.Listener {
		enabled        = true,
		address        = "127.0.0.1",
		port           = 0, // ephemeral, so the test never collides with a real server
		readers        = readers,
		receive_buffer = config.DEFAULT_UDP_RECEIVE_BUFFER,
	}
	cfg.listeners.tcp.enabled = false
	cfg.listeners.dot.enabled = false
	cfg.listeners.doh.enabled = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.log.queries = false
	cfg.server.max_connections = 8
	cfg.server.max_pending = 0
}

@(private = "file")
Received_Probe :: struct {
	listeners: ^Listeners,
	want:      u64,
}

@(private = "file")
received_reached :: proc(data: rawptr) -> bool {
	p := cast(^Received_Probe)data
	total: u64
	for &reader in p.listeners.udp {
		total += sync.atomic_load(&reader.received)
	}
	return total >= p.want
}

@(private = "file")
wait_for :: proc(predicate: proc(data: rawptr) -> bool, data: rawptr, within: time.Duration) -> bool {
	deadline := time.time_add(time.now(), within)
	for time.diff(time.now(), deadline) > 0 {
		if predicate(data) {
			return true
		}
		time.sleep(time.Millisecond)
	}
	return predicate(data)
}

/*
Each reader binds the port, and none of them is a client connection.

The port is asserted rather than assumed because the sockets after the first
bind what the first *got*: with `port: 0` the file's number is not a port at
all, and asking the kernel for another ephemeral one per reader would quietly
produce one listener per reader on ports nobody can find.

The connection table is asserted because the readers are threads in the same
manager that bounds client connections, and a reader that counted against
`server.max_connections` would take a slot from a client for every core the
machine has.
*/
@(test)
test_every_reader_binds_the_same_port :: proc(t: ^testing.T) {
	cfg: config.Config
	fixture(&cfg, READERS)
	handler_pool := pool.make_pool(2)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		pool.destroy(handler_pool)
		testing.expect(t, false, "could not start the UDP listener")
		return
	}
	defer {
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
	}

	if !testing.expect_value(t, len(l.udp), READERS) {
		return
	}
	for reader, i in l.udp {
		bound, berr := net.bound_endpoint(reader.socket)
		if !testing.expectf(t, berr == nil, "reader %d: cannot read the bound port: %v", i, berr) {
			continue
		}
		testing.expectf(
			t,
			bound.port == l.udp_bound.port,
			"reader %d bound port %d rather than %d, so it is a listener of its own",
			i,
			bound.port,
			l.udp_bound.port,
		)
		// Distinct sockets: the point of the exercise is a receive queue each.
		if i > 0 {
			testing.expectf(t, reader.socket != l.udp[0].socket, "reader %d shares reader 0's socket", i)
		}
		testing.expectf(t, reader.ctx != nil, "reader %d was given no context", i)
		// Not on Darwin, where there is no /proc to read it from; this suite
		// runs on Linux, where a socket this process holds always has one.
		when ODIN_OS == .Linux {
			testing.expectf(t, reader.inode != 0, "reader %d has no inode, so its drops cannot be counted", i)
		}
	}

	testing.expect_value(t, active_connections(&l.conns), 0)
}

/*
The kernel spreads datagrams over the readers, and every one of them answers.

Two properties in one exchange, because they are the same exchange. That more
than one reader received says the sockets really are sharing the port - a single
socket answering everything is exactly what this looked like before - and that
every query is answered says each reader's own socket is what its answers go
back out of.

A bare header with no question is enough: it is answered FORMERR without
reaching the cache, the filters or an upstream, none of which are wired up here.
*/
@(test)
test_the_kernel_spreads_datagrams_over_the_readers :: proc(t: ^testing.T) {
	cfg: config.Config
	fixture(&cfg, READERS)
	handler_pool := pool.make_pool(4)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		pool.destroy(handler_pool)
		testing.expect(t, false, "could not start the UDP listener")
		return
	}
	defer {
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
	}

	bound := l.udp_bound
	clients: [SOURCES]net.UDP_Socket
	opened := 0
	defer for i in 0 ..< opened {
		net.close(clients[i])
	}
	for i in 0 ..< SOURCES {
		// Bound rather than unbound, so each client has a source port of its
		// own: the kernel picks a reader by hashing the 4-tuple, and datagrams
		// sharing a source port are one client as far as that hash is concerned.
		socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if err != nil {
			testing.expectf(t, false, "cannot open client socket %d: %v", i, err)
			return
		}
		clients[i] = socket
		opened += 1
		_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	}

	query: [dns.HEADER_SIZE]u8
	for i in 0 ..< opened {
		_, err := net.send_udp(clients[i], query[:], bound)
		testing.expectf(t, err == nil, "cannot send from client %d: %v", i, err)
	}

	probe := Received_Probe {
		listeners = &l,
		want      = u64(opened),
	}
	if !testing.expect(t, wait_for(received_reached, &probe, 5 * time.Second), "not every datagram was read") {
		return
	}

	busy := 0
	for &reader in l.udp {
		if sync.atomic_load(&reader.received) > 0 {
			busy += 1
		}
	}
	testing.expectf(
		t,
		busy >= 2,
		"%d of %d readers received anything: the port is not being shared",
		busy,
		len(l.udp),
	)

	answered := 0
	reply: [512]u8
	for i in 0 ..< opened {
		n, _, err := net.recv_udp(clients[i], reply[:])
		if err == nil && n >= dns.HEADER_SIZE {
			answered += 1
		}
	}
	testing.expectf(t, answered == opened, "%d of %d queries were answered", answered, opened)
}

/*
One reader is still a whole listener.

The configuration every installation had before this setting existed, and the
one a single-core machine derives. Worth its own case because the code that
binds the second socket is the code that binds the first, and a listener that
worked only in a plural is one nobody would notice was broken until they set
`readers: 1`.
*/
@(test)
test_one_reader_is_a_whole_listener :: proc(t: ^testing.T) {
	cfg: config.Config
	fixture(&cfg, 1)
	handler_pool := pool.make_pool(2)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		pool.destroy(handler_pool)
		testing.expect(t, false, "could not start the UDP listener")
		return
	}
	defer {
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
	}

	if !testing.expect_value(t, len(l.udp), 1) {
		return
	}

	client, cerr := net.make_unbound_udp_socket(.IP4)
	if cerr != nil {
		testing.expectf(t, false, "cannot open a client socket: %v", cerr)
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 2 * time.Second)

	query: [dns.HEADER_SIZE]u8
	_, serr := net.send_udp(client, query[:], l.udp_bound)
	testing.expectf(t, serr == nil, "cannot send the query: %v", serr)

	reply: [512]u8
	n, _, rerr := net.recv_udp(client, reply[:])
	testing.expectf(t, rerr == nil, "the lone reader did not answer: %v", rerr)
	testing.expect(t, n >= dns.HEADER_SIZE, "the answer is not a DNS message")
	testing.expect_value(t, sync.atomic_load(&l.udp[0].received), u64(1))
}

/*
What the startup line says, in the three cases it has to tell apart.

The granted figure is the one an operator needs and the one nothing else
reports: Linux clamps the request to `net.core.rmem_max` without saying so, so a
line that repeated the request would describe a burst tolerance the server does
not have. `--check` has bound nothing and passes 0, where the line must not
claim anything was granted at all.
*/
@(test)
test_the_startup_line_says_what_was_granted :: proc(t: ^testing.T) {
	Case :: struct {
		readers, asked, granted: int,
		wants:                   []string,
		what:                    string,
	}
	CASES := []Case {
		{4, 1 << 20, 1 << 20, []string{"4 readers", "1MiB"}, "granted what it asked for"},
		{4, 1 << 20, 208 * 1024, []string{"4 readers", "208KiB", "1MiB", "rmem_max"}, "clamped by the sysctl"},
		{2, 1 << 20, 0, []string{"2 readers", "asking for", "1MiB"}, "nothing bound yet"},
		{1, 1 << 20, 1 << 20, []string{"1 reader,"}, "the lone reader is not a plural"},
	}
	for c in CASES {
		line := udp_readers_line(c.readers, c.asked, c.granted)
		for want in c.wants {
			testing.expectf(t, strings.contains(line, want), "%s: %q does not mention %q", c.what, line, want)
		}
	}
	// The clamped case is the one that has to name both figures; the granted
	// case must not claim a request was refused when it was not.
	testing.expect(
		t,
		!strings.contains(udp_readers_line(4, 1 << 20, 1 << 20), "rmem_max"),
		"a request that was granted was reported as clamped",
	)
	free_all(context.temp_allocator)
}

/*
A port somebody else already holds is still refused.

`SO_REUSEPORT` is what lets the readers share a port with each other, and left
to itself it would let a second elodin share one with them: same effective uid,
same address, and the kernel takes the newcomer into the group and gives it a
quarter of the datagrams. A stale process or a unit started twice would then be
answering production queries from whatever configuration it was handed, with
nothing said anywhere. Before the readers existed that second start was refused,
and this is the case that says it still is.

Asked of a listener that is running rather than of a bare socket, because the
first half of the claim matters as much as the second: the readers have to be
able to share the port with each other while nobody else can join them.
*/
@(test)
test_a_port_already_held_is_refused :: proc(t: ^testing.T) {
	// A port the kernel says is free, given up again before it is asked for by
	// name. `port: 0` is the one case the check cannot apply to - there is no
	// port to ask about until a reader has one - so this test needs a number.
	probe, perr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if perr != nil {
		testing.expectf(t, false, "cannot find a free port: %v", perr)
		return
	}
	bound, berr := net.bound_endpoint(probe)
	net.close(probe)
	if berr != nil {
		testing.expectf(t, false, "cannot read the free port: %v", berr)
		return
	}

	cfg: config.Config
	fixture(&cfg, READERS)
	cfg.listeners.udp.port = bound.port
	handler_pool := pool.make_pool(2)
	s := Server {
		cfg          = &cfg,
		handler_pool = handler_pool,
	}

	l: Listeners
	if !start_listeners(&s, &l) {
		// The port was taken between the probe and here, which is nobody's bug.
		pool.destroy(handler_pool)
		logx.infof("the free port %d was taken before the listener could bind it", bound.port)
		return
	}
	defer {
		stop_listeners(&l)
		pool.destroy(handler_pool)
		destroy_listeners(&l)
	}
	testing.expect_value(t, len(l.udp), READERS)

	// The second server is the one this is about: a whole listener of its own,
	// asking for a port the first one is holding.
	second_cfg: config.Config
	fixture(&second_cfg, READERS)
	second_cfg.listeners.udp.port = bound.port
	second_pool := pool.make_pool(2)
	second := Server {
		cfg          = &second_cfg,
		handler_pool = second_pool,
	}
	second_l: Listeners
	started := start_listeners(&second, &second_l)
	// Whether or not it got anywhere: `start_listeners` builds the connection
	// manager before it binds anything, and `stop_listeners` is what gives it
	// back.
	stop_listeners(&second_l)
	pool.destroy(second_pool)
	destroy_listeners(&second_l)
	testing.expect(t, !started, "a second listener joined the running one's port and took a share of its datagrams")
}
