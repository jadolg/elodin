package server

import "core:testing"
import "core:thread"
import "elodin:config"
import "elodin:loop"

/*
One event loop on a thread of its own, for a test that drives the server from
the test's thread and needs somewhere for detached work to run - a refresh, a
query a reader admitted, an HTTP/2 request.

`stop_test_loop` returns once every fiber on the loop has finished, which is the
join a test needs before it tears down what those fibers were using.
*/
Test_Loop :: struct {
	loops:  [1]^loop.Loop,
	thread: ^thread.Thread,
}

start_test_loop :: proc(tl: ^Test_Loop) -> bool {
	l, ok := loop.make_loop()
	if !ok {
		return false
	}
	tl.loops[0] = l
	tl.thread = loop.spawn_thread(l, loop.run, context)
	if tl.thread == nil {
		loop.destroy(l)
		tl.loops[0] = nil
		return false
	}
	return true
}

stop_test_loop :: proc(tl: ^Test_Loop) {
	if tl.loops[0] == nil {
		return
	}
	loop.stop(tl.loops[0])
	thread.join(tl.thread)
	thread.destroy(tl.thread)
	loop.destroy(tl.loops[0])
	tl^ = {}
}

/*
A server on `cfg` with one test loop and its listeners started, which is what a
case about the listeners needs from the server. False, with nothing left running,
when the loop or the listeners would not start.
*/
@(private)
start_test_listeners :: proc(
	t: ^testing.T,
	s: ^Server,
	l: ^Listeners,
	tl: ^Test_Loop,
	cfg: ^config.Config,
	loc := #caller_location,
) -> bool {
	if !testing.expect(t, start_test_loop(tl), "no loop", loc = loc) {
		return false
	}
	s^ = Server {
		cfg   = cfg,
		loops = tl.loops[:],
	}
	if !start_listeners(s, l) {
		// `start_listeners` builds the connection manager before it binds
		// anything, and `stop_listeners` is what gives it back.
		stop_test_listeners(l, tl)
		testing.expect(t, false, "could not start the listeners", loc = loc)
		return false
	}
	return true
}

@(private)
stop_test_listeners :: proc(l: ^Listeners, tl: ^Test_Loop) {
	stop_listeners(l)
	stop_test_loop(tl)
	destroy_listeners(l)
}

/*
The default configuration with only a UDP listener, on loopback and an ephemeral
port so a case never collides with a real server, and `readers` readers; nothing
behind it to answer from.
*/
@(private)
udp_listener_config :: proc(readers: int) -> config.Config {
	cfg := config.default_config()
	cfg.listeners.udp = config.Listener {
		enabled        = true,
		address        = "127.0.0.1",
		port           = 0,
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
	return cfg
}

// The same with only a TCP listener, and the default connection limits.
@(private)
tcp_listener_config :: proc() -> config.Config {
	cfg := config.default_config()
	cfg.listeners.udp.enabled = false
	cfg.listeners.tcp = config.Listener {
		enabled = true,
		address = "127.0.0.1",
		port    = 0,
	}
	cfg.listeners.dot.enabled = false
	cfg.listeners.doh.enabled = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.log.queries = false
	return cfg
}
