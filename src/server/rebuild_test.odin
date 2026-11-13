package server

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:filter"

@(private = "file")
on_test_signal :: proc "c" (sig: posix.Signal) {}

@(test)
test_a_rebuild_does_not_take_the_signals_main_acts_on :: proc(t: ^testing.T) {
	/*
	A signal the kernel hands to the thread a download waits on ends the wait
	with EINTR, and the download with it, as a failed one (#416). The rebuild's
	thread holds the signals `main` acts on, so one sent to that very thread
	stays pending and the download goes on.

	The list host accepts and reads the request and answers nothing. SIGHUP gets
	a handler for the test, without SA_RESTART as `main` installs it, so a
	signal the thread took would interrupt the read rather than end the process.
	*/
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	// Closed before the rebuild is waited for, rather than deferred: a connection
	// still in its backlog is then reset, which ends a download it holds.
	listener_open := true
	defer if listener_open {
		net.close(listener)
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the listener's port: %v", berr) {
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 5 * time.Second)

	// Process-wide, and the suite runs in parallel: harmless while no other test
	// sends SIGHUP, and put back as this one ends.
	act, old_act: posix.sigaction_t
	act.sa_handler = on_test_signal
	posix.sigaction(.SIGHUP, &act, &old_act)
	defer posix.sigaction(.SIGHUP, &old_act, nil)

	cfg := config.default_config()
	cfg.blocking.enabled = true
	cfg.blocking.cache_dir = "/nonexistent/elodin-rebuild-test"
	url := fmt.tprintf("http://127.0.0.1:%d/l.txt", bound.port)
	cfg.blocking.lists = []config.Block_List{{name = "l", url = url, format = .Adblock, enabled = true}}
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	s := Server {
		cfg     = &cfg,
		filters = engine,
	}
	defer delete(s.lists_loaded)

	r: Rebuild
	if !testing.expect(t, rebuild_start(&r, &s, true), "the rebuild did not get a thread of its own") {
		return
	}
	client, _, aerr := net.accept_tcp(listener)
	waiting := testing.expectf(t, aerr == nil, "the rebuild did not connect: %v", aerr)
	if waiting {
		// The whole request, so the download is past its write and reading.
		request: [dynamic]u8
		defer delete(request)
		buf: [512]u8
		for !strings.contains(string(request[:]), "\r\n\r\n") {
			n, rerr := net.recv_tcp(client, buf[:])
			if rerr != nil || n == 0 {
				break
			}
			append(&request, ..buf[:n])
		}
		time.sleep(50 * time.Millisecond)

		testing.expect_value(t, posix.pthread_kill(r.thread.unix_thread, .SIGHUP), posix.Errno.NONE)
		// Interrupted, the download fails and the rebuild is over at once.
		time.sleep(300 * time.Millisecond)
		testing.expect(t, !rebuild_done(&r), "the signal cut the download short")
		net.close(client)
	}

	// The host gone, the download fails and the rebuild is over.
	net.close(listener)
	listener_open = false
	deadline := time.tick_add(time.tick_now(), 10 * time.Second)
	for !rebuild_done(&r) && time.tick_diff(time.tick_now(), deadline) > 0 {
		time.sleep(10 * time.Millisecond)
	}
	testing.expect(t, rebuild_done(&r), "the rebuild did not end once its host was gone")
	// Its thread reads `s` and the engine, which are this frame's: it is
	// waited for even past the deadline, as `FETCH_DEADLINE` bounds it.
	for !rebuild_done(&r) {
		time.sleep(10 * time.Millisecond)
	}
	current, over := rebuild_collect(&r)
	testing.expect(t, over, "a rebuild that is over was not collected")
	testing.expect(t, !current, "a rebuild whose download failed was current")
	testing.expect(t, !rebuild_busy(&r), "a collected rebuild is still busy")
}
