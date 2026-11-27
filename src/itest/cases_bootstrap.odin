package itest

import "core:fmt"
import "core:time"
import "elodin:dns"
import "elodin:testkit"
import "elodin:upstream"

/*
An upstream named by hostname holds the address its bootstrap lookup gave for
the record's TTL (RFC 1035 section 3.2.1), raised to the floor elodin keeps,
and the bootstrap servers are asked again once it is past.
*/
run_bootstrap_cases :: proc(r: ^Runner) {
	GROUP :: "bootstrap"
	// What a TTL of one is raised to.
	FLOOR :: upstream.BOOTSTRAP_MIN_TTL
	f := fixture("a")

	boot_port := next_port(r)
	boot := mock_make("bootstrap", boot_port)
	defer mock_stop(boot)
	mock_synth_all(boot, {127, 0, 0, 1}, ttl = 1)
	if !mock_start_or_skip(r, boot, GROUP) {
		return
	}
	up_port := next_port(r)
	up := mock_make("named-upstream", up_port)
	defer mock_stop(up)
	mock_reply(up, f.qname, f.qtype, testkit.unhex(f.response, context.allocator))
	if !mock_start_or_skip(r, up, GROUP) {
		return
	}
	udp_port := next_port(r)
	// Before the server starts, which is where its first lookup is.
	started := time.tick_now()
	srv, ok := start_server(
		r,
		Server_Options {
			config = base_config(
				udp_port,
				fmt.tprintf(`[{{ name: named, type: udp, address: "up.bootstrap.test", port: %d }}]`, up_port),
				upstream_extra = fmt.tprintf(`  bootstrap: ["127.0.0.1:%d"]`, boot_port),
			),
			udp_port = udp_port,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)
	// The poll's deadline from here, so a slow start does not eat its margin.
	ready := time.tick_now()

	start_case(r, "bootstrap: an upstream's hostname is asked for again once its TTL is past")
	{
		res := query_udp(udp_port, build_query(f.qname, f.qtype))
		if check(r, res.ok, "no response") {
			check_eq_int(r, parse_header(r, res.wire).rcode, int(dns.Rcode.No_Error), "rcode")
		}
		check_eq_int(r, mock_total(boot), 1, "bootstrap lookups within the TTL")

		// Only an exchange looks again, so queries go on until it has, or
		// well past the floor.
		deadline := time.tick_add(ready, FLOOR + 5 * time.Second)
		asked_at: time.Duration
		for time.tick_diff(time.tick_now(), deadline) > 0 {
			res = query_udp(udp_port, build_query(f.qname, f.qtype, id = 0x6912))
			if mock_total(boot) >= 2 {
				asked_at = time.tick_since(started)
				break
			}
			time.sleep(250 * time.Millisecond) // lint:allow the poll's interval; the deadline above bounds it
		}
		if check(r, asked_at > 0, "the bootstrap was not asked again within %v of a TTL of 1s", FLOOR + 5 * time.Second) {
			check(r, asked_at >= FLOOR - time.Second, "asked again after %v, before the %v floor", asked_at, FLOOR)
			if check(r, res.ok, "no response to the query that asked again") {
				check_eq_int(r, parse_header(r, res.wire).rcode, int(dns.Rcode.No_Error), "rcode after the refresh")
			}
		}
	}
	end_case(r)
}

/*
A stop during the startup lookups of the upstreams' hostnames ends the process
at once, before anything is read from the listeners, rather than once every
lookup has timed out in turn: three hostnames against a bootstrap server that
never answers hold a start for `upstream.BOOTSTRAP_TIMEOUT` each, and more. The
thread they run on, like every other, leaves the signal to the main thread
(`threads_taking_signals`).
*/
run_bootstrap_stop_case :: proc(r: ^Runner) {
	NAME :: "bootstrap: SIGTERM is not held by the startup lookups"
	boot := mock_make("silent-bootstrap", next_port(r))
	defer mock_stop(boot)
	mock_silent(boot)
	if !mock_start_or_skip(r, boot, NAME) {
		return
	}
	start_case(r, NAME)
	defer end_case(r)
	udp_port := next_port(r)
	servers := `[{ name: a, type: udp, address: "a.stop.test", port: 53 }, { name: b, type: udp, address: "b.stop.test", port: 53 }, { name: c, type: udp, address: "c.stop.test", port: 53 }]`
	config := base_config(udp_port, servers, log = "{ level: info }", upstream_extra = fmt.tprintf(`  bootstrap: ["127.0.0.1:%d"]`, boot.port))
	srv, ok := start_server_raw(r, config, udp_port)
	if !ok {
		return
	}
	defer stop_server(&srv)
	// The premise: the start is waiting on a lookup.
	if !check(r, mock_wait_until(boot, mock_saw_type, int(dns.Type.A), 5 * time.Second), "the bootstrap server was never asked") {
		return
	}
	main_takes, others, taking, read := threads_taking_signals(srv.process.pid)
	if check(r, read, "cannot read the server's thread masks") {
		check(r, main_takes, "the main thread blocks the signals, so no handler would run")
		check(r, others > 0, "the server runs no other thread to check")
		check(r, taking == 0, "%d of %d other threads would take the signals during the startup lookups", taking, others)
	}
	state, exited := signal_shutdown(&srv, 5 * time.Second)
	if check(r, exited, "the server did not exit within 5s of SIGTERM during the startup lookups") {
		check(r, state.success && state.exit_code == 0, "exited with code %d (success=%v)", state.exit_code, state.success)
		check(r, !log_contains(&srv, "msg=ready"), "the stop waited for the lookups to end")
	}
}
