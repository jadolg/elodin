package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
An upstream named by hostname holds the address its bootstrap lookup gave for
the record's TTL (RFC 1035 section 3.2.1), raised to the floor elodin keeps,
and the bootstrap servers are asked again once it is past.
*/
run_bootstrap_cases :: proc(r: ^Runner) {
	GROUP :: "bootstrap"
	// `upstream.BOOTSTRAP_MIN_TTL`, which a TTL of one is raised to.
	FLOOR :: 10 * time.Second
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
	mock_reply(up, f.qname, f.qtype, from_hex(f.response, context.allocator))
	if !mock_start_or_skip(r, up, GROUP) {
		return
	}
	udp_port := next_port(r)
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
	started := time.tick_now()

	start_case(r, "bootstrap: an upstream's hostname is asked for again once its TTL is past")
	{
		res := query_udp(udp_port, build_query(f.qname, f.qtype))
		if check(r, res.ok, "no response") {
			check_eq_int(r, parse_header(r, res.wire).rcode, int(dns.Rcode.No_Error), "rcode")
		}
		check_eq_int(r, mock_total(boot), 1, "bootstrap lookups within the TTL")

		// Only an exchange looks again, so queries go on until it has, or
		// well past the floor.
		deadline := time.tick_add(started, FLOOR + 5 * time.Second)
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
