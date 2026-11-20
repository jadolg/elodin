package itest

import "core:fmt"
import "core:net"
import "elodin:dns"
import "elodin:netx"

/*
Issue #685: on a wildcard UDP bind, the answer leaves from the address the query
was sent to (RFC 1123 section 2.3, RFC 1122 section 4.1.3.5), not from whichever
local address the route picks. A client drops an answer from an address it did
not ask, so on a host with more than one address the query times out.

All of 127.0.0.0/8 is local on Linux, so `127.0.0.2` is a second local address
that needs no setup, and the route picks `127.0.0.1` as the source for a reply
to a loopback client. The client socket is unconnected, so an answer from the
wrong address is read and its source checked, rather than filtered out.

Both send sites: the answer, and the rate limiter's truncated slip.
*/

@(private = "file")
SECOND_LOOPBACK :: net.IP4_Address{127, 0, 0, 2}

run_udp_source_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("udp-source", upstream_port)
	mock_synth(mock, "source.test.", u16(dns.Type.A), {192, 0, 2, 1})
	if !mock_start_or_skip(r, mock, "udp: the answer leaves from the address asked") {
		return
	}
	defer mock_stop(mock)

	udp_source_answer_cases(r, upstream_port, "0.0.0.0")
	switch {
	case !dual_stack_available():
		skip_case(r, "udp: bound to :: or ::ffff:0.0.0.0, an answer comes from the address asked", "a `::` socket takes no IPv4 here")
	case !ipv6_loopback_available():
		skip_case(r, "udp: bound to :: or ::ffff:0.0.0.0, an answer comes from the address asked", "no IPv6 loopback on this machine")
	case:
		udp_source_answer_cases(r, upstream_port, "::")
		udp_source_answer_cases(r, upstream_port, "::ffff:0.0.0.0")
	}
	udp_source_slip_case(r, upstream_port)
}

@(private = "file")
udp_source_answer_cases :: proc(r: ^Runner, upstream_port: int, bind: string) {
	udp_port := next_port(r)
	config := config_rate_limit(udp_port, upstream_port, "enabled: false", udp_address = bind)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	asked := []net.Address{net.IP4_Loopback, SECOND_LOOPBACK}
	if bind == "::" {
		asked = []net.Address{net.IP4_Loopback, SECOND_LOOPBACK, net.IP6_Loopback}
	}
	for address in asked {
		start_case(r, fmt.tprintf("udp: bound to %s, an answer to %s comes from it", bind, net.address_to_string(address, context.temp_allocator)))
		res := query_udp(udp_port, build_query("source.test.", u16(dns.Type.A)), address = address)
		if check(r, res.ok, "no response") {
			check(
				r,
				netx.addresses_equal(netx.unmap(res.from.address), address) && res.from.port == udp_port,
				"answered from %v",
				res.from,
			)
		}
		end_case(r)
	}
}

@(private = "file")
udp_source_slip_case :: proc(r: ^Runner, upstream_port: int) {
	udp_port := next_port(r)
	// One answer a second and every query past it truncated, so the second
	// query of a burst is the slip.
	config := config_rate_limit(
		udp_port,
		upstream_port,
		"enabled: true, responses_per_second: 1, slip: 1",
		udp_address = "0.0.0.0",
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "udp: bound to 0.0.0.0, the rate limiter's truncated slip comes from the address asked")
	slipped := false
	for i in 0 ..< 8 {
		res := query_udp(udp_port, build_query("source.test.", u16(dns.Type.A), id = u16(0x6850 + i)), address = SECOND_LOOPBACK)
		if !check(r, res.ok, "no response to query %d", i) {
			break
		}
		check(
			r,
			netx.addresses_equal(res.from.address, SECOND_LOOPBACK) && res.from.port == udp_port,
			"query %d answered from %v",
			i,
			res.from,
		)
		if parse_header(r, res.wire).tc {
			slipped = true
			break
		}
	}
	check(r, slipped, "no truncated slip came back, so its send was never exercised")
	end_case(r)
}
