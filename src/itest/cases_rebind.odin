package itest

import "core:fmt"
import "elodin:dns"

/*
DNS rebinding protection, end to end.

The unit tests in `src/server/rebind_test.odin` pin the decision the guard makes
about a message; these pin what a client actually receives from the shipped
binary once that decision has been turned into a response and sent back over the
wire. The two things worth proving out here and not in a unit test are the
default - off, so a public name answering with a private address is forwarded
untouched unless the operator has turned the guard on - and the client-visible
shape of a refusal: NODATA with an SOA and RFC 8914 extended error 15, plus the
`outcome=blocked detail=rebind` line in the query log.

A synthesising mock answers whatever name is asked with a chosen address, which
is exactly the move the attack makes: the name is public, the address is not.
*/

// The info-code of the extended error a response carries, or -1 if it has none.
// Read here rather than through a shared helper because only the rebinding cases
// care about the value, not merely that an EDE is present.
@(private = "file")
extended_error_code :: proc(wire: []u8) -> int {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return -1
	}
	for rec in msg.additional {
		opt, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for option in opt.options {
			if option.code == u16(dns.EDNS_Option_Code.Ext_Error) && len(option.data) >= 2 {
				return int(option.data[0]) << 8 | int(option.data[1])
			}
		}
	}
	return -1
}

/*
Point the server at one synthesising upstream and hand back a running server.

The config is generated per case so the `rebind:` block can vary; caching and
blocking are off so nothing sits between the upstream's answer and the guard, and
the query log is on so the `outcome=blocked` line can be asserted.
*/
@(private = "file")
rebind_config :: proc(udp_port, upstream_port: int, rebind_block: string) -> string {
	return fmt.tprintf(
		`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 2s
  attempts: 1
  servers:
    - "127.0.0.1:%d"
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
%s`,
		udp_port,
		upstream_port,
		rebind_block,
	)
}

run_rebind_cases :: proc(r: ^Runner) {
	run_rebind_default_case(r)
	run_rebind_refusal_cases(r)
	run_rebind_exemption_cases(r)
}

/*
The default: off.

The operator this ships to commonly runs split horizon - a public zone answering
with a LAN address - so the guard is off until it is asked for, and a private
address from an upstream is forwarded exactly as any other answer is. This is the
case that would fail loudest if the default were ever flipped by accident.
*/
@(private = "file")
run_rebind_default_case :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("rebind-default", upstream_port)
	// A public name whose upstream answers with an RFC 1918 address - the shape
	// the guard exists to refuse, forwarded here because the guard is off.
	mock_synth_all(mock, {192, 168, 1, 1})
	if !mock_start(mock) {
		skip_case(r, "rebind: off by default", "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	// No `rebind:` block at all, so the shipped default is what answers.
	srv, ok := start_server(r, Server_Options{config = rebind_config(udp_port, upstream_port, ""), udp_port = udp_port})
	if !ok {
		skip_case(r, "rebind: off by default", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "rebind: a private address is forwarded when the guard is off by default")
	{
		res := query_udp(udp_port, build_query("rebind.attacker.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			addrs := answer_addresses(res.wire)
			if check(r, len(addrs) == 1, "expected the answer forwarded, got %d addresses", len(addrs)) {
				check_eq_str(r, addrs[0], "192.168.1.1", "forwarded address")
			}
		}
		check(r, !log_contains(&srv, "detail=rebind"), "the guard refused an answer while off")
	}
	end_case(r)
}

/*
The guard on: a private address is refused, a public one is not.

The refusal is the client-visible NODATA - NOERROR, no answer, an SOA in the
authority section and extended error 15 - and the `outcome=blocked` line that
tells the operator which name it was. The public-address case beside it is the
control: a guard that refused everything would pass the first assertion and be
useless, so the second says it lets an ordinary answer through untouched.
*/
@(private = "file")
run_rebind_refusal_cases :: proc(r: ^Runner) {
	// --- a private address is refused ---
	{
		upstream_port := next_port(r)
		mock := mock_make("rebind-private", upstream_port)
		mock_synth_all(mock, {192, 168, 1, 1})
		if !mock_start(mock) {
			skip_case(r, "rebind: refuses a private address", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = rebind_config(udp_port, upstream_port, "rebind: { enabled: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "rebind: a public name answering with a private address is refused as NODATA")
				{
					// EDNS advertised so the server carries the extended error
					// back - it attaches an OPT to the response only when the
					// client sent one, as an EDNS-less stub cannot read it anyway.
					res := query_udp(udp_port, build_query("rebind.attacker.test.", u16(dns.Type.A), edns_size = 1232))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
						check_eq_int(r, h.ancount, 0, "answer count")
						check(r, h.nscount >= 1, "no SOA in the authority section")
						check_eq_int(r, len(answer_addresses(res.wire)), 0, "addresses handed to the client")
						check_eq_int(r, extended_error_code(res.wire), 15, "extended error info-code")
					}
					check(r, log_contains(&srv, "outcome=blocked detail=rebind"), "the query log did not record the refusal")
					check(r, log_contains(&srv, "rebinding attack"), "no warning was logged for the first refusal")
				}
				end_case(r)
			} else {
				skip_case(r, "rebind: refuses a private address", "server did not start")
			}
		}
	}

	// --- a public address is forwarded unchanged ---
	{
		upstream_port := next_port(r)
		mock := mock_make("rebind-public", upstream_port)
		mock_synth_all(mock, {198, 51, 100, 7})
		if !mock_start(mock) {
			skip_case(r, "rebind: forwards a public address", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = rebind_config(udp_port, upstream_port, "rebind: { enabled: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "rebind: a public address is forwarded unchanged with the guard on")
				{
					res := query_udp(udp_port, build_query("example.test.", u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
						addrs := answer_addresses(res.wire)
						if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
							check_eq_str(r, addrs[0], "198.51.100.7", "forwarded address")
						}
					}
					check(r, !log_contains(&srv, "detail=rebind"), "a public answer was refused")
				}
				end_case(r)
			} else {
				skip_case(r, "rebind: forwards a public address", "server did not start")
			}
		}
	}
}

/*
The two exemptions, on the shipped binary.

`allow_domains` names the zones a split-horizon operator may keep answering
privately, matched on the question and at or below the zone - so `corp.test`
covers `nas.corp.test` and does nothing for `nas.notcorp.test`, the label break
being the thing an off-by-one in the matcher would get wrong. `allow_loopback`
opens loopback and nothing else, so `127.0.0.1` is let through while an RFC 1918
address on another name is still refused.
*/
@(private = "file")
run_rebind_exemption_cases :: proc(r: ^Runner) {
	// --- allow_domains ---
	{
		upstream_port := next_port(r)
		mock := mock_make("rebind-exempt", upstream_port)
		// Any name answers privately; only the exempt zone should be forwarded.
		mock_synth_all(mock, {192, 168, 1, 50})
		if !mock_start(mock) {
			skip_case(r, "rebind: allow_domains", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = rebind_config(udp_port, upstream_port, "rebind:\n  enabled: true\n  allow_domains: [corp.test]\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "rebind: an exempt zone may resolve to a private address")
				{
					res := query_udp(udp_port, build_query("nas.corp.test.", u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						addrs := answer_addresses(res.wire)
						if check(r, len(addrs) == 1, "expected the exempt answer forwarded, got %d", len(addrs)) {
							check_eq_str(r, addrs[0], "192.168.1.50", "forwarded address")
						}
					}
				}
				end_case(r)

				start_case(r, "rebind: a name just outside the exempt zone is still refused")
				{
					// notcorp.test is not below corp.test - the label boundary,
					// not a substring, decides.
					res := query_udp(udp_port, build_query("nas.notcorp.test.", u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check_eq_int(r, h.ancount, 0, "answer count")
						check_eq_int(r, len(answer_addresses(res.wire)), 0, "addresses handed to the client")
					}
				}
				end_case(r)
			} else {
				skip_case(r, "rebind: allow_domains", "server did not start")
			}
		}
	}

	// --- allow_loopback ---
	{
		upstream_port := next_port(r)
		mock := mock_make("rebind-loopback", upstream_port)
		// Loopback for one name, RFC 1918 for another, so the one setting can be
		// seen to open the first without opening the second.
		mock_synth(mock, "loop.test.", u16(dns.Type.A), {127, 0, 0, 1})
		mock_synth(mock, "priv.test.", u16(dns.Type.A), {192, 168, 1, 1})
		if !mock_start(mock) {
			skip_case(r, "rebind: allow_loopback", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = rebind_config(udp_port, upstream_port, "rebind:\n  enabled: true\n  allow_loopback: true\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "rebind: allow_loopback lets 127.0.0.1 through")
				{
					res := query_udp(udp_port, build_query("loop.test.", u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						addrs := answer_addresses(res.wire)
						if check(r, len(addrs) == 1, "expected loopback forwarded, got %d", len(addrs)) {
							check_eq_str(r, addrs[0], "127.0.0.1", "forwarded address")
						}
					}
				}
				end_case(r)

				start_case(r, "rebind: allow_loopback does not open RFC 1918")
				{
					res := query_udp(udp_port, build_query("priv.test.", u16(dns.Type.A)))
					if check(r, res.ok, "no response") {
						h, _ := parse_header(res.wire)
						check_eq_int(r, h.ancount, 0, "answer count")
						check_eq_int(r, len(answer_addresses(res.wire)), 0, "addresses handed to the client")
					}
				}
				end_case(r)
			} else {
				skip_case(r, "rebind: allow_loopback", "server did not start")
			}
		}
	}
}
