package itest

import "core:fmt"
import "elodin:dns"

/*
The reserved forward names, end to end.

`src/server/special_use_test.odin` pins the decision the table makes about a
message. These pin what the shipped binary does with it, and there are four
things worth proving out here rather than in a unit test.

The first is that the query never leaves the process. A unit test can watch a
mock socket, but the thing an operator is trusting is that the real binary, with
its real forwarding path and its real upstream group, does not send it - and
`.onion` is the case where a single escaped query is the whole harm, so it is
worth checking against the thing that ships.

The second is the client-visible shape: 127.0.0.1 and `::1` for `localhost.`,
NXDOMAIN with an SOA owned by the reserved apex for the rest. A resolver
downstream caches the negative answer against that owner name, so the apex being
`onion.` rather than the queried name's parent is a property of the wire, which
is where it should be checked.

The third is the defaults, which are the whole argument of the feature: `.local`,
`.test` and `example.com` are forwarded by a shipped configuration and the two
keys turn them off. This is the case that fails loudest if the table ever grows
past what was argued for it.

The fourth is the counter on the metrics endpoint, since it and `special_use=`
in the stats line are what an operator watches instead of the query log.

The mock synthesises an A answer for whatever it is asked, so any name that
reaches it comes back 198.51.100.7 - an address the table would never produce.
That makes a leak visible as an address rather than only as a query count.
*/

// The owner name of the first SOA in the authority section, or "" if there is
// none. The apex the negative answer is cached against is the point of several
// of these cases, and nothing else in the suite reads it.
@(private = "file")
authority_soa_owner :: proc(r: ^Runner, wire: []u8) -> string {
	msg, ok := decode_reply(r, wire)
	if !ok {
		return ""
	}
	for rec in msg.authority {
		if rec.type == .SOA {
			return rec.name
		}
	}
	return ""
}

run_special_use_cases :: proc(r: ^Runner) {
	run_special_use_answered_cases(r)
	run_special_use_default_forwarding_cases(r)
	run_special_use_key_cases(r)
	run_special_use_counter_cases(r)
}

/*
What the table answers, and that nothing was asked to answer it.

The mock is started and then checked for having received nothing at all: the
assertion is not merely that the client got the right answer, but that the right
answer was not obtained by asking somebody. A fix that forwarded the query and
rewrote the response would pass every assertion but the last.
*/
@(private = "file")
run_special_use_answered_cases :: proc(r: ^Runner) {
	mock, upstream_port, mock_ok := synth_mock(r, "special-use-answered", "special_use: reserved names are answered here", {198, 51, 100, 7})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = logged_config(udp_port, upstream_port), udp_port = udp_port},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	// The readiness probe is a CHAOS query, so anything the mock has seen by now
	// would be this server forwarding something it should not have.
	before := mock_total(mock)

	start_case(r, "special_use: localhost. resolves to loopback, both families")
	{
		v4 := query_udp(udp_port, build_query("localhost.", u16(dns.Type.A)))
		if check(r, v4.ok, "no response for localhost. A") {
			check_one_address(r, v4.wire, "127.0.0.1", "localhost. A")
		}
		v6 := query_udp(udp_port, build_query("localhost.", u16(dns.Type.AAAA)))
		if check(r, v6.ok, "no response for localhost. AAAA") {
			// Full form: `answer_addresses` prints every group rather than
			// compressing the run of zeros.
			check_one_address(r, v6.wire, "0000:0000:0000:0000:0000:0000:0000:0001", "localhost. AAAA")
		}
		// The reservation is of the subtree, not of the one label.
		sub := query_udp(udp_port, build_query("dev.localhost.", u16(dns.Type.A)))
		if check(r, sub.ok, "no response for dev.localhost.") {
			check_one_address(r, sub.wire, "127.0.0.1", "dev.localhost. A")
		}
	}
	end_case(r)

	start_case(r, "special_use: localhost. is NODATA for a type it has none of")
	{
		if res, h, answered := ask(r, udp_port, "localhost.", u16(dns.Type.MX), "no response for localhost. MX"); answered {
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
			// The name exists, so the SOA is its own rather than a parent's.
			check_eq_str(r, authority_soa_owner(r, res.wire), "localhost.", "SOA owner")
		}
	}
	end_case(r)

	start_case(r, "special_use: .onion and .invalid are NXDOMAIN with an SOA at the reserved apex")
	{
		cases := []struct {
			name:  string,
			apex:  string,
		} {
			{name = "duskgytldkxiuqc6otgh4.onion.", apex = "onion."},
			{name = "deeper.hidden.onion.", apex = "onion."},
			{name = "nothing.invalid.", apex = "invalid."},
		}
		for c in cases {
			if res, h, answered := ask(r, udp_port, c.name, u16(dns.Type.A), fmt.tprintf("no response for %s", c.name)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s: rcode %d, want NXDOMAIN", c.name, h.rcode)
				check_eq_int(r, len(answer_addresses(r, res.wire)), 0, "addresses handed to the client")
				// Owned by the apex, so a downstream caches the negative for the
				// tree rather than for one hidden service.
				check_eq_str(r, authority_soa_owner(r, res.wire), c.apex, "SOA owner")
			}
		}
	}
	end_case(r)

	start_case(r, "special_use: private reverse names are NXDOMAIN with an SOA at the RFC 6303 zone")
	{
		// Issue #321's reproduction: a LAN PTR never reaches the upstream,
		// which would name the network's private addressing to it.
		cases := []struct {
			name: string,
			apex: string,
		} {
			{name = "1.1.168.192.in-addr.arpa.", apex = "168.192.in-addr.arpa."},
			{name = "1.0.0.127.in-addr.arpa.", apex = "127.in-addr.arpa."},
			{name = "1.0.0.10.in-addr.arpa.", apex = "10.in-addr.arpa."},
			{name = "1.1.64.100.in-addr.arpa.", apex = "64.100.in-addr.arpa."},
		}
		for c in cases {
			if res, h, answered := ask(r, udp_port, c.name, u16(dns.Type.PTR), fmt.tprintf("no response for %s", c.name)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s: rcode %d, want NXDOMAIN", c.name, h.rcode)
				check_eq_int(r, h.ancount, 0, "answers handed to the client")
				check_eq_str(r, authority_soa_owner(r, res.wire), c.apex, "SOA owner")
			}
		}
	}
	end_case(r)

	start_case(r, "special_use: none of that reached the upstream")
	{
		check_eq_int(r, mock_total(mock) - before, 0, "queries the upstream was sent")
		check(r, log_contains(&srv, "outcome=local detail=special-use"), "no special-use line in the query log")
		check(r, log_contains(&srv, "outcome=local detail=private-reverse"), "no private-reverse line in the query log")
	}
	end_case(r)
}

/*
The defaults, which are the argument for the shape of the feature.

`.local`, `.test` and `home.arpa` are names deployed networks really do serve,
and `example.` is reserved but delegated, so all four are forwarded by a shipped
configuration. The mock answering 198.51.100.7 is what proves it: the address
could not have come from the table.
*/
@(private = "file")
run_special_use_default_forwarding_cases :: proc(r: ^Runner) {
	mock, upstream_port, mock_ok := synth_mock(r, "special-use-default", "special_use: the defaults still forward", {198, 51, 100, 7})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = logged_config(udp_port, upstream_port), udp_port = udp_port},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "special_use: .local, .test, home.arpa and example.com are forwarded by default")
	{
		for name in ([]string{"printer.local.", "internal.test.", "www.example.com.", "printer.home.arpa."}) {
			if res, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
				check(r, h.rcode == int(dns.Rcode.No_Error), "%s: rcode %d, want NOERROR", name, h.rcode)
				check_one_address(r, res.wire, "198.51.100.7", "forwarded address")
			}
		}
	}
	end_case(r)
}

/*
The keys, each turning over the one zone it names and no other.

`local: true` and `home_arpa: true` are departures from the default; `onion:
false` is the departure in the other direction, for an upstream that really can
answer those names. Each is checked against a second name that must not move
with it, since a key that turned the whole table on or off would pass the first
half of any of them.
*/
@(private = "file")
run_special_use_key_cases :: proc(r: ^Runner) {
	// --- local: true answers .local, and leaves .test forwarded ---
	{
		mock, upstream_port, mock_ok := synth_mock(r, "special-use-local", "special_use: local: true", {198, 51, 100, 7})
		if mock_ok {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = logged_config(udp_port, upstream_port, "special_use: { local: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: local: true answers .local and only .local")
				{
					if res, h, answered := ask(r, udp_port, "printer.local.", u16(dns.Type.A), "no response for printer.local."); answered {
						check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
						check_eq_str(r, authority_soa_owner(r, res.wire), "local.", "SOA owner")
					}
					// The other key is untouched, so this one is not the whole table.
					other := query_udp(udp_port, build_query("internal.test.", u16(dns.Type.A)))
					if check(r, other.ok, "no response for internal.test.") {
						check_one_address(r, other.wire, "198.51.100.7", "forwarded address")
					}
				}
				end_case(r)
			}
		}
	}

	// --- home_arpa: true serves the empty zone, and still fetches the apex DS ---
	{
		mock, upstream_port, mock_ok := synth_mock(r, "special-use-home-arpa", "special_use: home_arpa: true", {198, 51, 100, 7})
		if mock_ok {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = logged_config(udp_port, upstream_port, "special_use: { home_arpa: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: home_arpa: true serves home.arpa as an empty zone")
				{
					// Inside the zone: a name error, cached against the apex.
					if res, h, answered := ask(r, udp_port, "printer.home.arpa.", u16(dns.Type.A), "no response for printer.home.arpa."); answered {
						check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
						check_eq_int(r, len(answer_addresses(r, res.wire)), 0, "addresses handed to the client")
						check_eq_str(r, authority_soa_owner(r, res.wire), "home.arpa.", "SOA owner")
					}
					// The apex itself: NODATA, not a name error. `arpa` publishes
					// a signed delegation for it, so a client can prove the name
					// exists - RFC 8375 section 4 item 4.B, by way of RFC 6303
					// section 3.
					if apex, h, answered := ask(r, udp_port, "home.arpa.", u16(dns.Type.A), "no response for home.arpa."); answered {
						check(r, h.rcode == int(dns.Rcode.No_Error), "apex rcode %d, want NOERROR", h.rcode)
						check_eq_int(r, len(answer_addresses(r, apex.wire)), 0, "addresses at the apex")
						check_eq_str(r, authority_soa_owner(r, apex.wire), "home.arpa.", "apex SOA owner")
					}
					// The other key is untouched, so this one is not the whole table.
					other := query_udp(udp_port, build_query("internal.test.", u16(dns.Type.A)))
					if check(r, other.ok, "no response for internal.test.") {
						check_one_address(r, other.wire, "198.51.100.7", "forwarded address")
					}
				}
				end_case(r)

				start_case(r, "special_use: the home.arpa apex DS is fetched rather than invented")
				{
					// The one query the key does not answer. The proof that this
					// delegation carries no DS is signed and lives in `arpa`, so
					// answering it from the table would leave a validating client
					// below with a broken chain - SERVFAIL for the whole zone -
					// instead of a proved-insecure one. RFC 8375 section 4 item
					// 4.B requires it to go out; DO set or not, since a rcode
					// that turned on that bit would be wrong in one of the two.
					for dnssec_ok in ([]bool{true, false}) {
						before := mock_total(mock)
						res := query_udp(
							udp_port,
							build_query(
								"home.arpa.",
								u16(dns.Type.DS),
								edns_size = 1232,
								dnssec_ok = dnssec_ok,
							),
						)
						check(r, res.ok, "no response for home.arpa. DS (DO=%v)", dnssec_ok)
						check(
							r,
							mock_total(mock) - before == 1,
							"the home.arpa. DS (DO=%v) reached the upstream %d times, want 1",
							dnssec_ok,
							mock_total(mock) - before,
						)
					}
				}
				end_case(r)
			}
		}
	}

	// --- onion: false forwards .onion, and keeps localhost. answered here ---
	{
		mock, upstream_port, mock_ok := synth_mock(r, "special-use-onion", "special_use: onion: false", {198, 51, 100, 7})
		if mock_ok {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = logged_config(udp_port, upstream_port, "special_use: { onion: false }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: onion: false hands .onion to the upstream, and nothing else with it")
				{
					if res, h, answered := ask(r, udp_port, "duskgytldkxiuqc6otgh4.onion.", u16(dns.Type.A), "no response for the .onion name"); answered {
						check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
						check_one_address(r, res.wire, "198.51.100.7", "the Tor-aware upstream's answer")
					}
					// The rest of the table is still on: this is the key that
					// exists so an operator need not reach for `enabled: false`.
					local := query_udp(udp_port, build_query("localhost.", u16(dns.Type.A)))
					if check(r, local.ok, "no response for localhost.") {
						check_one_address(r, local.wire, "127.0.0.1", "localhost. A")
					}
					check(r, log_contains(&srv, "special_use.onion is off"), "the startup warning was not logged")
				}
				end_case(r)
			}
		}
	}
}

/*
The counter, as the metrics endpoint reports it.

`elodin_special_use_total` and `special_use=` in the `msg=stats` line are the
only aggregate evidence the table did anything, so the metric is checked against
a known number of queries rather than merely for being present.
*/
@(private = "file")
run_special_use_counter_cases :: proc(r: ^Runner) {
	mock, upstream_port, mock_ok := synth_mock(r, "special-use-counter", "special_use: the counter", {198, 51, 100, 7})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	metrics_port := next_port(r)
	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = logged_config(
				udp_port,
				upstream_port,
				fmt.tprintf("metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}\n", metrics_port),
			),
			udp_port = udp_port,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "special_use: answers are counted on the metrics endpoint")
	{
		// Three from the table, one forwarded. The forwarded one is the control:
		// a counter incremented on the way in rather than on the branch that
		// answers would read four.
		for name in ([]string{"localhost.", "nothing.invalid.", "secret.onion."}) {
			res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
			check(r, res.ok, "no response for %s", name)
		}
		forwarded := query_udp(udp_port, build_query("printer.local.", u16(dns.Type.A)))
		check(r, forwarded.ok, "no response for the forwarded name")

		if check(r, wait_http(metrics_port, "/metrics"), "the metrics endpoint never answered") {
			res := http_request(metrics_port, "GET", "/metrics", context.temp_allocator)
			if check(r, res.status == 200, "a scrape returned %d", res.status) {
				check(
					r,
					metric_value(string(res.body), "elodin_special_use_total") == 3,
					"elodin_special_use_total is %v, want 3",
					metric_value(string(res.body), "elodin_special_use_total"),
				)
			}
		}
	}
	end_case(r)
}
