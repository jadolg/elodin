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

The fourth is the counter, since `special_use=` in the stats line and
`elodin_special_use_total` on the metrics endpoint are what an operator watches
instead of the query log.

The mock synthesises an A answer for whatever it is asked, so any name that
reaches it comes back 198.51.100.7 - an address the table would never produce.
That makes a leak visible as an address rather than only as a query count.
*/

// The owner name of the first SOA in the authority section, or "" if there is
// none. The apex the negative answer is cached against is the point of several
// of these cases, and nothing else in the suite reads it.
@(private = "file")
authority_soa_owner :: proc(wire: []u8) -> string {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return ""
	}
	for rec in msg.authority {
		if rec.type == .SOA {
			return rec.name
		}
	}
	return ""
}

@(private = "file")
special_use_config :: proc(udp_port, upstream_port: int, extra: string) -> string {
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
dnssec: {{ enabled: false }}
%s`,
		udp_port,
		upstream_port,
		extra,
	)
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
	upstream_port := next_port(r)
	mock := mock_make("special-use-answered", upstream_port)
	mock_synth_all(mock, {198, 51, 100, 7})
	if !mock_start(mock) {
		skip_case(r, "special_use: reserved names are answered here", "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = special_use_config(udp_port, upstream_port, ""), udp_port = udp_port},
	)
	if !ok {
		skip_case(r, "special_use: reserved names are answered here", "server did not start")
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
			addrs := answer_addresses(v4.wire)
			if check(r, len(addrs) == 1, "localhost. A returned %d addresses", len(addrs)) {
				check_eq_str(r, addrs[0], "127.0.0.1", "localhost. A")
			}
		}
		v6 := query_udp(udp_port, build_query("localhost.", u16(dns.Type.AAAA)))
		if check(r, v6.ok, "no response for localhost. AAAA") {
			addrs := answer_addresses(v6.wire)
			if check(r, len(addrs) == 1, "localhost. AAAA returned %d addresses", len(addrs)) {
				// Full form: `answer_addresses` prints every group rather than
				// compressing the run of zeros.
				check_eq_str(r, addrs[0], "0000:0000:0000:0000:0000:0000:0000:0001", "localhost. AAAA")
			}
		}
		// The reservation is of the subtree, not of the one label.
		sub := query_udp(udp_port, build_query("dev.localhost.", u16(dns.Type.A)))
		if check(r, sub.ok, "no response for dev.localhost.") {
			addrs := answer_addresses(sub.wire)
			if check(r, len(addrs) == 1, "dev.localhost. returned %d addresses", len(addrs)) {
				check_eq_str(r, addrs[0], "127.0.0.1", "dev.localhost. A")
			}
		}
	}
	end_case(r)

	start_case(r, "special_use: localhost. is NODATA for a type it has none of")
	{
		res := query_udp(udp_port, build_query("localhost.", u16(dns.Type.MX)))
		if check(r, res.ok, "no response for localhost. MX") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
			// The name exists, so the SOA is its own rather than a parent's.
			check_eq_str(r, authority_soa_owner(res.wire), "localhost.", "SOA owner")
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
			res := query_udp(udp_port, build_query(c.name, u16(dns.Type.A)))
			if check(r, res.ok, "no response for %s", c.name) {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s: rcode %d, want NXDOMAIN", c.name, h.rcode)
				check_eq_int(r, len(answer_addresses(res.wire)), 0, "addresses handed to the client")
				// Owned by the apex, so a downstream caches the negative for the
				// tree rather than for one hidden service.
				check_eq_str(r, authority_soa_owner(res.wire), c.apex, "SOA owner")
			}
		}
	}
	end_case(r)

	start_case(r, "special_use: none of that reached the upstream")
	{
		check_eq_int(r, mock_total(mock) - before, 0, "queries the upstream was sent")
		check(r, log_contains(&srv, "outcome=local detail=special-use"), "no special-use line in the query log")
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
	upstream_port := next_port(r)
	mock := mock_make("special-use-default", upstream_port)
	mock_synth_all(mock, {198, 51, 100, 7})
	if !mock_start(mock) {
		skip_case(r, "special_use: the defaults still forward", "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = special_use_config(udp_port, upstream_port, ""), udp_port = udp_port},
	)
	if !ok {
		skip_case(r, "special_use: the defaults still forward", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "special_use: .local, .test, home.arpa and example.com are forwarded by default")
	{
		for name in ([]string{"printer.local.", "internal.test.", "www.example.com.", "printer.home.arpa."}) {
			res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
			if check(r, res.ok, "no response for %s", name) {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "%s: rcode %d, want NOERROR", name, h.rcode)
				addrs := answer_addresses(res.wire)
				if check(r, len(addrs) == 1, "%s returned %d addresses", name, len(addrs)) {
					check_eq_str(r, addrs[0], "198.51.100.7", "forwarded address")
				}
			}
		}
	}
	end_case(r)
}

/*
The keys, each turning over the one zone it names and no other.

`local: true` is the departure from the default; `onion: false` is the departure
in the other direction, for an upstream that really can answer those names. Both
are checked against a second name that must not move with them, since a key that
turned the whole table on or off would pass the first half of either case.
*/
@(private = "file")
run_special_use_key_cases :: proc(r: ^Runner) {
	// --- local: true answers .local, and leaves .test forwarded ---
	{
		upstream_port := next_port(r)
		mock := mock_make("special-use-local", upstream_port)
		mock_synth_all(mock, {198, 51, 100, 7})
		if !mock_start(mock) {
			skip_case(r, "special_use: local: true", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = special_use_config(udp_port, upstream_port, "special_use: { local: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: local: true answers .local and only .local")
				{
					res := query_udp(udp_port, build_query("printer.local.", u16(dns.Type.A)))
					if check(r, res.ok, "no response for printer.local.") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
						check_eq_str(r, authority_soa_owner(res.wire), "local.", "SOA owner")
					}
					// The other key is untouched, so this one is not the whole table.
					other := query_udp(udp_port, build_query("internal.test.", u16(dns.Type.A)))
					if check(r, other.ok, "no response for internal.test.") {
						addrs := answer_addresses(other.wire)
						if check(r, len(addrs) == 1, "internal.test. returned %d addresses", len(addrs)) {
							check_eq_str(r, addrs[0], "198.51.100.7", "forwarded address")
						}
					}
				}
				end_case(r)
			} else {
				skip_case(r, "special_use: local: true", "server did not start")
			}
		}
	}

	// --- home_arpa: true serves the empty zone, and still fetches the apex DS ---
	{
		upstream_port := next_port(r)
		mock := mock_make("special-use-home-arpa", upstream_port)
		mock_synth_all(mock, {198, 51, 100, 7})
		if !mock_start(mock) {
			skip_case(r, "special_use: home_arpa: true", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = special_use_config(udp_port, upstream_port, "special_use: { home_arpa: true }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: home_arpa: true serves home.arpa as an empty zone")
				{
					// Inside the zone: a name error, cached against the apex.
					res := query_udp(udp_port, build_query("printer.home.arpa.", u16(dns.Type.A)))
					if check(r, res.ok, "no response for printer.home.arpa.") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
						check_eq_int(r, len(answer_addresses(res.wire)), 0, "addresses handed to the client")
						check_eq_str(r, authority_soa_owner(res.wire), "home.arpa.", "SOA owner")
					}
					// The apex itself: NODATA, not a name error. `arpa` publishes
					// a signed delegation for it, so a client can prove the name
					// exists - RFC 8375 section 4 item 4.B, by way of RFC 6303
					// section 3.
					apex := query_udp(udp_port, build_query("home.arpa.", u16(dns.Type.A)))
					if check(r, apex.ok, "no response for home.arpa.") {
						h, _ := parse_header(apex.wire)
						check(r, h.rcode == int(dns.Rcode.No_Error), "apex rcode %d, want NOERROR", h.rcode)
						check_eq_int(r, len(answer_addresses(apex.wire)), 0, "addresses at the apex")
						check_eq_str(r, authority_soa_owner(apex.wire), "home.arpa.", "apex SOA owner")
					}
					// The other key is untouched, so this one is not the whole table.
					other := query_udp(udp_port, build_query("internal.test.", u16(dns.Type.A)))
					if check(r, other.ok, "no response for internal.test.") {
						addrs := answer_addresses(other.wire)
						if check(r, len(addrs) == 1, "internal.test. returned %d addresses", len(addrs)) {
							check_eq_str(r, addrs[0], "198.51.100.7", "forwarded address")
						}
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
			} else {
				skip_case(r, "special_use: home_arpa: true", "server did not start")
			}
		}
	}

	// --- onion: false forwards .onion, and keeps localhost. answered here ---
	{
		upstream_port := next_port(r)
		mock := mock_make("special-use-onion", upstream_port)
		mock_synth_all(mock, {198, 51, 100, 7})
		if !mock_start(mock) {
			skip_case(r, "special_use: onion: false", "cannot start the mock")
		} else {
			defer mock_stop(mock)
			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = special_use_config(udp_port, upstream_port, "special_use: { onion: false }\n"),
					udp_port = udp_port,
				},
			)
			if ok {
				defer stop_server(&srv)
				start_case(r, "special_use: onion: false hands .onion to the upstream, and nothing else with it")
				{
					res := query_udp(udp_port, build_query("duskgytldkxiuqc6otgh4.onion.", u16(dns.Type.A)))
					if check(r, res.ok, "no response for the .onion name") {
						h, _ := parse_header(res.wire)
						check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
						addrs := answer_addresses(res.wire)
						if check(r, len(addrs) == 1, "the .onion name returned %d addresses", len(addrs)) {
							check_eq_str(r, addrs[0], "198.51.100.7", "the Tor-aware upstream's answer")
						}
					}
					// The rest of the table is still on: this is the key that
					// exists so an operator need not reach for `enabled: false`.
					local := query_udp(udp_port, build_query("localhost.", u16(dns.Type.A)))
					if check(r, local.ok, "no response for localhost.") {
						addrs := answer_addresses(local.wire)
						if check(r, len(addrs) == 1, "localhost. returned %d addresses", len(addrs)) {
							check_eq_str(r, addrs[0], "127.0.0.1", "localhost. A")
						}
					}
					check(r, log_contains(&srv, "special_use.onion is off"), "the startup warning was not logged")
				}
				end_case(r)
			} else {
				skip_case(r, "special_use: onion: false", "server did not start")
			}
		}
	}
}

/*
The counter, in both places an operator reads it.

`special_use=` in the `msg=stats` line and `elodin_special_use_total` on the
metrics endpoint are the only aggregate evidence the table did anything, so both
are checked against a known number of queries rather than merely for being
present.
*/
@(private = "file")
run_special_use_counter_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("special-use-counter", upstream_port)
	mock_synth_all(mock, {198, 51, 100, 7})
	if !mock_start(mock) {
		skip_case(r, "special_use: the counter", "cannot start the mock")
		return
	}
	defer mock_stop(mock)

	metrics_port := next_port(r)
	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = special_use_config(
				udp_port,
				upstream_port,
				fmt.tprintf("metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}\n", metrics_port),
			),
			udp_port = udp_port,
		},
	)
	if !ok {
		skip_case(r, "special_use: the counter", "server did not start")
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
