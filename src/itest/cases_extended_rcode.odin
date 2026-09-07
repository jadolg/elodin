package itest

import "core:fmt"
import "elodin:dns"

/*
An upstream rcode a client cannot read, end to end through the shipped binary.

`dns.peek_rcode` composes twelve bits - four in the header and eight more in the
OPT record's TTL (RFC 6891 section 6.1.3) - and a stub reads the four. BADVERS is
16, so its low nibble is zero and a client handed that reply straight sees
NOERROR over an empty answer section: a NODATA. For the `TLSA` query below that
is the difference between a DANE client refusing to connect without a
certificate association and one concluding the name has no association to check.

Run with `dnssec.enabled: false` on purpose. The validator refuses this shape as
`Indeterminate` (#271), so with validation on the client gets SERVFAIL wherever
the reply came from; these are the arrangement where nothing but the guard in
`resolve_query` stands between the byte and the client.

Nothing here can pass on a mock that failed to produce an extended rcode: a
reply carrying the plain NOERROR nibble alone is forwarded as NOERROR, which is
what the first case refuses.
*/

@(private = "file")
DANE_NAME :: "_25._tcp.mx.test."

@(private = "file")
config_for :: proc(udp_port: int, servers: string, extra := "") -> string {
	return fmt.tprintf(
		`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  strategy: failover
  timeout: 2s
  attempts: 1
  servers:
%s
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
dnssec: {{ enabled: false }}
%s`,
		udp_port,
		servers,
		extra,
	)
}

// The info-code of the extended error a response carries (RFC 8914), or -1 if
// it has none.
@(private = "file")
extended_error :: proc(wire: []u8) -> int {
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

// The certificate association a DANE client is asking for. Raw RDATA because
// this codec models only a handful of RR types and TLSA is not one of them.
@(private = "file")
tlsa_answer :: proc(allocator := context.allocator) -> []u8 {
	rdata := make([]u8, 7, context.temp_allocator)
	copy(rdata, []u8{3, 1, 1, 0xde, 0xad, 0xbe, 0xef})
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = DANE_NAME,
		type  = .TLSA,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_Raw{data = rdata},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = DANE_NAME,
		type  = .TLSA,
		class = .IN,
	}
	msg := dns.Message {
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, allocator)
	if err != .None {
		return nil
	}
	return wire
}

run_extended_rcode_cases :: proc(r: ^Runner) {
	// --- one upstream, and it answers BADVERS ---
	{
		mock_port := next_port(r)
		broken := mock_make("badvers", mock_port)
		mock_rcode(broken, DANE_NAME, u16(dns.Type.TLSA), .Bad_Vers)
		if !mock_start(broken) {
			skip_case(r, "extended rcode: badvers", "cannot start the mock upstream")
		} else {
			defer mock_stop(broken)

			udp_port := next_port(r)
			srv, ok := start_server(
				r,
				Server_Options {
					config = config_for(udp_port, fmt.tprintf("    - \"127.0.0.1:%d\"\n", mock_port)),
					udp_port = udp_port,
				},
			)
			if !ok {
				skip_case(r, "extended rcode: badvers", "server did not start")
			} else {
				defer stop_server(&srv)

				start_case(r, "an upstream BADVERS is not passed on as a NODATA")
				{
					res := query_udp(udp_port, build_query(DANE_NAME, u16(dns.Type.TLSA), edns_size = 1232))
					if check(r, res.ok, "no response") {
						msg, err := dns.decode_message(res.wire, context.temp_allocator)
						if check(r, err == .None, "the response does not decode") {
							// What a stub reads, and the whole of the harm: the
							// header's own four bits.
							check_eq_int(
								r,
								int(msg.flags.rcode),
								int(dns.Rcode.Serv_Fail),
								"the rcode a client reads off the header",
							)
							// And what this server reads, which has to agree.
							check_eq_int(r, int(dns.rcode_of(msg)), int(dns.Rcode.Serv_Fail), "composed rcode")
							check_eq_int(r, len(msg.answer), 0, "answer records")
						}
						// And the client is told why rather than left with a
						// bare SERVFAIL: RFC 8914 code 0, "Other", with the
						// rcode in the text.
						check_eq_int(r, extended_error(res.wire), 0, "extended DNS error code")
					}
				}
				end_case(r)
			}
		}
	}

	// --- a second upstream that can answer is asked instead ---
	{
		broken_port := next_port(r)
		good_port := next_port(r)
		broken := mock_make("badvers", broken_port)
		mock_rcode(broken, DANE_NAME, u16(dns.Type.TLSA), .Bad_Vers)
		good := mock_make("good", good_port)
		mock_reply(good, DANE_NAME, u16(dns.Type.TLSA), tlsa_answer())

		if !mock_start(broken) || !mock_start(good) {
			skip_case(r, "extended rcode: failover", "cannot start the mock upstreams")
		} else {
			defer mock_stop(broken)
			defer mock_stop(good)

			udp_port := next_port(r)
			servers := fmt.tprintf("    - \"127.0.0.1:%d\"\n    - \"127.0.0.1:%d\"\n", broken_port, good_port)
			srv, ok := start_server(
				r,
				Server_Options{config = config_for(udp_port, servers), udp_port = udp_port},
			)
			if !ok {
				skip_case(r, "extended rcode: failover", "server did not start")
			} else {
				defer stop_server(&srv)

				/*
				elodin only ever asks in EDNS version 0, which every EDNS
				implementation is required to support, so a BADVERS in answer to
				one is that upstream violating the protocol rather than anything
				about the name. The rest of the group is asked, and the client
				gets the answer the second server had all along rather than a
				SERVFAIL for what the first one said.
				*/
				start_case(r, "an upstream answering BADVERS is asked past rather than believed")
				{
					res := query_udp(udp_port, build_query(DANE_NAME, u16(dns.Type.TLSA), edns_size = 1232))
					if check(r, res.ok, "no response") {
						msg, err := dns.decode_message(res.wire, context.temp_allocator)
						if check(r, err == .None, "the response does not decode") {
							check_eq_int(r, int(dns.rcode_of(msg)), int(dns.Rcode.No_Error), "rcode")
							if check_eq_int(r, len(msg.answer), 1, "answer records") {
								check_eq_int(r, int(msg.answer[0].type), int(dns.Type.TLSA), "answer type")
							}
						}
					}
					check(r, mock_total(good) > 0, "the second upstream was never asked")
				}
				end_case(r)
			}
		}
	}
	// --- and the refusal is visible on the metrics endpoint ---
	{
		mock_port := next_port(r)
		broken := mock_make("badvers", mock_port)
		mock_rcode(broken, DANE_NAME, u16(dns.Type.TLSA), .Bad_Vers)
		if !mock_start(broken) {
			skip_case(r, "extended rcode: counted", "cannot start the mock upstream")
			return
		}
		defer mock_stop(broken)

		udp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				// Named in the configuration, because the label on the series
				// below is the name an operator gave the server - which for an
				// entry written as a bare address is the address.
				config = config_for(
					udp_port,
					fmt.tprintf(
						`    - name: badvers
      type: udp
      address: 127.0.0.1
      port: %d
`,
						mock_port,
					),
					fmt.tprintf("metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}\n", metrics_port),
				),
				udp_port = udp_port,
			},
		)
		if !ok {
			skip_case(r, "extended rcode: counted", "server did not start")
			return
		}
		defer stop_server(&srv)

		/*
		The warning naming the upstream is said once per process and demoted to
		debug after it, because the two bytes behind it are ones an on-path
		attacker can write into any reply it can reach. That is only sound
		while something else goes on counting - the same argument
		`conn_refused` is written on - so this is the figure a deployment that
		has gone dark this way is left with.
		*/
		start_case(r, "an upstream rcode a client cannot read is counted for the operator")
		{
			for _ in 0 ..< 3 {
				res := query_udp(udp_port, build_query(DANE_NAME, u16(dns.Type.TLSA), edns_size = 1232))
				check(r, res.ok, "no response")
			}
			if check(r, wait_http(metrics_port, "/metrics"), "the metrics endpoint never answered") {
				res := http_request(metrics_port, "GET", "/metrics", context.temp_allocator)
				if check(r, res.status == 200, "a scrape returned %d", res.status) {
					page := string(res.body)
					// Per upstream, because "which member of the group is
					// doing this" is what the operator is left asking once the
					// one warn line has scrolled away.
					check_eq_int(
						r,
						metric_value(page, "elodin_upstream_unreadable_rcode_total{upstream=\"badvers\"}"),
						3,
						"elodin_upstream_unreadable_rcode_total",
					)
					// And the same server is not called failing for it, which
					// is why the series above has to exist.
					check_eq_int(
						r,
						metric_value(page, "elodin_upstream_failures_total{upstream=\"badvers\"}"),
						0,
						"upstream failures",
					)
					// The same queries are SERVFAILs like any other, so the
					// counter above is a subset of this rather than a figure
					// beside it.
					check_eq_int(
						r,
						metric_value(page, "elodin_answers_total{outcome=\"failed\"}"),
						3,
						"failed answers",
					)
				}
			}
		}
		end_case(r)
	}
}
