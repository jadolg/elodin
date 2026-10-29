package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
DNSSEC validation, end to end.

The cryptography is checked in `src/dnssec` against real captured chains; what
matters here is what the running server does with the verdict. The mock upstream
cannot produce a signed chain, so every answer it gives is one the validator
cannot authenticate - which is exactly the case that has to fail closed, and
exactly the case an operator would rather find out about from a test than from a
resolver that quietly serves whatever it is handed.
*/

@(private = "file")
dnssec_config :: proc(r: ^Runner, udp_port: int, upstream_port: int, extra := "") -> string {
	return fmt.tprintf(
		`log:
  level: info
  queries: true
listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers:
    - udp://127.0.0.1:%d
cache:
  enabled: false
blocking:
  enabled: false
dnssec:
  enabled: true
%s`,
		udp_port,
		upstream_port,
		extra,
	)
}

run_dnssec_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("dnssec", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 55})
	for f in ANCHORED_REVERSE_FIXTURES {
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	}
	if !mock_start(mock) {
		skip_case(r, "dnssec", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	// `private_reverse` off: the private reverse cases below are about what the
	// validator does with a forwarded answer, and with the key on - the
	// default - those names are answered here and never reach it.
	srv, ok := start_server(
		r,
		Server_Options {
			config = dnssec_config(r, udp_port, upstream_port, "special_use: {private_reverse: false}\n"),
			udp_port = udp_port,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "dnssec: an answer with no chain of trust is refused")
	{
		// The mock has no root DNSKEY to offer, so the chain cannot be built and
		// the answer must not be served. Failing open here would make the whole
		// feature decorative.
		res := query_udp(udp_port, build_query("unsigned.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode")
			check_eq_int(r, h.ancount, 0, "answers in a refused response")
		}
	}
	end_case(r)

	start_case(r, "dnssec: the refusal is logged with a reason")
	{
		check(r, log_contains(&srv, "did not validate"), "the log does not explain the refusal:\n%s", read_log(&srv))
	}
	end_case(r)

	start_case(r, "dnssec: the refusal names the upstream the answer came from")
	{
		/*
		Both lines have to name the server, and the reason is what an operator
		does next rather than tidiness.

		A verdict here is a property of the answer, so a group whose members
		disagree about a zone refuses some queries for a name and answers the
		rest, with every other field on the line identical either way. The
		upstream is the field that separates them, and counting it is how the
		server worth removing gets found; a line without it leaves a packet
		capture as the only way to tell.

		An unnamed server is known by the address it was configured as, which is
		what `describe_upstream` builds. The exact string is what gets asserted
		rather than merely that something follows the colon, which a placeholder
		left behind by a half-finished change would satisfy just as well.
		*/
		from := fmt.tprintf("udp://127.0.0.1:%d", upstream_port)
		text := read_log(&srv)
		check(
			r,
			strings.contains(text, fmt.tprintf("answer came from %s", from)),
			"the warning does not name the upstream (expected %q):\n%s",
			from,
			text,
		)
		// The reason stays in front of the name, so `detail=dnssec` still finds
		// every refusal whether or not the reader cares which server it was.
		check(
			r,
			strings.contains(text, fmt.tprintf("detail=dnssec:%s ", from)),
			"the query log does not carry the upstream beside the reason (expected detail=dnssec:%s):\n%s",
			from,
			text,
		)
	}
	end_case(r)

	start_case(r, "dnssec: a second refusal does not write a second warning")
	{
		/*
		The line is bounded by a `logx.Gate`, like every other per-query warning
		on the client path: one a window, so a second inside it is debug.

		Which name is asked about is the client's to choose, so a line per
		refusal is a line per query: one client asking for a zone with a broken
		signature at the rate the limiter allows writes gigabytes a day of
		identical warnings, and journald's per-unit limit then drops them along
		with every legitimate line. The first one is the warning an operator has
		to have; the rest within the window are debug, and `bogus=` in the stats line counts them.

		Different names from the first refusal's, and the cache is off in this
		configuration, so each really is a trip through the branch rather than a
		question that never reached it. Two of them back to back, well inside
		one window: the earlier cases may have taken long enough for the first
		refusal's window to close before either, or between them, so one of the
		two may warn - but not both.
		*/
		before := log_count(&srv, "did not validate")
		if check(r, before == 1, "expected one refusal warning before this case, found %d", before) {
			for name in ([]string{"second.test.", "third.test."}) {
				res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h := parse_header(r, res.wire)
					check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for a later refusal")
				}
			}
			after := log_count(&srv, "did not validate")
			check(r, after - before <= 1, "two refusals inside a window wrote %d warnings", after - before)
		}
	}
	end_case(r)

	start_case(r, "dnssec: the forwarded query asks for signatures")
	{
		// DO to get the signatures, CD so the upstream's own opinion of them
		// does not decide the matter for us.
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query("signatures.test.", u16(dns.Type.A)))

		forwarded := mock_last_query(mock)
		if check(r, len(forwarded) > 12, "the mock saw no query") {
			check(r, forwarded[3] & 0x10 != 0, "the forwarded query does not set CD")

			msg, derr := dns.decode_message(forwarded, context.temp_allocator)
			if check(r, derr == .None, "the forwarded query does not decode: %v", derr) {
				check(r, dns.edns_present(msg), "the forwarded query carries no OPT record")
				check(r, dns.edns_do(msg), "the forwarded query does not set DO")
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: a client that sets CD is served unvalidated")
	{
		// CD is the client saying it will do its own checking, or that it wants
		// the data whatever the verdict. Refusing it anyway would break the
		// resolvers that chain behind us.
		res := query_udp(udp_port, build_query("cd.test.", u16(dns.Type.A), checking_disabled = true))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a CD query")
			check_eq_int(r, h.ancount, 1, "answers for a CD query")

			addrs := answer_addresses(r, res.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "203.0.113.55", "address")
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: a private reverse name is served without validation")
	{
		// 20.2.168.192.in-addr.arpa is the reverse name for 192.168.2.20, an RFC
		// 1918 address. Nothing on the public Internet signs the RFC 6303
		// locally-served zones, so holding this mock's unsigned answer to the
		// chain of trust would SERVFAIL a LAN PTR lookup. It must come back
		// NoError instead - the same escape hatch the code gives these zones by
		// default, proven end to end while validation is on everywhere else.
		res := query_udp(udp_port, build_query("20.2.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a private reverse name")
		}
	}
	end_case(r)

	start_case(r, "dnssec: a public reverse name is still validated")
	{
		// The counterpart: a public reverse name has a real chain, so this mock's
		// unsigned answer for it must fail closed exactly as any other public name
		// does. The gate is narrow, not a hole for every in-addr.arpa name.
		res := query_udp(udp_port, build_query("8.8.8.8.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for a public reverse name")
		}
	}
	end_case(r)

	start_case(r, "dnssec: an operator anchor over a private zone validates it")
	{
		/*
		A site that signs its own reverse space and anchors it is asking for
		those names to be validated - the bypass must defer, and the walk must
		start at the operator's anchor (issue #226). The mock serves
		168.192.in-addr.arpa signed with a key nothing public vouches for, so
		AD on the PTR is the proof the chain began at that anchor: a walk from
		the root never reaches the zone, and SERVFAILs. 10.in-addr.arpa -
		anchored by no one - still bypasses and is served.

		A second server anchors the zone with a key it does not publish, and
		that is SERVFAIL with DNSSEC Bogus (EDE 6) rather than No Reachable
		Authority: the walk reached the zone and the anchor decided it.
		*/
		for c in ([]struct {
				anchor:   string,
				rcode:    dns.Rcode,
				ad:       bool,
				ede:      int,
			}{
				{ANCHORED_REVERSE_ANCHOR, .No_Error, true, -1},
				{"168.192.in-addr.arpa. IN DS 18109 15 2 0000000000000000000000000000000000000000000000000000000000000000", .Serv_Fail, false, 6},
			}) {
			anchored_port := next_port(r)
			config := fmt.tprintf(
				`listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers: [udp://127.0.0.1:%d]
cache: {{enabled: false}}
blocking: {{enabled: false}}
dnssec:
  enabled: true
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    - %q
special_use: {{private_reverse: false}}
`,
				anchored_port,
				upstream_port,
				c.anchor,
			)
			anchored, started := start_server(r, Server_Options{config = config, udp_port = anchored_port})
			if !started {
				continue
			}
			defer stop_server(&anchored)

			covered := query_udp(
				anchored_port,
				build_query("1.1.168.192.in-addr.arpa.", u16(dns.Type.PTR), edns_size = 1232, dnssec_ok = true),
			)
			if check(r, covered.ok, "no response for the anchored name") {
				h := parse_header(r, covered.wire)
				check_eq_int(r, h.rcode, int(c.rcode), "rcode for an anchored private name")
				check(r, (len(covered.wire) >= 4 && covered.wire[3] & 0x20 != 0) == c.ad, "AD for an anchored private name: want %v", c.ad)
				check_eq_int(r, extended_error(r, covered.wire), c.ede, "extended DNS error for an anchored private name")
			}

			uncovered := query_udp(anchored_port, build_query("1.1.10.in-addr.arpa.", u16(dns.Type.PTR)))
			if check(r, uncovered.ok, "no response for the unanchored name") {
				h := parse_header(r, uncovered.wire)
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for an unanchored private name")
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: the walk passes a name owning a CNAME its parent signed")
	{
		/*
		Issue #552: `seed.bitcoin.sipa.be.` and its like. The walk's DS question
		for `alias.cntest.` comes back as the CNAME it owns, signed by
		`cntest.`, which makes it no cut, so the walk reaches the unsigned
		delegation below and the answer is served insecure rather than refused.
		A CNAME the parent did not sign proves nothing, so the same walk through
		those is still DNSSEC Bogus.
		*/
		cut_port := next_port(r)
		cut_mock := mock_make("dnssec-cname-cut", cut_port)
		for f in CNAME_CUT_FIXTURES {
			mock_reply(cut_mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		}
		for name in ([]string{"seed.alias.cntest.", "x.bare.cntest.", "x.wild.cntest.", "x.stray.cntest."}) {
			mock_synth(cut_mock, name, u16(dns.Type.A), {192, 0, 2, 1})
		}
		if mock_start(cut_mock) {
			defer mock_stop(cut_mock)
			cut_udp := next_port(r)
			config := fmt.tprintf(
				`listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers: [udp://127.0.0.1:%d]
cache: {{enabled: false}}
blocking: {{enabled: false}}
dnssec:
  enabled: true
  trust_anchors: [%q]
`,
				cut_udp,
				cut_port,
				CNAME_CUT_ANCHOR,
			)
			cut, started := start_server(r, Server_Options{config = config, udp_port = cut_udp})
			if started {
				defer stop_server(&cut)
				for c in ([]struct {
						name:  string,
						rcode: dns.Rcode,
						ede:   int,
					}{
						{"seed.alias.cntest.", .No_Error, -1},
						{"x.bare.cntest.", .Serv_Fail, 6},
						{"x.wild.cntest.", .Serv_Fail, 6},
						{"x.stray.cntest.", .Serv_Fail, 6},
					}) {
					res := query_udp(cut_udp, build_query(c.name, u16(dns.Type.A), edns_size = 1232, dnssec_ok = true))
					if check(r, res.ok, "no response for %s", c.name) {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.rcode, int(c.rcode), fmt.tprintf("rcode for %s", c.name))
						check(r, len(res.wire) >= 4 && res.wire[3] & 0x20 == 0, "AD for %s, which is not secure", c.name)
						check_eq_int(r, extended_error(r, res.wire), c.ede, fmt.tprintf("extended DNS error for %s", c.name))
					}
				}
			}
		} else {
			check(r, false, "cannot start the mock upstream")
		}
	}
	end_case(r)

	start_case(r, "dnssec: a refused answer carries an extended DNS error")
	{
		res := query_udp(udp_port, build_query("ede.test.", u16(dns.Type.A), edns_size = 1232))
		if check(r, res.ok, "no response") {
			msg, derr := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, derr == .None, "response does not decode: %v", derr) {
				opt, found := dns.find_opt(msg)
				if check(r, found, "no OPT record came back") {
					check(r, has_extended_error(opt), "no extended DNS error in the OPT record")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: validation can be turned off")
	{
		// The same mock and the same question, with validation switched off:
		// the answer comes through. This is the escape hatch for an upstream
		// that cannot return DNSSEC records at all, and it has to work, because
		// the alternative for those deployments is a resolver that answers
		// nothing.
		plain_port := next_port(r)
		config := fmt.tprintf(
			`listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers: [udp://127.0.0.1:%d]
cache: {{enabled: false}}
blocking: {{enabled: false}}
dnssec: {{enabled: false}}
`,
			plain_port,
			upstream_port,
		)
		plain, started := start_server(r, Server_Options{config = config, udp_port = plain_port})
		if started {
			defer stop_server(&plain)
			res := query_udp(plain_port, build_query("unsigned.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h := parse_header(r, res.wire)
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode with validation off")
				check_eq_int(r, h.ancount, 1, "answers with validation off")
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: a configuration that says nothing validates anyway")
	{
		// The whole point of the default. Written verbatim, with no dnssec block
		// at all: the server should come up validating, and this mock cannot
		// satisfy a validator, so the answer has to be refused.
		default_port := next_port(r)
		config := fmt.tprintf(
			`listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers: [udp://127.0.0.1:%d]
cache: {{enabled: false}}
blocking: {{enabled: false}}
`,
			default_port,
			upstream_port,
		)
		defaulted, started := start_server_raw(r, config, default_port, verbatim = true)
		if started {
			defer stop_server(&defaulted)
			if wait_ready(&defaulted, 5 * time.Second) {
				check(r, log_contains(&defaulted, "dnssec: validating"), "the server did not start a validator")

				res := query_udp(default_port, build_query("default.test.", u16(dns.Type.A)))
				if check(r, res.ok, "no response") {
					h := parse_header(r, res.wire)
					check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode under the shipped defaults")
				}
			} else {
				fail(r, "the server never became ready")
			}
		}
	}
	end_case(r)

	run_dnssec_config_cases(r)
}

@(private = "file")
has_extended_error :: proc(opt: dns.Record) -> bool {
	options, ok := opt.data.(dns.Rdata_OPT)
	if !ok {
		return false
	}
	for option in options.options {
		if option.code == u16(dns.EDNS_Option_Code.Ext_Error) && len(option.data) >= 2 {
			return true
		}
	}
	return false
}

@(private = "file")
run_dnssec_config_cases :: proc(r: ^Runner) {
	check_config :: proc(r: ^Runner, tag: string, body: string) -> (exit_code: int, output: string) {
		path := filepath.join({r.work_dir, fmt.tprintf("%s.yaml", tag)}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)body)

		out_path := filepath.join({r.work_dir, fmt.tprintf("%s.txt", tag)}, context.temp_allocator) or_else ""
		out_file, oerr := os.open(out_path, {.Write, .Create, .Trunc}, os.Permissions_Read_All + {.Write_User})
		if oerr != nil {
			return -1, ""
		}
		process, perr := os.process_start(
			os.Process_Desc {
				command = []string{r.binary, "--config", path, "--check"},
				stdout = out_file,
				stderr = out_file,
			},
		)
		if perr != nil {
			os.close(out_file)
			return -1, ""
		}
		state, _ := os.process_wait(process)
		os.close(out_file)

		data, rerr := os.read_entire_file(out_path, context.temp_allocator)
		return state.exit_code, rerr == nil ? string(data) : ""
	}

	start_case(r, "dnssec: --check accepts a configured trust anchor")
	{
		code, _ := check_config(
			r,
			"dnssec-anchor-ok",
			"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  enabled: true\n  trust_anchors:\n" +
			"    - \". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\"\n",
		)
		check_eq_int(r, code, 0, "exit code")
	}
	end_case(r)

	start_case(r, "dnssec: --check rejects an unreadable trust anchor")
	{
		code, output := check_config(
			r,
			"dnssec-anchor-bad",
			"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  enabled: true\n  trust_anchors: [\"not a ds record\"]\n",
		)
		check(r, code != 0, "a broken trust anchor exited 0")
		check(r, strings.contains(output, "trust_anchors"), "the error does not name the setting: %q", output)
	}
	end_case(r)

	start_case(r, "dnssec: an anchor below the root this build cannot follow refuses the start")
	{
		/*
		Algorithm 200 is one no build runs. `--check` cannot say so - which
		algorithms run is the host's to answer, asked at startup - and the zone
		is a starting point for the walk (issue #226), so starting would serve
		`corp.` insecure under an anchor that asked for it to be validated.
		*/
		port := next_port(r)
		config := fmt.tprintf(
			`listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  servers: [udp://127.0.0.1:%d]
dnssec:
  enabled: true
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    - "corp. IN DS 1 200 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
`,
			port,
			next_port(r),
		)
		srv, started := start_server_raw(r, config, port)
		if check(r, started, "cannot start the binary") {
			defer stop_server(&srv)
			state, werr := os.process_wait(srv.process, 10 * time.Second)
			if check(r, werr == nil && state.exited, "the server started on an anchor it cannot follow") {
				srv.running = false
				check(r, state.exit_code != 0, "the refusal exited 0")
				check(r, log_contains(&srv, "no trust anchor for corp. names an algorithm"), "the refusal does not name the zone:\n%s", read_log(&srv))
			}
		}
	}
	end_case(r)

	// Issue #336: the zone-key cache had a bound only the source could set. It
	// is the one dial on how much memory validation may hold, so a box whose
	// memory the operator knows and this server does not needs to reach it.
	start_case(r, "dnssec: --check accepts a zone-cache bound")
	{
		code, output := check_config(
			r,
			"dnssec-zone-cache-ok",
			"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  enabled: true\n  max_cached_zones: 512\n",
		)
		check_eq_int(r, code, 0, "exit code")
		check(
			r,
			!strings.contains(output, "max_cached_zones"),
			"a valid zone-cache bound was complained about: %q",
			output,
		)
	}
	end_case(r)

	// Negative is not a cache without a bound. Reading it as one more way of
	// asking for the default would leave a typo running the cache unbounded.
	start_case(r, "dnssec: --check rejects a negative zone-cache bound")
	{
		code, output := check_config(
			r,
			"dnssec-zone-cache-bad",
			"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  enabled: true\n  max_cached_zones: -1\n",
		)
		check(r, code != 0, "a negative zone-cache bound exited 0")
		check(
			r,
			strings.contains(output, "max_cached_zones"),
			"the error does not name the setting: %q",
			output,
		)
	}
	end_case(r)
}
