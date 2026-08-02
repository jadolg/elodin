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
dnssec_config :: proc(r: ^Runner, port: int, upstream_port: int, extra := "") -> string {
	return fmt.tprintf(
		`log:
  level: info
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
		port,
		upstream_port,
		extra,
	)
}

run_dnssec_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("dnssec", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 55})
	if !mock_start(mock) {
		skip_case(r, "dnssec", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = dnssec_config(r, port, upstream_port), port = port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "dnssec: an answer with no chain of trust is refused")
	{
		// The mock has no root DNSKEY to offer, so the chain cannot be built and
		// the answer must not be served. Failing open here would make the whole
		// feature decorative.
		res := query_udp(port, build_query("unsigned.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode")
			check_eq_int(r, h.ancount, 0, "answers in a refused response")
		}
	}
	end_case(r)

	start_case(r, "dnssec: the refusal is logged with a reason")
	{
		check(r, log_contains(&srv, "dnssec:"), "the log does not explain the refusal:\n%s", read_log(&srv))
	}
	end_case(r)

	start_case(r, "dnssec: the forwarded query asks for signatures")
	{
		// DO to get the signatures, CD so the upstream's own opinion of them
		// does not decide the matter for us.
		mock_reset_counts(mock)
		_ = query_udp(port, build_query("signatures.test.", u16(dns.Type.A)))

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
		res := query_udp(port, build_query("cd.test.", u16(dns.Type.A), checking_disabled = true))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a CD query")
			check_eq_int(r, h.ancount, 1, "answers for a CD query")

			addrs := answer_addresses(res.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "203.0.113.55", "address")
			}
		}
	}
	end_case(r)

	start_case(r, "dnssec: a refused answer carries an extended DNS error")
	{
		res := query_udp(port, build_query("ede.test.", u16(dns.Type.A), edns_size = 1232))
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
		plain, started := start_server(r, Server_Options{config = config, port = plain_port})
		if started {
			defer stop_server(&plain)
			res := query_udp(plain_port, build_query("unsigned.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
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
					h, _ := parse_header(res.wire)
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
}
