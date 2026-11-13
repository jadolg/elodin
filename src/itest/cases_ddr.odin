package itest

import "core:fmt"
import "core:strings"
import "elodin:dns"
import "elodin:tlsx"

/*
Discovery of Designated Resolvers from the shipped binary (#218): with `ddr.name`
set, `_dns.resolver.arpa` SVCB names this server's own DoT and DoH listeners
(RFC 9462 section 4, SvcParams per RFC 9461), and a name the certificate does
not cover is warned about by `--check` and left undesignated by the server.
*/

@(private = "file")
ddr_config :: proc(r: ^Runner, udp_port, dot_port, doh_port: int, name: string) -> string {
	return base_config(
		udp_port,
		upstream_at(next_port(r)),
		// The shipped level, and the shipped upstream timeout.
		log = "{ level: info }",
		timeout = "",
		listeners_extra = fmt.tprintf(
			`  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
			dot_port,
			r.cert_file,
			r.key_file,
			doh_port,
			r.cert_file,
			r.key_file,
		),
		extra = fmt.tprintf("ddr:\n  name: %s\nrewrites:\n  - domain: %s\n    answers: [127.0.0.1]", name, name),
	)
}

run_ddr_cases :: proc(r: ^Runner) {
	start_case(r, "ddr: _dns.resolver.arpa designates the DoT and DoH listeners (#218)")
	{
		// The premise: the suite's certificate covers the name designated.
		ctx, cerr := tlsx.server_context(r.cert_file, r.key_file, nil)
		if check(r, cerr == .None, "the suite's certificate does not load: %v", cerr) {
			check(r, tlsx.signer_covers_host(ctx.signer, "elodin.local"), "the suite's certificate does not cover elodin.local")
			tlsx.context_destroy(ctx)
		}

		udp_port, dot_port, doh_port := next_port(r), next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = ddr_config(r, udp_port, dot_port, doh_port, "elodin.local"),
				udp_port = udp_port,
				dot_port = dot_port,
				doh_port = doh_port,
			},
		)
		if ok {
			defer stop_server(&srv)
			res := query_udp(udp_port, build_query("_dns.resolver.arpa.", u16(dns.Type.SVCB), allocator = context.temp_allocator))
			if check(r, res.ok, "no answer to the DDR probe") {
				msg, decoded := decode_reply(r, res.wire)
				if decoded && check(r, len(msg.answer) == 2, "%d SVCB records, want one per encrypted listener", len(msg.answer)) {
					// Checked, not asserted: a record of the wrong type fails this case,
					// not the whole run.
					dot, dot_ok := msg.answer[0].data.(dns.Rdata_SVCB)
					doh, doh_ok := msg.answer[1].data.(dns.Rdata_SVCB)
					if check(r, dot_ok && doh_ok, "the answers are not SVCB: %v", msg.answer) {
						check(r, dot.target == "elodin.local." && doh.target == "elodin.local.", "targets %q %q", dot.target, doh.target)
						check(r, string(dot.params) == svc_wire("\x03dot", dot_port, ""), "DoT params % x", dot.params)
						check(r, string(doh.params) == svc_wire("\x02h2\x08http/1.1", doh_port, "/dns-query{?dns}"), "DoH params % x", doh.params)
					}
					glue_ok := false
					if len(msg.additional) == 1 {
						glue, is_a := msg.additional[0].data.(dns.Rdata_A)
						glue_ok = is_a && glue.addr == [4]u8{127, 0, 0, 1}
					}
					check(r, glue_ok, "the rewrite's address is not in the additional section: %v", msg.additional)
				}
			}
		}
	}
	end_case(r)

	start_case(r, "ddr: a name the certificate does not cover is warned by --check and not designated (#218)")
	{
		udp_port, dot_port, doh_port := next_port(r), next_port(r), next_port(r)
		config := ddr_config(r, udp_port, dot_port, doh_port, "not-on-the-certificate.example")
		res := check_config_text(r, "ddr-uncovered", config)
		// A warning, not a failure: the server starts on this file, as below.
		if res.ok {
			check(r, res.exit_code == 0, "--check failed a file the server starts on: %q", res.output)
			check(r, strings.contains(res.output, "warning: ddr.name: the certificate of listeners.dot") && strings.contains(res.output, "is not designated"), "--check did not warn: %q", res.output)
		}

		/*
		Startup serves the certificate and designates nothing, as a reload does
		with a renewal that drops the name: refusing it here would turn the next
		restart after such a renewal into no resolver at all.
		*/
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, dot_port = dot_port, doh_port = doh_port})
		if ok {
			defer stop_server(&srv)
			check(r, log_contains(&srv, "does not cover not-on-the-certificate.example"), "startup did not say why nothing is designated:\n%s", read_log(&srv))
			res := query_udp(udp_port, build_query("_dns.resolver.arpa.", u16(dns.Type.SVCB), allocator = context.temp_allocator))
			if check(r, res.ok, "no answer to the DDR probe") {
				if msg, decoded := decode_reply(r, res.wire); decoded {
					check(r, len(msg.answer) == 0 && len(msg.authority) == 1, "an uncovered listener was designated: %v", msg.answer)
				}
			}
		}
	}
	end_case(r)
}

// SvcParams as the server writes them: alpn, then port, then dohpath if any.
@(private = "file")
svc_wire :: proc(alpn: string, port: int, dohpath: string) -> string {
	b := make([dynamic]u8, context.temp_allocator)
	append(&b, 0, 1, u8(len(alpn) >> 8), u8(len(alpn)))
	append(&b, alpn)
	append(&b, 0, 3, 0, 2, u8(port >> 8), u8(port))
	if dohpath != "" {
		append(&b, 0, 7, u8(len(dohpath) >> 8), u8(len(dohpath)))
		append(&b, dohpath)
	}
	return string(b[:])
}
