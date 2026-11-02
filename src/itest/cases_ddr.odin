package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
Discovery of Designated Resolvers from the shipped binary (#218): with `ddr.name`
set, `_dns.resolver.arpa` SVCB names this server's own DoT and DoH listeners
(RFC 9462 section 4, SvcParams per RFC 9461), and a name the certificate does
not cover is refused by `--check` and at startup.
*/

@(private = "file")
ddr_config :: proc(r: ^Runner, udp_port, dot_port, doh_port: int, name: string) -> string {
	return fmt.tprintf(
		`listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}
upstream:
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
ddr:
  name: %s
rewrites:
  - domain: %s
    answers: [127.0.0.1]
`,
		udp_port,
		dot_port,
		r.cert_file,
		r.key_file,
		doh_port,
		r.cert_file,
		r.key_file,
		next_port(r),
		name,
		name,
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
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, build_query("_dns.resolver.arpa.", u16(dns.Type.SVCB), allocator = context.temp_allocator))
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, res.ok && err == .None, "no answer to the DDR probe") &&
			   check(r, len(msg.answer) == 2, "%d SVCB records, want one per encrypted listener", len(msg.answer)) {
				dot := msg.answer[0].data.(dns.Rdata_SVCB)
				doh := msg.answer[1].data.(dns.Rdata_SVCB)
				check(r, dot.target == "elodin.local." && doh.target == "elodin.local.", "targets %q %q", dot.target, doh.target)
				check(r, string(dot.params) == svc_wire("\x03dot", dot_port, ""), "DoT params % x", dot.params)
				check(r, string(doh.params) == svc_wire("\x02h2\x08http/1.1", doh_port, "/dns-query{?dns}"), "DoH params % x", doh.params)
				check(
					r,
					len(msg.additional) == 1 && msg.additional[0].data.(dns.Rdata_A).addr == [4]u8{127, 0, 0, 1},
					"the rewrite's address is not in the additional section: %v",
					msg.additional,
				)
			}
		}
	}
	end_case(r)

	start_case(r, "ddr: a name the certificate does not cover is refused by --check and at startup (#218)")
	{
		udp_port, dot_port, doh_port := next_port(r), next_port(r), next_port(r)
		config := ddr_config(r, udp_port, dot_port, doh_port, "not-on-the-certificate.example")
		path := filepath.join({r.work_dir, "ddr-uncovered.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)config)
		res := run_binary(r, []string{"--config", path, "--check"}, "ddr-uncovered")
		check(r, res.ok && res.exit_code != 0, "--check passed a designation the certificate does not cover")
		check(r, strings.contains(res.output, "does not cover not-on-the-certificate.example"), "--check did not say why: %q", res.output)

		srv, started := start_server_raw(r, config, udp_port)
		if check(r, started, "cannot start the binary") {
			defer stop_server(&srv)
			state, werr := os.process_wait(srv.process, 10 * time.Second)
			if check(r, werr == nil && state.exited, "the server started designating a name its certificate does not cover") {
				srv.running = false
				check(r, state.exit_code != 0, "the refusal exited 0")
				check(r, log_contains(&srv, "does not cover not-on-the-certificate.example"), "the refusal does not name the name:\n%s", read_log(&srv))
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
