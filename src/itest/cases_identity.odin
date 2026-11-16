package itest

import "core:fmt"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
`server.identity` from the wire (#261): what version.bind answers over UDP, how
the query log records it, and whether a DoH answer names the build in `Server`.
*/
run_identity_cases :: proc(r: ^Runner) {
	Case :: struct {
		name, setting: string,
		// The TXT version.bind answers with; "" is REFUSED.
		text:          string,
		// What a DoH answer's `Server` field is; "" is no field.
		server:        string,
	}
	cases := []Case {
		{"server.identity unset: the build, on both (#261)", "", "elodin ", "Server: elodin/"},
		{"server.identity text: the text, and no Server field (#261)", `"resolver"`, "resolver", ""},
		{"server.identity off: REFUSED with detail=chaos, and no Server field (#261)", "off", "", ""},
	}
	for c in cases {
		start_case(r, c.name)
		defer end_case(r)

		udp_port, doh_port := next_port(r), next_port(r)
		extra := fmt.tprintf("server:\n  identity: %s", c.setting) if c.setting != "" else ""
		config := base_config(
			udp_port,
			upstream_at(next_port(r)),
			log = "{ level: info, queries: true }",
			listeners_extra = fmt.tprintf(
				`  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
				doh_port,
				r.cert_file,
				r.key_file,
			),
			extra = extra,
		)
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, doh_port = doh_port})
		if !ok {
			continue
		}
		defer stop_server(&srv)

		/*
		Counted from here: wait_ready's own probe is a version.bind query, and
		its line already says what this one should.
		*/
		want_line := "outcome=refused detail=chaos" if c.text == "" else "outcome=local detail=chaos"
		before := log_count(&srv, want_line)
		res := query_udp(udp_port, build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH)))
		if check(r, res.ok, "no answer to version.bind") {
			msg, decoded := decode_reply(r, res.wire)
			if decoded && c.text == "" {
				check(r, msg.flags.rcode == u8(dns.Rcode.Refused) && len(msg.answer) == 0, "rcode %d with %d answers, want REFUSED and none", msg.flags.rcode, len(msg.answer))
			} else if decoded && check(r, len(msg.answer) == 1, "%d answers, want one TXT", len(msg.answer)) {
				txt, is_txt := msg.answer[0].data.(dns.Rdata_TXT)
				if check(r, is_txt && len(txt.strings) == 1, "the answer is not one TXT string: %v", msg.answer[0]) {
					check(r, strings.has_prefix(txt.strings[0], c.text), "version.bind answered %q, want %q", txt.strings[0], c.text)
				}
			}
		}
		check(r, wait_for_log_count(&srv, want_line, before + 1, 5 * time.Second), "no query line with %q:\n%s", want_line, read_log(&srv))

		// A DoH answer from the cache-free local path: the same CHAOS query.
		doh := doh_post(doh_port, "/dns-query", build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH)), context.temp_allocator)
		if check(r, doh.ok && doh.status == 200, "DoH: status %d (ok %v), want 200", doh.status, doh.ok) {
			if c.server != "" {
				check(r, strings.contains(doh.headers, c.server), "DoH: the fields %q hold no %q", doh.headers, c.server)
			} else {
				check(r, !strings.contains(doh.headers, "Server:"), "DoH: the fields %q send a Server field", doh.headers)
			}
		}
	}
}
