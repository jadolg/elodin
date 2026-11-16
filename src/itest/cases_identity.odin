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
		// The TXT version.bind answers with, or what it starts with given
		// `prefix`; "" is REFUSED.
		text:          string,
		prefix:        bool,
		// What a DoH answer's `Server` field starts with; "" is no field.
		server:        string,
	}
	cases := []Case {
		{name = "server.identity unset: the build, on both (#261)", text = "elodin ", prefix = true, server = "elodin/"},
		{name = "server.identity text: the text, and no Server field (#261)", setting = `"resolver"`, text = "resolver"},
		{name = "server.identity off: REFUSED with detail=chaos, and no Server field (#261)", setting = "off"},
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
					matched := strings.has_prefix(txt.strings[0], c.text) if c.prefix else txt.strings[0] == c.text
					check(r, matched, "version.bind answered %q, want %q (prefix %v)", txt.strings[0], c.text, c.prefix)
				}
			}
		}
		check(r, wait_for_log_count(&srv, want_line, before + 1, 5 * time.Second), "no query line with %q:\n%s", want_line, read_log(&srv))

		// DoH answers to the same local query, over HTTP/1.1 and HTTP/2.
		query := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
		doh := doh_post(doh_port, "/dns-query", query, context.temp_allocator)
		if check(r, doh.ok && doh.status == 200, "DoH/1.1: status %d (ok %v), want 200", doh.status, doh.ok) {
			if c.server != "" {
				want := strings.concatenate({"\r\nServer: ", c.server}, context.temp_allocator)
				check(r, strings.contains(doh.headers, want), "DoH/1.1: the fields %q hold no %q", doh.headers, want)
			} else {
				check(r, !strings.contains(doh.headers, "Server:"), "DoH/1.1: the fields %q send a Server field", doh.headers)
			}
		}
		c2, connected := h2_connect(doh_port)
		if !check(r, connected, "DoH/2: cannot open a connection") {
			continue
		}
		defer h2_close(c2)
		if check(r, h2_send_request(c2, 1, "POST", "/dns-query", query), "DoH/2: cannot send the request") &&
		   check(r, h2_collect(c2, []u32{1}), "DoH/2: stream 1 never completed") {
			res, found := h2_stream(c2, 1)
			if check(r, found && res.status == 200, "DoH/2: stream 1 (found %v) is not a 200", found) {
				server := h2_header_value(res, "server")
				if c.server != "" {
					check(r, strings.has_prefix(server, c.server), "DoH/2: server field %q, want %q...", server, c.server)
				} else {
					check(r, server == "", "DoH/2: sends a server field %q", server)
				}
			}
		}
	}
}
