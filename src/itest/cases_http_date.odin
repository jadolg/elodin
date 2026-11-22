package itest

import "core:fmt"
import "elodin:dns"
import "elodin:h2"

/*
RFC 9110 6.6.1: a server with a clock MUST send a Date on every 2xx and 4xx, in
the IMF-fixdate form (5.6.7). DoH's 200 and 404 on HTTP/1.1 and HTTP/2.
*/
run_http_date_cases :: proc(r: ^Runner) {
	start_case(r, "DoH: a Date on every 200 and 404, over HTTP/1.1 and HTTP/2 (#710)")
	defer end_case(r)

	udp_port, doh_port := next_port(r), next_port(r)
	config := base_config(
		udp_port,
		upstream_at(next_port(r)),
		listeners_extra = fmt.tprintf(
			`  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
			doh_port,
			r.cert_file,
			r.key_file,
		),
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, doh_port = doh_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	// A local answer, so no upstream is needed for the 200.
	query := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
	Path :: struct {
		path:   string,
		status: int,
	}
	paths := []Path{{path = "/dns-query", status = 200}, {path = "/nope", status = 404}}
	for p in paths {
		res := doh_post(doh_port, p.path, query, context.temp_allocator)
		if check(r, res.ok && res.status == p.status, "DoH/1.1 %s: status %d (ok %v), want %d", p.path, res.status, res.ok, p.status) {
			date := header_value(res.headers, "Date")
			check(r, is_imf_fixdate(date), "DoH/1.1 %s: Date %q is not an IMF-fixdate", p.path, date)
		}
	}

	c, connected := h2_connect(doh_port)
	if !check(r, connected, "DoH/2: cannot open a connection") {
		return
	}
	defer h2_close(c)
	for p, i in paths {
		id := u32(2 * i + 1)
		if !check(r, h2_send_request(c, id, "POST", p.path, query), "DoH/2 %s: cannot send the request", p.path) ||
		   !check(r, h2_collect(c, []u32{id}), "DoH/2 %s: stream %d never completed", p.path, id) {
			continue
		}
		res, found := h2_stream(c, id)
		if check(r, found && res.status == p.status, "DoH/2 %s: stream %d (found %v) is not a %d", p.path, id, found, p.status) {
			date := h2_header_value(res, "date")
			check(r, is_imf_fixdate(date), "DoH/2 %s: date %q is not an IMF-fixdate", p.path, date)
		}
	}
}

// IMF-fixdate is the only form of the three of fixed length 29.
@(private = "file")
is_imf_fixdate :: proc(value: string) -> bool {
	_, ok := h2.parse_http_date(value, {})
	return ok && len(value) == len("Sun, 06 Nov 1994 08:49:37 GMT")
}
