package itest

import "core:fmt"
import "core:time"
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
			check(r, is_current_date(date), "DoH/1.1 %s: Date %q is not the current IMF-fixdate", p.path, date)
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
			check(r, is_current_date(date), "DoH/2 %s: date %q is not the current IMF-fixdate", p.path, date)
		}
	}
}

// How far a response's Date may be from the wall clock when it is read.
@(private = "file")
DATE_SLACK :: 60 * time.Second

/*
An IMF-fixdate (RFC 9110 5.6.7) with the weekday its date falls on, within
`DATE_SLACK` of the wall clock. IMF-fixdate is the only one of the three forms
that is 29 bytes long.
*/
@(private = "file")
is_current_date :: proc(value: string) -> bool {
	if len(value) != len("Sun, 06 Nov 1994 08:49:37 GMT") {
		return false
	}
	moment, parsed := h2.parse_http_date(value, {})
	if !parsed || h2.format_http_date(moment, context.temp_allocator) != value {
		return false
	}
	at, converted := time.datetime_to_time(moment)
	now := time.now() // lint:allow a Date is wall-clock time, so the wall clock is what it is checked against
	return converted && abs(time.diff(at, now)) < DATE_SLACK
}
