package itest

import "core:fmt"
import "elodin:dns"

/*
DNS cookies on the client-facing path (RFC 7873, RFC 9018).

What the client sees is checked against a live server rather than against the
cookie code, so these cases say something the unit tests cannot: that a cookie
survives the whole path a query takes, that it never reaches the upstream, and
that a client turned away with BADCOOKIE can get past it with what it was given.
*/

@(private = "file")
config_cookies :: proc(udp_port, upstream_port: int, require: bool) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
cookies:
  enabled: true
  require: %v
  secret: e5e973e5a6b2a43f48e7dc849e37bfcf
`,
		udp_port,
		udp_port,
		upstream_port,
		require,
	)
}

@(private = "file")
CLIENT_COOKIE := []u8{0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57}

run_cookie_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("cookie", upstream_port)
	f := fixture("a")
	mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	if !mock_start(mock) {
		skip_case(r, "cookies", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_cookies(udp_port, upstream_port, false), udp_port = udp_port})
	if !ok {
		skip_case(r, "cookies", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "cookies: a client cookie comes back with a server cookie behind it")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			got, found := find_cookie(res.wire)
			if check(r, found, "the answer carries no COOKIE option") {
				check_eq_int(r, len(got), 24, "cookie length")
				check(r, bytes_equal(got[:8], CLIENT_COOKIE), "the client cookie was not echoed")
			}
		}
	}
	end_case(r)

	start_case(r, "cookies: the same client gets a cookie it can use again")
	{
		first := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(udp_port, first)
		if check(r, res.ok, "no response") {
			issued, found := find_cookie(res.wire)
			if check(r, found, "the answer carries no COOKIE option") {
				second := build_query(f.qname, f.qtype, id = 0x4243, edns_size = 1232, cookie = issued)
				again := query_udp(udp_port, second)
				if check(r, again.ok, "no response to the second query") {
					h, _ := parse_header(again.wire)
					check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a query with a valid cookie")
					_, renewed := find_cookie(again.wire)
					check(r, renewed, "the second answer carries no COOKIE option")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "cookies: the client's cookie is not forwarded to the upstream")
	{
		// It is a secret between the client and this server. An upstream that
		// implements cookies would hash it against its own key, call it a
		// forgery and answer BADCOOKIE instead of the question. What the
		// upstream sees is elodin's own cookie for it, which is a different
		// value entirely.
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			seen := mock_last_query(mock)
			if check(r, seen != nil, "the upstream saw no query") {
				forwarded, has_cookie := find_cookie(seen)
				if check(r, has_cookie, "elodin's own cookie did not go upstream") {
					check(
						r,
						!bytes_equal(forwarded[:min(8, len(forwarded))], CLIENT_COOKIE),
						"the client's cookie was forwarded upstream",
					)
				}
				msg, err := dns.decode_message(seen, context.temp_allocator)
				if check(r, err == .None, "the forwarded query does not decode") {
					// Only the cookie goes; the rest of EDNS is still negotiated
					// end to end.
					check(r, dns.edns_present(msg), "the OPT record went with it")
					check_eq_int(r, int(dns.edns_udp_size(msg)), 1232, "advertised buffer size")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "cookies: a client that sends none gets none back")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			_, found := find_cookie(res.wire)
			check(r, !found, "a client that asked for no cookie was given one")
		}
	}
	end_case(r)

	start_case(r, "cookies: an impossible length yields FORMERR")
	{
		// Nine bytes is neither a client cookie nor a client cookie with a
		// server cookie behind it (RFC 7873 section 5.2.2).
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = make([]u8, 9, context.temp_allocator))
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Form_Err), "rcode for a malformed cookie")
		}
	}
	end_case(r)

	run_cookie_require_cases(r, mock, upstream_port)
}

@(private = "file")
config_upstream_cookies :: proc(udp_port, upstream_port: int, upstream_cookies: bool, client_cookies := true) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
cookies:
  enabled: %v
  upstream: %v
`,
		udp_port,
		udp_port,
		upstream_port,
		client_cookies,
		upstream_cookies,
	)
}

/*
The other direction: what elodin sends to the servers it asks.

The mock plays a cookie-aware resolver, so the conversation is observable from
the far side — which cookie went out, whether the server cookie came back on the
next query, and what a BADCOOKIE does.
*/
run_upstream_cookie_cases :: proc(r: ^Runner) {
	f := fixture("a")

	{
		upstream_port := next_port(r)
		mock := mock_make("upstream-cookie", upstream_port)
		mock.cookies = .Echo
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "cookies: upstream", "cannot start the mock upstream")
			return
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_upstream_cookies(udp_port, upstream_port, true), udp_port = udp_port})
		if !ok {
			skip_case(r, "cookies: upstream", "server did not start")
			return
		}
		defer stop_server(&srv)

		start_case(r, "cookies: the upstream is asked with a cookie, and the answer teaches us one")
		{
			res := query_udp(udp_port, build_query(f.qname, f.qtype, edns_size = 1232))
			if check(r, res.ok, "no response") {
				sent, found := find_cookie(mock_last_query(mock))
				if check(r, found, "the upstream saw no cookie") {
					// Nothing learned yet, so this is a client cookie alone.
					check_eq_int(r, len(sent), 8, "cookie length on the first query")
				}

				// The second query should carry what the first one learned.
				second := query_udp(udp_port, build_query("second.example.", u16(dns.Type.A), id = 0x4245, edns_size = 1232))
				if check(r, second.ok, "no response to the second query") {
					again, had := find_cookie(mock_last_query(mock))
					if check(r, had, "the second query carried no cookie") {
						check_eq_int(r, len(again), 16, "cookie length on the second query")
						check(r, bytes_equal(again[:8], sent), "the client cookie changed between queries")
					}
				}
			}
		}
		end_case(r)

		start_case(r, "cookies: the upstream's cookie is not passed on to the client")
		{
			// The client asked for no cookie, so it must get none - least of all
			// one belonging to the conversation between us and the upstream.
			res := query_udp(udp_port, build_query(f.qname, f.qtype, id = 0x4246, edns_size = 1232))
			if check(r, res.ok, "no response") {
				_, leaked := find_cookie(res.wire)
				check(r, !leaked, "the upstream's cookie reached the client")
			}
		}
		end_case(r)

		start_case(r, "cookies: a query with no EDNS goes upstream without one")
		{
			// Adding an OPT record would negotiate EDNS for a client that never
			// asked, and change what may come back.
			res := query_udp(udp_port, build_query("plain.example.", u16(dns.Type.A), id = 0x4247))
			if check(r, res.ok, "no response") {
				_, found := find_cookie(mock_last_query(mock))
				check(r, !found, "a cookie was added to a query with no OPT record")
			}
		}
		end_case(r)
	}

	{
		// A server that will not answer until it sees its own cookie.
		upstream_port := next_port(r)
		mock := mock_make("upstream-badcookie", upstream_port)
		mock.cookies = .Require
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "cookies: upstream badcookie", "cannot start the mock upstream")
			return
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_upstream_cookies(udp_port, upstream_port, true), udp_port = udp_port})
		if !ok {
			skip_case(r, "cookies: upstream badcookie", "server did not start")
			return
		}
		defer stop_server(&srv)

		start_case(r, "cookies: BADCOOKIE from the upstream is retried, and the client never sees it")
		{
			res := query_udp(udp_port, build_query(f.qname, f.qtype, edns_size = 1232))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode")
				check(r, h.ancount > 0, "the answer never arrived")
				check_eq_int(r, mock_total(mock), 2, "queries the upstream saw")
			}
		}
		end_case(r)
	}

	{
		// The two settings are independent. This is the combination where the
		// client's cookie is not taken out on the way in, so what keeps it off
		// the wire is our own cookie for this upstream replacing it.
		upstream_port := next_port(r)
		mock := mock_make("upstream-only", upstream_port)
		mock.cookies = .Echo
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "cookies: upstream only", "cannot start the mock upstream")
			return
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_upstream_cookies(udp_port, upstream_port, true, client_cookies = false),
				udp_port = udp_port,
			},
		)
		if !ok {
			skip_case(r, "cookies: upstream only", "server did not start")
			return
		}
		defer stop_server(&srv)

		start_case(r, "cookies: a client's cookie is replaced even with the client-facing side off")
		{
			res := query_udp(udp_port, build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE))
			if check(r, res.ok, "no response") {
				forwarded, has_cookie := find_cookie(mock_last_query(mock))
				if check(r, has_cookie, "elodin's own cookie did not go upstream") {
					check(
						r,
						!bytes_equal(forwarded[:min(8, len(forwarded))], CLIENT_COOKIE),
						"the client's cookie reached the upstream",
					)
				}
				// And with the client-facing side off, the client gets nothing back.
				_, given := find_cookie(res.wire)
				check(r, !given, "a cookie was issued with the client-facing side off")
			}
		}
		end_case(r)
	}

	{
		upstream_port := next_port(r)
		mock := mock_make("upstream-nocookie", upstream_port)
		mock.cookies = .Echo
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "cookies: upstream off", "cannot start the mock upstream")
			return
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_upstream_cookies(udp_port, upstream_port, false), udp_port = udp_port})
		if !ok {
			skip_case(r, "cookies: upstream off", "server did not start")
			return
		}
		defer stop_server(&srv)

		start_case(r, "cookies: upstream cookies can be turned off")
		{
			res := query_udp(udp_port, build_query(f.qname, f.qtype, edns_size = 1232))
			if check(r, res.ok, "no response") {
				_, found := find_cookie(mock_last_query(mock))
				check(r, !found, "a cookie went upstream with the setting off")
			}
		}
		end_case(r)
	}

	{
		// Both sides off, which is the combination where nothing replaces the
		// client's cookie on its way out. It still must not travel: it is a
		// stable identifier for that client, and its server half was minted here,
		// so an upstream that implements cookies reads it as a forgery.
		upstream_port := next_port(r)
		mock := mock_make("cookies-all-off", upstream_port)
		mock.cookies = .Echo
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
		if !mock_start(mock) {
			skip_case(r, "cookies: both off", "cannot start the mock upstream")
			return
		}
		defer mock_stop(mock)

		udp_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_upstream_cookies(udp_port, upstream_port, false, client_cookies = false), udp_port = udp_port},
		)
		if !ok {
			skip_case(r, "cookies: both off", "server did not start")
			return
		}
		defer stop_server(&srv)

		start_case(r, "cookies: a client's cookie is dropped even with both sides off")
		{
			res := query_udp(udp_port, build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE))
			if check(r, res.ok, "no response") {
				forwarded, found := find_cookie(mock_last_query(mock))
				check(r, !found, "the client's cookie reached the upstream with both sides off")
				if found {
					check(
						r,
						!bytes_equal(forwarded[:min(8, len(forwarded))], CLIENT_COOKIE),
						"the client's own cookie was the one forwarded",
					)
				}
			}
		}
		end_case(r)
	}
}

@(private = "file")
run_cookie_require_cases :: proc(r: ^Runner, mock: ^Mock, upstream_port: int) {
	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_cookies(udp_port, upstream_port, true), udp_port = udp_port, tcp_port = udp_port})
	if !ok {
		skip_case(r, "cookies: require", "server did not start")
		return
	}
	defer stop_server(&srv)

	f := fixture("a")

	start_case(r, "cookies: require turns an unproven UDP client away with BADCOOKIE")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			msg, err := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, err == .None, "the response does not decode") {
				check_eq_int(r, int(dns.rcode_of(msg)), int(dns.Rcode.Bad_Cookie), "rcode")
				check_eq_int(r, len(msg.answer), 0, "answer records in a refusal")
			}

			// And the refusal has to carry the cookie to come back with, or the
			// client has no way past it.
			issued, found := find_cookie(res.wire)
			if check(r, found, "BADCOOKIE without a cookie leaves the client stuck") {
				retry := build_query(f.qname, f.qtype, id = 0x4244, edns_size = 1232, cookie = issued)
				again := query_udp(udp_port, retry)
				if check(r, again.ok, "no response to the retry") {
					h, _ := parse_header(again.wire)
					check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for the retry")
					check(r, h.ancount > 0, "the retry was not answered")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "cookies: require leaves clients that send no cookie alone")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode")
			check(r, h.ancount > 0, "a client without cookies was not answered")
		}
	}
	end_case(r)

	start_case(r, "cookies: require does not apply over TCP")
	{
		// The connection already proved the client can receive at the address
		// it is claiming, which is all the cookie was there to establish.
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_tcp(udp_port, query)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode")
			check(r, h.ancount > 0, "a TCP client was refused")
		}
	}
	end_case(r)
}
