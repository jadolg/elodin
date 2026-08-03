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
config_cookies :: proc(port, upstream_port: int, require: bool) -> string {
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
		port,
		port,
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

	port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_cookies(port, upstream_port, false), port = port})
	if !ok {
		skip_case(r, "cookies", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "cookies: a client cookie comes back with a server cookie behind it")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(port, query)
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
		res := query_udp(port, first)
		if check(r, res.ok, "no response") {
			issued, found := find_cookie(res.wire)
			if check(r, found, "the answer carries no COOKIE option") {
				second := build_query(f.qname, f.qtype, id = 0x4243, edns_size = 1232, cookie = issued)
				again := query_udp(port, second)
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
		// forgery and answer BADCOOKIE instead of the question.
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(port, query)
		if check(r, res.ok, "no response") {
			seen := mock_last_query(mock)
			if check(r, seen != nil, "the upstream saw no query") {
				_, leaked := find_cookie(seen)
				check(r, !leaked, "the client's cookie was forwarded upstream")
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
		res := query_udp(port, query)
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
		res := query_udp(port, query)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Form_Err), "rcode for a malformed cookie")
		}
	}
	end_case(r)

	run_cookie_require_cases(r, mock, upstream_port)
}

@(private = "file")
run_cookie_require_cases :: proc(r: ^Runner, mock: ^Mock, upstream_port: int) {
	port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_cookies(port, upstream_port, true), port = port})
	if !ok {
		skip_case(r, "cookies: require", "server did not start")
		return
	}
	defer stop_server(&srv)

	f := fixture("a")

	start_case(r, "cookies: require turns an unproven UDP client away with BADCOOKIE")
	{
		query := build_query(f.qname, f.qtype, edns_size = 1232, cookie = CLIENT_COOKIE)
		res := query_udp(port, query)
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
				again := query_udp(port, retry)
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
		res := query_udp(port, query)
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
		res := query_tcp(port, query)
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode")
			check(r, h.ancount > 0, "a TCP client was refused")
		}
	}
	end_case(r)
}
