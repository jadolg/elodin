package itest

import "elodin:dns"
import "elodin:server"
import "elodin:testkit"

// A mock named `name` on a port of its own, answering each of `fixtures` with
// its captured response.
signed_mock :: proc(r: ^Runner, name: string, fixtures: []Fixture) -> ^Mock {
	mock := mock_make(name, next_port(r))
	for f in fixtures {
		mock_reply(mock, f.qname, f.qtype, testkit.unhex(f.response, context.allocator))
	}
	return mock
}

/*
Start `mock` and, in front of it, a validating server that trusts `anchor` alone,
logging at info, with its cache on where `cache` says. A mock that cannot start
skips `group`, and a server that cannot start fails it: either way `ok` is false
and nothing is left running. Otherwise the caller stops both, the server first.
*/
start_signed_pair :: proc(r: ^Runner, mock: ^Mock, anchor, group: string, cache := false) -> (srv: Server, udp_port: int, ok: bool) {
	if !mock_start_or_skip(r, mock, group) {
		return
	}
	udp_port = next_port(r)
	anchors := [1]string{anchor}
	config := dnssec_config(udp_port, mock.port, anchors[:], log = "{ level: info }", cache = "{ enabled: true }" if cache else "{ enabled: false }")
	if srv, ok = start_server(r, Server_Options{config = config, udp_port = udp_port}); !ok {
		mock_stop(mock)
	}
	return
}

// A case asking `qname` A with DO set, and the rcode its answer must carry.
Signed_Verdict :: struct {
	name:  string,
	qname: string,
	rcode: dns.Rcode,
}

/*
Ask each of `verdicts` as a case of its own: NOERROR must carry AD, and SERVFAIL
must not, and must say why with extended error 6 (DNSSEC Bogus, RFC 8914 section
4.7).
*/
check_signed_verdicts :: proc(r: ^Runner, udp_port: int, verdicts: []Signed_Verdict) {
	for c in verdicts {
		start_case(r, c.name)
		res := query_udp(udp_port, build_query(c.qname, u16(dns.Type.A), edns_size = 1232, dnssec_ok = true))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(c.rcode), "rcode")
			check(r, h.ad == (c.rcode == .No_Error), "AD is %v", h.ad)
			if c.rcode == .Serv_Fail {
				check_eq_int(r, extended_error(r, res.wire), server.EDE_DNSSEC_BOGUS, "extended DNS error")
			}
		}
		end_case(r)
	}
}
