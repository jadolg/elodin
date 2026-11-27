package itest

import "core:fmt"
import "elodin:dns"

// An upstream's NXDOMAIN for `name` A, with the zone's SOA.
@(private = "file")
nx_with_soa :: proc(name: string, allocator := context.allocator) -> []u8 {
	soa := [1]dns.Record {
		{
			name = "mock.test.",
			type = .SOA,
			class = .IN,
			ttl = 3600,
			data = dns.Rdata_SOA{ns = "ns.mock.test.", mbox = "h.mock.test.", serial = 1, refresh = 2, retry = 3, expire = 4, minimum = 3600},
		},
	}
	m := dns.Message {
		authority = soa[:],
	}
	m.flags.rcode = u8(dns.Rcode.NX_Domain)
	return encode_reply(name, .A, m, allocator)
}

/*
RFC 8020 and RFC 1034 section 3.1: a name above a rewrite, a wildcard rule's own
domain and an additive rule's name exist here, so an upstream NXDOMAIN for one
goes out as NODATA with the upstream's SOA; a name no rule is at or below keeps
its NXDOMAIN.
*/
run_rewrite_ent_cases :: proc(r: ^Runner) {
	GROUP :: "rewrite ent"
	Row :: struct {
		name: string,
		want: dns.Rcode,
	}
	rows := [?]Row {
		{name = "b.rw.mock.test.", want = .No_Error},
		{name = "wild.mock.test.", want = .No_Error},
		{name = "mx.mock.test.", want = .No_Error},
		{name = "nx.mock.test.", want = .NX_Domain},
	}
	upstream_port := next_port(r)
	mock := mock_make("rewrite-ent", upstream_port)
	payloads: [len(rows)][]u8
	defer for p in payloads {
		delete(p)
	}
	for row, i in rows {
		payloads[i] = nx_with_soa(row.name)
		if payloads[i] == nil {
			// The codec's failure or the fixture's, not a busy port: failed.
			fail(r, "%s: cannot build the NXDOMAIN reply", GROUP)
			mock_stop(mock)
			return
		}
		mock_reply(mock, row.name, u16(dns.Type.A), payloads[i])
	}
	if !mock_start_or_skip(r, mock, GROUP) {
		return
	}
	defer mock_stop(mock)
	udp_port := next_port(r)
	extra := `rewrites:
  - { domain: a.b.rw.mock.test, answer: 192.168.1.50 }
  - { domain: "*.wild.mock.test", answer: 10.0.0.1 }
  - { domain: mx.mock.test, answers: ["MX 10 mail.mock.test"] }
`
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port), cache = "{ enabled: true }", extra = extra), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "rewrite ent: an upstream NXDOMAIN for a name a rewrite makes exist goes out as NODATA, with its SOA")
	for row, i in rows {
		res := query_udp(udp_port, build_query(row.name, u16(dns.Type.A), id = u16(0x7060 + i)))
		if !check(r, res.ok, "%s: no response", row.name) {
			continue
		}
		msg, decoded := decode_reply(r, res.wire)
		if !decoded {
			continue
		}
		check(r, dns.rcode_of(msg) == row.want, "%s: rcode %v, want %v", row.name, dns.rcode_of(msg), row.want)
		check(r, len(msg.answer) == 0, "%s: %d answers", row.name, len(msg.answer))
		check(r, len(msg.authority) == 1 && msg.authority[0].type == .SOA, "%s: authority %v, want the upstream's SOA", row.name, msg.authority)
	}
	check_eq_int(r, mock_total(mock), len(rows), fmt.tprintf("upstream queries"))
	end_case(r)
}
