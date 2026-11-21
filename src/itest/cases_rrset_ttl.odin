package itest

import "core:fmt"
import "elodin:dns"

@(private = "file")
MIXED_QNAME :: "mixed.rrset-ttl.test."

// An A RRset whose two records arrive at TTLs 3600 and 10.
@(private = "file")
mixed_ttl_answer :: proc(allocator := context.allocator) -> []u8 {
	m := dns.Message {
		question = []dns.Question{{name = MIXED_QNAME, type = .A, class = .IN}},
		answer   = []dns.Record {
			{name = MIXED_QNAME, type = .A, class = .IN, ttl = 3600, data = dns.Rdata_A{addr = {192, 0, 2, 34}}},
			{name = MIXED_QNAME, type = .A, class = .IN, ttl = 10, data = dns.Rdata_A{addr = {192, 0, 2, 35}}},
		},
	}
	m.flags.qr = true
	m.flags.rd = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
RFC 2181 section 5.2: "In no case may a server send an RRSet with TTLs not all
equal"; one that arrives so is passed on, and cached, at its lowest TTL. The
forwarded copy and the copy the cache serves later are both held to it.
*/
run_rrset_ttl_cases :: proc(r: ^Runner) {
	GROUP :: "rrset ttl"
	payload := mixed_ttl_answer()
	defer delete(payload)
	if payload == nil {
		skip_case(r, GROUP, "cannot build the mixed-TTL answer")
		return
	}
	upstream_port := next_port(r)
	mock := mock_make("rrset-ttl", upstream_port)
	mock_reply(mock, MIXED_QNAME, u16(dns.Type.A), payload)
	if !mock_start_or_skip(r, mock, GROUP) {
		return
	}
	defer mock_stop(mock)
	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port), cache = "{ enabled: true }"), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "rrset ttl: an RRset that arrives with two TTLs leaves with its lowest, forwarded and cached")
	{
		for what, i in ([]string{"forwarded", "cached"}) {
			res := query_udp(udp_port, build_query(MIXED_QNAME, u16(dns.Type.A), id = u16(0x6940 + i)))
			if !check(r, res.ok, "%s: no response", what) {
				continue
			}
			msg, decoded := decode_reply(r, res.wire)
			if !decoded || !check(r, len(msg.answer) == 2, "%s: %d answers, want both", what, len(msg.answer)) {
				continue
			}
			check(r, msg.answer[0].ttl == msg.answer[1].ttl, "%s: TTLs %d and %d in one RRset", what, msg.answer[0].ttl, msg.answer[1].ttl)
			check(r, msg.answer[0].ttl <= 10, "%s: TTL %d, past the lowest of the set", what, msg.answer[0].ttl)
		}
		check_eq_int(r, mock_total(mock), 1, fmt.tprintf("upstream queries for %s", MIXED_QNAME))
	}
	end_case(r)
}
