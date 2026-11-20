package itest

import "elodin:dns"

/*
Issue #689: an additional RRset that does not fit is left out whole, with TC
clear (RFC 2181 section 9), not cut at the record that overflowed. The mock
answers an MX question with one MX for `mail.rrset.test.` and forty A records
for it in the additional section, about 700 bytes. A client without EDNS has
512, so the A RRset does not fit: it gets the MX and none of the addresses,
rather than the first twenty-odd of them reading as all there are. A client
that asks for 1232 gets all forty.
*/

@(private = "file")
MAIL_ADDRESSES :: 40

run_additional_rrset_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("additional-rrset", upstream_port)
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "rrset.test.",
		type  = .MX,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_MX{preference = 10, exchange = "mail.rrset.test."},
	}
	glue := make([]dns.Record, MAIL_ADDRESSES, context.temp_allocator)
	for i in 0 ..< MAIL_ADDRESSES {
		glue[i] = dns.Record {
			name  = "mail.rrset.test.",
			type  = .A,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_A{addr = {192, 0, 2, u8(i + 1)}},
		}
	}
	reply := encode_reply("rrset.test.", .MX, {answer = answer, additional = glue}, context.allocator)
	if reply == nil {
		fail(r, "additional rrset: the mock's reply could not be encoded")
		return
	}
	mock_reply(mock, "rrset.test.", u16(dns.Type.MX), reply)
	if !mock_start_or_skip(r, mock, "additional rrset") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port)), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	cases := []struct {
		name:      string,
		edns_size: u16,
		addresses: int,
	} {
		{name = "udp: an additional RRset too big for 512 bytes is left out whole, with TC clear", edns_size = 0, addresses = 0},
		{name = "udp: the same RRset goes out whole where it fits", edns_size = 1232, addresses = MAIL_ADDRESSES},
	}
	for c in cases {
		start_case(r, c.name)
		res := query_udp(udp_port, build_query("rrset.test.", u16(dns.Type.MX), edns_size = c.edns_size))
		if check(r, res.ok, "no response") {
			if msg, decoded := decode_reply(r, res.wire); decoded {
				check(r, !msg.flags.tc, "TC is set for additional data")
				check_eq_int(r, len(msg.answer), 1, "answer records")
				addresses := 0
				for rec in msg.additional {
					if rec.type == .A {
						addresses += 1
					}
				}
				check_eq_int(r, addresses, c.addresses, "A records for mail.rrset.test. in the additional section")
			}
		}
		end_case(r)
	}
}
