package server

import "core:testing"
import "elodin:dns"

/*
RFC 4035 section 3.2.1: the resolver side of a security-aware recursive name
server "MUST set the DO bit when sending requests, regardless of the state of
the DO bit in the initiating request". With validation on, that holds for a
query this server does not validate as well: CD set by the client, or a name
handed back to the upstream. A client that left DO clear still gets no DNSSEC
records: "the name server side MUST remove any authenticating DNSSEC RRs from
the response" (same section).
*/

@(private = "file")
query_with :: proc(name: string, cd, edns, dnssec_ok: bool) -> []u8 {
	question := [1]dns.Question{{name = name, type = .A, class = .IN}}
	opt := [1]dns.Record{dns.make_opt(1232, dnssec_ok)}
	m := dns.Message {
		id       = 0x7030,
		question = question[:],
	}
	m.flags.rd = true
	m.flags.cd = cd
	if edns {
		m.additional = opt[:]
	}
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("the test query does not encode")
	}
	return wire
}

// An answer for `name` A, with an RRSIG over it.
@(private = "file")
signed_reply :: proc(name: string) -> []u8 {
	return test_reply(
		name,
		.A,
		a_record(name, {192, 0, 2, 7}),
		dns.Record{name = name, type = .RRSIG, class = .IN, ttl = 60, data = rrsig_over(.A)},
	)
}

@(test)
test_do_is_set_upstream_whenever_validation_is_on :: proc(t: ^testing.T) {
	Row :: struct {
		what:       string,
		name:       string,
		validating: bool,
		cd:         bool,
		edns:       bool,
		dnssec_ok:  bool,
		want_do:    bool,
		want_sigs:  int,
	}
	rows := []Row {
		{what = "CD set, no EDNS", name = "www.example.com.", validating = true, cd = true, want_do = true, want_sigs = 0},
		{what = "CD set, DO clear", name = "www.example.com.", validating = true, cd = true, edns = true, want_do = true, want_sigs = 0},
		{what = "CD set, DO set", name = "www.example.com.", validating = true, cd = true, edns = true, dnssec_ok = true, want_do = true, want_sigs = 1},
		{what = "a name handed back to the upstream, DO clear", name = "x.onion.", validating = true, edns = true, want_do = true, want_sigs = 0},
		{what = "validation off, DO clear", name = "www.example.com.", edns = true, want_do = false, want_sigs = 1},
	}
	for row in rows {
		h: Harness
		if !harness_start(t, &h, validating = row.validating) {
			return
		}
		h.cfg.special_use.onion = false
		x := Canned_Mock {
			reply = signed_reply(row.name),
		}
		out, outcome, served := harness_exchange(&h, &x, query_with(row.name, row.cd, row.edns, row.dnssec_ok))
		harness_stop(&h)
		if !testing.expectf(t, served && x.got, "%s: served %v, upstream asked %v", row.what, served, x.got) {
			continue
		}
		testing.expectf(t, outcome == .Forwarded, "%s: outcome %v", row.what, outcome)

		sent, serr := dns.decode_message(x.seen[:x.seen_len], context.temp_allocator)
		if !testing.expectf(t, serr == .None, "%s: the forwarded query does not decode: %v", row.what, serr) {
			continue
		}
		testing.expectf(t, dns.edns_do(sent) == row.want_do, "%s: DO upstream %v, want %v", row.what, dns.edns_do(sent), row.want_do)

		m, err := dns.decode_message(out, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: the answer does not decode: %v", row.what, err) {
			continue
		}
		sigs, addrs := 0, 0
		for rec in m.answer {
			#partial switch rec.type {
			case .RRSIG:
				sigs += 1
			case .A:
				addrs += 1
			}
		}
		testing.expectf(t, addrs == 1, "%s: %d addresses, want the one", row.what, addrs)
		testing.expectf(t, sigs == row.want_sigs, "%s: %d RRSIGs to the client, want %d", row.what, sigs, row.want_sigs)
		testing.expectf(t, dns.edns_do(m) == (row.edns && row.dnssec_ok), "%s: DO in the answer %v", row.what, dns.edns_do(m))
	}
	free_all(context.temp_allocator)
}
