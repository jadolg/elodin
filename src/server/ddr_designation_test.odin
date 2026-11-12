package server

import "core:testing"
import "core:net"
import "elodin:config"
import "elodin:dns"

/*
The designation this server mints for `_dns.resolver.arpa` (RFC 9462 section 4,
with the SvcParams of RFC 9461). Which listeners are designated is set by hand
here; `test_reload_tls_designates_only_while_the_certificate_covers_ddr_name`
covers how the certificate sets it.
*/

@(private = "file")
designating_server :: proc(cfg: ^config.Config) -> Server {
	s := local_server(cfg)
	cfg.ddr.name = "dns.example."
	cfg.listeners.dot.enabled = true
	cfg.listeners.doh.enabled = true
	cfg.listeners.doh.port = 8443
	s.ddr = {dot = true, doh = true}
	return s
}

// The DoH designation's SvcParams for `designating_server`: alpn=h2,http/1.1
// port=8443 dohpath=/dns-query{?dns}, keys in order.
@(private = "file")
DOH_PARAMS :: "\x00\x01\x00\x0c\x02h2\x08http/1.1" + "\x00\x03\x00\x02\x20\xfb" + "\x00\x07\x00\x10/dns-query{?dns}"

// `name`'s `type` asked of `s` with RD set, and `opt` on it when there is one;
// a zero message, and a failed case, when nothing readable came back.
@(private = "file")
ask :: proc(t: ^testing.T, s: ^Server, name: string, type: dns.Type, opt: Maybe(dns.Record) = nil, loc := #caller_location) -> dns.Message {
	out, _, ok := handle_query(s, test_query(name, type, id = 0x4243, opt = opt), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expectf(t, ok, "%s %v went unanswered", name, type, loc = loc) {
		return {}
	}
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expectf(t, derr == .None, "the answer to %s %v does not decode: %v", name, type, derr, loc = loc)
	return decoded
}

// `n` AAAA answers for the designated name, more than a 512-byte answer holds.
@(private = "file")
rewrite_many_addresses :: proc(cfg: ^config.Config, n: int) {
	many := make([]config.Rewrite_Answer, n, context.temp_allocator)
	for &a, i in many {
		a = {kind = .AAAA, v6 = {0 = 0xfd, 15 = u8(i)}}
	}
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = {domain = "dns.example.", ttl = 60, answers = many}
	cfg.rewrites = rules
}

@(test)
test_ddr_designates_each_encrypted_listener :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)

	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, dns.rcode_of(resp), dns.Rcode.No_Error)
	if !testing.expect_value(t, len(resp.answer), 2) {
		return
	}
	testing.expect_value(t, len(resp.authority), 0)

	dot := resp.answer[0].data.(dns.Rdata_SVCB)
	testing.expect_value(t, dot.priority, 1)
	testing.expect_value(t, dot.target, "dns.example.")
	// alpn=dot and no port: 853 is the default, and `port` is automatically
	// mandatory (RFC 9461 section 4.2), so writing it costs clients that lack it.
	testing.expect(t, string(dot.params) == "\x00\x01\x00\x04\x03dot", "DoT SvcParams")

	doh := resp.answer[1].data.(dns.Rdata_SVCB)
	testing.expect_value(t, doh.priority, 1)
	testing.expect_value(t, doh.target, "dns.example.")
	testing.expectf(t, string(doh.params) == DOH_PARAMS, "DoH SvcParams: % x", doh.params)

	free_all(context.temp_allocator)
}

// No covering certificate, no designation: NODATA, as with no name at all.
@(test)
test_ddr_designates_nothing_without_a_covered_listener :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	s.ddr = {}

	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.answer), 0)
	testing.expect_value(t, len(resp.authority), 1)

	s.ddr = {doh = true}
	resp = ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	if testing.expect_value(t, len(resp.answer), 1) {
		doh := resp.answer[0].data.(dns.Rdata_SVCB)
		testing.expectf(t, string(doh.params) == DOH_PARAMS, "the DoH designation alone has SvcParams % x", doh.params)
	}

	free_all(context.temp_allocator)
}

// Only the SVCB question at `_dns.resolver.arpa` is a DDR probe; the rest of the
// zone stays NODATA.
@(test)
test_ddr_designates_only_the_svcb_probe :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)

	probes := []struct {
		name: string,
		type: dns.Type,
	}{{"_dns.resolver.arpa.", .A}, {"_dns.resolver.arpa.", .HTTPS}, {"resolver.arpa.", .SVCB}, {"x._dns.resolver.arpa.", .SVCB}}
	for p in probes {
		resp := ask(t, &s, p.name, p.type)
		testing.expectf(t, len(resp.answer) == 0, "%s %v was designated", p.name, p.type)
		testing.expectf(t, len(resp.authority) == 1, "%s %v has no SOA", p.name, p.type)
	}
	resp := ask(t, &s, "_DNS.Resolver.ARPA.", .SVCB)
	testing.expect_value(t, len(resp.answer), 2)

	free_all(context.temp_allocator)
}

/*
The addresses for the designated name (RFC 9462 section 4 SHOULD) come from the
rule that claims it in `rewrites`, with that table's precedence: a rule that has
nothing to say about addresses is passed over, as `apply_rewrite` passes it.
*/
@(test)
test_ddr_additional_addresses_come_from_the_rewrite :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	rules := []config.Rewrite {
		{domain = "dns.example.", ttl = 60, answers = []config.Rewrite_Answer{{kind = .MX, name = "mx.example.", preference = 10}}},
		{
			domain = "dns.example.",
			ttl = 60,
			answers = []config.Rewrite_Answer{{kind = .A, v4 = {192, 168, 1, 2}}, {kind = .AAAA, v6 = {0 = 0xfd, 15 = 2}}},
		},
	}
	cfg.rewrites = rules

	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.answer), 2)
	if !testing.expect_value(t, len(resp.additional), 2) {
		return
	}
	testing.expect_value(t, resp.additional[0].name, "dns.example.")
	testing.expect_value(t, resp.additional[0].data.(dns.Rdata_A).addr, [4]u8{192, 168, 1, 2})
	testing.expect_value(t, resp.additional[1].type, dns.Type.AAAA)

	free_all(context.temp_allocator)
}

// Addresses that will not fit are left out; the designation still arrives.
@(test)
test_ddr_drops_the_addresses_before_the_designation :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	rewrite_many_addresses(&cfg, 40)

	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.answer), 2)
	testing.expectf(t, len(resp.additional) < 40, "all %d addresses fit in 512 bytes", len(resp.additional))
	testing.expect(t, !resp.flags.tc, "the designation came back truncated")

	free_all(context.temp_allocator)
}

/*
The addresses are read through the same walk `apply_rewrite` answers by, so a
client is not handed one address in the designation and another when it asks:
the MX-only rule is passed over, the wildcard alias cannot answer a name a rule
above held records for, and the wildcard address is what an A query gets.
*/
@(test)
test_ddr_addresses_follow_the_rewrite_precedence :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	cfg.ddr.name = "dns.lan."
	cfg.rewrites = []config.Rewrite {
		{domain = "dns.lan.", ttl = 60, answers = []config.Rewrite_Answer{{kind = .MX, name = "mx.lan.", preference = 10}}},
		{domain = "lan.", wildcard = true, ttl = 60, answers = []config.Rewrite_Answer{{kind = .CNAME, name = "elsewhere.example."}}},
		{domain = "lan.", wildcard = true, ttl = 60, answers = []config.Rewrite_Answer{{kind = .A, v4 = {10, 0, 0, 5}}}},
	}

	direct := ask(t, &s, "dns.lan.", .A)
	if !testing.expect_value(t, len(direct.answer), 1) {
		return
	}
	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	if testing.expect_value(t, len(resp.additional), 1) {
		testing.expect_value(t, resp.additional[0].data.(dns.Rdata_A).addr, direct.answer[0].data.(dns.Rdata_A).addr)
	}

	// A rule that sinks the name has no address of the resolver to give.
	cfg.rewrites = []config.Rewrite{{domain = "dns.lan.", ttl = 60, answers = []config.Rewrite_Answer{{kind = .Block}}}}
	resp = ask(t, &s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.additional), 0)
	testing.expect_value(t, len(resp.answer), 2)

	free_all(context.temp_allocator)
}

// `::` takes IPv4 only while `net.ipv6.bindv6only` is off.
@(test)
test_ddr_wildcard_v6_listener_takes_v4_unless_v6only :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.listeners.dot.enabled = true
	cfg.listeners.dot.address = "::"
	v4 := net.Address(net.IP4_Address{192, 168, 1, 2})
	testing.expect(t, ddr_bound_to(cfg.listeners.dot, v4, v6only = false), "a dual-stack :: listener does not take IPv4")
	testing.expect(t, !ddr_bound_to(cfg.listeners.dot, v4, v6only = true), "a v6only :: listener was said to take IPv4")
	testing.expect(t, ddr_bound_to(cfg.listeners.dot, net.IP6_Loopback, v6only = true), ":: does not take IPv6")
	cfg.listeners.dot.address = "10.0.0.1"
	testing.expect(t, !ddr_bound_to(cfg.listeners.dot, v4, v6only = false), "a listener on another address was said to take this one")
}

/*
The addresses go in behind the client's OPT record, not over it, so the encoder
keeps that record's room as it fills the section: a client that asked with EDNS
gets its OPT record back however many addresses the rewrite holds.
*/
@(test)
test_ddr_addresses_keep_the_opt_record :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	rewrite_many_addresses(&cfg, 40)

	resp := ask(t, &s, "_dns.resolver.arpa.", .SVCB, dns.make_opt(1232, false))

	testing.expect_value(t, len(resp.answer), 2)
	testing.expect(t, dns.edns_present(resp), "the addresses took the OPT record's place")
	testing.expect(t, len(resp.additional) > 1, "no address came back")
	testing.expect(t, !resp.flags.tc, "the designation came back truncated")

	free_all(context.temp_allocator)
}
