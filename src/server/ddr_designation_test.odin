package server

import "core:testing"
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
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.ddr.name = "dns.example."
	cfg.listeners.dot.enabled = true
	cfg.listeners.doh.enabled = true
	cfg.listeners.doh.port = 8443
	s := Server{cfg = cfg}
	s.ddr = {dot = true, doh = true}
	return s
}

@(private = "file")
ask :: proc(s: ^Server, name: string, type: dns.Type) -> dns.Message {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{id = 0x4243, question = questions}
	msg.flags.rd = true
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	out, _, _ := handle_query(s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	decoded, _ := dns.decode_message(out, context.temp_allocator)
	return decoded
}

@(test)
test_ddr_designates_each_encrypted_listener :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)

	resp := ask(&s, "_dns.resolver.arpa.", .SVCB)
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
	// alpn=h2,http/1.1 port=8443 dohpath=/dns-query{?dns}, keys in order.
	want := "\x00\x01\x00\x0c\x02h2\x08http/1.1" + "\x00\x03\x00\x02\x20\xfb" + "\x00\x07\x00\x10/dns-query{?dns}"
	testing.expectf(t, string(doh.params) == want, "DoH SvcParams: % x", doh.params)

	free_all(context.temp_allocator)
}

// No covering certificate, no designation: NODATA, as with no name at all.
@(test)
test_ddr_designates_nothing_without_a_covered_listener :: proc(t: ^testing.T) {
	cfg: config.Config
	s := designating_server(&cfg)
	s.ddr = {}

	resp := ask(&s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.answer), 0)
	testing.expect_value(t, len(resp.authority), 1)

	s.ddr = {doh = true}
	resp = ask(&s, "_dns.resolver.arpa.", .SVCB)
	if testing.expect_value(t, len(resp.answer), 1) {
		testing.expect_value(t, resp.answer[0].data.(dns.Rdata_SVCB).params[5], u8('h'))
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
		resp := ask(&s, p.name, p.type)
		testing.expectf(t, len(resp.answer) == 0, "%s %v was designated", p.name, p.type)
		testing.expectf(t, len(resp.authority) == 1, "%s %v has no SOA", p.name, p.type)
	}
	resp := ask(&s, "_DNS.Resolver.ARPA.", .SVCB)
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

	resp := ask(&s, "_dns.resolver.arpa.", .SVCB)
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
	many := make([]config.Rewrite_Answer, 40, context.temp_allocator)
	for &a, i in many {
		a = {kind = .AAAA, v6 = {0 = 0xfd, 15 = u8(i)}}
	}
	cfg.rewrites = []config.Rewrite{{domain = "dns.example.", ttl = 60, answers = many}}

	resp := ask(&s, "_dns.resolver.arpa.", .SVCB)
	testing.expect_value(t, len(resp.answer), 2)
	testing.expectf(t, len(resp.additional) < 40, "all %d addresses fit in 512 bytes", len(resp.additional))
	testing.expect(t, !resp.flags.tc, "the designation came back truncated")

	free_all(context.temp_allocator)
}
