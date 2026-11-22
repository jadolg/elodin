package server

import "core:slice"
import "core:testing"
import "elodin:dns"

/*
RFC 8145 4.1: a DNSKEY lookup for a trust anchor's zone carries the anchors' key
tags as an `edns-key-tag` option, two bytes each in network order, beside the DO
bit 4.2 asks for; a lookup given none carries no option.
*/
@(test)
test_an_upstream_query_carries_the_key_tags_it_is_given :: proc(t: ^testing.T) {
	tags := []u16{0x4f66, 0x9728}
	wire, built := upstream_query({name = ".", type = .DNSKEY, class = .IN}, true, true, context.temp_allocator, key_tags = tags)
	if !testing.expect(t, built, "the query was not built") {
		return
	}
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the query does not decode: %v", derr) {
		return
	}
	data, found := dns.find_edns_option(m, .Key_Tag)
	testing.expect(t, found, "no edns-key-tag option")
	testing.expectf(t, slice.equal(data, []u8{0x4f, 0x66, 0x97, 0x28}), "the option holds %x, want 4f669728", data)
	testing.expect(t, dns.edns_do(m), "the DO bit is not set")

	plain, plain_built := upstream_query({name = ".", type = .DNSKEY, class = .IN}, true, true, context.temp_allocator)
	if testing.expect(t, plain_built, "the query without tags was not built") {
		pm, perr := dns.decode_message(plain, context.temp_allocator)
		if testing.expectf(t, perr == .None, "the query without tags does not decode: %v", perr) {
			_, has := dns.find_edns_option(pm, .Key_Tag)
			testing.expect(t, !has, "a query given no tags carries an edns-key-tag option")
		}
	}
	free_all(context.temp_allocator)
}
