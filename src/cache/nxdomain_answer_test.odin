package cache

import "core:testing"
import "elodin:dns"

/*
A name error that carries data is not remembered.

RFC 2308 section 2.1 lets an NXDOMAIN's answer section hold CNAME records and
nothing else - the rcode speaks for the end of the chain. Anything else there is
the header contradicting the section beneath it, and the way it arises is an
attacker rewriting the low nibble of byte 3 of a genuine answer: the records and
their signatures are untouched, so a validator that reads only the records finds
nothing wrong. `src/dnssec` refuses that shape outright now; this is the same
shape stopped one layer out, which is the layer that decides whether one packet
takes a name down for every client or only for the one that asked.

Cached, it is much the worse of the two. The lifetime for a name error is read
from the SOA beside it, a positive answer never carried one, and the fallback is
`negative_ttl` - so a five-minute authenticated absence, by default, for a name
whose records were in the packet.
*/

@(private = "file")
nx_with_answer :: proc(
	name: string,
	type: dns.Type,
	qtype := dns.Type.A,
	allocator := context.allocator,
) -> (
	[]u8,
	dns.Message,
) {
	data: dns.Record_Data
	#partial switch type {
	case .CNAME:
		data = dns.Rdata_Name{name = "target.example.net."}
	case:
		data = dns.Rdata_A{addr = {203, 0, 113, 7}}
	}
	m := dns.Message {
		id        = 0x3333,
		question  = []dns.Question{{name = name, type = qtype, class = .IN}},
		answer    = []dns.Record{{name = name, type = type, class = .IN, ttl = 300, data = data}},
		authority = []dns.Record {
			{
				name = "example.com.",
				type = .SOA,
				class = .IN,
				ttl = 3600,
				data = dns.Rdata_SOA {
					ns = "ns.example.com.",
					mbox = "hostmaster.example.com.",
					serial = 1,
					refresh = 7200,
					retry = 3600,
					expire = 1209600,
					minimum = 600,
				},
			},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		panic("failed to encode the test nxdomain")
	}
	decoded, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		panic("failed to decode the test nxdomain")
	}
	return wire, decoded
}

@(test)
test_nxdomain_carrying_data_is_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer destroy(c)

	wire, msg := nx_with_answer("mail.example.com.", .A, allocator = context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for_nx(kb[:], "mail.example.com.")

	testing.expect(t, !put(c, key, wire, msg), "an NXDOMAIN holding an A record was stored")
	testing.expect_value(t, len_entries(c), 0)

	// And nothing is served for it either, which is the harm: every later
	// client asking that question would have been told the name is not there.
	_, _, hit := get(c, key, context.temp_allocator)
	testing.expect(t, !hit, "a refused NXDOMAIN was served from the cache")
	free_all(context.temp_allocator)
}

@(test)
test_nxdomain_after_a_cname_is_still_cached :: proc(t: ^testing.T) {
	// The shape RFC 2308 allows, and the everyday one: the chain is real, and
	// the rcode is about the name it ends at.
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer destroy(c)

	wire, msg := nx_with_answer("www.example.com.", .CNAME, allocator = context.temp_allocator)
	kb: [KEY_MAX]u8
	key := key_for_nx(kb[:], "www.example.com.")

	testing.expect(t, put(c, key, wire, msg), "an NXDOMAIN after a CNAME should still be cached")
	testing.expect_value(t, len_entries(c), 1)
	free_all(context.temp_allocator)
}

/*
Unless the CNAME is what was asked about.

The exemption above is for a redirection, and a redirection is only what a CNAME
is while the client wanted something else: ask for the CNAME itself and RFC 1034
section 4.3.2 step 3a stops the walk there, so the record is data at the very
name the rcode denies. Entries are keyed by type, so what one spoofed packet
over a genuine `dig CNAME` answer would take away is `name/CNAME` for the whole
of `negative_ttl`.
*/
@(test)
test_nxdomain_over_the_cname_that_was_asked_for_is_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer destroy(c)

	wire, msg := nx_with_answer("www.example.com.", .CNAME, .CNAME, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "www.example.com.", .CNAME, .IN, false)

	testing.expect(t, !put(c, key, wire, msg), "an NXDOMAIN over the CNAME that was asked for was stored")
	testing.expect_value(t, len_entries(c), 0)
	free_all(context.temp_allocator)
}

/*
A signature is not the answer to a question about signatures.

The exemption above is about a redirection standing where the answer should be,
and only two record types can be one. An RRSIG is not data at any name (RFC 4035
section 2.2): it rides on the record it covers, and the record it covers here is
the CNAME. So `dig RRSIG` at a name that is a CNAME gets the everyday
NXDOMAIN-after-a-CNAME with its own signature attached - the shape RFC 2308
section 2.1 allows - and reading the RRSIG as "the type that was asked for"
would refuse to remember any of them, sending every repeat of that question back
to the upstream.
*/
@(test)
test_nxdomain_after_a_cname_is_cached_for_an_rrsig_question :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer destroy(c)

	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.example.com.",
		type  = .CNAME,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_Name{name = "target.example.net."},
	}
	// The signature's bytes are never read here - what matters is a record of
	// type RRSIG sitting at the name that was asked about.
	answer[1] = dns.Record {
		name  = "www.example.com.",
		type  = .RRSIG,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_Raw{data = make([]u8, 24, context.temp_allocator)},
	}
	m := dns.Message {
		id       = 0x3334,
		question = []dns.Question{{name = "www.example.com.", type = .RRSIG, class = .IN}},
		answer   = answer,
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	testing.expect(t, err == .None, "the test nxdomain did not encode")
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, derr == .None, "the test nxdomain did not decode")

	kb: [KEY_MAX]u8
	key := make_key(kb[:], "www.example.com.", .RRSIG, .IN, false)
	testing.expect(t, put(c, key, wire, msg), "an NXDOMAIN after a signed CNAME should still be cached")
	testing.expect_value(t, len_entries(c), 1)
	free_all(context.temp_allocator)
}

/*
And a redirection reached from somewhere else is not the answer either.

The DNAME that covers `a.sub.example.com.` sits at `sub.example.com.`, an
ancestor of the name asked about, so a `QTYPE=DNAME` question under a DNAME is
the ordinary redirection shape and not a contradiction. Comparing the type alone
would cost the entry for every one of them.
*/
@(test)
test_nxdomain_over_a_dname_above_the_queried_name_is_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer destroy(c)

	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "sub.example.com.",
		type  = .DNAME,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_Name{name = "elsewhere.example.net."},
	}
	m := dns.Message {
		id       = 0x3335,
		question = []dns.Question{{name = "a.sub.example.com.", type = .DNAME, class = .IN}},
		answer   = answer,
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	testing.expect(t, err == .None, "the test nxdomain did not encode")
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, derr == .None, "the test nxdomain did not decode")

	kb: [KEY_MAX]u8
	key := make_key(kb[:], "a.sub.example.com.", .DNAME, .IN, false)
	testing.expect(t, put(c, key, wire, msg), "an NXDOMAIN under a DNAME should still be cached")
	testing.expect_value(t, len_entries(c), 1)
	free_all(context.temp_allocator)
}

@(private = "file")
key_for_nx :: proc(buf: []u8, name: string) -> string {
	return make_key(buf, name, .A, .IN, false)
}
