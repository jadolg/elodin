package cache

import "core:testing"
import "core:time"
import "elodin:dns"

/*
NODATA after a CNAME is a denial, and is kept like one.

RFC 2308 section 2.2 counts a NOERROR whose answer section is a redirection
chain that never reaches the type asked for as a negative response, and section
5 says one without a SOA SHOULD NOT be cached. Read by the answer section alone
it looks like data, and would be held for the chain's own TTL - up to `max_ttl`,
a day by default - with nothing at the target.
*/

@(private = "file")
Chain :: struct {
	qtype:     dns.Type,
	// TTL of the CNAME at the question name.
	cname_ttl: u32,
	// A DNAME above the question name, with the CNAME it synthesizes.
	dname:     bool,
	// An A at the target, ending the chain.
	target_a:  bool,
	// The target zone's SOA in authority: `minimum` 300, TTL 900.
	soa:       bool,
	rcode:     dns.Rcode,
}

@(private = "file")
chain_response :: proc(c: Chain) -> ([]u8, dns.Message) {
	answer: [dynamic]dns.Record
	answer.allocator = context.temp_allocator
	if c.dname {
		append(&answer, dns.Record{name = "example.com.", type = .DNAME, class = .IN, ttl = c.cname_ttl, data = dns.Rdata_Name{"example.net."}})
	}
	append(&answer, dns.Record{name = "www.example.com.", type = .CNAME, class = .IN, ttl = c.cname_ttl, data = dns.Rdata_Name{"cdn.example.net."}})
	if c.target_a {
		append(&answer, dns.Record{name = "cdn.example.net.", type = .A, class = .IN, ttl = 600, data = dns.Rdata_A{addr = {203, 0, 113, 7}}})
	}
	authority: [dynamic]dns.Record
	authority.allocator = context.temp_allocator
	if c.soa {
		append(
			&authority,
			dns.Record {
				name = "example.net.",
				type = .SOA,
				class = .IN,
				ttl = 900,
				data = dns.Rdata_SOA {
					ns = "ns.example.net.",
					mbox = "hostmaster.example.net.",
					serial = 1,
					refresh = 7200,
					retry = 3600,
					expire = 1209600,
					minimum = 300,
				},
			},
		)
	} else {
		// What an upstream that does not recurse leaves there instead.
		append(&authority, dns.Record{name = "example.com.", type = .NS, class = .IN, ttl = 86400, data = dns.Rdata_Name{"ns1.example.com."}})
	}
	m := dns.Message {
		id        = 0x4180,
		question  = []dns.Question{{name = "www.example.com.", type = c.qtype, class = .IN}},
		answer    = answer[:],
		authority = authority[:],
	}
	m.flags.qr = true
	m.flags.rcode = u8(c.rcode)
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("failed to encode the test chain")
	}
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	if derr != .None {
		panic("failed to decode the test chain")
	}
	return wire, msg
}

// How long `put` holds the entry, or false when it is not kept.
@(private = "file")
held_for :: proc(c: ^Cache, ch: Chain) -> (time.Duration, bool) {
	wire, msg := chain_response(ch)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "www.example.com.", ch.qtype, .IN, false)
	if !put(c, key, wire, msg) {
		return 0, false
	}
	e := c.entries[key]
	return time.diff(e.inserted, e.expires), true
}

@(test)
test_a_bare_cname_without_a_soa_is_not_cached :: proc(t: ^testing.T) {
	// A `min_ttl` floor, so the refusal is the missing SOA and not a zero
	// lifetime the floor would lift.
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, min_ttl = 60, negative_ttl = 300})
	defer destroy(c)

	held, kept := held_for(c, {qtype = .A, cname_ttl = 86400})
	testing.expectf(t, !kept, "a bare CNAME with no SOA was held for %v", held)
	held, kept = held_for(c, {qtype = .AAAA, cname_ttl = 86400, dname = true})
	testing.expectf(t, !kept, "a bare DNAME chain with no SOA was held for %v", held)
	// Asked for the DNAME type: the one above the name is the redirection, not
	// the answer (see `answers_the_question`).
	held, kept = held_for(c, {qtype = .DNAME, cname_ttl = 86400, dname = true})
	testing.expectf(t, !kept, "a DNAME question answered by the DNAME above it was held for %v", held)

	// And a DNAME above a later link, not the question name: it synthesized
	// the second CNAME, so it is the chain and not the answer.
	later := dns.Message {
		question = []dns.Question{{name = "www.example.com.", type = .DNAME, class = .IN}},
		answer = []dns.Record {
			{name = "www.example.com.", type = .CNAME, class = .IN, ttl = 86400, data = dns.Rdata_Name{"a.example.org."}},
			{name = "example.org.", type = .DNAME, class = .IN, ttl = 86400, data = dns.Rdata_Name{"example.net."}},
			{name = "a.example.org.", type = .CNAME, class = .IN, ttl = 86400, data = dns.Rdata_Name{"a.example.net."}},
		},
	}
	later.flags.qr = true
	wire, _, err := dns.encode_message(later, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "www.example.com.", .DNAME, .IN, false)
	testing.expect(t, !put(c, key, wire, later), "a DNAME question answered by a DNAME above a later link was cached")
	free_all(context.temp_allocator)
}

@(test)
test_a_bare_cname_with_a_soa_is_held_for_the_soa_figure :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400})
	defer destroy(c)

	held, kept := held_for(c, {qtype = .A, cname_ttl = 86400, soa = true})
	testing.expect(t, kept, "NODATA after a CNAME with its SOA was not cached")
	testing.expect_value(t, held, 300 * time.Second)

	capped := make_cache(Options{max_entries = 8, max_ttl = 86400, negative_ttl = 60})
	defer destroy(capped)
	held, kept = held_for(capped, {qtype = .AAAA, cname_ttl = 86400, dname = true, soa = true})
	testing.expect(t, kept, "NODATA after a DNAME with its SOA was not cached")
	testing.expect_value(t, held, 60 * time.Second)
	free_all(context.temp_allocator)
}

/*
And not past the chain it carries. The entry hands the CNAME back with its TTL
counted down, so outliving it would serve the record at zero, or at `min_ttl`,
for the rest of the SOA figure - on NODATA and NXDOMAIN alike.
*/
@(test)
test_a_denial_after_a_cname_does_not_outlive_the_cname :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, negative_ttl = 300})
	defer destroy(c)

	held, kept := held_for(c, {qtype = .A, cname_ttl = 30, soa = true})
	testing.expect(t, kept, "NODATA after a CNAME with its SOA was not cached")
	testing.expect_value(t, held, 30 * time.Second)
	held, kept = held_for(c, {qtype = .A, cname_ttl = 30, soa = true, rcode = .NX_Domain})
	testing.expect(t, kept, "NXDOMAIN after a CNAME with its SOA was not cached")
	testing.expect_value(t, held, 30 * time.Second)
	free_all(context.temp_allocator)
}

// The chain that does reach the type, and the CNAME asked for by name, are
// answers and need no SOA.
@(test)
test_a_chain_that_answers_is_not_a_denial :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, negative_ttl = 60})
	defer destroy(c)

	held, kept := held_for(c, {qtype = .A, cname_ttl = 3600, target_a = true})
	testing.expect(t, kept, "a CNAME chain ending in the A asked for was not cached")
	testing.expect_value(t, held, 600 * time.Second)
	held, kept = held_for(c, {qtype = .CNAME, cname_ttl = 3600})
	testing.expect(t, kept, "the CNAME asked for was not cached")
	testing.expect_value(t, held, 3600 * time.Second)
	held, kept = held_for(c, {qtype = .ANY, cname_ttl = 3600})
	testing.expect(t, kept, "a CNAME in answer to ANY was not cached")
	testing.expect_value(t, held, 3600 * time.Second)

	// A DNAME owned at the question name is the data asked for.
	at := dns.Message {
		question = []dns.Question{{name = "example.com.", type = .DNAME, class = .IN}},
		answer = []dns.Record{{name = "example.com.", type = .DNAME, class = .IN, ttl = 3600, data = dns.Rdata_Name{"example.net."}}},
	}
	at.flags.qr = true
	wire, _, err := dns.encode_message(at, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "example.com.", .DNAME, .IN, false)
	testing.expect(t, put(c, key, wire, at), "the DNAME asked for, at the question name, was not cached")
	free_all(context.temp_allocator)
}
