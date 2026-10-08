package dns

import "core:fmt"
import "core:testing"

/*
`peek_referral` against RFC 2308 section 2.2's shapes: type 4 is a referral,
types 1 to 3 are NODATA, and nothing with an answer or another rcode is either
(issue #410).
*/
@(private = "file")
referral_wire :: proc(rcode: Rcode, answer, authority: []Record) -> []u8 {
	msg := Message {
		question  = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		answer    = answer,
		authority = authority,
	}
	msg.flags.qr = true
	msg.flags.rcode = u8(rcode)
	wire, _, err := encode_message(msg, context.temp_allocator)
	assert(err == .None)
	return wire
}

@(test)
test_peek_referral_reads_the_authority_section :: proc(t: ^testing.T) {
	ns := Record{name = "example.com.", type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.example.com."}}
	soa := Record {
		name  = "example.com.",
		type  = .SOA,
		class = .IN,
		ttl   = 300,
		data  = Rdata_SOA{ns = "ns1.example.com.", mbox = "h.example.com.", minimum = 60},
	}
	a := Record{name = "www.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{{1, 2, 3, 4}}}
	glue := Record{name = "ns1.example.com.", type = .A, class = .IN, ttl = 60, data = Rdata_A{{1, 2, 3, 4}}}

	testing.expect(t, peek_referral(referral_wire(.No_Error, nil, {ns})), "NS alone: type 4, a referral")
	testing.expect(t, peek_referral(referral_wire(.No_Error, nil, {glue, ns})), "NS after another record")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {soa, ns})), "SOA and NS: type 1 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {ns, soa})), "NS then SOA: type 1 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, {soa})), "SOA alone: type 2 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, nil, nil)), "empty authority: type 3 NODATA")
	testing.expect(t, !peek_referral(referral_wire(.No_Error, {a}, {ns})), "an answer beside NS is an answer")
	testing.expect(t, !peek_referral(referral_wire(.NX_Domain, nil, {ns})), "NXDOMAIN is not a referral")
	testing.expect(t, !peek_referral(referral_wire(.Serv_Fail, nil, {ns})), "SERVFAIL is not a referral")
	authoritative := referral_wire(.No_Error, nil, {ns})
	authoritative[2] |= 0x04
	testing.expect(t, !peek_referral(authoritative), "AA set: an authority's SOA-less NODATA, not a referral")

	// The composed rcode: BADVERS is 16, a zero low nibble under an OPT.
	opt := make_opt(1232, false, 1)
	badvers := Message {
		question   = []Question{{name = "www.example.com.", type = .A, class = .IN}},
		authority  = []Record{ns},
		additional = []Record{opt},
	}
	badvers.flags.qr = true
	wire, _, err := encode_message(badvers, context.temp_allocator)
	testing.expect_value(t, err, Encode_Error.None)
	testing.expect_value(t, peek_rcode(wire), Rcode(16))
	testing.expect(t, !peek_referral(wire), "BADVERS is not a NOERROR")

	// Truncated anywhere in the walk: not a referral, and no read past the end.
	full := referral_wire(.No_Error, nil, {ns})
	for n in 0 ..< len(full) {
		testing.expectf(t, !peek_referral(full[:n]), "cut at %d of %d read as a referral", n, len(full))
	}
	free_all(context.temp_allocator)
}

/*
The partial shape: a CNAME chain that ends at a name the server does not hold,
with that name's delegation in authority (RFC 2308 section 2.1's REFERRAL
RESPONSE; issue #451). An authority's own apex NS beside a CNAME out of its zone
is not one.
*/
@(test)
test_peek_referral_follows_a_cname_chain :: proc(t: ^testing.T) {
	cname :: proc(owner, target: string) -> Record {
		return Record{name = owner, type = .CNAME, class = .IN, ttl = 60, data = Rdata_Name{target}}
	}
	ns :: proc(zone: string) -> Record {
		return Record{name = zone, type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.elsewhere."}}
	}
	wire :: proc(answer, authority: []Record, aa := false) -> []u8 {
		msg := Message {
			question  = []Question{{name = "www.corp.", type = .A, class = .IN}},
			answer    = answer,
			authority = authority,
		}
		msg.flags.qr = true
		msg.flags.aa = aa
		out, _, err := encode_message(msg, context.temp_allocator)
		assert(err == .None)
		return out
	}
	soa := Record {
		name  = "sub.corp.",
		type  = .SOA,
		class = .IN,
		ttl   = 300,
		data  = Rdata_SOA{ns = "ns1.sub.corp.", mbox = "h.sub.corp.", minimum = 60},
	}
	addr := Record{name = "host.sub.corp.", type = .A, class = .IN, ttl = 60, data = Rdata_A{{192, 0, 2, 1}}}
	to_sub := cname("www.corp.", "host.sub.corp.")

	testing.expect(t, peek_referral(wire({to_sub}, {ns("sub.corp.")})), "CNAME, then the target's delegation")
	testing.expect(t, peek_referral(wire({to_sub}, {ns("sub.corp.")}, aa = true)), "AA over the alias says nothing of the target")
	testing.expect(
		t,
		peek_referral(wire({cname("www.corp.", "a.corp."), cname("a.corp.", "host.sub.corp.")}, {ns("sub.corp.")})),
		"a chain of two, then the target's delegation",
	)
	testing.expect(t, peek_referral(wire({to_sub}, {ns("corp."), ns("sub.corp.")})), "own apex NS beside the delegation")

	testing.expect(
		t,
		!peek_referral(wire({cname("www.corp.", "ghs.googlehosted.com.")}, {ns("corp.")}, aa = true)),
		"an authority's own apex NS beside a CNAME out of its zone is its whole answer",
	)
	testing.expect(t, !peek_referral(wire({to_sub, addr}, {ns("sub.corp.")})), "the chain ends in data: an answer")
	testing.expect(t, !peek_referral(wire({to_sub}, {ns("sub.corp."), soa})), "a SOA: the target's NODATA")
	testing.expect(t, !peek_referral(wire({to_sub}, nil)), "no NS at all")
	testing.expect(t, !peek_referral(wire({to_sub}, {ns("other.corp.")})), "NS for somewhere the chain does not go")
	testing.expect(t, !peek_referral(wire({cname("x.corp.", "host.sub.corp.")}, {ns("sub.corp.")})), "a CNAME not on the chain from the question")

	// A loop ends, and goes nowhere the NS are.
	looped := wire({cname("www.corp.", "a.corp."), cname("a.corp.", "www.corp.")}, {ns("sub.corp.")})
	testing.expect(t, !peek_referral(looped), "a CNAME loop")
	free_all(context.temp_allocator)
}

/*
A CNAME on the chain whose target cannot be read - here one that does not end
where its RDLENGTH says (issue #299) - leaves where the chain goes unknown, and
with NS and no SOA beside it that is answered as a referral, not passed on as
the answer it claims to be: "cannot tell" is never "serve it", as in
`cloaked_chain_target`. Nor is there a target to hand the reply on to.
*/
@(test)
test_peek_referral_does_not_pass_an_unreadable_link :: proc(t: ^testing.T) {
	target := []u8{4, 'h', 'o', 's', 't', 3, 's', 'u', 'b', 4, 'c', 'o', 'r', 'p', 0, 0xde, 0xad}
	msg := Message {
		question  = []Question{{name = "www.corp.", type = .A, class = .IN}},
		answer    = []Record{{name = "www.corp.", type = .CNAME, class = .IN, ttl = 60, data = Rdata_Raw{target}}},
		authority = []Record{{name = "sub.corp.", type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.elsewhere."}}},
	}
	msg.flags.qr = true
	wire, _, err := encode_message(msg, context.temp_allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	// The premise: the link decodes, and only as raw RDATA.
	decoded, derr := decode_message(wire, context.temp_allocator)
	if !testing.expect_value(t, derr, Decode_Error.None) || !testing.expect_value(t, len(decoded.answer), 1) {
		return
	}
	_, is_raw := decoded.answer[0].data.(Rdata_Raw)
	testing.expect(t, is_raw, "the overlong CNAME decoded as a name")

	testing.expect(t, peek_referral(wire), "a referral behind an unreadable CNAME passed as an answer")
	_, aliased := peek_alias_target(wire)
	testing.expect(t, !aliased, "a target was read past an unreadable CNAME")

	// A readable CNAME at the same owner, listed first and into the asked
	// name's own zone, does not make the unreadable one beside it readable.
	decoy := msg
	decoy.answer = []Record {
		{name = "www.corp.", type = .CNAME, class = .IN, ttl = 60, data = Rdata_Name{"web.corp."}},
		msg.answer[0],
	}
	decoy.authority = []Record{{name = "corp.", type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.corp."}}}
	dwire, _, eerr := encode_message(decoy, context.temp_allocator)
	if testing.expect_value(t, eerr, Encode_Error.None) {
		testing.expect(t, peek_referral(dwire), "an unreadable CNAME behind a readable one passed as an answer")
		_, decoy_aliased := peek_alias_target(dwire)
		testing.expect(t, !decoy_aliased, "a target was read beside an unreadable CNAME")
	}
	free_all(context.temp_allocator)
}


/*
The alias branch's bounds: a chain past `MAX_ALIAS_REFERRAL_RECORDS` records in
either section is left as an answer rather than decoded, a CNAME that was asked
for is the data, and a cut anywhere in the partial shape reads past nothing.
*/
@(test)
test_peek_referral_bounds_the_alias_branch :: proc(t: ^testing.T) {
	cname :: proc(owner, target: string) -> Record {
		return Record{name = owner, type = .CNAME, class = .IN, ttl = 60, data = Rdata_Name{target}}
	}
	ns :: proc(zone: string) -> Record {
		return Record{name = zone, type = .NS, class = .IN, ttl = 3600, data = Rdata_Name{"ns1.elsewhere."}}
	}
	wire :: proc(answer, authority: []Record, qtype := Type.A) -> []u8 {
		msg := Message {
			question  = []Question{{name = "www.corp.", type = qtype, class = .IN}},
			answer    = answer,
			authority = authority,
		}
		msg.flags.qr = true
		out, _, err := encode_message(msg, context.temp_allocator)
		assert(err == .None)
		return out
	}
	delegation := []Record{ns("sub.corp.")}

	// A chain of exactly the limit is followed; one record more is not.
	names := make([]string, MAX_ALIAS_REFERRAL_RECORDS + 1, context.temp_allocator)
	names[0] = "www.corp."
	for i in 1 ..< len(names) - 1 {
		names[i] = fmt.tprintf("l%d.corp.", i)
	}
	names[len(names) - 1] = "host.sub.corp."
	links := make([]Record, len(names) - 1, context.temp_allocator)
	for i in 0 ..< len(links) {
		links[i] = cname(names[i], names[i + 1])
	}
	testing.expect(t, peek_referral(wire(links, delegation)), "a chain at the limit is a referral")
	longer := make([]Record, len(links) + 1, context.temp_allocator)
	copy(longer, links)
	longer[len(links)] = cname("spare.corp.", "host.sub.corp.")
	testing.expect(t, !peek_referral(wire(longer, delegation)), "a chain past the limit is left as an answer")
	crowded := make([]Record, MAX_ALIAS_REFERRAL_RECORDS + 1, context.temp_allocator)
	for &r in crowded {
		r = ns("sub.corp.")
	}
	to_sub := []Record{cname("www.corp.", "host.sub.corp.")}
	testing.expect(t, peek_referral(wire(to_sub, crowded[:MAX_ALIAS_REFERRAL_RECORDS])), "an authority at the limit is read")
	testing.expect(t, !peek_referral(wire(to_sub, crowded)), "an authority past the limit is left as an answer")
	testing.expect(t, !peek_referral(wire(to_sub, delegation, qtype = .CNAME)), "a CNAME asked for is the answer")
	testing.expect(t, !peek_referral(wire(to_sub, delegation, qtype = .ANY)), "a CNAME answering ANY is the answer")

	full := wire(to_sub, delegation)
	for n in 0 ..< len(full) {
		testing.expectf(t, !peek_referral(full[:n]), "cut at %d of %d read as a referral", n, len(full))
	}
	free_all(context.temp_allocator)
}
