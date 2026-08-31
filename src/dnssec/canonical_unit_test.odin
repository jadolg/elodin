package dnssec

import "core:mem"
import "core:testing"
import "elodin:dns"

/*
Canonical form and canonical order, RFC 4034 section 6.

This is the one part of DNSSEC where being merely self-consistent is not enough.
The signer computed these bytes; we recompute them; if the two disagree by a
single octet every signature in the zone fails, and the failure looks exactly
like an attack. So the golden vectors below were computed outside this
implementation, from the rules in the RFC, and the structural tests pin the
three transformations a validator must perform and the several it must not:

  - the owner name is lowercased, and so are the domain names inside the RDATA
    of the types RFC 4034 section 6.2 lists - but not the ones it does not, and
    RFC 6840 section 5.1 took NSEC's next name off that list;
  - the TTL written is the signature's original TTL, never the one the record
    arrived with, which is what stops a caching resolver's countdown from
    invalidating a signature;
  - the RRset is sorted by RDATA and duplicates are dropped, so the order the
    records happened to arrive in cannot change the result.
*/

@(private = "file")
golden_sig :: proc(type_covered: dns.Type) -> Rrsig {
	return Rrsig {
		type_covered = type_covered,
		algorithm = ALG_ECDSAP256SHA256,
		labels = 3,
		original_ttl = 3600,
		expiration = 0x6a00_0000,
		inception = 0x6900_0000,
		key_tag = 0x1234,
		signer = "example.com.",
	}
}

@(private = "file")
a_record :: proc(name: string, last: u8, ttl: u32 = 3600) -> dns.Record {
	return dns.Record {
		name = name,
		type = .A,
		class = .IN,
		ttl = ttl,
		data = dns.Rdata_A{addr = {192, 0, 2, last}},
	}
}

@(private = "file")
expect_hex :: proc(t: ^testing.T, got: []u8, want_hex: string, label: string) {
	want, ok := decode_hex(want_hex, context.temp_allocator)
	testing.expectf(t, ok, "%s: the expected vector should decode", label)
	testing.expectf(
		t,
		mem.compare(got, want) == 0,
		"%s:\n     got %x\n  wanted %x",
		label,
		got,
		want,
	)
}

@(test)
test_signing_input_matches_a_golden_a_rrset :: proc(t: ^testing.T) {
	/*
	Two A records under `www.example.com.`, signed by `example.com.`. The bytes
	are the RRSIG RDATA up to the signature, then each record as owner, type,
	class, original TTL, length and RDATA, in RDATA order.
	*/
	records := []dns.Record{a_record("www.example.com.", 1), a_record("www.example.com.", 2)}
	data, ok := signing_input(golden_sig(.A), "www.example.com.", .IN, records, context.temp_allocator)
	testing.expect(t, ok, "a well-formed RRset should produce a signing input")
	expect_hex(
		t,
		data,
		"00010d0300000e106a000000690000001234076578616d706c6503636f6d0003777777076578616d706c6503636f6d00" +
		"0001000100000e100004c000020103777777076578616d706c6503636f6d000001000100000e100004c0000202",
		"the A RRset",
	)
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_downcases_a_name_inside_the_rdata :: proc(t: ^testing.T) {
	// MX is on the RFC 4034 section 6.2 list, so `MAIL.Example.COM.` is signed
	// over as `mail.example.com.`.
	records := []dns.Record {
		{
			name = "example.com.",
			type = .MX,
			class = .IN,
			ttl = 3600,
			data = dns.Rdata_MX{preference = 10, exchange = "MAIL.Example.COM."},
		},
	}
	data, ok := signing_input(golden_sig(.MX), "example.com.", .IN, records, context.temp_allocator)
	testing.expect(t, ok, "an MX RRset should produce a signing input")
	expect_hex(
		t,
		data,
		"000f0d0300000e106a000000690000001234076578616d706c6503636f6d00076578616d706c6503636f6d00000f0001" +
		"00000e100014000a046d61696c076578616d706c6503636f6d00",
		"the MX RRset",
	)
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_writes_the_original_ttl_not_the_records :: proc(t: ^testing.T) {
	/*
	RFC 4034 section 6.2: the TTL in the signing input is the RRSIG's Original
	TTL field. Every cache on the path counts the record's own TTL down, so
	signing over it would mean a signature that stops verifying a second after
	it was made.
	*/
	fresh := []dns.Record{a_record("www.example.com.", 1, 3600)}
	nearly_expired := []dns.Record{a_record("www.example.com.", 1, 1)}

	from_fresh, ok1 := signing_input(golden_sig(.A), "www.example.com.", .IN, fresh, context.temp_allocator)
	from_aged, ok2 := signing_input(golden_sig(.A), "www.example.com.", .IN, nearly_expired, context.temp_allocator)
	testing.expect(t, ok1 && ok2, "both should build")
	testing.expect(t, mem.compare(from_fresh, from_aged) == 0, "the record's own TTL must not reach the signing input")
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_sorts_and_deduplicates_the_rrset :: proc(t: ^testing.T) {
	/*
	RFC 4034 section 6.3. The order records arrive in is the sender's choice -
	upstreams shuffle RRsets deliberately - so the canonical order has to be
	recovered here, and a record repeated is written once. Neither is cosmetic:
	both change the bytes the signature is checked against, so getting either
	wrong makes honest answers look forged.
	*/
	ascending := []dns.Record{a_record("www.example.com.", 1), a_record("www.example.com.", 2)}
	descending := []dns.Record{a_record("www.example.com.", 2), a_record("www.example.com.", 1)}
	with_a_repeat := []dns.Record {
		a_record("www.example.com.", 2),
		a_record("www.example.com.", 1),
		a_record("www.example.com.", 2),
	}

	canonical, ok1 := signing_input(golden_sig(.A), "www.example.com.", .IN, ascending, context.temp_allocator)
	shuffled, ok2 := signing_input(golden_sig(.A), "www.example.com.", .IN, descending, context.temp_allocator)
	repeated, ok3 := signing_input(golden_sig(.A), "www.example.com.", .IN, with_a_repeat, context.temp_allocator)
	testing.expect(t, ok1 && ok2 && ok3, "all three should build")
	testing.expect(t, mem.compare(canonical, shuffled) == 0, "arrival order must not change the signing input")
	testing.expect(t, mem.compare(canonical, repeated) == 0, "a repeated record must be written once")
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_lowercases_the_owner_and_the_signer :: proc(t: ^testing.T) {
	/*
	A query whose case was randomised on the way out comes back with the case it
	left in, and the zone signed the lowercase form. Both the owner name written
	in front of every record and the signer name in the RRSIG's own RDATA have to
	be folded, or 0x20 encoding would break every signature it touched.
	*/
	lower := golden_sig(.A)
	mixed := golden_sig(.A)
	mixed.signer = "ExAmPlE.CoM."

	from_lower, ok1 := signing_input(
		lower,
		"www.example.com.",
		.IN,
		[]dns.Record{a_record("www.example.com.", 1)},
		context.temp_allocator,
	)
	from_mixed, ok2 := signing_input(
		mixed,
		"WWW.Example.COM.",
		.IN,
		[]dns.Record{a_record("WWW.Example.COM.", 1)},
		context.temp_allocator,
	)
	testing.expect(t, ok1 && ok2, "both should build")
	testing.expect(t, mem.compare(from_lower, from_mixed) == 0, "case must not reach the signing input")
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_refuses_what_it_cannot_sign :: proc(t: ^testing.T) {
	sig := golden_sig(.A)
	_, empty := signing_input(sig, "www.example.com.", .IN, nil, context.temp_allocator)
	testing.expect(t, !empty, "an empty RRset has nothing to sign")

	// OPT is a transport pseudo-record; RFC 6891 section 6.1.1 says it is never
	// signed, and rendering one would invent bytes no signer produced.
	opt := []dns.Record{{name = ".", type = .OPT, class = .IN, data = dns.Rdata_OPT{}}}
	_, is_opt := signing_input(sig, ".", .IN, opt, context.temp_allocator)
	testing.expect(t, !is_opt, "an OPT record cannot appear in a signing input")

	// An owner name that will not go on the wire.
	_, unencodable := signing_input(
		sig,
		"a..b.",
		.IN,
		[]dns.Record{a_record("a..b.", 1)},
		context.temp_allocator,
	)
	testing.expect(t, !unencodable, "an owner that will not encode cannot be signed over")
	free_all(context.temp_allocator)
}

@(test)
test_downcasing_list_is_rfc4034_as_amended_by_rfc6840 :: proc(t: ^testing.T) {
	/*
	Section 6.2 named the types whose RDATA domain names are lowercased for a
	signature. RFC 6840 section 5.1 then took NSEC's next name off it - that
	name is signed exactly as published. Adding a type to the list that does not
	belong, or leaving one off, breaks every signature over that type.
	*/
	on_the_list := []dns.Type{.NS, .CNAME, .SOA, .MX, .PTR, .SRV, .DNAME, .NAPTR, .RP, .AFSDB, .RT, .KX, .PX, .MINFO, .SIG, .RRSIG}
	for type in on_the_list {
		testing.expectf(t, downcases_rdata_names(type), "%v is on the RFC 4034 section 6.2 list", type)
	}
	off_the_list := []dns.Type{.NSEC, .NSEC3, .DS, .DNSKEY, .A, .AAAA, .TXT, .SVCB, .HTTPS, .CAA, .TLSA, .NSAP_PTR}
	for type in off_the_list {
		testing.expectf(t, !downcases_rdata_names(type), "%v is not on it", type)
	}
	free_all(context.temp_allocator)
}

@(test)
test_raw_rdata_downcasing_walks_the_layout :: proc(t: ^testing.T) {
	/*
	Types the codec keeps as raw bytes still have to have their embedded names
	lowercased, which means walking past the fixed fields and the
	character-strings first. A character-string is not a name and must be left
	exactly as it is - lowercasing a NAPTR's flags or its regular expression
	would change data the signer signed verbatim.
	*/
	out := make([dynamic]u8, context.temp_allocator)

	// SRV: two-byte priority, weight and port, then the target.
	srv := []u8{0, 1, 0, 2, 0, 80, 4, 'S', 'I', 'P', '1', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0}
	write_downcased_raw(&out, .SRV, srv)
	expect_hex(t, out[:], "0001000200500473697031076578616d706c6503636f6d00", "a raw SRV")

	// NAPTR: order and preference, three character-strings, then the
	// replacement name. Only the last of those is a name.
	clear(&out)
	naptr := []u8{0, 100, 0, 10, 1, 'U', 3, 'S', 'I', 'P', 2, '!', '!', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0}
	write_downcased_raw(&out, .NAPTR, naptr)
	expect_hex(t, out[:], "0064000a015503534950022121076578616d706c6503636f6d00", "a raw NAPTR")

	// SOA carries two names back to back.
	clear(&out)
	soa := []u8{2, 'N', 'S', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0, 4, 'R', 'O', 'O', 'T', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5}
	write_downcased_raw(&out, .SOA, soa)
	expect_hex(
		t,
		out[:],
		"026e73076578616d706c650004726f6f74076578616d706c65000000000100000002000000030000000400000005",
		"a raw SOA",
	)
	free_all(context.temp_allocator)
}

@(test)
test_raw_rdata_is_copied_verbatim_when_it_cannot_be_walked :: proc(t: ^testing.T) {
	/*
	A type with no layout entry, or a name inside one that turns out to be
	compressed, is copied through untouched. RFC 4034 forbade compressing those
	names in the first place, and the message they might have pointed into is
	long gone by the time this runs, so the honest outcome is a canonical form
	that will not match and a signature that fails - not a guess.
	*/
	out := make([dynamic]u8, context.temp_allocator)

	// A type with no name in its RDATA at all.
	unknown := []u8{0xde, 0xad, 0xbe, 0xef}
	write_downcased_raw(&out, .TLSA, unknown)
	testing.expect(t, mem.compare(out[:], unknown) == 0, "a type with no layout is copied through")

	// MX whose exchange is a compression pointer.
	clear(&out)
	compressed := []u8{0, 10, 0xc0, 0x0c}
	write_downcased_raw(&out, .MX, compressed)
	testing.expect(t, mem.compare(out[:], compressed) == 0, "a compressed name falls back to a verbatim copy")

	// MX whose exchange runs off the end of the RDATA.
	clear(&out)
	truncated := []u8{0, 10, 7, 'E', 'X'}
	write_downcased_raw(&out, .MX, truncated)
	testing.expect(t, mem.compare(out[:], truncated) == 0, "a truncated name falls back too")

	// And a record too short even for its fixed fields.
	clear(&out)
	stub := []u8{0}
	write_downcased_raw(&out, .MX, stub)
	testing.expect(t, mem.compare(out[:], stub) == 0, "so does one with no room for the fixed fields")
	free_all(context.temp_allocator)
}

@(test)
test_canonical_name_folds_case_and_plain_name_does_not :: proc(t: ^testing.T) {
	// The two spellings a name gets on the wire: folded where a signature is
	// computed over it, verbatim where the signer published it.
	folded, plain: [dns.MAX_NAME_WIRE]u8
	fn, fok := canonical_name("WwW.Example.COM.", folded[:])
	pn, pok := plain_name("WwW.Example.COM.", plain[:])
	testing.expect(t, fok && pok, "both spellings should encode")
	expect_hex(t, folded[:fn], "03777777076578616d706c6503636f6d00", "the canonical form")
	expect_hex(t, plain[:pn], "03577757074578616d706c6503434f4d00", "the published form")

	// The root is one byte either way.
	rn, rok := canonical_name(".", folded[:])
	testing.expect(t, rok && rn == 1 && folded[0] == 0, "the root name is a single zero octet")
	free_all(context.temp_allocator)
}

@(test)
test_label_helpers_walk_names_the_way_the_chain_does :: proc(t: ^testing.T) {
	testing.expect_value(t, label_count("www.example.com."), 3)
	testing.expect_value(t, label_count("example.com."), 2)
	testing.expect_value(t, label_count("."), 0)
	// An escaped dot is part of its label, not a separator.
	testing.expect_value(t, label_count("a\\.b.example."), 2)

	testing.expect_value(t, name_drop_labels("www.example.com.", 1), "example.com.")
	testing.expect_value(t, name_drop_labels("www.example.com.", 3), ".")

	testing.expect(t, name_in_zone("www.example.com.", "example.com."), "a child is in its zone")
	testing.expect(t, name_in_zone("example.com.", "example.com."), "a zone contains its own apex")
	testing.expect(t, name_in_zone("example.com.", "."), "everything is under the root")
	testing.expect(t, !name_in_zone("example.com.", "www.example.com."), "a parent is not inside its child")
	testing.expect(t, !name_in_zone("example.org.", "example.com."), "a sibling zone is not inside it")
	// The check that stops a zone vouching for a name it has no authority over,
	// and the near-miss an attacker would reach for.
	testing.expect(t, !name_in_zone("notexample.com.", "example.com."), "a longer label is not a subdomain")
	free_all(context.temp_allocator)
}
