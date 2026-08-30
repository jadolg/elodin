package dnssec

import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
2026-08-02T10:00:00Z, which falls inside the validity period of every signature
in `fixtures_test.odin`. Passing the time in rather than reading the clock is
what keeps captured traffic usable as a test vector: the bytes are frozen, so
the moment they are judged against has to be too.
*/
FIXTURE_TIME :: 1785664800

@(private = "file")
fixture_now :: proc() -> time.Time {
	return time.unix(FIXTURE_TIME, 0)
}

@(private = "file")
fixture :: proc(key: string) -> Fixture {
	for f in FIXTURES {
		if f.key == key {
			return f
		}
	}
	return {}
}

@(private = "file")
unhex :: proc(text: string, allocator := context.temp_allocator) -> []u8 {
	out, ok := decode_hex(text, allocator)
	if !ok {
		return nil
	}
	return out
}

// Answers from the captured set, standing in for the upstream the validator
// would otherwise have to ask.
@(private = "file")
fixture_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return unhex(f.wire, allocator), true
		}
	}
	return nil, false
}

@(private = "file")
test_validator :: proc(anchors: []Trust_Anchor = nil) -> ^Validator {
	return make_validator(fixture_query, nil, Options{anchors = anchors})
}

// Walks the chain with a fresh budget, the way `validate` does.
@(private = "file")
trust :: proc(v: ^Validator, name: string) -> (Status, []Dnskey, string) {
	budget := Budget{}
	return zone_trust(v, &budget, name, fixture_now(), context.temp_allocator)
}

@(private = "file")
validate_fixture :: proc(v: ^Validator, key: string, qname: string, qtype: dns.Type) -> Result {
	f := fixture(key)
	return validate(v, qname, qtype, unhex(f.wire), fixture_now())
}

// ---------------------------------------------------------------------------
// Pieces
// ---------------------------------------------------------------------------

@(test)
test_key_tag_matches_published_anchor :: proc(t: ^testing.T) {
	// The root DNSKEY set contains the key-signing key IANA publishes as tag
	// 20326, so computing tags over real RDATA is checked against a number
	// nobody here chose.
	msg, err := dns.decode_message(unhex(fixture("root_dnskey").wire), context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)

	found := false
	for rec in msg.answer {
		if rec.type != .DNSKEY {
			continue
		}
		rdata, ok := raw_rdata(rec)
		testing.expect(t, ok, "DNSKEY rdata should be raw")
		key, perr := parse_dnskey(rdata)
		testing.expect_value(t, perr, Parse_Error.None)
		if key.tag == 20326 {
			found = true
			testing.expect_value(t, key.algorithm, u8(ALG_RSASHA256))
			testing.expect(t, key.flags & DNSKEY_FLAG_SEP != 0, "the KSK should have the SEP bit")
		}
	}
	testing.expect(t, found, "key tag 20326 not found in the root DNSKEY set")
	free_all(context.temp_allocator)
}

@(test)
test_root_ksk_matches_trust_anchor :: proc(t: ^testing.T) {
	msg, _ := dns.decode_message(unhex(fixture("root_dnskey").wire), context.temp_allocator)
	matched := 0
	for rec in msg.answer {
		if rec.type != .DNSKEY {
			continue
		}
		rdata, _ := raw_rdata(rec)
		key, perr := parse_dnskey(rdata)
		if perr != .None {
			continue
		}
		for anchor in root_anchors() {
			if ds_matches(".", key, anchor.ds) {
				matched += 1
			}
		}
	}
	testing.expect(t, matched > 0, "no root key hashes to a built-in trust anchor")
	free_all(context.temp_allocator)
}

@(test)
test_name_compare_canonical_order :: proc(t: ^testing.T) {
	// The worked example from RFC 4034 section 6.1.
	ordered := []string{
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"\\200.z.example.",
	}
	for i in 1 ..< len(ordered) {
		order, ok := name_compare(ordered[i - 1], ordered[i])
		testing.expect(t, ok, "these names should all be comparable")
		testing.expect(t, order < 0, "canonical order broken around index")
	}
	same, ok := name_compare("EXAMPLE.com.", "example.COM.")
	testing.expect(t, ok, "case-different names should compare")
	testing.expect_value(t, same, 0)

	// A name that cannot be put on the wire - here an empty label - has no
	// position in the ordering, and saying so is what keeps a span from
	// appearing to cover it.
	_, encodable := name_compare("example.com.", "a..b.")
	testing.expect(t, !encodable, "an unencodable name should not compare")
	free_all(context.temp_allocator)
}

@(test)
test_bitmap_membership :: proc(t: ^testing.T) {
	// Window 0, three bytes: A (1), NS (2), SOA (6), and TXT (16) in the third.
	bitmap := []u8{0, 3, 0b0110_0010, 0, 0b1000_0000}
	testing.expect(t, bitmap_has(bitmap, .A), "A should be present")
	testing.expect(t, bitmap_has(bitmap, .NS), "NS should be present")
	testing.expect(t, bitmap_has(bitmap, .SOA), "SOA should be present")
	testing.expect(t, bitmap_has(bitmap, .TXT), "TXT should be present")
	testing.expect(t, !bitmap_has(bitmap, .AAAA), "AAAA should be absent")
	testing.expect(t, !bitmap_has(bitmap, .DS), "DS should be absent")
	// A type in a window the map does not carry at all.
	testing.expect(t, !bitmap_has(bitmap, .CAA), "CAA should be absent")
}

@(test)
test_base32hex_roundtrip :: proc(t: ^testing.T) {
	buf: [20]u8
	n, ok := base32hex_decode("00000000000000000000000000000000", buf[:])
	testing.expect(t, ok, "all-zero hash should decode")
	testing.expect_value(t, n, 20)

	n2, ok2 := base32hex_decode("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv", buf[:])
	testing.expect(t, ok2, "all-ones hash should decode")
	testing.expect_value(t, n2, 20)
	testing.expect_value(t, buf[0], u8(0xff))

	_, bad := base32hex_decode("w", buf[:])
	testing.expect(t, !bad, "w is not in the base32hex alphabet")
}

@(test)
test_parse_trust_anchor :: proc(t: ^testing.T) {
	anchor, ok := parse_trust_anchor(
		". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		context.temp_allocator,
	)
	testing.expect(t, ok, "presentation-form anchor should parse")
	testing.expect_value(t, anchor.zone, ".")
	testing.expect_value(t, anchor.ds.key_tag, u16(20326))
	testing.expect_value(t, anchor.ds.algorithm, u8(8))
	testing.expect_value(t, anchor.ds.digest_type, u8(2))
	testing.expect_value(t, len(anchor.ds.digest), 32)

	bare, bare_ok := parse_trust_anchor(
		"38696 8 2 683D2D0ACB8C9B712A1948B27F741219 298D0A450D612C483AF444A4C0FB2B16",
		context.temp_allocator,
	)
	testing.expect(t, bare_ok, "bare fields with a split digest should parse")
	testing.expect_value(t, bare.ds.key_tag, u16(38696))
	testing.expect_value(t, len(bare.ds.digest), 32)

	_, junk := parse_trust_anchor("not an anchor", context.temp_allocator)
	testing.expect(t, !junk, "nonsense should not parse")
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Whole responses
// ---------------------------------------------------------------------------

@(test)
test_validates_rsa_chain :: proc(t: ^testing.T) {
	// Root and com are signed with RSA/SHA-256; this walks both.
	v := test_validator()
	defer destroy_validator(v)

	status, keys, zone := trust(v, "com.")
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "com.")
	testing.expect(t, len(keys) > 0, "com should have keys")
	free_all(context.temp_allocator)
}

@(private = "file")
Counting_Ctx :: struct {
	queries: int,
}

@(private = "file")
counting_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	counter := cast(^Counting_Ctx)ctx
	counter.queries += 1
	return fixture_query(nil, name, type, allocator)
}

@(test)
test_zone_keys_are_cached :: proc(t: ^testing.T) {
	// Walking a chain costs a DS and a DNSKEY per label. Doing that again for
	// every query into the same zone would put four round trips in front of
	// each of them, so the second walk must cost nothing.
	counter := Counting_Ctx{}
	v := make_validator(counting_query, &counter, Options{})
	defer destroy_validator(v)

	status, _, zone := trust(v, "example.com.")
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, zone, "example.com.")
	testing.expect(t, counter.queries > 0, "the cold walk should have asked the upstream")

	cold := counter.queries
	again, keys, _ := trust(v, "example.com.")
	testing.expect_value(t, again, Status.Secure)
	testing.expect(t, len(keys) > 0, "cached keys should come back")
	testing.expect_value(t, counter.queries, cold)

	// Nothing has run out of time yet, so a sweep should take nothing away and
	// the walk after it should still be free.
	testing.expect_value(t, sweep(v, fixture_now()), 0)
	third, _, _ := trust(v, "example.com.")
	testing.expect_value(t, third, Status.Secure)
	testing.expect_value(t, counter.queries, cold)
	free_all(context.temp_allocator)
}

@(test)
test_validates_ecdsa_answer :: proc(t: ^testing.T) {
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "example_a", "www.example.com.", .A)
	testing.expect_value(t, result.status, Status.Secure)

	other := validate_fixture(v, "cloudflare_a", "www.cloudflare.com.", .A)
	testing.expect_value(t, other.status, Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_validates_ed25519_answer :: proc(t: ^testing.T) {
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "ed25519_a", "ed25519.nl.", .A)
	testing.expect_value(t, result.status, Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_validates_nsec_name_error :: proc(t: ^testing.T) {
	// The root zone uses NSEC, so a nonexistent top-level name is denied with it.
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "nxdomain_root", "zzzz-does-not-exist-xq7.", .A)
	testing.expect_value(t, result.status, Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_validates_nsec3_name_error :: proc(t: ^testing.T) {
	// com uses NSEC3 with opt-out.
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "nxdomain_com", "zzzz-does-not-exist-xq7.com.", .A)
	testing.expect(
		t,
		result.status == .Secure || result.status == .Insecure,
		"an NSEC3 name error should be proven or opted out, not bogus",
	)
	free_all(context.temp_allocator)
}

@(test)
test_validates_nodata :: proc(t: ^testing.T) {
	// cloudflare.com answers a nonexistent name with NODATA and an NSEC that
	// spans it, the "black lies" arrangement.
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "nodata_cloudflare", "nosuchname-xq7.cloudflare.com.", .A)
	testing.expect_value(t, result.status, Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_injected_signer_cannot_downgrade_a_denial :: proc(t: ^testing.T) {
	/*
	A denial of existence proves a name is absent, so there is no signature over
	the answer to fall back on: if the wrong zone is checked, nothing verifies,
	and "nothing verified" is indistinguishable from "this zone is unsigned".

	Here one RRSIG naming an unsigned zone is pushed to the front of the
	authority section. A validator that took the zone from the response would
	conclude the name lives in an unsigned zone and serve the denial as
	insecure - a forged NXDOMAIN accepted on the strength of one added record.
	The zone has to come from the name that was asked about.
	*/
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("nxdomain_root").wire)
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	append(
		&authority,
		dns.Record {
			name = "zzzz-does-not-exist-xq7.",
			type = .RRSIG,
			class = .IN,
			ttl = 60,
			// reddit.com is unsigned in the captured set.
			data = dns.Rdata_Raw{data = rrsig_rdata("reddit.com.", .NSEC, 1)},
		},
	)
	append(&authority, ..msg.authority)
	msg.authority = authority[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "zzzz-does-not-exist-xq7.", .A, tampered, fixture_now())
	testing.expect_value(t, result.status, Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_injected_answer_record_cannot_skip_a_denial :: proc(t: ^testing.T) {
	/*
	The same attack as above, aimed at the dispatch instead of at the zone.

	A denial is only checked when the answer section is empty of anything that
	could be authenticated. An RRSIG carries no signature of its own and is
	skipped by the positive path, so one dropped into the answer section is
	enough to make a response look like an answer while containing none - and a
	validator that dispatched on the section being non-empty would report having
	nothing to authenticate and never ask for the proof of non-existence.

	Here the genuine NSEC records are removed outright, so nothing whatsoever
	proves the name is absent. A forged NXDOMAIN for a name in the signed root
	has to be refused.
	*/
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("nxdomain_root").wire)
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	msg.authority = nil

	answer := make([dynamic]dns.Record, 0, 1, context.temp_allocator)
	append(
		&answer,
		dns.Record {
			name = "zzzz-does-not-exist-xq7.",
			type = .RRSIG,
			class = .IN,
			ttl = 60,
			data = dns.Rdata_Raw{data = rrsig_rdata("reddit.com.", .NSEC, 1)},
		},
	)
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "zzzz-does-not-exist-xq7.", .A, tampered, fixture_now())
	testing.expect(
		t,
		result.status == .Bogus || result.status == .Indeterminate,
		"a denial with no proof behind it must be refused, not served",
	)
	free_all(context.temp_allocator)
}

@(test)
test_rrsig_question_has_nothing_to_authenticate :: proc(t: ^testing.T) {
	/*
	The one case where an answer made only of RRSIG records is honest. An RRSIG
	RRset is never signed (RFC 4035 section 2.2), so a question about one is
	answered by records that carry no signature - insecure rather than bogus,
	and no denial of existence to demand.
	*/
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("nxdomain_root").wire)
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	msg.authority = nil
	answer := make([dynamic]dns.Record, 0, 1, context.temp_allocator)
	append(
		&answer,
		dns.Record {
			name = "example.com.",
			type = .RRSIG,
			class = .IN,
			ttl = 60,
			data = dns.Rdata_Raw{data = rrsig_rdata("example.com.", .A, 2)},
		},
	)
	msg.answer = answer[:]

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "example.com.", .RRSIG, tampered, fixture_now())
	testing.expect_value(t, result.status, Status.Insecure)
	free_all(context.temp_allocator)
}

@(test)
test_unsigned_delegation_is_insecure :: proc(t: ^testing.T) {
	// reddit.com has no DS record in com, so its data is unsigned - which is a
	// different thing from forged, and must not be refused.
	v := test_validator()
	defer destroy_validator(v)

	result := validate_fixture(v, "reddit_a", "www.reddit.com.", .A)
	testing.expect_value(t, result.status, Status.Insecure)
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Things that must not validate
// ---------------------------------------------------------------------------

@(test)
test_upstream_errors_are_not_called_forgeries :: proc(t: ^testing.T) {
	// A REFUSED carries nothing to authenticate. Insisting on a denial of
	// existence would turn every upstream error into a DNSSEC failure.
	v := test_validator()
	defer destroy_validator(v)

	msg := dns.Message {
		id       = 1,
		question = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}},
	}
	msg.flags.qr = true
	msg.flags.rcode = u8(dns.Rcode.Refused)
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)

	result := validate(v, "www.example.com.", .A, wire, fixture_now())
	testing.expect_value(t, result.status, Status.Insecure)
	free_all(context.temp_allocator)
}

@(test)
test_an_answer_of_only_signatures_is_not_secure :: proc(t: ^testing.T) {
	// An RRSIG RRset is never itself signed, so a question about one cannot be
	// answered authentically. Reporting the empty check as a pass would put the
	// AD bit on data nothing vouched for.
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("example_a").wire)
	msg, _ := dns.decode_message(wire, context.temp_allocator)

	only_sigs := make([dynamic]dns.Record, 0, len(msg.answer), context.temp_allocator)
	for rec in msg.answer {
		if rec.type == .RRSIG {
			append(&only_sigs, rec)
		}
	}
	testing.expect(t, len(only_sigs) > 0, "fixture should carry a signature")
	msg.answer = only_sigs[:]

	rebuilt, _, _ := dns.encode_message(msg, context.temp_allocator)
	result := validate(v, "www.example.com.", .RRSIG, rebuilt, fixture_now())
	testing.expect_value(t, result.status, Status.Insecure)
	free_all(context.temp_allocator)
}

@(private = "file")
rrsig_rdata :: proc(signer: string, covered: dns.Type, labels: u8) -> []u8 {
	name: [dns.MAX_NAME_WIRE]u8
	n, _ := dns.encode_name(signer, name[:])

	out := make([dynamic]u8, 0, 32 + n, context.temp_allocator)
	append(&out, u8(u16(covered) >> 8), u8(u16(covered)))
	append(&out, ALG_RSASHA256, labels)
	append(&out, 0, 0, 0, 60) // original TTL
	append(&out, 0xff, 0xff, 0xff, 0xff) // expiration
	append(&out, 0, 0, 0, 0) // inception
	append(&out, 0, 1) // key tag
	append(&out, ..name[:n])
	append(&out, 0) // a signature that will never be reached
	return out[:]
}

@(test)
test_one_question_cannot_provoke_unbounded_lookups :: proc(t: ^testing.T) {
	/*
	A response carrying many owner names, each naming itself as its signer, asks
	the validator to walk a separate chain for every one of them. Left alone
	that turns one client question into hundreds of upstream queries with a
	worker held for all of them, so the walk is given a budget and the answer
	fails rather than the resolver.
	*/
	counter := Counting_Ctx{}
	v := make_validator(counting_query, &counter, Options{})
	defer destroy_validator(v)

	answer := make([dynamic]dns.Record, 0, 80, context.temp_allocator)
	for i in 0 ..< 40 {
		owner := fmt.tprintf("a%d.example.com.", i)
		append(
			&answer,
			dns.Record {
				name = owner,
				type = .A,
				class = .IN,
				ttl = 60,
				data = dns.Rdata_A{addr = {192, 0, 2, u8(i)}},
			},
		)
		append(
			&answer,
			dns.Record {
				name = owner,
				type = .RRSIG,
				class = .IN,
				ttl = 60,
				data = dns.Rdata_Raw{data = rrsig_rdata(owner, .A, 3)},
			},
		)
	}

	msg := dns.Message {
		id       = 9,
		question = []dns.Question{{name = "a0.example.com.", type = .A, class = .IN}},
		answer   = answer[:],
	}
	msg.flags.qr = true
	wire, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "a0.example.com.", .A, wire, fixture_now())
	testing.expect(t, result.status != .Secure, "none of these signatures are real")
	// A fixed number rather than the constant under test, which would make this
	// agree with itself whatever the constant said. Unbounded, this same
	// response costs 85 lookups.
	CEILING :: 40
	testing.expect(
		t,
		counter.queries <= CEILING,
		fmt.tprintf("one question cost %d upstream lookups, ceiling is %d", counter.queries, CEILING),
	)
	free_all(context.temp_allocator)
}

// Serves one crafted DNSKEY response, whatever is asked for.
@(private = "file")
Canned_Ctx :: struct {
	wire: string,
}

@(private = "file")
canned_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	canned := cast(^Canned_Ctx)ctx
	return unhex(canned.wire, allocator), true
}

@(private = "file")
forged_ds :: proc() -> []Ds {
	digest, _ := decode_hex(FORGED_DS_DIGEST, context.temp_allocator)
	set := make([]Ds, 1, context.temp_allocator)
	set[0] = Ds {
		key_tag     = FORGED_KEY_TAG,
		algorithm   = ALG_ED25519,
		digest_type = DIGEST_SHA256,
		digest      = digest,
	}
	return set
}

@(private = "file")
fetch_forged :: proc(wire: string) -> Status {
	canned := Canned_Ctx{wire = wire}
	v := make_validator(canned_query, &canned, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	_, status := fetch_keys(
		v,
		&budget,
		FORGED_ZONE,
		forged_ds(),
		u32(FIXTURE_TIME),
		context.temp_allocator,
	)
	return status
}

@(test)
test_dnskey_set_signed_by_the_attested_key_validates :: proc(t: ^testing.T) {
	// The control. If this ever stops passing, the canonical form the fixture
	// was built against has drifted from the one the validator computes, and
	// the forgery test below would be passing for the wrong reason.
	testing.expect_value(t, fetch_forged(HONEST_DNSKEY), Status.Secure)
	free_all(context.temp_allocator)
}

@(test)
test_key_tag_collision_does_not_satisfy_the_ds :: proc(t: ^testing.T) {
	/*
	The same DNSKEY set, signed by the other key sharing the attested key's tag.
	The DS still hashes to a real key in the set, and the signature is perfectly
	valid - just made by a key the parent never vouched for. Accepting it would
	let anyone who can publish a second key under a colliding tag detach the
	zone from its parent entirely.
	*/
	testing.expect(
		t,
		fetch_forged(FORGED_DNSKEY) != .Secure,
		"a signature from a key the DS did not attest was accepted",
	)
	free_all(context.temp_allocator)
}

@(test)
test_tampered_answer_is_bogus :: proc(t: ^testing.T) {
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("example_a").wire)
	msg, _ := dns.decode_message(wire, context.temp_allocator)

	// Rewrite the address the client would use, leaving the signature alone.
	touched := false
	for rec, i in msg.answer {
		if rec.type != .A {
			continue
		}
		a := msg.answer[i].data.(dns.Rdata_A)
		a.addr[3] ~= 0xff
		msg.answer[i].data = a
		touched = true
	}
	testing.expect(t, touched, "fixture should contain an A record")

	forged, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, forged, fixture_now())
	testing.expect_value(t, result.status, Status.Bogus)
	free_all(context.temp_allocator)
}

@(test)
test_stripped_signature_is_bogus :: proc(t: ^testing.T) {
	v := test_validator()
	defer destroy_validator(v)

	wire := unhex(fixture("example_a").wire)
	msg, _ := dns.decode_message(wire, context.temp_allocator)

	kept := make([dynamic]dns.Record, 0, len(msg.answer), context.temp_allocator)
	for rec in msg.answer {
		if rec.type != .RRSIG {
			append(&kept, rec)
		}
	}
	msg.answer = kept[:]

	stripped, _, _ := dns.encode_message(msg, context.temp_allocator)
	result := validate(v, "www.example.com.", .A, stripped, fixture_now())
	testing.expect_value(t, result.status, Status.Bogus)
	free_all(context.temp_allocator)
}

@(test)
test_expired_signature_is_bogus :: proc(t: ^testing.T) {
	v := test_validator()
	defer destroy_validator(v)

	f := fixture("example_a")
	// A year past every signature in the set.
	late := time.unix(FIXTURE_TIME + 365 * 24 * 3600, 0)
	result := validate(v, "www.example.com.", .A, unhex(f.wire), late)
	testing.expect(t, result.status != .Secure, "an expired signature must not validate")
	free_all(context.temp_allocator)
}

@(test)
test_wrong_trust_anchor_is_bogus :: proc(t: ^testing.T) {
	// The right key tag against a digest that is not the root's: the chain has
	// to break at the very first step rather than fall back to trusting it.
	wrong := make([]u8, 32, context.temp_allocator)
	anchors := []Trust_Anchor {
		{zone = ".", ds = {key_tag = 20326, algorithm = ALG_RSASHA256, digest_type = DIGEST_SHA256, digest = wrong}},
	}
	v := test_validator(anchors)
	defer destroy_validator(v)

	result := validate_fixture(v, "example_a", "www.example.com.", .A)
	testing.expect_value(t, result.status, Status.Bogus)
	free_all(context.temp_allocator)
}

@(test)
test_forged_ds_breaks_the_chain :: proc(t: ^testing.T) {
	// Swapping the digest of example.com's DS record leaves a well-formed,
	// correctly signed delegation that points at a key nobody holds.
	v := test_validator()
	defer destroy_validator(v)

	status, _, _ := trust(v, "example.com.")
	testing.expect_value(t, status, Status.Secure)
	free_all(context.temp_allocator)

	// Same walk, but through a query proc that corrupts the DS answer.
	broken := make_validator(broken_ds_query, nil, Options{})
	defer destroy_validator(broken)
	bad_status, _, _ := trust(broken, "example.com.")
	testing.expect_value(t, bad_status, Status.Bogus)
	free_all(context.temp_allocator)
}

@(private = "file")
broken_ds_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	wire, ok := fixture_query(ctx, name, type, allocator)
	if !ok || type != .DS || !dns.name_equal_fold(name, "example.com.") {
		return wire, ok
	}
	// The DS digest is the last four bytes of the record's RDATA; flipping a
	// byte inside the message is enough to break the match without disturbing
	// anything the parser needs.
	msg, err := dns.decode_message(wire, allocator)
	if err != .None {
		return wire, ok
	}
	for rec, i in msg.answer {
		if rec.type != .DS {
			continue
		}
		raw := msg.answer[i].data.(dns.Rdata_Raw)
		raw.data[len(raw.data) - 1] ~= 0xff
		msg.answer[i].data = raw
	}
	forged, _, enc := dns.encode_message(msg, allocator)
	if enc != .None {
		return wire, ok
	}
	return forged, true
}

@(test)
test_answer_for_another_name_is_not_authentic :: proc(t: ^testing.T) {
	/*
	A response has to answer the question that was asked.

	Every RRset here is genuine and signed, and every signature checks out
	against a real chain from the root - it is simply an answer about a
	different name, replayed under someone else's question. Judging the records
	one by one and reporting the best of them says `Secure`, sets the AD bit,
	and files the whole thing in the cache under the name that was asked about.

	No forgery is needed for this. An attacker holding any signed zone of their
	own has a supply of validly signed RRsets to offer, and a stub reading the
	result sees an authenticated answer with nothing in it for the name it
	asked about - a denial it never proved.
	*/
	v := test_validator()
	defer destroy_validator(v)

	// A real, signed answer for www.cloudflare.com.
	wire := unhex(fixture("cloudflare_a").wire)
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	// Re-asked as though it answered a name in another signed zone.
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
	}
	msg.question = question

	tampered, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "www.example.com.", .A, tampered, fixture_now())
	testing.expectf(
		t,
		result.status != .Secure,
		"an answer about another name was called authentic (%v, %q)",
		result.status,
		result.reason,
	)
	free_all(context.temp_allocator)
}

@(private = "file")
rec :: proc(name: string, type: dns.Type, target: string = "") -> dns.Record {
	out := dns.Record {
		name  = name,
		type  = type,
		class = .IN,
		ttl   = 60,
	}
	if type == .CNAME {
		out.data = dns.Rdata_Name{name = target}
	}
	return out
}

@(test)
test_answers_question_follows_the_cname_chain :: proc(t: ^testing.T) {
	/*
	The shape of an answer that addresses its question, case by case. Chains
	that stop short are ordinary - the zone at the end may hold nothing of the
	type, which the authority section is what proves - so those count. An
	answer section with nothing at the queried name does not.
	*/
	direct := []dns.Record{rec("www.example.com.", .A)}
	testing.expect(t, answers_question(direct, "www.example.com.", .A, .IN), "the type at the name should count")

	// Case folding, since a name is not the bytes it was written with.
	testing.expect(t, answers_question(direct, "WWW.Example.COM.", .A, .IN), "names should match case-insensitively")

	chain := []dns.Record {
		rec("www.example.com.", .CNAME, "target.example.net."),
		rec("target.example.net.", .A),
	}
	testing.expect(t, answers_question(chain, "www.example.com.", .A, .IN), "a completed chain should count")

	// The chain stops at the CNAME: the target holds no A, which the authority
	// section proves rather than this.
	partial := []dns.Record{rec("www.example.com.", .CNAME, "target.example.net.")}
	testing.expect(t, answers_question(partial, "www.example.com.", .A, .IN), "a chain that stops short should count")

	// The CNAME itself, when that is what was asked for.
	testing.expect(t, answers_question(partial, "www.example.com.", .CNAME, .IN), "a CNAME answers a CNAME question")

	// Anything at the name answers ANY.
	testing.expect(t, answers_question(direct, "www.example.com.", .ANY, .IN), "ANY takes whatever is there")

	// The attack: signed records, wrong name.
	elsewhere := []dns.Record{rec("evil.attacker.example.", .A)}
	testing.expect(
		t,
		!answers_question(elsewhere, "www.example.com.", .A, .IN),
		"records about another name do not answer this question",
	)

	// A chain that leads somewhere unrelated still has to start at the name
	// that was asked about.
	detached := []dns.Record {
		rec("other.example.com.", .CNAME, "target.example.net."),
		rec("target.example.net.", .A),
	}
	testing.expect(
		t,
		!answers_question(detached, "www.example.com.", .A, .IN),
		"a chain that does not start at the queried name proves nothing",
	)

	// Class has to match too.
	wrong_class := []dns.Record{rec("www.example.com.", .A)}
	wrong_class[0].class = .CH
	testing.expect(t, !answers_question(wrong_class, "www.example.com.", .A, .IN), "a different class is a different question")

	// A loop must terminate rather than spin.
	loop := []dns.Record {
		rec("a.example.com.", .CNAME, "b.example.com."),
		rec("b.example.com.", .CNAME, "a.example.com."),
	}
	testing.expect(t, !answers_question(loop, "a.example.com.", .A, .IN), "a CNAME loop should not be an answer")
}

@(test)
test_cached_key_set_holds_no_gaps :: proc(t: ^testing.T) {
	/*
	`cache_put` copies each key, re-parses the copy, and skips any that fail -
	but writes by index, so a skip leaves a zero-valued `Dnskey` behind rather
	than a shorter set.

	Nothing reaches that today: every key handed here has already been parsed
	from the same bytes once. It is worth closing anyway, because of the
	direction it fails in. A zero key carries algorithm 0, which no signature
	matches, and an RRset with nothing to check it against is reported
	unsupported - which `validate_rrset` turns into insecure. A cache quietly
	holding entries that mean "treat this zone as unsigned" is the wrong way
	round for a validator.
	*/
	v := make_validator(fixture_query, nil, Options{})
	defer destroy_validator(v)

	// One key that parses, one that cannot: too short to hold a public key.
	good := fixture_dnskey(t)
	bad := Dnskey {
		rdata = []u8{1, 1},
	}
	cache_put(v, "example.com.", .Secure, []Dnskey{good, bad}, 300, fixture_now())

	entry, found := v.zones["example.com."]
	testing.expect(t, found, "the zone should have been cached")
	if !found {
		return
	}
	for key, i in entry.keys {
		testing.expectf(t, len(key.rdata) > 0, "cached key %d is a gap left by a parse failure", i)
		testing.expectf(t, key.algorithm != 0, "cached key %d has no algorithm", i)
	}
	free_all(context.temp_allocator)
}

@(private = "file")
fixture_dnskey :: proc(t: ^testing.T) -> Dnskey {
	msg, _ := dns.decode_message(unhex(fixture("example_dnskey").wire), context.temp_allocator)
	for rec in msg.answer {
		if rec.type != .DNSKEY {
			continue
		}
		rdata, ok := raw_rdata(rec)
		if !ok {
			continue
		}
		key, perr := parse_dnskey(rdata)
		if perr == .None {
			return key
		}
	}
	testing.expect(t, false, "no usable DNSKEY in the fixture")
	return {}
}

@(test)
test_literal_wildcard_name_is_not_an_expansion :: proc(t: ^testing.T) {
	/*
	A name that is itself a wildcard - a query for `*.example.com.`, which is a
	perfectly ordinary name to hold records - is not a wildcard expansion.

	RFC 4034 section 3.1.3 counts the Labels field without the leading `*`, so a
	correct signature over `*.example.com.` says 2 where the name has 3
	separators. Reading that as "fewer labels than the owner, so the zone
	answered from a wildcard" demands a proof that the name does not exist, for
	a name that plainly does, and the answer is refused.
	*/
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.Record {
		name  = "*.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
	sig := Rrsig {
		type_covered = .A,
		algorithm    = ALG_ED25519,
		// The zone's own count: three labels, less the `*`.
		labels       = 2,
		original_ttl = 60,
		// A real window around FIXTURE_TIME. Timestamps compare as RFC 1982
		// serials, so max(u32) is not "far future" - it reads as long past.
		inception    = u32(FIXTURE_TIME) - 86400,
		expiration   = u32(FIXTURE_TIME) + 86400 * 365,
		key_tag      = 1,
		signer       = "example.com.",
		signature    = []u8{0},
	}

	// No keys, so this cannot verify - the verdict is not what is under test.
	// What matters is whether it was read as a wildcard expansion.
	_, encloser := check_signature(sig, "*.example.com.", .IN, records, nil, u32(FIXTURE_TIME), context.temp_allocator)
	testing.expect(t, encloser == "", "a literal wildcard name was taken for a wildcard expansion")
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Algorithm downgrade
// ---------------------------------------------------------------------------

// Never answers. The zone cache is primed directly below, so a lookup reaching
// here means the walk went somewhere the test did not intend.
@(private = "file")
no_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	return nil, false
}

/*
A zone-signing DNSKEY for an algorithm this build cannot verify.

Algorithm 12 (GOST R 34.10-2001) is deprecated and absent from
`algorithm_supported`, which is exactly the property under test: a key the
validator will hold, match against a signature, and then find it has no way to
check.
*/
@(private = "file")
ALG_UNSUPPORTED :: 12

@(private = "file")
unsupported_key :: proc() -> Dnskey {
	rdata := make([]u8, 4 + 32, context.temp_allocator)
	flags := u16(DNSKEY_FLAG_ZONE)
	rdata[0] = u8(flags >> 8)
	rdata[1] = u8(flags)
	rdata[2] = 3 // protocol, fixed
	rdata[3] = ALG_UNSUPPORTED
	for i in 0 ..< 32 {
		rdata[4 + i] = u8(i)
	}
	key, err := parse_dnskey(rdata)
	assert(err == .None)
	return key
}

/*
Establish `zone` as signed, holding one key nothing here can verify.

Primed rather than walked: the defect is in what `validate_rrset` concludes
once a zone is Secure, and building a whole crafted chain to reach that state
would put the fixture, not the verdict, under test.
*/
@(private = "file")
validator_with_zone :: proc(zone: string, status: Status) -> (^Validator, []Dnskey) {
	v := make_validator(no_query, nil, Options{})
	keys := make([]Dnskey, 1, context.temp_allocator)
	keys[0] = unsupported_key()

	cache_put(v, ".", .Secure, nil, MAX_ZONE_TTL, fixture_now())
	cache_put(v, zone, status, keys if status == .Secure else nil, MAX_ZONE_TTL, fixture_now())
	return v, keys
}

// An RRset and a signature over it that names the unsupported key.
@(private = "file")
unsupported_rrset :: proc(owner: string, key: Dnskey) -> (records: []dns.Record, sigs: []Rrsig) {
	records = make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.Record {
		name  = owner,
		type  = .A,
		class = .IN,
		ttl   = 3600,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}

	sigs = make([]Rrsig, 1, context.temp_allocator)
	sigs[0] = Rrsig {
		type_covered = .A,
		algorithm    = ALG_UNSUPPORTED,
		labels       = u8(label_count(owner)),
		original_ttl = 3600,
		inception    = u32(FIXTURE_TIME) - 3600,
		expiration   = u32(FIXTURE_TIME) + 3600,
		key_tag      = key.tag,
		signer       = owner,
		// Never examined: the algorithm is refused before any bytes are read.
		signature    = make([]u8, 64, context.temp_allocator),
	}
	return
}

@(private = "file")
downgrade_status :: proc(zone_status: Status) -> Status {
	ZONE :: "test."
	v, keys := validator_with_zone(ZONE, zone_status)
	defer destroy_validator(v)

	records, sigs := unsupported_rrset(ZONE, keys[0])
	budget := Budget{}
	status, _, _, _, _ := validate_rrset(
		v,
		&budget,
		ZONE,
		.A,
		.IN,
		records,
		sigs,
		u32(FIXTURE_TIME),
		fixture_now(),
		context.temp_allocator,
	)
	return status
}

/*
An RRset in a signed zone, carrying only a signature we cannot check, is forged
until proven otherwise.

RFC 6840 section 5.11: a validator that supports an algorithm in the zone's
DNSKEY set must see a valid signature from one of those algorithms. Reporting
the RRset unsigned instead hands an attacker the downgrade — a zone signed with
two algorithms publishes an RRSIG for each, so stripping the one we can verify
and altering the records leaves a response that reaches the client as merely
unvalidated rather than refused.

`validate_answer` folds this straight into its verdict and `validate` returns
it, so an `Insecure` here is an answer served.
*/
@(test)
test_unverifiable_algorithm_in_a_signed_zone_is_bogus :: proc(t: ^testing.T) {
	testing.expect_value(t, downgrade_status(.Secure), Status.Bogus)
	free_all(context.temp_allocator)
}

/*
The case the early return was written for, which has to keep working.

A zone whose delegation names no algorithm we support is insecure, not broken —
RFC 6840 section 5.2 — and the same unverifiable signature there means the data
is merely unsigned. `zone_step` settles that at the DS, so the verdict must
follow the zone rather than the signature.
*/
@(test)
test_unverifiable_algorithm_in_an_unsigned_zone_is_insecure :: proc(t: ^testing.T) {
	testing.expect_value(t, downgrade_status(.Insecure), Status.Insecure)
	free_all(context.temp_allocator)
}

// ---------------------------------------------------------------------------
// Upstream failures during the walk
// ---------------------------------------------------------------------------

@(private = "file")
Failing_Lookup :: struct {
	name:  string,
	type:  dns.Type,
	rcode: dns.Rcode,
}

// A response carrying nothing but the question and an rcode, the way an
// upstream that cannot answer replies.
@(private = "file")
failure_wire :: proc(name: string, type: dns.Type, rcode: dns.Rcode, allocator: mem.Allocator) -> []u8 {
	question := make([]dns.Question, 1, allocator)
	question[0] = dns.Question {
		name  = name,
		type  = type,
		class = .IN,
	}
	msg := dns.Message {
		question = question,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = u8(rcode) & 0xf

	wire, _, err := dns.encode_message(msg, allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
failing_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	fail := cast(^Failing_Lookup)ctx
	if type == fail.type && dns.name_equal_fold(name, fail.name) {
		return failure_wire(name, type, fail.rcode, allocator), true
	}
	return fixture_query(nil, name, type, allocator)
}

@(private = "file")
walk_with_failure :: proc(name: string, type: dns.Type, rcode: dns.Rcode) -> Status {
	fail := Failing_Lookup {
		name  = name,
		type  = type,
		rcode = rcode,
	}
	v := make_validator(failing_query, &fail, Options{})
	defer destroy_validator(v)

	status, _, _ := trust(v, "www.example.com.")
	return status
}

/*
An upstream that answers a DS lookup with an error has said nothing about the
delegation.

SERVFAIL and REFUSED carry no records, so the walk finds no DS and no denial of
existence - which reads exactly like a delegation whose proof was stripped.
Calling that bogus turns every upstream hiccup into a forgery report and a
SERVFAIL the client is told was a DNSSEC failure; the chain is merely
unavailable, which is what `validate` itself concludes for the same rcodes on
the response being validated.
*/
@(test)
test_ds_lookup_failure_is_indeterminate :: proc(t: ^testing.T) {
	testing.expect_value(t, walk_with_failure("com.", .DS, .Serv_Fail), Status.Indeterminate)
	free_all(context.temp_allocator)
	testing.expect_value(t, walk_with_failure("com.", .DS, .Refused), Status.Indeterminate)
	free_all(context.temp_allocator)
}

// The same for the DNSKEY half of a step: an error there leaves the zone's keys
// unknown rather than proving the zone lied about them.
@(test)
test_dnskey_lookup_failure_is_indeterminate :: proc(t: ^testing.T) {
	testing.expect_value(t, walk_with_failure("example.com.", .DNSKEY, .Serv_Fail), Status.Indeterminate)
	free_all(context.temp_allocator)
	testing.expect_value(t, walk_with_failure(".", .DNSKEY, .Refused), Status.Indeterminate)
	free_all(context.temp_allocator)
}

/*
The reason has to belong to the verdict that is returned.

`validate_answer` keeps the worst status across the answer's RRsets, and every
RRset that fails hands back a reason of its own. Those two are reported
together - to the log, and to the client as the text of the extended error - so
a reason left over from an RRset whose verdict lost is a reason describing
something other than why the answer was refused.

The shape is an everyday one: a CNAME chain crossing zones, one of which this
server could not reach the trust chain for while the rest are plainly unsigned.
`Insecure` ranks below `Indeterminate`, so the status stays with the
unreachable zone while the text follows the last RRset to fail - and the
operator is told "unsigned zone", which reads as the benign, expected verdict,
for a response actually refused because a lookup did not come back.

The wildcard-proof loop below the same code already guards this, and for the
same reason.
*/
@(test)
test_reason_belongs_to_the_returned_verdict :: proc(t: ^testing.T) {
	// example.com is signed, so a DNSKEY lookup that errors leaves its chain
	// unavailable rather than broken; reddit.com has no DS in the captured set
	// and is provably unsigned.
	fail := Failing_Lookup {
		name  = "example.com.",
		type  = .DNSKEY,
		rcode = .Serv_Fail,
	}
	v := make_validator(failing_query, &fail, Options{})
	defer destroy_validator(v)

	// Unsigned, and in that order: the RRset that decides the status first, the
	// one that merely overwrote the reason second.
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "a.example.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
	answer[1] = dns.Record {
		name  = "b.reddit.com.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {192, 0, 2, 2}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = "a.example.com.",
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.ra = true

	wire, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	result := validate(v, "a.example.com.", .A, wire, fixture_now())
	testing.expect_value(t, result.status, Status.Indeterminate)
	testing.expect_value(t, result.reason, "chain of trust unavailable")
	free_all(context.temp_allocator)
}
