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
	testing.expect_value(t, sweep(v), 0)
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
