package dnssec

import "core:mem"
import "core:testing"
import "elodin:dns"

/*
The NSEC3 machinery on its own, against the worked example of RFC 5155
appendix A.

The end-to-end fixtures elsewhere in this package prove that a real NSEC3 denial
validates, but they exercise one shape each and they cannot reach the cases a
zone never produces on purpose: an opt-out span standing in for a proof, an
iteration count chosen to burn the validator's CPU, a hash algorithm nobody
defined, a chain whose spans do not line up with the name being asked about.
Those are the shapes an attacker picks, so they are the ones tested here.

Every hash below is the published value from RFC 5155 appendix A - salt
`aabbccdd`, 12 iterations - which makes this a conformance test rather than a
test of whatever this implementation happens to compute. A canonicalisation bug
that agreed with itself would still be caught, because the numbers came from
outside.

The zone is that appendix's, and its chain in hash order is:

	example.        0p9m...  ->  2t7b...
	ns1.example.    2t7b...  ->  2vpt...
	x.y.w.example.  2vpt...  ->  35mt...
	a.example.      35mt...  ->  b4um...
	x.w.example.    b4um...  ->  gjeq...
	ai.example.     gjeq...  ->  ji6n...
	y.w.example.    ji6n...  ->  k8ud...
	w.example.      k8ud...  ->  q04j...
	ns2.example.    q04j...  ->  r53b...
	*.w.example.    r53b...  ->  t644...
	xx.example.     t644...  ->  0p9m...   (the wrap)
*/

@(private = "file")
A_SALT := []u8{0xaa, 0xbb, 0xcc, 0xdd}

@(private = "file")
A_ITERATIONS :: 12

// The chain, by the first label of each owner name.
@(private = "file")
H_EXAMPLE :: "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
@(private = "file")
H_NS1 :: "2t7b4g4vsa5smi47k61mv5bv1a22bojr"
@(private = "file")
H_XYW :: "2vptu5timamqttgl4luu9kg21e0aor3s"
@(private = "file")
H_A :: "35mthgpgcu1qg68fab165klnsnk3dpvl"
@(private = "file")
H_XW :: "b4um86eghhds6nea196smvmlo4ors995"
@(private = "file")
H_AI :: "gjeqe526plbf1g8mklp59enfd789njgi"
@(private = "file")
H_YW :: "ji6neoaepv8b5o6k4ev33abha8ht9fgc"
@(private = "file")
H_W :: "k8udemvp1j2f7eg6jebps17vp3n8i58h"
@(private = "file")
H_NS2 :: "q04jkcevqvmu85r014c7dkba38o0ji5r"
@(private = "file")
H_STAR_W :: "r53bq7cc2uvmubfu5ocmm6pers9tk9en"
@(private = "file")
H_XX :: "t644ebqk9bibcna874givr6joj62mlhv"

@(private = "file")
A_VECTORS := []struct {
	name: string,
	hash: string,
}{
	{"example.", H_EXAMPLE},
	{"ns1.example.", H_NS1},
	{"x.y.w.example.", H_XYW},
	{"a.example.", H_A},
	{"x.w.example.", H_XW},
	{"ai.example.", H_AI},
	{"y.w.example.", H_YW},
	{"w.example.", H_W},
	{"ns2.example.", H_NS2},
	{"*.w.example.", H_STAR_W},
	{"xx.example.", H_XX},
}

// A type bit map with just these types set. Every type used here is below 256,
// so one window holds them all.
@(private = "file")
types_bitmap :: proc(types: []dns.Type) -> []u8 {
	if len(types) == 0 {
		return nil
	}
	high := 0
	for type in types {
		if int(type) > high {
			high = int(type)
		}
	}
	length := high / 8 + 1
	out := make([]u8, 2 + length, context.temp_allocator)
	out[0] = 0
	out[1] = u8(length)
	for type in types {
		out[2 + int(type) / 8] |= 0x80 >> u8(int(type) % 8)
	}
	return out
}

@(private = "file")
n3 :: proc(owner, next: string, types: []dns.Type, flags: u8 = 0, iterations: u16 = A_ITERATIONS) -> Nsec3_Rr {
	owner_hash := make([]u8, 20, context.temp_allocator)
	next_hash := make([]u8, 20, context.temp_allocator)
	on, ook := base32hex_decode(owner, owner_hash)
	nn, nok := base32hex_decode(next, next_hash)
	if !ook || !nok {
		return {}
	}
	return Nsec3_Rr {
		hash = owner_hash[:on],
		rr = Nsec3 {
			hash_algorithm = NSEC3_HASH_SHA1,
			flags = flags,
			iterations = iterations,
			salt = A_SALT,
			next_hash = next_hash[:nn],
			types = types_bitmap(types),
		},
	}
}

// The whole appendix A chain, with the bit maps that zone publishes.
@(private = "file")
a_zone :: proc() -> []Nsec3_Rr {
	zone := make([dynamic]Nsec3_Rr, context.temp_allocator)
	append(&zone, n3(H_EXAMPLE, H_NS1, {.NS, .SOA, .MX, .RRSIG, .DNSKEY, .NSEC3PARAM}))
	append(&zone, n3(H_NS1, H_XYW, {.A, .RRSIG}))
	append(&zone, n3(H_XYW, H_A, {.MX, .RRSIG}))
	append(&zone, n3(H_A, H_XW, {.NS, .DS, .RRSIG}))
	append(&zone, n3(H_XW, H_AI, {.MX, .RRSIG}))
	append(&zone, n3(H_AI, H_YW, {.A, .HINFO, .AAAA, .RRSIG}))
	append(&zone, n3(H_YW, H_W, {.NS}))
	append(&zone, n3(H_W, H_NS2, {.NS}))
	append(&zone, n3(H_NS2, H_STAR_W, {.A, .RRSIG}))
	append(&zone, n3(H_STAR_W, H_XX, {.MX, .RRSIG}))
	append(&zone, n3(H_XX, H_EXAMPLE, {.A, .HINFO, .AAAA, .RRSIG}))
	return zone[:]
}

@(test)
test_nsec3_hash_matches_the_rfc5155_vectors :: proc(t: ^testing.T) {
	// The published numbers, not ours. A bug in the canonical wire form, in the
	// salt handling or in the iteration loop moves every one of these.
	for vector in A_VECTORS {
		got: [20]u8
		testing.expectf(t, nsec3_hash(vector.name, A_SALT, A_ITERATIONS, got[:]), "%s should hash", vector.name)

		want: [20]u8
		n, decoded := base32hex_decode(vector.hash, want[:])
		testing.expectf(t, decoded && n == 20, "the vector for %s should decode", vector.name)
		testing.expectf(
			t,
			mem.compare(got[:], want[:]) == 0,
			"%s hashed to %x, RFC 5155 appendix A says %x",
			vector.name,
			got,
			want,
		)
	}
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_hash_is_case_insensitive :: proc(t: ^testing.T) {
	/*
	The hash runs over the canonical wire name, which is lowercased. A query
	whose case was randomised on the way out (0x20 encoding) has to hash to the
	same place as the name the zone signed, or every proof about it fails.
	*/
	lower, mixed: [20]u8
	testing.expect(t, nsec3_hash("a.example.", A_SALT, A_ITERATIONS, lower[:]), "the name should hash")
	testing.expect(t, nsec3_hash("A.ExAmPlE.", A_SALT, A_ITERATIONS, mixed[:]), "the mixed-case name should hash")
	testing.expect(t, mem.compare(lower[:], mixed[:]) == 0, "case must not change the hash")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_hash_refuses_a_short_buffer_and_an_oversized_salt :: proc(t: ^testing.T) {
	short: [19]u8
	testing.expect(t, !nsec3_hash("example.", A_SALT, 0, short[:]), "a buffer under 20 bytes cannot take a digest")

	out: [20]u8
	big := make([]u8, 256, context.temp_allocator)
	testing.expect(t, !nsec3_hash("example.", big, 0, out[:]), "a salt cannot exceed 255 bytes")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_iteration_ceiling_refuses_the_hash :: proc(t: ^testing.T) {
	/*
	The iteration count is the zone's to choose and the work is ours, so an
	absurd one is a denial-of-service lever. Refusing to compute the hash makes
	every proof built on that record fail, which downgrades the answer to
	insecure rather than letting it through - and never spends the CPU.
	*/
	rr := n3(H_EXAMPLE, H_NS1, {.NS, .SOA}).rr
	out: [20]u8
	testing.expect(t, nsec3_hash_with(rr, "example.", out[:], A_ITERATIONS), "12 iterations at a ceiling of 12 is fine")
	testing.expect(t, !nsec3_hash_with(rr, "example.", out[:], 11), "12 iterations past a ceiling of 11 must be refused")

	// And the refusal has to reach the verdict, not just the hash.
	zone := a_zone()
	for &record in zone {
		record.rr.iterations = 5000
	}
	testing.expect_value(t, nsec3_proves_name_error(zone, "nx.example.", "example.", 150), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_unknown_hash_algorithm_is_refused :: proc(t: ^testing.T) {
	// SHA-1 is the only hash RFC 5155 defines. A record naming another one
	// cannot be checked, so it must not be read as proving anything.
	rr := n3(H_EXAMPLE, H_NS1, {.NS, .SOA}).rr
	rr.hash_algorithm = 2
	out: [20]u8
	testing.expect(t, !nsec3_hash_with(rr, "example.", out[:], A_ITERATIONS), "an unknown hash algorithm is unusable")

	zone := a_zone()
	for &record in zone {
		record.rr.hash_algorithm = 2
	}
	testing.expect_value(t, nsec3_proves_name_error(zone, "nx.example.", "example.", A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_covering_span_wraps_at_the_end_of_the_chain :: proc(t: ^testing.T) {
	/*
	`xx.example.` holds the last span, and its next hash points back at the
	apex. A name hashing above it is inside that span even though the comparison
	against the owner says "greater". Reading the span as empty instead would
	leave a slice of the hash space no record ever covers, and every name that
	landed there would fail to be proven absent.

	`w28.example.` hashes to tmgp..., which is past xx.example.'s t644... .
	*/
	zone := a_zone()
	cover, covered := nsec3_covering(zone, "w28.example.", A_ITERATIONS)
	testing.expect(t, covered, "a name past the last owner should fall in the wrap-around span")
	if covered {
		last := zone[len(zone) - 1]
		testing.expect(t, mem.compare(cover.hash, last.hash) == 0, "the wrapping span is the last one")
	}
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_covering_never_covers_a_name_it_matches :: proc(t: ^testing.T) {
	// A span runs between its ends and does not include them. A record that
	// both matched and covered a name would prove the name absent and present
	// at once.
	zone := a_zone()
	_, covered := nsec3_covering(zone, "a.example.", A_ITERATIONS)
	testing.expect(t, !covered, "a name with a record of its own is not covered by any span")

	_, matched := nsec3_matching(zone, "a.example.", A_ITERATIONS)
	testing.expect(t, matched, "and it does match one")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_covering_ignores_a_span_of_the_wrong_width :: proc(t: ^testing.T) {
	/*
	Both ends of a span have to be as wide as the digest, or the byte compare is
	reading two different things against each other. A sender who truncates a
	next hash to a single byte would otherwise get a span that swallows most of
	the hash space and proves whatever they like absent.
	*/
	// `nx.example.` hashes to 9b86... . A next hash cut down to the single byte
	// 0xff sorts above that and above the apex's 0653..., so read as a span it
	// runs from the apex to very nearly the top of the hash space and swallows
	// the name - a proof of absence for a name the zone never spoke about.
	truncated := []Nsec3_Rr{n3(H_EXAMPLE, H_XX, {.NS})}
	truncated[0].rr.next_hash = []u8{0xff}
	_, covered := nsec3_covering(truncated, "nx.example.", A_ITERATIONS)
	testing.expect(t, !covered, "a next hash narrower than the digest cannot describe a span")

	// The same trick from the other end: an owner hash of one low byte, with a
	// genuine next hash above the target.
	short_owner := []Nsec3_Rr{n3(H_EXAMPLE, H_XX, {.NS})}
	short_owner[0].hash = short_owner[0].hash[:1]
	_, covered_owner := nsec3_covering(short_owner, "nx.example.", A_ITERATIONS)
	testing.expect(t, !covered_owner, "an owner hash narrower than the digest cannot either")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_closest_encloser_walks_up_to_the_deepest_match :: proc(t: ^testing.T) {
	zone := a_zone()
	// `deep.x.y.w.example.` has no record; `x.y.w.example.` does, so that is the
	// closest encloser and the name one label longer is the next closer.
	encloser, next_closer, ok := nsec3_closest_encloser(zone, "deep.x.y.w.example.", "example.", A_ITERATIONS)
	testing.expect(t, ok, "the walk should find an encloser")
	testing.expect_value(t, encloser, "x.y.w.example.")
	testing.expect_value(t, next_closer, "deep.x.y.w.example.")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_closest_encloser_refuses_a_name_that_exists :: proc(t: ^testing.T) {
	// A match on the queried name itself contradicts whatever the caller was
	// about to prove, so there is no encloser to hand back.
	zone := a_zone()
	_, _, ok := nsec3_closest_encloser(zone, "a.example.", "example.", A_ITERATIONS)
	testing.expect(t, !ok, "a name with a record of its own has no next closer")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_closest_encloser_refuses_out_of_zone_and_unanchored_walks :: proc(t: ^testing.T) {
	zone := a_zone()
	_, _, out_of_zone := nsec3_closest_encloser(zone, "nx.other.", "example.", A_ITERATIONS)
	testing.expect(t, !out_of_zone, "a name outside the zone cannot be enclosed by it")

	// Without the apex record the walk reaches the top having matched nothing,
	// which RFC 5155 sections 8.4 onwards treat as no proof at all rather than
	// as an encloser at the apex.
	no_apex := make([dynamic]Nsec3_Rr, context.temp_allocator)
	for record in zone[1:] {
		append(&no_apex, record)
	}
	_, _, unanchored := nsec3_closest_encloser(no_apex[:], "nx.example.", "example.", A_ITERATIONS)
	testing.expect(t, !unanchored, "a walk that reaches the apex without a match proves nothing")
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_name_error_needs_the_name_and_its_wildcard_covered :: proc(t: ^testing.T) {
	/*
	RFC 5155 section 8.4. `nx.example.` hashes into ai.example.'s span and so
	does `*.example.`, so the appendix A chain proves it absent. Drop either
	cover and the proof has to fail: without the second, a zone holding a
	wildcard could be made to look empty at that name.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_name_error(zone, "nx.example.", "example.", A_ITERATIONS), Proof.Proven)

	// The apex match plus one span, with the span that covers both the next
	// closer and the wildcard taken out.
	without_cover := []Nsec3_Rr{n3(H_EXAMPLE, H_NS1, {.NS, .SOA, .MX, .RRSIG, .DNSKEY, .NSEC3PARAM})}
	testing.expect_value(
		t,
		nsec3_proves_name_error(without_cover, "nx.example.", "example.", A_ITERATIONS),
		Proof.Failed,
	)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_opt_out_span_does_not_prove_a_name_error :: proc(t: ^testing.T) {
	/*
	An opt-out span is allowed to hold unsigned delegations the zone never
	published a record for, so it says nothing about what is inside it. Reading
	one as a name error is how an attacker turns "this name might exist,
	unsigned" into "this name does not exist" - and NXDOMAIN for a name that is
	really there is the denial of service that RFC 5155 section 12.1.1 warns
	about. The verdict has to be Opt_Out, which the caller turns into an
	unsigned answer rather than a proven one.
	*/
	zone := a_zone()
	// Index 5 is ai.example.'s record, the span holding both `nx.example.` and
	// `*.example.`.
	zone[5].rr.flags |= NSEC3_FLAG_OPT_OUT
	testing.expect_value(t, nsec3_proves_name_error(zone, "nx.example.", "example.", A_ITERATIONS), Proof.Opt_Out)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_data_reads_the_bit_map_on_the_matching_record :: proc(t: ^testing.T) {
	// RFC 5155 section 8.5.
	zone := a_zone()
	testing.expect_value(
		t,
		nsec3_proves_no_data(zone, "ai.example.", "example.", .TXT, A_ITERATIONS),
		Proof.Proven,
	)
	// The type is right there in the bit map, so the answer should have carried
	// it and the denial is a lie.
	testing.expect_value(t, nsec3_proves_no_data(zone, "ai.example.", "example.", .A, A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_data_refuses_a_name_that_is_a_cname :: proc(t: ^testing.T) {
	/*
	A CNAME answers for every type, so a record whose bit map carries one can
	never prove that a type is missing - the client should have been sent the
	CNAME instead.
	*/
	zone := []Nsec3_Rr{n3(H_AI, H_YW, {.CNAME, .RRSIG})}
	testing.expect_value(t, nsec3_proves_no_data(zone, "ai.example.", "example.", .A, A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_data_refuses_a_parent_side_record :: proc(t: ^testing.T) {
	/*
	NS without SOA is the parent's half of a zone cut. It describes the
	delegation, not the child's contents, so it cannot say a type is missing at
	the child - RFC 6840 section 4.4. DS is the exception: that type genuinely
	lives on the parent side, which is where the question was asked.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_no_data(zone, "y.w.example.", "example.", .A, A_ITERATIONS), Proof.Failed)
	testing.expect_value(t, nsec3_proves_no_data(zone, "y.w.example.", "example.", .DS, A_ITERATIONS), Proof.Proven)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_data_falls_back_to_the_wildcard :: proc(t: ^testing.T) {
	/*
	RFC 5155 section 8.7: nothing on the name itself, so a wildcard is what
	answered, and the proof is that the wildcard has no such type either.
	`foo.w.example.` has no record, `w.example.` matches, its next closer is
	covered, and `*.w.example.` matches with MX but no A.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_no_data(zone, "foo.w.example.", "example.", .A, A_ITERATIONS), Proof.Proven)
	// The wildcard does hold MX, so an MX answer was owed.
	testing.expect_value(t, nsec3_proves_no_data(zone, "foo.w.example.", "example.", .MX, A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_ds_reads_an_explicit_unsigned_delegation :: proc(t: ^testing.T) {
	/*
	RFC 5155 section 8.9. `y.w.example.` is delegated and carries no DS, which
	ends the chain of trust there honestly. `a.example.` carries one, so
	claiming otherwise is an attempt to detach a signed subtree.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_no_ds(zone, "y.w.example.", "example.", A_ITERATIONS), Proof.Proven)
	testing.expect_value(t, nsec3_proves_no_ds(zone, "a.example.", "example.", A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_ds_refuses_an_apex_or_a_non_delegation :: proc(t: ^testing.T) {
	/*
	A record with SOA is the zone's own apex, and one without NS is an ordinary
	name. Neither is a delegation, so neither can show that a delegation is
	unsigned. Accepting either would let any signed name in the zone be used to
	cut the subtree below it out of the chain.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_no_ds(zone, "example.", "example.", A_ITERATIONS), Proof.Failed)
	testing.expect_value(t, nsec3_proves_no_ds(zone, "ai.example.", "example.", A_ITERATIONS), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_ds_accepts_an_opt_out_cover_and_nothing_less :: proc(t: ^testing.T) {
	/*
	The one case opt-out exists for: the parent published no NSEC3 for a
	delegation it does not sign, so the next closer name falls in an opt-out
	span. Without the flag the same span proves nothing, and treating it as a
	proof would let an attacker who can drop records detach any subtree.
	*/
	zone := a_zone()
	testing.expect_value(t, nsec3_proves_no_ds(zone, "nx.example.", "example.", A_ITERATIONS), Proof.Failed)

	opt_out := a_zone()
	opt_out[5].rr.flags |= NSEC3_FLAG_OPT_OUT
	testing.expect_value(t, nsec3_proves_no_ds(opt_out, "nx.example.", "example.", A_ITERATIONS), Proof.Proven)
	free_all(context.temp_allocator)
}

@(test)
test_nsec3_no_delegation_reads_matches_and_covers :: proc(t: ^testing.T) {
	/*
	Whether the parent's keys still reach a name. An ordinary name and the apex
	are not zone cuts; a delegation is. A name that does not exist is not
	delegated either - but only if the span saying so is not opt-out, because an
	opt-out span may be hiding exactly the delegation being ruled out.
	*/
	zone := a_zone()
	testing.expect(t, nsec3_proves_no_delegation(zone, "ai.example.", "example.", A_ITERATIONS), "an ordinary name is not a cut")
	testing.expect(t, nsec3_proves_no_delegation(zone, "example.", "example.", A_ITERATIONS), "the apex has SOA, so it is not a cut below the parent")
	testing.expect(t, !nsec3_proves_no_delegation(zone, "y.w.example.", "example.", A_ITERATIONS), "a delegation is a cut")
	testing.expect(t, nsec3_proves_no_delegation(zone, "nx.example.", "example.", A_ITERATIONS), "a covered absent name is not a cut")

	opt_out := a_zone()
	opt_out[5].rr.flags |= NSEC3_FLAG_OPT_OUT
	testing.expect(t, !nsec3_proves_no_delegation(opt_out, "nx.example.", "example.", A_ITERATIONS), "an opt-out span cannot rule a delegation out")
	free_all(context.temp_allocator)
}

@(test)
test_base32hex_decode_rejects_characters_outside_the_alphabet :: proc(t: ^testing.T) {
	/*
	NSEC3 owner labels use the extended hex alphabet of RFC 4648 section 7,
	whose digits sort in the same order as the bytes they stand for. Anything
	outside it - the `w` through `z` of ordinary base32, padding, a label that
	was never a hash at all - has to be refused rather than folded into some
	nearby value, or two different owner names collapse onto one position in the
	chain.
	*/
	out: [20]u8
	_, ok := base32hex_decode("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", out[:])
	testing.expect(t, ok, "the apex hash is valid base32hex")

	rejects := []string{"0p9mhaveqvm6t7vbl5lop2u3t2rp3toz", "0p9mhaveqvm6t7vbl5lop2u3t2rp3to=", "not a hash"}
	for bad in rejects {
		_, decoded := base32hex_decode(bad, out[:])
		testing.expectf(t, !decoded, "%q should not decode", bad)
	}

	// And it must not write past the buffer it was given.
	small: [4]u8
	_, overflowed := base32hex_decode("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", small[:])
	testing.expect(t, !overflowed, "a hash longer than the buffer should be refused")
	free_all(context.temp_allocator)
}
