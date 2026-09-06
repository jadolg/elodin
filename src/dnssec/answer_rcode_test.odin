package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
The header's rcode against the records the answer section proves.

`validate_answer` reaches its verdict from signed data alone. That is the right
way round for deciding the *shape* of an answer - the rcode is the sender's to
write, and reading it to choose a path would hand the sender the choice. It
leaves one thing unsaid, though: once the shape is settled from signatures, the
rcode is a claim standing beside them, and NXDOMAIN standing beside a verified
record of the type asked for is a claim those signatures contradict.

The attack needs no forgery. An on-path attacker on the plain UDP or TCP leg to
an upstream - or the upstream itself - takes the zone's own signed answer for
`_25._tcp.mail.example.com. TLSA` and rewrites one nibble of the header. The
RRset and its RRSIG are untouched and still verify, so the verdict was `Secure`,
the AD bit went out over it, and the client read an authenticated statement that
a name it has signed data for does not exist. Consumers decide on the rcode
before they look at the answer section - glibc's `res_query` returns
HOST_NOT_FOUND, Go's `checkHeader` returns `errNoSuchHost` - so the record is
there and nobody reads it. A DANE client falls back to opportunistic TLS, which
the same attacker is placed to intercept.

RFC 4035 section 5.3 lets a validator authenticate RRsets, not a header claim
that contradicts them. So the rcode is checked *against* the shape rather than
consulted to pick it, which is what `ad_scope_test.odin`'s objection to reading
the rcode asks for: adding or removing records cannot move this, because the
shape it is checked against was already settled from signed data.
*/

@(private = "file")
rc_fixture :: proc(key: string) -> Fixture {
	for f in FIXTURES {
		if f.key == key {
			return f
		}
	}
	return {}
}

@(private = "file")
rc_unhex :: proc(text: string, allocator := context.temp_allocator) -> []u8 {
	out, _ := decode_hex(text, allocator)
	return out
}

@(private = "file")
rc_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return rc_unhex(f.wire, allocator), true
		}
	}
	return nil, false
}

@(private = "file")
rc_now :: proc() -> time.Time {
	return time.unix(FIXTURE_TIME, 0)
}

// The whole of the attacker's work: the low nibble of the flags' second byte,
// where the rcode lives. Nothing else in the message is touched, so every
// signature in it still verifies.
@(private = "file")
with_rcode :: proc(wire: []u8, rcode: dns.Rcode, allocator := context.temp_allocator) -> []u8 {
	out := make([]u8, len(wire), allocator)
	copy(out, wire)
	out[3] = (out[3] & 0xf0) | (u8(rcode) & 0x0f)
	return out
}

@(test)
test_nxdomain_over_a_signed_answer_is_bogus :: proc(t: ^testing.T) {
	Case :: struct {
		key:   string,
		qname: string,
	}
	// One per algorithm the positive path validates with, so a verdict that
	// depended on which signature was checked would show up as a partial pass.
	cases := []Case {
		{"example_a", "www.example.com."},
		{"cloudflare_a", "www.cloudflare.com."},
		{"ed25519_a", "ed25519.nl."},
	}
	for c in cases {
		v := make_validator(rc_query, nil, Options{})
		defer destroy_validator(v)

		wire := rc_unhex(rc_fixture(c.key).wire)

		// The capture as it stands: a genuine, signed positive answer. Asserted
		// first so a fixture that stopped validating for some other reason
		// cannot be mistaken for the guard below doing its job.
		honest := validate(v, c.qname, .A, wire, rc_now())
		testing.expectf(t, honest.status == .Secure, "%s should validate as captured (%v, %q)", c.key, honest.status, honest.reason)

		forged := validate(v, c.qname, .A, with_rcode(wire, .NX_Domain), rc_now())
		testing.expectf(
			t,
			forged.status == .Bogus,
			"%s with its rcode flipped to NXDOMAIN was called %v (%q); an authenticated denial for a name whose signed records are in the answer section",
			c.key,
			forged.status,
			forged.reason,
		)
		// Nothing is named, so nothing survives `strip_unauthenticated` and no
		// caller can prune a message down to a set this verdict vouches for.
		testing.expect(t, len(forged.answer) == 0, "a refused answer must name no authenticated RRsets")
		free_all(context.temp_allocator)
	}
}

/*
The guard is about the contradiction, not about NXDOMAIN.

A real denial still validates, and a real positive answer is not made bogus by
some other rcode arriving with it: only the pairing of NXDOMAIN with a verified
record of the type asked for is refused.
*/
@(test)
test_the_rcode_guard_leaves_honest_answers_alone :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	// A genuine NXDOMAIN, proven by NSEC in the root, with an empty answer
	// section - the shape this guard must not touch.
	denial := validate(v, "zzzz-does-not-exist-xq7.", .A, rc_unhex(rc_fixture("nxdomain_root").wire), rc_now())
	testing.expect_value(t, denial.status, Status.Secure)

	// And a genuine NODATA, which is NOERROR with an SOA behind it.
	nodata := validate(
		v,
		"nosuchname-xq7.cloudflare.com.",
		.A,
		rc_unhex(rc_fixture("nodata_cloudflare").wire),
		rc_now(),
	)
	testing.expect_value(t, nodata.status, Status.Secure)
	free_all(context.temp_allocator)
}
