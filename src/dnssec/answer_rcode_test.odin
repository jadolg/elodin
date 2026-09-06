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

/*
And the guard is not gated on the rest of the message holding up.

`worst` is the worst verdict any RRset in the answer section reached, and what
is in that section is the sender's choice. An attacker who has flipped the rcode
appends one unsigned RRset from a zone that really is unsigned - no forgery, no
signature to break - and the message comes out `Insecure` rather than `Secure`.
`Insecure` is forwarded to the client, so a guard that only ran on `Secure`
answers cost the attacker one extra record and gave back the whole attack: the
zone's signed records under a header saying the name does not exist.
*/
@(test)
test_an_unsigned_rrset_does_not_buy_past_the_rcode_guard :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	signed, serr := dns.decode_message(rc_unhex(rc_fixture("example_a").wire), context.temp_allocator)
	testing.expect(t, serr == .None, "the signed fixture did not decode")
	// reddit.com has no DS in com in the captured set, so its records are
	// genuinely unsigned and validate as `Insecure` on their own merits.
	unsigned, uerr := dns.decode_message(rc_unhex(rc_fixture("reddit_a").wire), context.temp_allocator)
	testing.expect(t, uerr == .None, "the unsigned fixture did not decode")

	answer := make([dynamic]dns.Record, 0, len(signed.answer) + len(unsigned.answer), context.temp_allocator)
	append(&answer, ..signed.answer)
	for rec in unsigned.answer {
		if rec.type == .A {
			append(&answer, rec)
		}
	}

	msg := signed
	msg.answer = answer[:]
	msg.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, eerr := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, eerr == .None, "the spliced message did not encode")

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(
		t,
		res.status == .Bogus,
		"one appended unsigned RRset made the flipped rcode %v (%q) instead of Bogus",
		res.status,
		res.reason,
	)
	testing.expect(t, len(res.answer) == 0, "a refused answer must name no authenticated RRsets")
	free_all(context.temp_allocator)
}

/*
And `ANY` is not a way round it either.

`chain_shape` reports whether the question was answered, and for `ANY` it stops
at the first record of any type at the queried name - a CNAME included. Writing
the guard in terms of that shape meant choosing between two wrong answers:
refuse an ordinary NXDOMAIN-after-a-CNAME asked as `ANY`, or exempt `ANY`
altogether and leave the whole of this bug open for one qtype. `dig ANY` is a
question people really ask, entries are keyed by type, and an exemption is a
thing to be steered towards rather than an edge to be tolerated.

`denial_contradicted` asks a different question - is the name the rcode speaks
for one this server has just proven exists - which has the same answer whatever
the client asked about, so neither wrong answer is on offer.
*/
@(test)
test_the_rcode_guard_is_not_escaped_by_asking_any :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	wire := rc_unhex(rc_fixture("example_a").wire)
	honest := validate(v, "www.example.com.", .ANY, wire, rc_now())
	testing.expectf(t, honest.status == .Secure, "the capture should validate as ANY (%v, %q)", honest.status, honest.reason)

	forged := validate(v, "www.example.com.", .ANY, with_rcode(wire, .NX_Domain), rc_now())
	testing.expectf(
		t,
		forged.status == .Bogus,
		"an ANY question let the flipped rcode through as %v (%q)",
		forged.status,
		forged.reason,
	)
	free_all(context.temp_allocator)
}

/*
The walk itself, at its own level.

Three of the shapes below cannot be built out of the captured chains - there is
no signed CNAME among them that stops short - and the rule is small enough that
driving it directly says more than a fixture would. What the tests above supply
is the part this cannot: that the sets it is handed are ones real signatures
produced.
*/
@(test)
test_denial_contradicted_reads_the_end_of_the_chain :: proc(t: ^testing.T) {
	rec :: proc(name: string, type: dns.Type, target := "") -> dns.Record {
		out := dns.Record{name = name, type = type, class = .IN, ttl = 60}
		if type == .CNAME {
			out.data = dns.Rdata_Name{name = target}
		} else {
			out.data = dns.Rdata_A{addr = {203, 0, 113, 1}}
		}
		return out
	}
	set :: proc(name: string, type: dns.Type) -> Authenticated_Set {
		return Authenticated_Set{name = name, type = type, class = .IN}
	}

	// A record at the queried name, with no chain: the rcode denies a name the
	// answer has just proven.
	direct := []dns.Record{rec("www.example.com.", .A)}
	testing.expect(
		t,
		denial_contradicted(direct, []Authenticated_Set{set("www.example.com.", .A)}, "www.example.com.", .IN),
		"a proven name under NXDOMAIN was not read as a contradiction",
	)

	// A chain that stops short. The rcode is about `target.example.`, which
	// nothing here says anything about - RFC 2308 section 2.1's own shape, and
	// the one `denial_claimed` declines to vouch for rather than refusing.
	chain := []dns.Record{rec("www.example.com.", .CNAME, "target.example.")}
	testing.expect(
		t,
		!denial_contradicted(chain, []Authenticated_Set{set("www.example.com.", .CNAME)}, "www.example.com.", .IN),
		"an ordinary NXDOMAIN after a CNAME was called a contradiction",
	)

	// The same chain, with the target's own records in the answer. Now the
	// denied name is the proven one.
	full := []dns.Record{rec("www.example.com.", .CNAME, "target.example."), rec("target.example.", .A)}
	kept_full := []Authenticated_Set{set("www.example.com.", .CNAME), set("target.example.", .A)}
	testing.expect(
		t,
		denial_contradicted(full, kept_full, "www.example.com.", .IN),
		"a proven chain target under NXDOMAIN was not read as a contradiction",
	)

	// A record of a type nobody asked for still proves the name. The question
	// this asks is existence, not whether the answer was answered.
	other := []dns.Record{rec("www.example.com.", .CNAME, "target.example."), rec("target.example.", .AAAA)}
	kept_other := []Authenticated_Set{set("www.example.com.", .CNAME), set("target.example.", .AAAA)}
	testing.expect(
		t,
		denial_contradicted(other, kept_other, "www.example.com.", .IN),
		"a proven name was missed because its type was not the one asked about",
	)

	// Records the verdict does not cover are not read at all, which is what
	// stops the sender steering the walk: the same two shapes, with nothing
	// authenticated, say nothing.
	testing.expect(t, !denial_contradicted(direct, nil, "www.example.com.", .IN), "an unauthenticated record was counted")
	testing.expect(
		t,
		!denial_contradicted(full, []Authenticated_Set{set("www.example.com.", .CNAME)}, "www.example.com.", .IN),
		"an unauthenticated record at the chain's end was counted",
	)

	// A loop is a stall and proves nothing either way.
	loop := []dns.Record{rec("a.example.", .CNAME, "b.example."), rec("b.example.", .CNAME, "a.example.")}
	kept_loop := []Authenticated_Set{set("a.example.", .CNAME), set("b.example.", .CNAME)}
	testing.expect(t, !denial_contradicted(loop, kept_loop, "a.example.", .IN), "a CNAME loop was read as a proof")
	free_all(context.temp_allocator)
}
