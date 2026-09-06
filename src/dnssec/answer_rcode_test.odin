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
		denial_contradicted(direct, []Authenticated_Set{set("www.example.com.", .A)}, "www.example.com.", .A, .IN),
		"a proven name under NXDOMAIN was not read as a contradiction",
	)

	// A chain that stops short. The rcode is about `target.example.`, which
	// nothing here says anything about - RFC 2308 section 2.1's own shape, and
	// the one `denial_claimed` declines to vouch for rather than refusing.
	chain := []dns.Record{rec("www.example.com.", .CNAME, "target.example.")}
	testing.expect(
		t,
		!denial_contradicted(chain, []Authenticated_Set{set("www.example.com.", .CNAME)}, "www.example.com.", .A, .IN),
		"an ordinary NXDOMAIN after a CNAME was called a contradiction",
	)

	/*
	The same records, asked about as themselves. RFC 1034 section 4.3.2 step 3a
	restarts the walk at the target only when the query type does *not* match
	the CNAME, so for `CNAME` and for `ANY` this record is the answer and the
	rcode is about the name that was asked about - which the record proves.
	Walked past as a hop, a flipped rcode over a signed `dig CNAME` answer came
	back `Secure` with AD set.
	*/
	kept_chain := []Authenticated_Set{set("www.example.com.", .CNAME)}
	testing.expect(
		t,
		denial_contradicted(chain, kept_chain, "www.example.com.", .CNAME, .IN),
		"a CNAME question walked past the record that refutes the denial",
	)
	testing.expect(
		t,
		denial_contradicted(chain, kept_chain, "www.example.com.", .ANY, .IN),
		"an ANY question walked past the record that refutes the denial",
	)

	// The same chain, with the target's own records in the answer. Now the
	// denied name is the proven one.
	full := []dns.Record{rec("www.example.com.", .CNAME, "target.example."), rec("target.example.", .A)}
	kept_full := []Authenticated_Set{set("www.example.com.", .CNAME), set("target.example.", .A)}
	testing.expect(
		t,
		denial_contradicted(full, kept_full, "www.example.com.", .A, .IN),
		"a proven chain target under NXDOMAIN was not read as a contradiction",
	)

	// A record of a type nobody asked for still proves the name. The question
	// this asks is existence, not whether the answer was answered.
	other := []dns.Record{rec("www.example.com.", .CNAME, "target.example."), rec("target.example.", .AAAA)}
	kept_other := []Authenticated_Set{set("www.example.com.", .CNAME), set("target.example.", .AAAA)}
	testing.expect(
		t,
		denial_contradicted(other, kept_other, "www.example.com.", .A, .IN),
		"a proven name was missed because its type was not the one asked about",
	)

	// Records the verdict does not cover are not read at all, which is what
	// stops the sender steering the walk: the same two shapes, with nothing
	// authenticated, say nothing.
	testing.expect(t, !denial_contradicted(direct, nil, "www.example.com.", .A, .IN), "an unauthenticated record was counted")
	testing.expect(
		t,
		!denial_contradicted(full, []Authenticated_Set{set("www.example.com.", .CNAME)}, "www.example.com.", .A, .IN),
		"an unauthenticated record at the chain's end was counted",
	)

	// A loop is a stall and proves nothing either way.
	loop := []dns.Record{rec("a.example.", .CNAME, "b.example."), rec("b.example.", .CNAME, "a.example.")}
	kept_loop := []Authenticated_Set{set("a.example.", .CNAME), set("b.example.", .CNAME)}
	testing.expect(t, !denial_contradicted(loop, kept_loop, "a.example.", .A, .IN), "a CNAME loop was read as a proof")
	free_all(context.temp_allocator)
}

/*
The two ways round the guard that cost the attacker one more byte each.

Both were found reviewing the guard above rather than reported with #271, and
both reach the same place by a different door: the client reads a name error for
a signed name, and no proof of it was ever asked for. Neither needs a forgery.
*/

/*
One unsigned record must not reroute a forged denial away from its proof.

`validate` picks the path from the answer section holding *something* it could
authenticate - any record, at any name. So a forged NXDOMAIN for a signed name
is `Bogus` while that section is empty, because `validate_denial` demands a
proof and finds none; append one record from a zone that really is unsigned and
the message goes to `validate_answer` instead, where nothing ever demanded one.
The check that catches it there is `shape == .None`, and it used to be gated on
`worst` - which the same appended record had already dragged to `Insecure`.

`Insecure` is forwarded to the client. So the record bought the attacker the
denial that the empty version was refused for, in exchange for a CNAME anyone
can copy out of an unsigned zone.
*/
@(test)
test_an_unsigned_record_does_not_reroute_a_forged_denial :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = "www.example.com.", type = .A, class = .IN}
	forged := dns.Message{question = question}
	forged.flags.qr = true
	forged.flags.rcode = u8(dns.Rcode.NX_Domain)

	// Empty, this is already refused: `validate_denial` asks for a proof.
	bare, _, berr := dns.encode_message(forged, context.temp_allocator)
	testing.expect(t, berr == .None, "the bare forgery did not encode")
	testing.expect_value(t, validate(v, "www.example.com.", .A, bare, rc_now()).status, Status.Bogus)

	// And one unsigned record from an unsigned zone must not change that.
	// reddit.com has no DS in com in the captured set, so this is a record an
	// attacker copies rather than makes.
	junk := make([]dns.Record, 1, context.temp_allocator)
	junk[0] = dns.Record {
		name  = "www.reddit.com.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "reddit.map.fastly.net."},
	}
	forged.answer = junk
	wire, _, err := dns.encode_message(forged, context.temp_allocator)
	testing.expect(t, err == .None, "the spliced forgery did not encode")

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(
		t,
		res.status == .Bogus,
		"one unsigned record rerouted a forged denial to %v (%q); it would have been forwarded to the client",
		res.status,
		res.reason,
	)
	free_all(context.temp_allocator)
}

/*
And the extended rcode is not a way to say NXDOMAIN to the client only.

`rcode_of` composes twelve bits - the header's four and eight more from the OPT
record's TTL (RFC 6891 section 6.1.3) - while every consumer this guard is
written for reads the four. So setting a bit in the OPT's top byte alongside the
flipped nibble made the message unanswerable to us and a name error to them:
`answerable_rcode` bailed out before `validate_answer` was ever entered, the
verdict was `Insecure`, and `resolve_query` forwarded it with the signed records
still in the answer section and a header saying the name is not there.
*/
@(test)
test_the_extended_rcode_is_not_a_way_past_the_guard :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	flipped := with_rcode(rc_unhex(rc_fixture("example_a").wire), .NX_Domain)
	msg, derr := dns.decode_message(flipped, context.temp_allocator)
	testing.expect(t, derr == .None, "the flipped capture did not decode")

	extended, has_opt := with_extended_rcode(msg.additional)
	testing.expect(t, has_opt, "the capture should carry an OPT record")
	msg.additional = extended
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, err == .None, "the re-encoded message did not encode")

	// The premise, read back off the wire: the client sees a name error, and we
	// see something else entirely.
	decoded, rerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, rerr == .None, "the re-encoded message did not decode")
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.NX_Domain)
	testing.expect(t, dns.rcode_of(decoded) != .NX_Domain, "the extended rcode should differ from the header's")

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(
		t,
		res.status == .Indeterminate,
		"an extended rcode carried the flipped header past the guard as %v (%q)",
		res.status,
		res.reason,
	)
	free_all(context.temp_allocator)
}

/*
And with the nibble left at 0 the client reads NOERROR, which is not a denial
bug at all but the whole validator stepped over.

The same one byte, and now the client takes the answer section instead of
discarding it. A forged `www.example.com. A` whose signature no longer covers it
is `Bogus` on its own; excused as "nothing to authenticate" it was forwarded as
`Insecure` and believed. Nothing here is about NXDOMAIN any more - it is every
answer this server would otherwise have checked.
*/
@(test)
test_a_forgery_does_not_hide_behind_an_extended_rcode :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(rc_unhex(rc_fixture("example_a").wire), context.temp_allocator)
	testing.expect(t, derr == .None, "the capture did not decode")

	// Rewrite the address the client would use, leaving the signature alone.
	answer := make([dynamic]dns.Record, 0, len(msg.answer), context.temp_allocator)
	touched := false
	for rec in msg.answer {
		r := rec
		if a, is_a := r.data.(dns.Rdata_A); is_a {
			bad := a
			bad.addr[3] ~= 0xff
			r.data = bad
			touched = true
		}
		append(&answer, r)
	}
	testing.expect(t, touched, "the capture should carry an A record")
	msg.answer = answer[:]

	// Plain, this is refused on the signature alone.
	plain, _, perr := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, perr == .None, "the forgery did not encode")
	testing.expect_value(t, validate(v, "www.example.com.", .A, plain, rc_now()).status, Status.Bogus)

	// One bit in the OPT's top byte, and the header's own nibble left at 0.
	extended, has_opt := with_extended_rcode(msg.additional)
	testing.expect(t, has_opt, "the capture should carry an OPT record")
	msg.additional = extended
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, err == .None, "the re-encoded forgery did not encode")

	decoded, rerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, rerr == .None, "the re-encoded forgery did not decode")
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.No_Error)
	testing.expect(t, u16(dns.rcode_of(decoded)) > 0xf, "the extended rcode should be set")

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(
		t,
		res.status == .Indeterminate,
		"an extended rcode carried a forged answer past the validator as %v (%q)",
		res.status,
		res.reason,
	)
	free_all(context.temp_allocator)
}

/*
And stripping the answer section instead is the same attack, so telling the two
apart by what is in the message cannot work.

The obvious narrowing - excuse an extended rcode only where the response
answered nothing - is what this pins as insufficient, and it is worth having the
reason written down because it reads like a safe one. A responder sending
BADVERS or BADCOOKIE has not answered, so it sends a question and an OPT and
nothing else. An attacker after a *NODATA* sends exactly that too: NOERROR with
an empty answer section is "that name has no such record" to everything that
reads it, and for the DANE lookup in #271 it is the same downgrade as the name
error - "no TLSA record here", fall back to opportunistic TLS. The two are the
same bytes, so the sections cannot separate them and neither is forwarded.
*/
@(test)
test_a_forged_nodata_does_not_hide_behind_an_extended_rcode :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(rc_unhex(rc_fixture("example_a").wire), context.temp_allocator)
	testing.expect(t, derr == .None, "the capture did not decode")
	// Everything the zone signed, taken out. What is left says the name has no
	// A record, and says it for a name whose A record the attacker just deleted.
	msg.answer = nil
	msg.authority = nil

	bare, _, berr := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, berr == .None, "the stripped message did not encode")
	// Refused on its own: `validate_denial` asks for a proof and finds none.
	testing.expect_value(t, validate(v, "www.example.com.", .A, bare, rc_now()).status, Status.Bogus)

	extended, has_opt := with_extended_rcode(msg.additional)
	testing.expect(t, has_opt, "the capture should carry an OPT record")
	msg.additional = extended
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, err == .None, "the re-encoded message did not encode")

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(
		t,
		res.status != .Insecure,
		"an extended rcode carried a forged NODATA past the validator as %v (%q); the client reads NOERROR with an empty answer",
		res.status,
		res.reason,
	)
	free_all(context.temp_allocator)
}

/*
And a real BADVERS is refused without being called a forgery.

This is the half of the pair that says what the refusals above are allowed to
cost, and the distinction it draws is the one worth keeping. A BADVERS is
indistinguishable on the wire from the forged NODATA above, so it is refused
too - but `Indeterminate` rather than `Bogus`, which is this server saying it
established nothing rather than accusing anyone. The client gets SERVFAIL either
way; the extended error is `NO_REACHABLE_AUTHORITY` rather than `DNSSEC_BOGUS`,
and the operator reading the log is not sent looking for an attacker.

Refusing costs a real one nothing it had. `rcode_of` reads twelve bits and every
client reads four, so forwarding a BADVERS hands the client NOERROR with an
empty answer - a NODATA it never sent. What this replaces is a silently wrong
answer, not a working one.

An earlier turn of this guard got the pair backwards, and only a realistic
BADVERS catches that: written against a capture whose answer section was still
full, the test passed while pinning the attack shape itself as acceptable.
*/
@(test)
test_badvers_is_refused_without_being_called_a_forgery :: proc(t: ^testing.T) {
	v := make_validator(rc_query, nil, Options{})
	defer destroy_validator(v)

	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = "www.example.com.", type = .A, class = .IN}
	msg := dns.Message{question = question}
	msg.flags.qr = true
	// What an upstream that cannot do the EDNS version we asked for sends back:
	// the question, an OPT, and nothing it looked up (RFC 6891 section 6.1.3).
	opt, has_opt := with_extended_rcode([]dns.Record{dns.make_opt(4096, true)})
	testing.expect(t, has_opt, "the BADVERS should carry an OPT record")
	msg.additional = opt

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect(t, err == .None, "the BADVERS did not encode")

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect(t, derr == .None, "the BADVERS did not decode")
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.Bad_Vers)

	res := validate(v, "www.example.com.", .A, wire, rc_now())
	testing.expectf(t, res.status == .Indeterminate, "a BADVERS was called %v (%q)", res.status, res.reason)
	testing.expect(t, res.status != .Bogus, "an EDNS version mismatch was reported as a forgery")
	free_all(context.temp_allocator)
}

// The upper eight bits of the extended rcode live in the OPT record's TTL (RFC
// 6891 section 6.1.3). Setting the lowest of them is BADVERS on its own, and
// what an attacker adds to a rewritten header.
@(private = "file")
with_extended_rcode :: proc(additional: []dns.Record) -> (out: []dns.Record, ok: bool) {
	records := make([dynamic]dns.Record, 0, len(additional), context.temp_allocator)
	found := false
	for rec in additional {
		r := rec
		if r.type == .OPT {
			r.ttl |= 0x01000000
			found = true
		}
		append(&records, r)
	}
	// Without an OPT there is nowhere for the upper bits to go, and a caller
	// handed the message back unchanged would assert about the ordinary path
	// while believing it had reached this one. Every caller checks.
	return records[:], found
}
