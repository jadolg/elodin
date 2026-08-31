package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
The chain walk's own signature checks, under a response written to make it work.

`validate_rrset` and `verified_rrset` are bounded: both spend
`MAX_VERIFICATIONS_PER_QUERY` and both throw the hopeless signatures out for
nothing through `signature_worth_trying`. The two loops that build the chain of
trust - the RRSIGs over a DS set in `zone_step`, and the RRSIGs over a DNSKEY
set in `fetch_keys` - had neither, and their signature list comes straight out
of a response, so its length is whoever answered the lookup.

That is the KeyTrap shape (CVE-2023-50387). Every field deciding whether a
signature is worth trying is public: the key tag and algorithm are printed in
the zone's own DNSKEY set, and the validity window is copyable from the genuine
signature beside it. So a DS response padded with several hundred RRSIGs
carrying the parent's real key tag fits inside one TCP, DoT or DoH reply, and
each one costs a canonicalisation over the whole set plus a real verification.
`MAX_LOOKUPS_PER_QUERY` allows 32 chain steps per client question, and the
`fetch_keys` case multiplies again by the number of DS records that match a
usable key - a count nothing caps, because a DS set padded with duplicates
still verifies: `signing_input` de-duplicates the canonical form, so the
parent's genuine signature covers the padded set unchanged.

Who can reach it: whoever answers the DS or DNSKEY lookup. A hostile upstream,
an on-path attacker in front of a plain UDP or TCP upstream, and - for
`fetch_keys` - a zone owner against their own zone, by publishing a DNSKEY set
padded with bogus signatures bearing their real key tag.

The tests below pad a real fixture and assert on two things at once: that the
walk stops (an answer that would have been reached by grinding through the
padding comes back `Indeterminate` instead), and that it stopped because the
budget ran out rather than for some other reason. The pair matters - the verdict
alone would be satisfied by a walk that failed early for an unrelated reason,
and the meter alone would be satisfied by a walk that charged for work it then
went on doing anyway.

Sharing one budget across the chain walk is deliberate, and the cost is real: a
padded DS set early in the walk can exhaust what a later step needs, turning a
resolvable name Bogus. That is the trade `MAX_VERIFICATIONS_PER_QUERY` already
documents for the two paths it was introduced on - an attacker who can pad a
response can already deny the answer by corrupting it - and it buys the thing
that has no alternative, which is that the work stays bounded.
*/

/*
One tampering to apply to one fixture response.

`sigs` forgeries go in front of everything else, which is the order an attacker
picks: the budget is spent before the record that would have verified is
reached. `junk_tag` makes them free to reject instead, `drop_real` removes the
signature they are padding so nothing verifies at all - which is what makes the
`fetch_keys` loops run to completion - and `records` duplicates the records of
the padded type, which is the multiplier the DS set carries into `fetch_keys`.
*/
@(private = "file")
Padding :: struct {
	name:      string,
	type:      dns.Type,
	sigs:      int,
	junk_tag:  bool,
	stale:     bool,
	drop_real: bool,
	records:   int,
}

// A forgery copied from the genuine signature beside it. Everything but the
// signature bytes is public, so everything but the signature bytes is kept:
// the key tag, the algorithm and the validity window are exactly what the cheap
// pre-check reads, and a forgery that changed any of them would be rejected for
// free and would prove nothing about the loops this file is about.
@(private = "file")
kt_forged :: proc(real: dns.Record, pad: Padding, allocator: mem.Allocator) -> dns.Record {
	rdata, is_raw := raw_rdata(real)
	if !is_raw {
		panic("the signature to copy did not arrive as raw RDATA")
	}
	out := make([]u8, len(rdata), allocator)
	copy(out, rdata)
	for i in max(0, len(out) - 8) ..< len(out) {
		out[i] ~= 0xff
	}
	// The key tag sits at offset 16, after the fixed fields and before the
	// signer name. Flipping it names a key the zone never published, which is
	// what `signature_worth_trying` refuses without doing any work.
	if pad.junk_tag {
		out[16] ~= 0xff
		out[17] ~= 0xff
	}
	// The other free reject: expiration at offset 8, set to the inception that
	// follows it, which is a window that closed the moment it opened. Nothing
	// else about the record changes, so it is the dates and only the dates that
	// can be refusing it.
	if pad.stale {
		copy(out[8:12], out[12:16])
	}
	return dns.Record {
		name = real.name,
		type = .RRSIG,
		class = real.class,
		ttl = real.ttl,
		data = dns.Rdata_Raw{data = out},
	}
}

@(private = "file")
kt_pad :: proc(wire: []u8, pad: Padding, allocator: mem.Allocator) -> []u8 {
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		panic("the fixture did not decode")
	}

	genuine: dns.Record
	have := false
	for rec in msg.answer {
		if rec.type != .RRSIG {
			continue
		}
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		sig, perr := parse_rrsig(rdata, allocator)
		if perr != .None || sig.type_covered != pad.type {
			continue
		}
		genuine, have = rec, true
		break
	}
	if !have {
		panic("the fixture carried no signature over the type being padded")
	}

	answer := make([dynamic]dns.Record, 0, len(msg.answer) + pad.sigs + pad.records, allocator)
	for _ in 0 ..< pad.sigs {
		append(&answer, kt_forged(genuine, pad, allocator))
	}
	for rec in msg.answer {
		if pad.drop_real && rec.type == .RRSIG {
			rdata, is_raw := raw_rdata(rec)
			if is_raw {
				sig, perr := parse_rrsig(rdata, allocator)
				if perr == .None && sig.type_covered == pad.type {
					continue
				}
			}
		}
		append(&answer, rec)
		if rec.type == pad.type && dns.name_equal_fold(rec.name, pad.name) {
			for _ in 0 ..< pad.records {
				append(&answer, rec)
			}
		}
	}
	msg.answer = answer[:]

	out, _, enc := dns.encode_message(msg, allocator, dns.MAX_MESSAGE)
	if enc != .None {
		panic("the padded response did not re-encode")
	}
	return out
}

// The fixture chain, with whatever tampering `ctx` names applied on the way
// out. A nil `ctx` serves the fixtures untouched, which is the baseline the
// free-reject tests compare against.
@(private = "file")
kt_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type != type || !dns.name_equal_fold(f.name, name) {
			continue
		}
		raw, decoded := decode_hex(f.wire, allocator)
		if !decoded {
			return nil, false
		}
		if ctx == nil {
			return raw, true
		}
		for pad in (^[]Padding)(ctx)^ {
			if pad.type == type && dns.name_equal_fold(pad.name, name) {
				return kt_pad(raw, pad, allocator), true
			}
		}
		return raw, true
	}
	return nil, false
}

// What the walk costs when nobody has touched the responses, so that a test
// claiming padding was free has something to say "free" against.
@(private = "file")
kt_baseline :: proc(t: ^testing.T) -> (spent: int, ok: bool) {
	v := make_validator(kt_query, nil, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	if !testing.expectf(t, status == .Secure, "the untampered chain did not establish, got %v", status) {
		return 0, false
	}
	return budget.verifications, true
}

/*
A DS set padded with signatures that name the parent's real key is bounded.

`zone_step` takes the RRSIGs over the DS set straight from the response and
tries every one whose signer names the parent. Two hundred copies of the real
signature with the last bytes flipped therefore bought two hundred
canonicalisations of the DS set and two hundred ECDSA verifications, for one
step of one chain, on nothing but a reply the attacker wrote.

The genuine signature sits behind the padding, so a walk that grinds through it
still ends `Secure` - which is exactly how this went unnoticed. The verdict here
is `Indeterminate` because the walk gave up, and the meter says it gave up on
the budget.
*/
@(test)
test_a_padded_ds_set_cannot_run_unbounded_verifications :: proc(t: ^testing.T) {
	pads := []Padding{{name = "cloudflare.com.", type = .DS, sigs = 200}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Indeterminate,
		"200 forged DS signatures were all tried and the walk went on to finish (%v): the loop has no bound",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == MAX_VERIFICATIONS_PER_QUERY,
		"the DS signature loop charged %d of %d verifications: it is not wired into the budget",
		budget.verifications,
		MAX_VERIFICATIONS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

/*
Padding a DS set with signatures nothing could verify costs nothing.

The other half of the fix, and the half that decides whether the budget is the
attacker's to spend. A forgery whose key tag names no key the parent published
cannot verify, and finding that out needs no crypto and no canonicalisation - so
two hundred of them must leave the meter exactly where an untouched response
leaves it, and the answer must still come back.

Without this the cheap pre-check could be dropped and the previous test would go
on passing, with every DS lookup in the world one padded response away from a
SERVFAIL.
*/
@(test)
test_free_rejectable_ds_padding_costs_the_chain_nothing :: proc(t: ^testing.T) {
	baseline, ok := kt_baseline(t)
	if !ok {
		return
	}

	pads := []Padding{{name = "cloudflare.com.", type = .DS, sigs = 200, junk_tag = true}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Secure,
		"200 free-rejectable forgeries in front of the real DS signature broke the chain (%v)",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == baseline,
		"free-rejectable padding spent %d verifications against a baseline of %d",
		budget.verifications,
		baseline,
	)
	free_all(context.temp_allocator)
}

/*
A signature whose window has closed is refused on the chain for nothing too.

The second half of the free pre-check, and the one that is easiest to leave out
because `check_signature` reads the dates as well. It reads them *first*, so a
lapsed forgery was already cheap - but only cheap, not free: with the budget
wired in, a signature nothing could verify must not be able to take a
verification off the allowance on its way to being refused. Two hundred lapsed
copies of the real DS signature therefore leave the meter where an untouched
response leaves it, and the answer arrives.
*/
@(test)
test_lapsed_ds_padding_costs_the_chain_nothing :: proc(t: ^testing.T) {
	baseline, ok := kt_baseline(t)
	if !ok {
		return
	}

	pads := []Padding{{name = "cloudflare.com.", type = .DS, sigs = 200, stale = true}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Secure,
		"200 lapsed forgeries in front of the real DS signature broke the chain (%v)",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == baseline,
		"lapsed padding spent %d verifications against a baseline of %d",
		budget.verifications,
		baseline,
	)
	free_all(context.temp_allocator)
}

/*
The trust anchor's own step is bounded, and it is the one that always runs.

`zone_keys` checks the root's DNSKEY set against the configured anchors through
the same `fetch_keys` loops, so the root is where a padded DNSKEY set is worth
the most to an attacker: every question a resolver validates starts here, and
the two IANA anchors are the DS set the loops multiply by. A padded root DNSKEY
reply is also the cheapest thing for a hostile or on-path upstream to produce,
since it needs no zone of its own and no name in particular.
*/
@(test)
test_a_padded_root_dnskey_set_is_bounded :: proc(t: ^testing.T) {
	pads := []Padding{{name = ".", type = .DNSKEY, sigs = 200}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _ := zone_keys(v, &budget, ".", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Indeterminate,
		"200 forged signatures over the root DNSKEY set were all tried and the anchor still resolved (%v)",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == MAX_VERIFICATIONS_PER_QUERY,
		"the root's key check charged %d of %d verifications",
		budget.verifications,
		MAX_VERIFICATIONS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

/*
A DNSKEY set padded with signatures bearing the zone's real key tag is bounded.

The same loop one level down, and the one a zone owner can point at a resolver
without needing to be on anybody's path: the signatures over a zone's own DNSKEY
set are published by the zone. Each copy carries the key tag the parent's DS
attests, so each reaches `check_signature`, which canonicalises the whole
DNSKEY set before it looks at a key.
*/
@(test)
test_a_padded_dnskey_set_cannot_run_unbounded_verifications :: proc(t: ^testing.T) {
	pads := []Padding{{name = "cloudflare.com.", type = .DNSKEY, sigs = 200}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Indeterminate,
		"200 forged DNSKEY signatures were all tried and the walk went on to finish (%v): the loop has no bound",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == MAX_VERIFICATIONS_PER_QUERY,
		"the DNSKEY signature loop charged %d of %d verifications: it is not wired into the budget",
		budget.verifications,
		MAX_VERIFICATIONS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

@(test)
test_free_rejectable_dnskey_padding_costs_the_chain_nothing :: proc(t: ^testing.T) {
	baseline, ok := kt_baseline(t)
	if !ok {
		return
	}

	pads := []Padding{{name = "cloudflare.com.", type = .DNSKEY, sigs = 200, junk_tag = true}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Secure,
		"200 free-rejectable forgeries in front of the real DNSKEY signature broke the chain (%v)",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == baseline,
		"free-rejectable padding spent %d verifications against a baseline of %d",
		budget.verifications,
		baseline,
	)
	free_all(context.temp_allocator)
}

/*
Duplicated DS records do not multiply the DNSKEY check by their count.

The sharpest form of this, because it needs the fewest forged signatures. The
signature loop in `fetch_keys` is nested inside a loop over the DS records that
match a usable key, so N DS records and M signatures are N*M verifications - and
N is not capped anywhere. `MAX_KEYS_PER_ZONE` caps the keys a zone may publish;
nothing caps the DS records a parent's response may carry.

Duplicates survive the parent's signature, which is what makes N free to choose:
`signing_input` sorts the RDATAs and drops the repeats, so the canonical form of
a DS set padded with sixty-three copies of itself is the canonical form of the
set, and the genuine RRSIG over it verifies exactly as it did.

The genuine DNSKEY signature is removed here so that nothing verifies and every
one of those iterations runs, which is the state an attacker arranges by
replacing the signature rather than adding to it. Sixty-four DS records and
eight forgeries were 512 verifications for a single step.
*/
@(test)
test_duplicate_ds_records_do_not_multiply_the_dnskey_check :: proc(t: ^testing.T) {
	pads := []Padding {
		{name = "cloudflare.com.", type = .DS, records = 63},
		{name = "cloudflare.com.", type = .DNSKEY, sigs = 8, drop_real = true},
	}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	status, _, _ := zone_trust(v, &budget, "cloudflare.com.", time.unix(FIXTURE_TIME, 0), context.temp_allocator)
	testing.expectf(
		t,
		status == .Indeterminate,
		"64 DS records times 8 forged signatures ran to completion (%v): the nested loop has no bound",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == MAX_VERIFICATIONS_PER_QUERY,
		"the nested DNSKEY loop charged %d of %d verifications",
		budget.verifications,
		MAX_VERIFICATIONS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

// The genuine DS record for a zone, read out of the fixture the way `zone_step`
// reads it, so that a test can hand `fetch_keys` a DS set of its own.
@(private = "file")
kt_ds :: proc(t: ^testing.T, zone: string) -> (ds: Ds, ok: bool) {
	wire, served := kt_query(nil, zone, .DS, context.temp_allocator)
	if !testing.expect(t, served, "the fixture set carries no DS for this zone") {
		return {}, false
	}
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the DS fixture did not decode") {
		return {}, false
	}
	for rec in records_of(msg.answer, zone, .DS, .IN, context.temp_allocator) {
		rdata, is_raw := raw_rdata(rec)
		if !is_raw {
			continue
		}
		parsed, perr := parse_ds(rdata)
		if perr == .None {
			return parsed, true
		}
	}
	testing.expect(t, false, "the DS fixture carried no parsable DS record")
	return {}, false
}

/*
Running out of verifications is not an insecure delegation.

The trap in wiring a budget into `fetch_keys`: its failure return is
`Insecure if unsupported else Bogus`, and `unsupported` is set by any DS in the
set naming an algorithm or digest this build cannot check - which a parent zone
is free to publish alongside a supported one. Leaving through that return when
the budget dies would hand an attacker a downgrade: pad the DNSKEY set, exhaust
the allowance before the genuine signature is reached, and the zone comes back
`Insecure` - no AD bit asked for, no chain, and every answer below it accepted
unvalidated.

The cache makes it worse than one answer: `zone_step` writes an `Insecure`
verdict for the zone into the zone cache for the DS set's TTL, so one padded
reply buys the downgrade for every question about that zone until it expires.

Exhaustion is a statement about this server and not about the zone, so it leaves
as `Indeterminate`, the same verdict `zone_step` already gives a DS step whose
denial proof ran the allowance out - and `Indeterminate` reaches the client as
SERVFAIL, caches nothing, and is ranked below no other verdict by `worse`.
*/
@(test)
test_an_exhausted_key_check_is_not_a_downgrade :: proc(t: ^testing.T) {
	genuine, ok := kt_ds(t, "cloudflare.com.")
	if !ok {
		return
	}
	// The same delegation, published a second time under an algorithm this
	// build has never implemented. Nothing forbids a parent from doing that,
	// and it is what sets `unsupported`.
	unsupported := genuine
	unsupported.algorithm = 253

	pads := []Padding{{name = "cloudflare.com.", type = .DNSKEY, sigs = 200}}
	v := make_validator(kt_query, &pads, Options{})
	defer destroy_validator(v)

	budget := Budget{}
	_, status := fetch_keys(
		v,
		&budget,
		"cloudflare.com.",
		[]Ds{unsupported, genuine},
		u32(FIXTURE_TIME),
		context.temp_allocator,
	)
	testing.expectf(
		t,
		status == .Indeterminate,
		"a DNSKEY set padded past the budget came back %v, not Indeterminate: exhaustion is being reported as a verdict about the zone",
		status,
	)
	testing.expectf(
		t,
		budget.verifications == MAX_VERIFICATIONS_PER_QUERY,
		"the DNSKEY signature loop charged %d of %d verifications",
		budget.verifications,
		MAX_VERIFICATIONS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}
