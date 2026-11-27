package dnssec

import "core:mem"
import "elodin:dns"

/*
Cut a validated response down to the records the verdict covers.

`validate` authenticates particular RRsets, and a response carries more than
those. The authority section of a positive answer holds a delegation nobody
here looked at, the additional section holds the addresses to go with it, and
handing the whole thing on with AD set says this server checked them. RFC 4035
section 3.2.3 asks it not to say that, and anyone able to add a record to a
response would be glad to hear it said: a nameserver of their choosing, or an
address for one, arriving under our authentication. A signed zone the attacker
owns can bolt those on and still answer the question perfectly; so can anyone on
the path to a plain UDP or TCP upstream, who need not touch the signed answer at
all.

Dropped rather than checked, and the reason is not the cost. Validating those
sections the way the answer section is validated is the obvious repair, and it
cannot work on the records it would need to work on: the NS RRset at a zone cut
and the glue below it are unsigned by design (RFC 4035 section 2.2). Exactly
what an attacker would forge is what no signature can ever settle, so a resolver
demanding one would refuse every delegation it was ever handed - and would then
have to special-case its way back to accepting them, which is where it started.

The cost is the second reason and still a real one: each owner name in a
response is free to name a signer of its own, and a chain walk apiece is what
MAX_LOOKUPS_PER_QUERY exists to stop one response provoking. Dropping cannot
cost a lookup.

A forwarder gives up little by dropping them. The client asked this server to
resolve the name; it is not going to chase a delegation or dial the glue. What
stays is what was proven and what a client has a use for: the answer, the NSEC
and NSEC3 records a denial rests on, and the SOA that denial is cached
negatively against.

Not everything in the additional section is glue, and the argument above does
not stretch to cover the rest of it. The address records a server sends beside
an HTTPS, SVCB, SRV or MX answer are ordinary signed zone data (RFC 9460 section
5 asks for them by name), and a client that has them is spared a round trip
before it can connect. Those are authenticated rather than dropped, and the ones
that hold up travel with the answer - see `validated_hints`, which is where the
narrow reading of "those" is written down. Not passed through unchecked: AD is a
property of the message, and a client that reads AD=1 and then connects to an
address nobody verified is the exact harm this procedure exists to prevent.

A CNAME chain that ends in a denial - a dual-stack client asking AAAA for an
IPv4-only name is the everyday version of it, and a CNAME pointing at a name
that does not exist is the same shape with NXDOMAIN on it - reaches `Secure`
only once `validate_answer` has proven the denial in the zone holding the
chain's end, so the NSEC or NSEC3 records and the SOA are among what the verdict
names and survive. An SOA that did not verify is not named, and goes with the
rest of what the verdict leaves out (see `proved_denial`); `cache.put` then
reads the result as the denial it is (RFC 2308 section 2.2), finds no SOA, and
keeps none of it (section 5).

The rcode is the part of this no prune can reach. AD covers the records in those
two sections, and this makes it honest about them; it says nothing about the
header. That is why `validate_answer` reads the rcode itself: an on-path
attacker who flips a signed CNAME answer to NXDOMAIN has to bring a name error
proof from the target's zone along with it, and without one the answer is
`Bogus`.

Keeping the records and clearing AD instead is the way out of that which looks
free, and is not: AD is a property of the message and not of a section, so the
commonest answer shape there is would go out unauthenticated - and the copy
that lands in the cache would be AD-less for every later client too.

The OPT record survives on its own account (see `authenticated_and_opt`).

Only a `Secure` verdict is pruned. Nothing else sets AD, so nothing else has a
boundary to keep, and the other paths name no RRsets at all - pruning against
that would throw the response away.
*/
strip_unauthenticated :: proc(
	wire: []u8,
	result: Result,
	allocator := context.temp_allocator,
	// The request's counter, as in `validate`: this is one more reading of the
	// same response into the same arena. See issue #354.
	spent: ^int = nil,
	// Set where the prune failed for want of memory, rather than on the message.
	refused: ^bool = nil,
) -> (
	out: []u8,
	ok: bool,
) {
	if result.status != .Secure {
		return wire, true
	}
	dry := false
	defer if refused != nil {
		refused^ = dry
	}
	// A signature whose signer cannot be read for want of memory is dropped
	// like one that does not parse, so a prune that ran dry is no prune.
	watched := dns.Dry_Watch{backing = allocator, dry = &dry}
	scratch := dns.Dry_Watch{backing = context.temp_allocator, dry = &dry}
	context.temp_allocator = dns.dry_watch_allocator(&scratch)
	watching := dns.dry_watch_allocator(&watched)

	msg, derr := dns.decode_message(wire, watching, spent)
	if derr != .None {
		return nil, false
	}
	answer, answer_kept := authenticated_only(msg.answer, result.answer, watching)
	authority, authority_kept := authenticated_only(msg.authority, result.authority, watching)
	additional, additional_kept := authenticated_and_opt(msg.additional, result.additional, watching)
	if !answer_kept || !authority_kept || !additional_kept {
		dry = true
		return nil, false
	}
	msg.answer, msg.authority, msg.additional = answer, authority, additional

	/*
	A truncated rebuild is a failure, not a result. `encode_message` drops
	whatever no longer fits and says so in `truncated`; taking that as the
	pruned message would hand the caller a response with records missing and
	nothing to distinguish it from a complete one - and the caller's next act is
	to set the AD bit over it. Failing instead leaves the original standing
	without the bit, which is the same fallback an encode error already gets.

	`truncated` covers the answer and authority sections, which are the two AD
	is a claim about: an additional record that will not fit is left out quietly,
	since TC is not about additional data (RFC 2181 section 9).
	*/
	encoded, truncated, enc := dns.encode_message(msg, watching, dns.MAX_MESSAGE)
	if enc != .None || truncated || dry {
		return nil, false
	}
	return encoded, true
}

/*
Whether the response asserts that there is nothing more to be had.

NXDOMAIN says the name is not there; NOERROR with an SOA in the authority
section is what RFC 2308 section 2.2 makes a NODATA. Anything else - a bare
chain, a referral - asserts nothing, and a sender asserting nothing has made no
claim for this server to put its name to.

This is the one place on this path that reads fields the sender writes, and it
is the right place for it: what it decides is whether a denial has to be
proven, and a sender that deletes the claim to avoid the proof has removed the
harm rather than hidden it. The client then sees a redirection and goes and
asks the target itself.
*/
@(private)
denial_claimed :: proc(msg: dns.Message) -> bool {
	if dns.rcode_of(msg) == .NX_Domain {
		return true
	}
	for rec in msg.authority {
		if rec.type == .SOA {
			return true
		}
	}
	return false
}

/*
What the answer section does with the question, as the chain sees it.

Two different outcomes are kept apart here: a record of the type asked for, and
a CNAME chain that stopped short of it. The second is not an answer - it is a
redirection, and whatever explains the missing type lives in the authority
section, signed by the zone at the chain's end. Keeping them apart is what lets
the caller demand that proof of the second and not of the first.
*/
@(private)
Answer_Shape :: enum u8 {
	// Nothing here concerns the question.
	None,
	// A record of the type asked for was reached.
	Direct,
	// A CNAME chain that ran out before the type was reached.
	Chain_Only,
}

/*
Follow the chain from `qname` and report where it ended up: the shape, and the
name the walk stopped at, which for `.Chain_Only` is the name a denial beside
the chain is about (RFC 6604 section 3).

The walk is the only thing consulted, and that is the point. Scanning the whole
section for any record of the type is not the same test and would be a way to
get this wrong: an attacker with a signed zone of its own appends
`x.evil.example. A`, which has nothing to do with the question, and a scan sees
the type and stops asking.
*/
@(private)
chain_walk :: proc(
	records: []dns.Record,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
) -> (
	shape: Answer_Shape,
	end: string,
) {
	name := qname
	hops := 0
	for hops < MAX_CNAME_CHAIN {
		target := ""
		for r in records {
			if r.class != class || !dns.name_equal_fold(r.name, name) {
				continue
			}
			if r.type == qtype || qtype == .ANY {
				return .Direct, name
			}
			if r.type == .CNAME {
				if v, is_name := r.data.(dns.Rdata_Name); is_name {
					target = v.name
				}
			}
		}
		if target == "" {
			// Nothing further to follow. Whether this concerns the question at
			// all comes down to having got here by a CNAME the queried name owns.
			return .Chain_Only if hops > 0 else .None, name
		}
		name = target
		hops += 1
	}
	// A chain this long is a loop or a stall, and either way proves nothing.
	return .None, name
}

/*
Does the answer prove the existence of the name the rcode denies?

An NXDOMAIN is about the *last* name in the CNAME chain, not the one the client
asked about (RFC 6604 section 3): `www.example.com. CNAME target.example.` with
NXDOMAIN beside it says `target.example.` is missing and says nothing at all
about `www.example.com.`, which the chain has just shown to exist. So the walk
follows the chain to its end and asks one question there - is there a record at
this name that this server authenticated - because a record at a name is proof
the name exists, whatever its type.

Where the chain ends is the client's question as much as the records, and that
is the part it is easy to get wrong. A CNAME is a hop only while the client
wanted something else: RFC 1034 section 4.3.2 step 3a restarts the walk at the
target *unless* the query type matches the CNAME, so for `CNAME` and for `ANY`
the record is the answer, the walk stops, and the rcode is about the name that
was asked about. Read as a hop instead, a flipped rcode over a signed
`dig CNAME` answer would walk past the very record that refutes it, find the
target empty, and come back `Secure` - #271 intact for that one question.

The general rule and both of those cases are the same line: a record that
matches the question ends the walk, whatever the type. It is only when nothing
here answers the question that a CNAME means go on looking.

Only the authenticated sets are followed, and that is what makes the answer
worth anything. Both halves of a response are the sender's to write, so a walk
over the section as it arrived could be steered with records nobody signed: one
appended CNAME redirects the walk to a name the sender chose and empties it, and
one appended record at the end fills it. Neither is possible over sets that had
to survive a zone's signature to get into `kept`.

Close to `chain_walk` and not the same question, which is why it is written out
rather than borrowed. That one reports whether the question was *answered*; this
one reports whether a name was *proven*. A chain ending in an AAAA where an A was
asked for is `.Chain_Only` and no answer at all, and is still a name shown to
exist under a header that denies it.
*/
@(private)
denial_contradicted :: proc(
	records: []dns.Record,
	kept: []Authenticated_Set,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
) -> bool {
	if len(kept) == 0 {
		return false
	}
	name := qname
	hops := 0
	for hops < MAX_CNAME_CHAIN {
		target := ""
		present := false
		for r in records {
			if r.class != class || !dns.name_equal_fold(r.name, name) {
				continue
			}
			/*
			An RRSIG is not data at a name for this purpose. Nothing signs one
			(RFC 4035 section 2.2), so it is never in `kept` on its own account
			and `authenticated_rrset` would not find it there anyway - but saying so
			here keeps the rule readable rather than resting on that.
			*/
			if r.type == .RRSIG || r.type == .OPT {
				continue
			}
			if _, vouched := authenticated_rrset(kept, r.name, r.type, class); !vouched {
				continue
			}
			present = true
			/*
			The question answered here, so the walk ends here and the rcode is
			about this name - which this record has just shown to exist. Ahead
			of the CNAME case below on purpose: that is what stops a `CNAME` or
			`ANY` question stepping over the record that refutes the denial.
			*/
			if r.type == qtype || qtype == .ANY {
				return true
			}
			if r.type == .CNAME {
				if v, is_name := r.data.(dns.Rdata_Name); is_name {
					target = v.name
				}
			}
		}
		if target == "" {
			// The end of the chain, and so the name the rcode speaks for.
			return present
		}
		name = target
		hops += 1
	}
	// A chain this long is a loop or a stall, and proves nothing either way.
	return false
}

@(private)
authenticated_only :: proc(
	section: []dns.Record,
	kept: []Authenticated_Set,
	allocator: mem.Allocator,
) -> (
	records: []dns.Record,
	ok: bool,
) {
	// Nothing in this section was authenticated, so nothing in it survives. Worth
	// saying up front: a denial names no RRsets in the answer section, and the
	// loop below would otherwise parse and allocate a signer name for every RRSIG
	// sitting there before dropping the lot.
	if len(kept) == 0 {
		return nil, true
	}
	// Signatures kept for each authenticated RRset beyond the one that verified,
	// and whether that one has been kept already.
	sigs_kept := dns.alloc_slice([]int, len(kept), allocator) or_return
	verified_kept := dns.alloc_slice([]bool, len(kept), allocator) or_return
	/*
	RFC 4035 section 5.3.3: the set and its RRSIGs go out with one TTL, no more
	than the least of the set's received TTLs, the verified RRSIG's received
	TTL, and the ceiling that RRSIG puts on it (`Authenticated_Set.ttl`). The
	TTL field is the one part of a record no signature covers, so leaving it as
	received would let an on-path sender keep a signed answer cached long after
	its signer meant. `owner` is the set each kept record belongs to.
	*/
	set_ttl := dns.alloc_slice([]u32, len(kept), allocator) or_return
	for k, i in kept {
		set_ttl[i] = k.ttl
	}
	owner := dns.alloc_list([dynamic]int, len(section), allocator) or_return
	out := dns.alloc_list([dynamic]dns.Record, len(section), allocator) or_return
	for rec in section {
		covered := rec.type
		parsed: Rrsig
		if rec.type == .RRSIG {
			/*
			An RRSIG rides on the RRset it covers. Nothing signs an RRSIG (RFC
			4035 section 2.2), so one whose RRset did not survive is a record
			the sender chose and nobody checked - and an answer section holding
			an RRSIG and nothing else is how a forged denial gets itself sent to
			`validate_denial` in the first place.

			Kept by what it covers rather than by having been the signature that
			verified. Deliberate: a set part-way through an algorithm rollover
			carries an RRSIG per algorithm, and a downstream validator may
			implement only the other one, so keeping just the signature this
			build happened to verify would fail exactly the client the records
			are being kept for.

			What is checked is the signer: it has to be the one whose signature
			actually carried this set, which `Authenticated_Set` records. That
			admits the whole rollover case, since the other algorithms' RRSIGs
			name the same signer, and refuses everything the validator itself
			never looked at.

			The signature that actually verified is kept whatever else happens
			to it, which is what makes a cap safe. A plain count cap would be
			worse than the problem: the section order belongs to whoever wrote
			the answer, so eight forgeries in front of the real signature would
			fill the allowance and the real one would be what got evicted - and
			the message would then go out under AD with nothing in it that
			verifies, cached that way for every downstream validator behind this
			resolver. A cap that cannot be made to drop the one record the
			answer rests on does not have that failure.

			The rest are held to `MAX_SIGNATURES_PER_RRSET`, which is what stops
			an answer padded with hundreds of same-signer forgeries being stamped
			with AD, cached, and then handed to every downstream validator to
			work through on every hit.
			*/
			rdata, is_raw := raw_rdata(rec)
			if !is_raw {
				continue
			}
			err: Parse_Error
			if parsed, err = parse_rrsig(rdata, allocator); err != .None {
				continue
			}
			covered = parsed.type_covered
		}
		idx, vouched := authenticated_rrset(kept, rec.name, covered, rec.class)
		if !vouched {
			continue
		}
		if rec.type != .RRSIG {
			set_ttl[idx] = min(set_ttl[idx], rec.ttl)
		} else if !keep_signature(kept, idx, parsed, rec.ttl, sigs_kept, verified_kept, set_ttl) {
			continue
		}
		append(&out, rec)
		append(&owner, idx)
	}
	for &rec, i in out {
		rec.ttl = set_ttl[owner[i]]
	}
	return out[:], true
}

/*
Whether the RRSIG `parsed`, over `kept[idx]` with TTL `ttl`, is kept: only from
the signer that carried the set, and within `MAX_SIGNATURES_PER_RRSET` apart
from the one that verified. Counts it in `sigs_kept`, or marks the verified one
in `verified_kept` and holds the set to its TTL in `set_ttl`.
*/
@(private)
keep_signature :: proc(
	kept: []Authenticated_Set,
	idx: int,
	parsed: Rrsig,
	ttl: u32,
	sigs_kept: []int,
	verified_kept: []bool,
	set_ttl: []u32,
) -> bool {
	if !dns.name_equal_fold(parsed.signer, kept[idx].signer) {
		return false
	}
	/*
	The record that verified is exempt from the cap, and exempt once.

	The test compares content rather than identity - and the genuine
	signature is public, so an attacker appends verbatim copies of it and
	every copy would match. An exemption that counted each of them would be
	unlimited and the cap would never fire, which is the padding it exists
	to stop, arrived at by copying instead of forging.
	*/
	exempt := !verified_kept[idx] && rrsig_equal(parsed, kept[idx].rrsig)
	if exempt {
		verified_kept[idx] = true
		set_ttl[idx] = min(set_ttl[idx], ttl)
	} else {
		if sigs_kept[idx] >= MAX_SIGNATURES_PER_RRSET {
			return false
		}
		sigs_kept[idx] += 1
	}
	return true
}

/*
The additional section keeps its OPT record and the hints that were checked.

`kept` is `Result.additional`, which `validated_hints` fills with the address
RRsets an authenticated answer pointed at and this server then authenticated in
their own zones. Everything else goes, because nothing else in the section was
looked at and there is no second copy of the answer to serve the clients that
would rather have the unauthenticated version: the cache key tells DO and CD
apart and nothing else, so one message is what every client behind this resolver
gets.

The OPT record survives on its own account and is written last, which is where
every responder puts it. It is transport rather than data - no owner name to
authenticate - and taking it out would drop the upper bits of the rcode and any
extended error with them.

An NS answer's addresses are not on the list, and the omission is deliberate.
The NS RRset of a delegation arrives in the *authority* section and is never
authenticated, so it names no target here and the addresses below it stay glue -
which is the whole of #177 and must not be undone by a procedure about hints.
*/
@(private)
authenticated_and_opt :: proc(
	section: []dns.Record,
	kept: []Authenticated_Set,
	allocator: mem.Allocator,
) -> (
	records: []dns.Record,
	ok: bool,
) {
	hints := authenticated_only(section, kept, allocator) or_return
	out := dns.alloc_list([dynamic]dns.Record, len(hints) + 1, allocator) or_return
	append(&out, ..hints)
	for rec in section {
		if rec.type == .OPT {
			if _, aerr := append(&out, rec); aerr != nil {
				return nil, false
			}
		}
	}
	return out[:], true
}

// Like `first_of_rrset`'s test, but the class is part of the question here: a record of
// some other class carries neither the name nor the type it appears to, and an
// RRset is only ever checked in the class it was checked in.
@(private)
authenticated_rrset :: proc(
	kept: []Authenticated_Set,
	name: string,
	type: dns.Type,
	class: dns.Class,
) -> (
	index: int,
	found: bool,
) {
	for q, i in kept {
		if q.type == type && q.class == class && dns.name_equal_fold(q.name, name) {
			return i, true
		}
	}
	return 0, false
}
