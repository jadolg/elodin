package dnssec

import "core:mem"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
The chain of trust.

elodin forwards rather than recurses, so the material a validator needs is not
lying around from a resolution it did itself: every DS and DNSKEY has to be
asked for. `Query_Proc` is how, and the caller supplies it, which keeps this
package free of any dependency on the transports and makes the whole thing
testable against captured traffic.

The walk always starts at a trust anchor and works down. At each label the
parent's keys are used to check the child's DS, and the DS is used to check the
child's DNSKEY; when the parent shows that no DS exists the chain ends there and
everything below is insecure rather than forged. Nothing below an unproven step
is ever treated as authentic.
*/

Status :: enum u8 {
	// Checked against the chain of trust and genuine.
	Secure,
	// Provably outside the chain of trust: an unsigned zone, or an algorithm
	// this build cannot check. Correct data, just unverifiable.
	Insecure,
	// Signed, and the signature does not hold up. Never served to a client.
	Bogus,
	// The chain could not be assembled - an upstream failure, most likely.
	// Treated like bogus at the door, but distinguished so logs are honest.
	Indeterminate,
}

/*
Fetch one record set on the validator's behalf.

Must ask with DO and CD set: the validator wants the signatures, and it wants
the upstream's own opinion of them kept out of the way. `wire` is a complete DNS
response allocated from `allocator`.
*/
Query_Proc :: #type proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool)

Trust_Anchor :: struct {
	zone: string,
	ds:   Ds,
}

Options :: struct {
	// Zero uses the built-in root anchors.
	anchors:              []Trust_Anchor,
	// Iteration counts above this make a proof unusable rather than trusted.
	max_nsec3_iterations: int,
	max_cached_zones:     int,
}

Validator :: struct {
	anchors:              []Trust_Anchor,
	query:                Query_Proc,
	query_ctx:            rawptr,
	max_nsec3_iterations: int,
	max_cached_zones:     int,

	mu:                   sync.Mutex,
	zones:                map[string]^Zone_Entry,

	allocator:            mem.Allocator,
}

@(private)
Zone_Entry :: struct {
	// Owns the string the map is keyed by, so replacing an entry can hand the
	// same allocation back to the map rather than leave one of them dangling.
	zone:    string,
	status:  Status,
	keys:    []Dnskey,
	expires: time.Time,
}

// A chain longer than this is not a real delegation hierarchy.
MAX_CHAIN_DEPTH :: 24

/*
DS and DNSKEY lookups one client question may provoke, in total.

The chain depth alone does not bound the work: a response is free to carry
records under many different owner names, each naming a different signer, and
validating every one of them would have the resolver walk a chain apiece. That
turns one question into hundreds of upstream queries, with a worker held for all
of them. Real answers need a handful, so a response that needs more than this is
answered with SERVFAIL rather than chased.
*/
MAX_LOOKUPS_PER_QUERY :: 32

/*
Signatures kept beside one RRset when the response is pruned.

Not an attempt limit any more: `validate_rrset` and `verified_rrset` both spend
`MAX_VERIFICATIONS_PER_QUERY` instead, having each had a per-RRset cap that an
attacker could fill. What is left is what `strip_unauthenticated` will hand on
besides the signature that actually verified, which is exempt - a set carries
one signature per algorithm in practice, and more than this is padding aimed at
whatever validates downstream.
*/
MAX_SIGNATURES_PER_RRSET :: 8

// CNAME hops followed when checking that an answer addresses the question.
// Real chains are one or two; anything past this is a loop or a stall.
MAX_CNAME_CHAIN :: 16

// Keys a zone may publish. Far past any real zone, and it bounds both the
// canonical form built over the set and what the cache then holds on to.
MAX_KEYS_PER_ZONE :: 64

/*
What one call to `validate` is allowed to spend.

Carried down the whole walk rather than kept on the validator, because the limit
is per client question: two queries arriving at once each get their own.
*/
@(private)
Budget :: struct {
	lookups:       int,
	verifications: int,
}

/*
Signature checks one client question may provoke, in total.

A per-RRset cap cannot do this job, and having one was a way to break a zone: a
signature is only tried when its signer names a zone in the owner's ancestry,
but the signer is a name in the RDATA and anyone able to add records can write
it. Eight forgeries at the head of an RRset therefore spent the whole per-RRset
allowance before the genuine signature was reached, the set was dropped, and the
answer came back Bogus - a denial's RRset taking every NXDOMAIN in the zone with
it. The cap could only ever be filled by signatures an attacker chose; the
genuine one is what it kept out. Both paths that verify a set - `validate_rrset`
for the answer section and `verified_rrset` for a denial - are counted here, so
neither keeps a private allowance that can be emptied on its own.

Counted across the question instead, and spent only on signatures that could
actually verify - see `signature_worth_trying`, which refuses the rest for
nothing. Generous next to any real answer: a set carries one signature per
algorithm, and a chain a handful of sets.

Spent by `validate_rrset` and `verified_rrset`, which is every signature over an
answer's own RRsets and over a denial's proof. It is *not* spent by the two
loops that check a DS set in `zone_step` or a DNSKEY set in `fetch_keys`; those
have never had a bound of any kind, before this change or after it, and giving
them one is #193 rather than something to bolt on here. So this is a bound on
the signatures a response's own records provoke, not on every verification a
question can reach.

It is also a bound on work and not a guarantee that the genuine signature is
reached, and the difference is worth being plain about. A forgery that copies the real
signature's key tag, algorithm and validity window - all of them public - buys a
verification apiece, and enough of them in front of the real one will exhaust
this and turn the answer Bogus. No number fixes that: the count and the order
are the sender's, so any budget spent in section order can be spent before the
record that matters. What stops it being worth doing is that whoever can rewrite
a response that far can deny the answer by corrupting it instead, which DNSSEC
never promised to prevent. Leaving the budget out is the option that is actually
unsafe - that is unbounded verification on a message an attacker wrote.
*/
MAX_VERIFICATIONS_PER_QUERY :: 64

/*
Whether a signature could verify at all, decided without doing any crypto.

Every signature reaching a verification is one an attacker may have written, so
the useful question before spending anything on one is whether it stands a
chance. Two things answer it for free: a signature outside its validity window
cannot verify, and neither can one whose key tag and algorithm name no key the
zone published.

That is what keeps the budgets below from being an attacker's to spend. A
forgery now has to name a key tag the zone actually has - and the tag is public,
so this is a cost rather than a wall - where before any sixteen bytes of noise
with the right owner name were enough to consume an attempt.

Deliberately the same test `check_signature` makes internally, hoisted out. It
stays there too: this one decides whether to spend, that one decides the result,
and a caller reaching the second without the first is answered correctly, just
more expensively.
*/
@(private)
signature_worth_trying :: proc(sig: Rrsig, keys: []Dnskey, unix: u32) -> bool {
	if !signature_current(sig, unix) {
		return false
	}
	for key in keys {
		if key.algorithm == sig.algorithm && key.tag == sig.key_tag && key_usable(key) {
			return true
		}
	}
	return false
}

@(private)
spend_verification :: proc(budget: ^Budget) -> bool {
	if budget.verifications >= MAX_VERIFICATIONS_PER_QUERY {
		return false
	}
	budget.verifications += 1
	return true
}

@(private)
spend_lookup :: proc(budget: ^Budget) -> bool {
	if budget.lookups >= MAX_LOOKUPS_PER_QUERY {
		return false
	}
	budget.lookups += 1
	return true
}

// RFC 9276 asks zones for zero iterations; a hundred is far past anything in
// use and still cheap to compute.
DEFAULT_MAX_NSEC3_ITERATIONS :: 100

DEFAULT_MAX_CACHED_ZONES :: 4096

// How long a zone's keys, or the fact that a zone is unsigned, may be reused.
// The record TTLs decide within these bounds.
MIN_ZONE_TTL :: 60
MAX_ZONE_TTL :: 3600

make_validator :: proc(
	query: Query_Proc,
	query_ctx: rawptr,
	opts: Options,
	allocator := context.allocator,
) -> ^Validator {
	v := new(Validator, allocator)
	v.allocator = allocator
	v.query = query
	v.query_ctx = query_ctx
	v.anchors = opts.anchors if len(opts.anchors) > 0 else root_anchors()
	v.max_nsec3_iterations = opts.max_nsec3_iterations if opts.max_nsec3_iterations > 0 else DEFAULT_MAX_NSEC3_ITERATIONS
	v.max_cached_zones = opts.max_cached_zones if opts.max_cached_zones > 0 else DEFAULT_MAX_CACHED_ZONES
	v.zones = make(map[string]^Zone_Entry, 64, allocator)
	return v
}

destroy_validator :: proc(v: ^Validator) {
	if v == nil {
		return
	}
	for _, entry in v.zones {
		free_entry(v, entry)
	}
	delete(v.zones)
	free(v, v.allocator)
}

@(private)
free_entry :: proc(v: ^Validator, entry: ^Zone_Entry) {
	for key in entry.keys {
		delete(key.rdata, v.allocator)
	}
	delete(entry.keys, v.allocator)
	delete(entry.zone, v.allocator)
	free(entry, v.allocator)
}

// ---------------------------------------------------------------------------
// Validating one response
// ---------------------------------------------------------------------------

Result :: struct {
	status:    Status,
	// A short phrase for the log line and the extended DNS error.
	reason:    string,
	/*
	The RRsets the verdict actually rests on, as owner/type/class triples, in
	the section each was read from.

	A `Secure` status is reached by checking particular record sets, not by
	reading the whole message: `validate_answer` looks at the answer section,
	`validate_denial` at the NSEC and NSEC3 records that carry the proof. What
	arrived alongside them - a delegation in the authority section, glue in the
	additional section - is never examined and is nobody's word but the
	sender's. RFC 4035 section 3.2.3 lets the AD bit be set only over data the
	resolver authenticated, so the caller needs to know which records those
	were; `strip_unauthenticated` is what does something about it.

	The two sections are kept apart because the section is part of an RRset's
	identity here. A signature is checked over the records of one section, so
	`www.example.com. A` holding up in the answer says nothing about a set of
	that name and type in the authority section - which is free to hold a
	different address, and would otherwise be waved through on its neighbour's
	credentials.

	Filled in only on the `Secure` path, since nothing else can set AD.
	*/
	answer:    []Authenticated_Set,
	authority: []Authenticated_Set,
}

/*
An RRset the verdict rests on, and the signer whose signature carried it.

The signer is here because `strip_unauthenticated` has to decide which of the
signatures in the message may travel with the set, and the only honest answer is
"the ones naming the signer this server actually verified against". Anything
looser is a guess: the name in an RRSIG's signer field is chosen by whoever
wrote the record, so a test that merely asks whether it lies in the owner's
ancestry admits signatures the validator itself skipped without a glance.
*/
Authenticated_Set :: struct {
	name:      string,
	type:      dns.Type,
	class:     dns.Class,
	signer:    string,
	/*
	The whole RRSIG that carried it, so the prune can keep that record whatever
	else it drops.

	All of it, and this took three goes to get right. Keyed on the key tag and
	algorithm, a forgery copied both out of the zone's public DNSKEY set and
	took the exemption. Keyed on the signature bytes, an attacker did not even
	have to forge: it appended verbatim copies, and then - once those were
	counted - a near-copy, the genuine record with one bit of its ORIGINAL TTL
	flipped and the signature left alone. That mutant satisfied a
	signature-bytes test, took the exemption, and the forgeries behind it filled
	the cap so that the *genuine* record was the one dropped. The answer then
	went out under AD and into the cache no longer validating for anybody.

	Every field is compared because every field an attacker can vary is a way to
	be mistaken for the record that verified while not being it. A copy that
	matches on all of them is the same record, which is what `verified_kept`
	is for.

	The slices inside point into the message the verdict was reached over, which
	the caller's arena keeps alive for as long as the prune needs it.
	*/
	rrsig: Rrsig,
}

// Whether two RRSIGs are the same record, field for field.
@(private)
rrsig_equal :: proc(a, b: Rrsig) -> bool {
	return(
		a.type_covered == b.type_covered &&
		a.algorithm == b.algorithm &&
		a.labels == b.labels &&
		a.original_ttl == b.original_ttl &&
		a.expiration == b.expiration &&
		a.inception == b.inception &&
		a.key_tag == b.key_tag &&
		dns.name_equal_fold(a.signer, b.signer) &&
		slice.equal(a.signature, b.signature) \
	)
}

/*
Decide whether a response is authentic.

`wire` is the upstream's answer to the client's question, fetched with DO and CD
set. `now` is passed in rather than read here so the tests can pin it inside the
validity window of the captured signatures.
*/
validate :: proc(
	v: ^Validator,
	qname: string,
	qtype: dns.Type,
	wire: []u8,
	now: time.Time,
	allocator := context.temp_allocator,
) -> Result {
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return {status = .Bogus, reason = "unparseable response"}
	}
	class := msg.question[0].class if len(msg.question) > 0 else dns.Class.IN
	unix := u32(time.to_unix_seconds(now))
	budget := Budget{}

	/*
	REFUSED, SERVFAIL and the rest carry nothing to authenticate. Demanding a
	denial of existence from them would turn every upstream error into a DNSSEC
	failure, and report it as a forgery in the bargain.
	*/
	if !answerable_rcode(msg) {
		return {status = .Insecure, reason = "no data to authenticate"}
	}

	/*
	Which path a response takes is decided by the records that can actually be
	authenticated, not by the answer section being non-empty.

	An RRSIG is never covered by a signature of its own, so it is skipped by
	`validate_answer` and can never be the thing that makes an answer genuine.
	Counting it as one would hand an attacker the denial path: a forged NXDOMAIN
	with a single junk RRSIG dropped into its answer section would be sent to
	`validate_answer`, which finds nothing it can check and says so - and the
	proof of non-existence that `validate_denial` would have demanded is never
	asked for. The denial is then served as merely unsigned.
	*/
	answerable := 0
	for rec in msg.answer {
		if rec.type != .RRSIG && rec.type != .OPT {
			answerable += 1
		}
	}
	if answerable > 0 {
		return validate_answer(v, &budget, msg, qname, qtype, class, unix, now, allocator)
	}
	/*
	A question about RRSIG records themselves is the one case where an answer
	made only of them is honest: an RRSIG RRset carries no signature of its own
	(RFC 4035 section 2.2), so there is nothing here to authenticate and no
	denial to demand either.
	*/
	if qtype == .RRSIG && len(msg.answer) > 0 {
		return {status = .Insecure, reason = "nothing to authenticate"}
	}
	return validate_denial(v, &budget, msg, qname, qtype, class, unix, now, allocator)
}

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
before it can connect. They are dropped all the same, because they are signed by
the target's zone rather than by the one this query established, so keeping them
authenticated means the same second chain walk the denial case needs - and
keeping them unauthenticated under our AD bit is the whole thing this procedure
exists to stop. The cost is a round trip on a shape that is getting commoner, so
it is filed rather than shrugged at.

The one real loss is a CNAME chain that ends in a denial - a dual-stack client
asking AAAA for an IPv4-only name is the everyday version of it, and a CNAME
pointing at a name that does not exist is the same shape with NXDOMAIN on it.
Either reaches `Secure` through `validate_answer` on the strength of the CNAME
alone, and the proof sitting in its authority section belongs to the target's
zone, which nothing here ever established. So out it goes with the rest, SOA
included, and a downstream resolver falls back to its own idea of how long to
remember the absence.

Our own cache falls back with it, and only on the NXDOMAIN half. `cache.put`
picks its lifetime on `rcode == .NX_Domain || len(msg.answer) == 0`, so the
NODATA one keeps its CNAME in the answer section and is held for the shortest
TTL still there; the NXDOMAIN one takes the negative branch whatever its answer
section holds, finds no SOA to read, and is held for `cache.negative_ttl`
instead - longer than a zone asking for less would like, and not at all where an
operator has set that to zero. Both are the same missing chain walk, and are
fixed by the same one.

The rcode is the part of this no prune can reach. AD covers the records in those
two sections, and this makes it honest about them; it says nothing about the
header. An on-path attacker who flips a signed CNAME answer to NXDOMAIN still
gets `Secure` out of `validate_answer`, on the strength of a CNAME that really
is signed, and the client reads an authenticated denial nobody proved. That is
the same missing chain walk again, from the other end, and the same issue.

Two ways not to lose it, and neither belongs here. Keeping the records and
clearing AD instead is the one that looks free: it is not, because AD is a
property of the message and not of a section, so the commonest answer shape
there is would go out unauthenticated - and the copy that lands in the cache
would be AD-less for every later client too. A negative-caching hint is not
worth the bit on the common path. The other way is the correct one, which is to
establish the target's zone and validate the denial there; that is a second
chain walk on a hot path, it widens what gets checked rather than narrowing what
gets claimed, and it is filed as its own issue rather than smuggled in here.

The OPT record survives on its own account. It is transport rather than data -
no owner name to authenticate - and taking it out would drop the upper bits of
the rcode and any extended error with them.

Only a `Secure` verdict is pruned. Nothing else sets AD, so nothing else has a
boundary to keep, and the other paths name no RRsets at all - pruning against
that would throw the response away.
*/
strip_unauthenticated :: proc(
	wire: []u8,
	result: Result,
	allocator := context.temp_allocator,
	limit := dns.MAX_MESSAGE,
) -> (
	out: []u8,
	ok: bool,
) {
	if result.status != .Secure {
		return wire, true
	}
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return nil, false
	}
	msg.answer = authenticated_only(msg.answer, result.answer, allocator)
	msg.authority = authenticated_only(msg.authority, result.authority, allocator)
	msg.additional = opt_only(msg.additional, allocator)

	/*
	A truncated rebuild is a failure, not a result. `encode_message` drops
	whatever no longer fits and says so in `truncated`; taking that as the
	pruned message would hand the caller a response with records missing and
	nothing to distinguish it from a complete one - and the caller's next act is
	to set the AD bit over it. Failing instead leaves the original standing
	without the bit, which is the same fallback an encode error already gets.
	*/
	encoded, truncated, enc := dns.encode_message(msg, allocator, limit)
	if enc != .None || truncated {
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
is the right place for it: what is guarded against is a false denial reaching a
client under our AD bit, so deleting the claim removes the harm rather than
hiding it. The client then sees a redirection and goes and asks the target
itself.
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

`answers_question` folded two different outcomes into one `true`: a record of
the type asked for, and a CNAME chain that stopped short of it. The second is
not an answer - it is a redirection, and whatever explains the missing type
lives in the authority section at a zone this path never walked to. Keeping them
apart is what lets the caller stamp AD on the first and decline to on the
second.
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
Follow the chain from `qname` and report where it ended up.

The walk is the only thing consulted, and that is the point. Scanning the whole
section for any record of the type is not the same test and was a way to get
this wrong: an attacker with a signed zone of its own appends
`x.evil.example. A`, which has nothing to do with the question, and a scan sees
the type and stops asking.
*/
@(private)
chain_shape :: proc(
	records: []dns.Record,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
) -> Answer_Shape {
	name := qname
	hops := 0
	for hops < MAX_CNAME_CHAIN {
		target := ""
		for r in records {
			if r.class != class || !dns.name_equal_fold(r.name, name) {
				continue
			}
			if r.type == qtype || qtype == .ANY {
				return .Direct
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
			return .Chain_Only if hops > 0 else .None
		}
		name = target
		hops += 1
	}
	// A chain this long is a loop or a stall, and either way proves nothing.
	return .None
}

@(private)
authenticated_only :: proc(
	section: []dns.Record,
	kept: []Authenticated_Set,
	allocator: mem.Allocator,
) -> []dns.Record {
	// Nothing in this section was authenticated, so nothing in it survives. Worth
	// saying up front: a denial names no RRsets in the answer section, and the
	// loop below would otherwise parse and allocate a signer name for every RRSIG
	// sitting there before dropping the lot.
	if len(kept) == 0 {
		return nil
	}
	// Signatures kept for each authenticated RRset beyond the one that verified,
	// and whether that one has been kept already.
	sigs_kept := make([]int, len(kept), allocator)
	verified_kept := make([]bool, len(kept), allocator)
	out := make([dynamic]dns.Record, 0, len(section), allocator)
	for rec in section {
		covered := rec.type
		signer: string
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
			to it, which is what makes a cap safe again. A plain count cap was
			tried here first and was worse than the problem: the section order
			belongs to whoever wrote the answer, so eight forgeries in front of
			the real signature filled the allowance and the real one was what
			got evicted - and the message then went out under AD with nothing in
			it that verifies, cached that way for every downstream validator
			behind this resolver. A cap that cannot be made to drop the one
			record the answer rests on does not have that failure.

			The rest are held to `MAX_SIGNATURES_PER_RRSET`, which is what stops
			an answer padded with hundreds of same-signer forgeries being stamped
			with AD, cached, and then handed to every downstream validator to
			work through on every hit.
			*/
			rdata, is_raw := raw_rdata(rec)
			if !is_raw {
				continue
			}
			sig, err := parse_rrsig(rdata, allocator)
			if err != .None {
				continue
			}
			covered = sig.type_covered
			signer = sig.signer
			parsed = sig
		}
		idx, ok := authenticated_rrset(kept, rec.name, covered, rec.class)
		if !ok {
			continue
		}
		if rec.type == .RRSIG {
			if !dns.name_equal_fold(signer, kept[idx].signer) {
				continue
			}
			/*
			The record that verified is exempt from the cap, and exempt once.

			The test is on the signature bytes, which is a comparison of content
			rather than of identity - and the genuine signature is public, so an
			attacker appends verbatim copies of it and every copy matched. The
			exemption was then unlimited and the cap never fired, which is the
			padding it exists to stop, arrived at by copying instead of forging.
			*/
			exempt := !verified_kept[idx] && rrsig_equal(parsed, kept[idx].rrsig)
			if exempt {
				verified_kept[idx] = true
			} else {
				if sigs_kept[idx] >= MAX_SIGNATURES_PER_RRSET {
					continue
				}
				sigs_kept[idx] += 1
			}
		}
		append(&out, rec)
	}
	return out[:]
}

/*
The additional section keeps its OPT record and nothing else.

Nothing else in it was authenticated, and there is no second copy of the answer
to serve the clients that would rather have the unauthenticated version: the
cache key tells DO and CD apart and nothing else, so one message is what every
client behind this resolver gets.

What that costs is the address records a responder sends beside an HTTPS, SVCB,
SRV, MX or NS answer (RFC 9460 section 5) - a client loses them and pays a round
trip to look them up. Filed as #189, which is where a way to keep the signed ones
belongs; it needs the answer's own RRsets checked in the additional section
rather than a change here.
*/
@(private)
opt_only :: proc(section: []dns.Record, allocator: mem.Allocator) -> []dns.Record {
	out := make([dynamic]dns.Record, 0, 1, allocator)
	for rec in section {
		if rec.type == .OPT {
			append(&out, rec)
		}
	}
	return out[:]
}

// Like `already_seen`, but the class is part of the question here: a record of
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

@(private)
validate_answer :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Result {
	worst := Status.Secure
	reason: string
	wildcard_seen := false
	checked := 0

	// What the verdict will be allowed to cover. Built from the RRsets that
	// came back `Secure` rather than from `seen`, which also holds the ones
	// that did not - the two only coincide while the whole answer holds up.
	authenticated := make([dynamic]Authenticated_Set, 0, len(msg.answer), allocator)
	seen := make([dynamic]dns.Question, 0, len(msg.answer), allocator)
	for rec in msg.answer {
		if rec.type == .RRSIG || rec.type == .OPT {
			continue
		}
		if already_seen(seen[:], rec.name, rec.type) {
			continue
		}
		append(&seen, dns.Question{name = rec.name, type = rec.type})

		records := records_of(msg.answer, rec.name, rec.type, class, allocator)
		sigs := sigs_covering(msg.answer, rec.name, rec.type, class, allocator)

		status, wildcard, why, signer, carried := validate_rrset(
			v,
			budget,
			rec.name,
			rec.type,
			class,
			records,
			sigs,
			unix,
			now,
			allocator,
		)
		/*
		A CNAME carrying no signature at all may be one a DNAME produced rather
		than one a zone forgot to sign. RFC 6672 section 3.4.1 has the server
		synthesize it and send it unsigned, the DNAME being what carries the
		authority, so demanding a signature here refuses every name that
		resolves through one.

		Only an unsigned CNAME is reconsidered. A CNAME that came with a
		signature was meant to have one, and a signature that did not hold up
		is not something a DNAME excuses.

		Every record of the set has to be covered, not just the first one found
		at that owner. The verdict recorded below names an RRset, and the prune
		keeps everything matching it - so asking about one record and vouching
		for the set let a second, unsigned CNAME at the same owner ride out
		under the AD bit, pointing wherever the sender liked. A zone may not
		publish two CNAMEs at one name (RFC 1034 section 3.6.2) and a DNAME
		synthesizes exactly one, so a set with a second is not a set a DNAME
		produced; the loop stops at the first record no DNAME accounts for.
		*/
		if status != .Secure && rec.type == .CNAME && len(sigs) == 0 {
			covered := len(records) > 0
			for r in records {
				if !dname_covered(v, budget, msg, r, class, unix, now, allocator) {
					covered = false
					break
				}
			}
			if covered {
				status = .Secure
				why = ""
			}
		}
		wildcard_seen ||= wildcard
		checked += 1
		if status != .Secure {
			worst = worse(worst, status)
			reason = why
			continue
		}
		append(
			&authenticated,
			Authenticated_Set {
				name = rec.name,
				type = rec.type,
				class = class,
				signer = signer,
				rrsig = carried,
			},
		)
	}

	/*
	A backstop. `validate` only sends a response here once it has counted a
	record this loop will check, so reaching this means the two disagree about
	what is authenticatable. Whatever the cause, an empty check is not a pass.
	*/
	if checked == 0 {
		return {status = .Insecure, reason = "nothing to authenticate"}
	}

	/*
	Every RRset held up on its own. That is not yet an answer to the question:
	each was judged against the zone that claims it, and nothing so far has
	asked whether any of them concern the name that was asked about.

	An attacker with a signed zone of their own has an endless supply of validly
	signed RRsets, and offering one under someone else's question would pass
	every check above. The verdict would be `Secure`, the AD bit would go out,
	and a stub would read an authenticated answer holding nothing for the name
	it asked about - a denial of existence that was never proven.
	*/
	shape := chain_shape(msg.answer, qname, qtype, class)
	if worst == .Secure && shape == .None {
		return {status = .Bogus, reason = "answer does not address the question"}
	}

	/*
	A wildcard answer is only good if the name really had nothing of its own.
	Without this an attacker holding one wildcard signature could serve it for
	names the zone answers for directly.

	That proof is also the only thing this path authenticates outside the answer
	section. It was checked against the zone's keys, so it is as authentic as
	the answer it stands behind, and a client that validates for itself needs it
	to reach the same conclusion.
	*/
	proved: []Authenticated_Set
	if worst == .Secure && wildcard_seen {
		proof, records := validate_wildcard_proof(v, budget, msg, qname, class, unix, now, allocator)
		if proof != .Secure {
			return {status = proof, reason = "wildcard expansion not proven"}
		}
		proved = records
	}

	/*
	A chain that ends without the type asked for, where the sender is claiming
	there is nothing more, is a denial this path did not check.

	The everyday shape is an AAAA lookup for a name whose CNAME leads somewhere
	with only an A record: the CNAME verifies, the chain concerns the question,
	and the verdict is `Secure` - reached entirely from the answer section. What
	says the target really has no AAAA lives in the *authority* section, at the
	target's zone, which nothing here walked to. The prune keeps only what the
	verdict names, so that proof was stripped, and the AD bit went out over what
	was left: a downstream resolver validating for itself gets an authenticated
	denial with nothing behind it and refuses it.

	Both halves are needed, and finding that out cost a regression. A chain
	stopping short is not enough on its own - a DNAME redirection is exactly
	that shape and is not a denial, so refusing on the shape alone took the AD
	bit off every one of them. `denial_claimed` is the other half.

	*After* the wildcard proof, and that ordering is load-bearing. Put before it,
	this became a way to skip that proof: an attacker replays a genuine wildcard
	record as the answer for a name that has its own records, adds one SOA, and
	what used to be `Bogus` - refused, SERVFAIL - came back `Insecure`, which
	`resolve_query` forwards to the client. A guard meant to withhold an answer
	must not be reachable before the check that would have withheld it outright.

	`Insecure` is the honest verdict: this server has no opinion on the denial.
	Nothing is pruned, so the proof reaches the client intact and it can check
	it, and no AD bit claims otherwise. Checking it here means walking to the
	target's zone, which is #186.
	*/
	if worst == .Secure && shape == .Chain_Only && denial_claimed(msg) {
		return {status = .Insecure, reason = "denial after a cname was not checked"}
	}
	/*
	The RRsets are named only when the verdict is `Secure`, which is what
	`Result` promises and the only case a caller may prune against. A partial
	verdict has a partial list behind it - the RRsets that happened to hold up
	while another did not - and pruning a message down to that would drop
	records from an answer nobody is vouching for anyway.
	*/
	if worst != .Secure {
		return {status = worst, reason = reason}
	}
	return {status = worst, reason = reason, answer = authenticated[:], authority = proved}
}

@(private)
validate_denial :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	qtype: dns.Type,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Result {
	/*
	The zone is worked out from the name that was asked about, not from a signer
	named in the response.

	On the positive path a signer name is a safe hint: whatever zone it points
	at, the data still has to survive that zone's signature, so a wrong guess
	buys nothing. Here there is no such backstop. "None of these records
	verified" and "that was the wrong zone to check them against" look
	identical, so a single injected RRSIG naming some unsigned zone would have
	the whole denial written off as insecure and served - which is precisely the
	forged NXDOMAIN that DNSSEC exists to refuse. Walking down to the name costs
	a lookup and settles it.
	*/
	status, keys, established := zone_trust(v, budget, qname, now, allocator)
	#partial switch status {
	case .Insecure:
		return {status = .Insecure, reason = "unsigned zone"}
	case .Bogus:
		return {status = .Bogus, reason = "broken chain of trust"}
	case .Indeterminate:
		return {status = .Indeterminate, reason = "chain of trust unavailable"}
	}

	nsecs, nsec3s, proved, denial_spent := validated_denial_records(
		v,
		budget,
		msg.authority,
		established,
		class,
		keys,
		unix,
		now,
		allocator,
	)
	/*
	Our own allowance again, and the same answer as everywhere else: a proof this
	server stopped short of reading is not a proof it found wanting. Reported as
	`Indeterminate` rather than left to fall through to "no denial of existence",
	which counts a forgery, warns with the client's address beside the word, and
	hands the client extended error 6.
	*/
	if denial_spent {
		return {.Indeterminate, "verification budget spent", nil, nil}
	}
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return {status = .Bogus, reason = "no denial of existence"}
	}

	rcode := dns.rcode_of(msg)
	proof: Proof = .Failed
	if rcode == .NX_Domain {
		proof = nsec_proves_name_error(nsecs, qname, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_name_error(nsec3s, qname, established, v.max_nsec3_iterations, allocator)
		}
	} else {
		proof = nsec_proves_no_data(nsecs, qname, qtype, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_no_data(nsec3s, qname, established, qtype, v.max_nsec3_iterations, allocator)
		}
	}

	switch proof {
	case .Proven:
		return {status = .Secure, authority = proved_denial(budget, msg, proved, established, class, keys, unix, allocator)}
	case .Opt_Out:
		return {status = .Insecure, reason = "opt-out span"}
	case .Failed:
		return {status = .Bogus, reason = "denial of existence not proven"}
	}
	return {status = .Bogus, reason = "denial of existence not proven"}
}

/*
What a proven denial is allowed to carry, on top of the proof itself.

The SOA, and only if it holds up. It is the one other record in the authority
section of a NODATA or an NXDOMAIN that a client has a use for - RFC 2308 has it
decide how long the absence may be remembered, and that number reaches this
server's own cache through `dns.negative_ttl` - and the denial path never looks
at it: `validated_denial_records` reads NSEC and NSEC3 records and walks past
everything else. Left unchecked it is a TTL of the sender's choosing under our
AD bit, which is a small forgery but a free one, and a `minimum` of a week on a
denial nobody signed is worth having.

Checking it costs nothing. The zone the denial was proven against is established
and its keys are already in hand, so this is a signature verification against
records that are already here - no walk, no lookup, no chance of turning a
question about a TTL into an upstream query. A sender padding the SOA with
signatures does not buy a fixed allowance of its own, though: it draws on the
query-wide `MAX_VERIFICATIONS_PER_QUERY`, which the denial's own proof has just
been spending. Running it out here drops the SOA - the denial stays proven and
loses only its negative TTL - and says so at debug rather than passing for a
signature that failed.

One owner name is looked at, and it is the apex of that zone: RFC 2308 puts the
SOA of the zone the denial came from in the authority section, and that zone is
the one this denial was established against. Taking the owner from the response
instead would let a sender name as many owners as fits in a message and buy a
signature verification apiece off the back of one question.
*/
@(private)
proved_denial :: proc(
	budget: ^Budget,
	msg: dns.Message,
	proved: []Authenticated_Set,
	zone: string,
	class: dns.Class,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
) -> []Authenticated_Set {
	out := make([dynamic]Authenticated_Set, 0, len(proved) + 1, allocator)
	append(&out, ..proved)
	_, signer, carried, ok, _ := verified_rrset(budget, msg.authority, zone, .SOA, class, zone, keys, unix, allocator)
	if ok {
		append(
			&out,
			Authenticated_Set {
				name = zone,
				type = .SOA,
				class = class,
				signer = signer,
				rrsig = carried,
			},
		)
	}
	return out[:]
}

/*
Check one RRset.

Returns the wildcard flag as well, because a wildcard-expanded answer needs a
denial proof of its own that only the caller can assemble.
*/
@(private)
validate_rrset :: proc(
	v: ^Validator,
	budget: ^Budget,
	owner: string,
	type: dns.Type,
	class: dns.Class,
	records: []dns.Record,
	sigs: []Rrsig,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	wildcard: bool,
	reason: string,
	// Which signature carried the set, for `Authenticated_Set`.
	signer: string,
	rrsig: Rrsig,
) {
	/*
	Each signature names the zone that claims the data, and each is judged
	against the chain down to that zone - rather than probing every label of the
	owner name for a delegation, which would cost a lookup per name.

	Every one of them gets a turn. Taking only the first would let anyone able to
	add a record to a response nominate a signer of their choosing and have the
	genuine signature sitting next to it go unexamined. Trying them all cannot
	help an attacker either: a signer outside the owner's ancestry is refused,
	one below the real zone cut has no DS to reach it, and one above it would
	have to hold a signature it was never in a position to make.
	*/
	unsupported := false
	refused := false
	exhausted := false
	/*
	One chain walk per distinct signer, not one per signature.

	`zone_trust` is the expensive thing in this loop - a walk down the
	hierarchy, taking the validator's lock and cloning a DNSKEY set out of its
	cache at every step - and it used to be bounded only by the per-RRset
	attempt cap that sat above it. With that cap gone the walk became the thing
	an attacker could multiply: a padded answer carrying two thousand RRSIGs
	whose signer merely names an ancestor of the owner bought two thousand
	walks, thousands of acquisitions of a lock every validating worker shares,
	and megabytes of arena, for one question.

	Memoised by signer, which bounds it by the number of ancestors a name has
	rather than by the number of records somebody wrote. Distinct signers are
	the only ones that cost anything, and a name has at most as many ancestors
	as it has labels.
	*/
	Walked :: struct {
		signer:      string,
		status:      Status,
		keys:        []Dnskey,
		established: string,
	}
	walked := make([dynamic]Walked, 0, 4, allocator)

	for sig in sigs {
		if !name_in_zone(owner, sig.signer) {
			continue
		}
		/*
		Free, and needs no keys, so it goes above the walk. An expired or
		not-yet-valid signature cannot verify whatever the chain says, and
		refusing it here is what stops a heap of stale forgeries paying for
		chain walks.
		*/
		if !signature_current(sig, unix) {
			continue
		}

		zone_status: Status
		keys: []Dnskey
		established: string
		seen_walk := false
		for w in walked {
			if dns.name_equal_fold(w.signer, sig.signer) {
				zone_status, keys, established = w.status, w.keys, w.established
				seen_walk = true
				break
			}
		}
		if !seen_walk {
			zone_status, keys, established = zone_trust(v, budget, sig.signer, now, allocator)
			append(
				&walked,
				Walked {
					signer = sig.signer,
					status = zone_status,
					keys = keys,
					established = established,
				},
			)
		}
		if zone_status != .Secure || !dns.name_equal_fold(sig.signer, established) {
			continue
		}
		/*
		Same two guards as the denial path, and for the same reason: this loop
		used to stop after eight signatures whose signer merely named a zone in
		the owner's ancestry, and the signer is a field an attacker writes. Eight
		forgeries in front of the genuine signature therefore spent the whole
		allowance and the answer came back Bogus - the very shape
		`MAX_VERIFICATIONS_PER_QUERY` was introduced to remove, left standing on
		the path every answer-section RRset takes.
		*/
		if !signature_worth_trying(sig, keys, unix) {
			continue
		}
		if !spend_verification(budget) {
			exhausted = true
			break
		}
		result, expanded := check_signature(sig, owner, class, records, keys, unix, allocator)
		#partial switch result {
		case .Ok:
			return .Secure, expanded, "", sig.signer, sig
		case .Unsupported:
			unsupported = true
		case .Refused:
			refused = true
		}
	}

	/*
	Nothing verified. Whether that means forged or merely unsigned is a question
	about the zone the name lives in, not about the signatures that arrived with
	it, so it is settled by walking down to the name itself.
	*/
	/*
	Our own allowance running out is not evidence about the zone.

	`spend_lookup` already settles this the same way: a chain this server could
	not afford to walk comes back `Indeterminate`, "chain of trust unavailable",
	because the answer might be perfectly good and we simply stopped looking.

	What that changes today is the extended error the client is sent - 22,
	"No Reachable Authority", instead of 6, "DNSSEC Bogus" - and the `reason`
	that reaches the log. It does not change the counters: `resolve_query`
	handles `Bogus` and `Indeterminate` in one branch, so `Stats.bogus` moves for
	both, which is worth knowing before reading that gauge as a forgery count.
	Splitting them is a change to what the metric means and belongs with the
	metric rather than here.
	*/
	if exhausted {
		return .Indeterminate, false, "verification budget spent", "", {}
	}

	missing := "signature missing" if len(sigs) == 0 else "no valid signature"
	owner_status, _, _ := zone_trust(v, budget, owner, now, allocator)
	switch owner_status {
	case .Insecure:
		return .Insecure, false, "unsigned zone", "", {}
	case .Indeterminate:
		return .Indeterminate, false, "chain of trust unavailable", "", {}
	case .Bogus:
		return .Bogus, false, "broken chain of trust", "", {}
	case .Secure:
	}

	/*
	Nothing here was checkable, and the zone it belongs to is signed with
	something that was.

	An algorithm we do not implement makes a *delegation* insecure - `zone_step`
	settles that at the DS, per RFC 6840 section 5.2 - but it cannot make an
	RRset inside an established zone insecure, which is the correction in
	section 5.11 of the same document. A zone signed with two algorithms
	publishes an RRSIG for each, so treating this as unsigned would let an
	attacker strip the signature we can verify, alter the records, and have what
	is left reach the client as merely unvalidated instead of refused. The whole
	point of the second algorithm, inverted.
	*/
	if unsupported {
		return .Bogus, false, "no signature this build can verify", "", {}
	}

	/*
	The library would not run an algorithm we do implement, which is a statement
	about this machine rather than about the zone.

	Refusing here would make a zone unresolvable on a host whose crypto policy
	rules SHA-1 out - Fedora and RHEL, for algorithms 5 and 7 - while the same
	build resolved it everywhere else, so the data is treated as unsigned as it
	always has been. That leaves the section 5.11 downgrade open on those hosts
	for zones that publish a refused algorithm alongside a supported one; the
	place to close it is `algorithm_supported`, which should answer for what the
	linked library will actually run so that the delegation goes insecure at the
	DS instead.
	*/
	if refused {
		return .Insecure, false, "algorithm refused by local policy", "", {}
	}
	return .Bogus, false, missing, "", {}
}

/*
Try one signature against the keys of its zone.

Rejects everything RFC 4035 section 5.3.1 asks to be rejected before any
cryptography happens: the wrong signer, a label count that does not fit the
owner name, an expired or not-yet-valid period.
*/
@(private)
check_signature :: proc(
	sig: Rrsig,
	owner: string,
	class: dns.Class,
	records: []dns.Record,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	result: Verify_Result,
	wildcard: bool,
) {
	if !signature_current(sig, unix) {
		return .Bad, false
	}
	// A zone may only sign what is inside it. Without this a zone could vouch
	// for names it has no authority over, which is the whole point of the
	// hierarchy.
	if !name_in_zone(owner, sig.signer) {
		return .Bad, false
	}
	/*
	RFC 4034 section 3.1.3 counts the Labels field without a leading `*`, so a
	name that is itself a wildcard - and `*.example.com.` is an ordinary name a
	zone may hold records for - has to be counted the same way here. Counting
	the `*` would make a correct signature look one label short, which is the
	mark of a wildcard expansion, and the answer would be sent off for a proof
	that the name does not exist. It plainly does.
	*/
	owner_labels := label_count(owner)
	if strings.has_prefix(owner, "*.") {
		owner_labels -= 1
	}
	signer_labels := label_count(sig.signer)
	if int(sig.labels) > owner_labels || int(sig.labels) < signer_labels {
		return .Bad, false
	}

	// Fewer labels than the owner name means the zone answered from a wildcard,
	// and the signature was made over that wildcard rather than over the name.
	signing_owner := owner
	if int(sig.labels) < owner_labels {
		signing_owner = wildcard_of(name_drop_labels(owner, owner_labels - int(sig.labels)), allocator)
		wildcard = true
	}

	data, built := signing_input(sig, signing_owner, class, records, allocator)
	if !built {
		return .Bad, wildcard
	}

	unsupported := false
	refused := false
	for key in keys {
		if key.algorithm != sig.algorithm || key.tag != sig.key_tag || !key_usable(key) {
			continue
		}
		switch verify_signature(sig.algorithm, key.public_key, sig.signature, data, allocator) {
		case .Ok:
			return .Ok, wildcard
		case .Unsupported:
			unsupported = true
		case .Refused:
			refused = true
		case .Bad:
		}
	}
	// `Unsupported` first when both turned up: it is the stricter verdict, and a
	// key we cannot read at all says more than one the library declined to run.
	switch {
	case unsupported:
		return .Unsupported, wildcard
	case refused:
		return .Refused, wildcard
	}
	return .Bad, wildcard
}

/*
Prove that a wildcard was allowed to answer.

The zone has to show that the queried name has nothing of its own, which is the
same denial of existence a NODATA answer would carry, in the authority section
alongside the answer.
*/
@(private)
validate_wildcard_proof :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	qname: string,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	proved: []Authenticated_Set,
) {
	// Established from the queried name, for the same reason as the denial path.
	trust, keys, established := zone_trust(v, budget, qname, now, allocator)
	if trust != .Secure {
		return trust, nil
	}
	nsecs, nsec3s, verified, wildcard_spent := validated_denial_records(
		v,
		budget,
		msg.authority,
		established,
		class,
		keys,
		unix,
		now,
		allocator,
	)
	/*
	The same allowance, and the same answer. Falling through here reports a
	budget of ours as "wildcard expansion not proven", which reaches the client
	as a forged answer - the one thing every other exhaustion path in this file
	now takes care not to say.
	*/
	if wildcard_spent {
		return .Indeterminate, nil
	}
	if len(nsecs) > 0 {
		if _, covered := nsec_covering(nsecs, qname); covered {
			return .Secure, verified
		}
	}
	if len(nsec3s) > 0 {
		if _, _, ce_ok := nsec3_closest_encloser(nsec3s, qname, established, v.max_nsec3_iterations); ce_ok {
			return .Secure, verified
		}
	}
	return .Bogus, nil
}

/*
Verify the NSEC and NSEC3 records of an authority section and hand back the ones
that held up. An unverified denial record is worse than none, so a single
failure discards the lot.

`verified` names the RRsets whose signatures were checked here, for a caller
that has to decide which of them may go out under an AD bit. It is not the same
as the proof: a record can verify and prove nothing, and it is still a record
this server authenticated.
*/
@(private)
validated_denial_records :: proc(
	v: ^Validator,
	budget: ^Budget,
	authority: []dns.Record,
	zone: string,
	class: dns.Class,
	keys: []Dnskey,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	nsecs: []Nsec_Rr,
	nsec3s: []Nsec3_Rr,
	verified: []Authenticated_Set,
	// True when the query's verification allowance ran out partway through, so
	// that a caller can tell "nothing proved this" from "we stopped looking".
	exhausted: bool,
) {
	out_nsec := make([dynamic]Nsec_Rr, 0, 4, allocator)
	out_nsec3 := make([dynamic]Nsec3_Rr, 0, 4, allocator)
	out_verified := make([dynamic]Authenticated_Set, 0, 4, allocator)
	seen := make([dynamic]dns.Question, 0, 4, allocator)

	for rec in authority {
		if rec.type != .NSEC && rec.type != .NSEC3 {
			continue
		}
		if already_seen(seen[:], rec.name, rec.type) {
			continue
		}
		append(&seen, dns.Question{name = rec.name, type = rec.type})

		records, signer, carried, ok, spent := verified_rrset(
			budget,
			authority,
			rec.name,
			rec.type,
			class,
			zone,
			keys,
			unix,
			allocator,
		)
		if spent {
			// The allowance, not the records. Stop and say so rather than
			// carrying on to report an empty proof as a forged one.
			exhausted = true
			break
		}
		if !ok {
			// Dropped rather than fatal. A proof assembled only from records
			// that verified is sound whatever else came along, and refusing the
			// lot would let one junk record added to a response deny every name
			// the real records were about to prove.
			continue
		}
		append(
			&out_verified,
			Authenticated_Set {
				name = rec.name,
				type = rec.type,
				class = class,
				signer = signer,
				rrsig = carried,
			},
		)

		for r in records {
			rdata, is_raw := raw_rdata(r)
			if !is_raw {
				continue
			}
			if r.type == .NSEC {
				parsed, perr := parse_nsec(rdata, allocator)
				if perr != .None {
					continue
				}
				append(&out_nsec, Nsec_Rr{owner = r.name, rr = parsed})
			} else {
				parsed, perr := parse_nsec3(rdata)
				if perr != .None {
					continue
				}
				hash := make([]u8, 32, allocator)
				n, decoded := base32hex_decode(first_label(r.name), hash)
				if !decoded || n != len(parsed.next_hash) {
					continue
				}
				append(&out_nsec3, Nsec3_Rr{hash = hash[:n], rr = parsed})
			}
		}
	}
	return out_nsec[:], out_nsec3[:], out_verified[:], exhausted
}

/*
Check one RRset against keys that are already in hand.

The zone is named by the caller rather than taken from the signature, so this
answers "did this zone sign this" and not "did somebody sign this". Every use is
in an authority section that has already been placed in a zone, where a signer
of the response's own choosing is precisely what must not be believed.

The attempts are bounded the way `validate_rrset` bounds them, which is no
longer a per-RRset cap: both spend the query-wide
`MAX_VERIFICATIONS_PER_QUERY`, and both throw out for nothing - through
`signature_worth_trying` - every signature whose key tag and algorithm name no
key the zone published. Running the budget out here is reported back as
`exhausted`, not as a set that failed to verify, because the two are different
things to say about a zone.
*/
@(private)
verified_rrset :: proc(
	budget: ^Budget,
	section: []dns.Record,
	owner: string,
	type: dns.Type,
	class: dns.Class,
	zone: string,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	records: []dns.Record,
	signer: string,
	rrsig: Rrsig,
	ok: bool,
	// True when the query's verification allowance ran out before a signature
	// held, which is a statement about this server and not about the records.
	exhausted: bool,
) {
	records = records_of(section, owner, type, class, allocator)
	if len(records) == 0 {
		return nil, "", {}, false, false
	}
	for sig in sigs_covering(section, owner, type, class, allocator) {
		if !dns.name_equal_fold(sig.signer, zone) {
			continue
		}
		// Free rejects first, so the budget is spent on signatures that could
		// actually verify rather than on whatever was written in front of them.
		if !signature_worth_trying(sig, keys, unix) {
			continue
		}
		// Bounded across the question rather than per RRset; see
		// `MAX_VERIFICATIONS_PER_QUERY` for why the difference matters.
		if !spend_verification(budget) {
			/*
			Said out loud. Running out here drops the RRset, and a dropped SOA
			takes the denial's negative TTL with it silently - `cache.put` falls
			back to `cache.negative_ttl`, and with that at zero the answer is not
			cached at all, so the same question goes upstream every time with
			nothing anywhere saying why.
			*/
			logx.debugf(
				"dnssec: %s %s ran out of verifications before a signature held; the set is dropped",
				dns.type_name(type),
				dns.name_trim_root(owner),
			)
			return nil, "", {}, false, true
		}
		result, _ := check_signature(sig, owner, class, records, keys, unix, allocator)
		if result == .Ok {
			return records, sig.signer, sig, true, false
		}
	}
	return nil, "", {}, false, false
}

// ---------------------------------------------------------------------------
// Walking the chain
// ---------------------------------------------------------------------------

@(private)
Step :: enum u8 {
	// The child is a signed zone in its own right.
	Secure,
	// No delegation here, so the parent still covers everything below.
	No_Cut,
	Insecure,
	Bogus,
	Indeterminate,
}

/*
Establish the deepest signed zone at or above `name`.

Returns that zone's keys and its name. A `Secure` result means every step from a
trust anchor down to `established` was checked.
*/
@(private)
zone_trust :: proc(
	v: ^Validator,
	budget: ^Budget,
	name: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	keys: []Dnskey,
	established: string,
) {
	root_status, root_keys := zone_keys(v, budget, ".", now, allocator)
	if root_status != .Secure {
		return root_status, nil, "."
	}

	zone := "."
	keys = root_keys
	depth := label_count(name)
	if depth > MAX_CHAIN_DEPTH {
		return .Indeterminate, nil, "."
	}

	for i in 1 ..= depth {
		child := name_drop_labels(name, depth - i)
		step, child_keys := zone_step(v, budget, zone, keys, child, now, allocator)
		switch step {
		case .Secure:
			zone = child
			keys = child_keys
		case .No_Cut:
			return .Secure, keys, zone
		case .Insecure:
			return .Insecure, nil, child
		case .Bogus:
			return .Bogus, nil, child
		case .Indeterminate:
			return .Indeterminate, nil, child
		}
	}
	return .Secure, keys, zone
}

/*
Take one step down: is `child` a signed zone, an unsigned delegation, or not a
zone cut at all?
*/
@(private)
zone_step :: proc(
	v: ^Validator,
	budget: ^Budget,
	parent: string,
	parent_keys: []Dnskey,
	child: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	step: Step,
	keys: []Dnskey,
) {
	if cached, found := cache_get(v, child, now, allocator); found {
		switch cached.status {
		case .Secure:
			return .Secure, cached.keys
		case .Insecure:
			return .Insecure, nil
		case .Bogus, .Indeterminate:
			// Nothing stores these; treating them as a broken step rather than
			// as an absent delegation keeps the failure closed if that changes.
			return .Bogus, nil
		}
	}

	if !spend_lookup(budget) {
		return .Indeterminate, nil
	}
	wire, ok := v.query(v.query_ctx, child, .DS, allocator)
	if !ok {
		return .Indeterminate, nil
	}
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return .Bogus, nil
	}
	/*
	An error carries no records, so a DS lookup that returns one finds neither a
	delegation nor a denial of it - which is indistinguishable from a delegation
	whose proof was stripped, and is what the checks below would call it.

	The upstream failing to answer is a statement about the upstream, not about
	the zone, and reporting it as a forgery would have every hiccup below a
	signed parent come back as a DNSSEC failure. `validate` reaches the same
	conclusion for the same rcodes on the response being validated.
	*/
	if !answerable_rcode(msg) {
		return .Indeterminate, nil
	}
	unix := u32(time.to_unix_seconds(now))
	// We asked in class IN, and the transport already checked the reply's
	// question against ours; taking the class from the reply would only let it
	// choose which canonical form we build.
	class := dns.Class.IN

	ds_records := records_of(msg.answer, child, .DS, class, allocator)
	if len(ds_records) > 0 {
		sigs := sigs_covering(msg.answer, child, .DS, class, allocator)
		verified := false
		for sig in sigs {
			if !dns.name_equal_fold(sig.signer, parent) {
				continue
			}
			result, _ := check_signature(sig, child, class, ds_records, parent_keys, unix, allocator)
			if result == .Ok {
				verified = true
				break
			}
		}
		if !verified {
			return .Bogus, nil
		}

		set := make([dynamic]Ds, 0, len(ds_records), allocator)
		usable := false
		for r in ds_records {
			rdata, is_raw := raw_rdata(r)
			if !is_raw {
				continue
			}
			parsed, perr := parse_ds(rdata)
			if perr != .None {
				continue
			}
			append(&set, parsed)
			if algorithm_supported(parsed.algorithm) && digest_supported(parsed.digest_type) {
				usable = true
			}
		}
		if !usable {
			// Every DS names an algorithm or a digest we cannot check, which
			// RFC 6840 section 5.2 makes an insecure delegation rather than a
			// broken one.
			cache_put(v, child, .Insecure, nil, rrset_ttl(ds_records), now)
			return .Insecure, nil
		}

		child_keys, kstatus := fetch_keys(v, budget, child, set[:], unix, allocator)
		if kstatus != .Secure {
			if kstatus == .Insecure {
				cache_put(v, child, .Insecure, nil, rrset_ttl(ds_records), now)
				return .Insecure, nil
			}
			return .Bogus if kstatus == .Bogus else .Indeterminate, nil
		}
		cache_put(v, child, .Secure, child_keys, rrset_ttl(ds_records), now)
		return .Secure, child_keys
	}

	// No DS in the answer. The authority section has to say why, and say it in
	// a form the parent signed.
	// Nothing here reaches a client - this is our own DS lookup - so which
	// RRsets verified is of no interest beyond the proof they carry.
	nsecs, nsec3s, _, ds_spent := validated_denial_records(v, budget, msg.authority, parent, class, parent_keys, unix, now, allocator)
	// A chain step this server ran out of allowance on is one it did not read,
	// which is `Indeterminate` territory rather than a broken delegation.
	if ds_spent {
		return .Indeterminate, nil
	}
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		return .Bogus, nil
	}

	if len(nsecs) > 0 {
		if nsec_proves_no_ds(nsecs, child) == .Proven {
			cache_put(v, child, .Insecure, nil, negative_ttl(msg), now)
			return .Insecure, nil
		}
		if nsec_proves_no_delegation(nsecs, child) {
			return .No_Cut, nil
		}
	}
	if len(nsec3s) > 0 {
		if nsec3_proves_no_ds(nsec3s, child, parent, v.max_nsec3_iterations) == .Proven {
			cache_put(v, child, .Insecure, nil, negative_ttl(msg), now)
			return .Insecure, nil
		}
		if nsec3_proves_no_delegation(nsec3s, child, parent, v.max_nsec3_iterations) {
			return .No_Cut, nil
		}
	}
	return .Bogus, nil
}

/*
Fetch a zone's DNSKEY set and check it against the DS records the parent
published.

At least one key has to hash to a DS and then sign the whole set, which is what
binds the zone's own keys to its parent.
*/
@(private)
fetch_keys :: proc(
	v: ^Validator,
	budget: ^Budget,
	zone: string,
	ds_set: []Ds,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	keys: []Dnskey,
	status: Status,
) {
	if !spend_lookup(budget) {
		return nil, .Indeterminate
	}
	wire, ok := v.query(v.query_ctx, zone, .DNSKEY, allocator)
	if !ok {
		return nil, .Indeterminate
	}
	msg, derr := dns.decode_message(wire, allocator)
	if derr != .None {
		return nil, .Bogus
	}
	// As in `zone_step`: an upstream error leaves the zone's keys unknown, which
	// is not the same as the zone failing to produce them.
	if !answerable_rcode(msg) {
		return nil, .Indeterminate
	}
	class := dns.Class.IN

	records := records_of(msg.answer, zone, .DNSKEY, class, allocator)
	if len(records) == 0 || len(records) > MAX_KEYS_PER_ZONE {
		return nil, .Bogus
	}
	parsed := make([dynamic]Dnskey, 0, len(records), allocator)
	for r in records {
		rdata, is_raw := raw_rdata(r)
		if !is_raw {
			continue
		}
		key, perr := parse_dnskey(rdata)
		if perr != .None {
			continue
		}
		append(&parsed, key)
	}

	sigs := sigs_covering(msg.answer, zone, .DNSKEY, class, allocator)
	unsupported := false

	for ds in ds_set {
		if !algorithm_supported(ds.algorithm) || !digest_supported(ds.digest_type) {
			unsupported = true
			continue
		}
		for key in parsed {
			if key.tag != ds.key_tag || key.algorithm != ds.algorithm || !key_usable(key) {
				continue
			}
			if !ds_matches(zone, key, ds) {
				continue
			}
			// The key is vouched for by the parent; now it must vouch for the
			// rest of the set.
			for sig in sigs {
				if sig.key_tag != key.tag || sig.algorithm != key.algorithm {
					continue
				}
				if !dns.name_equal_fold(sig.signer, zone) {
					continue
				}
				/*
				This one key, and no other. A key tag is a 16-bit fold of the
				RDATA, not an identity: two keys can share one, and an attacker
				is free to make that happen. Offering the whole set here would
				let a key of their own satisfy the signature while the parent's
				DS went on attesting a key that had signed nothing - which is
				the entire chain of trust bypassed in one step.
				*/
				attested := [1]Dnskey{key}
				result, _ := check_signature(sig, zone, class, records, attested[:], unix, allocator)
				switch result {
				case .Ok:
					return parsed[:], .Secure
				case .Unsupported, .Refused:
					// Both mean the same thing here. This is the delegation, and
					// a delegation we cannot follow is insecure whether the
					// algorithm is one we never implemented or one the library
					// declined to run (RFC 6840 section 5.2).
					unsupported = true
				case .Bad:
				}
			}
		}
	}
	return nil, .Insecure if unsupported else .Bogus
}

// Does this DNSKEY hash to this DS? The digest runs over the owner name in
// canonical form followed by the whole DNSKEY RDATA (RFC 4034 section 5.1.4).
ds_matches :: proc(zone: string, key: Dnskey, ds: Ds) -> bool {
	size := digest_size(ds.digest_type)
	if size == 0 || len(ds.digest) != size {
		return false
	}
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, ok := canonical_name(zone, name_buf[:])
	if !ok {
		return false
	}

	input_buf: [dns.MAX_NAME_WIRE + 4096]u8
	if n + len(key.rdata) > len(input_buf) {
		return false
	}
	copy(input_buf[:], name_buf[:n])
	copy(input_buf[n:], key.rdata)

	computed: [64]u8
	if !digest(ds.digest_type, input_buf[:n + len(key.rdata)], computed[:]) {
		return false
	}
	return mem.compare(computed[:size], ds.digest) == 0
}

/*
The keys of a zone, from the cache or from the trust anchors.

Only the root takes the anchor path; every other zone reaches this through
`zone_step`, which has a parent to check against.
*/
@(private)
zone_keys :: proc(
	v: ^Validator,
	budget: ^Budget,
	zone: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	keys: []Dnskey,
) {
	if cached, found := cache_get(v, zone, now, allocator); found {
		return cached.status, cached.keys
	}

	anchors := make([dynamic]Ds, 0, len(v.anchors), allocator)
	for a in v.anchors {
		if dns.name_equal_fold(a.zone, zone) {
			append(&anchors, a.ds)
		}
	}
	if len(anchors) == 0 {
		return .Indeterminate, nil
	}

	unix := u32(time.to_unix_seconds(now))
	fetched, fstatus := fetch_keys(v, budget, zone, anchors[:], unix, allocator)
	if fstatus != .Secure {
		return fstatus, nil
	}
	cache_put(v, zone, .Secure, fetched, MAX_ZONE_TTL, now)
	return .Secure, fetched
}

// ---------------------------------------------------------------------------
// The zone cache
// ---------------------------------------------------------------------------

@(private)
cache_get :: proc(
	v: ^Validator,
	zone: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	entry: Zone_Entry,
	found: bool,
) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := fold_into(zone, fold_buf[:])
	if !key_ok {
		return {}, false
	}

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	cached, in_map := v.zones[key]
	if !in_map {
		return {}, false
	}
	if time.diff(cached.expires, now) > 0 {
		return {}, false
	}
	/*
	The RDATA is copied, not referenced. A `Dnskey` is a handful of slices into
	memory this cache owns, and another thread may evict the entry the moment
	the lock is released; handing out the struct alone would leave the caller
	reading a freed key for the rest of its query. The caller works in a
	per-request arena, so the copy costs a couple of kilobytes and is dropped
	with everything else.
	*/
	out := Zone_Entry {
		status  = cached.status,
		expires = cached.expires,
	}
	if len(cached.keys) > 0 {
		copies := make([dynamic]Dnskey, 0, len(cached.keys), allocator)
		for key in cached.keys {
			rdata := make([]u8, len(key.rdata), allocator)
			copy(rdata, key.rdata)
			parsed, perr := parse_dnskey(rdata)
			if perr != .None {
				continue
			}
			append(&copies, parsed)
		}
		out.keys = copies[:]
	}
	return out, true
}

// `now` is the same clock the lookups use rather than the wall clock, so an
// entry cannot be written with an expiry the reader considers already past.
@(private)
cache_put :: proc(v: ^Validator, zone: string, status: Status, keys: []Dnskey, ttl: u32, now: time.Time) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := fold_into(zone, fold_buf[:])
	if !key_ok {
		return
	}
	lifetime := clamp(ttl, MIN_ZONE_TTL, MAX_ZONE_TTL)

	entry := new(Zone_Entry, v.allocator)
	entry.status = status
	entry.expires = time.time_add(now, time.Duration(lifetime) * time.Second)
	if len(keys) > 0 {
		// Appended rather than written by index: skipping a key that will not
		// parse must shorten the set, not leave a zero-valued one sitting in it.
		// A gap carries algorithm 0, which no signature matches, and an RRset
		// with nothing to check it against is reported unsupported - which
		// `validate_rrset` reads as insecure. A cache holding entries that
		// quietly mean "treat this zone as unsigned" fails the wrong way.
		owned := make([dynamic]Dnskey, 0, len(keys), v.allocator)
		for k in keys {
			rdata := make([]u8, len(k.rdata), v.allocator)
			copy(rdata, k.rdata)
			parsed, perr := parse_dnskey(rdata)
			if perr != .None {
				delete(rdata, v.allocator)
				continue
			}
			append(&owned, parsed)
		}
		entry.keys = owned[:]
	}

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	if old, exists := v.zones[key]; exists {
		// Reuse the string the map is already keyed by. Re-inserting under the
		// caller's stack-backed `key` would leave the map holding a pointer
		// into a frame that is about to go away.
		entry.zone = old.zone
		old.zone = ""
		free_entry(v, old)
		v.zones[entry.zone] = entry
		return
	}
	if len(v.zones) >= v.max_cached_zones {
		// A flush is crude, but this cache holds zones rather than answers: it
		// fills slowly, and refilling it costs a handful of queries.
		for _, e in v.zones {
			free_entry(v, e)
		}
		clear(&v.zones)
	}
	entry.zone = strings.clone(key, v.allocator)
	v.zones[entry.zone] = entry
}

// Drop entries whose lifetime has run out. A zero `now` reads the wall clock;
// tests pass the same fixed clock the walk itself was made to trust, so an
// entry timed against fixture signatures is not judged against real time.
sweep :: proc(v: ^Validator, now: time.Time = {}) -> (removed: int) {
	if v == nil {
		return 0
	}
	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	clock := now if now != {} else time.now()
	// Collected first: deleting from a map while walking it is not something to
	// rely on.
	expired := make([dynamic]^Zone_Entry, 0, 16, context.temp_allocator)
	for _, entry in v.zones {
		if time.diff(entry.expires, clock) > 0 {
			append(&expired, entry)
		}
	}
	for entry in expired {
		delete_key(&v.zones, entry.zone)
		free_entry(v, entry)
		removed += 1
	}
	return
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

@(private)
fold_into :: proc(name: string, buf: []u8) -> (string, bool) {
	if len(name) > len(buf) {
		return "", false
	}
	for i in 0 ..< len(name) {
		c := name[i]
		buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}
	return string(buf[:len(name)]), true
}

/*
Is this CNAME one that a DNAME in the same answer produced?

A DNAME redirects everything below its owner, and the server sends the CNAME it
worked out along with it, unsigned (RFC 6672 section 3.4.1). The signature is on
the DNAME, so that is what gets checked; the CNAME is accepted only once the
substitution has been recomputed and found to match.

Recomputing it is the entire safeguard. Accepting any unsigned CNAME that
happened to sit below a validated DNAME would hand out a redirect to anywhere,
for every name under every DNAME there is - a good deal worse than refusing
them, which is what this replaces.
*/
@(private)
dname_covered :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	cname: dns.Record,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> bool {
	target, is_name := cname.data.(dns.Rdata_Name)
	if !is_name {
		return false
	}

	seen := make([dynamic]dns.Question, 0, 2, allocator)
	for rec in msg.answer {
		if rec.type != .DNAME || rec.class != class {
			continue
		}
		if already_seen(seen[:], rec.name, rec.type) {
			continue
		}
		append(&seen, dns.Question{name = rec.name, type = rec.type})

		dname, dname_is_name := rec.data.(dns.Rdata_Name)
		if !dname_is_name {
			continue
		}
		if !dname_synthesizes(rec.name, dname.name, cname.name, target.name, allocator) {
			continue
		}
		// Only now is it worth checking the DNAME itself, which costs a walk.
		records := records_of(msg.answer, rec.name, .DNAME, class, allocator)
		sigs := sigs_covering(msg.answer, rec.name, .DNAME, class, allocator)
		status, _, _, _, _ := validate_rrset(v, budget, rec.name, .DNAME, class, records, sigs, unix, now, allocator)
		if status == .Secure {
			return true
		}
	}
	return false
}

/*
Would a DNAME at `owner` pointing to `target` produce exactly this CNAME?

The substitution swaps the DNAME's owner, which is a suffix of the redirected
name, for the DNAME's target, and carries the labels in front of it over
untouched (RFC 6672 section 3.4.1).
*/
@(private)
dname_synthesizes :: proc(owner, target, cname_owner, cname_target: string, allocator: mem.Allocator) -> bool {
	// A DNAME redirects what is below it, never its own name.
	if dns.name_equal_fold(cname_owner, owner) || !name_in_zone(cname_owner, owner) {
		return false
	}
	prefix_labels := label_count(cname_owner) - label_count(owner)
	if prefix_labels <= 0 {
		return false
	}
	cut, ok := label_offset(cname_owner, prefix_labels)
	if !ok {
		return false
	}
	// The same prefix, over the target this time.
	want := strings.concatenate({cname_owner[:cut], target}, allocator)
	return dns.name_equal_fold(cname_target, want)
}

// Byte offset just past the `count`th label separator, so `name[:offset]` is
// the first `count` labels with their trailing dot. Escapes are stepped over
// whole, since the character after a backslash is never a separator.
@(private)
label_offset :: proc(name: string, count: int) -> (offset: int, ok: bool) {
	seen := 0
	i := 0
	for i < len(name) {
		if name[i] == '\\' {
			i += 2
			continue
		}
		if name[i] == '.' {
			seen += 1
			if seen == count {
				return i + 1, true
			}
		}
		i += 1
	}
	return 0, false
}

/*
Does this response carry anything to reason about?

Only NOERROR and NXDOMAIN do. Under every other rcode the responder is saying it
did not answer, and its empty sections are not an absence anybody proved.
*/
@(private)
answerable_rcode :: proc(msg: dns.Message) -> bool {
	#partial switch dns.rcode_of(msg) {
	case .No_Error, .NX_Domain:
		return true
	}
	return false
}

/*
Does this answer section address `qname`?

Walks the CNAME chain from the name that was asked about. Reaching the type
asked for settles it; so does running out of records after at least one hop,
because a chain that stops before its target is a perfectly ordinary answer -
the zone at the end may simply hold nothing of that type, and what proves that
is the denial in the authority section, not anything here.

What this refuses is an answer section with nothing at the queried name at all,
which is not an answer to this question whatever else it is.

Only the shape is checked. Every record here has already been through
`validate_rrset`, so reaching a name by following this chain means the records
that led there carried signatures from the zones that own them.
*/
@(private)
answers_question :: proc(records: []dns.Record, qname: string, qtype: dns.Type, class: dns.Class) -> bool {
	return chain_shape(records, qname, qtype, class) != .None
}

@(private)
already_seen :: proc(seen: []dns.Question, name: string, type: dns.Type) -> bool {
	for q in seen {
		if q.type == type && dns.name_equal_fold(q.name, name) {
			return true
		}
	}
	return false
}

@(private)
records_of :: proc(
	recs: []dns.Record,
	name: string,
	type: dns.Type,
	class: dns.Class,
	allocator: mem.Allocator,
) -> []dns.Record {
	out := make([dynamic]dns.Record, 0, 4, allocator)
	for r in recs {
		if r.type == type && r.class == class && dns.name_equal_fold(r.name, name) {
			append(&out, r)
		}
	}
	return out[:]
}

@(private)
sigs_covering :: proc(
	recs: []dns.Record,
	name: string,
	type: dns.Type,
	class: dns.Class,
	allocator: mem.Allocator,
) -> []Rrsig {
	out := make([dynamic]Rrsig, 0, 2, allocator)
	for r in recs {
		if r.type != .RRSIG || r.class != class || !dns.name_equal_fold(r.name, name) {
			continue
		}
		rdata, is_raw := raw_rdata(r)
		if !is_raw {
			continue
		}
		sig, err := parse_rrsig(rdata, allocator)
		if err != .None || sig.type_covered != type {
			continue
		}
		append(&out, sig)
	}
	return out[:]
}

@(private)
rrset_ttl :: proc(records: []dns.Record) -> u32 {
	ttl := max(u32)
	for r in records {
		ttl = min(ttl, r.ttl)
	}
	return ttl if len(records) > 0 else 0
}

@(private)
negative_ttl :: proc(msg: dns.Message) -> u32 {
	return dns.negative_ttl(msg, MIN_ZONE_TTL)
}

@(private)
worse :: proc(a, b: Status) -> Status {
	rank :: proc(s: Status) -> int {
		switch s {
		case .Secure:
			return 0
		case .Insecure:
			return 1
		case .Indeterminate:
			return 2
		case .Bogus:
			return 3
		}
		return 3
	}
	return a if rank(a) >= rank(b) else b
}
