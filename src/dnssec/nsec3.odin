package dnssec

import "core:mem"
import "elodin:dns"

/*
NSEC3, RFC 5155.

Same job as NSEC, done over hashed names so that walking the chain does not hand
out the zone's contents. That costs the validator the ability to read a name off
the record: every question has to be turned into a hash first, with the salt and
iteration count the record itself carries, and answered by comparing hashes.
*/

/*
The iterated hash of RFC 5155 section 5.

`out` takes the 20 bytes of a SHA-1 digest. The first round hashes the canonical
wire name with the salt appended; each further round rehashes the digest with
the salt appended again.
*/
nsec3_hash :: proc(name: string, salt: []u8, iterations: u16, out: []u8) -> bool {
	if len(out) < 20 || len(salt) > 255 {
		return false
	}
	wire: [dns.MAX_NAME_WIRE]u8
	n, ok := canonical_name(name, wire[:])
	if !ok {
		return false
	}

	buf: [dns.MAX_NAME_WIRE + 256]u8
	copy(buf[:], wire[:n])
	copy(buf[n:], salt)

	hash: [20]u8
	if !digest(DIGEST_SHA1, buf[:n + len(salt)], hash[:]) {
		return false
	}
	for _ in 0 ..< int(iterations) {
		copy(buf[:], hash[:])
		copy(buf[20:], salt)
		if !digest(DIGEST_SHA1, buf[:20 + len(salt)], hash[:]) {
			return false
		}
	}
	copy(out, hash[:])
	return true
}

/*
SHA-1 rounds one client question may spend proving denials with NSEC3.

The per-record iteration ceiling is not a bound on the work, because the number
of records is the sender's too. A denial carrying 64 NSEC3 records, each with
the ceiling's iterations and a 255-byte salt, is hashed against every ancestor
of a 24-label question: around 150,000 rounds, 55 ms of SHA-1, for one query
that passes every other allowance this file keeps. Unbound answers the same
shape by capping hash calculations per pass (`MAX_NSEC3_CALCULATIONS`, the
CVE-2023-50868 fix) and this is that cap, counted across the question rather
than per pass.

A whole allowance measures at 2.1 ms of SHA-1 at worst on this box, optimised,
against the 55 ms above. At worst because the charge is by block rather than by
round: a 255-byte salt costs five blocks a round where a short one costs a
single block, so the longest salt now buys the least - half a millisecond for a
whole allowance - where counting rounds flat would have sold it five times the
most. Either way it puts NSEC3 hashing in the same order as the signature
verifications `MAX_VERIFICATIONS_PER_QUERY` already allows.

Real traffic is nowhere near it. A zone following RFC 9276 uses zero iterations,
so a hash is one round and a whole question tens - the zones still publishing
NSEC3 at the time of writing use zero, five and ten. What the number has to
leave room for is the other end of what is still legal, and the counts are
measured rather than guessed at: with the reuse `Nsec3_Hashes` does, a chain
step costs one hash where the zone holds the name and three where it does not,
and a name error four hashes, or five for a name two labels below its closest
encloser. A name eight labels deep in a zone sitting at the default ceiling of
100 therefore comes to something like 3000 rounds, and at the configurable
ceiling of `MAX_NSEC3_ITERATIONS_LIMIT` to something like 7500 - inside the
allowance, and not by much, which is the point of that limit.

Those numbers are for a salt of the length zones actually publish, up to the
thirty-five bytes that still fit one compression block beside the digest. A
longer one doubles them, and a zone publishing a 40-byte salt at the default
ceiling can put a deep enough name past the allowance. Nothing in use is
anywhere near that pair of choices - the salt exists to stop precomputation
across zones, which a few bytes does - and what such a name gets is
`Indeterminate`, which is this server saying it did not finish rather than that
the zone is wrong. A question that
wants more is answered `Indeterminate`, never `Bogus`: this is an allowance of
ours running out, not a proof found wanting.
*/
MAX_NSEC3_ROUNDS_PER_QUERY :: 8192

/*
The largest iteration ceiling worth configuring.

The ceiling refuses a record and `MAX_NSEC3_ROUNDS_PER_QUERY` refuses a
question, and high enough the second makes the first meaningless rather than
laxer: every record costs more than a whole question may spend, so every NSEC3
denial in every zone is `Indeterminate` and every name in one is SERVFAIL. A
setting that reads as "accept more" and acts as "accept nothing" is worth
catching, so `make_validator` holds a larger number down to this and says so in
the log rather than leaving it to be discovered as a resolver that came up fine
and answers nothing. Held down rather than refused at load: a configuration
carrying a larger number was legal before this bound existed, and a resolver
that does not come back from an upgrade is worse than either.

What it promises is a floor, not a guarantee, and the difference is worth being
plain about. At this ceiling a record with a salt of ordinary length costs 256
blocks a hash, so a whole allowance affords thirty-two of them: a name error
spends four or five of those and the walk down to it one a step, so a name of
ordinary depth fits and a very deep one does not. With the longest salt the same
allowance affords six hashes, which is one proof and nothing around it. No
single number could do better while the depth is the question's to choose: the
allowance is the bound, and this only keeps the ceiling in the range where the
bound can be met at all.

It leaves nothing anyone wants out of reach. RFC 9276 asks zones for zero, the
default here is 100, and the zones still publishing NSEC3 use single digits.
*/
MAX_NSEC3_ITERATIONS_LIMIT :: MAX_NSEC3_ROUNDS_PER_QUERY / 32 - 1

/*
What one question is allowed to spend on NSEC3 hashing, and the ceiling it
holds each record's iteration count to.

Carried as part of `Budget`, for the reason written there: the limit is per
client question, so two arriving at once each get their own. `max_iterations` is
the validator's, and `query_budget` is what puts it here - a zero is read as
zero, so an allowance built without one refuses every record asking for any
iterations at all. That is the direction to fail in: loudly, and having done no
work, rather than quietly at a ceiling nobody configured.
*/
Nsec3_Budget :: struct {
	max_iterations: int,
	rounds:         int,
	/*
	Hashes this server declined to compute, counted apart by reason: the
	allowance being gone, and a record asking for more iterations than the
	ceiling. Counts rather than flags, because what a caller needs to know is
	whether *its own* reading was cut short and by which refusal - and a flag,
	once set, belongs to every proof after it as much as to the one that set
	it. `nsec3_refusals` and `nsec3_declined` are how that question is asked.
	*/
	spent:          int,
	over_ceiling:   int,
	// The hashes kept from this question's scans, for whatever asks next: see
	// `Nsec3_Hashes`.
	hashed:         Nsec3_Hashes,
}

/*
The refusals a budget has counted so far, to be held against the same reading
taken afterwards.

A proof that failed and a proof this server would not finish look identical from
the verdict, and the difference decides whether a client is told its answer was
forged. The counts settle it, and they have to be read around the proof in
question rather than off the budget: an allowance is spent once for the whole
question, so every proof after the one that spent it would otherwise be filed
under a refusal that was never its own.
*/
@(private)
Nsec3_Refusals :: struct {
	spent:        int,
	over_ceiling: int,
}

@(private)
nsec3_refusals :: proc(budget: ^Nsec3_Budget) -> Nsec3_Refusals {
	return {spent = budget.spent, over_ceiling = budget.over_ceiling}
}

/*
Could this reading have been different with a whole allowance?

Only the allowance answers yes, and the difference between the two refusals is
the difference between a policy and a moment. A record above the ceiling is
unusable to this server for every question it will ever be asked, so skipping it
is the answer rather than a gap in one - the records around it still speak, and
the verdict they give is the verdict a fresh allowance would give too. A record
the allowance refused is one this server would have read a moment earlier, so a
negative reading over it is provisional, and anything built on that negative is
built on a gap.

So this is what a *positive* conclusion drawn from a negative reading has to
consult - the opt-out fallback, the step that ends a walk - and
`nsec3_declined` below is for the other question, which is only ever asked of a
proof that has already failed.
*/
@(private)
nsec3_cut_short :: proc(budget: ^Nsec3_Budget, before: Nsec3_Refusals) -> bool {
	return budget.spent > before.spent
}

/*
The two reasons, named once.

`server` reads the second of them to pick the extended error the client is
handed - RFC 8914 has a code for exactly this refusal - so these are shared
symbols rather than strings written twice, and changing the words here cannot
quietly change what a client is told.
*/
NSEC3_BUDGET_SPENT :: "nsec3 hashing budget spent"
NSEC3_OVER_CEILING :: "nsec3 iterations above the ceiling"

/*
Was anything refused since `before`, and which refusal was it?

For naming a failure, never for deciding one: a proof that failed is a proof
that failed, and this says whether to report it as the records' doing or as
ours. The allowance is named first because a question that ran out of it will
meet the ceiling too, and the number an operator has to look at is the one that
stopped the proof.
*/
@(private)
nsec3_declined :: proc(budget: ^Nsec3_Budget, before: Nsec3_Refusals) -> (declined: bool, reason: string) {
	if budget.spent > before.spent {
		return true, NSEC3_BUDGET_SPENT
	}
	if budget.over_ceiling > before.over_ceiling {
		return true, NSEC3_OVER_CEILING
	}
	return false, ""
}

/*
Is every record here one the ceiling refuses?

Then the denial is insecure to this server, which is what RFC 5155 section 10.3
asks, what RFC 9276 section 3.2 allows, and what Unbound, BIND and Knot do: it
is not read, so it cannot be proven, and serving it without the AD bit is the
answer it gets everywhere else. Issue #331. The chain walk reads the same
thing differently - as a step that keeps the parent's keys, never as an
unsigned child - and `Budget.walk_past_ceiling` says why.

Every record rather than any. A readable record beside refused ones is a chain
this server can check - a zone mid-rollover - and the readable chain decides an
honest answer. It is not a defence against a sender: one holding a signed
record of an old, expensive chain drops the readable records and sends the old
one alone, which is every record. So a zone that left a chain past the ceiling
is exposed as below until those old signatures expire, not only a zone still
publishing one.

A budget built without the ceiling (`max_iterations` of zero, which
`make_validator` never hands out) refuses every record asking for any
iterations. `query_budget` counts on that failing closed, so such a budget is
never read as all over the ceiling.

What it leaves open is the price of the verdict, and it is not small. Nothing
in a set past the ceiling is hashed, so nothing checks which names its records
cover: any on-path sender holding any record of the zone's chain - current, or
an old one replayed while its signatures last - can have any name in the zone
served as absent, with a negative TTL off an SOA nobody verified. And not only
in that zone: the walk reads the same records to find the cuts below it, so a
cold cache can be walked past a signed child's DS and the child's names made to
look absent too. What it never does is serve a forged record: signed data still
verifies, an unsigned answer under such a step is refused, and a wildcard is
not served on such a proof. That is less than Unbound concedes for the same
zone, where the child is read as unsigned and anything in it can be forged -
and it is what RFC 5155 section 10.3 asks of a zone that chose an iteration
count nobody should.

An NSEC record is readable too, so a denial carrying one is never this. A
record naming a hash other than SHA-1 is neither: `nsec3_hash_with` ignores it
before the ceiling is asked, so it cannot make a set refused.
*/
@(private)
nsec3_all_over_ceiling :: proc(nsecs: []Nsec_Rr, n3s: []Nsec3_Rr, budget: ^Nsec3_Budget) -> bool {
	if len(nsecs) > 0 || budget.max_iterations <= 0 {
		return false
	}
	refused := false
	for n in n3s {
		if n.rr.hash_algorithm != NSEC3_HASH_SHA1 {
			continue
		}
		if int(n.rr.iterations) <= budget.max_iterations {
			return false
		}
		refused = true
	}
	return refused
}

// SHA-1 compresses 64-byte blocks and appends a one-byte pad and an eight-byte
// length, so an input of `n` bytes is this many of them.
@(private)
sha1_blocks :: proc(n: int) -> int {
	return (n + 9 + 63) / 64
}

/*
Charge one hash to the question's allowance.

The unit is one SHA-1 compression block, which is what a round of the shortest
kind costs: everything here is a number of those. Counting rounds flat instead
would sell the two things that make a round expensive at the price of a cheap
one - a 255-byte salt is four more blocks on every round of the iteration loop,
and the first round hashes the wire name rather than a 20-byte digest, which is
up to nine blocks of its own. Both are the sender's to choose, so both are
charged for.

Refusing counts itself rather than only returning false, because the callers
that matter are several proofs up and the difference they have to report is
between a proof that failed and a proof this server stopped reading.
*/
@(private)
spend_nsec3_rounds :: proc(budget: ^Nsec3_Budget, rr: Nsec3, name: string) -> bool {
	// The wire name is the presentation name's length plus the root label, or
	// shorter where an escape stood for one byte - so this is an upper bound
	// and never an undercharge.
	cost := sha1_blocks(len(name) + 1 + len(rr.salt)) + int(rr.iterations) * sha1_blocks(20 + len(rr.salt))
	if budget.rounds + cost > MAX_NSEC3_ROUNDS_PER_QUERY {
		budget.spent += 1
		return false
	}
	budget.rounds += cost
	return true
}

/*
Hash `name` with one record's parameters.

Refusing an iteration count above the budget's ceiling is a denial-of-service
guard: the work is the validator's, the number is the zone's, and RFC 9276 asks
for zero anyway. The ceiling bounds one record; `MAX_NSEC3_ROUNDS_PER_QUERY`
bounds the question.

Both refusals are counted, and counted together, because what the callers have
to say about them is the same: a proof built on a hash this server declined to
compute failed for a reason of ours, and reporting it as `Bogus` would tell the
client its answer was forged over a number the zone chose. They report
`Indeterminate` and name which refusal it was, which is what reaches the client
as an extended error and an operator as the reason beside the query - unless
every record was over the ceiling, which `nsec3_all_over_ceiling` makes
`Insecure`.
*/
@(private)
nsec3_hash_with :: proc(rr: Nsec3, name: string, out: []u8, budget: ^Nsec3_Budget) -> bool {
	if rr.hash_algorithm != NSEC3_HASH_SHA1 {
		return false
	}
	if int(rr.iterations) > budget.max_iterations {
		budget.over_ceiling += 1
		return false
	}
	if !spend_nsec3_rounds(budget, rr, name) {
		return false
	}
	return nsec3_hash(name, rr.salt, rr.iterations, out)
}

/*
The hashes kept from one question's scans, and what each was computed from.

Two things ask for the same hash over and over. Every record a zone publishes
carries the parameters of its single NSEC3PARAM, so a scan over a denial's
records asks for one name's hash once per record. And the proofs ask each
other: `nsec3_proves_no_ds` scans for a match on the name, hands the same name
to `nsec3_closest_encloser`, whose first step is that same scan, and then asks
for a cover over it - three passes, one hash. Keeping them is what makes an
honest proof cheap enough for the allowance to be tight, so they are kept on the
budget and live as long as the question does rather than as long as a scan.

Two of them, not one, because a zone changing its NSEC3 salt publishes both
chains at once (RFC 5155 section 7.3) and a denial then carries records under
two parameter sets. They interleave, because the records are in hash order and
two chains' hashes fall through each other, so one entry would be missed by
every record in turn - a hash apiece, which is the cost this reuse exists to
avoid and which a zone at the iteration ceiling cannot pay. Two entries turn
that back into two hashes a scan. A third parameter set in one response is not a
rollover, and what it meets is the allowance.

Round robin rather than anything cleverer: the asking is runs, so the entry to
give up is the one that has been sat on longest.
*/
@(private)
Nsec3_Hash :: struct {
	name:       string,
	algorithm:  u8,
	salt:       []u8,
	iterations: u16,
	hash:       [20]u8,
	have:       bool,
}

@(private)
Nsec3_Hashes :: struct {
	kept: [2]Nsec3_Hash,
	next: int,
}

/*
A kept hash belongs to the name and to all three of the parameters that produced
it, and the algorithm is in the key for the same reason as the rest. Only SHA-1
is ever computed, so a record naming another hash has to miss here and be
refused by `nsec3_hash_with` - reusing a neighbour's digest for it would read a
record this package cannot check as one it had.
*/
@(private)
nsec3_hash_of :: proc(name: string, rr: Nsec3, budget: ^Nsec3_Budget) -> (hash: []u8, ok: bool) {
	for &kept in budget.hashed.kept {
		if kept.have &&
		   kept.name == name &&
		   kept.algorithm == rr.hash_algorithm &&
		   kept.iterations == rr.iterations &&
		   len(kept.salt) == len(rr.salt) &&
		   mem.compare(kept.salt, rr.salt) == 0 {
			return kept.hash[:], true
		}
	}

	c := &budget.hashed.kept[budget.hashed.next]
	if !nsec3_hash_with(rr, name, c.hash[:], budget) {
		// Both entries still hold the hash of their own name and parameters, so
		// a record this one could not be computed for leaves them alone.
		return nil, false
	}
	c.name, c.algorithm, c.salt, c.iterations, c.have = name, rr.hash_algorithm, rr.salt, rr.iterations, true
	budget.hashed.next = (budget.hashed.next + 1) % len(budget.hashed.kept)
	return c.hash[:], true
}

@(private)
nsec3_matching :: proc(n3s: []Nsec3_Rr, name: string, budget: ^Nsec3_Budget) -> (rr: Nsec3_Rr, found: bool) {
	for n in n3s {
		h, ok := nsec3_hash_of(name, n.rr, budget)
		if !ok {
			// Not `break`, even once the allowance is gone: a record whose
			// hash is one of the kept ones still answers for free, and giving
			// up at the first refusal would let the order the records arrive
			// in decide the verdict.
			continue
		}
		if mem.compare(n.hash, h) == 0 {
			return n, true
		}
	}
	return {}, false
}

/*
Does a record's span contain the hash of `name`, without matching it?

The chain is circular, so the record whose next hash does not sort after its own
is the one holding the wrap-around span.
*/
@(private)
nsec3_covering :: proc(n3s: []Nsec3_Rr, name: string, budget: ^Nsec3_Budget) -> (rr: Nsec3_Rr, found: bool) {
	for n in n3s {
		h, ok := nsec3_hash_of(name, n.rr, budget)
		if !ok {
			// Not `break`, even once the allowance is gone: a record whose
			// hash is one of the kept ones still answers for free, and giving
			// up at the first refusal would let the order the records arrive
			// in decide the verdict.
			continue
		}
		// Both ends of the span must be the width of the hash we computed, or
		// the byte comparisons below are comparing different things.
		if len(n.hash) != len(h) || len(n.rr.next_hash) != len(h) {
			continue
		}
		covered: bool
		if mem.compare(n.hash, n.rr.next_hash) < 0 {
			covered = mem.compare(n.hash, h) < 0 && mem.compare(h, n.rr.next_hash) < 0
		} else {
			covered = mem.compare(n.hash, h) < 0 || mem.compare(h, n.rr.next_hash) < 0
		}
		if covered {
			return n, true
		}
	}
	return {}, false
}

/*
Find the deepest ancestor of `qname` the zone is shown to hold.

Returns that name along with the "next closer" name, one label longer, whose
absence the caller then has to see covered. A match on `qname` itself means the
name exists, which contradicts whatever the caller was trying to prove.

The match has to be in band, the apex included: the walk stops at the deepest
ancestor some NSEC3 in the response matches, and reaching the apex without one
at all is a failure, as RFC 5155 sections 8.4 through 8.9 ask for. A wildcard
answer is the one shape that genuinely does arrive without an apex match, and it
does not come through here: its closest encloser is named by the signature that
expanded it, so `validate_wildcard_proof` reads it from there rather than
searching for it.
*/
@(private)
nsec3_closest_encloser :: proc(
	n3s: []Nsec3_Rr,
	qname, zone: string,
	budget: ^Nsec3_Budget,
) -> (
	encloser, next_closer: string,
	// The record that matched the encloser. Handed back rather than left to be
	// hashed for a second time: `nsec3_proves_name_error` has to read its bit
	// map, and the other callers must not - an opt-out proof rests on a
	// delegation record being the encloser, which is the whole mechanism.
	match: Nsec3_Rr,
	ok: bool,
) {
	if !name_in_zone(qname, zone) {
		return "", "", {}, false
	}
	name := qname
	previous := ""
	for {
		if found_match, found := nsec3_matching(n3s, name, budget); found {
			if previous == "" {
				return "", "", {}, false
			}
			return name, previous, found_match, true
		}
		if dns.name_equal_fold(name, zone) {
			return "", "", {}, false
		}
		previous = name
		name = dns.name_parent(name)
	}
}

// RFC 5155 section 8.4.
nsec3_proves_name_error :: proc(
	n3s: []Nsec3_Rr,
	qname, zone: string,
	budget: ^Nsec3_Budget,
	allocator := context.temp_allocator,
) -> Proof {
	encloser, next_closer, match, ok := nsec3_closest_encloser(n3s, qname, zone, budget)
	if !ok {
		return .Failed
	}
	/*
	The encloser has to be a name whose zone answers for what is under it.

	NS set with SOA clear is the parent's own record at a delegation, and the
	parent does not answer for names inside the child - so it encloses none of
	them, and a proof built on it would deny every name in the child against
	the parent's keys. The same statement `nsec_speaks_for` makes on the NSEC
	side.

	Here rather than in `nsec3_closest_encloser`, and that distinction is the
	whole of it: an opt-out proof reaches the same routine and *must* take a
	delegation as the encloser, because declining to speak for what is under an
	unsigned delegation is exactly what opt-out is. This is the one caller that
	claims a name is absent.
	*/
	if bitmap_has(match.rr.types, .NS) && !bitmap_has(match.rr.types, .SOA) {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, budget)
	if !covered {
		return .Failed
	}
	wildcard_cover, wildcard_covered := nsec3_covering(n3s, wildcard_of(encloser, allocator), budget)
	if !wildcard_covered {
		return .Failed
	}
	// An opt-out span may be hiding an unsigned delegation, so the name is not
	// proven absent - only proven unsigned.
	if cover.rr.flags & NSEC3_FLAG_OPT_OUT != 0 || wildcard_cover.rr.flags & NSEC3_FLAG_OPT_OUT != 0 {
		return .Opt_Out
	}
	return .Proven
}

// RFC 5155 sections 8.5 and 8.6.
nsec3_proves_no_data :: proc(
	n3s: []Nsec3_Rr,
	qname, zone: string,
	qtype: dns.Type,
	budget: ^Nsec3_Budget,
	allocator := context.temp_allocator,
) -> Proof {
	if match, found := nsec3_matching(n3s, qname, budget); found {
		if bitmap_has(match.rr.types, qtype) || bitmap_has(match.rr.types, .CNAME) {
			return .Failed
		}
		if qtype != .DS && bitmap_has(match.rr.types, .NS) && !bitmap_has(match.rr.types, .SOA) {
			return .Failed
		}
		// SOA set is the child's own apex, which holds no DS and never did -
		// see `denial_is_the_childs_own_apex`.
		if denial_is_the_childs_own_apex(match.rr.types, qname, qtype) {
			return .Failed
		}
		return .Proven
	}

	// No record on the name itself: a wildcard must be what answered, and it
	// must be missing the type too.
	encloser, next_closer, _, ok := nsec3_closest_encloser(n3s, qname, zone, budget)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, budget)
	if !covered {
		return .Failed
	}
	before := nsec3_refusals(budget)
	wildcard, wildcard_found := nsec3_matching(n3s, wildcard_of(encloser, allocator), budget)
	if !wildcard_found {
		/*
		The one place in this file where a scan finding nothing decides
		something, and so the one place the allowance has to be read before the
		result is. A scan this server stopped partway through says nothing about
		what it did not reach, and reading it as "the zone publishes no wildcard
		here" turns an unfinished proof into an insecure answer - the verdict
		that serves the records rather than refusing them. Every other negative
		below and above returns `Failed`, which the callers turn into
		`Indeterminate` once they see what it cost, and this joins them.

		The allowance, and counted against this scan rather than read off the
		budget: a wildcard that was really looked for and really is not there is
		a finding whatever some earlier proof spent. A record the ceiling
		refused is not the same thing - it is unusable to this server for good,
		the records around it still speak, and reading them is what this server
		does with such a zone rather than an answer it stopped short of.

		That rests on something the zone owes: RFC 5155 section 7.3 has a zone
		changing its parameters publish both chains complete, so a name the
		readable chain does not hold is a name the other one does not hold
		either. A zone that breaks that - two chains disagreeing about which
		names exist, the deciding record present only in the one past the
		ceiling - gets its NODATA served insecure where a refusal would have
		been safer. The trade is deliberate: the alternative reads every zone
		mid-rollover as unprovable, which is SERVFAIL for a subtree that
		resolves everywhere else, and nothing here is an attacker's to arrange,
		since every record in play carries the zone's own signature.
		*/
		if nsec3_cut_short(budget, before) {
			return .Failed
		}
		if cover.rr.flags & NSEC3_FLAG_OPT_OUT != 0 {
			return .Opt_Out
		}
		return .Failed
	}
	if bitmap_has(wildcard.rr.types, qtype) || bitmap_has(wildcard.rr.types, .CNAME) {
		return .Failed
	}
	return .Proven
}

/*
Prove that the delegation at `name` carries no DS record (RFC 5155 section 8.9).

Two shapes count. A record on the name itself with NS set and DS clear is an
explicit unsigned delegation. Failing that, an opt-out span covering the next
closer name is the whole reason opt-out exists: the parent chose not to publish
NSEC3 records for delegations it does not sign.
*/
nsec3_proves_no_ds :: proc(n3s: []Nsec3_Rr, name, zone: string, budget: ^Nsec3_Budget) -> Proof {
	if match, found := nsec3_matching(n3s, name, budget); found {
		if bitmap_has(match.rr.types, .DS) || bitmap_has(match.rr.types, .SOA) {
			return .Failed
		}
		if !bitmap_has(match.rr.types, .NS) {
			return .Failed
		}
		return .Proven
	}

	_, next_closer, _, ok := nsec3_closest_encloser(n3s, name, zone, budget)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, budget)
	if !covered || cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0 {
		return .Failed
	}
	return .Proven
}

/*
Whether the records show that nothing is delegated at `name`, so the parent
zone's keys still cover everything below it.

`matched` says whether that was settled by a record on the name itself, which
the caller needs and the scan already knows. Returning it is not a convenience:
asking again is a second scan over the same records for an answer this one had,
and a second scan can disagree with the first - once the hashing allowance
empties between them, the repeat finds nothing and the name reads as one the
zone does not hold.
*/
nsec3_proves_no_delegation :: proc(
	n3s: []Nsec3_Rr,
	name, zone: string,
	budget: ^Nsec3_Budget,
) -> (
	proven: bool,
	matched: bool,
) {
	if match, found := nsec3_matching(n3s, name, budget); found {
		return !bitmap_has(match.rr.types, .NS) || bitmap_has(match.rr.types, .SOA), true
	}
	// Opt-out spans prove nothing about what they cover, so they cannot rule a
	// delegation out.
	cover, covered := nsec3_covering(n3s, name, budget)
	return covered && cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0, false
}
