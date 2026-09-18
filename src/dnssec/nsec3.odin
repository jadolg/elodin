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

8192 rounds is about 1.5 ms of SHA-1 on a current machine, which puts NSEC3
hashing in the same order as the signature verifications
`MAX_VERIFICATIONS_PER_QUERY` already allows, and a hundredth of what the
paragraph above measures. Real traffic is nowhere near it: a zone following RFC
9276 uses zero iterations, so a denial costs one round per name tried and a
whole question tens. What the number has to leave room for is the other end of
what is still legal - a zone at the iteration ceiling, asked about a name deep
enough to walk eight ancestors - and that is around 6500 rounds with the reuse
`Nsec3_Hashes` does. A question that wants more is answered `Indeterminate`,
never `Bogus`: this is an allowance of ours running out, not a proof found
wanting.
*/
MAX_NSEC3_ROUNDS_PER_QUERY :: 8192

/*
What one question is allowed to spend on NSEC3 hashing, and the ceiling it
holds each record's iteration count to.

Carried as part of `Budget`, for the reason written there: the limit is per
client question, so two arriving at once each get their own. A zero
`max_iterations` means `DEFAULT_MAX_NSEC3_ITERATIONS`, which is the same reading
`make_validator` gives the option it comes from.
*/
Nsec3_Budget :: struct {
	max_iterations: int,
	rounds:         int,
	exhausted:      bool,
}

/*
Charge one hash to the question's allowance.

The unit is a SHA-1 round, weighted by the salt: a round hashes the 20-byte
digest with the salt appended, so a 255-byte salt is four compression blocks
where a short one is a single block, and counting rounds alone would let the
longest salt buy four times the work at the same price. The first round hashes
the wire name rather than a digest, which is the same handful of blocks and is
charged as one round like the rest.

Refusing sets `exhausted` rather than only returning false, because the callers
that matter are several proofs up and the difference they have to report is
between a proof that failed and a proof this server stopped reading.
*/
@(private)
spend_nsec3_rounds :: proc(budget: ^Nsec3_Budget, rr: Nsec3) -> bool {
	cost := (1 + int(rr.iterations)) * (1 + len(rr.salt) / 64)
	if budget.rounds + cost > MAX_NSEC3_ROUNDS_PER_QUERY {
		budget.exhausted = true
		return false
	}
	budget.rounds += cost
	return true
}

/*
Hash `name` with one record's parameters.

Refusing an iteration count above the budget's ceiling is a denial-of-service
guard: the work is the validator's, the number is the zone's, and RFC 9276 asks
for zero anyway. Refusing here makes the proof fail rather than succeed, and
callers turn that into an insecure answer rather than a bogus one. The ceiling
bounds one record; `MAX_NSEC3_ROUNDS_PER_QUERY` bounds the question.
*/
@(private)
nsec3_hash_with :: proc(rr: Nsec3, name: string, out: []u8, budget: ^Nsec3_Budget) -> bool {
	if rr.hash_algorithm != NSEC3_HASH_SHA1 {
		return false
	}
	ceiling := budget.max_iterations if budget.max_iterations > 0 else DEFAULT_MAX_NSEC3_ITERATIONS
	if int(rr.iterations) > ceiling {
		return false
	}
	if !spend_nsec3_rounds(budget, rr) {
		return false
	}
	return nsec3_hash(name, rr.salt, rr.iterations, out)
}

/*
One name's hash, kept across a scan of the records.

Every record a zone publishes carries the parameters of its single NSEC3PARAM,
so a scan over a denial's records asks for the same hash of the same name every
time. Computing it once and comparing it against each record is what keeps an
honest proof cheap enough for the allowance above to be tight. A sender that
chose a different salt for every record gets a hash per record, and pays for
each one out of the budget.
*/
@(private)
Nsec3_Hashes :: struct {
	name:       string,
	algorithm:  u8,
	salt:       []u8,
	iterations: u16,
	hash:       [20]u8,
	have:       bool,
}

/*
The kept hash belongs to all three of the parameters that produced it, and the
algorithm is in the key for the same reason as the other two. Only SHA-1 is ever
computed, so a record naming another hash has to miss here and be refused by
`nsec3_hash_with` - reusing a neighbour's digest for it would read a record this
package cannot check as one it had.
*/
@(private)
nsec3_hash_of :: proc(c: ^Nsec3_Hashes, rr: Nsec3, budget: ^Nsec3_Budget) -> (hash: []u8, ok: bool) {
	if c.have &&
	   c.algorithm == rr.hash_algorithm &&
	   c.iterations == rr.iterations &&
	   len(c.salt) == len(rr.salt) &&
	   mem.compare(c.salt, rr.salt) == 0 {
		return c.hash[:], true
	}
	if !nsec3_hash_with(rr, c.name, c.hash[:], budget) {
		// The previous hash is still the hash of its own parameters, so a
		// record this one could not be computed for leaves it alone.
		return nil, false
	}
	c.algorithm, c.salt, c.iterations, c.have = rr.hash_algorithm, rr.salt, rr.iterations, true
	return c.hash[:], true
}

@(private)
nsec3_matching :: proc(n3s: []Nsec3_Rr, name: string, budget: ^Nsec3_Budget) -> (rr: Nsec3_Rr, found: bool) {
	hashes := Nsec3_Hashes {
		name = name,
	}
	for n in n3s {
		h, ok := nsec3_hash_of(&hashes, n.rr, budget)
		if !ok {
			if budget.exhausted {
				break
			}
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
	hashes := Nsec3_Hashes {
		name = name,
	}
	for n in n3s {
		h, ok := nsec3_hash_of(&hashes, n.rr, budget)
		if !ok {
			if budget.exhausted {
				break
			}
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
	ok: bool,
) {
	if !name_in_zone(qname, zone) {
		return "", "", false
	}
	name := qname
	previous := ""
	for {
		if _, found := nsec3_matching(n3s, name, budget); found {
			if previous == "" {
				return "", "", false
			}
			return name, previous, true
		}
		// Nothing above this name can be matched either once the hashing
		// allowance is gone, and the caller reads `exhausted` rather than this
		// failure to tell the two apart.
		if budget.exhausted {
			return "", "", false
		}
		if dns.name_equal_fold(name, zone) {
			return "", "", false
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
	encloser, next_closer, ok := nsec3_closest_encloser(n3s, qname, zone, budget)
	if !ok {
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
	encloser, next_closer, ok := nsec3_closest_encloser(n3s, qname, zone, budget)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, budget)
	if !covered {
		return .Failed
	}
	wildcard, wildcard_found := nsec3_matching(n3s, wildcard_of(encloser, allocator), budget)
	if !wildcard_found {
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

	_, next_closer, ok := nsec3_closest_encloser(n3s, name, zone, budget)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, budget)
	if !covered || cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0 {
		return .Failed
	}
	return .Proven
}

// Whether the records show that nothing is delegated at `name`, so the parent
// zone's keys still cover everything below it.
nsec3_proves_no_delegation :: proc(n3s: []Nsec3_Rr, name, zone: string, budget: ^Nsec3_Budget) -> bool {
	if match, found := nsec3_matching(n3s, name, budget); found {
		return !bitmap_has(match.rr.types, .NS) || bitmap_has(match.rr.types, .SOA)
	}
	// Opt-out spans prove nothing about what they cover, so they cannot rule a
	// delegation out.
	cover, covered := nsec3_covering(n3s, name, budget)
	return covered && cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0
}
