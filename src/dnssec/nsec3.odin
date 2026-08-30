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
Hash `name` with one record's parameters.

Refusing an iteration count above `max_iterations` is a denial-of-service guard:
the work is the validator's, the number is the zone's, and RFC 9276 asks for
zero anyway. Refusing here makes the proof fail rather than succeed, and callers
turn that into an insecure answer rather than a bogus one.
*/
@(private)
nsec3_hash_with :: proc(rr: Nsec3, name: string, out: []u8, max_iterations: int) -> bool {
	if rr.hash_algorithm != NSEC3_HASH_SHA1 {
		return false
	}
	if int(rr.iterations) > max_iterations {
		return false
	}
	return nsec3_hash(name, rr.salt, rr.iterations, out)
}

@(private)
nsec3_matching :: proc(n3s: []Nsec3_Rr, name: string, max_iterations: int) -> (rr: Nsec3_Rr, found: bool) {
	h: [20]u8
	for n in n3s {
		if !nsec3_hash_with(n.rr, name, h[:], max_iterations) {
			continue
		}
		if mem.compare(n.hash, h[:]) == 0 {
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
nsec3_covering :: proc(n3s: []Nsec3_Rr, name: string, max_iterations: int) -> (rr: Nsec3_Rr, found: bool) {
	h: [20]u8
	for n in n3s {
		if !nsec3_hash_with(n.rr, name, h[:], max_iterations) {
			continue
		}
		// Both ends of the span must be the width of the hash we computed, or
		// the byte comparisons below are comparing different things.
		if len(n.hash) != len(h) || len(n.rr.next_hash) != len(h) {
			continue
		}
		covered: bool
		if mem.compare(n.hash, n.rr.next_hash) < 0 {
			covered = mem.compare(n.hash, h[:]) < 0 && mem.compare(h[:], n.rr.next_hash) < 0
		} else {
			covered = mem.compare(n.hash, h[:]) < 0 || mem.compare(h[:], n.rr.next_hash) < 0
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

An in-band NSEC3 match is required at every depth, the apex included, as RFC
5155 sections 8.4 through 8.9 ask for. A wildcard answer is the one shape that
genuinely does arrive without an apex match, and it does not come through here:
its closest encloser is named by the signature that expanded it, so
`validate_wildcard_proof` reads it from there rather than searching for it.
*/
@(private)
nsec3_closest_encloser :: proc(
	n3s: []Nsec3_Rr,
	qname, zone: string,
	max_iterations: int,
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
		if _, found := nsec3_matching(n3s, name, max_iterations); found {
			if previous == "" {
				return "", "", false
			}
			return name, previous, true
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
	max_iterations: int,
	allocator := context.temp_allocator,
) -> Proof {
	encloser, next_closer, ok := nsec3_closest_encloser(n3s, qname, zone, max_iterations)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, max_iterations)
	if !covered {
		return .Failed
	}
	wildcard_cover, wildcard_covered := nsec3_covering(n3s, wildcard_of(encloser, allocator), max_iterations)
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
	max_iterations: int,
	allocator := context.temp_allocator,
) -> Proof {
	if match, found := nsec3_matching(n3s, qname, max_iterations); found {
		if bitmap_has(match.rr.types, qtype) || bitmap_has(match.rr.types, .CNAME) {
			return .Failed
		}
		if qtype != .DS && bitmap_has(match.rr.types, .NS) && !bitmap_has(match.rr.types, .SOA) {
			return .Failed
		}
		return .Proven
	}

	// No record on the name itself: a wildcard must be what answered, and it
	// must be missing the type too.
	encloser, next_closer, ok := nsec3_closest_encloser(n3s, qname, zone, max_iterations)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, max_iterations)
	if !covered {
		return .Failed
	}
	wildcard, wildcard_found := nsec3_matching(n3s, wildcard_of(encloser, allocator), max_iterations)
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
nsec3_proves_no_ds :: proc(n3s: []Nsec3_Rr, name, zone: string, max_iterations: int) -> Proof {
	if match, found := nsec3_matching(n3s, name, max_iterations); found {
		if bitmap_has(match.rr.types, .DS) || bitmap_has(match.rr.types, .SOA) {
			return .Failed
		}
		if !bitmap_has(match.rr.types, .NS) {
			return .Failed
		}
		return .Proven
	}

	_, next_closer, ok := nsec3_closest_encloser(n3s, name, zone, max_iterations)
	if !ok {
		return .Failed
	}
	cover, covered := nsec3_covering(n3s, next_closer, max_iterations)
	if !covered || cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0 {
		return .Failed
	}
	return .Proven
}

// Whether the records show that nothing is delegated at `name`, so the parent
// zone's keys still cover everything below it.
nsec3_proves_no_delegation :: proc(n3s: []Nsec3_Rr, name, zone: string, max_iterations: int) -> bool {
	if match, found := nsec3_matching(n3s, name, max_iterations); found {
		return !bitmap_has(match.rr.types, .NS) || bitmap_has(match.rr.types, .SOA)
	}
	// Opt-out spans prove nothing about what they cover, so they cannot rule a
	// delegation out.
	cover, covered := nsec3_covering(n3s, name, max_iterations)
	return covered && cover.rr.flags & NSEC3_FLAG_OPT_OUT == 0
}
