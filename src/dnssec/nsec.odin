package dnssec

import "core:strings"
import "elodin:dns"

/*
Denial of existence.

A signature proves that data is genuine; it says nothing about data that is not
there. NSEC and NSEC3 close that hole by publishing, in signed form, the gaps
between the names a zone holds, so "there is no such name" and "there is no such
type" become statements a validator can check rather than take on trust.

Getting this wrong is how a validator is downgraded: an attacker who can make
"there is no DS record here" look proven detaches the whole subtree below that
point from the chain of trust. Every proof below therefore requires the exact
records RFC 4035 and RFC 5155 call for, and anything less fails.
*/

Proof :: enum u8 {
	// The records say what they were asked to say.
	Proven,
	// Not proven, but only because an opt-out span was in the way, which leaves
	// the answer unsigned rather than forged.
	Opt_Out,
	// The records do not prove it.
	Failed,
}

Nsec_Rr :: struct {
	owner: string,
	rr:    Nsec,
}

Nsec3_Rr :: struct {
	// The owner's first label, decoded from base32hex.
	hash: []u8,
	rr:   Nsec3,
}

// "example.com." -> "*.example.com."
wildcard_of :: proc(name: string, allocator := context.temp_allocator) -> string {
	if name == "." || name == "" {
		return "*."
	}
	return strings.concatenate({"*.", name}, allocator)
}

// The longest name that is an ancestor of both, root at worst.
common_ancestor :: proc(a, b: string) -> string {
	x, y := a, b
	al, bl := label_count(a), label_count(b)
	if al > bl {
		x = name_drop_labels(a, al - bl)
	} else if bl > al {
		y = name_drop_labels(b, bl - al)
	}
	for !dns.name_equal_fold(x, y) {
		if x == "." || y == "." {
			return "."
		}
		x = dns.name_parent(x)
		y = dns.name_parent(y)
	}
	return x
}

/*
Does an NSEC record's span contain `name`, without matching it?

The last NSEC of a zone points back at the apex, so a span whose end does not
sort after its start is the one that wraps round the end of the chain.
*/
nsec_covers :: proc(owner, next, name: string) -> bool {
	// Every comparison has to succeed. A name that will not canonicalise cannot
	// be placed in the ordering at all, and a span must never be read as
	// covering something whose position is unknown.
	owner_to_name, ok1 := name_compare(owner, name)
	owner_to_next, ok2 := name_compare(owner, next)
	name_to_next, ok3 := name_compare(name, next)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	if owner_to_name == 0 {
		return false
	}
	if owner_to_next < 0 {
		return owner_to_name < 0 && name_to_next < 0
	}
	// The last NSEC of a zone wraps round to the apex.
	return owner_to_name < 0 || name_to_next < 0
}

@(private)
nsec_matching :: proc(nsecs: []Nsec_Rr, name: string) -> (rr: Nsec_Rr, found: bool) {
	for n in nsecs {
		if dns.name_equal_fold(n.owner, name) {
			return n, true
		}
	}
	return {}, false
}

@(private)
nsec_covering :: proc(nsecs: []Nsec_Rr, name: string) -> (rr: Nsec_Rr, found: bool) {
	for n in nsecs {
		if nsec_covers(n.owner, n.rr.next, name) {
			return n, true
		}
	}
	return {}, false
}

/*
Prove that `qname` does not exist at all (RFC 4035 section 5.4).

Two spans are needed: one that swallows the name itself, and one that swallows
the wildcard that would otherwise have answered for it. Without the second, a
zone with a wildcard could be made to look empty.
*/
nsec_proves_name_error :: proc(nsecs: []Nsec_Rr, qname: string, allocator := context.temp_allocator) -> Proof {
	covering, found := nsec_covering(nsecs, qname)
	if !found {
		return .Failed
	}

	// The closest encloser is the deepest ancestor of qname that the covering
	// span shows to exist, which is whichever of its two ends shares more with
	// qname.
	from_owner := common_ancestor(qname, covering.owner)
	from_next := common_ancestor(qname, covering.rr.next)
	encloser := from_owner if label_count(from_owner) >= label_count(from_next) else from_next

	wildcard := wildcard_of(encloser, allocator)
	if _, covered := nsec_covering(nsecs, wildcard); !covered {
		return .Failed
	}
	return .Proven
}

/*
Prove that `qname` exists but has no records of `qtype` (RFC 4035 section 5.4).

Either an NSEC sits on the name with the type missing from its bit map, or the
name is covered and a wildcard NSEC answers for it with the type missing.
*/
nsec_proves_no_data :: proc(
	nsecs: []Nsec_Rr,
	qname: string,
	qtype: dns.Type,
	allocator := context.temp_allocator,
) -> Proof {
	if match, found := nsec_matching(nsecs, qname); found {
		if bitmap_has(match.rr.types, qtype) || bitmap_has(match.rr.types, .CNAME) {
			return .Failed
		}
		// An NSEC with NS but no SOA belongs to the parent side of a zone cut,
		// so it says nothing about the type at the child.
		if bitmap_has(match.rr.types, .NS) && !bitmap_has(match.rr.types, .SOA) && qtype != .DS {
			return .Failed
		}
		return .Proven
	}

	covering, found := nsec_covering(nsecs, qname)
	if !found {
		return .Failed
	}
	from_owner := common_ancestor(qname, covering.owner)
	from_next := common_ancestor(qname, covering.rr.next)
	encloser := from_owner if label_count(from_owner) >= label_count(from_next) else from_next

	wildcard, wfound := nsec_matching(nsecs, wildcard_of(encloser, allocator))
	if !wfound {
		return .Failed
	}
	if bitmap_has(wildcard.rr.types, qtype) || bitmap_has(wildcard.rr.types, .CNAME) {
		return .Failed
	}
	return .Proven
}

/*
Decide what an NSEC set says about a DS record at `name`.

`.Proven` means the delegation is real but unsigned, which ends the chain of
trust there. Everything else means the records did not establish that, and the
caller must not treat the subtree as insecure on their say-so.
*/
nsec_proves_no_ds :: proc(nsecs: []Nsec_Rr, name: string) -> Proof {
	if match, found := nsec_matching(nsecs, name); found {
		if bitmap_has(match.rr.types, .DS) {
			return .Failed
		}
		if bitmap_has(match.rr.types, .SOA) {
			// The apex of the zone itself, not a delegation from its parent.
			return .Failed
		}
		if !bitmap_has(match.rr.types, .NS) {
			return .Failed
		}
		return .Proven
	}
	return .Failed
}

/*
Does an NSEC set show that `name` is not a zone cut at all?

An empty non-terminal or an ordinary name inside the parent zone has no DS and
no NS, so the parent's own keys still cover it and the walk down should stop
rather than declare the subtree insecure.
*/
nsec_proves_no_delegation :: proc(nsecs: []Nsec_Rr, name: string) -> bool {
	if match, found := nsec_matching(nsecs, name); found {
		return !bitmap_has(match.rr.types, .NS) || bitmap_has(match.rr.types, .SOA)
	}
	// The name does not exist, so nothing is delegated at it.
	_, covered := nsec_covering(nsecs, name)
	return covered
}

/*
Does an NSEC set show that `name` is a node in the zone at all?

An NSEC on the name itself says so outright. An empty non-terminal has none of
its own - RFC 4035 section 2.3 asks for a record only where there is data or a
delegation - so the zone answers for it with the NSEC covering it, which is the
same record it would send for a name that is not there at all (RFC 7129 section
5.4 calls this out as the one place the two are indistinguishable by shape).

Where that record points tells them apart. Names sort so that everything under a
name follows it immediately, before any sibling, so the first name after an
empty non-terminal is the descendant it exists for. A name that is really not
there is followed by something outside it.

The walk down to a zone's keys turns on this: a node that is not a cut still has
cuts under it and has to be walked past, while a name that is not there has
nothing under it to walk to.
*/
nsec_shows_node :: proc(nsecs: []Nsec_Rr, name: string) -> bool {
	if _, found := nsec_matching(nsecs, name); found {
		return true
	}
	cover, covered := nsec_covering(nsecs, name)
	return covered && !dns.name_equal_fold(cover.rr.next, name) && name_in_zone(cover.rr.next, name)
}

/*
Decode the "extended hex" base32 of RFC 4648 section 7.

NSEC3 owner names use that alphabet rather than ordinary base32 because its
digits sort in the same order as the bytes they encode, which is what lets the
chain be walked in owner-name order.
*/
base32hex_decode :: proc(text: string, out: []u8) -> (n: int, ok: bool) {
	acc: u32
	bits: uint
	for i in 0 ..< len(text) {
		c := text[i]
		v: u32
		switch {
		case c >= '0' && c <= '9':
			v = u32(c - '0')
		case c >= 'a' && c <= 'v':
			v = u32(c - 'a') + 10
		case c >= 'A' && c <= 'V':
			v = u32(c - 'A') + 10
		case:
			return 0, false
		}
		acc = acc << 5 | v
		bits += 5
		if bits >= 8 {
			bits -= 8
			if n >= len(out) {
				return 0, false
			}
			out[n] = u8(acc >> bits)
			n += 1
		}
	}
	return n, true
}

// The leftmost label of a presentation-form name.
first_label :: proc(name: string) -> string {
	i := 0
	for i < len(name) {
		if name[i] == '\\' {
			i += 2
			continue
		}
		if name[i] == '.' {
			return name[:i]
		}
		i += 1
	}
	return name
}
