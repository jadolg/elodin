package dnssec

import "core:mem"
import "core:slice"
import "core:testing"
import "elodin:dns"

/*
What a DS denial is allowed to say about the name below it.

The walk down to a zone's keys asks for a DS at every label, and a denial that
comes back has to be read for two different things. "Nothing is delegated here"
is not the end of the walk - an empty non-terminal holds no NS and no DS and
still has zone cuts under it, which is the whole of `empty_non_terminal_test`.
"There is no such name here" is the end of it, because nothing exists below a
name that does not exist, so no cut can be hiding down there either.

Reading the second as the first is what these tests are for. It costs a DS
lookup per label for a name nobody has, which is a client's question turned into
twenty of this server's, and under NSEC3 it costs correctness outright: the
denial a server sends for `q.nx.example.` proves the closest encloser and the
next closer name, never the full name two labels down, so the step below the
next closer finds a proof it cannot read and calls the zone broken.
*/

@(private = "file")
D_SALT := []u8{0x01, 0x02}

@(private = "file")
Node :: struct {
	name:  string,
	types: []dns.Type,
}

@(private = "file")
bitmap_of :: proc(types: []dns.Type) -> []u8 {
	if len(types) == 0 {
		return nil
	}
	high := 0
	for type in types {
		if int(type) > high {
			high = int(type)
		}
	}
	length := high / 8 + 1
	out := make([]u8, 2 + length, context.temp_allocator)
	out[1] = u8(length)
	for type in types {
		out[2 + int(type) / 8] |= 0x80 >> u8(int(type) % 8)
	}
	return out
}

/*
The NSEC3 chain a zone holding exactly these names would publish: one record
per name, in hash order, each pointing at the next and the last wrapping round.

RFC 5155 section 7.1 asks for a record on every empty non-terminal too, which is
what lets an NSEC3 zone tell "not a cut" from "not there" without the rcode.
*/
@(private = "file")
nsec3_zone :: proc(nodes: []Node) -> []Nsec3_Rr {
	out := make([]Nsec3_Rr, len(nodes), context.temp_allocator)
	for node, i in nodes {
		hash := make([]u8, 20, context.temp_allocator)
		if !nsec3_hash(node.name, D_SALT, 0, hash) {
			return nil
		}
		out[i] = Nsec3_Rr {
			hash = hash,
			rr = Nsec3 {
				hash_algorithm = NSEC3_HASH_SHA1,
				salt = D_SALT,
				types = bitmap_of(node.types),
			},
		}
	}
	slice.sort_by(out, proc(a, b: Nsec3_Rr) -> bool {
		return mem.compare(a.hash, b.hash) < 0
	})
	for i in 0 ..< len(out) {
		out[i].rr.next_hash = out[(i + 1) % len(out)].hash
	}
	return out
}

@(private = "file")
nsec_rr_of :: proc(owner, next: string, types: []dns.Type) -> Nsec_Rr {
	return Nsec_Rr{owner = owner, rr = Nsec{next = next, types = bitmap_of(types)}}
}

@(test)
test_a_denial_of_a_name_that_is_not_there_ends_the_walk :: proc(t: ^testing.T) {
	// NSEC3 first, where reading this wrong is not just wasteful. The records
	// are the ones a server really sends for a name error under `example.`:
	// they speak for the closest encloser and the next closer name, and the
	// walk must stop on the second rather than ask about the label below it.
	zone := nsec3_zone({{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}}, {"a.example.", {.A, .RRSIG}}})
	testing.expect(t, len(zone) == 2, "the chain should build")
	testing.expect_value(t, denial_step(nil, zone, "nx.example.", "example.", 150), Step.Absent)

	// And NSEC, where the same span answers for every name inside it, so the
	// walk would otherwise keep going label by label to `MAX_CHAIN_DEPTH`.
	nsecs := []Nsec_Rr {
		nsec_rr_of("example.", "a.example.", {.NS, .SOA, .RRSIG, .NSEC, .DNSKEY}),
		nsec_rr_of("a.example.", "z.example.", {.A, .RRSIG, .NSEC}),
		nsec_rr_of("z.example.", "example.", {.A, .RRSIG, .NSEC}),
	}
	testing.expect_value(t, denial_step(nsecs, nil, "nx.example.", "example.", 150), Step.Absent)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_at_an_empty_non_terminal_keeps_the_walk_going :: proc(t: ^testing.T) {
	// The name exists and holds nothing, and the cut is below it. Stopping here
	// is the bug `empty_non_terminal_test` is about.
	zone := nsec3_zone(
		{
			{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}},
			{"ent.example.", nil},
			{"deep.ent.example.", {.A, .RRSIG}},
		},
	)
	testing.expect(t, len(zone) == 3, "the chain should build")
	testing.expect_value(t, denial_step(nil, zone, "ent.example.", "example.", 150), Step.No_Cut)

	/*
	An NSEC zone publishes no record on an empty non-terminal at all (RFC 4035
	section 2.3 asks for one only where there is data or a delegation), so the
	zone answers for it with the record covering it - the same shape it sends
	for a name that is not there. What tells them apart is where that record
	points: the name immediately after an empty non-terminal is the descendant
	it exists for.
	*/
	nsecs := []Nsec_Rr {
		nsec_rr_of("example.", "a.ent.example.", {.NS, .SOA, .RRSIG, .NSEC, .DNSKEY}),
		nsec_rr_of("a.ent.example.", "example.", {.A, .RRSIG, .NSEC}),
	}
	testing.expect_value(t, denial_step(nsecs, nil, "ent.example.", "example.", 150), Step.No_Cut)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_at_an_unsigned_delegation_still_ends_the_chain :: proc(t: ^testing.T) {
	// Neither of the two readings above: the name is there, it is delegated,
	// and it carries no DS, which is where the chain of trust stops.
	zone := nsec3_zone({{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}}, {"sub.example.", {.NS}}})
	testing.expect_value(t, denial_step(nil, zone, "sub.example.", "example.", 150), Step.Insecure)

	nsecs := []Nsec_Rr {
		nsec_rr_of("example.", "sub.example.", {.NS, .SOA, .RRSIG, .NSEC, .DNSKEY}),
		nsec_rr_of("sub.example.", "example.", {.NS, .NSEC}),
	}
	testing.expect_value(t, denial_step(nsecs, nil, "sub.example.", "example.", 150), Step.Insecure)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_that_settles_nothing_is_refused :: proc(t: ^testing.T) {
	// Records from some other part of the zone say nothing about this name, and
	// "says nothing" must not be read as either answer.
	nsecs := []Nsec_Rr{nsec_rr_of("a.example.", "b.example.", {.A, .RRSIG, .NSEC})}
	testing.expect_value(t, denial_step(nsecs, nil, "q.other.", "other.", 150), Step.Bogus)
	free_all(context.temp_allocator)
}
