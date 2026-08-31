package dnssec

import "core:testing"
import "elodin:dns"

/*
The NSEC machinery on its own.

NSEC is the readable half of denial of existence, and the half where the
mistakes are ordering mistakes: a span read as covering a name it does not, an
exact match mistaken for a cover, the record at the end of the chain that wraps
back to the apex. Every one of those turns "there is no such name" into
something an attacker can arrange, and the worst of them - a forged "there is no
DS here" - detaches every zone below that point from the chain of trust.

The zone below is a deliberate one rather than a captured one, so that each
record is here for a stated reason. It is in canonical order, which is the order
NSEC chains are built in: labels compared right to left, so everything under
`w.example.` sits between `w.example.` itself and `z.example.`, and `*` (0x2a)
sorts ahead of any letter.

	example.       -> a.example.      NS SOA MX RRSIG NSEC DNSKEY
	a.example.     -> ai.example.     NS DS RRSIG NSEC     signed delegation
	ai.example.    -> b.example.      A HINFO AAAA RRSIG NSEC
	b.example.     -> ns1.example.    NS RRSIG NSEC        unsigned delegation
	ns1.example.   -> ns2.example.    A RRSIG NSEC
	ns2.example.   -> w.example.      A RRSIG NSEC
	w.example.     -> *.w.example.    A RRSIG NSEC
	*.w.example.   -> x.w.example.    MX RRSIG NSEC
	x.w.example.   -> z.example.      MX RRSIG NSEC
	z.example.     -> example.        A RRSIG NSEC         the wrap
*/

@(private = "file")
nsec_rr :: proc(owner, next: string, types: []dns.Type) -> Nsec_Rr {
	high := 0
	for type in types {
		if int(type) > high {
			high = int(type)
		}
	}
	bitmap: []u8
	if len(types) > 0 {
		length := high / 8 + 1
		out := make([]u8, 2 + length, context.temp_allocator)
		out[0] = 0
		out[1] = u8(length)
		for type in types {
			out[2 + int(type) / 8] |= 0x80 >> u8(int(type) % 8)
		}
		bitmap = out
	}
	return Nsec_Rr{owner = owner, rr = Nsec{next = next, types = bitmap}}
}

@(private = "file")
e_zone :: proc() -> []Nsec_Rr {
	zone := make([dynamic]Nsec_Rr, context.temp_allocator)
	append(&zone, nsec_rr("example.", "a.example.", {.NS, .SOA, .MX, .RRSIG, .NSEC, .DNSKEY}))
	append(&zone, nsec_rr("a.example.", "ai.example.", {.NS, .DS, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("ai.example.", "b.example.", {.A, .HINFO, .AAAA, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("b.example.", "ns1.example.", {.NS, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("ns1.example.", "ns2.example.", {.A, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("ns2.example.", "w.example.", {.A, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("w.example.", "*.w.example.", {.A, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("*.w.example.", "x.w.example.", {.MX, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("x.w.example.", "z.example.", {.MX, .RRSIG, .NSEC}))
	append(&zone, nsec_rr("z.example.", "example.", {.A, .RRSIG, .NSEC}))
	return zone[:]
}

@(test)
test_nsec_covers_reads_the_span_as_open_at_both_ends :: proc(t: ^testing.T) {
	// A span runs strictly between its ends. A record that covered its own
	// owner would prove that name both present and absent.
	testing.expect(t, nsec_covers("a.example.", "c.example.", "b.example."), "an interior name is covered")
	testing.expect(t, !nsec_covers("a.example.", "c.example.", "a.example."), "the owner is not covered by its own span")
	testing.expect(t, !nsec_covers("a.example.", "c.example.", "c.example."), "the next name is not covered either")
	testing.expect(t, !nsec_covers("a.example.", "c.example.", "d.example."), "a name past the span is not covered")
	free_all(context.temp_allocator)
}

@(test)
test_nsec_covers_wraps_at_the_last_record_of_the_zone :: proc(t: ^testing.T) {
	/*
	The last NSEC of a zone points back at the apex, so its span is the one that
	runs off the end of the ordering and round to the start. Reading it as an
	empty or backwards span would leave every name sorting after the last owner
	with no record to prove it absent.
	*/
	testing.expect(t, nsec_covers("z.example.", "example.", "zz.example."), "a name past the last owner is inside the wrap")
	testing.expect(t, !nsec_covers("z.example.", "example.", "b.example."), "a name with its own record is not in the wrap")
	testing.expect(t, !nsec_covers("z.example.", "example.", "example."), "the apex ends the span rather than sitting inside it")
	free_all(context.temp_allocator)
}

@(test)
test_nsec_covers_refuses_a_name_it_cannot_place :: proc(t: ^testing.T) {
	/*
	A name that will not go on the wire has no position in the canonical
	ordering. Guessing one - or letting a failed comparison read as zero - would
	let a span appear to cover a name whose place nobody knows.
	*/
	testing.expect(t, !nsec_covers("a.example.", "c.example.", "b..example."), "an empty label has no place in the order")
	testing.expect(t, !nsec_covers("a..example.", "c.example.", "b.example."), "nor does an owner that will not encode")
	testing.expect(t, !nsec_covers("a.example.", "c..example.", "b.example."), "nor does a next name that will not encode")
	free_all(context.temp_allocator)
}

@(test)
test_nsec_name_error_needs_the_name_and_its_wildcard_covered :: proc(t: ^testing.T) {
	/*
	RFC 4035 section 5.4. `nx.example.` falls between `ns2.example.` and
	`w.example.`, and the wildcard that would otherwise have answered for it,
	`*.example.`, falls in the apex's own span. Both are needed: without the
	second, a zone holding a wildcard could be made to look empty at the name.
	*/
	zone := e_zone()
	testing.expect_value(t, nsec_proves_name_error(zone, "nx.example."), Proof.Proven)

	// The same chain with the apex record - the only one covering `*.example.`
	// - taken out.
	without_wildcard_cover := zone[1:]
	testing.expect_value(t, nsec_proves_name_error(without_wildcard_cover, "nx.example."), Proof.Failed)

	// And a name that plainly exists is not proven absent by any of it.
	testing.expect_value(t, nsec_proves_name_error(zone, "ai.example."), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_data_reads_the_bit_map_on_the_matching_record :: proc(t: ^testing.T) {
	zone := e_zone()
	testing.expect_value(t, nsec_proves_no_data(zone, "ai.example.", .TXT), Proof.Proven)
	// The type is in the map, so the answer owed the client records.
	testing.expect_value(t, nsec_proves_no_data(zone, "ai.example.", .A), Proof.Failed)
	testing.expect_value(t, nsec_proves_no_data(zone, "ai.example.", .AAAA), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_data_refuses_a_name_that_is_a_cname :: proc(t: ^testing.T) {
	// A CNAME stands in for every type, so its presence can never prove a type
	// missing - the client should have been redirected instead.
	zone := []Nsec_Rr{nsec_rr("c.example.", "d.example.", {.CNAME, .RRSIG, .NSEC})}
	testing.expect_value(t, nsec_proves_no_data(zone, "c.example.", .A), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_data_refuses_a_parent_side_record :: proc(t: ^testing.T) {
	/*
	NS without SOA is the parent's half of a zone cut: it describes the
	delegation, not the child's contents, so it cannot say what types exist
	below. RFC 6840 section 4.4. DS is the exception, because that type really
	does live on the parent side.
	*/
	zone := e_zone()
	testing.expect_value(t, nsec_proves_no_data(zone, "b.example.", .A), Proof.Failed)
	testing.expect_value(t, nsec_proves_no_data(zone, "b.example.", .DS), Proof.Proven)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_data_falls_back_to_the_wildcard :: proc(t: ^testing.T) {
	/*
	Nothing on the name itself, so a wildcard answered, and the proof is that
	the wildcard holds no such type either. `foo.w.example.` is covered by the
	span from `*.w.example.` to `x.w.example.`, which puts its closest encloser
	at `w.example.`, and `*.w.example.` is right there in the chain with MX and
	no A.
	*/
	zone := e_zone()
	testing.expect_value(t, nsec_proves_no_data(zone, "foo.w.example.", .A), Proof.Proven)
	testing.expect_value(t, nsec_proves_no_data(zone, "foo.w.example.", .MX), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_ds_reads_an_explicit_unsigned_delegation :: proc(t: ^testing.T) {
	/*
	`b.example.` is delegated and carries no DS, which ends the chain of trust
	there honestly. `a.example.` carries one, so a claim that it does not is an
	attempt to detach a signed subtree - the single most valuable forgery in
	DNSSEC, and the reason every other shape below is refused.
	*/
	zone := e_zone()
	testing.expect_value(t, nsec_proves_no_ds(zone, "b.example."), Proof.Proven)
	testing.expect_value(t, nsec_proves_no_ds(zone, "a.example."), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_ds_refuses_an_apex_a_non_delegation_and_an_absent_name :: proc(t: ^testing.T) {
	/*
	A record carrying SOA is the child zone's own apex, answered from the wrong
	side of the cut; one without NS is not a delegation at all; and a name with
	no record of its own proves nothing, because NSEC has no opt-out to fall
	back on the way NSEC3 does.
	*/
	zone := e_zone()
	testing.expect_value(t, nsec_proves_no_ds(zone, "example."), Proof.Failed)
	testing.expect_value(t, nsec_proves_no_ds(zone, "ai.example."), Proof.Failed)
	testing.expect_value(t, nsec_proves_no_ds(zone, "nx.example."), Proof.Failed)
	free_all(context.temp_allocator)
}

@(test)
test_nsec_no_delegation_reads_matches_and_covers :: proc(t: ^testing.T) {
	/*
	Whether the parent's own keys still reach a name, which is what stops the
	walk down at an empty non-terminal instead of declaring the subtree
	insecure.
	*/
	zone := e_zone()
	testing.expect(t, nsec_proves_no_delegation(zone, "ai.example."), "an ordinary name is not a zone cut")
	testing.expect(t, nsec_proves_no_delegation(zone, "example."), "the apex carries SOA, so it is not a cut from below")
	testing.expect(t, !nsec_proves_no_delegation(zone, "b.example."), "a delegation is a cut")
	testing.expect(t, nsec_proves_no_delegation(zone, "nx.example."), "a name shown absent is not delegated")

	// Neither matched nor covered: the records say nothing about it.
	testing.expect(t, !nsec_proves_no_delegation(zone[:1], "q.other."), "a name the records do not reach is not settled")
	free_all(context.temp_allocator)
}

@(test)
test_common_ancestor_finds_the_deepest_shared_suffix :: proc(t: ^testing.T) {
	// The closest encloser of a covered name is read off the ends of the span
	// that covers it, so this is what decides which wildcard has to be denied.
	testing.expect_value(t, common_ancestor("x.w.example.", "y.w.example."), "w.example.")
	testing.expect_value(t, common_ancestor("a.example.", "b.other."), ".")
	testing.expect_value(t, common_ancestor("deep.x.w.example.", "w.example."), "w.example.")
	testing.expect_value(t, common_ancestor("example.", "example."), "example.")
	/*
	Case must not split names that are the same name. The ancestor comes back in
	whatever case it was written in - every caller feeds it to `name_compare` or
	`dns.name_equal_fold`, both of which fold - so the check is that the walk
	found the right ancestor, not that it rewrote it.
	*/
	mixed := common_ancestor("A.ExAmPlE.", "b.example.")
	testing.expectf(t, dns.name_equal_fold(mixed, "example."), "expected example. in some case, got %q", mixed)
	free_all(context.temp_allocator)
}

@(test)
test_wildcard_of_prefixes_the_asterisk :: proc(t: ^testing.T) {
	testing.expect_value(t, wildcard_of("example.", context.temp_allocator), "*.example.")
	testing.expect_value(t, wildcard_of("w.example.", context.temp_allocator), "*.w.example.")
	// The root's wildcard is `*.`, not `*..`.
	testing.expect_value(t, wildcard_of(".", context.temp_allocator), "*.")
	testing.expect_value(t, wildcard_of("", context.temp_allocator), "*.")
	free_all(context.temp_allocator)
}

@(test)
test_first_label_steps_over_escapes :: proc(t: ^testing.T) {
	// NSEC3 owner names are read one label at a time, and a dot written `\.` is
	// part of the label rather than the end of it.
	testing.expect_value(t, first_label("abc.example."), "abc")
	testing.expect_value(t, first_label("example."), "example")
	testing.expect_value(t, first_label("a\\.b.example."), "a\\.b")
	testing.expect_value(t, first_label("."), "")
	free_all(context.temp_allocator)
}
