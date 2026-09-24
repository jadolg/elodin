package dnssec

import "core:fmt"
import "core:mem"
import "core:slice"
import "core:testing"
import "elodin:dns"

/*
A fresh hashing allowance, held to `max_iterations` per record.

Every call below gets its own, the way every client question does. The proofs
take one rather than a bare ceiling so that no path can hash without being
charged for it - see `MAX_NSEC3_ROUNDS_PER_QUERY`.
*/
@(private = "file")
budget_at :: proc(max_iterations: int) -> ^Nsec3_Budget {
	b := new(Nsec3_Budget, context.temp_allocator)
	b.max_iterations = max_iterations
	return b
}

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
nsec3_zone :: proc(nodes: []Node, salt := D_SALT, iterations: u16 = 0) -> []Nsec3_Rr {
	out := make([]Nsec3_Rr, len(nodes), context.temp_allocator)
	for node, i in nodes {
		hash := make([]u8, 20, context.temp_allocator)
		if !nsec3_hash(node.name, salt, iterations, hash) {
			return nil
		}
		out[i] = Nsec3_Rr {
			hash = hash,
			rr = Nsec3 {
				hash_algorithm = NSEC3_HASH_SHA1,
				salt = salt,
				iterations = iterations,
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
	nsec3_step, _ := denial_step(nil, zone, "nx.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec3_step, Step.Absent)

	// And NSEC, where the same span answers for every name inside it, so the
	// walk would otherwise keep going label by label to the bottom of the name.
	nsecs := []Nsec_Rr {
		nsec_rr_of("example.", "a.example.", {.NS, .SOA, .RRSIG, .NSEC, .DNSKEY}),
		nsec_rr_of("a.example.", "z.example.", {.A, .RRSIG, .NSEC}),
		nsec_rr_of("z.example.", "example.", {.A, .RRSIG, .NSEC}),
	}
	nsec_step, _ := denial_step(nsecs, nil, "nx.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec_step, Step.Absent)
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
	nsec3_step, _ := denial_step(nil, zone, "ent.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec3_step, Step.No_Cut)

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
	nsec_step, _ := denial_step(nsecs, nil, "ent.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec_step, Step.No_Cut)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_at_an_unsigned_delegation_still_ends_the_chain :: proc(t: ^testing.T) {
	// Neither of the two readings above: the name is there, it is delegated,
	// and it carries no DS, which is where the chain of trust stops.
	zone := nsec3_zone({{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}}, {"sub.example.", {.NS}}})
	nsec3_step, _ := denial_step(nil, zone, "sub.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec3_step, Step.Insecure)

	nsecs := []Nsec_Rr {
		nsec_rr_of("example.", "sub.example.", {.NS, .SOA, .RRSIG, .NSEC, .DNSKEY}),
		nsec_rr_of("sub.example.", "example.", {.NS, .NSEC}),
	}
	nsec_step, _ := denial_step(nsecs, nil, "sub.example.", "example.", budget_at(150))
	testing.expect_value(t, nsec_step, Step.Insecure)
	free_all(context.temp_allocator)
}

@(test)
test_a_denial_that_settles_nothing_is_refused :: proc(t: ^testing.T) {
	// Records from some other part of the zone say nothing about this name, and
	// "says nothing" must not be read as either answer.
	nsecs := []Nsec_Rr{nsec_rr_of("a.example.", "b.example.", {.A, .RRSIG, .NSEC})}
	out_of_zone, _ := denial_step(nsecs, nil, "q.other.", "other.", budget_at(150))
	testing.expect_value(t, out_of_zone, Step.Bogus)
	free_all(context.temp_allocator)
}

/*
A step read with the hashing allowance nearly gone is never "not there".

`.Absent` is the one reading that ends the walk, and `zone_trust` ends it by
returning `Secure` for the zone reached so far. That makes it the expensive
thing to get wrong: a name that really is delegated, judged against its parent's
keys, is an answer with no valid signature - our own limit reaching the client
as a forgery, which is the outcome this whole allowance exists to avoid.

So the step says for itself whether hashing was refused while it read, rather
than leaving the caller to read a meter that belongs to the whole question. The
records below cost one round a hash, and the step is given exactly what it needs
and then one round less.
*/
@(test)
test_a_step_whose_hashing_ran_out_is_not_read_as_an_absent_name :: proc(t: ^testing.T) {
	zone := nsec3_zone({{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}}, {"ent.example.", {.A, .RRSIG}}})
	testing.expect(t, len(zone) == 2, "the chain should build")

	measured := Nsec3_Budget {
		max_iterations = 150,
	}
	testing.expect_value(t, denial_step_probe(zone, "ent.example.", &measured), Step.No_Cut)
	testing.expect(t, measured.rounds > 0, "a step that hashes nothing cannot be starved")

	enough := Nsec3_Budget {
		max_iterations = 150,
		rounds         = MAX_NSEC3_ROUNDS_PER_QUERY - measured.rounds,
	}
	funded, funded_cut := denial_step(nil, zone, "ent.example.", "example.", &enough)
	testing.expect_value(t, funded, Step.No_Cut)
	testing.expect(t, !funded_cut, "a step that hashed everything it needed is not cut short")

	// One round less, and the step has to say so rather than guess: `Bogus`
	// here, which `zone_step` turns into `Indeterminate` when it sees the flag.
	short := Nsec3_Budget {
		max_iterations = 150,
		rounds         = MAX_NSEC3_ROUNDS_PER_QUERY - measured.rounds + 1,
	}
	step, cut_short := denial_step(nil, zone, "ent.example.", "example.", &short)
	testing.expect(t, cut_short, "the step should say it was cut short, rather than leave the caller to read a meter that is the whole question's")
	testing.expect(t, short.spent > 0, "the allowance should have been what stopped this")
	testing.expectf(t, step != .Absent, "a scan cut short is not a name that is not there, got %v", step)
	free_all(context.temp_allocator)
}

@(private = "file")
denial_step_probe :: proc(zone: []Nsec3_Rr, child: string, budget: ^Nsec3_Budget) -> Step {
	step, _ := denial_step(nil, zone, child, "example.", budget)
	return step
}

/*
A zone changing its salt is not a zone this server stops answering for.

RFC 5155 section 7.3 has a zone that wants different NSEC3 parameters publish a
second complete chain alongside the first and remove the old one afterwards, so
for as long as that takes a denial can carry records under two salts. They
arrive interleaved, because a chain is in hash order and two chains' hashes fall
through each other, and one kept hash would then be missed by every record in
turn - a hash per record, which is the multiplication the reuse exists to
prevent and which a zone near the iteration ceiling cannot pay for out of one
allowance.

A hundred iterations here, which is legal, is the ceiling this server ships with
and is what a zone that has not read RFC 9276 still publishes. The proof has to
hold up, and with one kept hash it does not: ninety hashes at a hundred and one
rounds each is more than a whole allowance, so a zone mid-rollover would have
gone SERVFAIL for as long as the rollover lasted.
*/
@(test)
test_a_denial_carrying_two_salts_still_fits_in_one_allowance :: proc(t: ^testing.T) {
	nodes := []Node {
		{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}},
		{"a.example.", {.A, .RRSIG}},
		{"b.example.", {.A, .RRSIG}},
		{"c.example.", {.A, .RRSIG}},
		{"d.example.", {.A, .RRSIG}},
	}
	old_salt := []u8{0x01, 0x02}
	new_salt := []u8{0x11, 0x22, 0x33, 0x44}
	iterations :: 100
	old_chain := nsec3_zone(nodes, old_salt, iterations)
	new_chain := nsec3_zone(nodes, new_salt, iterations)
	testing.expect(t, len(old_chain) == len(nodes) && len(new_chain) == len(nodes), "both chains should build")

	both := make([dynamic]Nsec3_Rr, context.temp_allocator)
	for i in 0 ..< len(nodes) {
		append(&both, old_chain[i])
		append(&both, new_chain[i])
	}

	budget := Nsec3_Budget {
		max_iterations = 150,
	}
	// A name six labels below the apex, so the walk has ancestors to try.
	proof := nsec3_proves_name_error(both[:], "q.r.s.t.u.v.example.", "example.", &budget)
	testing.expectf(t, proof == .Proven, "a denial mid-rollover should still prove, got %v", proof)
	testing.expect(t, budget.spent == 0, "and it should not have taken the whole allowance to do it")

	// Two chains, so two hashes a name and not ten. Nine names are asked about:
	// the question, six ancestors, the next closer name and the wildcard.
	per_hash := 1 + iterations
	testing.expectf(
		t,
		budget.rounds <= 18 * per_hash,
		"%d rounds for a two-chain denial, which is more than two hashes a name",
		budget.rounds,
	)
	free_all(context.temp_allocator)
}

/*
A step that found its record keeps its answer, whatever the meter says.

The allowance belongs to the whole question and stays spent once anything
spends it, so a step asked after that has to say whether *its* reading could
have been changed by a refusal. A match cannot: the record was found, and no
refusal produces a record. Reading the meter instead would throw the step away
and answer `Indeterminate` for a name the zone plainly holds - SERVFAIL for a
question that was answered, under a reason belonging to some other proof
entirely.
*/
@(test)
test_a_step_that_matched_is_not_cut_short_by_someone_elses_allowance :: proc(t: ^testing.T) {
	zone := nsec3_zone({{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}}, {"ent.example.", {.A, .RRSIG}}})
	testing.expect(t, len(zone) == 2, "the chain should build")

	// Enough for this step, and the meter already flagged by whatever came
	// before it in the question.
	budget := Nsec3_Budget {
		max_iterations = 150,
		spent          = 3,
	}
	step, cut_short := denial_step(nil, zone, "ent.example.", "example.", &budget)
	testing.expect_value(t, step, Step.No_Cut)
	testing.expect(t, !cut_short, "a record that was found is not a reading a refusal could have changed")
	free_all(context.temp_allocator)
}

/*
The deepest name a chain walk will follow still fits in one allowance.

Every label of the question is a name the walk hashes on the way down, before
the answer's own proof hashes any. What sets the floor is `ip6.arpa.`: a reverse
name for an IPv6 address is a nibble per label, thirty-two of them under a
two-label zone, and issue #352 is what happened when a bound was sized for
something shorter. The allowance is sized for that with room over, and the
sizing is prose in `nsec3.odin` until something runs it: a change to the reuse,
to what a proof scans, or to the charge itself moves the number, and the first
anyone would otherwise hear of it is a reverse lookup answering SERVFAIL.

The ceiling this server ships, and a salt of the length
zones really publish.
*/
@(test)
test_the_deepest_walk_this_server_follows_fits_in_one_allowance :: proc(t: ^testing.T) {
	nodes := make([dynamic]Node, context.temp_allocator)
	append(&nodes, Node{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}})
	// A run of empty non-terminals as deep as the nibbles under an IPv6 reverse
	// zone's apex, each a name the walk has to read a denial for.
	name := "example."
	for i in 0 ..< 32 {
		name = fmt.tprintf("n%d.%s", i, name)
		append(&nodes, Node{name, {.A, .RRSIG}})
	}
	zone := nsec3_zone(nodes[:], []u8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, DEFAULT_MAX_NSEC3_ITERATIONS)
	testing.expect(t, len(zone) == len(nodes), "the chain should build")

	budget := Nsec3_Budget {
		max_iterations = DEFAULT_MAX_NSEC3_ITERATIONS,
	}
	// Every step of the walk, then the denial of a name under the deepest one.
	for node in nodes[1:] {
		step, cut_short := denial_step(nil, zone, node.name, "example.", &budget)
		testing.expectf(t, !cut_short, "the walk ran out at %s after %d rounds", node.name, budget.rounds)
		testing.expectf(t, step == .No_Cut, "%s is a name the zone holds, got %v", node.name, step)
	}
	proof := nsec3_proves_name_error(zone, fmt.tprintf("nx.%s", name), "example.", &budget)
	testing.expectf(t, proof == .Proven, "the denial at the bottom of the walk should prove, got %v", proof)
	testing.expectf(
		t,
		budget.spent == 0,
		"a walk to the chain-depth limit spent %d rounds of %d",
		budget.rounds,
		MAX_NSEC3_ROUNDS_PER_QUERY,
	)
	// And with room left, not by a hair: the sizing comment claims this.
	testing.expectf(
		t,
		budget.rounds < MAX_NSEC3_ROUNDS_PER_QUERY / 2,
		"the deepest walk this server follows spent %d rounds of %d, which is no headroom at all",
		budget.rounds,
		MAX_NSEC3_ROUNDS_PER_QUERY,
	)
	free_all(context.temp_allocator)
}

/*
A chain this server will not read does not stop it reading the one beside it.

A zone changing its NSEC3 parameters publishes both chains at once, and the old
one can be the reason the ceiling exists: five thousand iterations on its way
out, nothing on its way in. Every record of the old chain is refused, and that
refusal is a policy rather than a moment - this server will not read those
records for any question, so what the new chain says is the whole of what it
knows about the zone, and it is a complete answer rather than one cut short.

Reading the refusals together got this wrong for as long as it took to be
noticed here: the step came back undecided, `zone_step` turned that into
`Indeterminate`, and a subtree that resolves on any other resolver went SERVFAIL
because of a chain this server had decided to ignore.
*/
@(test)
test_a_chain_above_the_ceiling_does_not_stop_the_one_beside_it :: proc(t: ^testing.T) {
	nodes := []Node {
		{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}},
		{"a.example.", {.A, .RRSIG}},
	}
	usable := nsec3_zone(nodes, []u8{0x0a, 0x0b}, 0)
	leaving := nsec3_zone(nodes, []u8{0x0c, 0x0d}, 5000)
	testing.expect(t, len(usable) == 2 && len(leaving) == 2, "both chains should build")

	both := make([dynamic]Nsec3_Rr, context.temp_allocator)
	for i in 0 ..< len(nodes) {
		append(&both, leaving[i])
		append(&both, usable[i])
	}

	budget := Nsec3_Budget {
		max_iterations = 100,
	}
	step, cut_short := denial_step(nil, both[:], "nx.example.", "example.", &budget)
	testing.expect_value(t, step, Step.Absent)
	testing.expect(t, !cut_short, "a chain refused for its iterations is not a reading this server stopped short of")
	testing.expect(t, budget.over_ceiling > 0, "the old chain should have been refused, or this proves nothing")
	testing.expect_value(t, budget.spent, 0)
	free_all(context.temp_allocator)
}

/*
A DS denial this server could read none of for its iteration count keeps the
walk going on the parent's keys, rather than leaving it undecided.

Every record above the ceiling is refused, and that refusal is a policy: no
question will ever read them. Reading it as `Indeterminate` made every name
below a parent over the ceiling SERVFAIL here and nowhere else. Issue #331.

Not `.Insecure` either, which is the other easy answer and a hole: the walk
runs over every label of every owner it checks, so an insecure step makes every
name in the zone unsigned, and an unsigned answer forged for any of them is
served. `.No_Cut` keeps the parent's keys, so what is signed still has to
verify; `test_a_forged_unsigned_answer_past_the_ceiling_is_not_served` is the
other half.

The allowance is the other refusal and keeps its answer: a record it turned away
is one this server would have read a moment earlier, so nothing is decided.
*/
@(test)
test_a_ds_denial_above_the_ceiling_keeps_the_parents_keys :: proc(t: ^testing.T) {
	nodes := []Node {
		{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}},
		{"a.example.", {.A, .RRSIG}},
	}
	chain := nsec3_zone(nodes, []u8{0x0c, 0x0d}, 150)
	testing.expect(t, len(chain) == 2, "the chain should build")

	budget := Nsec3_Budget {
		max_iterations = 100,
	}
	step, cut_short := denial_step(nil, chain, "sub.example.", "example.", &budget)
	testing.expect_value(t, step, Step.No_Cut)
	testing.expect(t, !cut_short, "a chain refused for its iterations is not a reading this server stopped short of")
	testing.expect_value(t, budget.rounds, 0)

	// Readable, but the allowance is gone: undecided, as before.
	starved := Nsec3_Budget {
		max_iterations = 150,
		rounds         = MAX_NSEC3_ROUNDS_PER_QUERY,
	}
	step, cut_short = denial_step(nil, chain, "sub.example.", "example.", &starved)
	testing.expect(t, cut_short, "a reading the allowance stopped is not a finding")
	testing.expect(t, step != .Insecure && step != .No_Cut, "and must decide nothing")
	free_all(context.temp_allocator)
}

/*
A refused record beside a readable one decides nothing.

`sub.example.` is a signed delegation - the readable chain says NS and DS - so a
DS answer denying it is a forgery. Anyone holding one signed record of an old
chain above the ceiling can put it beside that denial, and if a refusal anywhere
in the set were enough, the child would be read as insecure and everything in it
served on the attacker's word. Only a set with nothing readable in it is.

That is what a mixed set decides. One who drops the readable records and sends
the old one alone gets a step that keeps the parent's keys, not an insecure
child - see `test_a_ds_denial_above_the_ceiling_keeps_the_parents_keys`.
*/
@(test)
test_a_refused_record_does_not_downgrade_a_readable_denial :: proc(t: ^testing.T) {
	nodes := []Node {
		{"example.", {.NS, .SOA, .RRSIG, .DNSKEY}},
		{"sub.example.", {.NS, .DS, .RRSIG}},
	}
	usable := nsec3_zone(nodes, []u8{0x0a, 0x0b}, 0)
	leaving := nsec3_zone(nodes, []u8{0x0c, 0x0d}, 5000)
	both := make([dynamic]Nsec3_Rr, context.temp_allocator)
	append(&both, leaving[0])
	append(&both, ..usable)

	budget := Nsec3_Budget {
		max_iterations = 100,
	}
	step, _ := denial_step(nil, both[:], "sub.example.", "example.", &budget)
	testing.expect_value(t, step, Step.Bogus)
	free_all(context.temp_allocator)
}
