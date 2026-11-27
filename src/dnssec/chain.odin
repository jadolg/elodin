package dnssec

import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:logx"

// ---------------------------------------------------------------------------
// Walking the chain
// ---------------------------------------------------------------------------

/*
Take a slot for a lookup that is about to go upstream, or report that there is none.

Exact rather than optimistic. Adding first and backing off when the answer turns
out to be no is a line shorter, but every loser inflates the count while it does
so, and losers are what a flood is made of - so walks would be turned away with
slots genuinely free, at exactly the moment the slots matter. The loop below
retries only when somebody else changed the count in between, which is progress
rather than contention.

See `Validator.walks`.
*/
@(private)
take_walk_slot :: proc(v: ^Validator, pool := Walk_Pool.Shared) -> bool {
	for {
		held := sync.atomic_load(&v.walks[pool])
		if held >= v.max_walks[pool] {
			return false
		}
		if _, swapped := sync.atomic_compare_exchange_weak(&v.walks[pool], held, held + 1); swapped {
			return true
		}
	}
}

@(private)
drop_walk_slot :: proc(v: ^Validator, pool := Walk_Pool.Shared) {
	sync.atomic_sub(&v.walks[pool], 1)
}

/*
May this walk go upstream, and if it has not asked before, take the slot that
lets it?

Counted where the answer is no rather than where the slot is refused, so
`queries_shed` is walks that actually stopped: a walk both caches could answer is
refused a slot under a flood and finishes anyway, and counting that would leave
the number moving on a resolver working perfectly.
*/
@(private)
may_look_up :: proc(v: ^Validator, budget: ^Budget) -> bool {
	if budget.holds_walk {
		return true
	}
	if take_walk_slot(v, budget.pool) {
		budget.holds_walk = true
		return true
	}
	// Once per query, not once per walk. A shed query holds no slot, so every
	// walk it goes on to try is refused too - a single question would move the
	// counter five or ten times, and the number an operator reads against a
	// SERVFAIL rise would be several times what happened.
	budget.shed_walk = true
	return false
}

/*
Whether this question's verdict is the shedding, rather than merely a question
that had a walk shed somewhere along the way.

Both are needed. `shed_walk` alone says a slot was refused, which can happen to a
question that then answers perfectly or fails for something else entirely; the
reason alone is a string, and one clobbered assignment would change what a
caller concludes from it. Together they are exact, and they are read here once
rather than by every caller that wants to know.
*/
@(private)
shed_verdict :: proc(budget: ^Budget, result: Result) -> bool {
	return budget.shed_walk && result.reason == WALKS_IN_FLIGHT
}

/*
Count a question the shedding actually cost, once, when its verdict is in.

Not where the slot is refused, which is several times for one question and says
nothing about the outcome: a question can be refused at one signer's walk and
answered `Secure` on the next signature, or have a bonus address hint refused
after the answer is already settled. Both are questions this resolver answered
perfectly, and a number that moved for them would be useless for the one thing
an operator is told to do with it - read it beside a rise in SERVFAIL.

So it counts what that rise is made of: a question left undecided *by* the
shedding, which is what `Result.shed` already means - see `shed_verdict`.
`Bogus` is excluded with `Secure`: the answer was proved forged, and the
shedding is not what settled it.
*/
@(private)
count_shed :: proc(v: ^Validator, result: Result) {
	if result.shed && result.status == .Indeterminate {
		sync.atomic_add(&v.shed, 1)
	}
}

// Give back the slot this walk took, if it took one. Safe to call twice, which
// is what lets `validate` hold the line for any path that walks without going
// through `zone_trust`.
@(private)
end_walk :: proc(v: ^Validator, budget: ^Budget) {
	if budget.holds_walk {
		drop_walk_slot(v, budget.pool)
		budget.holds_walk = false
	}
}

// Walks this validator will have waiting on an upstream at once - the figure in
// force, which is `DEFAULT_MAX_CHAIN_WALKS` when the caller named none. What a
// server reports at start-up, so the log cannot name a number nothing is using.
chain_walk_limit :: proc(v: ^Validator, pool := Walk_Pool.Shared) -> int {
	return v.max_walks[pool] if v != nil else 0
}

/*
Questions in which a chain walk had to stop because the server was already going
upstream for as many as it will. Zero on a resolver that is not being flooded.

Questions rather than walks, which is why it is not named for them: one question
can want a walk per signer and another to the owner, and a question with no slot
is refused at every one of them. Counting those would have a single shed question
read as five or ten.
*/
queries_shed :: proc(v: ^Validator) -> u64 {
	return sync.atomic_load(&v.shed) if v != nil else 0
}

// DNSKEY sets the zone cache refused for size. See `Validator.oversized`.
oversized_key_sets :: proc(v: ^Validator) -> u64 {
	return sync.atomic_load(&v.oversized) if v != nil else 0
}

@(private)
Step :: enum u8 {
	// The child is a signed zone in its own right.
	Secure,
	// No delegation here, so the parent still covers everything below.
	No_Cut,
	// The name is not there at all, so nothing below it is either.
	Absent,
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
	// Cleared on the way in, so that what a caller reads afterwards is this
	// walk's own answer and not one left behind by an earlier proof.
	budget.walk_stopped = ""
	budget.walk_past_ceiling = false
	budget.broken = ""
	budget.broken_lapsed = {}
	/*
	The walk asks for a slot at its first upstream lookup and gives it back
	here. One that never needs a lookup never takes one, so a flood holding
	every slot cannot stop a chain both caches can answer; one that needs a
	lookup it cannot make comes back `Indeterminate`, never insecure - a
	downgrade is the one thing load shedding must not be able to produce.
	*/
	defer if !budget.keep_slot {
		end_walk(v, budget)
	}

	/*
	The walk starts at the closest anchor at or above the name (issue #226),
	which is the root only where nothing closer is anchored. RFC 4035 section
	4.3 makes a chain Secure when it runs "from a trusted security anchor", any
	of them, and RFC 6840 section 5.10 leaves the choice between nested anchors
	to the implementation. This is its Appendix C.1, "Closest Encloser", which
	is what Unbound, BIND, Knot Resolver and PowerDNS Recursor all do: an
	operator who anchors `corp.` has
	pinned that zone's keys, so the public tree's opinion of `corp.` - a DS, or
	a signed proof that there is none - is never asked, and cannot vouch for a
	key the anchor does not name. The cost C.1 itself states: an anchor left
	behind by a key rollover is Bogus for its zone, not rescued by the root.
	*/
	seed := closest_anchor(v.anchors, name)
	seed_status, seed_keys := zone_keys(v, budget, seed, now, allocator)
	if seed_status != .Secure {
		return seed_status, nil, seed
	}

	return walk_down(v, budget, name, seed, seed_keys, now, allocator)
}

/*
`zone_trust`'s walk from `seed`, whose `seed_keys` are trusted, down to `name`:
a step per label (`zone_step`), keeping the keys of each zone cut it proves.
*/
@(private)
walk_down :: proc(
	v: ^Validator,
	budget: ^Budget,
	name: string,
	seed: string,
	seed_keys: []Dnskey,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	trusted: []Dnskey,
	established: string,
) {
	zone := seed
	keys := seed_keys
	depth := label_count(name)
	/*
	Cuts found on the way down, against `MAX_CHAIN_DEPTH` - and not
	`label_count(name)`, which is what it would be spent on if a label were a zone
	cut (issue #352).

	A label is not a zone cut and a name is not a hierarchy. The reverse name of
	an IPv6 address is a nibble per label - thirty-two of them under
	`ip6.arpa.`, thirty-four in all - so every one of them would be past a bound
	of twenty-four before a single DS was asked for, and `Indeterminate` is
	SERVFAIL. That is every IPv6 reverse lookup a resolver with validation on is
	asked, which is what mail servers, `UseDNS` and every logging pipeline do.
	IPv4 reverse names are six labels, so nothing in `in-addr.arpa.` would ever
	show it.

	Nothing about the walk's cost rested on that reading. The round trips are
	`MAX_LOOKUPS_PER_QUERY`, the hashing a denial provokes is
	`MAX_NSEC3_ROUNDS_PER_QUERY`, the signature checks are
	`MAX_VERIFICATIONS_PER_QUERY`, and the loop below is bounded by the wire
	format: a name is 255 octets and a label costs two of them, so nothing
	reaches this with more than 127.

	What the bound is left guarding is what it was written for - a delegation
	hierarchy deeper than any that exists - and running out of it is
	`Indeterminate` rather than `Insecure`, because an allowance of ours ending
	is never this server saying a zone is unsigned.
	*/
	cuts := 0

	for i in label_count(seed) + 1 ..= depth {
		child := name_drop_labels(name, depth - i)
		step, child_keys := zone_step(v, budget, zone, keys, child, now, allocator)
		switch step {
		case .Secure:
			cuts += 1
			if cuts > MAX_CHAIN_DEPTH {
				budget.walk_stopped = CHAIN_UNAVAILABLE
				return .Indeterminate, nil, "."
			}
			zone = child
			keys = child_keys
			// A DS the parent signed: whatever the walk kept keys past above
			// this, what is below is judged against a zone it did read.
			budget.walk_past_ceiling = false
		case .No_Cut:
			/*
			Not a cut, so the walk keeps its keys and keeps going.

			Stopping here instead reads "nothing is delegated at this name" as
			"nothing below this name is delegated either", which is not the same
			statement and not true: an empty non-terminal has no NS and no DS of
			its own and still has zone cuts under it. `seed.btc.petertodd.net.`
			is one of those, under an empty `btc.petertodd.net.`, and stopping
			at `petertodd.net.` leaves every signature that zone makes coming
			from a zone this walk never established - which is refused, so a
			zone the rest of the internet validates comes back SERVFAIL.

			The cost is one DS lookup per label, and how many there are is not
			this server's to choose. `.Absent` below ends the walk at the first
			name the zone does not hold, which for a zone denying the ordinary
			way makes the depth the zone's own rather than the question's - but
			a zone minting its denials under RFC 4470 never says a name is
			absent, so every label of whatever was asked about comes back a
			non-cut and the depth is the client's, up to the 127 labels the
			wire format allows a name.

			`zone_step` remembers non-cuts, which takes the cost of a run that
			repeats down to one walk per name. It does not bound the run: the
			walk descends from the apex, so a question whose *upper* labels are
			fresh misses the memo the whole way down however many times it is
			asked. What bounds that is `MAX_LOOKUPS_PER_QUERY` and nothing
			finer - see the note after `MAX_NON_CUT_TTL` for why no bound on
			the run itself survives contact with `ip6.arpa.`.
			*/
			continue
		case .Absent:
			/*
			Nothing exists at this name, so nothing exists below it and no zone
			cut can be hiding down there: the zone reached so far is the deepest
			one, and the walk is done.

			Asking anyway is what the label-by-label walk above would otherwise
			do, and it is wrong twice over. It turns one client question into a
			blocking DS lookup per remaining label, none of which will ever be
			asked again for a name nobody has. And under NSEC3 it asks about a
			name the denial does not speak for: a name error proves the closest
			encloser and the next closer, so the step below the next closer
			finds neither a match nor a cover, and a zone that validates
			everywhere else comes back `Bogus`.
			*/
			return .Secure, keys, zone
		case .Insecure:
			return .Insecure, nil, child
		case .Bogus:
			if budget.walk_past_ceiling {
				budget.walk_stopped = NSEC3_OVER_CEILING
				return .Indeterminate, nil, child
			}
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

The signatures over the DS set are whatever the DS lookup came back with, so
they are bounded like every other verification: refused for nothing when their
key tag and algorithm name no key of the parent's, and charged to
`MAX_VERIFICATIONS_PER_QUERY` when they are not. A step whose allowance ran out
is one this server did not read, so it is `Indeterminate` rather than a
delegation reported broken.
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
	cached, found, non_cut := cache_get(v, child, walk_began(budget), allocator)
	if found {
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
	// A name already known to be no cut, which is the whole of this step: the
	// walk wants to know whether to keep its keys and keep going, and that is
	// the answer. See `Validator.non_cuts`.
	if non_cut {
		return .No_Cut, nil
	}

	msg, asked, broken := chain_lookup(v, budget, child, .DS, allocator)
	if !asked {
		return .Bogus if broken else .Indeterminate, nil
	}
	unix := u32(time.to_unix_seconds(now))
	// We asked in class IN, and the transport already checked the reply's
	// question against ours; taking the class from the reply would only let it
	// choose which canonical form we build.
	class := dns.Class.IN

	if len(records_of(msg.answer, child, .DS, class, allocator)) > 0 {
		return delegation_step(v, budget, msg, parent, parent_keys, child, class, unix, allocator)
	}

	/*
	No DS, but a CNAME at the name itself, which is how a name that owns one
	answers every type it does not hold (issue #552). A CNAME owner holds no NS
	(RFC 1034 section 3.6.2, RFC 2181 section 10.1), and a parent signs nothing
	at a cut but the DS and NSEC it is authoritative for (RFC 4035 section 2.2),
	so the parent's own signature over it, made at this name and not expanded
	from a wildcard, says the name is data in the parent's zone: no DS, no cut.
	The authority section is no help here - a resolver follows the CNAME, so
	the proof it carries is the target's. Unbound reads it the same way
	(`ds_response_to_ke`), and refuses the CNAME `verified_rrset` refuses.

	A replayed CNAME from before a delegation existed can only keep the walk on
	the parent's keys, which the child's signatures then fail: Bogus, never
	Insecure.
	*/
	cname, _, cname_sig, cname_ok, cname_spent, cname_lapsed := verified_rrset(budget, msg.answer, child, .CNAME, class, parent, parent_keys, unix, allocator)
	if cname_spent {
		return walk_gave_up(budget, exhausted_reason(budget)), nil
	}
	if cname_ok {
		non_cut_remember(v, budget, child, min(rrset_ttl(cname), cname_sig.original_ttl), walk_began(budget), lapses = sig_lapses(cname_sig, unix))
		return .No_Cut, nil
	}

	return ds_denial_step(v, budget, msg, parent, parent_keys, child, class, unix, now, allocator, cname_lapsed), nil
}

/*
`zone_step` once the parent's reply holds a DS set for `child`: the set checked
against the parent's keys, and the child's keys against the set.
*/
@(private)
delegation_step :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	parent: string,
	parent_keys: []Dnskey,
	child: string,
	class: dns.Class,
	unix: u32,
	allocator: mem.Allocator,
) -> (
	step: Step,
	keys: []Dnskey,
) {
	/*
	The parent's word about one child, so checked against the parent's keys
	by `verified_rrset` and held to what it holds every such set to: a
	signer other than the parent does not count, and neither does a
	signature made over `*.<parent>` - see there for the rest of it.
	*/
	ds_records, _, ds_sig, verified, exhausted, ds_lapsed := verified_rrset(budget, msg.answer, child, .DS, class, parent, parent_keys, unix, allocator)
	// A step this server ran out of allowance on is one it did not read,
	// which is `Indeterminate` territory rather than a broken delegation -
	// the same distinction the denial path (`ds_denial_step`) makes.
	if exhausted {
		return walk_gave_up(budget, exhausted_reason(budget)), nil
	}
	if !verified {
		/*
		The third way a delegation appearing at a remembered non-cut shows
		up here, and the one that arrives with records rather than without:
		the first name below the new cut is itself a signed zone, so its DS
		is served and signed by the new zone, and no signature over it
		names the parent the walk established. Same answer as
		`ds_denial_step`'s - give the skipped name back to the lookup.
		*/
		forget_skipped_non_cut(v, parent, child)
		broke_at(budget, child, "the DS set is not signed by any key of its parent, or its signature expanded a wildcard", allocator, ds_lapsed)
		return .Bogus, nil
	}
	// A DS the parent signed, so whatever the walk kept keys past above
	// here, what follows is judged against a zone it did read - a key set
	// that fails it included. See `Budget.walk_past_ceiling`.
	budget.walk_past_ceiling = false

	set, usable := parse_ds_set(ds_records, allocator)

	// Every DS names an algorithm or a digest we cannot check, which RFC
	// 6840 section 5.2 makes an insecure delegation rather than a broken
	// one - the same answer `fetch_keys` gives for a set it reads that way.
	kstatus := Status.Insecure
	child_keys: []Dnskey
	keys_sig: Rrsig
	keys_ttl: u32
	if usable {
		child_keys, kstatus, keys_sig, keys_ttl = fetch_keys(v, budget, child, set[:], unix, allocator)
	}
	switch kstatus {
	case .Insecure:
		cache_put(v, budget, child, .Insecure, nil, min(rrset_ttl(ds_records), ds_sig.original_ttl), walk_began(budget), lapses = sig_lapses(ds_sig, unix))
		return .Insecure, nil
	case .Bogus:
		return .Bogus, nil
	case .Indeterminate:
		return .Indeterminate, nil
	case .Secure:
	}
	// Held to both RRsets the keys rest on and the signatures over them:
	// the parent's over the DS and the zone's own over its DNSKEY set.
	ttl := min(rrset_ttl(ds_records), ds_sig.original_ttl, keys_ttl, keys_sig.original_ttl)
	cache_put(v, budget, child, .Secure, child_keys, ttl, walk_began(budget), lapses = min(sig_lapses(ds_sig, unix), sig_lapses(keys_sig, unix)))
	return .Secure, child_keys
}

// The DS records of `ds_records` this build can read, and whether any names an
// algorithm and digest it can check (`ds_usable`).
@(private)
parse_ds_set :: proc(ds_records: []dns.Record, allocator: mem.Allocator) -> (set: [dynamic]Ds, usable: bool) {
	set = make([dynamic]Ds, 0, len(ds_records), allocator)
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
		usable ||= ds_usable(parsed)
	}
	return
}

/*
`zone_step` once the parent's reply holds no DS for `child`, and no CNAME it
signed there: the step is what the parent's signed denial proves.
`cname_lapsed` is the window a CNAME at the name fell outside, if one did.
*/
@(private)
ds_denial_step :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	parent: string,
	parent_keys: []Dnskey,
	child: string,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
	cname_lapsed: Lapsed,
) -> (
	step: Step,
) {
	// No DS in the answer. The authority section has to say why, and say it in
	// a form the parent signed.
	// Nothing here reaches a client - this is our own DS lookup - so which
	// RRsets verified is of no interest beyond the proof they carry.
	nsecs, nsec3s, proved, ds_spent, ds_lapsed := validated_denial_records(v, budget, msg.authority, parent, class, parent_keys, unix, now, allocator)
	// A chain step this server ran out of allowance on is one it did not read,
	// which is `Indeterminate` territory rather than a broken delegation.
	if ds_spent {
		return walk_gave_up(budget, exhausted_reason(budget))
	}
	// A CNAME the parent signed outside its window is the other thing this
	// reply could have held; one whose current signature failed rules the
	// window out, as a denial set's does. Both broken steps below read this.
	keep_lapse(&ds_lapsed, cname_lapsed)
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		/*
		Nothing to read, and the likeliest reason is the one worth acting on: a
		delegation has appeared at a name the memo still calls no cut, so the
		walk skipped it and this DS question landed inside the child zone. What
		comes back is then signed by the child, `validated_denial_records`
		drops it for not being the parent's, and both slices are empty.
		*/
		forget_skipped_non_cut(v, parent, child)
		broke_at(budget, child, "the reply to the DS question held neither a DS nor a denial signed by the parent", allocator, ds_lapsed)
		return .Bogus
	}

	before := nsec3_refusals(&budget.nsec3)
	cut_short: bool
	step, cut_short = denial_step(nsecs, nsec3s, child, parent, &budget.nsec3)
	/*
	A step whose NSEC3 hashing ran out is one this server did not read to the
	end, which is `Indeterminate` territory rather than anything the records
	said - the same reading `ds_spent` above gets.

	Whatever the step says, not only `.Bogus`. A scan cut short returns "no such
	record", and every reading built on one of those is a reading of our own
	limit: `.Absent` most of all, which ends the walk at this zone and calls it
	`Secure`, leaving a name that really is delegated to be judged against the
	wrong zone's keys and reported to the client as a forgery.
	*/
	if cut_short {
		_, why := nsec3_declined(&budget.nsec3, before)
		logx.debugf("dnssec: the ds denial for %s was not read to the end (%s); the step is undecided", dns.name_trim_root(child), why)
		return walk_gave_up(budget, why)
	}
	/*
	A denial nothing in which could be read, for its iteration count: the walk
	keeps the parent's keys and says it did. See `Budget.walk_past_ceiling`.

	The rcode decides between going on and stopping. It is unsigned, but the
	only thing trusting it can do is end the walk early on the parent's keys,
	which leaves signed data below to verify against the wrong zone and fail -
	a SERVFAIL, which a sender able to forge an rcode could have had anyway.
	Going on past a name the reply says is absent would cost a DS lookup per
	label of whatever a client makes up.

	Neither is remembered: such a denial cannot tell a non-cut from a name
	nobody holds, so every name a client invents under the parent arrives
	here, and remembering each would let a random-subdomain flood push
	everything else out of the memo.
	*/
	if nsec3_all_over_ceiling(nsecs, nsec3s, &budget.nsec3) {
		budget.walk_past_ceiling = true
		return .Absent if dns.rcode_of(msg) == .NX_Domain else .No_Cut
	}
	if step == .Bogus {
		forget_skipped_non_cut(v, parent, child)
		broke_at(budget, child, "the signed denial of a DS proves neither an unsigned delegation nor a name that is not a cut", allocator, ds_lapsed)
	}
	switch step {
	case .Insecure:
		cache_put(v, budget, child, .Insecure, nil, min(negative_ttl(msg), sets_original_ttl(proved)), walk_began(budget), lapses = sets_lapse(proved, unix))
	case .No_Cut:
		/*
		Remembered for the denial's own negative TTL, held to the Original TTL
		and expiration of the signatures that proved it, the way an insecure
		delegation is, and for the same reason: this cost the network a round
		trip and the answer holds until the records it came from expire.

		A non-cut is the expensive one. The walk has to keep going past it - the
		cut may be below - so a run of them is a DS lookup per label waited on
		by the query already answering the client, and uncached every question
		under the name pays the whole run again (#330): a zone with twenty empty
		non-terminals would turn each question into twenty sequential upstream
		queries, and the same shape is what a legitimate deep hierarchy
		costs every time somebody asks about it - `ip6.arpa.` puts a nibble
		label between apexes, so a customer's reverse zone sits several
		non-cuts below its provider's.

		`.Absent` is not remembered, which is the other half of the issue's
		suggestion and deliberately left out. It ends the walk rather than
		continuing it, so it is one lookup rather than a run, and it is reached
		only by names nobody holds - a set the client picks from freely. There
		is nothing to win: the answer cache holds the NXDOMAIN, so the same
		question does not come back here anyway.
		*/
		non_cut_remember(v, budget, child, min(negative_ttl(msg), sets_original_ttl(proved)), walk_began(budget), lapses = sets_lapse(proved, unix))
	case .Secure, .Absent, .Bogus, .Indeterminate:
	}
	return step
}

/*
Read a verified DS denial: is `child` an unsigned delegation, a name that is
not a cut, or a name that is not there at all?

Kept apart from the lookup around it because this is the whole of the decision
and none of it needs a network: the records have already been checked against
the parent's keys, and what is left is what they say.

`cut_short` says this reading could have been different, and it is this step's
own answer rather than the question's: the counts on the budget only go up, so a
step that reached its verdict from NSEC records, from a record it found, or from
hashes kept by an earlier scan would otherwise be thrown away for a refusal that
was never its own.

Which refusal matters depends on what is being decided, and
`nsec3_cut_short` has the reasoning. A step that ends the walk - `.Absent` -
turns on the allowance alone, because a record over the ceiling is one this
server will not read for any question and the zone it can read is the zone it
has. A step that settles nothing carries either, since it is failing whatever
happens and the only thing left to get right is what it is called.
*/
@(private)
denial_step :: proc(
	nsecs: []Nsec_Rr,
	nsec3s: []Nsec3_Rr,
	child, parent: string,
	nsec3_budget: ^Nsec3_Budget,
) -> (
	step: Step,
	cut_short: bool,
) {
	if len(nsecs) > 0 {
		if nsec_proves_no_ds(nsecs, child) == .Proven {
			return .Insecure, false
		}
		if nsec_proves_no_delegation(nsecs, child) {
			return (.No_Cut if nsec_shows_node(nsecs, child) else .Absent), false
		}
	}
	if len(nsec3s) > 0 {
		if nsec3_all_over_ceiling(nsecs, nsec3s, nsec3_budget) {
			/*
			Not `.Insecure`: that would make every name in the zone unsigned to
			the walk, and an unsigned answer forged for any of them would be
			served. The parent's keys are kept instead, so what is signed below
			still has to verify - see `Budget.walk_past_ceiling` for what an
			unsigned answer under this gets.
			*/
			logx.debugf("dnssec: the ds denial for %s is past the nsec3 iteration ceiling; keeping the parent's keys", dns.name_trim_root(child))
			return .No_Cut, false
		}
		before := nsec3_refusals(nsec3_budget)
		// A proof that found what it was looking for is a proof that hashed:
		// nothing refused can return `Proven`, so this one needs no caveat.
		if nsec3_proves_no_ds(nsec3s, child, parent, nsec3_budget) == .Proven {
			return .Insecure, false
		}
		if proven, matched := nsec3_proves_no_delegation(nsec3s, child, parent, nsec3_budget); proven {
			/*
			An NSEC3 zone publishes a record for every empty non-terminal (RFC
			5155 section 7.1), so a name with none of its own is a name that is
			not there. `matched` comes from the scan that proved there is no
			delegation rather than from a third pass over the same records: see
			`nsec3_proves_no_delegation` for what asking twice cost.

			A match is a record found, which no refusal could have produced, so
			`.No_Cut` is this step's answer whatever the meter says. `.Absent`
			is the other half of the same scan finding nothing, which a refusal
			could have produced and which ends the walk, so it carries the
			doubt.
			*/
			if matched {
				return .No_Cut, false
			}
			/*
			The allowance only: a record the ceiling refused is one this server
			will not read for any question, so the records around it are the
			whole of the zone as far as it is concerned, and a walk that ends on
			them ends where it would have ended anyway.

			Which holds while the zone keeps its chains complete, as RFC 5155
			section 7.3 asks of one changing its parameters. A zone whose
			readable chain is missing a name its unreadable one holds ends the
			walk here, and a delegation below is then judged against the
			parent's keys - a broken zone answering SERVFAIL for itself, not
			something anyone else can arrange, and the price of not reading
			every mid-rollover zone as unresolvable.
			*/
			return .Absent, nsec3_cut_short(nsec3_budget, before)
		}
		// Nothing proven either way: a forgery when the records are what they
		// look like, and a decision of ours when a hash was refused while this
		// read. The count says which.
		bogus_declined, _ := nsec3_declined(nsec3_budget, before)
		return .Bogus, bogus_declined
	}
	return .Bogus, false
}

/*
Fetch a zone's DNSKEY set and check it against the DS records the parent
published.

At least one key has to hash to a DS and then sign the whole set, which is what
binds the zone's own keys to its parent.

Finding that key is three nested loops - the DS records, the keys they match,
the signatures over the set - and both the DS records and the signatures are
counts a response chooses, the DS set by padding it with duplicates that survive
the parent's signature and the DNSKEY set by publishing whatever it likes. So
the verification sits inside all three and spends
`MAX_VERIFICATIONS_PER_QUERY`, and a zone whose allowance ran out is
`Indeterminate`: see the note on that return for why it must not be `Insecure`.
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
	// On `Secure`, the signature that vouched for the set and the set's own
	// TTL as received, which with the signature's Original TTL and expiration
	// bound how long the keys are kept (RFC 4035 section 5.3.3).
	vouched: Rrsig,
	set_ttl: u32,
) {
	msg, asked, broken := chain_lookup(v, budget, zone, .DNSKEY, allocator)
	if !asked {
		return nil, .Bogus if broken else .Indeterminate, {}, 0
	}
	class := dns.Class.IN

	records := records_of(msg.answer, zone, .DNSKEY, class, allocator)
	if len(records) == 0 || len(records) > MAX_KEYS_PER_ZONE {
		why := "the DNSKEY reply held no keys" if len(records) == 0 else "the DNSKEY reply held more keys than this server reads"
		broke_at(budget, zone, why, allocator)
		return nil, .Bogus, {}, 0
	}
	parsed := parse_dnskeys(records, allocator)

	sigs := sigs_covering(msg.answer, zone, .DNSKEY, class, allocator)

	/*
	Whether anything in this DS set names something this build can check, which
	is the whole of what makes a delegation insecure.

	RFC 6840 section 5.2 asks about the set: a delegation is insecure when the
	resolver supports *none* of the algorithms the parent published. Asking it
	per record instead - "did some DS name something we cannot check" - is a
	different question with a much larger answer, because a parent is free to
	publish an algorithm we cannot check beside one we can, and every zone
	mid-rollover does. Asked that way, a DNSKEY set that then failed to verify
	against the DS we *could* check would come back insecure rather than bogus,
	which is a tampered DNSKEY response taking a signed zone out of validation -
	and `zone_step` would cache that for the DS TTL, so it would stay out.

	The same pass says whether the SHA-1 records are passed over; see
	`ds_set_reading`.
	*/
	checkable, skip_sha1 := ds_set_reading(ds_set)

	lapsed: Lapsed
	tried := false
	sig, vouch, set_aside := find_vouched_key(budget, zone, ds_set, parsed[:], records, sigs, skip_sha1, unix, allocator, &lapsed, &tried)
	switch vouch {
	case .Verified:
		return parsed[:], .Secure, sig, rrset_ttl(records)
	case .Exhausted:
		/*
		Before the verdict below, and not through it. A DS set with nothing
		checkable in it is insecure however the search above went, so leaving through
		that return when the allowance ran out would let a padded DNSKEY set choose
		`Insecure`, and with it every answer below the zone accepted unvalidated.
		Running out is a statement about this server, so it says so.
		*/
		walk_gave_up(budget, exhausted_reason(budget))
		return nil, .Indeterminate, {}, 0
	case .None:
	}
	return nil, unvouched_verdict(v, budget, zone, checkable, set_aside, tried, lapsed, allocator), {}, 0
}

/*
The first key in `parsed` that a usable DS in `ds_set` matches and that signs the
DNSKEY `records`, with the signature that held (`key_vouches`); `.Exhausted` when
the verification allowance ran out first. `set_aside` says a SHA-1 DS was passed
over (`skip_sha1`, see `ds_set_reading`).
*/
@(private)
find_vouched_key :: proc(
	budget: ^Budget,
	zone: string,
	ds_set: []Ds,
	parsed: []Dnskey,
	records: []dns.Record,
	sigs: []Rrsig,
	skip_sha1: bool,
	unix: u32,
	allocator: mem.Allocator,
	lapsed: ^Lapsed,
	tried: ^bool,
) -> (
	sig: Rrsig,
	vouch: Key_Vouch,
	set_aside: bool,
) {
	class := dns.Class.IN
	// One for the DNSKEY set, however many DS records and keys it is tried
	// under: the set is the same every time.
	scratch := Signing_Scratch{budget = budget}
	for ds in ds_set {
		if !ds_usable(ds) {
			continue
		}
		if skip_sha1 && ds.digest_type == DIGEST_SHA1 {
			set_aside = true
			continue
		}
		for key in parsed {
			if key.tag != ds.key_tag || key.algorithm != ds.algorithm || !key_usable(key) {
				continue
			}
			if !ds_matches(zone, key, ds) {
				continue
			}
			/*
			This one key, and no other. A key tag is a 16-bit fold of the RDATA,
			not an identity: two keys can share one, and an attacker is free to
			make that happen. Offering the whole set here would let a key of
			their own satisfy the signature while the parent's DS went on
			attesting a key that had signed nothing - which is the entire chain
			of trust bypassed in one step.
			*/
			attested := [1]Dnskey{key}
			// The key is vouched for by the parent; now it must vouch for the
			// rest of the set.
			switch sig, vouch = key_vouches(budget, zone, class, records, sigs, attested[:], unix, allocator, &scratch, lapsed, tried); vouch {
			case .Verified, .Exhausted:
				return sig, vouch, set_aside
			case .None:
			}
		}
	}

	return {}, .None, set_aside
}

// What `key_vouches` found for one key `fetch_keys` tries.
@(private)
Key_Vouch :: enum {
	None,
	// A signature by the key held over the DNSKEY set.
	Verified,
	// The verification allowance ran out before one did.
	Exhausted,
}

/*
Whether a signature in `sigs` by the one key of `attested`, made by `zone`,
holds over the DNSKEY `records`; the signature that held, on `.Verified`.
Windows that did not hold go into `lapsed`, and `tried` is set once one in its
window is tried.
*/
@(private)
key_vouches :: proc(
	budget: ^Budget,
	zone: string,
	class: dns.Class,
	records: []dns.Record,
	sigs: []Rrsig,
	attested: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
	scratch: ^Signing_Scratch,
	lapsed: ^Lapsed,
	tried: ^bool,
) -> (
	vouching: Rrsig,
	vouch: Key_Vouch,
) {
	key := attested[0]
	for sig in sigs {
		if sig.key_tag != key.tag || sig.algorithm != key.algorithm {
			continue
		}
		if !dns.name_equal_fold(sig.signer, zone) {
			continue
		}
		// Free rejects first, as everywhere else: a lapsed signature
		// cannot verify, and finding that out costs nothing where
		// canonicalising the DNSKEY set for it does not.
		if !signature_worth_trying(sig, attested, unix) {
			note_lapsed(lapsed, sig, attested, unix)
			continue
		}
		tried^ = true
		/*
		Charged against the query, and charged inside all three loops
		rather than around them: the count here is the DS records that
		match this key multiplied by the signatures the zone published,
		and a response chooses both.
		*/
		if !spend_verification(budget) {
			logx.debugf("dnssec: DNSKEY %s ran out of verifications before a signature held; the zone is undecided", dns.name_trim_root(zone))
			return {}, .Exhausted
		}
		result, _ := check_signature(sig, zone, class, records, attested, unix, allocator, scratch)
		if scratch.over_budget {
			return {}, .Exhausted
		}
		switch result {
		case .Ok:
			return sig, .Verified
		case .Unsupported, .Refused:
			/*
			The DS named an algorithm the table reports as checkable and
			the library declined it anyway, which `probe_algorithms`
			leaves only one way to reach: a policy that turns a key down
			for something about the key rather than the algorithm. Not
			evidence that the parent published nothing we can check, so
			it does not touch `checkable` - the zone comes back bogus,
			which is the direction policy.odin argues for and the only
			one available.
			*/
		case .Bad:
		}
	}
	return {}, .None
}

// The keys of `records` this build can read.
@(private)
parse_dnskeys :: proc(records: []dns.Record, allocator: mem.Allocator) -> [dynamic]Dnskey {
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
	return parsed
}

/*
`fetch_keys`' verdict when no key both matched a DS and signed the DNSKEY set:
broken where the DS set named something this build can check, and insecure where
it named nothing it can. `set_aside` says SHA-1 digests were set aside.
*/
@(private)
unvouched_verdict :: proc(
	v: ^Validator,
	budget: ^Budget,
	zone: string,
	checkable: bool,
	set_aside: bool,
	tried: bool,
	lapsed: Lapsed,
	allocator: mem.Allocator,
) -> Status {
	if checkable {
		// An anchored zone's DS set is its anchors: the walk starts there and
		// never reaches it through its parent (see `closest_anchor`).
		why := "no DNSKEY both matches a DS the parent published and signs the DNSKEY set"
		if dns.name_equal_fold(closest_anchor(v.anchors, zone), zone) {
			why = "no DNSKEY both matches a trust anchor and signs the DNSKEY set"
		}
		if set_aside {
			why = strings.concatenate({why, SHA1_DS_IGNORED}, allocator)
		}
		broke_at(budget, zone, why, allocator, Lapsed{} if tried else lapsed)
		return .Bogus
	}
	return .Insecure
}

// Said beside a bogus verdict reached with SHA-1 records set aside, which a
// key matching one of them would otherwise not explain.
@(private)
SHA1_DS_IGNORED :: "; a SHA-1 DS is ignored beside a SHA-256 or SHA-384 one (RFC 4509 section 3)"

/*
What a DS set offers to `fetch_keys`: whether anything in it names something
this build can check (RFC 6840 section 5.2), and whether its SHA-1 records are
to be passed over because a usable SHA-256 or SHA-384 one sits beside them (RFC
4509 section 3), so a key colliding with a SHA-1 digest cannot stand in for the
key the stronger digest names. A stronger DS whose digest is not its type's
length does not count, as BIND reads the rule.
*/
@(private)
ds_set_reading :: proc(ds_set: []Ds) -> (checkable: bool, skip_sha1: bool) {
	for ds in ds_set {
		if !ds_usable(ds) {
			continue
		}
		checkable = true
		stronger := ds.digest_type == DIGEST_SHA256 || ds.digest_type == DIGEST_SHA384
		if stronger && len(ds.digest) == digest_size(ds.digest_type) {
			skip_sha1 = true
		}
	}
	return
}

/*
The longest DNSKEY RDATA `ds_matches` hashes; a longer key never matches a DS.
Above the largest key the parser accepts - the flags, protocol and algorithm,
a three-byte exponent length, `MAX_EXPONENT_BYTES` and `MAX_MODULUS_BYTES` -
with room for an algorithm it does not parse, which a DS may still name.
*/
@(private)
MAX_HASHED_KEY_RDATA :: 4096
#assert(MAX_HASHED_KEY_RDATA >= 4 + 3 + MAX_EXPONENT_BYTES + MAX_MODULUS_BYTES)

// The largest digest `digest_size` names: SHA-384's.
@(private)
MAX_DIGEST_SIZE :: 48

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

	input_buf: [dns.MAX_NAME_WIRE + MAX_HASHED_KEY_RDATA]u8
	if n + len(key.rdata) > len(input_buf) {
		return false
	}
	copy(input_buf[:], name_buf[:n])
	copy(input_buf[n:], key.rdata)

	computed: [MAX_DIGEST_SIZE]u8
	if !digest(ds.digest_type, input_buf[:n + len(key.rdata)], computed[:]) {
		return false
	}
	return mem.compare(computed[:size], ds.digest) == 0
}

/*
The keys of a zone, from the cache or from the trust anchors.

Only the zone a walk starts at takes the anchor path, which is the closest
anchor above the name (see `closest_anchor`); every other zone reaches this
through `zone_step`, which has a parent to check against.
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
	if cached, found, _ := cache_get(v, zone, walk_began(budget), allocator); found {
		return cached.status, cached.keys
	}

	anchors := make([dynamic]Ds, 0, len(v.anchors), allocator)
	for a in v.anchors {
		if dns.name_equal_fold(a.zone, zone) {
			append(&anchors, a.ds)
		}
	}
	if len(anchors) == 0 {
		walk_gave_up(budget, CHAIN_UNAVAILABLE)
		return .Indeterminate, nil
	}

	unix := u32(time.to_unix_seconds(now))
	fetched, fstatus, vouched, keys_ttl := fetch_keys(v, budget, zone, anchors[:], unix, allocator)
	if fstatus != .Secure {
		return fstatus, nil
	}
	kept := cache_put(v, budget, zone, .Secure, fetched, min(keys_ttl, vouched.original_ttl), walk_began(budget), lapses = sig_lapses(vouched, unix))
	// Only keys that were kept: ones that were not are fetched again by the next
	// walk, which would send the query again with them.
	if kept && v.anchor_keys_cached != nil {
		v.anchor_keys_cached(v.query_ctx, zone, anchor_key_tags(v, zone, allocator))
	}
	return .Secure, fetched
}
