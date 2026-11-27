package dnssec

import "core:crypto"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:logx"
import "elodin:loop"

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

`deadline` is the client question's own, passed through from `validate` for the
query procedure to spend its upstream wait against (issue #439): every lookup a
walk makes is part of the one question. Nil where the caller set none.
*/
Query_Proc :: #type proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
	deadline: ^time.Tick,
) -> (
	wire: []u8,
	ok: bool,
)

/*
Called with `query_ctx` once a trust anchor's keys have been established and
cached, with the anchors' key tags (`anchor_key_tags`): the moment RFC 8145's
Key Tag query is sent at. Not called for keys that did not validate, which are
not cached and are fetched again by the next walk.
*/
Anchor_Keys_Proc :: #type proc(ctx: rawptr, zone: string, tags: []u16)

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
	// Chain walks that may be making upstream lookups at once, for questions
	// counted among the caller's queries in flight and for questions on a
	// connection of their own. Zero takes `DEFAULT_MAX_CHAIN_WALKS`; see
	// `Validator.walks`.
	max_chain_walks:      int,
	max_connection_walks: int,
	// Nil for none; see `Anchor_Keys_Proc`.
	anchor_keys_cached:   Anchor_Keys_Proc,
}

Validator :: struct {
	anchors:              []Trust_Anchor,
	query:                Query_Proc,
	query_ctx:            rawptr,
	anchor_keys_cached:   Anchor_Keys_Proc,
	max_nsec3_iterations: int,
	max_cached_zones:     int,

	mu:                   sync.Mutex,
	zones:                map[string]^Zone_Entry,
	/*
	`zones` in use order, most recent first, so a full cache knows what to drop.

	Emptying it wholesale when it filled would rest on the reasoning that a
	cache of zones fills slowly and refilling it costs a handful of queries.
	Both halves are true of a resolver's own traffic and neither is true under a
	client that picks the names: a flood of fresh delegations fills it as fast
	as it can send, and what the flush throws out is the root and the TLDs that
	every other client's walk starts from - so one client's names would cost
	everyone a re-walk from the top. Issue #336.

	A list rather than a stamp compared across the map, because the choice is
	made on the insert path: walking four thousand entries to find the coldest
	is the one thing a flood must not be able to make expensive. What survives
	here is what is being used, and the root is used by every walk there is.
	*/
	lru_head, lru_tail:   ^Zone_Entry,
	/*
	Names the chain walk found to be no zone cut, against when that stops being
	true. Nothing but an expiry is kept: a non-cut has no keys, and the only
	question asked of it is whether the walk may skip a DS lookup.

	Kept apart from `zones` rather than stored beside them, because what may
	enter the two is not the same. A name reaches `zones` by being delegated,
	which is the parent operator's doing and slow; a name reaches this by being
	descended through, which is the client's doing and as fast as it can send.
	RFC 4470 lets a zone answer a name it does not hold with an NSEC minted for
	the question - a record that says the name is there and carries no NS, which
	is exactly a non-cut - so under a zone serving those, every name anyone asks
	about lands here. One map would have that flood trip the overflow in
	`cache_put`, which frees every zone in it, and the root's keys with them.

	A table of fixed size, indexed by a hash of the name, rather than a map with
	a policy for what to throw out. Every scheme for choosing a victim out of a
	map walks it, and walking it on the insert path is the one thing a flood
	must not make expensive - while a scheme cheap enough not to walk it ends up
	throwing out whatever sits at the front, which under a flood is everything
	worth keeping. Here a name simply owns its slot until another name hashes to
	it, so what survives a flood is what keeps being asked for: a name looked up
	again is put back, and each single-use name the flood inserts threatens one
	slot in a thousand rather than the oldest thing in the map.
	*/
	non_cuts:             []Non_Cut,
	/*
	The offset basis `non_cut_slot` hashes with, drawn once at start-up.

	FNV-1a is published and this table is direct-mapped, so with the standard
	basis anyone could work out offline which names land on which slot and pick
	query names that displace a zone's empty non-terminals on purpose, instead
	of having to flood and hope. A seed nobody outside the process knows takes
	that back to the flood. It is a weak keying of a non-cryptographic hash and
	is meant as no more: nothing here is authenticated, and the worst a
	collision costs is the DS lookup the slot was saving.
	*/
	non_cut_seed:         u32,
	/*
	Chain walks in flight, and the most there may be at once.

	The walk is the one thing in this package that waits on the network on behalf
	of the query it is validating, and it waits once per label: `zone_trust` descends
	from the apex asking a DS per step, and each step that misses both caches is
	an upstream round trip taken in line. Thirty-two of those - what
	`MAX_LOOKUPS_PER_QUERY` allows - is the better part of a second at ordinary
	RTT, and a client choosing names whose *upper* labels are fresh pays that on
	every question however often it asks. Nothing cached can help; the note after
	`MAX_NON_CUT_TTL` says why (#356).

	So the bound is not on the walk but on how many of them may be doing this at
	once - two bounds, one per `Walk_Pool`, because the queries counted in flight
	and the connections are sized by different things and a flood on one must
	not spend the other's allowance. Past the bound, a walk runs against the caches alone and
	answers `Indeterminate` where it would have gone upstream - the same verdict,
	and the same extended error, that an upstream which did not answer produces.
	The flood then holds a fixed number of queries in flight *for a walk* rather
	than all of them: the rest may still be busy with their own upstream forward,
	which nothing here bounds, but they come back in a round trip instead of in
	the thirty a walk may take. That is the difference between a resolver
	degraded and one down.

	A slot is taken at the first lookup that would go upstream, not on the way
	into the walk, so a walk both caches can answer never asks for one and a
	flood holding every slot cannot stop it. Once taken it is held until the
	*question* is answered rather than until that walk ends - see
	`Budget.keep_slot` - so a slot means "a question that has gone upstream for
	a chain and is still being validated", which includes the verifying and
	hashing between its walks. Deliberately: a question that has already spent
	round trips must not be cut off halfway and have them thrown away, and what
	it can spend after the first lookup is bounded by
	`MAX_LOOKUPS_PER_QUERY`, `MAX_VERIFICATIONS_PER_QUERY` and
	`MAX_NSEC3_ROUNDS_PER_QUERY` like everything else.

	What such a flood *does* stop, and it is worth being exact because it is much
	more than it sounds: any walk that needs even one round trip, which is very
	nearly every cold name there is.

	Two steps to that. A cached apex is not a cached name - a name below one
	still costs a DS per label to rule out a cut, and only the non-cut memo makes
	those free - so a hostname nobody has asked for before under a zone this
	resolver knows well is refused.
	`test_a_shed_walk_below_a_warm_apex_still_stops` pins that. And an *unsigned*
	name is refused with it: `zone_step` cannot say `.Insecure` without the DS
	lookup that proves there is no delegation, so a name that would have been
	served insecure comes back SERVFAIL instead.
	`test_a_shed_walk_cannot_tell_an_unsigned_zone_from_a_signed_one` pins that
	one. So while every slot is held, what still answers is what both caches
	hold, and nothing else.

	That is why the bound is a reservation rather than a ceiling, kept for each
	`Walk_Pool` apart. It is still the trade #356 asks for, the alternative being
	every query in flight held and nothing answered at all, and it is why
	`max_chain_walks` is an operator's number rather than only ours.
	*/
	walks:                [Walk_Pool]int,
	max_walks:            [Walk_Pool]int,
	// Questions in which a walk found no slot, for the operator who wants to
	// know why DNSSEC started failing. One per question however many of its
	// walks were turned away - see `may_look_up`. Read through `queries_shed`.
	shed:                 u64,
	/*
	DNSKEY sets refused for size, for the operator who wants to know whether
	anything is trying it. One per `cache_put` that declined to store, which is
	one per chain walk that reached such a zone rather than one per zone.

	Worth a number of its own rather than a log line: the path is reachable by
	anyone who can get a zone of their own validated, so a line per refusal is
	log amplification aimed at whoever reads the logs - the thing
	`Validator.shed` is careful about too. Nothing here is a fault: a refused
	set means the answer was still validated and the zone simply went uncached.
	Read through `oversized_key_sets`.
	*/
	oversized:            u64,

	allocator:            mem.Allocator,
}

/*
Which queries a question is one of, and so which bound it is held to.

Two, because a server bounds two populations by different things. A query on a
fiber of its own - a datagram, an HTTP/2 request, a TCP or DoT query beside its
connection's own place, a refresh - is counted against the server's bound on
queries in flight; one in a connection's own place is not, since there is one
per connection and `max_connections` bounds those. A walk bound that is a share of one of them is wrong for the other:
a share of the queries in flight lets the connections take every walk, and a
share of both leaves the queries in flight with no reserve at all.

Counted apart rather than together for the same reason: a flood on one transport
must not spend the other's allowance.
*/
Walk_Pool :: enum u8 {
	// Counted among the server's queries in flight: UDP, HTTP/2, TCP and DoT
	// beside a connection's own place, refreshes.
	Shared,
	// In a connection's own place: one per TCP or DoT connection, and every
	// HTTP/1.1 query.
	Connection,
}

// One slot of `Validator.non_cuts`. An empty `name` is a free slot; a name is
// owned by the table and released when the slot is reused.
@(private)
Non_Cut :: struct {
	name:    string,
	expires: loop.Moment,
}

@(private)
Zone_Entry :: struct {
	// Owns the string the map is keyed by, so replacing an entry can hand the
	// same allocation back to the map rather than leave one of them dangling.
	zone:       string,
	status:     Status,
	keys:       []Dnskey,
	/*
	On the moment clock rather than the wall clock the walk checks signatures
	against (issue #557): a step of the wall clock would otherwise expire every
	zone at once, or keep keys and DS past their TTL for the length of the step.
	The signatures' own lapse is read off the wall clock once, when they are
	accepted, and arrives here as a duration - see `cache_put`.
	*/
	expires:    loop.Moment,
	// This entry's place in the eviction order `Validator.lru_head` heads.
	// Every removal from `zones` goes through `drop_zone`, so the list and the
	// map cannot come to disagree about what is held.
	prev, next: ^Zone_Entry,
}

/*
Zone cuts one chain may have between the root and the name asked about.

Cuts, not labels: a name with many labels is ordinary - `ip6.arpa.` puts one
nibble in each, so a reverse name for an IPv6 address has thirty-four - while a
delegation hierarchy this deep is not a shape anything in use has. Counting the
question's labels here instead would refuse every IPv6 reverse lookup (#352);
`zone_trust` has the whole of it.
*/
MAX_CHAIN_DEPTH :: 24

/*
DS and DNSKEY lookups one client question may provoke, in total.

The chain depth alone does not bound the work: a response is free to carry
records under many different owner names, each naming a different signer, and
validating every one of them would have the resolver walk a chain apiece. That
turns one question into hundreds of upstream queries, with a query held in flight
for all of them. Real answers need a handful, so a response that needs more than this is
answered with SERVFAIL rather than chased.
*/
MAX_LOOKUPS_PER_QUERY :: 32

/*
Signatures kept beside one RRset when the response is pruned.

Not an attempt limit: `validate_rrset` and `verified_rrset` both spend
`MAX_VERIFICATIONS_PER_QUERY` instead, since a per-RRset cap is one an
attacker could fill. What is left is what `strip_unauthenticated` will hand on
besides the signature that actually verified, which is exempt - a set carries
one signature per algorithm in practice, and more than this is padding aimed at
whatever validates downstream.
*/
MAX_SIGNATURES_PER_RRSET :: 8

// CNAME hops followed when checking that an answer addresses the question.
// Real chains are one or two; anything past this is a loop or a stall.
MAX_CNAME_CHAIN :: 16

/*
Targets one answer may have its address hints authenticated for.

RFC 9460 section 5 has an authoritative server send the A and AAAA records for
an HTTPS, SVCB, SRV or MX target beside the answer, so that a client can connect
without asking again. `validated_hints` keeps the ones that hold up, and holding
one up means establishing the zone that signed it - which for a target outside
the zone the answer established is a chain walk of its own. The number of
targets is the sender's to choose, so the walks need a bound that is not.

Eight is past every answer of this shape that anyone serves: an HTTPS answer
names one target, an SRV set a handful, and an eight-exchange MX set is a large
one. A target past the bound keeps no hints - a round trip for the client, not a
wrong answer - so erring small
costs little and erring large costs upstream queries somebody else picked. The
eight that are inside it keep theirs, and which eight those are is the order the
sender wrote its answer section in: a response naming more than eight decides
which of its targets a client is spared a lookup for, and can decide it badly,
but every one it picks is still authenticated before anything is kept.

The query budget is the other bound and the one that holds when this is not
enough: the walks spend `MAX_LOOKUPS_PER_QUERY` and
`MAX_VERIFICATIONS_PER_QUERY` like everything else. Hints are authenticated last
for that reason - what they spend is what the answer and its wildcard proofs did
not need, and a hint that runs the allowance out is dropped rather than allowed
to change the verdict the answer already earned.
*/
MAX_HINT_TARGETS :: 8

// Keys a zone may publish. Far past any real zone, and it bounds both the
// canonical form built over the set and what the cache then holds on to.
MAX_KEYS_PER_ZONE :: 64

/*
Keys one signature may be tried against.

`MAX_VERIFICATIONS_PER_QUERY` counts calls into `check_signature`, and that is a
bound on the crypto only if a call means a verification. Without this it does
not: a key tag is a 16-bit checksum over the RDATA rather than an identity, so a
signature naming one may name several keys, and `check_signature` has to try
each of them because any could be the one that made it. Every further key
sharing the tag is another full verification charged to nobody, so the query
budget would be bounding `MAX_KEYS_PER_ZONE` times what it counted.

The multiplier is the zone's to choose, and it needs no cleverness: nothing
requires a DNSKEY RRset's records to be distinct, so sixty-four copies of one
key does it, and grinding a decoy key to a chosen tag is a few thousand hashes
in any case. That is the collision half of KeyTrap (CVE-2023-50387), the half a
bound on attempts does not reach.

Four is far past what an accident produces - a tag collision falls out about
once in sixty-five thousand key pairs, and a zone mid-rollover publishes a
handful of keys in total - so the trade this makes is the one
`MAX_VERIFICATIONS_PER_QUERY` already describes, and a safer one: padding the
key set has to survive the zone's own self-signature and the DS above it, so
only the zone's owner can put it there, and only against their own zone.
*/
MAX_KEYS_PER_SIGNATURE :: 4

/*
What one call to `validate` is allowed to spend.

Carried down the whole walk rather than kept on the validator, because the limit
is per client question: two queries arriving at once each get their own.
*/
@(private)
Budget :: struct {
	lookups:       int,
	verifications: int,
	/*
	Why the walk gave up, written where it gave up.

	`zone_trust` reports one `Indeterminate` for every allowance a walk can run
	out of, and what a client is told about it - the extended error on the
	answer - comes from the reason beside it. Working that out afterwards from
	the counters gets it wrong, because a step can be refused a hash and decide
	anyway: a zone mid-rollover raises the NSEC3 count at one label and a
	lookup fails five labels later, and the counters then say the hashing did
	it. So each place that gives up says so in its own words, the last writer is
	the step that stopped the walk, and `zone_trust` clears it on the way in so
	nothing older can be read as this walk's.
	*/
	walk_stopped:  string,
	/*
	The first step of this question's walk to be called broken, as the zone and
	what was wrong at it, for the log. `Result.detail` carries it out.

	Not `walk_stopped`: that is the reason a client is sent, which names an
	allowance and is deliberately the same from one zone to the next. This is the
	one thing an operator reading "broken chain of trust" has no other way to
	learn, and the first writer wins because the step that broke the walk is the
	one that matters - what is tried after it is a consequence.
	*/
	broken:        string,
	// The window the signatures of the step in `broken` fell outside, if that
	// is why it broke. Written and cleared with it.
	broken_lapsed: Lapsed,
	/*
	This walk kept a parent's keys past a DS denial it could not read, because
	every NSEC3 record in it was above the iteration ceiling (issue #331).

	Such a step cannot tell a name that is not a cut from an unsigned
	delegation, so the walk carries on as though it were not one: signed data
	below still has to verify, and a denial of the name itself is what gets
	served insecure. What it must not do is let an *unsigned* answer or a
	broken step below be judged as if the parent had been read - calling the
	first insecure is a forgery served, calling either bogus accuses the zone
	of our refusal. Both are `Indeterminate` with the ceiling named instead.
	The same goes for a denial that proves
	nothing. Cleared with `walk_stopped`, and at a signed cut below the step.
	*/
	walk_past_ceiling: bool,
	/*
	Whether this walk holds one of `Validator.walks`.

	Taken at the first lookup that would go upstream rather than on the way into
	`zone_trust`, so a walk the caches can answer never asks for one - and kept
	for the rest of the walk once taken, because a walk that has already spent a
	round trip must be allowed to finish rather than stopped halfway, which
	would spend the upstream traffic and get nothing back for it.

	On the budget rather than on the validator because the slot belongs to this
	walk. `zone_trust` gives it back on the way out, so a later walk in the same
	query - a second signer, an address hint - asks for its own.
	*/
	holds_walk:    bool,
	/*
	Whether any walk of this query was turned away for want of a slot.

	Sticky, where `holds_walk` is not, and read by `validate_rrset` before it
	reports a set forged. A signature whose signer this server could not walk to
	is skipped rather than tried, and a later walk in the same query can still
	succeed - the flood ebbs, a slot frees - which would leave the set judged on
	the signatures that were tried and called a forgery on the strength of one
	that was not.

	It costs the precision of the extended error on answers that fail anyway:
	`Bogus` and `Indeterminate` are both SERVFAIL, so what changes is code 6
	against code 22 and the words in the log. Refusing to accuse a zone of
	forgery while this server is refusing itself lookups is worth that.
	*/
	shed_walk:     bool,
	/*
	Whether the slot outlives each walk, which is the caller saying it will give
	it back itself.

	`validate` sets this, because the verdict is the query's and not any one
	walk's: one answer can need a walk per signer and another to the owner, and
	a query whose first walk spent real round trips must not have its second
	turned away and the traffic thrown out - the whole answer is SERVFAIL either
	way. Holding it across the query costs no extra round trips, since
	`MAX_LOOKUPS_PER_QUERY` bounds those whatever the slot does, and it makes the
	slot mean what the bound is about: a query inside a validation that has gone
	upstream.

	Left unset by a caller that walks on its own - the tests do - so each walk
	there gives its slot back on the way out and nothing has to be released by
	hand.
	*/
	keep_slot:     bool,
	// Which queries this question is one of, and so which of
	// `Validator.max_walks` bounds it. See `Walk_Pool`.
	pool:          Walk_Pool,
	// The hashing a denial proved with NSEC3 may spend, which no count of
	// lookups or verifications bounds: see `MAX_NSEC3_ROUNDS_PER_QUERY`.
	nsec3:         Nsec3_Budget,
	/*
	The request's running total of what it has taken out of its arena reading
	messages and rendering the canonical forms signatures are checked against
	(see `Signing_Scratch`), against `dns.REQUEST_DECODE_BUDGET`, or nil where
	nobody is counting.

	The walk reads a reply of its own per step into the arena the request is
	served from, up to `MAX_LOOKUPS_PER_QUERY` of them, and each of those
readings is bounded only by its own length. Borrowed from the caller
	that owns the arena, so what this walk takes is charged against what the
	rest of the request already has. See issue #354.
	*/
	spent:         ^int,
	// The client question's upstream deadline, borrowed from the caller like
	// `spent` and handed to every lookup. See `Query_Proc`.
	deadline:      ^time.Tick,
	/*
	Which allowance the last signature loop to stop early ran out of, in the
	words `exhausted_reason` reports it with. Written where the loop stops, as
	`walk_stopped` is, rather than worked out afterwards: by then a reading may
	have taken the request past its budget in a loop that stopped for want of
	verifications, and the two would read the same.
	*/
	ran_out:       string,
	/*
	The walk's `now` on the zone cache's clock: `query_budget` reads it, and
	`validate` sets it back to the whole second `now` falls in. A signature's
	lapse is counted from that second, so an entry is timed from the same
	instant: timed from when its step finished, it would outlive the signature
	by however long the walk had run by then.

	The walk reads the cache at this instant too, as it checks every signature
	at `now`: an entry it stored is live for the rest of the walk, however short
	its lifetime, rather than missed and walked for again by the next proof.
	*/
	began:         loop.Moment,
	/*
	Set where an allocation of this question's is refused, or nil where nobody
	is watching. A walk that ran dry may have judged a set an append dropped a
	record from, so nothing it settles is cached; `validate` reports the whole
	question undecided.
	*/
	dry:           ^bool,
	/*
	The temp allocator the question came with, under `validate`'s watch, or
	zero where nobody is watching. `look_up` hands it back to a lookup made off
	a loop; see there.
	*/
	scratch:       mem.Allocator,
}

/*
Ask `v.query` for `name`. On a loop, under the watch: what the lookup starts
runs on the loop's fibers, with the loop's context, and a lookup refused memory
is this server's failure rather than an unreachable chain. Off a loop, with the
temp allocator the question came with (`Budget.scratch`): there what it starts
- a race's legs - runs on threads with the caller's context, and would hold the
watch past `validate`'s frame.
*/
@(private)
look_up :: proc(v: ^Validator, budget: ^Budget, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	// Not in an `if`: a context assignment lasts only to the end of its block.
	unwatched := loop.current_loop() == nil && budget.scratch.procedure != nil
	context.temp_allocator = budget.scratch if unwatched else context.temp_allocator
	return v.query(v.query_ctx, name, type, allocator, budget.deadline)
}

// Whether this question has been refused memory; see `Budget.dry`.
@(private)
ran_dry :: proc(budget: ^Budget) -> bool {
	return budget != nil && budget.dry != nil && budget.dry^
}

// `Budget.began`, or the clock for a budget built without one.
@(private)
walk_began :: proc(budget: ^Budget) -> loop.Moment {
	return budget.began if budget.began != 0 else loop.moment_now()
}

/*
Why a walk stopped when the server was already walking as many chains as it will.

Shared rather than written twice, for the same reason `NSEC3_OVER_CEILING` is:
the words reach the client as RFC 8914 extra text, beside code 22, which is what
an upstream that did not answer gets. That is the honest report - this server
stopped looking, so nothing about the zone was established - and it must not
quietly become `DNSSEC Bogus`, which would accuse the zone of a forgery the
resolver's own load shedding invented.
*/
WALKS_IN_FLIGHT :: "too many chains of trust being walked at once"

/*
Why a step stopped when the request had already taken what it may to read what
it was sent.

A reading refused for `dns.REQUEST_DECODE_BUDGET`, or for the memory to hold it
(`dns.reading_refused`), or any allocation of the validation refused (see
`validate`), is this server declining to read any more of what it
was sent, so the step established nothing - the same report an unanswered lookup
gets, code 22, and deliberately not `Bogus`. The reply may be perfectly genuine;
what ran out is ours. See issues #354 and #620.
*/
READING_OVER_BUDGET :: "this query has taken as much as it may to read what it was sent"

/*
Why a step stopped when the client question had no upstream waiting left.

The question's own deadline (issue #439), which the query procedure would refuse
anyway without asking anybody - so said here, before a lookup is spent or a slot
taken, in words that name this server's limit rather than "chain of trust
unavailable", which reads as the upstream failing. The upstream did spend the
time; what ran out is ours.
*/
DEADLINE_PASSED :: "this query has waited as long as it may on its upstreams"

// Whether the question's deadline is set and has passed. See `DEADLINE_PASSED`.
@(private)
deadline_passed :: proc(budget: ^Budget) -> bool {
	return budget.deadline != nil && budget.deadline^ != {} && time.tick_diff(loop.tick_now(), budget.deadline^) <= 0
}

/*
Why a walk that came back `Indeterminate` stopped, in the words of the step that
stopped it.

`CHAIN_UNAVAILABLE` is the fallback and the truth for most of them - a
lookup that could not be made, a parent that did not answer. The allowances can
be said more precisely, and saying them is worth a line, because this reason is
what picks the extended error the client is handed: the walk is where a zone
whose NSEC3 iteration count is past the ceiling is met first, since every name
inside one reaches its DS denial before the answer's own proof is read, so
without this the precise code would be the one nobody ever sees.
*/
@(private)
walk_reason :: proc(budget: ^Budget) -> string {
	return budget.walk_stopped if budget.walk_stopped != "" else CHAIN_UNAVAILABLE
}

// The reason of a verdict that a step of the chain of trust produced.
BROKEN_CHAIN :: "broken chain of trust"

/*
The other reasons more than one path gives, named once like `BROKEN_CHAIN`.

`CHAIN_UNAVAILABLE` is the fallback `walk_reason` gives (see there), and
`LOOKUPS_SPENT` is a walk out of `MAX_LOOKUPS_PER_QUERY`, whichever question
the last lookup was for. Both go out as RFC 8914 extra text beside code 22. The
rest are the verdicts a proof reaches: an unsigned zone and an opt-out span
(RFC 5155 section 6) are `Insecure`, a wildcard expansion or denial left
unproven (RFC 4035 section 5.4) is `Bogus`, and a response with nothing in it
to check is `Insecure`.
*/
CHAIN_UNAVAILABLE :: "chain of trust unavailable"
LOOKUPS_SPENT :: "lookup budget spent"
UNSIGNED_ZONE :: "unsigned zone"
OPT_OUT_SPAN :: "opt-out span"
WILDCARD_NOT_PROVEN :: "wildcard expansion not proven"
DENIAL_NOT_PROVEN :: "denial of existence not proven"
NOTHING_TO_AUTHENTICATE :: "nothing to authenticate"

// Say which step of the walk broke, for the log only: the first call in a walk
// wins, since what is tried after the step that broke is a consequence of it.
// `lapsed` is the window its signatures fell outside, when that is why.
@(private)
broke_at :: proc(budget: ^Budget, zone, why: string, allocator: mem.Allocator, lapsed := Lapsed{}) {
	if budget.broken != "" {
		return
	}
	shown := dns.name_trim_root(zone)
	budget.broken = strings.concatenate({shown if shown != "" else ".", ": ", why}, allocator)
	budget.broken_lapsed = lapsed
}

/*
A signature that would have been tried but for its validity period.

RFC 8914 has a code for each side of it - 7, Signature Expired, and 8, Signature
Not Yet Valid - for when "no signatures are presently valid" and some lapsed or
have yet to start. That is the one DNSSEC failure whose cause is usually this
side of the wire: a resolver whose clock is wrong refuses every signature minted
inside the drift, and an operator told "broken chain of trust" has no reason to
look at the clock. So the instant is kept, and the reason names it.

Only a signature naming a key its zone published counts - one
`signature_worth_trying` would otherwise have spent a verification on - so noise
in the RRSIGs of a response cannot put a window on a set it did not otherwise touch. And it
is reported only for a set that nothing in its window was tried for: a set that
had a current signature and failed it is a signature that does not verify, and
that is code 6 whatever lapsed beside it.
*/
Lapsed :: struct {
	window: Sig_Window,
	// The expiration of an expired signature, the inception of one not yet valid.
	at:      u32,
	// Set by `verified_rrset` on a set whose signature inside its window was
	// tried and failed, and passed on by `validated_denial_records`, so a
	// proof missing that set rests on a signature that does not verify rather
	// than on a window. `window` is then `.Current`.
	refuted: bool,
}

/*
Note `sig` in `lapsed` if it is one: outside its window, and naming one of `keys`.

Not yet valid is kept over expired when a set carries both. RFC 8914 fits either
code to that set, and a signature from the future is the one that says a clock
is behind - which is the reading an operator can act on. On one side, the
instant nearest `now` is kept: the latest expiration, the earliest inception,
which is when the set would be current again.

A window that ends before it starts is no lapse: no clock makes that signature
current, so it is one that does not verify, which is code 6.
*/
@(private)
note_lapsed :: proc(lapsed: ^Lapsed, sig: Rrsig, keys: []Dnskey, unix: u32) {
	window := signature_window(sig, unix)
	this := Lapsed {
		window = window,
		at     = sig.inception if window == .Not_Yet_Valid else sig.expiration,
	}
	if !lapse_outranks(this, lapsed^) || !serial_ge(sig.expiration, sig.inception) {
		return
	}
	if names_usable_key(sig, keys) {
		lapsed^ = this
	}
}

// Keep the one of two lapses `note_lapsed` would, across the sets of one proof.
// A refuted set rules the window out for the whole proof, so `refuted` sticks.
@(private)
keep_lapse :: proc(lapsed: ^Lapsed, other: Lapsed) {
	switch {
	case lapsed.refuted:
	case other.refuted:
		lapsed^ = {refuted = true}
	case lapse_outranks(other, lapsed^):
		lapsed^ = other
	}
}

@(private)
lapse_outranks :: proc(this, over: Lapsed) -> bool {
	switch {
	case this.window == .Current:
		return false
	case this.window != over.window:
		return over.window != .Not_Yet_Valid
	case this.window == .Expired:
		return !serial_ge(over.at, this.at)
	}
	return !serial_ge(this.at, over.at)
}

/*
Whether a verdict of `status` takes the reason from the one standing at `worst`.

A worse verdict always does. At `Bogus` beside `Bogus`, one resting on no window
takes it from one resting on a window: RFC 8914 codes 7 and 8 are for when "no
signatures are presently valid", and a set whose signature inside its window
failed is a forgery in the same message, whichever came first in it. Between
two lapses the one `note_lapsed` would keep takes it, so the code and the
instant do not depend on the order the sender chose either.
*/
@(private)
takes_reason :: proc(worst, status: Status, held, offered: Lapsed) -> bool {
	if worse(worst, status) != worst {
		return true
	}
	return(
		worst == .Bogus &&
		status == .Bogus &&
		held.window != .Current &&
		(offered.window == .Current || lapse_outranks(offered, held)) \
	)
}

/*
The reason a verdict resting on `lapsed` is given, naming the instant.

The RRSIG fields are serial numbers (RFC 4034 section 3.1.5), so the instant is
the one nearest `now` that they name.
*/
@(private)
lapsed_reason :: proc(lapsed: Lapsed, now: time.Time, allocator: mem.Allocator) -> string {
	unix := time.to_unix_seconds(now)
	at := time.unix(unix + i64(i32(lapsed.at - u32(unix))), 0)
	stamp, stamped := time.time_to_rfc3339(at, include_nanos = false, allocator = allocator)
	switch lapsed.window {
	case .Expired:
		return strings.concatenate({"signature expired at ", stamp}, allocator) if stamped else "signature expired"
	case .Not_Yet_Valid:
		return strings.concatenate({"signature not yet valid until ", stamp}, allocator) if stamped else "signature not yet valid"
	case .Current:
	}
	return ""
}

// Give up on a step, saying why. The words reach the client as an extended
// error, so they are the ones an operator would want to read first.
@(private)
walk_gave_up :: proc(budget: ^Budget, reason: string) -> Step {
	budget.walk_stopped = reason
	return .Indeterminate
}

/*
Ask the upstream for `name`'s `type` (DS or DNSKEY) as a step of the walk, and
decode the reply. `asked` false means the step established nothing, and says
why: either the reason is written (`walk_gave_up`), or the reply would not
decode and the step is recorded `broken` (`broke_at`).

The reasons are the deadline, this server's own shedding, the lookups or the
request's reading allowance spent - a reply it had no allowance left to read is
unread, not forged - and an upstream that did not answer, or answered with an
error rcode. An error carries no records, so it finds neither a delegation nor
keys, which the checks after this would read as a proof stripped; but it is a
statement about the upstream, not about the zone, and reporting it as a forgery
would have every hiccup below a signed parent come back as a DNSSEC failure.
`validate` reads the same rcodes the same way on the response it validates.
*/
@(private)
chain_lookup :: proc(
	v: ^Validator,
	budget: ^Budget,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	msg: dns.Message,
	asked: bool,
	broken: bool,
) {
	if deadline_passed(budget) {
		walk_gave_up(budget, DEADLINE_PASSED)
		return
	}
	if !may_look_up(v, budget) {
		walk_gave_up(budget, WALKS_IN_FLIGHT)
		return
	}
	if !spend_lookup(budget) {
		walk_gave_up(budget, LOOKUPS_SPENT)
		return
	}
	wire, ok := look_up(v, budget, name, type, allocator)
	if !ok {
		walk_gave_up(budget, CHAIN_UNAVAILABLE)
		return
	}
	derr: dns.Decode_Error
	msg, derr = dns.decode_message(wire, allocator, budget.spent)
	if derr != .None {
		if dns.reading_refused(derr) {
			walk_gave_up(budget, READING_OVER_BUDGET)
			return {}, false, false
		}
		broke_at(budget, name, "the DS reply could not be decoded" if type == .DS else "the DNSKEY reply could not be decoded", allocator)
		return {}, false, true
	}
	if !answerable_rcode(msg) {
		walk_gave_up(budget, CHAIN_UNAVAILABLE)
		return {}, false, false
	}
	return msg, true, false
}

/*
What one client question starts with.

The counters begin at zero and the NSEC3 ceiling comes from the validator, which
is the one field a `Budget{}` cannot supply for itself. Made here rather than at
the call site so that the ceiling an operator configured cannot be dropped on the
way to the proof that reads it: an allowance built without it refuses every
record asking for any iterations at all, which fails closed and fails loudly
rather than quietly validating at a number nobody chose.
*/
@(private)
query_budget :: proc(v: ^Validator) -> Budget {
	return {nsec3 = {max_iterations = v.max_nsec3_iterations}, began = loop.moment_now()}
}

/*
Signature checks one client question may provoke, in total.

A per-RRset cap cannot do this job, and having one would be a way to break a
zone: a signature is only tried when its signer names a zone in the owner's
ancestry, but the signer is a name in the RDATA and anyone able to add records
can write it. Eight forgeries at the head of an RRset would spend the whole
per-RRset allowance before the genuine signature was reached, the set would be
dropped, and the answer would come back Bogus - a denial's RRset taking every
NXDOMAIN in the zone with it. Such a cap could only ever be filled by signatures
an attacker chose; the genuine one is what it would keep out.

Counted across the question instead, and spent only on signatures that could
actually verify - see `signature_worth_trying`, which refuses the rest for
nothing. Every verification a question can reach comes from here, at three call
sites: `validate_rrset` for an answer's own RRsets, `verified_rrset` for a
denial's proof and for the DS set and CNAME `zone_step` reads, and the RRSIGs
over a DNSKEY set in `fetch_keys`. The chain walk's sets come out of a response,
so the length of their signature list is whoever answered the lookup's to
choose, and `MAX_LOOKUPS_PER_QUERY` allows 32 such lookups per question (#193).

One budget for all three, so no path keeps a private allowance that can be
emptied on its own - and so the chain walk shares what it spends with the
answer. That is deliberate, and it costs something: a padded DS set early in a
walk can exhaust what a later step needs and leave a resolvable name
Indeterminate. It is the trade the paragraph below describes, made once more -
an attacker who can pad a response can already deny the answer by corrupting it
- and the alternative, an allowance per step, is a bound that multiplies by the
step count and so is not much of a bound. The room is there for real traffic: a
set carries one signature per algorithm and the first one tried is the one that
verifies, so a genuine chain spends about one verification per lookup and a
whole question far less than this.

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
Signature checks a query makes between giving its loop to the other fibers on it.

A check is CPU and never waits, so a walk that reaches the budget without a
lookup in between would hold its loop for all of them - 64 checks at the 40 us an
Ed25519 one takes here is 2.6 ms - while every other query on the loop, cache
hits included, waits behind it: nothing preempts a fiber, so the turn has to be
given. Four is at most ~160 us between turns; a turn costs about a microsecond, which
before every check would be a tenth of the cheapest one (RSA-2048, 8 us).
*/
VERIFICATIONS_PER_TURN :: 4

/*
Whether a signature could verify at all, decided without doing any crypto.

Every signature reaching a verification is one an attacker may have written, so
the useful question before spending anything on one is whether it stands a
chance. Two things answer it for free: a signature outside its validity window
cannot verify, and neither can one whose key tag and algorithm name no key the
zone published.

That is what keeps the budgets below from being an attacker's to spend. A
forgery has to name a key tag the zone actually has - and the tag is public, so
this is a cost rather than a wall - where otherwise any sixteen bytes of noise
with the right owner name would be enough to consume an attempt.

Deliberately the same test `check_signature` makes internally, hoisted out. It
stays there too: this one decides whether to spend, that one decides the result,
and a caller reaching the second without the first is answered correctly, just
more expensively.
*/
@(private)
signature_worth_trying :: proc(sig: Rrsig, keys: []Dnskey, unix: u32) -> bool {
	return signature_current(sig, unix) && names_usable_key(sig, keys)
}

// Does `sig` name one of `keys` that may sign: same tag, same algorithm, usable?
@(private)
names_usable_key :: proc(sig: Rrsig, keys: []Dnskey) -> bool {
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
		budget.ran_out = VERIFICATIONS_SPENT
		return false
	}
	budget.verifications += 1
	if budget.verifications % VERIFICATIONS_PER_TURN == 0 {
		loop.yield()
	}
	return true
}

// Why a signature loop stopped when the question had spent
// `MAX_VERIFICATIONS_PER_QUERY`.
VERIFICATIONS_SPENT :: "verification budget spent"

/*
Which of this server's own allowances a signature loop ran out of: the
verification count, or the request's reading budget, which the canonical form
each signature is checked against is charged to as well (see `Signing_Scratch`).
Either way the answer is `Indeterminate`; the words are what tell them apart.
*/
@(private)
exhausted_reason :: proc(budget: ^Budget) -> string {
	return budget.ran_out if budget.ran_out != "" else VERIFICATIONS_SPENT
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

/*
Key bytes one zone may occupy in the cache.

`max_cached_zones` bounds the entries and says nothing about their size, and the
size is the zone's to choose: `fetch_keys` admits `MAX_KEYS_PER_ZONE` records
and the RSA parser reads up to `MAX_MODULUS_BYTES` plus `MAX_EXPONENT_BYTES` of
each, so one apex could hand this cache about 96 KB - times the entry bound,
more memory than the machine. Issue #336.

Eight kilobytes is past every apex anyone serves. The largest key in use is
RSA-4096 at some 520 bytes of RDATA, and a zone mid-rollover publishes a KSK and
two ZSKs; fifteen of those still fit. Only keys that survive `key_usable` are
counted, since those are the only ones any signature check will look at.

A zone past it is not cached rather than cached short. Truncating the set is the
one thing that must not happen here: which keys were dropped decides which of
the zone's signatures still verify, so a zone with an unusual number of large
keys would go SERVFAIL for as long as the entry lived, and go there quietly.
Declining the entry costs that zone a chain walk per question - what any cold
name costs - and costs everybody else nothing.

This counts RDATA and nothing else, so it is not what an entry costs. See
`MAX_CACHED_ZONE_BYTES` for the figure to size a machine against.
*/
MAX_CACHED_ZONE_KEY_BYTES :: 8192

/*
What one entry costs at worst, which is the number to multiply by
`max_cached_zones`.

`MAX_CACHED_ZONE_KEY_BYTES` bounds the RDATA and the RDATA is not the whole of
it: each key carries a `Dnskey` beside its bytes, and a zone may publish
`MAX_KEYS_PER_ZONE` of them - 64 small keys fit under the byte cap as readily as
three large ones - so the structs alone are three kilobytes on top. Then the
entry itself, and the name it is keyed by, which is bounded by
`dns.MAX_NAME_PRESENTATION` rather than by the couple of dozen bytes a real apex
spells: presentation form escapes a byte as `\DDD`, so the worst name is four
times the wire limit. It comes to about twelve kilobytes, and the RDATA the
other constant bounds is two thirds of it.

Written down because the cache's whole purpose here is to be sized by an
operator, and a figure that leaves out a third of what it measures is worse than
none. The map's own slot is not in it: what a `map` spends per key belongs to
the runtime rather than to this, and it is small beside the rest.
*/
MAX_CACHED_ZONE_BYTES ::
	MAX_CACHED_ZONE_KEY_BYTES +
	MAX_KEYS_PER_ZONE * size_of(Dnskey) +
	size_of(Zone_Entry) +
	dns.MAX_NAME_PRESENTATION

/*
Slots in the non-cut table.

Smaller than the zone cache and fixed rather than configurable, because this
holds what clients asked about rather than what the hierarchy is: it is sized to
cover the empty non-terminals a resolver's own traffic keeps meeting, not to be
a second answer cache. The whole table is allocated once - a few tens of
kilobytes - and a name entering a slot another name holds takes it, which is the
whole of the replacement policy.
*/
MAX_CACHED_NON_CUTS :: 1024

/*
How long a remembered non-cut may be believed.

Shorter than `MAX_ZONE_TTL`, and deliberately not the denial's own ceiling. A
zone entry going stale is a zone this server keeps checking against yesterday's
keys, which the DNS has always bounded by the TTL the operator published. A table
entry going stale is different in kind: it suppresses the very lookup that would
notice. A delegation appearing where an empty non-terminal was leaves the walk
stopping at the parent, and that goes wrong in both directions. Closed, which is
the obvious one: the new zone's signatures come from a zone the walk never
established, so they are refused. And open, which is not: the parent's own
delegation NSEC covers every name inside the new child, so a forged denial for
one of them can be proven against the parent's keys and served `.Secure`. That
second one is the same exposure any resolver's negative DS cache carries in the
same window, so it is standard rather than new - but it is the reason the
ceiling here is worth having rather than a detail of it.

The verdicts that rest on reaching a name give it back when they come out
broken - `forget_unreached_non_cut` - so both directions close on the question
after the first. This bounds the ones nobody asks twice.

Five minutes does that without giving up what the table is for. What it exists
to collapse is a run walked again and again - a flood, or ordinary repeated
traffic - and that arrives inside seconds, not inside an hour. The floor is
`MIN_ZONE_TTL` as everywhere else, so an operator who shortens a negative TTL
below a minute ahead of a delegation change does not get less than that.
*/
MAX_NON_CUT_TTL :: 300

/*
What the memo does not do, written down so the next reader does not have to
find out by measuring.

It makes a run of non-cuts cost one walk per name rather than one per question,
which is the whole of the issue's shape - a zone with a fixed run of empty
non-terminals under it - and the whole of what legitimate traffic pays, the
`ip6.arpa.` nibbles between a provider's zone and a customer's most of all. It
does not bound the run. `zone_trust` descends from the apex, so a question whose
labels nearest the apex are fresh has every name below them fresh too, and a
client varying one of those misses the memo the whole way down however often it
asks - and puts a single-use entry in for each name it walked while it is there.

Nothing here can fix that, which is worth saying plainly. A bound on the run is
the only thing that would, and there is no bound that separates the two cases: a
customer's reverse zone can sit fifteen empty non-terminals below its provider's
under `ip6.arpa.`, which is deeper than the walk an attacker needs. So what is
left bounding one question is `MAX_LOOKUPS_PER_QUERY`, and what would
change it is not caching but not holding a query in flight for the walk.
*/

/*
Chain walks allowed upstream at once when the caller names no figure.

The server derives its own from `server.max_pending` and `server.max_connections`
- all of each but a reserved quarter, so some queries are always free to answer
what needs no walk - and this is for every other caller, the tests among them.
Eight is well past what a single caller can want, since a walk is entered and
left on one fiber and never nested,
so nothing sequential ever meets it.
*/
DEFAULT_MAX_CHAIN_WALKS :: 8

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
	// Nothing may validate against a table nobody has checked against the
	// library; a build that never called this on its own gets it here.
	probe_algorithms()

	v := new(Validator, allocator)
	v.allocator = allocator
	v.query = query
	v.query_ctx = query_ctx
	v.anchor_keys_cached = opts.anchor_keys_cached
	v.anchors = opts.anchors if len(opts.anchors) > 0 else root_anchors()
	/*
	The ceiling belongs to the same arithmetic as the allowance, so it is held
	to `MAX_NSEC3_ITERATIONS_LIMIT` here rather than wherever the option came
	from. Above that the allowance is what answers - the zones a higher ceiling
	admits are the ones whose proofs it cannot pay for - so a bigger number can
	only turn zones that were being served as insecure into SERVFAIL. Held down
	rather than refused, and said out loud, because refusing is a resolver that
	does not come up after an upgrade, which is worse than either.
	*/
	v.max_nsec3_iterations = nsec3_iterations_ceiling(opts.max_nsec3_iterations)
	if opts.max_nsec3_iterations > MAX_NSEC3_ITERATIONS_LIMIT {
		logx.warnf(
			"dnssec: max_nsec3_iterations %d is past what one query's hashing allowance can pay for; using %d",
			opts.max_nsec3_iterations,
			MAX_NSEC3_ITERATIONS_LIMIT,
		)
	}
	v.max_cached_zones = opts.max_cached_zones if opts.max_cached_zones > 0 else DEFAULT_MAX_CACHED_ZONES
	v.max_walks[.Shared] = opts.max_chain_walks if opts.max_chain_walks > 0 else DEFAULT_MAX_CHAIN_WALKS
	v.max_walks[.Connection] =
		opts.max_connection_walks if opts.max_connection_walks > 0 else DEFAULT_MAX_CHAIN_WALKS
	v.zones = make(map[string]^Zone_Entry, 64, allocator)
	v.non_cuts = make([]Non_Cut, MAX_CACHED_NON_CUTS, allocator)
	seed: [4]u8
	crypto.rand_bytes(seed[:])
	v.non_cut_seed = transmute(u32)seed
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
	v.lru_head, v.lru_tail = nil, nil
	clear_non_cuts(v)
	delete(v.non_cuts, v.allocator)
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
	Where the walk broke and why, for the log and never for the client: the zone
	and the step, in words. Set only on a `Bogus` verdict whose reason is
	`BROKEN_CHAIN`, which is the one a chain-of-trust step produced; empty on
	every other, including ones that failed for a reason local to the message or
	that a step's `Bogus` was turned into something else for. The exception is a
	verdict `lapsed` names the window of: the check that failed is kept here
	when nothing else is, since `reason` then names the window instead.
	*/
	detail:    string,
	/*
	The validity window a `Bogus` verdict's signatures fell outside, when that
	is what it rests on: `reason` then names the instant, and the server picks
	RFC 8914 code 7 or 8 from this rather than 6. See `Lapsed`.
	*/
	lapsed:    Lapsed,
	/*
	Whether this verdict *is* the shedding: a walk of this question was turned
	away for want of a slot, and that is what the status and reason report.

	Both halves matter, and the second is the one that is easy to lose. A
	question can have a walk shed somewhere and then fail for a quite different
	allowance - a verification budget spent, an NSEC3 count over the ceiling -
	and telling a caller "this was shed" would have it counted as load shedding
	and logged with words that contradict `reason`. So this is set only where
	the two agree.

	Carried as a fact rather than left for the caller to match on `reason`,
	which is a string this package is free to reword and which one clobbered
	assignment would silently change the meaning of.
	*/
	shed:      bool,
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
	answer:     []Authenticated_Set,
	authority:  []Authenticated_Set,
	/*
	The address hints beside the answer that were authenticated as well.

	A third section, and the only one this validator goes looking in rather than
	being handed. `validate_answer` reads the targets out of the RRsets it has
	already authenticated and then checks the A and AAAA sets sitting at those
	names, which is what RFC 9460 section 5 puts them there for. Everything else
	in the additional section stays what it always was - nobody's word but the
	sender's - so this list is what separates the two.
	*/
	additional: []Authenticated_Set,
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

	All of it, because anything less can be matched by a forgery. Keyed on the
	key tag and algorithm, a forgery copies both out of the zone's public DNSKEY
	set and takes the exemption. Keyed on the signature bytes, an attacker does
	not even have to forge: it appends verbatim copies, and then - once those are
	counted - a near-copy, the genuine record with one bit of its ORIGINAL TTL
	flipped and the signature left alone. That mutant would satisfy a
	signature-bytes test and take the exemption, and the forgeries behind it
	would fill the cap so that the *genuine* record was the one dropped. The
	answer would then go out under AD and into the cache validating for nobody.

	Every field is compared because every field an attacker can vary is a way to
	be mistaken for the record that verified while not being it. A copy that
	matches on all of them is the same record, which is what `verified_kept`
	is for.

	The slices inside point into the message the verdict was reached over, which
	the caller's arena keeps alive for as long as the prune needs it.
	*/
	rrsig: Rrsig,
	/*
	The most this set may be served with: `rrsig`'s Original TTL, or the time
	left before it expires when it verified, whichever is less. For a CNAME a
	DNAME synthesized, which has no `rrsig`, the DNAME's signature's. The prune
	holds the set and its signatures to it (RFC 4035 section 5.3.3).
	*/
	ttl:   u32,
}

// One set that verified, as a verdict lists it.
@(private)
authenticated_set :: proc(name: string, type: dns.Type, class: dns.Class, signer: string, rrsig: Rrsig, ttl: u32) -> Authenticated_Set {
	return {name = name, type = type, class = class, signer = signer, rrsig = rrsig, ttl = ttl}
}

// The least TTL any set this verdict rests on may be served with.
ttl_ceiling :: proc(result: Result) -> u32 {
	ceiling := max(u32)
	for sets in ([][]Authenticated_Set{result.answer, result.authority, result.additional}) {
		for s in sets {
			ceiling = min(ceiling, s.ttl)
		}
	}
	return ceiling
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

A validation that is refused memory - by `allocator` or the temp allocator,
anywhere in it - is `Indeterminate` for `READING_OVER_BUDGET` whatever its steps
reached, and caches nothing it settles from then on: a refused allocation can
drop a DS, a key or a signature from the set a step judges, and the verdict on
what was left is not about the zone (issue #636).
*/
validate :: proc(
	v: ^Validator,
	qname: string,
	qtype: dns.Type,
	wire: []u8,
	now: time.Time,
	allocator := context.temp_allocator,
	/*
	Which queries this question is one of. It picks which of the two bounds
	applies - see `Walk_Pool` - not whether one does: a connection is a finite
	resource too, and a flood that holds every one of them in a walk is
	`max_connections` worth of chain walks and no new question answered on one.

	Defaulted to the shared reading, which is the smaller allowance, so a caller
	that has not thought about it gets the tighter guard.
	*/
	pool := Walk_Pool.Shared,
	/*
	What the request has taken out of `allocator` so far, against
	`dns.REQUEST_DECODE_BUDGET`, from the caller that owns it.

	This response is read here, the chain's replies are read a step at a time,
	and all of it lands in the one arena - so the counter has to be the
	request's or the bound is per reading and there are thirty-five of those.
	Nil for a caller that is not counting, which is every test that validates a
	captured message on its own. See issue #354.
	*/
	spent: ^int = nil,
	// The client question's upstream deadline, for the lookups; see `Query_Proc`.
	deadline: ^time.Tick = nil,
) -> Result {
	dry := false
	outer := context.temp_allocator
	answers := dns.Dry_Watch{backing = allocator, dry = &dry}
	scratch := dns.Dry_Watch{backing = outer, dry = &dry}
	context.temp_allocator = dns.dry_watch_allocator(&scratch)
	result := validate_watched(v, qname, qtype, wire, now, dns.dry_watch_allocator(&answers), pool, spent, deadline, &dry, outer)
	if dry {
		return {status = .Indeterminate, reason = READING_OVER_BUDGET}
	}
	return result
}

// `validate`'s body, with `dry` set where an allocation is refused; see
// `Budget.dry` and `Budget.scratch`.
@(private)
validate_watched :: proc(
	v: ^Validator,
	qname: string,
	qtype: dns.Type,
	wire: []u8,
	now: time.Time,
	allocator: mem.Allocator,
	pool: Walk_Pool,
	spent: ^int,
	deadline: ^time.Tick,
	dry: ^bool,
	scratch: mem.Allocator,
) -> Result {
	// Read before the decode, so the walk's moment trails `now` by as little
	// as it can; see `Budget.began`.
	budget := query_budget(v)
	budget.dry = dry
	budget.scratch = scratch
	msg, derr := dns.decode_message(wire, allocator, spent)
	if derr != .None {
		/*
		A reading this server refused itself is not a response it read and
		found wanting. `Bogus` here would accuse the zone of a forgery on the
		strength of our own accounting or our own memory - and an attacker with a signed zone
		gets to choose when that happens, by answering the chain with replies
		expensive enough to spend the request's allowance. `Indeterminate` is
		what an unreachable authority gets, which is what this is.
		*/
		if dns.reading_refused(derr) {
			return {status = .Indeterminate, reason = READING_OVER_BUDGET}
		}
		return {status = .Bogus, reason = "unparseable response"}
	}
	class := msg.question[0].class if len(msg.question) > 0 else dns.Class.IN
	unix := u32(time.to_unix_seconds(now))
	/*
	Every signature's lapse is counted from the whole second `unix`, which `now`
	is a fraction past. The zone cache is timed from that second too, or an entry
	would outlive its signatures by the fraction (RFC 4035 section 5.3.1).
	*/
	budget.began = loop.moment_add(budget.began, -time.diff(time.unix(i64(unix), 0), now))
	/*
	The slot is this question's rather than each walk's - see `keep_slot` - so
	the walks below hand it on to one another and it is given back here, once,
	whichever of them took it. This also covers a lookup reached without a walk
	at all, so a slot can never outlive the question that took it.
	*/
	budget.keep_slot = true
	budget.pool = pool
	budget.spent = spent
	budget.deadline = deadline
	defer end_walk(v, &budget)

	/*
	REFUSED, SERVFAIL and the rest carry nothing to authenticate. Demanding a
	denial of existence from them would turn every upstream error into a DNSSEC
	failure, and report it as a forgery in the bargain.

	Two shapes are refused rather than excused, and between them they are the
	way round everything below. `rcode_of` composes twelve bits: the header's
	four, and eight more from the OPT record's TTL (RFC 6891 section 6.1.3).
	Every consumer this validator's verdicts are written for reads the four -
	glibc's `res_query`, Go's `checkHeader` - so one bit set in the OPT's top
	byte gives this server and its client two different rcodes off one message,
	and the excuse above is written in terms of ours.

	With the nibble at 3 the client reads a name error. With the nibble left at
	0 it reads NOERROR and takes the answer section, and that half is not a
	denial bug at all but the whole validator stepped over: the same forged
	`www.example.com. A`, signature not covering it, is `Bogus` plain and would
	be `Insecure` with one byte set, forwarded, and believed, were the excuse
	read off this server's rcode alone. Neither costs the attacker a forgery
	they did not already have to make.

	Trying to tell a rewritten header from a real extended rcode by what else is
	in the message does not work, and the attempt is worth writing down because
	it looks like it should. A responder sending BADVERS or BADCOOKIE has not
	answered, so it sends a question and an OPT and nothing else - and so does
	an attacker who wants a NODATA, since NOERROR with an empty answer section
	*is* "that name has no such record" to everything that reads it. The two are
	the same bytes. Testing the sections only moves the attacker from the forged
	positive answer to the forged NODATA, which for a DANE or MTA-STS lookup is
	the same downgrade.

	So neither is forwarded. An extended rcode under a header the client will
	read as an answer or a denial is one this server cannot reason about and
	must not pass on, whichever of the two produced it, and the honest report is
	that nothing was established: `Indeterminate`, which is SERVFAIL to the
	client and `EDE_NO_REACHABLE_AUTHORITY` in the extended error rather than
	`EDE_DNSSEC_BOGUS`. That is the part of "an upstream error is not a forgery"
	worth keeping, and it is what
	`test_badvers_is_refused_without_being_called_a_forgery` pins. Refusing
	costs a real BADVERS nothing it had: forwarded, it would reach the client as
	NOERROR with an empty answer, so what refusing gives up is not a working
	answer but a silently wrong one.

	Only where the nibble reads as an answer. BADCOOKIE's is 7, which a client
	reads as YXRRSET and acts on as the error it is, and the upstream layer
	handles it long before this - so nothing here disturbs it.

	`cache.put` fails closed on the composed rcode either way, so none of these
	shapes was ever kept; what is closed here is what reached the client.
	*/
	if !answerable_rcode(msg) {
		return unanswerable_verdict(msg)
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
	if slice.any_of_proc(msg.answer, proc(rec: dns.Record) -> bool {return rec.type != .RRSIG && rec.type != .OPT}) {
		out := name_the_window(validate_answer(v, &budget, msg, qname, qtype, class, unix, now, allocator), now, allocator)
		out.shed = shed_verdict(&budget, out)
		count_shed(v, out)
		return out
	}
	/*
	A question about RRSIG records themselves is the one case where an answer
	made only of them is honest: an RRSIG RRset carries no signature of its own
	(RFC 4035 section 2.2), so there is nothing here to authenticate and no
	denial to demand either.
	*/
	if qtype == .RRSIG && len(msg.answer) > 0 {
		return {status = .Insecure, reason = NOTHING_TO_AUTHENTICATE}
	}
	denied := name_the_window(validate_denial(v, &budget, msg, qname, qtype, class, unix, now, allocator), now, allocator)
	denied.shed = shed_verdict(&budget, denied)
	count_shed(v, denied)
	return denied
}

// The verdict on a response whose rcode `answerable_rcode` turns away: an
// extended rcode under a header that reads as an answer is refused, and any
// other error has nothing to authenticate.
@(private)
unanswerable_verdict :: proc(msg: dns.Message) -> Result {
	nibble := dns.Rcode(msg.flags.rcode)
	if u16(dns.rcode_of(msg)) > 0xf && (nibble == .No_Error || nibble == .NX_Domain) {
		return {status = .Indeterminate, reason = "extended rcode under an answerable header"}
	}
	return {status = .Insecure, reason = "no data to authenticate"}
}

/*
Say so when a forgery verdict rests on a signature's validity period.

Done once, here, rather than where each verdict is reached: inside the package
the reasons are the constants the paths compare against - `BROKEN_CHAIN` is how
`detail` is kept - and only what leaves it names the instant. Anything but
`Bogus` keeps its own reason and no window, since only that verdict accuses the
zone of what the window may explain.
*/
@(private)
name_the_window :: proc(result: Result, now: time.Time, allocator: mem.Allocator) -> Result {
	out := result
	if out.status != .Bogus || out.lapsed.window == .Current {
		out.lapsed = {}
		return out
	}
	// The check that failed stays in the log, beside the window that failed it.
	if out.detail == "" {
		out.detail = out.reason
	}
	out.reason = lapsed_reason(out.lapsed, now, allocator)
	return out
}


// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/*
Is this CNAME one that a DNAME in the same answer produced?

A DNAME redirects everything below its owner, and the server sends the CNAME it
worked out along with it, unsigned (RFC 6672 section 3.4.1). The signature is on
the DNAME, so that is what gets checked; the CNAME is accepted only once the
substitution has been recomputed and found to match.

Recomputing it is the entire safeguard. Accepting any unsigned CNAME that
happened to sit below a validated DNAME would hand out a redirect to anywhere,
for every name under every DNAME there is - a good deal worse than refusing
them.
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
) -> (
	covered: bool,
	// The DNAME's verified signature, which bounds the CNAME's TTL as it does
	// the DNAME's own (RFC 4035 section 5.3.3).
	vouched: Rrsig,
	// The window of a synthesizing DNAME refused for it alone, when none holds.
	lapsed: Lapsed,
) {
	target, is_name := cname.data.(dns.Rdata_Name)
	if !is_name {
		return false, {}, {}
	}

	seen := make([dynamic]dns.Question, 0, 2, allocator)
	for rec in msg.answer {
		if rec.type != .DNAME || rec.class != class {
			continue
		}
		if !first_of_rrset(&seen, rec) {
			continue
		}

		dname, dname_is_name := rec.data.(dns.Rdata_Name)
		if !dname_is_name {
			continue
		}
		if !dname_synthesizes(rec.name, dname.name, cname.name, target.name, allocator) {
			continue
		}
		/*
		Only now is it worth checking the DNAME itself, which costs a walk.

		The status alone, deliberately. A DNAME may sit at a wildcard like any
		other type, so a legitimate redirection through one carries an RRSIG a
		label short, and refusing that here is every name behind every wildcard
		DNAME. What holds the expansion to account is that this record is in the
		answer section, so `validate_answer`'s own loop reaches the same RRset,
		records the encloser and makes the RFC 4035 section 5.3.4 proof a
		condition of the message - which is not a local property. A caller that
		ever consults a DNAME from somewhere other than `msg.answer` has to
		bring that proof with it. `wildcard_denial_test.odin` pins both halves.
		*/
		records, sigs := rrset_with_sigs(msg.answer, rec.name, .DNAME, class, allocator)
		status, _, _, _, sig, why_lapsed := validate_rrset(v, budget, rec.name, .DNAME, class, records, sigs, unix, now, allocator)
		if status == .Secure {
			return true, sig, {}
		}
		keep_lapse(&lapsed, why_lapsed)
	}
	return false, {}, lapsed
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
	if !dns.name_below(cname_owner, owner) {
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
	// The same prefix, over the target this time. The prefix keeps its
	// trailing dot, so a root target (RFC 6672 section 2.2) adds nothing.
	want := cname_owner[:cut] if target == "." else strings.concatenate({cname_owner[:cut], target}, allocator)
	return dns.name_equal_fold(cname_target, want)
}

// Byte offset just past the `count`th label separator, so `name[:offset]` is
// the first `count` labels with their trailing dot. Escapes are stepped over
// whole, since the character after a backslash is never a separator.
@(private)
label_offset :: proc(name: string, count: int) -> (offset: int, ok: bool) {
	seen := 0
	for i := dns.label_end(name, 0); i < len(name); i = dns.label_end(name, i + 1) {
		seen += 1
		if seen == count {
			return i + 1, true
		}
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
Whether `rec` is the first record of its RRset (owner, folded, and type) that a
walk over a section reaches, remembering it in `seen` when it is: each RRset is
then judged once however many records it holds.
*/
@(private)
first_of_rrset :: proc(seen: ^[dynamic]dns.Question, rec: dns.Record) -> bool {
	for q in seen {
		if q.type == rec.type && dns.name_equal_fold(q.name, rec.name) {
			return false
		}
	}
	append(seen, dns.Question{name = rec.name, type = rec.type})
	return true
}

// The records of `owner`'s `type` in `section`, and the signatures covering them.
@(private)
rrset_with_sigs :: proc(
	section: []dns.Record,
	owner: string,
	type: dns.Type,
	class: dns.Class,
	allocator: mem.Allocator,
) -> (
	records: []dns.Record,
	sigs: []Rrsig,
) {
	return records_of(section, owner, type, class, allocator), sigs_covering(section, owner, type, class, allocator)
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

// The least Original TTL among the signatures behind these sets.
@(private)
sets_original_ttl :: proc(sets: []Authenticated_Set) -> u32 {
	ttl := max(u32)
	for s in sets {
		ttl = min(ttl, s.rrsig.original_ttl)
	}
	return ttl
}

// The soonest any of the signatures behind these sets stops verifying.
@(private)
sets_lapse :: proc(sets: []Authenticated_Set, unix: u32) -> u32 {
	left := max(u32)
	for s in sets {
		left = min(left, sig_lapses(s.rrsig, unix))
	}
	return left
}

@(private)
negative_ttl :: proc(msg: dns.Message) -> u32 {
	ttl, has_soa := dns.negative_ttl(msg)
	return ttl if has_soa else MIN_ZONE_TTL
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
