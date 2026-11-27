package dnssec

import "core:mem"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
The names an authenticated answer points a client at.

Read from the RRsets that came back `Secure` and from nowhere else, which is the
load-bearing half of this. The additional section is written by whoever wrote the
response, and so is the answer section - but an answer RRset had to survive its
zone's signature to get into `answered`, so the targets named here are the ones
the zone itself published. Reading them off the answer section directly would let
anyone able to append a record nominate the names whose addresses get
authenticated and carried out under the AD bit; that would still be authentic
data, since each hint is checked against its own zone, but it would be a stranger
choosing what this server spends its chain walks on.

What it removes is the free version of that. An attacker who holds a signed zone
of their own can still nominate a target, by appending a signed SVCB or MX RRset
from it - `validate_answer` authenticates whatever it can and does not ask which
RRsets concern the question, so that set reaches `answered` like any other. It
buys the same thing appending an unsigned record would: up to
`MAX_HINT_TARGETS` names of the attacker's choosing walked to, inside the query
budget every other walk shares, and authentic data or nothing at the end of it.
Which is why the bound above is a bound and not a comfort.

An HTTPS or SVCB record in ServiceMode may write its TargetName as ".", which RFC
9460 section 2.5 makes the owner name itself rather than the root. AliasMode -
priority zero - is a redirection to be followed rather than a service to connect
to, and the client will ask about the target by name, so it names no hint.
*/
@(private)
hint_targets :: proc(
	msg: dns.Message,
	answered: []Authenticated_Set,
	class: dns.Class,
	allocator: mem.Allocator,
) -> []string {
	out := make([dynamic]string, 0, 4, allocator)
	for rec in msg.answer {
		if len(out) >= MAX_HINT_TARGETS {
			break
		}
		if rec.class != class {
			continue
		}
		#partial switch rec.type {
		case .HTTPS, .SVCB, .SRV, .MX:
		case:
			continue
		}
		if _, ok := authenticated_rrset(answered, rec.name, rec.type, class); !ok {
			continue
		}

		target := ""
		if svcb, is_svcb := rec.data.(dns.Rdata_SVCB); is_svcb {
			if svcb.priority == 0 {
				continue
			}
			target = rec.name if svcb.target == "." else svcb.target
		} else if srv, is_srv := rec.data.(dns.Rdata_SRV); is_srv {
			target = srv.target
		} else if mx, is_mx := rec.data.(dns.Rdata_MX); is_mx {
			target = mx.exchange
		}
		// The root holds no addresses, and a target that did not parse is not a
		// name to go looking for one under.
		if target == "" || target == "." {
			continue
		}
		if name_listed(out[:], target) {
			continue
		}
		append(&out, target)
	}
	return out[:]
}

@(private)
name_listed :: proc(names: []string, name: string) -> bool {
	for n in names {
		if dns.name_equal_fold(n, name) {
			return true
		}
	}
	return false
}

/*
Authenticate the address records sent beside the answer, and keep the ones that
hold up.

RFC 9460 section 5 asks a recursive resolver to pass those on so that a client
does not have to resolve the target before it can connect, and #177 took them out
along with the glue. They are not glue: an address for an HTTPS, SVCB, SRV or MX
target is ordinary zone data, signed by the zone that holds it, and the only
reason it cannot ride on the answer's verdict is that the zone which signed it is
usually not the zone the answer established. So it gets established here.

`validate_rrset` does the establishing, which means each hint is judged exactly
as an answer-section RRset is: the signer has to lie in the owner's ancestry, the
chain from a trust anchor down to that signer has to hold, and the signature has
to be one this build can check. What is different is what a failure means. The
answer has already been judged by the time this runs, and a hint is a
convenience - so anything short of `Secure` drops the record and changes nothing
else. A response cannot be made to fail by having a bad address bolted onto it.

Two things are refused that an answer-section RRset would not be.

A wildcard expansion, because the proof that goes with one is not here. RFC 4035
section 5.3.4 has a validator demand a denial that the expanded name has nothing
of its own, `validate_answer` assembles that proof for the answer, and for a hint
it would live in the authority section of a zone this message is not even about.
Without it, a wildcard signature lifted from any name under the encloser vouches
for an address at any other - so the hint is dropped, and a client that wants the
address asks for it, which is where it started.

Anything outside the query's class, and A or AAAA and nothing else. A target's
address is what section 5 is about and what a client connects to; a CNAME, a
DNAME or a second SVCB record at the target would be this server following a
redirection nobody asked it to follow, on the strength of a section it does not
otherwise read.

The cost is upstream queries, and where it falls is worth being plain about: a
signed hint inside the zone the answer established costs nothing at all, because
the walk goes to the RRSIG's signer and `zone_step` finds that zone in the
validator's cache. A hint in a second zone costs the walk down to it, shared
with every later question through the same cache. A hint nothing verified -
unsigned, or forged - costs one step more than either: `validate_rrset` settles
forged against unsigned by walking to the *owner*, and the owner of a hint is a
name below its zone rather than the zone itself, so that step is a DS query for
a name that is no cut. `zone_step` remembers those, so appending an unsigned
address at a target the answer really names is worth a lookup to whoever appends
it once per name rather than on every miss. A hint padded past the allowance is the one
that costs nothing extra: the exhausted return comes before that walk.
`MAX_HINT_TARGETS` bounds how many of these one response can ask for, and the
query budget bounds what they may spend between them.

One more thing changes for the client, and it is not a security property: the
records kept here carry TTLs of their own, and `cache.put` holds an entry for the
shortest TTL in the message. A hint with a shorter life than the answer therefore
shortens the entry - which is what already happens to every unsigned answer that
keeps its additional section, so this makes the two paths agree rather than
introducing anything.
*/
@(private)
validated_hints :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	answered: []Authenticated_Set,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> []Authenticated_Set {
	targets := hint_targets(msg, answered, class, allocator)
	if len(targets) == 0 {
		return nil
	}

	out := make([dynamic]Authenticated_Set, 0, 2 * len(targets), allocator)
	seen := make([dynamic]dns.Question, 0, 2 * len(targets), allocator)
	for rec in msg.additional {
		if rec.class != class || (rec.type != .A && rec.type != .AAAA) {
			continue
		}
		if !name_listed(targets, rec.name) {
			continue
		}
		if !first_of_rrset(&seen, rec) {
			continue
		}

		records, sigs := rrset_with_sigs(msg.additional, rec.name, rec.type, class, allocator)
		status, encloser, _, signer, carried, _ := validate_rrset(
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
		if status != .Secure || encloser != "" {
			continue
		}
		append(&out, authenticated_set(rec.name, rec.type, class, signer, carried, signed_ttl_ceiling(carried, unix)))
	}
	return out[:]
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
	a := judge_answer(v, budget, msg, class, unix, now, allocator)

	/*
	A backstop. `validate` only sends a response here once it has counted a
	record this loop will check, so reaching this means the two disagree about
	what is authenticatable. Whatever the cause, an empty check is not a pass.
	*/
	if a.checked == 0 {
		return {status = .Insecure, reason = NOTHING_TO_AUTHENTICATE}
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
	shape, end := chain_walk(msg.answer, qname, qtype, class)
	/*
	Not gated on `worst`, for the same reason the rcode guard below is not, and
	this one is the load-bearing half of the pair.

	`validate` sends a response here on the strength of the answer section
	holding one authenticatable record - any record, at any name. So a forged
	NXDOMAIN for a signed name goes to `validate_denial` and is refused as
	`Bogus, "no denial of existence"` while its answer section is empty, and one
	appended record from a zone that really is unsigned - `www.reddit.com.
	CNAME`, no forgery, no signature to break - reroutes the whole message to
	this path instead, where nothing ever demands a proof. So the check runs
	whatever `worst` is: that unsigned record has already dragged `worst` to
	`Insecure`, a check gated on it would be skipped, the verdict would fall
	through as `Insecure`, `resolve_query` forwards those, and the client would
	read a name error for a signed name that nobody had proven anything about.

	A record that does not address the question cannot make a response an
	answer, whatever its zone thinks of it, and being unable to authenticate the
	record is not a reason to hold it to less. `Bogus` and `Indeterminate` are
	the two left out, because those are refused already and their own reason is
	the one that explains the refusal.
	*/
	if a.worst != .Bogus && a.worst != .Indeterminate && shape == .None {
		return {status = .Bogus, reason = "answer does not address the question"}
	}

	/*
	NXDOMAIN over a record this path just authenticated is the sender
	contradicting the zone, and the zone wins.

	The shape above was settled from records each of which verified or lies in a
	zone proven unsigned; the rcode is the one part of
	the message no signature covers, and the header is a byte an attacker on a
	plain UDP or TCP leg can rewrite without touching an RRset. Left alone, a
	genuine signed answer with one nibble changed would come out of here
	`Secure` - the RRsets are the zone's own and verify perfectly - and the AD
	bit would go out over an authenticated denial for a name whose signed records were sitting in
	the answer section. Clients decide on the rcode before they read that
	section (glibc's `res_query` returns HOST_NOT_FOUND, Go's `checkHeader`
	returns `errNoSuchHost`), so the records would be there and nobody would
	look, and a fail-closed DANE or MTA-STS lookup that defers on a Bogus answer
	would proceed without the record it was checking for. RFC 4035
	section 5.3 lets a validator authenticate RRsets, not a header claim that
	contradicts them.

	`Bogus` rather than a correction to NOERROR. Which of the two the sender
	meant is not knowable from here, and rewriting the header would hand the
	client an answer this server invented; the honest report is that the message
	does not hold together. It is what the attacker already had - the response
	is refused, SERVFAIL - so setting the rcode buys them nothing, and leaving
	it alone is the case above.

	Read against the shape, never to pick it. `ad_scope_test.odin` records the
	objection to deciding a path from the rcode: the sender chooses what records
	to send, so a path chosen from the header can be steered by adding or
	removing them. Nothing here is chosen from the header - `shape` came from
	records that verified or lie in a zone proven unsigned - and adding or removing records can only move it
	between `.Direct`, `.Chain_Only` and `.None`, each of which is already
	answered on its own terms.

	Which name the rcode is about is the whole of the rest. In a CNAME chain it
	is the last name in it and not the one asked about (RFC 6604 section 3), so
	a chain that stops short is the ordinary NXDOMAIN-after-a-CNAME and no
	contradiction at all: the denial is of the chain's target, and it is the
	check below, against that target's zone, that proves it or refuses it.
	`denial_contradicted` follows the chain to that name and asks only whether
	an authenticated record is sitting at it.

	Not gated on the whole message being `Secure`, which would be a way round
	the whole thing. `worst` is the worst verdict any RRset in the section reached,
	and the section is the sender's to fill: one unsigned RRset appended from a
	zone that really is unsigned - `www.reddit.com. A` in the captured set -
	comes back `Insecure`, drags `worst` down with it, and would leave the
	flipped rcode sailing past a check that only ran on `Secure`. `Insecure` is
	not refused; `resolve_query` forwards it, so the client still reads NXDOMAIN
	with the zone's own signed records underneath, which is the harm again minus
	the AD bit - and it costs the attacker one appended record and no forgery.
	`Bogus` and `Indeterminate` are the two left out, because those are refused
	already and the reason they carry is the one that explains the refusal.

	What makes that safe is `denial_contradicted` reading none of the sender's
	additions: it walks the RRsets this path authenticated and nothing else, so
	a record bolted on beside them can lower `worst` without being able to move
	the question this asks.
	*/
	if a.worst != .Bogus && a.worst != .Indeterminate && dns.rcode_of(msg) == .NX_Domain {
		if denial_contradicted(msg.answer, a.authenticated[:], qname, qtype, class) {
			return {status = .Bogus, reason = "rcode contradicts the authenticated answer"}
		}
	}

	/*
	A wildcard answer is only good if the name really had nothing of its own.
	Without this an attacker holding one wildcard signature could serve it for
	names the zone answers for directly.

	Every expanded RRset is asked for separately. A CNAME chain can be answered
	partly from real records and partly from a wildcard, and the one that was
	expanded is not always the one carrying the question's own name.

	Those proofs are also the only thing this path authenticates outside the
	answer section. Each was checked against the zone's keys, so it is as
	authentic as the answer it stands behind, and a client that validates for
	itself needs it to reach the same conclusion.
	*/
	proved := make([dynamic]Authenticated_Set, 0, 1, allocator)
	// Verified once for the message, not once per expansion or once more for a
	// denial at the chain's end below: they are the same records, read against
	// the same zone, and re-verifying them spends an allowance the answer needs
	// for its own RRsets.
	denials := make([dynamic]Verified_Denial, 0, 1, allocator)
	/*
	Not gated on `worst` being `Secure`, for the reason the rcode guard above
	gives: a genuine wildcard record replayed for a name with records of its own
	would ride out on one appended unsigned RRset. A proof that fails is refused whatever else the section holds;
	one that holds leaves the verdict where the rest of the answer put it.
	*/
	if a.worst != .Bogus && a.worst != .Indeterminate && prove_expansions(v, budget, msg, class, unix, now, allocator, &a, &proved, &denials) {
		return {status = a.worst, reason = a.reason, detail = a.detail, lapsed = a.lapsed}
	}

	/*
	A chain that ends without the type asked for, where the sender is claiming
	there is nothing more, is a denial, and it is checked as one.

	The everyday shape is an AAAA lookup for a name whose CNAME leads somewhere
	with only an A record: the CNAME verifies and the chain concerns the
	question, but what says the target has no AAAA is the NSEC or NSEC3 and the
	SOA in the *authority* section, signed by the target's zone. RFC 6840
	section 5.8 has the AD bit cover "any relevant negative response RRs in the
	Authority section" as well as the answer, and the prune keeps only what the
	verdict names - so an unchecked denial either loses its proof from under the
	AD bit or withholds the bit from the commonest answer there is.

	`validate_denial` is asked about `end`, the last name in the chain, because
	that is the name the rcode and the proof are about (RFC 6604 section 3), and
	it establishes the zone from that name rather than from any signer in the
	message - so a genuine proof lifted from the source zone, or from anywhere
	else, is read against keys that did not sign it and fails. Its verdict is
	the message's: a proof that does not hold is `Bogus` as the same denial
	asked for directly would be, an unsigned or opt-out target is `Insecure`, a
	walk that did not finish is `Indeterminate`.

	The cost is one more walk, to the zone holding `end`, and one per response
	however many CNAMEs it carries: a chain has one end, and the CNAMEs before it
	have each paid for their own zone above. It comes out of the same
	`MAX_LOOKUPS_PER_QUERY` and `MAX_VERIFICATIONS_PER_QUERY` as everything else
	the question spends, so a response full of CNAMEs to distinct zones costs no
	more than the budget it already had - and running that out here is
	`Indeterminate`, not a forgery.

	Both halves of the condition are needed. A chain stopping short is not
	enough on its own - a DNAME redirection or a bare chain an upstream did not
	follow is exactly that shape and claims no denial, so demanding a proof on
	the shape alone would refuse every one of them. `denial_claimed` is the
	other half.

	*After* the wildcard proof, and that ordering is load-bearing. Put before it,
	this would be a way to skip that proof: an attacker replays a genuine
	wildcard record as the answer for a name that has its own records, adds a
	proven denial for the target, and the expansion is never asked about.

	Not gated on `worst` being `Secure`, for the reason the rcode guard above
	gives: a denial an attacker forged behind a signed CNAME would ride out on
	one appended unsigned RRset, which leaves the chain untouched. So an unproven denial is refused whatever else the
	section holds, and a proven one leaves the verdict where the rest put it.
	*/
	if a.worst != .Bogus && a.worst != .Indeterminate && shape == .Chain_Only && denial_claimed(msg) {
		denied := validate_denial(v, budget, msg, end, qtype, class, unix, now, allocator, &denials)
		switch {
		case denied.status == .Secure:
			name_once(&proved, denied.authority)
		case denied.status == .Insecure && a.worst == .Insecure:
		// Insecure already, and the reason that made it so stands.
		case:
			return denied
		}
	}
	/*
	The RRsets are named only when the verdict is `Secure`, which is what
	`Result` promises and the only case a caller may prune against. A partial
	verdict has a partial list behind it - the RRsets that happened to hold up
	while another did not - and pruning a message down to that would drop
	records from an answer nobody is vouching for anyway.
	*/
	if a.worst != .Secure {
		return {status = a.worst, reason = a.reason, detail = a.detail, lapsed = a.lapsed}
	}
	/*
	Last, and after the verdict is settled. The hints spend what the answer and
	its proofs left of the budget, and nothing they find - or fail to find - can
	move `worst`: a response is not made bogus by an address bolted onto it, and
	an address this server could not afford to check is one the client asks for
	itself.
	*/
	hints := validated_hints(v, budget, msg, a.authenticated[:], class, unix, now, allocator)
	return {status = a.worst, reason = a.reason, answer = a.authenticated[:], authority = proved[:], additional = hints}
}

/*
Prove each wildcard expansion in `a` (RFC 4035 section 5.3.4), naming the proofs
in `proved` and moving `a`'s verdict and reason when one is worse. `refused` when
that verdict is one the answer does not survive.
*/
@(private)
prove_expansions :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
	a: ^Answer_Verdict,
	proved: ^[dynamic]Authenticated_Set,
	denials: ^[dynamic]Verified_Denial,
) -> (
	refused: bool,
) {
	// Every one of them, and the worst verdict wins. Stopping at the first
	// failure would let an expansion that came out merely insecure - an
	// opt-out cover does - hide a forged one behind it, and which comes
	// first in the answer section is the sender's choice.
	before := a.worst
	proof_reason, proof_detail: string
	proof_lapsed: Lapsed
	for e in a.expansions {
		proof, records, why, why_lapsed := validate_wildcard_proof(v, budget, msg, e.owner, e.encloser, class, denials, unix, now, allocator)
		// The reason belongs to the verdict that is being returned, so it
		// moves only when the verdict does, or when a forgery joins a
		// lapse (`takes_reason`).
		if takes_reason(a.worst, proof, proof_lapsed, why_lapsed) {
			proof_reason = why
			proof_detail = budget.broken if why == BROKEN_CHAIN else ""
			proof_lapsed = why_lapsed
		}
		a.worst = worse(a.worst, proof)
		name_once(proved, records)
	}
	if a.worst != before {
		a.reason, a.detail, a.lapsed = proof_reason, proof_detail, proof_lapsed
		// An expansion proven only through an opt-out span is insecure,
		// and that is no more an excuse for the denial `validate_answer`
		// checks next than an unsigned RRset is: it carries on to be asked,
		// and the reason stands.
		if a.worst != .Insecure {
			return true
		}
	}
	return false
}

/*
What the answer section's RRsets come to on their own: the worst verdict among
them with the reason it was given, the wildcard expansions still to prove, and
the sets that verified.
*/
@(private)
Answer_Verdict :: struct {
	worst:         Status,
	reason:        string,
	// The step behind `reason`, when that is `BROKEN_CHAIN`. Read as the RRset's
	// walk ends, since any later walk clears it.
	detail:        string,
	// The window behind `reason`, when it rests on one; it moves with `reason`.
	lapsed:        Lapsed,
	expansions:    [dynamic]Wildcard_Expansion,
	checked:       int,
	// What the verdict will be allowed to cover. Built from the RRsets that
	// came back `Secure` rather than from the RRsets seen, which also holds the
	// ones that did not - the two only coincide while the whole answer holds up.
	authenticated: [dynamic]Authenticated_Set,
}

// Judge every RRset in the answer section once (`judge_rrset`).
@(private)
judge_answer :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	a: Answer_Verdict,
) {
	a = Answer_Verdict {
		worst         = .Secure,
		expansions    = make([dynamic]Wildcard_Expansion, 0, 1, allocator),
		authenticated = make([dynamic]Authenticated_Set, 0, len(msg.answer), allocator),
	}
	seen := make([dynamic]dns.Question, 0, len(msg.answer), allocator)
	for rec in msg.answer {
		if rec.type == .RRSIG || rec.type == .OPT {
			continue
		}
		if !first_of_rrset(&seen, rec) {
			continue
		}

		status, encloser, why, signer, carried, why_lapsed, broken, ceiling := judge_rrset(v, budget, msg, rec, class, unix, now, allocator)
		if encloser != "" {
			append(&a.expansions, Wildcard_Expansion{owner = rec.name, encloser = encloser})
		}
		a.checked += 1
		if status != .Secure {
			// The reason belongs to the verdict that is being returned, so it
			// moves only when the verdict does, or when a forgery joins a lapse
			// (`takes_reason`) - the same rule the wildcard proofs
			// (`prove_expansions`) follow. `Insecure` ranks under `Indeterminate`, so
			// a later unsigned RRset would otherwise leave "unsigned zone"
			// standing beside a verdict reached because a chain could not be
			// walked: the benign reason reported, in the log and in the
			// client's extended error, for a refusal that was anything but.
			if takes_reason(a.worst, status, a.lapsed, why_lapsed) {
				a.reason = why
				a.detail = broken if why == BROKEN_CHAIN else ""
				a.lapsed = why_lapsed if status == .Bogus else {}
			}
			a.worst = worse(a.worst, status)
			continue
		}
		append(&a.authenticated, authenticated_set(rec.name, rec.type, class, signer, carried, ceiling))
	}
	return
}

/*
Validate the RRset of `rec` in the answer section, and the two things about it
`validate_rrset` cannot settle alone: an unsigned CNAME a DNAME produced, and a
type a wildcard never legitimately produces. `broken` is the step the RRset's
walk broke at, read before the DNAME check walks again; `ceiling` is the TTL
ceiling of what vouched for the set.
*/
@(private)
judge_rrset :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	rec: dns.Record,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	encloser: string,
	why: string,
	signer: string,
	carried: Rrsig,
	why_lapsed: Lapsed,
	broken: string,
	ceiling: u32,
) {
	records, sigs := rrset_with_sigs(msg.answer, rec.name, rec.type, class, allocator)

	status, encloser, why, signer, carried, why_lapsed = validate_rrset(
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
	// The step this RRset's walk broke at, read now: the DNAME check below
	// walks too, and clears it.
	broken = budget.broken
	ceiling = signed_ttl_ceiling(carried, unix)
	if status != .Secure && rec.type == .CNAME && len(sigs) == 0 {
		covered: bool
		if covered, ceiling = dname_rescues(v, budget, msg, records, class, unix, now, allocator, &why_lapsed); covered {
			status = .Secure
			why = ""
		}
	}
	/*
	For most types an expansion is a fact to be proved, and the RFC 4035
	section 5.3.4 denial below proves it: it asks whether the wildcard was
	entitled to stand in for this name, and if it was, the answer is an
	answer.

	For these four the proof settles nothing, because RFC 4592 section 4
	says a wildcard never legitimately produces one:

	  - NSEC (section 4.7): a wildcard owns an NSEC of its own, but
	    "synthesis of these records will only occur when the query exactly
	    matches the record". NSEC3 goes with it, being the same record
	    hashed.
	  - DS (section 4.6): "meaningless and harmless" at a wildcard, and a
	    synthesized one "will not be very useful as it exists in the
	    context of a delegation point".
	  - SOA (section 4.1): a wildcard owning one means the zone apex is
	    that name, and an apex is not a source of synthesis.

	So an expanded one of these was moved, and what an attacker has to
	prove to move it is a true statement fetched with one harmless query -
	the wildcard's own NSEC, covering whatever name they picked. Proving
	the expansion legitimate while the record is still forged is the whole
	shape of the attack.

	Section 4.7 also calls a synthesized NSEC harmless, "as [it] will never
	be used in negative caching or to generate a negative response". That
	is true here - `parse_nsec` is reached only from the authority section
	- and it is not the whole account: the AD bit is this server's own
	claim that the record is what its zone published, and the owner name is
	the one part of it the signature never covered.

	`signed_labels` drops a literal leading `*.`, so a zone's own
	`*.zone. NSEC`, asked for by name, comes back with no encloser and
	still passes. This is the answer-section half of what `verified_rrset`
	refuses for the authority section and the chain walk refuses for a DS.
	*/
	if status == .Secure &&
	   encloser != "" &&
	   (rec.type == .NSEC || rec.type == .NSEC3 || rec.type == .DS || rec.type == .SOA) {
		status = .Bogus
		why = "wildcard expansion not possible"
	}
	return
}

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
at that owner. The verdict `validate_answer` records names an RRset, and the prune
keeps everything matching it - so asking about one record and vouching
for the set would let a second, unsigned CNAME at the same owner ride
out under the AD bit, pointing wherever the sender liked. A zone may not
publish two CNAMEs at one name (RFC 1034 section 3.6.2) and a DNAME
synthesizes exactly one, so a set with a second is not a set a DNAME
produced; the loop stops at the first record no DNAME accounts for.
*/
@(private)
dname_rescues :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	records: []dns.Record,
	class: dns.Class,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
	why_lapsed: ^Lapsed,
) -> (
	covered: bool,
	ceiling: u32,
) {
	covered = len(records) > 0
	// No signature of its own, so the DNAME's sets its ceiling.
	ceiling = max(u32)
	for r in records {
		ok, by, dname_lapsed := dname_covered(v, budget, msg, r, class, unix, now, allocator)
		if !ok {
			// Unsigned because its DNAME lapsed: the window is why.
			keep_lapse(why_lapsed, dname_lapsed)
			covered = false
			break
		}
		ceiling = min(ceiling, signed_ttl_ceiling(by, unix))
	}
	return covered, ceiling
}

// Add the sets `proved` does not name yet. Proofs read against one zone come
// from the same `Verified_Denial` memo, so each expansion, and a denial at the
// chain's end, hands back the same sets.
@(private)
name_once :: proc(proved: ^[dynamic]Authenticated_Set, sets: []Authenticated_Set) {
	for s in sets {
		if _, named := authenticated_rrset(proved[:], s.name, s.type, s.class); !named {
			append(proved, s)
		}
	}
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
	// The message's verified denial records, when a wildcard proof over the same
	// authority section may already have read them. See `Verified_Denial`.
	seen: ^[dynamic]Verified_Denial = nil,
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

	Except that for a DS the name asked about is not the zone that answers. A
	DS lives in the parent (RFC 4035 section 5.3.1), so the walk stops at the
	zone holding the parent, and the proof is read against that zone's keys.
	Walking to the name itself would pass through the very DS in question: an
	unsigned delegation would end the walk as insecure before the parent's
	proof that it is unsigned was read, and a signed one would make the child
	the only zone whose records could be checked - the one zone with no say.
	The root has no parent, and keeps its own. See `zone_holding`.
	*/
	zone_of := zone_holding(qname, qtype)
	status, keys, established := zone_trust(v, budget, zone_of, now, allocator)
	#partial switch status {
	case .Insecure:
		return {status = .Insecure, reason = UNSIGNED_ZONE}
	case .Bogus:
		return {status = .Bogus, reason = BROKEN_CHAIN, detail = budget.broken, lapsed = budget.broken_lapsed}
	case .Indeterminate:
		return {status = .Indeterminate, reason = walk_reason(budget)}
	}

	local: [dynamic]Verified_Denial
	if seen == nil {
		local = make([dynamic]Verified_Denial, 0, 1, allocator)
	}
	records := denial_records_for(v, budget, seen if seen != nil else &local, msg.authority, established, class, keys, unix, now, allocator)
	nsecs, nsec3s, denial_spent := records.nsecs, records.nsec3s, records.exhausted
	/*
	Our own allowance again, and the same answer as everywhere else: a proof this
	server stopped short of reading is not a proof it found wanting. Reported as
	`Indeterminate` rather than left to fall through to "no denial of existence",
	which counts a forgery, warns with the client's address beside the word, and
	hands the client extended error 6.
	*/
	if denial_spent {
		return {status = .Indeterminate, reason = exhausted_reason(budget)}
	}
	if len(nsecs) == 0 && len(nsec3s) == 0 {
		// Nothing here spoke for the name, and one reason is that the walk
		// never reached it: a delegation appearing at a name the table still
		// calls no cut leaves the proof signed by a zone `established` is
		// above. See `forget_unreached_non_cut`.
		forget_unreached_non_cut(v, zone_of, established)
		// Or the walk kept a parent's keys past a DS denial it could not read,
		// and this is an unsigned delegation's own answer. See
		// `Budget.walk_past_ceiling`.
		if budget.walk_past_ceiling {
			return {status = .Indeterminate, reason = NSEC3_OVER_CEILING}
		}
		return {status = .Bogus, reason = "no denial of existence", lapsed = records.lapsed}
	}

	before := nsec3_refusals(&budget.nsec3)
	proof := denial_proof(budget, dns.rcode_of(msg), nsecs, nsec3s, qname, qtype, established, allocator)

	return denial_verdict(budget, msg, proof, before, records, qname, established, class, keys, unix, allocator)
}

// `validate_denial`'s verdict once `proof` is known: the allowances and the
// iteration ceiling, then the proof itself. `before` is the NSEC3 refusal count
// before this proof ran.
@(private)
denial_verdict :: proc(
	budget: ^Budget,
	msg: dns.Message,
	proof: Proof,
	before: Nsec3_Refusals,
	records: Verified_Denial,
	qname: string,
	zone: string,
	class: dns.Class,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
) -> Result {
	/*
	Hashing this server declined, and the same answer as the two allowances
	above it. A proof built on a hash we would not compute is not a proof found
	wanting, and `Bogus` says forgery: the client is handed extended error 6,
	"DNSSEC bogus", over a decision of ours. What the client gets instead says
	what happened - and the reason travels with it, so the log line naming this
	query names the allowance too.

	Worth being exact about how far that difference reaches: `server`
	counts and logs the two verdicts in one branch, so the bogus counter ticks
	either way. The extended error, the status the warn line names and the
	reason text are what an operator or a client can tell apart.

	Counted over this proof rather than read off the budget, because the flags
	there belong to the whole question and stay set once anything sets them: an
	NSEC proof, which hashes nothing, would otherwise be filed under an
	allowance it could not have spent.
	*/
	// Named apart from the signature budget, in the reason and in the log,
	// because an operator whose names start failing has to be able to tell
	// SHA-1 rounds from verifications, and both of those from a zone asking for
	// more iterations than this server computes - which is the whole point of
	// saying `Indeterminate` rather than `Bogus`.
	//
	// Except where nothing here was readable at all: that is the zone's number
	// deciding, not a proof we stopped short of, and it is insecure. See
	// `nsec3_all_over_ceiling`.
	if proof == .Failed && nsec3_all_over_ceiling(records.nsecs, records.nsec3s, &budget.nsec3) {
		return {status = .Insecure, reason = NSEC3_OVER_CEILING}
	}
	if declined, why := nsec3_declined(&budget.nsec3, before); proof == .Failed && declined {
		logx.debugf("dnssec: the denial of %s was not read to the end: %s", dns.name_trim_root(qname), why)
		return {status = .Indeterminate, reason = why}
	}

	switch proof {
	case .Proven:
		return {status = .Secure, authority = proved_denial(budget, msg, records.verified, zone, class, keys, unix, allocator)}
	case .Opt_Out:
		return {status = .Insecure, reason = OPT_OUT_SPAN}
	case .Failed:
		if budget.walk_past_ceiling {
			return {status = .Indeterminate, reason = NSEC3_OVER_CEILING}
		}
		return {status = .Bogus, reason = DENIAL_NOT_PROVEN, lapsed = records.lapsed}
	}
	return {status = .Bogus, reason = DENIAL_NOT_PROVEN, lapsed = records.lapsed}
}

// What `nsecs` and `nsec3s`, from `zone`, prove of `qname`'s `qtype`: a name
// error under NXDOMAIN and no data otherwise, NSEC tried before NSEC3.
@(private)
denial_proof :: proc(
	budget: ^Budget,
	rcode: dns.Rcode,
	nsecs: []Nsec_Rr,
	nsec3s: []Nsec3_Rr,
	qname: string,
	qtype: dns.Type,
	zone: string,
	allocator: mem.Allocator,
) -> (
	proof: Proof,
) {
	proof = .Failed
	if rcode == .NX_Domain {
		proof = nsec_proves_name_error(nsecs, qname, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_name_error(nsec3s, qname, zone, &budget.nsec3, allocator)
		}
	} else {
		proof = nsec_proves_no_data(nsecs, qname, qtype, allocator) if len(nsecs) > 0 else .Failed
		if proof != .Proven && len(nsec3s) > 0 {
			proof = nsec3_proves_no_data(nsec3s, qname, zone, qtype, &budget.nsec3, allocator)
		}
	}
	return
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
been spending. Running it out here drops the SOA - the denial stays proven but
loses its negative TTL, and with it its place in the server's cache, which keeps
no denial without a SOA - and says so at debug rather than passing for a
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
	_, signer, carried, ok, _, _ := verified_rrset(budget, msg.authority, zone, .SOA, class, zone, keys, unix, allocator)
	if ok {
		append(&out, authenticated_set(zone, .SOA, class, signer, carried, signed_ttl_ceiling(carried, unix)))
	}
	return out[:]
}

/*
Check one RRset.

Returns the closest encloser a wildcard expansion claimed, empty when the
signature was made over the owner name itself. A wildcard-expanded answer needs
a denial proof of its own that only the caller can assemble, and that proof is
about the name the asterisk stood in for, so the caller has to be told which
name that was rather than merely that there was one.
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
	encloser: string,
	reason: string,
	// Which signature carried the set, for `Authenticated_Set`.
	signer: string,
	rrsig: Rrsig,
	// The window this set's signatures fell outside, on a `Bogus` that rests on
	// it; `refuted` on one whose signature inside its window failed.
	lapsed: Lapsed,
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
	trial: Rrset_Trial
	scratch := Signing_Scratch{budget = budget}
	/*
	One chain walk per distinct signer, not one per signature.

	`zone_trust` is the expensive thing in this loop - a walk down the
	hierarchy, taking the validator's lock and cloning a DNSKEY set out of its
	cache at every step - and no per-RRset attempt cap bounds it. Unmemoised it
	would be the thing an attacker could multiply: a padded answer carrying two
	thousand RRSIGs whose signer merely names an ancestor of the owner would buy
	two thousand walks, thousands of acquisitions of a lock every validating
	query shares, and megabytes of arena, for one question.

	Memoised by signer, which bounds it by the number of ancestors a name has
	rather than by the number of records somebody wrote. Distinct signers are
	the only ones that cost anything, and a name has at most as many ancestors
	as it has labels.
	*/
	walked := make([dynamic]Signer_Walk, 0, 4, allocator)
	/*
	And no signer above the closest anchor (RFC 6840 Appendix C.1): an operator
	who anchors `corp.` has pinned that zone's keys, so a key above the anchor -
	a public ancestor's copy of a split-horizon name - does not vouch for a name
	inside it. Of the holder, so `corp. DS` is still the parent's to sign.
	*/
	anchor := closest_anchor(v.anchors, zone_holding(owner, type))

	for sig in sigs {
		/*
		The window is free, and needs no keys, so it goes above the walk. An expired or
		not-yet-valid signature cannot verify whatever the chain says, and
		refusing it here is what stops a heap of stale forgeries paying for
		chain walks.
		*/
		if !signer_holds(owner, type, sig.signer) || !dns.name_at_or_below(sig.signer, anchor) || !signature_current(sig, unix) {
			continue
		}

		walk := signer_walk(v, budget, &walked, sig.signer, now, allocator)
		if walk.status != .Secure || !dns.name_equal_fold(sig.signer, walk.established) {
			// A signature this server never looked at, because it refused
			// itself the lookup that would have reached the signer. Remembered
			// so the verdict below cannot call the set forged on the strength
			// of one that was not tried; see `signed_zone_verdict`.
			trial.skipped_for_shed ||= walk.shed
			if walk.status == .Indeterminate && !walk.shed && trial.unreached == "" {
				trial.unreached = walk.stopped
			}
			continue
		}
		/*
		Same two guards as the denial path, and for the same reason: a loop that
		stopped after a fixed number of signatures whose signer merely named a zone
		in the owner's ancestry would be at the mercy of a field an attacker writes.
		Eight forgeries in front of the genuine signature would spend the whole
		allowance and the answer would come back Bogus - the very shape
		`MAX_VERIFICATIONS_PER_QUERY` exists to remove, on the path every
		answer-section RRset takes.
		*/
		verified, expanded_from := try_signature(sig, owner, class, records, walk.keys, unix, allocator, &scratch, &trial)
		if verified {
			return .Secure, expanded_from, "", sig.signer, sig, {}
		}
		if trial.exhausted {
			break
		}
	}

	/*
	Nothing verified. Whether that means forged or merely unsigned is a question
	about the zone the name lives in, not about the signatures that arrived with
	it, so it is settled by walking down to the zone that holds the set.
	*/
	/*
	Our own allowance running out is not evidence about the zone.

	`spend_lookup` already settles this the same way: a chain this server could
	not afford to walk comes back `Indeterminate`, `LOOKUPS_SPENT`,
	because the answer might be perfectly good and we simply stopped looking.

	What that changes is the extended error the client is sent - 22, "No
	Reachable Authority", instead of 6, "DNSSEC Bogus" - and the `reason` that
	reaches the log. It does not change `Stats.bogus`: `resolve_query` counts every
	`Bogus` and `Indeterminate` verdict there except this server's own shedding
	and a reading it refused (`server.counts_as_bogus`), so a spent verification
	budget counts like a forgery, which is worth knowing before reading that gauge
	as a forgery count.
	*/
	if trial.exhausted {
		return .Indeterminate, "", exhausted_reason(budget), "", {}, {}
	}

	status, reason, lapsed = unverified_verdict(v, budget, owner, type, sigs, unix, now, allocator, trial)
	return
}

// What `validate_rrset`'s loop found about the signatures it did not verify,
// for the verdict `unverified_verdict` gives.
@(private)
Rrset_Trial :: struct {
	unsupported:      bool,
	exhausted:        bool,
	skipped_for_shed: bool,
	// Why a signer's walk stopped short, for the first signature skipped for
	// it other than by shedding; see the return that reads it.
	unreached:        string,
	// Whether a signature inside its window named a key and was tried, which
	// keeps a lapsed one beside it from being what the verdict is put down to.
	tried:            bool,
}

/*
Try `sig` over the set with its zone's `keys`, recording in `trial` what a
signature that does not verify says about the set; `verified` with the closest
encloser a wildcard expansion claimed, as `check_signature` gives it.
*/
@(private)
try_signature :: proc(
	sig: Rrsig,
	owner: string,
	class: dns.Class,
	records: []dns.Record,
	keys: []Dnskey,
	unix: u32,
	allocator: mem.Allocator,
	scratch: ^Signing_Scratch,
	trial: ^Rrset_Trial,
) -> (
	verified: bool,
	expanded_from: string,
) {
	if !signature_worth_trying(sig, keys, unix) {
		return
	}
	trial.tried = true
	/*
	A third free reject, and one only the policy table can make: this
	signature names a key the zone published, of an algorithm the library
	will not run, so the verdict is known without asking - `verify_signature`
	would answer from the same table and spend a verification getting there.

	Which matters because the allowance is what an attacker fills. A zone
	mid-rollover really does publish the refused algorithm, so copies of its
	own signature pass every cheap test above and would cost a
	verification each: sixty-four of them in front of the one that would
	have held, and the answer is `Indeterminate` and a SERVFAIL for a name
	that resolves.
	*/
	if !algorithm_supported(sig.algorithm) {
		trial.unsupported = true
		return
	}
	if !spend_verification(scratch.budget) {
		trial.exhausted = true
		return
	}
	result, from := check_signature(sig, owner, class, records, keys, unix, allocator, scratch)
	if scratch.over_budget {
		trial.exhausted = true
		return
	}
	#partial switch result {
	case .Ok:
		return true, from
	case .Unsupported, .Refused:
		/*
		The same thing to say about this RRset. One is an algorithm this
		build never implemented and the other one the library declined to
		run, and neither looked at the signature before deciding - so
		neither is evidence that what arrived is genuine, which is all the
		verdict turns on.
		*/
		trial.unsupported = true
	}
	return false, ""
}

// One signer's chain walk as `validate_rrset` remembers it, so that a set whose
// signatures name a signer many times walks to it once.
@(private)
Signer_Walk :: struct {
	signer:      string,
	status:      Status,
	keys:        []Dnskey,
	established: string,
	// Whether this walk was the one turned away for want of a slot, rather
	// than stopped by anything about the zone. `validate_rrset` reads it
	// where a signature it would have judged is skipped.
	shed:        bool,
	// Why it stopped, where it came back `Indeterminate`.
	stopped:     string,
}

// The walk to `signer`: from `walked`, when this RRset's loop already took it,
// and otherwise taken now and remembered there.
@(private)
signer_walk :: proc(
	v: ^Validator,
	budget: ^Budget,
	walked: ^[dynamic]Signer_Walk,
	signer: string,
	now: time.Time,
	allocator: mem.Allocator,
) -> Signer_Walk {
	for w in walked {
		if dns.name_equal_fold(w.signer, signer) {
			return w
		}
	}
	w := Signer_Walk {
		signer = signer,
	}
	w.status, w.keys, w.established = zone_trust(v, budget, signer, now, allocator)
	// Exact for this walk: `zone_trust` clears the reason on the way in,
	// so what is there afterwards is this walk's own.
	w.shed = budget.walk_stopped == WALKS_IN_FLIGHT
	w.stopped = walk_reason(budget) if w.status == .Indeterminate else ""
	// The walk held up and still did not reach the zone this signature
	// names; see `forget_unreached_non_cut`. The signer is the
	// response's to choose rather than the client's, so what it can
	// reach is a name on its own owner's ancestry.
	if w.status == .Secure {
		forget_unreached_non_cut(v, signer, w.established)
	}
	append(walked, w)
	return w
}

/*
The verdict on a set none of whose signatures verified, which is a question
about the zone that holds it and about why signatures went untried: `tried`,
`unsupported`, `skipped_for_shed` and `unreached` are what `validate_rrset`'s
loop found.
*/
@(private)
unverified_verdict :: proc(
	v: ^Validator,
	budget: ^Budget,
	owner: string,
	type: dns.Type,
	sigs: []Rrsig,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
	trial: Rrset_Trial,
) -> (
	status: Status,
	reason: string,
	lapsed: Lapsed,
) {
	missing := "signature missing" if len(sigs) == 0 else "no valid signature"
	// The zone holding the set, which for a DS is the parent: walking to the
	// owner would stop at the parent's proof that an unsigned delegation has no
	// DS, and serve a forged DS set there as merely insecure.
	holder := zone_holding(owner, type)
	owner_status, owner_keys, owner_zone := zone_trust(v, budget, holder, now, allocator)
	// The walk held up and stopped above the holder, and nothing here verified:
	// one reason is a delegation at a name the table still calls no cut, which
	// for an *unsigned* one leaves this the only verdict that can notice. The
	// denial and wildcard paths do the same; see `forget_unreached_non_cut`.
	if owner_status == .Secure {
		forget_unreached_non_cut(v, holder, owner_zone)
	}
	switch owner_status {
	case .Insecure:
		return .Insecure, UNSIGNED_ZONE, {}
	case .Indeterminate:
		return .Indeterminate, walk_reason(budget), {}
	case .Bogus:
		// A signature of this set tried and failed is a forgery beside the
		// chain's lapse, which is code 6 (`takes_reason`).
		return .Bogus, BROKEN_CHAIN, Lapsed{refuted = true} if trial.tried else budget.broken_lapsed
	case .Secure:
	}
	return signed_zone_verdict(budget, sigs, missing, owner_keys, owner_zone, unix, trial)
}

// `unverified_verdict` once the zone holding the set has proven signed: the
// set's own signatures, and why any went untried, decide what is said.
@(private)
signed_zone_verdict :: proc(
	budget: ^Budget,
	sigs: []Rrsig,
	missing: string,
	owner_keys: []Dnskey,
	owner_zone: string,
	unix: u32,
	trial: Rrset_Trial,
) -> (
	status: Status,
	reason: string,
	lapsed: Lapsed,
) {
	/*
	The zone is signed, nothing verified - and this server turned one of its own
	walks away to get here.

	A signature whose signer could not be walked to is skipped above rather than
	tried, so what is left to judge the set on is not the whole of what arrived.
	The walk that stopped may even be the one that mattered: the signer's chain
	is a prefix of the owner's, so a slot freeing in between is all it takes for
	the owner walk below to succeed where the signer walk did not, and the set
	is then called forged on the strength of a signature nobody looked at.
	`Indeterminate` is the honest report - the same one every other allowance in
	this file gives, for the same reason.

	This walk, not this question. `Budget.shed_walk` is sticky across the whole
	question, and reading it here would have a shed anywhere - an earlier RRset,
	a wholly different name in a CNAME chain - excuse a set that was proved
	forged on signatures every one of which was tried. That hides real forgeries
	from `elodin_dnssec_answers_total` and from the log while a flood is on,
	which is the attacker's own doing twice over. `skipped_for_shed` is set only
	where a signature of *this* set went unjudged.

	After the switch, so an `Insecure` owner still wins: an unsigned zone needs
	no signature, and no walk of ours changes that.
	*/
	if trial.skipped_for_shed {
		return .Indeterminate, WALKS_IN_FLIGHT, {}
	}
	/*
	The same for a signer walk that stopped for any other reason - a lookup
	that failed, an allowance spent - and a later walk to the owner that held
	up. A single lost reply is enough: the signature went untried, and might
	have been the genuine one. An upstream that did not answer is not a forgery.
	*/
	if trial.unreached != "" {
		return .Indeterminate, trial.unreached, {}
	}
	// Unsigned, below a DS denial nobody could read: an unsigned delegation or
	// a forgery, and nothing here says which. See `Budget.walk_past_ceiling`.
	// After the shed check, so a signature that went untried is still counted
	// as shed rather than blamed on the zone.
	if budget.walk_past_ceiling {
		return .Indeterminate, NSEC3_OVER_CEILING, {}
	}

	/*
	Nothing here was checkable, and the zone it belongs to is signed with
	something that was.

	An algorithm this build cannot check makes a *delegation* insecure -
	`zone_step` settles that at the DS, per RFC 6840 section 5.2 - but it cannot
	make an RRset inside an established zone insecure, which is the correction
	in section 5.11 of the same document. A zone signed with two algorithms
	publishes an RRSIG for each, so treating this as unsigned would let an
	attacker strip the signature we can verify, alter the records, and have what
	is left reach the client as merely unvalidated instead of refused. The whole
	point of the second algorithm, inverted.

	"Cannot check" covers the algorithm the library declined as well as the one
	this build never implemented, and it has to: the refusal is a decision about
	the algorithm taken before the signature is read, so a forgery earns it as
	readily as the genuine article. Which one it was is settled at the
	delegation instead, where the escape hatch belongs - `probe_algorithms`
	takes a refused algorithm out of `algorithm_supported` at start-up, so a
	zone that publishes only that algorithm has no usable DS and goes insecure
	in front of this loop rather than through it.
	*/
	// `unsupported` is set only on a signature that was tried, so the set is
	// `refuted`, as on every other return that tried one.
	if trial.unsupported {
		return .Bogus, "no signature this build can verify", {refuted = true}
	}
	/*
	Whether that was the window. A lapsed signature never reaches the loop - it
	is turned away before its signer is walked - so the zone's keys are read
	here, off the walk that just established the holder, and checking a
	signature against them is a comparison of two fields apiece. A set that had
	one tried is `refuted`, as in `verified_rrset`.
	*/
	if trial.tried {
		return .Bogus, missing, {refuted = true}
	}
	for sig in sigs {
		if dns.name_equal_fold(sig.signer, owner_zone) {
			note_lapsed(&lapsed, sig, owner_keys, unix)
		}
	}
	return .Bogus, missing, lapsed
}

/*
The name whose zone holds an RRset of `type` at `name`: the name itself, except
for a DS, which lives in the parent (RFC 4035 section 5.3.1). The root has no
parent and `dns.name_parent` keeps it at the root.
*/
@(private)
zone_holding :: proc(name: string, type: dns.Type) -> string {
	return dns.name_parent(name) if type == .DS else name
}

/*
Whether `signer` is the zone that may hold an RRset of `type` at `owner`.

A zone may only sign what is inside it. Without this a zone could vouch for
names it has no authority over, which is the whole point of the hierarchy.

And a DS is the one type a zone never holds at its own apex: it lives in the
parent (RFC 4035 section 5.3.1), so a DS signed by the zone it names is the
child vouching for its own delegation, and its keys are reached through the
genuine DS - the signature verifies, and says nothing. The root has no parent
and so no DS, and nothing may sign one there.
*/
@(private)
signer_holds :: proc(owner: string, type: dns.Type, signer: string) -> bool {
	if !dns.name_at_or_below(owner, signer) {
		return false
	}
	return type != .DS || !dns.name_equal_fold(owner, signer)
}

/*
Try one signature against the keys of its zone.

Rejects everything RFC 4035 section 5.3.1 asks to be rejected before any
cryptography happens: a Type Covered that is not the set's type, the wrong
signer (see `signer_holds`), a label count that does not fit the owner name, an
expired or not-yet-valid period.
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
	scratch: ^Signing_Scratch = nil,
) -> (
	result: Verify_Result,
	encloser: string,
) {
	if !signature_current(sig, unix) {
		return .Bad, ""
	}
	// RFC 4035 section 5.3.1: the RRSIG's Type Covered must equal the RRset's
	// type. Callers filter by type already; read here off the records, so the
	// DS signer rule below never rests on a field the sender wrote.
	if len(records) == 0 || sig.type_covered != records[0].type {
		return .Bad, ""
	}
	if !signer_holds(owner, records[0].type, sig.signer) {
		return .Bad, ""
	}
	/*
	RFC 4034 section 3.1.3 counts the Labels field without a leading `*`, so a
	name that is itself a wildcard - and `*.example.com.` is an ordinary name a
	zone may hold records for - has to be counted the same way here. Counting
	the `*` would make a correct signature look one label short, which is the
	mark of a wildcard expansion, and the answer would be sent off for a proof
	that the name does not exist. It plainly does.

	Only the count the Labels field is compared against drops the asterisk. The
	name still has that label, so reconstructing an encloser out of it has to
	walk the labels the name actually carries.
	*/
	owner_labels := label_count(owner)
	signed_labels := owner_labels - 1 if strings.has_prefix(owner, "*.") else owner_labels
	signer_labels := label_count(sig.signer)
	if int(sig.labels) > signed_labels || int(sig.labels) < signer_labels {
		return .Bad, ""
	}

	// Fewer labels than the owner name means the zone answered from a wildcard,
	// and the signature was made over that wildcard rather than over the name.
	// The name the asterisk stood in for is the closest encloser the answer
	// claims, which is what the caller has to see a denial proof lined up with.
	signing_owner := owner
	if int(sig.labels) < signed_labels {
		encloser = name_drop_labels(owner, owner_labels - int(sig.labels))
		signing_owner = wildcard_of(encloser, allocator)
	}

	data, built := signing_input(sig, signing_owner, class, records, allocator, scratch)
	if !built {
		return .Bad, encloser
	}

	return verify_with_keys(sig, keys, data, allocator), encloser
}

// Verify `sig` over `data` with the keys of `keys` it names, up to
// `MAX_KEYS_PER_SIGNATURE` of them: `.Ok` on the first that verifies, otherwise
// what the keys that did not verify say about the signature.
@(private)
verify_with_keys :: proc(sig: Rrsig, keys: []Dnskey, data: []u8, allocator: mem.Allocator) -> Verify_Result {
	unsupported := false
	refused := false
	/*
	One verification per key the tag names, and the tag names as many keys as
	the zone cares to publish under it - so the attempts are counted. See
	`MAX_KEYS_PER_SIGNATURE`: without this the query's verification budget
	bounds the calls made here rather than the crypto they run, which is the
	collision half of KeyTrap.
	*/
	tried := 0
	for key in keys {
		if key.algorithm != sig.algorithm || key.tag != sig.key_tag || !key_usable(key) {
			continue
		}
		if tried >= MAX_KEYS_PER_SIGNATURE {
			break
		}
		tried += 1
		switch verify_signature(sig.algorithm, key.public_key, sig.signature, data, allocator) {
		case .Ok:
			return .Ok
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
		return .Unsupported
	case refused:
		return .Refused
	}
	return .Bad
}

// One RRset an answer expanded from a wildcard, and the closest encloser that
// expansion claims - the immediate ancestor of the generating wildcard.
@(private)
Wildcard_Expansion :: struct {
	owner:    string,
	encloser: string,
}

/*
Denial records already verified for one message, held for the length of a single
`validate_answer` call.

An answer can expand from more than one wildcard, and every expansion needs the
same authority section verified against the same zone. Verifying it per
expansion is not free, since `validated_denial_records` spends
`MAX_VERIFICATIONS_PER_QUERY`, and the cost would fall on answers that did
nothing wrong. Eight expansions over an authority
section carrying five NSEC3 RRsets is forty verifications for five sets' worth
of information, which alone is most of the allowance - so a legitimate response
would come back `Indeterminate`, and reach the client as SERVFAIL, for being
large rather than for being false.

Keyed by the zone the records were established against. That, with the message
and the class, is everything the verification depends on: the keys are the
zone's, and one `validate_answer` call fixes the rest.
*/
@(private)
Verified_Denial :: struct {
	zone:      string,
	nsecs:     []Nsec_Rr,
	nsec3s:    []Nsec3_Rr,
	verified:  []Authenticated_Set,
	exhausted: bool,
	lapsed:    Lapsed,
}

// The records for `zone`, verifying them if this message has not needed them yet.
@(private)
denial_records_for :: proc(
	v: ^Validator,
	budget: ^Budget,
	seen: ^[dynamic]Verified_Denial,
	authority: []dns.Record,
	zone: string,
	class: dns.Class,
	keys: []Dnskey,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> Verified_Denial {
	for entry in seen^ {
		if dns.name_equal_fold(entry.zone, zone) {
			return entry
		}
	}
	nsecs, nsec3s, verified, exhausted, lapsed := validated_denial_records(
		v,
		budget,
		authority,
		zone,
		class,
		keys,
		unix,
		now,
		allocator,
	)
	entry := Verified_Denial {
		zone      = zone,
		nsecs     = nsecs,
		nsec3s    = nsec3s,
		verified  = verified,
		exhausted = exhausted,
		lapsed    = lapsed,
	}
	append(seen, entry)
	return entry
}

/*
Prove that a wildcard was allowed to answer.

RFC 5155 section 8.8: the verified RRset is what hands the validator a closest
encloser, that encloser being the immediate ancestor of the wildcard that signed
it, and what the zone then has to show is an NSEC or NSEC3 covering the "next
closer" name - the ancestor of `owner` one label below the encloser. That is the
half saying no closer name exists, so the wildcard really was what applied.

Deriving the encloser from the denial records instead would let the sender pick
it. Given a zone holding `*.example.com.` and a real `y.example.com.`, an
attacker can pair a genuine wildcard-signed RRset with the genuine NSEC3s from
an NXDOMAIN for `x.y.example.com.` - one matching `y.example.com.`, one covering
`x.y.example.com.` - and a walk up from the name stops at that match and asks
only for the cover it was handed. The signature reconstructs `*.example.com.`,
so it verifies, and an NXDOMAIN becomes a `Secure` answer. Taking the encloser
from the signature's own label count is what rules that out: the wildcard names
`example.com.`, so the name to see covered is `y.example.com.`, which exists.
*/
@(private)
validate_wildcard_proof :: proc(
	v: ^Validator,
	budget: ^Budget,
	msg: dns.Message,
	owner, encloser: string,
	class: dns.Class,
	seen: ^[dynamic]Verified_Denial,
	unix: u32,
	now: time.Time,
	allocator: mem.Allocator,
) -> (
	status: Status,
	proved: []Authenticated_Set,
	reason: string,
	// The window behind a `Bogus` reason, when it rests on one. See `Lapsed`.
	lapsed: Lapsed,
) {
	// Established from the expanded name, for the same reason as the denial path.
	trust, keys, established := zone_trust(v, budget, owner, now, allocator)
	if trust != .Secure {
		return unproven_zone(budget, trust)
	}
	next_closer := name_drop_labels(owner, label_count(owner) - label_count(encloser) - 1)
	// The denial records were verified against `established`, so a name outside
	// it is not theirs to speak for - a hash of one landing in some span of the
	// zone would say nothing at all.
	if !dns.name_at_or_below(next_closer, established) {
		forget_unreached_non_cut(v, owner, established)
		return .Bogus, nil, WILDCARD_NOT_PROVEN, {}
	}
	denial := denial_records_for(v, budget, seen, msg.authority, established, class, keys, unix, now, allocator)
	/*
	The same allowance, and the same answer. Falling through here reports a
	budget of ours as "wildcard expansion not proven", which reaches the client
	as a forged answer - the one thing every other exhaustion path in this file
	takes care not to say.
	*/
	if denial.exhausted {
		return .Indeterminate, nil, exhausted_reason(budget), {}
	}
	// A cover that shows the next closer name is an empty non-terminal says it
	// exists, so the wildcard could not have answered (RFC 4592 section 2.2.2).
	if len(denial.nsecs) > 0 && !nsec_shows_node(denial.nsecs, next_closer) {
		if _, covered := nsec_covering(denial.nsecs, next_closer); covered {
			return .Secure, denial.verified, "", {}
		}
	}
	before := nsec3_refusals(&budget.nsec3)
	if len(denial.nsec3s) > 0 {
		if cover, covered := nsec3_covering(denial.nsec3s, next_closer, &budget.nsec3); covered {
			// RFC 5155 section 9.2 forbids the AD bit over an opt-out cover:
			// the span may be hiding an unsigned delegation, so the next closer
			// name is not proven absent and the wildcard may not have applied.
			if cover.rr.flags & NSEC3_FLAG_OPT_OUT != 0 {
				return .Insecure, nil, OPT_OUT_SPAN, {}
			}
			return .Secure, denial.verified, "", {}
		}
	}
	/*
	As above: hashing we declined is not a cover we looked for and failed to
	find, and what this counts is what this proof was refused rather than what
	the question has spent. Both answers are SERVFAIL to the client, and the
	difference is the extended error the answer carries and the reason written
	beside it.

	Not `Insecure` when nothing here was readable, unlike a denial past the
	ceiling. A denial served unproven can make a name look absent; a wildcard
	served unproven is a record the zone really signed, handed out for a name
	that may have records of its own - `*.example.` answering for `www.example.`
	on the word of any NSEC3 record the zone ever published, since nothing
	checks which name it covers. That is a substitution, and it stays refused.
	*/
	if declined, why := nsec3_declined(&budget.nsec3, before); declined {
		logx.debugf("dnssec: the wildcard proof for %s was not read to the end: %s", dns.name_trim_root(owner), why)
		return .Indeterminate, nil, why, {}
	}
	// As on the denial path: a proof that speaks for nothing may be one the
	// walk stopped above. See `forget_unreached_non_cut`.
	forget_unreached_non_cut(v, owner, established)
	return .Bogus, nil, WILDCARD_NOT_PROVEN, denial.lapsed
}

// What a wildcard proof comes to when the expanded name's zone came back
// `trust`, short of `Secure`: that verdict, and the reason for it.
@(private)
unproven_zone :: proc(budget: ^Budget, trust: Status) -> (status: Status, proved: []Authenticated_Set, reason: string, lapsed: Lapsed) {
	// A chain this server could not walk, or one that broke, is not a proof
	// that failed, and the two must not reach the log or the client saying
	// the same thing.
	switch trust {
	case .Indeterminate:
		return trust, nil, walk_reason(budget), {}
	case .Bogus:
		return trust, nil, BROKEN_CHAIN, budget.broken_lapsed
	case .Insecure:
		// The expanded name's zone is unsigned, or sits in an opt-out span:
		// nothing to prove, and nothing forged.
		return trust, nil, UNSIGNED_ZONE, {}
	case .Secure:
	}
	return trust, nil, WILDCARD_NOT_PROVEN, {}
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
	// True when the query's verification allowance or its request budget ran
	// out partway through, so that a caller can tell "nothing proved this" from
	// "we stopped looking". `exhausted_reason` says which.
	exhausted: bool,
	// The window of a set dropped for its signatures' validity period alone,
	// for a caller whose proof then fails - `refuted` instead when another set
	// was dropped for a signature inside its window that failed. See `Lapsed`.
	lapsed: Lapsed,
) {
	out_nsec := make([dynamic]Nsec_Rr, 0, 4, allocator)
	out_nsec3 := make([dynamic]Nsec3_Rr, 0, 4, allocator)
	out_verified := make([dynamic]Authenticated_Set, 0, 4, allocator)
	seen := make([dynamic]dns.Question, 0, 4, allocator)

	for rec in authority {
		if rec.type != .NSEC && rec.type != .NSEC3 {
			continue
		}
		if !first_of_rrset(&seen, rec) {
			continue
		}

		records, signer, carried, ok, spent, dropped := verified_rrset(budget, authority, rec.name, rec.type, class, zone, keys, unix, allocator)
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
			keep_lapse(&lapsed, dropped)
			continue
		}
		append(&out_verified, authenticated_set(rec.name, rec.type, class, signer, carried, signed_ttl_ceiling(carried, unix)))

		for r in records {
			append_denial_record(r, &out_nsec, &out_nsec3, allocator)
		}
	}
	return out_nsec[:], out_nsec3[:], out_verified[:], exhausted, lapsed
}

/*
Check one RRset against keys that are already in hand.

The zone is named by the caller rather than taken from the signature, so this
answers "did this zone sign this" and not "did somebody sign this". Every use is
a set already placed in a zone - a denial's records in an authority section, or
the DS set and CNAME a parent answers `zone_step` with - where a signer of the
response's own choosing is precisely what must not be believed.

The attempts are bounded the way `validate_rrset` bounds them, which is not a
per-RRset cap: both spend the query-wide
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
	// True when the query's verification allowance or its request budget ran
	// out before a signature held, which is a statement about this server and
	// not about the records.
	exhausted: bool,
	// The window its signatures fell outside, on a set that did not verify for
	// that alone; `refuted` on one whose signature inside its window failed.
	// See `Lapsed`.
	lapsed: Lapsed,
) {
	records = records_of(section, owner, type, class, allocator)
	if len(records) == 0 {
		return nil, "", {}, false, false, {}
	}
	// As in `validate_rrset`: a set with a signature in its window that failed
	// is not put down to one that lapsed. One that verified and was turned
	// away for expanding a wildcard did not fail, and leaves the window open.
	refuted := false
	scratch := Signing_Scratch{budget = budget}
	for sig in sigs_covering(section, owner, type, class, allocator) {
		if !dns.name_equal_fold(sig.signer, zone) {
			continue
		}
		// Free rejects first, so the budget is spent on signatures that could
		// actually verify rather than on whatever was written in front of them.
		if !signature_worth_trying(sig, keys, unix) {
			note_lapsed(&lapsed, sig, keys, unix)
			continue
		}
		// Bounded across the question rather than per RRset; see
		// `MAX_VERIFICATIONS_PER_QUERY` for why the difference matters.
		if !spend_verification(budget) {
			/*
			Said out loud. Running out here drops the RRset, and a dropped SOA
			takes the denial's negative TTL with it silently - `cache.put` does
			not keep a denial without a SOA, so the same question goes upstream
			every time with nothing anywhere saying why.
			*/
			return spent_set(type, owner, "ran out of verifications")
		}
		/*
		The encloser is what the caller does not get to discard here. A short
		Labels field means the signature was made over `*.<encloser>` and says
		nothing about the owner the record arrived under, so an attacker may
		rewrite that owner freely - and the sets this routine verifies are the
		ones nobody checks a wildcard proof for afterwards. Both are types RFC
		4592 section 4 never has a wildcard produce: an NSEC is synthesised
		only for a query matching it exactly (section 4.7), and a wildcard
		owning an SOA is the apex, which is no source of synthesis (section
		4.1). `signed_labels` drops a literal leading `*.`, so a wildcard's own
		NSEC - the record that proves NODATA for a type the wildcard lacks -
		still comes back with no encloser and still passes.
		*/
		result, encloser := check_signature(sig, owner, class, records, keys, unix, allocator, &scratch)
		if scratch.over_budget {
			// Said out loud for the same reason as running out of
			// verifications above: the set is dropped.
			return spent_set(type, owner, "went past the request budget")
		}
		if result == .Ok && encloser != "" {
			// Said out loud, because the two ways to reach it look identical
			// from the verdict: a relocated record, and a signer that wildcard
			// signed one it should not have. Without this the operator of a
			// zone doing the second reads only `no denial of existence`.
			logx.debugf("dnssec: %s %s verified against %s but its signature expanded a wildcard; the set is dropped", dns.type_name(type), dns.name_trim_root(owner), dns.name_trim_root(encloser))
		}
		if result == .Ok && encloser == "" {
			return records, sig.signer, sig, true, false, {}
		}
		refuted ||= result != .Ok
	}
	return nil, "", {}, false, false, Lapsed{refuted = true} if refuted else lapsed
}

// `verified_rrset`'s result for a set dropped because `what` ran out before a
// signature held, said in the debug log.
@(private)
spent_set :: proc(
	type: dns.Type,
	owner: string,
	what: string,
) -> (
	records: []dns.Record,
	signer: string,
	rrsig: Rrsig,
	ok: bool,
	exhausted: bool,
	lapsed: Lapsed,
) {
	logx.debugf("dnssec: %s %s %s before a signature held; the set is dropped", dns.type_name(type), dns.name_trim_root(owner), what)
	return nil, "", {}, false, true, {}
}
