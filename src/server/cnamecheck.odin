package server

import "core:mem"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:filter"
import "elodin:logx"

/*
Names one answer may be looked up under.

Sixteen, which is what the validator allows its own chain walk
(`dnssec.MAX_CNAME_CHAIN`) and for the same reason: a real chain is one or two
hops, and a longer one is a loop or an answer trying to make us work rather than
be believed. Kept as a number of this package's own rather than read from the
validator's, because the two bound different work - that one bounds signature
chasing, which costs upstream queries, and this one bounds list lookups over
records already in hand - and sharing the constant would let a change made for
one of those silently retune the other.

Counted in names matched rather than in hops followed, which for any answer a
zone would publish is the same number. It is not the same number for an answer
built to be expensive: one owner name may carry a thousand CNAMEs, every one of
them a name to look up and each a branch of its own to walk, and a cap on the
hops alone would let the width of the answer through while bounding only its
length. What is left is one scan of the answer section per name walked - a
string compare that fails on the first byte for all but the records sharing that
owner - so the whole walk is bounded at seventeen passes over an answer whose
size the decoder has already bounded.
*/
@(private)
MAX_CHAIN_NAMES :: 16

/*
What the walk concluded about an answer.

The three are kept apart because they are three different things to an operator:
one names a rule they wrote, one says the answer was too long to check, and one
says a record in it could not be read. All three withhold the answer, and an
operator whose site broke needs to know which - being sent to look for a
seventeen-name chain that does not exist is worse than being told nothing.

Stored in the cache as the byte behind them, so a remembered refusal still says
which of the three it was.
*/
@(private)
Cloak_Verdict :: enum u8 {
	Clear,
	Listed,
	Unwalkable,
	Unreadable,
}

/*
What outcome a verdict is reported under.

`Unreadable` is a failure rather than a refusal - see `refuse_cloaked` - so the
counters and the query log have to agree with the rcode that goes out. Written
once here rather than at each of the four places a verdict is turned into a
return, which is how the two would drift.
*/
@(private)
cloak_outcome :: proc(verdict: Cloak_Verdict) -> Outcome {
	return .Failed if verdict == .Unreadable else .Blocked
}

/*
Whether a verdict is one to remember against the stored answer.

`Listed` and `Unwalkable` are stable facts about an answer somebody built - a
name is on a list, a chain is seventeen long - and re-deriving them on every hit
is the cost that made a cloaked name the most expensive kind to serve. Those are
worth keeping.

`Unreadable` is not a fact about anything stable. It is the case the SERVFAIL was
chosen for, an upstream or a middlebox having a bad day, and keeping it turns
that bad minute into a bad day: the entry answers SERVFAIL until it expires with
the upstream never asked again, and a reload cannot release it because the
re-walk reads the same bytes and reaches the same verdict.

Asked here rather than written out at each site that persists a verdict, because
writing it out is how the two sites came to disagree: the forwarding path was
taught this and the cache's own recheck was not, so an answer that went in clean
and turned unreadable on a later walk was pinned exactly as before. A third site
should have to answer this question rather than remember to.
*/
@(private)
cloak_verdict_worth_keeping :: proc(verdict: Cloak_Verdict) -> bool {
	switch verdict {
	case .Listed, .Unwalkable:
		return true
	case .Clear, .Unreadable:
		return false
	}
	return false
}

/*
The name on the lists that this answer redirects to, if it redirects to one.

Blocking the question and nothing else is a rule a list author cannot write
against. The tracker is given a name inside the site's own zone -
`metrics.brand.example` CNAME `tracker.evil.example` - so the question the
browser asks is a first-party name that will never appear on anybody's list, and
the address it ends up connecting to is the tracker's, with the site's own
cookies attached, which is the entire point of the arrangement. Pi-hole calls
the answer to this deep CNAME inspection and AdGuard Home runs its filters over
the CNAME targets; this is the same check.

The chain is walked from the question rather than matched against every name the
answer section happens to mention, because the chain is what a client follows.
Both are bounded work, and the difference is which way they fail: a scan over
every record would also match names that no question reaches - a hostile
responder can put whatever it likes in there - and turn those into a withheld
answer for a site that did nothing.

The question name is matched again here even though the caller has already
matched it. It cannot come back `Blocked`, because that answer was already given
above; it can come back `Allowed`, and an operator who wrote an exception for
the name they asked about meant the lookup, not the label.

That second match is behind a look for a CNAME in the answer at all, which
nearly every answer there is does not have. Every forwarded response reaches
this, so an address answer would otherwise pay a normalise, a lock and two hash
lookups to learn what the walk below would have told it for nothing: with no
CNAME anywhere in the section there is no target to return, whatever the lists
say about the question.

An allow rule speaks for the name it names and for nothing else. `engine_match`
resolves allow over block for a single name, and that is the whole of what it
settles: an allowed name is not a block, and the walk goes on. It does not
excuse a *different* name found beside it.

Hoisting it to the answer - any allowed name anywhere clears the lot - was the
first shape of this and it handed the whole check away. The party that writes
the answer section is the party this feature is aimed at, so it may write
whatever names it likes into it: one extra CNAME at the question's owner
pointing at any host the operator has ever allowlisted, the tracker's CNAME
beside it, and the answer went out intact. Every allowlist entry was a master
key, and an allowlist is a thing operators add to precisely because they had to
unbreak something.

So the only whole-answer exemption is an allow rule on the *question*, matched
above before any of this runs. That one is safe because the question is the
client's, not the responder's: nobody but the client chooses what gets asked.
It is also the escape hatch to reach for when a first-party name resolves
through a CDN somebody has listed - name the first-party lookup, not the CDN.

A block found early still does not end the walk, because the walk is also
looking for the budget's end.

A DNAME is not followed, and for an answer built to RFC 6672 section 3.1 it does
not need to be: the responder synthesizes the CNAME that the redirection amounts
to and puts it in the same answer, so the name the client ends up at is already
on this walk. Matching the DNAME's own target instead would be matching a suffix
- a rule naming `bar.example` says nothing about whether `x.bar.example` is
listed - and would withhold a whole subtree on the strength of a name nobody
asked for.

What that leaves open is a responder which omits the synthesized CNAME while a
client derives the target from the DNAME itself, which is a decoder differential
rather than an oversight: this walk sees no redirection and clears the answer,
and a client that synthesizes follows one. Stub resolvers do not generally
synthesize, and the responder has to be the party running the cloaked zone for
it to matter - which is why it is written down here rather than closed. Closing
it means doing the suffix substitution properly and matching what comes out,
not matching the DNAME's target as a name.

A CNAME whose RDATA this decoder would not parse arrives as `Rdata_Raw`, and the
answer is refused rather than walked past it. There is no target in hand to look
up, so what the record redirects onto is exactly the thing this check cannot
find out - and passing over it was the last place here that answered "cannot
tell" with "serve it". The rest of this file, and both unreadable-answer paths in
the resolver, answer it the other way.

It costs nothing that a client keeps: a CNAME reaches `Rdata_Raw` only when the
name inside it ran outside the message, pointed forward, or came to more than
255 octets, and the whole message decoded around it - so this is a target the
client cannot read either, in an answer that otherwise parsed.
*/
@(private)
cloaked_chain_target :: proc(
	s: ^Server,
	answer: []dns.Record,
	qname: string,
) -> (
	target: string,
	verdict: Cloak_Verdict,
) {
	if !s.cfg.blocking.enabled || s.filters == nil || len(answer) == 0 {
		return "", .Clear
	}

	redirects := false
	for r in answer {
		if r.type == .CNAME {
			redirects = true
			break
		}
	}
	if !redirects {
		return "", .Clear
	}

	if filter.engine_match(s.filters, qname) == .Allowed {
		return "", .Clear
	}

	/*
	Names still to have their own CNAMEs looked for, the question first.

	A work list rather than a single name carried forward, because an owner may
	hold more than one CNAME and each of them is a name a client may end up at.
	Following only the first would leave the rest matched but not walked, and a
	decoy one hop deep - an innocent target listed first, the tracker reached
	through the second - would carry the whole chain below it past this.

	The budget is spent when a name joins this list, not when a record naming it
	is found, and the two are only the same number for an answer nobody built to
	be awkward. A name already on the list is passed over entirely - not matched
	again, not counted again - which is what stops a chain that loops from
	spending the budget going round it, and what stops the cheapest evasion there
	is: the same CNAME written out sixteen times is sixteen records to scan but
	one name to look up, and charging for each copy would let a padded answer use
	the budget up before the walk reached the record that mattered. No chain to
	build, no second zone to run, just the one line repeated.

	So `tail` is the count, and there is no separate one to keep in step with it.
	The list holds the question plus at most `MAX_CHAIN_NAMES` targets, which is
	the bound on lookups; the scan below runs once per name on it, which is the
	bound on passes over the answer.
	*/
	pending: [MAX_CHAIN_NAMES + 1]string
	pending[0] = qname
	head, tail := 0, 1

	for head < tail {
		name := pending[head]
		head += 1
		for r in answer {
			if r.type != .CNAME || !dns.name_equal_fold(r.name, name) {
				continue
			}
			v, is_name := r.data.(dns.Rdata_Name)
			if !is_name {
				// A name already matched is the better thing to report: it is
				// the same answer either way, and one of the two has a rule
				// behind it that an operator can go and look at. Same
				// preference as the budget's, below.
				if target != "" {
					return target, .Listed
				}
				return "", .Unreadable
			}
			/*
			Every CNAME at this owner is walked, not just the first. A name may
			own one CNAME and nothing else (RFC 1034 section 3.6.2), so a second
			is a broken answer - but it is one somebody wrote on purpose, and
			which of them a client picks is the client's business rather than
			something to guess at here.
			*/
			seen := false
			for i in 0 ..< tail {
				if dns.name_equal_fold(pending[i], v.name) {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
			/*
			The walk has outrun its budget, and the answer is refused rather
			than served.

			Serving it was the whole of the evasion this check exists to stop.
			An attacker who can write the answer can write as many distinct
			names into it as it likes, and while the budget bounded the work it
			did nothing about what happened at the end of it: the walk stopped,
			the listed name sat one hop past where it stopped, and the answer
			went out. A plain eighteen-name chain did it - no repetition, no
			malformed record, nothing a client would not follow to the end.

			So the budget now bounds the work *and* the answer. An answer this
			server could not finish checking is one it does not know about, and
			the honest thing to do with a name it does not know about is decline
			it, exactly as it declines a name it knows is listed.

			Returning here rather than matching what is left is deliberate. The
			verdict is settled - the answer is going to be withheld either way -
			so going on would only be work an attacker chose the size of, and
			`seen` cannot record a name there is no room to store, which is what
			would make that work unbounded.

			What this costs is an allowlist entry that would have matched past
			the budget, on a chain of more than sixteen names. No zone publishes
			one; the escape hatch for a name that somehow needs it is an allow
			rule on the question, which is matched above before any of this runs.
			*/
			if tail >= len(pending) {
				if target != "" {
					return target, .Listed
				}
				return "", .Unwalkable
			}
			pending[tail] = v.name
			tail += 1

			switch filter.engine_match(s.filters, v.name) {
			case .Blocked:
				if target == "" {
					target = v.name
				}
			case .Allowed, .None:
				// Allowed says this name is not a block. It says nothing about
				// the next one; see the note above on why that distinction is
				// the whole of the check.
			}
		}
	}
	return target, .Listed if target != "" else .Clear
}

/*
Turn an answer that redirects onto a listed name into a block.

Both callers hand over an answer they were about to serve - the one an upstream
just produced, and the one the cache held - and get back the response to send
instead. Written as one procedure with the counter and the log line inside it so
that the two paths cannot drift into blocking on different grounds or counting
it differently.

The answer section arrives decoded rather than as wire. Each caller has the
message in hand already - the forwarding path decodes it for the cache and the
hit path to reach this at all - and taking the bytes here meant decoding every
forwarded response a second time for nothing.

The response is built from the question, exactly as a block on the question is:
what the client asked for is `www.brand.example`, and `blocking.response` says
what a blocked name is answered with. It gets the same `Blocked` outcome and the
same counter - it is the same rule set refusing the same lookup - and a detail of
`cname` rather than `list`, because "the name you asked for is on a list" and
"the answer to the name you asked for leads to one" are different things to an
operator reading a query log, and only the second one has a name in it that the
log line does not carry. That name goes out at debug, once per blocked query,
which is where somebody working out why a site broke will look for it.
*/
@(private)
block_cloaked_answer :: proc(
	s: ^Server,
	answer: []dns.Record,
	msg: dns.Message,
	q: dns.Question,
	proto: Protocol,
	client: string,
	limit: int,
	started: time.Time,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	verdict: Cloak_Verdict,
) {
	target, reached := cloaked_chain_target(s, answer, q.name)
	if reached == .Clear {
		return nil, .Clear
	}
	return refuse_cloaked(s, target, reached, msg, q, proto, client, limit, started, allocator), reached
}

/*
Serve a refusal the walk has already decided on.

Split out so that the cache can hand back a verdict it recorded earlier without
the walk being run again to re-reach it - see `serve_from_cache`. The counter,
the log line and the response are all here rather than at the two call sites, so
that an answer refused from the cache and one refused on the way in cannot come
to differ in what an operator is shown or in what is counted.
*/
@(private)
refuse_cloaked :: proc(
	s: ^Server,
	target: string,
	verdict: Cloak_Verdict,
	msg: dns.Message,
	q: dns.Question,
	proto: Protocol,
	client: string,
	limit: int,
	started: time.Time,
	allocator: mem.Allocator,
) -> []u8 {
	/*
	A record this server could not read is a failure, not a policy answer.

	The other two refusals are things somebody built: a name on a list, and a
	chain of seventeen that no zone publishes. `blocking.response` is the right
	shape for those - the operator asked for NXDOMAIN or an address, and that is
	what a refused lookup gets.

	An unreadable record is not that. One malformed CNAME is as likely to be an
	upstream or a middlebox having a bad day as it is to be an attack, and
	answering it through `blocking.response` tells the client something confident
	and wrong: with the default it is NXDOMAIN, so a name that exists is reported
	not to, with no rule behind it and nothing in the lists to explain it, and
	the stub caches that for `blocking.block_ttl`. Under `zero_ip` or `custom_ip`
	it is worse - NOERROR and an address, which the client will try to connect
	to.

	SERVFAIL says what actually happened and is the only one of the three a stub
	will retry or fail over from. It is also what `answer-unreadable` returns for
	the wider version of the same problem, so the narrow case no longer answers
	more confidently than the broad one.
	*/
	if verdict == .Unreadable {
		sync.atomic_add(&s.stats.failed, 1)
		logx.debugf(
			"%s %s from %s redirects onto a name this server could not read, so where it leads could not be checked; withheld",
			dns.type_name(q.type),
			dns.name_trim_root(q.name),
			client,
		)
		out, _ := dns.error_response(nil, msg, .Serv_Fail, allocator, limit)
		log_query(s, client, proto, q, .Failed, "cname-unreadable", started)
		return out
	}

	sync.atomic_add(&s.stats.blocked, 1)
	if verdict == .Unwalkable {
		logx.debugf(
			"%s %s from %s redirects through more than %d names, which is more than this server will follow; withheld",
			dns.type_name(q.type),
			dns.name_trim_root(q.name),
			client,
			MAX_CHAIN_NAMES,
		)
	} else if target == "" {
		/*
		A refusal the cache remembered, which records that the answer redirects
		onto a listed name without keeping which one - see `serve_from_cache`.
		Worded for what is actually known rather than printed with an empty name
		in the sentence, which is what naming a target this path has not got
		amounts to.
		*/
		logx.debugf(
			"%s %s from %s redirects onto a name on the block list, found when the answer was first checked",
			dns.type_name(q.type),
			dns.name_trim_root(q.name),
			client,
		)
	} else {
		logx.debugf(
			"%s %s from %s is a cname to %s, which is on the block list",
			dns.type_name(q.type),
			dns.name_trim_root(q.name),
			client,
			dns.name_trim_root(target),
		)
	}
	out := build_block_response(s, msg, q, allocator, limit)
	detail := "cname-deep" if verdict == .Unwalkable else "cname"
	log_query(s, client, proto, q, .Blocked, detail, started)
	return out
}

/*
Whether a refusal the cache remembers is still this server's to act on.

The verdict was recorded under a rule set, and the number that says whether that
set is current is what `recheck` already answers. What it cannot answer is
blocking having been switched off entirely since, which would make a remembered
refusal this server declining a name under a feature the operator has turned
off.

Nothing can switch it off today: SIGHUP re-reads the certificates and the lists
and nothing else, so `blocking.enabled` is fixed for the life of the process and
this half of the guard is a constant. It is kept as the cheap half of a
condition that is about to be read wrongly the day configuration reload grows -
not as a claim that reload exists.
*/
@(private)
cloak_refusal_stands :: proc(s: ^Server) -> bool {
	return s.cfg.blocking.enabled && s.filters != nil
}
