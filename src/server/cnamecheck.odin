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
them a name to look up, and a cap on the hops alone would let the width of the
answer through while bounding only its length. What is left is the record scan
per hop, which is a string compare that fails on the first byte for all but the
few records that share the owner name being followed.
*/
@(private)
MAX_CHAIN_NAMES :: 16

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

Allow beats block anywhere in the chain, which is how `engine_match` already
resolves the two for a single name, and is the only escape hatch there is for a
first-party name whose CDN or analytics host is on somebody's list. So the walk
runs to the end of the chain before returning a block rather than stopping at
the first one.

A DNAME is not followed, and does not need to be: RFC 6672 section 3.1 has the
responder synthesize the CNAME that the redirection amounts to and put it in the
same answer, so the name the client ends up at is already on this walk. Matching
the DNAME's own target instead would be matching a suffix - a rule naming
`bar.example` says nothing about whether `x.bar.example` is listed - and would
withhold a whole subtree on the strength of a name nobody asked for.

A CNAME whose RDATA this decoder would not parse arrives as `Rdata_Raw`, and is
passed over: there is no target in hand to look up. Refusing the answer instead
would turn a malformed record into a withheld name, and a target this server
cannot read is one the client is being handed in the same unreadable state.
*/
@(private)
cloaked_chain_target :: proc(
	s: ^Server,
	wire: []u8,
	qname: string,
	allocator: mem.Allocator,
) -> (
	target: string,
	found: bool,
) {
	if !s.cfg.blocking.enabled || s.filters == nil {
		return "", false
	}
	msg, err := dns.decode_message(wire, allocator)
	if err != .None || len(msg.answer) == 0 {
		return "", false
	}

	if filter.engine_match(s.filters, qname) == .Allowed {
		return "", false
	}

	name := qname
	looked_up := 0
	for looked_up < MAX_CHAIN_NAMES {
		next := ""
		for r in msg.answer {
			if looked_up >= MAX_CHAIN_NAMES {
				break
			}
			if r.type != .CNAME || !dns.name_equal_fold(r.name, name) {
				continue
			}
			v, is_name := r.data.(dns.Rdata_Name)
			if !is_name {
				continue
			}
			/*
			Every CNAME at this owner is matched, not only the one the walk goes
			on to follow. A name may own one CNAME and nothing else (RFC 1034
			section 3.6.2), so a second is a broken answer - but it is a broken
			answer somebody wrote on purpose, and which of the two a client picks
			is the client's business. Matching only the first would let a decoy
			hop carry the listed one past this.
			*/
			looked_up += 1
			switch filter.engine_match(s.filters, v.name) {
			case .Allowed:
				return "", false
			case .Blocked:
				if target == "" {
					target = v.name
				}
			case .None:
			}
			if next == "" {
				next = v.name
			}
		}
		if next == "" {
			break
		}
		name = next
	}
	return target, target != ""
}

/*
Turn an answer that redirects onto a listed name into a block.

Both callers hand over an answer they were about to serve - the one an upstream
just produced, and the one the cache held - and get back the response to send
instead. Written as one procedure with the counter and the log line inside it so
that the two paths cannot drift into blocking on different grounds or counting
it differently.

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
	wire: []u8,
	msg: dns.Message,
	q: dns.Question,
	proto: Protocol,
	client: string,
	limit: int,
	started: time.Time,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	blocked: bool,
) {
	target, cloaked := cloaked_chain_target(s, wire, q.name, allocator)
	if !cloaked {
		return nil, false
	}
	sync.atomic_add(&s.stats.blocked, 1)
	logx.debugf(
		"%s %s from %s is a cname to %s, which is on the block list",
		dns.type_name(q.type),
		dns.name_trim_root(q.name),
		client,
		dns.name_trim_root(target),
	)
	out := build_block_response(s, msg, q, allocator, limit)
	log_query(s, client, proto, q, .Blocked, "cname", started)
	return out, true
}
