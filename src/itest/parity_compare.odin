package itest

import "core:fmt"
import "core:mem"
import "core:strings"

/*
Hold elodin's answer against the upstream's and say where they differ.

The rule the comparison enforces is that a forwarding resolver is a pipe: what
came in goes out. Every place elodin is nonetheless entitled to change something
has to be written down here, with the reason, and anything not written down is a
failure. That is deliberate and it is the whole value of the file - a divergence
nobody can name is a divergence nobody decided on, and the way this test earns
its keep is by making someone name it.

Two things the resolver does are outside the comparison rather than allowed
inside it, because for them there is no upstream answer to compare against at
all: a name the sinkhole blocks, and a name a rewrite answers. Both are settled
before an upstream is consulted, and both have cases of their own elsewhere in
this suite.
*/

Parity_Mode :: enum u8 {
	/*
	Compare against the bytes a mock upstream actually put on the wire.

	The strongest form: the reference is not another answer to the same
	question, it is the very message elodin was handed, so any difference is
	elodin's doing and nothing else's.
	*/
	Mock,
	/*
	Compare against a second, byte-identical query put to the same resolver
	directly.

	Weaker, because a real resolver may answer the same question twice in two
	ways, and everything this mode reports has to survive that (see
	`parity_stable_twice`). What it buys is answers no mock would think to
	serve.
	*/
	Live,
}

Parity_Policy :: struct {
	mode: Parity_Mode,
	// Validation is on. It decides whether the AD bit may be set at all and
	// whether DNSSEC records are stripped for a client that did not ask for
	// them.
	dnssec_validation: bool,
	/*
	Hold a TTL to the upstream's exactly.

	True only in the mock mode, and only because that mode earns it: the
	reference there is the very message elodin was handed, so the TTL that comes
	out must be the TTL that went in and any other number is a finding.

	The live mode cannot have this. Its reference is a separate fetch of the
	same name at a slightly different moment, and both sides are serving copies
	that have been counting down since whenever each was taken - so the two
	numbers differ by an amount that says nothing about elodin. Bounding it does
	not help either: a resolver whose cached copy is nearly expired reports a
	handful of seconds where a fresh fetch reports the zone's full TTL, and any
	bound loose enough to admit that is loose enough to admit anything. So the
	live mode names the difference and moves on, and the strict check lives
	where it can actually hold.
	*/
	ttl_exact: bool,
	// The client's transport, which decides whether padding may appear and
	// whether the answer had to fit a datagram.
	transport: Parity_Transport,
	// What the client advertised it could receive, or 512 with no EDNS.
	client_udp_limit: int,
}

// The smallest an OPT record can be on the wire: a root owner name, the type,
// the class carrying the payload size, the four TTL bytes and an empty RDATA.
PC_MIN_OPT :: 1 + 2 + 2 + 4 + 2

Parity_Kind :: enum u8 {
	Parse,
	Identity,
	Header,
	Rcode,
	Question,
	Answer,
	Authority,
	Additional,
	Edns,
}

Parity_Diff :: struct {
	kind:     Parity_Kind,
	what:     string,
	upstream: string,
	elodin:   string,
	// Empty for a failure. Anything else is the written-down reason this
	// difference is the resolver doing its job.
	reason:   string,
}

parity_failed :: proc(diffs: []Parity_Diff) -> bool {
	for d in diffs {
		if d.reason == "" {
			return true
		}
	}
	return false
}

Parity_Compare :: struct {
	diffs:     [dynamic]Parity_Diff,
	allocator: mem.Allocator,
	// The two messages, kept so a failing query can be printed in full without
	// the caller having to carry them alongside.
	reference: []u8,
	answer:    []u8,
	// True when the two messages were the same bytes once the transaction ID
	// and the question's case are set aside. Not required - a re-encoded
	// message can be perfectly faithful - but a run's proportion of them is the
	// quickest read on whether the fast path is still the fast path.
	identical: bool,
}

parity_compare :: proc(
	q: Parity_Query,
	up_wire: []u8,
	el_wire: []u8,
	policy: Parity_Policy,
	allocator := context.temp_allocator,
) -> Parity_Compare {
	c := Parity_Compare {
		diffs     = make([dynamic]Parity_Diff, 0, 8, allocator),
		allocator = allocator,
		reference = up_wire,
		answer    = el_wire,
	}

	up := pw_parse(up_wire, allocator)
	el := pw_parse(el_wire, allocator)
	c.identical = pc_same_but_for_id(up_wire, el_wire)

	if !up.ok || !el.ok {
		pc_parse_diff(&c, up, el)
		return c
	}

	pc_identity(&c, q, el)
	dropped := pc_first_dropped(&c, up, el)
	pc_header(&c, q, up, el, policy, dropped)
	pc_records(&c, q, up, el, policy)
	pc_edns(&c, q, up, el, policy, dropped)
	return c
}

/*
What a record would have cost the message that left it out, in bytes.

Its best case - a two-byte compression pointer for the owner name, the ten
fixed bytes, and the RDATA - because the question every caller is asking is
whether elodin *could* have carried it. Over-estimating would excuse a record
left out with room to spare, which is the thing they are all here to catch.

Both ways, in truth, and the sentence above is the intent rather than a
guarantee.

Under by the owner name, where a record was written with compression already
turned off - which `encode_message` does for the rest of a message once it
has dropped an additional record. That one is not left to the intent:
`pc_missing` charges the full name to a record dropped behind another.

Over by whatever a name inside the RDATA would have compressed to, because
`pw_canonical_rdata` expands those and `w_record` writes them back compressed
for the types that may carry one - NS, MX, PTR, SOA and the rest of
`rdata_name_compressible` - none of which any shape the mock serves puts in an
additional section. Over-charging excuses a record that had room, which is the
quieter way to be wrong and so the one to know about.
*/
@(private = "file")
pc_rr_cost :: proc(rec: Pw_RR) -> int {
	return 2 + 10 + len(rec.rdata)
}

/*
The first record the upstream sent that elodin did not, in bytes on the wire.

-1 when elodin kept everything. Used to judge a TC bit: truncation is the
protocol working only if there was genuinely no room, and the record that decides
that is this one - the next one that would have been written.

The first rather than the smallest, because a message is truncated by dropping a
tail. Sections come in a fixed order and a record cannot be lifted out of the
middle to make a later one fit, so a small record further down being left out
says nothing; the only question is whether the one at the truncation point would
have gone in.

Costed by `pc_rr_cost`, like every other record whose room is in question.
*/
@(private = "file")
pc_first_dropped :: proc(c: ^Parity_Compare, up, el: Pw_Msg) -> int {
	// Matches are consumed as they are found. Without that, a section holding
	// forty copies of one record reads as complete however few of them came
	// back: every upstream copy matches the one elodin kept, and a truncation
	// that dropped thirty-six records looks like a truncation that dropped
	// none.
	next :: proc(c: ^Parity_Compare, up_recs, el_recs: []Pw_RR) -> int {
		taken := make([]bool, len(el_recs), c.allocator)
		for u in up_recs {
			key := pw_rr_key_folded_no_ttl(u, c.allocator)
			found := false
			for e, i in el_recs {
				if taken[i] {
					continue
				}
				if pw_rr_key_folded_no_ttl(e, c.allocator) == key {
					taken[i] = true
					found = true
					break
				}
			}
			if !found {
				return pc_rr_cost(u)
			}
		}
		return -1
	}
	if n := next(c, up.answer, el.answer); n >= 0 {
		return n
	}
	if n := next(c, up.authority, el.authority); n >= 0 {
		return n
	}
	return next(c, up.additional, el.additional)
}

@(private = "file")
pc_add :: proc(c: ^Parity_Compare, kind: Parity_Kind, what, upstream, elodin, reason: string) {
	append(
		&c.diffs,
		Parity_Diff {
			kind = kind,
			what = what,
			upstream = upstream,
			elodin = elodin,
			reason = reason,
		},
	)
}

@(private = "file")
pc_parse_diff :: proc(c: ^Parity_Compare, up, el: Pw_Msg) {
	switch {
	case !up.ok && !el.ok:
		// Both unreadable by this walker. Not elodin's doing, and reported so
		// a run full of them is visible rather than counted as agreement.
		pc_add(
			c,
			.Parse,
			"neither message parses",
			up.err,
			el.err,
			"the reference did not parse either, so there is nothing to hold elodin to",
		)
	case !up.ok:
		pc_add(c, .Parse, "the upstream answer does not parse", up.err, "parses", "")
	case:
		pc_add(c, .Parse, "elodin's answer does not parse", "parses", el.err, "")
	}
}

/*
The two properties a client uses to decide an answer is its own.

Not parity - neither is a copy of anything the upstream sent - but checked here
because the parity generator is the only thing in the suite that varies them
together, and a resolver that echoed the question in the wrong case would
otherwise pass every case in this file while every real stub threw its answers
away.
*/
@(private = "file")
pc_identity :: proc(c: ^Parity_Compare, q: Parity_Query, el: Pw_Msg) {
	if el.id != q.id {
		pc_add(
			c,
			.Identity,
			"transaction id",
			fmt.aprintf("%d (asked)", q.id, allocator = c.allocator),
			fmt.aprintf("%d", el.id, allocator = c.allocator),
			"",
		)
	}
	if len(el.question) != 1 {
		pc_add(
			c,
			.Question,
			"question count",
			"1 (asked)",
			fmt.aprintf("%d", len(el.question), allocator = c.allocator),
			"",
		)
		return
	}
	got := el.question[0]
	if !pc_bytes_equal(got.name, q.name) {
		pc_add(
			c,
			.Question,
			"question name is not echoed byte for byte",
			pw_name_text(q.name, c.allocator),
			pw_name_text(got.name, c.allocator),
			"",
		)
	}
	if got.type != q.qtype || got.class != q.qclass {
		pc_add(
			c,
			.Question,
			"question type or class",
			fmt.aprintf("TYPE%d CLASS%d", q.qtype, q.qclass, allocator = c.allocator),
			fmt.aprintf("TYPE%d CLASS%d", got.type, got.class, allocator = c.allocator),
			"",
		)
	}
}

@(private = "file")
pc_header :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	up, el: Pw_Msg,
	policy: Parity_Policy,
	first_dropped: int,
) {
	pc_flag(c, "qr", true, el.qr, "")
	if up.opcode != el.opcode {
		// Not through `pc_flag`: its two columns are the values, and passing a
		// predicate through them prints "upstream 0, elodin 1" for every
		// mismatch whatever the opcodes were - which is the one thing a reader
		// needs from the line.
		pc_add(
			c,
			.Header,
			"opcode",
			fmt.aprintf("%d", up.opcode, allocator = c.allocator),
			fmt.aprintf("%d", el.opcode, allocator = c.allocator),
			"",
		)
	}

	if up.rcode != el.rcode {
		pc_add(
			c,
			.Rcode,
			"rcode",
			pc_rcode_text(up.rcode, c.allocator),
			pc_rcode_text(el.rcode, c.allocator),
			"",
		)
	}

	pc_flag(c, "aa (authoritative answer)", up.aa, el.aa, "")
	pc_flag(c, "rd (recursion desired)", q.rd, el.rd, "")
	/*
	CD is judged against the client's query rather than against the upstream's
	answer.

	It is not a field to copy: RFC 4035 section 3.2.2 has a responder echo the
	CD it was asked with, and this server asks its own upstream with CD set when
	it means to validate for itself. So the upstream's CD describes the question
	this server put, and the client's describes the question the client put; the
	only one that belongs in the answer is the client's.
	*/
	pc_flag(c, "cd (checking disabled)", q.cd, el.cd, "")

	if el.z != 0 {
		pc_add(c, .Header, "reserved z bit is set", "0", "1", "")
	}

	// RA says this server offers recursion, which is a fact about this server
	// and not a copy of anything upstream said.
	if !el.ra && el.rcode != 5 {
		pc_add(c, .Header, "ra (recursion available) is clear", "-", "0", "")
	}

	pc_tc(c, up, el, policy, first_dropped)
	pc_ad(c, q, up, el, policy)
}

/*
Truncation.

A datagram that will not hold the answer is cut down and marked, which is the
protocol working rather than data being lost: the client retries over TCP and
gets all of it. So TC set here and clear upstream is allowed - but only over UDP,
and only where there was really no room. Anywhere else a set TC bit is an answer
thrown away.

"No room" is judged on what elodin wrote rather than on what arrived, because
the two differ: this server expands the compressed names inside the RDATA of the
older record types (RFC 3597 section 4, and src/dns/rdata_raw.odin), and an
answer that arrived at 1230 bytes can need more than 1232 once those names are
spelled out. So the test is whether the smallest record left out would have fitted
alongside what was kept. If it would have, the truncation was not forced and the
client is paying for a TCP round trip it did not need.
*/
@(private = "file")
pc_tc :: proc(c: ^Parity_Compare, up, el: Pw_Msg, policy: Parity_Policy, first_dropped: int) {
	if up.tc == el.tc {
		return
	}
	if el.tc && !up.tc {
		if policy.transport == .UDP &&
		   first_dropped >= 0 &&
		   el.size + first_dropped > policy.client_udp_limit {
			// The sizes go in the columns rather than into the reason, so
			// every truncation tallies under one heading in a run's summary
			// instead of each producing a heading of its own.
			pc_add(
				c,
				.Header,
				fmt.aprintf(
					"tc (truncated): %d bytes upstream, %d written, the next record costs %d, and this client's limit is %d",
					up.size,
					el.size,
					first_dropped,
					policy.client_udp_limit,
					allocator = c.allocator,
				),
				"0",
				"1",
				"the answer did not fit the client's datagram, so it is cut and marked for a retry over tcp",
			)
			return
		}
	}
	pc_flag(c, "tc (truncated)", up.tc, el.tc, "")
}

/*
The AD bit.

AD is this server's assertion that it authenticated the data, so it is the one
header bit that must not be copied: forwarding an upstream's AD would be
repeating a claim this server did not check. Clearing it is therefore always
allowed and setting it never is.

Two things clear it (`settle_ad_bit` in src/server/dnssec.odin): validation being
off, and a client that asked for neither DO nor AD, which RFC 6840 section 5.7
says must not be handed one.
*/
@(private = "file")
pc_ad :: proc(c: ^Parity_Compare, q: Parity_Query, up, el: Pw_Msg, policy: Parity_Policy) {
	if up.ad == el.ad {
		return
	}
	if el.ad && !up.ad {
		/*
		AD is an assertion about work this server did, so setting it where the
		reference did not is not necessarily a copy of anything - in the live
		mode it is this server having validated an answer the reference resolver
		did not vouch for. Both are entitled to their own verdict.

		Only in the live mode, and only with validation on. Against the mock
		there is no validator running, so an AD bit could not have been earned
		and can only have been invented.
		*/
		if policy.mode == .Live && policy.dnssec_validation && (q.do_bit || q.ad) {
			pc_add(
				c,
				.Header,
				"ad (authenticated data)",
				"0",
				"1",
				"this server validated the answer itself; ad is its own verdict and not a copy of the reference resolver's",
			)
			return
		}
		pc_add(c, .Header, "ad (authenticated data)", "0", "1", "")
		return
	}
	reason := "validation is off, so this server has authenticated nothing and may not say it has"
	if policy.dnssec_validation {
		if q.do_bit || q.ad {
			pc_add(c, .Header, "ad (authenticated data)", "1", "0", "")
			return
		}
		reason = "the client set neither do nor ad, and RFC 6840 section 5.7 says not to hand it an ad bit it did not ask for"
	}
	pc_add(c, .Header, "ad (authenticated data)", "1", "0", reason)
}

@(private = "file")
pc_flag :: proc(c: ^Parity_Compare, what: string, want, got: bool, reason: string) {
	if want == got {
		return
	}
	pc_add(c, .Header, what, want ? "1" : "0", got ? "1" : "0", reason)
}

// --- records ---------------------------------------------------------------

@(private = "file")
pc_records :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	up, el: Pw_Msg,
	policy: Parity_Policy,
) {
	pc_section(c, q, .Answer, "answer", up.answer, el.answer, up, el, policy)
	pc_section(c, q, .Authority, "authority", up.authority, el.authority, up, el, policy)
	pc_section(c, q, .Additional, "additional", up.additional, el.additional, up, el, policy)
}

@(private = "file")
pc_section :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	kind: Parity_Kind,
	name: string,
	up_recs, el_recs: []Pw_RR,
	up, el: Pw_Msg,
	policy: Parity_Policy,
) {
	taken := make([]bool, len(el_recs), c.allocator)
	/*
	A record and where in the section it was sent.

	The position travels with it because the size arithmetic in `pc_missing`
	is about where in the packing a record would have gone, which its contents
	do not say.
	*/
	Unmatched :: struct {
		rec:   Pw_RR,
		index: int,
	}
	unmatched := make([dynamic]Unmatched, 0, len(up_recs), c.allocator)

	// First pass: records that came back exactly as they were sent, case
	// included. In an untouched answer this is all of them.
	for u, ui in up_recs {
		key := pw_rr_key_no_ttl(u, c.allocator)
		matched := -1
		for e, i in el_recs {
			if taken[i] {
				continue
			}
			if pw_rr_key_no_ttl(e, c.allocator) == key {
				matched = i
				break
			}
		}
		if matched < 0 {
			append(&unmatched, Unmatched{rec = u, index = ui})
			continue
		}
		taken[matched] = true
		pc_ttl(c, kind, name, u, el_recs[matched], policy)
	}

	// Second pass: the same record with a name spelled in a different case.
	// Named rather than folded into the first pass, so a run says how often it
	// happens instead of hiding it.
	for u in unmatched {
		key := pw_rr_key_folded_no_ttl(u.rec, c.allocator)
		matched := -1
		for e, i in el_recs {
			if taken[i] {
				continue
			}
			if pw_rr_key_folded_no_ttl(e, c.allocator) == key {
				matched = i
				break
			}
		}
		if matched < 0 {
			pc_missing(c, q, kind, name, u.rec, u.index, up, el, policy)
			continue
		}
		taken[matched] = true
		pc_add(
			c,
			kind,
			fmt.aprintf("a name in the %s section came back in a different case", name, allocator = c.allocator),
			pw_rr_key(u.rec, c.allocator),
			pw_rr_key(el_recs[matched], c.allocator),
			"the answer was re-encoded and the name compressed against an earlier one, which RFC 1035 section 4.1.4 matches without regard to case, so the earlier spelling is the one written",
		)
		pc_ttl(c, kind, name, u.rec, el_recs[matched], policy)
	}

	for e, i in el_recs {
		if taken[i] {
			continue
		}
		pc_add(
			c,
			kind,
			fmt.aprintf("a record in the %s section that the upstream did not send", name, allocator = c.allocator),
			"-",
			pw_rr_key(e, c.allocator),
			pc_added_record_allowance(kind, e, policy),
		)
	}
}

/*
A record the upstream sent and elodin did not.

Allowed in exactly four situations, and none of them is "the record looked
unimportant".
*/
@(private = "file")
pc_missing :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	kind: Parity_Kind,
	name: string,
	rec: Pw_RR,
	// Where in the upstream's section this record was sent, which is where in
	// elodin's packing it would have gone.
	index: int,
	up, el: Pw_Msg,
	policy: Parity_Policy,
) {
	what := fmt.aprintf("a record missing from the %s section", name, allocator = c.allocator)

	// Cut to fit a datagram, with TC set so the client comes back over TCP.
	if el.tc && !up.tc && policy.transport == .UDP {
		pc_add(
			c,
			kind,
			what,
			pw_rr_key(rec, c.allocator),
			"-",
			"the answer was cut to fit the client's datagram and tc is set, so the client retries over tcp for the rest",
		)
		return
	}

	// DNSSEC records a client that did not set DO has no use for. Stripped by
	// `strip_dnssec_records` in src/server/dnssec.odin: the validator needed
	// them, this client did not ask for them, and RFC 4035 section 3.2.1 says
	// not to send them unasked.
	if policy.dnssec_validation && !q.do_bit && pc_dnssec_type(rec.type) && rec.type != q.qtype {
		pc_add(
			c,
			kind,
			what,
			pw_rr_key(rec, c.allocator),
			"-",
			"a dnssec record, and this client set neither do nor the type as its question, so RFC 4035 section 3.2.1 says not to send it",
		)
		return
	}

	/*
	A record the validator did not vouch for, on an answer it did vouch for.

	`strip_unauthenticated` in src/dnssec/validate.odin prunes any RRset the
	chain did not cover before the AD bit goes on, so that the bit covers
	everything left. The reference resolver was asked its own question and
	serves what it received; this one serves what it authenticated, and the two
	legitimately differ.

	Live mode only, and only on an answer carrying AD - which is the only
	circumstance in which that pruning runs at all. Against the mock there is no
	validator, so nothing may be pruned and every missing record is a missing
	record.
	*/
	if policy.mode == .Live && policy.dnssec_validation && el.ad {
		pc_add(
			c,
			kind,
			what,
			pw_rr_key(rec, c.allocator),
			"-",
			"this answer carries ad, so what the chain did not cover was pruned before the bit went on it",
		)
		return
	}

	/*
	Cut to fit a datagram from the additional section, where no TC bit says so.

	Last of the four, because the others name a cause and this one names a
	consequence. A DNSSEC record a client did not ask for was gone before the
	answer was ever fitted into a datagram, and an answer near the ceiling
	would otherwise tally it here - `parity_tally` groups by reason, and a
	reason that collects other allowances' records is a count nobody can read.

	RFC 2181 section 9: TC is not to be set merely because extra information
	could not be fitted, the results of additional section processing included,
	and the RRSet that will not fit is left out with the bit clear instead.
	`encode_message` in src/dns/encode.odin does exactly that, so unlike the
	allowance above this one has no bit to read and the arithmetic is the whole
	of the evidence.

	Like `pc_tc` it judges on what elodin wrote rather than on what arrived,
	because this server expands the compressed names inside the older types'
	RDATA and an answer that came in under the ceiling can go out over it.
	Unlike `pc_tc` it asks the question of a particular record at a particular
	point, and both halves of that matter, because the additional section is
	not cut but filled as far as it goes: the encoder drops a record that will
	not fit and keeps writing the ones behind it.

	So the cost is this record's own - `pc_first_dropped`'s figure would judge
	a whole section by whichever record was lost first - and the room is what
	stood written when this record's turn came rather than the finished
	message's length. The finished length is the high-water mark, and against
	it a record dropped early with room to spare is excused the moment the
	records written after it bring the total near the ceiling. That is the
	data loss this comparison exists to catch, in the one section it is being
	loosened for.

	The ceiling is short of the client's limit by what the OPT record costs,
	which is the room the encoder holds back while it fills the section
	(src/dns/encode.odin, `ceiling = max_size - opt_len`). Without that, a
	record dropped for exactly that reserved room - which is what #281 was
	about - would read as a record dropped for nothing.

	Narrow on three counts, because "additional records may go missing" would
	retire the check on the section glue and the OPT record both live in:

	  - over UDP only, the one transport with a datagram to fit;
	  - only where this record would genuinely not have fitted, so one missing
	    with room to spare is still a finding;
	  - with TC clear, because this reason says "with tc clear" and a message
	    carrying the bit was cut rather than filled. Both sides truncated is
	    the shape that reaches here - one side truncated is the allowance
	    above - and it stays the finding it was before this one existed;
	  - not on a referral, which is `omitted_glue_truncates`' exception (RFC
	    9471 section 3.3): glue for a name server inside the zone being
	    delegated is learnable from that reply and nowhere else, so a referral
	    that could not carry it must set TC.

	`pc_referral` is deliberately looser than the encoder's test, which asks
	in addition that the record be an address for a name server named inside
	the zone being delegated. Narrowing it that far would be this comparison
	repeating the rule it is here to check, and a judge that copies the
	implementation cannot catch the implementation being wrong. What the
	looseness costs is a finding on a referral that dropped additional data of
	another kind, which no shape the mock serves produces - and a finding is
	the direction to be wrong in.

	A missing OPT record does not reach here at all: `pw_parse` lifts it out of
	the section into `Pw_Msg.opt`, where `pc_edns` holds it to its own rule.
	*/
	if kind == .Additional && policy.transport == .UDP && !el.tc && !pc_referral(el) {
		// Costed inside the guard rather than beside it: `index` is an index
		// into this section, and `pc_written_before` walks the additional one.
		written, after_a_drop := pc_written_before(c, index, up, el)
		/*
		Costed with its owner name written out where a record ahead of it in
		this section was dropped: `encode_message` turns compression off at
		the first drop and leaves it off, so everything behind that one really
		does carry its name in full. The mock's two glue records are exactly
		that shape - both owned by ns1.parity.test., fifteen bytes apart on
		whether the pointer was available - and charging the second of them a
		pointer it never got would read a record that did not fit as one that
		did, which is a run failing on something nobody did wrong.
		*/
		cost := pc_rr_cost(rec)
		if after_a_drop {
			cost = len(rec.name) + 10 + len(rec.rdata)
		}
		/*
		The room the encoder was holding back at this point, which is the OPT
		record's only while the OPT record is still to come: it reserves that
		room while filling the section and stops once the record is written
		(src/dns/encode.odin, `!opt_written`). An upstream that put its OPT
		record ahead of its glue is re-encoded in that order, and there the
		ceiling for the glue behind it is the whole datagram.
		*/
		owed := 0
		if el.opt.present && el.opt.start >= written {
			owed = pc_opt_cost(el)
		}
		if written + cost > policy.client_udp_limit - owed {
			pc_add(
				c,
				kind,
				fmt.aprintf(
					"%s: %d bytes stood written, the record costs %d, and this client's limit is %d less the %d the opt record is owed",
					what,
					written,
					cost,
					policy.client_udp_limit,
					owed,
					allocator = c.allocator,
				),
				pw_rr_key(rec, c.allocator),
				"-",
				"additional data that did not fit the client's datagram, which RFC 2181 section 9 has left out with tc clear",
			)
			return
		}
	}

	pc_add(c, kind, what, pw_rr_key(rec, c.allocator), "-", "")
}

/*
Whether this answer is a delegation rather than an answer.

The shape RFC 9471 section 3.3 is about, and the encoder's own reading of it
(`omitted_glue_truncates`): nothing in the answer section and a name server
named in the authority section. An answer section with records in it settles
the question, and so does an empty one over a SOA - a NODATA or an NXDOMAIN
is not a delegation, and additional data it could not fit is ordinary
additional data.
*/
@(private = "file")
pc_referral :: proc(m: Pw_Msg) -> bool {
	if len(m.answer) != 0 {
		return false
	}
	for ns in m.authority {
		if ns.type == 2 {
			return true
		}
	}
	return false
}

/*
How much of the datagram stood written when a record the upstream sent at
`index` would have been written.

Elodin fills the additional section in the order it was given and leaves out
what will not fit, so its section is the upstream's with records removed, and
the record it wrote next after a drop began exactly where the dropped one
would have. That record's offset is therefore the answer; where nothing was
written after the drop, it is wherever the OPT record itself begins, read off
the wire rather than assumed to be the end of the message - a reply whose
upstream wrote the OPT record ahead of its glue is re-encoded in the order it
was decoded, and taking the message's end for the record's position there
would overstate the room by everything written after it.

One thing makes that reading wrong, and it falls back to the finished length
less the OPT record, which is what this judged by before it could tell the
difference: a section holding a record elodin minted is not the upstream's
with records removed, so the order says nothing about where anything stood.
The fallback is as if the drop had happened at the very end, the most
permissive reading of it, so a fallback can only ever excuse and never
accuse.
*/
@(private = "file")
pc_written_before :: proc(
	c: ^Parity_Compare,
	index: int,
	up, el: Pw_Msg,
) -> (
	written: int,
	after_a_drop: bool,
) {
	// Walked in order: each of elodin's records is the next upstream record
	// that was not dropped, so the count of matches made before `index` is
	// the count of records it wrote before the drop, and any upstream record
	// before `index` that made no match is a record dropped before this one.
	kept := 0
	seen := 0
	for u, i in up.additional {
		if i >= index && seen >= len(el.additional) {
			break
		}
		if seen < len(el.additional) &&
		   pw_rr_key_folded_no_ttl(u, c.allocator) ==
			   pw_rr_key_folded_no_ttl(el.additional[seen], c.allocator) {
			seen += 1
			if i < index {
				kept += 1
			}
			continue
		}
		if i < index {
			after_a_drop = true
		}
	}
	if seen != len(el.additional) {
		return pc_additional_end(el), after_a_drop
	}
	if kept < len(el.additional) {
		return el.additional[kept].start, after_a_drop
	}
	return pc_additional_end(el), after_a_drop
}

/*
Where elodin's additional section ended.

The OPT record is the landmark only where the encoder left it last, which is
where it appends one of its own - a message that carries the upstream's in
some other position is re-encoded in that position, and there the section
ended at the end of the message like any other.
*/
@(private = "file")
pc_additional_end :: proc(m: Pw_Msg) -> int {
	if m.opt.present && m.opt.start + pc_opt_cost(m) == m.size {
		return m.opt.start
	}
	return m.size
}


/*
What elodin's OPT record costs on the wire, or zero where it has none.

The room `encode_message` holds back while it fills the additional section,
worked out the way `dns.opt_wire_len` works it out: the root owner name, the
fixed ten bytes, the RDLENGTH, and four bytes of header per option.
*/
@(private = "file")
pc_opt_cost :: proc(m: Pw_Msg) -> int {
	if !m.opt.present {
		return 0
	}
	n := PC_MIN_OPT
	for o in m.opt.options {
		n += 4 + len(o.data)
	}
	return n
}

/*
Why a record elodin sent and the reference did not may nonetheless be genuine.

In the mock mode: never. The reference there is the message elodin was handed,
so a record that is not in it is a record from nowhere, and that is the failure
this whole file exists to find.

The live mode cannot be that strict, and the reason is not slack. Its reference
is what the resolver returned to *the client's* query; what elodin asked was its
own question, and a validating resolver asks with DO set for the proof it needs
whether or not the client wanted it. So the proof can be here and absent there.
The allowance is confined to exactly the records a proof is made of - anything
else appearing out of nowhere still fails, in either mode.
*/
@(private = "file")
pc_added_record_allowance :: proc(
	kind: Parity_Kind,
	rec: Pw_RR,
	policy: Parity_Policy,
) -> string {
	if policy.mode != .Live {
		return ""
	}
	if pc_dnssec_type(rec.type) {
		return "a dnssec record: this server asked its upstream with do set so it could validate, and the reference query did not have to"
	}
	if kind == .Authority && rec.type == 6 {
		return "the soa that anchors a denial of existence, which comes back with the proof this server asked for"
	}
	return ""
}

@(private = "file")
pc_dnssec_type :: proc(t: u16) -> bool {
	// RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, DS.
	switch t {
	case 46, 47, 50, 51, 48, 43:
		return true
	}
	return false
}

@(private = "file")
pc_ttl :: proc(
	c: ^Parity_Compare,
	kind: Parity_Kind,
	name: string,
	u, e: Pw_RR,
	policy: Parity_Policy,
) {
	if u.ttl == e.ttl {
		return
	}
	reason := ""
	if !policy.ttl_exact {
		// See `Parity_Policy.ttl_exact`.
		reason = "the reference and this answer are two separate fetches, so their ttls have been counting down since two different moments"
	}
	pc_add(
		c,
		kind,
		fmt.aprintf(
			"a ttl in the %s section for %s",
			name,
			pw_name_text(u.name, c.allocator),
			allocator = c.allocator,
		),
		fmt.aprintf("%d", u.ttl, allocator = c.allocator),
		fmt.aprintf("%d", e.ttl, allocator = c.allocator),
		reason,
	)
}

// --- edns ------------------------------------------------------------------

@(private = "file")
pc_edns :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	up, el: Pw_Msg,
	policy: Parity_Policy,
	first_dropped: int,
) {
	if !q.edns {
		// A client that sent no OPT must get none back (RFC 6891 section 6.1.1).
		// The upstream may well have sent one, because this server speaks EDNS
		// upstream whatever the client did.
		if el.opt.present {
			pc_add(c, .Edns, "an opt record for a client that sent none", "-", "present", "")
		}
		return
	}
	if !el.opt.present {
		/*
		An answer with no room for the record, kept whole instead.

		`match_client_opt` in src/server/resolver.odin abandons a mint that will
		not fit rather than dropping records to make room: a client that asked
		with EDNS and gets a complete answer without an OPT record is better off
		than one sent to TCP for the same records plus eleven bytes. Measured
		there, on a 504-byte answer against a 512-byte client.

		Held to exactly that. The record has to have been genuinely impossible -
		a bare OPT is eleven bytes and there is no room even for that - nothing
		may have been dropped from the answer, and the rcode has to be one the
		header can state on its own. An rcode of 16 or more keeps its top half
		in that record and nowhere else (RFC 6891 section 6.1.3), so an answer
		that loses it states a different rcode, and `opt_holds_extended_rcode`
		is what forces the record to stay.
		*/
		if first_dropped < 0 && el.rcode <= 0xf && el.size + PC_MIN_OPT > policy.client_udp_limit {
			pc_add(
				c,
				.Edns,
				fmt.aprintf(
					"no opt record: %d bytes written and the limit is %d, so the eleven a bare one costs were not there",
					el.size,
					policy.client_udp_limit,
					allocator = c.allocator,
				),
				"present",
				"-",
				"the answer was kept whole rather than cut to make room for an opt record the client would have got instead of its records",
			)
			return
		}
		pc_add(c, .Edns, "no opt record for a client that sent one", "present", "-", "")
		return
	}
	if !el.opt.root {
		pc_add(c, .Edns, "the opt record's owner name is not root", ".", "not .", "")
	}
	if el.opt.version != 0 {
		pc_add(
			c,
			.Edns,
			"opt version",
			"0",
			fmt.aprintf("%d", el.opt.version, allocator = c.allocator),
			"",
		)
	}
	if el.opt.malformed {
		pc_add(c, .Edns, "elodin's opt rdata is not a well-formed option list", "-", "malformed", "")
	}
	if el.opt.duplicate {
		pc_add(c, .Edns, "more than one opt record", "-", "duplicate", "")
	}

	// The payload size in a response is this server saying what it can receive,
	// not a copy of what the upstream said it could, so it is not compared.
	pc_opt_flags(c, q, el)
	pc_opt_contents(c, q, up, el, policy)
}

@(private = "file")
pc_opt_contents :: proc(c: ^Parity_Compare, q: Parity_Query, up, el: Pw_Msg, policy: Parity_Policy) {
	/*
	The one part of the answer that is not held to parity, and is held to the
	opposite.

	RFC 6891 section 6.1.1 forbids caching or forwarding an OPT record, so the
	record the client reads is this server's own statement rather than a copy of
	anything. Everything written inside it describes an exchange the client was
	not part of - an NSID naming the instance that answered upstream, an ECS
	echo of a subnet this server chose on the client's behalf, a cookie
	belonging to the other hop - and none of it may cross.

	So the rule reverses here: an option of the upstream's that reached the
	client is the failure. What elodin wrote for itself - its own cookie, its
	own extended error, the padding an encrypted transport needs - is its own,
	and is not compared against the upstream's list at all.

	`normalise_client_opt` in src/server/resolver.odin is the code this mirrors,
	and the argument for each field is written out there.
	*/
	for u in up.opt.options {
		for e in el.opt.options {
			if e.code != u.code {
				continue
			}
			/*
			A code this server would not have written into *this* answer has no
			business being here at all, whatever it now says.

			Byte equality is not the test, and was: an option can cross
			half-rewritten and still be the upstream's. For a code this server
			never mints, the code appearing on both sides is the finding, and
			comparing the values would only ask whether the leak was tidy.

			Asked of the answer rather than of the code, because two of the
			mintable ones are minted under conditions rather than always - see
			`pc_client_mintable`. A blanket exemption for the code would retire
			the check on every transport where this server writes nothing, which
			is most of them for the keepalive: a leak on a UDP answer would then
			read as this server's own option and pass in silence.
			*/
			if !pc_client_mintable(u.code, q, policy) {
				pc_add(
					c,
					.Edns,
					fmt.aprintf(
						"edns option %d written by the upstream reached the client",
						u.code,
						allocator = c.allocator,
					),
					pc_hex(u.data, c.allocator),
					pc_hex(e.data, c.allocator),
					"",
				)
				break
			}
			/*
			Padding carries no evidence in its value at all.

			RFC 7830 section 3 defines its content as zeros, so the upstream's
			padding and this server's are byte-identical whenever their lengths
			happen to match - which would report a copy on every DoT or DoH
			answer where both hops padded to the same block. There is nothing
			for a comparison to learn from it in either direction.
			*/
			if u.code == 12 {
				break
			}
			/*
			The keepalive timeout carries evidence in one mode and not the
			other, which is the `ttl_exact` split.

			It is two octets of an idle timeout. In the live mode both ends
			chose theirs independently and ten seconds is the way to bet, so the
			same bytes on both sides says nothing - the same coincidence padding
			has, arrived at from the other direction. In the mock mode the
			upstream's value is not a coincidence at all: `pm_opt` states one
			second where `parity_config` pins ten, so the two can only agree if
			one of them is the other. That is the only reading under which this
			option can be caught crossing on a transport where elodin mints one
			of its own, and it is free.
			*/
			if u.code == 11 && policy.mode != .Mock {
				break
			}
			/*
			For the other two, the same bytes on both sides is a copy rather
			than a coincidence. Two servers can independently reach the same
			extended-error info-code, which is why the text is part of the
			test and the info-code alone is not (see
			`pc_option_text_allowance`).
			*/
			if pc_bytes_equal(e.data, u.data) {
				pc_add(
					c,
					.Edns,
					fmt.aprintf(
						"edns option %d came back with the upstream's own value",
						u.code,
						allocator = c.allocator,
					),
					pc_hex(u.data, c.allocator),
					pc_hex(e.data, c.allocator),
					"",
				)
				break
			}
			/*
			And a cookie is checked a third way, because it is the one that can
			cross in half. RFC 7873 section 5.3 splits it into eight bytes the
			client chose and a server half behind them; this server writes its
			own client half over the upstream's, so the two differ as whole
			values while the upstream's server cookie - the secret half - is
			still sitting behind it.
			*/
			if u.code == 10 && len(u.data) > 8 && len(e.data) > 8 &&
			   pc_bytes_equal(u.data[8:], e.data[8:]) {
				pc_add(
					c,
					.Edns,
					"the upstream's server cookie reached the client behind a rewritten client half",
					pc_hex(u.data, c.allocator),
					pc_hex(e.data, c.allocator),
					"",
				)
				break
			}
		}
	}
}

/*
Whether this server could have written `code` into the answer to *this* query of
its own accord.

Everything else in a client's OPT record can only have come from the upstream,
which is what makes its presence enough to report without reading its value.
Kept as a list rather than inferred, so that the next one to start being minted
is a line somebody adds here deliberately.

Two of them are hop-by-hop rather than answers to anything the upstream was
asked: the keepalive timeout describes the connection this client holds with
this server, and the padding is sized for that connection's transport. Neither
may be compared against the upstream's value for that reason - but both are also
written only on some answers, so "this server mints this code" is not the same
statement as "this server minted it here". The query and the transport are taken
so it can be the second one: an exemption that held on every answer would retire
the leak check for the codes it names on every transport where this server
writes nothing at all.

The cookie and the extended error are left unconditional. Both are minted on
paths with more conditions than a comparison can restate - a cookie keeper that
may be off, a verdict that may be absent, a validator that may have nothing to
say - and neither is reached at all by an answer this server merely forwarded,
which is where a leak would have to show up.
*/
@(private = "file")
pc_client_mintable :: proc(code: u16, q: Parity_Query, policy: Parity_Policy) -> bool {
	switch code {
	case 10: // COOKIE, issued to this client (src/server/cookie.odin)
		return true
	case 11:
		/*
		edns-tcp-keepalive, this connection's idle timeout
		(src/server/keepalive.odin). Written on the two TCP transports, and
		only back to a client that sent the option: RFC 7828 section 3.3.1
		has it ignored on UDP, RFC 8484 section 10 puts it outside DoH, and a
		client that did not ask is told nothing.
		*/
		if policy.transport != .TCP && policy.transport != .DoT {
			return false
		}
		return pc_query_sent_option(q, 11)
	case 12:
		// Padding, sized for this client's transport (src/dns/padding.odin):
		// the encrypted transports, and only for a client that padded its own
		// query (RFC 7830 section 4, RFC 8467 section 5).
		if policy.transport != .DoT && policy.transport != .DoH {
			return false
		}
		return pc_query_sent_option(q, 12)
	case 15: // extended DNS error, this server's own (src/server/dnssec.odin)
		return true
	}
	return false
}

// Whether the generated query carried `code` in its OPT record.
@(private = "file")
pc_query_sent_option :: proc(q: Parity_Query, code: u16) -> bool {
	for o in q.options {
		if o.code == code {
			return true
		}
	}
	return false
}

/*
The DO bit, and the fifteen bits beside it.

DO is copied from the query and not from the answer: RFC 3225 section 3 makes
echoing the requestor's bit a MUST, and the upstream's copy is its echo of the
question this server asked, which is not the question the client asked. The rest
of the flag field is reserved and must be zero (RFC 6891 section 6.1.4).
*/
@(private = "file")
pc_opt_flags :: proc(c: ^Parity_Compare, q: Parity_Query, el: Pw_Msg) {
	if pw_do(el) != q.do_bit {
		pc_add(
			c,
			.Edns,
			"the do bit does not echo the query's",
			q.do_bit ? "1" : "0",
			pw_do(el) ? "1" : "0",
			"",
		)
	}
	if reserved := el.opt.flags &~ u16(PW_DO); reserved != 0 {
		pc_add(
			c,
			.Edns,
			"reserved opt flag bits are set",
			"0",
			fmt.aprintf("%#04x", reserved, allocator = c.allocator),
			"",
		)
	}
}


// --- helpers ---------------------------------------------------------------

/*
Whether two messages are the same bytes once the transaction ID and the
question's case are set aside.

Not a requirement. A resolver that decoded a message and encoded it again can be
perfectly faithful and byte-different, and one that copies the bytes across can
be unfaithful in the header. It is reported because the proportion is the
cheapest signal there is that the pass-through path is still passing through:
if it falls, something started re-encoding answers that used to be forwarded.
*/
@(private = "file")
pc_same_but_for_id :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) || len(a) < 12 {
		return false
	}
	/*
	Case is folded over the question's name and nowhere else.

	That is the only place it may legitimately differ: the client randomised it
	and the server echoes what it was sent, so the upstream's copy and the
	client's carry different letters for the same name. Folding the whole
	message instead - which this did - counts two answers as identical when a
	byte inside an RDATA differs in case, and a downcased name inside RDATA is
	exactly the kind of quiet re-encoding this statistic exists to notice.
	*/
	name_end := 12
	for name_end < len(a) {
		n := int(a[name_end])
		if n == 0 || n & 0xc0 != 0 {
			name_end += 1
			break
		}
		name_end += 1 + n
	}
	if name_end > len(a) {
		name_end = len(a)
	}
	for i in 2 ..< len(a) {
		x, y := a[i], b[i]
		if i >= 12 && i < name_end {
			if x >= 'A' && x <= 'Z' {
				x += 32
			}
			if y >= 'A' && y <= 'Z' {
				y += 32
			}
		}
		if x != y {
			return false
		}
	}
	return true
}

@(private = "file")
pc_bytes_equal :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

@(private = "file")
pc_hex :: proc(b: []u8, allocator: mem.Allocator) -> string {
	if len(b) == 0 {
		return "(empty)"
	}
	sb := strings.builder_make(allocator)
	for x in b {
		fmt.sbprintf(&sb, "%02x", x)
	}
	return strings.to_string(sb)
}

@(private = "file")
pc_rcode_text :: proc(rcode: u16, allocator: mem.Allocator) -> string {
	switch rcode {
	case 0:
		return "noerror"
	case 1:
		return "formerr"
	case 2:
		return "servfail"
	case 3:
		return "nxdomain"
	case 4:
		return "notimp"
	case 5:
		return "refused"
	case 16:
		return "badvers"
	case 23:
		return "badcookie"
	}
	return fmt.aprintf("rcode%d", rcode, allocator = allocator)
}
