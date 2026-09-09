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
The first record the upstream sent that elodin did not, in bytes on the wire.

-1 when elodin kept everything. Used to judge a TC bit: truncation is the
protocol working only if there was genuinely no room, and the record that decides
that is this one - the next one that would have been written.

The first rather than the smallest, because a message is truncated by dropping a
tail. Sections come in a fixed order and a record cannot be lifted out of the
middle to make a later one fit, so a small record further down being left out
says nothing; the only question is whether the one at the truncation point would
have gone in.

Costed at its best case - a two-byte compression pointer for the owner name, the
ten fixed bytes, and the RDATA - because the question is whether elodin *could*
have carried it. Over-estimating would excuse a truncation that had room to
spare, which is the thing this is here to catch.
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
				return 2 + 10 + len(u.rdata)
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
	pc_flag(c, "opcode", up.opcode == el.opcode, true, "")

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
The ceiling the encoder actually packed this answer against.

Lower than the client's, by the length of the options that were stripped after
the packing was done. `encode_message` reserves room for the OPT record as the
message stands when it is encoded - which is the upstream's, options and all -
and `normalise_client_opt` in src/server/resolver.odin strips those options
afterwards. Nothing puts back what was dropped for room the strip handed back.

Used by both places that admit the consequence, so the two cannot drift apart.
*/
@(private = "file")
pc_reserved_ceiling :: proc(up, el: Pw_Msg, policy: Parity_Policy) -> int {
	return policy.client_udp_limit - max(pw_opt_wire_len(up) - pw_opt_wire_len(el), 0)
}

/*
Why a record that would have fitted was left out anyway.

A defect, written down as one rather than argued for. It costs a client either a
TCP round trip or a glue address it has to go and ask for, in both cases for
room that turned out to be there. Admitted only where the reservation accounts
for the whole of the gap, so a record short by any other amount still fails, and
labelled so that whoever fixes it deletes this with it.
*/
@(private = "file")
PC_RESERVATION_DEFECT ::
	"known defect: the answer was packed against room reserved for the upstream's opt record, and the options in it were stripped afterwards without the records being put back"

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
		/*
		The ceiling the encoder actually packed against.

		It reserves room for the OPT record as the message stands when it is
		encoded - which is the upstream's, options and all - and the options are
		stripped afterwards, by `normalise_client_opt`. Nothing puts the records
		back that were dropped for room the strip then handed back, so the
		answer is packed against a ceiling lower than the one it goes out under
		by exactly the length of the options that were removed.

		That is a defect and it is written down here as one: it costs a client a
		TCP round trip for records that would have fitted. It is admitted rather
		than failed only so that the rest of the check can run, and admitted
		this narrowly - the gap has to account for the whole of the unused room -
		so that a truncation short by any other amount still fails.

		Reproduce: --parity-seed 1 --parity-runs 61 against a synthetic upstream
		whose OPT carries a cookie and an NSID.
		*/
		reserved := pc_reserved_ceiling(up, el, policy)
		if policy.transport == .UDP &&
		   first_dropped >= 0 &&
		   el.size + first_dropped <= policy.client_udp_limit &&
		   el.size + first_dropped > reserved {
			pc_add(
				c,
				.Header,
				fmt.aprintf(
					"tc (truncated): %d bytes written, the next record costs %d, the limit is %d, and the encoder packed against %d",
					el.size,
					first_dropped,
					policy.client_udp_limit,
					reserved,
					allocator = c.allocator,
				),
				"0",
				"1",
				PC_RESERVATION_DEFECT,
			)
			return
		}
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
	unmatched := make([dynamic]Pw_RR, 0, len(up_recs), c.allocator)

	// First pass: records that came back exactly as they were sent, case
	// included. In an untouched answer this is all of them.
	for u in up_recs {
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
			append(&unmatched, u)
			continue
		}
		taken[matched] = true
		pc_ttl(c, kind, name, u, el_recs[matched], policy)
	}

	// Second pass: the same record with a name spelled in a different case.
	// Named rather than folded into the first pass, so a run says how often it
	// happens instead of hiding it.
	for u in unmatched {
		key := pw_rr_key_folded_no_ttl(u, c.allocator)
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
			pc_missing(c, q, kind, name, u, up, el, policy)
			continue
		}
		taken[matched] = true
		pc_add(
			c,
			kind,
			fmt.aprintf("a name in the %s section came back in a different case", name, allocator = c.allocator),
			pw_rr_key(u, c.allocator),
			pw_rr_key(el_recs[matched], c.allocator),
			"the answer was re-encoded and the name compressed against an earlier one, which RFC 1035 section 4.1.4 matches without regard to case, so the earlier spelling is the one written",
		)
		pc_ttl(c, kind, name, u, el_recs[matched], policy)
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

Allowed in exactly two situations, and neither of them is "the record looked
unimportant".
*/
@(private = "file")
pc_missing :: proc(
	c: ^Parity_Compare,
	q: Parity_Query,
	kind: Parity_Kind,
	name: string,
	rec: Pw_RR,
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
	A hint dropped for room the reservation was holding.

	The other face of the defect above. The additional section keeps the OPT
	record's room as it fills and a glue address is what pays for it - which is
	the right trade when the room is real, and is this when it is not. No TC
	goes with it: nothing on the wire says an additional record was left out, so
	the client simply never learns the address.
	*/
	if kind == .Additional && !el.tc && policy.transport == .UDP {
		cost := 2 + 10 + len(rec.rdata)
		if el.size + cost <= policy.client_udp_limit &&
		   el.size + cost > pc_reserved_ceiling(up, el, policy) {
			pc_add(
				c,
				kind,
				fmt.aprintf(
					"%s: %d bytes written, the record costs %d, the limit is %d, and the encoder packed against %d",
					what,
					el.size,
					cost,
					policy.client_udp_limit,
					pc_reserved_ceiling(up, el, policy),
					allocator = c.allocator,
				),
				pw_rr_key(rec, c.allocator),
				"-",
				PC_RESERVATION_DEFECT,
			)
			return
		}
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

	pc_add(c, kind, what, pw_rr_key(rec, c.allocator), "-", "")
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
			if e.code != u.code || !pc_bytes_equal(e.data, u.data) {
				continue
			}
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
	}
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
