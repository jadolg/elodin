package server

import "core:mem"
import "core:fmt"
import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"

/*
Blocking is decided on the answer as well as the question.

An answer may point somewhere else entirely: the question is a first-party name
the site owns, the CNAME in the answer lands on the tracker, and the address the
browser ends up talking to is the tracker's. Pi-hole calls this CNAME cloaking
and inspects the chain for it; so does `cloaked_chain_target`, and what follows
holds it to that - through a mock upstream for the forwarding path, and through
an answer put straight into the cache for the hit path.
*/

/*
The lists a case runs under: `block` and `allow` as domains, and `rules` as
blocklist lines, each of which has to parse or the case would pass on an empty
list.
*/
@(private = "file")
make_engine :: proc(t: ^testing.T, block, allow: []string, rules: []string = nil) -> ^filter.Engine {
	engine := filter.engine_make()
	block_set := filter.set_make()
	allow_set := filter.set_make()
	for d in block {
		filter.set_add(block_set, d, {.Apex, .Subdomains})
	}
	for d in allow {
		filter.set_add(allow_set, d, {.Apex, .Subdomains})
	}
	for r in rules {
		testing.expectf(t, filter.parse_rule(block_set, allow_set, r) > 0, "rule %q did not parse", r)
	}
	filter.engine_swap(engine, block_set, allow_set)
	return engine
}

// A server forwarding to a mock upstream with blocking on under `block` and
// `allow`. Torn down with `blocking_harness_stop`.
@(private = "file")
blocking_harness :: proc(t: ^testing.T, h: ^Harness, caching: bool, block: []string, allow: []string = nil) -> bool {
	if !harness_start(t, h, caching) {
		return false
	}
	h.cfg.blocking.enabled = true
	h.srv.filters = make_engine(t, block, allow)
	return true
}

@(private = "file")
blocking_harness_stop :: proc(h: ^Harness) {
	filter.engine_destroy(h.srv.filters)
	harness_stop(h)
}

/*
A CNAME at the question whose RDATA is a compression pointer past the end of the
message: the record decodes as `Rdata_Raw`, and the message decodes whole.
`extra_a` adds an A record at the question name behind it.
*/
@(private = "file")
unreadable_cname_reply :: proc(extra_a := false) -> []u8 {
	base := test_reply("www.brand.example.", .A)
	owner: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name("www.brand.example.", owner[:])
	if err != .None {
		panic("the CNAME's owner does not encode")
	}
	wire := make([dynamic]u8, 0, len(base) + n + 28, context.temp_allocator)
	append(&wire, ..base)
	wire[7] = 2 if extra_a else 1 // ANCOUNT
	// Owner written out rather than compressed; CNAME, IN, TTL 60, RDLENGTH 2,
	// and the pointer.
	append(&wire, ..owner[:n])
	append(&wire, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0xfe)
	if extra_a {
		append(&wire, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	}
	return wire[:]
}

@(test)
test_a_blocked_name_reached_through_a_cname_is_still_blocked :: proc(t: ^testing.T) {
	h: Harness
	if !blocking_harness(t, &h, false, {"tracker.evil.example"}) {
		return
	}
	defer blocking_harness_stop(&h)
	engine := h.srv.filters

	// The tracker is on the list: asked for directly, it is blocked.
	testing.expect_value(t, filter.engine_match(engine, "tracker.evil.example.", .A), filter.Decision.Blocked)

	out, outcome, ok, _ := harness_ask(
		&h,
		test_query("www.brand.example."),
		chain_reply({"www.brand.example.", "tracker.evil.example."}),
	)
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	// Whatever `blocking.response` is, what goes out is built from the question:
	// nothing of the upstream's chain reaches the client.
	for rec in decoded.answer {
		if cname, is_cname := rec.data.(dns.Rdata_Name); is_cname {
			testing.expectf(
				t,
				filter.engine_match(engine, cname.name, .A) != .Blocked,
				"the answer carries a CNAME to %s, which is on the block list",
				cname.name,
			)
		}
	}
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
The rest of the walk, exercised from the cache rather than through a mock
upstream. An entry that predates the rule now covering its chain is the case the
cache path exists to catch, and putting the answer in directly is the only way to
have one.
*/

@(private = "file")
chain_reply :: proc(hops: []string) -> []u8 {
	// A CNAME per hop and an address at the end, which is the shape of a cloaked
	// answer: the chain is what leads there and the address is the point of it.
	answer := make([]dns.Record, len(hops), context.temp_allocator)
	for i in 0 ..< len(hops) - 1 {
		answer[i] = cname_record(hops[i], hops[i + 1])
	}
	answer[len(hops) - 1] = a_record(hops[len(hops) - 1], TRACKER_ADDR)
	return test_reply(hops[0], .A, ..answer)
}

// The address every chain here ends at.
@(private = "file")
TRACKER_ADDR :: [4]u8{203, 0, 113, 7}

@(private = "file")
serve_cached_chain :: proc(t: ^testing.T, hops, block, allow: []string) -> Outcome {
	return serve_cached_answer(t, hops[0], chain_reply(hops), block, allow)
}

// A server answering from its cache alone, with blocking on under the lists
// `make_engine` builds. Torn down with `cached_server_destroy`.
@(private = "file")
cached_server :: proc(t: ^testing.T, cfg: ^config.Config, block, allow: []string, rules: []string = nil) -> Server {
	cfg^ = test_config()
	cfg.cache.enabled = true
	cfg.blocking.enabled = true
	return Server {
		cfg = cfg,
		answers = cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600}),
		filters = make_engine(t, block, allow, rules),
	}
}

@(private = "file")
cached_server_destroy :: proc(s: ^Server) {
	cache.destroy(s.answers)
	filter.engine_destroy(s.filters)
}

/*
`stamped` stores the entry as the miss path would have stored it a moment ago:
matched against the rule sets that are in force now. Left off, the entry carries
no stamp at all, which is every entry that predates a reload.
*/
@(private = "file")
serve_cached_answer :: proc(
	t: ^testing.T,
	qname: string,
	wire: []u8,
	block, allow: []string,
	stamped := false,
	rules: []string = nil,
	response: ^[]u8 = nil,
	asks := 1,
) -> Outcome {
	cfg: config.Config
	s := cached_server(t, &cfg, block, allow, rules)
	defer cached_server_destroy(&s)

	checked := filter.engine_generation(s.filters) if stamped else 0
	if !seed_cache(t, s.answers, qname, wire, checked = checked) {
		return .Failed
	}

	out: []u8
	outcome: Outcome
	ok: bool
	for _ in 0 ..< asks {
		out, outcome, ok = handle_query(&s, test_query(qname), .UDP, "127.0.0.1:5555", context.temp_allocator)
	}
	testing.expect(t, ok, "nothing came back at all")
	if response != nil {
		response^ = out
	}
	return outcome
}

// Lists are reloaded under a running server, so an entry can outlive the moment
// its chain became something to refuse. Matched on the way out, every time.
@(test)
test_a_cached_answer_is_matched_against_the_lists_as_they_stand_now :: proc(t: ^testing.T) {
	outcome := serve_cached_chain(
		t,
		[]string{"www.brand.example.", "tracker.evil.example."},
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
An exception written for the name that was asked about covers the lookup and not
just the label: the chain below it is not searched for a reason to refuse.

That is the escape hatch that remains. Nobody but the client chooses what gets
asked, so an allow rule on the question is an operator statement about a lookup
rather than something a responder can manufacture. This is what an operator
reaches for when a first-party name resolves through a CDN somebody has listed.
*/
@(test)
test_an_allowed_question_exempts_the_chain_it_leads_to :: proc(t: ^testing.T) {
	outcome := serve_cached_chain(
		t,
		[]string{"www.brand.example.", "tracker.evil.example."},
		[]string{"evil.example"},
		[]string{"www.brand.example"},
	)
	testing.expect_value(t, outcome, Outcome.Cached)
	free_all(context.temp_allocator)
}

/*
An allow rule speaks for its own name and does not excuse the one beside it.

An allowlisted name anywhere in the answer would be a key the responder can use
to turn the check off. The chain here reaches a listed name and then an allowed
one, and the answer is refused for the listed name regardless of what follows it.
*/
@(test)
test_an_allow_rule_later_in_the_chain_does_not_excuse_a_block_earlier_in_it :: proc(t: ^testing.T) {
	outcome := serve_cached_chain(
		t,
		[]string{"www.brand.example.", "tracker.evil.example.", "safe.example."},
		[]string{"evil.example"},
		[]string{"safe.example"},
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
The same thing in the shape an attacker would actually write it.

Not a chain at all: two CNAMEs at the question's owner, one pointing at whatever
host the operator has allowlisted and one at the tracker. Both are reachable, so
both are matched, and an allow that cleared the answer would clear this one -
for the cost of a single extra record that the responder writes itself. Every
allowlist entry would be a master key, and an allowlist is a thing operators add
to precisely because they had to unbreak a site.
*/
@(test)
test_an_allowed_sibling_does_not_clear_the_listed_target :: proc(t: ^testing.T) {
	answer := test_reply(
		"www.brand.example.",
		.A,
		cname_record("www.brand.example.", "cdn.allowed.example."),
		cname_record("www.brand.example.", "tracker.evil.example."),
		a_record("tracker.evil.example.", TRACKER_ADDR),
	)
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		answer,
		[]string{"tracker.evil.example"},
		[]string{"cdn.allowed.example"},
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
Two CNAMEs at one owner name, the listed one second.

A zone may not publish that (RFC 1034 section 3.6.2), which is the point: the
answer comes from whoever runs the cloaked zone, and following only the first
CNAME at each owner would let them put an innocent one in front of the tracker
and have the walk end there while the tracker's address rides along in the same
answer.
*/
@(test)
test_a_decoy_cname_beside_the_listed_one_does_not_hide_it :: proc(t: ^testing.T) {
	answer := test_reply(
		"www.brand.example.",
		.A,
		cname_record("www.brand.example.", "decoy.brand.example."),
		cname_record("www.brand.example.", "tracker.evil.example."),
		a_record("tracker.evil.example.", TRACKER_ADDR),
	)
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		answer,
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
And the decoy one hop further down, where nothing on the branch is listed until
the second name on it.

Matching both CNAMEs at the owner and then following only the first is the same
hole with one more hop in front of it: the innocent branch ends immediately, the
walk ends with it, and the tracker sits two names along the branch the client is
equally free to take.
*/
@(test)
test_a_decoy_branch_does_not_end_the_walk_before_the_other_one :: proc(t: ^testing.T) {
	answer := test_reply(
		"www.brand.example.",
		.A,
		cname_record("www.brand.example.", "decoy.brand.example."),
		cname_record("www.brand.example.", "hop.other.example."),
		cname_record("hop.other.example.", "tracker.evil.example."),
		a_record("tracker.evil.example.", TRACKER_ADDR),
	)
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		answer,
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
The budget is spent on names, so repeating one does not spend it.

The answer comes from whoever runs the cloaked zone, and the same CNAME written
out sixteen times is sixteen records to scan but one name to look up. Counting
the records instead would let a padded answer use the whole budget up before the
walk reached the record that mattered, which is the cheapest evasion there is:
no chain to build, no second zone to run, just the same line repeated.
*/
@(test)
test_a_repeated_cname_does_not_spend_the_budget_for_the_listed_one :: proc(t: ^testing.T) {
	answer := make([]dns.Record, MAX_CHAIN_NAMES + 2, context.temp_allocator)
	for i in 0 ..< MAX_CHAIN_NAMES {
		answer[i] = cname_record("www.brand.example.", "decoy.brand.example.")
	}
	answer[MAX_CHAIN_NAMES] = cname_record("www.brand.example.", "tracker.evil.example.")
	answer[MAX_CHAIN_NAMES + 1] = a_record("tracker.evil.example.", TRACKER_ADDR)
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		test_reply("www.brand.example.", .A, ..answer),
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

// The hop cap from the other side: a chain that never ends is answered rather
// than walked forever.
@(test)
test_a_cname_chain_that_loops_is_still_answered :: proc(t: ^testing.T) {
	outcome := serve_cached_chain(
		t,
		[]string{"a.example.", "b.example.", "a.example."},
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Cached)
	free_all(context.temp_allocator)
}

/*
An entry stored under the rule sets in force is served without the chain being
walked again.

This is the whole of what keeps the re-match off the hot path, so it is worth a
test that fails if the stamp stops being honoured: what is stored here is an
answer that leads to a listed name, and it goes out, because the entry says it
was matched against these very rules. Nothing in a running server can reach that
state - an answer that matched is refused before `cache.put` sees it - which is
the reason the stamp can be believed at all.
*/
@(test)
test_an_entry_matched_against_the_rules_in_force_is_not_walked_again :: proc(t: ^testing.T) {
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_reply([]string{"www.brand.example.", "tracker.evil.example."}),
		[]string{"tracker.evil.example"},
		nil,
		stamped = true,
	)
	testing.expect_value(t, outcome, Outcome.Cached)
	free_all(context.temp_allocator)
}

/*
And the stamp goes forward once the answer has been looked at, so a reload costs
one walk per entry rather than one per hit.

Observed through the cache rather than by counting walks: after the first hit
the entry is stamped with the generation it was matched against, which is what
`cache.get` reads to decide there is nothing to do.
*/
@(test)
test_a_clean_answer_is_walked_once_per_reload_and_not_once_per_hit :: proc(t: ^testing.T) {
	cfg: config.Config
	s := cached_server(t, &cfg, {"tracker.evil.example"}, nil)
	defer cached_server_destroy(&s)
	answers, engine := s.answers, s.filters

	hops := []string{"www.brand.example.", "cdn.brand.example."}
	// Stored before the lists this server is running: the first hit has to walk it.
	if !seed_cache(t, answers, hops[0], chain_reply(hops)) {
		return
	}
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], hops[0], .A, .IN, false, false)

	_, first, _ := cache.get(answers, key, context.temp_allocator, checked_against = filter.engine_generation(engine))
	testing.expect(t, first.recheck, "an entry from before the reload was not flagged for a second look")

	_, outcome, ok := handle_query(&s, test_query(hops[0]), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "nothing came back at all")
	testing.expect_value(t, outcome, Outcome.Cached)

	_, second, _ := cache.get(answers, key, context.temp_allocator, checked_against = filter.engine_generation(engine))
	testing.expect(t, !second.recheck, "the walk was not recorded, so every later hit pays for it again")
	free_all(context.temp_allocator)
}

/*
Sixteen distinct decoys, and then the tracker.

The budget is spent on distinct names, so distinct decoys spend it - which the
repeated-CNAME case above cannot show, its decoys all being one name. Sixteen of
them use the walk up before it reaches the seventeenth record, and what the
walk has not reached it has not cleared.
*/
@(test)
test_distinct_decoys_do_not_bury_the_listed_name :: proc(t: ^testing.T) {
	answer := make([]dns.Record, MAX_CHAIN_NAMES + 2, context.temp_allocator)
	for i in 0 ..< MAX_CHAIN_NAMES {
		answer[i] = cname_record("www.brand.example.", fmt.tprintf("decoy%d.brand.example.", i))
	}
	answer[MAX_CHAIN_NAMES] = cname_record("www.brand.example.", "tracker.evil.example.")
	answer[MAX_CHAIN_NAMES + 1] = a_record("tracker.evil.example.", TRACKER_ADDR)
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		test_reply("www.brand.example.", .A, ..answer),
		[]string{"tracker.evil.example"},
		nil,
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
A plain chain longer than the budget is withheld, listed name or not.

This is the shape that matters, because there is nothing wrong with it: one
CNAME per owner, no repetition, no malformed record, every client follows it to
the end and arrives at the tracker. Bounding the walk and then serving whatever
the walk did not reach is not a bound on anything an attacker cares about - it
is a length they have to exceed, and exceeding it was free.

So the answer is refused. The chain is eighteen names where a real one is two,
and an answer this server could not finish checking is not one to hand over.
*/
@(test)
test_a_chain_longer_than_the_budget_is_refused :: proc(t: ^testing.T) {
	// The question plus seventeen targets: one more than the walk admits, so it
	// is the first length that is refused rather than merely a long one.
	hops := make([dynamic]string, 0, MAX_CHAIN_NAMES + 3, context.temp_allocator)
	append(&hops, "www.brand.example.")
	for i in 0 ..< MAX_CHAIN_NAMES {
		append(&hops, fmt.tprintf("h%d.brand.example.", i))
	}
	append(&hops, "tracker.evil.example.")

	// Listed at the far end: the walk must not clear what it never reached.
	testing.expect_value(
		t,
		serve_cached_chain(t, hops[:], []string{"tracker.evil.example"}, nil),
		Outcome.Blocked,
	)
	// And with nothing listed at all, the same chain is still withheld: the
	// refusal is "not checkable", not "found something".
	testing.expect_value(t, serve_cached_chain(t, hops[:], nil, nil), Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
A chain of exactly the budget is walked to the end and served.

The boundary in the other direction, and it has to be the *exact* one, on a
number that decides whether ordinary answers are withheld. Sixteen targets here
and seventeen in the test above pin `MAX_CHAIN_NAMES` exactly.
*/
@(test)
test_a_chain_that_fits_the_budget_is_answered :: proc(t: ^testing.T) {
	// The question plus sixteen targets, which is the most the walk will follow.
	hops := make([dynamic]string, 0, MAX_CHAIN_NAMES + 2, context.temp_allocator)
	append(&hops, "www.brand.example.")
	for i in 0 ..< MAX_CHAIN_NAMES {
		append(&hops, fmt.tprintf("h%d.brand.example.", i))
	}
	testing.expect_value(t, serve_cached_chain(t, hops[:], nil, nil), Outcome.Cached)
	free_all(context.temp_allocator)
}

/*
A cloaked name is fetched from the upstream once, not once per query.

The refusal is stamped onto the stored answer, so the second query is answered
from the entry without the upstream being asked again. Without that, the case
this feature exists for - a cloaked name that was never in the cache - is the
one case it never memoises, and every client query becomes an upstream query
while a name blocked on the *question* costs none at all.
*/
@(test)
test_a_cloaked_answer_is_fetched_from_the_upstream_only_once :: proc(t: ^testing.T) {
	h: Harness
	if !blocking_harness(t, &h, true, {"tracker.evil.example"}) {
		return
	}
	defer blocking_harness_stop(&h)

	_, first, _, asked := harness_ask(
		&h,
		test_query("www.brand.example."),
		chain_reply({"www.brand.example.", "tracker.evil.example."}),
	)
	testing.expect(t, asked, "the upstream was never asked for the first query")
	testing.expect_value(t, first, Outcome.Blocked)

	// No mock is listening now. A second upstream query would time out and the
	// query would fail; answered from the stored refusal, it is blocked again.
	_, second, ok := handle_query(&h.srv, test_query("www.brand.example."), .UDP, "127.0.0.2:5555", context.temp_allocator)
	testing.expect(t, ok, "the second query produced nothing at all")
	testing.expect_value(t, second, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
A refused answer does not take the upstream's AD bit into the cache with it.

The bytes are stored so a later reload has something to walk, and a reload that
clears the name serves them. If the upstream's AD bit went in with them, that
later answer would carry this server's assurance that it validated something it
never looked at - which is what clearing the bit before the store is for.

Driven with DNSSEC off, so `validating` is false and the bit must be cleared on
every stored answer, refused or not.
*/
@(test)
test_a_refused_answer_is_not_cached_with_the_upstream_ad_bit :: proc(t: ^testing.T) {
	h: Harness
	if !blocking_harness(t, &h, true, {"tracker.evil.example"}) {
		return
	}
	defer blocking_harness_stop(&h)

	// The upstream claims the answer is authenticated.
	reply := chain_reply({"www.brand.example.", "tracker.evil.example."})
	reply[3] |= 0x20

	_, outcome, _, _ := harness_ask(&h, test_query("www.brand.example."), reply)
	testing.expect_value(t, outcome, Outcome.Blocked)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "www.brand.example.", .A, .IN, false, false)
	entry, found := h.answers.shards[0].entries[key]
	if !testing.expect(t, found, "the refused answer was not stored, so nothing can re-walk it later") {
		return
	}
	testing.expect(
		t,
		cache.wire_of(entry)[3] & 0x20 == 0,
		"the stored answer kept the upstream's AD bit, which a later reload would serve under our name",
	)
	free_all(context.temp_allocator)
}

/*
A malformed record in a section the walk never reads does not cost the answer.

The walk reads the answer section. The cache reads the whole message, so a
record it cannot parse anywhere means the answer is not stored - which is fine.
What is not fine is refusing to *serve* it: that would turn one bad RDLENGTH in
an additional section into SERVFAIL for a clean, walkable answer, and only once
blocking is on.

The reply here has a good CNAME chain and one additional record whose RDLENGTH
runs past the end of the message.
*/
@(test)
test_junk_outside_the_answer_section_does_not_withhold_the_answer :: proc(t: ^testing.T) {
	// A well-formed reply for www.brand.example -> good.brand.example, built and
	// then extended by hand with an additional record that cannot be parsed.
	base := test_reply(
		"www.brand.example.",
		.A,
		cname_record("www.brand.example.", "good.brand.example."),
		a_record("good.brand.example.", {203, 0, 113, 20}),
	)

	// One additional record: root name, type TXT, class IN, ttl 0, RDLENGTH 32
	// with no bytes behind it. The answer section ahead of it is untouched.
	junk := make([dynamic]u8, 0, len(base) + 11, context.temp_allocator)
	append(&junk, ..base)
	junk[11] = 1 // ARCOUNT = 1
	append(&junk, 0) // root name
	append(&junk, 0, 16) // TYPE = TXT
	append(&junk, 0, 1) // CLASS = IN
	append(&junk, 0, 0, 0, 0) // TTL
	append(&junk, 0, 32) // RDLENGTH, with nothing following it

	wire := junk[:]
	_, whole_err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, whole_err != .None, "the fixture was meant to be undecodable as a whole") {
		return
	}
	through, answer_err := dns.decode_through_answer(wire, context.temp_allocator)
	if !testing.expect(t, answer_err == .None, "the answer section was meant to still parse") {
		return
	}
	testing.expect_value(t, len(through.answer), 2)

	// Driven through the forwarding path: the cache path cannot store a message
	// it could not decode, so this is only reachable from an upstream reply.
	h: Harness
	if !blocking_harness(t, &h, false, {"tracker.evil.example"}) {
		return
	}
	defer blocking_harness_stop(&h)

	_, outcome, _, _ := harness_ask(&h, test_query("www.brand.example."), wire)

	testing.expectf(
		t,
		outcome != .Failed,
		"a clean answer section was refused for junk in a section the walk never reads (outcome=%v)",
		outcome,
	)
	free_all(context.temp_allocator)
}

/*
A refusal reached on a partial decode is not frozen into the cache.

The walk can run on an answer section alone, and the cache wants the whole
message. When only the first succeeds, `decoded` is still the zero message it
was declared as, and storing the refusal from it would build an entry out of
nothing to do with these bytes: `redirects` would come out false, and `get`
derives `recheck` from `redirects`, so the entry could never be walked again.
The refusal it carried would be replayed on every hit until it expired -
including after the operator wrote the allow rule the documentation points them
at, which is the one thing that is supposed to release it.

So nothing is stored for that answer, and the name goes upstream again. This
asserts the release: the same cloaked answer, refused, and then allowed once the
question is on the allow list and the lists have been reloaded.
*/
@(test)
test_a_refusal_on_a_partial_decode_is_released_by_a_reload :: proc(t: ^testing.T) {
	base := chain_reply({"www.brand.example.", "tracker.evil.example."})

	/*
	One additional record whose owner name is a compression pointer aiming past
	the end of the message.

	The pointer rather than a short RDLENGTH, because the two are rejected by
	different things. `decode_message` refuses both. `scan_ttl_offsets`, which is
	what decides whether `cache.put` stores anything, bounds an RDLENGTH but
	follows no pointer at all - `skip_name` takes any 0xc0 byte as two bytes and
	moves on. So a truncated RDLENGTH never reaches the cache and this does,
	which is the whole of what makes the entry below possible.
	*/
	junk := make([dynamic]u8, 0, len(base) + 12, context.temp_allocator)
	append(&junk, ..base)
	junk[11] = 1 // ARCOUNT = 1
	append(&junk, 0xc0, 0xff) // owner: a pointer to offset 255, which is forward
	append(&junk, 0, 16) // TYPE = TXT
	append(&junk, 0, 1) // CLASS = IN
	append(&junk, 0, 0, 0, 0) // TTL
	append(&junk, 0, 0) // RDLENGTH = 0
	wire := junk[:]

	if _, whole := dns.decode_message(wire, context.temp_allocator); !testing.expect(
		t,
		whole != .None,
		"the fixture was meant to be undecodable as a whole",
	) {
		return
	}
	if _, partial := dns.decode_through_answer(wire, context.temp_allocator); !testing.expect(
		t,
		partial == .None,
		"the fixture's answer section was meant to still parse",
	) {
		return
	}

	/*
	Caching, with the `negative_ttl` the harness takes from the configuration.
	A cache made without one rejects the bogus entry this is about for having a
	zero lifetime, so without it the test cannot fail - `put` derives the
	lifetime from a zero message, which reads as a denial, and a denial with no
	negative TTL configured is not stored at all. The running server has 300
	there.
	*/
	h: Harness
	if !blocking_harness(t, &h, true, {"tracker.evil.example"}) {
		return
	}
	defer blocking_harness_stop(&h)

	_, first, _, _ := harness_ask(&h, test_query("www.brand.example."), wire)
	testing.expect_value(t, first, Outcome.Blocked)

	// The operator writes the documented escape hatch and reloads.
	block2 := filter.set_make()
	allow2 := filter.set_make()
	filter.set_add(block2, "tracker.evil.example", {.Apex, .Subdomains})
	filter.set_add(allow2, "www.brand.example", {.Apex, .Subdomains})
	ob, oa := filter.engine_swap(h.srv.filters, block2, allow2)
	filter.set_destroy(ob)
	filter.set_destroy(oa)

	_, second, _, _ := harness_ask(&h, test_query("www.brand.example."), wire, client = "127.0.0.2:5555")

	testing.expectf(
		t,
		second != .Blocked,
		"the allow rule did not release the name: a refusal reached on a partial decode outlived the reload (outcome=%v)",
		second,
	)
	free_all(context.temp_allocator)
}

/*
An unreadable CNAME is SERVFAIL, not a policy answer.

The three refusals are not the same kind of thing. A listed name and a chain
past `MAX_CHAIN_NAMES` targets are answers somebody built, and
`blocking.response` is what the operator asked for those. One CNAME whose target
will not parse is as likely to be an upstream or a middlebox as an attack, and
rendering it through `blocking.response` says something confident and wrong:
with the default that is NXDOMAIN, so a name that exists is reported not to,
with no rule behind it and nothing in the lists to explain it - and the stub
caches that for `blocking.block_ttl`. Under `zero_ip` the client gets an address
to connect to instead.

SERVFAIL is the only one of the three a stub retries or fails over from, and it
is what the whole-message version of the same problem already returns.
*/
@(test)
test_an_unreadable_cname_target_is_servfail_not_a_block_answer :: proc(t: ^testing.T) {
	wire := unreadable_cname_reply()
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture was meant to decode as a whole") {
		return
	}
	if !testing.expect(t, len(decoded.answer) == 1, "the fixture was meant to carry one record") {
		return
	}
	if _, is_name := decoded.answer[0].data.(dns.Rdata_Name); is_name {
		testing.fail_now(t, "the CNAME parsed after all, so this does not reach the Unreadable path")
	}

	// Nothing on any list: the refusal is about the record, not about a rule.
	h: Harness
	if !blocking_harness(t, &h, false, nil) {
		return
	}
	defer blocking_harness_stop(&h)

	out, outcome, ok, asked := harness_ask(&h, test_query("www.brand.example."), wire)
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	// Asked, or the SERVFAIL below is a timeout and says nothing of the record.
	testing.expect(t, asked, "the upstream was never asked")
	testing.expect_value(t, outcome, Outcome.Failed)
	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expectf(
		t,
		dns.rcode_of(served) == .Serv_Fail,
		"a record that would not parse was answered %v rather than SERVFAIL",
		dns.rcode_of(served),
	)
	free_all(context.temp_allocator)
}

/*
An unreadable record does not pin the name until the entry expires.

The refusal for a listed name is remembered on purpose: it is a stable fact
about an answer somebody built, and re-deriving it on every hit was the cost
that made a cloaked name the most expensive kind to serve. A record this decoder
could not parse is not a stable fact about anything. It is the case the SERVFAIL
was chosen for - an upstream or a middlebox having a bad day - and remembering
it turns a bad minute into a bad day: the entry answers SERVFAIL for up to
`cache.max_ttl` without the upstream being asked again, and a list reload cannot
release it because the re-walk reads the same stored bytes and reaches the same
verdict.

So the upstream is asked again, and a good answer is served.
*/
@(test)
test_an_unreadable_refusal_does_not_outlive_the_answer_that_caused_it :: proc(t: ^testing.T) {
	// Nothing on any list: the refusal is about the record alone.
	h: Harness
	if !blocking_harness(t, &h, true, nil) {
		return
	}
	defer blocking_harness_stop(&h)

	_, first, _, _ := harness_ask(&h, test_query("www.brand.example."), unreadable_cname_reply())
	testing.expect_value(t, first, Outcome.Failed)

	// The upstream stops sending the malformed record. It must be asked.
	_, second, _, asked := harness_ask(
		&h,
		test_query("www.brand.example."),
		chain_reply({"www.brand.example.", "good.brand.example."}),
		client = "127.0.0.2:5555",
	)
	testing.expect(t, asked, "the upstream was never re-asked: the parse failure was memoised")
	testing.expectf(t, second != .Failed, "the name stayed broken after a good answer was available (outcome=%v)", second)
	free_all(context.temp_allocator)
}

/*
An entry that turns unreadable on a *later* walk is dropped, not pinned.

The sibling test covers the forwarding path: an answer that is unreadable the
first time it is seen is never stored. This is the way in that the sibling
misses: the entry goes in clean, and only a later walk reaches the verdict.

It goes in clean because the question was allowlisted when it was stored, so the
walk returned before looking at any record. The operator then removes that rule
and reloads; the re-walk now reads the malformed CNAME and returns `Unreadable`.
Stamping that verdict onto the entry would pin the name to SERVFAIL until it
expired, with the upstream never asked again - the same outcome the forwarding
path declines to create, reached from the other side.
*/
@(test)
test_an_entry_that_turns_unreadable_on_a_later_walk_is_dropped :: proc(t: ^testing.T) {
	// The question is allowlisted, so the first walk returns before reading any
	// record and the answer is stored clean.
	h: Harness
	if !blocking_harness(t, &h, true, nil, {"www.brand.example"}) {
		return
	}
	defer blocking_harness_stop(&h)

	/*
	The malformed CNAME and an A at the question name, so the answer is one the
	cache keeps: a chain that stops short of the type asked for is a denial, and
	with no SOA it is not stored. Beside a CNAME at the same name that is
	CNAME-and-other-data (RFC 2181 section 10.1), which no zone serves - but the
	CNAME's target is unreadable, so no name past this one is there to hold it,
	and the walk that refuses the entry later never reads the A.
	*/
	_, first, _, _ := harness_ask(&h, test_query("www.brand.example."), unreadable_cname_reply(extra_a = true))
	// Allowlisted, so it was served and stored rather than refused.
	testing.expect_value(t, first, Outcome.Forwarded)
	// Stored, or the refusal below is the dead mock's timeout and not the re-walk.
	testing.expect_value(t, cache.stats(h.answers).inserts, 1)

	// The operator drops the allow rule and reloads.
	ob, oa := filter.engine_swap(h.srv.filters, filter.set_make(), filter.set_make())
	filter.set_destroy(ob)
	filter.set_destroy(oa)

	// The re-walk now reaches the malformed record: refused, and the entry goes.
	_, second, _ := handle_query(&h.srv, test_query("www.brand.example."), .UDP, "127.0.0.2:5555", context.temp_allocator)
	testing.expect_value(t, second, Outcome.Failed)

	// The upstream stops sending the malformed record. It must be asked again.
	_, third, _, asked := harness_ask(
		&h,
		test_query("www.brand.example."),
		chain_reply({"www.brand.example.", "good.brand.example."}),
		client = "127.0.0.3:5555",
	)
	testing.expect(t, asked, "the upstream was never re-asked: the parse failure was pinned onto the entry")
	testing.expectf(t, third != .Failed, "the name stayed broken after a good answer was available (outcome=%v)", third)
	free_all(context.temp_allocator)
}

/*
A `$dnstype` rule is judged on the type the client asked for (#406), for the
question and for every name its answer's chain reaches: an A query whose chain
ends at a name listed for A gets that name's addresses, which is what the rule is
there to stop. AdGuard Home matches a chain's targets as type CNAME instead,
which would let one CNAME carry any typed rule past the check.
*/
@(test)
test_a_dnstype_rule_is_judged_on_the_question_type :: proc(t: ^testing.T) {
	hops := []string{"www.brand.example.", "tracker.evil.example."}
	Case :: struct {
		rule:    string,
		blocked: bool,
	}
	cases := []Case {
		{"||www.brand.example^$dnstype=A", true},
		{"||www.brand.example^$dnstype=AAAA", false},
		{"||tracker.evil.example^$dnstype=A", true},
		{"||tracker.evil.example^$dnstype=AAAA", false},
		{"||tracker.evil.example^$dnstype=~AAAA", true},
		{"||tracker.evil.example^$dnstype=~A", false},
		{"||tracker.evil.example^$dnstype=CNAME", false},
		{"/^tracker\\.evil\\.example$/$dnstype=A", true},
		{"/^tracker\\.evil\\.example$/$dnstype=AAAA", false},
	}
	for c in cases {
		rules := []string{c.rule}
		outcome := serve_cached_answer(t, hops[0], chain_reply(hops), nil, nil, rules = rules)
		testing.expectf(t, (outcome == .Blocked) == c.blocked, "%q on an A query: %v", c.rule, outcome)
	}
	// An allow rule for the question's type is the escape hatch, as untyped.
	allowed := []string{"||tracker.evil.example^", "@@||www.brand.example^$dnstype=A"}
	testing.expect(t, serve_cached_answer(t, hops[0], chain_reply(hops), nil, nil, rules = allowed) != .Blocked)
	not_allowed := []string{"||tracker.evil.example^", "@@||www.brand.example^$dnstype=AAAA"}
	testing.expect_value(t, serve_cached_answer(t, hops[0], chain_reply(hops), nil, nil, rules = not_allowed), Outcome.Blocked)
}

/*
A block made only by `$dnstype` rules leaves the name its other types, so under
the default `blocking.response: nxdomain` it is answered NODATA: NXDOMAIN would
say the name has nothing of any type (RFC 8020 section 2), and a stub caching
that would stop resolving the types the rule left open. Asked about the cache
twice, so a refusal it remembers is answered the same way.
*/
@(test)
test_a_block_by_dnstype_alone_is_nodata :: proc(t: ^testing.T) {
	hops := []string{"www.brand.example.", "tracker.evil.example."}
	Case :: struct {
		rules: []string,
		rcode: dns.Rcode,
	}
	cases := []Case {
		{{"||www.brand.example^$dnstype=A"}, .No_Error},
		{{"||tracker.evil.example^$dnstype=A"}, .No_Error},
		{{"/^tracker\\.evil\\.example$/$dnstype=~AAAA"}, .No_Error},
		{{"||www.brand.example^"}, .NX_Domain},
		{{"||tracker.evil.example^"}, .NX_Domain},
		{{"||www.brand.example^$dnstype=A", "||brand.example^"}, .NX_Domain},
		{{"||tracker.evil.example^$dnstype=A", "||evil.example^"}, .NX_Domain},
	}
	for c in cases {
		for asks in 1 ..= 2 {
			out: []u8
			outcome := serve_cached_answer(t, hops[0], chain_reply(hops), nil, nil, rules = c.rules, response = &out, asks = asks)
			decoded, derr := dns.decode_message(out, context.temp_allocator)
			if !testing.expectf(t, outcome == .Blocked && derr == .None, "%v: %v, %v", c.rules, outcome, derr) {
				continue
			}
			rcode := dns.Rcode(decoded.flags.rcode)
			testing.expectf(t, rcode == c.rcode, "%v, asked %d times: rcode %v, want %v", c.rules, asks, rcode, c.rcode)
			testing.expectf(t, len(decoded.answer) == 0, "%v: %d answers", c.rules, len(decoded.answer))
		}
	}
}

/*
An entry whose recheck this server had no memory to read stays in the cache
(issue #620): the bytes are fine, and a later hit with room to read them walks
them then. Dropped, a spell of memory pressure would send every chained answer
asked for back upstream.
*/
@(test)
test_a_recheck_read_without_memory_keeps_the_entry :: proc(t: ^testing.T) {
	cfg: config.Config
	s := cached_server(t, &cfg, {"tracker.evil.example"}, nil)
	defer cached_server_destroy(&s)
	answers, engine := s.answers, s.filters

	hops := []string{"www.brand.example.", "cdn.brand.example."}
	if !seed_cache(t, answers, hops[0], chain_reply(hops)) {
		return
	}
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], hops[0], .A, .IN, false, false)
	hit, stored := stored_answer(&s, key, rules_generation(&s), context.temp_allocator)
	if !testing.expect(t, stored && hit.recheck, "an entry from before the reload was not flagged for a second look") {
		return
	}

	query := test_query(hops[0])
	msg, merr := dns.decode_message(query, context.temp_allocator)
	if !testing.expect(t, merr == .None && len(msg.question) == 1, "the query does not decode") {
		return
	}
	spent: int
	st := Query_State {
		s         = &s,
		query     = query,
		msg       = msg,
		q         = msg.question[0],
		proto     = .UDP,
		client    = "127.0.0.1:5555",
		limit     = dns.MAX_UDP_SIZE,
		spent     = &spent,
		allocator = mem.nil_allocator(),
	}
	_, outcome, _ := serve_from_cache(&st, hit)
	testing.expect_value(t, outcome, Outcome.Failed)

	_, kept, found := cache.get(answers, key, context.temp_allocator, checked_against = filter.engine_generation(engine))
	testing.expect(t, found && kept.recheck, "an entry nothing was wrong with was dropped for want of memory")
	free_all(context.temp_allocator)
}

// A cloaked name refused with no memory to build the refusal is counted failed.
@(test)
test_a_cloak_refusal_that_built_nothing_is_counted_failed :: proc(t: ^testing.T) {
	cfg := test_config()
	cfg.blocking.enabled = true
	s := Server{cfg = &cfg}
	defer free_all(context.temp_allocator)
	msg, derr := dns.decode_message(test_query("www.brand.example."), context.temp_allocator)
	if !testing.expect(t, derr == .None && len(msg.question) == 1, "the query does not decode") {
		return
	}

	out := refuse_cloaked(
		&s,
		"tracker.evil.example.",
		.Listed,
		msg,
		msg.question[0],
		.UDP,
		"127.0.0.1:5555",
		dns.MAX_UDP_SIZE,
		time.tick_now(),
		mem.nil_allocator(),
	)
	testing.expect_value(t, len(out), 0)
	testing.expect_value(t, s.stats.blocked, 0)
	testing.expect_value(t, s.stats.failed, 1)
}
