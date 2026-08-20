package server

import "core:fmt"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:upstream"

/*
Blocking is decided on the answer as well as the question.

An answer may point somewhere else entirely: the question is a first-party name
the site owns, the CNAME in the answer lands on the tracker, and the address the
browser ends up talking to is the tracker's. Pi-hole calls this CNAME cloaking
and inspects the chain for it; so does `cloaked_chain_target`, and what follows
holds it to that - through a mock upstream for the forwarding path, and through
an answer put straight into the cache for the hit path.
*/

@(private = "file")
Cloak_Mock :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	asked:  bool,
}

@(private = "file")
serve_cloak :: proc(x: ^Cloak_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.asked = true
	out: [4096]u8
	copy(out[:], x.reply)
	// The resolver draws a fresh transaction ID for every query it forwards.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
cloak_query :: proc(name: string) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = .A, class = .IN}
	msg := dns.Message{id = 0x4321, question = questions}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
cloak_reply :: proc(qname, target: string) -> []u8 {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name  = qname,
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = target},
	}
	answer[1] = dns.Record {
		name  = target,
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = qname, type = .A, class = .IN}
	msg := dns.Message{question = question, answer = answer}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(test)
test_a_blocked_name_reached_through_a_cname_is_still_blocked :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block := filter.set_make()
	allow := filter.set_make()
	filter.set_add(block, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block, allow)

	s := Server{cfg = &cfg, group = group, filters = engine}

	// The tracker is on the list: asked for directly, it is blocked.
	testing.expect_value(t, filter.engine_match(engine, "tracker.evil.example."), filter.Decision.Blocked)

	x := Cloak_Mock{socket = socket, reply = cloak_reply("www.brand.example.", "tracker.evil.example.")}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	out, outcome, ok := handle_query(&s, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

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
				filter.engine_match(engine, cname.name) != .Blocked,
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
		answer[i] = dns.Record {
			name  = hops[i],
			type  = .CNAME,
			class = .IN,
			ttl   = 60,
			data  = dns.Rdata_Name{name = hops[i + 1]},
		}
	}
	answer[len(hops) - 1] = dns.Record {
		name  = hops[len(hops) - 1],
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	return chain_wire(hops[0], answer)
}

@(private = "file")
chain_wire :: proc(qname: string, answer: []dns.Record) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = qname, type = .A, class = .IN}
	msg := dns.Message{question = question, answer = answer}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
serve_cached_chain :: proc(t: ^testing.T, hops, block, allow: []string) -> Outcome {
	return serve_cached_answer(t, hops[0], chain_reply(hops), block, allow)
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
) -> Outcome {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block_set := filter.set_make()
	allow_set := filter.set_make()
	for d in block {
		filter.set_add(block_set, d, {.Apex, .Subdomains})
	}
	for d in allow {
		filter.set_add(allow_set, d, {.Apex, .Subdomains})
	}
	filter.engine_swap(engine, block_set, allow_set)

	s := Server{cfg = &cfg, answers = answers, filters = engine}

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the answer would not decode: %v", derr) {
		return .Failed
	}
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], qname, .A, .IN, false, false)
	checked := filter.engine_generation(engine) if stamped else 0
	if !testing.expect(t, cache.put(answers, key, wire, decoded, checked), "the answer was not cached") {
		return .Failed
	}

	_, outcome, ok := handle_query(&s, cloak_query(qname), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expect(t, ok, "nothing came back at all")
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

// An exception written for the name that was asked about covers the lookup and
// not just the label: the chain below it is not searched for a reason to refuse.
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

This asserted the opposite until an allowlisted name anywhere in the answer was
recognised for what it is: a key the responder can use to turn the check off.
The chain here reaches a listed name and then an allowed one, and the answer is
refused for the listed name regardless of what follows it.
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
	answer := make([]dns.Record, 3, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "cdn.allowed.example."},
	}
	answer[1] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[2] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_wire("www.brand.example.", answer),
		[]string{"tracker.evil.example"},
		[]string{"cdn.allowed.example"},
	)
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
The escape hatch that remains: allow the question.

Nobody but the client chooses what gets asked, so an allow rule on the question
is an operator statement about a lookup rather than something a responder can
manufacture. This is what an operator reaches for when a first-party name
resolves through a CDN somebody has listed.
*/
@(test)
test_allowing_the_question_still_exempts_a_listed_chain :: proc(t: ^testing.T) {
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
Two CNAMEs at one owner name, the listed one second.

A zone may not publish that (RFC 1034 section 3.6.2), which is the point: the
answer comes from whoever runs the cloaked zone, and following only the first
CNAME at each owner would let them put an innocent one in front of the tracker
and have the walk end there while the tracker's address rides along in the same
answer.
*/
@(test)
test_a_decoy_cname_beside_the_listed_one_does_not_hide_it :: proc(t: ^testing.T) {
	answer := make([]dns.Record, 3, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "decoy.brand.example."},
	}
	answer[1] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[2] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_wire("www.brand.example.", answer),
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
	answer := make([]dns.Record, 4, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "decoy.brand.example."},
	}
	answer[1] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "hop.other.example."},
	}
	answer[2] = dns.Record {
		name  = "hop.other.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[3] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_wire("www.brand.example.", answer),
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
		answer[i] = dns.Record {
			name  = "www.brand.example.",
			type  = .CNAME,
			class = .IN,
			ttl   = 60,
			data  = dns.Rdata_Name{name = "decoy.brand.example."},
		}
	}
	answer[MAX_CHAIN_NAMES] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[MAX_CHAIN_NAMES + 1] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_wire("www.brand.example.", answer),
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
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block_set := filter.set_make()
	filter.set_add(block_set, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block_set, filter.set_make())

	s := Server{cfg = &cfg, answers = answers, filters = engine}

	hops := []string{"www.brand.example.", "cdn.brand.example."}
	wire := chain_reply(hops)
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], hops[0], .A, .IN, false, false)
	// Stored before the lists this server is running: the first hit has to walk it.
	testing.expect(t, cache.put(answers, key, wire, decoded), "the answer was not cached")

	_, first, _ := cache.get(answers, key, context.temp_allocator, checked_against = filter.engine_generation(engine))
	testing.expect(t, first.recheck, "an entry from before the reload was not flagged for a second look")

	_, outcome, ok := handle_query(&s, cloak_query(hops[0]), .UDP, "127.0.0.1:5555", context.temp_allocator)
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
		answer[i] = dns.Record {
			name  = "www.brand.example.",
			type  = .CNAME,
			class = .IN,
			ttl   = 60,
			data  = dns.Rdata_Name{name = fmt.tprintf("decoy%d.brand.example.", i)},
		}
	}
	answer[MAX_CHAIN_NAMES] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[MAX_CHAIN_NAMES + 1] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	outcome := serve_cached_answer(
		t,
		"www.brand.example.",
		chain_wire("www.brand.example.", answer),
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

The boundary in the other direction, and it has to be the *exact* one. This
tested fifteen targets against a walk that admits sixteen, and its partner
tested eighteen against a refusal that starts at seventeen - so the pair passed
whether the budget was 15, 16 or 17, on a number that decides whether ordinary
answers are withheld. Sixteen here and seventeen there is what pins it.
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
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block := filter.set_make()
	allow := filter.set_make()
	filter.set_add(block, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block, allow)

	s := Server{cfg = &cfg, group = group, filters = engine, answers = answers}

	x := Cloak_Mock{socket = socket, reply = cloak_reply("www.brand.example.", "tracker.evil.example.")}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	_, first, _ := handle_query(&s, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	testing.expect(t, x.asked, "the upstream was never asked for the first query")
	testing.expect_value(t, first, Outcome.Blocked)

	// No mock is listening now. A second upstream query would time out and the
	// query would fail; answered from the stored refusal, it is blocked again.
	_, second, ok := handle_query(&s, cloak_query("www.brand.example."), .UDP, "127.0.0.2:5555", context.temp_allocator)
	testing.expect(t, ok, "the second query produced nothing at all")
	testing.expect_value(t, second, Outcome.Blocked)
	free_all(context.temp_allocator)
}

/*
A refused answer does not take the upstream's AD bit into the cache with it.

The bytes are stored so a later reload has something to walk, and a reload that
clears the name serves them. If the upstream's AD bit went in with them, that
later answer would carry this server's assurance that it validated something it
never looked at - which is what clearing the bit before the store is for, and
which the refused branch quietly did not do when it was added.

Driven with DNSSEC off, so `validating` is false and the bit must be cleared on
every stored answer, refused or not.
*/
@(test)
test_a_refused_answer_is_not_cached_with_the_upstream_ad_bit :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block := filter.set_make()
	allow := filter.set_make()
	filter.set_add(block, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block, allow)

	s := Server{cfg = &cfg, group = group, filters = engine, answers = answers}

	// The upstream claims the answer is authenticated.
	reply := cloak_reply("www.brand.example.", "tracker.evil.example.")
	reply[3] |= 0x20

	x := Cloak_Mock{socket = socket, reply = reply}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	_, outcome, _ := handle_query(&s, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	testing.expect_value(t, outcome, Outcome.Blocked)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "www.brand.example.", .A, .IN, false, false)
	entry, found := answers.entries[key]
	if !testing.expect(t, found, "the refused answer was not stored, so nothing can re-walk it later") {
		return
	}
	testing.expect(
		t,
		entry.wire[3] & 0x20 == 0,
		"the stored answer kept the upstream's AD bit, which a later reload would serve under our name",
	)
	free_all(context.temp_allocator)
}

/*
A malformed record in a section the walk never reads does not cost the answer.

The walk reads the answer section. The cache reads the whole message, so a
record it cannot parse anywhere means the answer is not stored - which is fine,
and was always the behaviour. What is not fine is refusing to *serve* it: for a
round this gate was `!have_decoded`, which is the whole message, so one bad
RDLENGTH in an additional section turned a clean, walkable answer into SERVFAIL,
and only once blocking was on.

The reply here has a good CNAME chain and one additional record whose RDLENGTH
runs past the end of the message.
*/
@(test)
test_junk_outside_the_answer_section_does_not_withhold_the_answer :: proc(t: ^testing.T) {
	// A well-formed reply for www.brand.example -> good.brand.example, built and
	// then extended by hand with an additional record that cannot be parsed.
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "good.brand.example."},
	}
	answer[1] = dns.Record {
		name  = "good.brand.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 20}},
	}
	base := chain_wire("www.brand.example.", answer)

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
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block := filter.set_make()
	allow := filter.set_make()
	filter.set_add(block, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block, allow)

	srv := Server{cfg = &cfg, group = group, filters = engine}

	x := Cloak_Mock{socket = socket, reply = wire}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	_, outcome, _ := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

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
was declared as, and storing the refusal from it built an entry out of nothing
to do with these bytes: `redirects` came out false, and `get` derives `recheck`
from `redirects`, so the entry could never be walked again. The refusal it
carried was then replayed on every hit until it expired - including after the
operator wrote the allow rule the documentation points them at, which is the one
thing that was supposed to release it.

So nothing is stored for that answer, and the name goes upstream again. This
asserts the release: the same cloaked answer, refused, and then allowed once the
question is on the allow list and the lists have been reloaded.
*/
@(test)
test_a_refusal_on_a_partial_decode_is_released_by_a_reload :: proc(t: ^testing.T) {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name  = "www.brand.example.",
		type  = .CNAME,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_Name{name = "tracker.evil.example."},
	}
	answer[1] = dns.Record {
		name  = "tracker.evil.example.",
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = {203, 0, 113, 7}},
	}
	base := chain_wire("www.brand.example.", answer)

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

	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	/*
	Built from the configuration rather than with a literal, and `negative_ttl`
	is the reason. A cache made without one rejects the bogus entry this is
	about for having a zero lifetime, so the test passed against the bug -
	`put` derives the lifetime from a zero message, which reads as a denial, and
	a denial with no negative TTL configured is not stored at all. The running
	server has 300 there.
	*/
	answers := cache.make_cache(
		cache.Options {
			max_entries = 8,
			max_ttl = cfg.cache.max_ttl,
			min_ttl = cfg.cache.min_ttl,
			negative_ttl = cfg.cache.negative_ttl,
		},
	)
	defer cache.destroy(answers)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	block := filter.set_make()
	allow := filter.set_make()
	filter.set_add(block, "tracker.evil.example", {.Apex, .Subdomains})
	filter.engine_swap(engine, block, allow)

	srv := Server{cfg = &cfg, group = group, filters = engine, answers = answers}

	x := Cloak_Mock{socket = socket, reply = wire}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	_, first, _ := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	testing.expect_value(t, first, Outcome.Blocked)

	// The operator writes the documented escape hatch and reloads.
	block2 := filter.set_make()
	allow2 := filter.set_make()
	filter.set_add(block2, "tracker.evil.example", {.Apex, .Subdomains})
	filter.set_add(allow2, "www.brand.example", {.Apex, .Subdomains})
	ob, oa := filter.engine_swap(engine, block2, allow2)
	filter.set_destroy(ob)
	filter.set_destroy(oa)

	y := Cloak_Mock{socket = socket, reply = wire}
	mock2 := thread.create_and_start_with_poly_data(&y, serve_cloak)
	_, second, _ := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.2:5555", context.temp_allocator)
	thread.join(mock2)
	thread.destroy(mock2)

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

The three refusals are not the same kind of thing. A listed name and a
seventeen-name chain are answers somebody built, and `blocking.response` is what
the operator asked for those. One CNAME whose target will not parse is as likely
to be an upstream or a middlebox as an attack, and rendering it through
`blocking.response` says something confident and wrong: with the default that is
NXDOMAIN, so a name that exists is reported not to, with no rule behind it and
nothing in the lists to explain it - and the stub caches that for
`blocking.block_ttl`. Under `zero_ip` the client gets an address to connect to
instead.

SERVFAIL is the only one of the three a stub retries or fails over from, and it
is what the whole-message version of the same problem already returns.
*/
@(test)
test_an_unreadable_cname_target_is_servfail_not_a_block_answer :: proc(t: ^testing.T) {
	// A CNAME whose RDATA is a compression pointer aiming past the end of the
	// message: the record decodes as Rdata_Raw, the message decodes fine.
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = "www.brand.example.", type = .A, class = .IN}
	msg := dns.Message{question = question}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	base, _, enc := dns.encode_message(msg, context.temp_allocator)
	if !testing.expect(t, enc == .None, "could not build the fixture") {
		return
	}

	wire := make([dynamic]u8, 0, len(base) + 32, context.temp_allocator)
	append(&wire, ..base)
	wire[7] = 1 // ANCOUNT = 1
	// Owner: www.brand.example., written out rather than compressed.
	for label in ([]string{"www", "brand", "example"}) {
		append(&wire, u8(len(label)))
		append(&wire, ..transmute([]u8)label)
	}
	append(&wire, 0)
	append(&wire, 0, 5) // TYPE = CNAME
	append(&wire, 0, 1) // CLASS = IN
	append(&wire, 0, 0, 0, 60) // TTL
	append(&wire, 0, 2) // RDLENGTH = 2
	append(&wire, 0xc0, 0xfe) // a pointer past the end of the message

	decoded, derr := dns.decode_message(wire[:], context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture was meant to decode as a whole") {
		return
	}
	if !testing.expect(t, len(decoded.answer) == 1, "the fixture was meant to carry one record") {
		return
	}
	if _, is_name := decoded.answer[0].data.(dns.Rdata_Name); is_name {
		testing.fail_now(t, "the CNAME parsed after all, so this does not reach the Unreadable path")
	}

	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	// Nothing on any list: the refusal is about the record, not about a rule.
	filter.engine_swap(engine, filter.set_make(), filter.set_make())

	srv := Server{cfg = &cfg, group = group, filters = engine}

	x := Cloak_Mock{socket = socket, reply = wire[:]}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	out, outcome, ok := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Failed)
	served, serr2 := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr2, dns.Decode_Error.None)
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
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	answers := cache.make_cache(
		cache.Options {
			max_entries = 8,
			max_ttl = cfg.cache.max_ttl,
			min_ttl = cfg.cache.min_ttl,
			negative_ttl = cfg.cache.negative_ttl,
		},
	)
	defer cache.destroy(answers)

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	// Nothing on any list: the refusal is about the record alone.
	filter.engine_swap(engine, filter.set_make(), filter.set_make())

	srv := Server{cfg = &cfg, group = group, filters = engine, answers = answers}

	// A CNAME whose RDATA is a pointer past the end of the message.
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = "www.brand.example.", type = .A, class = .IN}
	skeleton := dns.Message{question = question}
	skeleton.flags.qr = true
	skeleton.flags.rd = true
	skeleton.flags.ra = true
	base, _, enc := dns.encode_message(skeleton, context.temp_allocator)
	if !testing.expect(t, enc == .None, "could not build the fixture") {
		return
	}
	bad := make([dynamic]u8, 0, len(base) + 32, context.temp_allocator)
	append(&bad, ..base)
	bad[7] = 1
	for label in ([]string{"www", "brand", "example"}) {
		append(&bad, u8(len(label)))
		append(&bad, ..transmute([]u8)label)
	}
	append(&bad, 0)
	append(&bad, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0xfe)

	x := Cloak_Mock{socket = socket, reply = bad[:]}
	mock := thread.create_and_start_with_poly_data(&x, serve_cloak)
	_, first, _ := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	testing.expect_value(t, first, Outcome.Failed)

	// The upstream stops sending the malformed record. It must be asked.
	y := Cloak_Mock{socket = socket, reply = cloak_reply("www.brand.example.", "good.brand.example.")}
	mock2 := thread.create_and_start_with_poly_data(&y, serve_cloak)
	_, second, _ := handle_query(&srv, cloak_query("www.brand.example."), .UDP, "127.0.0.2:5555", context.temp_allocator)
	thread.join(mock2)
	thread.destroy(mock2)

	testing.expect(t, y.asked, "the upstream was never re-asked: the parse failure was memoised")
	testing.expectf(t, second != .Failed, "the name stayed broken after a good answer was available (outcome=%v)", second)
	free_all(context.temp_allocator)
}
