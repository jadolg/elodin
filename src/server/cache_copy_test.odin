package server

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:loop"

/*
The answer path copies an entry only where it serves it (issue #532).

An expired entry is forwarded past and served only once the upstream has failed
(RFC 8767 section 5), so the lookup takes its flags and `lend_stale` takes the
bytes. The panic allocator is the assertion: a copy made at the lookup fails the
test.
*/
@(test)
test_a_stale_lookup_copies_nothing_until_it_is_lent :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}
	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)

	held, found := stored_answer(&s, key, 0, mem.panic_allocator())
	testing.expect(t, found && held.stale && held.wire == nil, "the lookup of an expired entry copied it")

	lent, lfound := lend_stale(&s, held, context.temp_allocator)
	testing.expect(t, lfound && lent.stale && lent.wire != nil, "the expired entry was not lent once asked for")
	// The query's own lookup counted the miss; the lend is not a second one.
	testing.expect_value(t, cache.stats(answers).misses, u64(1))

	// Read as the entry stands at the lend: refreshed meanwhile, it is the fresh
	// answer; gone, there is no fallback.
	if !testing.expect(t, cache_an_answer(answers, expired = false), "the refresh was not cached") {
		return
	}
	fresh, ffound := lend_stale(&s, held, context.temp_allocator)
	testing.expect(t, ffound && !fresh.stale && fresh.wire != nil, "a lend after a refresh did not read the fresh answer")
	cache.forget(answers, key, fresh.serial)
	_, gone := lend_stale(&s, held, context.temp_allocator)
	testing.expect(t, !gone, "a lend of a forgotten entry found something")
	free_all(context.temp_allocator)
}

/*
The lend is matched against the rule sets in force when it is served, not when
the lookup ran: the wait for the upstream can outlast a list reload, and an
entry stamped under the old rules would otherwise go out without the re-walk.
*/
@(test)
test_a_stale_lend_reads_the_rules_in_force :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	cfg.blocking.enabled = true
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, filter.set_make(), filter.set_make())
	s.filters = engine

	m := dns.Message {
		question = []dns.Question{{name = STALE_NAME, type = .A, class = .IN}},
		answer   = []dns.Record {
			{name = STALE_NAME, type = .CNAME, class = .IN, ttl = 300, data = dns.Rdata_Name{name = "cdn.example.net."}},
			{name = "cdn.example.net.", type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 1}}},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, enc := dns.encode_message(m, context.temp_allocator)
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	before := rules_generation(&s)
	if !testing.expect(t, enc == .None && derr == .None && cache.put(answers, key, wire, decoded, before), "the answer was not cached") {
		return
	}
	if e, found := answers.entries[key]; found {
		e.expires = loop.moment_add(loop.moment_now(), -1 * time.Second)
	}

	held, found := stored_answer(&s, key, before, context.temp_allocator)
	testing.expect(t, found && held.stale && !held.recheck, "the lookup under the rules it was stored with asked for a re-walk")

	old_block, old_allow := filter.engine_swap(engine, filter.set_make(), filter.set_make())
	filter.set_destroy(old_block)
	filter.set_destroy(old_allow)
	lent, lfound := lend_stale(&s, held, context.temp_allocator)
	testing.expect(t, lfound && lent.recheck && lent.checked == rules_generation(&s), "the lend was not matched against the reloaded rules")
	free_all(context.temp_allocator)
}

/*
An entry whose refusal is current is refused from its flags, with no copy taken,
and stays refused if blocking reads as off by the time it is served: a hit
without bytes has nothing to serve.
*/
@(test)
test_a_standing_refusal_copies_nothing :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, filter.set_make(), filter.set_make())
	s := Server{cfg = &cfg, answers = answers, filters = engine}

	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}
	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	generation := rules_generation(&s)
	_, first, _ := cache.get(answers, key, context.temp_allocator)
	cache.note_checked(answers, key, first.serial, generation, u8(Cloak_Verdict.Listed))

	held, found := stored_answer(&s, key, generation, mem.panic_allocator())
	if !testing.expect(t, found && held.wire == nil && held.refused != 0, "the lookup of a refused entry copied it") {
		return
	}

	cfg.blocking.enabled = false
	msg, _ := dns.decode_message(stale_query(true), context.temp_allocator)
	spent: int
	_, outcome, ok := serve_from_cache(&s, held, stale_query(true), msg, msg.question[0], .UDP, "127.0.0.1:5555", 512, false, {}, &spent, context.temp_allocator)
	testing.expect(t, ok, "nothing came back at all")
	testing.expect_value(t, outcome, Outcome.Blocked)
	free_all(context.temp_allocator)
}
