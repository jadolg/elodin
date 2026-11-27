package server

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:dns"
import "elodin:logx"
import "elodin:dnssec"

/*
What a name that does not validate costs the server that refuses it.

The refusal itself is not in question - an answer with no chain to the anchor is
SERVFAIL. What this is about is the second query for it, and the ten thousandth:
without memory of the verdict, every one of them would be an exchange with an
upstream that is only ever going to hand back the same unusable answer. Which
name is asked about is the client's choice, so a zone somebody breaks on purpose
is the cheapest way there is to spend this server's upstream budget - and it is
not a fetch anybody benefits from, because the answer is thrown away when it
arrives.

The verdict is remembered instead (`cache.BOGUS_TTL`), and what is written down
is this server's own SERVFAIL rather than the answer that failed: there is
nothing in the cache for a later reload, or a bug, to serve as data. The bounds
on that memory are as much of the subject as the memory is, so each one is a
test here: it is only a verdict that is kept and never a walk that could not be
finished, it is kept under a key of its own so that the answer `serve_stale`
holds for the same name is untouched, and it answers only a request that would
have reached a verdict of its own.
*/

@(private = "file")
BOGUS_NAME :: "broken.example."

/*
An upstream that answers everything the same way, and counts what it was asked.

A loop rather than the one-shot mocks elsewhere in this package, because a
validating query is more than one exchange: the client's question goes out
first, and then the validator asks for the keys of the zone it would have to
check the answer against. What these tests assert is not that the upstream sees
one query - it is what a second identical *client* query adds to whatever the
first one cost.

`answer_keys` is which of the two verdicts this mock produces. Answering the key
lookup with a zone that published none is an answer that was checked and failed,
which is `Bogus`; saying nothing to it at all leaves the walk unable to finish,
which is `Indeterminate`. The server treats the two alike towards the client and
must not treat them alike in the cache.
*/
@(private = "file")
Counting_Mock :: struct {
	socket:      net.UDP_Socket,
	// A copy of its own, not a slice of the test's arena: each test resets the
	// temp arena before its deferred `fixture_stop` joins this loop.
	reply:       [512]u8,
	length:      int,
	answer_keys: bool,
	seen:        u64,
	// How many times the client's question was answered with the reply, sent.
	answered:    u64,
	stop:        bool,
}

@(private = "file")
counting_mock_serve :: proc(m: ^Counting_Mock) {
	buf: [4096]u8
	for !sync.atomic_load(&m.stop) {
		n, remote, err := net.recv_udp(m.socket, buf[:])
		// A timeout, which is how the loop gets to look at `stop` again.
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		// Counted on arrival, so a query these tests say was never sent is one
		// that was never counted either.
		sync.atomic_add(&m.seen, 1)
		// The client's question rather than one of the validator's own.
		if dns.same_question(buf[:n], m.reply[:m.length]) {
			if send_reply_as(m.socket, m.reply[:m.length], buf[:n], remote) {
				sync.atomic_add(&m.answered, 1)
			}
			continue
		}
		if !m.answer_keys {
			continue
		}
		// The question back with an empty answer section: a zone that published
		// no keys, which is a chain that fails rather than one that could not be
		// read.
		buf[2] |= 0x80 // QR
		buf[3] |= 0x80 // RA
		_, _ = net.send_udp(m.socket, buf[:n], remote)
	}
}

// An ordinary unsigned answer. Nothing signs it, so a validator holding it
// against the root anchor cannot authenticate it - which is the verdict these
// tests are about, reached without a captured chain.
@(private = "file")
unsigned_answer :: proc() -> []u8 {
	return test_reply(BOGUS_NAME, .A, a_record(BOGUS_NAME, {203, 0, 113, 55}, ttl = 300))
}

@(private = "file")
bogus_client_query :: proc(with_edns := false, rd := true) -> []u8 {
	if with_edns {
		return test_query(BOGUS_NAME, id = 0x7a7a, rd = rd, opt = dns.make_opt(1232, false))
	}
	return test_query(BOGUS_NAME, id = 0x7a7a, rd = rd)
}

/*
A resolver with one upstream, a real validator and an answer cache.

Held in one struct because the server points at the configuration and every part
of it has to be torn down in an order: the mock's loop reads its own socket, and
the validator asks the group questions on the thread that is answering a client.
The caller keeps it on its own stack, so nothing here may be moved after
`fixture_start` has handed the server a pointer into it.
*/
@(private = "file")
Fixture :: struct {
	h:         Harness,
	validator: ^dnssec.Validator,
	mock:      Counting_Mock,
	worker:    ^thread.Thread,
	key_buf:   [cache.KEY_MAX]u8,
	key:       string,
	// Where the verdict for the same question is kept. A key of its own, so
	// that remembering one takes nothing away from the answer under the key
	// above; see `cache.make_key`.
	vkey_buf:  [cache.KEY_MAX]u8,
	vkey:      string,
}

@(private = "file")
fixture_start :: proc(t: ^testing.T, f: ^Fixture, answer_keys: bool, serve_stale := false) -> bool {
	// Short, because it is what the serve loop uses to notice that the test is
	// over; nothing here waits on a query that is not coming. Left long, the
	// loop would not see `stop` and `fixture_stop` would wait out the long one.
	if !harness_bind(t, &f.h, wait = 100 * time.Millisecond) {
		return false
	}
	f.mock.socket = f.h.socket
	f.mock.answer_keys = answer_keys

	answer := unsigned_answer()
	if len(answer) > len(f.mock.reply) {
		testing.expect(t, false, "the fixture does not fit the mock's buffer")
		net.close(f.h.socket)
		return false
	}
	f.mock.length = copy(f.mock.reply[:], answer)

	f.h.cfg.cache.serve_stale = serve_stale
	/*
	Short, and it is the validator's lookup that may spend it: a mock that does
	not answer the walk's questions leaves it waiting, which is most of what
	that case takes. A second on loopback is far past what an answered exchange
	needs, and the client's own query timing out instead would fail the
	assertions rather than pass them quietly.
	*/
	f.h.cfg.upstream.timeout = 1 * time.Second
	// The real validator, asking this mock for the chain it needs, exactly as
	// the running server's does. Kept in a field of its own as well, so a test
	// can stop the server validating without the teardown losing track of it.
	if !harness_build(t, &f.h, caching = true, validating = true, chain_lookups = true) {
		return false
	}
	f.validator = f.h.srv.validator
	f.key = cache.make_key(f.key_buf[:], BOGUS_NAME, .A, .IN, false, checking_disabled = false)
	f.vkey = cache.make_key(f.vkey_buf[:], BOGUS_NAME, .A, .IN, false, checking_disabled = false, verdict = true)

	f.worker = thread.create_and_start_with_poly_data(&f.mock, counting_mock_serve)
	return true
}

@(private = "file")
fixture_stop :: proc(f: ^Fixture) {
	sync.atomic_store(&f.mock.stop, true)
	thread.join(f.worker)
	thread.destroy(f.worker)
	f.h.srv.validator = f.validator
	harness_stop(&f.h)
}

@(test)
test_a_bogus_verdict_is_not_asked_of_the_upstream_twice :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f, answer_keys = true) {
		return
	}
	defer fixture_stop(&f)

	query := bogus_client_query()

	first, outcome, served := handle_query(&f.h.srv, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced for the first query")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, dns.peek_rcode(first) == .Serv_Fail, "the first query was not refused")

	asked := sync.atomic_load(&f.mock.seen)
	if !testing.expect(t, asked > 0, "the upstream was never asked, so nothing was validated") {
		return
	}
	// The premise: what failed is the unsigned answer, told apart from the
	// validator's own lookups by its question.
	testing.expect_value(t, sync.atomic_load(&f.mock.answered), 1)

	// What the entry holds is the refusal and not the answer that failed: the
	// unvalidated data must not be anywhere a later hit could reach it.
	stored, _, found := cache.get(f.h.answers, f.vkey, context.temp_allocator)
	if testing.expect(t, found, "the verdict was not remembered") {
		testing.expect(t, dns.peek_rcode(stored) == .Serv_Fail, "the answer that did not validate was stored")
		testing.expect(t, stored[6] == 0 && stored[7] == 0, "the stored refusal carries an answer section")
	}

	counted := cache.stats(f.h.answers)
	second, again, served_again := handle_query(&f.h.srv, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect_value(t, again, Outcome.Failed)
	testing.expect(t, dns.peek_rcode(second) == .Serv_Fail, "the second query was not refused")
	// The whole of it: the second client query cost nothing upstream.
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	/*
	And it cost the cache's own numbers one lookup rather than two.

	The verdict is looked for under a key of its own, after the answer cache has
	already been asked and has already counted what it found, so it is asked for
	as a `probe` and counted in neither direction. Counted, one query would show
	up as two misses and the identity an operator reads these numbers by - hits
	and misses are what the queries came to - would stop holding on exactly this
	traffic.
	*/
	settled := cache.stats(f.h.answers)
	testing.expect_value(t, settled.misses - counted.misses, 1)
	testing.expect_value(t, settled.hits, counted.hits)

	expect_explained_to_edns(t, &f, asked)
	expect_forwarded_unvalidated(t, &f, query, asked)
	free_all(context.temp_allocator)
}

// The remembered refusal, asked for by a client with EDNS, without the upstream:
// it carries an extended error.
@(private = "file")
expect_explained_to_edns :: proc(t: ^testing.T, f: ^Fixture, asked: u64) {
	/*
	And the explanation survives the entry, whoever caused it.

	The queries above carry no EDNS, so the refusal they were answered with had
	nowhere to put an extended error - `dns.make_response` attaches an OPT
	record only when the query had one. The copy that was stored is built with
	one regardless, because which client happens to miss first is not a thing
	the next client's diagnostics should depend on.
	*/
	third, edns, served_edns := handle_query(
		&f.h.srv,
		bogus_client_query(with_edns = true),
		.UDP,
		"test",
		context.temp_allocator,
	)
	testing.expect(t, served_edns, "no response was produced for the EDNS client")
	testing.expect_value(t, edns, Outcome.Failed)
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)
	msg, derr := dns.decode_message(third, context.temp_allocator)
	if testing.expect(t, derr == .None, "the response does not decode") {
		_, has := dns.find_opt(msg)
		if testing.expect(t, has, "the EDNS client got no OPT record back") {
			code, _ := extended_error(third) // lint:allow only the info-code is checked
			testing.expect(t, code >= 0, "the remembered refusal explains nothing to an EDNS client")
		}
	}
}

// The remembered refusal ignored once `f` stops validating: `query` is forwarded
// past `asked` and answered as the upstream answers.
@(private = "file")
expect_forwarded_unvalidated :: proc(t: ^testing.T, f: ^Fixture, query: []u8, asked: u64) {
	/*
	And the verdict stops answering the moment this server stops validating.

	`validating` is recomputed for every query - a validator switched off by a
	reload, a zone since given a route, an anchor taken away from one that has
	one - and the entry carries no record of the rules it was refused under. So
	the memory is ignored rather than served, the question goes upstream as it
	would on a miss, and the answer that comes back is the one the client gets.
	*/
	f.h.srv.validator = nil
	fourth, plain, served_plain := handle_query(&f.h.srv, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_plain, "no response was produced with validation off")
	testing.expect_value(t, plain, Outcome.Forwarded)
	testing.expect(
		t,
		len(fourth) >= dns.HEADER_SIZE && dns.peek_rcode(fourth) == .No_Error,
		"the remembered verdict answered a query this server was not validating",
	)
	testing.expect(
		t,
		sync.atomic_load(&f.mock.seen) > asked,
		"the upstream was not asked once the verdict stopped applying",
	)
}

/*
An `Indeterminate` verdict is not a verdict to keep.

The two share a branch because both are SERVFAIL to the client, and they are
opposite statements about the answer: `Bogus` was checked and failed, while
`Indeterminate` is this server saying it could not finish looking - a key lookup
that got no reply, a parent that answered SERVFAIL, a walk that ran out of its
allowance. Kept, one lost datagram would refuse a perfectly good name to every
client for a minute, with the upstream never asked again in the meantime.

The mock here answers the client's question and nothing else, which is exactly
that: the walk cannot be made, and the answer might have been fine.
*/
@(test)
test_a_verdict_that_could_not_be_reached_is_not_remembered :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f, answer_keys = false) {
		return
	}
	defer fixture_stop(&f)

	query := bogus_client_query()
	first, outcome, served := handle_query(&f.h.srv, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, dns.peek_rcode(first) == .Serv_Fail, "the query was not refused")

	_, _, found := cache.get(f.h.answers, f.vkey, context.temp_allocator)
	testing.expect(t, !found, "a walk this server could not finish was stored as a verdict")

	asked := sync.atomic_load(&f.mock.seen)
	_, _, served_again := handle_query(&f.h.srv, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect(
		t,
		sync.atomic_load(&f.mock.seen) > asked,
		"the second query was answered from a memory of a verdict that was never reached",
	)

	free_all(context.temp_allocator)
}

/*
The memory is kept without taking the answer `serve_stale` is holding.

An entry replaces what is under its key, so a verdict filed under the question's
own key would throw away the expired answer being kept for exactly the outage
that may be starting - and a verdict that gave way to that answer instead would
leave a name somebody controls costing an upstream exchange per query for as
long as `cache.MAX_STALE`, which is the whole of what this is about. They are
wanted at once and they answer different minutes, so the verdict has a key of
its own: it refuses the next minute of queries, and what is under the question's
key is still there to cover the upstream going down after that.
*/
@(test)
test_a_verdict_is_remembered_without_taking_the_answer_kept_for_an_outage :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f, answer_keys = true, serve_stale = true) {
		return
	}
	defer fixture_stop(&f)

	if !store_expired_answer(t, &f) {
		return
	}

	out, outcome, served := handle_query(&f.h.srv, bogus_client_query(), .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, dns.peek_rcode(out) == .Serv_Fail, "the query was not refused")

	expect_answer_and_verdict_kept(t, &f)

	asked := sync.atomic_load(&f.mock.seen)
	_, again, served_again := handle_query(&f.h.srv, bogus_client_query(), .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect_value(t, again, Outcome.Failed)
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	/*
	An RD=0 client is refused at the RD gate, above the verdict, and the expired
	answer is not served to it (RFC 8767 section 5): the refusal is REFUSED with
	`detail=rd`, not the verdict's SERVFAIL.
	*/
	local, refused, answered := handle_query(
		&f.h.srv,
		bogus_client_query(rd = false),
		.UDP,
		"test",
		context.temp_allocator,
	)
	testing.expect(t, answered, "no response was produced for the RD=0 query")
	testing.expect_value(t, refused, Outcome.Refused)
	testing.expect_value(t, dns.peek_rcode(local), dns.Rcode.Refused)
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	free_all(context.temp_allocator)
}

// An answer for `f`'s question, expired, and inside the window `serve_stale`
// keeps one for; false, with the failure reported, when it could not be stored.
@(private = "file")
store_expired_answer :: proc(t: ^testing.T, f: ^Fixture) -> bool {
	wire := unsigned_answer()
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture does not decode") {
		return false
	}
	if !testing.expect(t, cache.put(f.h.answers, f.key, wire, decoded), "the answer was not cached") {
		return false
	}
	return testing.expect(t, expire_entry(f.h.answers, f.key), "the answer is not stored under its question's key")
}

// Both under their own keys: the expired answer under the question's, and the
// verdict under its own.
@(private = "file")
expect_answer_and_verdict_kept :: proc(t: ^testing.T, f: ^Fixture) {
	kept, hit, found := cache.get(f.h.answers, f.key, context.temp_allocator)
	if testing.expect(t, found, "the expired answer was dropped when the verdict was written down") {
		testing.expect(t, hit.stale, "the entry under the question's key is no longer the expired answer")
		if e := cached_entry(f.h.answers, f.key); testing.expect(t, e != nil, "the answer under the question's key is gone") {
			testing.expect(t, !e.bogus, "the verdict replaced the answer being kept for an outage")
		}
		testing.expect(
			t,
			len(kept) >= dns.HEADER_SIZE && kept[7] == 1,
			"what is left under the question's key is not the answer that was there",
		)
	}

	// And the verdict was written down all the same, which is the half that
	// giving way to the expired answer would have cost.
	verdict, _, remembered := cache.get(f.h.answers, f.vkey, context.temp_allocator)
	if testing.expect(t, remembered, "the verdict was not remembered beside the expired answer") {
		if e := cached_entry(f.h.answers, f.vkey); testing.expect(t, e != nil, "the verdict went in elsewhere") {
			testing.expect(t, e.bogus, "what is under the verdict key is not a verdict")
		}
		testing.expect(t, dns.peek_rcode(verdict) == .Serv_Fail, "the verdict is not a refusal")
	}
}

/*
A Bogus verdict is gated per zone, so a zone that stays broken and busy cannot
take the window from one that breaks later and is asked for rarely.

Every name under one zone shares a gate, whatever its case and whether or not
the walk named the zone; another zone has its own. The two zones here are ones
whose slots differ, which is what the case is about rather than the hash.
*/
@(test)
test_a_bogus_zone_has_a_gate_of_its_own :: proc(t: ^testing.T) {
	broken := dnssec.Result{status = .Bogus, reason = "broken chain of trust", detail = "busy.example: the DNSKEY reply held no keys"}
	forged := dnssec.Result{status = .Bogus, reason = "no valid signature"}

	// A table of the test's own, so nothing here touches the server's.
	gates: [ZONE_GATES]logx.Gate
	busy := zone_gate(&gates, dns.Question{name = "a1.busy.example.", type = .A}, forged)
	testing.expect(t, busy == zone_gate(&gates, dns.Question{name = "ZZ9.Busy.Example.", type = .A}, forged), "two names under one zone took two gates")
	testing.expect(t, busy == zone_gate(&gates, dns.Question{name = "deep.under.busy.example.", type = .A}, broken), "the zone the walk named was not the key")
	testing.expect(t, busy != zone_gate(&gates, dns.Question{name = "www.quiet.example.", type = .A}, forged), "another zone shared the busy one's gate")
}
