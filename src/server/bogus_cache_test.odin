package server

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:upstream"

/*
What a name that does not validate costs the server that refuses it.

The refusal itself is not in question - an answer with no chain to the anchor is
SERVFAIL and always was. What this is about is the second query for it, and the
ten thousandth: nothing on that path was stored, so every one of them was an
exchange with an upstream that was only ever going to hand back the same
unusable answer. Which name is asked about is the client's choice, so a zone
somebody breaks on purpose is the cheapest way there is to spend this server's
upstream budget - and it is not a fetch anybody benefits from, because the
answer is thrown away when it arrives.

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
	// A copy of its own, not a slice of the test's arena: the loop outlives the
	// body it was started from on every early return here.
	reply:       [512]u8,
	length:      int,
	// How many bytes of the question section the fixture's reply carries, so a
	// query for something else can be told apart from the client's.
	question:    int,
	answer_keys: bool,
	seen:        u64,
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
		if n >= dns.HEADER_SIZE + m.question &&
		   mem.compare(buf[dns.HEADER_SIZE:][:m.question], m.reply[dns.HEADER_SIZE:][:m.question]) == 0 {
			out := m.reply
			// The query's transaction id back, so the reply is matched to it.
			out[0], out[1] = buf[0], buf[1]
			_, _ = net.send_udp(m.socket, out[:m.length], remote)
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
	m := dns.Message {
		id       = 0x4d4d,
		question = []dns.Question{{name = BOGUS_NAME, type = .A, class = .IN}},
		answer   = []dns.Record {
			{
				name = BOGUS_NAME,
				type = .A,
				class = .IN,
				ttl = 300,
				data = dns.Rdata_A{addr = {203, 0, 113, 55}},
			},
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("failed to encode the mock's answer")
	}
	return wire
}

@(private = "file")
bogus_client_query :: proc(with_edns := false, rd := true) -> []u8 {
	m := dns.Message {
		id       = 0x7a7a,
		question = []dns.Question{{name = BOGUS_NAME, type = .A, class = .IN}},
	}
	m.flags.rd = rd
	if with_edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, false)
		m.additional = additional
	}
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("failed to encode the client query")
	}
	return wire
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
	cfg:       config.Config,
	answers:   ^cache.Cache,
	group:     ^upstream.Group,
	validator: ^dnssec.Validator,
	mock:      Counting_Mock,
	worker:    ^thread.Thread,
	server:    Server,
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
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return false
	}
	f.mock.socket = socket
	f.mock.answer_keys = answer_keys
	// Short, because it is what the serve loop uses to notice that the test is
	// over; nothing here waits on a query that is not coming.
	_ = net.set_option(socket, .Receive_Timeout, 100 * time.Millisecond)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		net.close(socket)
		return false
	}

	answer := unsigned_answer()
	if len(answer) > len(f.mock.reply) {
		testing.expect(t, false, "the fixture does not fit the mock's buffer")
		net.close(socket)
		return false
	}
	f.mock.length = copy(f.mock.reply[:], answer)
	name_buf: [dns.MAX_NAME_WIRE]u8
	name_len, name_err := dns.encode_name(BOGUS_NAME, name_buf[:])
	if name_err != .None {
		testing.expect(t, false, "the fixture's name does not encode")
		net.close(socket)
		return false
	}
	f.mock.question = name_len + 4

	f.cfg = config.default_config()
	f.cfg.log.queries = false
	f.cfg.cache.enabled = true
	f.cfg.cache.serve_stale = serve_stale
	f.cfg.dnssec.enabled = true
	f.cfg.upstream.strategy = .Failover
	f.cfg.upstream.attempts = 1
	/*
	Short, and it is the validator's lookup that may spend it: a mock that does
	not answer the walk's questions leaves it waiting, which is most of what
	that case takes. A second on loopback is far past what an answered exchange
	needs, and the client's own query timing out instead would fail the
	assertions rather than pass them quietly.
	*/
	f.cfg.upstream.timeout = 1 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	f.cfg.upstream.servers = servers

	g, gerr := upstream.make_group(f.cfg.upstream, nil)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		net.close(socket)
		return false
	}
	f.group = g
	f.answers = cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = serve_stale})
	f.server = Server {
		cfg     = &f.cfg,
		group   = f.group,
		answers = f.answers,
	}
	// The real thing, asking this mock for the chain it needs, exactly as the
	// running server's does. Kept in a field of its own as well, so a test can
	// stop the server validating without the teardown losing track of it.
	f.validator = dnssec.make_validator(validator_query, &f.server, dnssec.Options{})
	f.server.validator = f.validator
	f.key = cache.make_key(f.key_buf[:], BOGUS_NAME, .A, .IN, false, false)
	f.vkey = cache.make_key(f.vkey_buf[:], BOGUS_NAME, .A, .IN, false, false, verdict = true)

	f.worker = thread.create_and_start_with_poly_data(&f.mock, counting_mock_serve)
	return true
}

@(private = "file")
fixture_stop :: proc(f: ^Fixture) {
	sync.atomic_store(&f.mock.stop, true)
	thread.join(f.worker)
	thread.destroy(f.worker)
	dnssec.destroy_validator(f.validator)
	upstream.destroy_group(f.group)
	cache.destroy(f.answers)
	net.close(f.mock.socket)
}

@(private = "file")
is_servfail :: proc(wire: []u8) -> bool {
	return len(wire) >= dns.HEADER_SIZE && wire[3] & 0xf == u8(dns.Rcode.Serv_Fail)
}

@(private = "file")
carries_extended_error :: proc(opt: dns.Record) -> bool {
	options, ok := opt.data.(dns.Rdata_OPT)
	if !ok {
		return false
	}
	for option in options.options {
		if option.code == u16(dns.EDNS_Option_Code.Ext_Error) && len(option.data) >= 2 {
			return true
		}
	}
	return false
}

@(test)
test_a_bogus_verdict_is_not_asked_of_the_upstream_twice :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f, answer_keys = true) {
		return
	}
	defer fixture_stop(&f)

	query := bogus_client_query()

	first, outcome, served := handle_query(&f.server, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced for the first query")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, is_servfail(first), "the first query was not refused")

	asked := sync.atomic_load(&f.mock.seen)
	if !testing.expect(t, asked > 0, "the upstream was never asked, so nothing was validated") {
		return
	}

	// What the entry holds is the refusal and not the answer that failed: the
	// unvalidated data must not be anywhere a later hit could reach it.
	stored, _, found := cache.get(f.answers, f.vkey, context.temp_allocator)
	if testing.expect(t, found, "the verdict was not remembered") {
		testing.expect(t, is_servfail(stored), "the answer that did not validate was stored")
		testing.expect(t, stored[6] == 0 && stored[7] == 0, "the stored refusal carries an answer section")
	}

	counted := cache.stats(f.answers)
	second, again, served_again := handle_query(&f.server, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect_value(t, again, Outcome.Failed)
	testing.expect(t, is_servfail(second), "the second query was not refused")
	// The whole of it: the second client query cost nothing upstream.
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	/*
	And it cost the cache's own numbers one lookup rather than two.

	The verdict is looked for under a key of its own, after the answer cache has
	already been asked and has already counted what it found, so it is asked for
	as a `probe` and counted in neither direction. Counted, one query would show
	up as two misses and the identity an operator reads these numbers by - hits
	and misses are what the queries came to - would stop holding on exactly the
	traffic this change is about.
	*/
	settled := cache.stats(f.answers)
	testing.expect_value(t, settled.misses - counted.misses, 1)
	testing.expect_value(t, settled.hits, counted.hits)

	/*
	And the explanation survives the entry, whoever caused it.

	The queries above carry no EDNS, so the refusal they were answered with had
	nowhere to put an extended error - `dns.make_response` attaches an OPT
	record only when the query had one. The copy that was stored is built with
	one regardless, because which client happens to miss first is not a thing
	the next client's diagnostics should depend on.
	*/
	third, edns, served_edns := handle_query(
		&f.server,
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
		opt, has := dns.find_opt(msg)
		if testing.expect(t, has, "the EDNS client got no OPT record back") {
			testing.expect(t, carries_extended_error(opt), "the remembered refusal explains nothing to an EDNS client")
		}
	}

	/*
	And the verdict stops answering the moment this server stops validating.

	`validating` is recomputed for every query - a validator switched off by a
	reload, a zone since given a route, an anchor taken away from one that has
	one - and the entry carries no record of the rules it was refused under. So
	the memory is ignored rather than served, the question goes upstream as it
	would on a miss, and the answer that comes back is the one the client gets.
	*/
	f.server.validator = nil
	fourth, plain, served_plain := handle_query(&f.server, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_plain, "no response was produced with validation off")
	testing.expect_value(t, plain, Outcome.Forwarded)
	testing.expect(
		t,
		len(fourth) >= dns.HEADER_SIZE && fourth[3] & 0xf == u8(dns.Rcode.No_Error),
		"the remembered verdict answered a query this server was not validating",
	)
	testing.expect(
		t,
		sync.atomic_load(&f.mock.seen) > asked,
		"the upstream was not asked once the verdict stopped applying",
	)

	free_all(context.temp_allocator)
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
	first, outcome, served := handle_query(&f.server, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, is_servfail(first), "the query was not refused")

	_, _, found := cache.get(f.answers, f.vkey, context.temp_allocator)
	testing.expect(t, !found, "a walk this server could not finish was stored as a verdict")

	asked := sync.atomic_load(&f.mock.seen)
	_, _, served_again := handle_query(&f.server, query, .UDP, "test", context.temp_allocator)
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

	// An answer for the same question, expired, and inside the window
	// `serve_stale` keeps one for.
	wire := unsigned_answer()
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the fixture does not decode") {
		return
	}
	if !testing.expect(t, cache.put(f.answers, f.key, wire, decoded), "the answer was not cached") {
		return
	}
	if e, in_cache := f.answers.entries[f.key]; in_cache {
		e.expires = time.time_add(time.now(), -1 * time.Second)
		e.inserted = time.time_add(time.now(), -3600 * time.Second)
	} else {
		testing.expect(t, false, "the answer went in under another key")
		return
	}

	out, outcome, served := handle_query(&f.server, bogus_client_query(), .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(t, is_servfail(out), "the query was not refused")

	kept, hit, found := cache.get(f.answers, f.key, context.temp_allocator)
	if testing.expect(t, found, "the expired answer was dropped when the verdict was written down") {
		testing.expect(t, hit.stale, "the entry under the question's key is no longer the expired answer")
		if e, still_there := f.answers.entries[f.key]; still_there {
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
	verdict, _, remembered := cache.get(f.answers, f.vkey, context.temp_allocator)
	if testing.expect(t, remembered, "the verdict was not remembered beside the expired answer") {
		if e, in_cache := f.answers.entries[f.vkey]; testing.expect(t, in_cache, "the verdict went in elsewhere") {
			testing.expect(t, e.bogus, "what is under the verdict key is not a verdict")
		}
		testing.expect(t, is_servfail(verdict), "the verdict is not a refusal")
	}

	asked := sync.atomic_load(&f.mock.seen)
	_, again, served_again := handle_query(&f.server, bogus_client_query(), .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect_value(t, again, Outcome.Failed)
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	/*
	And the client that asked for local knowledge and nothing else still gets
	it.

	RD=0 is answered from what this server already holds or refused, and the
	expired answer is something it holds - which is why the gate hands it over
	rather than refusing, and why the verdict is looked for below that gate
	rather than above it. There is no upstream call on this path for a verdict
	to save, so reading one here would only take the fallback away from the
	clients the gate was written for.
	*/
	local, from_cache, answered := handle_query(
		&f.server,
		bogus_client_query(rd = false),
		.UDP,
		"test",
		context.temp_allocator,
	)
	testing.expect(t, answered, "no response was produced for the RD=0 query")
	testing.expect_value(t, from_cache, Outcome.Cached)
	testing.expect(
		t,
		len(local) >= dns.HEADER_SIZE && local[3] & 0xf == u8(dns.Rcode.No_Error) && local[7] == 1,
		"the RD=0 client was refused from the verdict instead of served what this server holds",
	)
	testing.expect_value(t, sync.atomic_load(&f.mock.seen), asked)

	free_all(context.temp_allocator)
}
