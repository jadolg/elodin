package server

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
ten thousandth: nothing on that path was ever stored, so every one of them was
an exchange with an upstream that was only ever going to hand back the same
unusable answer. Which name is asked about is the client's choice, so a zone
somebody breaks on purpose is the cheapest way there is to spend this server's
upstream budget - and it is not a fetch anybody benefits from, because the
answer is thrown away when it arrives.

The verdict is remembered instead (`cache.BOGUS_TTL`), and what is written down
is this server's own SERVFAIL rather than the answer that failed: there is
nothing in the cache for a later reload, or a bug, to serve as data.
*/

@(private = "file")
BOGUS_NAME :: "broken.example."

/*
An upstream that answers everything the same way, and counts what it was asked.

A loop rather than the one-shot mocks elsewhere in this package, because a
validating query is more than one exchange: the client's question goes out
first, and then the validator asks for the keys of the zone it would have to
check the answer against. What this test asserts is not that the upstream sees
one query - it is that a second identical *client* query adds nothing at all to
whatever the first one cost.
*/
@(private = "file")
Counting_Mock :: struct {
	socket: net.UDP_Socket,
	// A copy of its own, not a slice of the test's arena: the loop outlives the
	// body it was started from on every early return here.
	reply:  [512]u8,
	length: int,
	seen:   u64,
	stop:   bool,
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
		// Counted on arrival, so a query this test says was never sent is one
		// that was never counted either.
		sync.atomic_add(&m.seen, 1)
		out := m.reply
		// The query's transaction id back, so the reply is matched to it.
		out[0], out[1] = buf[0], buf[1]
		_, _ = net.send_udp(m.socket, out[:m.length], remote)
	}
}

// An ordinary unsigned answer. Nothing signs it, so a validator holding it
// against the root anchor cannot authenticate it - which is the verdict this
// test is about, reached without a captured chain.
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
bogus_client_query :: proc() -> []u8 {
	m := dns.Message {
		id       = 0x7a7a,
		question = []dns.Question{{name = BOGUS_NAME, type = .A, class = .IN}},
	}
	m.flags.rd = true
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("failed to encode the client query")
	}
	return wire
}

@(test)
test_a_bogus_verdict_is_not_asked_of_the_upstream_twice :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return
	}
	defer net.close(socket)
	// Short, because it is what the serve loop uses to notice that the test is
	// over; nothing here waits on a query that is not coming.
	_ = net.set_option(socket, .Receive_Timeout, 100 * time.Millisecond)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return
	}

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = true
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	/*
	Short, and it is the validator's lookup that spends it: this mock answers
	the client's question and nothing else, so the walk for the zone's keys gets
	no reply and the wait for it is most of what this test takes. A second on
	loopback is far past what the answered exchange needs and bounds the
	unanswered one; the client's own query timing out instead would fail the
	assertions below rather than pass them quietly.
	*/
	cfg.upstream.timeout = 1 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	g, gerr := upstream.make_group(cfg.upstream, nil)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		return
	}
	defer upstream.destroy_group(g)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		group   = g,
		answers = answers,
	}
	// The real thing, asking this mock for the chain it needs, exactly as the
	// running server's does. Held in a local of its own as well, so the server
	// can stop validating below without the teardown losing track of it.
	validator := dnssec.make_validator(validator_query, &s, dnssec.Options{})
	defer dnssec.destroy_validator(validator)
	s.validator = validator

	m := Counting_Mock {
		socket = socket,
	}
	answer := unsigned_answer()
	if !testing.expect(t, len(answer) <= len(m.reply), "the fixture does not fit the mock's buffer") {
		return
	}
	m.length = copy(m.reply[:], answer)
	mock := thread.create_and_start_with_poly_data(&m, counting_mock_serve)
	defer {
		sync.atomic_store(&m.stop, true)
		thread.join(mock)
		thread.destroy(mock)
	}

	query := bogus_client_query()

	first, outcome, served := handle_query(&s, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served, "no response was produced for the first query")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect(
		t,
		len(first) >= dns.HEADER_SIZE && first[3] & 0xf == u8(dns.Rcode.Serv_Fail),
		"the first query was not refused",
	)

	asked := sync.atomic_load(&m.seen)
	if !testing.expect(t, asked > 0, "the upstream was never asked, so nothing was validated") {
		return
	}

	// What the entry holds is the refusal and not the answer that failed: the
	// unvalidated data must not be anywhere a later hit could reach it.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], BOGUS_NAME, .A, .IN, false, false)
	stored, _, found := cache.get(answers, key, context.temp_allocator)
	if testing.expect(t, found, "the verdict was not remembered") {
		testing.expect(
			t,
			len(stored) >= dns.HEADER_SIZE && stored[3] & 0xf == u8(dns.Rcode.Serv_Fail),
			"the answer that did not validate was stored",
		)
		testing.expect(t, stored[6] == 0 && stored[7] == 0, "the stored refusal carries an answer section")
	}

	second, again, served_again := handle_query(&s, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_again, "no response was produced for the second query")
	testing.expect_value(t, again, Outcome.Failed)
	testing.expect(
		t,
		len(second) >= dns.HEADER_SIZE && second[3] & 0xf == u8(dns.Rcode.Serv_Fail),
		"the second query was not refused",
	)
	// The whole of it: the second client query cost nothing upstream.
	testing.expect_value(t, sync.atomic_load(&m.seen), asked)

	/*
	And the verdict stops answering the moment this server stops validating.

	`validating` is recomputed for every query - a validator switched off by a
	reload, a zone since routed or anchored - and the entry carries no record of
	the rules it was refused under. So the memory is ignored rather than served,
	the question goes upstream as it would on a miss, and the answer that comes
	back is the one the client gets.
	*/
	s.validator = nil
	third, plain, served_plain := handle_query(&s, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, served_plain, "no response was produced with validation off")
	testing.expect_value(t, plain, Outcome.Forwarded)
	testing.expect(
		t,
		len(third) >= dns.HEADER_SIZE && third[3] & 0xf == u8(dns.Rcode.No_Error),
		"the remembered verdict answered a query this server was not validating",
	)
	testing.expect(t, sync.atomic_load(&m.seen) > asked, "the upstream was not asked once the verdict stopped applying")

	free_all(context.temp_allocator)
}
