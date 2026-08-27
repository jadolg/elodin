package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
How large a response this server will build, and what bounds it.

`response_limit` is the one place the UDP ceiling is applied, so it is the one
place the two numbers that meet there - what the client advertised and what
`server.max_udp_response` allows - have to be resolved the right way round.
*/

// The OPT record is allocated rather than written as a slice literal: a literal
// lives in the frame that made it, and this one has to outlive this call.
@(private = "file")
query_advertising :: proc(size: u16) -> dns.Message {
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.make_opt(size, false)
	return dns.Message{additional = records}
}

// The smaller of the two wins, whichever one it is: the client's number is a
// request and the setting is a ceiling, and neither is a floor under the other.
@(test)
test_response_limit_takes_the_smaller_of_the_two :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}

	// Asked for more than the ceiling: held to the ceiling.
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.DEFAULT_MAX_UDP_RESPONSE)
	// Asked for less: given what it asked for, not the ceiling.
	testing.expect_value(t, response_limit(&s, query_advertising(512), .UDP), 512)
	// No OPT record at all is 512 by RFC 1035, and the ceiling does not raise it.
	testing.expect_value(t, response_limit(&s, dns.Message{}, .UDP), 512)

	// Raised, and the client's larger number is now the one that binds.
	cfg.server.max_udp_response = config.MAX_UDP_RESPONSE
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.MAX_UDP_RESPONSE)
	testing.expect_value(t, response_limit(&s, query_advertising(1232), .UDP), 1232)
	free_all(context.temp_allocator)
}

/*
The ceiling is UDP's alone.

The stream transports establish a connection before a query arrives, so the
address is proven and there is nothing to reflect. A ceiling leaking onto them
would cost a client a second round trip for an answer that was always going to
fit.
*/
@(test)
test_response_limit_does_not_apply_to_streams :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	streams := []Protocol{.TCP, .DoT, .DoH}
	for proto in streams {
		testing.expectf(
			t,
			response_limit(&s, query_advertising(4096), proto) == dns.MAX_MESSAGE,
			"%v is bounded by the UDP ceiling",
			proto,
		)
	}
	free_all(context.temp_allocator)
}

/*
A ceiling nobody set does not truncate every answer to nothing.

Every `Config` in a running server comes from `default_config` and is then
validated, so the field is in range there. A `Config` built literally is not, and
a zero ceiling read straight through would make `min` return zero for every UDP
answer - a resolver that responds to nothing, from a field nobody noticed was
unset. The floor keeps that invariant local to the procedure that depends on it.
*/
@(test)
test_response_limit_floors_an_unset_ceiling :: proc(t: ^testing.T) {
	cfg := config.Config{}
	s := Server {
		cfg = &cfg,
	}
	testing.expect_value(t, response_limit(&s, query_advertising(4096), .UDP), config.MIN_UDP_RESPONSE)
	testing.expect_value(t, response_limit(&s, dns.Message{}, .UDP), config.MIN_UDP_RESPONSE)
	free_all(context.temp_allocator)
}

/*
The ceiling holds on the paths that go wrong too.

`fit_response` is the only thing between an answer and the wire, so whatever it
returns is what a UDP client receives. An answer it cannot re-encode used to be
returned unchanged, which meant the one case where the size was not under this
server's control was the case where the size was not bounded either - and the
number it is bounded by is an amplification factor.
*/
@(test)
test_fit_response_never_exceeds_the_limit :: proc(t: ^testing.T) {
	query := dns.Message {
		id       = 0x1234,
		question = []dns.Question{{name = "big.example.", type = .TXT, class = .IN}},
	}
	// Bytes no decoder will accept, past the ceiling: the path where there is
	// nothing to re-encode and what is in hand is too large to send.
	junk := make([]u8, 2048, context.temp_allocator)
	for i in 0 ..< len(junk) {
		junk[i] = 0xff
	}

	out := fit_response(junk, config.DEFAULT_MAX_UDP_RESPONSE, query, context.temp_allocator)
	testing.expectf(
		t,
		len(out) <= config.DEFAULT_MAX_UDP_RESPONSE,
		"fit_response returned %d bytes against a %d-byte ceiling",
		len(out),
		config.DEFAULT_MAX_UDP_RESPONSE,
	)
	if testing.expect(t, len(out) >= dns.HEADER_SIZE, "nothing came back that a client could read") {
		testing.expect(t, out[2] & 0x02 != 0, "the client was not told to retry over TCP")
	}
	free_all(context.temp_allocator)
}

/*
Stale serving, from the resolver's side.

RFC 8767 section 5 has a resolver try the refresh first and reach for expired
data only once that attempt has failed, which is also what
`cache.serve_stale` promises in the configuration: an answer from an expired
entry *if the upstream is down*. The fixtures below stand an upstream up in the
one state a unit test can reach honestly - a group with nothing in it to ask,
which fails without a socket, a timeout or a name to resolve.
*/

@(private = "file")
STALE_NAME :: "stale.example."

// A group with no servers to ask: `upstream.resolve` walks the list, finds
// nothing, and reports it unhealthy. Failover rather than round robin, which
// divides by the number of servers there are none of.
@(private = "file")
down_upstream :: proc() -> upstream.Group {
	return upstream.Group{strategy = .Failover, attempts = 1}
}

@(private = "file")
stale_query :: proc(rd: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = STALE_NAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x4321,
		question = questions,
	}
	msg.flags.rd = rd
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
Store an answer for `STALE_NAME`, expired if `expired` says so.

The cache has no public way to age an entry, so the deadline is written
directly. The alternative - storing a one-second answer and sleeping past it -
would spend a second of real time in every run of the suite on a clock that is
not what any of this is about.
*/
@(private = "file")
cache_an_answer :: proc(answers: ^cache.Cache, expired: bool) -> bool {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = STALE_NAME,
		type  = .A,
		class = .IN,
		ttl   = 300,
		data  = dns.Rdata_A{addr = {192, 0, 2, 1}},
	}
	stored := dns.Message {
		id       = 0x1111,
		question = []dns.Question{{name = STALE_NAME, type = .A, class = .IN}},
		answer   = answer,
	}
	stored.flags.qr = true
	stored.flags.ra = true
	wire, _, enc := dns.encode_message(stored, context.temp_allocator)
	if enc != .None {
		return false
	}
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if derr != .None {
		return false
	}

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], STALE_NAME, .A, .IN, false, false)
	if !cache.put(answers, key, wire, decoded) {
		return false
	}
	if expired {
		if e, found := answers.entries[key]; found {
			e.expires = time.time_add(time.now(), -1 * time.Second)
			e.inserted = time.time_add(time.now(), -3600 * time.Second)
		}
	}
	return true
}

@(private = "file")
stale_server :: proc(cfg: ^config.Config, answers: ^cache.Cache, group: ^upstream.Group) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.cache.serve_stale = true
	return Server{cfg = cfg, answers = answers, group = group}
}

/*
An expired entry is a fallback, not an answer.

Serving it the moment it is found means every client gets data known to be out
of date while a healthy upstream sits unqueried - the refresh RFC 8767 section 5
asks for is never attempted at all. So a stale hit is held rather than served,
the query goes on down the forwarding path as a miss would, and the held bytes
come out only when the upstream has failed. What the client then receives has to
be indistinguishable from a fresh hit: this server's transaction ID, the
question in the case it was asked in, and the short TTL that brings the client
back soon.

The counters are checked because they are the only record an operator has of
which of the two happened. A stale answer that was actually served is a query
this server answered from its cache; the upstream failure behind it is not a
failed query, since the client got an answer.
*/
@(test)
test_a_stale_answer_waits_for_the_upstream_to_fail :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "the stale answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expect_value(t, served.id, u16(0x4321))
	if testing.expect(t, len(served.answer) == 1, "the stale answer carried no record") {
		testing.expect_value(t, served.answer[0].ttl, u32(cache.STALE_TTL))
	}

	stats := stats_of(&s)
	testing.expect_value(t, stats.cached, u64(1))
	testing.expect_value(t, stats.forwarded, u64(0))
	testing.expect_value(t, stats.failed, u64(0))
	testing.expect_value(t, cache.stats(answers).stale, u64(1))
	free_all(context.temp_allocator)
}

// The address the mock upstream answers with, which is not the one in the
// cache: what the client receives says which of the two produced it.
@(private = "file")
LIVE_ADDR :: [4]u8{192, 0, 2, 99}

@(private = "file")
Stale_Exchange :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	got:    bool,
}

/*
Serve exactly one query.

One query per thread, joined by the caller before it reads `got`: there is no
shared state to guard, and a query that never arrives leaves `got` false rather
than hanging the suite - the socket carries a receive timeout.
*/
@(private = "file")
serve_one_stale :: proc(x: ^Stale_Exchange) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.got = true

	out: [4096]u8
	copy(out[:], x.reply)
	// Echo the ID it was asked with. The resolver draws a fresh one for every
	// query it forwards, so nothing here can know it in advance.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
live_reply :: proc() -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = STALE_NAME,
		type  = .A,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_A{addr = LIVE_ADDR},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = STALE_NAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0,
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
An upstream that is up is asked, and its answer is the one the client gets.

This is the half of RFC 8767 section 5 that a counter cannot show: not that a
stale answer is available, but that it is not reached for while the refresh can
still succeed. Serving the expired copy on sight means a client gets data known
to be out of date - for as long as the entry is kept, now a day rather than the
thirty seconds the sweep used to allow - while a healthy upstream sits unqueried
and the name it would have returned goes on changing.

Driven against a real socket, because what is being asserted is that a query
left this process at all. The two answers carry different addresses, so the one
that comes back says which path produced it, and the refreshed entry is checked
afterwards: the stale copy has to be replaced rather than left to be served
again on the next failure.
*/
@(test)
test_a_live_upstream_beats_a_stale_entry :: proc(t: ^testing.T) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return
	}
	defer net.close(socket)
	// A query that never comes must not stall the run; the upstream timeout below
	// is longer, so a real exchange is never cut short by this.
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return
	}

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	s := stale_server(&cfg, answers, nil)
	cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 5 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	s.group = group

	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	x := Stale_Exchange {
		socket = socket,
		reply  = live_reply(),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked, though it was up")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)

	served, err := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	if testing.expect(t, len(served.answer) == 1, "the answer carried no record") {
		a, is_a := served.answer[0].data.(dns.Rdata_A)
		testing.expect(t, is_a, "the answer did not carry an A record")
		testing.expectf(t, a.addr == LIVE_ADDR, "the client was served %v, which is the expired entry", a.addr)
	}

	counters := stats_of(&s)
	testing.expect_value(t, counters.forwarded, u64(1))
	testing.expect_value(t, counters.cached, u64(0))
	testing.expect_value(t, cache.stats(answers).stale, u64(0))

	// And the entry behind it was refreshed rather than left expired, so the next
	// outage falls back on the answer that was just fetched.
	kb: [cache.KEY_MAX]u8
	key := cache.make_key(kb[:], STALE_NAME, .A, .IN, false, false)
	_, refreshed, found := cache.get(answers, key, context.temp_allocator)
	testing.expect(t, found, "the refreshed answer was not cached")
	testing.expect(t, !refreshed.stale, "the entry is still the expired one")
	free_all(context.temp_allocator)
}

/*
A fresh entry is still answered without asking anybody.

The upstream in this fixture cannot answer, so a lookup that reached it would
come back SERVFAIL. That is the whole check: holding a stale hit back until the
upstream has been tried must not turn the ordinary hit - the one the cache
exists for, and the great majority of them - into a query that goes out on the
network first.
*/
@(test)
test_a_fresh_hit_is_answered_without_the_upstream :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	if !testing.expect(t, cache_an_answer(answers, expired = false), "the answer was not cached") {
		return
	}

	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "the cached answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	if testing.expect(t, len(served.answer) == 1, "the cached answer carried no record") {
		// The stored TTL, counted down but not replaced: nothing about this
		// answer is stale, so it does not go out with the stale TTL.
		testing.expect_value(t, served.answer[0].ttl, u32(300))
	}
	testing.expect_value(t, cache.stats(answers).stale, u64(0))
	free_all(context.temp_allocator)
}

/*
With `serve_stale` off, an expired entry is not a fallback either.

The setting is the operator's answer to a question with two defensible sides -
whether a client is better served with data known to be out of date or with a
failure - and the fallback path must not decide it for them. `cache.get` refuses
the expired entry outright here, so `resolve_query` never has anything in hand
when the upstream fails, and the client is told the truth.
*/
@(test)
test_an_expired_entry_is_no_fallback_without_serve_stale :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)
	cfg: config.Config
	group := down_upstream()
	s := stale_server(&cfg, answers, &group)
	s.cfg.cache.serve_stale = false
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	out, outcome, ok := handle_query(&s, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Failed)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expect_value(t, dns.rcode_of(served), dns.Rcode.Serv_Fail)
	free_all(context.temp_allocator)
}

/*
RD=0 is answered from a stale entry rather than refused.

RD=0 asks for whatever this server already knows and forbids it from recursing
on the client's behalf - RFC 1035 section 4.1.1 - which is why `resolve_query`
refuses one it would have to forward. An expired entry is something this server
already knows, so the refusal does not apply to it: there is an answer in hand
and no recursion needed to produce it. Refusing here would be the fallback
withheld from precisely the clients - monitoring probes, other resolvers - that
asked for local knowledge and nothing else.

`s.group` is left nil, so a query that reached the forwarding step would crash
rather than quietly refuse.
*/
@(test)
test_rd_zero_is_answered_from_a_stale_entry :: proc(t: ^testing.T) {
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer cache.destroy(answers)
	cfg: config.Config
	s := stale_server(&cfg, answers, nil)
	if !testing.expect(t, cache_an_answer(answers, expired = true), "the answer was not cached") {
		return
	}

	out, outcome, ok := handle_query(&s, stale_query(false), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "an RD=0 query went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	if testing.expect(t, len(served.answer) == 1, "the stale answer carried no record") {
		testing.expect_value(t, served.answer[0].ttl, u32(cache.STALE_TTL))
	}
	free_all(context.temp_allocator)
}

/*
The snapshot carries every counter, and this is what makes that true.

`stats_of` reads the live counters one at a time, so a counter added to `Stats`
and not added here reports zero forever - which is worse than not reporting it,
because the stats line still prints the name and an operator reads the zero as
the answer. `refused` was exactly that: incremented on every refused datagram
and connection, and absent from the snapshot the report is built from.

Whole-struct equality rather than a field-by-field walk, because the failure
being guarded against is a field nobody thought to check.
*/
@(test)
test_stats_of_carries_every_counter :: proc(t: ^testing.T) {
	// Distinct values, so a snapshot that reads the wrong field is a failure
	// rather than a coincidence.
	want := Stats {
		queries      = 1,
		blocked      = 2,
		cached       = 3,
		forwarded    = 4,
		failed       = 5,
		rewritten    = 6,
		dropped      = 7,
		refused      = 8,
		conn_refused = 9,
		conn_failed  = 10,
		secure       = 11,
		bogus        = 12,
	}
	s := Server {
		stats = want,
	}
	got := stats_of(&s)
	testing.expectf(t, got == want, "stats_of did not carry every counter: got %v, want %v", got, want)
}

/*
Which names a rewrite rule claims, and in particular that the claim does not
depend on how the client happened to spell them.

DNS names compare without regard to case (RFC 1035 section 2.3.3, restated for
every label by RFC 4343), and nothing folds the question name on its way in:
`resolve_query` reads it straight off the wire so that the response can echo
back the exact bytes the client sent, which is what a resolver doing DNS-0x20
(RFC 5452 section 9.2) is checking. The whole of the case-insensitivity has
therefore to live in the matcher. A wildcard that only recognised lowercase
would leave "answer: block" bypassable by shifting a single letter, and would
send a split-horizon name upstream instead of answering it locally.
*/
@(test)
test_wildcard_rewrite_matches_regardless_of_case :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "lan.", wildcard = true, ttl = 60}}

	names := [?]string{"host.lan.", "host.LAN.", "HOST.Lan.", "deep.HOST.lAn."}
	for name in names {
		_, found := find_rewrite(rules, name)
		testing.expectf(t, found, "%s should match the wildcard rule *.lan.", name)
	}
}

/*
The two edges a wildcard has to keep, which the case-insensitive comparison
must not quietly widen.

"*.lan." stands for at least one label below "lan.", so the zone apex is
outside the rule however it is spelled; and the suffix has to begin on a label
break, or "notlan." would be swallowed by a rule written for "lan.".
*/
@(test)
test_wildcard_rewrite_excludes_the_apex_and_bare_suffixes :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "lan.", wildcard = true, ttl = 60}}

	outside := [?]string{"lan.", "LAN.", "notlan.", "NOTLAN.", "an.", "example.com."}
	for name in outside {
		_, found := find_rewrite(rules, name)
		testing.expectf(t, !found, "%s must not match the wildcard rule *.lan.", name)
	}
}

/*
An exact rewrite is unaffected by any of this and has always folded case; it is
pinned here beside the wildcard so that a change to one matcher that forgets the
other shows up.
*/
@(test)
test_exact_rewrite_matches_regardless_of_case :: proc(t: ^testing.T) {
	rules := []config.Rewrite{{domain = "host.lan.", ttl = 60}}

	_, exact := find_rewrite(rules, "HOST.LAN.")
	testing.expect(t, exact, "an exact rewrite must match a differently-cased name")

	_, deeper := find_rewrite(rules, "sub.HOST.LAN.")
	testing.expect(t, !deeper, "an exact rewrite must not claim names below it")
}

/*
The same property end to end, which is what says the bypass is actually closed
rather than only that the helper agrees with itself.

The query carries RD=0 so that a rewrite which failed to match cannot reach the
forwarding path - there is no upstream configured - and comes back as Refused
instead, naming the failure exactly. A wildcard rule with `answer: block` is
the same code path with a different verdict, so a mixed-case query answered
from configuration here is a mixed-case query blocked in that deployment.
*/
@(test)
test_mixed_case_query_is_answered_by_a_wildcard_rewrite :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false

	cfg.rewrites = make([]config.Rewrite, 1, context.temp_allocator)
	cfg.rewrites[0] = config.Rewrite {
		domain   = "lan.",
		wildcard = true,
		answers  = []config.Rewrite_Answer{{kind = .A, v4 = {192, 0, 2, 1}}},
		ttl      = 300,
	}

	s := Server {
		cfg = &cfg,
	}

	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = "HOST.LaN.",
		type  = .A,
		class = .IN,
	}
	query := dns.Message {
		id       = 0x4d21,
		question = questions,
	}
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	out, outcome, ok := handle_query(&s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "a mixed-case query under a wildcard rewrite went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)

	resp, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !testing.expect(t, len(resp.answer) == 1, "the rewrite produced no answer record") {
		return
	}
	a, is_a := resp.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the rewritten answer is not an A record")
	testing.expect_value(t, a.addr, [4]u8{192, 0, 2, 1})

	free_all(context.temp_allocator)
}
