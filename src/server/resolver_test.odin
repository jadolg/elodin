package server

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:loop"
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
returns is what a UDP client receives. Returning an answer it cannot re-encode
unchanged would make the one case where the size is not under this server's
control the case where the size is not bounded either - and the number it is
bounded by is an amplification factor.
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

	out := fit_response(junk, config.DEFAULT_MAX_UDP_RESPONSE, query, nil, context.temp_allocator)
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

@(private)
STALE_NAME :: "stale.example."

// A group with no servers to ask: `upstream.resolve` walks the list, finds
// nothing, and reports it unhealthy. Failover rather than round robin, which
// divides by the number of servers there are none of.
@(private)
down_upstream :: proc() -> upstream.Group {
	return upstream.Group{strategy = .Failover, attempts = 1}
}

@(private)
stale_query :: proc(rd: bool) -> []u8 {
	return test_query(STALE_NAME, id = 0x4321, rd = rd)
}

// The cache's entry for `STALE_NAME`, or nil.
@(private)
stale_entry :: proc(answers: ^cache.Cache) -> ^cache.Entry {
	kb: [cache.KEY_MAX]u8
	return answers.shards[0].entries[cache.make_key(kb[:], STALE_NAME, .A, .IN, false)]
}

// What a lookup of `STALE_NAME` finds in `answers`.
@(private)
stale_get :: proc(answers: ^cache.Cache) -> (wire: []u8, hit: cache.Hit, found: bool) {
	kb: [cache.KEY_MAX]u8
	return cache.get(answers, cache.make_key(kb[:], STALE_NAME, .A, .IN, false), context.temp_allocator)
}

/*
Store an answer for `STALE_NAME`, expired if `expired` says so.

The cache has no public way to age an entry, so the deadline is written
directly. The alternative - storing a one-second answer and sleeping past it -
would spend a second of real time in every run of the suite on a clock that is
not what any of this is about.
*/
@(private)
cache_an_answer :: proc(answers: ^cache.Cache, expired: bool) -> bool {
	wire := test_reply(STALE_NAME, .A, a_record(STALE_NAME, {192, 0, 2, 1}, 300))
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if derr != .None {
		return false
	}
	key_buf: [cache.KEY_MAX]u8
	if !cache.put(answers, cache.make_key(key_buf[:], STALE_NAME, .A, .IN, false), wire, decoded) {
		return false
	}
	if expired {
		e := stale_entry(answers)
		if e == nil {
			return false
		}
		e.expires = loop.moment_add(loop.moment_now(), -1 * time.Second)
		e.inserted = loop.moment_add(loop.moment_now(), -3600 * time.Second)
	}
	return true
}

@(private)
stale_server :: proc(cfg: ^config.Config, answers: ^cache.Cache, group: ^upstream.Group) -> Server {
	cfg^ = test_config()
	cfg.cache.enabled = true
	cfg.cache.serve_stale = true
	return Server{cfg = cfg, answers = answers, group = group}
}

/*
A stale-serving server forwarding to one mock upstream on loopback, with
`STALE_NAME` already in its cache: expired, unless `expired` says otherwise.

The upstream gets `attempts` tries of `timeout` each, and `stale_timeout`, where
given, replaces the configured response timer. `answers` is the cache to serve
from, a stale-serving one when nil; the fixture destroys it either way. With
`looped` the server has a test loop to detach refreshes onto, which
`stale_fixture_join` stops in the middle of a case and `stale_fixture_stop`
stops first if it is still running: the loop waits out a refresh that writes to
the cache and the group on its way out.
*/
@(private)
Stale_Fixture :: struct {
	socket:  net.UDP_Socket,
	answers: ^cache.Cache,
	cfg:     config.Config,
	group:   ^upstream.Group,
	srv:     Server,
	tl:      Test_Loop,
}

@(private)
stale_fixture_start :: proc(
	t: ^testing.T,
	f: ^Stale_Fixture,
	timeout: time.Duration,
	stale_timeout: Maybe(time.Duration) = nil,
	looped := false,
	attempts := 1,
	expired := true,
	answers: ^cache.Cache = nil,
	loc := #caller_location,
) -> bool {
	f.answers = answers
	if f.answers == nil {
		f.answers = cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	}
	socket, spec, ok := bind_mock(t, loc = loc)
	if !ok {
		cache.destroy(f.answers)
		return false
	}
	f.socket = socket
	f.srv = stale_server(&f.cfg, f.answers, nil)
	f.cfg.upstream.attempts = attempts
	f.cfg.upstream.timeout = timeout
	if wait, has := stale_timeout.?; has {
		f.cfg.cache.stale_timeout = wait
	}
	f.cfg.upstream.servers = loopback_upstream(spec.port)
	group, gerr := upstream.make_group(f.cfg.upstream)
	f.group = group
	f.srv.group = group
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		stale_fixture_stop(f)
		return false
	}
	if looped {
		if !testing.expect(t, start_test_loop(&f.tl), "no loop", loc = loc) {
			stale_fixture_stop(f)
			return false
		}
		f.srv.loops = f.tl.loops[:]
	}
	if !testing.expect(t, cache_an_answer(f.answers, expired), "the answer was not cached", loc = loc) {
		stale_fixture_stop(f)
		return false
	}
	return true
}

// Stops the loop, so whatever was detached onto it has finished.
@(private)
stale_fixture_join :: proc(f: ^Stale_Fixture) {
	stop_test_loop(&f.tl)
	f.srv.loops = nil
}

@(private)
stale_fixture_stop :: proc(f: ^Stale_Fixture) {
	stale_fixture_join(f)
	upstream.destroy_group(f.group)
	cache.destroy(f.answers)
	net.close(f.socket)
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
@(private)
LIVE_ADDR :: [4]u8{192, 0, 2, 99}

@(private)
Stale_Exchange :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	got:    bool,
	// How long to sit on the query before answering it. Zero answers at once,
	// which is what every case but the response-timer ones wants; the others
	// need an upstream that is slow rather than absent, so that the client
	// gives up on it while it is still going to answer.
	delay:  time.Duration,
	// Held until posted, rather than for a duration, where the case needs the
	// client answered before the upstream is; bounded by `MOCK_RECV_TIMEOUT`.
	hold:   ^sync.Sema,
}

/*
Serve exactly one query: the one asking `reply`'s question, skipping any other
datagram as `Canned_Mock` does (a straggler from another case on a reused
port), with the delay or hold `Canned_Mock` has no room for.

One query per thread, joined by the caller before it reads `got`: there is no
shared state to guard, and a query that never arrives leaves `got` false rather
than hanging the suite - the socket carries a receive timeout.
*/
@(private)
serve_one_stale :: proc(x: ^Stale_Exchange) {
	buf: [4096]u8
	if len(x.reply) > len(buf) {
		return
	}
	_, remote, asked := recv_question(x.socket, x.reply, buf[:])
	if !asked {
		return
	}
	x.got = true
	if x.delay > 0 {
		time.sleep(x.delay)
	}
	if x.hold != nil {
		_ = sync.sema_wait_with_timeout(x.hold, MOCK_RECV_TIMEOUT)
	}

	out: [4096]u8
	copy(out[:], x.reply)
	// Echo the ID it was asked with. The resolver draws a fresh one for every
	// query it forwards, so nothing here can know it in advance.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private)
live_reply :: proc() -> []u8 {
	return test_reply(STALE_NAME, .A, a_record(STALE_NAME, LIVE_ADDR))
}

/*
A stale copy whose RRSIG lapses while the upstream is waited on is not served
(issue #165, RFC 4034 section 3.1.5).

`cache.get` hands the copy over inside its signature, and the upstream then
takes its timeout to fail. The signature lapses in between, so what the client
gets is SERVFAIL rather than an answer it cannot validate. The upstream is a
bound socket nothing reads, so the wait is the timeout and nothing else.
*/
@(test)
test_a_stale_copy_is_not_served_past_its_rrsig_after_the_wait :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 200 * time.Millisecond) {
		return
	}
	defer stale_fixture_stop(&f)
	// Live when `get` reads it, lapsed long before the upstream times out.
	stale_entry(f.answers).signed_until = loop.moment_add(loop.moment_now(), 50 * time.Millisecond)

	out, _, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if testing.expect(t, ok, "nothing came back at all") {
		served, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		testing.expect_value(t, dns.rcode_of(served), dns.Rcode.Serv_Fail)
	}
	free_all(context.temp_allocator)
}

/*
And where the timer fires on a copy whose RRSIG has lapsed in the meantime, the
client is not failed there: that copy does not satisfy the request (RFC 8767
section 5), so it waits the refresh out and is given what the upstream sends.

The signature lapses 50 ms in, the timer fires at 100 ms and the upstream answers
at 400 ms. A runner slow enough to hand the copy over after the 50 ms has no
stale copy at all and waits for the upstream on the ordinary path, which ends
the same way; nothing here can pass a SERVFAIL.
*/
@(test)
test_a_lapsed_stale_copy_waits_for_the_refresh :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second, stale_timeout = 100 * time.Millisecond, looped = true) {
		return
	}
	defer stale_fixture_stop(&f)
	stale_entry(f.answers).signed_until = loop.moment_add(loop.moment_now(), 50 * time.Millisecond)

	x := Stale_Exchange {
		socket = f.socket,
		reply  = live_reply(),
		delay  = 400 * time.Millisecond,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	defer {
		thread.join(mock)
		thread.destroy(mock)
	}

	out, _, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if testing.expect(t, ok, "nothing came back at all") {
		served, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		testing.expect_value(t, dns.rcode_of(served), dns.Rcode.No_Error)
		if testing.expect(t, len(served.answer) == 1, "the answer carried no record") {
			a, is_a := served.answer[0].data.(dns.Rdata_A)
			testing.expectf(t, is_a && a.addr == LIVE_ADDR, "served %v rather than the refresh's answer", served.answer[0].data)
		}
	}
	free_all(context.temp_allocator)
}

/*
An upstream that is up is asked, and its answer is the one the client gets.

This is the half of RFC 8767 section 5 that a counter cannot show: not that a
stale answer is available, but that it is not reached for while the refresh can
still succeed. Serving the expired copy on sight means a client gets data known
to be out of date - for as long as the entry is kept, up to a day - while a
healthy upstream sits unqueried
and the name it would have returned goes on changing.

Driven against a real socket, because what is being asserted is that a query
left this process at all. The two answers carry different addresses, so the one
that comes back says which path produced it, and the refreshed entry is checked
afterwards: the stale copy has to be replaced rather than left to be served
again on the next failure.
*/
@(test)
test_a_live_upstream_beats_a_stale_entry :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second) {
		return
	}
	defer stale_fixture_stop(&f)

	x := Stale_Exchange {
		socket = f.socket,
		reply  = live_reply(),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
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

	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.forwarded, u64(1))
	testing.expect_value(t, counters.cached, u64(0))
	testing.expect_value(t, cache.stats(f.answers).stale, u64(0))

	// And the entry behind it was refreshed rather than left expired, so the next
	// outage falls back on the answer that was just fetched.
	_, refreshed, found := stale_get(f.answers)
	testing.expect(t, found, "the refreshed answer was not cached")
	testing.expect(t, !refreshed.stale, "the entry is still the expired one")
	free_all(context.temp_allocator)
}

/*
A referral is the outage `serve_stale` covers, not an answer (issue #410).

The upstream is up and answers, but only with the NS of a zone and no SOA:
`resolve_query` reads that as no answer before the failure branch, so the
expired entry is what the client gets - not a SERVFAIL, and not the empty
NOERROR it would read as NODATA. Without that check the referral is forwarded
as the answer, and below the failure branch it would never reach the fallback.
*/
@(test)
test_a_referral_falls_back_on_a_stale_entry :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second) {
		return
	}
	defer stale_fixture_stop(&f)

	referral := dns.Message {
		question  = []dns.Question{{name = STALE_NAME, type = .A, class = .IN}},
		authority = []dns.Record{{name = STALE_NAME, type = .NS, class = .IN, ttl = 3600, data = dns.Rdata_Name{"ns1.example."}}},
	}
	referral.flags.qr = true
	referral.flags.rd = true
	wire, _, enc := dns.encode_message(referral, context.temp_allocator)
	if !testing.expect_value(t, enc, dns.Encode_Error.None) {
		return
	}
	x := Stale_Exchange {
		socket = f.socket,
		reply  = wire,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)
	served, err := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(served.flags.rcode), dns.Rcode.No_Error)
	testing.expectf(t, len(served.answer) == 1, "the client got %d answer records, not the expired entry", len(served.answer))
	testing.expect_value(t, stats_of(&f.srv).failed, u64(0))
	testing.expect_value(t, cache.stats(f.answers).stale, u64(1))
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
The client response timer, which is what `cache.serve_stale` is worth.

Issue #164: a fallback reached only once `upstream.resolve` had given up would
wait out `attempts` x servers x `timeout` - ten seconds with the defaults against
one blackholed upstream, twenty against two - while a glibc stub gives up at five
and systemd-resolved sooner. The expired answer would arrive after the client it
was kept for had already failed, so the setting would do nothing in the one
outage an operator turns it on for.

The upstream here is a socket that is bound and never read. That is the shape
the issue is about and the one a closed port cannot stand in for: a datagram to
a port nobody is listening on draws an ICMP refusal, and the exchange fails at
once, which is the *fast* failure `serve_stale` already covered. Here nothing
comes back and nothing is refused, so only the timeout ends the attempt.

The budget below is two seconds and the timer is 150 ms, so the assertion has
850 ms of slack in it - enough that a loaded runner cannot fail it without also
being a second behind, and tight enough that waiting out the upstream cannot
pass. Set `cache.stale_timeout` to 0 - the escape hatch - and this case takes the
whole two seconds and fails.
*/
@(test)
test_a_stale_answer_does_not_wait_out_the_upstream_budget :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 1 * time.Second, stale_timeout = 150 * time.Millisecond, looped = true, attempts = 2) {
		return
	}
	defer stale_fixture_stop(&f)

	begun := time.now()
	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	waited := time.since(begun)

	if !testing.expect(t, ok, "the stale answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)
	testing.expectf(
		t,
		waited < 1 * time.Second,
		"the client waited %v for an expired entry it could have had at once; the upstream budget is %v",
		waited,
		time.Duration(f.cfg.upstream.attempts) * f.cfg.upstream.timeout,
	)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expect_value(t, served.id, u16(0x4321))
	if testing.expect(t, len(served.answer) == 1, "the stale answer carried no record") {
		testing.expect_value(t, served.answer[0].ttl, u32(cache.STALE_TTL))
	}

	// And the failure the refresh is still walking into is not the client's:
	// it got an answer, so nothing is counted failed for it.
	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.cached, u64(1))
	testing.expect_value(t, counters.failed, u64(0))
	testing.expect_value(t, cache.stats(f.answers).stale, u64(1))
	free_all(context.temp_allocator)
}

/*
One refresh per name, however many clients ask for it.

The stampede the response timer would otherwise create: every client that
arrives while an expired entry is being refreshed would start a refresh of its
own, so a popular name whose TTL has just run out puts one upstream query on the
wire per client - against an upstream that is by assumption already in trouble.

A second query is answered from the entry straight away rather than queued
behind the refresh already running for it. That is deliberate and it is the
lazier half of RFC 8767 section 5: the bytes that come back from a refresh carry
the transaction ID and the question spelling of the one query it was started
from, so a second client waiting on them would be waiting to be handed somebody
else's answer with both patched back out of it.

Counted at the upstream rather than at the resolver, because what is being
asserted is that a query left this process once. The socket is never read while
the case runs, so the datagrams that reached it are still in the receive buffer
afterwards and can simply be counted. One attempt per refresh, so the count is
the number of refreshes rather than a multiple of it.
*/
@(test)
test_one_refresh_covers_every_client_waiting_on_a_name :: proc(t: ^testing.T) {
	// One attempt, so every datagram counted below is a refresh of its own, and
	// long enough that the first refresh is certainly still running when the
	// second query arrives.
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 2 * time.Second, stale_timeout = 100 * time.Millisecond, looped = true) {
		return
	}
	defer stale_fixture_stop(&f)

	for i in 0 ..< 4 {
		begun := time.now()
		_, outcome, ok := handle_query(
			&f.srv,
			stale_query(true),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		waited := time.since(begun)
		testing.expectf(t, ok, "query %d went unanswered", i)
		testing.expect_value(t, outcome, Outcome.Cached)
		testing.expectf(t, waited < 1 * time.Second, "query %d waited %v", i, waited)
	}

	/*
	Joined before the count is taken, and the count is exact because of it.

	The refresh sends from a fiber on the test loop, and nothing about a client
	having been answered says that fiber has reached its send: the four calls above
	return when the timer fires, which is 100 ms into a two-second upstream
	attempt the job is still sitting in. Counting then would be counting
	against a scheduler - the assertion would be waiting for a datagram rather
	than reading one, and a runner slow enough to lose that race would report a
	missing refresh as a failure of the single-flight this case is about.

	`stop_test_loop` waits out the loop, so the refresh has returned and its one
	attempt is on the socket or was never going to be. That is a fact about this
	process rather than a delay long enough to hope.
	*/
	stale_fixture_join(&f)

	testing.expect_value(t, drain_datagrams(f.socket), 1)
	free_all(context.temp_allocator)
}

/*
And the refresh the client stopped waiting for still renews the entry.

The other half of RFC 8767 section 5, and the one a counter cannot show: the
answer that arrives after the timer has fired is not thrown away, it is stored,
so the next client is served a fresh entry rather than the same expired bytes
over again. Without it a slow upstream - one that answers, but later than the
timer - would leave a name stale for the whole of `MAX_STALE`, since every
client would be answered from the entry and every refresh abandoned.

The upstream here answers 400 ms after it is asked, against a 100 ms timer, so
the client is certainly served from the entry and the refresh certainly
succeeds. The two addresses differ, which is what says which of them the cache
ended up holding.
*/
@(test)
test_a_refresh_outlives_the_client_that_started_it :: proc(t: ^testing.T) {
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second, stale_timeout = 100 * time.Millisecond, looped = true) {
		return
	}
	defer stale_fixture_stop(&f)

	x := Stale_Exchange {
		socket = f.socket,
		reply  = live_reply(),
		delay  = 400 * time.Millisecond,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)

	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "the stale answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)
	served, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if testing.expect(t, len(served.answer) == 1, "the stale answer carried no record") {
		a, is_a := served.answer[0].data.(dns.Rdata_A)
		testing.expect(t, is_a, "the stale answer did not carry an A record")
		testing.expectf(t, a.addr != LIVE_ADDR, "the client waited for the upstream after all")
	}

	thread.join(mock)
	thread.destroy(mock)
	testing.expect(t, x.got, "the refresh never reached the upstream")

	// The refresh is joined rather than slept on: the store happens on its way
	// out, so the loop going quiet is what says the entry is final.
	stale_fixture_join(&f)

	wire, hit, found := stale_get(f.answers)
	if !testing.expect(t, found, "the entry is gone") {
		return
	}
	testing.expect(t, !hit.stale, "the entry is still the expired one; the refresh was dropped")
	stored, cerr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, cerr, dns.Decode_Error.None)
	if testing.expect(t, len(stored.answer) == 1, "the stored answer carried no record") {
		a, is_a := stored.answer[0].data.(dns.Rdata_A)
		testing.expect(t, is_a, "the stored answer did not carry an A record")
		testing.expectf(t, a.addr == LIVE_ADDR, "the cache still holds %v", a.addr)
	}
	free_all(context.temp_allocator)
}

/*
An upstream that answers inside the timer is still the one the client hears.

The timer must not turn every expired entry into a stale answer. RFC 8767
section 5 has the refresh answer the client whenever it can, and it usually can:
an upstream that is up replies in milliseconds against a timer measured in
hundreds of them, so the ordinary refresh of an expired name is a client served
fresh data and a cache that renewed itself, with nothing stale involved.

`test_a_live_upstream_beats_a_stale_entry` asserts the same thing on the path
with no event loop, where the refresh cannot be detached and the client waits
for the upstream itself. This is the detached one.
*/
@(test)
test_a_refresh_that_beats_the_timer_answers_the_client :: proc(t: ^testing.T) {
	// A timer well past what a loopback exchange takes, so a case that goes
	// wrong says the refresh was not reached rather than that the machine was busy.
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 5 * time.Second, stale_timeout = 5 * time.Second, looped = true) {
		return
	}
	defer stale_fixture_stop(&f)

	x := Stale_Exchange {
		socket = f.socket,
		reply  = live_reply(),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_stale)
	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.got, "the upstream was never asked, though it was up")
	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)

	served, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	// The client's own transaction ID, off a response the refresh built from a
	// copy of the client's own query.
	testing.expect_value(t, served.id, u16(0x4321))
	if testing.expect(t, len(served.answer) == 1, "the answer carried no record") {
		a, is_a := served.answer[0].data.(dns.Rdata_A)
		testing.expect(t, is_a, "the answer did not carry an A record")
		testing.expectf(t, a.addr == LIVE_ADDR, "the client was served %v, which is the expired entry", a.addr)
	}
	testing.expect_value(t, cache.stats(f.answers).stale, u64(0))
	free_all(context.temp_allocator)
}

/*
And `cache.stale_timeout: 0` really is the escape hatch it is documented as.

The setting promises an operator that zero restores what every release before
the timer did: the client waits the whole upstream budget out and is served the
expired entry only once that has failed. Everything else here asserts the timer
firing, so without this the promise was held up by the loader parsing the figure
and by nothing at all downstream of it - which is the half an operator actually
relies on when they decide they would rather wait than be handed data known to
be out of date.

Asserted as the wait rather than as an absence, because the wait is the whole of
what the setting buys. The upstream is the same blackholed socket the case above
uses and the budget is one 400 ms attempt, so a client on the timer path would
have been answered in a fraction of it; this one has to still be waiting when
the attempt times out. The datagram count says the upstream was asked at all -
it cannot tell the two paths apart, since either way exactly one query goes out,
which is why the clock is what carries this.

An event loop is built and handed over, which is the point of the case: with
no loop there is nothing to detach onto and the fall-through happens for a
second reason, so a `Server` without one would pass this while proving nothing
about the setting. Here the loop is there, unused, and the zero is the only
thing keeping the refresh on this thread.
*/
@(test)
test_a_zero_timer_waits_the_upstream_out :: proc(t: ^testing.T) {
	// The escape hatch, and the only thing under test.
	f: Stale_Fixture
	if !stale_fixture_start(t, &f, 400 * time.Millisecond, stale_timeout = 0, looped = true) {
		return
	}
	defer stale_fixture_stop(&f)

	begun := time.now()
	out, outcome, ok := handle_query(&f.srv, stale_query(true), .UDP, "127.0.0.1:5555", context.temp_allocator)
	waited := time.since(begun)

	if !testing.expect(t, ok, "the stale answer went unserved") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Cached)
	/*
	The attempt cannot come back before its own timeout: there is nothing at the
	other end to answer it and nothing to refuse it, so `SO_RCVTIMEO` is what
	ends it. A margin of a tenth for the clock, which still leaves this an order
	of magnitude away from what the timer path would have measured.
	*/
	testing.expectf(
		t,
		waited >= 360 * time.Millisecond,
		"the client waited %v, which is not the %v upstream budget this setting asks it to wait",
		waited,
		time.Duration(f.cfg.upstream.attempts) * f.cfg.upstream.timeout,
	)

	served, serr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, serr, dns.Decode_Error.None)
	testing.expect_value(t, served.id, u16(0x4321))
	if testing.expect(t, len(served.answer) == 1, "the stale answer carried no record") {
		testing.expect_value(t, served.answer[0].ttl, u32(cache.STALE_TTL))
	}
	counters := stats_of(&f.srv)
	testing.expect_value(t, counters.cached, u64(1))
	testing.expect_value(t, counters.failed, u64(0))
	testing.expect_value(t, cache.stats(f.answers).stale, u64(1))

	// Nothing was ever submitted, so this stops an idle loop; the count behind
	// it is the one attempt this thread made for itself.
	stale_fixture_join(&f)
	testing.expect_value(t, drain_datagrams(f.socket), 1)
	free_all(context.temp_allocator)
}

/*
How many datagrams are sitting in a socket nobody read.

Exact rather than raced, and it is the caller that makes it so: every thread
that could still send has been joined before this is called, so the timeout
below only has to separate "the buffer is empty" from "the kernel has not
finished handing over what it already has". It is not a window for a send to
arrive in - a caller that needed one would be asserting about a scheduler.

`SO_RCVTIMEO` reads zero as no timeout at all, which on an empty socket is the
one value that hangs - the same trap `mock_untouched` documents.
*/
@(private = "file")
drain_datagrams :: proc(socket: net.UDP_Socket) -> (count: int) {
	_ = net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond)
	buf: [4096]u8
	for {
		n, _, err := net.recv_udp(socket, buf[:])
		if err != nil || n == 0 {
			return
		}
		count += 1
	}
}

/*
The snapshot carries every counter, and this is what makes that true.

`stats_of` reads the live counters one at a time, so a counter added to `Stats`
and not added here reports zero forever - which is worse than not reporting it,
because the stats line still prints the name and an operator reads the zero as
the answer. `refused` is the example: incremented on every refused datagram and
connection, it would be absent from the snapshot the report is built from if
`stats_of` left it out.

Whole-struct equality rather than a field-by-field walk, because the failure
being guarded against is a field nobody thought to check.
*/
@(test)
test_stats_of_carries_every_counter :: proc(t: ^testing.T) {
	want := DISTINCT_STATS
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
		_, found := find_rewrite_index(rules, name)
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
		_, found := find_rewrite_index(rules, name)
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

	_, exact := find_rewrite_index(rules, "HOST.LAN.")
	testing.expect(t, exact, "an exact rewrite must match a differently-cased name")

	_, deeper := find_rewrite_index(rules, "sub.HOST.LAN.")
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
	cfg := test_config()
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

	out, outcome, ok := handle_query(&s, test_query("HOST.LaN.", id = 0x4d21, rd = false), .UDP, "127.0.0.1:5555", context.temp_allocator)
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
