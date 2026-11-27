package server

import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:filter"
import "elodin:loop"
import "elodin:testkit"
import "elodin:upstream"

/*
The fixtures the package's tests share: a mock upstream on a loopback socket,
the quiet configuration that forwards to it, the server built over both, and the
messages that pass between them. A test builds what it is about by hand and
takes the rest from here, so what it sets is what it is about.
*/

/*
How long a mock upstream waits for the query it was started to answer.

Every mock upstream in this package has the same shape: the test binds a socket,
points the resolver's only upstream at it, starts the mock on a thread and then
calls `handle_query` on the test thread. The mock's wait therefore begins when
its thread is scheduled and covers everything that happens before the test
thread reaches the send - and nothing bounds that gap. The resolver's own
`upstream.timeout` does not: it only starts running once the query is on the
wire.

So this is a bound on a hang and nothing else, the same job `Send_Timeout`
does for the sender in `test_a_refusal_outlives_a_body_that_is_still_arriving`.
A value tight enough to double as a deadline on the exchange asserts a property
of the machine instead of one of the resolver: on a loaded runner the scheduler
alone can spend it, and the case then fails with `the upstream was never asked`,
a statement about the scheduler dressed up as one about forwarding.

Well past every `upstream.timeout` the harnesses here configure, so the resolver
is what gives up first: a query that genuinely never comes fails the exchange on
the test thread, and the mock is only what stops the join behind it from waiting
forever.

A mock that is there to report that *nothing* arrived wants the opposite of this
and does not use it: `mock_untouched` below reads the socket after the call has
returned rather than racing it, which is both exact and quick.
*/
MOCK_RECV_TIMEOUT :: 10 * time.Second

// The client address the cases here ask from, where who asked is no part of
// what they test.
@(private)
TEST_CLIENT :: "127.0.0.1:5555"

/*
Whether the upstream was left alone, read once `handle_query` has returned.

For the cases that expect nothing to be forwarded at all. No mock thread, and so
nothing to race: a query this server forwards is written to the socket before the
call can return, so anything that leaked is already sitting in the receive buffer
by the time this looks. A mock started beforehand can only be worse at the same
job - it stops waiting on a timer, and a leak that arrives after it gave up is a
leak the test reports as absence.

Not zero milliseconds: `SO_RCVTIMEO` reads zero as "no timeout", which on a socket
nothing is going to send to is the one value that hangs. `nothing_reached` in
special_use_test.odin reads the socket the same way but matches differently: any
datagram naming the query's name counts, whatever type it asks, and it reports
the question that arrived.

With `query`, only a datagram asking its question counts, and any other is
skipped as `Canned_Mock` skips it: for a socket whose port may have been another
case's a moment ago, whose server can still be retrying to it.
*/
@(private)
mock_untouched :: proc(socket: net.UDP_Socket, query: []u8 = nil) -> bool {
	// A read the short bound did not reach would wait out `MOCK_RECV_TIMEOUT`
	// for nothing; reported as touched, the case fails instead.
	if net.set_option(socket, .Receive_Timeout, 20 * time.Millisecond) != nil {
		return false
	}
	// Left as the harnesses set it, so a fixture socket can be read this way in
	// the middle of a test that goes on to expect an exchange. Left short, the
	// next exchange fails early rather than hangs.
	defer _ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT) // lint:allow a restore left undone only shortens a later wait
	buf: [4096]u8
	for {
		n, _, err := net.recv_udp(socket, buf[:])
		if err != nil {
			return true
		}
		if query == nil {
			return n == 0
		}
		if dns.same_question(buf[:n], query) {
			return false
		}
	}
}

/*
A mock upstream's socket on loopback, and the spec that names it.

The socket waits `wait` for a query: `MOCK_RECV_TIMEOUT`, past the upstream
timeout of `test_config` rather than under it (see the note on the constant), or
a short poll for a mock loop that watches a stop flag. Closed again on every
failure, so a caller that gets `ok` false has nothing to clean up.
*/
@(private)
bind_mock :: proc(
	t: ^testing.T,
	name := "mock",
	wait := MOCK_RECV_TIMEOUT,
	loc := #caller_location,
) -> (
	socket: net.UDP_Socket,
	spec: config.Upstream_Spec,
	ok: bool,
) {
	sock, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr, loc = loc) {
		return {}, {}, false
	}
	terr := net.set_option(sock, .Receive_Timeout, wait)
	if !testing.expectf(t, terr == nil, "cannot bound the mock's wait: %v", terr, loc = loc) {
		net.close(sock)
		return {}, {}, false
	}
	bound, berr := net.bound_endpoint(sock)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr, loc = loc) {
		net.close(sock)
		return {}, {}, false
	}
	return sock, config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port}, true
}

// A UDP upstream on loopback at each of `ports`, in order, as `upstream.servers`
// would name them; every one is called `name`.
@(private)
loopback_upstream :: proc(ports: ..int, name := "mock") -> []config.Upstream_Spec {
	servers := make([]config.Upstream_Spec, len(ports), context.temp_allocator)
	for port, i in ports {
		servers[i] = config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = port}
	}
	return servers
}

/*
The default configuration with nothing between the client and the upstream: no
query log, no cache to answer from or store into, no blocklist and no validator.
A case turns back on what it is about.

`servers` get one try each, in order, so a case that is going wrong says so
instead of retrying; and three seconds, under `MOCK_RECV_TIMEOUT`, so the
resolver gives up before a mock does.
*/
@(private)
test_config :: proc(servers: []config.Upstream_Spec = nil) -> config.Config {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	cfg.upstream.servers = servers
	return cfg
}

// A group of a UDP upstream on loopback at each of `ports`, in order, with
// `cfg`'s settings; nil, with the failure reported, when it cannot be built.
@(private)
mock_group :: proc(t: ^testing.T, cfg: config.Upstream_Config, ports: ..int, loc := #caller_location) -> ^upstream.Group {
	one := cfg
	one.servers = loopback_upstream(..ports)
	group, gerr := upstream.make_group(one, context.allocator)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		return nil
	}
	return group
}

// A server forwarding to one mock upstream on loopback; see `harness_start`.
@(private)
Harness :: struct {
	socket:  net.UDP_Socket,
	cfg:     config.Config,
	group:   ^upstream.Group,
	answers: ^cache.Cache,
	srv:     Server,
}

/*
Start `h`: `harness_bind`, then `harness_build`.

`cfg` is `test_config` pointed at the mock and `srv` points into it, so the
caller keeps the harness where it put it, and changes `cfg` in place - turning
blocking on, say - between `harness_start` and the first query. A setting the
group or the cache is built from is set between `harness_bind` and
`harness_build` instead.
*/
@(private)
harness_start :: proc(
	t: ^testing.T,
	h: ^Harness,
	caching := false,
	cookies := false,
	validating := false,
	loc := #caller_location,
) -> bool {
	if !harness_bind(t, h, loc = loc) {
		return false
	}
	return harness_build(t, h, caching = caching, cookies = cookies, validating = validating, loc = loc)
}

/*
Bind `h`'s mock, waiting `wait` as `bind_mock` does, and set `h.cfg` to
`test_config` pointed at it. Nothing else is built, so the caller can change the
settings `harness_build` reads first. Nothing is left to clean up on false.
*/
@(private)
harness_bind :: proc(t: ^testing.T, h: ^Harness, name := "mock", wait := MOCK_RECV_TIMEOUT, loc := #caller_location) -> bool {
	socket, spec, ok := bind_mock(t, name, wait = wait, loc = loc)
	if !ok {
		return false
	}
	h^ = {}
	h.socket = socket
	h.cfg = test_config(loopback_upstream(spec.port, name = name))
	return true
}

/*
The group, the cache and the server for `h.cfg`, on a mock `harness_bind` bound.
On false the mock is closed too, and nothing is left to clean up.

The cache, when there is one, takes its TTL bounds and `serve_stale` from `cfg`
rather than from literals, and `negative_ttl` is the reason: a cache made
without one stores no denial at all, so a case about what is or is not
remembered could not fail.

`cookies` hands clients server cookies (`start_cookies`); the group never sends
one upstream, which would add an option to every forwarded query. `validating`
puts a validator in front of the answers: one that can fetch no chain
(`no_chain`), so whatever it judges comes out unproven without reaching the
network, or with `chain_lookups` the server's own `validator_query`, which asks
the mock.
*/
@(private)
harness_build :: proc(
	t: ^testing.T,
	h: ^Harness,
	caching := false,
	cookies := false,
	validating := false,
	chain_lookups := false,
	loc := #caller_location,
) -> bool {
	h.cfg.cache.enabled = caching
	h.cfg.cookies.enabled = cookies
	h.cfg.dnssec.enabled = validating
	group, gerr := upstream.make_group(h.cfg.upstream, context.allocator)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		net.close(h.socket)
		return false
	}
	h.group = group
	if caching {
		h.answers = cache.make_cache(
			cache.Options {
				max_entries = 8,
				max_ttl = h.cfg.cache.max_ttl,
				min_ttl = h.cfg.cache.min_ttl,
				negative_ttl = h.cfg.cache.negative_ttl,
				serve_stale = h.cfg.cache.serve_stale,
			},
		)
	}
	h.srv = Server {
		cfg     = &h.cfg,
		group   = h.group,
		answers = h.answers,
	}
	if validating && chain_lookups {
		h.srv.validator = dnssec.make_validator(validator_query, &h.srv, dnssec.Options{})
	} else if validating {
		h.srv.validator = dnssec.make_validator(no_chain, nil, dnssec.Options{})
	}
	if !testing.expect(t, start_cookies(&h.srv), "cannot set the cookie secret up", loc = loc) {
		harness_stop(h)
		return false
	}
	return true
}

/*
A server whose group is one mock upstream per name, asked in that order. The
caller keeps the fixture where it declared it: `srv` points at `cfg`.
`timeout` and `attempts`, when set, replace `test_config`'s before the group is
built from them.
*/
@(private)
Mocks :: struct {
	sockets: [2]net.UDP_Socket,
	bound:   int,
	cfg:     config.Config,
	group:   ^upstream.Group,
	srv:     Server,
}

@(private)
mocks_start :: proc(
	t: ^testing.T,
	f: ^Mocks,
	names: ..string,
	timeout: time.Duration = 0,
	attempts := 0,
	loc := #caller_location,
) -> bool {
	assert(len(names) <= len(f.sockets))
	specs := make([]config.Upstream_Spec, len(names), context.temp_allocator)
	for name, i in names {
		socket, spec, ok := bind_mock(t, name, loc = loc)
		if !ok {
			mocks_stop(f)
			return false
		}
		f.sockets[i] = socket
		f.bound += 1
		specs[i] = spec
	}
	f.cfg = test_config(specs)
	if timeout > 0 {
		f.cfg.upstream.timeout = timeout
	}
	if attempts > 0 {
		f.cfg.upstream.attempts = attempts
	}
	group, gerr := upstream.make_group(f.cfg.upstream)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		mocks_stop(f)
		return false
	}
	f.group = group
	f.srv = Server {
		cfg   = &f.cfg,
		group = f.group,
	}
	return true
}

@(private)
mocks_stop :: proc(f: ^Mocks) {
	if f.group != nil {
		upstream.destroy_group(f.group)
		f.group = nil
	}
	for socket in f.sockets[:f.bound] {
		net.close(socket)
	}
	f.bound = 0
}

@(private)
harness_stop :: proc(h: ^Harness) {
	release_parts(&h.srv, {.Cookie_Secrets, .Cookies})
	if h.srv.validator != nil {
		dnssec.destroy_validator(h.srv.validator)
		h.srv.validator = nil
	}
	if h.answers != nil {
		cache.destroy(h.answers)
	}
	upstream.destroy_group(h.group)
	net.close(h.socket)
}

/*
One query through the harness's server, with a `Canned_Mock` answering it with
`reply`; `asked` is whether the mock saw the question and its reply went out.
*/
@(private)
harness_ask :: proc(
	h: ^Harness,
	query, reply: []u8,
	client := TEST_CLIENT,
) -> (
	out: []u8,
	outcome: Outcome,
	served: bool,
	asked: bool,
) {
	x := Canned_Mock {
		reply = reply,
	}
	out, outcome, served = harness_exchange(h, &x, query, client = client)
	return out, outcome, served, x.got && x.served
}

// As `harness_ask`, with the caller's own mock, for a case that reads what the
// upstream was sent (`x.seen`) as well as whether it was asked.
@(private)
harness_exchange :: proc(
	h: ^Harness,
	x: ^Canned_Mock,
	query: []u8,
	proto := Protocol.UDP,
	client := TEST_CLIENT,
) -> (
	out: []u8,
	outcome: Outcome,
	served: bool,
) {
	x.socket = h.socket
	return exchange_with(&h.srv, x, serve_canned, query, proto, client)
}

// One query through `s`, with `serve` answering it from `x` on a thread of its
// own, joined before this returns.
@(private)
exchange_with :: proc(
	s: ^Server,
	x: ^$T,
	serve: proc(x: ^T),
	query: []u8,
	proto := Protocol.UDP,
	client := TEST_CLIENT,
) -> (
	out: []u8,
	outcome: Outcome,
	served: bool,
) {
	mock := thread.create_and_start_with_poly_data(x, serve)
	out, outcome, served = handle_query(s, query, proto, client, context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	return
}

/*
One query through the harness that has to be forwarded: the mock is asked and
answers `reply`, the client is answered, and the outcome says it was forwarded.
`ok` is false when the exchange itself did not happen, so a caller reads no
answer out of nothing.
*/
@(private)
forward_once :: proc(
	t: ^testing.T,
	h: ^Harness,
	query, reply: []u8,
	proto := Protocol.UDP,
	loc := #caller_location,
) -> (
	out: []u8,
	ok: bool,
) {
	x := Canned_Mock {
		reply = reply,
	}
	response, outcome, served := harness_exchange(h, &x, query, proto)
	if !testing.expect(t, x.got, "the upstream was never asked", loc = loc) {
		return nil, false
	}
	if !testing.expect(t, served, "the query went unanswered", loc = loc) {
		return nil, false
	}
	testing.expect_value(t, outcome, Outcome.Forwarded, loc = loc)
	return response, true
}

// The one A record answer `addr` still says what it said, to the client that
// asked with `id`, whatever happened to its OPT record on the way.
@(private)
expect_the_answer_survived :: proc(
	t: ^testing.T,
	m: dns.Message,
	label: string,
	addr: [4]u8,
	id: u16,
	loc := #caller_location,
) {
	if !testing.expectf(t, len(m.answer) == 1, "%s: the answer section holds %d records, not 1", label, len(m.answer), loc = loc) {
		return
	}
	testing.expectf(t, m.answer[0].type == .A, "%s: the answer is a %v", label, m.answer[0].type, loc = loc)
	a, is_a := m.answer[0].data.(dns.Rdata_A)
	if !testing.expectf(t, is_a, "%s: the answer's RDATA did not survive", label, loc = loc) {
		return
	}
	testing.expectf(t, a.addr == addr, "%s: the address came back as %v", label, a.addr, loc = loc)
	testing.expectf(t, m.id == id, "%s: the answer carries ID %d", label, m.id, loc = loc)
	testing.expectf(t, len(m.question) == 1, "%s: the question did not come back", label, loc = loc)
}

/*
A mock upstream that answers one question with a canned reply.

The question is the one `reply` carries, and a datagram asking anything else is
skipped rather than answered. The tests in this package run in parallel against
sockets bound to port zero, and a port a finished test's mock has released is one
the kernel can hand to the next test that asks - so a query another case's server
is still retrying can arrive here, be taken for the question this case asked, and
fail it on a name it never mentioned. Waiting for the question turns that into a
packet nobody answered, which is what it is.

One query per thread, joined by the caller before it reads `got`: there is
nothing shared to guard, and a question that never arrives leaves `got` false
rather than hanging the suite - the socket carries a receive timeout.
*/
@(private)
Canned_Mock :: struct {
	socket:   net.UDP_Socket,
	reply:    []u8,
	got:      bool,
	// Whether the reply went out, so a lost send is not read as a timeout.
	served:   bool,
	// The query as it arrived, so a case can assert on what this server
	// actually forwarded. Read after the thread is joined. As long as the
	// buffer `serve_canned` reads into, so nothing read is cut short here.
	seen:     [4096]u8,
	seen_len: int,
	// Wait for any question naming `want`, whatever its type, rather than for
	// `reply`'s own: for a route or a rewrite whose upstream is asked another
	// name than the client's.
	want:     string,
	// How long to wait, or what to wait for (bounded by `MOCK_RECV_TIMEOUT`, and
	// answered when that runs out too), between the question and the answer, so
	// the client's own deadline or a case's ordering is what decides the race.
	delay:    time.Duration,
	hold:     ^sync.Sema,
}

@(private)
serve_canned :: proc(x: ^Canned_Mock) {
	buf: [4096]u8
	if len(x.reply) > len(buf) {
		return
	}
	n: int
	remote: net.Endpoint
	asked: bool
	if x.want != "" {
		n, remote, asked = recv_named(x.socket, x.want, buf[:])
	} else {
		n, remote, asked = recv_question(x.socket, x.reply, buf[:])
	}
	if !asked {
		return
	}
	x.got = true
	x.seen_len = copy(x.seen[:], buf[:n])
	if x.delay > 0 {
		time.sleep(x.delay) // lint:allow the delay is what the case times its deadline against
	}
	if x.hold != nil {
		// Answered either way, so a case whose release came late still sees the
		// answer arrive late rather than never.
		_ = sync.sema_wait_with_timeout(x.hold, MOCK_RECV_TIMEOUT) // lint:allow late is still answered
	}
	x.served = send_reply_as(x.socket, x.reply, buf[:n], remote)
}

/*
The next datagram on `socket` asking any question about `name`, read into `buf`;
runts and other names are skipped, as `recv_question` skips them. The question
is peeked into an arena on this thread's own stack: a mock thread's decode must
not reach the temp arena the test thread frees.
*/
@(private)
recv_named :: proc(socket: net.UDP_Socket, name: string, buf: []u8) -> (n: int, remote: net.Endpoint, ok: bool) {
	backing: [1024]u8
	scratch: mem.Arena
	mem.arena_init(&scratch, backing[:])
	for {
		got, from, err := net.recv_udp(socket, buf)
		if err != nil {
			return 0, {}, false
		}
		if got < dns.HEADER_SIZE {
			continue
		}
		free_all(mem.arena_allocator(&scratch))
		if q, peeked := dns.peek_question(buf[:got], mem.arena_allocator(&scratch)); peeked && dns.name_equal_fold(q.name, name) {
			return got, from, true
		}
	}
}

/*
How many datagrams are sitting unread in `socket` asking any question about
`name`, or how many datagrams at all for an empty `name`; -1 when the read
cannot be bounded. Read once the call that may have sent them has returned, as
`mock_untouched` reads, and left with the harnesses' `MOCK_RECV_TIMEOUT`.
*/
@(private)
mock_heard :: proc(socket: net.UDP_Socket, name := "") -> (heard: int) {
	if net.set_option(socket, .Receive_Timeout, 20 * time.Millisecond) != nil {
		return -1
	}
	defer _ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT) // lint:allow a restore left undone only shortens a later wait
	buf: [4096]u8
	for {
		n, _, err := net.recv_udp(socket, buf[:])
		if err != nil {
			return
		}
		if name == "" {
			heard += 1
			continue
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		if q, ok := dns.peek_question(buf[:n], context.temp_allocator); ok && dns.name_equal_fold(q.name, name) {
			heard += 1
		}
	}
}

/*
Send `reply` to `remote` as the answer to `query`: under the ID it was asked
with, which the resolver draws fresh for every query it forwards, so nothing
here can know it in advance. False when either is too short to hold an ID, the
reply is past a datagram buffer here, or the send fails.
*/
@(private)
send_reply_as :: proc(socket: net.UDP_Socket, reply, query: []u8, remote: net.Endpoint) -> bool {
	out: [4096]u8
	if len(reply) < 2 || len(query) < 2 || len(reply) > len(out) {
		return false
	}
	copy(out[:], reply)
	out[0], out[1] = query[0], query[1]
	_, err := net.send_udp(socket, out[:len(reply)], remote)
	return err == nil
}

/*
The next datagram on `socket` that asks `question`'s question, read into `buf`.
A runt, or another case's question, is skipped rather than taken as the end of
the wait: see `Canned_Mock`. `ok` is false once the socket's receive timeout
passes with nothing that asks it.
*/
@(private)
recv_question :: proc(socket: net.UDP_Socket, question: []u8, buf: []u8) -> (n: int, remote: net.Endpoint, ok: bool) {
	for {
		got, from, err := net.recv_udp(socket, buf)
		if err != nil {
			return 0, {}, false
		}
		if dns.same_question(buf[:got], question) {
			return got, from, true
		}
	}
}

// A client's query for `name`, with an OPT record when `opt` holds one.
@(private)
test_query :: proc(
	name: string,
	type := dns.Type.A,
	id: u16 = 0x4242,
	rd := true,
	opt: Maybe(dns.Record) = nil,
	class := dns.Class.IN,
) -> []u8 {
	question := [1]dns.Question{{name = name, type = type, class = class}}
	additional: [1]dns.Record
	m := dns.Message {
		id       = id,
		question = question[:],
	}
	m.flags.rd = rd
	if record, has := opt.?; has {
		additional[0] = record
		m.additional = additional[:]
	}
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("the test query does not encode")
	}
	return wire
}

/*
The signer these synthetic signatures name.

Written out rather than left as the root, because the prune keeps a signature
only when its signer is the one the verdict was reached against - so the name in
here and the `signer` on a test's `Authenticated_Set` have to be the same name,
and a test whose fixture quietly disagreed with its verdict would drop the
signature and look like a prune bug.
*/
@(private)
TEST_SIGNER :: "example.com."

/*
An RRSIG's RDATA, far enough along to be read as one.

What is read of it is the covered type, the signer and the validity window -
`dnssec.strip_unauthenticated` keeps a signature for the RRset it covers, so a
record whose first two bytes say nothing is a signature over nothing and is
dropped. The rest is filler: no signature is verified anywhere in this file,
which is `src/dnssec`'s work against captured chains.

The window is a day either side of now unless `expiration` is given, with
inception thirty days before it; `original_ttl`, `signer` and `labels` (the
owner's label count, RFC 4034 section 3.1.3) are written as given.
*/
@(private)
rrsig_over :: proc(
	covered: dns.Type,
	expiration: Maybe(u32) = nil,
	original_ttl: u32 = 0,
	signer := TEST_SIGNER,
	labels: u8 = 3,
) -> dns.Rdata_Raw {
	// 18 bytes of fixed fields, the signer name, then a signature.
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name(signer, name_buf[:])
	if err != .None {
		panic("cannot encode the test signer")
	}
	rdata := make([]u8, 18 + n + 8, context.temp_allocator)
	rdata[0] = u8(u16(covered) >> 8)
	rdata[1] = u8(u16(covered))
	rdata[2] = 13 // ECDSA P-256, so the algorithm at least names something real
	rdata[3] = labels
	// A window around now, so a cache that will not keep an answer past its
	// signatures (#165) keeps this one: expiration a day ahead, inception a day
	// behind.
	now := u32(time.time_to_unix(time.now())) // lint:allow wall-clock: an RRSIG's validity window is an instant on it
	dns.write_ttl_at(rdata, 4, original_ttl)
	if until, given := expiration.?; given {
		dns.write_ttl_at(rdata, 8, until)
		dns.write_ttl_at(rdata, 12, until - 30 * 86400)
	} else {
		dns.write_ttl_at(rdata, 8, now + 86400)
		dns.write_ttl_at(rdata, 12, now - 86400)
	}
	copy(rdata[18:], name_buf[:n])
	return dns.Rdata_Raw{data = rdata}
}

// An upstream's answer to `name`'s `type`, with QR, RD and RA set, AA as `aa`
// says, and `authority` and `additional` as given.
@(private)
test_reply :: proc(
	name: string,
	type: dns.Type,
	answers: ..dns.Record,
	rcode := dns.Rcode.No_Error,
	authority: []dns.Record = nil,
	additional: []dns.Record = nil,
	aa := false,
) -> []u8 {
	question := [1]dns.Question{{name = name, type = type, class = .IN}}
	m := dns.Message {
		question   = question[:],
		answer     = answers,
		authority  = authority,
		additional = additional,
	}
	m.flags.qr = true
	m.flags.aa = aa
	m.flags.rd = true
	m.flags.ra = true
	m.flags.rcode = u8(rcode)
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if err != .None {
		panic("the test reply does not encode")
	}
	return wire
}

@(private)
a_record :: proc(name: string, addr: [4]u8, ttl: u32 = 60) -> dns.Record {
	return dns.Record{name = name, type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = addr}}
}

@(private)
cname_record :: proc(name, target: string, ttl: u32 = 60) -> dns.Record {
	return dns.Record{name = name, type = .CNAME, class = .IN, ttl = ttl, data = dns.Rdata_Name{name = target}}
}

// An OPT record carrying one option.
@(private)
opt_with :: proc(code: dns.EDNS_Option_Code, data: []u8, udp_size: u16 = config.DEFAULT_MAX_UDP_RESPONSE, do_bit := false, version: u8 = 0) -> dns.Record {
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option{code = u16(code), data = data}
	return opt_record(udp_size, version, do_bit, options)
}

// An OPT record in EDNS `version` carrying `options`, with the DO bit as given.
// The version is the TTL's second byte (RFC 6891 section 6.1.3); the extended
// rcode above it stays zero.
@(private)
opt_record :: proc(udp_size: u16 = config.DEFAULT_MAX_UDP_RESPONSE, version: u8 = 0, do_bit := false, options: []dns.EDNS_Option = nil) -> dns.Record {
	opt := dns.make_opt(udp_size, do_bit)
	opt.ttl |= u32(version) << 16
	opt.data = dns.Rdata_OPT{options = options}
	return opt
}

// The info-code and EXTRA-TEXT of the extended error a response carries
// (RFC 8914), or -1 and "" if it has none.
@(private)
extended_error :: proc(wire: []u8) -> (code: int, text: string) {
	data, found := dns.peek_edns_option(wire, .Ext_Error)
	if !found || len(data) < 2 {
		return -1, ""
	}
	return int(data[0]) << 8 | int(data[1]), string(data[2:])
}

// Store `wire` in `answers` as the answer to `name`'s `type`, stamped `checked`.
@(private)
seed_cache :: proc(
	t: ^testing.T,
	answers: ^cache.Cache,
	name: string,
	wire: []u8,
	type := dns.Type.A,
	checked: u64 = 0,
	loc := #caller_location,
) -> bool {
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the answer would not decode: %v", derr, loc = loc) {
		return false
	}
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], name, type, .IN, false)
	return testing.expect(t, cache.put(answers, key, wire, decoded, checked), "the answer was not cached", loc = loc)
}

// Whether `predicate` holds within `within`, asked every millisecond and once
// more at the end.
@(private)
wait_until :: proc(predicate: proc(data: rawptr) -> bool, data: rawptr, within: time.Duration) -> bool {
	start := time.tick_now()
	for time.tick_since(start) < within {
		if predicate(data) {
			return true
		}
		time.sleep(time.Millisecond) // lint:allow the poll interval of a deadline-bounded wait
	}
	return predicate(data)
}

// An NSEC at `owner` whose next name is `next`.
@(private)
nsec_at :: proc(owner, next: string, types: ..dns.Type) -> dns.Record {
	name: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name(next, name[:])
	if err != .None {
		panic("the NSEC's next name does not encode")
	}
	rdata := make([dynamic]u8, context.temp_allocator)
	append(&rdata, ..name[:n])
	append(&rdata, ..testkit.type_bitmap(..types))
	return dns.Record{name = owner, type = .NSEC, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = rdata[:]}}
}

// A NODATA for `name`'s `DS` carrying `authority`.
@(private)
ds_nodata :: proc(name: string, authority: ..dns.Record) -> []u8 {
	question := [1]dns.Question{{name = name, type = .DS, class = .IN}}
	msg := dns.Message {
		question  = question[:],
		authority = authority,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		panic("the DS NODATA does not encode")
	}
	return wire
}

// A validator fetch that finds nothing: every chain lookup fails, so whatever
// a case validates comes out unproven rather than reaching the network.
@(private)
no_chain :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> ([]u8, bool) {
	return nil, false
}

/*
A filter engine holding the rules of `text`. `ok` is false when the list added
no rule at all, which would leave a case about blocking blocking nothing. The
engine is the caller's to destroy either way.
*/
@(private)
test_filters :: proc(
	t: ^testing.T,
	text: string,
	format: filter.Format,
	loc := #caller_location,
) -> (
	engine: ^filter.Engine,
	ok: bool,
) {
	block, allow := filter.set_make(), filter.set_make()
	added := filter.parse_list(block, allow, text, format)
	engine = filter.engine_make()
	filter.engine_swap(engine, block, allow)
	return engine, testing.expectf(t, added > 0, "the list %q added no rule", text, loc = loc)
}

/*
The lists a case runs under: `block` and `allow` as domains, and `rules` as
blocklist lines, each of which has to parse or the case would pass on an empty
list.
*/
@(private)
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

/*
A `Server` with counters and nothing else behind them, configured from `cfg`.

`render_metrics` reaches for the cache, the filter engine and the upstream
group, and every one of those is absent here: what is being tested
is what the endpoint says about the numbers, and the components have tests of
their own. The renderer leaves out the families it has no component for, which
is why this builds.
*/
@(private)
metrics_fixture :: proc(cfg: ^config.Config, stats: Stats) -> Server {
	cfg^ = config.default_config()
	cfg.server.max_connections = 512
	cfg.metrics.enabled = true
	return Server{cfg = cfg, stats = stats, started = time.now()} // lint:allow wall-clock: `started` is an epoch instant
}

/*
A loopback TCP listener on an ephemeral port, for a case whose client dials from
a thread of its own. Closed again on failure.
*/
@(private)
loopback_listener :: proc(
	t: ^testing.T,
	loc := #caller_location,
) -> (
	listener: net.TCP_Socket,
	bound: net.Endpoint,
	ok: bool,
) {
	sock, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr, loc = loc) {
		return {}, {}, false
	}
	at, berr := net.bound_endpoint(sock)
	if !testing.expectf(t, berr == nil, "cannot read the bound port: %v", berr, loc = loc) {
		net.close(sock)
		return {}, {}, false
	}
	return sock, at, true
}

/*
Both ends of one loopback TCP connection: `client` dialled it and `accepted` is
the server's end. The listener is closed once it has handed `accepted` over, and
everything opened is closed again on failure, so a caller that gets `ok` false
has nothing to clean up.
*/
@(private)
loopback_tcp_pair :: proc(
	t: ^testing.T,
	loc := #caller_location,
) -> (
	client: net.TCP_Socket,
	accepted: net.TCP_Socket,
	ok: bool,
) {
	listener, bound, lok := loopback_listener(t, loc)
	if !lok {
		return {}, {}, false
	}
	defer net.close(listener)
	dialled, derr := net.dial_tcp_from_endpoint(bound)
	if !testing.expectf(t, derr == nil, "cannot dial the listener: %v", derr, loc = loc) {
		return {}, {}, false
	}
	taken, _, aerr := net.accept_tcp(listener)
	if !testing.expectf(t, aerr == nil, "nothing connected: %v", aerr, loc = loc) {
		net.close(dialled)
		return {}, {}, false
	}
	return dialled, taken, true
}

// Everything `client` reads until the peer closes, an error, or `timeout` passes
// with nothing new; `err` is what ended the read, nil for a clean close.
@(private)
read_until_close :: proc(client: net.TCP_Socket, timeout: time.Duration) -> (got: string, err: net.Network_Error) {
	if err = net.set_option(client, .Receive_Timeout, timeout); err != nil {
		return
	}
	b := strings.builder_make(context.temp_allocator)
	for {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			return strings.to_string(b), rerr
		}
		strings.write_bytes(&b, chunk[:n])
	}
}

// `serve_doh` over one connection, on a thread of its own.
@(private)
Doh_Session :: struct {
	server: ^Server,
	conn:   Conn,
}

@(private)
run_serve_doh :: proc(d: ^Doh_Session) {
	serve_doh(d.server, d.conn, "test")
	// The FIN the listener's close sends once `serve_doh` returns, so a client
	// reading until close stops here rather than at its timeout. The caller
	// still owns the descriptor.
	net.shutdown(d.conn.socket, .Send)
}

/*
Bytes `fd` holds that its reader has not taken: `FIONREAD`, which on a UDP
socket is the next datagram's. -1 when the kernel will not say.
*/
@(private)
unread_bytes :: proc(fd: linux.Fd) -> int {
	FIONREAD :: 0x541B
	n: i32
	if i32(linux.ioctl(fd, FIONREAD, uintptr(&n))) < 0 {
		return -1
	}
	return int(n)
}

/*
Spend all of `peer`'s stream budget, `RRL_BURST_SECONDS` of it, through
`stream_rate_check`: the pool a DoH request is charged to, over either HTTP
version, and one datagrams cannot empty - see `Rate_Class`.
*/
@(private)
spend_stream_budget :: proc(t: ^testing.T, limiter: ^Rate_Limiter, peer: net.Endpoint, loc := #caller_location) {
	for _ in 0 ..< RRL_BURST_SECONDS {
		testing.expect(
			t,
			stream_rate_check(limiter, peer, time.tick_now()),
			"the stream budget refused a query it had room for",
			loc = loc,
		)
	}
}

/*
A server with no upstream and nothing between it and its own answers: no query
log, no cache and no blocklist. `s.group` is nil, so a query that reached the
forwarding step would fault rather than hang, which is what makes a case about
where something is answered loud when it is answered in the wrong place.
*/
@(private)
local_server :: proc(cfg: ^config.Config) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	return Server{cfg = cfg}
}

// `name`'s `type` asked of `s` with RD set, and `opt` on it when there is one;
// a zero message, and a failed case, when nothing readable came back.
@(private)
ask_message :: proc(t: ^testing.T, s: ^Server, name: string, type: dns.Type, opt: Maybe(dns.Record) = nil, loc := #caller_location) -> dns.Message {
	out, _, ok := handle_query(s, test_query(name, type, id = 0x4243, opt = opt), .UDP, TEST_CLIENT, context.temp_allocator)
	if !testing.expectf(t, ok, "%s %v went unanswered", name, type, loc = loc) {
		return {}
	}
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expectf(t, derr == .None, "the answer to %s %v does not decode: %v", name, type, derr, loc = loc)
	return decoded
}

/*
A `local_server`, with no validator either, that answers `domain` from one
rewrite rule: A 192.0.2.1, TTL 300. What it sends is then something this
server minted on its own, with nothing in the path that could have echoed it.
*/
@(private)
rewrite_server :: proc(cfg: ^config.Config, domain: string) -> Server {
	s := local_server(cfg)
	cfg.dnssec.enabled = false
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite {
		domain  = domain,
		answers = answers_of({kind = .A, v4 = {192, 0, 2, 1}}),
		ttl     = 300,
	}
	cfg.rewrites = rules
	return s
}

// That `wire` is `rewrite_server`'s answer, whole: NOERROR and its one address.
@(private)
answers_the_rewrite :: proc(t: ^testing.T, wire: []u8, loc := #caller_location) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the answer does not decode: %v", err, loc = loc) {
		return
	}
	testing.expect_value(t, dns.peek_rcode(wire), dns.Rcode.No_Error, loc = loc)
	if !testing.expect_value(t, len(m.answer), 1, loc = loc) {
		return
	}
	a, is_a := m.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the answer lost its A record", loc = loc)
	testing.expect_value(t, a.addr, [4]u8{192, 0, 2, 1}, loc = loc)
}

/*
A rewrite's answer list that outlives the procedure that wrote it.

`[]T{...}` slices a temporary the compiler puts in the enclosing frame, so a
rule set built that way and returned carries slices into a frame that has gone -
which reads as rules nobody wrote rather than as a crash. Copying into the
temporary allocator keeps the list alive for as long as the test that asked for it.
*/
@(private)
answers_of :: proc(list: ..config.Rewrite_Answer) -> []config.Rewrite_Answer {
	out := make([]config.Rewrite_Answer, len(list), context.temp_allocator)
	copy(out, list)
	return out
}

/*
`name`'s `type` asked of `s` over UDP and read back. RD is clear by default, so
a name nothing local answers cannot reach the forwarding path - there is no
upstream - and comes back Refused instead, which names the failure exactly.
`ok` is false when nothing came back or it would not decode.
*/
@(private)
ask_local :: proc(
	s: ^Server,
	name: string,
	type: dns.Type,
	rd := false,
	class := dns.Class.IN,
) -> (
	resp: dns.Message,
	outcome: Outcome,
	ok: bool,
) {
	out, how, answered := handle_query(s, test_query(name, type, rd = rd, class = class), .UDP, TEST_CLIENT, context.temp_allocator)
	if !answered {
		return {}, how, false
	}
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	return decoded, how, derr == .None
}

/*
The request `resolve_query` holds for `msg` from a UDP client, for running its
stages one at a time. `msg` is encoded as the query's bytes.
*/
@(private)
stage_state :: proc(s: ^Server, msg: dns.Message, spent: ^int, allocator: mem.Allocator) -> Query_State {
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		panic("the staged query does not encode")
	}
	return Query_State {
		s = s,
		query = wire,
		msg = msg,
		q = msg.question[0],
		proto = .UDP,
		client = TEST_CLIENT,
		limit = dns.MAX_UDP_SIZE,
		started = time.tick_now(),
		spent = spent,
		allocator = allocator,
	}
}

/*
A client's A query for `name` carrying `additional` as written: two OPT records,
or one that is not last, go out as they are, which is what a case about a
malformed EDNS section needs.
*/
@(private)
query_with_records :: proc(name: string, additional: ..dns.Record) -> []u8 {
	question := [1]dns.Question{{name = name, type = .A, class = .IN}}
	msg := dns.Message {
		id         = 0x4242,
		question   = question[:],
		additional = additional,
	}
	msg.flags.rd = true
	wire, _, err := dns.encode_with_every_opt(msg, context.temp_allocator)
	if err != .None {
		panic("the test query does not encode")
	}
	return wire
}

// An upstream's A answer for `name`, with an OPT record of its own advertising
// `udp_size`, as an EDNS upstream writes one.
@(private)
edns_reply :: proc(name: string, addr: [4]u8, udp_size: u16 = config.DEFAULT_MAX_UDP_RESPONSE) -> []u8 {
	wire, ok := dns.ensure_opt(test_reply(name, .A, a_record(name, addr, 300)), udp_size, context.temp_allocator)
	if !ok {
		panic("the test reply took no OPT record")
	}
	return wire
}

/*
A mock upstream that answers one question and reports whether the query carried
EDNS option `code`.

Every OPT record is walked, not just the first one `find_edns_option` stops at.
A resolver reading these bytes is under no obligation to stop where this
server's decoder stops, so a mock that looked only where a strip looks could not
tell a query the strip cleaned from one still carrying the option somewhere the
strip never reached.

The question is `reply`'s, and a datagram asking anything else is skipped as
`Canned_Mock` skips it. `reply_seen`, when set, is answered instead to a query
that carried the option, so a case can tell from the answer alone which one the
upstream was asked.
*/
@(private)
Option_Mock :: struct {
	socket:     net.UDP_Socket,
	code:       dns.EDNS_Option_Code,
	reply:      []u8,
	reply_seen: []u8,
	saw:        bool,
	saw_do:     bool,
	served:     bool,
}

@(private)
serve_option_sniffer :: proc(x: ^Option_Mock) {
	buf: [4096]u8
	n, remote, asked := recv_question(x.socket, x.reply, buf[:])
	if !asked {
		return
	}
	m, derr := dns.decode_message(buf[:n], context.temp_allocator)
	if derr != .None {
		return
	}
	for rec in m.additional {
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if rec.type != .OPT || !is_opt {
			continue
		}
		for o in rdata.options {
			if o.code == u16(x.code) {
				x.saw = true
			}
		}
	}
	x.saw_do = dns.edns_do(m)
	free_all(context.temp_allocator)

	reply := x.reply_seen if x.saw && x.reply_seen != nil else x.reply
	x.served = send_reply_as(x.socket, reply, buf[:n], remote)
}

/*
One query through the harness's server with an `Option_Mock` answering it; `x`
names the option to look for and the replies.
*/
@(private)
harness_sniff :: proc(
	h: ^Harness,
	x: ^Option_Mock,
	query: []u8,
	proto := Protocol.UDP,
	client := TEST_CLIENT,
) -> (
	out: []u8,
	outcome: Outcome,
	ok: bool,
) {
	x.socket = h.socket
	return exchange_with(&h.srv, x, serve_option_sniffer, query, proto, client)
}

/*
That `query` is refused FORMERR by the harness's server and never reaches its
upstream: the shape `edns_opt_readable` turns away. `what` is the failure if it
was forwarded. Returns the answer for any further check.
*/
@(private)
expect_refused_unforwarded :: proc(t: ^testing.T, h: ^Harness, query: []u8, what: string, loc := #caller_location) -> []u8 {
	out, outcome, ok := handle_query(&h.srv, query, .UDP, TEST_CLIENT, context.temp_allocator)
	testing.expect(t, mock_untouched(h.socket, query), what, loc = loc)
	testing.expect(t, ok, "the client was left with nothing at all", loc = loc)
	testing.expect_value(t, outcome, Outcome.Failed, loc = loc)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err, loc = loc)
	return out
}

// A keeper issuing under `key` alone, its secrets on the temp allocator.
secret_keeper :: proc(key: [COOKIE_SECRET_LEN]u8) -> Cookie_Keeper {
	k := Cookie_Keeper{secrets = new(Cookie_Secrets, context.temp_allocator)}
	k.secrets.slots[0].key = key
	return k
}

// RFC 9018 appendix A's server secret, as configured and as the key it decodes
// to, and its client cookie and client.
@(private)
RFC9018_SECRET :: "e5e973e5a6b2a43f48e7dc849e37bfcf"

@(private)
RFC9018_SECRET_KEY :: [COOKIE_SECRET_LEN]u8{0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf}

@(private)
RFC9018_CLIENT_COOKIE :: "2464c4abcf10c957"

@(private)
RFC9018_CLIENT :: "198.51.100.100:9999"

// An eight-byte client cookie no server has answered yet, so its verdict is
// `Unproven` and a server cookie is minted for it.
@(private)
test_client_cookie :: proc() -> []u8 {
	cookie := make([]u8, 8, context.temp_allocator)
	for i in 0 ..< len(cookie) {
		cookie[i] = u8(0xa0 + i)
	}
	return cookie
}

/*
Answer `query` from a cache holding `stored` for `name`, with cookies under
the RFC 9018 secret, so the whole client-facing path runs with no upstream
behind it. `ok` is false when the fixture could not be set up or nothing was
served.
*/
@(private)
cookie_roundtrip :: proc(
	t: ^testing.T,
	name: string,
	stored, query: []u8,
	proto: Protocol,
	client: string,
	enabled := true,
	require := false,
	loc := #caller_location,
) -> (
	out: []u8,
	ok: bool,
) {
	cfg := test_config()
	cfg.cache.enabled = true
	cfg.cookies.enabled = enabled
	cfg.cookies.require = require
	cfg.cookies.secret = RFC9018_SECRET

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	if !testing.expect(t, start_cookies(&s), "the cookie keeper would not start", loc = loc) {
		return nil, false
	}
	defer release_parts(&s, {.Cookie_Secrets, .Cookies})

	if !seed_cache(t, answers, name, stored, loc = loc) {
		return nil, false
	}
	response, _, served := handle_query(&s, query, proto, client, context.temp_allocator)
	return response, served
}

// The entry `answers` holds under `key`, or nil. Every shard is looked in:
// which one a key lands in is the cache's own seeded hash.
@(private)
cached_entry :: proc(answers: ^cache.Cache, key: string) -> ^cache.Entry {
	for &shard in answers.shards {
		if e, found := shard.entries[key]; found {
			return e
		}
	}
	return nil
}

/*
Age the entry under `key` past its TTL, stored an hour ago, which is how
`serve_stale` finds an answer kept through an outage. False when nothing is
stored under `key`.

The cache has no public way to age an entry, so the deadline is written
directly; storing a one-second answer and sleeping past it would spend real
time on a clock that is not what these cases are about.
*/
@(private)
expire_entry :: proc(answers: ^cache.Cache, key: string) -> bool {
	e := cached_entry(answers, key)
	if e == nil {
		return false
	}
	e.expires = loop.moment_add(loop.moment_now(), -1 * time.Second)
	e.inserted = loop.moment_add(loop.moment_now(), -3600 * time.Second)
	return true
}

// A rate limiter's clock `ms` milliseconds in. Not from zero: a bucket's
// `last_ns` of zero means "never used".
@(private)
limiter_tick :: proc(ms: i64) -> time.Tick {
	return time.Tick{_nsec = (3600 + ms) * i64(time.Millisecond)}
}

// Bound `socket`'s `option` wait to `d`, so a case cannot block for good on a
// peer that never comes. False, with the failure reported, when it did not take.
@(private)
set_wait :: proc(t: ^testing.T, socket: net.Any_Socket, option: net.Socket_Option, d: time.Duration, loc := #caller_location) -> bool {
	err := net.set_option(socket, option, d)
	return testing.expectf(t, err == nil, "cannot bound the wait with %v: %v", option, err, loc = loc)
}
