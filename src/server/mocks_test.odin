package server

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
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
of the machine instead of one of the resolver: two seconds was enough to fail
`Tests (arm64)` at random, on a loaded shared runner where the whole package
took 5.1s against ~3.3s locally, with `the upstream was never asked` - a
statement about the scheduler dressed up as one about forwarding (#191).

Well past every `upstream.timeout` the harnesses here configure, so the resolver
is what gives up first: a query that genuinely never comes fails the exchange on
the test thread, and the mock is only what stops the join behind it from waiting
forever.

A mock that is there to report that *nothing* arrived wants the opposite of this
and does not use it: `mock_untouched` below reads the socket after the call has
returned rather than racing it, which is both exact and quick.
*/
MOCK_RECV_TIMEOUT :: 10 * time.Second

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
special_use_test.odin is this same reading, kept there because it also wants the
question the leaked query asked.
*/
mock_untouched :: proc(socket: net.UDP_Socket) -> bool {
	_ = net.set_option(socket, .Receive_Timeout, 20 * time.Millisecond)
	// Left as the harnesses set it, so a fixture socket can be read this way in
	// the middle of a test that goes on to expect an exchange.
	defer _ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	buf: [4096]u8
	n, _, err := net.recv_udp(socket, buf[:])
	return err != nil || n == 0
}

/*
A mock upstream's socket on loopback, and the spec that names it.

The socket waits `MOCK_RECV_TIMEOUT` for a query, past the upstream timeout of
`test_config` rather than under it: see the note on the constant. Closed again
on every failure, so a caller that gets `ok` false has nothing to clean up.
*/
@(private)
bind_mock :: proc(
	t: ^testing.T,
	name := "mock",
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
	terr := net.set_option(sock, .Receive_Timeout, MOCK_RECV_TIMEOUT)
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

// One UDP upstream on loopback at `port`, as `upstream.servers` would name it.
@(private)
loopback_upstream :: proc(port: int, name := "mock") -> []config.Upstream_Spec {
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = port}
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

// A group of one UDP upstream on loopback at `port`, with `cfg`'s settings.
@(private)
mock_group :: proc(t: ^testing.T, cfg: config.Upstream_Config, port: int) -> ^upstream.Group {
	one := cfg
	one.servers = loopback_upstream(port)
	group, gerr := upstream.make_group(one, context.allocator)
	testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr)
	return group
}

/*
A server forwarding to one mock upstream on loopback.

`cfg` is `test_config` pointed at the mock and `srv` points into it, so the
caller keeps the harness where it put it, and changes `cfg` in place - turning
blocking on, say - between `harness_start` and the first query.

The cache, when there is one, is sized from `cfg` rather than with a literal,
and `negative_ttl` is the reason: a cache made without one stores no denial at
all, so a case about what is or is not remembered could not fail.
*/
@(private)
Harness :: struct {
	socket:  net.UDP_Socket,
	cfg:     config.Config,
	group:   ^upstream.Group,
	answers: ^cache.Cache,
	srv:     Server,
}

@(private)
harness_start :: proc(t: ^testing.T, h: ^Harness, caching := false, loc := #caller_location) -> bool {
	socket, spec, ok := bind_mock(t, loc = loc)
	if !ok {
		return false
	}
	h.cfg = test_config(loopback_upstream(spec.port))
	h.cfg.cache.enabled = caching
	group, gerr := upstream.make_group(h.cfg.upstream, context.allocator)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr, loc = loc) {
		net.close(socket)
		return false
	}
	h.socket = socket
	h.group = group
	h.answers = nil
	if caching {
		h.answers = cache.make_cache(
			cache.Options {
				max_entries = 8,
				max_ttl = h.cfg.cache.max_ttl,
				min_ttl = h.cfg.cache.min_ttl,
				negative_ttl = h.cfg.cache.negative_ttl,
			},
		)
	}
	h.srv = Server {
		cfg     = &h.cfg,
		group   = h.group,
		answers = h.answers,
	}
	return true
}

@(private)
harness_stop :: proc(h: ^Harness) {
	if h.answers != nil {
		cache.destroy(h.answers)
	}
	upstream.destroy_group(h.group)
	net.close(h.socket)
}

/*
One query through the harness's server, with a `Canned_Mock` answering it with
`reply`; `asked` is whether the mock saw the question at all.
*/
@(private)
harness_ask :: proc(
	h: ^Harness,
	query, reply: []u8,
	client := "127.0.0.1:5555",
) -> (
	out: []u8,
	outcome: Outcome,
	served: bool,
	asked: bool,
) {
	x := Canned_Mock {
		socket = h.socket,
		reply  = reply,
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_canned)
	out, outcome, served = handle_query(&h.srv, query, .UDP, client, context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)
	return out, outcome, served, x.got
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
	// The query as it arrived, so a case can assert on what this server
	// actually forwarded. Read after the thread is joined.
	seen:     [512]u8,
	seen_len: int,
	// How long to sit on the query before answering it, for a case that needs
	// an upstream that is slow rather than absent.
	delay:    time.Duration,
	// Held until posted, where the case needs the client answered before the
	// upstream is; bounded by `MOCK_RECV_TIMEOUT`.
	hold:     ^sync.Sema,
}

@(private)
serve_canned :: proc(x: ^Canned_Mock) {
	buf: [4096]u8
	if len(x.reply) > len(buf) {
		return
	}
	for {
		n, remote, err := net.recv_udp(x.socket, buf[:])
		if err != nil {
			// The receive timeout, which is how this returns when the question
			// it waits for never arrives.
			return
		}
		// A runt, or another case's question, is skipped rather than taken as
		// the end of the wait: see the type.
		if !dns.same_question(buf[:n], x.reply) {
			continue
		}
		x.got = true
		x.seen_len = copy(x.seen[:], buf[:n])
		if x.delay > 0 {
			time.sleep(x.delay)
		}
		if x.hold != nil {
			_ = sync.sema_wait_with_timeout(x.hold, MOCK_RECV_TIMEOUT)
		}
		out: [4096]u8
		copy(out[:], x.reply)
		// Echo the ID it was asked with. The resolver draws a fresh one for
		// every query it forwards, so nothing here can know it in advance.
		out[0], out[1] = buf[0], buf[1]
		_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
		return
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
) -> []u8 {
	question := [1]dns.Question{{name = name, type = type, class = .IN}}
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

// An upstream's answer to `name`'s `type`, with QR, RD and RA set.
@(private)
test_reply :: proc(name: string, type: dns.Type, answers: ..dns.Record, rcode := dns.Rcode.No_Error) -> []u8 {
	question := [1]dns.Question{{name = name, type = type, class = .IN}}
	m := dns.Message {
		question = question[:],
		answer   = answers,
	}
	m.flags.qr = true
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
opt_with :: proc(code: dns.EDNS_Option_Code, data: []u8, udp_size: u16 = 1232, do_bit := false) -> dns.Record {
	opt := dns.make_opt(udp_size, do_bit)
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option{code = u16(code), data = data}
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
		time.sleep(time.Millisecond)
	}
	return predicate(data)
}

// A window-0 type bitmap (RFC 4034 section 4.1.2) holding `types`.
@(private)
type_bitmap :: proc(types: ..dns.Type) -> []u8 {
	bits := make([]u8, 32, context.temp_allocator)
	top := 0
	for t in types {
		bits[int(t) / 8] |= 0x80 >> (uint(t) % 8)
		top = max(top, int(t) / 8 + 1)
	}
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, 0, u8(top))
	append(&out, ..bits[:top])
	return out[:]
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
	append(&rdata, ..type_bitmap(..types))
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
