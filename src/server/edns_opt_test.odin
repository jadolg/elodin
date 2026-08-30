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
EDNS this server cannot account for, refused before it is read.

Two shapes reach `decode_message` intact and then hide an option from every
reader here: a second OPT record, which `find_opt` and `find_opt_span` both stop
short of, and an OPT whose RDATA is not a well-formed option list, which
`decode_record` keeps as raw bytes with the options in front of the fault
unreadable. Either one survives a strip that reports success, so `handle_query`
answers both FORMERR - RFC 6891 section 6.1.1, which permits exactly one OPT
record and an option list to be a list - before a cookie is looked for, a name
is looked up or a cache is consulted.

The cases below are the two properties that follow: what the gate keeps off the
wire (a client's cookie, the secret of the two options that stop here), and that
it holds whatever the cache would otherwise have answered. The client-subnet
half of the same gate is in `ecs_test.odin`.
*/

@(private = "file")
SERVED :: [4]u8{192, 0, 2, 7}

@(private = "file")
Opt_Mock :: struct {
	socket:     net.UDP_Socket,
	name:       string,
	saw_cookie: bool,
	served:     bool,
}

@(private = "file")
serve_opt :: proc(x: ^Opt_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE {
		return
	}
	m, derr := dns.decode_message(buf[:n], context.temp_allocator)
	if derr != .None {
		return
	}
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for o in rdata.options {
			if o.code == u16(dns.EDNS_Option_Code.Cookie) {
				x.saw_cookie = true
			}
		}
	}

	reply := opt_reply(x.name)
	if len(reply) > len(buf) {
		return
	}
	out: [4096]u8
	copy(out[:], reply)
	out[0], out[1] = buf[0], buf[1]
	_, serr := net.send_udp(x.socket, out[:len(reply)], remote)
	x.served = serr == nil
	free_all(context.temp_allocator)
}

@(private = "file")
opt_reply :: proc(name: string) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record{name = name, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = SERVED}}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = .A, class = .IN}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	msg := dns.Message{question = question, answer = answer, additional = additional}
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
opt_query :: proc(name: string, additional: []dns.Record) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = .A, class = .IN}
	msg := dns.Message{id = 0x4242, question = questions, additional = additional}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// An OPT record carrying one eight-byte client cookie.
@(private = "file")
cookie_opt :: proc() -> dns.Record {
	payload := make([]u8, 8, context.temp_allocator)
	for i in 0 ..< len(payload) {
		payload[i] = u8(0xa0 + i)
	}
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option{code = u16(dns.EDNS_Option_Code.Cookie), data = payload}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}
	return opt
}

/*
An OPT record whose option list stops in the middle of an option header, with
nothing else in it.

Three bytes are not enough for the four an option header takes, so
`decode_rdata` gives up on the list and `decode_record` keeps the RDATA as raw
bytes - the shape the gate refuses. Deliberately empty of anything else: what it
pins is that the refusal is about the RDATA and not about what happens to be
inside it.
*/
@(private = "file")
truncated_opt :: proc() -> dns.Record {
	raw := make([]u8, 3, context.temp_allocator)
	raw[0], raw[1] = 0, 12 // OPTION-CODE: Padding, and then nothing to say how long
	raw[2] = 0
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_Raw{data = raw}
	return opt
}

@(private = "file")
Opt_Fixture :: struct {
	socket:  net.UDP_Socket,
	cfg:     config.Config,
	group:   ^upstream.Group,
	answers: ^cache.Cache,
	srv:     Server,
}

@(private = "file")
opt_fixture_start :: proc(t: ^testing.T, f: ^Opt_Fixture) -> bool {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return false
	}
	f.socket = socket
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return false
	}

	f.cfg = config.default_config()
	f.cfg.log.queries = false
	f.cfg.cache.enabled = true
	f.cfg.dnssec.enabled = false
	f.cfg.blocking.enabled = false
	f.cfg.upstream.strategy = .Failover
	f.cfg.upstream.attempts = 1
	f.cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	f.cfg.upstream.servers = servers

	// No cookie of this server's own towards the upstream: the only cookie
	// these cases are about is the client's.
	group, gerr := upstream.make_group(f.cfg.upstream, nil, context.allocator, false)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		return false
	}
	f.group = group
	f.answers = cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	f.srv = Server {
		cfg     = &f.cfg,
		group   = f.group,
		answers = f.answers,
	}
	return true
}

@(private = "file")
opt_fixture_stop :: proc(f: ^Opt_Fixture) {
	cache.destroy(f.answers)
	upstream.destroy_group(f.group)
	net.close(f.socket)
}

/*
A cookie in a second OPT record does not reach the upstream.

`inspect_cookie` reads the first OPT record and no other, so a cookie in a
second one is a cookie this server never notices it was sent - the strip in
`resolve_query` is asked for only when `cookie.sent`, and it edits the first
record anyway. Forwarded, that hands a secret shared between the client and this
server to a third party that cannot check it and did not need it, which is the
whole of what the cookie strip exists to prevent.

The first half of the case is the one that keeps the gate honest: an ordinary
query with one OPT record and a cookie in it is answered, and the cookie still
does not reach the upstream. A gate that refused that too would close the leak
by turning away every client that uses cookies.
*/
@(test)
test_a_cookie_in_a_second_opt_record_is_not_forwarded :: proc(t: ^testing.T) {
	f: Opt_Fixture
	if !opt_fixture_start(t, &f) {
		return
	}
	defer opt_fixture_stop(&f)

	// One OPT record, a cookie in it: answered, and stripped on the way out.
	{
		x := Opt_Mock{socket = f.socket, name = "cookie.example."}
		mock := thread.create_and_start_with_poly_data(&x, serve_opt)
		single := make([]dns.Record, 1, context.temp_allocator)
		single[0] = cookie_opt()
		out, outcome, ok := handle_query(
			&f.srv,
			opt_query("cookie.example.", single),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		thread.join(mock)
		thread.destroy(mock)

		testing.expect(t, x.served, "the mock upstream never answered an ordinary cookie query")
		testing.expect(t, !x.saw_cookie, "the client's cookie was forwarded to the upstream")
		testing.expect(t, ok, "an ordinary cookie query produced nothing at all")
		testing.expect_value(t, outcome, Outcome.Forwarded)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.No_Error)
	}

	// Two OPT records, the cookie in the second: refused, and nothing sent.
	{
		x := Opt_Mock{socket = f.socket, name = "hidden.example."}
		// The mock is here to report that nothing arrived, so it should not hold
		// the run open for the two seconds a real exchange is allowed.
		_ = net.set_option(f.socket, .Receive_Timeout, 200 * time.Millisecond)
		mock := thread.create_and_start_with_poly_data(&x, serve_opt)
		pair := make([]dns.Record, 2, context.temp_allocator)
		pair[0] = dns.make_opt(1232, false)
		pair[1] = cookie_opt()
		out, outcome, ok := handle_query(
			&f.srv,
			opt_query("hidden.example.", pair),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		thread.join(mock)
		thread.destroy(mock)

		testing.expect(t, !x.saw_cookie, "the client's cookie reached the upstream in a second OPT record")
		testing.expect(t, !x.served, "the query was forwarded instead of being refused")
		testing.expect(t, ok, "the client was left with nothing at all")
		testing.expect_value(t, outcome, Outcome.Failed)
		testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err)
	}
	free_all(context.temp_allocator)
}

/*
An OPT this decoder cannot walk is refused whether or not anything is hiding
behind the fault.

Worth pinning as its own case because it is the cost of the gate rather than its
benefit: a client whose OPT record is merely malformed loses the answer, not
only the option it mangled. That is what RFC 6891 section 6.1.1 asks for, and
the alternative is guessing at bytes this server has already established it
cannot read - but it is broader than the leak that motivated the gate, so it
should fail loudly if anyone narrows it by accident.
*/
@(test)
test_an_unreadable_opt_is_refused_with_nothing_hidden_in_it :: proc(t: ^testing.T) {
	f: Opt_Fixture
	if !opt_fixture_start(t, &f) {
		return
	}
	defer opt_fixture_stop(&f)
	_ = net.set_option(f.socket, .Receive_Timeout, 200 * time.Millisecond)

	x := Opt_Mock{socket = f.socket, name = "stump.example."}
	mock := thread.create_and_start_with_poly_data(&x, serve_opt)
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = truncated_opt()
	out, outcome, ok := handle_query(
		&f.srv,
		opt_query("stump.example.", additional),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, !x.served, "an OPT record this server cannot read was forwarded")
	testing.expect(t, ok, "the client was left with nothing at all")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err)
	free_all(context.temp_allocator)
}

/*
The refusal is a property of the message, not of what the cache happens to hold.

The gate sits in `handle_query`, ahead of the rewrites, the blocklist, the
special-use table and the cache lookup, so the same bytes get the same answer
twice. Below any of those, a client sending one malformed query twice would be
told FORMERR on the miss and handed an answer on the hit - two rcodes for one
message, decided by what some other client asked for earlier.
*/
@(test)
test_a_second_opt_record_is_refused_whatever_the_cache_holds :: proc(t: ^testing.T) {
	f: Opt_Fixture
	if !opt_fixture_start(t, &f) {
		return
	}
	defer opt_fixture_stop(&f)

	// A plain query for the name first, so there is an entry to be tempted by.
	warm := Opt_Mock{socket = f.socket, name = "warm.example."}
	mock := thread.create_and_start_with_poly_data(&warm, serve_opt)
	plain := make([]dns.Record, 1, context.temp_allocator)
	plain[0] = dns.make_opt(1232, false)
	_, first, _ := handle_query(
		&f.srv,
		opt_query("warm.example.", plain),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)
	if !testing.expect(t, warm.served, "the mock upstream never answered the first query") {
		return
	}
	testing.expect_value(t, first, Outcome.Forwarded)

	// The same name, now cached, asked with two OPT records. No mock is
	// listening, so a query that got past the gate would be answered from the
	// entry rather than time out - which is the mistake being guarded against.
	pair := make([]dns.Record, 2, context.temp_allocator)
	pair[0] = dns.make_opt(1232, false)
	pair[1] = cookie_opt()
	out, outcome, ok := handle_query(
		&f.srv,
		opt_query("warm.example.", pair),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, ok, "the client was left with nothing at all")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err)
	if m, derr := dns.decode_message(out, context.temp_allocator); derr == .None {
		testing.expect_value(t, len(m.answer), 0)
	}
	free_all(context.temp_allocator)
}
