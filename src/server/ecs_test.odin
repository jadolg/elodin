package server

import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:upstream"

/*
EDNS Client Subnet on the way to an upstream.

An ECS option is a client saying which network the answer should be tailored
for, and forwarding one is only correct alongside the caching RFC 7871 section
7.3 describes - an entry per network, chosen by longest prefix match. This
server's cache key is the question plus DO and CD, so it has no such thing, and
the option is taken back out of every query on the way upstream instead.

What that has to hold against is a client naming somebody else's network: the
tailored answer would otherwise be filed under the bare question and handed to
everyone behind this resolver, and the client's claim about its own address
would have travelled to a public upstream under this server's name (section
11.1). So the mock below answers one address when it is told a subnet and
another when it is not, which makes the two halves visible at once - what the
upstream was told, and which of the two answers the next client is given.

Both ways of building the outgoing query are covered, because they differ:
`dnssec_upstream_query` rebuilds the message and copies the client's OPT data
across wholesale, where the plain path forwards the client's bytes as they
stand.
*/

// The address the mock serves when it is told a subnet, and the one it serves
// when it is not. Nothing distinguishes them but which question was asked.
@(private = "file")
TAILORED :: [4]u8{203, 0, 113, 9}
@(private = "file")
GLOBAL :: [4]u8{192, 0, 2, 1}

@(private = "file")
Ecs_Mock :: struct {
	socket:  net.UDP_Socket,
	name:    string,
	saw_ecs: bool,
	saw_do:  bool,
	served:  bool,
}

@(private = "file")
serve_ecs :: proc(x: ^Ecs_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE {
		return
	}
	m, derr := dns.decode_message(buf[:n], context.temp_allocator)
	if derr != .None {
		return
	}
	/*
	Every OPT record is walked, not just the first one `find_edns_option` stops
	at. A resolver reading these bytes is under no obligation to stop where this
	server's decoder stops, so a mock that looked only where the strip looks
	could not tell a query the strip cleaned from one still carrying the option
	somewhere the strip never reached.
	*/
	for rec in m.additional {
		if rec.type != .OPT {
			continue
		}
		rdata, is_opt := rec.data.(dns.Rdata_OPT)
		if !is_opt {
			continue
		}
		for o in rdata.options {
			if o.code == u16(dns.EDNS_Option_Code.Client_Subnet) {
				x.saw_ecs = true
			}
		}
	}
	x.saw_do = dns.edns_do(m)

	reply := scoped_reply(x.name, TAILORED if x.saw_ecs else GLOBAL)
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

// An OPT record carrying one ECS option for `prefix`/24.
@(private = "file")
ecs_opt :: proc(prefix: [4]u8) -> dns.Record {
	payload := make([]u8, 8, context.temp_allocator)
	payload[0], payload[1] = 0, 1 // FAMILY: IPv4
	payload[2] = 24 // SOURCE PREFIX-LENGTH
	payload[3] = 0 // SCOPE PREFIX-LENGTH
	pfx := prefix
	copy(payload[4:], pfx[:])
	options := make([]dns.EDNS_Option, 1, context.temp_allocator)
	options[0] = dns.EDNS_Option{code = u16(dns.EDNS_Option_Code.Client_Subnet), data = payload}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}
	return opt
}

@(private = "file")
a_query :: proc(name: string, additional: []dns.Record) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = .A, class = .IN}
	msg := dns.Message{id = 0x5150, question = questions, additional = additional}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// An A query, optionally carrying an ECS option naming `prefix`/24.
@(private = "file")
ecs_query :: proc(name: string, prefix: [4]u8, with_ecs: bool) -> []u8 {
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = ecs_opt(prefix) if with_ecs else dns.make_opt(1232, false)
	return a_query(name, additional)
}

@(private = "file")
scoped_reply :: proc(name: string, addr: [4]u8) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record{name = name, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = addr}}
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

// The first address in a response, which is the whole of what the mock varies.
@(private = "file")
answer_addr :: proc(wire: []u8) -> (addr: [4]u8, found: bool) {
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if derr != .None {
		return {}, false
	}
	for rec in m.answer {
		if a, is_a := rec.data.(dns.Rdata_A); is_a {
			return a.addr, true
		}
	}
	return {}, false
}

/*
A validator that can fetch nothing, borrowed from the query-ID cases.

The verdict is not what this file is about - a chain for a name the mock
invented could not be built from anything it would answer - and refusing to
fetch reaches the assertion, which is about what went out on the wire before any
of that happened.
*/
@(private = "file")
no_chain :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	return nil, false
}

@(private = "file")
Fixture :: struct {
	socket:  net.UDP_Socket,
	cfg:     config.Config,
	group:   ^upstream.Group,
	answers: ^cache.Cache,
	srv:     Server,
}

@(private = "file")
fixture_start :: proc(t: ^testing.T, f: ^Fixture, validating := false) -> bool {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return false
	}
	f.socket = socket
	// Only a bound on a hang, and past the upstream timeout below rather than
	// under it: see the note on `MOCK_RECV_TIMEOUT`.
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return false
	}

	f.cfg = config.default_config()
	f.cfg.log.queries = false
	f.cfg.cache.enabled = true
	f.cfg.dnssec.enabled = validating
	f.cfg.blocking.enabled = false
	f.cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
	f.cfg.upstream.attempts = 1
	f.cfg.upstream.timeout = 3 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	f.cfg.upstream.servers = servers

	// No cookie towards the upstream: it would add an option of its own to the
	// outgoing query, which has nothing to do with the one under test.
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
	if validating {
		f.srv.validator = dnssec.make_validator(no_chain, nil, dnssec.Options{})
	}
	return true
}

@(private = "file")
fixture_stop :: proc(f: ^Fixture) {
	if f.srv.validator != nil {
		dnssec.destroy_validator(f.srv.validator)
		f.srv.validator = nil
	}
	cache.destroy(f.answers)
	upstream.destroy_group(f.group)
	net.close(f.socket)
}

@(test)
test_a_client_subnet_scoped_answer_does_not_reach_other_clients :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f) {
		return
	}
	defer fixture_stop(&f)

	// One client asks with an ECS option naming a network that is not its own.
	// The mock serves TAILORED to anyone who names a subnet.
	x := Ecs_Mock{socket = f.socket, name = "cdn.example."}
	mock := thread.create_and_start_with_poly_data(&x, serve_ecs)
	first, _, first_ok := handle_query(
		&f.srv,
		ecs_query("cdn.example.", {198, 51, 100, 0}, true),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.served, "the mock upstream never answered")
	testing.expect(t, !x.saw_ecs, "the client's ECS option was forwarded to the upstream")

	// The client that asked gets the untailored answer too. Its claim about
	// where it is bought it nothing, which is the point of dropping the option
	// rather than acting on it.
	testing.expect(t, first_ok, "the first query produced nothing at all")
	if addr, found := answer_addr(first); testing.expect(t, found, "the first client got no address") {
		testing.expect_value(t, addr, GLOBAL)
	}

	/*
	A second client, on another address, asking without ECS at all. No mock is
	listening now, so what it gets is the entry the first query left behind -
	and that entry has to be an answer for everybody rather than one somebody
	chose. Which is what makes the cache key honest without carrying a subnet:
	nothing tailored ever reaches it.
	*/
	second, _, second_ok := handle_query(
		&f.srv,
		ecs_query("cdn.example.", {0, 0, 0, 0}, false),
		.UDP,
		"127.0.0.2:5555",
		context.temp_allocator,
	)
	testing.expect(t, second_ok, "the second query produced nothing at all")
	if addr, found := answer_addr(second); testing.expect(t, found, "the second client got no address") {
		testing.expectf(
			t,
			addr == GLOBAL,
			"an answer scoped to somebody else's subnet was served from the cache: %v",
			addr,
		)
	}
	free_all(context.temp_allocator)
}

/*
A subnet the strip cannot reach costs the client its answer, not everyone else
theirs.

`remove_edns_option` edits the first OPT record and no other, so an ECS option
in a second one would survive a removal that reported success. `handle_query`
turns that message away before any of this - FORMERR, as RFC 6891 section 6.1.1
says of it - so what this case pins is that the subnet never reaches the
upstream, whichever gate is the one that stops it.
*/
@(test)
test_an_unstrippable_client_subnet_is_not_forwarded :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f) {
		return
	}
	defer fixture_stop(&f)

	additional := make([]dns.Record, 2, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	additional[1] = ecs_opt({198, 51, 100, 0})
	out, outcome, ok := handle_query(
		&f.srv,
		a_query("cdn.example.", additional),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)

	testing.expect(t, mock_untouched(f.socket), "the query reached the upstream with a subnet still on it")
	testing.expect(t, ok, "the client was left with nothing at all")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err)
	free_all(context.temp_allocator)
}

/*
The same, for a subnet the decoder cannot see rather than one it can see in the
wrong place.

`decode_record` keeps RDATA it cannot parse as raw bytes rather than rejecting
the message, so an option list ending in a partial option header decodes to an
OPT record holding `Rdata_Raw` rather than an option list - and the ECS option
in front of that stump reads as absent to anything asking the decoded message,
`find_edns_option` included. It is not absent to the upstream, which walks the
same bytes and stops at the option it understands. So the query is stopped by
the `edns_opt_readable` gate rather than forwarded with the subnet still on it -
which it is whether or not the stump has a subnet in front of it, the case
`edns_opt_test.odin` pins from the other side.
*/
@(test)
test_a_client_subnet_behind_unreadable_opt_bytes_is_not_forwarded :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f) {
		return
	}
	defer fixture_stop(&f)

	// One well-formed ECS option, then three bytes of a fourth option header:
	// enough for `decode_rdata` to give up on the list, not enough to hide the
	// option from a resolver reading it the same way this one would have.
	raw := make([]u8, 4 + 8 + 3, context.temp_allocator)
	raw[0], raw[1] = 0, 8 // OPTION-CODE: Client Subnet
	raw[2], raw[3] = 0, 8 // OPTION-LENGTH
	raw[4], raw[5] = 0, 1 // FAMILY: IPv4
	raw[6] = 24 // SOURCE PREFIX-LENGTH
	raw[7] = 0 // SCOPE PREFIX-LENGTH
	raw[8], raw[9], raw[10], raw[11] = 198, 51, 100, 0
	raw[12], raw[13], raw[14] = 0, 3, 0 // an option header cut short

	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_Raw{data = raw}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = opt

	out, outcome, ok := handle_query(
		&f.srv,
		a_query("cdn.example.", additional),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)

	testing.expect(t, mock_untouched(f.socket), "the query reached the upstream with a subnet still on it")
	testing.expect(t, ok, "the client was left with nothing at all")
	testing.expect_value(t, outcome, Outcome.Failed)
	testing.expect_value(t, dns.peek_rcode(out), dns.Rcode.Form_Err)
	free_all(context.temp_allocator)
}

@(test)
test_a_client_subnet_does_not_survive_the_dnssec_rewrite :: proc(t: ^testing.T) {
	f: Fixture
	if !fixture_start(t, &f, validating = true) {
		return
	}
	defer fixture_stop(&f)

	x := Ecs_Mock{socket = f.socket, name = "cdn.example."}
	mock := thread.create_and_start_with_poly_data(&x, serve_ecs)
	// CD is left clear and the validator is in place, so the question is asked
	// again through `dnssec_upstream_query` rather than forwarded as it stands.
	handle_query(
		&f.srv,
		ecs_query("cdn.example.", {198, 51, 100, 0}, true),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.served, "the mock upstream never answered")
	// Without this the case could quietly become the plain forwarding one
	// above, and prove nothing about the path it is named for.
	testing.expect(t, x.saw_do, "the query did not go out through the DNSSEC rewrite")
	testing.expect(t, !x.saw_ecs, "the DNSSEC rewrite carried the client's ECS option upstream")
	free_all(context.temp_allocator)
}

// An OPT record carrying `n` ECS options at once, each naming a different /24.
@(private = "file")
ecs_opt_repeated :: proc(n: int) -> dns.Record {
	options := make([]dns.EDNS_Option, n, context.temp_allocator)
	for i in 0 ..< n {
		payload := make([]u8, 8, context.temp_allocator)
		payload[0], payload[1] = 0, 1 // FAMILY: IPv4
		payload[2] = 24 // SOURCE PREFIX-LENGTH
		payload[3] = 0 // SCOPE PREFIX-LENGTH
		payload[4], payload[5], payload[6] = 198, 51, u8(100 + i)
		options[i] = dns.EDNS_Option{code = u16(dns.EDNS_Option_Code.Client_Subnet), data = payload}
	}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}
	return opt
}

/*
The OPT record is not required to be the last thing in the additional section.

RFC 6891 section 6.1.1 puts one OPT in the additional section and says nothing
about where; a client is free to write it first and something else after it.
`remove_edns_option` rewrites the record in place and has the rest of the
section to carry past it, which is the part that would go wrong quietly - a
strip that reported success while leaving the option, or one that truncated
whatever followed.

Pinned rather than left to the round trip because a query shaped like this is
rare enough that no other test here builds one, and the failure it guards
against is the client's subnet reaching the upstream after this server decided
it had removed it.
*/
@(test)
test_a_client_subnet_is_stripped_from_an_opt_that_is_not_last :: proc(t: ^testing.T) {
	additional := make([]dns.Record, 2, context.temp_allocator)
	additional[0] = ecs_opt({198, 51, 100, 0})
	additional[1] = dns.Record {
		name  = "extra.example.",
		type  = .TXT,
		class = .IN,
		ttl   = 0,
		data  = dns.Rdata_TXT{strings = nil},
	}
	wire := a_query("cdn.example.", additional)

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, client_subnet_sent(decoded), "the subnet was not noticed at all")

	out, ok := dns.remove_edns_option(wire, .Client_Subnet, context.temp_allocator)
	if !testing.expect(t, ok, "the strip failed on an OPT that is not last") {
		return
	}
	after, aerr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, aerr, dns.Decode_Error.None)
	_, survived := dns.find_edns_option(after, .Client_Subnet)
	testing.expect(t, !survived, "the subnet survived the strip")
	// The record that followed the OPT is still there and still readable.
	testing.expect_value(t, len(after.additional), 2)
	free_all(context.temp_allocator)
}

/*
One OPT record may carry the option twice.

Nothing in RFC 6891 section 6.1.2 stops a client repeating an option inside one
OPT's RDATA, and `remove_edns_option` rebuilds that RDATA from the options it
kept rather than cutting the first match out of it - so both copies go. The
distinction worth pinning is against the neighbouring case: two ECS options in
*one* OPT record are strippable and the query is forwarded, while two OPT
*records* are not and the query is refused. A change that conflated the two
would either leak a subnet or start refusing ordinary queries.
*/
@(test)
test_a_repeated_client_subnet_in_one_opt_is_stripped_whole :: proc(t: ^testing.T) {
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = ecs_opt_repeated(2)
	wire := a_query("cdn.example.", additional)

	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, client_subnet_sent(decoded), "the repeated subnet was not noticed")

	out, ok := dns.remove_edns_option(wire, .Client_Subnet, context.temp_allocator)
	if !testing.expect(t, ok, "the strip failed on a repeated option") {
		return
	}
	after, _ := dns.decode_message(out, context.temp_allocator)
	_, survived := dns.find_edns_option(after, .Client_Subnet)
	testing.expect(t, !survived, "a second copy of the subnet survived the strip")
	testing.expect(t, !client_subnet_sent(after), "the stripped query still reports a subnet")
	free_all(context.temp_allocator)
}
