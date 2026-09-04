package server

import "core:mem"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
Per-domain upstreams: `upstream.zones` in the configuration, `routes.odin` here.

The feature is one sentence - the client's question goes to the route's servers
rather than to the default ones - and three consequences that are not: the chain
walk stays on the default group, a routed zone is served insecure, and a routed
zone may answer with private addresses. Each of those is checked on its own
below, because each is a different way for the sentence to be true while the
deployment it was written for still does not work.
*/

@(private = "file")
Route_Mock :: struct {
	socket:   net.UDP_Socket,
	reply:    []u8,
	asked:    bool,
	// What was asked, for the test to read once the mock has been joined. It is
	// held in `name_buf` rather than pointing at whatever memory the question
	// was decoded into, that memory belonging to the mock thread.
	name:     string,
	// The question this mock is waiting for. Every case sets it: a mock that
	// answers whatever arrives first is one another test's stray retry can be
	// recorded by, which is the flake `serve_route` below describes.
	want:     string,
	name_buf: [512]u8,
}

/*
Answer one query, recording the name it asked for.

The name is what separates this from the mocks in the other files: a test that
only asks whether a socket was written to cannot tell a routed question from the
chain lookups the validator makes on its own account, and those two go to
different groups on purpose.

`want` skips packets asking about anything else rather than answering them, and
every case names one. The tests in this package run in parallel against sockets
bound to port zero, and a port a finished test's mock has released is one the
kernel can hand to the next test that asks - so a query another case's server is
still retrying can arrive here, be recorded as the question this case asked, and
fail it on a name it never mentioned. Waiting for the name turns that into a
packet nobody answered, which is what it is. Nothing about how many sockets a
case binds changes that, the stray packet coming from outside the case
altogether, so there is no shape of case that wants the unfiltered reading.

The name is copied into `name_buf` on the way out, and that is the part not to
undo. `thread.create_and_start_with_poly_data` is called with no `init_context`,
which per `thread.Thread.init_context` gives this procedure a temporary
allocator of its own that the runtime destroys when the thread dies - so a name
decoded into temp memory here is freed by `thread.join` returning, which is
precisely when the test reads it. That read is a use-after-free; it was one for
as long as this mock has existed, and it segfaulted the test runner on arm64
while passing on amd64, the way that class of bug does. `name_buf` lives in the
caller's own frame, which outlives the mock by construction.

The stack arena below keeps that honest rather than merely fixed: nothing this
procedure decodes can outlive the arena it was decoded into, so the copy is the
only way anything leaves. `peek_question` reads one name and stops, where a
whole-message decode would allocate per record for a reply the mock never looks
at.
*/
@(private = "file")
serve_route :: proc(x: ^Route_Mock) {
	scratch: mem.Arena
	backing: [4096]u8
	mem.arena_init(&scratch, backing[:])
	buf: [4096]u8
	if len(x.reply) > len(buf) {
		return
	}
	for {
		n, remote, err := net.recv_udp(x.socket, buf[:])
		if err != nil {
			// The receive timeout expiring, which is how this returns when the
			// question it wants never arrives.
			return
		}
		// A datagram too short to be a question is skipped rather than taken as
		// the end of the wait: giving up on one would hand a stray runt from
		// another parallel test the power to fail this case on "never asked",
		// which is the flake the loop exists to close.
		if n < dns.HEADER_SIZE {
			continue
		}
		free_all(mem.arena_allocator(&scratch))
		q, ok := dns.peek_question(buf[:n], mem.arena_allocator(&scratch))
		if !ok || !dns.name_equal_fold(q.name, x.want) {
			continue
		}
		x.name = string(x.name_buf[:copy(x.name_buf[:], q.name)])
		x.asked = true
		out: [4096]u8
		copy(out[:], x.reply)
		out[0], out[1] = buf[0], buf[1]
		_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
		return
	}
}

/*
Whether nothing asked `socket` about `name`.

`mock_untouched` reads one packet and calls any packet at all a leak, which is
sound for a socket nothing else in the process knows about and not for one whose
port may have been another test's a moment ago - see `serve_route` above. This
reads for as long as that one does and holds only the question this case asked
against the socket.
*/
@(private = "file")
route_mock_quiet :: proc(socket: net.UDP_Socket, name: string) -> bool {
	_ = net.set_option(socket, .Receive_Timeout, 20 * time.Millisecond)
	defer _ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	buf: [4096]u8
	for {
		n, _, err := net.recv_udp(socket, buf[:])
		if err != nil {
			return true
		}
		// Skipped rather than read as silence, the same way `serve_route` skips
		// it: a runt ahead of a real leak would otherwise report the socket
		// quiet with the leaked query still sitting in its buffer.
		if n < dns.HEADER_SIZE {
			continue
		}
		// The temp allocator is safe here where it is not in `serve_route`: this
		// runs on the test's own thread, and nothing decoded escapes the call.
		if q, ok := dns.peek_question(buf[:n], context.temp_allocator);
		   ok && dns.name_equal_fold(q.name, name) {
			return false
		}
	}
}

// `type` defaults to the `A` every case here asked for before the apex `DS`
// carve-out gave one of them a reason to ask for something else.
@(private = "file")
route_query :: proc(name: string, type: dns.Type = .A) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{id = 0x7f7f, question = questions}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
route_reply :: proc(name: string, addr: [4]u8) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record{name = name, type = .A, class = .IN, ttl = 60, data = dns.Rdata_A{addr = addr}}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = .A, class = .IN}
	msg := dns.Message{question = question, answer = answer}
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
An empty answer that echoes the question, for the types with no `Rdata` here.

`upstream.response_matches` compares the reply's first question with the query's
name, type and class and drops a reply that differs, so a mock standing in for
the parent of a routed zone cannot answer a `DS` query with the `A` record
`route_reply` builds - the reply would be discarded as an off-path packet and
the test would read as the upstream never having answered.
*/
@(private = "file")
route_reply_nodata :: proc(name: string, type: dns.Type, rcode := dns.Rcode.No_Error) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{question = question}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	msg.flags.rcode = u8(rcode)
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
A `DS` answer, which is the reply a parent that does signs its delegation gives.

`Rdata_Raw` rather than a modelled DS: what the carve-out reads is the record's
type and nothing inside it, and a digest this test invented would be no more
checkable than an opaque one. The bytes are a well-formed DS RDATA all the same -
key tag, algorithm 8, digest type 2, and a SHA-256-sized digest - so a decoder
walking the answer section finds a record it can measure rather than one it has
to reject.
*/
@(private = "file")
route_reply_ds :: proc(name: string) -> []u8 {
	digest := make([]u8, 36, context.temp_allocator)
	digest[0], digest[1] = 0x30, 0x39
	digest[2], digest[3] = 8, 2
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = name,
		type  = .DS,
		class = .IN,
		ttl   = 3600,
		data  = dns.Rdata_Raw{data = digest},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = .DS, class = .IN}
	msg := dns.Message{question = question, answer = answer}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

// One UDP upstream on loopback, as `upstream.servers` would name it.
@(private = "file")
mock_group :: proc(t: ^testing.T, cfg: config.Upstream_Config, port: int) -> ^upstream.Group {
	one := cfg
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = port}
	one.servers = servers
	group, gerr := upstream.make_group(one, nil, context.allocator, false)
	testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr)
	return group
}

@(private = "file")
forwarding_config :: proc() -> config.Config {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second
	return cfg
}

/*
Longest match, so a route can be carved out of a route.

`dev.corp.example.` is the case an operator hits second: the domain controller
answers `corp.example`, a lab server answers everything under `dev`, and the
second route has to win for its own names without the first one having to be
rewritten to exclude them. Both directions are asserted - the specific route
takes what it claims, the general route keeps the rest - because a selector that
simply preferred the last entry would pass the first half alone.
*/
@(test)
test_the_longest_route_wins :: proc(t: ^testing.T) {
	cfg := config.default_config()
	broad := upstream.Group{}
	narrow := upstream.Group{}
	fallback := upstream.Group{}

	routes := []Zone_Route {
		{domains = []string{"corp.example."}, group = &broad},
		{domains = []string{"dev.corp.example."}, group = &narrow},
	}
	s := Server {
		cfg    = &cfg,
		group  = &fallback,
		routes = routes,
	}

	testing.expect(t, route_group(&s, "nas.corp.example.", .A) == &broad, "the zone's own route did not answer for it")
	testing.expect(t, route_group(&s, "corp.example.", .A) == &broad, "the apex did not follow its route")
	testing.expect(t, route_group(&s, "build.dev.corp.example.", .A) == &narrow, "the longer route did not win")
	testing.expect(t, route_group(&s, "dev.corp.example.", .A) == &narrow, "the longer route did not take its own apex")

	// Outside every route, and the two ways to be outside one: a different zone,
	// and a name that merely ends in the same bytes without a label break.
	testing.expect(t, route_group(&s, "example.com.", .A) == &fallback, "an unrouted name left the default group")
	testing.expect(t, route_group(&s, "notcorp.example.", .A) == &fallback, "a suffix match was treated as a subtree")

	// DNS names compare without regard to case, and nothing lowercases the
	// question on the way in - the response echoes it back as the client spelled
	// it - so the match has to fold case itself.
	testing.expect(t, route_group(&s, "NAS.Corp.Example.", .A) == &broad, "the match did not fold case")

	// A server with no routes configured at all is every deployment that
	// existed before this feature: everything goes to the default group.
	plain := Server {
		cfg   = &cfg,
		group = &fallback,
	}
	testing.expect(t, route_group(&plain, "nas.corp.example.", .A) == &fallback, "a server with no routes routed something")
	free_all(context.temp_allocator)
}

/*
The apex `DS` goes to whoever answers the parent, which is not always the default
group.

`test_a_client_ds_query_at_a_routed_apex_leaves_the_route` below drives the
carve-out through the resolver against the deployment it was written for, where
the parent is `arpa.`, nothing routes it, and "the parent" and "the default
group" are the same upstream. This is the selector on its own, on the fixture
that tells those two apart: `corp.example.` on the domain controller and
`dev.corp.example.` on a lab server, where the delegation `dev.corp.example. DS`
asks about is held by the domain controller and by nothing else. Sending it to
the public upstream would satisfy the sentence in issue #227 and still hand the
stub an NXDOMAIN for a zone that exists, so the two halves are asserted apart.

The single-label route is the edge the walk up has to survive: an internal
`.test` zone's parent is the root, which is refused as a route domain at load,
so `zone_route` finds nothing for it and the default group answers.
*/
@(test)
test_an_apex_ds_is_asked_of_the_parents_own_upstream :: proc(t: ^testing.T) {
	cfg := config.default_config()
	broad := upstream.Group{}
	narrow := upstream.Group{}
	lab := upstream.Group{}
	fallback := upstream.Group{}

	s := Server {
		cfg    = &cfg,
		group  = &fallback,
		routes = []Zone_Route {
			{domains = []string{"corp.example."}, group = &broad},
			{domains = []string{"dev.corp.example."}, group = &narrow},
			{domains = []string{"test."}, group = &lab},
		},
	}

	// The apex of the outermost route: `example.` is routed nowhere, so the
	// parent's upstream is the default one.
	testing.expect(t, route_group(&s, "corp.example.", .DS) == &fallback, "the apex DS followed its own route")
	testing.expect(t, route_group(&s, "CORP.Example.", .DS) == &fallback, "the apex DS match did not fold case")

	// The apex of a route carved out of another route: the parent is routed, and
	// the machine it points at is the one holding that delegation.
	testing.expect(
		t,
		route_group(&s, "dev.corp.example.", .DS) == &broad,
		"the nested apex DS did not go to the parent zone's own upstream",
	)

	// A route whose parent is the root, which no route can claim.
	testing.expect(t, route_group(&s, "test.", .DS) == &fallback, "a single-label route's apex DS did not fall back")

	// Everything the carve-out is not: a DS below the apex, the apex DNSKEY, and
	// the apex under any other type.
	testing.expect(t, route_group(&s, "nas.corp.example.", .DS) == &broad, "a DS below the apex left the route")
	testing.expect(t, route_group(&s, "corp.example.", .DNSKEY) == &broad, "the apex DNSKEY left the route")
	testing.expect(t, route_group(&s, "corp.example.", .SOA) == &broad, "the apex SOA left the route")

	// An unrouted name is not an apex, whatever the type: the DS for a public
	// zone goes where every other question about it goes.
	testing.expect(t, route_group(&s, "example.com.", .DS) == &fallback, "an unrouted DS moved")
	testing.expect(t, route_group(&s, "notcorp.example.", .DS) == &fallback, "a suffix match was treated as an apex")
	free_all(context.temp_allocator)
}

/*
The whole point, end to end: the routed question reaches the routed server, and
the default upstream never hears the name.

Both halves matter and the second is the one that closes issue #200. A route
that sent the query to the router *as well* would keep the zone resolving and go
on telling a public resolver what this network calls its printer, which is the
leak RFC 8375 section 3 is about.
*/
@(test)
test_a_routed_question_reaches_its_own_upstream_and_not_the_default :: proc(t: ^testing.T) {
	def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
		return
	}
	defer net.close(def_socket)
	def_bound, _ := net.bound_endpoint(def_socket)

	route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
		return
	}
	defer net.close(route_socket)
	_ = net.set_option(route_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	route_bound, _ := net.bound_endpoint(route_socket)

	cfg := forwarding_config()
	group := mock_group(t, cfg.upstream, def_bound.port)
	defer upstream.destroy_group(group)
	routed := mock_group(t, cfg.upstream, route_bound.port)
	defer upstream.destroy_group(routed)

	s := Server {
		cfg    = &cfg,
		group  = group,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
	}

	x := Route_Mock {
		socket = route_socket,
		reply  = route_reply("nas.corp.example.", {10, 0, 0, 7}),
		want   = "nas.corp.example.",
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_route)
	out, _, ok := handle_query(&s, route_query("nas.corp.example."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect(t, x.asked, "the routed upstream was never asked")
	testing.expect_value(t, x.name, "nas.corp.example.")
	testing.expect(
		t,
		route_mock_quiet(def_socket, "nas.corp.example."),
		"the name leaked to the default upstream as well",
	)

	decoded, derr2 := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr2, dns.Decode_Error.None)
	found := false
	for rec in decoded.answer {
		if a, is_a := rec.data.(dns.Rdata_A); is_a {
			found = true
			testing.expect_value(t, a.addr, [4]u8{10, 0, 0, 7})
		}
	}
	testing.expect(t, found, "the routed server's answer did not reach the client")
	free_all(context.temp_allocator)
}

/*
The other side of the same switch: a name no route claims still goes to
`upstream.servers`.

Worth its own case rather than being read off the one above. A selector that
matched everything would pass that test and break every name the resolver has
ever answered, and the symptom - all public names now going to the router - is
one the routed zone's own test cannot see.
*/
@(test)
test_an_unrouted_question_still_goes_to_the_default_upstream :: proc(t: ^testing.T) {
	def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
		return
	}
	defer net.close(def_socket)
	_ = net.set_option(def_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	def_bound, _ := net.bound_endpoint(def_socket)

	route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
		return
	}
	defer net.close(route_socket)
	route_bound, _ := net.bound_endpoint(route_socket)

	cfg := forwarding_config()
	group := mock_group(t, cfg.upstream, def_bound.port)
	defer upstream.destroy_group(group)
	routed := mock_group(t, cfg.upstream, route_bound.port)
	defer upstream.destroy_group(routed)

	s := Server {
		cfg    = &cfg,
		group  = group,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
	}

	x := Route_Mock {
		socket = def_socket,
		reply  = route_reply("www.example.com.", {93, 184, 216, 34}),
		want   = "www.example.com.",
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_route)
	_, _, ok := handle_query(&s, route_query("www.example.com."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, ok, "nothing came back at all")
	testing.expect(t, x.asked, "the default upstream was never asked")
	testing.expect_value(t, x.name, "www.example.com.")
	testing.expect(
		t,
		route_mock_quiet(route_socket, "www.example.com."),
		"an unrouted name was sent to the route's server",
	)
	free_all(context.temp_allocator)
}

/*
The one question a client asks that does not follow the route: `DS` at the apex.

Issue #227. A route sends the client's own questions to the local authority, and
a validating stub below this server asks `home.arpa. DS` for itself on its way
down from `arpa.`. The router the route points at is authoritative for
`home.arpa.` and answers that out of its own zone - an unsigned NODATA, no NSEC
- while the signed proof that the delegation carries no DS lives in `arpa.` and
nowhere else. The stub sees a chain broken rather than proved absent, which is
Bogus, which is SERVFAIL for every name in the zone: the failure RFC 8375
section 4 item 4.B carves the apex `DS` out of the MUST NOT to prevent, and the
one `special_use_zone` and `validator_query` already carve out here.

`home.arpa.` with `special_use.home_arpa` off is the exact configuration the
README recommends for that deployment - the key on refuses a route for the zone
at load - so it is the fixture, rather than the `corp.example.` the other cases
use.

Four cases, because the carve-out has to be that narrow. A name below the apex
is a question about a name that exists nowhere but this network, and its answer
really is on the router. `DNSKEY` at the apex is the zone's own data, so the
authority for the zone is the right place to ask even though `DS` beside it is
not. And every other type at the apex - `A` stands in for them - is the ordinary
routed question this feature exists for.
*/
@(test)
test_a_client_ds_query_at_a_routed_apex_leaves_the_route :: proc(t: ^testing.T) {
	Case :: struct {
		name:     string,
		type:     dns.Type,
		to_route: bool,
	}
	cases := []Case {
		{"home.arpa.", .DS, false},
		{"nas.home.arpa.", .DS, true},
		{"home.arpa.", .DNSKEY, true},
		{"home.arpa.", .A, true},
	}

	for c in cases {
		def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
			return
		}
		defer net.close(def_socket)
		_ = net.set_option(def_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
		def_bound, _ := net.bound_endpoint(def_socket)

		route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
			return
		}
		defer net.close(route_socket)
		_ = net.set_option(route_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
		route_bound, _ := net.bound_endpoint(route_socket)

		cfg := forwarding_config()
		group := mock_group(t, cfg.upstream, def_bound.port)
		defer upstream.destroy_group(group)
		routed := mock_group(t, cfg.upstream, route_bound.port)
		defer upstream.destroy_group(routed)

		s := Server {
			cfg    = &cfg,
			group  = group,
			routes = []Zone_Route{{domains = []string{"home.arpa."}, group = routed}},
		}

		x := Route_Mock {
			socket = route_socket if c.to_route else def_socket,
			reply  = route_reply_nodata(c.name, c.type),
			want   = c.name,
		}
		mock := thread.create_and_start_with_poly_data(&x, serve_route)
		_, _, ok := handle_query(&s, route_query(c.name, c.type), .UDP, "127.0.0.1:5555", context.temp_allocator)
		thread.join(mock)
		thread.destroy(mock)

		testing.expectf(t, ok, "nothing came back at all for %s %s", dns.type_name(c.type), c.name)
		testing.expectf(
			t,
			x.asked,
			"%s %s did not reach the %s upstream",
			dns.type_name(c.type),
			c.name,
			"routed" if c.to_route else "default",
		)
		testing.expect_value(t, x.name, c.name)
		testing.expectf(
			t,
			route_mock_quiet(route_socket if !c.to_route else def_socket, c.name),
			"%s %s was sent to the %s upstream as well",
			dns.type_name(c.type),
			c.name,
			"routed" if !c.to_route else "default",
		)
	}
	free_all(context.temp_allocator)
}

/*
The parent keeps the question only by proving the delegation carries no DS.

The other half of the carve-out above. Sending the apex `DS` to the parent is
worth doing for one answer - a NODATA, the proof that the delegation is insecure,
which is `home.arpa.`'s answer from `arpa.` and the whole of what RFC 8375
section 4 item 4.B asks to be fetched. Every other *statement about the
delegation* is the route's to give, and each of the three here is a deployment
that breaks if it is not:

  - *No such name.* An internal `corp.example.com` under a public, signed
    `example.com` that delegates no `corp`. The parent answers, with a signature
    over it, that the name does not exist. Passing that on is worse than the
    answer it replaced: an unsigned NODATA from the domain controller leaves a
    lenient validator free to call the zone unsigned and resolve it, while a
    signed proof of non-existence takes that away - and a validator implementing
    RFC 8020 reads it as proof that every name under the apex is gone with it.
  - *A `DS` RRset.* Split horizon over a zone that really is delegated and signed
    in public, routed to an internal view that is not the signed one. Handing the
    client the public DS makes it demand a `DNSKEY` the internal view has no
    matching key for, and Bogus is what it gets - where the same deployment
    resolved before the carve-out existed.

  - *SERVFAIL.* An upstream with an ACL, or a CPE resolver that answers every
    `DS` query it does not understand with a refusal. It says nothing about the
    delegation, so the route answers - the one place this file reads a client's
    rcode the way `upstream.resolve_answerable` reads its own rather than passing
    it on, and `parent_answers_apex_ds` argues why.

All four cases run against one fixture and differ only in what the parent says,
which is the point: what the route does has to follow from the parent's answer
and from nothing else. `apex_ds_off_route` and `parent_answers_apex_ds` argue
each of them in full.
*/
@(test)
test_an_apex_ds_goes_back_on_the_route_unless_the_parent_proves_no_ds :: proc(t: ^testing.T) {
	Case :: struct {
		// What the parent's group says about `corp.example. DS`.
		what:     string,
		parent:   dns.Rcode,
		// A `DS` RRset in the answer rather than a NODATA, which is a parent
		// that delegates the zone and signs the delegation.
		signed:   bool,
		to_route: bool,
		// What the client is handed, which is the last upstream to speak.
		client:   dns.Rcode,
	}
	cases := []Case {
		{"no such name", .NX_Domain, false, true, .No_Error},
		{"a DS RRset", .No_Error, true, true, .No_Error},
		{"no DS at the delegation", .No_Error, false, false, .No_Error},
		/*
		SERVFAIL says nothing about the delegation, so the route answers it - the
		reading `parent_answers_apex_ds` takes from
		`upstream.resolve_answerable` and the one place this file departs from
		"the rcode is the client's answer". An upstream with an ACL, or a CPE
		resolver that mangles every `DS` it meets, must not take an internal zone
		down with it.
		*/
		{"SERVFAIL", .Serv_Fail, false, true, .No_Error},
	}

	for c in cases {
		def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
			return
		}
		defer net.close(def_socket)
		_ = net.set_option(def_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
		def_bound, _ := net.bound_endpoint(def_socket)

		route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
			return
		}
		defer net.close(route_socket)
		_ = net.set_option(route_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
		route_bound, _ := net.bound_endpoint(route_socket)

		cfg := forwarding_config()
		group := mock_group(t, cfg.upstream, def_bound.port)
		defer upstream.destroy_group(group)
		routed := mock_group(t, cfg.upstream, route_bound.port)
		defer upstream.destroy_group(routed)

		s := Server {
			cfg    = &cfg,
			group  = group,
			routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
		}

		parent := Route_Mock {
			socket = def_socket,
			reply  = route_reply_ds("corp.example.") if c.signed else route_reply_nodata("corp.example.", .DS, c.parent),
			want   = "corp.example.",
		}
		authority := Route_Mock {
			socket = route_socket,
			reply  = route_reply_nodata("corp.example.", .DS),
			want   = "corp.example.",
		}
		parent_mock := thread.create_and_start_with_poly_data(&parent, serve_route)
		/*
		The route's mock is only started for the case that expects it. A thread
		blocked on a socket nothing sends to would hold the test open for
		`MOCK_RECV_TIMEOUT`, and the assertion that it stayed quiet is
		`route_mock_quiet` reading the socket itself - which cannot be done from
		two places at once.
		*/
		route_thread: ^thread.Thread
		if c.to_route {
			route_thread = thread.create_and_start_with_poly_data(&authority, serve_route)
		}
		out, _, ok := handle_query(
			&s,
			route_query("corp.example.", .DS),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		thread.join(parent_mock)
		thread.destroy(parent_mock)
		if route_thread != nil {
			thread.join(route_thread)
			thread.destroy(route_thread)
		}

		if !testing.expectf(t, ok, "nothing came back at all for a parent that said %s", c.what) {
			return
		}
		testing.expectf(t, parent.asked, "the parent's group was not asked at all (%s)", c.what)
		testing.expectf(
			t,
			authority.asked == c.to_route,
			"with the parent answering %s the route was %sasked",
			c.what,
			"not " if c.to_route else "",
		)
		if !c.to_route {
			testing.expect(
				t,
				route_mock_quiet(route_socket, "corp.example."),
				"an answer that was the parent's to give was re-asked down the route",
			)
		}

		// What the client is handed: the answer of whichever upstream was asked
		// last, so never the parent's NXDOMAIN once the route has spoken for the
		// zone - and never the parent's DS either, which is the half of this a
		// rcode assertion alone would miss.
		decoded, derr2 := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr2, dns.Decode_Error.None)
		testing.expect_value(t, dns.Rcode(decoded.flags.rcode), c.client)
		if c.to_route {
			for rec in decoded.answer {
				testing.expectf(
					t,
					rec.type != .DS,
					"the parent's DS reached the client for a zone the route answers (%s)",
					c.what,
				)
			}
		}
	}
	free_all(context.temp_allocator)
}

/*
A parent's group that does not answer at all also puts the question on the route.

The fourth arrangement, and the one that decides whether a routed zone still
stands on its own. Before the carve-out the apex `DS` went to the local
authority like every other question about the zone, so the public upstream being
down, unreachable, or absent from the network entirely had no bearing on it. Read
as an rcode test alone the carve-out would hand that dependency back: one outage
out there, and a validating client below here gets SERVFAIL for the apex `DS`,
which is a broken chain and SERVFAIL for every name in an internal zone whose
authority is answering perfectly well - the failure the carve-out exists to
prevent, arriving by the road it opened.

The parent's socket is bound and nobody serves it, which is what an upstream
that has gone away looks like from here, and the timeout is cut so the case does
not sit out `forwarding_config`'s three seconds. The control is
`test_an_apex_ds_goes_back_on_the_route_unless_the_parent_proves_no_ds` above: a
parent that answers the proof keeps the question, so this is the absence of a
reply doing the work and not the fallback firing for everything.
*/
@(test)
test_an_apex_ds_the_parent_could_not_answer_falls_back_to_the_route :: proc(t: ^testing.T) {
	def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
		return
	}
	defer net.close(def_socket)
	def_bound, _ := net.bound_endpoint(def_socket)

	route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
		return
	}
	defer net.close(route_socket)
	_ = net.set_option(route_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	route_bound, _ := net.bound_endpoint(route_socket)

	cfg := forwarding_config()
	cfg.upstream.timeout = 200 * time.Millisecond

	group := mock_group(t, cfg.upstream, def_bound.port)
	defer upstream.destroy_group(group)
	routed := mock_group(t, cfg.upstream, route_bound.port)
	defer upstream.destroy_group(routed)

	s := Server {
		cfg    = &cfg,
		group  = group,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
	}

	authority := Route_Mock {
		socket = route_socket,
		reply  = route_reply_nodata("corp.example.", .DS),
		want   = "corp.example.",
	}
	route_thread := thread.create_and_start_with_poly_data(&authority, serve_route)
	out, _, ok := handle_query(
		&s,
		route_query("corp.example.", .DS),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(route_thread)
	thread.destroy(route_thread)

	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect(t, authority.asked, "the route was not asked after the parent's group went quiet")

	decoded, derr2 := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr2, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.No_Error)
	free_all(context.temp_allocator)
}

/*
An apex `DS` neither group could settle is a SERVFAIL, and nothing is kept.

The third arrangement of the case above: the parent's group answers something
other than the proof - a signed NXDOMAIN over the routed zone, in the deployment
this is drawn from - and the route that should have answered in its place cannot
be reached.

What the parent said is not an answer to the question, so it is not served. It
would be the very thing the rule refuses: a signed proof of non-existence over a
zone whose own authority may answer a millisecond later, cached by the *client*
for the parent's negative TTL and read by anything implementing RFC 8020 as
covering every name under the apex. Suppressing only this server's copy of it
would not reach that, the damaging cache being the client's.

SERVFAIL instead, which says what is true - the delegation could not be
established - and which no validator keeps as a proof of anything, so the zone
returns the moment its authority does. Both halves are asserted: the rcode the
client is handed, and that the cache holds nothing under the name afterwards.
*/
@(test)
test_an_apex_ds_neither_group_could_settle_is_a_servfail :: proc(t: ^testing.T) {
	def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
		return
	}
	defer net.close(def_socket)
	_ = net.set_option(def_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	def_bound, _ := net.bound_endpoint(def_socket)

	route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
		return
	}
	defer net.close(route_socket)
	route_bound, _ := net.bound_endpoint(route_socket)

	cfg := forwarding_config()
	cfg.cache.enabled = true
	cfg.upstream.timeout = 200 * time.Millisecond

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer cache.destroy(answers)

	group := mock_group(t, cfg.upstream, def_bound.port)
	defer upstream.destroy_group(group)
	routed := mock_group(t, cfg.upstream, route_bound.port)
	defer upstream.destroy_group(routed)

	s := Server {
		cfg     = &cfg,
		group   = group,
		answers = answers,
		routes  = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
	}

	parent := Route_Mock {
		socket = def_socket,
		reply  = route_reply_nodata("corp.example.", .DS, .NX_Domain),
		want   = "corp.example.",
	}
	parent_mock := thread.create_and_start_with_poly_data(&parent, serve_route)
	out, _, ok := handle_query(
		&s,
		route_query("corp.example.", .DS),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(parent_mock)
	thread.destroy(parent_mock)

	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect(t, parent.asked, "the parent's group was not asked at all")

	// Not the parent's NXDOMAIN, which was never an answer to this question.
	decoded, derr2 := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr2, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.Serv_Fail)

	// And nothing is kept, so the next query asks both again.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "corp.example.", .DS, .IN, false, false)
	_, _, cached := cache.get(answers, key, context.temp_allocator)
	testing.expect(t, !cached, "the parent's unchecked denial was stored against the routed zone")
	free_all(context.temp_allocator)
}

/*
A parent group already parked by its own failures is not waited on.

The apex `DS` is asked of the parent first and of the route second, which on a
network whose path out is down means the route is only reached after the parent
group has spent `attempts` rounds over every server it has. With the default
five-second timeout that is ten seconds or more, and a validating stub gives up
in two to five - so the deployment the carve-out was written for would watch the
zone fail anyway, having waited on an upstream this server already knew was down.

Parked here the way the resolver parks one: `FAILURE_THRESHOLD` is 3, so three
exchanges against a socket nobody answers puts the group in its cooldown. The
three go to a name of their own, which keeps them out of the way of the
assertion that the parent was never asked about `corp.example.` - the datagrams
are still sitting unread in the socket's buffer, and `route_mock_quiet` holds
only this case's question against it.
*/
@(test)
test_a_parked_parent_group_is_skipped_for_an_apex_ds :: proc(t: ^testing.T) {
	def_socket, derr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, derr == nil, "cannot bind the default mock: %v", derr) {
		return
	}
	defer net.close(def_socket)
	def_bound, _ := net.bound_endpoint(def_socket)

	route_socket, rerr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, rerr == nil, "cannot bind the routed mock: %v", rerr) {
		return
	}
	defer net.close(route_socket)
	_ = net.set_option(route_socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	route_bound, _ := net.bound_endpoint(route_socket)

	cfg := forwarding_config()
	cfg.upstream.timeout = 100 * time.Millisecond
	/*
	Two attempts, which is the default and the figure that makes this case bite.
	`resolve_sequential` skips an unhealthy server in round 0 and tries it anyway
	in round 1, so with one attempt a parked group already fails without sending
	anything and there would be nothing here to fix. It is the second round that
	spends the timeout on a server known to be down.
	*/
	cfg.upstream.attempts = 2

	group := mock_group(t, cfg.upstream, def_bound.port)
	defer upstream.destroy_group(group)
	routed := mock_group(t, cfg.upstream, route_bound.port)
	defer upstream.destroy_group(routed)

	// Three failures is `FAILURE_THRESHOLD`, and the name is not the one the
	// assertions below are about.
	for _ in 0 ..< 3 {
		_, _, _ = upstream.resolve(group, route_query("park.example."), context.temp_allocator)
	}

	s := Server {
		cfg    = &cfg,
		group  = group,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
	}

	authority := Route_Mock {
		socket = route_socket,
		reply  = route_reply_nodata("corp.example.", .DS),
		want   = "corp.example.",
	}
	route_thread := thread.create_and_start_with_poly_data(&authority, serve_route)
	out, _, ok := handle_query(
		&s,
		route_query("corp.example.", .DS),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(route_thread)
	thread.destroy(route_thread)

	if !testing.expect(t, ok, "nothing came back at all") {
		return
	}
	testing.expect(t, authority.asked, "the route was not asked while the parent's group was parked")
	testing.expect(
		t,
		route_mock_quiet(def_socket, "corp.example."),
		"a group in its failure cooldown was asked the apex DS anyway",
	)

	decoded, derr2 := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr2, dns.Decode_Error.None)
	testing.expect_value(t, dns.Rcode(decoded.flags.rcode), dns.Rcode.No_Error)
	free_all(context.temp_allocator)
}

/*
A routed zone is served insecure, and an anchor over it takes that back.

`served_locally` is the predicate `resolve_query` reads to decide whether to
validate, and it is asserted here on its own rather than through the resolver
because the two halves of it mask each other. The RFC 6303 table already claims
`home.arpa.`, so a route over that name would look like it worked whether or not
routes were consulted at all; `corp.example.` is in no table, which makes it the
only name that can tell the two apart.
*/
@(test)
test_a_routed_zone_is_served_insecure_unless_the_operator_anchored_it :: proc(t: ^testing.T) {
	cfg := config.default_config()
	routed := upstream.Group{}
	s := Server {
		cfg    = &cfg,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = &routed}},
	}

	testing.expect(t, served_locally(&s, "nas.corp.example."), "a routed name was going to be validated")
	testing.expect(t, served_locally(&s, "corp.example."), "the routed apex was going to be validated")
	testing.expect(t, !served_locally(&s, "example.com."), "an unrouted public name stopped being validated")
	testing.expect(t, !served_locally(&s, "notcorp.example."), "a suffix match was treated as a subtree")

	// The table's own entries still qualify with no route configured at all,
	// which is what keeps every deployment that predates this feature working.
	bare := Server {
		cfg = &cfg,
	}
	testing.expect(t, served_locally(&bare, "50.1.168.192.in-addr.arpa."), "an RFC 6303 reverse name lost its bypass")
	testing.expect(t, !served_locally(&bare, "nas.corp.example."), "an unrouted name gained a bypass")

	/*
	An operator who signed `corp.example` and configured an anchor over it has
	asked for these names to be checked against it. That is a deliberate
	statement about this zone, where the bypass is a default about zones nobody
	signs, so the anchor wins.
	*/
	anchored := Server {
		cfg          = &cfg,
		routes       = s.routes,
		anchor_zones = []string{"corp.example."},
	}
	testing.expect(t, !served_locally(&anchored, "nas.corp.example."), "the operator's own anchor was ignored")
	// The anchor covers its own zone and nothing beside it: a second routed zone
	// with no anchor keeps the bypass.
	two := Server {
		cfg          = &cfg,
		routes       = []Zone_Route {
			{domains = []string{"corp.example."}, group = &routed},
			{domains = []string{"home.example."}, group = &routed},
		},
		anchor_zones = []string{"corp.example."},
	}
	testing.expect(t, served_locally(&two, "nas.home.example."), "an anchor over one zone disabled the bypass on another")
	free_all(context.temp_allocator)
}

/*
A routed zone may answer with private addresses without being named twice.

Split horizon is the reason `rebind.enabled` defaults off, and a route is the
operator saying in the configuration that this zone is answered by a local
authority. Local authorities answer with local addresses; requiring the same
zone in `rebind.allow_domains` as well would leave every internal name coming
back NODATA for whoever configured only the half they had read about.

The control is the same answer for a name outside the route, which still has to
be refused - otherwise this is not an exemption, it is the guard switched off.
*/
@(test)
test_a_routed_zone_may_answer_with_private_addresses :: proc(t: ^testing.T) {
	Case :: struct {
		name:    string,
		refused: bool,
	}
	cases := []Case{{"nas.corp.example.", false}, {"nas.attacker.example.", true}}

	for c in cases {
		socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
			return
		}
		defer net.close(socket)
		_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
		bound, _ := net.bound_endpoint(socket)

		cfg := forwarding_config()
		cfg.rebind.enabled = true

		/*
		One mock behind both the default group and the route, so the only thing
		that differs between the two cases is whether the question is inside the
		routed zone. A second socket would leave open the possibility that the
		exemption came from something about the upstream rather than about the
		route.
		*/
		group := mock_group(t, cfg.upstream, bound.port)
		defer upstream.destroy_group(group)
		routed := mock_group(t, cfg.upstream, bound.port)
		defer upstream.destroy_group(routed)

		s := Server {
			cfg    = &cfg,
			group  = group,
			routes = []Zone_Route{{domains = []string{"corp.example."}, group = routed}},
		}

		x := Route_Mock {
			socket = socket,
			reply  = route_reply(c.name, {192, 168, 1, 50}),
			want   = c.name,
		}
		mock := thread.create_and_start_with_poly_data(&x, serve_route)
		out, outcome, ok := handle_query(&s, route_query(c.name), .UDP, "127.0.0.1:5555", context.temp_allocator)
		thread.join(mock)
		thread.destroy(mock)

		if !testing.expect(t, ok, "nothing came back at all") {
			return
		}
		testing.expectf(
			t,
			(outcome == .Blocked) == c.refused,
			"%s came back as %v, which is not what the rebinding guard should have made of it",
			c.name,
			outcome,
		)

		decoded, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		kept := false
		for rec in decoded.answer {
			if a, is_a := rec.data.(dns.Rdata_A); is_a {
				kept = a.addr == [4]u8{192, 168, 1, 50}
			}
		}
		testing.expectf(t, kept != c.refused, "the private address for %s was not handled as expected", c.name)
	}
	free_all(context.temp_allocator)
}

/*
The metrics endpoint sees a route's servers, and sees each name once.

Two halves, and the second is the one that breaks a scrape rather than an
operator's dashboard. A routed upstream that is failing affects only the
internal names, so it is precisely the one nobody notices without a series for
it. And listing the same server in `upstream.servers` and in a route for its own
zone is an ordinary thing to write, which without the de-duplication below emits
two samples with identical label sets in one family - malformed exposition, and
Prometheus rejects the whole scrape for it, not just the duplicate.

Once each, and each carrying both groups' figures: the two entries are separate
`Upstream` values with separate counters, so a de-duplication that kept the
first would leave the route's queries and failures out of the endpoint under a
name that looks like it is being reported. See `render_upstream_metrics`.
*/
@(test)
test_routed_upstreams_are_reported_once_each :: proc(t: ^testing.T) {
	cfg := config.default_config()

	shared := make([]config.Upstream_Spec, 1, context.temp_allocator)
	shared[0] = config.Upstream_Spec{name = "router", kind = .UDP, address = "127.0.0.1", port = 15353}
	base := cfg.upstream
	base.servers = shared

	only := make([]config.Upstream_Spec, 1, context.temp_allocator)
	only[0] = config.Upstream_Spec{name = "dc1", kind = .UDP, address = "127.0.0.1", port = 15354}
	routed_cfg := cfg.upstream
	routed_cfg.servers = only

	group, gerr := upstream.make_group(base, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the default group: %v", gerr) {
		return
	}
	defer upstream.destroy_group(group)
	// The same server again, in a route of its own: one operator writing down
	// one fact twice, which is the arrangement the de-duplication is for.
	again, aerr := upstream.make_group(base, nil, context.allocator, false)
	if !testing.expectf(t, aerr == .None, "cannot build the duplicate group: %v", aerr) {
		return
	}
	defer upstream.destroy_group(again)
	routed, rerr := upstream.make_group(routed_cfg, nil, context.allocator, false)
	if !testing.expectf(t, rerr == .None, "cannot build the routed group: %v", rerr) {
		return
	}
	defer upstream.destroy_group(routed)

	s := Server {
		cfg    = &cfg,
		group  = group,
		routes = []Zone_Route {
			{domains = []string{"corp.example."}, group = routed},
			{domains = []string{"home.arpa."}, group = again},
		},
	}

	b := strings.builder_make(context.temp_allocator)
	render_upstream_metrics(&b, &s)
	text := strings.to_string(b)

	testing.expect(
		t,
		strings.contains(text, `upstream="dc1"`),
		"the routed upstream has no series of its own",
	)
	testing.expect_value(t, strings.count(text, `elodin_upstream_up{upstream="router"}`), 1)
	testing.expect_value(t, strings.count(text, `elodin_upstream_up{upstream="dc1"}`), 1)
	free_all(context.temp_allocator)
}

/*
The summing itself, driven with counters that are not zero.

`test_routed_upstreams_are_reported_once_each` above proves one sample per name
and that a routed upstream gets a series at all, but every counter in its
fixture is zero - so it would pass equally against the de-duplication that kept
the first group and dropped the rest, which is the defect that motivated the
merge. This drives real figures into two upstreams sharing a name and asserts
the endpoint reports their total.

The traffic is failures against a port nothing is listening on, which is the
cheapest way to move `queries` and `failures` at once: `record_failure`
increments both. Three of them on one group and none on the other also sets up
the `up` gauge's own claim - a name is up while any upstream wearing it is
usable - since `FAILURE_THRESHOLD` is 3, so the first group is in cooldown and
the second is not.
*/
@(test)
test_two_upstreams_of_one_name_have_their_figures_added :: proc(t: ^testing.T) {
	cfg := config.default_config()

	// A port nothing is bound to, so every exchange fails inside the timeout.
	dead := make([]config.Upstream_Spec, 1, context.temp_allocator)
	dead[0] = config.Upstream_Spec{name = "router", kind = .UDP, address = "127.0.0.1", port = 1}
	spec := cfg.upstream
	spec.servers = dead
	spec.attempts = 1
	spec.timeout = 200 * time.Millisecond

	failing, ferr := upstream.make_group(spec, nil, context.allocator, false)
	if !testing.expectf(t, ferr == .None, "cannot build the failing group: %v", ferr) {
		return
	}
	defer upstream.destroy_group(failing)
	idle, ierr := upstream.make_group(spec, nil, context.allocator, false)
	if !testing.expectf(t, ierr == .None, "cannot build the idle group: %v", ierr) {
		return
	}
	defer upstream.destroy_group(idle)

	query := route_query("probe.example.")
	/*
	Three on one and one on the other, and neither number is arbitrary.

	Three is `FAILURE_THRESHOLD`, so that copy of the name is parked while the
	other stays usable - which is what makes the `up` assertion below
	discriminate. And the second group has to contribute a non-zero count of its
	own, or the total is the first group's total and the sum assertion would
	hold just as well against the de-duplication that dropped it.
	*/
	for _ in 0 ..< 3 {
		_, _, _ = upstream.resolve(failing, query, context.temp_allocator)
	}
	_, _, _ = upstream.resolve(idle, query, context.temp_allocator)

	s := Server {
		cfg    = &cfg,
		group  = failing,
		routes = []Zone_Route{{domains = []string{"corp.example."}, group = idle}},
	}

	b := strings.builder_make(context.temp_allocator)
	render_upstream_metrics(&b, &s)
	text := strings.to_string(b)

	// One sample, carrying both groups' figures rather than the first group's.
	testing.expect_value(t, strings.count(text, `elodin_upstream_queries_total{upstream="router"}`), 1)
	testing.expectf(
		t,
		strings.contains(text, `elodin_upstream_queries_total{upstream="router"} 4`),
		"the two groups' query counts were not added; got:\n%s",
		text,
	)
	testing.expectf(
		t,
		strings.contains(text, `elodin_upstream_failures_total{upstream="router"} 4`),
		"the two groups' failure counts were not added; got:\n%s",
		text,
	)
	// Up, because the idle copy of the name is still usable even though the
	// other is in its cooldown. Dropping either would report the wrong one.
	testing.expectf(
		t,
		strings.contains(text, `elodin_upstream_up{upstream="router"} 1`),
		"a name with one usable upstream was reported down; got:\n%s",
		text,
	)
	free_all(context.temp_allocator)
}
