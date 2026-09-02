package server

import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
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
	socket: net.UDP_Socket,
	reply:  []u8,
	asked:  bool,
	name:   string,
}

/*
Answer one query, recording the name it asked for.

The name is what separates this from the mocks in the other files: a test that
only asks whether a socket was written to cannot tell a routed question from the
chain lookups the validator makes on its own account, and those two go to
different groups on purpose.
*/
@(private = "file")
serve_route :: proc(x: ^Route_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	if msg, derr := dns.decode_message(buf[:n], context.temp_allocator); derr == .None && len(msg.question) > 0 {
		x.name = msg.question[0].name
	}
	x.asked = true
	out: [4096]u8
	copy(out[:], x.reply)
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
route_query :: proc(name: string) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = .A, class = .IN}
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

	testing.expect(t, route_group(&s, "nas.corp.example.") == &broad, "the zone's own route did not answer for it")
	testing.expect(t, route_group(&s, "corp.example.") == &broad, "the apex did not follow its route")
	testing.expect(t, route_group(&s, "build.dev.corp.example.") == &narrow, "the longer route did not win")
	testing.expect(t, route_group(&s, "dev.corp.example.") == &narrow, "the longer route did not take its own apex")

	// Outside every route, and the two ways to be outside one: a different zone,
	// and a name that merely ends in the same bytes without a label break.
	testing.expect(t, route_group(&s, "example.com.") == &fallback, "an unrouted name left the default group")
	testing.expect(t, route_group(&s, "notcorp.example.") == &fallback, "a suffix match was treated as a subtree")

	// DNS names compare without regard to case, and nothing lowercases the
	// question on the way in - the response echoes it back as the client spelled
	// it - so the match has to fold case itself.
	testing.expect(t, route_group(&s, "NAS.Corp.Example.") == &broad, "the match did not fold case")

	// A server with no routes configured at all is every deployment that
	// existed before this feature: everything goes to the default group.
	plain := Server {
		cfg   = &cfg,
		group = &fallback,
	}
	testing.expect(t, route_group(&plain, "nas.corp.example.") == &fallback, "a server with no routes routed something")
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
	testing.expect(t, mock_untouched(def_socket), "the name leaked to the default upstream as well")

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
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_route)
	_, _, ok := handle_query(&s, route_query("www.example.com."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, ok, "nothing came back at all")
	testing.expect(t, x.asked, "the default upstream was never asked")
	testing.expect_value(t, x.name, "www.example.com.")
	testing.expect(t, mock_untouched(route_socket), "an unrouted name was sent to the route's server")
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
