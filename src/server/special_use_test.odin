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
import "elodin:filter"
import "elodin:upstream"

/*
The names that are never meant to reach a public resolver.

RFC 6761 reserves `localhost.`, `invalid.`, `test.` and `example.`; RFC 6762
section 22 reserves `local.` for mDNS; RFC 7686 reserves `onion.`; RFC 8375
section 3 reserves `home.arpa.` for a home network's own zone. Each of them says
the same thing in slightly different words: a caching resolver should answer
these itself and MUST NOT forward them to the public DNS. Forwarding a `.onion`
name in particular publishes to the upstream operator that somebody on this
network is looking for a specific hidden service, and forwarding a `home.arpa.`
name names that network's own hardware to whoever is listening.

`home.arpa.` has two shapes of its own that the others do not, both from RFC
8375 section 4 item 4.B, and both pinned below: it is served as an empty zone
rather than as a name that cannot exist, its parent being signed and saying it
exists; and the `DS` at its apex is forwarded rather than answered, that proof
living in `arpa.` and nowhere this server can reach.

A mock upstream stands behind the resolver in these tests and records whether it
was asked anything at all, which is the half of the requirement that is about
the leak. The other half is what the client is handed instead, checked here too:
a fix that dropped these queries on the floor, or answered `localhost.` with the
upstream's idea of it, would satisfy the first half and be wrong.
*/

@(private = "file")
Leak_Mock :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	asked:  bool,
	name:   string,
}

@(private = "file")
serve_leak :: proc(x: ^Leak_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.asked = true
	if q, ok := dns.peek_question(buf[:n], context.allocator); ok {
		x.name = q.name
	}
	out: [4096]u8
	copy(out[:], x.reply)
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
leak_query :: proc(name: string, type := dns.Type.A, do_bit := false) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{id = 0x4321, question = questions}
	msg.flags.rd = true
	if do_bit {
		extra := make([]dns.Record, 1, context.temp_allocator)
		extra[0] = dns.make_opt(1232, true)
		msg.additional = extra
	}
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
leak_reply :: proc(name: string, type := dns.Type.A) -> []u8 {
	// An address for an A question, and NODATA for anything else: the cases
	// that reach this only care that the upstream answered at all, and a canned
	// A record under a question of some other type is a reply no forwarder
	// should accept in the first place.
	answer := make([]dns.Record, 0, context.temp_allocator)
	if type == .A {
		answer = make([]dns.Record, 1, context.temp_allocator)
		answer[0] = dns.Record {
			name  = name,
			type  = .A,
			class = .IN,
			ttl   = 60,
			data  = dns.Rdata_A{addr = {203, 0, 113, 1}},
		}
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = type, class = .IN}
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
A resolver with one mock upstream behind it, built fresh per case.

The mock is bound before the group so the group can be pointed at the port it
got, and the caller is handed both: the server to ask, and the mock to ask
afterwards whether anything reached it. The reply it is armed with is a lie -
203.0.113.1 for whatever was asked - so a query that does slip through comes
back as a wrong answer as well as a leak.
*/
@(private = "file")
leak_server :: proc(
	t: ^testing.T,
	cfg: ^config.Config,
	name: string,
	type := dns.Type.A,
) -> (
	s: Server,
	mock: ^Leak_Mock,
	ok: bool,
) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return {}, nil, false
	}
	// A bound on the exchange in the cases that expect one: the mock runs on its
	// own thread there and has to see the query and answer it before the
	// resolver's own `upstream.timeout` runs out. The cases that expect nothing
	// do not wait this out - see `nothing_reached`.
	_ = net.set_option(socket, .Receive_Timeout, 500 * time.Millisecond)
	bound, _ := net.bound_endpoint(socket)

	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = false
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 2 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		net.close(socket)
		return {}, nil, false
	}

	x := new(Leak_Mock, context.temp_allocator)
	x^ = Leak_Mock {
		socket = socket,
		reply  = leak_reply(name, type),
	}
	return Server{cfg = cfg, group = group}, x, true
}

/*
Whether the upstream was left alone, asked once `handle_query` has returned.

No second thread and no waiting for one. A query this server forwards is written
to the socket before the call can return - the send is what it then waits on an
answer for - so if anything leaked it is already sitting in the receive buffer by
the time this looks, and the case that leaks nothing pays a few milliseconds
rather than a whole timeout. That is most of the cases here, and the concurrent
mock is kept only where an answer has to come back.

Not zero milliseconds: `SO_RCVTIMEO` reads zero as "no timeout", which on a
socket nothing is going to send to is the one value that hangs.
*/
@(private = "file")
nothing_reached :: proc(x: ^Leak_Mock) -> bool {
	_ = net.set_option(x.socket, .Receive_Timeout, 20 * time.Millisecond)
	serve_leak(x)
	return !x.asked
}

@(private = "file")
Want :: enum {
	// NOERROR carrying exactly one A of 127.0.0.1, or one AAAA of ::1.
	Loopback_4,
	Loopback_6,
	// NOERROR, no answer, an SOA to cache it against: the name exists and has
	// nothing of this type.
	No_Data,
	Nx_Domain,
	// NOERROR carrying the empty zone's own SOA, or its own NS: the two types
	// RFC 6303 section 3 has an apex answer rather than decline.
	Zone_Soa,
	Zone_Ns,
}

@(private = "file")
Leak_Case :: struct {
	name:  string,
	type:  dns.Type,
	want:  Want,
	// The zone the synthesised SOA is expected to be owned by, for the cases
	// that carry one.
	soa:   string,
	// Which of the off-by-default keys the case needs. One field each rather
	// than one for the set: a table that answered `test.` from
	// `special_use.local` would be a live bug, and a shared flag would hide it.
	local:     bool,
	test:      bool,
	home_arpa: bool,
}

@(test)
test_special_use_names_are_not_sent_to_the_upstream :: proc(t: ^testing.T) {
	cases := []Leak_Case {
		// RFC 6761 section 6.3: the loopback address, and nothing else, is what
		// this name is allowed to resolve to.
		{name = "localhost.", type = .A, want = .Loopback_4},
		{name = "localhost.", type = .AAAA, want = .Loopback_6},
		// "and anything under it" - the reservation is of the whole subtree.
		{name = "dev.localhost.", type = .A, want = .Loopback_4},
		// The name exists, so a type it has nothing of is NODATA rather than
		// NXDOMAIN, and there is no invented MX for a zone we do not have.
		{name = "localhost.", type = .MX, want = .No_Data, soa = "localhost."},
		// RFC 7686 section 2. The SOA sits at the apex of the reserved zone, not
		// at the parent of the queried name, so a resolver downstream can cache
		// the negative answer for the tree rather than for one hidden service.
		{name = "duskgytldkxiuqc6otgh4.onion.", type = .A, want = .Nx_Domain, soa = "onion."},
		{name = "nothing.invalid.", type = .A, want = .Nx_Domain, soa = "invalid."},
		// RFC 6762 section 22, behind `special_use.local`: see the table in
		// localzones.odin for why that one is asked for rather than assumed.
		{name = "printer.local.", type = .A, want = .Nx_Domain, soa = "local.", local = true},
		{name = "internal.test.", type = .A, want = .Nx_Domain, soa = "test.", test = true},
		// RFC 8375 section 3, behind `special_use.home_arpa`. The SOA sits at
		// the zone apex for the same reason `onion.`'s does, and the point of
		// the case is the half above: the printer's name does not leave.
		{
			name = "printer.home.arpa.",
			type = .A,
			want = .Nx_Domain,
			soa = "home.arpa.",
			home_arpa = true,
		},
		// The apex is the empty zone RFC 6303 section 3 describes, which RFC
		// 8375 section 4 item 4.B asks for here by name. NODATA rather than
		// NXDOMAIN: `arpa.` is signed and publishes this delegation, so a
		// client can prove the name exists, and answering that it does not
		// would be this server contradicting a zone the client can check. It is
		// also what the blackhole servers answer, which is what makes turning
		// the key on a change of route rather than a change of answer.
		{
			name = "home.arpa.",
			type = .A,
			want = .No_Data,
			soa = "home.arpa.",
			home_arpa = true,
		},
		// "SOA, NS, and 'no data' responses ... as appropriate to the query
		// type" - the two the empty zone answers rather than declines. The NS
		// names the zone itself and has no address record anywhere, per RFC
		// 6303 section 3, which is what aborts an UPDATE client trying to
		// register a name into a zone nothing here serves.
		{name = "home.arpa.", type = .SOA, want = .Zone_Soa, home_arpa = true},
		{name = "home.arpa.", type = .NS, want = .Zone_Ns, home_arpa = true},
		// Only the apex is the zone. A DS *below* it asks about a name that
		// exists nowhere but this network, so that one is a name error like any
		// other inside the zone - it is the apex DS, forwarded, that has a test
		// of its own below.
		{
			name = "printer.home.arpa.",
			type = .DS,
			want = .Nx_Domain,
			soa = "home.arpa.",
			home_arpa = true,
		},
	}

	for c in cases {
		cfg := config.default_config()
		cfg.special_use.local = c.local
		cfg.special_use.test = c.test
		cfg.special_use.home_arpa = c.home_arpa

		s, x, built := leak_server(t, &cfg, c.name)
		if !built {
			return
		}
		defer net.close(x.socket)
		defer upstream.destroy_group(s.group)

		out, outcome, ok := handle_query(&s, leak_query(c.name, c.type), .UDP, "127.0.0.1:5555", context.temp_allocator)

		testing.expectf(
			t,
			nothing_reached(x),
			"%s was sent to the public upstream, which asked for %q",
			c.name,
			x.name,
		)
		if !testing.expectf(t, ok, "%s went unanswered", c.name) {
			continue
		}
		testing.expectf(t, outcome == .Local, "%s came back as %v rather than a local answer", c.name, outcome)

		resp, derr := dns.decode_message(out, context.temp_allocator)
		if !testing.expectf(t, derr == .None, "%s produced a response that will not decode: %v", c.name, derr) {
			continue
		}

		switch c.want {
		case .Loopback_4:
			testing.expectf(t, dns.rcode_of(resp) == .No_Error, "%s is not NOERROR", c.name)
			if !testing.expectf(t, len(resp.answer) == 1, "%s has %d answers, want 1", c.name, len(resp.answer)) {
				continue
			}
			a, is_a := resp.answer[0].data.(dns.Rdata_A)
			testing.expectf(t, is_a, "%s did not come back as an A record", c.name)
			testing.expectf(t, a.addr == [4]u8{127, 0, 0, 1}, "%s resolved to %v, not 127.0.0.1", c.name, a.addr)
		case .Loopback_6:
			testing.expectf(t, dns.rcode_of(resp) == .No_Error, "%s is not NOERROR", c.name)
			if !testing.expectf(t, len(resp.answer) == 1, "%s has %d answers, want 1", c.name, len(resp.answer)) {
				continue
			}
			aaaa, is_aaaa := resp.answer[0].data.(dns.Rdata_AAAA)
			testing.expectf(t, is_aaaa, "%s did not come back as an AAAA record", c.name)
			loopback := [16]u8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
			testing.expectf(t, aaaa.addr == loopback, "%s resolved to %v, not ::1", c.name, aaaa.addr)
		case .Zone_Soa, .Zone_Ns:
			want_type := dns.Type.SOA if c.want == .Zone_Soa else dns.Type.NS
			testing.expectf(t, dns.rcode_of(resp) == .No_Error, "%s %v is not NOERROR", c.name, c.type)
			if !testing.expectf(
				t,
				len(resp.answer) == 1,
				"%s %v has %d answers, want 1",
				c.name,
				c.type,
				len(resp.answer),
			) {
				continue
			}
			testing.expectf(
				t,
				resp.answer[0].type == want_type,
				"%s %v came back as %v",
				c.name,
				c.type,
				resp.answer[0].type,
			)
			testing.expectf(
				t,
				dns.name_equal_fold(resp.answer[0].name, c.name),
				"%s %v is owned by %q",
				c.name,
				c.type,
				resp.answer[0].name,
			)
			if ns, is_ns := resp.answer[0].data.(dns.Rdata_Name); is_ns {
				testing.expectf(
					t,
					dns.name_equal_fold(ns.name, c.name),
					"the empty zone's NS names %q rather than the zone",
					ns.name,
				)
			}
		case .No_Data, .Nx_Domain:
			want_rcode := dns.Rcode.No_Error if c.want == .No_Data else dns.Rcode.NX_Domain
			testing.expectf(t, dns.rcode_of(resp) == want_rcode, "%s is %v, want %v", c.name, dns.rcode_of(resp), want_rcode)
			testing.expectf(t, len(resp.answer) == 0, "%s came back with %d answer records", c.name, len(resp.answer))
			if !testing.expectf(t, len(resp.authority) == 1, "%s carries no SOA to cache it against", c.name) {
				continue
			}
			testing.expectf(t, resp.authority[0].type == .SOA, "%s: the authority record is not an SOA", c.name)
			testing.expectf(
				t,
				dns.name_equal_fold(resp.authority[0].name, c.soa),
				"%s: the SOA is owned by %q, want %q",
				c.name,
				resp.authority[0].name,
				c.soa,
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
The names that are still forwarded, and are meant to be.

`local.`, `test.` and `home.arpa.` are reserved but served for real by networks
that have been running them for years, so they wait for `special_use.local`,
`special_use.test` and `special_use.home_arpa`; `example.` is reserved and
explicitly *not* to be treated as special (RFC 6761 section 6.5), its delegated
subdomains being names that resolve. This is the case that catches a table that
grew past what was argued for it.

`home.arpa.` matters most here. A home router authoritative for the zone is the
deployment RFC 8375 wrote the name for, and answering it from the table by
default would take that network's own hostnames away on an upgrade - so the
default has to keep forwarding it, and `LOCALLY_SERVED_ZONES` is what keeps the
router's unsigned answer from being called a forgery on the way back.
*/
@(test)
test_a_default_configuration_still_forwards_local_test_and_example :: proc(t: ^testing.T) {
	names := []string{"printer.local.", "internal.test.", "www.example.com.", "printer.home.arpa."}

	for name in names {
		cfg := config.default_config()
		s, x, built := leak_server(t, &cfg, name)
		if !built {
			return
		}
		defer net.close(x.socket)
		defer upstream.destroy_group(s.group)

		mock := thread.create_and_start_with_poly_data(x, serve_leak)
		_, outcome, _ := handle_query(&s, leak_query(name), .UDP, "127.0.0.1:5555", context.temp_allocator)
		thread.join(mock)
		thread.destroy(mock)

		testing.expectf(t, x.asked, "%s was answered locally by a default configuration", name)
		testing.expectf(t, outcome == .Forwarded, "%s came back as %v rather than forwarded", name, outcome)
	}
	free_all(context.temp_allocator)
}

/*
The one query `special_use.home_arpa` is not allowed to answer.

RFC 8375 section 4 item 4.B carves the delegation's own `DS` out of the MUST NOT
that keeps the rest of the zone at home: "a query for a DS record with the DO
bit set MUST return the correct answer for that question, including correct
information in the authority section that proves that the record is
nonexistent", and that proof is signed and lives in `arpa.`.

Answering it from the table would hand a validating client below this server a
chain that is broken rather than one proved absent - an unsigned NXDOMAIN for a
name whose parent publishes it - and a broken chain is Bogus, which is SERVFAIL
for every name in the zone. That is the failure `LOCALLY_SERVED_ZONES` describes
a home router causing, and it would be this server causing it, in the
configuration whose whole purpose is to answer those names cleanly.

Both DO settings, though the RFC only requires the one: a question whose rcode
depended on a bit in the request would be answered wrongly in the cheaper path,
and cached there by any downstream resolver that asked without it.
*/
@(test)
test_the_home_arpa_apex_ds_is_still_forwarded :: proc(t: ^testing.T) {
	for do_bit in ([]bool{true, false}) {
		cfg := config.default_config()
		cfg.special_use.home_arpa = true

		s, x, built := leak_server(t, &cfg, "home.arpa.", .DS)
		if !built {
			return
		}
		defer net.close(x.socket)
		defer upstream.destroy_group(s.group)

		mock := thread.create_and_start_with_poly_data(x, serve_leak)
		_, outcome, _ := handle_query(
			&s,
			leak_query("home.arpa.", .DS, do_bit),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		thread.join(mock)
		thread.destroy(mock)

		testing.expectf(
			t,
			x.asked,
			"the home.arpa. DS (DO=%v) was answered from the table, leaving a validating client below with no proof",
			do_bit,
		)
		testing.expectf(
			t,
			outcome == .Forwarded,
			"the home.arpa. DS (DO=%v) came back as %v rather than forwarded",
			do_bit,
			outcome,
		)
		free_all(context.temp_allocator)
	}
}

/*
The upstream that really can answer a `.onion` name.

RFC 7686 section 2 puts its instruction to caching servers on those "not
explicitly adapted to interoperate with Tor", and a local tor with `DNSPort` and
`AutomapHostsOnResolve` as the upstream is the adapted case. `special_use.onion`
hands that one zone back without costing the operator `localhost.` and
`invalid.` as `special_use.enabled: false` would - which is what the second half
of this checks, since a key that turned the whole table off would pass the first
half on its own.
*/
@(test)
test_a_tor_aware_upstream_can_be_given_onion_back :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.special_use.onion = false

	s, x, built := leak_server(t, &cfg, "duskgytldkxiuqc6otgh4.onion.")
	if !built {
		return
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	mock := thread.create_and_start_with_poly_data(x, serve_leak)
	_, outcome, _ := handle_query(
		&s,
		leak_query("duskgytldkxiuqc6otgh4.onion."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	thread.join(mock)
	thread.destroy(mock)

	testing.expect(t, x.asked, "special_use.onion: false did not hand the query to the upstream")
	testing.expectf(t, outcome == .Forwarded, "the .onion query came back as %v rather than forwarded", outcome)

	// The rest of the table is untouched by that key.
	_, local_outcome, _ := handle_query(&s, leak_query("localhost."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	testing.expectf(
		t,
		local_outcome == .Local,
		"localhost. came back as %v; special_use.onion took the rest of the table with it",
		local_outcome,
	)

	free_all(context.temp_allocator)
}

/*
A validator that can fetch nothing, which is what a Tor-aware upstream is.

`tor`'s `DNSPort` answers A and AAAA and knows nothing of DS or DNSKEY, so a
chain walk over it produces no records whatever the name. The verdict that
follows - Indeterminate rather than Bogus - is not the point; either one is
SERVFAIL to the client, and the point is that the validator is never consulted
about a name the operator handed over on purpose.
*/
@(private = "file")
tor_has_no_chain :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> ([]u8, bool) {
	return nil, false
}

/*
The `.onion` answer that comes back from that upstream is not validated - by
whichever key sent it there.

`dnssec.enabled` is on by default and is reachable at once with either key that
forwards `.onion`, so if the forwarded answer were held to the public chain of
trust the key would hand every `.onion` name to the upstream and then turn what
came back into SERVFAIL. Nothing signs a `.onion` answer, and nothing can: the
root publishes a signed proof that there is no `onion.` to delegate, so a
validator reads any answer under it as unsigned data inside the root zone.

Both keys are checked because the rule is about forwarding, not about one
setting. `onion: false` is the narrow claim about the upstream; `enabled: false`
is the blunt key an operator with a local tor may well reach for instead, having
no reason to read the difference off the names. When only the first stood the
validator down, the second was a SERVFAIL for every `.onion` name and a startup
warning was all that pointed at it. If `special_use_deferred` is ever narrowed
back to `onion` alone, the second case here fails.

The mock answers with an address the way a local tor would, and the assertion is
that the client sees it.
*/
@(test)
test_a_deferred_onion_answer_is_not_held_to_the_public_chain :: proc(t: ^testing.T) {
	Case :: struct {
		label: string,
		apply: proc(cfg: ^config.Config),
	}
	cases := []Case {
		{
			label = "special_use.onion: false",
			apply = proc(cfg: ^config.Config) {cfg.special_use.onion = false},
		},
		{
			label = "special_use.enabled: false",
			apply = proc(cfg: ^config.Config) {cfg.special_use.enabled = false},
		},
	}
	for c in cases {
		check_onion_is_not_validated(t, c.label, c.apply)
	}
}

@(private = "file")
check_onion_is_not_validated :: proc(t: ^testing.T, label: string, apply: proc(cfg: ^config.Config)) {
	name := "duskgytldkxiuqc6otgh4.onion."
	cfg := config.default_config()
	apply(&cfg)

	s, x, built := leak_server(t, &cfg, name)
	if !built {
		return
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	s.validator = dnssec.make_validator(tor_has_no_chain, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	mock := thread.create_and_start_with_poly_data(x, serve_leak)
	out, _, ok := handle_query(&s, leak_query(name), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	testing.expectf(t, x.asked, "%s: the .onion query never reached the Tor-aware upstream", label)
	if !testing.expectf(t, ok, "%s: the .onion query went unanswered", label) {
		return
	}

	resp, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "%s: the response will not decode: %v", label, derr) {
		return
	}
	if !testing.expectf(
		t,
		dns.rcode_of(resp) == .No_Error,
		"%s: the mapped .onion address came back as %v: the validator was asked about a name handed to the upstream",
		label,
		dns.rcode_of(resp),
	) {
		return
	}
	if !testing.expectf(t, len(resp.answer) == 1, "%s: the mapped .onion address did not survive", label) {
		return
	}
	a, is_a := resp.answer[0].data.(dns.Rdata_A)
	testing.expectf(t, is_a, "%s: the .onion answer is not an A record", label)
	testing.expect_value(t, a.addr, [4]u8{203, 0, 113, 1})

	free_all(context.temp_allocator)
}

/*
A rewrite outranks the table.

This is the escape hatch for a site that serves a reserved name for real and
wants one specific answer for it, and it works by placement alone: `apply_rewrite`
runs before the special-use check in `resolve_query`. No upstream is configured
here, so a query that reached the forwarding path would fail loudly rather than
quietly produce the right-looking answer from the wrong place.
*/
@(test)
test_a_rewrite_wins_over_the_special_use_table :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.special_use.local = true

	cfg.rewrites = make([]config.Rewrite, 1, context.temp_allocator)
	cfg.rewrites[0] = config.Rewrite {
		domain   = "local.",
		wildcard = true,
		answers  = []config.Rewrite_Answer{{kind = .A, v4 = {192, 168, 1, 50}}},
		ttl      = 300,
	}

	s := Server {
		cfg = &cfg,
	}

	out, outcome, ok := handle_query(&s, leak_query("nas.local."), .UDP, "127.0.0.1:5555", context.temp_allocator)
	if !testing.expect(t, ok, "a rewritten name under local. went unanswered") {
		return
	}
	testing.expect_value(t, outcome, Outcome.Rewritten)

	resp, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !testing.expect(t, len(resp.answer) == 1, "the rewrite under local. produced no answer record") {
		return
	}
	a, is_a := resp.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the rewritten answer is not an A record")
	testing.expect_value(t, a.addr, [4]u8{192, 168, 1, 50})

	free_all(context.temp_allocator)
}

/*
These answers are not stored.

They are built from a table that is already in memory, so a cache entry would
spend the budget to save nothing and would outlive the reload meant to change
it. Asked twice with the cache on, the second answer is still a local one rather
than a cached one - which is what an operator sees in the query log, and what
tells them the setting is still in force rather than a copy of what it once
said.
*/
@(test)
test_special_use_answers_do_not_enter_the_cache :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}

	for i in 0 ..< 2 {
		_, outcome, ok := handle_query(
			&s,
			leak_query("duskgytldkxiuqc6otgh4.onion."),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		testing.expectf(t, ok, "the .onion query went unanswered on attempt %d", i + 1)
		testing.expectf(t, outcome == .Local, "attempt %d came back as %v rather than a local answer", i + 1, outcome)
	}

	testing.expect(t, cache.len_entries(answers) == 0, "a synthesised special-use answer was stored in the cache")

	free_all(context.temp_allocator)
}

/*
The counter, and what it does not count.

`stats.special_use` is the only aggregate evidence the table ever did anything -
an operator who has not turned the query log on has nothing else to look at - so
it is worth a test that it moves, and worth one that it does not move for a name
that was forwarded. The second half is the one that would catch a counter
incremented on the way into `resolve_query` rather than on the branch that
answers, which would report a leak stopped every time one was not.
*/
@(test)
test_the_special_use_counter_counts_only_what_the_table_answered :: proc(t: ^testing.T) {
	// Answered from the table: two names, one query each.
	for name in ([]string{"localhost.", "nothing.invalid."}) {
		cfg := config.default_config()
		s, x, built := leak_server(t, &cfg, name)
		if !built {
			return
		}
		defer net.close(x.socket)
		defer upstream.destroy_group(s.group)

		_, _, _ = handle_query(&s, leak_query(name), .UDP, "127.0.0.1:5555", context.temp_allocator)
		testing.expectf(
			t,
			s.stats.special_use == 1,
			"%s left the counter at %d, want 1",
			name,
			s.stats.special_use,
		)
	}

	/*
	Forwarded, so not counted. `.local` is outside the table by default, and the
	mock has to be served for the query to complete - the point being that a
	query which went to an upstream leaves this counter alone.
	*/
	{
		name := "printer.local."
		cfg := config.default_config()
		s, x, built := leak_server(t, &cfg, name)
		if !built {
			return
		}
		defer net.close(x.socket)
		defer upstream.destroy_group(s.group)

		mock := thread.create_and_start_with_poly_data(x, serve_leak)
		_, outcome, _ := handle_query(&s, leak_query(name), .UDP, "127.0.0.1:5555", context.temp_allocator)
		thread.join(mock)
		thread.destroy(mock)

		testing.expectf(t, outcome == .Forwarded, "%s came back as %v rather than forwarded", name, outcome)
		testing.expectf(
			t,
			s.stats.special_use == 0,
			"a forwarded name moved the counter to %d",
			s.stats.special_use,
		)
	}
	free_all(context.temp_allocator)
}

/*
A blocklist entry for a reserved name beats the table, and is counted as blocked.

This is the ordering the table's docstring in `resolver.odin` argues for and
which nothing else pins: the block lists run first, so an operator who put a
specific hidden service on a list gets the block response they configured and
sees it in `blocked` rather than having the table quietly answer first and leave
the list looking like it did nothing.

It is also the half of the comparison with the DDR zone that could actually
regress. DDR is answered *above* the block lists, deliberately, because nothing
legitimately lists `resolver.arpa`; if that placement were ever copied onto this
table to make the two look alike, this test is what would fail.
*/
@(test)
test_a_blocklist_entry_for_a_reserved_name_wins :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = true

	block, allow := filter.set_make(), filter.set_make()
	filter.parse_list(block, allow, "0.0.0.0 duskgytldkxiuqc6otgh4.onion\n", .Hosts)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, block, allow)

	s := Server {
		cfg     = &cfg,
		filters = engine,
	}

	_, outcome, ok := handle_query(
		&s,
		leak_query("duskgytldkxiuqc6otgh4.onion."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, ok, "the blocked .onion name went unanswered")
	testing.expectf(
		t,
		outcome == .Blocked,
		"came back as %v: the table answered a name the operator had blocked",
		outcome,
	)
	testing.expectf(
		t,
		s.stats.special_use == 0,
		"the table counted an answer it did not give (%d)",
		s.stats.special_use,
	)

	// The control: an unlisted name in the same zone still reaches the table, so
	// the above is the list winning rather than blocking swallowing the zone.
	_, other, other_ok := handle_query(
		&s,
		leak_query("unlisted.onion."),
		.UDP,
		"127.0.0.1:5555",
		context.temp_allocator,
	)
	testing.expect(t, other_ok, "an unlisted .onion name went unanswered")
	testing.expectf(t, other == .Local, "unlisted.onion. came back as %v rather than from the table", other)

	free_all(context.temp_allocator)
}

/*
An anchor over `onion.` wins against the key that forwards it.

The forward-side bypass stands down for the same reason the reverse-side one
does, and this is the case that separates the two policies: `onion: false` says
the upstream can answer these names, an anchor over `onion.` says the operator
wants what comes back checked, and the anchor is the more specific of the two.
Without this, the narrower instruction would lose to the broader one - and it
would lose silently, since an unvalidated answer looks like a working one.

SERVFAIL is the pass condition, which reads oddly until you consider what the
alternative means. The mock is a tor-like upstream with no chain at all, so a
validator that is *consulted* can only fail; that it failed is the evidence it
was asked. The test above is the same arrangement without the anchor, where
NOERROR is the evidence it was not.
*/
@(test)
test_an_anchor_over_onion_beats_the_key_that_forwards_it :: proc(t: ^testing.T) {
	name := "duskgytldkxiuqc6otgh4.onion."
	cfg := config.default_config()
	cfg.special_use.onion = false

	s, x, built := leak_server(t, &cfg, name)
	if !built {
		return
	}
	defer net.close(x.socket)
	defer upstream.destroy_group(s.group)

	s.validator = dnssec.make_validator(tor_has_no_chain, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	anchors := make([]string, 1, context.temp_allocator)
	anchors[0] = "onion."
	s.anchor_zones = anchors

	mock := thread.create_and_start_with_poly_data(x, serve_leak)
	out, _, ok := handle_query(&s, leak_query(name), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, ok, "the anchored .onion query went unanswered") {
		return
	}
	resp, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the response will not decode: %v", derr) {
		return
	}
	testing.expectf(
		t,
		dns.rcode_of(resp) == .Serv_Fail,
		"came back as %v: the anchor was ignored and the bypass stood",
		dns.rcode_of(resp),
	)

	// And the label boundary holds here too: an anchor over `onion.` is not an
	// anchor over somebody else's `notonion.`, so that name keeps the bypass.
	other := "x.notonion."
	ocfg := config.default_config()
	ocfg.special_use.onion = false
	os_, ox, obuilt := leak_server(t, &ocfg, other)
	if !obuilt {
		return
	}
	defer net.close(ox.socket)
	defer upstream.destroy_group(os_.group)
	testing.expect(
		t,
		!special_use_deferred(&os_, other),
		"notonion. was treated as being inside onion.",
	)

	free_all(context.temp_allocator)
}
