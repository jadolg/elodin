package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:upstream"

/*
An answer that points a public name back into the network the client sits on.

This is the DNS half of a rebinding attack: a page loaded from
`rebind.attacker.example` is same-origin with whatever that name resolves to, so
an answer of 127.0.0.1 or 192.168.1.1 lets the page reach the router's admin
page or a service bound to loopback. dnsmasq calls the guard
`--stop-dns-rebind`, AdGuard Home calls it rebinding protection, and both drop
private addresses arriving from an upstream.
*/

@(private = "file")
Rebind_Mock :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
}

@(private = "file")
serve_rebind :: proc(x: ^Rebind_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	out: [4096]u8
	copy(out[:], x.reply)
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
rebind_query :: proc(name: string) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = .A, class = .IN}
	msg := dns.Message{id = 0x4321, question = questions}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
rebind_reply :: proc(name: string, addr: [4]u8) -> []u8 {
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

@(private = "file")
is_private_v4 :: proc(a: [4]u8) -> bool {
	switch {
	case a[0] == 127:
		return true
	case a[0] == 10:
		return true
	case a[0] == 172 && a[1] >= 16 && a[1] <= 31:
		return true
	case a[0] == 192 && a[1] == 168:
		return true
	case a[0] == 169 && a[1] == 254:
		return true
	}
	return false
}

@(test)
test_a_public_name_is_not_answered_with_a_private_address :: proc(t: ^testing.T) {
	addresses := [][4]u8{{127, 0, 0, 1}, {192, 168, 1, 1}, {10, 0, 0, 5}, {169, 254, 169, 254}}

	for addr in addresses {
		socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
		if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
			return
		}
		defer net.close(socket)
		_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
		bound, _ := net.bound_endpoint(socket)

		cfg := config.default_config()
		cfg.log.queries = false
		cfg.cache.enabled = false
		cfg.dnssec.enabled = false
		cfg.blocking.enabled = false
		cfg.upstream.strategy = .Failover
		cfg.upstream.attempts = 1
		cfg.upstream.timeout = 3 * time.Second
		servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
		servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
		cfg.upstream.servers = servers

		group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
		if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
			return
		}
		defer upstream.destroy_group(group)
		s := Server{cfg = &cfg, group = group}

		x := Rebind_Mock{socket = socket, reply = rebind_reply("rebind.attacker.example.", addr)}
		mock := thread.create_and_start_with_poly_data(&x, serve_rebind)
		out, _, ok := handle_query(
			&s,
			rebind_query("rebind.attacker.example."),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		thread.join(mock)
		thread.destroy(mock)

		if !testing.expect(t, ok, "nothing came back at all") {
			return
		}
		decoded, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		for rec in decoded.answer {
			a, is_a := rec.data.(dns.Rdata_A)
			if !is_a {
				continue
			}
			testing.expectf(
				t,
				!is_private_v4(a.addr),
				"a public name was answered with %v, which is inside the client's own network",
				a.addr,
			)
		}
	}
	free_all(context.temp_allocator)
}

/*
Everything below asks the same question of the finished feature rather than of
the bug: the guard has to refuse the attack without refusing the deployments it
sits in front of, and that second half is where a check like this goes wrong.

The helpers are the reproducer's, generalised: one mock upstream, one query, one
answer that this file decides the contents of.
*/

@(private = "file")
rebind_query_type :: proc(name: string, type: dns.Type) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{id = 0x4321, question = questions}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
rebind_reply_of :: proc(name: string, type: dns.Type, answers: []dns.Record) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = type, class = .IN}
	msg := dns.Message{question = question, answer = answers}
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
a_record :: proc(name: string, addr: [4]u8) -> dns.Record {
	return dns.Record{name = name, type = .A, class = .IN, ttl = 60, data = dns.Rdata_A{addr = addr}}
}

@(private = "file")
aaaa_record :: proc(name: string, addr: [16]u8) -> dns.Record {
	return dns.Record{name = name, type = .AAAA, class = .IN, ttl = 60, data = dns.Rdata_AAAA{addr = addr}}
}

/*
Put one question to a server whose only upstream answers with `reply`.

`cfg` is the caller's, so each test says in its own body what configuration it is
about; the upstream is filled in here because the mock's port is not known until
it is bound. The cache is the caller's too, since the ordering against `cache.put`
is one of the things being tested and a helper that switched caching off could not
tell the difference between running before it and running instead of it.
*/
@(private = "file")
ask_with_reply :: proc(
	t: ^testing.T,
	cfg: ^config.Config,
	name: string,
	type: dns.Type,
	reply: []u8,
	answers: ^cache.Cache = nil,
) -> (
	decoded: dns.Message,
	ok: bool,
) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return {}, false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, _ := net.bound_endpoint(socket)

	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec{name = "mock", kind = .UDP, address = "127.0.0.1", port = bound.port}
	cfg.upstream.servers = servers
	cfg.upstream.strategy = .Failover
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 3 * time.Second

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return {}, false
	}
	defer upstream.destroy_group(group)
	s := Server {
		cfg     = cfg,
		group   = group,
		answers = answers,
	}

	x := Rebind_Mock{socket = socket, reply = reply}
	mock := thread.create_and_start_with_poly_data(&x, serve_rebind)
	out, _, sent := handle_query(&s, rebind_query_type(name, type), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, sent, "nothing came back at all") {
		return {}, false
	}
	msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the response did not decode: %v", derr) {
		return {}, false
	}
	return msg, true
}

// A configuration with nothing in the way of the check but the check itself.
@(private = "file")
rebind_config :: proc() -> config.Config {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = false
	return cfg
}

@(private = "file")
addresses_in :: proc(msg: dns.Message) -> (out: [dynamic][16]u8) {
	out = make([dynamic][16]u8, 0, 2, context.temp_allocator)
	for rec in msg.answer {
		#partial switch data in rec.data {
		case dns.Rdata_A:
			a: [16]u8
			a[0], a[1], a[2], a[3] = data.addr[0], data.addr[1], data.addr[2], data.addr[3]
			append(&out, a)
		case dns.Rdata_AAAA:
			append(&out, data.addr)
		}
	}
	return out
}

@(private = "file")
v4_bytes :: proc(a: [4]u8) -> (out: [16]u8) {
	out[0], out[1], out[2], out[3] = a[0], a[1], a[2], a[3]
	return out
}

/*
The other half of the guard, and the half that decides whether it can be on by
default: an answer that is not pointing anywhere private goes through untouched.

Worth a test of its own rather than being taken as read from the refusals above.
A check that refused everything would pass every one of them.
*/
@(test)
test_a_public_address_is_forwarded_unchanged :: proc(t: ^testing.T) {
	cfg := rebind_config()
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("ok.example.", {93, 184, 216, 34})
	reply := rebind_reply_of("ok.example.", .A, records)

	msg, ok := ask_with_reply(t, &cfg, "ok.example.", .A, reply)
	if !ok {
		return
	}
	got := addresses_in(msg)
	if testing.expect_value(t, len(got), 1) {
		testing.expect_value(t, got[0], v4_bytes({93, 184, 216, 34}))
	}
	free_all(context.temp_allocator)
}

/*
Split horizon, which is the deployment this feature has to not break.

A site whose upstream is its own internal server resolves `nas.corp.example` to
an RFC 1918 address through the public name space, and that is a normal thing to
run rather than an attack. `rebind.allow_domains` names the zone, and the
exemption covers everything below it - an operator writing a zone name is not
also expected to enumerate the hosts in it.
*/
@(test)
test_an_exempt_domain_may_resolve_to_a_private_address :: proc(t: ^testing.T) {
	names := []string{"corp.example.", "nas.corp.example.", "a.b.corp.example."}
	for name in names {
		cfg := rebind_config()
		exempt := make([]string, 1, context.temp_allocator)
		exempt[0] = "corp.example."
		cfg.rebind.allow_domains = exempt

		records := make([]dns.Record, 1, context.temp_allocator)
		records[0] = a_record(name, {192, 168, 1, 50})
		msg, ok := ask_with_reply(t, &cfg, name, .A, rebind_reply_of(name, .A, records))
		if !ok {
			return
		}
		got := addresses_in(msg)
		testing.expectf(t, len(got) == 1, "%s was refused despite rebind.allow_domains covering it", name)
	}

	/*
	And the exemption stops at the label break. `notcorp.example` is not inside
	`corp.example`, however much of a string suffix it is - the same rule the
	rewrites and the locally-served zones are matched by, and the reason all
	three go through `name_at_or_below`.
	*/
	cfg := rebind_config()
	exempt := make([]string, 1, context.temp_allocator)
	exempt[0] = "corp.example."
	cfg.rebind.allow_domains = exempt

	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("notcorp.example.", {192, 168, 1, 50})
	msg, ok := ask_with_reply(t, &cfg, "notcorp.example.", .A, rebind_reply_of("notcorp.example.", .A, records))
	if ok {
		testing.expect_value(t, len(msg.answer), 0)
	}
	free_all(context.temp_allocator)
}

/*
The v6 half of the address set, and the one entry of it that is not a v6 address
at all.

`::ffff:192.168.1.1` is 192.168.1.1 to every stack that connects to it, so an
AAAA record holding one is a way to write a private address that a check reading
sixteen bytes as an IPv6 address would not see. `address_in` undoes the mapping
for the same reason `source_allowed` does on the way in.
*/
@(test)
test_private_ipv6_answers_are_refused_too :: proc(t: ^testing.T) {
	refused := [][16]u8 {
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // ::1
		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // fe80::1
		{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // fd00::1
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1}, // ::ffff:192.168.1.1
		{}, // ::
	}
	for addr in refused {
		cfg := rebind_config()
		records := make([]dns.Record, 1, context.temp_allocator)
		records[0] = aaaa_record("rebind.attacker.example.", addr)
		msg, ok := ask_with_reply(
			t,
			&cfg,
			"rebind.attacker.example.",
			.AAAA,
			rebind_reply_of("rebind.attacker.example.", .AAAA, records),
		)
		if !ok {
			return
		}
		testing.expectf(t, len(msg.answer) == 0, "a public name was answered with %v", addr)
		testing.expect_value(t, msg.flags.rcode, u8(dns.Rcode.No_Error))
	}

	// 2001:4860:4860::8888 is a public address and stays one.
	cfg := rebind_config()
	public := [16]u8{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = aaaa_record("ok.example.", public)
	msg, ok := ask_with_reply(t, &cfg, "ok.example.", .AAAA, rebind_reply_of("ok.example.", .AAAA, records))
	if ok {
		testing.expect_value(t, len(msg.answer), 1)
	}
	free_all(context.temp_allocator)
}

/*
A rewrite is what an operator uses to point a name at their own NAS, so it is the
first thing this must not break.

It cannot: `apply_rewrite` answers out of the configuration before anything is
forwarded, so the guard never sees the name. Pinned all the same, because that is
a fact about where the two sit in `resolve_query` rather than about either of
them - a rewrite moved below the forwarding path would acquire the problem
silently, and this is what would say so.
*/
@(test)
test_a_rewritten_name_keeps_its_private_address :: proc(t: ^testing.T) {
	cfg := rebind_config()
	answers := make([]config.Rewrite_Answer, 1, context.temp_allocator)
	answers[0] = config.Rewrite_Answer{kind = .A, v4 = {192, 168, 1, 50}}
	rules := make([]config.Rewrite, 1, context.temp_allocator)
	rules[0] = config.Rewrite{domain = "nas.home.", answers = answers, ttl = 60}
	cfg.rewrites = rules

	// The upstream would answer with a public address, so anything but
	// 192.168.1.50 coming back means the rewrite was not what answered.
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("nas.home.", {93, 184, 216, 34})
	msg, ok := ask_with_reply(t, &cfg, "nas.home.", .A, rebind_reply_of("nas.home.", .A, records))
	if !ok {
		return
	}
	got := addresses_in(msg)
	if testing.expect_value(t, len(got), 1) {
		testing.expect_value(t, got[0], v4_bytes({192, 168, 1, 50}))
	}
	free_all(context.temp_allocator)
}

/*
One bad record refuses the whole answer.

Filtering it out and serving the rest is what Unbound does and is the tempting
shape, but it makes the guard's correctness depend on being exhaustive over every
way an address can appear in a message. Refusing the message is one decision, and
it is the one that holds for an RR type this code does not model yet.
*/
@(test)
test_one_private_address_refuses_the_whole_answer :: proc(t: ^testing.T) {
	cfg := rebind_config()
	records := make([]dns.Record, 2, context.temp_allocator)
	records[0] = a_record("mixed.attacker.example.", {93, 184, 216, 34})
	records[1] = a_record("mixed.attacker.example.", {192, 168, 1, 1})

	msg, ok := ask_with_reply(
		t,
		&cfg,
		"mixed.attacker.example.",
		.A,
		rebind_reply_of("mixed.attacker.example.", .A, records),
	)
	if !ok {
		return
	}
	testing.expect_value(t, len(msg.answer), 0)
	/*
	NODATA rather than SERVFAIL: a stub with a second resolver configured treats
	SERVFAIL as this server having failed and asks the other one, which on a home
	network is the router - and the router answers 192.168.1.1 quite happily. The
	refusal would route the attack around itself.
	*/
	testing.expect_value(t, msg.flags.rcode, u8(dns.Rcode.No_Error))
	// With an SOA to say how long to remember it, so the name is not re-asked
	// every second while an attack runs.
	testing.expect_value(t, len(msg.authority), 1)
	free_all(context.temp_allocator)
}

/*
`rebind.allow_loopback` opens 127.0.0.0/8 and ::1, and nothing else.

dnsmasq draws `--rebind-localhost-ok` at exactly this line. The half of the test
that matters is the second one: a switch that also let RFC 1918 through would be
one an operator reaches for to fix a loopback name and thereby turns the feature
off.
*/
@(test)
test_allow_loopback_opens_loopback_alone :: proc(t: ^testing.T) {
	cfg := rebind_config()
	cfg.rebind.allow_loopback = true

	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("local.example.", {127, 0, 0, 1})
	msg, ok := ask_with_reply(t, &cfg, "local.example.", .A, rebind_reply_of("local.example.", .A, records))
	if !ok {
		return
	}
	testing.expect_value(t, len(msg.answer), 1)

	private := make([]dns.Record, 1, context.temp_allocator)
	private[0] = a_record("router.example.", {192, 168, 1, 1})
	msg2, ok2 := ask_with_reply(t, &cfg, "router.example.", .A, rebind_reply_of("router.example.", .A, private))
	if ok2 {
		testing.expect_value(t, len(msg2.answer), 0)
	}
	free_all(context.temp_allocator)
}

/*
The refusal happens before `cache.put`, and nothing about it is stored.

Two things are being said. The first is the ordering the whole feature rests on:
an answer cached before the check is one every later client is served without the
check running again, so the second query here would come back with 192.168.1.1
out of the cache and never reach an upstream. The second is that the synthesised
NODATA is not cached either - what was seen was one answer rather than a property
of the name, and an upstream that answers sensibly a moment later is believed.
*/
@(test)
test_a_refused_answer_is_not_cached :: proc(t: ^testing.T) {
	cfg := rebind_config()
	cfg.cache.enabled = true
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	bad := make([]dns.Record, 1, context.temp_allocator)
	bad[0] = a_record("flip.example.", {192, 168, 1, 1})
	first, ok := ask_with_reply(t, &cfg, "flip.example.", .A, rebind_reply_of("flip.example.", .A, bad), answers)
	if !ok {
		return
	}
	testing.expect_value(t, len(first.answer), 0)
	testing.expect_value(t, cache.len_entries(answers), 0)

	good := make([]dns.Record, 1, context.temp_allocator)
	good[0] = a_record("flip.example.", {93, 184, 216, 34})
	second, ok2 := ask_with_reply(t, &cfg, "flip.example.", .A, rebind_reply_of("flip.example.", .A, good), answers)
	if !ok2 {
		return
	}
	got := addresses_in(second)
	if testing.expect_value(t, len(got), 1) {
		testing.expect_value(t, got[0], v4_bytes({93, 184, 216, 34}))
	}
	free_all(context.temp_allocator)
}

/*
Off is off.

The setting has to restore the previous behaviour exactly, because the operator
reaching for it is one whose network this broke and who needs the server
resolving again in one line while they work out which zone to exempt.
*/
@(test)
test_the_guard_can_be_turned_off :: proc(t: ^testing.T) {
	cfg := rebind_config()
	cfg.rebind.enabled = false

	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("rebind.attacker.example.", {192, 168, 1, 1})
	msg, ok := ask_with_reply(
		t,
		&cfg,
		"rebind.attacker.example.",
		.A,
		rebind_reply_of("rebind.attacker.example.", .A, records),
	)
	if !ok {
		return
	}
	got := addresses_in(msg)
	if testing.expect_value(t, len(got), 1) {
		testing.expect_value(t, got[0], v4_bytes({192, 168, 1, 1}))
	}
	free_all(context.temp_allocator)
}

/*
An HTTPS record's `ipv4hint` is an address a browser connects to without ever
having asked for the A record, so a guard that only read A and AAAA would have a
documented way round it (RFC 9460 section 7.3).

The hints are inside the RDATA of the name in the question rather than glue for
somebody else's name, which is what separates them from the additional section
this deliberately does not read.
*/
@(test)
test_an_https_record_cannot_hint_at_a_private_address :: proc(t: ^testing.T) {
	// One SvcParam: key 4 (ipv4hint), four bytes of value, 192.168.1.1.
	params := make([]u8, 8, context.temp_allocator)
	params[0], params[1] = 0, 4
	params[2], params[3] = 0, 4
	params[4], params[5], params[6], params[7] = 192, 168, 1, 1

	cfg := rebind_config()
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = dns.Record {
		name  = "svc.attacker.example.",
		type  = .HTTPS,
		class = .IN,
		ttl   = 60,
		data  = dns.Rdata_SVCB{priority = 1, target = ".", params = params},
	}
	msg, ok := ask_with_reply(
		t,
		&cfg,
		"svc.attacker.example.",
		.HTTPS,
		rebind_reply_of("svc.attacker.example.", .HTTPS, records),
	)
	if !ok {
		return
	}
	testing.expect_value(t, len(msg.answer), 0)
	free_all(context.temp_allocator)
}

/*
`localhost.` may be answered with loopback, without anybody configuring it.

RFC 6761 section 6.3 makes 127.0.0.1 and ::1 the only answers that name can
have, so this is not the operator granting latitude but the guard declining to
refuse the one answer the standard permits. It is deliberately not a setting,
and deliberately not deferred to the RFC 6761 handling that would answer the
name locally and keep it off the forwarding path entirely: two guards whose
correctness depends on which of them merged first is a live bug waiting for one
to land while the other is still in review.

The second half is the scope. The exemption is for the addresses section 6.3
allows, not for the name - an upstream answering `evil.localhost` with
192.168.1.1 is doing something the RFC does not permit either, and gets no
latitude from this.
*/
@(test)
test_localhost_may_be_answered_with_loopback :: proc(t: ^testing.T) {
	loopback := [16]u8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	names := []string{"localhost.", "app.localhost."}
	for name in names {
		cfg := rebind_config()
		records := make([]dns.Record, 1, context.temp_allocator)
		records[0] = a_record(name, {127, 0, 0, 1})
		msg, ok := ask_with_reply(t, &cfg, name, .A, rebind_reply_of(name, .A, records))
		if !ok {
			return
		}
		testing.expectf(t, len(msg.answer) == 1, "%s was refused its own loopback address", name)

		v6cfg := rebind_config()
		v6recs := make([]dns.Record, 1, context.temp_allocator)
		v6recs[0] = aaaa_record(name, loopback)
		v6msg, v6ok := ask_with_reply(t, &v6cfg, name, .AAAA, rebind_reply_of(name, .AAAA, v6recs))
		if v6ok {
			testing.expectf(t, len(v6msg.answer) == 1, "%s was refused ::1", name)
		}
	}

	// Loopback and no further: RFC 1918 out of a `.localhost` name is not an
	// answer section 6.3 permits, so the exemption does not reach it.
	cfg := rebind_config()
	records := make([]dns.Record, 1, context.temp_allocator)
	records[0] = a_record("evil.localhost.", {192, 168, 1, 1})
	msg, ok := ask_with_reply(t, &cfg, "evil.localhost.", .A, rebind_reply_of("evil.localhost.", .A, records))
	if ok {
		testing.expect_value(t, len(msg.answer), 0)
	}

	// And the label break holds here as everywhere else: `notlocalhost.` is not
	// inside `localhost.`.
	plain := rebind_config()
	precs := make([]dns.Record, 1, context.temp_allocator)
	precs[0] = a_record("notlocalhost.", {127, 0, 0, 1})
	pmsg, pok := ask_with_reply(t, &plain, "notlocalhost.", .A, rebind_reply_of("notlocalhost.", .A, precs))
	if pok {
		testing.expect_value(t, len(pmsg.answer), 0)
	}
	free_all(context.temp_allocator)
}

/*
`blocking.response: zeroip` answers a blocked name with 0.0.0.0, and 0.0.0.0 is
in the set of addresses this guard refuses.

Those two do not collide, because a block response is built locally by
`build_block_response` and never travels the forwarding path the check sits on.
But that is a fact about where the call site is, not about either feature: a
check moved to cover locally-built answers would refuse every blocked name and
take the whole blocking feature down with it, silently, for the one
`blocking.response` mode that produces an address. This is what would fail
instead.

Both families, since `zeroip` answers AAAA with `::` and that is in the set too.
*/
@(test)
test_a_zero_ip_block_response_still_reaches_the_client :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.dnssec.enabled = false
	cfg.blocking.enabled = true
	cfg.blocking.response = .Zero_IP
	// The guard is on, as it is by default. That is the point of the test.
	testing.expect(t, cfg.rebind.enabled)

	block, allow := filter.set_make(), filter.set_make()
	filter.parse_list(block, allow, "0.0.0.0 ads.example.com\n", .Hosts)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, block, allow)

	s := Server {
		cfg     = &cfg,
		filters = engine,
	}

	types := []dns.Type{.A, .AAAA}
	for type in types {
		out, outcome, ok := handle_query(
			&s,
			rebind_query_type("ads.example.com.", type),
			.UDP,
			"127.0.0.1:5555",
			context.temp_allocator,
		)
		if !testing.expectf(t, ok, "the %v block response was not sent at all", type) {
			return
		}
		testing.expect_value(t, outcome, Outcome.Blocked)

		msg, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		testing.expectf(
			t,
			len(msg.answer) == 1,
			"the %v sink answer was refused: blocking with zeroip has been taken down by the rebinding guard",
			type,
		)
	}
	free_all(context.temp_allocator)
}
