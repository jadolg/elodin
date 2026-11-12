package itest

import "core:fmt"
import "core:strings"
import "elodin:dns"

/*
Per-domain upstreams (`upstream.zones`), end to end.

The deployment: a network that runs
its own DNS for its own zone - a domain controller for `corp.example`, a router
answering `home.arpa.` - while everything else goes to a public resolver. Two
mocks stand in for the two, and every case below is about which of them a name
reaches and what the server then does with the reply.

Three properties, all of which have to hold together for the deployment to work
and each of which fails differently:

  - the routed name reaches the local authority, and the public upstream never
    hears it (issue #200, RFC 8375 section 3);
  - the reply is served rather than validated, since a local zone's unsigned
    data sits under a public parent that delegates nothing to it;
  - the reply may carry private addresses, since answering with private
    addresses is what a local authority is for.

Everything else keeps going to `upstream.servers`, which is the fourth case and
the one that would take the whole resolver down with it.
*/

@(private = "file")
INTERNAL :: [4]u8{10, 0, 0, 7}
@(private = "file")
PUBLIC :: [4]u8{198, 51, 100, 9}

/*
The `dnssec` section is a parameter rather than something a caller appends.

Appending it would put a second top-level `dnssec:` in the document, and which
of the two won would then be the YAML loader's business rather than the test's -
`yaml` happens to keep the last, so the anchored case below would go on passing
for a reason nothing in it states. One key, written once, whoever is asking.
*/
@(private = "file")
DEFAULT_DNSSEC :: `dnssec:
  enabled: true
`

/*
A `DS` answer for `name`, as a parent that signs its delegation gives one.

`Rdata_Raw` rather than a modelled DS: what the server reads is the record's
type, not anything inside it, and the bytes are a well-formed DS RDATA all the
same - key tag, algorithm 8, digest type 2, a SHA-256-sized digest - so a
decoder walking the section finds a record it can measure rather than reject.

The wire goes on the heap rather than into the temp allocator, as every other
canned payload in the suite does: the mock holds that slice for the whole run,
and `end_case` empties the temp arena under it long before the case that asks
for it. The records it is built from are another matter - `encode_message` copies
the RDATA into the wire, so nothing here outlives the call and the temp arena is
where it belongs.
*/
@(private = "file")
signed_delegation_reply :: proc(name: string) -> []u8 {
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
	return encode_reply(name, .DS, {answer = answer})
}

/*
A NODATA for `name`'s `DS` whose NSEC shows a name the parent holds itself: A,
RRSIG and NSEC in the bitmap and no NS, so nothing is delegated there (issue
#244). On the heap, as `signed_delegation_reply` is, for the same reason.
*/
@(private = "file")
held_name_reply :: proc(name: string) -> []u8 {
	// The next name is the root; window 0 holds A (byte 0) and RRSIG, NSEC (byte 5).
	nsec := []u8{0, 0, 6, 0x40, 0, 0, 0, 0, 0x03}
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = dns.Record{name = name, type = .NSEC, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = nsec}}
	return encode_reply(name, .DS, {authority = authority})
}

// One `upstream.zones` entry: `domains`, a flow list's contents, sent to the
// mock on `port`.
@(private = "file")
zone_route :: proc(domains: string, port: int) -> string {
	return fmt.tprintf("    - domains: [%s]\n      servers: [udp://127.0.0.1:%d]\n", domains, port)
}

/*
A server whose `upstream.servers` are the mocks on `servers`, tried once each,
with `zones` (`zone_route` entries) routed past them. The cache and blocking are
off, as everywhere, and the rebinding guard is on unless a case says otherwise.
*/
@(private = "file")
routed_config :: proc(
	udp_port: int,
	servers: []int,
	zones: string,
	dnssec := DEFAULT_DNSSEC,
	rebind := true,
	strategy := "",
) -> string {
	list := strings.builder_make(context.temp_allocator)
	strings.write_byte(&list, '[')
	for port, i in servers {
		fmt.sbprintf(&list, "%sudp://127.0.0.1:%d", ", " if i > 0 else "", port)
	}
	strings.write_byte(&list, ']')
	upstream := strings.builder_make(context.temp_allocator)
	strings.write_string(&upstream, "  attempts: 1\n")
	if strategy != "" {
		fmt.sbprintf(&upstream, "  strategy: %s\n", strategy)
	}
	fmt.sbprintf(&upstream, "  zones:\n%s", zones)
	return base_config(
		udp_port,
		strings.to_string(list),
		log = "{ level: info }",
		upstream_extra = strings.to_string(upstream),
		extra = fmt.tprintf("%srebind: {{ enabled: %v }}\n", dnssec, rebind),
	)
}

/*
`--check` says what a route gives up, and says it only where there is something
to give up.

The coupling is deliberate and argued in `routes.odin`, but nothing at load can
tell a network's own `corp.example` from a public signed zone routed down a VPN,
and in the second case a route turns off two checks that were working. One line
per route is what stands in for the per-route key this does not have, so the
line has to actually appear - and has to stay absent for a file that turned both
checks off itself, or it is noise where a real warning should be.
*/
@(private = "file")
run_route_warning_cases :: proc(r: ^Runner) {
	ROUTE :: "upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n      servers: [10.0.0.1]\n"

	start_case(r, "upstream.zones: --check says what a route gives up")
	{
		// dnssec on by default, rebind off by default: one of the two.
		res := check_config_text(r, "route-warn", ROUTE)
		if res.ok {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.contains(res.output, "corp.example."), "the warning does not name the routed zone: %q", res.output)
			check(r, strings.contains(res.output, "insecure"), "the warning does not mention validation: %q", res.output)
			check(
				r,
				!strings.contains(res.output, "rebind protection"),
				"a guard the file leaves off was named anyway: %q",
				res.output,
			)
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: with both guards on the warning names both")
	{
		body := fmt.tprintf("%srebind:\n  enabled: true\n", ROUTE)
		res := check_config_text(r, "route-warn-both", body)
		if res.ok {
			check(r, strings.contains(res.output, "insecure"), "validation was not named: %q", res.output)
			check(r, strings.contains(res.output, "rebind protection"), "the rebinding guard was not named: %q", res.output)
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: an anchored route is not said to give up validation")
	{
		/*
		The one file where the first half of that line would be untrue.

		`covered_by_local_anchor` stands the route's bypass down for a name an
		anchor covers, so a site that signed its own zone and anchored it gives
		up no validation at all by routing it. Telling it otherwise would be the
		warning misfiring at the most careful configuration there is. The second
		half still holds and is asserted with it: an anchor says nothing about
		what addresses the zone may answer with.

		The root DS is listed alongside because `trust_anchors` replaces the
		built-in keys rather than adding to them.
		*/
		body := fmt.tprintf(
			"%sdnssec:\n  enabled: true\n  trust_anchors:\n    - %q\n    - %q\nrebind:\n  enabled: true\n",
			ROUTE,
			". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			"corp.example. IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		)
		res := check_config_text(r, "route-warn-anchored", body)
		if res.ok {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(
				r,
				!strings.contains(res.output, "insecure"),
				"an anchored route was said to be served insecure: %q",
				res.output,
			)
			check(
				r,
				strings.contains(res.output, "rebind protection"),
				"the rebinding guard was not named: %q",
				res.output,
			)
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: nothing is claimed for a check the file already turned off")
	{
		// Both off: the route gives up neither, so a line naming either would be
		// telling the operator they lost something they had already declined.
		body := fmt.tprintf("%sdnssec:\n  enabled: false\n", ROUTE)
		res := check_config_text(r, "route-warn-none", body)
		if res.ok {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(
				r,
				!strings.contains(res.output, "giving up"),
				"a route gave up nothing and said otherwise: %q",
				res.output,
			)
		}
	}
	end_case(r)
}

run_zone_route_cases :: proc(r: ^Runner) {
	run_route_warning_cases(r)

	public_port := next_port(r)
	public := mock_make("public", public_port)
	mock_synth_all(public, PUBLIC)
	/*
	The one question this mock denies, scripted here rather than in the case that
	needs it: `match_rule` walks `m.rules` from the serving threads without the
	mutex, so appending a rule to a mock that is already running races with them -
	and the append reallocates the moment the rules outgrow their capacity, which
	turns the race into a read of freed memory. Every other rule in the suite is
	written before `mock_start` for the same reason.

	Read with "an apex DS the parent denies goes back to the route" below, which
	is the case it is for.
	*/
	mock_rcode(public, "denied.example.", u16(dns.Type.DS), .NX_Domain)
	// And the one it signs, for the case below it: a zone the public tree really
	// does delegate, whose DS is not the "no data" the carve-out went to fetch.
	mock_reply(public, "signed.example.", u16(dns.Type.DS), signed_delegation_reply("signed.example."))
	// And a name it holds itself, which is no delegation for the NODATA to prove.
	mock_reply(public, "held.example.", u16(dns.Type.DS), held_name_reply("held.example."))
	if !mock_start_or_skip(r, public, "upstream.zones") {
		return
	}
	defer mock_stop(public)

	internal_port := next_port(r)
	internal := mock_make("internal", internal_port)
	mock_synth_all(internal, INTERNAL)
	for f in ANCHORED_CORP_FIXTURES {
		mock_reply(internal, f.qname, f.qtype, from_hex(f.response, context.allocator))
	}
	if !mock_start_or_skip(r, internal, "upstream.zones") {
		return
	}
	defer mock_stop(internal)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = routed_config(udp_port, {public_port}, zone_route("corp.example", internal_port)), udp_port = udp_port},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "upstream.zones: a routed name is answered by its own upstream")
	{
		/*
		Three assertions in one exchange, because the deployment needs all
		three and any one of them alone is a feature that does not work.

		The address proves the query went to the local authority. `dnssec` is on
		and the mock cannot sign anything, so the answer coming back at all -
		rather than as the SERVFAIL every other unsigned name gets below - proves
		the route took the zone out of the chain walk. `rebind` is on and
		10.0.0.7 is RFC 1918 space, so the address surviving proves the route
		exempted the zone without it having to appear in
		`rebind.allow_domains` as well.
		*/
		mock_reset_counts(public)
		if res, h, answered := ask(r, udp_port, "nas.corp.example.", u16(dns.Type.A)); answered {
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a routed name")

			check_one_address(r, res.wire, "10.0.0.7", "address for a routed name")
		}

		// The half that closes the issue: the internal name did not also go to
		// the public resolver, which is the leak RFC 8375 section 3 is about.
		u, t, s := mock_counts(public)
		check(r, u + t + s == 0, "the routed name leaked to the public upstream (%d queries)", u + t + s)
	}
	end_case(r)

	start_case(r, "upstream.zones: the zone's own apex follows the route")
	{
		// A route covers the zone it names as well as everything under it, which
		// is what `server=/corp.example/` means to a dnsmasq operator.
		mock_reset_counts(public)
		res := query_udp(udp_port, build_query("corp.example.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_one_address(r, res.wire, "10.0.0.7", "address for the routed apex")
		}
		u, t, s := mock_counts(public)
		check(r, u + t + s == 0, "the routed apex leaked to the public upstream")
	}
	end_case(r)

	start_case(r, "upstream.zones: the apex DS does not follow the route")
	{
		/*
		The one exception to the case above, and issue #227.

		A validating client below this server walks down from `example.` and
		asks `corp.example. DS` for itself. The domain controller the route
		points at is authoritative for the zone and answers that out of its own
		data - an unsigned "no data", no NSEC - while the signed proof about the
		delegation lives in the parent and nowhere else. The client reads that as
		a chain broken rather than provably absent, which is SERVFAIL for every
		name in the zone: the failure RFC 8375 section 4 item 4.B carves this
		query out of the same MUST NOT to prevent, and the one the chain lookups
		elodin makes on its own account already avoid by staying on the default
		group.

		Asserted on which mock was asked rather than on the answer, since what is
		under test is where the question went. Both directions, because a
		carve-out that sent it to both upstreams would keep the DS working and go
		on telling the domain controller nothing it did not know, while a
		selector that had simply stopped matching the zone would pass the
		public-side half alone.
		*/
		mock_reset_counts(public)
		mock_reset_counts(internal)
		if _, h, answered := ask(r, udp_port, "corp.example.", u16(dns.Type.DS)); answered {
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for the routed apex DS")
		}
		check(r, mock_total(public) > 0, "the apex DS never reached the upstream that can answer it")
		check(r, mock_total(internal) == 0, "the apex DS was sent to the zone's own authority")
	}
	end_case(r)

	start_case(r, "upstream.zones: an apex DS the parent denies goes back to the route")
	{
		/*
		The other side of the carve-out above, on the deployment it exists for:
		an internal zone under a public parent that delegates nothing to it -
		`corp.example.com` on a domain controller, `example.com` signed and
		public. Asked for that zone's `DS`, the public upstream does not answer
		"insecure delegation"; it answers, signed, that the name does not exist.

		Handing that to the client is worse than the answer it replaced. An
		unsigned NODATA from the domain controller leaves a lenient validator
		free to treat the zone as unsigned and resolve it, where a signed proof
		of non-existence takes that freedom away - and a validator implementing
		RFC 8020 reads it as proof that every name under the apex is gone too.
		So an NXDOMAIN from the parent's group is read as "nothing public
		delegates this zone" and the question goes back on the route, which is
		the only thing that can answer for it at all.

		A zone of its own and a server of its own, because the public mock
		answers this one question NXDOMAIN and the case above needs it answering
		normally. The control for this case is that one: there the parent replies
		NOERROR and the route is never asked.

		The rule that denies `denied.example. DS` is scripted where the mock is
		built, above, rather than here - a rule appended to a running mock races
		with the threads reading them.
		*/
		denied_port := next_port(r)
		config := routed_config(
			denied_port,
			{public_port},
			zone_route("denied.example", internal_port),
			dnssec = "dnssec: { enabled: false }\n",
			rebind = false,
		)
		denied, started := start_server(r, Server_Options{config = config, udp_port = denied_port})
		if started {
			defer stop_server(&denied)
			mock_reset_counts(internal)
			if _, h, answered := ask(r, denied_port, "denied.example.", u16(dns.Type.DS)); answered {
				// The route's answer, not the parent's NXDOMAIN.
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode after the parent denied the zone")
			}
			check(r, mock_total(internal) > 0, "the denied apex DS was not put back on the route")
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: an apex DS the parent signs goes back to the route too")
	{
		/*
		The second way the parent's answer is not the one the carve-out went for:
		a zone that really is delegated and signed in the public tree, routed to
		an internal view of itself. That is split horizon, and the internal view
		is very unlikely to be the signed one - so handing the client the public
		DS makes it demand a DNSKEY the view has no matching key for, and bogus
		is what it gets, where the same deployment resolved before the carve-out
		existed.

		`signed.example.` is answered with a DS RRset by the public mock and
		routed to the internal one, and the assertion is that the internal mock
		was asked and the client's answer carries no DS. The rule is one line in
		`parent_answers_apex_ds`: of the statements a parent can make about the
		delegation, only a NODATA keeps the question there.
		*/
		signed_port := next_port(r)
		config := routed_config(
			signed_port,
			{public_port},
			zone_route("signed.example", internal_port),
			dnssec = "dnssec: { enabled: false }\n",
			rebind = false,
		)
		signed, started := start_server(r, Server_Options{config = config, udp_port = signed_port})
		if started {
			defer stop_server(&signed)
			mock_reset_counts(internal)
			if res, h, answered := ask(r, signed_port, "signed.example.", u16(dns.Type.DS)); answered {
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a signed routed apex")
				check(
					r,
					!answer_has_type(r, res.wire, u16(dns.Type.DS)),
					"the parent's DS reached the client for a zone the route answers",
				)
			}
			check(r, mock_total(internal) > 0, "the signed apex DS was not put back on the route")
		}
	}
	end_case(r)

	{
		/*
		Issue #245. The parent's group has two members that disagree: the first
		answers NXDOMAIN for one apex and a `DS` RRset for another, the second
		answers both with the NODATA proof - an empty non-terminal one upstream
		denies against RFC 8020 is how that arises. Each reply from the first is
		answerable, and a sweep that stops there hands the question to the
		route while the group holds the proof.

		`round_robin`, where the flap lives, and two warm-up queries first so
		that each member has answered once: the sweep holds out for a proof
		only from a member known to be answering (`upstream.answering`). Each
		apex is then asked twice, so one of the two starts at the dissenting
		member. The assertion is the route never being asked: the proof came
		from the second member every time.
		*/
		name :: "upstream.zones: one parent member's denial does not hide another's proof"
		dissent_port := next_port(r)
		dissent := mock_make("dissent", dissent_port)
		mock_rcode(dissent, "split.example.", u16(dns.Type.DS), .NX_Domain)
		mock_reply(dissent, "split-signed.example.", u16(dns.Type.DS), signed_delegation_reply("split-signed.example."))
		if mock_start_or_skip(r, dissent, name) {
			defer mock_stop(dissent)
			start_case(r, name)
			split_port := next_port(r)
			config := routed_config(
				split_port,
				{dissent_port, public_port},
				zone_route("split.example, split-signed.example", internal_port),
				dnssec = "dnssec: { enabled: false }\n",
				rebind = false,
				strategy = "round_robin",
			)
			split, started := start_server(r, Server_Options{config = config, udp_port = split_port})
			if started {
				defer stop_server(&split)
				// One query starting at each member: the dissent's fallback
				// answers NXDOMAIN, the public mock an address.
				mock_reset_counts(public)
				for _ in 0 ..< 2 {
					warm := query_udp(split_port, build_query("warm.example.", u16(dns.Type.A)))
					check(r, warm.ok, "no response to the warm-up query")
				}
				check(r, mock_total(dissent) == 1 && mock_total(public) == 1, "the warm-up did not reach each member once")
				for apex in ([]string{"split.example.", "split-signed.example."}) {
					mock_reset_counts(dissent)
					mock_reset_counts(public)
					mock_reset_counts(internal)
					for _ in 0 ..< 2 {
						if res, h, answered := ask(r, split_port, apex, u16(dns.Type.DS), fmt.tprintf("no response for %s", apex)); answered {
							check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), fmt.tprintf("rcode for %s", apex))
							check(r, !answer_has_type(r, res.wire, u16(dns.Type.DS)), "the dissenting member's DS reached the client for %s", apex)
						}
					}
					// The premise: the dissenting member was asked, and answered.
					check(r, mock_total(dissent) > 0, "the dissenting member was not asked for %s", apex)
					check(r, mock_total(public) > 0, "the member holding the proof was not asked for %s", apex)
					check(r, mock_total(internal) == 0, "the route answered %s while the parent's group held the proof", apex)
				}
			}
			end_case(r)
		}
	}

	{
		/*
		The other side of the case above. A routed private zone under a public
		parent that denies it - `denied.example.`, answered NXDOMAIN - with a
		failover spare behind the public upstream that has gone silent. The
		NXDOMAIN is not the proof, so the sweep would hold out past it; but the
		spare has never answered, and waiting `g.timeout` on it puts a dead
		upstream in front of every query for a zone whose authority answers in
		milliseconds. Asserted on the spare's query count, not the clock.
		*/
		name :: "upstream.zones: a dead parent spare is not waited on past a denial"
		silent_port := next_port(r)
		silent := mock_make("silent", silent_port)
		mock_silent(silent)
		if mock_start_or_skip(r, silent, name) {
			defer mock_stop(silent)
			start_case(r, name)
			spare_port := next_port(r)
			config := routed_config(
				spare_port,
				{public_port, silent_port},
				zone_route("denied.example", internal_port),
				dnssec = "dnssec: { enabled: false }\n",
				rebind = false,
				strategy = "failover",
			)
			spare, started := start_server(r, Server_Options{config = config, udp_port = spare_port})
			if started {
				defer stop_server(&spare)
				mock_reset_counts(public)
				mock_reset_counts(internal)
				if _, h, answered := ask(r, spare_port, "denied.example.", u16(dns.Type.DS)); answered {
					check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode after the parent denied the zone")
				}
				// The premise: the public member was asked and denied the zone.
				check(r, mock_total(public) > 0, "the parent's live member was not asked")
				check(r, mock_total(silent) == 0, "the sweep waited on a spare that has never answered")
				check(r, mock_total(internal) > 0, "the denied apex DS was not put back on the route")
			}
			end_case(r)
		}
	}

	start_case(r, "upstream.zones: an apex DS for a name the parent holds goes back to the route")
	{
		/*
		The NODATA that is not the proof (issue #244). `held.example.` is a name
		the public parent publishes itself - an address for a portal - so its
		NSEC carries no NS bit and nothing is delegated there for the NODATA to
		prove insecure (RFC 4035 section 5.2). The control is "the apex DS does
		not follow the route" above, whose NODATA carries no NSEC at all and stays
		at the parent.
		*/
		held_port := next_port(r)
		config := routed_config(held_port, {public_port}, zone_route("held.example", internal_port), dnssec = "dnssec: { enabled: false }\n")
		held, started := start_server(r, Server_Options{config = config, udp_port = held_port})
		if started {
			defer stop_server(&held)
			mock_reset_counts(public)
			mock_reset_counts(internal)
			if _, h, answered := ask(r, held_port, "held.example.", u16(dns.Type.DS)); answered {
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a held routed apex")
			}
			check(r, mock_total(public) > 0, "the parent was not asked for the held apex DS")
			check(r, mock_total(internal) > 0, "a NODATA without the NS bit was read as an insecure delegation")
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: everything else still goes to upstream.servers")
	{
		/*
		The case that would be missed by testing only the feature. A selector
		that matched everything would pass both cases above and send the whole
		Internet to the domain controller, and the symptom - one internal server
		asked to recurse the world - is not visible from inside the routed zone.

		SERVFAIL rather than the address, and that is the assertion: this name
		has no route, so it is validated like any other public name, and the
		mock has no chain to offer. The routed name above got its answer through
		precisely because the route took it out of this path.
		*/
		mock_reset_counts(internal)
		if _, h, answered := ask(r, udp_port, "www.example.com.", u16(dns.Type.A)); answered {
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for an unrouted name")
		}
		u, t, s := mock_counts(internal)
		check(r, u + t + s == 0, "an unrouted name was sent to the route's server (%d queries)", u + t + s)
	}
	end_case(r)

	start_case(r, "upstream.zones: a name that only looks like the zone is not routed")
	{
		// The match is on label boundaries: `notcorp.example` ends in the same
		// bytes as `corp.example` and is a different zone entirely. Routing it
		// would send a stranger's name to the domain controller.
		mock_reset_counts(internal)
		if _, h, answered := ask(r, udp_port, "notcorp.example.", u16(dns.Type.A)); answered {
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for a suffix that is not a subtree")
		}
		u, t, s := mock_counts(internal)
		check(r, u + t + s == 0, "a bare suffix match was routed")
	}
	end_case(r)

	start_case(r, "upstream.zones: an anchor over a routed zone validates it")
	{
		/*
		The escape hatch, and what it is.

		A site that anchors `corp.example` has asked for those names to be
		checked, and that request outranks a default meant for zones nobody
		signs. The walk starts at that anchor (issue #226), and the zone's keys
		are asked of the route's authority - the public tree has no `DS` for an
		internal zone and no copy of its keys. So the signed name comes back
		with AD, which a walk from the root or keys asked of the public mock
		could not give, and the internal mock's unsigned names are SERVFAIL: the
		bypass stood down and they failed the check, rather than being served.

		The root anchor is re-listed alongside because `trust_anchors` replaces
		the built-in keys rather than adding to them.
		*/
		anchored_port := next_port(r)
		anchors := fmt.tprintf(
			`dnssec:
  enabled: true
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    - %q
`,
			ANCHORED_CORP_ANCHOR,
		)
		anchored, started := start_server(
			r,
			Server_Options {
				config = routed_config(anchored_port, {public_port}, zone_route("corp.example", internal_port), anchors),
				udp_port = anchored_port,
			},
		)
		if started {
			defer stop_server(&anchored)
			res := query_udp(
				anchored_port,
				build_query("vault.corp.example.", u16(dns.Type.A), edns_size = 1232, dnssec_ok = true),
			)
			if check(r, res.ok, "no response for the signed routed name") {
				h := parse_header(r, res.wire)
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a signed routed name")
				check(r, h.ad, "the signed routed name does not carry AD")
				addrs := answer_addresses(r, res.wire)
				check(r, len(addrs) == 1 && addrs[0] == "10.0.0.5", "addresses for the signed routed name: %v", addrs)
			}
			if _, h, answered := ask(r, anchored_port, "nas.corp.example.", u16(dns.Type.A), "no response for the unsigned routed name"); answered {
				check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for an unsigned name in an anchored route")
			}
		}
	}
	end_case(r)

	start_case(r, "upstream.zones: the longest route wins")
	{
		/*
		Two routes, one inside the other: the domain controller answers
		`corp.example` and a lab server answers everything under `dev`. The
		second has to win for its own names without the first being rewritten to
		exclude them, or a site that grows a sub-zone has to restate its whole
		routing table.
		*/
		nested_port := next_port(r)
		config := routed_config(
			nested_port,
			{public_port},
			strings.concatenate({zone_route("corp.example", internal_port), zone_route("dev.corp.example", public_port)}, context.temp_allocator),
			dnssec = "dnssec: { enabled: false }\n",
			rebind = false,
		)
		nested, started := start_server(r, Server_Options{config = config, udp_port = nested_port})
		if started {
			defer stop_server(&nested)

			// Inside the narrower route: answered by the server that route names,
			// which here is the one the broader route does not use.
			deep := query_udp(nested_port, build_query("build.dev.corp.example.", u16(dns.Type.A)))
			if check(r, deep.ok, "no response for the nested zone") {
				check_one_address(r, deep.wire, "198.51.100.9", "address for the nested zone")
			}

			// Outside it but inside the broader one: still the broader route's
			// server, so the longer entry took only what it claimed.
			shallow := query_udp(nested_port, build_query("nas.corp.example.", u16(dns.Type.A)))
			if check(r, shallow.ok, "no response for the outer zone") {
				check_one_address(r, shallow.wire, "10.0.0.7", "address for the outer zone")
			}
		}
	}
	end_case(r)
}
