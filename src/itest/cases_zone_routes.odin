package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "elodin:dns"

/*
Per-domain upstreams (`upstream.zones`), end to end.

The deployment is the one elodin had no answer for at all: a network that runs
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

@(private = "file")
routed_config :: proc(udp_port, public_port, internal_port: int, dnssec := DEFAULT_DNSSEC) -> string {
	return fmt.tprintf(
		`log:
  level: info
listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  timeout: 2s
  attempts: 1
  servers:
    - udp://127.0.0.1:%d
  zones:
    - domains: [corp.example]
      servers:
        - udp://127.0.0.1:%d
cache:
  enabled: false
blocking:
  enabled: false
%srebind:
  enabled: true
`,
		udp_port,
		public_port,
		internal_port,
		dnssec,
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
	write :: proc(r: ^Runner, name, body: string) -> string {
		path := filepath.join({r.work_dir, name}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)body)
		return path
	}

	ROUTE :: "upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n      servers: [10.0.0.1]\n"

	start_case(r, "upstream.zones: --check says what a route gives up")
	{
		// dnssec on by default, rebind off by default: one of the two.
		res := run_binary(r, []string{"--config", write(r, "route-warn.yaml", ROUTE), "--check"}, "route-warn")
		if check(r, res.ok, "could not run the binary") {
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
		res := run_binary(r, []string{"--config", write(r, "route-warn-both.yaml", body), "--check"}, "route-warn-both")
		if check(r, res.ok, "could not run the binary") {
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
		res := run_binary(
			r,
			[]string{"--config", write(r, "route-warn-anchored.yaml", body), "--check"},
			"route-warn-anchored",
		)
		if check(r, res.ok, "could not run the binary") {
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
		res := run_binary(r, []string{"--config", write(r, "route-warn-none.yaml", body), "--check"}, "route-warn-none")
		if check(r, res.ok, "could not run the binary") {
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
	if !mock_start(public) {
		skip_case(r, "upstream.zones", "cannot start the public mock")
		return
	}
	defer mock_stop(public)

	internal_port := next_port(r)
	internal := mock_make("internal", internal_port)
	mock_synth_all(internal, INTERNAL)
	if !mock_start(internal) {
		skip_case(r, "upstream.zones", "cannot start the internal mock")
		return
	}
	defer mock_stop(internal)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = routed_config(udp_port, public_port, internal_port), udp_port = udp_port},
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
		res := query_udp(udp_port, build_query("nas.corp.example.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode for a routed name")

			addrs := answer_addresses(res.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "10.0.0.7", "address for a routed name")
			}
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
			addrs := answer_addresses(res.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "10.0.0.7", "address for the routed apex")
			}
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
		res := query_udp(udp_port, build_query("corp.example.", u16(dns.Type.DS)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
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
		config := fmt.tprintf(
			`log:
  level: info
listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  timeout: 2s
  attempts: 1
  servers:
    - udp://127.0.0.1:%d
  zones:
    - domains: [denied.example]
      servers:
        - udp://127.0.0.1:%d
cache: {{enabled: false}}
blocking: {{enabled: false}}
dnssec: {{enabled: false}}
rebind: {{enabled: false}}
`,
			denied_port,
			public_port,
			internal_port,
		)
		denied, started := start_server(r, Server_Options{config = config, udp_port = denied_port})
		if started {
			defer stop_server(&denied)
			mock_reset_counts(internal)
			res := query_udp(denied_port, build_query("denied.example.", u16(dns.Type.DS)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				// The route's answer, not the parent's NXDOMAIN.
				check_eq_int(r, h.rcode, int(dns.Rcode.No_Error), "rcode after the parent denied the zone")
			}
			check(r, mock_total(internal) > 0, "the denied apex DS was not put back on the route")
		} else {
			skip_case(r, "upstream.zones: denied apex DS", "server did not start")
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
		res := query_udp(udp_port, build_query("www.example.com.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
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
		res := query_udp(udp_port, build_query("notcorp.example.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for a suffix that is not a subtree")
		}
		u, t, s := mock_counts(internal)
		check(r, u + t + s == 0, "a bare suffix match was routed")
	}
	end_case(r)

	start_case(r, "upstream.zones: an anchor over a routed zone stands the bypass down")
	{
		/*
		The escape hatch, and what it is and is not.

		A site that anchors `corp.example` has asked for those names to be
		checked, and that request outranks a default meant for zones nobody
		signs: the routed name SERVFAILs where it was served before. What that
		proves is only the bypass standing down - the route itself is unchanged,
		and the query still goes to the internal mock, which simply cannot
		satisfy a validator.

		It is deliberately not a claim that anchoring a zone makes it validate.
		The chain walk starts at the root and descends by `DS` (`zone_trust`), so
		an anchor below the root does not seed it; a zone signed purely
		internally, with no `DS` in the public tree, cannot be reached whatever
		is anchored over it. Anchoring such a zone therefore trades a working
		insecure answer for SERVFAIL, which is what this case actually
		demonstrates. Making a below-root anchor a starting point for the walk is
		its own change, in `src/dnssec`, and it would apply to the RFC 6303
		reverse zones before it applied here.

		The root anchor is re-listed alongside because `trust_anchors` replaces
		the built-in keys rather than adding to them - without it there would be
		no root anchor at all and every name would SERVFAIL, which would pass
		this assertion while proving nothing about the routed zone.
		*/
		anchored_port := next_port(r)
		anchors := `dnssec:
  enabled: true
  trust_anchors:
    - ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    - "corp.example. IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
`
		anchored, started := start_server(
			r,
			Server_Options {
				config = routed_config(anchored_port, public_port, internal_port, anchors),
				udp_port = anchored_port,
			},
		)
		if started {
			defer stop_server(&anchored)
			res := query_udp(anchored_port, build_query("nas.corp.example.", u16(dns.Type.A)))
			if check(r, res.ok, "no response for the anchored routed name") {
				h, _ := parse_header(res.wire)
				check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode for an anchored routed name")
			}
		} else {
			skip_case(r, "upstream.zones: anchored route", "server did not start")
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
		config := fmt.tprintf(
			`log:
  level: info
listeners:
  udp: {{enabled: true, address: 127.0.0.1, port: %d}}
  tcp: {{enabled: false}}
upstream:
  timeout: 2s
  attempts: 1
  servers:
    - udp://127.0.0.1:%d
  zones:
    - domains: [corp.example]
      servers:
        - udp://127.0.0.1:%d
    - domains: [dev.corp.example]
      servers:
        - udp://127.0.0.1:%d
cache: {{enabled: false}}
blocking: {{enabled: false}}
dnssec: {{enabled: false}}
rebind: {{enabled: false}}
`,
			nested_port,
			public_port,
			internal_port,
			public_port,
		)
		nested, started := start_server(r, Server_Options{config = config, udp_port = nested_port})
		if started {
			defer stop_server(&nested)

			// Inside the narrower route: answered by the server that route names,
			// which here is the one the broader route does not use.
			deep := query_udp(nested_port, build_query("build.dev.corp.example.", u16(dns.Type.A)))
			if check(r, deep.ok, "no response for the nested zone") {
				addrs := answer_addresses(deep.wire)
				if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
					check_eq_str(r, addrs[0], "198.51.100.9", "address for the nested zone")
				}
			}

			// Outside it but inside the broader one: still the broader route's
			// server, so the longer entry took only what it claimed.
			shallow := query_udp(nested_port, build_query("nas.corp.example.", u16(dns.Type.A)))
			if check(r, shallow.ok, "no response for the outer zone") {
				addrs := answer_addresses(shallow.wire)
				if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
					check_eq_str(r, addrs[0], "10.0.0.7", "address for the outer zone")
				}
			}
		} else {
			skip_case(r, "upstream.zones: longest match", "server did not start")
		}
	}
	end_case(r)
}
