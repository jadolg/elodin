package itest

import "core:fmt"
import "core:slice"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
Policy coverage: sink lists, block response modes, rewrites and the cache.
*/

// The returned path is heap-allocated on purpose: it is reused across cases,
// and end_case resets the temp allocator between them.
@(private = "file")
write_list :: proc(r: ^Runner, name: string, contents: string) -> string {
	// A write that did not land has failed the case already, and the server
	// it is for then fails on the missing file.
	path, _ := write_work_file(r, name, contents)
	return strings.clone(path)
}

run_blocking_cases :: proc(r: ^Runner) {
	// Anything not blocked resolves to this address, so a query that reached
	// the upstream is distinguishable from one that was sunk. The answer is
	// synthesised per query because elodin checks that a reply's question
	// matches what it asked.
	mock, upstream_port, started := synth_mock(r, "policy", "blocking", {203, 0, 113, 1})
	if !started {
		return
	}
	defer mock_stop(mock)

	hosts_path := write_list(
		r,
		"hosts.txt",
		`# hosts-format list
127.0.0.1 localhost
0.0.0.0 ads.tracker.test
0.0.0.0 metrics.tracker.test analytics.tracker.test
`,
	)
	abp_path := write_list(
		r,
		"abp.txt",
		`[Adblock Plus 2.0]
! adblock-format list
||evil.test^
||modifiers.test^$important
||third-party.test^$third-party
||first-party.test^$~third-party
/third-party-regex/$third-party
||v6only.test^$dnstype=AAAA
||not-a.test^$dnstype=~A
/^v6only\.regex\.test$/$dnstype=AAAA
@@||good.evil.test^
|http://exact.test^
address=/dnsmasq.test/0.0.0.0
/a-regex-rule.*/
/^ads[0-9]+\.regex\.test$/$important
@@/^keep\.evil\.test$/
/^ads#x\.regex\.test$/
/^[]q]z\.regex\.test$/
/^a\\\(b\.regex\.test$/
/^c\(d\.regex\.test$/
`,
	)
	domains_path := write_list(
		r,
		"domains.txt",
		`# domains-format list
subtree.test
*.wildcard.test
.dotted.test
`,
	)

	// Each response mode gets its own server; they differ only in that setting.
	Mode :: struct {
		name:     string,
		response: string,
		extra:    string,
	}
	modes := []Mode {
		{"nxdomain", "nxdomain", ""},
		{"nodata", "nodata", ""},
		{"zeroip", "zeroip", ""},
		{"custom", "custom", "custom_ipv4: 10.1.2.3, custom_ipv6: \"fd00::abcd\", "},
		{"refused", "refused", ""},
	}

	for mode in modes {
		udp_port := next_port(r)
		config := base_config(
			udp_port,
			upstream_at(upstream_port),
			timeout = "3s",
			blocking = fmt.tprintf(
				"{{ enabled: true, response: %s, block_ttl: 42, %slists: [" +
				"{{ name: hosts, file: %s, format: hosts }}, " +
				"{{ name: abp, file: %s, format: adblock }}, " +
				"{{ name: domains, file: %s, format: domains }}] }}",
				mode.response,
				mode.extra,
				hosts_path,
				abp_path,
				domains_path,
			),
		)

		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
		if !ok {
			continue
		}

		start_case(r, fmt.tprintf("blocking: response mode %s", mode.name))
		{
			if res, h, answered := ask(r, udp_port, "ads.tracker.test.", u16(dns.Type.A)); answered {
				switch mode.response {
				case "nxdomain":
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
					check(r, h.nscount == 1, "expected a SOA in the authority section")
				case "nodata":
					check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
					check_eq_int(r, h.ancount, 0, "answer count")
					check(r, h.nscount == 1, "expected a SOA in the authority section")
				case "refused":
					check(r, h.rcode == int(dns.Rcode.Refused), "rcode %d, want REFUSED", h.rcode)
				case "zeroip":
					check_eq_int(r, h.ancount, 1, "answer count")
					check_one_address(r, res.wire, "0.0.0.0", "sink address")
				case "custom":
					check_eq_int(r, h.ancount, 1, "answer count")
					check_one_address(r, res.wire, "10.1.2.3", "sink address")
					ttl, has := min_answer_ttl(r, res.wire)
					check(r, has && ttl == 42, "block TTL: got %d, want 42", ttl)
				}
			}
		}
		end_case(r)

		if mode.response == "custom" {
			start_case(r, "blocking: custom IPv6 answer for AAAA")
			{
				res := query_udp(udp_port, build_query("ads.tracker.test.", u16(dns.Type.AAAA)))
				if check(r, res.ok, "no response") {
					check_one_address(r, res.wire, "fd00:0000:0000:0000:0000:0000:0000:abcd", "sink address")
				}
			}
			end_case(r)
		}

		// Matching semantics only need checking once.
		if mode.response != "nxdomain" {
			stop_server(&srv)
			continue
		}

		start_case(r, "blocking: hosts entries match exactly, not subtrees")
		{
			if _, h, answered := ask(r, udp_port, "metrics.tracker.test.", u16(dns.Type.A), "no response for the listed name"); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "listed name not blocked")
			}
			if _, h, answered := ask(r, udp_port, "deep.ads.tracker.test.", u16(dns.Type.A), "no response for the subdomain"); answered {
				check(r, h.rcode == int(dns.Rcode.No_Error), "a hosts entry blocked its subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: the list's own localhost lines are not rules")
		{
			if _, h, answered := ask(r, udp_port, "localhost.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.No_Error), "localhost was turned into a block rule")
			}
		}
		end_case(r)

		start_case(r, "blocking: adblock || covers the domain and its subtree")
		{
			for name in ([]string{"evil.test.", "sub.evil.test.", "a.b.evil.test."}) {
				if _, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: allow rules beat block rules")
		{
			for name in ([]string{"good.evil.test.", "deeper.good.evil.test."}) {
				if _, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
					check(r, h.rcode == int(dns.Rcode.No_Error), "%s should have been allowed", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: modifiers are stripped, the rule still applies")
		{
			if _, h, answered := ask(r, udp_port, "modifiers.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "a rule with $modifiers was dropped")
			}
		}
		end_case(r)

		// AdGuard Home's DNS engine never loads a rule with `$third-party` set or negated (#464).
		start_case(r, "blocking: a $third-party or $~third-party rule blocks nothing")
		{
			for name in ([]string{"third-party.test.", "a.third-party-regex.test.", "first-party.test."}) {
				if _, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
					check(r, h.rcode == int(dns.Rcode.No_Error), "%s was blocked by a rule with a third-party modifier", name)
				}
			}
		}
		end_case(r)

		/*
		`$dnstype` narrows a rule to the query types it names (#406). The name
		keeps its other types, so the block is NODATA where `blocking.response`
		says nxdomain (RFC 8020 section 2), and it never reaches the upstream.
		*/
		start_case(r, "blocking: a $dnstype rule blocks only its types, as NODATA")
		{
			Typed :: struct {
				name:    string,
				qtype:   dns.Type,
				blocked: bool,
			}
			typed := []Typed {
				{"v6only.test.", .AAAA, true},
				{"sub.v6only.test.", .AAAA, true},
				{"v6only.test.", .A, false},
				{"v6only.test.", .TXT, false},
				{"not-a.test.", .A, false},
				{"not-a.test.", .AAAA, true},
				{"not-a.test.", .TXT, true},
				{"v6only.regex.test.", .AAAA, true},
				{"v6only.regex.test.", .A, false},
			}
			for c in typed {
				before := mock_total(mock)
				if _, h, answered := ask(r, udp_port, c.name, u16(c.qtype), fmt.tprintf("no response for %s %v", c.name, c.qtype)); answered {
					asked := mock_total(mock) > before
					check(r, h.rcode == int(dns.Rcode.No_Error), "%s %v: rcode %d, want NOERROR", c.name, c.qtype, h.rcode)
					check(r, asked != c.blocked, "%s %v: blocked %v, want %v", c.name, c.qtype, !asked, c.blocked)
					if c.blocked {
						check(r, h.ancount == 0 && h.nscount == 1, "%s %v: %d answers, %d authority, want NODATA with its SOA", c.name, c.qtype, h.ancount, h.nscount)
					}
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: | anchors match the exact name only")
		{
			if _, h, answered := ask(r, udp_port, "exact.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the anchored name was not blocked")
			}
			if _, h, answered := ask(r, udp_port, "sub.exact.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.No_Error), "an anchored rule blocked a subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: dnsmasq address=/ syntax")
		{
			if _, h, answered := ask(r, udp_port, "deep.dnsmasq.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "address=/ rule was not applied")
			}
		}
		end_case(r)

		start_case(r, "blocking: a regex rule is matched against the query name")
		{
			Want :: struct {
				name:    string,
				blocked: bool,
			}
			for w in ([]Want {
					{"a-regex-rule.test.", true},
					{"ads12.regex.test.", true},
					{"ADS7.Regex.Test.", true},
					{"ads.regex.test.", false},
					{"x.ads1.regex.test.", false},
					// An allow regex outranks the `||evil.test^` above it.
					{"keep.evil.test.", false},
					// Read as RE2 reads them (#465): a `#` is no comment, and a
					// class may open with `]`.
					{"ads#x.regex.test.", true},
					{"]z.regex.test.", true},
					{"qz.regex.test.", true},
					{"rz.regex.test.", false},
					// Matched against the name as AdGuard Home spells it, with a
					// `\` before the `(`.
					{"a(b.regex.test.", true},
					{"c(d.regex.test.", false},
				}) {
				if _, h, answered := ask(r, udp_port, w.name, u16(dns.Type.A), fmt.tprintf("no response for %s", w.name)); answered {
					want := dns.Rcode.NX_Domain if w.blocked else dns.Rcode.No_Error
					check(r, h.rcode == int(want), "%s: rcode %d, want %v", w.name, h.rcode, want)
				}
			}
		}
		end_case(r)

		// A leading dot (Squid, Privoxy) marks the same subtree as a bare line (#591).
		start_case(r, "blocking: bare and leading-dot domains cover their subtree")
		{
			for name in ([]string{"subtree.test.", "a.subtree.test.", "dotted.test.", "a.dotted.test."}) {
				if _, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: *.name covers subdomains but not the apex")
		{
			if _, h, answered := ask(r, udp_port, "host.wildcard.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the subdomain was not blocked")
			}
			if _, h, answered := ask(r, udp_port, "wildcard.test.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.No_Error), "*.name should not block the apex")
			}
		}
		end_case(r)

		start_case(r, "blocking: matching ignores case")
		{
			if _, h, answered := ask(r, udp_port, "ADS.Tracker.TEST.", u16(dns.Type.A)); answered {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "an upper-case name evaded the list")
			}
		}
		end_case(r)

		stop_server(&srv)
	}

	run_regex_bomb_case(r, upstream_port)
}

/*
A downloaded list is untrusted, and a regex in it reaches the compiler (#405).
Each of these would take the server down at load if it got there - a count pair
past `max(i64)` hits the compiler's panic, the nested one writes gigabytes of
program - so the case fails, rather than skips, when the server does not start.
*/
@(private = "file")
run_regex_bomb_case :: proc(r: ^Runner, upstream_port: int) {
	start_case(r, "blocking: a list of regex bombs loads, and the rules after them apply")
	defer end_case(r)

	list := write_list(
		r,
		"regex-bombs.txt",
		`! regex rules no list should be able to spend the server on
/a{9223372036854775808,9223372036854775809}/
/a{0,18446744073709551615}/
/((a{1000}){1000}){1000}/
/(?=lookahead)/
||after-the-bombs.test^
/^after[0-9]\.regex\.test$/
`,
	)
	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "3s",
		blocking = fmt.tprintf("{{ enabled: true, lists: [{{ name: bombs, file: %s, format: adblock }}] }}", list),
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	for name in ([]string{"after-the-bombs.test.", "after7.regex.test."}) {
		if _, h, answered := ask(r, udp_port, name, u16(dns.Type.A), fmt.tprintf("no response for %s", name)); answered {
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
		}
	}
	if _, h, answered := ask(r, udp_port, "aaaa.test.", u16(dns.Type.A)); answered {
		check(r, h.rcode == int(dns.Rcode.No_Error), "a refused bomb blocked a name")
	}
}

run_rewrite_cases :: proc(r: ^Runner) {
	mock, upstream_port, started := synth_mock(r, "rewrites", "rewrites", {203, 0, 113, 1})
	if !started {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "3s",
		blocking = "{ enabled: true, response: nxdomain }",
		extra = `# Off, so the "gets no PTR" cases below can prove a reverse name is forwarded
# rather than invented; with the key on it would be the empty zone's NXDOMAIN.
special_use: { private_reverse: false }
rewrites:
  - { domain: nas.home, answer: 192.168.1.50, ttl: 111 }
  - { domain: nas6.home, answer: "fd00::50" }
  - { domain: mail.lab, answers: ["MX 10 mx.lab"] }
  - { domain: "*.lab", answers: [10.0.0.1, "fd00::1"] }
  - { domain: old.example.org, answer: new.example.org }
  - { domain: telemetry.example.org, answer: block }
  - { domain: cloak.example.org, answer: telemetry.example.org }
  - { domain: www.example.org, answer: 203.0.113.9 }
  - { domain: shadowed.lab, answer: 192.168.1.70 }
  - { domain: sink.example.org, answers: [block, 192.168.1.60] }
  - { domain: blockpage.example.org, answer: 192.168.1.80, ptr: false }
  - { domain: mail.example.org, answers: ["MX 10 mx1.example.org", "MX 20 mx2.example.org", "TXT v=spf1 -all"] }
  - { domain: _sip._tcp.example.org, answer: "SRV 0 5 5060 sip.example.org" }
`,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "rewrite: a literal name answers with the configured A")
	{
		res := query_udp(udp_port, build_query("nas.home.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_one_address(r, res.wire, "192.168.1.50", "rewritten address")
			ttl, has := min_answer_ttl(r, res.wire)
			check(r, has && ttl == 111, "TTL: got %d, want 111", ttl)
		}
	}
	end_case(r)

	start_case(r, "rewrite: a wildcard answers A and AAAA separately")
	{
		v4 := query_udp(udp_port, build_query("host1.lab.", u16(dns.Type.A)))
		if check(r, v4.ok, "no A response") {
			check_one_address(r, v4.wire, "10.0.0.1", "A answer")
		}
		v6 := query_udp(udp_port, build_query("host2.lab.", u16(dns.Type.AAAA)))
		if check(r, v6.ok, "no AAAA response") {
			check_one_address(r, v6.wire, "fd00:0000:0000:0000:0000:0000:0000:0001", "AAAA answer")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a wildcard does not match its own apex")
	{
		res := query_udp(udp_port, build_query("lab.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			// It should have fallen through to the upstream instead.
			check_one_address(r, res.wire, "203.0.113.1", "answer source")
		}
	}
	end_case(r)

	// With the target's own address behind it, from the upstream: glibc and musl
	// report a name whose A answer is a bare CNAME as not found (issue #320).
	start_case(r, "rewrite: a name answer becomes a CNAME, followed to the target")
	{
		res := query_udp(udp_port, build_query("old.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "new.example.org.", "CNAME target")
			check_one_address(r, res.wire, "203.0.113.1", "target address")
		}
	}
	end_case(r)

	// The target is put to the same rules a question for it by name would be.
	start_case(r, "rewrite: a CNAME to a sunk name is sunk")
	{
		if res, h, answered := ask(r, udp_port, "cloak.example.org.", u16(dns.Type.A)); answered {
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
			check_eq_str(r, first_cname_or_name(r, res.wire), "telemetry.example.org.", "CNAME target")
		}
	}
	end_case(r)

	start_case(r, "rewrite: answer 'block' sinks the name")
	{
		if _, h, answered := ask(r, udp_port, "telemetry.example.org.", u16(dns.Type.A)); answered {
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
		}
	}
	end_case(r)

	start_case(r, "rewrite: an unmatched type gets NODATA, not a wrong answer")
	{
		if _, h, answered := ask(r, udp_port, "nas.home.", u16(dns.Type.MX)); answered {
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
		}
	}
	end_case(r)

	start_case(r, "rewrite: MX answers with both hosts and their preferences")
	{
		res := query_udp(udp_port, build_query("mail.example.org.", u16(dns.Type.MX)))
		if check(r, res.ok, "no response") {
			msg, decoded := decode_reply(r, res.wire)
			if decoded &&
			   check(r, len(msg.answer) == 2, "expected two MX records, got %d", len(msg.answer)) {
				for rec, i in msg.answer {
					mx, is_mx := rec.data.(dns.Rdata_MX)
					if !check(r, is_mx, "answer %d is not an MX record", i) {
						continue
					}
					want_pref := u16(10) if i == 0 else u16(20)
					want_host := "mx1.example.org." if i == 0 else "mx2.example.org."
					check(r, mx.preference == want_pref, "preference %d, want %d", mx.preference, want_pref)
					check_eq_str(r, mx.exchange, want_host, "exchange")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: TXT answers with the text as written")
	{
		res := query_udp(udp_port, build_query("mail.example.org.", u16(dns.Type.TXT)))
		if check(r, res.ok, "no response") {
			msg, decoded := decode_reply(r, res.wire)
			if decoded &&
			   check(r, len(msg.answer) == 1, "expected one TXT record, got %d", len(msg.answer)) {
				txt, is_txt := msg.answer[0].data.(dns.Rdata_TXT)
				if check(r, is_txt, "the answer is not a TXT record") &&
				   check(r, len(txt.strings) == 1, "expected one string, got %d", len(txt.strings)) {
					check_eq_str(r, txt.strings[0], "v=spf1 -all", "text")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: SRV answers with priority, weight, port and target")
	{
		res := query_udp(udp_port, build_query("_sip._tcp.example.org.", u16(dns.Type.SRV)))
		if check(r, res.ok, "no response") {
			msg, decoded := decode_reply(r, res.wire)
			if decoded &&
			   check(r, len(msg.answer) == 1, "expected one SRV record, got %d", len(msg.answer)) {
				srv, is_srv := msg.answer[0].data.(dns.Rdata_SRV)
				if check(r, is_srv, "the answer is not an SRV record") {
					// Four different numbers, so a swapped pair cannot pass.
					check(r, srv.priority == 0, "priority %d, want 0", srv.priority)
					check(r, srv.weight == 5, "weight %d, want 5", srv.weight)
					check(r, srv.port == 5060, "port %d, want 5060", srv.port)
					check_eq_str(r, srv.target, "sip.example.org.", "target")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: a record-only rule leaves the other types to the upstream")
	{
		// mail.example.org has MX and TXT records here and no address, which is
		// the ordinary shape: a domain whose mail this operator directs and
		// whose website is somebody else's. Answering its A out of the rule
		// would take that website away from every client behind this server.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("mail.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_one_address(r, res.wire, "203.0.113.1", "answer source")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a record-only rule steps aside for the rules below it")
	{
		// "mail.lab" holds only an MX and is written above the "*.lab" wildcard,
		// which answers every name under "lab" with 10.0.0.1 - the order anybody
		// writes, specific before general. An A query for it has to reach that
		// wildcard: stopping at the first matching rule would send an internal
		// name to the public upstream while the rule that answers it sat one
		// line below, unread.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("mail.lab.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_one_address(r, res.wire, "10.0.0.1", "the wildcard should have answered")
			check_eq_int(r, mock_total(mock), 0, "upstream queries for a name answered here")
		}

		// And its own type is still answered by the rule that holds it.
		mx := query_udp(udp_port, build_query("mail.lab.", u16(dns.Type.MX)))
		if check(r, mx.ok, "no response for the MX query") {
			msg, decoded := decode_reply(r, mx.wire)
			if decoded &&
			   check(r, len(msg.answer) == 1, "expected one MX record, got %d", len(msg.answer)) {
				rec, is_mx := msg.answer[0].data.(dns.Rdata_MX)
				if check(r, is_mx, "the answer is not an MX record") {
					check_eq_str(r, rec.exchange, "mx.lab.", "exchange")
				}
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: an address in the rule still claims the whole name")
	{
		// The other side of the line: nas.home has an address, so the rule
		// speaks for the name and a type it has no record of is NODATA rather
		// than a question for the upstream. Same assertion as the MX case
		// further up, made here against the rule that has both kinds in play.
		mock_reset_counts(mock)
		if _, h, answered := ask(r, udp_port, "nas.home.", u16(dns.Type.SRV)); answered {
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
			check_eq_int(r, h.nscount, 1, "authority count")
			check_eq_int(r, mock_total(mock), 0, "upstream queries for a name answered here")
		}
	}
	end_case(r)

	start_case(r, "rewrite: an address a rule hands out answers its own PTR")
	{
		// The reverse of the first rule, which nobody wrote down: without the
		// synthesis this leaves for the upstream, and for RFC 1918 space the
		// real answer out there is the blackhole servers' NXDOMAIN. The TTL is
		// the rule's own, so the two directions expire together.
		mock_reset_counts(mock)
		if res, h, answered := ask(r, udp_port, "50.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)); answered {
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_str(r, first_cname_or_name(r, res.wire), "nas.home.", "PTR target")
			ttl, has := min_answer_ttl(r, res.wire)
			check(r, has && ttl == 111, "TTL: got %d, want 111", ttl)
			check_eq_int(r, mock_total(mock), 0, "upstream queries for a name answered here")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a v6 address answers its nibble PTR")
	{
		res := query_udp(
			udp_port,
			build_query(
				"0.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
				u16(dns.Type.PTR),
			),
		)
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "nas6.home.", "PTR target")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a wildcard address gets no PTR")
	{
		// "*.lab" answers every name below "lab" with 10.0.0.1, so there is no
		// one name to point back at and this server must not invent one. The
		// query goes upstream like any other, which the mock's query count is
		// what proves - it answers a PTR with NOERROR and nothing in it, exactly
		// as an empty answer synthesised here would look.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("1.0.0.10.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "", "a wildcard must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a public address keeps its own reverse")
	{
		// 203.0.113.9 is delegated to somebody, and their PTR is the right one.
		// A rewrite pointing a local name at it says nothing about who owns the
		// address, so the reverse still leaves.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("9.113.0.203.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "", "a public address must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a rule the forward direction never reaches gets no PTR")
	{
		// "*.lab" is written above "shadowed.lab", so the wildcard is what
		// answers that name and 192.168.1.70 is never handed to anybody. A PTR
		// for it would point at a name that resolves to 10.0.0.1 - this server
		// disagreeing with itself across two answers.
		v4 := query_udp(udp_port, build_query("shadowed.lab.", u16(dns.Type.A)))
		if check(r, v4.ok, "no response for the shadowed name") {
			check_one_address(r, v4.wire, "10.0.0.1", "the wildcard is what answers")
		}
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("70.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "", "a shadowed rule must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a sunk rule's address gets no PTR")
	{
		// `answers: [block, 192.168.1.60]` sinks the name, so the address is
		// never given out and has nothing to be the reverse of.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("60.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "", "a sunk rule must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: ptr: false keeps the forward answer and drops the reverse")
	{
		// A block page on a host that has a name of its own: the rule answers
		// its own name as any other rule would, and says nothing about the
		// address in the other direction.
		fwd := query_udp(udp_port, build_query("blockpage.example.org.", u16(dns.Type.A)))
		if check(r, fwd.ok, "no response for the opted-out name") {
			check_one_address(r, fwd.wire, "192.168.1.80", "the forward answer is unaffected")
		}
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("80.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(r, res.wire), "", "ptr: false must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a synthesised reverse name is NODATA for other types")
	{
		// The name exists - its PTR was just answered - so another type is
		// "there is none" rather than a forwarded query. The upstream would have
		// synthesised an A for it, so an empty answer is the proof it stayed.
		if _, h, answered := ask(r, udp_port, "50.1.168.192.in-addr.arpa.", u16(dns.Type.A)); answered {
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
			check_eq_int(r, h.nscount, 1, "authority count")
		}
	}
	end_case(r)
}

run_cache_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	upstream_port := next_port(r)
	mock := mock_make("cache", upstream_port)
	mock_reply(mock, fix.qname, fix.qtype, from_hex(fix.response, context.allocator))
	mock_reply(mock, "nx.example.com.", u16(dns.Type.A), denial_reply("nx.example.com.", .No_Error, data = false))
	mock_reply(mock, POISONED_NAME, u16(dns.Type.A), denial_reply(POISONED_NAME, .NX_Domain, data = true))
	mock_reply(mock, "nosoa.example.com.", u16(dns.Type.A), nil)
	mock_reply(mock, "referral.example.com.", u16(dns.Type.A), referral_reply("referral.example.com."))
	mock_reply(mock, "cname-nosoa.example.com.", u16(dns.Type.A), bare_cname_reply("cname-nosoa.example.com."))
	// Any other question (the AAAA case below) gets a matching synthesised
	// answer rather than a canned one for the wrong name.
	mock_synth_all(mock, {203, 0, 113, 2})
	if !mock_start_or_skip(r, mock, "cache") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "3s",
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, udp_port),
		cache = "{ enabled: true, max_entries: 100, min_ttl: 30, negative_ttl: 60 }",
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, tcp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "cache: a repeated query does not reach the upstream")
	{
		mock_reset_counts(mock)
		first := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 1))
		if !check(r, first.ok, "no response to the first query") {
			end_case(r)
			return
		}
		check_eq_int(r, mock_total(mock), 1, "upstream queries after the first request")

		second := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 2))
		if check(r, second.ok, "no response to the second query") {
			check_eq_int(r, mock_total(mock), 1, "upstream queries after a cache hit")
			h := parse_header(r, second.wire)
			check(r, h.id == 2, "the cached answer kept the wrong ID: %04x", h.id)
			check_eq_int(r, h.ancount, fix.ancount, "answer count from cache")
		}
	}
	end_case(r)

	start_case(r, "cache: TTLs count down while an entry is held")
	{
		before, has_before := min_answer_ttl(r, query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 3)).wire)
		if !check(r, has_before, "no TTL in the first answer") {
			end_case(r)
			return
		}
		time.sleep(1100 * time.Millisecond)
		after, has_after := min_answer_ttl(r, query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 4)).wire)
		if check(r, has_after, "no TTL in the second answer") {
			check(r, after < before, "TTL did not decrease: %d then %d", before, after)
		}
	}
	end_case(r)

	start_case(r, "cache: a cached answer serves other transports too")
	{
		mock_reset_counts(mock)
		res := query_tcp(udp_port, build_query(fix.qname, fix.qtype, id = 5))
		if check(r, res.ok, "no response over TCP") {
			check_eq_int(r, mock_total(mock), 0, "upstream queries for a cached name over TCP")
		}
	}
	end_case(r)

	start_case(r, "cache: the question case is restored for the asking client")
	{
		query := build_query("EXAMPLE.com.", fix.qtype, id = 6)
		res := query_udp(udp_port, query)
		if check(r, res.ok, "no response") {
			check(
				r,
				len(res.wire) > 25 && slice.equal(res.wire[12:25], query[12:25]),
				"the cached answer did not echo the client's spelling",
			)
		}
	}
	end_case(r)

	start_case(r, "cache: negative answers are cached")
	{
		mock_reset_counts(mock)
		// Both answered, and the first by the upstream, or an unchanged count
		// proves nothing.
		first := query_udp(udp_port, build_query("nx.example.com.", u16(dns.Type.A), id = 7))
		check(r, first.ok, "no response to the first query")
		count_after_first := mock_total(mock)
		check_eq_int(r, count_after_first, 1, "upstream queries for the first negative answer")
		second := query_udp(udp_port, build_query("nx.example.com.", u16(dns.Type.A), id = 8))
		check(r, second.ok, "no response to the second query")
		check_eq_int(r, mock_total(mock), count_after_first, "upstream queries after a cached negative answer")
	}
	end_case(r)

	start_case(r, "cache: a denial without a SOA is not cached")
	{
		// RFC 2308 section 5, issue #310: nothing in it says how long it holds,
		// so one upstream that stumbled - an empty NOERROR, or a referral from
		// a server that did not recurse - is not every client's answer for
		// `negative_ttl`. Asked twice, the upstream has to hear both. For the
		// empty NOERROR, the server's `min_ttl` is what makes this reach the
		// guard: without it the zero lifetime a SOA-less denial has would
		// refuse it anyway.
		//
		// The referral is not passed on at all (issue #410): it is no answer,
		// and a client would read the empty NOERROR as NODATA, so with no other
		// member to ask the query is a SERVFAIL.
		for name, i in ([]string{"nosoa.example.com.", "referral.example.com."}) {
			mock_reset_counts(mock)
			first := query_udp(udp_port, build_query(name, u16(dns.Type.A), id = u16(20 + 2 * i)))
			if !check(r, first.ok, "no response to the first query for %s", name) {
				continue
			}
			h := parse_header(r, first.wire)
			if i == 0 {
				check(r, h.rcode == int(dns.Rcode.No_Error) && h.ancount == 0, "%s: want the empty NOERROR the mock sent", name)
			} else {
				check(r, h.rcode == int(dns.Rcode.Serv_Fail), "%s: rcode %d, want SERVFAIL for a referral", name, h.rcode)
			}
			_ = query_udp(udp_port, build_query(name, u16(dns.Type.A), id = u16(21 + 2 * i)))
			check_eq_int(r, mock_total(mock), 2, fmt.tprintf("upstream queries for %s asked twice", name))
		}
	}
	end_case(r)

	start_case(r, "cache: NODATA after a CNAME without a SOA is not cached")
	{
		// Issue #418: a CNAME that never reaches the type asked for is a denial
		// (RFC 2308 section 2.2) and is kept like one, so with no SOA it is not
		// kept at all - rather than for the CNAME's own TTL, up to `max_ttl`.
		mock_reset_counts(mock)
		name := "cname-nosoa.example.com."
		first := query_udp(udp_port, build_query(name, u16(dns.Type.A), id = 30))
		if check(r, first.ok, "no response to the first query") {
			h := parse_header(r, first.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want the NOERROR the mock sent", h.rcode)
			check_eq_int(r, h.ancount, 1, "answer count, the bare CNAME")
			check_eq_int(r, h.nscount, 0, "authority count")
			_ = query_udp(udp_port, build_query(name, u16(dns.Type.A), id = 31))
			check_eq_int(r, mock_total(mock), 2, "upstream queries for a bare CNAME asked twice")
		}
	}
	end_case(r)

	start_case(r, "cache: A and AAAA are separate entries")
	{
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query(fix.qname, u16(dns.Type.AAAA), id = 9))
		check(r, mock_total(mock) >= 1, "an AAAA query was answered from the A entry")
	}
	end_case(r)

	start_case(r, "cache: an NXDOMAIN carrying data is not remembered")
	{
		/*
		The shape an attacker makes out of a genuine answer by rewriting the
		low nibble of byte 3 of the header: the records and their signatures
		are untouched, only the rcode says the name is not there. RFC 2308
		section 2.1 lets a name error carry CNAMEs and nothing else, so this
		is a response contradicting itself.

		`src/dnssec` refuses it outright where validation is on. This case is
		the layer under that - validation is off here, as it is for every
		case in this file - and what it asserts is the part that decides how
		far one packet reaches: the negative lifetime comes from the SOA
		beside it, capped at `negative_ttl`, and a single spoofed datagram
		would otherwise take the name away from every client for a minute.
		Asked twice, the upstream has to hear both.
		*/
		mock_reset_counts(mock)
		first := query_udp(udp_port, build_query(POISONED_NAME, u16(dns.Type.A), id = 10))
		if check(r, first.ok, "no response to the first query") {
			/*
			The premise, before the judgement. What this case measures is a
			second upstream query, and a reply elodin threw away for some
			reason of its own - a question that did not match, a decode that
			failed, a rule the mock never matched - produces exactly that too,
			so the case would pass while `put` was never asked the question.
			The header says the poisoned reply is the one that came back: the
			rcode the attacker wrote, over the answer section they left alone.
			*/
			h := parse_header(r, first.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want the NXDOMAIN the mock sent", h.rcode)
			check_eq_int(r, h.ancount, 1, "answer count, the A record under the name error")

			count_after_first := mock_total(mock)
			second := query_udp(udp_port, build_query(POISONED_NAME, u16(dns.Type.A), id = 11))
			if check(r, second.ok, "no response to the second query") {
				check(
					r,
					mock_total(mock) > count_after_first,
					"an NXDOMAIN holding an A record was served from the cache",
				)
			}
		}
	}
	end_case(r)

	/*
	One entry, two kinds of client, and neither of them reads the other's OPT
	record.

	The key is the question plus DO and CD (`cache.make_key`) and not whether the
	query carried an OPT record at all, so the entry a client with EDNS fills is
	the entry a client without EDNS is served from - and the query forwarded for
	the first carried its OPT record upstream while the second's did not, so the
	stored bytes have an OPT record or no OPT record depending on which client
	asked first. RFC 6891 section 6.1.1 forbids exactly that crossing: "An OPT
	RR MUST NOT be cached, forwarded, or stored in or loaded from Zone Master
	Files."

	Through the shipped binary because the unit cases for this stop at
	`handle_query`, and what an OPT record does to a stub is decided by the bytes
	that leave the socket. `mock_synth_all` answers either client the way a real
	upstream would - `dns.make_response` echoes an OPT record only for a query
	that carried one - so the entry really is filled in the shape the first
	client's query produced.
	*/
	start_case(r, "cache: an OPT record does not cross from an EDNS client to one without")
	{
		mock_reset_counts(mock)
		filled := query_udp(udp_port, build_query(MIXED_EDNS_FIRST, u16(dns.Type.A), id = 12, edns_size = 1232))
		if check(r, filled.ok, "no response to the EDNS client") {
			check_eq_int(r, mock_total(mock), 1, "upstream queries after the EDNS client")
			check_eq_int(r, int(dns.peek_udp_size(filled.wire)), 1232, "the payload size the EDNS client is told")

			bare := query_udp(udp_port, build_query(MIXED_EDNS_FIRST, u16(dns.Type.A), id = 13))
			if check(r, bare.ok, "no response to the client without EDNS") {
				// The premise: it is the same entry being served, or the two
				// clients never shared anything and nothing could have crossed.
				check_eq_int(r, mock_total(mock), 1, "upstream queries after the cache hit")
				check(
					r,
					!has_opt_record(r, bare.wire),
					"a cached OPT record was handed to a client that asked without EDNS",
				)
				check_eq_int(r, parse_header(r, bare.wire).ancount, 1, "the answer the client came for")
			}
		}
	}
	end_case(r)

	/*
	And the other direction, which is the one that quietly costs a round trip.

	`dns.set_edns_udp_size` has no field to write into when the answer carries no
	OPT record, so an EDNS client served from an entry a non-EDNS client filled
	would be told nothing about what this server can deliver. A downstream
	forwarder reading no OPT record falls back to the 512 bytes RFC 1035 makes it
	assume, and pays for the TC bits and TCP retries the 1232 ceiling exists to
	spare it - for as long as the entry lives, and for no reason to do with the
	question it asked.
	*/
	start_case(r, "cache: a client with EDNS is told the payload size even when a non-EDNS client asked first")
	{
		mock_reset_counts(mock)
		filled := query_udp(udp_port, build_query(MIXED_BARE_FIRST, u16(dns.Type.A), id = 14))
		if check(r, filled.ok, "no response to the client without EDNS") {
			check_eq_int(r, mock_total(mock), 1, "upstream queries after the first client")
			// The premise again: the entry really was filled by an answer with
			// no OPT record in it.
			check(r, !has_opt_record(r, filled.wire), "the client without EDNS was given an OPT record")

			edns := query_udp(udp_port, build_query(MIXED_BARE_FIRST, u16(dns.Type.A), id = 15, edns_size = 1232))
			if check(r, edns.ok, "no response to the EDNS client") {
				check_eq_int(r, mock_total(mock), 1, "upstream queries after the cache hit")
				if check(r, has_opt_record(r, edns.wire), "an EDNS client got a cached answer with no OPT record") {
					check_eq_int(
						r,
						int(dns.peek_udp_size(edns.wire)),
						1232,
						"the payload size the EDNS client is told",
					)
				}
				check_eq_int(r, parse_header(r, edns.wire).ancount, 1, "the answer the client came for")
			}
		}
	}
	end_case(r)
}

// Two names, one per direction, so neither case is served an entry the other
// one filled. Answered by `mock_synth_all` like any other name here.
@(private = "file")
MIXED_EDNS_FIRST :: "mixed-edns-first.example.com."

@(private = "file")
MIXED_BARE_FIRST :: "mixed-bare-first.example.com."

// Whether the answer carries an OPT record, read off the wire the client got.
// `decode_reply` fails the case on bytes nothing could read, so a case asserting
// the absence of an OPT record cannot pass over an answer nobody decoded.
@(private = "file")
has_opt_record :: proc(r: ^Runner, wire: []u8) -> bool {
	msg := decode_reply(r, wire) or_return
	return dns.edns_present(msg)
}

// A name error whose answer section holds the record it denies. Nothing sends
// this but an attacker; see the case that uses it.
@(private = "file")
POISONED_NAME :: "poisoned.example.com."

/*
A canned denial with the zone's SOA beside it - a NODATA, or an NXDOMAIN over an
A record at the denied name when `data` is set - built once and left on the heap.

The mock keeps the slice for the whole run and `end_case` empties the temp arena
long before the case that asks for it, which is why every other canned payload
in the suite is allocated the same way.
*/
@(private = "file")
denial_reply :: proc(name: string, rcode: dns.Rcode, data: bool) -> []u8 {
	answer := make([]dns.Record, 1 if data else 0, context.temp_allocator)
	if data {
		answer[0] = dns.Record {
			name  = name,
			type  = .A,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_A{addr = {203, 0, 113, 9}},
		}
	}
	// The zone's SOA beside it, as the genuine denial the attacker could lift
	// it from carries: without one the cache would turn the reply away for
	// that alone, and the case would pass without the data ever being read.
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = dns.Record {
		name = "example.com.",
		type = .SOA,
		class = .IN,
		ttl = 3600,
		data = dns.Rdata_SOA{ns = "ns.example.com.", mbox = "hostmaster.example.com.", serial = 1, minimum = 600},
	}
	msg := dns.Message {
		answer    = answer,
		authority = authority,
	}
	msg.flags.rcode = u8(rcode)
	return encode_reply(name, .A, msg)
}

// An answer with `records` A records under one owner name: the shape of a
// response whose size the party answering the query chose.
@(private = "file")
bulk_answer :: proc(name: string, records: int, allocator := context.allocator) -> []u8 {
	answers := make([]dns.Record, records, context.temp_allocator)
	for i in 0 ..< records {
		answers[i] = dns.Record {
			name  = name,
			type  = .A,
			class = .IN,
			ttl   = 3600,
			// Not RFC 1918, though these are only filler: with the rebinding
			// guard on, a private address would refuse the whole answer and the
			// cache would never see it.
			data  = dns.Rdata_A{addr = {198, 51, u8(i >> 8), u8(i)}},
		}
	}
	return encode_reply(name, .A, {id = 0x4242, answer = answers}, allocator)
}

/*
The cache has to be bounded by what it holds, not only by how many things it
holds.

An entry is the response as it arrived plus an offset and a TTL for each of its
records, and the size of a response is decided by whoever answered the query -
up to 64 KiB of it. So an entry count alone bounds nothing: ten thousand
maximal entries are about 640 MB, and an attacker serving
maximal answers from a zone it controls needs only distinct names to walk elodin
there.

The server below is told it may hold a hundred thousand entries and one mebibyte.
Four hundred names are walked through it, each answered with about 3 KB, which is
nowhere near the entry count and several times the budget. Whether the first of
them is still cached afterwards is the whole question.
*/
run_cache_bytes_cases :: proc(r: ^Runner) {
	NAMES :: 400
	RECORDS :: 200

	upstream_port := next_port(r)
	mock := mock_make("cache-bytes", upstream_port)

	names := make([]string, NAMES, context.allocator)
	// Deferred ahead of `mock_stop`, so it runs after the mock that reads the
	// names is gone.
	defer {
		for name in names {
			delete(name)
		}
		delete(names)
	}
	for i in 0 ..< NAMES {
		names[i] = fmt.aprintf("bulk%d.example.com.", i)
		mock_reply(mock, names[i], u16(dns.Type.A), bulk_answer(names[i], RECORDS, context.allocator))
	}
	if !mock_start_or_skip(r, mock, "cache bytes") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "3s",
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, udp_port),
		cache = "{ enabled: true, max_entries: 100000, max_bytes: 1MiB }",
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "cache: a byte budget evicts long before the entry count does")
	{
		// 4096 advertised, so a 3 KB answer comes back over UDP as it is rather
		// than driving a retry over TCP.
		answered := 0
		for i in 0 ..< NAMES {
			res := query_udp(udp_port, build_query(names[i], u16(dns.Type.A), id = u16(i), edns_size = 4096))
			if res.ok {
				answered += 1
			}
		}
		if !check(r, answered == NAMES, "only %d of %d names were answered", answered, NAMES) {
			end_case(r)
			return
		}

		// The most recent is still held, so the cache is working and the check
		// below is about the bound rather than about caching being off.
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query(names[NAMES - 1], u16(dns.Type.A), id = 1000, edns_size = 4096))
		check_eq_int(r, mock_total(mock), 0, "upstream queries for the most recently cached name")

		// The oldest is not, and only the byte bound can have taken it: four
		// hundred entries is a fraction of the hundred thousand allowed.
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query(names[0], u16(dns.Type.A), id = 1001, edns_size = 4096))
		check(
			r,
			mock_total(mock) >= 1,
			"%d names at ~3 KB each all fit in a 1 MiB cache, so the byte bound did nothing",
			NAMES,
		)
	}
	end_case(r)
}

/*
`cache.serve_stale` against an upstream that has gone away, which is the outage
the setting exists for (#164).

The expired entry does not wait for `upstream.resolve` to give up on every
server for every attempt. With the defaults that is ten seconds against one
blackholed upstream and twenty against two, while a glibc stub resolver gives
up after five (`RES_TIMEOUT`) and systemd-resolved sooner - so a fallback that
late arrives after the client has already failed.

RFC 8767 section 5's client response timer is what these cases are about: the
held bytes go out once `cache.stale_timeout` has run, and the refresh carries
on without the client. The upstream here is silenced rather than stopped,
because a stopped one is a closed port and a closed port answers ICMP - the
fast failure, which is not this case. One attempt and a five-second timeout, so
the refresh is certainly still running while the second case runs and every
datagram counted is a refresh of its own.
*/
run_serve_stale_cases :: proc(r: ^Runner) {
	qname := "stale.example."
	upstream_port := next_port(r)
	mock := mock_make("stale", upstream_port)
	// A one-second TTL, so the entry expires inside the case rather than the
	// clock being what the case is about.
	mock_synth_all(mock, {203, 0, 113, 9}, ttl = 1)
	if !mock_start_or_skip(r, mock, "serve_stale") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "5s",
		upstream_extra = "  attempts: 1",
		cache = "{ enabled: true, max_entries: 100, serve_stale: true, stale_timeout: 300ms }",
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "serve_stale: an expired entry is served before the upstream gives up")
	{
		first := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 1))
		if !check(r, first.ok, "no response to the query that filled the cache") {
			end_case(r)
			return
		}
		check_eq_str(r, first_address(r, first.wire), "203.0.113.9", "the answer that was cached")

		// Past the one-second TTL, so the entry is expired and `serve_stale` is
		// all that is keeping it.
		time.sleep(1200 * time.Millisecond)
		mock_go_silent(mock)
		mock_reset_counts(mock)

		begun := time.tick_now()
		res := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 2))
		waited := time.tick_since(begun)
		if check(r, res.ok, "the expired entry was never served") {
			check_eq_str(r, first_address(r, res.wire), "203.0.113.9", "the expired answer")
			ttl, has_ttl := min_answer_ttl(r, res.wire)
			if check(r, has_ttl, "no TTL in the stale answer") {
				// The short fixed TTL a stale answer goes out with, so the
				// client comes back for a fresh one rather than holding this.
				check(r, ttl <= 30, "the stale answer went out with a TTL of %d", ttl)
			}
			check(
				r,
				waited < 2 * time.Second,
				"the client waited %v for an expired entry; the upstream budget is 5s",
				waited,
			)
		}
		// And the refresh really went out, rather than the entry being served
		// without anything being asked of the upstream.
		check(r, mock_total(mock) >= 1, "the refresh never reached the upstream")
	}
	end_case(r)

	start_case(r, "serve_stale: a second client does not put a second refresh on the wire")
	{
		mock_reset_counts(mock)
		begun := time.tick_now()
		res := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 3))
		waited := time.tick_since(begun)
		if check(r, res.ok, "the second client went unanswered") {
			check_eq_str(r, first_address(r, res.wire), "203.0.113.9", "the expired answer")
			check(r, waited < 2 * time.Second, "the second client waited %v", waited)
		}
		check_eq_int(r, mock_total(mock), 0, "upstream queries while a refresh is already running")
	}
	end_case(r)
}

/*
And the refresh the client stopped waiting for still renews the entry.

The other half of RFC 8767 section 5, and the half a fast case cannot see: an
answer that arrives after the timer has fired is stored rather than dropped, so
the next client is served a fresh entry instead of the same expired bytes over
again. Without it a slow upstream - one that answers, but later than the timer -
would leave a name stale for the whole day the cache keeps it, every client
answered from the entry and every refresh thrown away.

What says which of the two happened is the upstream's own query count. A third
query that finds the entry refreshed is a cache hit and asks nobody; one that
finds it still expired starts another refresh, and the count goes up. Neither
the address nor the TTL can tell them apart here - the mock answers the same
bytes every time, and `cache.max_ttl` of 4 bounds the stale answer's 30-second
TTL to the same figure as a fresh one's.

The upstream answers 1.2 seconds after it is asked, against a 300 ms timer, so
the client is certainly served from the entry and the refresh certainly succeeds
behind it. The gap is what makes the middle assertion discriminating as well: a
build without the timer waits the upstream out and answers in 1.2 seconds, which
is not under the 700 ms allowed here.
*/
run_stale_refresh_cases :: proc(r: ^Runner) {
	qname := "slow.example."
	upstream_port := next_port(r)
	mock := mock_make("stale-refresh", upstream_port)
	mock_delay_all(
		mock,
		1200 * time.Millisecond,
		make_a_response(qname, {203, 0, 113, 8}, 60, context.allocator),
	)
	if !mock_start_or_skip(r, mock, "serve_stale refresh") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "5s",
		upstream_extra = "  attempts: 1",
		cache = "{ enabled: true, max_entries: 100, max_ttl: 4, serve_stale: true, stale_timeout: 300ms }",
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "serve_stale: the refresh the client gave up on still lands in the cache")
	{
		first := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 11))
		if !check(r, first.ok, "no response to the query that filled the cache") {
			end_case(r)
			return
		}
		check_eq_str(r, first_address(r, first.wire), "203.0.113.8", "the answer that was cached")

		// Past `max_ttl`, which is what the entry was stored under.
		time.sleep(4300 * time.Millisecond)
		mock_reset_counts(mock)

		begun := time.tick_now()
		second := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 12))
		waited := time.tick_since(begun)
		if !check(r, second.ok, "the expired entry was never served") {
			end_case(r)
			return
		}
		check(
			r,
			waited < 700 * time.Millisecond,
			"the client waited %v rather than being served from the entry at the 300ms timer",
			waited,
		)
		check_eq_int(r, mock_total(mock), 1, "upstream queries for the refresh")

		// Long enough for a 1.2-second upstream to have answered and the
		// refresh to have stored it, and well short of the four seconds the
		// entry it stored is then good for.
		time.sleep(2 * time.Second)

		third := query_udp(udp_port, build_query(qname, u16(dns.Type.A), id = 13))
		if check(r, third.ok, "no response after the refresh") {
			check_eq_str(r, first_address(r, third.wire), "203.0.113.8", "the refreshed answer")
			check_eq_int(
				r,
				mock_total(mock),
				1,
				"upstream queries after the refresh; a second one means it was dropped",
			)
		}
	}
	end_case(r)
}

// NOERROR whose answer is a CNAME out of the zone and nothing else: no record at
// the target, and nothing in authority.
bare_cname_reply :: proc(name: string) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = name,
		type  = .CNAME,
		class = .IN,
		ttl   = 3600,
		data  = dns.Rdata_Name{name = "cdn.example.net."},
	}
	return encode_reply(name, .A, {answer = answer})
}

// A referral: NOERROR, RA clear, the zone's NS in authority and no SOA - what a
// server that does not recurse sends for a name below a cut.
@(private = "file")
referral_reply :: proc(name: string) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = name, type = .A, class = .IN}
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = dns.Record {
		name  = "example.com.",
		type  = .NS,
		class = .IN,
		ttl   = 3600,
		data  = dns.Rdata_Name{name = "ns1.example.com."},
	}
	msg := dns.Message {
		question  = question,
		authority = authority,
	}
	msg.flags.qr = true
	wire, _, err := dns.encode_message(msg, context.allocator)
	if err != .None {
		return nil
	}
	return wire
}
