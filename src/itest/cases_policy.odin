package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:time"
import "elodin:dns"

/*
Policy coverage: sink lists, block response modes, rewrites and the cache.
*/

// The returned path is heap-allocated on purpose: it is reused across cases,
// and end_case resets the temp allocator between them.
@(private = "file")
write_list :: proc(r: ^Runner, name: string, contents: string) -> string {
	path := filepath.join({r.work_dir, name}, context.allocator) or_else ""
	_ = os.write_entire_file(path, transmute([]u8)contents)
	return path
}

run_blocking_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("policy", upstream_port)
	// Anything not blocked resolves to this address, so a query that reached
	// the upstream is distinguishable from one that was sunk. The answer is
	// synthesised per query because elodin checks that a reply's question
	// matches what it asked.
	mock_synth_all(mock, {203, 0, 113, 1})
	if !mock_start(mock) {
		skip_case(r, "blocking", "cannot start the mock upstream")
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
||modifiers.test^$third-party
@@||good.evil.test^
|http://exact.test^
address=/dnsmasq.test/0.0.0.0
/a-regex-rule.*/
`,
	)
	domains_path := write_list(
		r,
		"domains.txt",
		`# domains-format list
subtree.test
*.wildcard.test
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
		{"custom", "custom", "  custom_ipv4: 10.1.2.3\n  custom_ipv6: \"fd00::abcd\"\n"},
		{"refused", "refused", ""},
	}

	for mode in modes {
		udp_port := next_port(r)
		config := fmt.tprintf(
			`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  response: %s
  block_ttl: 42
%s  lists:
    - {{ name: hosts, file: %s, format: hosts }}
    - {{ name: abp, file: %s, format: adblock }}
    - {{ name: domains, file: %s, format: domains }}
`,
			udp_port,
			upstream_port,
			mode.response,
			mode.extra,
			hosts_path,
			abp_path,
			domains_path,
		)

		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
		if !ok {
			skip_case(r, fmt.tprintf("blocking mode %s", mode.name), "server did not start")
			continue
		}

		start_case(r, fmt.tprintf("blocking: response mode %s", mode.name))
		{
			res := query_udp(udp_port, build_query("ads.tracker.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
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
					addrs := answer_addresses(res.wire)
					if check(r, len(addrs) == 1, "expected one address") {
						check_eq_str(r, addrs[0], "0.0.0.0", "sink address")
					}
				case "custom":
					check_eq_int(r, h.ancount, 1, "answer count")
					addrs := answer_addresses(res.wire)
					if check(r, len(addrs) == 1, "expected one address") {
						check_eq_str(r, addrs[0], "10.1.2.3", "sink address")
					}
					ttl, has := min_answer_ttl(res.wire)
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
					addrs := answer_addresses(res.wire)
					if check(r, len(addrs) == 1, "expected one address") {
						check_eq_str(r, addrs[0], "fd00:0000:0000:0000:0000:0000:0000:abcd", "sink address")
					}
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
			blocked := query_udp(udp_port, build_query("metrics.tracker.test.", u16(dns.Type.A)))
			if check(r, blocked.ok, "no response for the listed name") {
				h, _ := parse_header(blocked.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "listed name not blocked")
			}
			sub := query_udp(udp_port, build_query("deep.ads.tracker.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response for the subdomain") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "a hosts entry blocked its subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: the list's own localhost lines are not rules")
		{
			res := query_udp(udp_port, build_query("localhost.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "localhost was turned into a block rule")
			}
		}
		end_case(r)

		start_case(r, "blocking: adblock || covers the domain and its subtree")
		{
			for name in ([]string{"evil.test.", "sub.evil.test.", "a.b.evil.test."}) {
				res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h, _ := parse_header(res.wire)
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: allow rules beat block rules")
		{
			for name in ([]string{"good.evil.test.", "deeper.good.evil.test."}) {
				res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h, _ := parse_header(res.wire)
					check(r, h.rcode == int(dns.Rcode.No_Error), "%s should have been allowed", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: modifiers are stripped, the rule still applies")
		{
			res := query_udp(udp_port, build_query("modifiers.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "a rule with $modifiers was dropped")
			}
		}
		end_case(r)

		start_case(r, "blocking: | anchors match the exact name only")
		{
			exact := query_udp(udp_port, build_query("exact.test.", u16(dns.Type.A)))
			if check(r, exact.ok, "no response") {
				h, _ := parse_header(exact.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the anchored name was not blocked")
			}
			sub := query_udp(udp_port, build_query("sub.exact.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "an anchored rule blocked a subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: dnsmasq address=/ syntax")
		{
			res := query_udp(udp_port, build_query("deep.dnsmasq.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "address=/ rule was not applied")
			}
		}
		end_case(r)

		start_case(r, "blocking: an unusable rule is skipped, the list still loads")
		{
			res := query_udp(udp_port, build_query("a-regex-rule.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "a regex rule was treated as a domain")
			}
		}
		end_case(r)

		start_case(r, "blocking: bare domains cover their subtree")
		{
			for name in ([]string{"subtree.test.", "a.subtree.test."}) {
				res := query_udp(udp_port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h, _ := parse_header(res.wire)
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: *.name covers subdomains but not the apex")
		{
			sub := query_udp(udp_port, build_query("host.wildcard.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the subdomain was not blocked")
			}
			apex := query_udp(udp_port, build_query("wildcard.test.", u16(dns.Type.A)))
			if check(r, apex.ok, "no response") {
				h, _ := parse_header(apex.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "*.name should not block the apex")
			}
		}
		end_case(r)

		start_case(r, "blocking: matching ignores case")
		{
			res := query_udp(udp_port, build_query("ADS.Tracker.TEST.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "an upper-case name evaded the list")
			}
		}
		end_case(r)

		stop_server(&srv)
	}
}

run_rewrite_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("rewrites", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 1})
	if !mock_start(mock) {
		skip_case(r, "rewrites", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: true, response: nxdomain }}
rewrites:
  - {{ domain: nas.home, answer: 192.168.1.50, ttl: 111 }}
  - {{ domain: nas6.home, answer: "fd00::50" }}
  - {{ domain: "*.lab", answers: [10.0.0.1, "fd00::1"] }}
  - {{ domain: old.example.org, answer: new.example.org }}
  - {{ domain: telemetry.example.org, answer: block }}
  - {{ domain: www.example.org, answer: 203.0.113.9 }}
  - {{ domain: shadowed.lab, answer: 192.168.1.70 }}
  - {{ domain: sink.example.org, answers: [block, 192.168.1.60] }}
  - {{ domain: blockpage.example.org, answer: 192.168.1.80, ptr: false }}
  - {{ domain: mail.example.org, answers: ["MX 10 mx1.example.org", "MX 20 mx2.example.org", "TXT v=spf1 -all"] }}
  - {{ domain: _sip._tcp.example.org, answer: "SRV 0 5 5060 sip.example.org" }}
`,
		udp_port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "rewrites", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "rewrite: a literal name answers with the configured A")
	{
		res := query_udp(udp_port, build_query("nas.home.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			addrs := answer_addresses(res.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "192.168.1.50", "rewritten address")
			}
			ttl, has := min_answer_ttl(res.wire)
			check(r, has && ttl == 111, "TTL: got %d, want 111", ttl)
		}
	}
	end_case(r)

	start_case(r, "rewrite: a wildcard answers A and AAAA separately")
	{
		v4 := query_udp(udp_port, build_query("host1.lab.", u16(dns.Type.A)))
		if check(r, v4.ok, "no A response") {
			addrs := answer_addresses(v4.wire)
			if check(r, len(addrs) == 1, "expected one A record") {
				check_eq_str(r, addrs[0], "10.0.0.1", "A answer")
			}
		}
		v6 := query_udp(udp_port, build_query("host2.lab.", u16(dns.Type.AAAA)))
		if check(r, v6.ok, "no AAAA response") {
			addrs := answer_addresses(v6.wire)
			if check(r, len(addrs) == 1, "expected one AAAA record") {
				check_eq_str(r, addrs[0], "fd00:0000:0000:0000:0000:0000:0000:0001", "AAAA answer")
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: a wildcard does not match its own apex")
	{
		res := query_udp(udp_port, build_query("lab.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			addrs := answer_addresses(res.wire)
			// It should have fallen through to the upstream instead.
			if check(r, len(addrs) == 1, "expected the upstream answer, got %d records", len(addrs)) {
				check_eq_str(r, addrs[0], "203.0.113.1", "answer source")
			}
		}
	}
	end_case(r)

	start_case(r, "rewrite: a name answer becomes a CNAME")
	{
		res := query_udp(udp_port, build_query("old.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(res.wire), "new.example.org.", "CNAME target")
		}
	}
	end_case(r)

	start_case(r, "rewrite: answer 'block' sinks the name")
	{
		res := query_udp(udp_port, build_query("telemetry.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
		}
	}
	end_case(r)

	start_case(r, "rewrite: an unmatched type gets NODATA, not a wrong answer")
	{
		res := query_udp(udp_port, build_query("nas.home.", u16(dns.Type.MX)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
		}
	}
	end_case(r)

	start_case(r, "rewrite: MX answers with both hosts and their preferences")
	{
		res := query_udp(udp_port, build_query("mail.example.org.", u16(dns.Type.MX)))
		if check(r, res.ok, "no response") {
			msg, derr := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, derr == .None, "response did not decode: %v", derr) &&
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
			msg, derr := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, derr == .None, "response did not decode: %v", derr) &&
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
			msg, derr := dns.decode_message(res.wire, context.temp_allocator)
			if check(r, derr == .None, "response did not decode: %v", derr) &&
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

	start_case(r, "rewrite: a record rule is NODATA for the types it has none of")
	{
		// The upstream would have synthesised an A for this name, so an empty
		// answer is the proof the rule answered rather than the query leaving.
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("mail.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
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
		res := query_udp(udp_port, build_query("50.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_str(r, first_cname_or_name(res.wire), "nas.home.", "PTR target")
			ttl, has := min_answer_ttl(res.wire)
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
			check_eq_str(r, first_cname_or_name(res.wire), "nas6.home.", "PTR target")
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
			check_eq_str(r, first_cname_or_name(res.wire), "", "a wildcard must produce no PTR")
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
			check_eq_str(r, first_cname_or_name(res.wire), "", "a public address must produce no PTR")
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
			addrs := answer_addresses(v4.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "10.0.0.1", "the wildcard is what answers")
			}
		}
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("70.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(res.wire), "", "a shadowed rule must produce no PTR")
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
			check_eq_str(r, first_cname_or_name(res.wire), "", "a sunk rule must produce no PTR")
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
			addrs := answer_addresses(fwd.wire)
			if check(r, len(addrs) == 1, "expected one address, got %d", len(addrs)) {
				check_eq_str(r, addrs[0], "192.168.1.80", "the forward answer is unaffected")
			}
		}
		mock_reset_counts(mock)
		res := query_udp(udp_port, build_query("80.1.168.192.in-addr.arpa.", u16(dns.Type.PTR)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(res.wire), "", "ptr: false must produce no PTR")
			check(r, mock_total(mock) >= 1, "the query should have been forwarded")
		}
	}
	end_case(r)

	start_case(r, "rewrite: a synthesised reverse name is NODATA for other types")
	{
		// The name exists - its PTR was just answered - so another type is
		// "there is none" rather than a forwarded query. The upstream would have
		// synthesised an A for it, so an empty answer is the proof it stayed.
		res := query_udp(udp_port, build_query("50.1.168.192.in-addr.arpa.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
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
	mock_reply(mock, "nx.example.com.", u16(dns.Type.A), nil)
	// Any other question (the AAAA case below) gets a matching synthesised
	// answer rather than a canned one for the wrong name.
	mock_synth_all(mock, {203, 0, 113, 2})
	if !mock_start(mock) {
		skip_case(r, "cache", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache:
  enabled: true
  max_entries: 100
  negative_ttl: 60
blocking: {{ enabled: false }}
`,
		udp_port,
		udp_port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, tcp_port = udp_port})
	if !ok {
		skip_case(r, "cache", "server did not start")
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
			h, _ := parse_header(second.wire)
			check(r, h.id == 2, "the cached answer kept the wrong ID: %04x", h.id)
			check_eq_int(r, h.ancount, fix.ancount, "answer count from cache")
		}
	}
	end_case(r)

	start_case(r, "cache: TTLs count down while an entry is held")
	{
		before, has_before := min_answer_ttl(query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 3)).wire)
		if !check(r, has_before, "no TTL in the first answer") {
			end_case(r)
			return
		}
		time.sleep(1100 * time.Millisecond)
		after, has_after := min_answer_ttl(query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 4)).wire)
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
				len(res.wire) > 25 && bytes_equal(res.wire[12:25], query[12:25]),
				"the cached answer did not echo the client's spelling",
			)
		}
	}
	end_case(r)

	start_case(r, "cache: negative answers are cached")
	{
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query("nx.example.com.", u16(dns.Type.A), id = 7))
		count_after_first := mock_total(mock)
		_ = query_udp(udp_port, build_query("nx.example.com.", u16(dns.Type.A), id = 8))
		check_eq_int(r, mock_total(mock), count_after_first, "upstream queries after a cached negative answer")
	}
	end_case(r)

	start_case(r, "cache: A and AAAA are separate entries")
	{
		mock_reset_counts(mock)
		_ = query_udp(udp_port, build_query(fix.qname, u16(dns.Type.AAAA), id = 9))
		check(r, mock_total(mock) >= 1, "an AAAA query was answered from the A entry")
	}
	end_case(r)
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
	m := dns.Message {
		id       = 0x4242,
		question = []dns.Question{{name = name, type = .A, class = .IN}},
		answer   = answers,
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
The cache has to be bounded by what it holds, not only by how many things it
holds.

An entry is the response as it arrived plus an offset and a TTL for each of its
records, and the size of a response is decided by whoever answered the query -
up to 64 KiB of it. So an entry count is not a bound on memory: ten thousand
entries at the default stood for something near 640 MB, and an attacker serving
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
	defer delete(names)
	for i in 0 ..< NAMES {
		names[i] = fmt.aprintf("bulk%d.example.com.", i)
		mock_reply(mock, names[i], u16(dns.Type.A), bulk_answer(names[i], RECORDS, context.allocator))
	}
	if !mock_start(mock) {
		skip_case(r, "cache bytes", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache:
  enabled: true
  max_entries: 100000
  max_bytes: 1MiB
blocking: {{ enabled: false }}
`,
		udp_port,
		udp_port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "cache bytes", "server did not start")
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
