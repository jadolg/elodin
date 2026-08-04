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
		port := next_port(r)
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
			port,
			upstream_port,
			mode.response,
			mode.extra,
			hosts_path,
			abp_path,
			domains_path,
		)

		srv, ok := start_server(r, Server_Options{config = config, port = port})
		if !ok {
			skip_case(r, fmt.tprintf("blocking mode %s", mode.name), "server did not start")
			continue
		}

		start_case(r, fmt.tprintf("blocking: response mode %s", mode.name))
		{
			res := query_udp(port, build_query("ads.tracker.test.", u16(dns.Type.A)))
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
				res := query_udp(port, build_query("ads.tracker.test.", u16(dns.Type.AAAA)))
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
			blocked := query_udp(port, build_query("metrics.tracker.test.", u16(dns.Type.A)))
			if check(r, blocked.ok, "no response for the listed name") {
				h, _ := parse_header(blocked.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "listed name not blocked")
			}
			sub := query_udp(port, build_query("deep.ads.tracker.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response for the subdomain") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "a hosts entry blocked its subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: the list's own localhost lines are not rules")
		{
			res := query_udp(port, build_query("localhost.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "localhost was turned into a block rule")
			}
		}
		end_case(r)

		start_case(r, "blocking: adblock || covers the domain and its subtree")
		{
			for name in ([]string{"evil.test.", "sub.evil.test.", "a.b.evil.test."}) {
				res := query_udp(port, build_query(name, u16(dns.Type.A)))
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
				res := query_udp(port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h, _ := parse_header(res.wire)
					check(r, h.rcode == int(dns.Rcode.No_Error), "%s should have been allowed", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: modifiers are stripped, the rule still applies")
		{
			res := query_udp(port, build_query("modifiers.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "a rule with $modifiers was dropped")
			}
		}
		end_case(r)

		start_case(r, "blocking: | anchors match the exact name only")
		{
			exact := query_udp(port, build_query("exact.test.", u16(dns.Type.A)))
			if check(r, exact.ok, "no response") {
				h, _ := parse_header(exact.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the anchored name was not blocked")
			}
			sub := query_udp(port, build_query("sub.exact.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "an anchored rule blocked a subdomain")
			}
		}
		end_case(r)

		start_case(r, "blocking: dnsmasq address=/ syntax")
		{
			res := query_udp(port, build_query("deep.dnsmasq.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "address=/ rule was not applied")
			}
		}
		end_case(r)

		start_case(r, "blocking: an unusable rule is skipped, the list still loads")
		{
			res := query_udp(port, build_query("a-regex-rule.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "a regex rule was treated as a domain")
			}
		}
		end_case(r)

		start_case(r, "blocking: bare domains cover their subtree")
		{
			for name in ([]string{"subtree.test.", "a.subtree.test."}) {
				res := query_udp(port, build_query(name, u16(dns.Type.A)))
				if check(r, res.ok, "no response for %s", name) {
					h, _ := parse_header(res.wire)
					check(r, h.rcode == int(dns.Rcode.NX_Domain), "%s was not blocked", name)
				}
			}
		}
		end_case(r)

		start_case(r, "blocking: *.name covers subdomains but not the apex")
		{
			sub := query_udp(port, build_query("host.wildcard.test.", u16(dns.Type.A)))
			if check(r, sub.ok, "no response") {
				h, _ := parse_header(sub.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the subdomain was not blocked")
			}
			apex := query_udp(port, build_query("wildcard.test.", u16(dns.Type.A)))
			if check(r, apex.ok, "no response") {
				h, _ := parse_header(apex.wire)
				check(r, h.rcode == int(dns.Rcode.No_Error), "*.name should not block the apex")
			}
		}
		end_case(r)

		start_case(r, "blocking: matching ignores case")
		{
			res := query_udp(port, build_query("ADS.Tracker.TEST.", u16(dns.Type.A)))
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

	port := next_port(r)
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
  - {{ domain: "*.lab", answers: [10.0.0.1, "fd00::1"] }}
  - {{ domain: old.example.org, answer: new.example.org }}
  - {{ domain: telemetry.example.org, answer: block }}
`,
		port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, port = port})
	if !ok {
		skip_case(r, "rewrites", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "rewrite: a literal name answers with the configured A")
	{
		res := query_udp(port, build_query("nas.home.", u16(dns.Type.A)))
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
		v4 := query_udp(port, build_query("host1.lab.", u16(dns.Type.A)))
		if check(r, v4.ok, "no A response") {
			addrs := answer_addresses(v4.wire)
			if check(r, len(addrs) == 1, "expected one A record") {
				check_eq_str(r, addrs[0], "10.0.0.1", "A answer")
			}
		}
		v6 := query_udp(port, build_query("host2.lab.", u16(dns.Type.AAAA)))
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
		res := query_udp(port, build_query("lab.", u16(dns.Type.A)))
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
		res := query_udp(port, build_query("old.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			check_eq_str(r, first_cname_or_name(res.wire), "new.example.org.", "CNAME target")
		}
	}
	end_case(r)

	start_case(r, "rewrite: answer 'block' sinks the name")
	{
		res := query_udp(port, build_query("telemetry.example.org.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "rcode %d, want NXDOMAIN", h.rcode)
		}
	}
	end_case(r)

	start_case(r, "rewrite: an unmatched type gets NODATA, not a wrong answer")
	{
		res := query_udp(port, build_query("nas.home.", u16(dns.Type.MX)))
		if check(r, res.ok, "no response") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "rcode %d, want NOERROR", h.rcode)
			check_eq_int(r, h.ancount, 0, "answer count")
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

	port := next_port(r)
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
		port,
		port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, port = port})
	if !ok {
		skip_case(r, "cache", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "cache: a repeated query does not reach the upstream")
	{
		mock_reset_counts(mock)
		first := query_udp(port, build_query(fix.qname, fix.qtype, id = 1))
		if !check(r, first.ok, "no response to the first query") {
			end_case(r)
			return
		}
		check_eq_int(r, mock_total(mock), 1, "upstream queries after the first request")

		second := query_udp(port, build_query(fix.qname, fix.qtype, id = 2))
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
		before, has_before := min_answer_ttl(query_udp(port, build_query(fix.qname, fix.qtype, id = 3)).wire)
		if !check(r, has_before, "no TTL in the first answer") {
			end_case(r)
			return
		}
		time.sleep(1100 * time.Millisecond)
		after, has_after := min_answer_ttl(query_udp(port, build_query(fix.qname, fix.qtype, id = 4)).wire)
		if check(r, has_after, "no TTL in the second answer") {
			check(r, after < before, "TTL did not decrease: %d then %d", before, after)
		}
	}
	end_case(r)

	start_case(r, "cache: a cached answer serves other transports too")
	{
		mock_reset_counts(mock)
		res := query_tcp(port, build_query(fix.qname, fix.qtype, id = 5))
		if check(r, res.ok, "no response over TCP") {
			check_eq_int(r, mock_total(mock), 0, "upstream queries for a cached name over TCP")
		}
	}
	end_case(r)

	start_case(r, "cache: the question case is restored for the asking client")
	{
		query := build_query("EXAMPLE.com.", fix.qtype, id = 6)
		res := query_udp(port, query)
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
		_ = query_udp(port, build_query("nx.example.com.", u16(dns.Type.A), id = 7))
		count_after_first := mock_total(mock)
		_ = query_udp(port, build_query("nx.example.com.", u16(dns.Type.A), id = 8))
		check_eq_int(r, mock_total(mock), count_after_first, "upstream queries after a cached negative answer")
	}
	end_case(r)

	start_case(r, "cache: A and AAAA are separate entries")
	{
		mock_reset_counts(mock)
		_ = query_udp(port, build_query(fix.qname, u16(dns.Type.AAAA), id = 9))
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
			data  = dns.Rdata_A{addr = {10, u8(i >> 8), u8(i), 1}},
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

	port := next_port(r)
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
		port,
		port,
		upstream_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, port = port})
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
			res := query_udp(port, build_query(names[i], u16(dns.Type.A), id = u16(i), edns_size = 4096))
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
		_ = query_udp(port, build_query(names[NAMES - 1], u16(dns.Type.A), id = 1000, edns_size = 4096))
		check_eq_int(r, mock_total(mock), 0, "upstream queries for the most recently cached name")

		// The oldest is not, and only the byte bound can have taken it: four
		// hundred entries is a fraction of the hundred thousand allowed.
		mock_reset_counts(mock)
		_ = query_udp(port, build_query(names[0], u16(dns.Type.A), id = 1001, edns_size = 4096))
		check(
			r,
			mock_total(mock) >= 1,
			"%d names at ~3 KB each all fit in a 1 MiB cache, so the byte bound did nothing",
			NAMES,
		)
	}
	end_case(r)
}
