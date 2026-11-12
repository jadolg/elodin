package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "elodin:config"
import "elodin:dns"

/*
A DoH upstream and a list that the file names only by a url with a key in the
query (#487). The query is still sent - the list mock serves only the path with
it - but the name the log and /metrics show stops before it, and so does the
name of the list's cache file. A dead upstream ahead of the live one puts a
warn-level failure line under the name.
*/
run_name_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	payload := from_hex(fix.response, context.allocator)
	defer delete(payload)

	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/hosts.txt?key=SECRET3", "0.0.0.0 named.test\n")
	// Each mock is stopped whether or not it started: the stop frees a failed start too.
	http_ok := http_mock_start(http)
	defer http_mock_stop(http)
	if !http_ok {
		skip_case(r, "names: a default name holds no query", "cannot start the HTTP mock")
		return
	}

	upstream_port := next_port(r)
	mock := doh2_mock_make(upstream_port, "/dns-query", payload)
	mock_ok := doh2_mock_start(mock, r.cert_file, r.key_file)
	defer doh2_mock_stop(mock)
	if !mock_ok {
		skip_case(r, "names: a default name holds no query", "cannot start the mock")
		return
	}

	cache_dir := filepath.join({r.work_dir, "namecache"}, context.allocator) or_else ""
	defer delete(cache_dir)
	dead_port := next_port(r)
	udp_port := next_port(r)
	metrics_port := next_port(r)
	conf := base_config(
		udp_port,
		fmt.tprintf(`[{{ url: "https://127.0.0.1:%d/dns-query?token=SECRET1", verify: false }}, {{ url: "https://127.0.0.1:%d/dns-query?token=SECRET2#frag", verify: false }}]`, dead_port, upstream_port),
		log = "{ level: debug }",
		timeout = "3s",
		upstream_extra = "  strategy: failover",
		blocking = fmt.tprintf(`{{ enabled: true, response: nxdomain, cache_dir: %q, lists: ["http://127.0.0.1:%d/hosts.txt?key=SECRET3"] }}`, cache_dir, http_port),
		extra = fmt.tprintf(`metrics: {{ enabled: true, address: "127.0.0.1", port: %d }}`, metrics_port),
	)
	srv, ok := start_server(r, Server_Options{config = conf, udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "names: a default name holds no query, in the log, on /metrics or in the list cache")
	{
		check_eq_int(r, http_mock_hits(http, "/hosts.txt?key=SECRET3"), 1, "fetches of the list with its query")
		blocked := query_udp(udp_port, build_query("named.test.", u16(dns.Type.A)))
		if check(r, blocked.ok, "no response for a listed name") {
			check(r, parse_header(r, blocked.wire).rcode == int(dns.Rcode.NX_Domain), "the list was not applied")
		}
		if _, h, asked := ask(r, udp_port, fix.qname, fix.qtype); asked {
			check_eq_int(r, h.ancount, fix.ancount, "answer count")
		}

		live := fmt.tprintf("https://127.0.0.1:%d/dns-query", upstream_port)
		dead := fmt.tprintf("https://127.0.0.1:%d/dns-query", dead_port)
		if page := metrics_page(metrics_port); check(r, page != "", "the metrics endpoint never answered") {
			check(r, strings.contains(page, fmt.tprintf("elodin_upstream_queries_total{{upstream=\"%s\"}}", live)), "no series for %s:\n%s", live, page)
			check(r, strings.contains(page, fmt.tprintf("elodin_upstream_failures_total{{upstream=\"%s\"}}", dead)), "no failures for %s:\n%s", dead, page)
			check(r, !strings.contains(page, "SECRET"), "the scrape shows a query:\n%s", page)
		}
		log := read_log(&srv)
		// The warn line's own shape: a debug line names the upstream too, and a
		// name with the query still in it would match a bare prefix.
		check(r, strings.contains(log, fmt.tprintf("upstream %s (HTTPS ", dead)), "the dead upstream's failure is not logged under its name:\n%s", log)
		check(r, !strings.contains(log, "SECRET"), "the log shows a query:\n%s", log)
		list_name := fmt.tprintf("http://127.0.0.1:%d/hosts.txt", http_port)
		file := config.list_cache_file(config.Block_List{name = list_name, url = fmt.tprintf("%s?key=SECRET3", list_name)})
		check_eq_str(r, file, fmt.tprintf("http___127.0.0.1_%d_hosts.txt.list", http_port), "the cache file")
		cached := filepath.join({cache_dir, file}, context.temp_allocator) or_else ""
		check(r, os.exists(cached), "the list is not cached as %s", cached)
		src, _ := os.read_entire_file(fmt.tprintf("%s.src", cached), context.temp_allocator)
		check(r, len(src) > 0 && !strings.contains(string(src), "SECRET"), "the fingerprint beside the copy is %q", string(src))
	}
	end_case(r)
}
