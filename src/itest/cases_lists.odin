package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "elodin:dns"

/*
Downloading sink lists and caching them on disk.

Every other case runs with --no-fetch, which skips this path entirely. It is
also where a crash lived: the cache directory was derived with `filepath.dir`,
which returns a slice of its argument rather than a new string, and freeing it
corrupted the heap. The symptom appeared on the *second* list, so these cases
use two.
*/

run_list_download_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(
		http,
		"/hosts.txt",
		"# a hosts list\n127.0.0.1 localhost\n0.0.0.0 downloaded.test\n0.0.0.0 second.downloaded.test\n",
	)
	http_mock_serve(http, "/abp.txt", "[Adblock Plus 2.0]\n||fetched.test^\n@@||ok.fetched.test^\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: download", "cannot start the HTTP mock")
		return
	}
	defer http_mock_stop(http)

	upstream_port := next_port(r)
	mock := mock_make("lists", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "lists: download", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	cache_dir := filepath.join({r.work_dir, "listcache"}, context.allocator) or_else ""
	defer delete(cache_dir)

	udp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: debug }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  response: nxdomain
  cache_dir: %s
  refresh: 24h
  lists:
    - {{ name: hosts-list, url: "http://127.0.0.1:%d/hosts.txt", format: hosts }}
    - {{ name: abp-list, url: "http://127.0.0.1:%d/abp.txt", format: adblock }}
`,
		udp_port,
		upstream_port,
		cache_dir,
		http_port,
		http_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if !ok {
		skip_case(r, "lists: download", "server did not start")
		return
	}

	start_case(r, "lists: two lists are downloaded and both take effect")
	{
		// Reaching this at all means the fetch-and-cache path did not corrupt
		// the heap on the way through the second list.
		check_eq_int(r, http_mock_hits(http, "/hosts.txt"), 1, "fetches of the hosts list")
		check_eq_int(r, http_mock_hits(http, "/abp.txt"), 1, "fetches of the adblock list")

		res := query_udp(udp_port, build_query("downloaded.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no response for a name from the first list") {
			h, _ := parse_header(res.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the first list was not applied")
		}
		res2 := query_udp(udp_port, build_query("sub.fetched.test.", u16(dns.Type.A)))
		if check(r, res2.ok, "no response for a name from the second list") {
			h, _ := parse_header(res2.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the second list was not applied")
		}
		allowed := query_udp(udp_port, build_query("ok.fetched.test.", u16(dns.Type.A)))
		if check(r, allowed.ok, "no response for an allowed name") {
			h, _ := parse_header(allowed.wire)
			check(r, h.rcode == int(dns.Rcode.No_Error), "the allow rule from the download was lost")
		}
	}
	end_case(r)

	start_case(r, "lists: downloads are written to the cache directory")
	{
		for name in ([]string{"hosts-list.list", "abp-list.list"}) {
			path := filepath.join({cache_dir, name}, context.temp_allocator) or_else ""
			check(r, os.exists(path), "%s was not cached to disk", name)
		}
	}
	end_case(r)

	stop_server(&srv)

	start_case(r, "lists: a restart reuses the cache instead of downloading again")
	{
		// The refresh window has not elapsed, so nothing should be re-fetched.
		port2 := next_port(r)
		config2 := fmt.tprintf(
			`log: {{ level: debug }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  cache_dir: %s
  refresh: 24h
  lists:
    - {{ name: hosts-list, url: "http://127.0.0.1:%d/hosts.txt", format: hosts }}
    - {{ name: abp-list, url: "http://127.0.0.1:%d/abp.txt", format: adblock }}
`,
			port2,
			upstream_port,
			cache_dir,
			http_port,
			http_port,
		)
		srv2, ok2 := start_server(r, Server_Options{config = config2, udp_port = port2, allow_fetch = true})
		if check(r, ok2, "the second server did not start") {
			defer stop_server(&srv2)
			check_eq_int(r, http_mock_hits(http, "/hosts.txt"), 1, "fetches after a restart")
			res := query_udp(port2, build_query("downloaded.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the cached list was not applied")
			}
			check(r, log_contains(&srv2, "using the cached copy"), "the cache was not reported as used")
		}
	}
	end_case(r)

	start_case(r, "lists: an unwritable cache directory is a warning, not a failure")
	{
		port3 := next_port(r)
		config3 := fmt.tprintf(
			`log: {{ level: debug }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  cache_dir: /proc/elodin-cannot-write-here
  refresh: 24h
  lists:
    - {{ name: hosts-list, url: "http://127.0.0.1:%d/hosts.txt", format: hosts }}
    - {{ name: abp-list, url: "http://127.0.0.1:%d/abp.txt", format: adblock }}
`,
			port3,
			upstream_port,
			http_port,
			http_port,
		)
		srv3, ok3 := start_server(r, Server_Options{config = config3, udp_port = port3, allow_fetch = true})
		if check(r, ok3, "the server did not start with an unwritable cache directory") {
			defer stop_server(&srv3)
			res := query_udp(port3, build_query("downloaded.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h, _ := parse_header(res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list was not applied")
			}
			check(r, log_contains(&srv3, "is not writable"), "no warning about the cache directory")
		}
	}
	end_case(r)
}
