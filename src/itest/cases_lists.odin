package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:time"
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
			h := parse_header(r, res.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the first list was not applied")
		}
		res2 := query_udp(udp_port, build_query("sub.fetched.test.", u16(dns.Type.A)))
		if check(r, res2.ok, "no response for a name from the second list") {
			h := parse_header(r, res2.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the second list was not applied")
		}
		allowed := query_udp(udp_port, build_query("ok.fetched.test.", u16(dns.Type.A)))
		if check(r, allowed.ok, "no response for an allowed name") {
			h := parse_header(r, allowed.wire)
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
				h := parse_header(r, res.wire)
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
				h := parse_header(r, res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list was not applied")
			}
			check(r, log_contains(&srv3, "is not writable"), "no warning about the cache directory")
		}
	}
	end_case(r)
}

/*
A refresh at runtime that can reach neither a list nor a cached copy of it.

The startup fallback above is to the copy on disk. With no copy - an unwritable
or cleared `cache_dir` - and the list server gone at the refresh, the rules in
effect have to stay, not be swapped for a set without the list until the next
refresh (#411). The first refresh runs on the maintenance loop's first 30s tick.
*/
run_list_refresh_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/hosts.txt", "0.0.0.0 refreshed.test\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: refresh", "cannot start the HTTP mock")
		return
	}
	stopped := false
	defer if !stopped {
		http_mock_stop(http)
	}

	upstream_port := next_port(r)
	mock := mock_make("lists-refresh", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "lists: refresh", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

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
  cache_dir: /proc/elodin-cannot-write-here
  refresh: 1s
  lists:
    - {{ name: hosts-list, url: "http://127.0.0.1:%d/hosts.txt", format: hosts }}
`,
		udp_port,
		upstream_port,
		http_port,
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if !ok {
		skip_case(r, "lists: refresh", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "lists: a refresh that cannot load a list keeps its rules")
	{
		// The premise: the list loaded, and nothing on disk can stand in for it.
		check_eq_int(r, http_mock_hits(http, "/hosts.txt"), 1, "fetches of the list at startup")
		check(r, log_contains(&srv, "is not writable"), "the cache directory was writable")
		http_mock_stop(http)
		stopped = true

		if check(r, wait_for_log(&srv, "download failed", 45 * time.Second), "no refresh ran") {
			check(r, wait_for_log(&srv, "trying again in", 5 * time.Second), "the failed refresh was not retried early")
			check(r, log_contains(&srv, "keeping the rules already in effect"), "the refresh did not keep the rules")
			res := query_udp(udp_port, build_query("refreshed.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h := parse_header(r, res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list's rules were lost in the refresh")
			}
		}
	}
	end_case(r)
}

/*
A download that succeeds and is not a list: a captive portal's page or a
mirror's error page served as a 200, or an empty file mid-publish (#317). None
may be written over the cached copy: the list would go out of effect and the
copy every later fallback reads with it. The page carries a line that parses as
a hosts rule, so it is refused for being a page rather than for holding no
rules. Each start here comes after the 1s refresh window, so each one downloads
again, under the same list name and so the same cached copy.
*/
run_list_bad_download_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/good.txt", "0.0.0.0 cached.test\n")
	http_mock_serve(http, "/portal.html", "\n<!DOCTYPE html>\n<html><body>Sign in to continue.\n0.0.0.0 portal.example\n</body></html>\n")
	http_mock_serve(http, "/empty.txt", "")
	http_mock_serve(http, "/busy.txt", "429 Too Many Requests\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: bad download", "cannot start the HTTP mock")
		return
	}
	defer http_mock_stop(http)

	upstream_port := next_port(r)
	mock := mock_make("lists-bad", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "lists: bad download", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	cache_dir := filepath.join({r.work_dir, "badlistcache"}, context.allocator) or_else ""
	defer delete(cache_dir)
	cached := filepath.join({cache_dir, "the-list.list"}, context.allocator) or_else ""
	defer delete(cached)

	Step :: struct {
		name: string,
		path: string,
	}
	steps := []Step {
		{"lists: a good download is cached", "/good.txt"},
		{"lists: a web page served as a list keeps the cached copy", "/portal.html"},
		{"lists: an empty download keeps the cached copy", "/empty.txt"},
		{"lists: a plain-text error page keeps the cached copy", "/busy.txt"},
	}
	for step, i in steps {
		start_case(r, step.name)
		if i > 0 {
			// Past the refresh window, so this start downloads again.
			time.sleep(1100 * time.Millisecond)
		}
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
  refresh: 1s
  lists:
    - {{ name: the-list, url: "http://127.0.0.1:%d%s", format: hosts }}
`,
			udp_port,
			upstream_port,
			cache_dir,
			http_port,
			step.path,
		)
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
		if check(r, ok, "the server did not start") {
			// The premise: this start downloaded the body under test.
			check_eq_int(r, http_mock_hits(http, step.path), 1, "downloads of the body under test")
			res := query_udp(udp_port, build_query("cached.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no response") {
				h := parse_header(r, res.wire)
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list went out of effect")
			}
			if i > 0 {
				check(r, log_contains(&srv, "using the cached copy"), "the cached copy did not stand in")
			}
			stop_server(&srv)
		}
		data, rerr := os.read_entire_file(cached, context.temp_allocator)
		check(r, rerr == nil && string(data) == "0.0.0.0 cached.test\n", "the cached copy was overwritten: %q", string(data))
		end_case(r)
	}
}

/*
A list host that moves its list answers with a relative Location (RFC 9110
10.2.2), which the fetcher resolves against the url it asked for (RFC 3986 5.2)
and follows (#460). The query is part of what is asked for at each hop.
*/
run_list_redirect_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_redirect(http, "/old/hosts.txt?v=1", "../new/hosts.txt?v=2")
	http_mock_serve(http, "/new/hosts.txt?v=2", "0.0.0.0 moved.test\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: relative redirect", "cannot start the HTTP mock")
		return
	}
	defer http_mock_stop(http)

	upstream_port := next_port(r)
	mock := mock_make("lists-redirect", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "lists: relative redirect", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	cache_dir := filepath.join({r.work_dir, "redirectcache"}, context.allocator) or_else ""
	defer delete(cache_dir)

	start_case(r, "lists: a relative redirect is followed, query and all")
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
    - {{ name: moved-list, url: "http://127.0.0.1:%d/old/hosts.txt?v=1", format: hosts }}
`,
		udp_port,
		upstream_port,
		cache_dir,
		http_port,
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if check(r, ok, "the server did not start") {
		check_eq_int(r, http_mock_hits(http, "/old/hosts.txt?v=1"), 1, "requests for the list url, query and all")
		check_eq_int(r, http_mock_hits(http, "/new/hosts.txt?v=2"), 1, "requests for where it moved")
		res := query_udp(udp_port, build_query("moved.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no response") {
			h := parse_header(r, res.wire)
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the moved list was not loaded")
		}
		stop_server(&srv)
	}
	end_case(r)
}
