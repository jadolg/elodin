package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "elodin:dns"

/*
Downloading sink lists and caching them on disk.

Every other case runs with --no-fetch, which skips this path entirely. These
cases use more than one list, so a cache-path mistake that only shows on the
*second* list is caught.
*/

run_list_download_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(
		http,
		"/hosts.txt",
		"# a hosts list\n127.0.0.1 localhost\n0.0.0.0 downloaded.test\n0.0.0.0 second.downloaded.test\n",
	)
	http_mock_serve(http, "/abp.txt", "[Adblock Plus 2.0]\n||fetched.test^\n@@||ok.fetched.test^\n||b\u00fccher.test^\n")
	// No format given, and a comment that mentions adblock syntax (#322).
	http_mock_serve(http, "/auto.txt", "# not adblock: no ||rule^ here\n0.0.0.0 sniffed.test # nor ||here^\n0.0.0.0 second.sniffed.test ! nor ||here^\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: download", "cannot start the HTTP mock")
		return
	}
	defer http_mock_stop(http)

	mock, upstream_port, mock_ok := synth_mock(r, "lists", "lists: download", {203, 0, 113, 9})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	cache_dir := filepath.join({r.work_dir, "listcache"}, context.allocator) or_else ""
	defer delete(cache_dir)

	udp_port := next_port(r)
	config := config_lists(
		udp_port,
		upstream_port,
		{list_entry("hosts-list", http_port, "/hosts.txt"), list_entry("abp-list", http_port, "/abp.txt", "adblock"), list_entry("auto-list", http_port, "/auto.txt", "")},
		cache_dir = cache_dir,
		refresh = "24h",
	)

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}

	start_case(r, "lists: two lists are downloaded and both take effect")
	{
		// Reaching this at all means the fetch-and-cache path did not corrupt
		// the heap on the way through the second list.
		check_eq_int(r, http_mock_hits(http, "/hosts.txt"), 1, "fetches of the hosts list")
		check_eq_int(r, http_mock_hits(http, "/abp.txt"), 1, "fetches of the adblock list")

		if _, h, asked := ask(r, udp_port, "downloaded.test.", u16(dns.Type.A), "no response for a name from the first list"); asked {
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

	start_case(r, "lists: a name written in UTF-8 is skipped with a warning naming its list")
	{
		check(r, log_contains(&srv, "list abp-list: 1 names skipped as not ASCII"), "the UTF-8 entry was dropped without a word:\n%s", read_log(&srv))
		warned := log_count(&srv, "names skipped as not ASCII")
		check(r, warned == 1, "%d lists were warned of, but only abp-list holds a UTF-8 name", warned)
	}
	end_case(r)

	start_case(r, "lists: a comment that mentions adblock syntax leaves a hosts list a hosts list")
	{
		if _, h, asked := ask(r, udp_port, "sniffed.test.", u16(dns.Type.A), "no response for a name from the auto-detected list"); asked {
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the hosts list was read as adblock and blocked nothing")
		}
		check(r, log_contains(&srv, "list auto-list: 2 rules"), "the auto-detected list did not count its two entries")
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
		config2 := config_lists(
			port2,
			upstream_port,
			{list_entry("hosts-list", http_port, "/hosts.txt"), list_entry("abp-list", http_port, "/abp.txt", "adblock")},
			cache_dir = cache_dir,
			refresh = "24h",
		)
		srv2, ok2 := start_server(r, Server_Options{config = config2, udp_port = port2, allow_fetch = true})
		if ok2 {
			defer stop_server(&srv2)
			check_eq_int(r, http_mock_hits(http, "/hosts.txt"), 1, "fetches after a restart")
			if _, h, asked := ask(r, port2, "downloaded.test.", u16(dns.Type.A)); asked {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the cached list was not applied")
			}
			check(r, log_contains(&srv2, "using the cached copy"), "the cache was not reported as used")
		}
	}
	end_case(r)

	start_case(r, "lists: an unwritable cache directory is a warning, not a failure")
	{
		port3 := next_port(r)
		config3 := config_lists(
			port3,
			upstream_port,
			{list_entry("hosts-list", http_port, "/hosts.txt"), list_entry("abp-list", http_port, "/abp.txt", "adblock")},
			refresh = "24h",
		)
		srv3, ok3 := start_server(r, Server_Options{config = config3, udp_port = port3, allow_fetch = true})
		if ok3 {
			defer stop_server(&srv3)
			if _, h, asked := ask(r, port3, "downloaded.test.", u16(dns.Type.A)); asked {
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

	mock, upstream_port, mock_ok := synth_mock(r, "lists-refresh", "lists: refresh", {203, 0, 113, 9})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := config_lists(udp_port, upstream_port, {list_entry("hosts-list", http_port, "/hosts.txt")})

	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if !ok {
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
			if _, h, asked := ask(r, udp_port, "refreshed.test.", u16(dns.Type.A)); asked {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list's rules were lost in the refresh")
			}
		}
	}
	end_case(r)
}

/*
A blocking configuration over `lists`, each a `list_entry`, with an upstream at
`upstream_port` and the cache off. The default `cache_dir` cannot be written, so
a case that wants the cached copy names one of its own.
*/
@(private = "file")
config_lists :: proc(
	udp_port, upstream_port: int,
	lists: []string,
	cache_dir := "/proc/elodin-cannot-write-here",
	refresh := "1s",
	log := "{ level: debug }",
	extra := "",
) -> string {
	return base_config(
		udp_port,
		upstream_at(upstream_port),
		log = log,
		timeout = "3s",
		blocking = fmt.tprintf(
			"{{ enabled: true, response: nxdomain, cache_dir: %q, refresh: %s, lists: [%s] }}",
			cache_dir,
			refresh,
			strings.join(lists, ", ", context.temp_allocator),
		),
		extra = extra,
	)
}

// One `blocking.lists` entry, fetched from the HTTP mock at `path`; an empty
// `format` leaves it to be sniffed.
@(private = "file")
list_entry :: proc(name: string, http_port: int, path: string, format := "hosts") -> string {
	entry := fmt.tprintf(`{{ name: %s, url: "http://127.0.0.1:%d%s"`, name, http_port, path)
	return fmt.tprintf("%s, format: %s }}", entry, format) if format != "" else fmt.tprintf("%s }}", entry)
}

// The signal cases: one list on the HTTP mock, the shipped log level.
@(private = "file")
config_for_refresh_signals :: proc(udp_port, upstream_port, http_port: int, extra_lists: []string = nil, extra := "") -> string {
	lists := make([dynamic]string, context.temp_allocator)
	append(&lists, list_entry("hosts-list", http_port, "/hosts.txt"))
	append(&lists, ..extra_lists)
	return config_lists(udp_port, upstream_port, lists[:], log = "{ level: info }", extra = extra)
}

@(private = "file")
listen_silent :: proc(r: ^Runner, port: int) -> (net.TCP_Socket, bool) {
	sock, err := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
	return sock, check(r, err == nil, "cannot listen on port %d: %v", port, err)
}

/*
Wait until the server's download has reached a silent host.

The kernel completes the handshake and queues the connection, which nothing
accepts, so a queued connection is the download parked on a reply that never
comes. `tcpi_unacked` in a listening socket's TCP_INFO is that queue's depth;
it sits 24 bytes in, behind eight one-byte fields and four u32s.
*/
@(private = "file")
wait_parked :: proc(sock: net.TCP_Socket, timeout: time.Duration) -> bool {
	start := time.tick_now()
	for time.tick_since(start) < timeout {
		info: [104]u8
		size := posix.socklen_t(len(info))
		if posix.getsockopt(posix.FD(sock), posix.IPPROTO_TCP, posix.Sock_Option(TCP_INFO), &info, &size) == .OK && size >= 28 {
			if (^u32le)(&info[24])^ > 0 {
				return true
			}
		}
		time.sleep(PROBE_RETRY_PAUSE)
	}
	return false
}

@(private = "file")
TCP_INFO :: 11

/*
Signals while a list download waits on a host that has stopped answering (#416).

The rule sets are rebuilt off the maintenance loop, so a SIGHUP is acted on and a
SIGTERM ends the process while a download waits, rather than once `FETCH_TIMEOUT`
has run out for each read; and the signal does not cut the download short as a
failed one, as it would on a thread that took it. A silent host is a socket that
listens and never accepts: the kernel completes the handshake, and nothing is
sent. Closing it resets the connection, which ends the download at once.
*/
run_list_refresh_signal_cases :: proc(r: ^Runner) {
	mock, upstream_port, mock_ok := synth_mock(r, "lists-refresh-signals", "lists: signals during a download", {203, 0, 113, 9})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	start_case(r, "lists: SIGTERM is not held by the download at startup")
	{
		silent_port := next_port(r)
		udp_port := next_port(r)
		silent, listening := listen_silent(r, silent_port)
		if listening {
			defer net.close(silent)
			config := config_for_refresh_signals(udp_port, upstream_port, silent_port)
			if srv, ok := start_server_raw(r, config, udp_port, true); ok {
				defer stop_server(&srv)
				if check(r, wait_for_log(&srv, "list hosts-list: downloading", 5 * time.Second), "no download started") &&
				   check(r, wait_parked(silent, 5 * time.Second), "the download never reached the silent host") {
					state, exited := signal_shutdown(&srv, 5 * time.Second)
					if check(r, exited, "the server did not exit within 5s of SIGTERM during the startup download") {
						check(r, state.success && state.exit_code == 0, "exited with code %d (success=%v)", state.exit_code, state.success)
						check(r, !log_contains(&srv, "download failed"), "the stop waited for the download to fail")
					}
				}
			}
		}
	}
	end_case(r)

	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/hosts.txt", "0.0.0.0 refreshed.test\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: signals during a refresh", "cannot start the HTTP mock")
		return
	}
	stopped := false
	defer if !stopped {
		http_mock_stop(http)
	}
	udp_port := next_port(r)
	stalled_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = config_for_refresh_signals(udp_port, upstream_port, http_port), udp_port = udp_port, allow_fetch = true},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	start_case(r, "lists: SIGHUP and SIGTERM are not held by a refresh, nor cut it short")
	{
		http_mock_stop(http)
		stopped = true
		silent, listening := listen_silent(r, http_port)
		stalled, stalling := listen_silent(r, stalled_port)
		defer if stalling {
			net.close(stalled)
		}
		// Closed below to end the refresh; here when the premise fails first.
		defer if listening {
			net.close(silent)
		}
		// The premise: a refresh has started its download and is waiting on it.
		if listening && stalling && check(r, wait_for_log_count(&srv, "list hosts-list: downloading", 2, 45 * time.Second), "no refresh ran") &&
		   check(r, wait_parked(silent, 5 * time.Second), "the refresh never reached the silent host") {
			check(r, !log_contains(&srv, "download failed"), "the download did not wait")

			// A list added by the reload, from a host that stays silent.
			added := config_for_refresh_signals(
				udp_port,
				upstream_port,
				http_port,
				{list_entry("stalled-list", stalled_port, "/hosts.txt")},
				"rewrites:\n  - { domain: during.test, answer: 192.0.2.7 }",
			)
			// Applied at once, its rule change left for after the refresh.
			check(
				r,
				reload_to(r, &srv, added, "changed=blocking,rewrites", 3 * time.Second),
				"the reload waited for the refresh",
			)
			// Logged after the `reloaded` line, so waited for rather than read at once.
			check(r, wait_for_log(&srv, "rebuilt once the rebuild in progress is over", 2 * time.Second), "the reload's rebuild did not wait for the refresh")
			check(r, !log_contains(&srv, "download failed"), "SIGHUP cut the download short")
			if res := query_udp(udp_port, build_query("during.test.", u16(dns.Type.A))); check(r, res.ok, "no response during the refresh") {
				check_one_address(r, res.wire, "192.0.2.7", "the reloaded rewrite during the refresh")
			}
			if _, h, asked := ask(r, udp_port, "refreshed.test.", u16(dns.Type.A), "no response during the refresh"); asked {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list's rules are not in effect during the refresh")
			}

			// The refresh fails, and the rebuild the reload asked for starts:
			// it waits on the added list.
			check(r, !log_contains(&srv, "list stalled-list: downloading"), "the reload's rebuild ran beside the refresh")
			net.close(silent)
			listening = false
			check(r, wait_for_log(&srv, "list stalled-list: downloading", 5 * time.Second), "the reload's rebuild did not download the added list")
			check(r, wait_parked(stalled, 5 * time.Second), "the rebuild's download never reached the silent host")

			state, exited := signal_shutdown(&srv, 5 * time.Second)
			if check(r, exited, "the server did not exit within 5s of SIGTERM during a rebuild") {
				check(r, state.success && state.exit_code == 0, "exited with code %d (success=%v)", state.exit_code, state.success)
				check(r, !log_contains(&srv, "list stalled-list: download failed"), "the stop waited for the download to fail")
				check(r, log_contains(&srv, "not waiting for the rebuild in progress"), "the stop did not say it left the rebuild")
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
rules. Each start here finds the cached copy aged past the 1s refresh window, so
each one downloads again, under the same list name and so the same cached copy.
*/
run_list_bad_download_cases :: proc(r: ^Runner) {
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/good.txt", "0.0.0.0 cached.test\n")
	http_mock_serve(http, "/portal.html", "\n<!DOCTYPE html>\n<html><body>Sign in to continue.\n0.0.0.0 portal.example\n</body></html>\n")
	http_mock_serve(http, "/empty.txt", "")
	http_mock_serve(http, "/busy.txt", "429 Too Many Requests\n")
	http_mock_serve(http, "/idn.txt", "0.0.0.0 b\u00fccher.test\n")
	if !http_mock_start(http) {
		skip_case(r, "lists: bad download", "cannot start the HTTP mock")
		return
	}
	defer http_mock_stop(http)

	mock, upstream_port, mock_ok := synth_mock(r, "lists-bad", "lists: bad download", {203, 0, 113, 9})
	if !mock_ok {
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
		// A line the start must log, when there is one.
		log:  string,
	}
	steps := []Step {
		{"lists: a good download is cached", "/good.txt", ""},
		{"lists: a web page served as a list keeps the cached copy", "/portal.html", ""},
		{"lists: an empty download keeps the cached copy", "/empty.txt", ""},
		{"lists: a plain-text error page keeps the cached copy", "/busy.txt", ""},
		{"lists: a download of only UTF-8 names keeps the cached copy and says why", "/idn.txt", "list the-list: 1 names skipped as not ASCII"},
	}
	for step, i in steps {
		start_case(r, step.name)
		if i > 0 {
			// Aged past the refresh window, so this start downloads again: the
			// window is read off the cached copy's mtime.
			aged := time.time_add(time.now(), -time.Hour)
			if err := os.change_times(cached, aged, aged); !check(r, err == nil, "cannot age the cached copy: %v", err) {
				end_case(r)
				continue
			}
		}
		udp_port := next_port(r)
		config := config_lists(udp_port, upstream_port, {list_entry("the-list", http_port, step.path)}, cache_dir = cache_dir)
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
		if ok {
			// The premise: this start downloaded the body under test.
			check_eq_int(r, http_mock_hits(http, step.path), 1, "downloads of the body under test")
			if _, h, asked := ask(r, udp_port, "cached.test.", u16(dns.Type.A)); asked {
				check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list went out of effect")
			}
			if i > 0 {
				check(r, log_contains(&srv, "using the cached copy"), "the cached copy did not stand in")
			}
			if step.log != "" {
				check(r, log_contains(&srv, step.log), "the log does not say %q:\n%s", step.log, read_log(&srv))
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

	mock, upstream_port, mock_ok := synth_mock(r, "lists-redirect", "lists: relative redirect", {203, 0, 113, 9})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	cache_dir := filepath.join({r.work_dir, "redirectcache"}, context.allocator) or_else ""
	defer delete(cache_dir)

	start_case(r, "lists: a relative redirect is followed, query and all")
	udp_port := next_port(r)
	config := config_lists(udp_port, upstream_port, {list_entry("moved-list", http_port, "/old/hosts.txt?v=1")}, cache_dir = cache_dir, refresh = "24h")
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if ok {
		check_eq_int(r, http_mock_hits(http, "/old/hosts.txt?v=1"), 1, "requests for the list url, query and all")
		check_eq_int(r, http_mock_hits(http, "/new/hosts.txt?v=2"), 1, "requests for where it moved")
		if _, h, asked := ask(r, udp_port, "moved.test.", u16(dns.Type.A)); asked {
			check(r, h.rcode == int(dns.Rcode.NX_Domain), "the moved list was not loaded")
		}
		stop_server(&srv)
	}
	end_case(r)
}
