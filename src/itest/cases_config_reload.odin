package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "elodin:dns"

/*
SIGHUP reloads the configuration file, end to end (issue #216).

Two synthesising upstreams that answer every name with different addresses are
the probe: which address comes back says which upstream was asked, and the
mocks' query counts say whether it was asked at all or answered from the cache.
Every case reloads the one running server by rewriting the file it was started
with and sending the signal an operator's `systemctl reload` sends.
*/

@(private = "file")
config_reload_text :: proc(udp_port, upstream_port: int, extra: string) -> string {
	return fmt.tprintf(
		`log: {{ level: debug, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 2s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: true }}
blocking: {{ enabled: false }}
server:
  rate_limit: {{ enabled: false }}
%s`,
		udp_port,
		udp_port,
		upstream_port,
		extra,
	)
}

/*
Rewrite the server's file, send SIGHUP, and wait for `needle` to be logged once
more than it was: the line that says this reload, rather than an earlier one,
is over.
*/
@(private)
reload_to :: proc(r: ^Runner, srv: ^Server, config: string, needle: string, timeout := 5 * time.Second) -> bool {
	path := filepath.join({r.work_dir, fmt.tprintf("elodin-%d.yaml", srv.udp_port)}, context.temp_allocator) or_else ""
	before := log_count(srv, needle)
	written := without_dnssec(config)
	if os.write_entire_file(path, transmute([]u8)written) != nil {
		return false
	}
	return signal_reload(srv) && wait_for_log_count(srv, needle, before + 1, timeout)
}

@(private = "file")
first_address :: proc(r: ^Runner, res: Query_Result) -> string {
	if !res.ok {
		return "(no reply)"
	}
	addrs := answer_addresses(r, res.wire)
	if len(addrs) == 0 {
		return "(no address)"
	}
	return addrs[0]
}

run_config_reload_cases :: proc(r: ^Runner) {
	a_port := next_port(r)
	b_port := next_port(r)
	a := mock_make("reload-a", a_port)
	b := mock_make("reload-b", b_port)
	mock_synth(a, "inside.reload.test.", u16(dns.Type.A), {10, 0, 0, 1}, ttl = 300)
	mock_synth_all(a, {192, 0, 2, 1}, ttl = 300)
	mock_synth(b, "inside.reload.test.", u16(dns.Type.A), {10, 0, 0, 2}, ttl = 300)
	mock_synth_all(b, {192, 0, 2, 2}, ttl = 300)
	// Both are stopped, started or not: the first may have started when the
	// second did not.
	a_ok, b_ok := mock_start(a), mock_start(b)
	defer mock_stop(a)
	defer mock_stop(b)
	if !a_ok || !b_ok {
		skip_case(r, "config reload", "cannot start the mocks")
		return
	}

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_reload_text(udp_port, a_port, ""), udp_port = udp_port})
	if !ok {
		skip_case(r, "config reload", "server did not start")
		return
	}
	defer stop_server(&srv)

	REWRITE :: "rewrites:\n  - { domain: rw.reload.test, answer: 198.51.100.7 }\n"

	start_case(r, "config reload: a rewrite edit applies without a restart, and the cache it left alone keeps its answers")
	{
		got := first_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A))))
		check_eq_str(r, got, "192.0.2.1", "the first answer")
		asked := mock_total(a)
		if check(r, reload_to(r, &srv, config_reload_text(udp_port, a_port, REWRITE), "msg=reloaded"), "the reload was never logged") {
			check_eq_str(r, first_address(r, query_udp(udp_port, build_query("rw.reload.test.", u16(dns.Type.A)))), "198.51.100.7", "the new rewrite")
			check_eq_str(r, first_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A)))), "192.0.2.1", "the cached answer")
			check_eq_int(r, mock_total(a), asked, "upstream queries after the reload")
			check(r, log_contains(&srv, "changed=rewrites rebuilt=none cache=kept"), "the reload line does not say what it did")
		}
	}
	end_case(r)

	start_case(r, "config reload: a connection held across a reload is answered under the new configuration")
	{
		socket, derr := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = udp_port})
		if check(r, derr == nil, "cannot connect over tcp") {
			defer net.close(socket)
			_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
			_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)
			conn := Test_Conn {
				socket = socket,
			}
			before := stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator)
			check_eq_str(r, first_address(r, before), "198.51.100.7", "the rewrite before the reload")
			moved := strings.concatenate({config_reload_text(udp_port, a_port, ""), "rewrites:\n  - { domain: rw.reload.test, answer: 198.51.100.8 }\n"}, context.temp_allocator)
			if check(r, reload_to(r, &srv, moved, "msg=reloaded"), "the reload was never logged") {
				after := stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator)
				check_eq_str(r, first_address(r, after), "198.51.100.8", "the rewrite after the reload, on the same connection")
			}
		}
	}
	end_case(r)

	// The accept loop checks `server.allow_from` once, so a reload that narrows
	// it has to reach the connections already open as well.
	start_case(r, "config reload: a connection held across a reload that drops its network from allow_from is refused")
	{
		socket, derr := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = udp_port})
		if check(r, derr == nil, "cannot connect over tcp") {
			defer net.close(socket)
			_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
			_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)
			conn := Test_Conn {
				socket = socket,
			}
			check(r, stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator).ok, "no answer before the reload")
			narrowed := config_reload_text(udp_port, a_port, "  allow_from: [\"192.0.2.0/24\"]\n")
			if check(r, reload_to(r, &srv, narrowed, "msg=reloaded"), "the reload was never logged") {
				after := stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator)
				check(r, !after.ok, "a source allow_from no longer admits was answered on its held connection")
			}
		}
	}
	end_case(r)

	start_case(r, "config reload: a changed upstream is asked from then on, and its predecessor's cached answers are not served")
	{
		if check(r, reload_to(r, &srv, config_reload_text(udp_port, b_port, REWRITE), "msg=reloaded"), "the reload was never logged") {
			check_eq_str(r, first_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A)))), "192.0.2.2", "the answer after the upstream changed")
			check(r, log_contains(&srv, "rebuilt=upstreams cache=flushed"), "the reload line does not say the cache was flushed")
		}
	}
	end_case(r)

	/*
	The safety case the issue singles out: rebind protection runs before an
	answer is cached, not when it is served, so a reload that turns it on has to
	keep a private address cached under the old rules from being served under
	the new ones.
	*/
	start_case(r, "config reload: turning rebind protection on covers names already in the cache")
	{
		got := first_address(r, query_udp(udp_port, build_query("inside.reload.test.", u16(dns.Type.A))))
		check_eq_str(r, got, "10.0.0.2", "the private answer while the guard is off")
		guarded := strings.concatenate({config_reload_text(udp_port, b_port, REWRITE), "rebind: { enabled: true }\n"}, context.temp_allocator)
		if check(r, reload_to(r, &srv, guarded, "msg=reloaded"), "the reload was never logged") {
			res := query_udp(udp_port, build_query("inside.reload.test.", u16(dns.Type.A)))
			if check(r, res.ok, "no reply") {
				check_eq_int(r, len(answer_addresses(r, res.wire)), 0, "addresses served once the guard is on")
			}
		}
	}
	end_case(r)

	start_case(r, "config reload: a file that does not load leaves the running configuration serving")
	{
		path := filepath.join({r.work_dir, fmt.tprintf("elodin-%d.yaml", udp_port)}, context.temp_allocator) or_else ""
		before := log_count(&srv, "keeping the configuration already in effect")
		if check(r, os.write_entire_file(path, transmute([]u8)string("upstream: { servers: [\n")) == nil, "cannot break the file") &&
		   check(r, signal_reload(&srv), "could not deliver SIGHUP") &&
		   check(r, wait_for_log_count(&srv, "keeping the configuration already in effect", before + 1, 5 * time.Second), "the refusal was never logged") {
			check_eq_str(r, first_address(r, query_udp(udp_port, build_query("rw.reload.test.", u16(dns.Type.A)))), "198.51.100.7", "the rewrite in effect")
		}
	}
	end_case(r)

	start_case(r, "config reload: a listener change is named and the listener keeps its port")
	{
		moved, _ := strings.replace_all(config_reload_text(udp_port, b_port, REWRITE), fmt.tprintf("port: %d }", udp_port), fmt.tprintf("port: %d }", udp_port + 1000), context.temp_allocator)
		if check(r, reload_to(r, &srv, moved, "listeners.udp changed, which takes a restart"), "the restart-only key was not named") {
			check(r, query_udp(udp_port, build_query("rw.reload.test.", u16(dns.Type.A))).ok, "the listener stopped answering on its port")
		}
	}
	end_case(r)

	start_case(r, "config reload: queries are answered through a burst of reloads")
	{
		Querier :: struct {
			port:     int,
			stop:     bool,
			sent:     int,
			answered: int,
		}
		q := Querier {
			port = udp_port,
		}
		run :: proc(q: ^Querier) {
			for i := 0; !sync.atomic_load(&q.stop); i += 1 {
				// A cached name and a fresh one in turn, so both the cache and the
				// upstream groups are being read while they are swapped.
				name := "cached.reload.test." if i % 2 == 0 else fmt.tprintf("n%d.burst.reload.test.", i)
				q.sent += 1
				if query_udp(q.port, build_query(name, u16(dns.Type.A)), context.temp_allocator).ok {
					q.answered += 1
				}
				free_all(context.temp_allocator)
			}
		}
		querier := thread.create_and_start_with_poly_data(&q, run)
		reloads := 0
		for i in 0 ..< 16 {
			upstream := a_port if i % 2 == 0 else b_port
			extra := "rebind: { enabled: true }\n" if i % 4 < 2 else ""
			if !reload_to(r, &srv, config_reload_text(udp_port, upstream, extra), "msg=reloaded") {
				break
			}
			reloads += 1
		}
		sync.atomic_store(&q.stop, true)
		thread.join(querier)
		thread.destroy(querier)
		check_eq_int(r, reloads, 16, "reloads that completed")
		check(r, q.sent > 0, "nothing was asked during the reloads")
		check_eq_int(r, q.answered, q.sent, "queries answered while reloading")
		check(r, query_udp(udp_port, build_query("after.burst.reload.test.", u16(dns.Type.A))).ok, "the server stopped answering")
	}
	end_case(r)

	run_log_reopen_case(r, a_port)
	run_cookie_limit_reload_case(r, a_port)
}

/*
The log is opened again by name on every SIGHUP, which is what logrotate's
default `create` arrangement relies on: it renames the file and sends the
signal, and a server that kept writing to the renamed one would fill a file
nobody reads while the new one stays empty.
*/
@(private = "file")
run_log_reopen_case :: proc(r: ^Runner, upstream_port: int) {
	udp_port := next_port(r)
	log_file := fmt.aprintf("%s/reload-%d.log", r.work_dir, udp_port)
	defer delete(log_file)
	config := strings.concatenate(
		{config_reload_text(udp_port, upstream_port, ""), fmt.tprintf("log: {{ level: info, file: %q }}\n", log_file)},
		context.temp_allocator,
	)
	// The `log:` above is the second one in the file; keep only the last.
	config, _ = strings.replace(config, "log: { level: debug, queries: true }\n", "", 1, context.temp_allocator)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "config reload: the log is reopened", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "config reload: SIGHUP opens the log file again after it was rotated away")
	{
		rotated := strings.concatenate({log_file, ".1"}, context.temp_allocator)
		if check(r, os.rename(log_file, rotated) == nil, "cannot rotate the log") && check(r, signal_reload(&srv), "could not deliver SIGHUP") {
			deadline := time.time_add(time.now(), 5 * time.Second)
			reopened := false
			for !reopened && time.diff(deadline, time.now()) < 0 {
				data, err := os.read_entire_file(log_file, context.temp_allocator)
				reopened = err == nil && strings.contains(string(data), "SIGHUP received")
				if !reopened {
					time.sleep(20 * time.Millisecond)
				}
			}
			check(r, reopened, "nothing was written to the log file's name after the rotation")
		}
	}
	end_case(r)
}

/*
The startup line names the cookie rescue pool only with cookies on, so a reload
that turns them on says it again, though the limiter itself is kept and no
budget is refilled.
*/
@(private = "file")
run_cookie_limit_reload_case :: proc(r: ^Runner, upstream_port: int) {
	udp_port := next_port(r)
	text :: proc(udp_port, upstream_port: int, cookies: bool) -> string {
		base, _ := strings.replace(
			config_reload_text(udp_port, upstream_port, fmt.tprintf("cookies: {{ enabled: %v }}\n", cookies)),
			"rate_limit: { enabled: false }",
			"rate_limit: { enabled: true }",
			1,
			context.temp_allocator,
		)
		return base
	}
	srv, ok := start_server(r, Server_Options{config = text(udp_port, upstream_port, false), udp_port = udp_port})
	if !ok {
		skip_case(r, "config reload: the rate limit line follows cookies", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "config reload: turning cookies on names the rescue pool in the rate limit line")
	{
		RESCUE :: "for datagrams a server cookie rescues"
		check(r, !log_contains(&srv, RESCUE), "the rescue pool was named with cookies off")
		check(
			r,
			reload_to(r, &srv, text(udp_port, upstream_port, true), RESCUE),
			"a reload that turned cookies on left the rate limit line as it was",
		)
	}
	end_case(r)
}
