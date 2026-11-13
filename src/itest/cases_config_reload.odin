package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
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
config_reload_text :: proc(
	udp_port, upstream_port: int,
	extra: string,
	log := "{ level: debug, queries: true }",
	rate_limit := false,
) -> string {
	return base_config(
		udp_port,
		upstream_at(upstream_port),
		log = log,
		upstream_extra = "  attempts: 1",
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, udp_port),
		cache = "{ enabled: true }",
		extra = fmt.tprintf("server:\n  rate_limit: {{ enabled: %v }}\n%s", rate_limit, extra),
	)
}

// The first address of a reply, or what stood in its way, for `check_eq_str`.
@(private = "file")
reply_address :: proc(r: ^Runner, res: Query_Result) -> string {
	if !res.ok {
		return "(no reply)"
	}
	if addr := first_address(r, res.wire); addr != "" {
		return addr
	}
	return "(no address)"
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
		return
	}
	defer stop_server(&srv)

	REWRITE :: "rewrites:\n  - { domain: rw.reload.test, answer: 198.51.100.7 }\n"

	start_case(r, "config reload: a rewrite edit applies without a restart, and the cache it left alone keeps its answers")
	{
		got := reply_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A))))
		check_eq_str(r, got, "192.0.2.1", "the first answer")
		asked := mock_total(a)
		if check(r, reload_to(r, &srv, config_reload_text(udp_port, a_port, REWRITE), "msg=reloaded"), "the reload was never logged") {
			check_eq_str(r, reply_address(r, query_udp(udp_port, build_query("rw.reload.test.", u16(dns.Type.A)))), "198.51.100.7", "the new rewrite")
			check_eq_str(r, reply_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A)))), "192.0.2.1", "the cached answer")
			check_eq_int(r, mock_total(a), asked, "upstream queries after the reload")
			check(r, log_contains(&srv, "changed=rewrites rebuilt=none cache=kept"), "the reload line does not say what it did")
		}
	}
	end_case(r)

	start_case(r, "config reload: a connection held across a reload is answered under the new configuration")
	{
		conn, dialled := dial_tcp(udp_port)
		if check(r, dialled, "cannot connect over tcp") {
			defer net.close(conn.socket)
			before := stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator)
			check_eq_str(r, reply_address(r, before), "198.51.100.7", "the rewrite before the reload")
			moved := strings.concatenate({config_reload_text(udp_port, a_port, ""), "rewrites:\n  - { domain: rw.reload.test, answer: 198.51.100.8 }\n"}, context.temp_allocator)
			if check(r, reload_to(r, &srv, moved, "msg=reloaded"), "the reload was never logged") {
				after := stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator)
				check_eq_str(r, reply_address(r, after), "198.51.100.8", "the rewrite after the reload, on the same connection")
			}
		}
	}
	end_case(r)

	// The accept loop checks `server.allow_from` once, so a reload that narrows
	// it has to reach the connections already open as well.
	start_case(r, "config reload: a connection held across a reload that drops its network from allow_from is refused")
	{
		conn, dialled := dial_tcp(udp_port)
		if check(r, dialled, "cannot connect over tcp") {
			defer net.close(conn.socket)
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
			check_eq_str(r, reply_address(r, query_udp(udp_port, build_query("cached.reload.test.", u16(dns.Type.A)))), "192.0.2.2", "the answer after the upstream changed")
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
		got := reply_address(r, query_udp(udp_port, build_query("inside.reload.test.", u16(dns.Type.A))))
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
		path := config_path(r, udp_port)
		before := log_count(&srv, "keeping the configuration already in effect")
		if check(r, os.write_entire_file(path, transmute([]u8)string("upstream: { servers: [\n")) == nil, "cannot break the file") &&
		   check(r, signal_reload(&srv), "could not deliver SIGHUP") &&
		   check(r, wait_for_log_count(&srv, "keeping the configuration already in effect", before + 1, 5 * time.Second), "the refusal was never logged") {
			check_eq_str(r, reply_address(r, query_udp(udp_port, build_query("rw.reload.test.", u16(dns.Type.A)))), "198.51.100.7", "the rewrite in effect")
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

	/*
	A reload that shortens `client_timeout` reaches a connection already open: its
	next idle wait is the new one (#594). The wait that was parked when the signal came keeps
	the figure it was armed with, so a query after the reload starts the next one.
	One second against the default ten, read with a five-second wait: a close is
	the new figure, a timeout here the old one. Last on this server: a case after it
	holding a connection across its own reload would be cut by the one-second wait,
	and a refusal it expects would pass for that reason.
	*/
	start_case(r, "config reload: a shorter client_timeout reaches a connection held across the reload")
	{
		conn, dialled := dial_tcp(udp_port)
		if check(r, dialled, "cannot connect over tcp") {
			defer net.close(conn.socket)
			check(r, stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator).ok, "no answer before the reload")
			shorter := config_reload_text(udp_port, a_port, "  client_timeout: 1s\n")
			if check(r, reload_to(r, &srv, shorter, "msg=reloaded"), "the reload was never logged") {
				check(r, stream_query(&conn, build_query("rw.reload.test.", u16(dns.Type.A)), context.temp_allocator).ok, "no answer after the reload")
				_ = net.set_option(conn.socket, .Receive_Timeout, 5 * time.Second)
				buf: [1]u8
				n, rerr := net.recv_tcp(conn.socket, buf[:])
				check(r, n == 0 && rerr == nil, "the idle connection was not closed on the new client_timeout (read %d, %v)", n, rerr)
			}
		}
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
	config := config_reload_text(udp_port, upstream_port, "", log = fmt.tprintf("{{ level: info, file: %q }}", log_file))
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	// Owner-only, both as the server created it and as the reload did: with
	// `log.queries` on it names every client.
	start_case(r, "log: the file is created readable by its owner only")
	check_log_mode(r, log_file)
	end_case(r)

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
			if reopened {
				check_log_mode(r, log_file)
			}
		}
	}
	end_case(r)
}

@(private = "file")
check_log_mode :: proc(r: ^Runner, path: string) {
	st: posix.stat_t
	if check(r, posix.stat(strings.clone_to_cstring(path, context.temp_allocator), &st) == .OK, "cannot stat the log file") {
		mode := transmute(u32)st.st_mode & 0o777
		check(r, mode == 0o600, "the log file is %o, want 600", mode)
	}
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
		return config_reload_text(udp_port, upstream_port, fmt.tprintf("cookies: {{ enabled: %v }}\n", cookies), rate_limit = true)
	}
	srv, ok := start_server(r, Server_Options{config = text(udp_port, upstream_port, false), udp_port = udp_port})
	if !ok {
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
