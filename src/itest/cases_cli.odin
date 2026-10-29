package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "core:time"

/*
Command-line behaviour: the checks an operator relies on before a deploy.
*/

run_cli_cases :: proc(r: ^Runner) {
	start_case(r, "cli: --version prints the build")
	{
		res := run_binary(r, []string{"--version"}, "version")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.has_prefix(res.output, "elodin "), "unexpected output %q", res.output)
		}
	}
	end_case(r)

	start_case(r, "cli: --help prints usage")
	{
		res := run_binary(r, []string{"--help"}, "help")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.contains(res.output, "--config"), "usage does not mention --config")
		}
	}
	end_case(r)

	start_case(r, "cli: an unknown option fails with a message")
	{
		res := run_binary(r, []string{"--nonsense"}, "unknown")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "an unknown option exited 0")
			check(r, strings.contains(res.output, "unknown option"), "no explanation was printed")
		}
	}
	end_case(r)

	start_case(r, "cli: --check accepts a valid config")
	{
		path := filepath.join({r.work_dir, "valid.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nblocking:\n  rules: [\"||a.test^\"]\n"),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-ok")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			check(r, strings.contains(res.output, "is valid"), "no confirmation was printed")
		}
	}
	end_case(r)

	/*
	A rate-limit figure that is accepted, charges nothing, and says so here.

	`server.rate_limit.response_size_estimate` is bounded at load by the widest a
	figure of its kind can be on any configuration; what bounds it on a given one
	is that file's own `server.max_udp_response`. Everything between the two is
	accepted and unreachable - an operator who writes 2048 over the shipped 1232
	has tightened nothing and believes they have - and the startup line that says
	what the estimate comes to is written only when it can bite.

	So `--check` is where it is caught, which is before the file is serving
	anybody. The same sentence is written to the log at startup, from the same
	procedure; the integration case in `cases_ratelimit.odin` is that half.
	*/
	start_case(r, "cli: --check reports an estimate no answer can reach")
	{
		path := filepath.join({r.work_dir, "inert-estimate.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string(
				"upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: true\n    response_size_estimate: 2048\n",
			),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-inert-estimate")
		if check(r, res.ok, "could not run the binary") {
			// Valid, which is the point: it loads, and the warning is the only
			// thing that says the setting is doing nothing.
			check_eq_int(r, res.exit_code, 0, "exit code for an estimate above the ceiling")
			check(
				r,
				strings.contains(res.output, "above the 1232 server.max_udp_response allows"),
				"an estimate no answer can reach was not reported: %q",
				res.output,
			)
		}

		// And the estimate that does bite is multiplied out here, which is the
		// figure an operator is confirming before they restart: 500/s at 128
		// bytes is 64,000 bytes a second at one prefix.
		biting := filepath.join({r.work_dir, "biting-estimate.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			biting,
			transmute([]u8)string(
				"upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: true\n    responses_per_second: 500\n    response_size_estimate: 128\n",
			),
		)
		bres := run_binary(r, []string{"--config", biting, "--check"}, "check-biting-estimate")
		if check(r, bres.ok, "could not run the binary") {
			check_eq_int(r, bres.exit_code, 0, "exit code for an estimate under the ceiling")
			check(
				r,
				strings.contains(bres.output, "62.5KiB/s"),
				"the byte budget the two figures come to was not reported: %q",
				bres.output,
			)
		}

		// And the file that does not name one is not warned at: the loader
		// resolves an unset estimate to the ceiling itself.
		quiet := filepath.join({r.work_dir, "default-estimate.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(quiet, transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\n"))
		qres := run_binary(r, []string{"--config", quiet, "--check"}, "check-default-estimate")
		if check(r, qres.ok, "could not run the binary") {
			check(
				r,
				!strings.contains(qres.output, "response_size_estimate"),
				"a file that names no estimate was warned about one: %q",
				qres.output,
			)
		}
	}
	end_case(r)

	start_case(r, "cli: --check rejects a config with no upstreams")
	{
		path := filepath.join({r.work_dir, "no-upstream.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("log:\n  level: info\n"))
		res := run_binary(r, []string{"--config", path, "--check"}, "check-empty")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "an unusable config exited 0")
			check(r, strings.contains(res.output, "upstream"), "the error does not mention upstreams")
		}
	}
	end_case(r)

	// A zero timeout is not "no limit": every query would answer SERVFAIL at once
	// (#499). Refused at the top level and on a route.
	start_case(r, "cli: --check rejects an upstream timeout of zero")
	{
		path := filepath.join({r.work_dir, "zero-timeout.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string(
				"upstream:\n  timeout: 0s\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: 0ms\n      servers: [192.168.1.1]\n",
			),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-zero-timeout")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a zero upstream timeout exited 0")
			check(r, strings.contains(res.output, "upstream.timeout"), "the top-level timeout was not reported")
			check(r, strings.contains(res.output, "upstream.zones[0].timeout"), "the route's timeout was not reported")
		}
	}
	end_case(r)

	// The file from #316: each figure the server cannot honour is named, rather
	// than a port picked by the kernel and a TTL cast to 4294967295.
	start_case(r, "cli: --check rejects ports, TTLs and timeouts out of range")
	{
		path := filepath.join({r.work_dir, "out-of-range.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string(
				"listeners:\n  udp: {enabled: true, address: 127.0.0.1, port: 106837}\n  tcp: {enabled: true, address: 127.0.0.1, port: 0}\n" +
				"server:\n  client_timeout: 0s\nupstream:\n  timeout: 0s\n  servers:\n    - {name: none, type: udp, address: 127.0.0.1, port: 41302}\n" +
				"blocking:\n  enabled: false\nrewrites:\n  - domain: nas.home\n    answer: 192.168.1.50\n    ttl: -1\n",
			),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-out-of-range")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "an out-of-range config exited 0")
			for key in ([]string{"listeners.udp.port", "listeners.tcp.port", "server.client_timeout", "upstream.timeout", "rewrites[0].ttl"}) {
				check(r, strings.contains(res.output, key), "%s was not reported: %q", key, res.output)
			}
		}
	}
	end_case(r)

	start_case(r, "cli: --check reports every problem at once, with line numbers")
	{
		path := filepath.join({r.work_dir, "bad.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  strategy: teleport\n  servers: [1.1.1.1]\nblocking:\n  response: explode\n"),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "check-bad")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a bad config exited 0")
			check(r, strings.contains(res.output, "teleport"), "the unknown strategy was not reported")
			check(r, strings.contains(res.output, "explode"), "the unknown block mode was not reported")
		}
	}
	end_case(r)

	start_case(r, "cli: a missing config file is reported, not ignored")
	{
		res := run_binary(r, []string{"--config", "/nonexistent/elodin.yaml", "--check"}, "check-missing")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a missing config exited 0")
			check(r, strings.contains(res.output, "cannot read"), "the error does not say the file is unreadable")
		}
	}
	end_case(r)

	start_case(r, "cli: malformed YAML is reported with a line number")
	{
		path := filepath.join({r.work_dir, "malformed.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nthis is not a mapping\n"))
		res := new_check(r, path, "check-yaml")
		check(r, res.exit_code != 0, "malformed YAML exited 0")
		check(r, strings.contains(res.output, "line 3"), "the failing line was not identified: %q", res.output)
	}
	end_case(r)

	// YAML reads `*.lan` as an alias (1.2.2 section 7.3.3), so a file holding
	// it unquoted means something else to every other YAML reader.
	start_case(r, "cli: a plain value starting with a YAML indicator is refused")
	{
		path := filepath.join({r.work_dir, "indicator.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: *.lan\n    answer: 192.168.1.10\n"))
		res := new_check(r, path, "check-yaml-indicator")
		check(r, res.exit_code != 0, "an unquoted *.lan exited 0: %q", res.output)
		check(r, strings.contains(res.output, "line 4") && strings.contains(res.output, "quote"), "the line and the remedy were not given: %q", res.output)
	}
	end_case(r)

	start_case(r, "cli: a DoT listener without a certificate is refused")
	{
		path := filepath.join({r.work_dir, "nocert.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nlisteners:\n  dot:\n    enabled: true\n"),
		)
		res := new_check(r, path, "check-nocert")
		check(r, res.exit_code != 0, "a DoT listener with no certificate exited 0")
		check(r, strings.contains(res.output, "cert_file"), "the missing certificate was not reported")
	}
	end_case(r)

	start_case(r, "cli: --check rejects a service account nobody has")
	{
		path := filepath.join({r.work_dir, "baduser.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nserver:\n  user: elodin-no-such-user\n"),
		)
		res := new_check(r, path, "check-baduser")
		check(r, res.exit_code != 0, "an unknown server.user exited 0")
		check(r, strings.contains(res.output, "no such user"), "the unknown account was not reported: %q", res.output)
	}
	end_case(r)

	start_case(r, "cli: --check rejects a group with no user")
	{
		path := filepath.join({r.work_dir, "groupalone.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nserver:\n  group: elodin\n"),
		)
		res := new_check(r, path, "check-groupalone")
		check(r, res.exit_code != 0, "server.group without server.user exited 0")
		check(r, strings.contains(res.output, "server.group"), "the lone group was not reported: %q", res.output)
	}
	end_case(r)

	/*
	A drop that cannot happen has to stop the process.

	The failure mode this guards is the quiet one: listeners up, log line saying
	the server is ready, and the whole of the query path still running with
	whatever privilege it started with. Asking an unprivileged process to become
	root is the one way to provoke it without needing root to run the suite.
	*/
	if posix.geteuid() == 0 {
		skip_case(r, "cli: a failed privilege drop stops the server", "running as root, so no drop can fail")
	} else {
		start_case(r, "cli: a privilege drop that cannot happen stops the server")
		{
			cfg := fmt.tprintf(
				`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  servers: ["127.0.0.1:%d"]
blocking: {{ enabled: false }}
dnssec: {{ enabled: false }}
server: {{ user: root }}
`,
				next_port(r),
				next_port(r),
			)
			path := filepath.join({r.work_dir, "cannotdrop.yaml"}, context.temp_allocator) or_else ""
			_ = os.write_entire_file(path, transmute([]u8)cfg)

			res := run_binary(r, []string{"--config", path}, "cannot-drop")
			if check(r, res.ok, "could not run the binary") {
				check(r, res.exit_code != 0, "the server kept running after a failed drop")
				check(
					r,
					strings.contains(res.output, "cannot drop privileges"),
					"the failed drop was not reported: %q",
					res.output,
				)
			}
		}
		end_case(r)
	}

	start_case(r, "cli: the shipped example config is valid")
	{
		res := new_check(r, "examples/elodin.yaml", "check-example")
		check_eq_int(r, res.exit_code, 0, "exit code for examples/elodin.yaml")
		/*
		The shipped file leaves the loop count and the in-flight bound unset, so
		the numbers only exist once a machine has been measured. `--check` is
		where an operator looks before restarting a resolver, and a size that
		appears in no file and no output is one nobody can argue with.
		*/
		check(
			r,
			strings.contains(res.output, "loops=") &&
			strings.contains(res.output, "max_pending=") &&
			strings.contains(res.output, "derived from"),
			"the derived sizes were not reported: %q",
			res.output,
		)
	}
	end_case(r)

	/*
	A file that names the keys #547 retired still passes `--check`, as it still
	starts, and each one is named with what replaced it: refused outright, a
	configuration that was correct before the upgrade would stop the resolver
	the moment the package was updated.
	*/
	start_case(r, "cli: --check accepts the retired worker keys and names each")
	{
		path := filepath.join({r.work_dir, "retired-keys.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string(
				"upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 8\n  upstream_workers: 2\n  running_workers: 4\ndnssec:\n  max_connection_walks: 24\n",
			),
		)
		res := new_check(r, path, "check-retired-keys")
		check_eq_int(r, res.exit_code, 0, "exit code for a file naming the retired keys")
		for key in ([]string{"server.workers", "server.upstream_workers", "server.running_workers"}) {
			check(r, strings.contains(res.output, fmt.tprintf("warning: %s is no longer used", key)), "%s was not named: %q", key, res.output)
		}
		// Still a setting: the connections keep a walk bound of their own.
		check(r, !strings.contains(res.output, "max_connection_walks is no longer used"), "max_connection_walks was called retired: %q", res.output)
		check(r, strings.contains(res.output, "connection_walks=24"), "the configured connection walk bound was not printed: %q", res.output)
	}
	end_case(r)

	/*
	The per-deployment examples, held to the same bar as the reference file.

	Each of them turns settings on that the reference file leaves at their
	defaults - zone routes, reserved-name keys, a connection share, an empty
	allow list - and several of those combinations are refused at load on
	purpose. A file that stops loading is documentation that has quietly
	become wrong, and it would otherwise be found by whoever copied it.
	*/
	start_case(r, "cli: the per-deployment examples are valid")
	{
		for path in ([]string {
			"examples/local-only.yaml",
			"examples/lan.yaml",
			"examples/small-device.yaml",
			"examples/container.yaml",
			"examples/dev.yaml",
		}) {
			res := new_check(r, path, "check-deployment-example")
			check_eq_int(r, res.exit_code, 0, fmt.tprintf("exit code for %s", path))
		}
	}
	end_case(r)

	/*
	`examples/public.yaml` is the one that cannot pass here, and that is the
	file behaving as it says: it enables DoT and DoH against a certificate at
	an installed path, and `--check` refuses a listener whose certificate is
	not there rather than starting a resolver that cannot serve it. The rest of
	the file is held to the bar above by pointing those paths at this tree's own
	test certificate.
	*/
	start_case(r, "cli: the public example needs its certificate")
	{
		res := new_check(r, "examples/public.yaml", "check-public-example")
		check(r, res.exit_code != 0, "public.yaml passed --check without its certificate")
		check(
			r,
			strings.contains(res.output, "listeners.dot.cert_file"),
			"the missing certificate was not named: %q",
			res.output,
		)

		/*
		The rest of the file, checked with the certificate this suite already
		has - `r.cert_file`, which is `certs/cert.pem` when the tree has one and
		a freshly generated pair in the work directory otherwise. Written as an
		absolute path, since `--check` resolves these against elodin's own
		working directory rather than this test's.

		Only when there is a certificate to name: a machine with no `openssl`
		leaves the harness without one and skips every TLS case, and the first
		half above is the assertion that does not need it.
		*/
		src, read_err := os.read_entire_file(
			"examples/public.yaml",
			context.temp_allocator,
		)
		have_cert := r.cert_file != "" && r.key_file != ""
		if have_cert && check(r, read_err == nil, "could not read examples/public.yaml: %v", read_err) {
			// `replace_all` reports whether it allocated rather than whether it
			// matched, so the flag says nothing useful here and the text is
			// taken as it comes back either way.
			text, _ := strings.replace_all(
				string(src),
				"/etc/elodin/cert.pem",
				r.cert_file,
				context.temp_allocator,
			)
			text, _ = strings.replace_all(
				text,
				"/etc/elodin/key.pem",
				r.key_file,
				context.temp_allocator,
			)
			path := filepath.join({r.work_dir, "public-with-certs.yaml"}, context.temp_allocator) or_else ""
			_ = os.write_entire_file(path, transmute([]u8)text)

			res = new_check(r, path, "check-public-example-certs")
			check_eq_int(r, res.exit_code, 0, "exit code for public.yaml with a certificate it has")
			check(
				r,
				strings.contains(res.output, "server.allow_from is empty"),
				"the open-resolver warning was not reported: %q",
				res.output,
			)
		}
	}
	end_case(r)
}

@(private = "file")
new_check :: proc(r: ^Runner, path: string, tag: string) -> Run_Result {
	return run_binary(r, []string{"--config", path, "--check"}, tag)
}

/*
Graceful shutdown.

An init system stops a service with SIGTERM and expects it to put itself away.
Without a handler the default disposition applies and the process is simply
terminated, which means none of the teardown ever runs: connections are cut
mid-answer, and the ordering that makes the teardown safe is never exercised at
all.
*/
@(private = "file")
config_for_shutdown :: proc(udp_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
upstream:
  timeout: 2s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: true }}
blocking: {{ enabled: false }}
`,
		udp_port,
		udp_port,
		upstream_port,
	)
}

/*
Which of the server's threads would take SIGTERM, SIGINT or SIGHUP (#416).

The kernel hands a process-directed signal to any thread that has it unblocked,
and one taken in a timed socket read fails that read with EINTR: a list
download, or an upstream read and the query behind it. Only the main thread,
whose reads are none of those, is to take them, so every other is started with
them blocked (`loop.spawn_thread`). Read from each thread's SigBlk, the mask the kernel
consults.
*/
@(private = "file")
STOP_AND_RELOAD_MASK :: u64(1) << (u64(posix.Signal.SIGHUP) - 1) | u64(1) << (u64(posix.Signal.SIGINT) - 1) | u64(1) << (u64(posix.Signal.SIGTERM) - 1)

@(private = "file")
threads_taking_signals :: proc(pid: int) -> (main_takes: bool, others, taking: int, ok: bool) {
	entries, err := os.read_directory_by_path(fmt.tprintf("/proc/%d/task", pid), -1, context.temp_allocator)
	if err != nil {
		return
	}
	for e in entries {
		mask, read := proc_status_field(fmt.tprintf("/proc/%d/task/%s/status", pid, e.name), "SigBlk")
		if !read {
			continue // a thread that has just ended
		}
		blocked, parsed := strconv.parse_u64_of_base(mask, 16)
		if !parsed {
			return
		}
		takes := blocked & STOP_AND_RELOAD_MASK != STOP_AND_RELOAD_MASK
		if e.name == fmt.tprintf("%d", pid) {
			main_takes = takes
			continue
		}
		others += 1
		if takes {
			taking += 1
		}
	}
	return main_takes, others, taking, true
}

run_shutdown_cases :: proc(r: ^Runner) {
	f := fixture("a")
	upstream_port := next_port(r)
	mock := mock_make("shutdown", upstream_port)
	mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	if !mock_start(mock) {
		skip_case(r, "shutdown", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = config_for_shutdown(udp_port, upstream_port), udp_port = udp_port},
	)
	if !ok {
		skip_case(r, "shutdown", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "signals: only the main thread takes SIGTERM, SIGINT and SIGHUP")
	{
		res := query_udp(udp_port, from_hex(f.query))
		check(r, res.ok, "the server did not answer")
		main_takes, others, taking, read := threads_taking_signals(srv.process.pid)
		if check(r, read, "cannot read the server's thread masks") {
			check(r, main_takes, "the main thread blocks them, so no handler would run")
			check(r, others > 0, "the server runs no other thread to check")
			check(r, taking == 0, "%d of %d other threads would take them, and fail a read they are in", taking, others)
		}
	}
	end_case(r)

	start_case(r, "shutdown: SIGTERM is answered by an orderly exit")
	{
		// Answer something first, so the shutdown has a warmed-up server with
		// its worker pools and caches populated to take down.
		res := query_udp(udp_port, from_hex(f.query))
		check(r, res.ok, "the server did not answer before being asked to stop")

		state, exited := signal_shutdown(&srv, 15 * time.Second)
		if check(r, exited, "the server did not exit within 15s of SIGTERM") {
			check(
				r,
				state.success && state.exit_code == 0,
				"exited with code %d (success=%v); a signal default disposition looks like this",
				state.exit_code,
				state.success,
			)
			check(r, log_contains(&srv, "shutting down"), "no shutdown was logged, so the teardown never ran")
		}
	}
	end_case(r)
}
