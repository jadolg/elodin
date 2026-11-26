package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
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
			// The OpenSSL it runs with, which an advisory is checked against.
			check(r, strings.contains(res.output, " (OpenSSL "), "the OpenSSL is not named: %q", res.output)
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
		res := check_config_text(r, "check-ok", "upstream:\n  servers: [1.1.1.1]\nblocking:\n  rules: [\"||a.test^\"]\n")
		if res.ok {
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
		res := check_config_text(
			r,
			"check-inert-estimate",
			"upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: true\n    response_size_estimate: 2048\n",
		)
		if res.ok {
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
		bres := check_config_text(
			r,
			"check-biting-estimate",
			"upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: true\n    responses_per_second: 500\n    response_size_estimate: 128\n",
		)
		if bres.ok {
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
		qres := check_config_text(r, "check-default-estimate", "upstream:\n  servers: [1.1.1.1]\n")
		if qres.ok {
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
		res := check_config_text(r, "check-empty", "log:\n  level: info\n")
		if res.ok {
			check(r, res.exit_code != 0, "an unusable config exited 0")
			check(r, strings.contains(res.output, "upstream"), "the error does not mention upstreams")
		}
	}
	end_case(r)

	// A zero timeout is not "no limit": every query would answer SERVFAIL at once
	// (#499). Refused at the top level and on a route.
	start_case(r, "cli: --check rejects an upstream timeout of zero")
	{
		res := check_config_text(
			r,
			"check-zero-timeout",
			"upstream:\n  timeout: 0s\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: 0ms\n      servers: [192.168.1.1]\n",
		)
		if res.ok {
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
		res := check_config_text(
			r,
			"check-out-of-range",
			"listeners:\n  udp: {enabled: true, address: 127.0.0.1, port: 106837}\n  tcp: {enabled: true, address: 127.0.0.1, port: 0}\n" +
			"server:\n  client_timeout: 0s\nupstream:\n  timeout: 0s\n  servers:\n    - {name: none, type: udp, address: 127.0.0.1, port: 41302}\n" +
			"blocking:\n  enabled: false\nrewrites:\n  - domain: nas.home\n    answer: 192.168.1.50\n    ttl: -1\n",
		)
		if res.ok {
			check(r, res.exit_code != 0, "an out-of-range config exited 0")
			for key in ([]string{"listeners.udp.port", "listeners.tcp.port", "server.client_timeout", "upstream.timeout", "rewrites[0].ttl"}) {
				check(r, strings.contains(res.output, key), "%s was not reported: %q", key, res.output)
			}
		}
	}
	end_case(r)

	start_case(r, "cli: --check reports every problem at once, with line numbers")
	{
		res := check_config_text(r, "check-bad", "upstream:\n  strategy: teleport\n  servers: [1.1.1.1]\nblocking:\n  response: explode\n")
		if res.ok {
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
		res := check_config_text(r, "check-yaml", "upstream:\n  servers: [1.1.1.1]\nthis is not a mapping\n")
		check(r, res.exit_code != 0, "malformed YAML exited 0")
		check(r, strings.contains(res.output, "line 3"), "the failing line was not identified: %q", res.output)
	}
	end_case(r)

	// YAML reads `*.lan` as an alias (1.2.2 section 7.3.3), so a file holding
	// it unquoted means something else to every other YAML reader.
	start_case(r, "cli: a plain value starting with a YAML indicator is refused")
	{
		res := check_config_text(r, "check-yaml-indicator", "upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: *.lan\n    answer: 192.168.1.10\n")
		check(r, res.exit_code != 0, "an unquoted *.lan exited 0: %q", res.output)
		check(r, strings.contains(res.output, "line 4") && strings.contains(res.output, "quote"), "the line and the remedy were not given: %q", res.output)
	}
	end_case(r)

	start_case(r, "cli: a DoT listener without a certificate is refused")
	{
		res := check_config_text(r, "check-nocert", "upstream:\n  servers: [1.1.1.1]\nlisteners:\n  dot:\n    enabled: true\n")
		check(r, res.exit_code != 0, "a DoT listener with no certificate exited 0")
		check(r, strings.contains(res.output, "cert_file"), "the missing certificate was not reported")
	}
	end_case(r)

	start_case(r, "cli: --check rejects a service account nobody has")
	{
		res := check_config_text(r, "check-baduser", "upstream:\n  servers: [1.1.1.1]\nserver:\n  user: elodin-no-such-user\n")
		check(r, res.exit_code != 0, "an unknown server.user exited 0")
		check(r, strings.contains(res.output, "no such user"), "the unknown account was not reported: %q", res.output)
	}
	end_case(r)

	/*
	`--check` opens no log file. Run as root it would otherwise create the file
	as root, and the real start after it would find it already there and leave
	it root's instead of handing it to `server.user`.
	*/
	start_case(r, "cli: --check does not create the log file")
	{
		log_path := filepath.join({r.work_dir, "check-nolog.log"}, context.temp_allocator) or_else ""
		res := check_config_text(r, "check-nolog", fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nlog:\n  file: %q\n", log_path))
		check(r, res.exit_code == 0, "--check with a log file exited %d: %q", res.exit_code, res.output)
		check(r, !os.exists(log_path), "--check created the log file")
		check(r, !strings.contains(res.output, "cannot open the log file"), "--check warned about a log file it can create: %q", res.output)

		// One the start could not open is still said, though nothing is opened.
		missing := filepath.join({r.work_dir, "no-such-dir", "check.log"}, context.temp_allocator) or_else ""
		res = check_config_text(r, "check-nolog-dir", fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nlog:\n  file: %q\n", missing))
		check(r, res.exit_code == 0, "--check with a log file in a missing directory exited %d: %q", res.exit_code, res.output)
		check(r, strings.contains(res.output, "cannot open the log file"), "--check did not say the log file cannot be opened: %q", res.output)

		// Nor in a directory the account cannot write; root writes any.
		if posix.geteuid() != 0 {
			ro := filepath.join({r.work_dir, "read-only-dir"}, context.temp_allocator) or_else ""
			_ = os.make_directory(ro)
			_ = os.chmod(ro, {.Read_User, .Execute_User})
			defer _ = os.chmod(ro, {.Read_User, .Write_User, .Execute_User})
			in_ro := filepath.join({ro, "check.log"}, context.temp_allocator) or_else ""
			res = check_config_text(r, "check-nolog-ro", fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nlog:\n  file: %q\n", in_ro))
			check(r, res.exit_code == 0, "--check with a log file in a read-only directory exited %d: %q", res.exit_code, res.output)
			check(r, strings.contains(res.output, "cannot open the log file"), "--check did not say a log file in a read-only directory cannot be created: %q", res.output)
		}
	}
	end_case(r)

	start_case(r, "cli: --check rejects a group with no user")
	{
		res := check_config_text(r, "check-groupalone", "upstream:\n  servers: [1.1.1.1]\nserver:\n  group: elodin\n")
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
			cfg := base_config(
				next_port(r),
				upstream_at(next_port(r)),
				log = "{ level: info }",
				timeout = "",
				cache = "{ enabled: true }",
				extra = "dnssec: { enabled: false }\nserver: { user: root }",
			)
			// A write that did not land has failed the case already.
			if path, written := write_work_file(r, "cannotdrop.yaml", cfg); written {
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
	The worker keys #547 removed are unknown keys: `--check` refuses a file that
	names one, and says which. The connection walk bound is still a setting.
	*/
	start_case(r, "cli: --check refuses the removed worker keys and names each")
	{
		for key in ([]string{"workers", "upstream_workers", "running_workers"}) {
			res := check_config_text(r, fmt.tprintf("check-removed-%s", key), fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nserver:\n  %s: 8\n", key))
			check(r, res.exit_code != 0, "a file naming server.%s passed --check", key)
			check(r, strings.contains(res.output, fmt.tprintf("server.%s: unknown key", key)), "server.%s was not named: %q", key, res.output)
		}
		res := check_config_text(r, "check-connection-walks", "upstream:\n  servers: [1.1.1.1]\ndnssec:\n  max_connection_walks: 24\n")
		check_eq_int(r, res.exit_code, 0, "exit code for dnssec.max_connection_walks")
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
			"examples/docker.yaml",
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
	`examples/public.yaml` and `examples/docker-public.yaml` are the ones that
	cannot pass here, and that is the files behaving as they say: they enable
	DoT and DoH against a certificate at an installed path, and `--check`
	refuses a listener whose certificate is not there rather than starting a
	resolver that cannot serve it. The rest of each file is held to the bar
	above by pointing those paths at this tree's own test certificate.
	*/
	start_case(r, "cli: the public examples need their certificate")
	{
		Public_Example :: struct {
			path, cert, key: string,
		}
		for ex in ([]Public_Example {
			{"examples/public.yaml", "/etc/elodin/cert.pem", "/etc/elodin/key.pem"},
			// One file for both: the certificate and its key, as compose-public.yaml writes it.
			{"examples/docker-public.yaml", "/etc/elodin/certs/pair.pem", "/etc/elodin/certs/pair.pem"},
		}) {
			// Tagged per file, so each run keeps its own output in the work directory.
			stem := filepath.stem(ex.path)
			res := new_check(r, ex.path, fmt.tprintf("check-%s-example", stem))
			check(r, res.exit_code != 0, "%s passed --check without its certificate", ex.path)
			check(
				r,
				strings.contains(res.output, "listeners.dot.cert_file"),
				"%s: the missing certificate was not named: %q",
				ex.path,
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
			src, read_err := os.read_entire_file(ex.path, context.temp_allocator)
			have_cert := r.cert_file != "" && r.key_file != ""
			if have_cert && check(r, read_err == nil, "could not read %s: %v", ex.path, read_err) {
				// Matched with the key in front, since docker-public.yaml names the
				// same file for both: by path alone, the first replacement would
				// point `key_file` at the certificate too. `replace_all` reports
				// whether it allocated rather than whether it matched, so the flag
				// says nothing useful here; the counts below check the matches.
				cert_line := fmt.tprintf("cert_file: %s", ex.cert)
				key_line := fmt.tprintf("key_file: %s", ex.key)
				check_eq_int(r, strings.count(string(src), cert_line), 2, fmt.tprintf("%s lines in %s", cert_line, ex.path))
				check_eq_int(r, strings.count(string(src), key_line), 2, fmt.tprintf("%s lines in %s", key_line, ex.path))
				text, _ := strings.replace_all(string(src), cert_line, fmt.tprintf("cert_file: %s", r.cert_file), context.temp_allocator) // lint:allow the flag is allocation, not a match
				text, _ = strings.replace_all(text, key_line, fmt.tprintf("key_file: %s", r.key_file), context.temp_allocator) // lint:allow the flag is allocation, not a match
				check(r, !strings.contains(text, ex.key), "%s still names %s after the rewrite", ex.path, ex.key)
				res = check_config_text(r, fmt.tprintf("check-%s-example-certs", stem), text)
				check_eq_int(r, res.exit_code, 0, fmt.tprintf("exit code for %s with a certificate it has", ex.path))
				check(
					r,
					strings.contains(res.output, "server.allow_from is empty"),
					"%s: the open-resolver warning was not reported: %q",
					ex.path,
					res.output,
				)
			}
		}
	}
	end_case(r)
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
	return base_config(
		udp_port,
		upstream_at(upstream_port),
		log = "{ level: info }",
		tcp = fmt.tprintf(`{{ enabled: true, address: "127.0.0.1", port: %d }}`, udp_port),
		cache = "{ enabled: true }",
	)
}

run_shutdown_cases :: proc(r: ^Runner) {
	f := fixture("a")
	upstream_port := next_port(r)
	mock := mock_make("shutdown", upstream_port)
	mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	if !mock_start_or_skip(r, mock, "shutdown") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options{config = config_for_shutdown(udp_port, upstream_port), udp_port = udp_port},
	)
	if !ok {
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
		// its caches populated to take down.
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
