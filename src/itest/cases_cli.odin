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
		The shipped file leaves both worker counts unset, so the numbers only
		exist once a machine has been measured. `--check` is where an operator
		looks before restarting a resolver, and a pool size that appears in no
		file and no output is one nobody can argue with.
		*/
		check(
			r,
			strings.contains(res.output, "workers=") && strings.contains(res.output, "derived from"),
			"the derived worker counts were not reported: %q",
			res.output,
		)
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

		src, read_err := os.read_entire_file(
			"examples/public.yaml",
			context.temp_allocator,
		)
		if check(r, read_err == nil, "could not read examples/public.yaml: %v", read_err) {
			// `replace_all` reports whether it allocated rather than whether it
			// matched, so the flag says nothing useful here and the text is
			// taken as it comes back either way.
			text, _ := strings.replace_all(
				string(src),
				"/etc/elodin/cert.pem",
				"certs/cert.pem",
				context.temp_allocator,
			)
			text, _ = strings.replace_all(
				text,
				"/etc/elodin/key.pem",
				"certs/key.pem",
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
