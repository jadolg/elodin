package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "elodin:tlsx"

/*
Integration suite for elodin.

Runs the built binary as a separate process against scripted mock upstreams, so
what is exercised is the artefact that ships rather than the library it was
compiled from. Everything is hermetic: no public resolver is contacted, and the
only external requirement is a certificate for the TLS cases, which the suite
generates for itself.

    mise run itest              # summary
    mise run itest -- -v        # one line per case
*/

USAGE :: `elodin integration tests

usage:
  itest [-v] [--binary <path>] [--keep]

options:
  -v, --verbose       print each case as it runs
      --binary <path> the elodin binary to test (default: bin/elodin)
      --keep          keep the temporary working directory
  -h, --help          print this message
`

main :: proc() {
	// The suite deliberately closes connections mid-exchange; without this a
	// resulting SIGPIPE would take the runner down with it.
	posix.sigignore(.SIGPIPE)

	binary := "bin/elodin"
	verbose := false
	keep := false

	args := os.args[1:]
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-v", "--verbose":
			verbose = true
		case "--keep":
			keep = true
		case "--binary":
			if i + 1 >= len(args) {
				fmt.eprintln("itest: --binary needs a path")
				os.exit(2)
			}
			i += 1
			binary = args[i]
		case "-h", "--help":
			fmt.print(USAGE)
			os.exit(0)
		case:
			fmt.eprintfln("itest: unknown option %q", args[i])
			os.exit(2)
		}
		i += 1
	}

	if !os.exists(binary) {
		fmt.eprintfln("itest: %s does not exist; run `mise run build` first", binary)
		os.exit(2)
	}

	work_dir := make_work_dir()
	defer if !keep {
		remove_work_dir(work_dir)
	}

	r := Runner {
		binary    = absolute(binary),
		work_dir  = work_dir,
		next_port = BASE_PORT,
		failures  = make([dynamic]string, 0, 16),
		verbose   = verbose,
	}

	cert, key, cert_ok := ensure_certificate(work_dir)
	r.cert_file = cert
	r.key_file = key

	fmt.printfln("elodin integration tests")
	fmt.printfln("  binary:    %s", r.binary)
	fmt.printfln("  work dir:  %s", work_dir)
	if !cert_ok {
		fmt.println("  note:      no certificate available, TLS cases will be skipped")
	}
	fmt.println()

	started := time.now()

	section(&r, "command line")
	run_cli_cases(&r)
	run_shutdown_cases(&r)

	section(&r, "log format")
	run_logfmt_cases(&r)

	section(&r, "wire format and message handling")
	run_wire_cases(&r)

	if cert_ok {
		section(&r, "listeners: udp, tcp, dot, doh")
		run_transport_cases(&r)
	} else {
		skip_case(&r, "listeners", "no certificate")
	}

	section(&r, "tls certificate reload")
	run_reload_cases(&r)

	section(&r, "blocking and sink lists")
	run_blocking_cases(&r)

	section(&r, "rewrites")
	run_rewrite_cases(&r)

	section(&r, "dns rebinding protection")
	run_rebind_cases(&r)

	section(&r, "rate limiting")
	run_rate_limit_cases(&r)

	section(&r, "client access control")
	run_acl_cases(&r)

	section(&r, "udp response ceiling")
	run_udp_size_cases(&r)

	section(&r, "cache")
	run_cache_cases(&r)
	run_cache_bytes_cases(&r)

	section(&r, "blocklist downloads")
	run_list_download_cases(&r)

	section(&r, "upstream strategies")
	run_strategy_cases(&r)

	if cert_ok {
		section(&r, "doh over http/2")
		run_h2_cases(&r)
		run_h2_large_response_case(&r)
	} else {
		skip_case(&r, "doh over http/2", "no certificate")
	}

	section(&r, "upstream transports")
	run_upstream_transport_cases(&r)
	run_stale_connection_cases(&r)
	run_query_id_cases(&r)

	if cert_ok {
		section(&r, "upstream: doh over h2")
		run_upstream_doh2_cases(&r)
	} else {
		skip_case(&r, "upstream: doh over h2", "no certificate")
	}

	section(&r, "dnssec validation")
	run_dnssec_cases(&r)

	section(&r, "dns cookies")
	run_cookie_cases(&r)
	run_upstream_cookie_cases(&r)

	section(&r, "metrics")
	run_metrics_cases(&r)

	elapsed := time.diff(started, time.now())
	report(&r, elapsed)

	if r.failed > 0 {
		os.exit(1)
	}
}

@(private)
section :: proc(r: ^Runner, title: string) {
	if r.verbose {
		fmt.printfln("\n%s", title)
	}
}

@(private)
report :: proc(r: ^Runner, elapsed: time.Duration) {
	if !r.verbose {
		fmt.println()
	}
	fmt.println()

	problems := 0
	for line in r.failures {
		if strings.has_prefix(line, "FAIL") || strings.has_prefix(line, "SKIP") {
			if problems == 0 {
				fmt.println("details:")
			}
			fmt.printfln("  %s", line)
			problems += 1
		}
	}
	if problems > 0 {
		fmt.println()
	}

	verdict := r.failed == 0 ? "PASS" : "FAIL"
	fmt.printfln(
		"%s  %d passed, %d failed, %d skipped in %.1fs",
		verdict,
		r.passed,
		r.failed,
		r.skipped,
		time.duration_seconds(elapsed),
	)
}

@(private)
absolute :: proc(path: string) -> string {
	abs, err := filepath.abs(path)
	return abs if err == nil else strings.clone(path)
}

@(private)
make_work_dir :: proc() -> string {
	base := os.get_env("TMPDIR", context.temp_allocator)
	if base == "" {
		base = "/tmp"
	}
	dir := fmt.aprintf("%s/elodin-itest-%d", base, time.now()._nsec)
	if err := os.make_directory(dir); err != nil {
		fmt.eprintfln("itest: cannot create %s: %v", dir, err)
		os.exit(2)
	}
	return dir
}

@(private)
remove_work_dir :: proc(dir: string) {
	// Best effort: remove the files we created, then the directory itself.
	entries, err := os.read_directory_by_path(dir, -1, context.temp_allocator)
	if err == nil {
		for entry in entries {
			_ = os.remove(entry.fullpath)
		}
	}
	_ = os.remove(dir)
}

/*
Provide a certificate for the TLS cases.

`certs/cert.pem` is reused when present so a developer running the suite
repeatedly does not pay for key generation each time; otherwise one is generated
into the working directory.
*/
@(private)
ensure_certificate :: proc(work_dir: string) -> (cert, key: string, ok: bool) {
	if os.exists("certs/cert.pem") && os.exists("certs/key.pem") {
		return absolute("certs/cert.pem"), absolute("certs/key.pem"), true
	}

	cert_path := fmt.aprintf("%s/cert.pem", work_dir)
	key_path := fmt.aprintf("%s/key.pem", work_dir)

	process, perr := os.process_start(
		os.Process_Desc {
			command = []string {
				"openssl",
				"req",
				"-x509",
				"-newkey",
				"ec",
				"-pkeyopt",
				"ec_paramgen_curve:prime256v1",
				"-nodes",
				"-keyout",
				key_path,
				"-out",
				cert_path,
				"-days",
				"2",
				"-subj",
				"/CN=elodin.local",
				"-addext",
				"subjectAltName=DNS:elodin.local,DNS:localhost,IP:127.0.0.1",
			},
		},
	)
	if perr != nil {
		return "", "", false
	}
	state, werr := os.process_wait(process)
	if werr != nil || state.exit_code != 0 {
		return "", "", false
	}

	// Confirm OpenSSL will actually load the pair before promising TLS cases.
	tlsx.init()
	ctx, terr := tlsx.server_context(cert_path, key_path, []string{"dot"})
	if terr != .None {
		return "", "", false
	}
	tlsx.context_destroy(ctx)
	return cert_path, key_path, true
}
