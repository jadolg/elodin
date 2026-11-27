package itest

import "core:fmt"
import "core:os"
import "core:strings"
import "core:slice"
import "core:sys/linux"
import "core:sys/posix"
import "core:time"
import "elodin:dns"

/*
`server.sandbox` on the shipped binary (#417): which layers each mode puts on
every thread of the process, as each thread's `status` under `/proc` shows
them, what
the startup line says about Landlock against what this kernel offers, and that
a reload cannot take the sandbox off. The rest of the suite runs under `strict`
(`with_sandbox`, `suite_sandbox`), which is what shows the allowlist and the Landlock
rules cover the paths a serving process takes.
*/
run_sandbox_cases :: proc(r: ^Runner) {
	own_filters, own_read := proc_status_int(os.get_pid(), "Seccomp_filters")
	// The suite's own: a run under bubblewrap or a unit with NoNewPrivileges
	// starts with it set, and off leaves the server as it started.
	own_nnp, nnp_read := proc_status_int(os.get_pid(), "NoNewPrivs")
	if !own_read || !nnp_read {
		skip_case(r, "server.sandbox", "this kernel reports no Seccomp_filters in /proc")
		return
	}
	abi := max(linux.syscall(linux.SYS_landlock_create_ruleset, uintptr(0), uintptr(0), uintptr(1)), 0)

	Case :: struct {
		name, setting: string,
	}
	cases := []Case {
		// Left to the harness: `suite_sandbox`.
		{name = "server.sandbox unset in the suite: the harness's mode is the one in force (#417)"},
		{name = "server.sandbox strict: every thread runs under no_new_privs and one more filter (#417)", setting = "strict"},
		{name = "server.sandbox basic: every thread runs under no_new_privs and no filter of its own (#417)", setting = "basic"},
		{name = "server.sandbox off: no thread is narrowed and nothing is said (#417)", setting = "off"},
	}
	for c in cases {
		mode := c.setting if c.setting != "" else suite_sandbox(r)
		if mode == "strict" && r.asan {
			skip_case(r, c.name, "LeakSanitizer's exit makes calls the allowlist does not have (see `suite_sandbox`)")
			continue
		}
		start_case(r, c.name)
		defer end_case(r)
		// What every thread's status says.
		no_new_privs := own_nnp if mode == "off" else 1
		filters := own_filters + 1 if mode == "strict" else own_filters

		udp_port := next_port(r)
		extra := fmt.tprintf("server:\n  sandbox: %s", c.setting) if c.setting != "" else ""
		config := base_config(udp_port, upstream_at(next_port(r)), log = "{ level: info }", extra = extra)
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
		if !ok {
			continue
		}
		defer stop_server(&srv)
		if !check(r, wait_for_log(&srv, "msg=ready", 5 * time.Second), "the server never logged ready:\n%s", read_log(&srv)) {
			continue
		}

		if mode != "off" {
			line := fmt.tprintf("msg=sandbox mode=%s no_new_privs=true landlock_abi=%d seccomp=%v", mode, abi, mode == "strict")
			check(r, strings.contains(read_log(&srv), line), "no %q in the log:\n%s", line, read_log(&srv))
		} else {
			check(r, !strings.contains(read_log(&srv), "msg=sandbox"), "a sandbox line with the sandbox off:\n%s", read_log(&srv))
		}
		expect_every_thread(r, srv.process.pid, no_new_privs, filters)

		if c.setting != "strict" {
			continue
		}
		// Changed to off in the file: named, held, and every thread as it was.
		off := base_config(udp_port, upstream_at(next_port(r)), log = "{ level: info }", extra = "server:\n  sandbox: off")
		if check(r, reload_to(r, &srv, off, "server.sandbox changed, which takes a restart"), "the change was not named:\n%s", read_log(&srv)) {
			expect_every_thread(r, srv.process.pid, no_new_privs, filters)
		}
	}
}

// Every thread of `pid` - more than the main one, or there is nothing to say
// about the others - shows `no_new_privs` and `filters` in its status.
@(private = "file")
expect_every_thread :: proc(r: ^Runner, pid: int, no_new_privs, filters: int) {
	ids, listed := task_ids(pid)
	if !check(r, listed && len(ids) > 1, "the threads of %d could not be listed, or there is only one: %v", pid, ids) {
		return
	}
	for id in ids {
		task := fmt.tprintf("task/%s/status", id)
		nnp, nnp_read := proc_status_int(pid, "NoNewPrivs", task)
		count, count_read := proc_status_int(pid, "Seccomp_filters", task)
		if !nnp_read || !count_read {
			continue // a thread that has just ended
		}
		check(r, nnp == no_new_privs, "thread %s: NoNewPrivs %d, want %d", id, nnp, no_new_privs)
		check(r, count == filters, "thread %s: Seccomp_filters %d, want %d", id, count, filters)
	}
}

/*
What a strict sandbox has to leave working, end to end, on the paths a mock on
127.0.0.1 does not take (#417). Each passes with or without Landlock; under it,
in CI, each fails when the grant it names is taken out of `sandbox_plan`. Run in
the suite's mode, `suite_sandbox`.
*/
run_sandbox_path_cases :: proc(r: ^Runner) {
	if r.cert_file == "" {
		skip_case(r, "server.sandbox: TLS paths", "no certificate")
	} else {
		sandbox_hashed_ca_case(r)
		sandbox_certbot_renewal_case(r)
	}
	sandbox_system_resolver_case(r)
	sandbox_log_rotation_case(r)
	sandbox_relative_log_reload_case(r)
	sandbox_cache_turned_on_case(r)
}

/*
A DoH upstream verified against a hashed certificate directory whose one entry
is a symlink into another directory, with no bundle file: how the static build
runs on Debian and Ubuntu. The same server with an empty directory is the
control: it must refuse, or the first proves nothing about verification.
*/
@(private = "file")
sandbox_hashed_ca_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a DoH upstream verified through hashed certificates elsewhere (#417)"
	hash_out := fmt.tprintf("%s/sandbox-hash.txt", r.work_dir)
	res := run_command({"openssl", "x509", "-hash", "-noout", "-in", r.cert_file}, nil, hash_out)
	hash, read_err := os.read_entire_file(hash_out, context.temp_allocator)
	if !res.ok || res.exit_code != 0 || read_err != nil {
		fail(r, "%s: openssl could not hash the certificate", NAME)
		return
	}
	// The hashed entry leads into a directory nothing else grants, as
	// /etc/ssl/certs leads into /usr/share/ca-certificates.
	shared, shared_ok := outside_work_dir(r, "sandbox-ca-shared")
	if !shared_ok {
		return
	}
	defer remove_outside(r, shared)
	// Heap: read in every case below, and `end_case` frees the temp allocator.
	hashed := fmt.aprintf("%s/sandbox-hashed", r.work_dir)
	defer delete(hashed)
	empty := fmt.aprintf("%s/sandbox-hashed-empty", r.work_dir)
	defer delete(empty)
	real := fmt.tprintf("%s/elodin-test.crt", shared)
	link := fmt.tprintf("%s/%s.0", hashed, strings.trim_space(string(hash)))
	if !install_cert(real, r.cert_file) || os.make_directory(hashed) != nil || os.make_directory(empty) != nil || os.symlink(real, link) != nil {
		fail(r, "%s: cannot stage the certificate directories", NAME)
		return
	}

	fix := fixture("a")
	payload := from_hex(fix.response, context.allocator)
	defer delete(payload)
	upstream_port := next_port(r)
	mock := doh2_mock_make(upstream_port, "/dns-query", payload)
	started := doh2_mock_start(mock, r.cert_file, r.key_file)
	defer doh2_mock_stop(mock)
	if !started {
		skip_case(r, NAME, "cannot start the mock")
		return
	}

	for cert_dir, trusted in ([2]string{hashed, empty}) {
		start_case(r, NAME if trusted == 0 else "server.sandbox: the same upstream is refused when the directory trusts nothing (#417)")
		defer end_case(r)
		env, env_ok := environ_without(r, NAME, {"SSL_CERT_FILE=", "SSL_CERT_DIR="}, extra = 2)
		if !env_ok {
			continue
		}
		append(&env, fmt.tprintf("SSL_CERT_FILE=%s/sandbox-absent.pem", r.work_dir), fmt.tprintf("SSL_CERT_DIR=%s", cert_dir))
		servers := fmt.tprintf(`[{{ name: hashed, type: https, url: "https://127.0.0.1:%d/dns-query", verify: true }}]`, upstream_port)
		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = base_config(udp_port, servers, timeout = "5s"), udp_port = udp_port, env = env[:]})
		if !ok {
			continue
		}
		defer stop_server(&srv)
		h2_before, h1_before := doh2_mock_counts(mock)
		_, h, answered := ask(r, udp_port, fix.qname, fix.qtype)
		h2_after, h1_after := doh2_mock_counts(mock)
		before, after := h2_before + h1_before, h2_after + h1_after
		if trusted == 0 {
			if check(r, answered, "no answer:\n%s", read_log(&srv)) {
				check(r, h.rcode == int(dns.Rcode.No_Error) && h.ancount == fix.ancount, "rcode %d with %d answers, want NOERROR and %d:\n%s", h.rcode, h.ancount, fix.ancount, read_log(&srv))
			}
			check(r, after > before, "the upstream was never reached:\n%s", read_log(&srv))
		} else {
			check(r, answered && h.rcode == int(dns.Rcode.Serv_Fail), "answered %v with rcode %d, want SERVFAIL from an untrusted upstream", answered, h.rcode)
			check_eq_int(r, after - before, 0, "requests the untrusted upstream answered")
		}
	}
}

/*
A list on `http://localhost`, with no bootstrap: `upstream.resolve_address`
falls back to `netx.resolve`, which reads `/etc/resolv.conf` (and refuses
without a name server there) and then `/etc/hosts`. Strict grants both files.
*/
@(private = "file")
sandbox_system_resolver_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a list on a host named in /etc/hosts downloads with no bootstrap (#417)"
	hosts, herr := os.read_entire_file("/etc/hosts", context.temp_allocator)
	resolv, rerr := os.read_entire_file("/etc/resolv.conf", context.temp_allocator)
	if herr != nil || rerr != nil || !hosts_maps_localhost(string(hosts)) || !strings.contains(string(resolv), "nameserver") {
		skip_case(r, NAME, "this host's /etc/hosts does not map localhost to 127.0.0.1, or /etc/resolv.conf names no name server")
		return
	}
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/byname.txt", "0.0.0.0 byname.test\n")
	http_ok := http_mock_start(http)
	defer http_mock_stop(http)
	if !http_ok {
		skip_case(r, NAME, "cannot start the HTTP mock")
		return
	}
	start_case(r, NAME)
	defer end_case(r)
	udp_port, upstream_port := next_port(r), next_port(r)
	entry := fmt.tprintf(`{{ name: byname, url: "http://localhost:%d/byname.txt", format: hosts }}`, http_port)
	srv, ok := start_server(r, Server_Options{config = config_lists(udp_port, upstream_port, []string{entry}, refresh = "24h"), udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}
	defer stop_server(&srv)
	check_eq_int(r, http_mock_hits(http, "/byname.txt"), 1, "fetches of the list by host name")
	if _, h, asked := ask(r, udp_port, "byname.test.", u16(dns.Type.A)); asked {
		check(r, h.rcode == int(dns.Rcode.NX_Domain), "the list fetched by name was not applied:\n%s", read_log(&srv))
	}
}

/*
A directory beside the run's work directory, not in it: the work directory
holds each server's configuration file, so strict grants reads beneath it, and
a case about a grant of its own would pass whatever that grant was. Heap, for
the caller to remove and free.
*/
@(private = "file")
outside_work_dir :: proc(r: ^Runner, name: string) -> (dir: string, ok: bool) {
	dir = fmt.aprintf("%s-%s", r.work_dir, name)
	if err := os.make_directory_all(dir); err != nil {
		fail(r, "cannot make %s: %v", dir, err)
		delete(dir)
		return "", false
	}
	return dir, true
}

@(private = "file")
remove_outside :: proc(r: ^Runner, dir: string) {
	if err := os.remove_all(dir); err != nil {
		fail(r, "cannot remove %s: %v", dir, err)
	}
	delete(dir)
}

// Whether `hosts` maps `localhost` to 127.0.0.1, as a resolver reading it would.
@(private = "file")
hosts_maps_localhost :: proc(hosts: string) -> bool {
	text := hosts
	for line in strings.split_lines_iterator(&text) {
		fields := strings.fields(strings.trim_space(line), context.temp_allocator)
		if len(fields) >= 2 && fields[0] == "127.0.0.1" && slice.contains(fields[1:], "localhost") {
			return true
		}
	}
	return false
}

/*
A certbot renewal: `live/` holds symlinks into `archive/`, and renewing writes
new files there and re-points the links before the SIGHUP. Strict grants the
directories of both the links and their targets, which a rule on the file the
link led to at startup would not.
*/
@(private = "file")
sandbox_certbot_renewal_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a certbot renewal through live/ symlinks is served after SIGHUP (#417)"
	// As /etc/letsencrypt is: nothing else the server reads is in it.
	le, le_ok := outside_work_dir(r, "sandbox-le")
	if !le_ok {
		return
	}
	defer remove_outside(r, le)
	live := fmt.tprintf("%s/live", le)
	archive := fmt.tprintf("%s/archive", le)
	if os.make_directory_all(live) != nil || os.make_directory_all(archive) != nil {
		fail(r, "%s: cannot make the certbot tree", NAME)
		return
	}
	cert1, key1 := fmt.tprintf("%s/cert1.pem", archive), fmt.tprintf("%s/privkey1.pem", archive)
	cert2, key2 := fmt.tprintf("%s/cert2.pem", archive), fmt.tprintf("%s/privkey2.pem", archive)
	cert, key := fmt.tprintf("%s/cert.pem", live), fmt.tprintf("%s/privkey.pem", live)
	if !generate_named_cert(cert1, key1, "renew-a.test") || os.symlink(cert1, cert) != nil || os.symlink(key1, key) != nil {
		fail(r, "%s: cannot stage the first certificate", NAME)
		return
	}

	start_case(r, NAME)
	defer end_case(r)
	udp_port, dot_port := next_port(r), next_port(r)
	dot := dot_listener(r, dot_port, cert = cert, key = key)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(next_port(r)), listeners_extra = dot), udp_port = udp_port, dot_port = dot_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	if !check(r, dot_handshake_verifies(dot_port, cert1, "renew-a.test"), "the first certificate is not served") {
		return
	}
	// Written after the start, beside the first, as certbot does.
	if !check(r, generate_named_cert(cert2, key2, "renew-b.test"), "cannot write the renewed certificate") {
		return
	}
	for pair in ([2][2]string{{cert2, cert}, {key2, key}}) {
		if !check(r, os.remove(pair[1]) == nil && os.symlink(pair[0], pair[1]) == nil, "cannot re-point %s", pair[1]) {
			return
		}
	}
	check(r, signal_reload(&srv), "could not deliver SIGHUP")
	check(r, wait_for_handshake(dot_port, cert2, "renew-b.test", 5 * time.Second), "the renewed certificate was never served:\n%s", read_log(&srv))
}

/*
logrotate's `create`: the log is renamed, and the SIGHUP that follows makes a
new file of the same name, in the directory the sandbox grants writing to.
*/
@(private = "file")
sandbox_log_rotation_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a rotated log is made again on SIGHUP (#417)"
	dir := fmt.tprintf("%s/sandbox-logs", r.work_dir)
	if os.make_directory(dir) != nil {
		fail(r, "%s: cannot make %s", NAME, dir)
		return
	}
	path := fmt.tprintf("%s/elodin.log", dir)
	start_case(r, NAME)
	defer end_case(r)
	udp_port := next_port(r)
	log := fmt.tprintf("{{ level: info, file: %q }}", path)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(next_port(r)), log = log), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	rotated := strings.concatenate({path, ".1"}, context.temp_allocator)
	if !check(r, os.exists(path) && os.rename(path, rotated) == nil, "cannot rotate %s", path) {
		return
	}
	check(r, signal_reload(&srv), "could not deliver SIGHUP")
	check(r, wait_file_count(path, "SIGHUP received", 1, 5 * time.Second), "the log was not made again at %s:\n%s", path, read_log(&srv))
}

/*
Blocking off at the start, over a cache directory that is there; a reload turns
it on, and the download is kept in that directory - which only a grant made
while blocking was off allows.
*/
@(private = "file")
sandbox_cache_turned_on_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a reload that turns blocking on keeps its lists in the cache (#417)"
	cache := fmt.tprintf("%s/sandbox-cache", r.work_dir)
	if os.make_directory(cache) != nil {
		fail(r, "%s: cannot make %s", NAME, cache)
		return
	}
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/sandbox.txt", "0.0.0.0 sandboxed.test\n")
	http_ok := http_mock_start(http)
	defer http_mock_stop(http)
	if !http_ok {
		skip_case(r, NAME, "cannot start the HTTP mock")
		return
	}

	start_case(r, NAME)
	defer end_case(r)
	udp_port, upstream_port := next_port(r), next_port(r)
	off := base_config(udp_port, upstream_at(upstream_port), log = "{ level: info }", blocking = fmt.tprintf("{{ enabled: false, cache_dir: %q }}", cache))
	srv, ok := start_server(r, Server_Options{config = off, udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}
	defer stop_server(&srv)
	on := config_lists(udp_port, upstream_port, []string{list_entry("sandbox-list", http_port, "/sandbox.txt")}, cache_dir = cache, refresh = "24h", log = "{ level: info }")
	if !check(r, reload_to(r, &srv, on, "list sandbox-list:", 10 * time.Second), "the list never loaded:\n%s", read_log(&srv)) {
		return
	}
	cached := fmt.tprintf("%s/sandbox-list.list", cache)
	check(r, wait_file_count(cached, "sandboxed.test", 1, 5 * time.Second), "the list was not kept at %s:\n%s", cached, read_log(&srv))
	check(r, !log_contains(&srv, "is not writable"), "the cache was refused:\n%s", read_log(&srv))
}

/*
A reload that moves `log.file` to a relative name: nothing after the filter may
resolve it, as `realpath` would through `getcwd`, which the allowlist does not
have. The directory named is not there, so the reopen fails as any other does
and the log stays where it was - without a file made in the suite's directory.
*/
@(private = "file")
sandbox_relative_log_reload_case :: proc(r: ^Runner) {
	NAME :: "server.sandbox: a reload to a relative log.file keeps the server serving (#417)"
	start_case(r, NAME)
	defer end_case(r)
	udp_port, upstream_port := next_port(r), next_port(r)
	srv, ok := start_server(r, Server_Options{config = base_config(udp_port, upstream_at(upstream_port), log = "{ level: info }"), udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	moved := base_config(udp_port, upstream_at(upstream_port), log = `{ level: info, file: "elodin-sandbox-absent/elodin.log" }`)
	if !check(r, reload_to(r, &srv, moved, "cannot open the log file"), "the reopen of a relative log was not reported:\n%s", read_log(&srv)) {
		return
	}
	check(r, wait_ready(&srv, 2 * time.Second), "the server stopped answering after the reload:\n%s", read_log(&srv))
}

/*
Nothing is read from a listener before the process is as narrow as it gets
(#681): every line that says a listener is being read - UDP, TCP and the metrics
endpoint - comes after the sandbox line and, started as root, after the drop to
`nobody`. The listeners are bound before both, so a client's bytes wait in the
kernel instead. This orders `run`; that a line is written only once its
listener reads is `test_a_bound_listener_reads_nothing_until_armed`.
*/
run_listener_arming_case :: proc(r: ^Runner) {
	NAME :: "listeners: nothing is read before the privilege drop and the sandbox (#681)"
	mode := suite_sandbox(r)
	start_case(r, NAME)
	defer end_case(r)
	// Without a `nobody` account the drop cannot be asked for; the sandbox
	// line still orders the case.
	root := posix.geteuid() == 0 && posix.getpwnam("nobody") != nil
	udp_port, tcp_port, metrics_port := next_port(r), next_port(r), next_port(r)
	user := "\n  user: nobody" if root else ""
	config := base_config(
		udp_port,
		upstream_at(next_port(r)),
		log = "{ level: info }",
		tcp = tcp_at(tcp_port),
		extra = fmt.tprintf("server:\n  sandbox: %s%s\nmetrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}", mode, user, metrics_port),
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, tcp_port = tcp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	if !check(r, wait_for_log(&srv, "msg=ready", 5 * time.Second), "the server never logged ready:\n%s", read_log(&srv)) {
		return
	}
	log := read_log(&srv)
	narrowed, found := narrowed_at(r, log, root)
	if !found {
		return
	}
	reading := [3]string {
		fmt.tprintf("listening for DNS on 127.0.0.1:%d/udp", udp_port),
		fmt.tprintf("listening for DNS on 127.0.0.1:%d/tcp", tcp_port),
		fmt.tprintf("serving metrics on 127.0.0.1:%d", metrics_port),
	}
	for line in reading {
		at := strings.index(log, line)
		check(r, at > narrowed, "%q is at %d, not after the process was narrowed at %d:\n%s", line, at, narrowed, log)
	}
}

/*
Where in `log` the process is as narrow as it gets: the later of the sandbox
line and, with `dropped`, the line saying it runs as `nobody`. Fails the case
when either is missing.
*/
@(private = "file")
narrowed_at :: proc(r: ^Runner, log: string, dropped: bool) -> (at: int, ok: bool) {
	markers := [2]string{"msg=sandbox ", "running as nobody" if dropped else ""}
	for m in markers {
		if m == "" {
			continue
		}
		i := strings.index(log, m)
		if !check(r, i >= 0, "no %q in the log:\n%s", m, log) {
			return 0, false
		}
		at = max(at, i)
	}
	return at, true
}

/*
Nothing the network sends is parsed at startup before the process is as narrow
as it gets (#755): the bootstrap lookup of an upstream named by hostname and the
download of a blocklist both come after the sandbox line and, started as root,
after the drop to `nobody`. The bootstrap server answers NXDOMAIN, so the line
saying its answer was read is the one to order by.
*/
run_startup_fetch_order_case :: proc(r: ^Runner) {
	NAME :: "startup: no bootstrap lookup or list download before the privilege drop and the sandbox (#755)"
	HOST :: "up.order.test"
	boot := mock_make("order-bootstrap", next_port(r))
	defer mock_stop(boot)
	mock_rcode(boot, HOST + ".", u16(dns.Type.A), .NX_Domain)
	mock_rcode(boot, HOST + ".", u16(dns.Type.AAAA), .NX_Domain)
	if !mock_start_or_skip(r, boot, NAME) {
		return
	}
	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/order.txt", "0.0.0.0 order.test\n")
	http_ok := http_mock_start(http)
	defer http_mock_stop(http)
	if !http_ok {
		skip_case(r, NAME, "cannot start the HTTP mock")
		return
	}
	start_case(r, NAME)
	defer end_case(r)
	root := posix.geteuid() == 0 && posix.getpwnam("nobody") != nil
	udp_port := next_port(r)
	user := "\n  user: nobody" if root else ""
	config := base_config(
		udp_port,
		fmt.tprintf(`[{{ name: named, type: udp, address: %q, port: 53 }}]`, HOST),
		log = "{ level: info }",
		upstream_extra = fmt.tprintf(`  bootstrap: ["127.0.0.1:%d"]`, boot.port),
		blocking = fmt.tprintf(
			`{{ enabled: true, cache_dir: %q, lists: ["http://127.0.0.1:%d/order.txt"] }}`,
			fmt.tprintf("%s/order-cache", r.work_dir),
			http_port,
		),
		extra = fmt.tprintf("server:\n  sandbox: %s%s", suite_sandbox(r), user),
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}
	defer stop_server(&srv)
	if !check(r, wait_for_log(&srv, "msg=ready", 5 * time.Second), "the server never logged ready:\n%s", read_log(&srv)) {
		return
	}
	log := read_log(&srv)
	narrowed, found := narrowed_at(r, log, root)
	if !found {
		return
	}
	// The log escapes the quotes around the name.
	fetched := [2]string{`cannot resolve \"` + HOST + `\" via bootstrap resolvers`, "order.txt: downloading"}
	for line in fetched {
		at := strings.index(log, line)
		check(r, at > narrowed, "%q is at %d, not after the process was narrowed at %d:\n%s", line, at, narrowed, log)
	}
}
