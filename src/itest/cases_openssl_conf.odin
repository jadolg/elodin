package itest

import "core:fmt"
import "core:os"
import "core:time"
import "elodin:dns"
import "elodin:tlsx"

/*
The host's OpenSSL configuration and the two builds (#512).

A dynamic build runs on the host's OpenSSL and applies its `openssl.cnf`, and
says so at startup when OpenSSL refuses the file. The static build carries an
OpenSSL of its own, for which the host's file was never written, and does not
read it at all. Both are driven through OPENSSL_CONF, which names the file
OpenSSL reads in place of the system one: a file that caps TLS at 1.2, which
the server's listener shows or not, and a file OpenSSL refuses for an option it
does not know, as an upstream OpenSSL refuses openSUSE's vendor-patched EVP
property.
*/

// Read by OpenSSL when it loads a configuration: a ceiling of TLS 1.2 on every
// context, the server's listener among them.
@(private = "file")
CAPPED_CONF :: `openssl_conf = elodin_itest
[elodin_itest]
ssl_conf = elodin_ssl
[elodin_ssl]
system_default = elodin_system
[elodin_system]
MaxProtocol = TLSv1.2
`

// A host policy stricter than elodin's TLS 1.2 list: AES-256-GCM only (#687).
@(private = "file")
NARROWED_CONF :: `openssl_conf = elodin_itest
[elodin_itest]
ssl_conf = elodin_ssl
[elodin_ssl]
system_default = elodin_system
[elodin_system]
CipherString = ECDHE+AES256+AESGCM
`

// A host policy stricter than elodin's floor: TLS 1.3 only (#687).
@(private = "file")
FLOOR_CONF :: `openssl_conf = elodin_itest
[elodin_itest]
ssl_conf = elodin_ssl
[elodin_ssl]
system_default = elodin_system
[elodin_system]
MinProtocol = TLSv1.3
`

// A host policy that leaves elodin nothing: no suite of its own over TLS 1.2,
// and no TLS 1.3 (#687).
@(private = "file")
NOTHING_LEFT_CONF :: `openssl_conf = elodin_itest
[elodin_itest]
ssl_conf = elodin_ssl
[elodin_ssl]
system_default = elodin_system
[elodin_system]
CipherString = ECDHE-ECDSA-AES128-SHA
MaxProtocol = TLSv1.2
`

// An EVP property no OpenSSL knows. `config_diagnostics`, which openSUSE's file
// also sets, makes that an initialisation failure rather than a module skipped.
@(private = "file")
REFUSED_CONF :: `config_diagnostics = 1
openssl_conf = elodin_itest
[elodin_itest]
alg_section = elodin_evp
[elodin_evp]
elodin-itest-unknown-option = yes
`

// The start of the warning `openssl_init_warning` in src/main logs.
@(private = "file")
REFUSED_WARNING :: "OpenSSL could not apply its configuration"

@(private = "file")
openssl_conf_config :: proc(r: ^Runner, udp_port, dot_port: int) -> string {
	return base_config(
		udp_port,
		upstream_at(next_port(r)),
		log = "{ level: info }",
		listeners_extra = fmt.tprintf(
			`  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}`,
			dot_port,
			r.cert_file,
			r.key_file,
		),
		extra = "rewrites:\n  - domain: conf.test\n    answers: [192.0.2.7]",
	)
}

/*
Start the server with OPENSSL_CONF naming `conf`, and check its DoT listener
answers. `srv` is the started server for the caller to stop; `ok` false means
the case has already failed.
*/
@(private = "file")
start_with_conf :: proc(r: ^Runner, name, conf: string) -> (srv: Server, ok: bool) {
	// The suite's own OPENSSL_CONF, if it has one, is dropped for the case's.
	env := environ_without(r, name, {"OPENSSL_CONF="}, extra = 1) or_return
	append(&env, fmt.tprintf("OPENSSL_CONF=%s", conf))
	udp_port, dot_port := next_port(r), next_port(r)
	srv = start_server(
		r,
		Server_Options{config = openssl_conf_config(r, udp_port, dot_port), udp_port = udp_port, dot_port = dot_port, env = env[:]},
	) or_return
	res := query_dot(dot_port, build_query("conf.test.", u16(dns.Type.A), allocator = context.temp_allocator), context.temp_allocator)
	if !check(r, res.ok, "%s: no answer over DoT; log:\n%s", name, read_log(&srv)) {
		stop_server(&srv)
		return {}, false
	}
	return srv, true
}

run_openssl_conf_cases :: proc(r: ^Runner) {
	{
		NAME :: "tls: a dynamic build applies the host's openssl.cnf, the static build does not (#512)"
		static := r.static
		if conf, conf_ok := write_work_file(r, "openssl-capped.cnf", CAPPED_CONF); conf_ok {
			start_case(r, NAME)
			if srv, ok := start_with_conf(r, NAME, conf); ok {
				defer stop_server(&srv)
				want := tlsx.TLS1_3_VERSION if static else tlsx.TLS1_2_VERSION
				version, shook := tls_version_at(srv.dot_port)
				if check(r, shook, "no TLS handshake with the DoT listener") {
					check(r, version == want, "static %v: the listener settled on TLS %x, want %x", static, version, want)
				}
			}
			end_case(r)
		}
	}
	{
		NAME :: "tls: an openssl.cnf OpenSSL refuses is warned about by a dynamic build, and DoT still serves (#512)"
		static := r.static
		if conf, conf_ok := write_work_file(r, "openssl-refused.cnf", REFUSED_CONF); conf_ok {
			start_case(r, NAME)
			if srv, ok := start_with_conf(r, NAME, conf); ok {
				defer stop_server(&srv)
				warned := log_contains(&srv, REFUSED_WARNING)
				check(r, warned == !static, "static %v: warned %v; log:\n%s", static, warned, read_log(&srv))
				// OpenSSL's own reason rides along, so the operator knows what to
				// fix; a static build, which never reads the file, has none to log
				// under any wording.
				reason := log_contains(&srv, "unknown option")
				check(r, reason == !static, "static %v: OpenSSL's reason logged %v; log:\n%s", static, reason, read_log(&srv))
			}
			end_case(r)
		}
	}
	{
		NAME :: "tls: a host policy narrower than elodin's tls 1.2 suites stays narrow in a dynamic build (#687)"
		static := r.static
		if conf, conf_ok := write_work_file(r, "openssl-narrowed.cnf", NARROWED_CONF); conf_ok {
			start_case(r, NAME)
			if srv, ok := start_with_conf(r, NAME, conf); ok {
				defer stop_server(&srv)
				// The policy's own suite, which elodin's list holds too.
				chosen, _, failed := tls_handshake(srv.dot_port, "ECDHE-ECDSA-AES256-GCM-SHA384", nil)
				if check(r, failed == "", "%s", failed) {
					check(r, chosen == "ECDHE-ECDSA-AES256-GCM-SHA384", "the policy's own suite: negotiated %q", chosen)
				}
				// One elodin's list holds and the policy does not.
				chosen, _, failed = tls_handshake(srv.dot_port, "ECDHE-ECDSA-AES128-GCM-SHA256", nil)
				if check(r, failed == "", "%s", failed) {
					want := "ECDHE-ECDSA-AES128-GCM-SHA256" if static else ""
					check(r, chosen == want, "static %v: a suite the policy left out: negotiated %q, want %q", static, chosen, want)
				}
			}
			end_case(r)
		}
	}
	{
		NAME :: "tls: a host policy's tls 1.3 floor stays in a dynamic build (#687)"
		static := r.static
		if conf, conf_ok := write_work_file(r, "openssl-floor.cnf", FLOOR_CONF); conf_ok {
			start_case(r, NAME)
			if srv, ok := start_with_conf(r, NAME, conf); ok {
				defer stop_server(&srv)
				chosen, _, failed := tls_handshake(srv.dot_port, "ECDHE-ECDSA-AES128-GCM-SHA256", nil)
				if check(r, failed == "", "%s", failed) {
					want := "ECDHE-ECDSA-AES128-GCM-SHA256" if static else ""
					check(r, chosen == want, "static %v: a TLS 1.2 client negotiated %q, want %q", static, chosen, want)
				}
			}
			end_case(r)
		}
	}
	{
		NAME :: "tls: a host policy leaving no suite and no tls 1.3 stops a dynamic build at startup, naming why (#687)"
		if conf, conf_ok := write_work_file(r, "openssl-nothing-left.cnf", NOTHING_LEFT_CONF); conf_ok {
			start_case(r, NAME)
			if r.static {
				// The static build reads no openssl.cnf, so it serves as ever.
				if srv, ok := start_with_conf(r, NAME, conf); ok {
					stop_server(&srv)
				}
			} else if env, env_ok := environ_without(r, NAME, {"OPENSSL_CONF="}, extra = 1); env_ok {
				append(&env, fmt.tprintf("OPENSSL_CONF=%s", conf))
				udp_port, dot_port := next_port(r), next_port(r)
				srv, started := start_server_raw(r, openssl_conf_config(r, udp_port, dot_port), udp_port, env = env[:])
				if check(r, started, "cannot start the binary") {
					defer stop_server(&srv)
					state, werr := os.process_wait(srv.process, 10 * time.Second)
					if check(r, werr == nil && state.exited, "the server started with no TLS it could speak") {
						srv.running = false
						check(r, state.exit_code != 0, "the refusal exited 0")
						check(r, log_contains(&srv, "No_Suite"), "the refusal does not say why:\n%s", read_log(&srv))
					}
				}
			}
			end_case(r)
		}
	}
}
