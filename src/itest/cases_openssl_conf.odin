package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
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
This process's environment with OPENSSL_CONF naming `path`, and with no
OPENSSL_CONF of its own, so the server reads the case's file whatever the suite
was started with.
*/
@(private = "file")
env_with_openssl_conf :: proc(r: ^Runner, name, path: string) -> (env: []string, ok: bool) {
	inherited, eerr := os.environ(context.temp_allocator)
	if eerr != nil {
		fail(r, "%s: cannot read the environment: %v", name, eerr)
		return
	}
	kept := make([dynamic]string, 0, len(inherited) + 1, context.temp_allocator)
	for kv in inherited {
		if !strings.has_prefix(kv, "OPENSSL_CONF=") {
			append(&kept, kv)
		}
	}
	append(&kept, fmt.tprintf("OPENSSL_CONF=%s", path))
	return kept[:], true
}

// Write `text` to `file` in the work directory and return its path.
@(private = "file")
write_conf :: proc(r: ^Runner, name, file, text: string) -> (path: string, ok: bool) {
	path = filepath.join({r.work_dir, file}, context.temp_allocator) or_else ""
	if werr := os.write_entire_file(path, transmute([]u8)text); werr != nil {
		fail(r, "%s: cannot write %s: %v", name, path, werr)
		return "", false
	}
	return path, true
}

/*
Start the server with OPENSSL_CONF naming `conf`, and check its DoT listener
answers. `srv` is the started server for the caller to stop; `ok` false means
the case has already failed.
*/
@(private = "file")
start_with_conf :: proc(r: ^Runner, name, conf: string) -> (srv: Server, ok: bool) {
	env := env_with_openssl_conf(r, name, conf) or_return
	udp_port, dot_port := next_port(r), next_port(r)
	srv = start_server(
		r,
		Server_Options{config = openssl_conf_config(r, udp_port, dot_port), udp_port = udp_port, dot_port = dot_port, env = env},
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
		static, static_ok := binary_is_static(r, NAME)
		conf, conf_ok := write_conf(r, NAME, "openssl-capped.cnf", CAPPED_CONF)
		if static_ok && conf_ok {
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
		static, static_ok := binary_is_static(r, NAME)
		conf, conf_ok := write_conf(r, NAME, "openssl-refused.cnf", REFUSED_CONF)
		if static_ok && conf_ok {
			start_case(r, NAME)
			if srv, ok := start_with_conf(r, NAME, conf); ok {
				defer stop_server(&srv)
				warned := log_contains(&srv, REFUSED_WARNING)
				check(r, warned == !static, "static %v: warned %v; log:\n%s", static, warned, read_log(&srv))
				if !static {
					// OpenSSL's own reason rides along, so the operator knows what to fix.
					check(r, log_contains(&srv, "unknown option"), "the warning does not carry OpenSSL's reason; log:\n%s", read_log(&srv))
				}
			}
			end_case(r)
		}
	}
}
