package server

import "core:os"
import "core:testing"
import "elodin:config"
import "elodin:tlsx"

/*
`reload_tls` is exercised end-to-end (real SIGHUP, real renewed certificate) by
the itest suite's "tls certificate reload" cases; these cover the mechanism
directly and cheaply: the swap happens, the displaced context is not the one
callers now see, and a certificate that fails to load leaves the working one
in place rather than tearing it down.
*/

@(private = "file")
CERT_DIR :: "/tmp/elodin-server-reload-test"

// A certificate this test can point `reload_tls` at, reusing the one a
// developer already has in `certs/` and otherwise generating one - the same
// fallback `tlsx`'s own tests use, kept local because that helper is private
// to its package.
@(private = "file")
ensure_cert :: proc() -> (cert, key: string, ok: bool) {
	if os.exists("certs/cert.pem") && os.exists("certs/key.pem") {
		return "certs/cert.pem", "certs/key.pem", true
	}
	cert = CERT_DIR + "/cert.pem"
	key = CERT_DIR + "/key.pem"
	if os.exists(cert) && os.exists(key) {
		return cert, key, true
	}
	if !os.exists(CERT_DIR) {
		if err := os.make_directory(CERT_DIR); err != nil {
			return "", "", false
		}
	}
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
				key,
				"-out",
				cert,
				"-days",
				"2",
				"-subj",
				"/CN=elodin.local",
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
	return cert, key, true
}

@(test)
test_reload_tls_swaps_in_a_fresh_context :: proc(t: ^testing.T) {
	cert, key, ok := ensure_cert()
	if !ok {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	cfg := config.default_config()
	cfg.listeners.dot.cert_file = cert
	cfg.listeners.dot.key_file = key

	first, ferr := tlsx.server_context(cert, key, DOT_ALPN)
	if ferr != .None {
		testing.expectf(t, false, "server_context: %v", ferr)
		return
	}

	l := Listeners{}
	l.dot_ctx = first
	l.dot_open = true
	s := Server{cfg = &cfg}
	defer tlsx.context_destroy(l.dot_ctx)

	testing.expect(t, reload_tls(&s, &l), "reload_tls reported failure against a certificate that loads fine")
	testing.expect(
		t,
		l.dot_ctx != first,
		"reload_tls left the old context in place instead of swapping in a freshly loaded one",
	)
}

@(test)
test_reload_tls_keeps_the_working_context_when_the_new_certificate_does_not_load :: proc(t: ^testing.T) {
	cert, key, ok := ensure_cert()
	if !ok {
		testing.expect(t, false, "no certificate available and openssl could not make one")
		return
	}

	working, werr := tlsx.server_context(cert, key, DOT_ALPN)
	if werr != .None {
		testing.expectf(t, false, "server_context: %v", werr)
		return
	}

	cfg := config.default_config()
	// A path nothing wrote to: the same shape of failure as a renewal that
	// never landed, or landed with the wrong permissions.
	cfg.listeners.dot.cert_file = "/nonexistent/cert.pem"
	cfg.listeners.dot.key_file = "/nonexistent/key.pem"

	l := Listeners{}
	l.dot_ctx = working
	l.dot_open = true
	s := Server{cfg = &cfg}
	defer tlsx.context_destroy(l.dot_ctx)

	testing.expect(t, !reload_tls(&s, &l), "reload_tls reported success loading a certificate that does not exist")
	testing.expect_value(t, l.dot_ctx, working)
}

@(test)
test_reload_tls_does_nothing_for_a_listener_that_is_not_open :: proc(t: ^testing.T) {
	cfg := config.default_config()
	// Deliberately bad: proves this is skipped for being closed, not merely
	// tolerated because the certificate happens to load.
	cfg.listeners.dot.cert_file = "/nonexistent/cert.pem"
	cfg.listeners.doh.cert_file = "/nonexistent/cert.pem"

	l := Listeners{}
	s := Server{cfg = &cfg}

	testing.expect(t, reload_tls(&s, &l), "reload_tls tried to load a certificate for a listener that was never opened")
	testing.expect(t, l.dot_ctx == nil, "a context appeared for a listener that was never opened")
	testing.expect(t, l.doh_ctx == nil, "a context appeared for a listener that was never opened")
}
