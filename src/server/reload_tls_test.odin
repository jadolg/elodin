package server

import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
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

@(private = "file")
cert_once: sync.Once
@(private = "file")
cert_path: string
@(private = "file")
key_path: string
@(private = "file")
cert_ok: bool

@(private = "file")
generate_cert :: proc() {
	if os.exists("certs/cert.pem") && os.exists("certs/key.pem") {
		cert_path, key_path, cert_ok = "certs/cert.pem", "certs/key.pem", true
		return
	}
	cert_path = CERT_DIR + "/cert.pem"
	key_path = CERT_DIR + "/key.pem"
	if !os.exists(CERT_DIR) {
		if err := os.make_directory(CERT_DIR); err != nil {
			return
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
				key_path,
				"-out",
				cert_path,
				"-days",
				"2",
				"-subj",
				"/CN=elodin.local",
			},
		},
	)
	if perr != nil {
		return
	}
	state, werr := os.process_wait(process)
	if werr != nil || state.exit_code != 0 {
		return
	}
	cert_ok = true
}

// A certificate this test can point `reload_tls` at, reusing the one a
// developer already has in `certs/` and otherwise generating one - the same
// fallback `tlsx`'s own tests use, kept local because that helper is private
// to its package.
//
// Generated once and shared: the test runner runs these concurrently, and two
// threads racing `openssl` over the same output files corrupted them often
// enough in CI to fail a test that never touches the generation path itself.
@(private = "file")
ensure_cert :: proc() -> (cert, key: string, ok: bool) {
	sync.once_do(&cert_once, generate_cert)
	return cert_path, key_path, cert_ok
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

@(private = "file")
Reload_Race :: struct {
	server:    ^Server,
	listeners: ^Listeners,
	// Written once the reload has returned; read by the test while it waits.
	finished:  bool,
}

/*
A reload must not release the context while a connection is still taking a
reference from it.

This is the whole of the bug that was here. `reload_tls` freed the context it
displaced the moment it had swapped a new one in, and `accept_tls` reads that
pointer and dereferences it in `tlsx.server_session` a few instructions later —
so a SIGHUP landing in between left a connection thread calling `SSL_new` on
freed memory. Under ASan and with the window widened to a couple of
milliseconds it is a `heap-use-after-free` that ends the process; in production
it is a rare crash on the one operation an operator is told is safe to automate.

What closes it is that `accept_tls` holds `tls_mu` shared across the pointer
read and `SSL_new`, and the reload takes it exclusively to swap and free. So the
property to hold onto is an ordering one, and it is what this asserts: while
something holds the reader's side, the reload does not get as far as replacing
the context, let alone freeing it.

The wait is generous and only ever fails in the safe direction — a reload thread
that has not reached the lock yet looks the same as one correctly blocked on it,
so this cannot report a failure that is not there.
*/
@(test)
test_reload_tls_waits_for_a_connection_holding_the_context :: proc(t: ^testing.T) {
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

	// Stand in for a connection thread that has read the context and not yet
	// finished taking its reference — the state `accept_tls` is in while it
	// holds the shared lock.
	sync.rw_mutex_shared_lock(&l.tls_mu)

	race := Reload_Race {
		server    = &s,
		listeners = &l,
	}
	worker := thread.create_and_start_with_poly_data(&race, proc(race: ^Reload_Race) {
		reload_tls(race.server, race.listeners)
		sync.atomic_store(&race.finished, true)
	})

	time.sleep(200 * time.Millisecond)
	testing.expect(
		t,
		!sync.atomic_load(&race.finished),
		"reload_tls ran to completion while a connection still held the context it frees",
	)
	testing.expect_value(t, l.dot_ctx, first)

	sync.rw_mutex_shared_unlock(&l.tls_mu)
	thread.join(worker)
	thread.destroy(worker)

	testing.expect(t, sync.atomic_load(&race.finished), "reload_tls never finished after the connection let go")
	testing.expect(t, l.dot_ctx != first, "reload_tls did not swap the context in once it could")
}
