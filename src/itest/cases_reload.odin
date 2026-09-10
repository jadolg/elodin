package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:time"
import "elodin:tlsx"

/*
SIGHUP must swap in a certificate renewed on disk without a restart.

Two distinct self-signed pairs are generated up front - "reload-a" and
"reload-b" - and a verifying client that trusts only one of them is the probe:
it can only complete a handshake against the pair the server is actually
presenting right now, so it proves which certificate is live far more directly
than reading the log would.
*/

@(private = "file")
config_for_reload :: proc(udp_port, dot_port, doh_port: int, cert_file, key_file: string) -> string {
	return fmt.tprintf(
		`log: {{ level: debug }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
upstream:
  timeout: 2s
  servers: ["127.0.0.1:1"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		udp_port,
		dot_port,
		cert_file,
		key_file,
		doh_port,
		cert_file,
		key_file,
	)
}

// A self-signed pair naming `name` in both CN and SAN, so a verifying client
// dialling `name` accepts one and refuses the other.
@(private = "file")
generate_named_cert :: proc(cert_path, key_path, name: string) -> bool {
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
				fmt.tprintf("/CN=%s", name),
				"-addext",
				fmt.tprintf("subjectAltName=DNS:%s", name),
			},
		},
	)
	if perr != nil {
		return false
	}
	state, werr := os.process_wait(process)
	return werr == nil && state.exit_code == 0
}

// Overwrite `dst` with `src`'s bytes, the way a renewal tool replaces a
// certificate file in place.
@(private = "file")
install_cert :: proc(dst, src: string) -> bool {
	data, err := os.read_entire_file(src, context.temp_allocator)
	if err != nil {
		return false
	}
	return os.write_entire_file(dst, data) == nil
}

// Complete a DoT handshake verifying the peer against `ca_file`, under the
// name the corresponding certificate was issued for. `false` covers both "no
// connection" and "the certificate presented was not the one trusted" - the
// suite only ever needs to tell "the expected certificate is live" from
// "it is not".
@(private = "file")
dot_handshake_verifies :: proc(dot_port: int, ca_file, hostname: string) -> bool {
	socket, derr := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = dot_port})
	if derr != nil {
		return false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
	_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

	ctx, cerr := tlsx.client_context(true, ca_file, nil, context.temp_allocator)
	if cerr != .None {
		return false
	}
	defer tlsx.context_destroy(ctx)

	conn, terr := tlsx.client_connect(ctx, socket, hostname)
	if terr != .None {
		return false
	}
	tlsx.close(conn)
	return true
}

// Retries the probe rather than sleeping a fixed amount: the reload is
// noticed on the maintenance loop's 200ms poll, which is fast but not
// instant, and a fixed sleep would either race it or pad every run.
@(private = "file")
wait_for_handshake :: proc(dot_port: int, ca_file, hostname: string, within: time.Duration) -> bool {
	deadline := time.time_add(time.now(), within)
	for time.diff(time.now(), deadline) > 0 {
		if dot_handshake_verifies(dot_port, ca_file, hostname) {
			return true
		}
		time.sleep(50 * time.Millisecond)
	}
	return false
}

run_reload_cases :: proc(r: ^Runner) {
	// Heap, not scratch: end_case resets the temp allocator between cases and
	// these paths are read again by every case in this function.
	cert_a := fmt.aprintf("%s/reload-a-cert.pem", r.work_dir)
	key_a := fmt.aprintf("%s/reload-a-key.pem", r.work_dir)
	cert_b := fmt.aprintf("%s/reload-b-cert.pem", r.work_dir)
	key_b := fmt.aprintf("%s/reload-b-key.pem", r.work_dir)
	if !generate_named_cert(cert_a, key_a, "reload-a.test") || !generate_named_cert(cert_b, key_b, "reload-b.test") {
		skip_case(r, "tls reload", "openssl could not produce the test certificates")
		return
	}

	// The path the server is told about; its content is swapped in place,
	// which is what a renewal does and what start_dot/reload_tls must agree on
	// serving from moment to moment.
	active_cert := fmt.aprintf("%s/reload-active-cert.pem", r.work_dir)
	active_key := fmt.aprintf("%s/reload-active-key.pem", r.work_dir)
	if !install_cert(active_cert, cert_a) || !install_cert(active_key, key_a) {
		skip_case(r, "tls reload", "cannot stage the initial certificate")
		return
	}

	udp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_for_reload(udp_port, dot_port, doh_port, active_cert, active_key),
			udp_port = udp_port,
			dot_port = dot_port,
			// Named because the profile cases below dial it: the listeners bind
			// in sequence and doh is the last of them, so answering over dot
			// says nothing yet about whether doh is up.
			doh_port = doh_port,
		},
	)
	if !ok {
		skip_case(r, "tls reload", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "tls reload: serves the certificate it started with")
	{
		check(r, dot_handshake_verifies(dot_port, cert_a, "reload-a.test"), "the initial certificate did not verify")
		check(
			r,
			!dot_handshake_verifies(dot_port, cert_b, "reload-b.test"),
			"the server accepted a certificate it was never given",
		)
	}
	end_case(r)

	/*
	The Apple profile is signed by the certificate the listener is presenting.

	`cms_verify` is handed the certificate the signature must chain to, so passing
	the one that is live and then the one that is not is what makes this an
	assertion about *which* key signed rather than about whether anything did.
	*/
	start_case(r, "tls reload: the Apple profile is signed by the certificate in use")
	{
		res := doh_raw(
			doh_port,
			"GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: reload-a.test\r\nConnection: close\r\n\r\n",
		)
		if check(r, res.ok, "no HTTP response") && check_eq_int(r, res.status, 200, "status") {
			_, by_a := cms_verify(r, res.body, cert_a)
			check(r, by_a, "the profile is not signed by the certificate the listener started with")
			_, by_b := cms_verify(r, res.body, cert_b)
			check(r, !by_b, "the profile verified against a certificate the server was never given")
		}
	}
	end_case(r)

	start_case(r, "tls reload: SIGHUP swaps in a certificate renewed on disk")
	{
		installed := install_cert(active_cert, cert_b) && install_cert(active_key, key_b)
		if check(r, installed, "cannot install the renewed certificate") &&
		   check(r, signal_reload(&srv), "could not deliver SIGHUP") &&
		   check(r, wait_for_handshake(dot_port, cert_b, "reload-b.test", 3 * time.Second), "the renewed certificate never came into effect") {
			check(
				r,
				!dot_handshake_verifies(dot_port, cert_a, "reload-a.test"),
				"the old certificate is still being served after reload",
			)
			// Polled, not read once: the handshake above goes through the moment
			// the context is swapped, and the log line the reload writes can reach
			// the file a beat later, so a single read races it on a loaded runner.
			check(r, wait_for_log(&srv, "reloaded the certificate", 2 * time.Second), "no reload was logged")
		}
	}
	end_case(r)

	/*
	The renewal reaches the profile endpoint too, and takes the old profiles with
	it.

	This is the case the signing had to not break: the profile is signed with the
	listener's own certificate and kept in a cache, so a renewal has to move the
	signing identity *and* drop everything signed with the one before it. A cache
	that survived the swap would answer this with a profile signed by a key the
	listener has stopped presenting - and would do it for a name the new
	certificate no longer covers, which is the second half of this case.
	*/
	start_case(r, "tls reload: the renewed certificate signs the Apple profile")
	{
		res := doh_raw(
			doh_port,
			"GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: reload-b.test\r\nConnection: close\r\n\r\n",
		)
		if check(r, res.ok, "no HTTP response") && check_eq_int(r, res.status, 200, "status") {
			_, by_b := cms_verify(r, res.body, cert_b)
			check(r, by_b, "the profile is not signed by the renewed certificate")
			_, by_a := cms_verify(r, res.body, cert_a)
			check(r, !by_a, "the profile is still signed by the certificate that was replaced")
		}

		// Warmed into the cache before the reload, and no longer a name the
		// certificate covers after it.
		stale := doh_raw(
			doh_port,
			"GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: reload-a.test\r\nConnection: close\r\n\r\n",
		)
		check(r, stale.ok, "no HTTP response")
		check_eq_int(r, stale.status, 400, "status for the replaced certificate's name")
	}
	end_case(r)

	start_case(r, "tls reload: a connection held across the reload still negotiates ALPN")
	{
		/*
		The listener's ALPN preference list is read by OpenSSL on every
		handshake, out of memory the `SSL_CTX` points at. A connection takes its
		reference to that context when it is accepted; the ClientHello that makes
		the selection callback run arrives whenever the client chooses to send
		it, deliberately outside the lock the reload holds. So a connection
		opened before a SIGHUP and handshaken after it is where that list has to
		still be there - and where, while it was freed along with the wrapper the
		reload releases, the callback walked reclaimed heap and OpenSSL copied
		what it found into the ServerHello.

		Nothing on disk changes here: a reload rebuilds the context and releases
		the displaced one whether or not the certificate is new, which is the
		whole of what this case needs.
		*/
		socket, derr := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = dot_port})
		if check(r, derr == nil, "cannot open a connection to the DoT port") {
			held: ^tlsx.Conn
			defer {
				if held != nil {
					tlsx.close(held)
				} else {
					net.close(socket)
				}
			}
			_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
			_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)

			// A whole handshake on a second connection, to place the one above
			// well inside the server. One accept loop serves this listener and
			// spawns a thread per connection in the order they arrive, so a
			// later connection completing a whole handshake says the earlier
			// one's thread was started before it. What that does not order is
			// that thread reaching `server_session`, which is where the
			// reference to the current context is taken; what covers the rest
			// is the reload being a maintenance-loop poll - 200ms - further
			// away still.
			check(
				r,
				dot_handshake_verifies(dot_port, cert_b, "reload-b.test"),
				"the server stopped completing handshakes",
			)

			reloads := log_count(&srv, "reloaded the certificate")
			if check(r, signal_reload(&srv), "could not deliver SIGHUP") &&
			   check(
					   r,
					   wait_for_log_count(&srv, "reloaded the certificate", reloads + 1, 3 * time.Second),
					   "the reload never completed",
				   ) {
				// Verification off: the certificate either side of this reload is
				// the same one, and what is under test is the ALPN list.
				ctx, cerr := tlsx.client_context(false, "", []string{"dot"}, context.temp_allocator)
				if check(r, cerr == .None, "cannot build the client context") {
					defer tlsx.context_destroy(ctx)
					conn, terr := tlsx.client_connect(ctx, socket, "")
					if check(r, terr == .None, "the handshake failed after the reload it was held across") {
						held = conn
						check(
							r,
							tlsx.alpn_protocol(conn) == "dot",
							"the reloaded listener did not select the protocol it advertises",
						)
					}
				}
			}
		}
	}
	end_case(r)

	start_case(r, "tls reload: a bad certificate on disk leaves the working one in place")
	{
		// A truncated key: openssl will not load it, which is what a renewal
		// caught mid-write or a bad file permission would also look like.
		corrupted := os.write_entire_file(active_key, transmute([]u8)string("not a key")) == nil
		if check(r, corrupted, "cannot corrupt the key file") && check(r, signal_reload(&srv), "could not deliver SIGHUP") {
			// The maintenance loop notices the signal on its 200ms poll, tries
			// the bad certificate and refuses to load it. That refusal is the log
			// line, so poll for it rather than sleeping a fixed amount and reading
			// once; its appearance is also what says the reload attempt is over,
			// so the handshake check below is not racing an in-flight swap.
			if check(
				r,
				wait_for_log(&srv, "keeping the certificate already in use", 2 * time.Second),
				"the bad reload was not logged",
			) {
				check(
					r,
					dot_handshake_verifies(dot_port, cert_b, "reload-b.test"),
					"a certificate that failed to load knocked out the one already serving",
				)
			}
		}
	}
	end_case(r)
}
