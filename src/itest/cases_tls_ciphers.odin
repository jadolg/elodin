package itest

import "core:fmt"

/*
Issue #687: over TLS 1.2 the DoT and DoH listeners negotiate ECDHE with an AEAD
cipher and nothing else. Static RSA gives no forward secrecy (RFC 9325 section
4.1), and CBC is allowed only with encrypt_then_mac (RFC 9325 section 4.2) and
forbidden for HTTP/2 outright (RFC 9113 Appendix A), which DoH negotiates.

The listeners serve an RSA certificate here, since static RSA needs one: with
the suite's usual P-256 pair every `Kx=RSA` row would be refused for the key
alone. Each row offers one TLS 1.2 suite, ALPN h2 on DoH; an accepted row
checks that h2 was what DoH agreed.
*/
run_tls_cipher_cases :: proc(r: ^Runner) {
	cert := fmt.aprintf("%s/cipher-rsa-cert.pem", r.work_dir)
	key := fmt.aprintf("%s/cipher-rsa-key.pem", r.work_dir)
	if !generate_named_cert(cert, key, "elodin.local", rsa = true) {
		skip_case(r, "tls 1.2 ciphers", "openssl could not produce an RSA test certificate")
		return
	}

	udp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(next_port(r)),
		listeners_extra = fmt.tprintf("%s\n%s", dot_listener(r, dot_port, cert = cert, key = key), doh_listener(r, doh_port, cert = cert, key = key)),
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port, dot_port = dot_port, doh_port = doh_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	rows := []struct {
		offered: cstring,
		// The suite the server picks, or "" for a refused handshake.
		chosen:  string,
	} {
		{offered = "ECDHE-RSA-AES128-GCM-SHA256", chosen = "ECDHE-RSA-AES128-GCM-SHA256"},
		{offered = "ECDHE-RSA-AES256-GCM-SHA384", chosen = "ECDHE-RSA-AES256-GCM-SHA384"},
		{offered = "ECDHE-RSA-CHACHA20-POLY1305", chosen = "ECDHE-RSA-CHACHA20-POLY1305"},
		// Static RSA: CBC, then AEAD.
		{offered = "AES128-SHA", chosen = ""},
		{offered = "AES256-GCM-SHA384", chosen = ""},
		// ECDHE, CBC.
		{offered = "ECDHE-RSA-AES128-SHA", chosen = ""},
		{offered = "ECDHE-RSA-AES256-SHA384", chosen = ""},
		// The server's order over the client's (RFC 9325 section 4.2)...
		{offered = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256", chosen = "ECDHE-RSA-AES128-GCM-SHA256"},
		// ...except that a client putting ChaCha20 first keeps it.
		{offered = "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256", chosen = "ECDHE-RSA-CHACHA20-POLY1305"},
		{offered = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305", chosen = "ECDHE-RSA-AES256-GCM-SHA384"},
	}
	/*
	TLS 1.3 by the same order: AES-128-GCM over AES-256-GCM, and ChaCha20 for a
	client putting it first. OpenSSL's own TLS 1.3 list starts with AES-256.
	*/
	rows13 := []struct {
		offered: cstring,
		chosen:  string,
	} {
		{offered = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256", chosen = "TLS_AES_128_GCM_SHA256"},
		{offered = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256", chosen = "TLS_CHACHA20_POLY1305_SHA256"},
	}
	for row in rows13 {
		start_case(r, fmt.tprintf("dot: tls 1.3 offering %s gets %s", row.offered, row.chosen))
		chosen, _, failed := tls_handshake(dot_port, row.offered, nil, tls13 = true)
		if check(r, failed == "", "%s", failed) {
			check(r, chosen == row.chosen, "negotiated %q, want %q", chosen, row.chosen)
		}
		end_case(r)
	}
	for row in rows {
		for doh in ([]bool{false, true}) {
			listener := "doh (h2)" if doh else "dot"
			verdict := fmt.tprintf("gets %s", row.chosen) if row.chosen != "" else "is refused"
			start_case(r, fmt.tprintf("%s: tls 1.2 offering %s %s", listener, row.offered, verdict))
			alpn: []string = {"h2"} if doh else nil
			chosen, agreed, failed := tls_handshake(doh_port if doh else dot_port, row.offered, alpn)
			if check(r, failed == "", "%s", failed) {
				check(r, chosen == row.chosen, "negotiated %q, want %q", chosen, row.chosen)
				if chosen != "" && doh {
					check(r, agreed == "h2", "ALPN agreed %q, not h2", agreed)
				}
			}
			end_case(r)
		}
	}
}
