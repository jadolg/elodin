package itest

import "core:c"
import "core:fmt"
import "core:strings"
import "elodin:tlsx"

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
		listeners_extra = fmt.tprintf(
			`  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
			dot_port,
			cert,
			key,
			doh_port,
			cert,
			key,
		),
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
	for row in rows {
		for doh in ([]bool{false, true}) {
			listener := "doh (h2)" if doh else "dot"
			verdict := fmt.tprintf("gets %s", row.chosen) if row.chosen != "" else "is refused"
			start_case(r, fmt.tprintf("%s: tls 1.2 offering %s %s", listener, row.offered, verdict))
			alpn: []string = {"h2"} if doh else nil
			chosen, agreed, ran := tls12_handshake(doh_port if doh else dot_port, row.offered, alpn)
			if check(r, ran, "this client could not offer %s", row.offered) {
				check(r, chosen == row.chosen, "negotiated %q, want %q", chosen, row.chosen)
				if chosen != "" && doh {
					check(r, agreed == "h2", "ALPN agreed %q, not h2", agreed)
				}
			}
			end_case(r)
		}
	}
}

/*
One TLS 1.2 handshake with `port` offering `offered`, and the suite and ALPN
protocol agreed; an empty suite is a refused handshake. `ran` is false when
this client could not be made to offer that list at all, which says nothing
about the server.
*/
@(private = "file")
tls12_handshake :: proc(port: int, offered: cstring, alpn: []string) -> (chosen, agreed: string, ran: bool) {
	ctx := raw_tls_context(tlsx.TLS1_2_VERSION, alpn) or_return
	defer tlsx.context_destroy(ctx)
	if tlsx.SSL_CTX_set_cipher_list(ctx.ptr, offered) != 1 {
		return "", "", false
	}
	conn, connected := raw_tls_connect(ctx, port)
	if !connected {
		return "", "", true
	}
	defer raw_tls_close(conn)
	data: [^]u8
	n: c.uint
	tlsx.SSL_get0_alpn_selected(conn.ssl, &data, &n)
	chosen = strings.clone_from_cstring(SSL_CIPHER_get_name(SSL_get_current_cipher(conn.ssl)), context.temp_allocator)
	return chosen, strings.clone(string(data[:n]), context.temp_allocator), true
}

@(private = "file")
SSL_CIPHER :: struct {}

foreign import cipher_ssl "system:ssl"

@(default_calling_convention = "c")
foreign cipher_ssl {
	@(private = "file")
	SSL_get_current_cipher :: proc(ssl: ^tlsx.SSL) -> ^SSL_CIPHER ---
	@(private = "file")
	SSL_CIPHER_get_name :: proc(cipher: ^SSL_CIPHER) -> cstring ---
}
