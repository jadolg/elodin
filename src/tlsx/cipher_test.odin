package tlsx

import "core:c"
import "core:testing"

/*
Over TLS 1.2, both ends offer ECDHE key exchange with an AEAD cipher and nothing
else: no static RSA (RFC 9325 section 4.1), and no CBC, which RFC 9325 section
4.2 allows only with encrypt_then_mac and RFC 9113 Appendix A forbids for HTTP/2
outright. TLS 1.3's suites are all of that shape and carry no key exchange of
their own (`NID_kx_any`). The server picks by its own order (RFC 9325 section
4.2).
*/
@(test)
test_tls12_offers_only_ecdhe_with_aead :: proc(t: ^testing.T) {
	cert, key, have := ensure_certs()
	if !testing.expect(t, have, "no test certificate") {
		return
	}
	server, serr := server_context(cert, key)
	if !testing.expectf(t, serr == .None, "server context: %v", serr) {
		return
	}
	defer context_destroy(server)
	client, cerr := client_context(verify = false)
	if !testing.expectf(t, cerr == .None, "client context: %v", cerr) {
		return
	}
	defer context_destroy(client)

	for ctx, i in ([]^Context{server, client}) {
		end := "server" if i == 0 else "client"
		ciphers := SSL_CTX_get_ciphers(ctx.ptr)
		if !testing.expectf(t, ciphers != nil, "%s: no cipher list", end) {
			continue
		}
		tls12 := 0
		for j in 0 ..< OPENSSL_sk_num(ciphers) {
			cipher := OPENSSL_sk_value(ciphers, j)
			kx := SSL_CIPHER_get_kx_nid(cipher)
			if kx == NID_KX_ANY {
				continue
			}
			tls12 += 1
			testing.expectf(
				t,
				kx == NID_KX_ECDHE && SSL_CIPHER_is_aead(cipher) == 1,
				"%s offers %s over TLS 1.2",
				end,
				SSL_CIPHER_get_name(cipher),
			)
		}
		// Without this, an empty TLS 1.2 list would pass everything above.
		testing.expectf(t, tls12 > 0, "%s offers no TLS 1.2 suite at all", end)
	}
	testing.expect(t, SSL_CTX_get_options(server.ptr) & SSL_OP_CIPHER_SERVER_PREFERENCE != 0, "the server does not pick by its own order")
}

// From `<openssl/obj_mac.h>`.
@(private = "file")
NID_KX_ECDHE :: 1038
@(private = "file")
NID_KX_ANY :: 1063

@(private = "file")
SSL_CIPHER :: struct {}

foreign import cipher_ssl "system:ssl"
foreign import cipher_crypto "system:crypto"

@(default_calling_convention = "c")
foreign cipher_ssl {
	SSL_CTX_get_ciphers :: proc(ctx: ^SSL_CTX) -> rawptr ---
	SSL_CTX_get_options :: proc(ctx: ^SSL_CTX) -> u64 ---
	SSL_CIPHER_get_kx_nid :: proc(cipher: ^SSL_CIPHER) -> c.int ---
	SSL_CIPHER_is_aead :: proc(cipher: ^SSL_CIPHER) -> c.int ---
	SSL_CIPHER_get_name :: proc(cipher: ^SSL_CIPHER) -> cstring ---
}

@(default_calling_convention = "c")
foreign cipher_crypto {
	OPENSSL_sk_num :: proc(stack: rawptr) -> c.int ---
	@(link_name = "OPENSSL_sk_value")
	sk_cipher_value :: proc(stack: rawptr, i: c.int) -> ^SSL_CIPHER ---
}

@(private = "file")
OPENSSL_sk_value :: proc(stack: rawptr, i: c.int) -> ^SSL_CIPHER {
	return sk_cipher_value(stack, i)
}
