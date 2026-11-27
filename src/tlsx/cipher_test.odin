package tlsx

import "core:c"
import "core:log"
import "core:slice"
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
		// A host policy (`OPENSSL_CONF`) leaving none of the suites holds the
		// context to TLS 1.3; see `test_hold_to_floor_never_widens_a_host_policy`.
		if ssl_ctx_get_min_proto_version(ctx.ptr) >= TLS1_3_VERSION {
			log.infof("skipped for the %s: this host's OpenSSL policy leaves no TLS 1.2", end)
			continue
		}
		ciphers := SSL_CTX_get_ciphers(ctx.ptr)
		if !testing.expectf(t, ciphers != nil, "%s: no cipher list", end) {
			continue
		}
		tls12 := 0
		for j in 0 ..< OPENSSL_sk_num(ciphers) {
			cipher := (^SSL_CIPHER)(OPENSSL_sk_value(ciphers, j))
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

foreign import cipher_ssl "system:ssl"

@(default_calling_convention = "c")
foreign cipher_ssl {
	SSL_CIPHER_get_kx_nid :: proc(cipher: ^SSL_CIPHER) -> c.int ---
	SSL_CIPHER_is_aead :: proc(cipher: ^SSL_CIPHER) -> c.int ---
}

/*
`hold_to_floor` only ever narrows: a context a host policy already holds to
fewer suites, or to TLS 1.3, keeps that, and one that allows none of ours goes
to TLS 1.3 rather than to OpenSSL's default list, or is refused when the policy
caps TLS below 1.3 as well.
*/
@(test)
test_hold_to_floor_never_widens_a_host_policy :: proc(t: ^testing.T) {
	cases := []struct {
		name:      string,
		// What the host policy left the context with; "" leaves OpenSSL's.
		ciphers:   cstring,
		min:       c.long,
		max:       c.long,
		// The TLS 1.3 suites the policy left; nil leaves OpenSSL's.
		suites:    Maybe(cstring),
		want_err:  Error,
		want_min:  c.long,
		want_list: []string,
	} {
		{
			name = "OpenSSL's defaults",
			want_min = TLS1_2_VERSION,
			want_list = {
				"ECDHE-ECDSA-AES128-GCM-SHA256",
				"ECDHE-RSA-AES128-GCM-SHA256",
				"ECDHE-ECDSA-AES256-GCM-SHA384",
				"ECDHE-RSA-AES256-GCM-SHA384",
				"ECDHE-ECDSA-CHACHA20-POLY1305",
				"ECDHE-RSA-CHACHA20-POLY1305",
			},
		},
		{
			name = "a policy without AES-128 or ChaCha20",
			ciphers = "ECDHE+AES256+AESGCM:AES256-SHA",
			want_min = TLS1_2_VERSION,
			want_list = {"ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
		},
		{name = "a policy holding TLS 1.3 at least", min = TLS1_3_VERSION, want_min = TLS1_3_VERSION},
		{name = "a policy with none of ours over TLS 1.2", ciphers = "AES128-SHA", want_min = TLS1_3_VERSION},
		// Nothing left: no TLS 1.2 suite of ours within the bounds, and no
		// TLS 1.3.
		{name = "a CBC-only policy capped at TLS 1.2", ciphers = "ECDHE-RSA-AES128-SHA", max = TLS1_2_VERSION, want_err = .No_Suite},
		{name = "a CBC-only policy with no TLS 1.3 suite", ciphers = "ECDHE-RSA-AES128-SHA", suites = "", want_err = .No_Suite},
		{name = "a policy capped at TLS 1.1", max = 0x0302, want_err = .No_Suite},
		{name = "a TLS 1.3 floor with no TLS 1.3 suite", min = TLS1_3_VERSION, suites = "", want_err = .No_Suite},
	}
	for tc in cases {
		ptr := SSL_CTX_new(TLS_server_method())
		if !testing.expectf(t, ptr != nil, "%s: no context", tc.name) {
			return
		}
		defer SSL_CTX_free(ptr)
		if !testing.expectf(t, builtin_defaults(ptr), "%s: OpenSSL's defaults could not be restored", tc.name) {
			continue
		}
		if tc.ciphers != "" && !testing.expectf(t, SSL_CTX_set_cipher_list(ptr, tc.ciphers) == 1, "%s: the fixture's list was refused", tc.name) {
			continue
		}
		if tc.min != 0 && !testing.expectf(t, ssl_ctx_set_min_proto_version(ptr, tc.min), "%s: the fixture's floor was refused", tc.name) {
			continue
		}
		if tc.max != 0 && !testing.expectf(t, ssl_ctx_set_max_proto_version(ptr, tc.max), "%s: the fixture's ceiling was refused", tc.name) {
			continue
		}
		if suites, set := tc.suites.?; set && !testing.expectf(t, SSL_CTX_set_ciphersuites(ptr, suites) == 1, "%s: the fixture's TLS 1.3 suites were refused", tc.name) {
			continue
		}
		if err := hold_to_floor(ptr); !testing.expectf(t, err == tc.want_err, "%s: %v, want %v", tc.name, err, tc.want_err) || err != .None {
			continue
		}
		testing.expectf(t, ssl_ctx_get_min_proto_version(ptr) == tc.want_min, "%s: floor %x, want %x", tc.name, ssl_ctx_get_min_proto_version(ptr), tc.want_min)
		if tc.want_min == TLS1_3_VERSION {
			continue
		}
		got := suite_names(ptr, tls13 = false)
		defer delete(got)
		testing.expectf(t, slice.equal(got[:], tc.want_list), "%s: TLS 1.2 list %v, want %v", tc.name, got[:], tc.want_list)
	}
}

/*
`order_tls13` puts AES-128-GCM first among the TLS 1.3 suites a context allows,
and adds none: a list a host policy narrowed keeps only its own suites.
*/
@(test)
test_order_tls13_reorders_and_never_adds :: proc(t: ^testing.T) {
	cases := []struct {
		name:   string,
		suites: cstring,
		want:   []string,
	} {
		{
			name = "OpenSSL's default order",
			suites = OPENSSL_TLS13_DEFAULT,
			want = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		},
		{
			name = "a policy without AES-128-GCM, with CCM",
			suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_SHA256",
			want = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_CCM_SHA256"},
		},
		{name = "a policy with no TLS 1.3 suite", suites = "", want = {}},
	}
	for tc in cases {
		ptr := SSL_CTX_new(TLS_server_method())
		if !testing.expectf(t, ptr != nil, "%s: no context", tc.name) {
			return
		}
		defer SSL_CTX_free(ptr)
		if !testing.expectf(t, builtin_defaults(ptr) && SSL_CTX_set_ciphersuites(ptr, tc.suites) == 1, "%s: the fixture's suites were refused", tc.name) {
			continue
		}
		if err := order_tls13(ptr); !testing.expectf(t, err == .None, "%s: %v", tc.name, err) {
			continue
		}
		got := suite_names(ptr, tls13 = true)
		defer delete(got)
		testing.expectf(t, slice.equal(got[:], tc.want), "%s: TLS 1.3 order %v, want %v", tc.name, got[:], tc.want)
	}
}

// The names of `ptr`'s suites in its order: the TLS 1.3 ones, which name no key
// exchange (`NID_KX_ANY`), or the rest. The caller deletes the list.
@(private = "file")
suite_names :: proc(ptr: ^SSL_CTX, tls13: bool) -> [dynamic]string {
	names: [dynamic]string
	ciphers := SSL_CTX_get_ciphers(ptr)
	for j in 0 ..< OPENSSL_sk_num(ciphers) {
		cipher := (^SSL_CIPHER)(OPENSSL_sk_value(ciphers, j))
		if (SSL_CIPHER_get_kx_nid(cipher) == NID_KX_ANY) == tls13 {
			append(&names, string(SSL_CIPHER_get_name(cipher)))
		}
	}
	return names
}

// OpenSSL's own TLS 1.3 list, `OSSL_default_ciphersuites`, before any policy.
@(private = "file")
OPENSSL_TLS13_DEFAULT :: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

// Put a context back on OpenSSL's built-in lists and no version bounds, so a
// test reads the same on a host whose `openssl.cnf` sets any of them.
@(private = "file")
builtin_defaults :: proc(ptr: ^SSL_CTX) -> bool {
	return(
		SSL_CTX_set_cipher_list(ptr, "DEFAULT") == 1 &&
		SSL_CTX_set_ciphersuites(ptr, OPENSSL_TLS13_DEFAULT) == 1 &&
		ssl_ctx_set_min_proto_version(ptr, 0) &&
		ssl_ctx_set_max_proto_version(ptr, 0) 	)
}
