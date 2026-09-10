package tlsx

import "core:c"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sys/posix"
import "core:time"

/*
Signing a blob of bytes with the certificate a server context already serves.

This exists for the Apple configuration profile the DoH listener hands out: a
profile carries a CMS signature or a device calls it unsigned. The signing
identity is not a second certificate to configure but the listener's own, so
there is nothing new for an operator to provision and nothing for a renewal to
forget.

The identity is taken out of the `SSL_CTX` rather than by reading the certificate
and key files again. Two reads could disagree - a renewal that rewrites both
files is not atomic across them, and the second read could land between the two
writes - and what a profile must be signed by is exactly the certificate the
device just verified the connection against.
*/

/*
A certificate, its key, and the intermediates between it and a root.

The pointers belong to the `SSL_CTX` they came from unless `signer_retain` has
been called, which takes a reference to each and hands back an identity whose
lifetime is its holder's. See `signer_release` for the other end of that.

The chain matters as much as the leaf: a device builds a path from the signer to
a root it trusts, and it has only the roots. A profile signed by a leaf whose
intermediates were left out is one a device cannot verify even though it trusts
the root the leaf came from.
*/
Signer :: struct {
	cert:   ^X509,
	key:    ^EVP_PKEY,
	chain:  ^OPENSSL_STACK,
	// Whether the three above are this struct's to free. False for one borrowed
	// from a context, which frees them itself.
	owned:  bool,
}

// Whether there is anything here to sign with. A client context has no
// certificate of its own, so it carries an empty signer rather than an error.
signer_present :: proc(s: Signer) -> bool {
	return s.cert != nil && s.key != nil
}

// The identity a server context serves, borrowed from it. Valid for as long as
// the context is.
@(private)
signer_of :: proc(ptr: ^SSL_CTX) -> (s: Signer) {
	s.cert = SSL_CTX_get0_certificate(ptr)
	s.key = SSL_CTX_get0_privatekey(ptr)
	if !signer_present(s) {
		return Signer{}
	}
	s.chain = ssl_ctx_get0_chain_certs(ptr)
	return s
}

/*
Take a reference to each of a borrowed signer's parts.

What this buys is a signing identity that outlives the context it came from, so
a caller can hold one without holding the lock that guards the context against
the reload that replaces it. A certificate renewal then becomes: retain the new
context's signer, release the old one, and let the contexts be swapped by
whoever owns them.
*/
signer_retain :: proc(s: Signer) -> (held: Signer) {
	if !signer_present(s) {
		return Signer{}
	}
	if X509_up_ref(s.cert) != 1 {
		return Signer{}
	}
	if EVP_PKEY_up_ref(s.key) != 1 {
		X509_free(s.cert)
		return Signer{}
	}
	held.cert = s.cert
	held.key = s.key
	held.owned = true
	if s.chain != nil {
		// Each certificate in the copy carries its own reference; a nil result
		// costs the intermediates, not correctness, so it is not an error.
		held.chain = X509_chain_up_ref(s.chain)
	}
	return held
}

// Drop the references `signer_retain` took. A borrowed signer owns nothing and
// is left alone.
signer_release :: proc(s: ^Signer) {
	if s == nil || !s.owned {
		return
	}
	if s.cert != nil {
		X509_free(s.cert)
	}
	if s.key != nil {
		EVP_PKEY_free(s.key)
	}
	if s.chain != nil {
		OPENSSL_sk_pop_free(s.chain, rawptr(X509_free))
	}
	s^ = Signer{}
}

/*
Whether the certificate was valid at `at_unix`.

The instant is the caller's rather than the wall clock's for two reasons. The
caller is a cache, and what it has to decide is whether the entry it is holding
was signed by something still valid *now* - a question it already has a clock
reading for. And a test can ask about a moment past the certificate's expiry
without forging a system clock or waiting for one to arrive.

A certificate whose dates will not parse answers false: `X509_cmp_time` returns
zero for that, which is neither of the two comparisons this wants, and an
unreadable validity window is not one to sign under.
*/
signer_valid_at :: proc(s: Signer, at_unix: i64) -> bool {
	if !signer_present(s) {
		return false
	}
	at := posix.time_t(at_unix)
	not_before := X509_get0_notBefore(s.cert)
	not_after := X509_get0_notAfter(s.cert)
	if not_before == nil || not_after == nil {
		return false
	}
	return X509_cmp_time(not_before, &at) < 0 && X509_cmp_time(not_after, &at) > 0
}

// The wall clock in the form `signer_valid_at` wants.
unix_now :: proc() -> i64 {
	return time.to_unix_seconds(time.now())
}

/*
Whether the certificate would verify for `host`.

OpenSSL answers this, not this package: subject alternative names, the wildcard
rules and the common-name fallback are RFC 6125 in a form that is easy to get
subtly wrong, and the certificate is being asked the same question a client's
TLS stack asks it. An IP literal is a different extension from a DNS name, so it
is a different call.

`host` is a bare hostname or address - no port, no brackets. See
`split_host_port` for where that is peeled off.
*/
signer_covers_host :: proc(s: Signer, host: string) -> bool {
	if !signer_present(s) || host == "" {
		return false
	}
	if net.parse_address(host) != nil {
		return X509_check_ip_asc(s.cert, strings.clone_to_cstring(host, context.temp_allocator), 0) == 1
	}
	// Passed with an explicit length, so an embedded NUL cannot truncate the
	// name that is checked to a prefix of the name that gets served.
	bytes := transmute([]u8)host
	return X509_check_host(s.cert, raw_data(bytes), c.size_t(len(bytes)), 0, nil) == 1
}

/*
Wrap `payload` in a CMS SignedData structure, DER encoded.

The payload travels inside the result, so what comes back is a signed file that
replaces the plain one rather than a signature to carry beside it.

Nothing here consults the clock: whether the certificate should be signing at
all is `signer_valid_at`'s question, asked by the caller that also decides what
to do about the answer.
*/
sign_cms :: proc(s: Signer, payload: []u8, allocator := context.allocator) -> (der: []u8, ok: bool) {
	if !signer_present(s) {
		return nil, false
	}
	ERR_clear_error()

	// `BIO_new_mem_buf` only reads, so the payload is not copied.
	in_bio := BIO_new_mem_buf(raw_data(payload), c.int(len(payload)))
	if in_bio == nil {
		return nil, false
	}
	defer BIO_free(in_bio)

	cms := CMS_sign(s.cert, s.key, s.chain, in_bio, CMS_BINARY | CMS_NOSMIMECAP)
	if cms == nil {
		return nil, false
	}
	defer CMS_ContentInfo_free(cms)

	out_bio := BIO_new(BIO_s_mem())
	if out_bio == nil {
		return nil, false
	}
	defer BIO_free(out_bio)
	if i2d_CMS_bio(out_bio, cms) != 1 {
		return nil, false
	}

	// The bytes belong to the BIO, which the defer above frees.
	encoded := bio_mem_data(out_bio)
	if len(encoded) == 0 {
		return nil, false
	}
	copied, aerr := mem.make_aligned([]u8, len(encoded), 1, allocator)
	if aerr != nil {
		return nil, false
	}
	copy(copied, encoded)
	return copied, true
}

/*
Split an HTTP authority into its host and port.

The host may be a bracketed IPv6 literal, whose colons are not port separators,
so the last colon is only a port when it follows the closing bracket. The
brackets themselves are stripped: what a certificate carries is the address, not
the URL spelling of it.
*/
split_host_port :: proc(authority: string) -> (host: string, port: string) {
	if strings.has_prefix(authority, "[") {
		if end := strings.index_byte(authority, ']'); end >= 0 {
			host = authority[1:end]
			rest := authority[end + 1:]
			if strings.has_prefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
		return authority, ""
	}
	if idx := strings.last_index_byte(authority, ':'); idx >= 0 {
		// A bare IPv6 literal has several colons and no port at all.
		if strings.index_byte(authority, ':') == idx {
			return authority[:idx], authority[idx + 1:]
		}
	}
	return authority, ""
}
