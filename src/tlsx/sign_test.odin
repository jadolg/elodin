package tlsx

import "core:os"
import "core:sync"
import "core:testing"

/*
The signing identity a server context carries, exercised against a real
certificate.

Nothing here mocks OpenSSL. What these assert is that the bytes handed to a
device are a CMS structure someone else's CMS reader accepts, and a mock would
only be asserting this package's own opinion of the format. `openssl cms
-verify` is that someone else: an independent implementation reading the same
bytes an Apple device's profile installer would.
*/

@(private = "file")
CERT_DIR :: "/tmp/elodin-tlsx-sign-test"

/*
Generated on every run rather than reused from a previous one.

The other suites in this tree cache a pair to keep key generation off the clock,
and then have to ask whether what they cached has since expired. These tests
assert on the certificate's own validity window and on the exact names it
carries, so a pair left behind by an older revision of this file would not be a
slow test but a wrong one. A P-256 key costs under a millisecond to make.
*/
@(private = "file")
cert_once: sync.Once
@(private = "file")
signer_cert: string
@(private = "file")
signer_key: string
@(private = "file")
signer_cert_ok: bool

@(private = "file")
generate_signer_cert :: proc() {
	signer_cert = CERT_DIR + "/cert.pem"
	signer_key = CERT_DIR + "/key.pem"
	if !os.exists(CERT_DIR) {
		if err := os.make_directory(CERT_DIR); err != nil {
			return
		}
	}
	code, ok := run_openssl(
		{
			"req",
			"-x509",
			"-newkey",
			"ec",
			"-pkeyopt",
			"ec_paramgen_curve:prime256v1",
			"-nodes",
			"-keyout",
			signer_key,
			"-out",
			signer_cert,
			"-days",
			"30",
			"-subj",
			"/CN=elodin.local",
			"-addext",
			"subjectAltName=DNS:elodin.local,DNS:localhost,IP:127.0.0.1",
		},
	)
	signer_cert_ok = ok && code == 0
}

@(private = "file")
ensure_signer_cert :: proc() -> (cert, key: string, ok: bool) {
	sync.once_do(&cert_once, generate_signer_cert)
	return signer_cert, signer_key, signer_cert_ok
}

// Run openssl with its chatter discarded; the exit code is the whole answer.
@(private = "file")
run_openssl :: proc(args: []string) -> (code: int, ok: bool) {
	command := make([dynamic]string, context.temp_allocator)
	append(&command, "openssl")
	append(&command, ..args)

	devnull, nerr := os.open("/dev/null", {.Write})
	defer if nerr == nil {
		os.close(devnull)
	}
	desc := os.Process_Desc {
		command = command[:],
	}
	if nerr == nil {
		desc.stdout = devnull
		desc.stderr = devnull
	}
	process, perr := os.process_start(desc)
	if perr != nil {
		return 0, false
	}
	state, werr := os.process_wait(process)
	if werr != nil {
		return 0, false
	}
	return state.exit_code, true
}

@(private = "file")
PROFILE :: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string></dict></plist>
`

/*
A server context picks its signing identity up from the certificate it serves.

Taken from the `SSL_CTX` rather than by reading the files a second time, so the
identity that signs a profile is by construction the one the listener is
presenting - there is no window during a renewal where the two disagree.
*/
@(test)
test_server_context_carries_a_signer :: proc(t: ^testing.T) {
	cert, key, ok := ensure_signer_cert()
	if !ok {
		testing.expect(t, false, "openssl could not make a certificate")
		return
	}
	ctx, err := server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return
	}
	defer context_destroy(ctx)
	testing.expect(t, signer_present(ctx.signer), "a server context should carry a signer")
}

// A client context signs nothing: it has no certificate of its own to sign with.
@(test)
test_client_context_has_no_signer :: proc(t: ^testing.T) {
	ctx, err := client_context(false)
	if err != .None {
		testing.expectf(t, false, "no client context: %v", err)
		return
	}
	defer context_destroy(ctx)
	testing.expect(t, !signer_present(ctx.signer), "a client context should carry no signer")
}

/*
The signed bytes are a CMS structure another implementation verifies, and the
profile comes back out of it unchanged.

This is the property the whole feature rests on: a device that cannot verify the
signature, or that recovers something other than the profile that was signed,
has been handed a worse file than the unsigned one it used to get.
*/
@(test)
test_signed_profile_verifies_with_openssl :: proc(t: ^testing.T) {
	cert, key, ok := ensure_signer_cert()
	if !ok {
		testing.expect(t, false, "openssl could not make a certificate")
		return
	}
	ctx, err := server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return
	}
	defer context_destroy(ctx)

	signed, sok := sign_cms(ctx.signer, transmute([]u8)string(PROFILE), context.temp_allocator)
	if !sok {
		testing.expect(t, false, "the profile did not sign")
		return
	}
	testing.expect(t, len(signed) > 0, "a signed profile should not be empty")

	der := CERT_DIR + "/verify.der"
	out := CERT_DIR + "/verify.out"
	if werr := os.write_entire_file(der, signed); werr != nil {
		testing.expectf(t, false, "cannot write the signed profile: %v", werr)
		return
	}
	code, ran := run_openssl({"cms", "-verify", "-inform", "der", "-in", der, "-CAfile", cert, "-out", out})
	if !ran {
		testing.expect(t, false, "openssl could not be run")
		return
	}
	testing.expect_value(t, code, 0)

	recovered, rerr := os.read_entire_file_from_path(out, context.temp_allocator)
	if rerr != nil {
		testing.expectf(t, false, "cannot read what openssl recovered: %v", rerr)
		return
	}
	testing.expect_value(t, string(recovered), PROFILE)
}

/*
The validity window is answered against a caller-supplied instant, not the wall
clock.

The caller is the one endpoint that must never hand out a profile signed with a
certificate that is not currently valid, and it is also the thing that has to be
testable without waiting a month or forging a system clock. So the question
`signer_valid_at` answers is "was this certificate valid at that moment", and
both ends of the window are refused.
*/
@(test)
test_signer_refuses_a_time_outside_the_validity_window :: proc(t: ^testing.T) {
	cert, key, ok := ensure_signer_cert()
	if !ok {
		testing.expect(t, false, "openssl could not make a certificate")
		return
	}
	ctx, err := server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return
	}
	defer context_destroy(ctx)

	now := i64(1893456000) // 2030-01-01, after a certificate minted today for 30 days.
	testing.expect(t, !signer_valid_at(ctx.signer, now), "an expired certificate should not sign")
	testing.expect(
		t,
		!signer_valid_at(ctx.signer, 946684800), // 2000-01-01, before it was issued.
		"a certificate that is not yet valid should not sign",
	)
	testing.expect(t, signer_valid_at(ctx.signer, unix_now()), "a current certificate should sign")
}

/*
Only the names the certificate actually carries are signable.

A profile names the host the device will resolve through, and that URL has to
verify against this same certificate when the device uses it. A host the
certificate does not cover would produce a profile that cannot work - and,
because the host arrives in a request header, an unbounded supply of distinct
profiles to sign. Both are closed by asking the certificate.
*/
@(test)
test_signer_covers_only_the_certificate_names :: proc(t: ^testing.T) {
	cert, key, ok := ensure_signer_cert()
	if !ok {
		testing.expect(t, false, "openssl could not make a certificate")
		return
	}
	ctx, err := server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return
	}
	defer context_destroy(ctx)

	for name in ([]string{"elodin.local", "localhost", "127.0.0.1"}) {
		testing.expectf(t, signer_covers_host(ctx.signer, name), "%s is in the certificate", name)
	}
	for name in ([]string{"example.com", "evil.elodin.local", "", "10.0.0.1"}) {
		testing.expectf(t, !signer_covers_host(ctx.signer, name), "%s is not in the certificate", name)
	}
}

/*
A retained signer outlives the context it came from.

This is what lets the profile endpoint hold a signing identity without holding
the TLS context's lock: a reload builds a fresh context, the endpoint retains its
signer, and the displaced context is then freed while the retained identity stays
usable.
*/
@(test)
test_retained_signer_outlives_its_context :: proc(t: ^testing.T) {
	cert, key, ok := ensure_signer_cert()
	if !ok {
		testing.expect(t, false, "openssl could not make a certificate")
		return
	}
	ctx, err := server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return
	}
	held := signer_retain(ctx.signer)
	defer signer_release(&held)
	context_destroy(ctx)

	testing.expect(t, signer_present(held), "the retained signer should still be there")
	testing.expect(t, signer_covers_host(held, "elodin.local"), "and should still answer for its names")
	signed, sok := sign_cms(held, transmute([]u8)string(PROFILE), context.temp_allocator)
	testing.expect(t, sok && len(signed) > 0, "and should still sign")
}

/*
An authority is split into the host a certificate is asked about and the port it
is not.

The bracket cases are the ones worth pinning. Brackets are the URL spelling of an
IP literal and of nothing else, so they come off `[::1]` and stay on
`[elodin.local]` - unwrapping the second would match a certificate against
`elodin.local` and then hand a device `https://[elodin.local]/dns-query`, an
authority no client can resolve.
*/
@(test)
test_split_host_port_unwraps_only_address_literals :: proc(t: ^testing.T) {
	Case :: struct {
		authority, host, port: string,
	}
	for c in ([]Case {
			{"elodin.local", "elodin.local", ""},
			{"elodin.local:8443", "elodin.local", "8443"},
			{"[::1]", "::1", ""},
			{"[::1]:8443", "::1", "8443"},
			{"::1", "::1", ""},
			{"127.0.0.1:8443", "127.0.0.1", "8443"},
			// Not an address, so not a bracketed literal: left whole, which is
			// what no certificate will cover.
			{"[elodin.local]", "[elodin.local]", ""},
			{"[elodin.local]:8443", "[elodin.local]:8443", ""},
			// No closing bracket at all.
			{"[::1", "[::1", ""},
			// Brackets are the URL spelling of an IPv6 literal alone. `[1.2.3.4]`
			// is not an authority a client can dial, so the address inside it is
			// not one to match a certificate against.
			{"[127.0.0.1]", "[127.0.0.1]", ""},
			{"[127.0.0.1]:8443", "[127.0.0.1]:8443", ""},
			// Anything trailing the bracket is part of the authority and not part
			// of the address: unwrapping these would take one address to be an
			// unbounded set of spellings of itself.
			{"[::1]x", "[::1]x", ""},
			{"[::1]x:8443", "[::1]x:8443", ""},
			// A separator with no port after it is a second spelling of no port.
			{"[::1]:", "[::1]:", ""},
			{"elodin.local:", "elodin.local:", ""},
		}) {
		host, port := split_host_port(c.authority)
		testing.expectf(t, host == c.host, "%q: host %q, wanted %q", c.authority, host, c.host)
		testing.expectf(t, port == c.port, "%q: port %q, wanted %q", c.authority, port, c.port)
	}
}
