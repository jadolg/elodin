package server

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:sync"
import "core:testing"
import "elodin:tlsx"

/*
The profile endpoint's signing cache.

Signing is the one expensive thing a request to this endpoint can ask for, and
the host it is asked about arrives in a request header. So these are mostly about
what the endpoint refuses to do: sign for a name the certificate does not cover,
sign the same thing twice, sign at a rate an attacker chooses, or hand out
anything at all once the certificate it would be signed with has expired.
*/

@(private = "file")
CERT_DIR :: "/tmp/elodin-server-profile-test"

@(private = "file")
cert_once: sync.Once
@(private = "file")
cert_path: string
@(private = "file")
key_path: string
@(private = "file")
cert_ok: bool

/*
Two certificates for the same names, so a test can rotate from one to the other
and tell which one signed.

Regenerated on every run: these assert on the validity window and on the exact
names carried, so a pair cached by an older revision of this file would be wrong
rather than merely slow.
*/
@(private = "file")
second_cert_path: string
@(private = "file")
second_key_path: string
/*
A wildcard pair, for the cases about a client asking for many distinct
authorities.

With the port bounded to the ones this listener answers on, a certificate naming
three hosts can only be asked about a handful of authorities - not enough to fill
a cache, let alone flood one. A wildcard SAN is the shape that still can, and so
the one the cache's eviction order and the signing budget have to be tested
against.
*/
@(private = "file")
wild_cert_path: string
@(private = "file")
wild_key_path: string

@(private = "file")
generate_certs :: proc() {
	if !os.exists(CERT_DIR) {
		if err := os.make_directory(CERT_DIR); err != nil {
			return
		}
	}
	cert_path = CERT_DIR + "/cert.pem"
	key_path = CERT_DIR + "/key.pem"
	second_cert_path = CERT_DIR + "/cert2.pem"
	second_key_path = CERT_DIR + "/key2.pem"
	if !make_cert(cert_path, key_path) {
		return
	}
	if !make_cert(second_cert_path, second_key_path) {
		return
	}
	wild_cert_path = CERT_DIR + "/wild.pem"
	wild_key_path = CERT_DIR + "/wild-key.pem"
	if !make_cert(wild_cert_path, wild_key_path, "*.elodin.test") {
		return
	}
	cert_ok = true
}

@(private = "file")
make_cert :: proc(cert, key: string, name := "") -> bool {
	subject := "/CN=elodin.local"
	san := "subjectAltName=DNS:elodin.local,DNS:localhost,IP:127.0.0.1"
	if name != "" {
		subject = fmt.tprintf("/CN=%s", name)
		san = fmt.tprintf("subjectAltName=DNS:%s", name)
	}
	devnull, nerr := os.open("/dev/null", {.Write})
	defer if nerr == nil {
		os.close(devnull)
	}
	desc := os.Process_Desc {
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
			"30",
			"-subj",
			subject,
			"-addext",
			san,
		},
	}
	if nerr == nil {
		desc.stdout = devnull
		desc.stderr = devnull
	}
	process, perr := os.process_start(desc)
	if perr != nil {
		return false
	}
	state, werr := os.process_wait(process)
	return werr == nil && state.exit_code == 0
}

// Package-visible: `mobileconfig_test` drives the same certificate through the
// real HTTP endpoints, and a second copy of the generation would be a second
// `openssl` racing this one over its own output files.
ensure_profile_certs :: proc() -> (cert, key: string, ok: bool) {
	sync.once_do(&cert_once, generate_certs)
	return cert_path, key_path, cert_ok
}

// A signer over the first certificate, with everything the tests need to drive
// it by hand: the context is returned so the caller can rotate onto another.
make_test_profile_signer :: proc(t: ^testing.T) -> (p: ^Profile_Signer, ctx: ^tlsx.Context, ok: bool) {
	cert, key, cok := ensure_profile_certs()
	if !cok {
		testing.expect(t, false, "openssl could not make a certificate")
		return nil, nil, false
	}
	tctx, err := tlsx.server_context(cert, key)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return nil, nil, false
	}
	return make_profile_signer(tctx, "/dns-query", TEST_DOH_PORT), tctx, true
}

// The port the test listener is on, so `elodin.local`, `elodin.local:443` and
// `elodin.local:8443` are the authorities it will sign for and nothing else is.
@(private = "file")
TEST_DOH_PORT :: 8443

// The same, over a certificate whose wildcard SAN makes an unbounded number of
// hosts signable - which is what the cache and the budget have to hold up under.
@(private = "file")
make_test_wildcard_signer :: proc(t: ^testing.T) -> (p: ^Profile_Signer, ctx: ^tlsx.Context, ok: bool) {
	if _, _, cok := ensure_profile_certs(); !cok {
		testing.expect(t, false, "openssl could not make a certificate")
		return nil, nil, false
	}
	tctx, err := tlsx.server_context(wild_cert_path, wild_key_path)
	if err != .None {
		testing.expectf(t, false, "no server context: %v", err)
		return nil, nil, false
	}
	return make_profile_signer(tctx, "/dns-query", TEST_DOH_PORT), tctx, true
}

// Offsets from now, against certificates minted at test time for 30 days.
@(private = "file")
at :: proc(offset: i64) -> i64 {
	return tlsx.unix_now() + offset
}

/*
The same authority is signed once and served from the cache after that.

This is the whole answer to a flood on this endpoint: the second request and
every one after it costs a copy rather than a signature.
*/
@(test)
test_profile_is_signed_once_per_authority :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	first, s1 := profile_for_host(p, "elodin.local", at(0), context.temp_allocator)
	testing.expect_value(t, s1, Profile_Status.OK)
	testing.expect(t, len(first) > 0, "a profile should have come back")

	second, s2 := profile_for_host(p, "elodin.local", at(0), context.temp_allocator)
	testing.expect_value(t, s2, Profile_Status.OK)
	testing.expect(t, bytes.equal(first, second), "the cached profile should be the one already signed")
	testing.expect_value(t, sync.atomic_load(&p.signed_total), u64(1))
}

/*
The profile that comes back is the signed form of the profile for that authority.

The payload travels inside the CMS structure, so the URL the device is being
pointed at is there in the bytes; a signature over somebody else's profile would
verify just as well and point the device somewhere else.
*/
@(test)
test_profile_carries_the_authority_it_was_asked_about :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	profile, status := profile_for_host(p, "elodin.local:8443", at(0), context.temp_allocator)
	testing.expect_value(t, status, Profile_Status.OK)
	// DER: a SignedData is a SEQUENCE, so the first byte is the universal
	// constructed tag. An unsigned profile would start with '<'.
	testing.expect(t, len(profile) > 0 && profile[0] == 0x30, "the profile should be DER, not plain XML")
	testing.expect(
		t,
		bytes.contains(profile, transmute([]u8)string("https://elodin.local:8443/dns-query")),
		"the signed payload should be the profile for that authority",
	)
}

/*
An expired certificate serves nothing, cache or no cache.

The cache is what makes this worth a test of its own: an entry signed while the
certificate was valid is still sitting there when it expires, and serving it
would be handing a device a profile signed by a certificate that is no longer
good. The entry has to be refused on the way out, not merely not refreshed.
*/
@(test)
test_profile_is_refused_once_the_certificate_has_expired :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	warm, s1 := profile_for_host(p, "elodin.local", at(0), context.temp_allocator)
	testing.expect_value(t, s1, Profile_Status.OK)
	testing.expect(t, len(warm) > 0, "the cache should have been warmed")

	// A year on, well past the thirty days the test certificate was minted for.
	expired, status := profile_for_host(p, "elodin.local", at(365 * 24 * 3600), context.temp_allocator)
	testing.expect_value(t, status, Profile_Status.Unavailable)
	testing.expect(t, len(expired) == 0, "nothing should be served from a certificate that has expired")

	// And the same for one that is not valid yet.
	early, estatus := profile_for_host(p, "elodin.local", at(-365 * 24 * 3600), context.temp_allocator)
	testing.expect_value(t, estatus, Profile_Status.Unavailable)
	testing.expect(t, len(early) == 0, "nothing should be served before the certificate is valid")
}

/*
A host the certificate does not cover is refused without signing anything.

Two things at once: a profile naming a host this server has no certificate for
could never work on the device, and the host arrives in a header, so signing for
whatever it says is an invitation to spend the CPU on an unbounded supply of
distinct profiles.
*/
@(test)
test_profile_refuses_a_host_outside_the_certificate :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	for host in ([]string{"example.com", "evil.elodin.local", "10.0.0.1", "elodin.local.evil.com:443"}) {
		profile, status := profile_for_host(p, host, at(0), context.temp_allocator)
		testing.expectf(t, status == .Unknown_Host, "%s should be refused, got %v", host, status)
		testing.expectf(t, len(profile) == 0, "%s should get no profile", host)
	}
	testing.expect_value(t, sync.atomic_load(&p.signed_total), u64(0))
}

/*
Rotating the certificate drops what was signed with the old one.

A renewal is the one moment when every cached entry becomes something that must
not be served again: it is signed by a key the listener has stopped presenting.
*/
@(test)
test_profile_cache_is_dropped_when_the_certificate_rotates :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	before, _ := profile_for_host(p, "elodin.local", at(0), context.temp_allocator)
	testing.expect_value(t, sync.atomic_load(&p.signed_total), u64(1))

	fresh, ferr := tlsx.server_context(second_cert_path, second_key_path)
	if ferr != .None {
		testing.expectf(t, false, "no replacement context: %v", ferr)
		return
	}
	defer tlsx.context_destroy(fresh)
	profile_signer_adopt(p, fresh)

	after, status := profile_for_host(p, "elodin.local", at(0), context.temp_allocator)
	testing.expect_value(t, status, Profile_Status.OK)
	testing.expect_value(t, sync.atomic_load(&p.signed_total), u64(2))
	testing.expect(
		t,
		!bytes.equal(before, after),
		"the profile should have been signed again, by the certificate now in use",
	)
}

/*
The cache holds a bounded number of entries however many authorities are asked
for.

The port is part of the URL a profile carries and so part of what is cached, and
a client picks it. Without a ceiling that is a way to spend the server's memory
one distinct authority at a time.
*/
@(test)
test_profile_cache_is_bounded :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_wildcard_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	for i in 1 ..= PROFILE_CACHE_ENTRIES * 4 {
		authority := fmt.tprintf("h%d.elodin.test", i)
		// The budget refills over time; each of these is a fresh second so the
		// signing is allowed and the cache is the thing under test.
		profile_for_host(p, authority, at(i64(i)), context.temp_allocator)
	}

	held := 0
	for entry in p.entries {
		if len(entry.authority) > 0 {
			held += 1
		}
	}
	testing.expect_value(t, held, PROFILE_CACHE_ENTRIES)
}

/*
Signing is rate limited, and a burst beyond the budget is refused rather than
paid for.

The cache answers a flood that repeats an authority; this answers one that keeps
picking new ones, which the cache cannot hold and which each cost a signature.
*/
@(test)
test_profile_signing_budget_is_bounded :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_wildcard_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	now := at(0)
	refused := 0
	for i in 1 ..= PROFILE_SIGN_BURST * 3 {
		authority := fmt.tprintf("h%d.elodin.test", i)
		// All in the same second, so nothing refills.
		_, status := profile_for_host(p, authority, now, context.temp_allocator)
		if status == .Unavailable {
			refused += 1
		}
	}
	testing.expect_value(t, sync.atomic_load(&p.signed_total), u64(PROFILE_SIGN_BURST))
	testing.expect(t, refused > 0, "a burst past the budget should be refused")
}

/*
A flood that exhausts the budget does not stop the endpoint answering for an
authority it has already signed.

This is what keeps the rate limit from being the attack: the names a real client
asks for are in the cache, and the cache is consulted before the budget is.
*/
@(test)
test_profile_still_serves_from_cache_with_no_budget_left :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_wildcard_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	now := at(0)
	wanted, s1 := profile_for_host(p, "wanted.elodin.test", now, context.temp_allocator)
	testing.expect_value(t, s1, Profile_Status.OK)

	for i in 1 ..= PROFILE_SIGN_BURST * 2 {
		authority := fmt.tprintf("h%d.elodin.test", i)
		profile_for_host(p, authority, now, context.temp_allocator)
	}

	again, s2 := profile_for_host(p, "wanted.elodin.test", now, context.temp_allocator)
	testing.expect_value(t, s2, Profile_Status.OK)
	testing.expect(t, bytes.equal(wanted, again), "the cached profile should still be served")
}

/*
A device that has been served keeps being served through a flood of authorities
that differ only in an invented port.

The port is part of the URL and so part of the cache key, and a client picks it -
so a flood can mint distinct keys indefinitely while passing the certificate
check, which only ever sees the host. Left alone that turns both defences into
the attack: the flood evicts the entry a real device was being served from, and
the budget it drained means the re-signing needed to replace that entry is
refused. The device gets a 503 for a name the certificate covers.
*/
@(test)
test_profile_survives_a_flood_of_invented_ports :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_profile_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	start := at(0)
	wanted, s1 := profile_for_host(p, "elodin.local", start, context.temp_allocator)
	testing.expect_value(t, s1, Profile_Status.OK)

	// Ten seconds of a hundred a second, which outruns the refill by far more
	// than it has to.
	for tick in 0 ..< 10 {
		for i in 0 ..< 100 {
			authority := fmt.tprintf("elodin.local:%d", tick * 100 + i + 1)
			profile_for_host(p, authority, start + i64(tick), context.temp_allocator)
		}
	}

	// Asked in the same second as the last of the flood, which is the position a
	// real device is in: there is no pause for the budget to refill in.
	again, s2 := profile_for_host(p, "elodin.local", start + 9, context.temp_allocator)
	testing.expect_value(t, s2, Profile_Status.OK)
	testing.expect(t, len(again) > 0, "the device should still get its profile")
	_ = wanted
}

/*
An authority devices keep asking for is not evicted by a run of authorities asked
for once each.

The port bound puts a ceiling on what a client can invent against an ordinary
certificate, but a wildcard SAN has no such ceiling - every name under it is one
the certificate covers. What stands in the way there is the eviction order: the
entry a real device is served from has been asked for more than once, and the
flood's entries never are, so the flood can only ever displace its own.

Asked at the end in the same second as the last of the flood, where there is no
budget left to sign a replacement with - so a cache that had let the entry go
would have to answer 503.
*/
@(test)
test_established_profile_survives_a_flood_of_new_hosts :: proc(t: ^testing.T) {
	p, ctx, ok := make_test_wildcard_signer(t)
	if !ok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(p)

	start := at(0)
	wanted, s1 := profile_for_host(p, "wanted.elodin.test", start, context.temp_allocator)
	testing.expect_value(t, s1, Profile_Status.OK)
	// A second device asking for the same name, which is what marks it as one
	// being asked for rather than one merely tried.
	_, s2 := profile_for_host(p, "wanted.elodin.test", start, context.temp_allocator)
	testing.expect_value(t, s2, Profile_Status.OK)

	for tick in 0 ..< 20 {
		for i in 0 ..< 20 {
			authority := fmt.tprintf("h%d-%d.elodin.test", tick, i)
			profile_for_host(p, authority, start + i64(tick), context.temp_allocator)
		}
	}

	again, s3 := profile_for_host(p, "wanted.elodin.test", start + 19, context.temp_allocator)
	testing.expect_value(t, s3, Profile_Status.OK)
	testing.expect(t, bytes.equal(wanted, again), "it should still be the profile that was signed, from the cache")
}
