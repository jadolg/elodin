package server

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:tlsx"

/*
The profile carries the DoH URL built from the host and path it was asked for.

The URL is the one thing a device cannot do without: get it wrong and every
lookup goes nowhere. So this checks the pieces that make it up are present and
joined the way a `ServerURL` has to be, and that the payload is the managed-DNS
kind iOS reads rather than some other profile that happens to parse.
*/
@(test)
test_mobileconfig_carries_the_doh_url :: proc(t: ^testing.T) {
	profile := build_doh_mobileconfig("dns.example", "/dns-query", context.temp_allocator)

	testing.expect(
		t,
		strings.contains(profile, "<string>https://dns.example/dns-query</string>"),
		"the ServerURL is not the host and path it was built from",
	)
	testing.expect(
		t,
		strings.contains(profile, "<key>DNSProtocol</key>"),
		"the DNS payload is missing",
	)
	testing.expect(
		t,
		strings.contains(profile, "<string>HTTPS</string>"),
		"the profile does not say the protocol is HTTPS",
	)
	testing.expect(
		t,
		strings.contains(profile, "<string>com.apple.dnsSettings.managed</string>"),
		"the payload is not the managed DNS-settings kind iOS reads",
	)
	// A valid plist opens with the declaration and the root element.
	testing.expect(t, strings.has_prefix(profile, "<?xml"), "not an XML document")
	testing.expect(t, strings.contains(profile, "<plist version=\"1.0\">"), "not a plist")
	free_all(context.temp_allocator)
}

/*
A non-standard port survives into the URL.

A DoH listener that is not on 443 is reached at `host:port`, and the authority
the request carries is that whole string. It has to end up in the URL as it came,
or the profile points a device at 443 when the server is somewhere else.
*/
@(test)
test_mobileconfig_keeps_a_port :: proc(t: ^testing.T) {
	profile := build_doh_mobileconfig("dns.example:8443", "/dns-query", context.temp_allocator)
	testing.expect(
		t,
		strings.contains(profile, "<string>https://dns.example:8443/dns-query</string>"),
		"the port did not survive into the ServerURL",
	)
	free_all(context.temp_allocator)
}

/*
The same URL yields the same profile; a different one yields a different profile.

The UUIDs are derived from the URL rather than drawn at random precisely so a
device that reinstalls updates the profile it had. Two hosts must not collide
onto one identifier, or installing the second would silently replace the first.
*/
@(test)
test_mobileconfig_uuids_are_stable_and_distinct :: proc(t: ^testing.T) {
	a1 := build_doh_mobileconfig("dns.example", "/dns-query", context.temp_allocator)
	a2 := build_doh_mobileconfig("dns.example", "/dns-query", context.temp_allocator)
	b := build_doh_mobileconfig("other.example", "/dns-query", context.temp_allocator)

	testing.expect(t, a1 == a2, "the same URL produced two different profiles")
	testing.expect(t, a1 != b, "two different hosts produced the same profile")

	// The two payloads inside one profile must not share a UUID either.
	uuid_dns := mobileconfig_uuid("https://dns.example/dns-query", "dns")
	uuid_profile := mobileconfig_uuid("https://dns.example/dns-query", "profile")
	testing.expect(t, uuid_dns != uuid_profile, "the two payloads share a UUID")
	// 8-4-4-4-12 is 36 characters.
	testing.expect_value(t, len(uuid_dns), 36)
	free_all(context.temp_allocator)
}

/*
A character that would be markup is escaped, so the document stays well formed.

The host and path are attacker-influenced - the `Host` header is whatever the
client sent - and they are placed inside XML element text. `valid_mobileconfig_host`
turns away most of what could break out, but a path from the config is not run
through it, so the escaping is what keeps a stray `&` or `<` from making the
profile unparseable.
*/
@(test)
test_xml_escape :: proc(t: ^testing.T) {
	got := xml_escape("a&b<c>d\"e'f", context.temp_allocator)
	testing.expect_value(t, got, "a&amp;b&lt;c&gt;d&quot;e&#39;f")
	// Nothing special is left untouched.
	plain := xml_escape("dns.example:8443", context.temp_allocator)
	testing.expect_value(t, plain, "dns.example:8443")
	free_all(context.temp_allocator)
}

@(test)
test_valid_mobileconfig_host :: proc(t: ^testing.T) {
	Case :: struct {
		host: string,
		ok:   bool,
	}
	CASES := []Case {
		{"dns.example", true},
		{"dns.example:8443", true},
		{"192.0.2.1", true},
		{"192.0.2.1:8443", true},
		{"[2001:db8::1]:8443", true},
		{"", false}, // no host at all
		{"dns example", false}, // a space
		{"dns.example/dns-query", false}, // a slash escapes the authority
		{"dns.example<script>", false}, // markup
		{"a&b.example", false}, // an ampersand
		{strings.repeat("a", 300, context.temp_allocator), false}, // longer than any host
	}
	for c in CASES {
		testing.expectf(
			t,
			valid_mobileconfig_host(c.host) == c.ok,
			"valid_mobileconfig_host(%q) should be %v",
			c.host,
			c.ok,
		)
	}
	free_all(context.temp_allocator)
}

@(private = "file")
mc_send_all :: proc(t: ^testing.T, socket: net.TCP_Socket, raw: string) -> bool {
	sent := 0
	bytes := transmute([]u8)raw
	for sent < len(bytes) {
		n, err := net.send_tcp(socket, bytes[sent:])
		if err != nil || n <= 0 {
			testing.expectf(t, false, "cannot send: %v", err)
			return false
		}
		sent += n
	}
	return true
}

@(private = "file")
Mc_Session :: struct {
	server: ^Server,
	conn:   Conn,
}

@(private = "file")
run_serve_doh_mc :: proc(d: ^Mc_Session) {
	serve_doh(d.server, d.conn, "test")
}

/*
Run one request through the real `serve_doh` loop and return everything written
back.

The three profile cases below differ only in the request line and in what the
server was given to sign with, so the loopback pair, the handler thread and the
drain are here once. What is deliberately not factored out is `serve_doh` itself:
these exist to catch a break in the wiring between routing, the Host capture and
the signing, and a test that called the builder directly would not see one.
*/
@(private = "file")
mc_roundtrip :: proc(t: ^testing.T, s: ^Server, request: string) -> (reply: string, ok: bool) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return "", false
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return "", false
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return "", false
	}
	defer net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return "", false
	}
	defer net.close(accepted)
	// With nothing following the one request, the handler ends on this rather
	// than on a close.
	_ = net.set_option(accepted, .Receive_Timeout, 500 * time.Millisecond)

	session := Mc_Session {
		server = s,
		conn   = Conn{socket = accepted},
	}
	handler := thread.create_and_start_with_poly_data(&session, run_serve_doh_mc)
	defer {
		thread.join(handler)
		thread.destroy(handler)
	}

	if !mc_send_all(t, client, request) {
		net.shutdown(client, .Send)
		return "", false
	}

	_ = net.set_option(client, .Receive_Timeout, 2 * time.Second)
	answer := strings.builder_make(context.temp_allocator)
	for {
		chunk: [4096]u8
		n, rerr := net.recv_tcp(client, chunk[:])
		if rerr != nil || n <= 0 {
			break
		}
		strings.write_bytes(&answer, chunk[:n])
	}
	return strings.to_string(answer), true
}

// The response body, which for a signed profile is DER and so cannot be read as
// text up to the next blank line.
@(private = "file")
mc_body :: proc(reply: string) -> string {
	if idx := strings.index(reply, "\r\n\r\n"); idx >= 0 {
		return reply[idx + 4:]
	}
	return ""
}

@(private = "file")
GET_PROFILE :: "GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"

/*
A GET to the profile path is answered end to end over the HTTP/1.1 endpoint, with
a signed profile.

The routing, the Host capture, the profile build and the signing have to line up:
a request to `mobileconfig_path` with a Host the certificate covers comes back
200, as the Apple profile content type, carrying a CMS structure whose payload is
the profile for that Host. This goes through the real `serve_doh` loop rather than
the builder alone, so a break in the wiring between them shows up here.
*/
@(test)
test_serve_doh_returns_the_signed_profile :: proc(t: ^testing.T) {
	signer, ctx, sok := make_test_profile_signer(t)
	if !sok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(signer)

	cfg := config.default_config()
	s := Server {
		cfg      = &cfg,
		profiles = signer,
	}
	reply, ok := mc_roundtrip(t, &s, fmt.tprintf(GET_PROFILE, "elodin.local"))
	if !ok {
		return
	}

	testing.expect(t, strings.contains(reply, "HTTP/1.1 200"), "the profile request was not answered 200")
	testing.expect(
		t,
		strings.contains(reply, DOH_MOBILECONFIG_CONTENT_TYPE),
		"the response is not the Apple profile content type",
	)

	body := mc_body(reply)
	testing.expect(t, len(body) > 0 && body[0] == 0x30, "the body should be a DER structure, not plain XML")
	testing.expect(
		t,
		strings.contains(body, "https://elodin.local/dns-query"),
		"the signed payload does not carry the URL built from the Host header",
	)
	free_all(context.temp_allocator)
}

/*
A Host the certificate does not cover is a 400, and nothing is signed for it.

The profile would name a host this server cannot present a certificate for, so it
could not work on the device that installed it. Refusing is also what keeps the
work bounded: the Host is a header, and signing whatever it says is an unbounded
supply of distinct profiles to sign.
*/
@(test)
test_serve_doh_profile_refuses_a_host_outside_the_certificate :: proc(t: ^testing.T) {
	signer, ctx, sok := make_test_profile_signer(t)
	if !sok {
		return
	}
	defer tlsx.context_destroy(ctx)
	defer destroy_profile_signer(signer)

	cfg := config.default_config()
	s := Server {
		cfg      = &cfg,
		profiles = signer,
	}
	reply, ok := mc_roundtrip(t, &s, fmt.tprintf(GET_PROFILE, "dns.example"))
	if !ok {
		return
	}
	testing.expect(
		t,
		strings.contains(reply, "HTTP/1.1 400"),
		"a Host outside the certificate should be a 400",
	)
	testing.expect_value(t, sync.atomic_load(&signer.signed_total), u64(0))
	free_all(context.temp_allocator)
}

/*
With nothing to sign with, the endpoint says so rather than serving an unsigned
profile.

A silent downgrade is the one answer that would be wrong here: a device would
install a profile reporting itself unverified, and the operator whose certificate
stopped being usable would have no sign that anything had changed.
*/
@(test)
test_serve_doh_profile_is_unavailable_without_a_signer :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	reply, ok := mc_roundtrip(t, &s, fmt.tprintf(GET_PROFILE, "elodin.local"))
	if !ok {
		return
	}
	testing.expect(
		t,
		strings.contains(reply, "HTTP/1.1 503"),
		"a server with no signing identity should answer 503",
	)
	free_all(context.temp_allocator)
}

/*
A POST to the profile path is a 405.

The profile is a download, reached by navigating to it, so only GET makes sense;
a POST there is a client using the endpoint wrong, and telling it so is better
than signing a profile for a request that was never going to install one.
*/
@(test)
test_serve_doh_profile_rejects_post :: proc(t: ^testing.T) {
	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	reply, ok := mc_roundtrip(
		t,
		&s,
		"POST /apple-doh.mobileconfig HTTP/1.1\r\nHost: elodin.local\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
	)
	if !ok {
		return
	}
	testing.expect(t, strings.contains(reply, "HTTP/1.1 405"), "a POST to the profile path should be a 405")
	free_all(context.temp_allocator)
}
