package server

import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"

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
A GET to the profile path is answered end to end over the HTTP/1.1 endpoint.

The routing, the Host capture and the profile build have to line up: a request
to `mobileconfig_path` with a Host header comes back 200, as the Apple profile
content type, carrying the URL built from that Host. This goes through the real
`serve_doh` loop rather than the builder alone, so a break in the wiring between
them shows up here.
*/
@(test)
test_serve_doh_returns_the_profile :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return
	}
	defer net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	// With nothing following the one request, the handler ends on this rather
	// than on a close.
	_ = net.set_option(accepted, .Receive_Timeout, 500 * time.Millisecond)

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	session := Mc_Session {
		server = &s,
		conn   = Conn{socket = accepted},
	}
	handler := thread.create_and_start_with_poly_data(&session, run_serve_doh_mc)
	defer {
		thread.join(handler)
		thread.destroy(handler)
	}

	request := "GET /apple-doh.mobileconfig HTTP/1.1\r\nHost: dns.example\r\nConnection: close\r\n\r\n"
	if !mc_send_all(t, client, request) {
		net.shutdown(client, .Send)
		return
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

	reply := strings.to_string(answer)
	testing.expect(t, strings.contains(reply, "HTTP/1.1 200"), "the profile request was not answered 200")
	testing.expect(
		t,
		strings.contains(reply, DOH_MOBILECONFIG_CONTENT_TYPE),
		"the response is not the Apple profile content type",
	)
	testing.expect(
		t,
		strings.contains(reply, "https://dns.example/dns-query"),
		"the profile does not carry the URL built from the Host header",
	)
	free_all(context.temp_allocator)
}

/*
A POST to the profile path is a 405.

The profile is a download, reached by navigating to it, so only GET makes sense;
a POST there is a client using the endpoint wrong, and telling it so is better
than building a profile for a request that was never going to install one.
*/
@(test)
test_serve_doh_profile_rejects_post :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if lerr != nil {
		testing.expectf(t, false, "cannot listen on loopback: %v", lerr)
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if berr != nil {
		testing.expectf(t, false, "cannot read the bound port: %v", berr)
		return
	}

	client, derr := net.dial_tcp_from_endpoint(bound)
	if derr != nil {
		testing.expectf(t, false, "cannot dial the listener: %v", derr)
		return
	}
	defer net.close(client)

	accepted, _, aerr := net.accept_tcp(listener)
	if aerr != nil {
		testing.expectf(t, false, "nothing connected: %v", aerr)
		return
	}
	defer net.close(accepted)
	_ = net.set_option(accepted, .Receive_Timeout, 500 * time.Millisecond)

	cfg := config.default_config()
	s := Server {
		cfg = &cfg,
	}
	session := Mc_Session {
		server = &s,
		conn   = Conn{socket = accepted},
	}
	handler := thread.create_and_start_with_poly_data(&session, run_serve_doh_mc)
	defer {
		thread.join(handler)
		thread.destroy(handler)
	}

	request := "POST /apple-doh.mobileconfig HTTP/1.1\r\nHost: dns.example\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
	if !mc_send_all(t, client, request) {
		net.shutdown(client, .Send)
		return
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

	testing.expect(
		t,
		strings.contains(strings.to_string(answer), "HTTP/1.1 405"),
		"a POST to the profile path should be a 405",
	)
	free_all(context.temp_allocator)
}
