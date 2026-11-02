package config

import "core:fmt"
import "core:strings"
import "core:testing"

@(private = "file")
DDR_BASE :: "upstream:\n  servers: [9.9.9.9]\nlisteners:\n  dot: {{enabled: true, cert_file: c.pem, key_file: k.pem}}\n  doh: {{enabled: %s, cert_file: c.pem, key_file: k.pem, path: %q}}\n"

@(private = "file")
ddr_load :: proc(name: string, doh := false, path := "/dns-query") -> (Config, string) {
	src := fmt.tprintf(DDR_BASE, "true" if doh else "false", path)
	if name != "" {
		src = fmt.tprintf("%sddr:\n  name: %q\n", src, name)
	}
	cfg, err := load_string(src, context.temp_allocator, tls_files = false)
	if e, has := err.?; has {
		return cfg, strings.join(e.messages, "; ", context.temp_allocator)
	}
	return cfg, ""
}

@(test)
test_ddr_is_off_by_default :: proc(t: ^testing.T) {
	cfg, msg := ddr_load("")
	testing.expect_value(t, msg, "")
	testing.expect_value(t, cfg.ddr.name, "")
}

@(test)
test_ddr_name_is_canonical :: proc(t: ^testing.T) {
	cfg, msg := ddr_load("DNS.Example.COM", doh = true)
	testing.expect_value(t, msg, "")
	testing.expect_value(t, cfg.ddr.name, "dns.example.com.")
}

// RFC 9462 section 4: the TargetName MUST NOT be the root or `resolver.arpa`;
// and it is a hostname a certificate covers, so neither an address nor a label
// outside letters, digits and hyphens.
@(test)
test_ddr_name_must_be_a_hostname_outside_resolver_arpa :: proc(t: ^testing.T) {
	for name in ([]string{".", "resolver.arpa", "_dns.resolver.arpa.", "192.168.1.1", "::1", "dns_1.example", "-a.example", "a..example", "*.example", "dns.example.123"}) {
		_, msg := ddr_load(name)
		testing.expectf(t, strings.contains(msg, "ddr.name"), "%q was accepted: %q", name, msg)
	}
}

@(test)
test_ddr_needs_an_encrypted_listener :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [9.9.9.9]\nddr:\n  name: dns.example\n"
	_, err := load_string(src, context.temp_allocator, tls_files = false)
	e, has := err.?
	testing.expect(t, has && strings.contains(e.messages[0], "nothing to designate"), "a designation with no DoT or DoH listener loaded")
}

// The dohpath is the path with `{?dns}` after it (RFC 9461 section 5), so it
// has to be literal text to a URI template (RFC 6570 section 2.1).
@(test)
test_ddr_needs_a_doh_path_a_template_takes :: proc(t: ^testing.T) {
	for path in ([]string{"/dns{x}", "/a|b", "/a^b", "/50%", "/%zz"}) {
		_, msg := ddr_load("dns.example", doh = true, path = path)
		testing.expectf(t, strings.contains(msg, "dohpath"), "%q was accepted: %q", path, msg)
	}
	_, msg := ddr_load("dns.example", doh = true, path = "/dns-query/%2Fx")
	testing.expect_value(t, msg, "")
	// The rule is the designation's: without it the same path is a DoH path.
	_, msg = ddr_load("", doh = true, path = "/dns{x}")
	testing.expect_value(t, msg, "")
}
