package config

import "core:fmt"
import "core:testing"

/*
A DoH upstream's url is sent as written from the path on, query and all: some
services name the account in the query, and without it every query goes to
the service's default. A url with no path is `/` (RFC 3986 6.2.3), with the
query after it, its order, repeated keys and escapes kept, and the host and
port end at the first `/`, `?` or `#` (RFC 3986 3.2). Both forms of upstream,
the map and the bare url, read it the same way, and the scheme in any case
(RFC 3986 3.1).
*/
@(test)
test_a_doh_upstream_keeps_its_query :: proc(t: ^testing.T) {
	Case :: struct {
		src, want: string,
		port:      int,
	}
	cases := []Case {
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query?profile=ab12&b=1&b=2\"]\n", "/dns-query?profile=ab12&b=1&b=2", 443},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"HTTPS://dns.example/q?profile=ab12&b=2&b=1&c=%2f+#x\"}]\n", "/q?profile=ab12&b=2&b=1&c=%2f+", 443},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"Https://dns.example?profile=ab12\"]\n", "/?profile=ab12", 443},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"https://dns.example:8443\"}]\n", "/", 8443},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example:8443?profile=ab12#x\"]\n", "/?profile=ab12", 8443},
	}
	for c in cases {
		cfg, err := load_string(c.src, context.temp_allocator)
		if e, has := err.?; has {
			testing.expectf(t, false, "%q: %v", c.src, e.messages)
			continue
		}
		if testing.expectf(t, len(cfg.upstream.servers) == 1, "%q: %d servers", c.src, len(cfg.upstream.servers)) {
			s := cfg.upstream.servers[0]
			testing.expect_value(t, s.path, c.want)
			testing.expect_value(t, s.hostname, "dns.example")
			testing.expect_value(t, s.port, c.port)
		}
	}
	// And a url that is no url is told so, not read as a host.
	_, err := load_string("upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"dns.example/dns-query\"}]\n", context.temp_allocator)
	_, has := err.?
	testing.expect(t, has, "a url with no scheme was accepted")
	free_all(context.temp_allocator)
}

/*
RFC 3986 3.1: a scheme is compared without regard to case, at every place the
config reads one: `HTTPS://` names a list url, not a file, and `TLS://` a DoT
upstream. And a list url is an http or https one, in either spelling of a list,
since the fetcher reads no other scheme.
*/
@(test)
test_a_scheme_is_read_in_any_case :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [\"TLS://1.1.1.1#one.one.one.one\"]\nblocking:\n  lists:\n    - HTTPS://lists.example/hosts\n",
		context.temp_allocator,
	)
	if e, has := err.?; has {
		testing.expectf(t, false, "%v", e.messages)
	} else {
		testing.expect_value(t, cfg.upstream.servers[0].kind, Upstream_Kind.TLS)
		testing.expect_value(t, cfg.blocking.lists[0].url, "HTTPS://lists.example/hosts")
		testing.expect_value(t, cfg.blocking.lists[0].file, "")
	}
	for list in ([]string{"{url: \"ftp://lists.example/hosts\"}", "{url: \"lists.example/hosts\"}"}) {
		_, lerr := load_string(
			fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists:\n    - %s\n", list),
			context.temp_allocator,
		)
		_, has := lerr.?
		testing.expectf(t, has, "%s was accepted", list)
	}
	free_all(context.temp_allocator)
}
