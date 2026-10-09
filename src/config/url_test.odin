package config

import "core:testing"

/*
A DoH upstream's url is sent as written from the path on, query and all: some
services name the account in the query, and without it every query goes to
the service's default. A url with no path is still
`/dns-query`, with the query after it. Both forms of upstream, the map and the
bare url, read it the same way.
*/
@(test)
test_a_doh_upstream_keeps_its_query :: proc(t: ^testing.T) {
	Case :: struct {
		src, want: string,
	}
	cases := []Case {
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query?profile=ab12\"]\n", "/dns-query?profile=ab12"},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"https://dns.example/q?profile=ab12#x\"}]\n", "/q?profile=ab12"},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example?profile=ab12\"]\n", "/dns-query?profile=ab12"},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"https://dns.example:8443\"}]\n", "/dns-query"},
	}
	for c in cases {
		cfg, err := load_string(c.src, context.temp_allocator)
		if e, has := err.?; has {
			testing.expectf(t, false, "%q: %v", c.src, e.messages)
			continue
		}
		if testing.expectf(t, len(cfg.upstream.servers) == 1, "%q: %d servers", c.src, len(cfg.upstream.servers)) {
			testing.expect_value(t, cfg.upstream.servers[0].path, c.want)
		}
	}
	// And a url that is no url is told so, not read as a host.
	_, err := load_string("upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"dns.example/dns-query\"}]\n", context.temp_allocator)
	_, has := err.?
	testing.expect(t, has, "a url with no scheme was accepted")
	free_all(context.temp_allocator)
}
