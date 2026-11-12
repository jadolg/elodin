package config

import "core:fmt"
import "core:strings"
import "core:testing"

/*
A name the file does not give is the url up to its query, in both spellings of
an upstream and of a list: a query can carry a key, and the name is what the log
and the `upstream` label on /metrics show (#487).
*/
@(test)
test_a_default_name_holds_no_query :: proc(t: ^testing.T) {
	for src in ([]string {
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query?token=SECRET\"]\n",
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"https://dns.example/dns-query?token=SECRET#frag\"}]\n",
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query#SECRET\"]\n",
	}) {
		cfg, ok := expect_loads(t, src)
		if !ok {
			continue
		}
		s := cfg.upstream.servers[0]
		testing.expect_value(t, s.name, "https://dns.example/dns-query")
		// The query is still what the upstream is asked with.
		testing.expect(t, strings.contains(s.path, "SECRET") == strings.contains(src, "?token"))
	}
	for list in ([]string{"https://lists.example/hosts?key=SECRET", "{url: \"https://lists.example/hosts?key=SECRET#x\"}"}) {
		cfg, ok := expect_loads(t, fmt.tprintf(MINIMAL + "blocking:\n  lists:\n    - %s\n", list))
		if !ok {
			continue
		}
		testing.expect_value(t, cfg.blocking.lists[0].name, "https://lists.example/hosts")
		testing.expect(t, strings.contains(cfg.blocking.lists[0].url, "key=SECRET"))
	}
	// A name the file gives is kept as written.
	if cfg, ok := expect_loads(t, "upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"mine?x\", url: \"https://dns.example/q?token=SECRET\"}]\n"); ok {
		testing.expect_value(t, cfg.upstream.servers[0].name, "mine?x")
	}
	// A list's given name keys its copy alone, though it spells the url up to
	// its query: the copy an earlier build cached under that name is still it.
	if cfg, ok := expect_loads(t, MINIMAL + "blocking:\n  lists: [{name: \"https://l.example/h\", url: \"https://l.example/h?k=1\"}]\n"); ok {
		testing.expect_value(t, list_cache_file(cfg.blocking.lists[0]), "https___l.example_h.list")
	}
	free_all(context.temp_allocator)
}

/*
Two servers that come to one name only because the query was cut are refused,
since their counters would sum into one series; so are two lists that would share
one cache file. A name two servers shared before the cut, and lists that differ
in their cache file, are not.
*/
@(test)
test_a_default_name_names_one_thing :: proc(t: ^testing.T) {
	Case :: struct {
		src: string,
		ok:  bool,
	}
	cases := []Case {
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\", \"https://dns.example/q?a=2\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\"]\n  zones:\n    - domains: [corp.example]\n      servers: [{url: \"https://dns.example/q?a=2\"}]\n", false},
		{"upstream:\n  servers: [\"tls://1.1.1.1#one.one.one.one\", \"tls://1.1.1.1#cloudflare-dns.com\"]\n", true},
		{"upstream:\n  servers: [{url: \"https://dns.google/dns-query?a=1\", address: 8.8.8.8}, {url: \"https://dns.google/dns-query?a=1\", address: 8.8.4.4}]\n", true},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://dns.example/r\"}, \"https://dns.example/q\"]\n", true},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://dns.example/r\"}, \"https://dns.example/q?a=1\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://other.example/q?a=1\"}, \"https://dns.example/q?a=1\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\"]\n  zones:\n    - domains: [corp.example]\n      servers: [\"https://dns.example/q?a=1#x\"]\n", true},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: a, url: \"https://dns.example/q?a=1\"}, {name: b, url: \"https://dns.example/q?a=2\"}]\n", true},
		// A fragment is cut too: a given name equal to a cut url on another host.
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q#x\", {name: \"https://dns.example/q\", url: \"https://other.example/z\"}]\n", false},
		// One name the file gives two servers, though it spells a url up to a query.
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://dns.example/q?a=1\"}, {name: \"https://dns.example/q\", url: \"https://dns.example/q?a=2\"}]\n", true},
		// The cut server is one url with the first and another server with the
		// third: it is held against every server of its name, not the first alone.
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://dns.example/q?a=1\"}, \"https://dns.example/q?a=1\", {name: \"https://dns.example/q\", url: \"https://other.example/z\"}]\n", false},
		{"upstream:\n  servers: [{name: cf, address: 1.1.1.1}, {name: cf, address: 1.0.0.1}]\n", true},
		{"upstream:\n  servers: [\"1.1.1.1\"]\n  zones:\n    - domains: [corp.example]\n      servers: [{address: 1.1.1.1, verify: false, hostname: x.example}]\n", true},
		{MINIMAL + "blocking:\n  lists: [\"https://l.example/h?k=1\"]\n  allowlists: [\"https://l.example/h?k=2\"]\n", false},
		{MINIMAL + "blocking:\n  lists: [{name: \"https://l.example/h\", url: \"https://l.example/x\"}]\n  allowlists: [\"https://l.example/h\"]\n", false},
		{MINIMAL + "blocking:\n  lists: [{name: x, url: \"https://l.example/a\"}, {name: x, url: \"https://l.example/b\"}]\n", false},
		{MINIMAL + "blocking:\n  lists: [\"https://l.example/a_b\", \"https://l.example/a/b\"]\n", false},
		{MINIMAL + "blocking:\n  enabled: false\n  lists: [\"https://l.example/a_b\", \"https://l.example/a/b\"]\n", true},
		{MINIMAL + "blocking:\n  lists: [\"https://l.example/h?k=1\", {name: two, url: \"https://l.example/h?k=2\"}, {url: \"https://l.example/h?k=3\", enabled: false}]\n", true},
		{MINIMAL + "blocking:\n  lists: [\"https://l.example/h?k=1\"]\n  allowlists: [\"https://l.example/h?k=1\"]\n", true},
		{MINIMAL + "blocking:\n  lists: [\"https://l.example/h?k=1\", \"https://l.example/h?k=1#x\"]\n", true},
		{MINIMAL + "blocking:\n  lists: [{url: \"https://l.example/h?k=1\", file: /a}, {url: \"https://l.example/h?k=2\", file: /b}]\n", true},
	}
	for c in cases {
		_, err := load_string(c.src, context.temp_allocator)
		e, has := err.?
		testing.expectf(t, has != c.ok, "%q: refused %v (%v)", c.src, has, e.messages if has else nil)
		if has {
			for m in e.messages {
				testing.expectf(t, !strings.contains(m, "a=") && !strings.contains(m, "k="), "the refusal shows the query: %s", m)
			}
		}
	}
	free_all(context.temp_allocator)
}
