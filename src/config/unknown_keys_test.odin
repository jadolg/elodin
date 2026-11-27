package config

import "core:path/filepath"
import "core:strings"
import "core:testing"

/*
A key nobody reads is refused, at every level of the file.

Each line below is a misspelling or a mis-nesting of a real key, and each one
would pass `--check` with the default left in force - rebind protection off,
RRL at 500 - if the loader only asked for the keys it knew.
*/
@(test)
test_unknown_keys_are_refused :: proc(t: ^testing.T) {
	src := `
rebind:
  enable: true
server:
  max_connection_per_prefix: 24
  rate_limit:
    response_per_second: 50
    overrides:
      - { prefix: 198.51.100.0/24, responses_per_second: 5, slp: 1 }
rate_limit:
  enabled: true
listeners:
  udp: { enabled: true, recieve_buffer: 1MiB }
upstream:
  servers:
    - { address: 1.1.1.1, verfiy: false }
  zones:
    - domains: [corp.example]
      servers: [10.0.0.1]
      stratgy: race
blocking:
  lists:
    - { url: "https://example.com/list", fromat: hosts }
rewrites:
  - { domain: nas.home, answer: 192.168.1.50, tll: 60 }
cookies:
  requires: true
`
	for want in ([]string {
			"rebind.enable",
			"server.max_connection_per_prefix",
			"server.rate_limit.response_per_second",
			"server.rate_limit.overrides[0].slp",
			"rate_limit",
			"listeners.udp.recieve_buffer",
			"upstream.servers[0].verfiy",
			"upstream.zones[0].stratgy",
			"blocking.lists[0].fromat",
			"rewrites[0].tll",
			"cookies.requires",
		}) {
		expect_refused(t, src, strings.concatenate({want, ": unknown key"}, context.temp_allocator), exact = true)
	}
}

/*
A section written as one value or a list, where its settings belong, is refused
too: `yaml.keys` has nothing to offer for it, so `rebind: true` would read as a
section with no keys in it and leave rebind protection off. And a list written
as one value or a mapping - a single URL for `blocking.lists`, one rule under
`rewrites` with no `-` - would read as an empty list.
*/
@(test)
test_misshapen_sections_are_refused :: proc(t: ^testing.T) {
	cases := [][2]string {
		{"rebind: true\n", "rebind: expected"},
		{"server:\n  rate_limit: false\n", "server.rate_limit: expected"},
		{"listeners:\n  doh: true\n", "listeners.doh: expected"},
		{"cookies: [require]\n", "cookies: expected"},
		{"rewrites:\n  domain: nas.home\n  answer: 192.168.1.50\n", "rewrites: expected"},
		{"blocking:\n  lists: https://example.com/hosts\n", "blocking.lists: expected"},
		{"blocking:\n  lists:\n    -\n", "blocking.lists[0]: needs either a url or a file"},
		{"upstream:\n  servers:\n    address: 10.0.0.1\n", "upstream.servers: expected"},
		{
			MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers:\n        address: 10.0.0.1\n",
			"upstream.zones[0].servers: expected",
		},
	}
	for c in cases {
		// A case about `upstream` writes the section itself: a second one would
		// be refused as a duplicate key before the loader saw either.
		src := c[0]
		if !strings.has_prefix(src, "upstream:") {
			src = strings.concatenate({MINIMAL, c[0]}, context.temp_allocator)
		}
		expect_refused(t, src, c[1], prefix = true)
	}
	free_all(context.temp_allocator)
}

// A list entry in the wrong shape is said to be that once, not also reported as
// missing every key it was meant to hold.
@(test)
test_a_misshapen_entry_is_one_error :: proc(t: ^testing.T) {
	for src in ([]string {
			MINIMAL + "rewrites:\n  - nas.home\n",
			MINIMAL + "blocking:\n  lists:\n    - [a, b]\n",
			"upstream:\n  servers:\n    - 1.1.1.1\n    - [9.9.9.9]\n",
		}) {
		expect_refused(t, src, "expected a mapping", count = 1)
	}
	free_all(context.temp_allocator)
}

// Every shipped example still loads: each key in them is one the loader reads.
@(test)
test_examples_load :: proc(t: ^testing.T) {
	paths, gerr := filepath.glob("examples/*.yaml", context.temp_allocator)
	testing.expectf(t, gerr == nil, "examples/*.yaml: %v", gerr)
	testing.expect(t, len(paths) > 0, "no examples found; run from the repository root")
	for p in paths {
		// Docker Compose's files, which run the image with examples/docker.yaml
		// and examples/docker-public.yaml and are no configuration of elodin's.
		if base := filepath.base(p); base == "compose.yaml" || base == "compose-public.yaml" {
			continue
		}
		// Any refusal but a missing file: an example naming a certificate that is
		// not on this machine is refused for that, and rightly. Matching only
		// "unknown key" would let a duplicate key (a parse error) or a section in
		// the wrong shape through.
		_, err := load_file(p, context.temp_allocator)
		if e, has := err.?; has {
			for m in e.messages {
				testing.expectf(t, strings.has_suffix(m, "does not exist"), "%s: %s", p, m)
			}
		}
	}
}
