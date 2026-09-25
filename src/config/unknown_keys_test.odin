package config

import "core:path/filepath"
import "core:strings"
import "core:testing"

/*
A key nobody reads is refused, at every level of the file.

Each line below is a misspelling or a mis-nesting of a real key, and each one
used to pass `--check` with the default left in force - rebind protection off,
RRL at 500 - because the loader only ever asked for the keys it knew.
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
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if !testing.expect(t, has, "a file full of misspelt keys loaded clean") {
		return
	}
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
		found := false
		for m in e.messages {
			if strings.has_prefix(m, want) && strings.contains(m, "unknown key") {
				found = true
				break
			}
		}
		testing.expectf(t, found, "no unknown-key error for %s in %v", want, e.messages)
	}
}

/*
A section written as one value or a list, where its settings belong, is refused
too: `yaml.keys` has nothing to offer for it, so `rebind: true` read as a
section with no keys in it and left rebind protection off. And a list written
as one value or a mapping - a single URL for `blocking.lists`, one rule under
`rewrites` with no `-` - read as an empty list.
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
	}
	for c in cases {
		src := strings.concatenate({"upstream:\n  servers: [1.1.1.1]\n", c[0]}, context.temp_allocator)
		_, err := load_string(src, context.temp_allocator)
		e, has := err.?
		found := false
		for m in e.messages {
			if strings.has_prefix(m, c[1]) {
				found = true
				break
			}
		}
		testing.expectf(t, has && found, "%q: no %q error in %v", c[0], c[1], e.messages)
	}
	free_all(context.temp_allocator)
}

// Every shipped example still loads: each key in them is one the loader reads.
@(test)
test_examples_load :: proc(t: ^testing.T) {
	paths, _ := filepath.glob("examples/*.yaml", context.temp_allocator)
	testing.expect(t, len(paths) > 0, "no examples found; run from the repository root")
	for p in paths {
		// Only this check's refusals: an example naming a certificate that is not
		// on this machine is refused for that, and rightly.
		_, err := load_file(p, context.temp_allocator)
		e, _ := err.?
		for m in e.messages {
			testing.expectf(t, !strings.contains(m, "unknown key"), "%s: %s", p, m)
		}
	}
}
