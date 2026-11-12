package config

import "core:slice"
import "core:strings"
import "core:testing"

/*
A list or a mapping where a word belongs is refused with the key's name, on every
key that is read as one word: the same "expected a string" every other string key
gives, not the default left in force as if the key were not there.
*/
@(test)
test_non_string_scalar_keys_are_refused :: proc(t: ^testing.T) {
	Case :: struct {
		src:  string, // `%s` is the value under test
		want: string,
	}
	cases := []Case {
		{"log:\n  level: %s\n", "log.level: expected a string"},
		{"upstream:\n  strategy: %s\n", "upstream.strategy: expected a string"},
		{
			"upstream:\n  zones:\n    - domains: [corp.example]\n      servers: [10.0.0.1]\n      strategy: %s\n",
			"upstream.zones[0].strategy: expected a string",
		},
		{"upstream:\n  servers:\n    - address: 1.1.1.1\n      type: %s\n", "upstream.servers[0].type: expected a string"},
		{
			"upstream:\n  zones:\n    - domains: [corp.example]\n      servers:\n        - address: 10.0.0.1\n          type: %s\n",
			"upstream.zones[0].servers[0].type: expected a string",
		},
		{
			"blocking:\n  lists:\n    - url: https://example.com/hosts\n      format: %s\n",
			"blocking.lists[0].format: expected a string",
		},
		{
			"blocking:\n  allowlists:\n    - file: allow.txt\n      format: %s\n",
			"blocking.allowlists[0].format: expected a string",
		},
		{"blocking:\n  response: %s\n", "blocking.response: expected a string"},
		{"blocking:\n  custom_ipv4: %s\n", "blocking.custom_ipv4: expected a string"},
		{"blocking:\n  custom_ipv6: %s\n", "blocking.custom_ipv6: expected a string"},
	}
	for c in cases {
		for v in ([]string{"[x]", "{x: y}"}) {
			src, _ := strings.replace_all(c.src, "%s", v, context.temp_allocator)
			_, err := load_string(src, context.temp_allocator)
			e, has := err.?
			if !testing.expectf(t, has, "loaded clean:\n%s", src) {
				continue
			}
			found := false
			for m in e.messages {
				if m == c.want {
					found = true
					break
				}
			}
			testing.expectf(t, found, "no %q for:\n%s\ngot %v", c.want, src, e.messages)
		}
	}
}

/*
`type: [tls]` on an upstream given by address does not load at all: read as no
`type`, it would be plain UDP to port 53, an encrypted upstream asked for and
plaintext sent with nothing said.
*/
@(test)
test_upstream_type_list_does_not_load_as_udp :: proc(t: ^testing.T) {
	src := "upstream:\n  servers:\n    - address: 1.1.1.1\n      type: [tls]\n"
	cfg, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if !testing.expectf(t, has, "type: [tls] loaded, as %v", cfg.upstream.servers) {
		return
	}
	// Refused for the `type`, not for some other reason that would pass this
	// with the list still read as no `type`.
	testing.expectf(
		t,
		slice.contains(e.messages, "upstream.servers[0].type: expected a string"),
		"refused for something else: %v",
		e.messages,
	)
}

// A key written empty (`type:` or `type: ~`) is still the key left out, and a
// quoted empty string is still a word nobody knows.
@(test)
test_upstream_type_null_keeps_default :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers:\n    - address: 1.1.1.1\n      type: ~\n    - url: https://9.9.9.9/dns-query\n      type:\n",
		context.temp_allocator,
	)
	if !testing.expectf(t, err == nil, "%v", err) {
		return
	}
	testing.expect_value(t, cfg.upstream.servers[0].kind, Upstream_Kind.UDP)
	testing.expect_value(t, cfg.upstream.servers[1].kind, Upstream_Kind.HTTPS)

	_, err = load_string("upstream:\n  servers:\n    - address: 1.1.1.1\n      type: \"\"\n", context.temp_allocator)
	testing.expect(t, err != nil, "type: \"\" loaded")
}

// `null` is one of `blocking.response`'s names, and written bare it is that mode,
// not YAML's empty value leaving the default nxdomain in force.
@(test)
test_blocking_response_null_is_zero_ip :: proc(t: ^testing.T) {
	for v in ([]string{"null", "Null", "NULL", "\"null\""}) {
		src := strings.concatenate({MINIMAL + "blocking:\n  response: ", v, "\n"}, context.temp_allocator)
		cfg, err := load_string(src, context.temp_allocator)
		if !testing.expectf(t, err == nil, "%s: %v", v, err) {
			continue
		}
		testing.expectf(t, cfg.blocking.response == .Zero_IP, "%s: %v", v, cfg.blocking.response)
	}
	for v in ([]string{"~", ""}) {
		src := strings.concatenate({MINIMAL + "blocking:\n  response: ", v, "\n"}, context.temp_allocator)
		cfg, err := load_string(src, context.temp_allocator)
		if !testing.expectf(t, err == nil, "%q: %v", v, err) {
			continue
		}
		testing.expectf(t, cfg.blocking.response == .NX_Domain, "%q: %v", v, cfg.blocking.response)
	}
}
