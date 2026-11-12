package config

import "core:strings"
import "core:testing"

/*
A listener on port 0 binds whichever port the kernel picks, which no client can
be told, and one past 65535 is no port at all (#316). Either way the server
would come up somewhere nothing asked for, so both are refused - the metrics
endpoint's rule, and like it only for a listener that binds.
*/
@(test)
test_a_listener_port_outside_1_to_65535_is_refused :: proc(t: ^testing.T) {
	base :: MINIMAL + "listeners:\n"
	for key in ([]string{"udp", "tcp"}) {
		path := strings.concatenate({"listeners.", key, ".port"}, context.temp_allocator)
		for port in ([]string{"0", "-1", "65536", "106837"}) {
			doc := strings.concatenate({base, "  ", key, ":\n    enabled: true\n    port: ", port, "\n"}, context.temp_allocator)
			expect_refused(t, doc, path, "between 1 and 65535")
		}
		expect_loads(t, strings.concatenate({base, "  ", key, ":\n    enabled: true\n    port: 65535\n"}, context.temp_allocator))
		expect_loads(t, strings.concatenate({base, "  ", key, ":\n    enabled: false\n    port: 0\n"}, context.temp_allocator))
		// Only 0 is let through on a disabled listener: past either edge is no
		// port whether or not it binds.
		for port in ([]string{"-1", "65536"}) {
			doc := strings.concatenate({base, "  ", key, ":\n    enabled: false\n    port: ", port, "\n"}, context.temp_allocator)
			expect_refused(t, doc, path, "between 1 and 65535")
		}
	}
	// DoT and DoH go through the same check; their certificates are checked
	// later, so the port is what is read here.
	expect_refused(t, base + "  dot:\n    enabled: true\n    port: 0\n", "listeners.dot.port", "between 1 and 65535")
	expect_refused(t, base + "  doh:\n    enabled: true\n    port: 0\n", "listeners.doh.port", "between 1 and 65535")
	free_all(context.temp_allocator)
}

/*
RFC 2181 section 8: a TTL is 0 to 2^31-1, and a receiver treats one with the top
bit set as zero, so a rewrite TTL of -1 cast to 4294967295 is no TTL at all
(#316), and the same holds for every other TTL this file sets - the cache's and
the block answers'. Each is refused, at both ends, by name, and so is a fraction
of a second, which no TTL can carry.
*/
@(test)
test_a_ttl_outside_rfc_2181_range_is_refused :: proc(t: ^testing.T) {
	rw :: proc(ttl: string) -> string {
		return strings.concatenate(
			{MINIMAL + "rewrites:\n  - domain: nas.home\n    answer: 192.168.1.50\n    ttl: ", ttl, "\n"},
			context.temp_allocator,
		)
	}
	expect_refused(t, rw("-1"), "rewrites[0].ttl", "0 to 2147483647")
	expect_refused(t, rw("2147483648"), "rewrites[0].ttl", "0 to 2147483647")
	expect_refused(t, rw("4294967295"), "rewrites[0].ttl", "0 to 2147483647")
	expect_loads(t, rw("2147483647"))
	expect_loads(t, rw("0"))
	// Written as a duration, as every other TTL key can be, or as any YAML
	// integer, and read as the seconds it says.
	for c in ([]struct {
			v:    string,
			secs: u32,
		}{{"5m", 300}, {"3_600", 3600}, {"0x12c", 300}, {"1.5m", 90}, {"2.3h", 8280}}) {
		cfg, err := load_string(rw(c.v), context.temp_allocator)
		if testing.expectf(t, err == nil, "%s refused: %v", c.v, err) {
			testing.expectf(t, cfg.rewrites[0].ttl == c.secs, "%s read as %d", c.v, cfg.rewrites[0].ttl)
		}
	}
	// A fraction is cut off nowhere: "500ms" is not a TTL of 0.
	for v in ([]string{"500ms", "1.5", "0.5s"}) {
		expect_refused(t, rw(v), "rewrites[0].ttl", "whole seconds")
	}

	for key in ([]string{"min_ttl", "max_ttl", "negative_ttl", "prefetch_min_ttl"}) {
		doc := strings.concatenate({MINIMAL + "cache:\n  ", key, ": 2147483648\n"}, context.temp_allocator)
		expect_refused(t, doc, strings.concatenate({"cache.", key}, context.temp_allocator), "0 to 2147483647")
	}
	expect_refused(t, MINIMAL + "blocking:\n  block_ttl: 2147483648\n", "blocking.block_ttl", "0 to 2147483647")
	expect_refused(t, MINIMAL + "blocking:\n  block_ttl: -1\n", "blocking.block_ttl", "0 to 2147483647")
	// Past 2^64 an integer is still out of range, not wrapped round to 1.
	for v in ([]string{"18446744073709551617", "-18446744073709551615"}) {
		expect_refused(t, rw(v), "rewrites[0].ttl", "0 to 2147483647")
		doc := strings.concatenate({MINIMAL + "cache:\n  min_ttl: ", v, "\n"}, context.temp_allocator)
		expect_refused(t, doc, "cache.min_ttl", "0 to 2147483647")
	}
	expect_loads(t, MINIMAL + "cache:\n  min_ttl: 2147483647\n  max_ttl: 2147483647\n")
	expect_loads(t, MINIMAL + "blocking:\n  block_ttl: 2147483647\n")
	free_all(context.temp_allocator)
}

/*
`client_timeout` is how long an idle client connection is held. RFC 7766 6.2.3
recommends an idle period "on the order of seconds" and warns that long ones
exhaust a server; zero there means closing at once, while SO_RCVTIMEO reads a
zero timeval - and anything under a microsecond truncates to one - as forever
(#316). Refused under a millisecond, the same floor as `upstream.timeout`, and
over a day, where a message's deadline added to the clock would wrap into one
already spent.
*/
@(test)
test_a_client_timeout_outside_1ms_to_24h_is_refused :: proc(t: ^testing.T) {
	doc :: proc(v: string) -> string {
		return strings.concatenate({MINIMAL + "server:\n  client_timeout: ", v, "\n"}, context.temp_allocator)
	}
	for v in ([]string{"0s", "0", "0.5us", "999us", "0.5ms"}) {
		expect_refused(t, doc(v), "server.client_timeout", "from 1ms to 24h")
	}
	for v in ([]string{"24h1s", "9999999999", "1000000d"}) {
		expect_refused(t, doc(v), "server.client_timeout", "from 1ms to 24h")
	}
	// A duration has no sign, so this one never parses.
	expect_refused(t, doc("-1s"), "server.client_timeout", "expected a duration")
	expect_loads(t, doc("1ms"))
	expect_loads(t, doc("10s"))
	expect_loads(t, doc("24h"))
	free_all(context.temp_allocator)
}
