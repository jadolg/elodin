package config

import "core:testing"
import "core:time"

/*
An upstream `timeout` under a millisecond or over a day is refused, at the top
level and on a route (#499).

It is what every exchange with one server is given, and a query's budget is two
of them, so zero is not "wait as long as it takes": the query has run out before
it starts, a dial gets a one-millisecond connect window, and every query answers
SERVFAIL. A millisecond is the smallest wait the sockets and `poll` underneath
can express, so anything shorter reads as zero there too. Past a day the far end
is the same failure: the dial's millisecond count wraps past about 596h, and two
of a timeout past about 1.28 million hours overflow into a spent budget.
*/
@(test)
test_an_upstream_timeout_outside_1ms_to_24h_is_refused :: proc(t: ^testing.T) {
	// The bound's refusal and nothing else: a parse error names the key too.
	refused :: proc(t: ^testing.T, doc, key: string, loc := #caller_location) {
		expect_refused(t, doc, key, "1ms to 24h:", exactly_one = true, loc = loc)
	}
	refused(t, "upstream:\n  timeout: 0s\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(t, "upstream:\n  timeout: 0.5ms\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(t, "upstream:\n  timeout: 600h\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(t, "upstream:\n  timeout: 99999999999999999999h\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(t, "upstream:\n  timeout: 99999999999999999999h99999999999999999999h5s\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(
		t,
		MINIMAL + "  zones:\n    - domains: [home.arpa]\n      timeout: 0\n      servers: [192.168.1.1]\n",
		"upstream.zones[0].timeout",
	)

	// A route whose timeout does not parse is reported once, as that, even
	// when the figure it would otherwise inherit was refused.
	{
		_, err := load_string(
			"upstream:\n  timeout: 0s\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: soon\n      servers: [192.168.1.1]\n",
			context.temp_allocator,
		)
		e, has := err.?
		if testing.expect(t, has, "an unparsable route timeout was accepted") {
			testing.expectf(t, len(e.messages) == 2, "want the top level's refusal and the route's parse error: %v", e.messages)
		}
	}

	// The smallest and largest figures that are a wait, at both levels.
	if cfg, ok := expect_loads(t, "upstream:\n  timeout: 1ms\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: 24h\n      servers: [192.168.1.1]\n"); ok {
		testing.expect_value(t, cfg.upstream.timeout, time.Millisecond)
		testing.expect_value(t, cfg.upstream.zones[0].upstream.timeout, 24 * time.Hour)
	}
	free_all(context.temp_allocator)
}
