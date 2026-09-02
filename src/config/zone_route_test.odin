package config

import "core:strings"
import "core:testing"
import "core:time"

/*
`upstream.zones`: the per-domain upstreams.

A route is the only thing in this file that changes where a query goes, so the
ways it can be written wrong are the ways a zone silently keeps going to the
public resolver. Every refusal below is one of those - a form that would sit in
the configuration looking like the fix while nothing about the deployment
changed.
*/

@(private = "file")
ROUTED :: `
upstream:
  strategy: race
  timeout: 3s
  attempts: 3
  bootstrap: [1.1.1.1]
  servers: [1.1.1.1, 9.9.9.9]
  zones:
    - domains: [corp.example, "DEV.corp.example."]
      servers: [10.0.0.1]
    - domains: [home.arpa]
      strategy: failover
      timeout: 1s
      servers:
        - name: router
          type: udp
          address: 192.168.1.1
          port: 53
`

@(test)
test_zone_routes_are_read_with_their_own_servers :: proc(t: ^testing.T) {
	cfg, err := load_string(ROUTED, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "config errors: %v", e.messages)
		return
	}
	if !testing.expect_value(t, len(cfg.upstream.zones), 2) {
		return
	}

	first := cfg.upstream.zones[0]
	// Canonical on the way in: lowercased and root-dotted, whichever way the
	// operator wrote them, so the resolver compares two names that were spelled
	// the same way.
	testing.expect_value(t, len(first.domains), 2)
	testing.expect_value(t, first.domains[0], "corp.example.")
	testing.expect_value(t, first.domains[1], "dev.corp.example.")
	testing.expect_value(t, len(first.upstream.servers), 1)
	testing.expect_value(t, first.upstream.servers[0].address, "10.0.0.1")

	/*
	Inherited from the section it sits in, all of it: an operator who set a
	strategy and a timeout at the top meant them for the file, and a route that
	quietly reverted to the built-in defaults would be a second set of numbers
	nothing in the configuration mentions.
	*/
	testing.expect_value(t, first.upstream.strategy, Strategy.Race)
	testing.expect_value(t, first.upstream.timeout, 3 * time.Second)
	testing.expect_value(t, first.upstream.attempts, 3)
	testing.expect_value(t, len(first.upstream.bootstrap), 1)

	// And overridden where the route says so, which is the reason a route is a
	// whole upstream configuration rather than a list of addresses.
	second := cfg.upstream.zones[1]
	testing.expect_value(t, second.domains[0], "home.arpa.")
	testing.expect_value(t, second.upstream.strategy, Strategy.Failover)
	testing.expect_value(t, second.upstream.timeout, 1 * time.Second)
	testing.expect_value(t, second.upstream.attempts, 3)
	testing.expect_value(t, second.upstream.servers[0].address, "192.168.1.1")

	// The default group keeps its own servers and does not acquire the routes'.
	testing.expect_value(t, len(cfg.upstream.servers), 2)
	free_all(context.temp_allocator)
}

// Nothing configured is every file that predates the feature: no routes, and
// the default upstream answering everything.
@(test)
test_no_zones_means_no_routes :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, len(cfg.upstream.zones), 0)
	free_all(context.temp_allocator)
}

// An explicit empty list is a file saying there are no routes, which is not the
// same statement as a malformed section and must not be refused as one.
@(test)
test_an_empty_zones_list_is_not_an_error :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n  zones: []\n", context.temp_allocator)
	testing.expect(t, err == nil, "an empty zones list was refused")
	testing.expect_value(t, len(cfg.upstream.zones), 0)
	free_all(context.temp_allocator)
}

@(private = "file")
expect_one_error :: proc(t: ^testing.T, src: string, wanted: string, loc := #caller_location) {
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if !testing.expectf(t, has, "expected an error mentioning %q", wanted, loc = loc) {
		return
	}
	found := false
	for msg in e.messages {
		if strings.contains(msg, wanted) {
			found = true
		}
	}
	testing.expectf(t, found, "no error mentioned %q; got %v", wanted, e.messages, loc = loc)
}

/*
A route with nowhere to send the query.

Fatal rather than dropped, and caught here rather than at startup: the name it
claims would fall through to the public upstream, which answers - so the symptom
is not a failure but an internal zone resolving to whatever a public resolver
says about it, which is the leak the route was written to stop.
*/
@(test)
test_a_route_needs_servers :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n",
		"needs at least one server",
	)
}

// And somewhere to send it from: a route with no domains claims nothing.
@(test)
test_a_route_needs_domains :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - servers: [10.0.0.1]\n",
		"has to say which names it takes",
	)
}

/*
The root, which routes every name there is.

That is `upstream.servers` written in a way nothing about the file makes
obvious, and it would take the DNSSEC bypass and the rebinding exemption with it
across the whole name space. Refused for what it is, the same way
`rebind.allow_domains` refuses the root.
*/
@(test)
test_the_root_cannot_be_routed :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [\".\"]\n      servers: [10.0.0.1]\n",
		"routes every name",
	)
}

/*
The two shapes an operator arrives with from elsewhere in this same file, and
from `no_proxy`.

`*.corp.example` is what the rewrites section takes and `.corp.example` is what
`no_proxy` takes; either one kept as written would match nothing a client can
ask for, so every internal name would go on being sent to the public upstream
while the route sat there looking configured.
*/
@(test)
test_a_route_takes_no_wildcard_and_no_empty_label :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [\"*.corp.example\"]\n      servers: [10.0.0.1]\n",
		"takes no wildcard",
	)
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [\".corp.example\"]\n      servers: [10.0.0.1]\n",
		"has an empty label",
	)
}

/*
One zone in two routes.

Not a longest-match question - the two are the same length - so the winner would
be whichever the file happened to list first and the other would sit there
looking configured while nothing ever reached it. The duplicate is named
instead, along with the entry that already claimed it.
*/
@(test)
test_a_zone_cannot_be_routed_twice :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n" +
		"    - domains: [corp.example]\n      servers: [10.0.0.1]\n" +
		"    - domains: [\"CORP.example.\"]\n      servers: [10.0.0.2]\n",
		"already routed by upstream.zones[0]",
	)
}

// Routes do not nest: a `zones` key inside a route is a misreading of the shape,
// and reading it and doing nothing with it is the one response that leaves no
// evidence.
@(test)
test_routes_do_not_nest :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n" +
		"      servers: [10.0.0.1]\n      zones:\n        - domains: [dev.corp.example]\n          servers: [10.0.0.2]\n",
		"routes do not nest",
	)
}

// The two ways to write the section itself wrong: a mapping where a list
// belongs, and a bare string where a route belongs.
@(test)
test_a_malformed_zones_section_is_refused :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    domains: [corp.example]\n",
		"expected a list of routes",
	)
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones: [corp.example]\n",
		"expected a mapping with domains and servers",
	)
}

// A route naming a DoT server by hostname needs a bootstrap resolver exactly as
// the default group does, and the check that says so has to see the route's
// servers as well as the default ones.
@(test)
test_a_routed_hostname_needs_a_bootstrap_resolver :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n" +
		"      servers:\n        - type: tls\n          address: dc.corp.example\n",
		"no bootstrap resolver is configured",
	)
}
