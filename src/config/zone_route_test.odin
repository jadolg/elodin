package config

import "core:fmt"
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

/*
A route into a zone the special-use table answers, which is a route that never
fires.

`special_use_zone` runs in `resolve_query` before anything is forwarded, so with
`special_use.home_arpa` on the names are answered from the table and the route
below them is never consulted. The operator upgrading from the key to a route -
which is exactly what the README sends them to do once their router does answer
the zone - would otherwise keep the key's NXDOMAIN and never see the router.

The control is the same file with the key left at its default, where the route
is the only thing claiming those names and the load is clean.
*/
@(test)
test_a_route_under_an_enabled_special_use_zone_is_refused :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      servers: [192.168.1.1]\n" +
		"special_use:\n  home_arpa: true\n",
		"would never be used",
	)
	// A name below the table's own entry is inside it just as the apex is.
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [lab.test]\n      servers: [10.0.0.1]\n" +
		"special_use:\n  test: true\n",
		"would never be used",
	)
	// And the whole table off puts every one of them back within reach.
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      servers: [192.168.1.1]\n" +
		"special_use:\n  enabled: false\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "a route under a table nothing consults was refused")
	testing.expect_value(t, len(cfg.upstream.zones), 1)
	free_all(context.temp_allocator)
}

/*
A route into `resolver.arpa`, which is the same trap with no key attached.

`is_resolver_arpa` answers that zone in `resolve_query` ahead of everything that
forwards, and no configuration key turns it off - so unlike the special-use
zones above there is no edit that would bring such a route within reach, and
leaving it to load cleanly would leave it looking configured for the life of the
file. Refused whichever way the special-use table is set, which is the second
case here.
*/
@(test)
test_a_route_into_the_ddr_zone_is_refused :: proc(t: ^testing.T) {
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [resolver.arpa]\n      servers: [10.0.0.1]\n",
		"would never be used",
	)
	// A name inside it is inside it just as the apex is, and the whole
	// special-use table off changes nothing about this one.
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [_dns.resolver.arpa]\n      servers: [10.0.0.1]\n" +
		"special_use:\n  enabled: false\n",
		"would never be used",
	)
}

/*
The counterpart to the `attempts` inheritance: a number the route did not write.

`attempts` comes down from the section above, so `upstream.attempts: 0` is one
mistake in one place. Naming every route for it as well would send an operator
editing routes that say nothing about attempts, and the error would still be
there afterwards. One line, about the key that was actually written.
*/
@(test)
test_a_bad_inherited_attempts_is_reported_once :: proc(t: ^testing.T) {
	_, err := load_string(
		"upstream:\n  attempts: 0\n  servers: [1.1.1.1]\n  zones:\n" +
		"    - domains: [corp.example]\n      servers: [10.0.0.1]\n" +
		"    - domains: [lab.example]\n      servers: [10.0.0.2]\n",
		context.temp_allocator,
	)
	e, has := err.?
	if !testing.expect(t, has, "attempts of 0 was accepted") {
		return
	}
	routes_named := 0
	key_named := 0
	for msg in e.messages {
		if strings.contains(msg, "needs attempts of at least 1") {
			routes_named += 1
		}
		if strings.contains(msg, "upstream.attempts must be at least 1") {
			key_named += 1
		}
	}
	testing.expectf(t, routes_named == 0, "the routes were named for an inherited number; got %v", e.messages)
	testing.expect_value(t, key_named, 1)

	// A route that writes the number itself is still its own error.
	expect_one_error(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [corp.example]\n      attempts: 0\n      servers: [10.0.0.1]\n",
		"the route for corp.example. needs attempts of at least 1",
	)
	free_all(context.temp_allocator)
}

/*
A route the operator anchored gives up no validation, and `--check` has to be
able to tell.

`covered_by_local_anchor` stands the route's DNSSEC bypass down for a name an
anchor covers, so the line `main` prints about what a route costs would be
untrue of exactly the file that signed its own zone and said so. The three ways
not to be covered are each their own case: no anchor at all, the root anchor -
which covers every name and validates none of the zones the bypass exists for,
and is left out of `anchor_zones` for that reason - and an anchor sitting below
the routed zone, which leaves the rest of the zone insecure.
*/
@(test)
test_a_route_knows_whether_an_anchor_covers_it :: proc(t: ^testing.T) {
	ROOT :: `". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"`
	DS :: `IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF`

	load :: proc(t: ^testing.T, anchors: string, domains := "[corp.example]") -> (Config, bool) {
		src := fmt.tprintf(
			"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: %s\n      servers: [10.0.0.1]\ndnssec:\n  enabled: true\n%s",
			domains,
			anchors,
		)
		cfg, err := load_string(src, context.temp_allocator)
		if e, has := err.?; has {
			testing.expectf(t, false, "config errors: %v", e.messages)
			return {}, false
		}
		return cfg, len(cfg.upstream.zones) == 1
	}

	// Nothing configured: the built-in root keys, and no zone of the operator's
	// own to defer to.
	if cfg, ok := load(t, ""); ok {
		testing.expect(t, !route_is_anchored(&cfg, cfg.upstream.zones[0]), "a route with no anchors was called anchored")
	}
	// The root alone is not an anchor over anything, which is what
	// `start_validator` decides by leaving it out of `anchor_zones`.
	if cfg, ok := load(t, "  trust_anchors:\n    - " + ROOT + "\n"); ok {
		testing.expect(t, !route_is_anchored(&cfg, cfg.upstream.zones[0]), "the root anchor was read as covering a zone")
	}
	// The zone itself, which is the case the warning has to keep quiet about.
	if cfg, ok := load(t, "  trust_anchors:\n    - " + ROOT + "\n    - \"corp.example. " + DS + "\"\n"); ok {
		testing.expect(t, route_is_anchored(&cfg, cfg.upstream.zones[0]), "an anchor over the routed zone was ignored")
	}
	// An anchor inside the zone covers its own names and leaves the rest of the
	// zone exactly as insecure as it was.
	if cfg, ok := load(t, "  trust_anchors:\n    - \"dev.corp.example. " + DS + "\"\n"); ok {
		testing.expect(t, !route_is_anchored(&cfg, cfg.upstream.zones[0]), "an anchor below the zone was read as covering it")
	}
	// One domain of a route anchored and the other not is the whole route still
	// giving validation up, the line being one sentence about all of them.
	if cfg, ok := load(
		t,
		"  trust_anchors:\n    - \"corp.example. " + DS + "\"\n",
		"[corp.example, lab.example]",
	); ok {
		testing.expect(t, !route_is_anchored(&cfg, cfg.upstream.zones[0]), "a half-anchored route was called anchored")
	}
	free_all(context.temp_allocator)
}

// The control for the case above: with the key at its default the route is the
// only thing claiming the zone, and the file loads.
@(test)
test_a_route_over_a_default_off_special_use_zone_is_kept :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      servers: [192.168.1.1]\n",
		context.temp_allocator,
	)
	if e, has := err.?; has {
		testing.expectf(t, false, "config errors: %v", e.messages)
		return
	}
	testing.expect_value(t, len(cfg.upstream.zones), 1)
	free_all(context.temp_allocator)
}
