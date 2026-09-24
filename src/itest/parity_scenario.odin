package itest

import "core:fmt"
import "core:strings"

/*
The configurations a parity run is made under.

One configuration answers one question. The run that existed first held every
answer against its upstream with the cache off, a single plain-UDP upstream and
nothing between the two sides but the codec - which is the question of whether
the pipe itself loses anything, and says nothing about what a cache, a cookie
exchange, a TLS upstream or a block list does to an answer on its way through.
Those are where a resolver in service actually spends its time, and each is a
path of its own with its own chances to drop a record or leak an option.

So a scenario is a set of levers moved together, and a run can be made under any
of them. Several levers per scenario rather than one, because the comparison
does not care why an answer diverged, only that it did, and the product of
every lever with every other is not a matrix anyone would run. What a failure
under a scenario says is which configuration to reproduce it in; the levers are
listed beside its name for that.

Every scenario keeps the one rule the comparison is built on: whatever it
forwards comes back as the upstream sent it, and the only answers allowed to
differ outright are the ones the configuration says this server answers itself
- a blocked name, a cookie it demands first. Those are not skipped: each is
checked for being exactly the answer the configuration promises, and every
query that is not one of them is held to parity as before.
*/

Parity_Upstream_Kind :: enum u8 {
	UDP,
	TCP,
	TLS,
	HTTPS,
}

Parity_Cookies :: enum u8 {
	// The shipped defaults: a cookie to any client that sends one, and one of
	// this server's own to the upstream.
	Default,
	// Neither direction. Nothing is minted, and the upstream's cookie has no
	// exchange to belong to at all, so it is the plainest leak there is.
	Off,
	// `cookies.require`: a UDP client that sends a cookie is answered BADCOOKIE
	// until it comes back with this server's (RFC 7873 section 5.2.3).
	Required,
}

Parity_Scenario :: struct {
	name:     string,
	// What this scenario moves, printed beside its name so a failure says what
	// configuration to reproduce it in.
	levers:   string,
	// One upstream per entry. In the mock mode each is a mock of its own,
	// answering from the same synthetic zone.
	kinds:    []Parity_Upstream_Kind,
	strategy: string,
	// A zone routed to the last upstream alone, the rest going to the others.
	// Empty routes nothing.
	route:    string,
	cache:    bool,
	cookies:  Parity_Cookies,
	blocking: bool,
	// `server.max_udp_response`, which the comparison has to know to judge a
	// truncation. Zero is the shipped default.
	max_udp:  int,
	// Live only: validation on. The mock's zone has no chain to the root.
	validate: bool,
}

/*
The synthetic upstream's scenarios.

Every one of them is hermetic and deterministic, so each is a gate rather than a
report: a divergence under any of them is this server's and nobody else's.
*/
PARITY_SCENARIOS := []Parity_Scenario {
	{
		name = "baseline",
		levers = "one udp upstream, no cache, default cookies",
		kinds = {.UDP},
		strategy = "failover",
	},
	{
		name = "tcp-upstream",
		levers = "tcp upstream, cookies off, 4096-byte udp ceiling",
		kinds = {.TCP},
		strategy = "failover",
		cookies = .Off,
		max_udp = 4096,
	},
	{
		name = "dot-upstream",
		levers = "dot upstream, cache on, 512-byte udp ceiling",
		kinds = {.TLS},
		strategy = "failover",
		cache = true,
		max_udp = 512,
	},
	{
		name = "doh-upstream",
		levers = "doh upstream, cookies required",
		kinds = {.HTTPS},
		strategy = "failover",
		cookies = .Required,
	},
	{
		name = "race",
		levers = "udp and tcp upstreams raced, cache on",
		kinds = {.UDP, .TCP},
		strategy = "race",
		cache = true,
	},
	{
		name = "round-robin",
		levers = "three udp upstreams in rotation, 4096-byte udp ceiling",
		kinds = {.UDP, .UDP, .UDP},
		strategy = "round_robin",
		max_udp = 4096,
	},
	{
		name = "zone-route",
		levers = "deep.nested.parity.test routed to a dot upstream, cookies off",
		kinds = {.UDP, .TLS},
		strategy = "failover",
		route = "deep.nested.parity.test.",
		cookies = .Off,
	},
	{
		name = "cache",
		levers = "cache on, every query asked twice, 4096-byte udp ceiling",
		kinds = {.UDP},
		strategy = "failover",
		cache = true,
		max_udp = 4096,
	},
	{
		name = "cookies-required",
		levers = "cookies required, 512-byte udp ceiling",
		kinds = {.UDP},
		strategy = "failover",
		cookies = .Required,
		max_udp = 512,
	},
	{
		name = "blocking",
		levers = "block rules on a name and on a cname target, an allow rule, cache on",
		kinds = {.UDP},
		strategy = "failover",
		blocking = true,
		cache = true,
	},
}

/*
The live mode's scenarios.

Reported rather than gated, for the reasons parity.yml gives. What these add is
the upstream transport against a real resolver - the answer a DoH frontend gives
is not obliged to be the one its port 53 gives, and a forwarder that speaks to it
over TLS has a different client under it - and a run with validation and the
cache both off, which is the only live run where a TTL is the one thing the two
separate fetches excuse.
*/
PARITY_LIVE_SCENARIOS := []Parity_Scenario {
	{
		name = "live",
		levers = "udp upstream, validation and cache on",
		kinds = {.UDP},
		strategy = "failover",
		cache = true,
		validate = true,
	},
	{
		name = "live-pipe",
		levers = "udp upstream, validation and cache off",
		kinds = {.UDP},
		strategy = "failover",
	},
	{
		name = "live-dot",
		levers = "dot upstream, validation and cache on",
		kinds = {.TLS},
		strategy = "failover",
		cache = true,
		validate = true,
	},
	{
		name = "live-doh",
		levers = "doh upstream, validation and cache on",
		kinds = {.HTTPS},
		strategy = "failover",
		cache = true,
		validate = true,
	},
}

/*
Where a public resolver takes DoT and DoH, keyed by the address its port 53 is
on.

The reference is still asked over plain DNS at that address, so these are the
names of the same service behind a different door - which is the comparison a
live DoT or DoH run is making. A resolver that is not listed runs the plain
scenarios only.
*/
Parity_Resolver :: struct {
	address:  string,
	hostname: string,
	url:      string,
}

PARITY_RESOLVERS := []Parity_Resolver {
	{"1.1.1.1", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"},
	{"8.8.8.8", "dns.google", "https://dns.google/dns-query"},
	{"9.9.9.9", "dns.quad9.net", "https://dns.quad9.net/dns-query"},
	{"94.140.14.140", "unfiltered.adguard-dns.com", "https://unfiltered.adguard-dns.com/dns-query"},
	{"208.67.222.222", "dns.opendns.com", "https://doh.opendns.com/dns-query"},
	{"185.222.222.222", "dot.sb", "https://doh.sb/dns-query"},
	{"76.76.2.11", "p0.freedns.controld.com", "https://freedns.controld.com/p0"},
}

parity_resolver :: proc(address: string) -> (Parity_Resolver, bool) {
	for r in PARITY_RESOLVERS {
		if r.address == address {
			return r, true
		}
	}
	return {}, false
}

// The scenarios `name` selects: one by name, or every one of the mode's.
parity_scenarios_named :: proc(name: string, live: bool) -> []Parity_Scenario {
	table := live ? PARITY_LIVE_SCENARIOS : PARITY_SCENARIOS
	if name == "all" {
		return table
	}
	for &s, i in table {
		if s.name == name {
			return table[i:i + 1]
		}
	}
	return nil
}

parity_needs_tls :: proc(s: Parity_Scenario) -> bool {
	for k in s.kinds {
		if k == .TLS || k == .HTTPS {
			return true
		}
	}
	return false
}

parity_max_udp :: proc(s: Parity_Scenario) -> int {
	return s.max_udp if s.max_udp > 0 else PARITY_MAX_UDP_RESPONSE
}

/*
The names a blocking scenario refuses, and the one it lets through.

`www.parity.test.` is in the generator's pool, so it and the subdomains the
generator makes under it are blocked by name. `alias.parity.test.` is in nobody's
pool: it is the target of every CNAME the mock serves (`pm_cname_chain`), so it is
only ever reached through an answer - which is the path `block_cloaked_answer`
exists for, and the one a name-only check would never walk. The allow rule sits
inside the first, so the exception has to beat the rule it is an exception to.
*/
PARITY_BLOCKED :: []string{"www.parity.test.", "alias.parity.test."}
PARITY_ALLOWED :: "safe.www.parity.test."

// The blocking scenario's pool: the usual one, and the allowed name inside the
// blocked one, so the exception is asked about by name.
PARITY_BLOCKING_POOL := []string {
	"parity.test.",
	"www.parity.test.",
	"safe.www.parity.test.",
	"deep.nested.parity.test.",
	"a.parity.test.",
	"_dns.resolver.parity.test.",
	"xn--bcher-kva.parity.test.",
	"one.two.three.four.five.parity.test.",
}

/*
Where a parity run's upstreams are, as the configuration needs them.

`ports[i]` is upstream `i`'s port. In the live mode every upstream is the one
resolver, at `host`.
*/
Parity_Endpoints :: struct {
	host:     string,
	ports:    []int,
	resolver: Parity_Resolver,
	live:     bool,
}

@(private = "file")
PARITY_CONFIG_HEAD :: `log:
  level: warn

server:
  workers: 8
  upstream_workers: 4
  client_timeout: 10s
  # Pinned rather than left at the shipped default, because the comparison has
  # to know it: an answer larger than this is cut down and marked whatever the
  # client advertised. See parity_max_udp.
  max_udp_response: %d
  rate_limit:
    enabled: false

listeners:
  udp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  tcp:
    enabled: true
    address: "127.0.0.1"
    port: %d
`

@(private = "file")
PARITY_CONFIG_TLS :: `  dot:
    enabled: true
    address: "127.0.0.1"
    port: %d
    cert_file: %s
    key_file: %s
  doh:
    enabled: true
    address: "127.0.0.1"
    port: %d
    path: /dns-query
    cert_file: %s
    key_file: %s
`

/*
The configuration a scenario runs under.

Everything the scenario does not name is off, and each for its own reason:

  cache      a cached answer's ttl counts down, so a scenario that turns it on
             pays for it with a ttl rule that bounds rather than equals - see
             `Parity_Policy.cache_age`. The ones that leave it off keep
             equality.
  blocking   a blocked name is answered without an upstream. A scenario that
             turns it on checks those answers for being the block response
             and nothing else; the rest leave it off.
  dnssec     the mock serves a zone with no chain to the root, so validation
             would turn every answer into servfail. The live scenarios have a
             real chain and turn it on where they say so.
  rate limit the generator is one address asking as fast as it can, which is
             exactly the shape the limiter exists to stop.

`attempts: 1` so one client query means one upstream exchange, which is what
lets a mock's last reply be read as this query's reference.
*/
parity_scenario_config :: proc(
	r: ^Runner,
	s: Parity_Scenario,
	udp_port, dot_port, doh_port: int,
	tls: bool,
	ends: Parity_Endpoints,
) -> string {
	sb := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(&sb, PARITY_CONFIG_HEAD, parity_max_udp(s), udp_port, udp_port)
	if tls {
		fmt.sbprintf(
			&sb,
			PARITY_CONFIG_TLS,
			dot_port,
			r.cert_file,
			r.key_file,
			doh_port,
			r.cert_file,
			r.key_file,
		)
	}

	fmt.sbprintf(&sb, "\nupstream:\n  strategy: %s\n  timeout: 5s\n  attempts: 1\n  servers:\n", s.strategy)
	routed := len(s.kinds) - (s.route != "" ? 1 : 0)
	for i in 0 ..< routed {
		parity_server_line(&sb, "    ", i, s.kinds[i], ends)
	}
	if s.route != "" {
		last := len(s.kinds) - 1
		fmt.sbprintf(&sb, "  zones:\n    - domains: [%s]\n      servers:\n", s.route)
		parity_server_line(&sb, "        ", last, s.kinds[last], ends)
	}

	if s.cache {
		strings.write_string(&sb, "\ncache:\n  enabled: true\n  max_entries: 20000\n")
	} else {
		strings.write_string(&sb, "\ncache:\n  enabled: false\n")
	}

	if s.blocking {
		strings.write_string(&sb, "\nblocking:\n  enabled: true\n  response: nxdomain\n  block_ttl: 60\n  rules:\n")
		for name in PARITY_BLOCKED {
			fmt.sbprintf(&sb, "    - \"||%s^\"\n", strings.trim_suffix(name, "."))
		}
		fmt.sbprintf(&sb, "  allow:\n    - \"||%s^\"\n", strings.trim_suffix(PARITY_ALLOWED, "."))
	} else {
		strings.write_string(&sb, "\nblocking:\n  enabled: false\n")
	}

	fmt.sbprintf(&sb, "\ndnssec:\n  enabled: %v\n", s.validate)

	switch s.cookies {
	case .Default:
	case .Off:
		strings.write_string(&sb, "\ncookies:\n  enabled: false\n  upstream: false\n")
	case .Required:
		strings.write_string(&sb, "\ncookies:\n  enabled: true\n  require: true\n")
	}
	return strings.to_string(sb)
}

@(private = "file")
parity_server_line :: proc(
	sb: ^strings.Builder,
	indent: string,
	i: int,
	kind: Parity_Upstream_Kind,
	ends: Parity_Endpoints,
) {
	port := ends.ports[i]
	if ends.live {
		switch kind {
		case .UDP:
			fmt.sbprintf(sb, "%s- {{ name: p%d, type: udp, address: %s, port: %d }}\n", indent, i, ends.host, port)
		case .TCP:
			fmt.sbprintf(sb, "%s- {{ name: p%d, type: tcp, address: %s, port: %d }}\n", indent, i, ends.host, port)
		case .TLS:
			fmt.sbprintf(
				sb,
				"%s- {{ name: p%d, type: tls, address: %s, port: 853, hostname: %s }}\n",
				indent,
				i,
				ends.host,
				ends.resolver.hostname,
			)
		case .HTTPS:
			fmt.sbprintf(
				sb,
				"%s- {{ name: p%d, type: https, url: \"%s\", bootstrap: [%s] }}\n",
				indent,
				i,
				ends.resolver.url,
				ends.host,
			)
		}
		return
	}
	switch kind {
	case .UDP:
		fmt.sbprintf(sb, "%s- {{ name: p%d, type: udp, address: 127.0.0.1, port: %d }}\n", indent, i, port)
	case .TCP:
		fmt.sbprintf(sb, "%s- {{ name: p%d, type: tcp, address: 127.0.0.1, port: %d }}\n", indent, i, port)
	case .TLS:
		fmt.sbprintf(
			sb,
			"%s- {{ name: p%d, type: tls, address: 127.0.0.1, port: %d, hostname: elodin.local, verify: false }}\n",
			indent,
			i,
			port,
		)
	case .HTTPS:
		fmt.sbprintf(
			sb,
			"%s- {{ name: p%d, type: https, url: \"https://127.0.0.1:%d/dns-query\", verify: false }}\n",
			indent,
			i,
			port,
		)
	}
}
