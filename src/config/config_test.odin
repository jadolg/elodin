package config

import "core:fmt"
import "core:net"
import "core:strings"
import "core:testing"
import "core:time"

@(private = "file")
GOOD :: `
log:
  level: warn
  queries: true

listeners:
  udp: { enabled: true, address: "127.0.0.1", port: 5353 }
  tcp: { enabled: true, address: "127.0.0.1", port: 5353 }

upstream:
  strategy: race
  timeout: 3s
  bootstrap: [1.1.1.1, 9.9.9.9]
  servers:
    - name: cloudflare-dot
      type: tls
      address: 1.1.1.1
      port: 853
      hostname: cloudflare-dns.com
    - https://dns.google/dns-query
    - tcp://9.9.9.9
    - 192.168.1.1

server:
  rate_limit:
    responses_per_second: 100
    slip: 0

cache:
  max_entries: 5000
  max_bytes: 32MiB
  max_ttl: 1h

blocking:
  response: custom
  custom_ipv4: 10.0.0.1
  custom_ipv6: "fd00::1"
  block_ttl: 30
  lists:
    - name: steven-black
      url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      format: hosts
    - /etc/elodin/local.txt
  rules:
    - "||tracker.example^"
  allow:
    - "@@||needed.example^"

rewrites:
  - domain: nas.home
    answer: 192.168.1.50
  - domain: "*.lan"
    answers: [192.168.1.10, "fd00::10"]
  - domain: legacy.example
    answer: new.example.com
`

@(test)
test_load_good_config :: proc(t: ^testing.T) {
	cfg, err := load_string(GOOD, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "config errors: %v", e.messages)
		return
	}

	testing.expect_value(t, cfg.log.level, Log_Level.Warn)
	testing.expect(t, cfg.log.queries, "queries should be enabled")
	testing.expect_value(t, cfg.listeners.udp.port, 5353)
	testing.expect_value(t, cfg.listeners.udp.address, "127.0.0.1")
	testing.expect(t, !cfg.listeners.dot.enabled, "dot should default to disabled")

	testing.expect_value(t, cfg.upstream.strategy, Strategy.Race)
	testing.expect_value(t, cfg.upstream.timeout, 3 * time.Second)
	testing.expect_value(t, len(cfg.upstream.servers), 4)

	s0 := cfg.upstream.servers[0]
	testing.expect_value(t, s0.kind, Upstream_Kind.TLS)
	testing.expect_value(t, s0.hostname, "cloudflare-dns.com")
	testing.expect_value(t, s0.port, 853)

	s1 := cfg.upstream.servers[1]
	testing.expect_value(t, s1.kind, Upstream_Kind.HTTPS)
	testing.expect_value(t, s1.hostname, "dns.google")
	testing.expect_value(t, s1.port, 443)
	testing.expect_value(t, s1.path, "/dns-query")
	// Bootstrap falls through from the upstream block.
	testing.expect_value(t, len(s1.bootstrap), 2)

	s2 := cfg.upstream.servers[2]
	testing.expect_value(t, s2.kind, Upstream_Kind.TCP)
	testing.expect_value(t, s2.address, "9.9.9.9")
	testing.expect_value(t, s2.port, 53)

	s3 := cfg.upstream.servers[3]
	testing.expect_value(t, s3.kind, Upstream_Kind.UDP)
	testing.expect_value(t, s3.port, 53)

	// On unless it is switched off, and the numbers are the file's.
	testing.expect(t, cfg.server.rate_limit.enabled, "rate limiting should default to on")
	testing.expect_value(t, cfg.server.rate_limit.responses_per_second, 100)
	testing.expect_value(t, cfg.server.rate_limit.slip, 0)

	testing.expect_value(t, cfg.cache.max_entries, 5000)
	testing.expect_value(t, cfg.cache.max_bytes, 32 * 1024 * 1024)
	testing.expect_value(t, cfg.cache.max_ttl, u32(3600))

	testing.expect_value(t, cfg.blocking.response, Block_Response.Custom_IP)
	testing.expect_value(t, cfg.blocking.custom_ipv4, [4]u8{10, 0, 0, 1})
	testing.expect_value(t, cfg.blocking.custom_ipv6[0], u8(0xfd))
	testing.expect_value(t, cfg.blocking.custom_ipv6[15], u8(0x01))
	testing.expect_value(t, cfg.blocking.block_ttl, u32(30))
	testing.expect_value(t, len(cfg.blocking.lists), 2)
	testing.expect_value(t, cfg.blocking.lists[0].format, List_Format.Hosts)
	testing.expect_value(t, cfg.blocking.lists[1].file, "/etc/elodin/local.txt")
	testing.expect_value(t, len(cfg.blocking.rules), 1)
	testing.expect_value(t, len(cfg.blocking.allow_rules), 1)

	testing.expect_value(t, len(cfg.rewrites), 3)
	testing.expect_value(t, cfg.rewrites[0].domain, "nas.home.")
	testing.expect(t, !cfg.rewrites[0].wildcard, "first rewrite is not a wildcard")
	testing.expect_value(t, cfg.rewrites[0].answers[0].kind, Rewrite_Kind.A)
	testing.expect(t, cfg.rewrites[1].wildcard, "second rewrite should be a wildcard")
	testing.expect_value(t, cfg.rewrites[1].domain, "lan.")
	testing.expect_value(t, len(cfg.rewrites[1].answers), 2)
	testing.expect_value(t, cfg.rewrites[1].answers[1].kind, Rewrite_Kind.AAAA)
	testing.expect_value(t, cfg.rewrites[2].answers[0].kind, Rewrite_Kind.CNAME)
	testing.expect_value(t, cfg.rewrites[2].answers[0].name, "new.example.com.")
	// The reverse of a rule's address is answered unless the rule says
	// otherwise, so a file that has never heard of `ptr` gets it.
	testing.expect(t, cfg.rewrites[0].ptr, "ptr defaults to on")

	free_all(context.temp_allocator)
}

/*
`ptr: false` on one rule, which is how an operator says this address is not
theirs to name in the reverse direction - a sinkhole pointed at a host that has
a name of its own. See `server/reverse.odin`.

Pinned beside a rule that says nothing, because the default is the half that
every existing configuration relies on: the key is opt-out, and a loader that
forgot to set it would silence the whole feature rather than fail.
*/
@(test)
test_rewrite_ptr_opt_out :: proc(t: ^testing.T) {
	src :=
		"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: ads.example\n    answer: 192.168.1.10\n    ptr: false\n  - domain: nas.home\n    answer: 192.168.1.50\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil)
	if testing.expect_value(t, len(cfg.rewrites), 2) {
		testing.expect(t, !cfg.rewrites[0].ptr, "ptr: false should be read")
		testing.expect(t, cfg.rewrites[1].ptr, "the key is per rule")
	}

	bad := "upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: ads.example\n    answer: 192.168.1.10\n    ptr: maybe\n"
	_, berr := load_string(bad, context.temp_allocator)
	e, has := berr.?
	if testing.expect(t, has, "a non-boolean ptr was accepted") {
		testing.expect(t, strings.contains(e.messages[0], "rewrites[0].ptr"))
	}

	free_all(context.temp_allocator)
}

@(test)
test_defaults_applied :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.listeners.udp.port, 53)
	testing.expect_value(t, cfg.upstream.strategy, Strategy.Failover)
	testing.expect_value(t, cfg.cache.negative_ttl, u32(300))
	testing.expect_value(t, cfg.blocking.response, Block_Response.NX_Domain)
	// A configuration that says nothing about DNSSEC still validates.
	testing.expect(t, cfg.dnssec.enabled, "DNSSEC validation should be on by default")
	testing.expect_value(t, cfg.dnssec.max_nsec3_iterations, 100)
	free_all(context.temp_allocator)
}

@(test)
test_doh_mobileconfig_path :: proc(t: ^testing.T) {
	// The default is a served path, so a device can be pointed at the resolver
	// the moment DoH is turned on, without another setting.
	base, berr := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, berr == nil, "expected a clean load")
	testing.expect_value(t, base.listeners.doh.mobileconfig_path, "/apple-doh.mobileconfig")

	// A value is read as given.
	set, serr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  doh:\n    mobileconfig_path: /profile.mobileconfig\n",
		context.temp_allocator,
	)
	testing.expect(t, serr == nil, "expected a clean load")
	testing.expect_value(t, set.listeners.doh.mobileconfig_path, "/profile.mobileconfig")

	// Empty is how it is withheld.
	off, oerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nlisteners:\n  doh:\n    mobileconfig_path: \"\"\n",
		context.temp_allocator,
	)
	testing.expect(t, oerr == nil, "expected a clean load")
	testing.expect_value(t, off.listeners.doh.mobileconfig_path, "")
	free_all(context.temp_allocator)
}

@(test)
test_dnssec_can_be_turned_off :: proc(t: ^testing.T) {
	// The escape hatch for an upstream that cannot return DNSSEC records, where
	// validating would mean answering nothing rather than answering unverified.
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\ndnssec:\n  enabled: false\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, !cfg.dnssec.enabled, "dnssec.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_cookies_defaults_and_overrides :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.cookies.enabled, "cookies should be answered by default")
	testing.expect(t, !cfg.cookies.require, "cookies should not be demanded by default")
	testing.expect(t, cfg.cookies.upstream, "cookies should be sent upstream by default")

	// `require` is set with `enabled` left on, since the two disagree by
	// definition; that pairing has its own case below.
	src := "upstream:\n  servers: [1.1.1.1]\ncookies:\n  require: true\n  upstream: false\n  secret: e5e973e5a6b2a43f48e7dc849e37bfcf\n"
	tuned, terr := load_string(src, context.temp_allocator)
	testing.expect(t, terr == nil, "expected a clean load")
	testing.expect(t, tuned.cookies.require, "cookies.require: true should be honoured")
	testing.expect(t, !tuned.cookies.upstream, "cookies.upstream: false should be honoured")
	testing.expect_value(t, tuned.cookies.secret, "e5e973e5a6b2a43f48e7dc849e37bfcf")

	off, oerr := load_string("upstream:\n  servers: [1.1.1.1]\ncookies:\n  enabled: false\n", context.temp_allocator)
	testing.expect(t, oerr == nil, "expected a clean load")
	testing.expect(t, !off.cookies.enabled, "cookies.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_secret_must_be_hex :: proc(t: ^testing.T) {
	// Caught here rather than at startup, so `--check` says so instead of a
	// resolver that comes up and refuses to start.
	src := "upstream:\n  servers: [1.1.1.1]\ncookies:\n  secret: not-a-secret\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error for a secret that is not hex")
	testing.expect_value(t, len(e.messages), 1)
	free_all(context.temp_allocator)
}

@(test)
test_cookie_require_needs_the_client_facing_side :: proc(t: ^testing.T) {
	// `require` is enforced by the keeper `enabled` builds, so the two together
	// are a setting that does nothing. Said at `--check` rather than left to be
	// discovered when the attack it was turned on for arrives.
	src := "upstream:\n  servers: [1.1.1.1]\ncookies:\n  enabled: false\n  require: true\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error for require without enabled")
	testing.expect_value(t, len(e.messages), 1)
	free_all(context.temp_allocator)
}

@(test)
test_special_use_defaults_and_overrides :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.special_use.enabled, "localhost., onion. and invalid. should be answered locally by default")
	testing.expect(t, cfg.special_use.onion, "onion. should be answered locally by default")
	// The two that deployed networks serve for real. Off unless asked for; see
	// the table in the server package for the argument.
	testing.expect(t, !cfg.special_use.local, "local. should be forwarded by default")
	testing.expect(t, !cfg.special_use.test, "test. should be forwarded by default")
	// Off for the same reason, and with the leak that costs written down in the
	// type: a router authoritative for the zone needs the query forwarded.
	testing.expect(t, !cfg.special_use.home_arpa, "home.arpa. should be forwarded by default")

	src :=
		"upstream:\n  servers: [1.1.1.1]\nspecial_use:\n  onion: false\n  local: true\n  test: true\n  home_arpa: true\n"
	tuned, terr := load_string(src, context.temp_allocator)
	testing.expect(t, terr == nil, "expected a clean load")
	testing.expect(t, tuned.special_use.enabled, "special_use.enabled should survive the other four being set")
	testing.expect(t, !tuned.special_use.onion, "special_use.onion: false should be honoured")
	testing.expect(t, tuned.special_use.local, "special_use.local: true should be honoured")
	testing.expect(t, tuned.special_use.test, "special_use.test: true should be honoured")
	testing.expect(t, tuned.special_use.home_arpa, "special_use.home_arpa: true should be honoured")

	off, oerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nspecial_use:\n  enabled: false\n",
		context.temp_allocator,
	)
	testing.expect(t, oerr == nil, "expected a clean load")
	testing.expect(t, !off.special_use.enabled, "special_use.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_special_use_extras_need_the_table :: proc(t: ^testing.T) {
	// Nothing looks at `local` or `test` with `enabled` off, so the pair reads
	// as a leak that was stopped and was not. Said at `--check`.
	src := "upstream:\n  servers: [1.1.1.1]\nspecial_use:\n  enabled: false\n  local: true\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error for local without enabled")
	testing.expect_value(t, len(e.messages), 1)

	// `home_arpa` is in the same check, and is the one where the misreading
	// costs the most: it exists to stop a leak, so an operator who wrote it down
	// under `enabled: false` believes their own hostnames are staying on the
	// network while they are being forwarded.
	hsrc := "upstream:\n  servers: [1.1.1.1]\nspecial_use:\n  enabled: false\n  home_arpa: true\n"
	_, herr := load_string(hsrc, context.temp_allocator)
	he, has_h := herr.?
	testing.expect(t, has_h, "expected an error for home_arpa without enabled")
	testing.expect_value(t, len(he.messages), 1)

	// `onion` is not part of that check and must not be: it is on by default, so
	// turning the table off without mentioning it is the ordinary way to do it
	// rather than a contradiction anybody wrote down.
	off, oerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nspecial_use:\n  enabled: false\n",
		context.temp_allocator,
	)
	testing.expect(t, oerr == nil, "special_use.enabled: false on its own should load")
	testing.expect(t, !off.special_use.enabled, "special_use.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_missing_upstream_is_an_error :: proc(t: ^testing.T) {
	_, err := load_string("log:\n  level: info\n", context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error for a config with no upstreams")
	testing.expect(t, len(e.messages) > 0, "expected a message")
	free_all(context.temp_allocator)
}

@(test)
test_unknown_enum_values_reported :: proc(t: ^testing.T) {
	src := "upstream:\n  strategy: teleport\n  servers: [1.1.1.1]\nblocking:\n  response: explode\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected errors")
	testing.expect_value(t, len(e.messages), 2)
	free_all(context.temp_allocator)
}

/*
A byte budget too small to hold one answer is a misconfiguration, not a small
cache: every large response would be refused while the cache went on answering.
Left to a caching server that has switched caching off, it is nothing at all.
*/
@(test)
test_cache_byte_budget_is_checked :: proc(t: ^testing.T) {
	too_small := "upstream:\n  servers: [1.1.1.1]\ncache:\n  max_bytes: 64KiB\n"
	_, err := load_string(too_small, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "a budget below one maximal answer was accepted")
	if has {
		testing.expect_value(t, len(e.messages), 1)
	}

	disabled := "upstream:\n  servers: [1.1.1.1]\ncache:\n  enabled: false\n  max_bytes: 64KiB\n"
	_, off_err := load_string(disabled, context.temp_allocator)
	_, off_has := off_err.?
	testing.expect(t, !off_has, "a cache that is switched off was sized anyway")

	nonsense := "upstream:\n  servers: [1.1.1.1]\ncache:\n  max_bytes: plenty\n"
	_, bad_err := load_string(nonsense, context.temp_allocator)
	_, bad_has := bad_err.?
	testing.expect(t, bad_has, "a size that is not a size was accepted")

	free_all(context.temp_allocator)
}

/*
A rate limit that cannot limit is a misconfiguration rather than a small one,
and a limiter that is switched off is not sized at all.
*/
@(test)
test_rate_limit_settings_are_checked :: proc(t: ^testing.T) {
	zero := "upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    responses_per_second: 0\n"
	_, err := load_string(zero, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "a budget of zero responses a second was accepted")
	if has {
		testing.expect_value(t, len(e.messages), 1)
	}

	negative := "upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    slip: -1\n"
	_, nerr := load_string(negative, context.temp_allocator)
	_, nhas := nerr.?
	testing.expect(t, nhas, "a negative slip was accepted")

	off := "upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: false\n    responses_per_second: 0\n"
	_, oerr := load_string(off, context.temp_allocator)
	_, ohas := oerr.?
	testing.expect(t, !ohas, "a limiter that is switched off was sized anyway")

	free_all(context.temp_allocator)
}

// A configuration whose `server.rate_limit.overrides` is `body`.
@(private = "file")
with_overrides :: proc(body: string) -> string {
	return fmt.tprintf(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    responses_per_second: 500\n    slip: 2\n    overrides:\n%s",
		body,
	)
}

/*
An override is read into the network and the figures it names.

The parse, and the two things about it worth pinning: the prefix goes through the
parser `allow_from` uses, and an entry that says nothing about `slip` inherits
the figure above it rather than defaulting to 0 - which would be "truncate
nothing", a setting the operator did not ask for and the opposite of what the
file says two lines up.
*/
@(test)
test_rate_limit_overrides_are_read :: proc(t: ^testing.T) {
	src := with_overrides(
		"      - { prefix: 198.51.100.0/24, responses_per_second: 5000, slip: 0 }\n      - { prefix: \"2001:db8::/32\", responses_per_second: 50 }\n",
	)
	cfg, err := load_string(src, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "a valid pair of overrides was rejected: %v", e.messages)
		return
	}
	o := cfg.server.rate_limit.overrides
	if !testing.expect_value(t, len(o), 2) {
		return
	}

	testing.expect_value(t, o[0].responses_per_second, 5000)
	testing.expect_value(t, o[0].slip, 0)
	testing.expect_value(t, o[0].prefix.bits, u8(24))
	testing.expect(t, !o[0].prefix.v6, "an IPv4 network was read as IPv6")

	testing.expect_value(t, o[1].responses_per_second, 50)
	// Not named, so inherited from `slip: 2` above rather than left at 0.
	testing.expect_value(t, o[1].slip, 2)
	testing.expect_value(t, o[1].prefix.bits, u8(32))
	testing.expect(t, o[1].prefix.v6, "an IPv6 network was read as IPv4")

	free_all(context.temp_allocator)
}

/*
Every way an override can be wrong is a startup error rather than a default
quietly applied.

The one that matters most is the network finer than the accounting. A /32 is what
somebody thinking about a single client reaches for, and the budgets are kept per
/24 - so it could only ever be applied to the whole /24 around it, giving 256
addresses a figure that was written for one. That is a mistake only measurement
would find, which is why it is refused with a message naming what to write
instead.
*/
@(test)
test_rate_limit_overrides_are_checked :: proc(t: ^testing.T) {
	Bad :: struct {
		body: string,
		what: string,
	}
	cases := []Bad {
		{"      - { responses_per_second: 5000 }\n", "an override with no prefix"},
		/*
		The network on its own, which is what an `allow_from` entry looks like
		and so the shorthand this setting invites. A scalar answers nil to every
		key, so read through the missing-key branch it becomes "this entry does
		not name a network" - said to an operator looking straight at the
		network they wrote. The message has to be about the shape.
		*/
		{"      - 198.51.100.0/24\n", "a network written on its own rather than as an entry"},
		{"      - { prefix: not-a-network, responses_per_second: 5000 }\n", "an unparseable prefix"},
		{"      - { prefix: 198.51.100.5/25, responses_per_second: 5000 }\n", "an IPv4 network finer than /24"},
		{"      - { prefix: \"2001:db8::1/128\", responses_per_second: 50 }\n", "an IPv6 network finer than /64"},
		{"      - { prefix: 198.51.100.0/24 }\n", "an override with no figure of its own"},
		{"      - { prefix: 198.51.100.0/24, responses_per_second: 0 }\n", "a budget of zero"},
		{"      - { prefix: 198.51.100.0/24, responses_per_second: 5000, slip: -2 }\n", "a negative slip"},
		// -1 in particular, which is the loader's own marker for an entry that
		// said nothing about `slip`. Read as silence it would inherit the figure
		// above without a word, while `slip: -1` at the top level is refused.
		{"      - { prefix: 198.51.100.0/24, responses_per_second: 5000, slip: -1 }\n", "a slip of minus one"},
		{
			"      - { prefix: 198.51.100.0/24, responses_per_second: 5000 }\n      - { prefix: 198.51.100.0/24, responses_per_second: 50 }\n",
			"the same network twice",
		},
		/*
		And the entries written without a `-` in front of them, which is a
		mapping where a list belongs and the commonest way to write this
		setting wrong. `yaml.items` answers nil to that exactly as it does to
		`overrides: []`, so read off the item count it would be a file that
		passes `--check`, starts clean, names no network in the log and puts
		every prefix back on the default.
		*/
		{
			"      prefix: 198.51.100.0/24\n      responses_per_second: 5000\n",
			"the entries written as a mapping rather than a list",
		},
	}
	for c in cases {
		_, err := load_string(with_overrides(c.body), context.temp_allocator)
		e, has := err.?
		if !testing.expectf(t, has, "%s was accepted", c.what) {
			continue
		}
		/*
		And the message reached the operator whole. Every one of these is a
		`printf` format, so a literal `{` or `%` written into one renders as
		`%!(MISSING ARGUMENT)` or `%!(NO VERB)` and eats the text around it - a
		mistake nothing else here would catch, since a garbled message is still
		an error and this loop only asked whether there was one. The one that
		matters most is the entry written without its `-`, whose message carries
		an example of the shape a list should have.
		*/
		for m in e.messages {
			testing.expectf(
				t,
				!strings.contains(m, "%!"),
				"the message for %s did not render: %s",
				c.what,
				m,
			)
		}
	}

	/*
	And the network written on its own is told about its shape rather than about
	a line that is in the file.

	Asserted on the message and not only on there being one, because the loop
	above passes either way: "missing prefix" is an error too, and it is the
	wrong one - it sends an operator looking for the network they can already
	see. This is the one case here where the text is the fix.
	*/
	bare := with_overrides("      - 198.51.100.0/24\n")
	_, berr := load_string(bare, context.temp_allocator)
	if e, has := berr.?; has {
		for m in e.messages {
			testing.expectf(
				t,
				!strings.contains(m, "missing prefix"),
				"a network written on its own was reported as a missing key: %s",
				m,
			)
		}
	}

	// And overrides beside a limiter that is switched off, which is an operator
	// configuring budgets for a server that will not keep any.
	disabled := "upstream:\n  servers: [1.1.1.1]\nserver:\n  rate_limit:\n    enabled: false\n    overrides:\n      - { prefix: 198.51.100.0/24, responses_per_second: 5000 }\n"
	_, derr := load_string(disabled, context.temp_allocator)
	_, dhas := derr.?
	testing.expect(t, dhas, "overrides were accepted with the limiter switched off")

	free_all(context.temp_allocator)
}

/*
A /24 written with host bits set is the network, as `allow_from` reads it.

`parse_prefix` masks rather than refusing, which is what BIND and Unbound do with
the same input, so `198.51.100.7/24` is the same entry as `198.51.100.0/24` and
not a /32 in disguise. Worth its own case because the length check sits right
beside it: an operator who wrote the first form must not be told to name a
network they had already named.
*/
@(test)
test_an_override_prefix_is_masked_not_refused :: proc(t: ^testing.T) {
	src := with_overrides("      - { prefix: 198.51.100.7/24, responses_per_second: 5000 }\n")
	cfg, err := load_string(src, context.temp_allocator)
	if e, has := err.?; has {
		testing.expectf(t, false, "a /24 written with host bits was rejected: %v", e.messages)
		return
	}
	o := cfg.server.rate_limit.overrides
	if !testing.expect_value(t, len(o), 1) {
		return
	}
	testing.expect_value(t, o[0].prefix.bits, u8(24))
	testing.expect_value(t, o[0].prefix.addr[3], u8(0))
	free_all(context.temp_allocator)
}

/*
The most specific entry claims an address, whatever order the file lists them in.

`prefix_match` is what the limiter resolves a prefix's figures through, so this
is the arithmetic behind "the /24 inside the /8 gets the /24's figure". Written
widest-first here, so a first-match implementation passes the /8 and fails.
*/
@(test)
test_prefix_match_takes_the_most_specific :: proc(t: ^testing.T) {
	wide, _ := parse_prefix("10.0.0.0/8")
	narrow, _ := parse_prefix("10.1.2.0/24")
	six, _ := parse_prefix("2001:db8::/32")
	list := []Prefix{wide, narrow, six}

	inside, ok := prefix_match(list, net.Address(net.IP4_Address{10, 1, 2, 3}))
	testing.expect(t, ok, "an address inside both entries matched neither")
	testing.expect_value(t, inside, 1)

	elsewhere, eok := prefix_match(list, net.Address(net.IP4_Address{10, 9, 9, 9}))
	testing.expect(t, eok, "an address inside the /8 matched nothing")
	testing.expect_value(t, elsewhere, 0)

	_, none := prefix_match(list, net.Address(net.IP4_Address{192, 0, 2, 1}))
	testing.expect(t, !none, "an address outside every entry matched one")

	// The families do not reach each other, and a v4-mapped address is IPv4.
	v6addr := net.IP6_Address{0x2001, 0x0db8, 0, 0, 0, 0, 0, 1}
	sixth, sok := prefix_match(list, net.Address(v6addr))
	testing.expect(t, sok, "an IPv6 address inside the /32 matched nothing")
	testing.expect_value(t, sixth, 2)

	m := net.IP6_Address{0, 0, 0, 0, 0, 0xffff, 0x0a01, 0x0203}
	mapped, mok := prefix_match(list, net.Address(m))
	testing.expect(t, mok, "a v4-mapped address matched no IPv4 entry")
	testing.expect_value(t, mapped, 1)

	// An empty list claims nothing, which is what every deployment that
	// configures no override asks of this.
	_, empty := prefix_match(nil, net.Address(net.IP4_Address{10, 1, 2, 3}))
	testing.expect(t, !empty, "an empty list claimed an address")
}

@(test)
test_tls_listener_requires_cert :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nlisteners:\n  dot:\n    enabled: true\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "expected an error when DoT has no certificate")
	testing.expect(t, len(e.messages) > 0, "expected a message")
	free_all(context.temp_allocator)
}

/*
A verifying DoT upstream needs a name to verify against.

Certificate checking is chain plus name; with no name it is chain alone, which
accepts anything a trusted CA ever signed and leaves the connection open to
anyone who can get one. An address given as an IP literal has no name to fall
back on, so the configuration has to carry one — or say plainly that it does
not want checking.
*/
@(test)
test_verifying_dot_upstream_requires_a_hostname :: proc(t: ^testing.T) {
	SHORTHAND :: "upstream:\n  servers: [tls://1.1.1.1:853]\n"
	_, sh_err := load_string(SHORTHAND, context.temp_allocator)
	e1, has1 := sh_err.?
	testing.expect(t, has1, "tls:// by IP with no #hostname should be refused")
	testing.expect(t, len(e1.messages) > 0, "expected a message")

	MAPPING :: "upstream:\n  servers:\n    - type: tls\n      address: 1.1.1.1\n"
	_, map_err := load_string(MAPPING, context.temp_allocator)
	e2, has2 := map_err.?
	testing.expect(t, has2, "type: tls by IP with no hostname should be refused")
	testing.expect(t, len(e2.messages) > 0, "expected a message")

	free_all(context.temp_allocator)
}

// The two ways to make that configuration well-formed: name the certificate, or
// say that it is not to be checked.
@(test)
test_dot_upstream_hostname_alternatives_are_accepted :: proc(t: ^testing.T) {
	PINNED :: "upstream:\n  servers: [tls://1.1.1.1:853#cloudflare-dns.com]\n"
	cfg, perr := load_string(PINNED, context.temp_allocator)
	testing.expect(t, perr == nil, "a pinned certificate name should load cleanly")
	testing.expect_value(t, len(cfg.upstream.servers), 1)
	testing.expect_value(t, cfg.upstream.servers[0].hostname, "cloudflare-dns.com")

	UNVERIFIED :: "upstream:\n  servers:\n    - type: tls\n      address: 1.1.1.1\n      verify: false\n"
	cfg2, uerr := load_string(UNVERIFIED, context.temp_allocator)
	testing.expect(t, uerr == nil, "verify: false is a deliberate opt-out and should load")
	testing.expect_value(t, len(cfg2.upstream.servers), 1)
	testing.expect(t, !cfg2.upstream.servers[0].verify, "verify should stay off")

	free_all(context.temp_allocator)
}

@(test)
test_service_account_is_read :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  user: elodin\n  group: elodin\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "a service account should load cleanly")
	testing.expect_value(t, cfg.server.user, "elodin")
	testing.expect_value(t, cfg.server.group, "elodin")

	// Nothing configured is the historical behaviour: stay as started.
	bare, berr := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, berr == nil, "a config without a service account should load")
	testing.expect_value(t, bare.server.user, "")
	testing.expect_value(t, bare.server.group, "")

	free_all(context.temp_allocator)
}

// A group with no user drops nothing, and looks from the file as though it does.
@(test)
test_group_without_user_is_an_error :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  group: elodin\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "server.group alone should be refused")
	testing.expect(t, len(e.messages) > 0, "expected a message")
	free_all(context.temp_allocator)
}

/*
`server.allow_from` as it comes out of a file.

The three states are different settings rather than three ways of writing one:
absent is the shipped default, a list is that list, and an empty list is a
public resolver. Getting the last two the wrong way round would turn a default
into an outage or an outage into an open resolver.
*/
@(test)
test_allow_from_absent_keeps_the_local_default :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, len(cfg.server.allow_from) > 0, "a file that says nothing should not open the resolver")
	testing.expect(
		t,
		source_allowed(cfg.server.allow_from, net.IP4_Address{127, 0, 0, 1}),
		"the default refuses loopback",
	)
	testing.expect(
		t,
		!source_allowed(cfg.server.allow_from, net.IP4_Address{8, 8, 8, 8}),
		"the default answers the internet",
	)
	free_all(context.temp_allocator)
}

@(test)
test_allow_from_replaces_the_default :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from: [\"203.0.113.0/24\", \"2001:db8::/32\"]\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, len(cfg.server.allow_from), 2)
	testing.expect(
		t,
		source_allowed(cfg.server.allow_from, net.IP4_Address{203, 0, 113, 9}),
		"a network that was named is refused",
	)
	// The default is replaced, not added to: an operator who lists their own
	// networks has said which ones, and inheriting 10/8 on top would serve a
	// network they did not name.
	testing.expect(
		t,
		!source_allowed(cfg.server.allow_from, net.IP4_Address{127, 0, 0, 1}),
		"loopback survived a list that does not mention it",
	)
	free_all(context.temp_allocator)
}

@(test)
test_allow_from_empty_is_a_public_resolver :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from: []\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "an empty allow_from should load")
	testing.expect_value(t, len(cfg.server.allow_from), 0)
	testing.expect(
		t,
		source_allowed(cfg.server.allow_from, net.IP4_Address{8, 8, 8, 8}),
		"an empty list refused a source instead of allowing everything",
	)
	free_all(context.temp_allocator)
}

// A network that will not parse has to stop `--check`, and the message has to
// name the entry: a list of eight is not one an operator wants to bisect.
@(test)
test_allow_from_reports_every_bad_entry :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from: [\"10.0.0.0/8\", \"nonsense\", \"::1/999\"]\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	testing.expect(t, has, "an unparseable network should be refused")
	testing.expect_value(t, len(e.messages), 2)
	for m in e.messages {
		testing.expect(t, strings.contains(m, "allow_from"), "the message does not name the setting")
	}
	free_all(context.temp_allocator)
}

/*
`allow_from:` with nothing after it is neither of the two settings it looks like.

Null is what YAML makes of an empty value, and the two readings available for it
here are the shipped default and its exact opposite. Guessing either way is a
resolver that is not the one in the file, so it is an error - and the message has
to name `[]`, since an operator who meant "serve everybody" is two characters
from saying so.
*/
@(test)
test_allow_from_with_no_value_is_an_error :: proc(t: ^testing.T) {
	sources := []string {
		// Last key in the mapping, and with another key after it: the same node
		// either way, but both are what people actually write.
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from:\n",
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from:\n  workers: 4\n",
	}
	for src in sources {
		cfg, err := load_string(src, context.temp_allocator)
		e, has := err.?
		if !testing.expectf(t, has, "an empty allow_from value loaded as %v", cfg.server.allow_from) {
			continue
		}
		named := false
		for m in e.messages {
			if strings.contains(m, "allow_from") && strings.contains(m, "[]") {
				named = true
			}
		}
		testing.expectf(t, named, "the message does not offer [] as the way to say it: %v", e.messages)
	}
	free_all(context.temp_allocator)
}

// A scalar where a list belongs is a mistake worth a message rather than a
// silently ignored setting.
@(test)
test_allow_from_of_the_wrong_shape_is_an_error :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_from: { a: 1 }\n"
	_, err := load_string(src, context.temp_allocator)
	_, has := err.?
	testing.expect(t, has, "a mapping should not be accepted as a list of networks")
	free_all(context.temp_allocator)
}

/*
`server.max_udp_response` is an amplification factor written as a number.

1232 by default, refused outside [512, 4096] rather than clamped: a resolver
that quietly served 4096 to somebody who asked for 8192 would be one whose
ceiling is not the one in its file.
*/
@(test)
test_max_udp_response_defaults_to_flag_day :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.server.max_udp_response, DEFAULT_MAX_UDP_RESPONSE)
	testing.expect_value(t, cfg.server.max_udp_response, 1232)
	free_all(context.temp_allocator)
}

@(test)
test_max_udp_response_can_be_raised :: proc(t: ^testing.T) {
	cfg, err := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_udp_response: 4096\n",
		context.temp_allocator,
	)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.server.max_udp_response, 4096)

	// Read as a size, so the suffixed forms the cache settings take work here.
	sized, serr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_udp_response: 1KiB\n",
		context.temp_allocator,
	)
	testing.expect(t, serr == nil, "a suffixed size should load")
	testing.expect_value(t, sized.server.max_udp_response, 1024)
	free_all(context.temp_allocator)
}

@(test)
test_max_udp_response_outside_the_range_is_an_error :: proc(t: ^testing.T) {
	out_of_range := []string{"8192", "511", "0", "-1"}
	for value in out_of_range {
		src := strings.concatenate(
			{"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_udp_response: ", value, "\n"},
			context.temp_allocator,
		)
		_, err := load_string(src, context.temp_allocator)
		e, has := err.?
		testing.expectf(t, has, "max_udp_response: %s was accepted", value)
		if has {
			named := false
			for m in e.messages {
				if strings.contains(m, "max_udp_response") {
					named = true
				}
			}
			testing.expectf(t, named, "the error for %s does not name the setting", value)
		}
	}
	free_all(context.temp_allocator)
}

/*
Off unless it is asked for.

The default matters more than the rest of this section: an operator upgrading
into a release with a metrics endpoint should not find a port open that their
old configuration file never mentioned.
*/
@(test)
test_metrics_is_off_by_default :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, !cfg.metrics.enabled, "the metrics endpoint should be off by default")
	testing.expect_value(t, cfg.metrics.address, "127.0.0.1")
	testing.expect_value(t, cfg.metrics.port, 9153)
	testing.expect_value(t, cfg.metrics.path, "/metrics")
	free_all(context.temp_allocator)
}

@(test)
test_metrics_settings_are_honoured :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nmetrics:\n  enabled: true\n  address: \"0.0.0.0\"\n  port: 9999\n  path: /stats\n"
	cfg, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect(t, cfg.metrics.enabled, "metrics.enabled: true should be honoured")
	testing.expect_value(t, cfg.metrics.address, "0.0.0.0")
	testing.expect_value(t, cfg.metrics.port, 9999)
	testing.expect_value(t, cfg.metrics.path, "/stats")
	free_all(context.temp_allocator)
}

/*
Caught by `--check` rather than at startup.

Each of these comes up as a listener that binds and is never scraped: a path a
scrape config does not use, a port the kernel chose, an address that is not one.
The endpoint would be up and the dashboard empty, which is the failure that
takes longest to attribute.
*/
@(test)
test_unusable_metrics_settings_are_errors :: proc(t: ^testing.T) {
	cases := []string{"  path: metrics\n", "  port: 0\n", "  port: 70000\n", "  address: \"localhost\"\n"}
	for tail in cases {
		src := strings.concatenate(
			{"upstream:\n  servers: [1.1.1.1]\nmetrics:\n  enabled: true\n", tail},
			context.temp_allocator,
		)
		_, err := load_string(src, context.temp_allocator)
		e, has := err.?
		testing.expectf(t, has, "metrics:\n%s was accepted", tail)
		if has {
			named := false
			for m in e.messages {
				if strings.has_prefix(m, "metrics.") {
					named = true
				}
			}
			testing.expectf(t, named, "the error for %q does not name the setting", tail)
		}
	}
	free_all(context.temp_allocator)
}

// The same settings with the endpoint off are settings that describe nothing,
// and a file left over from an instance that once had it on should not be what
// stops a resolver starting.
@(test)
test_metrics_settings_are_not_checked_while_it_is_off :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nmetrics:\n  enabled: false\n  port: 0\n  path: nowhere\n"
	_, err := load_string(src, context.temp_allocator)
	testing.expect(t, err == nil, "a disabled metrics endpoint should not be validated")
	free_all(context.temp_allocator)
}

/*
The rebinding guard's defaults and its two exemptions.

The default is the part worth pinning: it is off, so that an operator running
split horizon - a public name answering with a LAN address, which the deployment
this ships to commonly does on purpose - does not have every such name stop
resolving the moment they upgrade. A change to `enabled` here is a change to
whether that happens, and it should not be possible to make by accident.
*/
@(test)
test_rebind_defaults_to_off_with_nothing_exempt :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil)
	testing.expect(t, !cfg.rebind.enabled)
	testing.expect(t, !cfg.rebind.allow_loopback)
	testing.expect_value(t, len(cfg.rebind.allow_domains), 0)

	src := "upstream:\n  servers: [1.1.1.1]\nrebind:\n  enabled: false\n  allow_loopback: true\n  allow_domains: [Corp.Example., other.example]\n"
	set, serr := load_string(src, context.temp_allocator)
	testing.expect(t, serr == nil)
	testing.expect(t, !set.rebind.enabled)
	testing.expect(t, set.rebind.allow_loopback)
	if testing.expect_value(t, len(set.rebind.allow_domains), 2) {
		// Canonicalised with the procedure `rewrites` uses, so that a trailing
		// dot and a capital letter are not two ways of writing a zone the
		// resolver then fails to match.
		testing.expect_value(t, set.rebind.allow_domains[0], "corp.example.")
		testing.expect_value(t, set.rebind.allow_domains[1], "other.example.")
	}
	free_all(context.temp_allocator)
}

/*
The root exempts every name there is, which is the feature turned off written in
a way nothing about the file admits to. Refused for the same reason `allow_from:`
with no value is refused: the two readings are a setting and its opposite, and
there is a two-character way to say the other one.
*/
@(test)
test_rebind_allow_domains_will_not_take_the_root :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [\".\"]\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if testing.expect(t, has, "the root was accepted as an exempt domain") {
		testing.expect(t, strings.contains(e.messages[0], "rebind.allow_domains"))
	}

	// A bare star is the root written the other way, and means the same thing.
	star := "upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [\"*\"]\n"
	_, serr := load_string(star, context.temp_allocator)
	_, star_has := serr.?
	testing.expect(t, star_has, "a bare * was accepted as an exempt domain")
	free_all(context.temp_allocator)
}

/*
A wildcard is refused rather than kept, because keeping it matches nothing.

`rewrites` in the same file does take `*.lab`, so an operator who has written one
there writes one here - and `canonical_domain` would hold it as `*.corp.example.`,
which no name a client asks for is ever at or below. The entry would sit in the
configuration looking like the fix while every internal name went on answering
NODATA, which is precisely the failure `allow_domains` exists to end. The error
names the zone to write instead.
*/
@(test)
test_rebind_allow_domains_will_not_take_a_wildcard :: proc(t: ^testing.T) {
	src := "upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [\"*.corp.example\"]\n"
	_, err := load_string(src, context.temp_allocator)
	e, has := err.?
	if testing.expect(t, has, "a wildcard was accepted as an exempt domain, and would match nothing") {
		testing.expect(t, strings.contains(e.messages[0], "rebind.allow_domains"))
		testing.expect(t, strings.contains(e.messages[0], "corp.example"))
	}

	// And the plain zone, which is what it should have said, still loads and
	// still covers everything below itself.
	ok_src := "upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [corp.example]\n"
	cfg, oerr := load_string(ok_src, context.temp_allocator)
	testing.expect(t, oerr == nil)
	if testing.expect_value(t, len(cfg.rebind.allow_domains), 1) {
		testing.expect_value(t, cfg.rebind.allow_domains[0], "corp.example.")
	}
	free_all(context.temp_allocator)
}

/*
The leading dot, which is the third way to write an entry that matches nothing.

`no_proxy` takes `.corp.example` and means by it what this list writes plain, so
it is a form an operator arrives with rather than one they invent. Held as
written it would be an entry no name a client asks for is ever at or below - the
same silent no-op the wildcard is refused for, and the same symptom: every
internal name still answering NODATA after the fix was applied.
*/
@(test)
test_rebind_allow_domains_will_not_take_an_empty_label :: proc(t: ^testing.T) {
	sources := []string {
		"upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [\".corp.example\"]\n",
		"upstream:\n  servers: [1.1.1.1]\nrebind:\n  allow_domains: [\"corp..example\"]\n",
	}
	for src in sources {
		_, err := load_string(src, context.temp_allocator)
		e, has := err.?
		if testing.expect(t, has, "an empty label was accepted, and would match nothing") {
			testing.expect(t, strings.contains(e.messages[0], "rebind.allow_domains"))
		}
	}
	free_all(context.temp_allocator)
}

/*
One client's share of the connection table: derived from the table, and never
larger than it.

`max_connections` is a budget for the whole server, and before this setting
existed nothing said how it was shared - so one client could hold all 512 slots
and no configured limit said otherwise. The default is half, which leaves the
other half for everybody else; a figure at or above the table is stored as the
table's own size, which is no cap at all and is how an operator asks for the old
behaviour on purpose.

Derived at load rather than at startup, for the reason the worker counts are:
`--check` and the run after it then report the same number by construction.
*/
@(test)
test_the_connection_share_is_derived_from_the_table :: proc(t: ^testing.T) {
	cfg, err := load_string("upstream:\n  servers: [1.1.1.1]\n", context.temp_allocator)
	testing.expect(t, err == nil, "expected a clean load")
	testing.expect_value(t, cfg.server.max_connections, 512)
	testing.expect_value(t, cfg.server.max_connections_per_prefix, 256)

	// It follows the table rather than the shipped default of it: an operator
	// who raises one expects a client's share to move with it.
	raised, rerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_connections: 4096\n",
		context.temp_allocator,
	)
	testing.expect(t, rerr == nil, "expected a clean load")
	testing.expect_value(t, raised.server.max_connections_per_prefix, 2048)

	// A number in the file wins.
	set, serr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_connections_per_prefix: 8\n",
		context.temp_allocator,
	)
	testing.expect(t, serr == nil, "expected a clean load")
	testing.expect_value(t, set.server.max_connections_per_prefix, 8)

	/*
	And a number past the table is the table.

	Clamped rather than kept as written, so that `conn_spawn` can compare
	against it without a special case: a share that cannot be reached before
	the total is reached is a share that never refuses anything, which is what
	asking for more than the table means.
	*/
	over, oerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_connections: 64\n  max_connections_per_prefix: 10000\n",
		context.temp_allocator,
	)
	testing.expect(t, oerr == nil, "a share larger than the table is not an error")
	testing.expect_value(t, over.server.max_connections_per_prefix, 64)

	// Negative is refused rather than read as one of the two special values it
	// sits next to.
	_, nerr := load_string(
		"upstream:\n  servers: [1.1.1.1]\nserver:\n  max_connections_per_prefix: -1\n",
		context.temp_allocator,
	)
	e, has := nerr.?
	if testing.expect(t, has, "a negative share was accepted") {
		testing.expect(t, strings.contains(e.messages[0], "max_connections_per_prefix"))
	}
	free_all(context.temp_allocator)
}

/*
And the table the share is derived from has to be a table.

`conn_manager_init` reads anything below one as one connection, so a zero or a
negative used to load: the server came up serving a single client while the
startup line and `--check` said "at most 0 at once ... any one client prefix may
hold all of them", and `elodin_connections_max` published the same. Refused
here for the reason `max_udp_response` is refused rather than clamped - a figure
an operator can read off the server has to be the one the server is using - and
because every figure below is derived from it.
*/
@(test)
test_the_connection_table_must_be_at_least_one :: proc(t: ^testing.T) {
	sources := []string{"max_connections: 0", "max_connections: -5"}
	for src in sources {
		_, err := load_string(
			fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nserver:\n  %s\n", src),
			context.temp_allocator,
		)
		e, has := err.?
		if testing.expectf(t, has, "%q was accepted", src) {
			testing.expectf(
				t,
				strings.contains(e.messages[0], "server.max_connections must be at least 1"),
				"%q was refused for the wrong reason: %s",
				src,
				e.messages[0],
			)
		}
	}
	free_all(context.temp_allocator)
}
