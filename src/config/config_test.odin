package config

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
