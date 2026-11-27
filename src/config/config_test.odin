package config

import "core:fmt"
import "core:mem/virtual"
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
	cfg, ok := expect_loads(t, GOOD)
	if !ok {
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
		MINIMAL + "rewrites:\n  - domain: ads.example\n    answer: 192.168.1.10\n    ptr: false\n  - domain: nas.home\n    answer: 192.168.1.50\n"
	cfg, ok := expect_loads(t, src)
	if !ok {
		return
	}
	if testing.expect_value(t, len(cfg.rewrites), 2) {
		testing.expect(t, !cfg.rewrites[0].ptr, "ptr: false should be read")
		testing.expect(t, cfg.rewrites[1].ptr, "the key is per rule")
	}

	bad := MINIMAL + "rewrites:\n  - domain: ads.example\n    answer: 192.168.1.10\n    ptr: maybe\n"
	expect_refused(t, bad, "rewrites[0].ptr")

	free_all(context.temp_allocator)
}

/*
The client response timer, and the two readings of the figure that sets it.

RFC 8767 section 5's recommendation is 1.8 seconds and that is where the default
sits, because with `serve_stale` on the fallback is worth nothing unless it
reaches the client before the client's own resolver gives up - five seconds for a
glibc stub, sooner for systemd-resolved (issue #164). Zero is the escape hatch
and is deliberately not an error: it waits the whole upstream budget out. A negative figure is neither
of those and is refused rather than read as a third meaning.
*/
@(test)
test_cache_stale_timeout :: proc(t: ^testing.T) {
	base, bok := expect_loads(t, MINIMAL)
	if !bok {
		return
	}
	testing.expect_value(t, base.cache.stale_timeout, 1800 * time.Millisecond)

	set, sok := expect_loads(t, MINIMAL + "cache:\n  serve_stale: true\n  stale_timeout: 500ms\n")
	if !sok {
		return
	}
	testing.expect_value(t, set.cache.stale_timeout, 500 * time.Millisecond)

	// The figure the annotated reference carries, which is fractional: a parser
	// that read it as one second would quietly halve the documented default.
	doc, dok := expect_loads(t, MINIMAL + "cache:\n  stale_timeout: 1.8s\n")
	if !dok {
		return
	}
	testing.expect_value(t, doc.cache.stale_timeout, 1800 * time.Millisecond)

	off, ook := expect_loads(t, MINIMAL + "cache:\n  stale_timeout: 0s\n")
	if !ook {
		return
	}
	testing.expect_value(t, off.cache.stale_timeout, time.Duration(0))

	expect_refused(t, MINIMAL + "cache:\n  stale_timeout: -1s\n", "cache.stale_timeout")
	free_all(context.temp_allocator)
}

/*
Prefetching is on unless the file says otherwise, and the threshold below which
an entry is left to expire is the operator's (issue #468).

A threshold the file writes is refused above `max_ttl`, since no entry could
then reach it and prefetching would be off while the file said it was on.
Refused only while prefetching is on and the cache is, so a setting left in a
file that turned either off does not stop the server starting - and never for
the default, which a file from before the key existed never chose.
*/
@(test)
test_cache_prefetch :: proc(t: ^testing.T) {
	base, bok := expect_loads(t, MINIMAL)
	if !bok {
		return
	}
	testing.expect(t, base.cache.prefetch, "prefetching is off by default")
	testing.expect_value(t, base.cache.prefetch_min_ttl, 9)

	set, sok := expect_loads(t, MINIMAL + "cache:\n  prefetch: false\n  prefetch_min_ttl: 1m\n")
	if !sok {
		return
	}
	testing.expect(t, !set.cache.prefetch, "prefetch: false was not read")
	testing.expect_value(t, set.cache.prefetch_min_ttl, 60)

	every, eok := expect_loads(t, MINIMAL + "cache:\n  prefetch_min_ttl: 0\n")
	if !eok {
		return
	}
	testing.expect_value(t, every.cache.prefetch_min_ttl, 0)

	expect_refused(t, MINIMAL + "cache:\n  prefetch_min_ttl: -1\n", "cache.prefetch_min_ttl")

	expect_refused(t, MINIMAL + "cache:\n  max_ttl: 1h\n  prefetch_min_ttl: 2h\n", "cache.prefetch_min_ttl")

	// `max_ttl: 0` is the cache's day, and a threshold above that is as unreachable.
	expect_refused(t, MINIMAL + "cache:\n  max_ttl: 0\n  prefetch_min_ttl: 100000\n", "cache.prefetch_min_ttl")

	expect_loads(t, MINIMAL + "cache:\n  max_ttl: 1h\n  prefetch: false\n  prefetch_min_ttl: 2h\n")

	// A file that caps entries under the default threshold and never names it,
	// as every file from before the key did, still loads.
	expect_loads(t, MINIMAL + "cache:\n  max_ttl: 4\n")
	free_all(context.temp_allocator)
}

@(test)
test_defaults_applied :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect_value(t, cfg.listeners.udp.port, 53)
	testing.expect_value(t, cfg.upstream.strategy, Strategy.Failover)
	testing.expect_value(t, cfg.cache.negative_ttl, u32(300))
	testing.expect_value(t, cfg.blocking.response, Block_Response.NX_Domain)
	// A configuration that says nothing about DNSSEC still validates.
	testing.expect(t, cfg.dnssec.enabled, "DNSSEC validation should be on by default")
	testing.expect_value(t, cfg.dnssec.max_nsec3_iterations, 100)
	testing.expect(t, cfg.dnssec.trust_anchor_signaling, "RFC 8145 trust anchor signalling should be on by default")
	free_all(context.temp_allocator)
}

@(test)
test_trust_anchor_signaling_can_be_turned_off :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL + "dnssec:\n  trust_anchor_signaling: false\n")
	if !ok {
		return
	}
	testing.expect(t, !cfg.dnssec.trust_anchor_signaling, "trust_anchor_signaling: false left it on")
	free_all(context.temp_allocator)
}

@(test)
test_doh_mobileconfig_path :: proc(t: ^testing.T) {
	// The default is a served path, so a device can be pointed at the resolver
	// the moment DoH is turned on, without another setting.
	base, bok := expect_loads(t, MINIMAL)
	if !bok {
		return
	}
	testing.expect_value(t, base.listeners.doh.mobileconfig_path, "/apple-doh.mobileconfig")

	// A value is read as given.
	set, sok := expect_loads(t, MINIMAL + "listeners:\n  doh:\n    mobileconfig_path: /profile.mobileconfig\n")
	if !sok {
		return
	}
	testing.expect_value(t, set.listeners.doh.mobileconfig_path, "/profile.mobileconfig")

	// Empty is how it is withheld.
	off, ook := expect_loads(t, MINIMAL + "listeners:\n  doh:\n    mobileconfig_path: \"\"\n")
	if !ook {
		return
	}
	testing.expect_value(t, off.listeners.doh.mobileconfig_path, "")
	free_all(context.temp_allocator)
}

@(test)
test_dnssec_can_be_turned_off :: proc(t: ^testing.T) {
	// The escape hatch for an upstream that cannot return DNSSEC records, where
	// validating would mean answering nothing rather than answering unverified.
	cfg, ok := expect_loads(t, MINIMAL + "dnssec:\n  enabled: false\n")
	if !ok {
		return
	}
	testing.expect(t, !cfg.dnssec.enabled, "dnssec.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_cookies_defaults_and_overrides :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect(t, cfg.cookies.enabled, "cookies should be answered by default")
	testing.expect(t, !cfg.cookies.require, "cookies should not be demanded by default")
	testing.expect(t, cfg.cookies.upstream, "cookies should be sent upstream by default")

	// `require` is set with `enabled` left on, since the two disagree by
	// definition; that pairing has its own case below.
	src := MINIMAL + "cookies:\n  require: true\n  upstream: false\n  secret: e5e973e5a6b2a43f48e7dc849e37bfcf\n  previous_secret: 000102030405060708090a0b0c0d0e0f\n"
	tuned, tok := expect_loads(t, src)
	if !tok {
		return
	}
	testing.expect(t, tuned.cookies.require, "cookies.require: true should be honoured")
	testing.expect(t, !tuned.cookies.upstream, "cookies.upstream: false should be honoured")
	testing.expect_value(t, tuned.cookies.secret, "e5e973e5a6b2a43f48e7dc849e37bfcf")
	testing.expect_value(t, tuned.cookies.previous_secret, "000102030405060708090a0b0c0d0e0f")

	off, ook := expect_loads(t, MINIMAL + "cookies:\n  enabled: false\n")
	if !ook {
		return
	}
	testing.expect(t, !off.cookies.enabled, "cookies.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_cookie_secret_must_be_hex :: proc(t: ^testing.T) {
	// Caught here rather than at startup, so `--check` says so instead of a
	// resolver that comes up and refuses to start.
	for key in ([]string{"secret", "previous_secret"}) {
		other := "previous_secret" if key == "secret" else "secret"
		src := fmt.tprintf("%scookies:\n  %s: not-a-secret\n  %s: e5e973e5a6b2a43f48e7dc849e37bfcf\n", MINIMAL, key, other)
		expect_refused(t, src, fmt.tprintf("cookies.%s must be", key), prefix = true, exactly_one = true)
	}
	free_all(context.temp_allocator)
}

// A fixed key accepted beside a drawn secret that rolls over would outlive
// every rollover, so the key is refused without `secret`.
@(test)
test_cookie_previous_secret_needs_a_secret :: proc(t: ^testing.T) {
	src := MINIMAL + "cookies:\n  previous_secret: e5e973e5a6b2a43f48e7dc849e37bfcf\n"
	expect_refused(t, src, "cookies.previous_secret needs cookies.secret", prefix = true, exactly_one = true)
	free_all(context.temp_allocator)
}

@(test)
test_cookie_require_needs_the_client_facing_side :: proc(t: ^testing.T) {
	// `require` is enforced by the keeper `enabled` builds, so the two together
	// are a setting that does nothing. Said at `--check` rather than left to be
	// discovered when the attack it was turned on for arrives.
	src := MINIMAL + "cookies:\n  enabled: false\n  require: true\n"
	expect_refused(t, src, "cookies.require needs cookies.enabled", prefix = true, exactly_one = true)
	free_all(context.temp_allocator)
}

@(test)
test_special_use_defaults_and_overrides :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect(t, cfg.special_use.enabled, "localhost., onion. and invalid. should be answered locally by default")
	testing.expect(t, cfg.special_use.onion, "onion. should be answered locally by default")
	// The two that deployed networks serve for real. Off unless asked for; see
	// the table in the server package for the argument.
	testing.expect(t, !cfg.special_use.local, "local. should be forwarded by default")
	testing.expect(t, !cfg.special_use.test, "test. should be forwarded by default")
	// Off for the same reason, and with the leak that costs written down in the
	// type: a router authoritative for the zone needs the query forwarded.
	testing.expect(t, !cfg.special_use.home_arpa, "home.arpa. should be forwarded by default")
	// On (issue #321): a router answering its LAN's PTRs is reached by a route,
	// which wins over the key, so the default can stop the leak.
	testing.expect(t, cfg.special_use.private_reverse, "the RFC 6303 reverse zones should be answered locally by default")

	src :=
		MINIMAL + "special_use:\n  onion: false\n  local: true\n  test: true\n  home_arpa: true\n  private_reverse: false\n"
	tuned, tok := expect_loads(t, src)
	if !tok {
		return
	}
	testing.expect(t, tuned.special_use.enabled, "special_use.enabled should survive the others being set")
	testing.expect(t, !tuned.special_use.onion, "special_use.onion: false should be honoured")
	testing.expect(t, tuned.special_use.local, "special_use.local: true should be honoured")
	testing.expect(t, tuned.special_use.test, "special_use.test: true should be honoured")
	testing.expect(t, tuned.special_use.home_arpa, "special_use.home_arpa: true should be honoured")
	testing.expect(t, !tuned.special_use.private_reverse, "special_use.private_reverse: false should be honoured")

	off, ook := expect_loads(t, MINIMAL + "special_use:\n  enabled: false\n")
	if !ook {
		return
	}
	testing.expect(t, !off.special_use.enabled, "special_use.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_special_use_extras_need_the_table :: proc(t: ^testing.T) {
	// Nothing looks at `local` or `test` with `enabled` off, so the pair reads
	// as a leak that was stopped and was not. Said at `--check`.
	src := MINIMAL + "special_use:\n  enabled: false\n  local: true\n"
	expect_refused(t, src, "special_use.local needs special_use.enabled", prefix = true, exactly_one = true)

	// `home_arpa` is in the same check, and is the one where the misreading
	// costs the most: it exists to stop a leak, so an operator who wrote it down
	// under `enabled: false` believes their own hostnames are staying on the
	// network while they are being forwarded.
	hsrc := MINIMAL + "special_use:\n  enabled: false\n  home_arpa: true\n"
	expect_refused(t, hsrc, "special_use.home_arpa needs special_use.enabled", prefix = true, exactly_one = true)

	// `onion` is not part of that check and must not be: it is on by default, so
	// turning the table off without mentioning it is the ordinary way to do it
	// rather than a contradiction anybody wrote down.
	off, ook := expect_loads(t, MINIMAL + "special_use:\n  enabled: false\n")
	if !ook {
		return
	}
	testing.expect(t, !off.special_use.enabled, "special_use.enabled: false should be honoured")
	free_all(context.temp_allocator)
}

@(test)
test_missing_upstream_is_an_error :: proc(t: ^testing.T) {
	expect_refused(t, "log:\n  level: info\n", "upstream.servers: at least one upstream server is required", exact = true, exactly_one = true)
	free_all(context.temp_allocator)
}

@(test)
test_unknown_enum_values_reported :: proc(t: ^testing.T) {
	src := "upstream:\n  strategy: teleport\n  servers: [1.1.1.1]\nblocking:\n  response: explode\n"
	// Both, not only the first.
	expect_refused(t, src, "upstream.strategy: unknown strategy \"teleport\"", prefix = true)
	expect_refused(t, src, "blocking.response: unknown mode \"explode\"", prefix = true)
	free_all(context.temp_allocator)
}

/*
A byte budget too small to hold one answer is a misconfiguration, not a small
cache: every large response would be refused while the cache went on answering.
Left to a caching server that has switched caching off, it is nothing at all.
*/
@(test)
test_cache_byte_budget_is_checked :: proc(t: ^testing.T) {
	too_small := MINIMAL + "cache:\n  max_bytes: 64KiB\n"
	expect_refused(t, too_small, "cache.max_bytes must be at least", prefix = true, exactly_one = true)

	// A cache that is switched off is not sized.
	expect_loads(t, MINIMAL + "cache:\n  enabled: false\n  max_bytes: 64KiB\n")

	expect_refused(t, MINIMAL + "cache:\n  max_bytes: plenty\n", "cache.max_bytes: expected a size", prefix = true)

	free_all(context.temp_allocator)
}

/*
A rate limit that cannot limit is a misconfiguration rather than a small one,
and a limiter that is switched off is not sized at all.
*/
@(test)
test_rate_limit_settings_are_checked :: proc(t: ^testing.T) {
	zero := MINIMAL + "server:\n  rate_limit:\n    responses_per_second: 0\n"
	expect_refused(t, zero, "server.rate_limit.responses_per_second must be at least 1", exact = true, exactly_one = true)

	negative := MINIMAL + "server:\n  rate_limit:\n    slip: -1\n"
	expect_refused(t, negative, "server.rate_limit.slip must not be negative", exact = true)

	// A limiter that is switched off is not sized.
	expect_loads(t, MINIMAL + "server:\n  rate_limit:\n    enabled: false\n    responses_per_second: 0\n")

	free_all(context.temp_allocator)
}

/*
What the datagram budget is denominated in, and what it is when nobody says.

The default is the one property that matters for every file already written: the
estimate resolves to `server.max_udp_response`, which no datagram can exceed, so
every answer costs exactly one token and the figure counts answers. That holds at a raised ceiling too, which is the case a constant
1232 here would have quietly changed.
*/
@(test)
test_the_response_size_estimate_defaults_to_the_udp_ceiling :: proc(t: ^testing.T) {
	unset := MINIMAL + "server:\n  rate_limit:\n    responses_per_second: 500\n"
	if cfg, ok := expect_loads(t, unset); ok {
		testing.expect_value(t, cfg.server.rate_limit.response_size_estimate, DEFAULT_MAX_UDP_RESPONSE)
	}

	raised := fmt.tprintf(MINIMAL + "server:\n  max_udp_response: %d\n  rate_limit:\n    responses_per_second: 500\n", MAX_UDP_RESPONSE)
	if rcfg, ok := expect_loads(t, raised); ok {
		testing.expect_value(t, rcfg.server.rate_limit.response_size_estimate, MAX_UDP_RESPONSE)
	}

	// Written, and written as a size: the same spellings `max_udp_response`
	// takes, since it is the figure this is measured against.
	sized := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: 1KiB\n"
	if scfg, ok := expect_loads(t, sized); ok {
		testing.expect_value(t, scfg.server.rate_limit.response_size_estimate, 1024)
	}

	free_all(context.temp_allocator)
}

/*
An estimate outside its bounds is refused rather than clamped.

Below the floor every answer this server can send costs more than one token,
which is `responses_per_second` turned into a byte budget with an unstated
multiplier; above `MAX_UDP_RESPONSE` no datagram is large enough for the figure
to reach, so it is a key doing nothing. Both are worth a startup error rather
than a server whose bound is not the one its file states.
*/
@(test)
test_a_response_size_estimate_out_of_bounds_is_refused :: proc(t: ^testing.T) {
	tiny := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: 8\n"
	BOUNDS :: "server.rate_limit.response_size_estimate must be between"
	NOT_A_SIZE :: "server.rate_limit.response_size_estimate: expected a size"
	expect_refused(t, tiny, BOUNDS, prefix = true, exactly_one = true)

	huge := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: 64KiB\n"
	expect_refused(t, huge, BOUNDS, prefix = true)

	negative := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: -1\n"
	expect_refused(t, negative, NOT_A_SIZE, prefix = true)

	/*
	And 0, which is the loader's marker for a key nobody wrote.

	Written, it would resolve to `max_udp_response` like an absent key does - the
	setting doing nothing, with nothing said about it - so it is refused rather
	than read as agreement with the default.
	*/
	zero := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: 0\n"
	expect_refused(t, zero, BOUNDS, "(it is 0); leave the key out")

	/*
	And a value that is not a size at all is refused once, in its own words.

	The 0 above is the loader's marker for an absent key, and it is also what a
	field is left holding when `opt_bytes` cannot parse what was written. A
	refusal that read the field rather than the node would report both as "it is
	0", so a file saying `abc` would be told about a value it does not contain -
	beside the message that already says what is actually wrong with it.
	*/
	unparseable := MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: abc\n"
	expect_refused(t, unparseable, NOT_A_SIZE, prefix = true, exactly_one = true)

	/*
	None of which applies with the limiter off.

	`validate` leaves `responses_per_second` and `slip` unchecked when
	`rate_limit.enabled` is false, since there are no budgets for them to be
	figures of, and this key is no different: refusing a start over one of the
	three and not the other two would be an asymmetry with nothing behind it.
	*/
	off := MINIMAL + "server:\n  rate_limit:\n    enabled: false\n    response_size_estimate: 0\n"
	expect_loads(t, off)

	// The floor and the ceiling themselves are inside, not outside.
	for edge in ([]int{MIN_RESPONSE_SIZE_ESTIMATE, MAX_UDP_RESPONSE}) {
		edges := fmt.tprintf(MINIMAL + "server:\n  rate_limit:\n    response_size_estimate: %d\n", edge)
		if ecfg, ok := expect_loads(t, edges); ok {
			testing.expect_value(t, ecfg.server.rate_limit.response_size_estimate, edge)
		}
	}

	free_all(context.temp_allocator)
}

// A configuration whose `server.rate_limit.overrides` is `body`.
@(private = "file")
with_overrides :: proc(body: string) -> string {
	return fmt.tprintf(
		MINIMAL + "server:\n  rate_limit:\n    responses_per_second: 500\n    slip: 2\n    overrides:\n%s",
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
	cfg, ok := expect_loads(t, src)
	if !ok {
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
	expect_refused(
		t,
		with_overrides("      - 198.51.100.0/24\n"),
		"server.rate_limit.overrides[0]: expected a network and the figures it gets",
		prefix = true,
		exactly_one = true,
	)

	// And overrides beside a limiter that is switched off, which is an operator
	// configuring budgets for a server that will not keep any.
	disabled := MINIMAL + "server:\n  rate_limit:\n    enabled: false\n    overrides:\n      - { prefix: 198.51.100.0/24, responses_per_second: 5000 }\n"
	expect_refused(t, disabled, "server.rate_limit.overrides names 1 network(s), but server.rate_limit.enabled is false", prefix = true)

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
	cfg, ok := expect_loads(t, src)
	if !ok {
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
	wide, wok := parse_prefix("10.0.0.0/8")
	narrow, nok := parse_prefix("10.1.2.0/24")
	six, sixok := parse_prefix("2001:db8::/32")
	if !testing.expect(t, wok && nok && sixok, "a fixture prefix did not parse") {
		return
	}
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
	src := MINIMAL + "listeners:\n  dot:\n    enabled: true\n"
	expect_refused(t, src, "listeners.dot: cert_file and key_file are required", exact = true)
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
	NO_NAME :: "upstream.servers[0]: verify is on but there is no hostname to check the certificate against"
	expect_refused(t, SHORTHAND, NO_NAME, prefix = true, exactly_one = true)

	MAPPING :: "upstream:\n  servers:\n    - type: tls\n      address: 1.1.1.1\n"
	expect_refused(t, MAPPING, NO_NAME, prefix = true, exactly_one = true)

	free_all(context.temp_allocator)
}

// The two ways to make that configuration well-formed: name the certificate, or
// say that it is not to be checked.
@(test)
test_dot_upstream_hostname_alternatives_are_accepted :: proc(t: ^testing.T) {
	PINNED :: "upstream:\n  servers: [tls://1.1.1.1:853#cloudflare-dns.com]\n"
	cfg, pok := expect_loads(t, PINNED)
	if !pok {
		return
	}
	testing.expect_value(t, len(cfg.upstream.servers), 1)
	testing.expect_value(t, cfg.upstream.servers[0].hostname, "cloudflare-dns.com")

	UNVERIFIED :: "upstream:\n  servers:\n    - type: tls\n      address: 1.1.1.1\n      verify: false\n"
	cfg2, uok := expect_loads(t, UNVERIFIED)
	if !uok {
		return
	}
	testing.expect_value(t, len(cfg2.upstream.servers), 1)
	testing.expect(t, !cfg2.upstream.servers[0].verify, "verify should stay off")

	free_all(context.temp_allocator)
}

@(test)
test_service_account_is_read :: proc(t: ^testing.T) {
	src := MINIMAL + "server:\n  user: elodin\n  group: elodin\n"
	cfg, ok := expect_loads(t, src)
	if !ok {
		return
	}
	testing.expect_value(t, cfg.server.user, "elodin")
	testing.expect_value(t, cfg.server.group, "elodin")

	// Nothing configured stays as started.
	bare, bok := expect_loads(t, MINIMAL)
	if !bok {
		return
	}
	testing.expect_value(t, bare.server.user, "")
	testing.expect_value(t, bare.server.group, "")

	free_all(context.temp_allocator)
}

// A group with no user drops nothing, and looks from the file as though it does.
@(test)
test_group_without_user_is_an_error :: proc(t: ^testing.T) {
	src := MINIMAL + "server:\n  group: elodin\n"
	expect_refused(t, src, "server.group is set without server.user, so no privileges would be dropped", exact = true)
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
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
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
	src := MINIMAL + "server:\n  allow_from: [\"203.0.113.0/24\", \"2001:db8::/32\"]\n"
	cfg, ok := expect_loads(t, src)
	if !ok {
		return
	}
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
	cfg, ok := expect_loads(t, MINIMAL + "server:\n  allow_from: []\n")
	if !ok {
		return
	}
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
	src := MINIMAL + "server:\n  allow_from: [\"10.0.0.0/8\", \"nonsense\", \"::1/999\"]\n"
	expect_refused(t, src, "server.allow_from[1]: \"nonsense\"", prefix = true)
	expect_refused(t, src, "server.allow_from[2]: \"::1/999\"", prefix = true)
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
		MINIMAL + "server:\n  allow_from:\n",
		MINIMAL + "server:\n  allow_from:\n  max_pending: 4\n",
	}
	for src in sources {
		// The message offers [] as the way to say it.
		expect_refused(t, src, "allow_from", "[]")
	}
	free_all(context.temp_allocator)
}

// A scalar where a list belongs is a mistake worth a message rather than a
// silently ignored setting.
@(test)
test_allow_from_of_the_wrong_shape_is_an_error :: proc(t: ^testing.T) {
	src := MINIMAL + "server:\n  allow_from: { a: 1 }\n"
	expect_refused(t, src, "server.allow_from: expected a list of networks", prefix = true)
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
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect_value(t, cfg.server.max_udp_response, DEFAULT_MAX_UDP_RESPONSE)
	free_all(context.temp_allocator)
}

@(test)
test_max_udp_response_can_be_raised :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL + "server:\n  max_udp_response: 4096\n")
	if !ok {
		return
	}
	testing.expect_value(t, cfg.server.max_udp_response, 4096)

	// Read as a size, so the suffixed forms the cache settings take work here.
	sized, sok := expect_loads(t, MINIMAL + "server:\n  max_udp_response: 1KiB\n")
	if !sok {
		return
	}
	testing.expect_value(t, sized.server.max_udp_response, 1024)
	free_all(context.temp_allocator)
}

@(test)
test_max_udp_response_outside_the_range_is_an_error :: proc(t: ^testing.T) {
	out_of_range := []string{"8192", "511", "0", "-1"}
	for value in out_of_range {
		src := strings.concatenate(
			{MINIMAL + "server:\n  max_udp_response: ", value, "\n"},
			context.temp_allocator,
		)
		expect_refused(t, src, "max_udp_response")
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
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect(t, !cfg.metrics.enabled, "the metrics endpoint should be off by default")
	testing.expect_value(t, cfg.metrics.address, "127.0.0.1")
	testing.expect_value(t, cfg.metrics.port, 9153)
	testing.expect_value(t, cfg.metrics.path, "/metrics")
	free_all(context.temp_allocator)
}

@(test)
test_metrics_settings_are_honoured :: proc(t: ^testing.T) {
	src := MINIMAL + "metrics:\n  enabled: true\n  address: \"0.0.0.0\"\n  port: 9999\n  path: /stats\n"
	cfg, ok := expect_loads(t, src)
	if !ok {
		return
	}
	testing.expect(t, cfg.metrics.enabled, "metrics.enabled: true should be honoured")
	testing.expect_value(t, cfg.metrics.address, "0.0.0.0")
	testing.expect_value(t, cfg.metrics.port, 9999)
	testing.expect_value(t, cfg.metrics.path, "/stats")
	free_all(context.temp_allocator)
}

/*
A DoH path is matched against the request target, so a path that no target can
spell is an endpoint that comes up and is never reached: the reader splits the
target at `?`, a fragment is never sent, and a space, a control or a byte
outside ASCII is a request line the reader refuses (#438).
*/
@(test)
test_unreachable_doh_paths_are_errors :: proc(t: ^testing.T) {
	Case :: struct {
		key, value: string,
	}
	cases := []Case {
		{"path", "\"/dns query\""},
		{"path", "\"/dns\\tquery\""},
		{"path", "\"/dns-query?x\""},
		{"path", "\"/dns-query#x\""},
		{"path", "\"/dns-qu\u00e9ry\""},
		{"path", "\"/dns-query\\x7f\""},
		{"mobileconfig_path", "\"/apple doh.mobileconfig\""},
		{"mobileconfig_path", "\"/apple-doh.mobileconfig?x\""},
	}
	for c in cases {
		src := strings.concatenate(
			{MINIMAL + "listeners:\n  doh:\n    enabled: true\n    ", c.key, ": ", c.value, "\n"},
			context.temp_allocator,
		)
		expect_refused(t, src, strings.concatenate({"listeners.doh.", c.key, ":"}, context.temp_allocator), prefix = true)
	}
	free_all(context.temp_allocator)
}

/*
An upstream URL is written into the request line and the `Host` field of every
query sent to it, so a byte there that the request line cannot hold is a request
line of elodin's own making that is malformed - or, given a CR LF, one that
carries fields the operator never meant to send (#438). Refused on both spellings
of an upstream, the shorthand and the map, and of a block or allow list.
*/
@(test)
test_upstream_urls_outside_visible_ascii_are_errors :: proc(t: ^testing.T) {
	// Refused, and for the rule: a bootstrap in each source, so that the URL is
	// the only thing wrong with it.
	urls := []string {
		"\"https://dns.example/dns query\"",
		"\"https://dns.example/dns-query\\tx\"",
		"\"https://dns.example/dns-query\\r\\nX-Injected: 1\"",
		"\"https://dns.example/dns-qu\u00e9ry\"",
		"\"https://dns.ex\\x7fample/dns-query\"",
		// Unicode whitespace is not trimmed off the shorthand into a valid url.
		"\"https://dns.example/dns-query\u00a0\"",
		// The url's host is the `Host` and `:authority`: no userinfo in it.
		"\"https://a.example@dns.example/dns-query\"",
	}
	// A document as what goes before the url and what goes after it.
	fill :: proc(form: [2]string, url: string) -> string {
		return strings.concatenate({form[0], url, form[1]}, context.temp_allocator)
	}
	FORMS :: [][2]string {
		{"upstream:\n  bootstrap: [9.9.9.9]\n  servers: [", "]\n"},
		{"upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - url: ", "\n"},
	}
	for form in FORMS {
		expect_loads(t, fill(form, "\"https://dns.example/dns-query\""))
		for url in urls {
			expect_refused(t, fill(form, url), UPSTREAM_URL_RULE)
		}
	}
	// The map spelling can name the `Host` apart from the url.
	for hostname in ([]string{"\"dns.example\\r\\nX-Injected: 1\"", "\"dns example\""}) {
		src := fmt.tprintf(
			"upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - url: https://dns.example/dns-query\n      hostname: %s\n",
			hostname,
		)
		expect_refused(t, src, UPSTREAM_URL_RULE)
	}
	// The other shorthands are refused the same way, rather than trimmed of
	// Unicode whitespace or kept with it: an NBSP after `#name` is a certificate
	// name no server has.
	SHORTHAND :: "upstream:\n  bootstrap: [9.9.9.9]\n  servers: [%s]\n"
	expect_loads(t, fmt.tprintf(SHORTHAND, "\"tls://1.1.1.1:853#dns.example\""))
	for s in ([]string{"\"tls://1.1.1.1:853#dns.example\u00a0\"", "\"1.1.1.1\u00a0\"", "\"tls://1.1.1.1:853#a.example@b.example\"", "\"tls://a@dns.example:853\""}) {
		expect_refused(t, fmt.tprintf(SHORTHAND, s), "cannot parse")
	}
	// And the map spelling of one: the same name, spelled `hostname:`.
	DOT_MAP :: "upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - type: tls\n      address: 1.1.1.1\n      hostname: %s\n"
	expect_loads(t, fmt.tprintf(DOT_MAP, "dns.example"))
	// With no `hostname:`, a name address is the certificate name as well.
	expect_refused(
		t,
		"upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - type: tls\n      address: \"dns.example \"\n",
		"address: must be visible ASCII",
	)
	expect_refused(t, fmt.tprintf(DOT_MAP, "\"dns.example \""), "hostname: must be visible ASCII")
	// And a host: userinfo or a path in one is a name no certificate has, and a
	// `Host` that a hop routing by it reads its own way.
	expect_refused(t, fmt.tprintf(DOT_MAP, "\"a.example@b.example\""), "hostname: must be visible ASCII")
	expect_refused(
		t,
		"upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - url: https://dns.example/dns-query\n      hostname: a.example/x\n",
		UPSTREAM_URL_RULE,
	)
	// An https upstream's own address is a lookup just the same.
	expect_refused(
		t,
		"upstream:\n  bootstrap: [9.9.9.9]\n  servers:\n    - url: https://dns.example/dns-query\n      address: \"dns.example \"\n",
		"address: must be visible ASCII",
	)
	// A list url goes into a request line and `Host` just the same, on both of
	// its spellings.
	LIST_FORMS :: [][2]string {
		{"upstream:\n  bootstrap: [9.9.9.9]\n  servers: [1.1.1.1]\nblocking:\n  lists: [", "]\n"},
		{"upstream:\n  bootstrap: [9.9.9.9]\n  servers: [1.1.1.1]\nblocking:\n  allowlists:\n    - url: ", "\n"},
	}
	for form in LIST_FORMS {
		expect_loads(t, fill(form, "\"https://lists.example/hosts.txt\""))
		expect_loads(t, fill(form, "\"https://[2001:db8::1]:8443/hosts.txt\""))
		for url in ([]string {
				"\"https://lists.example/hosts.txt\\r\\nX-Injected: 1\"",
				"\"https://lists.example/a b\"",
				"\"https://a.example@lists.example/hosts.txt\"",
				// A host the fetcher cannot split fails every refresh, so not at load.
				"\"https://lists.example:5_3/hosts.txt\"",
				"\"https://[1.1.1.1]/hosts.txt\"",
				"\"https://[lists.example:443/hosts.txt\"",
				"\"https:///hosts.txt\"",
			}) {
			expect_refused(t, fill(form, url), LIST_URL_RULE)
		}
	}
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
	cases := []string {
		"  path: metrics\n",
		"  port: 0\n",
		"  port: 70000\n",
		"  address: \"localhost\"\n",
		// A path no request target can spell: see `http_path_is_valid`.
		"  path: \"/st ats\"\n",
		"  path: \"/st\\tats\"\n",
		"  path: \"/stats?x\"\n",
		"  path: \"/stats#x\"\n",
		"  path: \"/st\u00e4ts\"\n",
	}
	for tail in cases {
		src := strings.concatenate(
			{MINIMAL + "metrics:\n  enabled: true\n", tail},
			context.temp_allocator,
		)
		expect_refused(t, src, "metrics.", prefix = true)
	}
	free_all(context.temp_allocator)
}

// The same settings with the endpoint off are settings that describe nothing,
// and a file left over from an instance that once had it on should not be what
// stops a resolver starting.
@(test)
test_metrics_settings_are_not_checked_while_it_is_off :: proc(t: ^testing.T) {
	src := MINIMAL + "metrics:\n  enabled: false\n  port: 0\n  path: nowhere\n"
	expect_loads(t, src)
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
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect(t, !cfg.rebind.enabled)
	testing.expect(t, !cfg.rebind.allow_loopback)
	testing.expect_value(t, len(cfg.rebind.allow_domains), 0)

	src := MINIMAL + "rebind:\n  enabled: false\n  allow_loopback: true\n  allow_domains: [Corp.Example., other.example]\n"
	set, sok := expect_loads(t, src)
	if !sok {
		return
	}
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
	src := MINIMAL + "rebind:\n  allow_domains: [\".\"]\n"
	expect_refused(t, src, "rebind.allow_domains")

	// A bare star is the root written the other way, and means the same thing.
	star := MINIMAL + "rebind:\n  allow_domains: [\"*\"]\n"
	expect_refused(t, star, "rebind.allow_domains[0]: \"*\" exempts every name", prefix = true)
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
	src := MINIMAL + "rebind:\n  allow_domains: [\"*.corp.example\"]\n"
	expect_refused(t, src, "rebind.allow_domains", "corp.example")

	// And the plain zone, which is what it should have said, still loads and
	// still covers everything below itself.
	ok_src := MINIMAL + "rebind:\n  allow_domains: [corp.example]\n"
	cfg, ook := expect_loads(t, ok_src)
	if !ook {
		return
	}
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
		MINIMAL + "rebind:\n  allow_domains: [\".corp.example\"]\n",
		MINIMAL + "rebind:\n  allow_domains: [\"corp..example\"]\n",
	}
	for src in sources {
		expect_refused(t, src, "rebind.allow_domains")
	}
	free_all(context.temp_allocator)
}

/*
One client's share of the connection table: derived from the table, and never
larger than it.

`max_connections` is a budget for the whole server, and this setting says how
it is shared, so that one client cannot hold all 512 slots. The default is half,
which leaves the other half for everybody else; a figure at or above the table
is stored as the table's own size, which is no cap at all and is how an operator
asks for one client to be able to hold the whole table.

Derived at load rather than at startup, for the reason `max_pending` is:
`--check` and the run after it then report the same number by construction.
*/
@(test)
test_the_connection_share_is_derived_from_the_table :: proc(t: ^testing.T) {
	cfg, ok := expect_loads(t, MINIMAL)
	if !ok {
		return
	}
	testing.expect_value(t, cfg.server.max_connections, DEFAULT_MAX_CONNECTIONS)
	testing.expect_value(t, cfg.server.max_connections_per_prefix, DEFAULT_MAX_CONNECTIONS / 2)

	// It follows the table rather than the shipped default of it: an operator
	// who raises one expects a client's share to move with it.
	raised, rok := expect_loads(t, MINIMAL + "server:\n  max_connections: 4096\n")
	if !rok {
		return
	}
	testing.expect_value(t, raised.server.max_connections_per_prefix, 2048)

	// A number in the file wins.
	set, sok := expect_loads(t, MINIMAL + "server:\n  max_connections_per_prefix: 8\n")
	if !sok {
		return
	}
	testing.expect_value(t, set.server.max_connections_per_prefix, 8)

	/*
	And a number past the table is the table.

	Clamped rather than kept as written, so that `conn_spawn` can compare
	against it without a special case: a share that cannot be reached before
	the total is reached is a share that never refuses anything, which is what
	asking for more than the table means.
	*/
	over, ook := expect_loads(t, MINIMAL + "server:\n  max_connections: 64\n  max_connections_per_prefix: 10000\n")
	if !ook {
		return
	}
	testing.expect_value(t, over.server.max_connections_per_prefix, 64)

	// Negative is refused rather than read as one of the two special values it
	// sits next to.
	expect_refused(t, MINIMAL + "server:\n  max_connections_per_prefix: -1\n", "max_connections_per_prefix")
	free_all(context.temp_allocator)
}

/*
And the table the share is derived from has to be a table.

`conn_manager_init` reads anything below one as one connection, so a zero or a
negative that loaded would serve a single client while the startup line and
`--check` said "at most 0 at once ... any one client prefix may hold all of
them", and `elodin_connections_max` published the same. Refused
here for the reason `max_udp_response` is refused rather than clamped - a figure
an operator can read off the server has to be the one the server is using - and
because every figure below is derived from it.
*/
@(test)
test_the_connection_table_must_be_at_least_one :: proc(t: ^testing.T) {
	sources := []string{"max_connections: 0", "max_connections: -5"}
	for src in sources {
		expect_refused(t, fmt.tprintf(MINIMAL + "server:\n  %s\n", src), "server.max_connections must be at least 1", prefix = true)
	}
	free_all(context.temp_allocator)
}

/*
A stray bracket, a port that is not 0 to 65535 in digits, or a port where only an
address goes is a config error on its line, not a value read some other way or
dropped. Every source of an address or a port is here.
*/
@(test)
test_an_address_or_port_out_of_shape_is_a_config_error :: proc(t: ^testing.T) {
	// Each source, and the one refusal it gets.
	Refused :: struct {
		src, want: string,
	}
	SOURCES := []Refused {
		{"upstream:\n  servers: [\"]:53\"]\n", "upstream.servers[0]: cannot parse \"]:53\""},
		{"upstream:\n  servers: [\"tls://]:853#dns.example\"]\n", "upstream.servers[0]: cannot parse \"tls://]:853#dns.example\""},
		{"upstream:\n  servers: [\"a]:]:53\"]\n", "upstream.servers[0]: cannot parse \"a]:]:53\""},
		{"upstream:\n  servers: [\"1.1.1.1:-1\"]\n", "upstream.servers[0]: cannot parse \"1.1.1.1:-1\""},
		{"upstream:\n  servers: [\"1.1.1.1:5_3\"]\n", "upstream.servers[0]: cannot parse \"1.1.1.1:5_3\""},
		{"upstream:\n  servers: [\"1.1.1.1:9223372036854775861\"]\n", "upstream.servers[0]: cannot parse \"1.1.1.1:9223372036854775861\""},
		{"upstream:\n  servers: [\"1.1.1.1:18446744073709551669\"]\n", "upstream.servers[0]: cannot parse \"1.1.1.1:18446744073709551669\""},
		{"upstream:\n  servers:\n    - { address: 1.1.1.1, port: -7 }\n", "upstream.servers[0].port: must be between 1 and 65535, or 0 for the default"},
		{"upstream:\n  servers:\n    - { address: 1.1.1.1, port: 65536 }\n", "upstream.servers[0].port: must be between 1 and 65535, or 0 for the default"},
		{MINIMAL + "  bootstrap: [\"]:53\"]\n", "upstream.bootstrap: \"]:53\" is not an IP address"},
		{MINIMAL + "  bootstrap: [\"a]:]:53\"]\n", "upstream.bootstrap: \"a]:]:53\" is not an IP address"},
		{MINIMAL + "  bootstrap: [dns.example]\n", "upstream.bootstrap: \"dns.example\" is not an IP address"},
		{"upstream:\n  servers:\n    - { address: 1.1.1.1, bootstrap: [\"]:53\"] }\n", "upstream.servers[0].bootstrap: \"]:53\" is not an IP address"},
		{MINIMAL + "  zones:\n    - domains: [corp.example]\n      servers: [10.0.0.1]\n      bootstrap: [\"]:53\"]\n", "upstream.zones[0].bootstrap: \"]:53\" is not an IP address"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"A ]:1.2.3.4\"\n", "rewrites[0].answers: A needs an IPv4 address, got \"]:1.2.3.4\""},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"AAAA ]::1\"\n", "rewrites[0].answers: AAAA needs an IPv6 address, got \"]::1\""},
		{MINIMAL + "metrics:\n  enabled: true\n  address: \"]:\"\n", "metrics.address: \"]:\" is not an IP address"},
		{MINIMAL + "listeners:\n  udp: { port: -1 }\n", "listeners.udp.port: must be between 1 and 65535"},
		// A port in an address field: read through `core:net`, it is dropped
		// for the default one with nothing said.
		{"upstream:\n  servers:\n    - { address: \"1.1.1.1:5353\" }\n", "upstream.servers[0].address: \"1.1.1.1:5353\" is not an address or a name alone; a port goes in port:"},
		{"upstream:\n  servers:\n    - { address: \"dns.example:853\", type: tls }\n", "upstream.servers[0].address: \"dns.example:853\" is not an address or a name alone; a port goes in port:"},
		{"upstream:\n  servers:\n    - { url: \"https://dns.google/dns-query\", address: \"8.8.8.8:5353\" }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0].address: \"8.8.8.8:5353\" is not an address or a name alone; a port goes in port:"},
		{MINIMAL + "listeners:\n  udp: { enabled: true, address: \"127.0.0.1:5353\" }\n", "listeners.udp.address: \"127.0.0.1:5353\" is not an IP address; a port goes in port:"},
		{MINIMAL + "listeners:\n  udp: { enabled: true, address: \"]:\" }\n", "listeners.udp.address: \"]:\" is not an IP address"},
		{MINIMAL + "metrics:\n  enabled: true\n  address: \"127.0.0.1:9100\"\n", "metrics.address: \"127.0.0.1:9100\" is not an IP address; a port goes in port:"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"A 1.2.3.4:80\"\n", "rewrites[0].answers: A needs an IPv4 address, got \"1.2.3.4:80\""},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"1.2.3.4:80\"\n", "rewrites[0].answers: an answer host \"1.2.3.4:80\" has a port, and a host has none"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"dns.example:53\"\n", "rewrites[0].answers: an answer host \"dns.example:53\" has a port, and a host has none"},
		{MINIMAL + "server:\n  allow_from: [\"10.0.0.1:53\"]\n", "server.allow_from[0]: \"10.0.0.1:53\" is not a network in CIDR form such as 192.168.0.0/16 or ::1/128"},
		// A short IPv4 form: `core:net` reads `192.168.1` as 192.168.0.1, so this
		// would allow another network.
		{MINIMAL + "server:\n  allow_from: [\"192.168.1/24\"]\n", "server.allow_from[0]: \"192.168.1/24\" is not a network in CIDR form such as 192.168.0.0/16 or ::1/128"},
		{MINIMAL + "listeners:\n  udp: { enabled: true, address: \"10.20.30\" }\n", "listeners.udp.address: \"10.20.30\" is not an IP address"},
		{"upstream:\n  servers:\n    - { address: 10.20.30 }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0].address: \"10.20.30\" is not an address or a name alone"},
		{MINIMAL + "  bootstrap: [\"10.20.30\"]\n", "upstream.bootstrap: \"10.20.30\" is not an IP address"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"10.20.30\"\n", "rewrites[0].answers: an answer host \"10.20.30\" ends in a number, so it is no name, and it is no IPv4 address either"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"A 10.20.30\"\n", "rewrites[0].answers: A needs an IPv4 address, got \"10.20.30\""},
		// A port on the certificate name: an SNI and a name check no server passes.
		{"upstream:\n  servers:\n    - { address: 1.1.1.1, hostname: \"dns.example:853\", type: tls }\n", "upstream.servers[0].hostname: \"dns.example:853\" is not a name alone; a port goes in port:"},
		{"upstream:\n  servers: [\"tls://1.1.1.1#dns.example:853\"]\n", "upstream.servers[0]: cannot parse \"tls://1.1.1.1#dns.example:853\""},
		{"upstream:\n  servers:\n    - { url: \"https://1.1.1.1/dns-query\", hostname: \"dns.example:443\" }\n", "upstream.servers[0].hostname: \"dns.example:443\" is not a name alone; a port goes in the url"},
		// Two colons or a stray bracket: no IPv6 literal, and no name either.
		{"upstream:\n  servers:\n    - { address: 1.1.1.1, hostname: \"dns.example::853\", type: tls }\n", "upstream.servers[0].hostname: \"dns.example::853\" is not a name alone"},
		{"upstream:\n  servers:\n    - { address: \"dns.example:853:\", type: tls }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0].address: \"dns.example:853:\" is not an address or a name alone"},
		{"upstream:\n  servers:\n    - { address: \"[::1]x\", type: tls }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0].address: \"[::1]x\" is not an address or a name alone"},
		{"upstream:\n  servers:\n    - { url: \"https://dns.example:853:/dns-query\" }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: " + UPSTREAM_URL_RULE},
		{"upstream:\n  servers: [\"tls://1.1.1.1#dns.example:853:\"]\n", "upstream.servers[0]: cannot parse \"tls://1.1.1.1#dns.example:853:\""},
		{"upstream:\n  servers: [\"tls://dns.example:853:\"]\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: cannot parse \"tls://dns.example:853:\""},
		{"upstream:\n  servers: [\"https://dns.example:853:/dns-query\"]\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: " + UPSTREAM_URL_RULE},
		// No host at all: with verify off, nothing else asks for one.
		{"upstream:\n  servers:\n    - { url: \"https:///dns-query\", verify: false }\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: " + UPSTREAM_URL_RULE},
		{"upstream:\n  servers: [\"https:///dns-query\"]\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: " + UPSTREAM_URL_RULE},
		{"upstream:\n  servers: [\"udp://\"]\n", "upstream.servers[0]: cannot parse \"udp://\""},
		{"upstream:\n  servers: [\":53\"]\n", "upstream.servers[0]: cannot parse \":53\""},
		{"upstream:\n  servers: [\"tls://:853#dns.example\"]\n  bootstrap: [9.9.9.9]\n", "upstream.servers[0]: cannot parse \"tls://:853#dns.example\""},
		// An IPv6 address's IPv4 part has four parts too.
		{MINIMAL + "server:\n  allow_from: [\"::ffff:192.168.1./120\"]\n", "server.allow_from[0]: \"::ffff:192.168.1./120\" is not a network in CIDR form such as 192.168.0.0/16 or ::1/128"},
		{MINIMAL + "listeners:\n  udp: { enabled: true, address: \"::ffff:10.20.30.\" }\n", "listeners.udp.address: \"::ffff:10.20.30.\" is not an IP address"},
		// A host in an answer, typed or not, has no port or brackets.
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"[1.2.3.4]\"\n", "rewrites[0].answers: an answer host \"[1.2.3.4]\" has brackets; an address goes without them"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"CNAME dns.example:53\"\n", "rewrites[0].answers: CNAME host \"dns.example:53\" has a port, and a host has none"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"MX 10 mail.example:25\"\n", "rewrites[0].answers: MX host \"mail.example:25\" has a port, and a host has none"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"CNAME 10.20.30\"\n", "rewrites[0].answers: CNAME host \"10.20.30\" ends in a number, so it is no name, and it is no IPv4 address either"},
		// An address where a name goes, either family.
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"CNAME 2001:db8::1\"\n", "rewrites[0].answers: CNAME host \"2001:db8::1\" is an address, and a CNAME points at a name"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"MX 10 ::1\"\n", "rewrites[0].answers: MX host \"::1\" is an address, and an MX points at a name"},
		{MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"SRV 1 1 53 192.0.2.1\"\n", "rewrites[0].answers: SRV host \"192.0.2.1\" is an address, and an SRV points at a name"},
	}
	for c in SOURCES {
		expect_refused(t, c.src, c.want, exact = true, exactly_one = true)
	}
	_, network := parse_prefix("]:53")
	testing.expect(t, !network, "nor is it a network")

	// And says so: without its own check, the address is taken for a hostname
	// and the error is about a certificate or a bootstrap resolver instead.
	for src in ([]string {
			"upstream:\n  servers:\n    - { address: \"1.1.1.1:5353\" }\n",
			"upstream:\n  servers:\n    - { address: \"dns.example:853\", type: tls }\n",
			"upstream:\n  servers:\n    - { url: \"https://dns.google/dns-query\", address: \"8.8.8.8:5353\" }\n  bootstrap: [9.9.9.9]\n",
			MINIMAL + "listeners:\n  udp: { enabled: true, address: \"127.0.0.1:5353\" }\n",
			MINIMAL + "metrics:\n  enabled: true\n  address: \"127.0.0.1:9100\"\n",
		}) {
		expect_refused(t, src, "a port goes in port:", exactly_one = true)
	}
	// On https the authority's port is the url's, so that is where a hostname's goes.
	expect_refused(
		t,
		"upstream:\n  servers:\n    - { url: \"https://1.1.1.1/dns-query\", hostname: \"dns.example:8443\" }\n",
		"a port goes in the url",
		exactly_one = true,
	)
	// An address where a name goes is called one.
	expect_refused(t, MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"CNAME 1.2.3.4\"\n", "is an address", exactly_one = true)
	// A bracketed literal is told to drop the brackets, on each source.
	for src in ([]string {
			"upstream:\n  servers:\n    - { address: \"[2606:4700::1111]\" }\n",
			MINIMAL + "listeners:\n  udp: { enabled: true, address: \"[::]\" }\n",
			MINIMAL + "metrics:\n  enabled: true\n  address: \"[::1]\"\n",
		}) {
		expect_refused(t, src, "without brackets", exactly_one = true)
	}

	// And only when there is one: a bracketed literal has no port to move, and
	// is told about its brackets alone.
	for src in ([]string {
			"upstream:\n  servers:\n    - { address: \"[2606:4700::1111]\" }\n",
			MINIMAL + "listeners:\n  udp: { enabled: true, address: \"[::]\" }\n",
			MINIMAL + "rewrites:\n  - domain: example.com\n    answers: \"[::1]\"\n",
		}) {
		expect_refused(t, src, "brackets", exactly_one = true)
	}

	// A listener that does not bind is not held to an address it never uses.
	expect_loads(t, MINIMAL + "listeners:\n  dot: { enabled: false, address: localhost }\n")

	// A file list has no url to hold to the url's rule, in either spelling.
	for src in ([]string {
			MINIMAL + "blocking:\n  lists: [/etc/elodin/ads.txt]\n",
			MINIMAL + "blocking:\n  lists:\n    - { file: /etc/elodin/ads.txt }\n",
		}) {
		if cfg, ok := expect_loads(t, src); ok {
			testing.expect_value(t, len(cfg.blocking.lists), 1)
		}
	}

	// And what they sit beside still loads.
	expect_loads(t, "upstream:\n  servers: [\"tls://1.1.1.1:853#one.one.one.one\", \"[2606:4700::1111]:53\"]\n  bootstrap: [\"9.9.9.9\", \"[2620:fe::fe]:53\"]\n")

	// A bracketed literal with no port is an address too, not a name that needs
	// a bootstrap resolver.
	for src in ([]string {
			"upstream:\n  servers: [\"[2606:4700::1111]\"]\n",
			"upstream:\n  servers: [\"https://[2606:4700::1111]/dns-query\"]\n",
		}) {
		if cfg, ok := expect_loads(t, src); ok {
			testing.expect_value(t, cfg.upstream.servers[0].address, "2606:4700::1111")
		}
	}
	// A bootstrap entry is kept as written, so loading is the whole of its check.
	expect_loads(t, MINIMAL + "  bootstrap: [\"[2620:fe::fe]\"]\n")
	free_all(context.temp_allocator)
}

@(test)
test_the_certificate_check_can_be_left_to_the_listener :: proc(t: ^testing.T) {
	// `tls_files` off is what a SIGHUP reload loads with; the default still
	// refuses a certificate that is not there, which is what `--check` and
	// startup want.
	arena: virtual.Arena
	testing.expect(t, virtual.arena_init_growing(&arena) == nil)
	defer virtual.arena_destroy(&arena)
	TEXT :: "upstream: { servers: [\"127.0.0.1\"] }\nlisteners: { dot: { enabled: true, cert_file: /nonexistent/c.pem, key_file: /nonexistent/k.pem } }\n"
	expect_refused(t, TEXT, "listeners.dot.cert_file: \"/nonexistent/c.pem\" does not exist", exact = true)
	_, lenient := load_string(TEXT, virtual.arena_allocator(&arena), tls_files = false)
	e, refused := lenient.?
	testing.expectf(t, !refused, "refused with the certificate check off: %v", e.messages)
}

@(test)
test_keywords_fold_ascii_only :: proc(t: ^testing.T) {
	// A keyword matches with an ASCII fold. Under Unicode, `İ` (U+0130) lowers
	// to `i`, so it would spell one.
	UP :: "upstream:\n  servers: [1.1.1.1]\n"
	expect_loads(t, UP + "  strategy: FIRST\nlog:\n  level: INFO\n")
	expect_refused(t, UP + "log:\n  level: \u0130nfo\n", "log.level: unknown level")
	expect_refused(t, UP + "  strategy: f\u0130rst\n", "upstream.strategy: unknown strategy")
	expect_refused(t, UP + "blocking:\n  response: nxdoma\u0130n\n", "blocking.response: unknown mode")
	expect_refused(
		t,
		UP + "blocking:\n  lists:\n    - url: https://lists.example/hosts.txt\n      format: doma\u0130ns\n",
		"format: unknown format",
	)
	free_all(context.temp_allocator)
}

/*
YAML 1.2's core schema decides what is a boolean and what is an integer (1.2.2
section 10.3.2): `yes`, `on`, `3_000`, `0b...` and anything quoted are strings,
so where a boolean or a number belongs they are refused, and the refusal names
what was written. A file an editor saved with a byte order mark loads.
*/
@(test)
test_yaml_1_1_forms_are_refused_and_a_bom_is_not :: proc(t: ^testing.T) {
	Case :: struct {
		doc:  string,
		path: string,
		want: string,
	}
	for c in ([]Case {
			{"listeners:\n  tcp: {enabled: n}\n", "listeners.tcp.enabled", "not \"n\""},
			{"listeners:\n  tcp: {enabled: yes}\n", "listeners.tcp.enabled", "not \"yes\""},
			{"listeners:\n  tcp: {enabled: \"false\"}\n", "listeners.tcp.enabled", "not \"false\""},
			{"listeners:\n  udp: {port: 3_8053}\n", "listeners.udp.port", "not \"3_8053\""},
			{"listeners:\n  udp: {port: \"53\"}\n", "listeners.udp.port", "not \"53\""},
			{"cache:\n  max_entries: 0b10011100010000\n", "cache.max_entries", "a YAML 1.1 form"},
			{"cache:\n  max_entries: +0x10\n", "cache.max_entries", "a YAML 1.1 form"},
			{"listeners:\n  udp: {port: \"53\"}\n", "listeners.udp.port", "quoted or a block scalar, so a string"},
			{"listeners:\n  udp:\n    port: |-\n      53\n", "listeners.udp.port", "quoted or a block scalar, so a string"},
			{"listeners:\n  udp: {port: 0X35}\n", "listeners.udp.port", "read by earlier versions of elodin"},
			{"listeners:\n  tcp: {enabled: tRUE}\n", "listeners.tcp.enabled", "read by earlier versions of elodin"},
			{"listeners:\n  tcp: {enabled: yes}\n", "listeners.tcp.enabled", "a YAML 1.1 form"},
			{"rewrites:\n  - {domain: a.test, answer: 192.0.2.1, ttl: 3_600}\n", "rewrites[0].ttl", "not \"3_600\" (a YAML 1.1 form"},
		}) {
		expect_refused(t, strings.concatenate({MINIMAL, c.doc}, context.temp_allocator), c.path, c.want)
	}
	// A value that is no form of a boolean or integer, quoted or not, is named
	// with no YAML 1.1 or quoting hint it would be wrong about; nor is a quoted
	// TTL, which may be a duration.
	for doc in ([]string {
			"listeners:\n  udp: {port: abc}\n",
			"listeners:\n  udp: {port: \"abc\"}\n",
			"listeners:\n  udp: {port: ab_cd}\n",
			"listeners:\n  udp: {port: 0bad}\n",
			"listeners:\n  tcp: {enabled: maybe}\n",
			"listeners:\n  tcp: {enabled: \"maybe\"}\n",
			// Quoted 1.1 forms were strings in 1.1 as well: unquoting them is
			// no fix, so neither hint is given.
			"listeners:\n  tcp: {enabled: \"yes\"}\n",
			"listeners:\n  udp: {port: \"3_000\"}\n",
			"cache:\n  min_ttl: \"500ms\"\n",
			"cache:\n  min_ttl: \"99999999999\"\n",
		}) {
		_, err := load_string(strings.concatenate({MINIMAL, doc}, context.temp_allocator), context.temp_allocator)
		if e, has := err.?; testing.expectf(t, has, "%s loaded", doc) {
			for m in e.messages {
				testing.expectf(t, !strings.contains(m, "YAML 1.1") && !strings.contains(m, "quoted"), "a hint that does not hold: %s", m)
			}
		}
	}
	// A TTL that is not a scalar names no value it does not have.
	_, merr := load_string(strings.concatenate({MINIMAL, "cache:\n  min_ttl: {a: 1}\n"}, context.temp_allocator), context.temp_allocator)
	if e, has := merr.?; testing.expect(t, has, "a mapping TTL loaded") {
		for m in e.messages {
			testing.expectf(t, !strings.contains(m, "not \"\""), "an empty value named: %s", m)
		}
	}
	// The 1.2 forms of each load.
	expect_loads(t, MINIMAL + "listeners:\n  tcp: {enabled: False}\n  udp: {port: 0x35}\n")

	if cfg, ok := expect_loads(t, "\xef\xbb\xbf" + MINIMAL + "listeners:\n  udp: {port: 5353}\n"); ok {
		testing.expect_value(t, cfg.listeners.udp.port, 5353)
	}
	free_all(context.temp_allocator)
}
