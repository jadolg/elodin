package filter

import "core:testing"

@(private = "file")
build :: proc(text: string, format: Format) -> (^Set, ^Set) {
	block, allow := set_make(), set_make()
	parse_list(block, allow, text, format)
	return block, allow
}

@(test)
test_hosts_format_is_exact :: proc(t: ^testing.T) {
	src := `
# Title: test
127.0.0.1 localhost
::1 ip6-localhost
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com metrics.example.com
`
	block, allow := build(src, .Hosts)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "ads.example.com."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "metrics.example.com"), Decision.Blocked)
	// Hosts entries are exact: a subdomain is not implied.
	testing.expect_value(t, engine_match(e, "deep.ads.example.com."), Decision.None)
	testing.expect_value(t, engine_match(e, "example.com."), Decision.None)
	// The file's own localhost bookkeeping must not become a rule.
	testing.expect_value(t, engine_match(e, "localhost."), Decision.None)
}

@(test)
test_domains_format_covers_subdomains :: proc(t: ^testing.T) {
	src := "doubleclick.net\n*.tracking.example\n# comment\n\n"
	block, allow := build(src, .Domains)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "doubleclick.net."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ad.g.doubleclick.net."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "notdoubleclick.net."), Decision.None)

	// "*.tracking.example" covers subdomains only, not the apex.
	testing.expect_value(t, engine_match(e, "a.tracking.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "tracking.example."), Decision.None)
}

@(test)
test_adblock_syntax :: proc(t: ^testing.T) {
	src := `
[Adblock Plus 2.0]
! a comment
||ads.example^
||analytics.example^$third-party
@@||allowed.ads.example^
|http://exactly.example^
address=/dnsmasq.example/0.0.0.0
/regex-rule.*/
||has/path.example^
`
	block, allow := build(src, .Adblock)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "ads.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "sub.ads.example."), Decision.Blocked)
	// Modifiers are stripped, the rule still applies.
	testing.expect_value(t, engine_match(e, "analytics.example."), Decision.Blocked)
	// An allow rule wins over the broader block rule above it.
	testing.expect_value(t, engine_match(e, "allowed.ads.example."), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "exactly.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "sub.exactly.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "dnsmasq.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "deep.dnsmasq.example."), Decision.Blocked)
	// Rules that need more than a domain name are ignored, not fatal.
	testing.expect_value(t, engine_match(e, "regex-rule.example."), Decision.None)
}

@(test)
test_format_detection :: proc(t: ^testing.T) {
	testing.expect_value(t, detect_format("[Adblock Plus 2.0]\n||a.example^\n"), Format.Adblock)
	testing.expect_value(t, detect_format("! title\nfoo.example\n"), Format.Adblock)
	testing.expect_value(t, detect_format("# header\n0.0.0.0 a.example\n0.0.0.0 b.example\n"), Format.Hosts)
	testing.expect_value(t, detect_format("a.example\nb.example\n"), Format.Domains)
	testing.expect_value(t, detect_format("::1 a.example\n::1 b.example\n"), Format.Hosts)
}

@(test)
test_case_and_trailing_dot_insensitive :: proc(t: ^testing.T) {
	block, allow := build("Ads.Example.COM\n", .Domains)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "ADS.example.com."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads.example.com"), Decision.Blocked)
}

@(test)
test_allow_beats_block :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	parse_list(block, allow, "||example.com^\n", .Adblock)
	parse_list(block, allow, "@@||safe.example.com^\n", .Adblock)

	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "example.com."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "safe.example.com."), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "deep.safe.example.com."), Decision.Allowed)
}

@(test)
test_swap_returns_old_sets :: proc(t: ^testing.T) {
	e := engine_make()
	defer engine_destroy(e)

	b1, a1 := build("first.example\n", .Domains)
	old_b, old_a := engine_swap(e, b1, a1)
	set_destroy(old_b)
	set_destroy(old_a)
	testing.expect_value(t, engine_match(e, "first.example."), Decision.Blocked)

	b2, a2 := build("second.example\n", .Domains)
	old_b2, old_a2 := engine_swap(e, b2, a2)
	set_destroy(old_b2)
	set_destroy(old_a2)
	testing.expect_value(t, engine_match(e, "first.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "second.example."), Decision.Blocked)

	s := engine_stats(e)
	testing.expect_value(t, s.block_rules, 1)
}

@(test)
test_stats_counted :: proc(t: ^testing.T) {
	block, allow := build("blocked.example\n", .Domains)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	engine_match(e, "blocked.example.")
	engine_match(e, "fine.example.")
	engine_match(e, "blocked.example.")

	s := engine_stats(e)
	testing.expect_value(t, s.queries, u64(3))
	testing.expect_value(t, s.blocked, u64(2))
}
