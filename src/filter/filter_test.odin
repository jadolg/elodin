package filter

import "core:sync"
import "core:testing"
import "core:thread"

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

	testing.expect_value(t, engine_match(e, "ads.example.com.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "metrics.example.com", .A), Decision.Blocked)
	// Hosts entries are exact: a subdomain is not implied.
	testing.expect_value(t, engine_match(e, "deep.ads.example.com.", .A), Decision.None)
	testing.expect_value(t, engine_match(e, "example.com.", .A), Decision.None)
	// The file's own localhost bookkeeping must not become a rule.
	testing.expect_value(t, engine_match(e, "localhost.", .A), Decision.None)
}

@(test)
test_domains_format_covers_subdomains :: proc(t: ^testing.T) {
	src := "doubleclick.net\n*.tracking.example\n# comment\n\n"
	block, allow := build(src, .Domains)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "doubleclick.net.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ad.g.doubleclick.net.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "notdoubleclick.net.", .A), Decision.None)

	// "*.tracking.example" covers subdomains only, not the apex.
	testing.expect_value(t, engine_match(e, "a.tracking.example.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "tracking.example.", .A), Decision.None)
}

@(test)
test_adblock_syntax :: proc(t: ^testing.T) {
	src := `
[Adblock Plus 2.0]
! a comment
||ads.example^
||analytics.example^$important
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

	testing.expect_value(t, engine_match(e, "ads.example.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "sub.ads.example.", .A), Decision.Blocked)
	// Modifiers are stripped, the rule still applies.
	testing.expect_value(t, engine_match(e, "analytics.example.", .A), Decision.Blocked)
	// An allow rule wins over the broader block rule above it.
	testing.expect_value(t, engine_match(e, "allowed.ads.example.", .A), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "exactly.example.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "sub.exactly.example.", .A), Decision.None)
	testing.expect_value(t, engine_match(e, "dnsmasq.example.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "deep.dnsmasq.example.", .A), Decision.Blocked)
	// A regex rule is matched against the name, as AdGuard Home does (#405).
	testing.expect_value(t, engine_match(e, "regex-rule.example.", .A), Decision.Blocked)
	// A path rule still needs more than a name, and is skipped, not fatal.
	testing.expect_value(t, engine_match(e, "has.", .A), Decision.None)
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

	testing.expect_value(t, engine_match(e, "ADS.example.com.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads.example.com", .A), Decision.Blocked)
}

@(test)
test_allow_beats_block :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	parse_list(block, allow, "||example.com^\n", .Adblock)
	parse_list(block, allow, "@@||safe.example.com^\n", .Adblock)

	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)

	testing.expect_value(t, engine_match(e, "example.com.", .A), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "safe.example.com.", .A), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "deep.safe.example.com.", .A), Decision.Allowed)
}

@(test)
test_swap_returns_old_sets :: proc(t: ^testing.T) {
	e := engine_make()
	defer engine_destroy(e)

	b1, a1 := build("first.example\n", .Domains)
	old_b, old_a := engine_swap(e, b1, a1)
	set_destroy(old_b)
	set_destroy(old_a)
	testing.expect_value(t, engine_match(e, "first.example.", .A), Decision.Blocked)

	b2, a2 := build("second.example\n", .Domains)
	old_b2, old_a2 := engine_swap(e, b2, a2)
	set_destroy(old_b2)
	set_destroy(old_a2)
	testing.expect_value(t, engine_match(e, "first.example.", .A), Decision.None)
	testing.expect_value(t, engine_match(e, "second.example.", .A), Decision.Blocked)

	s := engine_stats(e)
	testing.expect_value(t, s.block_rules, 1)
}

/*
Matches on several threads while the sets are swapped and the old ones freed at
once, as `server.reload_filters_from` does: every match still answers from a
whole set, and neither side starves the other. That the swap waits for a match
in flight is `brlock`'s test; a freed set reads back unchanged here, so it
cannot be told.
*/
@(test)
test_swap_waits_for_matches_on_other_threads :: proc(t: ^testing.T) {
	Shared :: struct {
		e:       ^Engine,
		stop:    bool,
		started: int,
		wrong:   int,
	}
	sh := new(Shared)
	defer free(sh)
	sh.e = engine_make()
	defer engine_destroy(sh.e)
	b, a := build("blocked.example\n", .Domains)
	engine_swap(sh.e, b, a)

	readers: [3]^thread.Thread
	for &r in readers {
		r = thread.create_and_start_with_data(sh, proc(data: rawptr) {
			sh := (^Shared)(data)
			sync.atomic_add(&sh.started, 1)
			for !sync.atomic_load(&sh.stop) {
				if engine_match(sh.e, "www.blocked.example.", .A) != .Blocked {
					sync.atomic_add(&sh.wrong, 1)
				}
			}
		})
	}
	for sync.atomic_load(&sh.started) < len(readers) {
		thread.yield()
	}
	for _ in 0 ..< 2000 {
		nb, na := build("blocked.example\n", .Domains)
		ob, oa := engine_swap(sh.e, nb, na)
		set_destroy(ob)
		set_destroy(oa)
	}
	sync.atomic_store(&sh.stop, true)
	for r in readers {
		thread.join(r)
		thread.destroy(r)
	}
	testing.expect_value(t, sync.atomic_load(&sh.wrong), 0)
}
