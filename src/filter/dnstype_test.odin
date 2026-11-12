package filter

import "core:fmt"
import "core:strings"
import "core:testing"
import "elodin:dns"

// `$dnstype` (#406), read as urlfilter reads it: `|`-separated types, a `~`
// excluding one, and a rule matching a type no `~` names and, when any type is
// named without one, one of those.

@(private = "file")
decide :: proc(text: string, name: string, qtype: dns.Type) -> Decision {
	e := engine_of(text)
	defer engine_destroy(e)
	return engine_match(e, name, qtype)
}

@(test)
test_a_dnstype_rule_blocks_only_its_types :: proc(t: ^testing.T) {
	Case :: struct {
		rule:  string,
		qtype: dns.Type,
		want:  Decision,
	}
	cases := []Case {
		{"||v6.example^$dnstype=AAAA", .AAAA, .Blocked},
		{"||v6.example^$dnstype=AAAA", .A, .None},
		{"||v6.example^$dnstype=AAAA", .ANY, .None},
		{"||v6.example^$dnstype=A|AAAA", .A, .Blocked},
		{"||v6.example^$dnstype=A|AAAA", .AAAA, .Blocked},
		{"||v6.example^$dnstype=A|AAAA", .HTTPS, .None},
		// A `~` excludes a type and matches every other.
		{"||v6.example^$dnstype=~A", .A, .None},
		{"||v6.example^$dnstype=~A", .AAAA, .Blocked},
		{"||v6.example^$dnstype=~A", .TXT, .Blocked},
		{"||v6.example^$dnstype=~A|~AAAA", .AAAA, .None},
		{"||v6.example^$dnstype=~A|~AAAA", .MX, .Blocked},
		// Named and excluded: the named ones not excluded.
		{"||v6.example^$dnstype=A|AAAA|~A", .AAAA, .Blocked},
		{"||v6.example^$dnstype=A|AAAA|~A", .A, .None},
		{"||v6.example^$dnstype=A|AAAA|~A", .TXT, .None},
		// As urlfilter's `strToRRType`: any case; and RFC 3597 section 5's TYPEnnn.
		{"||v6.example^$dnstype=aaaa", .AAAA, .Blocked},
		{"||v6.example^$dnstype=Https", .HTTPS, .Blocked},
		{"||v6.example^$dnstype=TYPE65", .HTTPS, .Blocked},
		{"||v6.example^$dnstype=type28", .AAAA, .Blocked},
		{"||v6.example^$dnstype=NSAP-PTR", dns.Type(23), .Blocked},
		{"||v6.example^$dnstype=TYPE300", dns.Type(300), .Blocked},
		{"||v6.example^$dnstype=TYPE300", .AAAA, .None},
		// With other modifiers, in any order.
		{"||v6.example^$important,dnstype=AAAA", .AAAA, .Blocked},
		{"||v6.example^$dnstype=AAAA,important", .A, .None},
		// An allow rule narrowed the same way.
		{"||v6.example^\n@@||v6.example^$dnstype=AAAA", .AAAA, .Allowed},
		{"||v6.example^\n@@||v6.example^$dnstype=AAAA", .A, .Blocked},
		// A plain rule for the name covers every type, whatever else names it.
		{"||v6.example^\n||v6.example^$dnstype=AAAA", .A, .Blocked},
		{"||v6.example^$dnstype=AAAA\n||v6.example^", .TXT, .Blocked},
	}
	for c in cases {
		got := decide(c.rule, "v6.example.", c.qtype)
		testing.expectf(t, got == c.want, "%q for %v: got %v, want %v", c.rule, c.qtype, got, c.want)
	}
}

@(test)
test_a_dnstype_rule_keeps_its_anchor :: proc(t: ^testing.T) {
	// `||` covers the name and below; `|` the name; `||*.` only below.
	testing.expect_value(t, decide("||v6.example^$dnstype=AAAA", "a.b.v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide("||v6.example^$dnstype=AAAA", "a.b.v6.example.", .A), Decision.None)
	testing.expect_value(t, decide("|v6.example^$dnstype=AAAA", "v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide("|v6.example^$dnstype=AAAA", "a.v6.example.", .AAAA), Decision.None)
	testing.expect_value(t, decide("||*.v6.example^$dnstype=AAAA", "v6.example.", .AAAA), Decision.None)
	testing.expect_value(t, decide("||*.v6.example^$dnstype=AAAA", "a.v6.example.", .AAAA), Decision.Blocked)
	// An apex rule for one type and a subtree rule for another stay apart.
	both := "|v6.example^$dnstype=A\n||*.v6.example^$dnstype=AAAA"
	testing.expect_value(t, decide(both, "v6.example.", .A), Decision.Blocked)
	testing.expect_value(t, decide(both, "v6.example.", .AAAA), Decision.None)
	testing.expect_value(t, decide(both, "a.v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide(both, "a.v6.example.", .A), Decision.None)
}

@(test)
test_dnstype_rules_for_one_name_add_up :: proc(t: ^testing.T) {
	// Every rule for a name applies, so the name matches what any of them does.
	Case :: struct {
		rules: string,
		yes:   []dns.Type,
		no:    []dns.Type,
	}
	cases := []Case {
		{"$dnstype=A\n$dnstype=AAAA", {.A, .AAAA}, {.TXT}},
		{"$dnstype=~A\n$dnstype=~AAAA", {.A, .AAAA, .TXT}, {}},
		{"$dnstype=~A|~AAAA\n$dnstype=~AAAA|~TXT", {.A, .TXT, .MX}, {.AAAA}},
		{"$dnstype=~A|~AAAA\n$dnstype=AAAA", {.AAAA, .MX}, {.A}},
		{"$dnstype=AAAA\n$dnstype=~A|~AAAA", {.AAAA, .MX}, {.A}},
		{"$dnstype=A\n$dnstype=A", {.A}, {.AAAA}},
	}
	for c in cases {
		text, _ := strings.replace_all(strings.concatenate({"||v6.example^", c.rules}, context.temp_allocator), "\n", "\n||v6.example^", context.temp_allocator)
		for q in c.yes {
			testing.expectf(t, decide(text, "v6.example.", q) == .Blocked, "%q did not block %v", text, q)
		}
		for q in c.no {
			testing.expectf(t, decide(text, "v6.example.", q) == .None, "%q blocked %v", text, q)
		}
	}
}

@(test)
test_a_dnstype_rule_that_cannot_be_read_is_skipped :: proc(t: ^testing.T) {
	/*
	Dropping a `$dnstype` the parser cannot read would widen the rule to every
	type, so the rule is skipped, as urlfilter refuses it. So is one naming a
	type and excluding it, which matches nothing.
	*/
	skipped := []string {
		"||v6.example^$dnstype=",
		"||v6.example^$dnstype",
		"||v6.example^$dnstype=BOGUS",
		"||v6.example^$dnstype=AAAA|",
		"||v6.example^$dnstype=|AAAA",
		"||v6.example^$dnstype=AAAA|BOGUS",
		"||v6.example^$dnstype=~",
		"||v6.example^$dnstype=~~AAAA",
		"||v6.example^$dnstype= AAAA",
		"||v6.example^$dnstype=NONE",
		"||v6.example^$dnstype=None",
		"||v6.example^$dnstype=TYPE0",
		"||v6.example^$dnstype=TYPE65536",
		"||v6.example^$dnstype=TYPE",
		"||v6.example^$dnstype=TYPE+1",
		"||v6.example^$dnstype=TYPE1_0",
		"||v6.example^$dnstype=NSAP_PTR",
		"||v6.example^$dnstype=AAAA|~AAAA",
	}
	for rule in skipped {
		block, allow := set_make(), set_make()
		testing.expectf(t, parse_rule(block, allow, rule) == 0, "%q was taken", rule)
		set_destroy(block)
		set_destroy(allow)
		for q in ([]dns.Type{.A, .AAAA, .TXT}) {
			testing.expectf(t, decide(rule, "v6.example.", q) == .None, "%q blocked %v", rule, q)
		}
	}
	// As urlfilter's handler, a second `$dnstype` replaces the first.
	testing.expect_value(t, decide("||v6.example^$dnstype=A,dnstype=AAAA", "v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide("||v6.example^$dnstype=A,dnstype=AAAA", "v6.example.", .A), Decision.None)
}

@(test)
test_a_rule_lists_at_most_max_rule_types :: proc(t: ^testing.T) {
	// One rule, and every rule for one name together, name at most
	// MAX_RULE_TYPES types, which keeps adding a rule to a name a bounded merge.
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, "||v6.example^$dnstype=")
	for i in 1 ..= MAX_RULE_TYPES {
		fmt.sbprintf(&sb, "%sTYPE%d", "|" if i > 1 else "", 1000 + i)
	}
	fits := strings.to_string(sb)
	testing.expect_value(t, decide(fits, "v6.example.", dns.Type(1000 + MAX_RULE_TYPES)), Decision.Blocked)
	over := strings.concatenate({fits, "|TYPE999"}, context.temp_allocator)
	testing.expect_value(t, decide(over, "v6.example.", dns.Type(1001)), Decision.None)
	// The same count in exclusions is a rule like any other, and so is the limit.
	neg, _ := strings.replace_all(fits, "TYPE", "~TYPE", context.temp_allocator)
	testing.expect_value(t, decide(neg, "v6.example.", .A), Decision.Blocked)
	testing.expect_value(t, decide(neg, "v6.example.", dns.Type(1001)), Decision.None)
	neg_over := strings.concatenate({neg, "|~TYPE999"}, context.temp_allocator)
	testing.expect_value(t, decide(neg_over, "v6.example.", .A), Decision.None)
	// A type named again in one rule takes no room.
	repeated := strings.concatenate({fits, "|TYPE1001|type1001|~A|~A"}, context.temp_allocator)
	testing.expect_value(t, decide(repeated, "v6.example.", dns.Type(1001)), Decision.Blocked)

	// Rules that together name one type too many: the last is skipped, and
	// what came before still holds.
	two := strings.concatenate({fits, "\n||v6.example^$dnstype=TYPE999"}, context.temp_allocator)
	testing.expect_value(t, decide(two, "v6.example.", dns.Type(999)), Decision.None)
	testing.expect_value(t, decide(two, "v6.example.", dns.Type(1001)), Decision.Blocked)
	// Repeating a type the name already has adds nothing to count.
	again := strings.concatenate({fits, "\n||v6.example^$dnstype=TYPE1001"}, context.temp_allocator)
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect(t, parse_list(block, allow, again, .Adblock) == 2, "a repeated type was refused")
}

@(test)
test_badfilter_cancels_a_dnstype_rule_whatever_its_types :: proc(t: ^testing.T) {
	/*
	urlfilter's `negatesBadfilter` compares a rule's pattern and options but not
	its `$dnstype`, so a `$badfilter` takes back the rule whichever types either
	names - before it or after it in the list.
	*/
	lists := []string {
		"||v6.example^$dnstype=AAAA\n||v6.example^$badfilter",
		"||v6.example^$badfilter\n||v6.example^$dnstype=AAAA",
		"||v6.example^$dnstype=AAAA\n||v6.example^$dnstype=A,badfilter",
		"||v6.example^\n||v6.example^$dnstype=A,badfilter",
		"/^v6\\.example$/$dnstype=AAAA\n/^v6\\.example$/$badfilter",
		"/^v6\\.example$/$badfilter\n/^v6\\.example$/$dnstype=AAAA",
	}
	for list in lists {
		testing.expectf(t, decide(list, "v6.example.", .AAAA) == .None, "%q blocked AAAA", list)
		testing.expectf(t, decide(list, "v6.example.", .A) == .None, "%q blocked A", list)
	}
	// A subtree-only `$badfilter` leaves the apex.
	testing.expect_value(t, decide("||v6.example^$dnstype=AAAA\n||*.v6.example^$badfilter", "v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide("||v6.example^$dnstype=AAAA\n||*.v6.example^$badfilter", "a.v6.example.", .AAAA), Decision.None)
}

@(test)
test_a_dnstype_regex_rule_blocks_only_its_types :: proc(t: ^testing.T) {
	testing.expect_value(t, decide("/^v6\\.example$/$dnstype=AAAA", "v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide("/^v6\\.example$/$dnstype=AAAA", "v6.example.", .A), Decision.None)
	testing.expect_value(t, decide("/^v6\\.example$/$dnstype=~AAAA", "v6.example.", .A), Decision.Blocked)
	testing.expect_value(t, decide("@@/^v6\\.example$/$dnstype=AAAA\n||v6.example^", "v6.example.", .AAAA), Decision.Allowed)
	testing.expect_value(t, decide("@@/^v6\\.example$/$dnstype=AAAA\n||v6.example^", "v6.example.", .A), Decision.Blocked)
	// One pattern under several rules matches what any of them does; written
	// plain once, every type.
	two := "/^v6\\.example$/$dnstype=AAAA\n/^v6\\.example$/$dnstype=A"
	testing.expect_value(t, decide(two, "v6.example.", .A), Decision.Blocked)
	testing.expect_value(t, decide(two, "v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide(two, "v6.example.", .TXT), Decision.None)
	plain := "/^v6\\.example$/$dnstype=AAAA\n/^v6\\.example$/"
	testing.expect_value(t, decide(plain, "v6.example.", .TXT), Decision.Blocked)
	plain_first := "/^v6\\.example$/\n/^v6\\.example$/$dnstype=AAAA"
	testing.expect_value(t, decide(plain_first, "v6.example.", .TXT), Decision.Blocked)

	// Held once, so the regex budget is charged once.
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	parse_list(block, allow, two, .Adblock)
	testing.expect_value(t, len(block.regexes), 1)
	testing.expect_value(t, block.count, 1)
}

@(test)
test_dnstype_rules_are_counted_once_a_name :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	parse_list(block, allow, "||a.example^$dnstype=A\n||a.example^$dnstype=AAAA\n||b.example^$dnstype=A\n", .Adblock)
	testing.expect_value(t, block.count, 2)
	parse_list(block, allow, "||a.example^$badfilter\n", .Adblock)
	testing.expect_value(t, block.count, 1)

	// A name with a plain rule too is still one name, whichever comes first, and
	// is taken back once.
	for list in ([]string{"||c.example^\n||c.example^$dnstype=A\n", "||c.example^$dnstype=A\n||c.example^\n"}) {
		b, a := set_make(), set_make()
		parse_list(b, a, list, .Adblock)
		testing.expectf(t, b.count == 1, "%q counted %d", list, b.count)
		parse_list(b, a, "||c.example^$badfilter\n", .Adblock)
		testing.expectf(t, b.count == 0, "%q counted %d after its badfilter", list, b.count)
		set_destroy(b)
		set_destroy(a)
	}
}

@(test)
test_a_dnstype_rule_costs_little_more_than_a_plain_one :: proc(t: ^testing.T) {
	/*
	A typed name is a table entry with eight bytes of filter ids after it, and a
	list narrowing names to the same types holds that filter once. These names
	are 20 to 24 bytes; a plain rule for one is at most 38 (table_test.odin).
	*/
	N :: 20_000
	block, allow := set_make(), set_make()
	for i in 0 ..< N {
		testing.expect(t, parse_rule(block, allow, fmt.tprintf("||sink-%d.bench.invalid^$dnstype=AAAA", i)) == 1)
	}
	testing.expect_value(t, block.count, N)
	testing.expect_value(t, len(block.filters), 2)
	e := engine_make()
	defer engine_destroy(e)
	engine_swap(e, block, allow)
	bytes := len(block.names.slots) * size_of(Slot) + cap(block.names.blob)
	testing.expectf(t, bytes / N <= 46, "%d bytes a rule", bytes / N)
	testing.expect_value(t, engine_match(e, "sink-7.bench.invalid.", .AAAA), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "sink-7.bench.invalid.", .A), Decision.None)
}

/*
Every step a name's filter takes stays interned, so a list adding one type at a
time to each name, on distinct types, makes a filter per rule. The set keeps
MAX_TYPE_FILTERS and skips rules past them, typed regexes too.
*/
@(test)
test_the_dnstype_filters_a_set_keeps_are_bounded :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	added := 0
	for i in 0 ..< MAX_TYPE_FILTERS + 64 {
		added += parse_rule(block, allow, fmt.tprintf("||n%d.example^$dnstype=TYPE%d", i / 32, 1000 + i))
	}
	testing.expect_value(t, len(block.filters), MAX_TYPE_FILTERS)
	testing.expect_value(t, added, MAX_TYPE_FILTERS - 1)
	testing.expect_value(t, parse_rule(block, allow, "/^re\\.example$/$dnstype=TYPE9"), 0)
	// A filter already held, and a rule for every type, still take.
	testing.expect_value(t, parse_rule(block, allow, "||m.example^$dnstype=TYPE1000"), 1)
	testing.expect_value(t, parse_rule(block, allow, "/^re\\.example$/"), 1)
}

@(test)
test_a_typed_rule_joins_a_name_a_plain_rule_holds :: proc(t: ^testing.T) {
	// The entry is written again with room for its filters; both rules hold.
	list := "|v6.example^\n||*.v6.example^$dnstype=AAAA\n||other.example^\n"
	block, allow := set_make(), set_make()
	parse_list(block, allow, list, .Adblock)
	testing.expect_value(t, block.count, 2)
	set_destroy(block)
	set_destroy(allow)
	testing.expect_value(t, decide(list, "v6.example.", .A), Decision.Blocked)
	testing.expect_value(t, decide(list, "a.v6.example.", .AAAA), Decision.Blocked)
	testing.expect_value(t, decide(list, "a.v6.example.", .A), Decision.None)
	testing.expect_value(t, decide(list, "other.example.", .A), Decision.Blocked)
}

@(test)
test_a_block_says_when_only_a_dnstype_rule_made_it :: proc(t: ^testing.T) {
	Case :: struct {
		list:       string,
		name:       string,
		typed_only: bool,
	}
	cases := []Case {
		{"||v6.example^$dnstype=AAAA", "v6.example.", true},
		{"||v6.example^$dnstype=~A", "a.v6.example.", true},
		{"/^v6\\.example$/$dnstype=AAAA", "v6.example.", true},
		// A rule for every type makes it a block of the name, wherever it is.
		{"||v6.example^$dnstype=AAAA\n||v6.example^", "v6.example.", false},
		{"||v6.example^$dnstype=AAAA\n||example^", "v6.example.", false},
		{"||a.v6.example^$dnstype=AAAA\n||v6.example^", "a.v6.example.", false},
		{"||v6.example^$dnstype=AAAA\n/^v6\\./", "v6.example.", false},
		{"/^v6\\.example$/$dnstype=AAAA\n/example$/", "v6.example.", false},
		// Rules that add up to every type are a rule for every type.
		{"||v6.example^$dnstype=~A\n||v6.example^$dnstype=~AAAA", "v6.example.", false},
		{"||v6.example^$dnstype=A\n||v6.example^$dnstype=~A", "a.v6.example.", false},
		{"/^v6\\.example$/$dnstype=~A\n/^v6\\.example$/$dnstype=~AAAA", "v6.example.", false},
		// A `$dnstype` allow rule leaves the name the types it exempts.
		{"||v6.example^\n@@||v6.example^$dnstype=A", "v6.example.", true},
		{"||v6.example^\n@@||example^$dnstype=A", "v6.example.", true},
		{"||v6.example^\n@@/^v6\\.example$/$dnstype=A", "v6.example.", true},
		{"||v6.example^\n@@|example^$dnstype=A", "v6.example.", false},
		{"||v6.example^\n@@||a.v6.example^$dnstype=A", "v6.example.", false},
		{"||v6.example^\n@@/^a\\.v6\\.example$/$dnstype=A", "v6.example.", false},
	}
	for c in cases {
		e := engine_of(c.list)
		typed_only := !c.typed_only
		got := engine_match(e, c.name, .AAAA, &typed_only)
		testing.expectf(t, got == .Blocked && typed_only == c.typed_only, "%q: %v, typed only %v", c.list, got, typed_only)
		engine_destroy(e)
	}
}
