package filter

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"

/*
Adblock regex rules (#405): `/re/` is matched against the lowercased query name
without its trailing dot, as AdGuard Home's urlfilter matches it against the
hostname, and the list's text never gets to choose how long that takes.
*/

@(private = "file")
engine_of :: proc(text: string, format := Format.Adblock) -> ^Engine {
	block, allow := set_make(), set_make()
	parse_list(block, allow, text, format)
	e := engine_make()
	engine_swap(e, block, allow)
	return e
}

@(test)
test_regex_rule_matches_the_name :: proc(t: ^testing.T) {
	e := engine_of("/^ads[0-9]+\\.example\\.com$/\n/tracker/\n")
	defer engine_destroy(e)

	testing.expect_value(t, engine_match(e, "ads12.example.com."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads12.example.com"), Decision.Blocked)
	// The name is lowercased before it is matched.
	testing.expect_value(t, engine_match(e, "ADS3.Example.COM."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads.example.com."), Decision.None)
	// The anchors hold at the ends of the name, not of a label.
	testing.expect_value(t, engine_match(e, "xads1.example.com."), Decision.None)
	testing.expect_value(t, engine_match(e, "ads1.example.com.evil."), Decision.None)
	// Unanchored, it matches anywhere in the name.
	testing.expect_value(t, engine_match(e, "a.tracker.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "trackers.example"), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "track.example"), Decision.None)
}

// urlfilter compiles a rule without `$match-case` as `(?i)` + pattern, so an
// upper-case class in the pattern still matches the lowercased name.
@(test)
test_regex_rule_is_case_insensitive :: proc(t: ^testing.T) {
	e := engine_of("/^ADS[A-Z]\\.example$/\n")
	defer engine_destroy(e)
	testing.expect_value(t, engine_match(e, "adsq.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads1.example."), Decision.None)
}

// A `$` inside the slashes is the regex's; the options start at the last `$`
// after the closing slash, as urlfilter's `findOptionsDelimiter` finds them.
@(test)
test_regex_rule_dollar_and_modifiers :: proc(t: ^testing.T) {
	src := `/^a\.example$/
/^b\.example$/$important
/^c\.example$/$dnstype=AAAA
/^d\.example/
/^d\.example/$badfilter
/^e\.example/$badfilter
/^e\.example/
/^(f|g)\.example$/
/^i\.example/$
/^j\.ex?ample|x/$replace=/a/b/
`
	e := engine_of(src)
	defer engine_destroy(e)

	testing.expect_value(t, engine_match(e, "a.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "b.example."), Decision.Blocked)
	// A modifier DNS cannot honour skips the rule, as for any other rule.
	testing.expect_value(t, engine_match(e, "c.example."), Decision.None)
	// `$badfilter` takes the rule back whichever side of it the rule sits.
	testing.expect_value(t, engine_match(e, "d.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "e.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "g.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "h.example."), Decision.None)
	// urlfilter's `findOptionsDelimiter` starts at the last byte, so a
	// trailing `$` opens an empty options list and `/re/$` is the regex.
	testing.expect_value(t, engine_match(e, "i.example."), Decision.Blocked)
	// A rule holding `replace=` is split at its last `$` even when it ends in
	// `/` (urlfilter's `isRegexRuleWithoutOptions`), so it is a `$replace`
	// rule and skipped, not a regex taking in everything up to the end.
	testing.expect_value(t, engine_match(e, "j.eample."), Decision.None)
}

@(test)
test_regex_allow_rule :: proc(t: ^testing.T) {
	e := engine_of("||example.org^\n@@/^keep\\./\n@@/^free\\./\n/^blocked\\./\n@@/^blocked\\.but-allowed\\./\n")
	defer engine_destroy(e)

	// An allow regex outranks a hash-set block ...
	testing.expect_value(t, engine_match(e, "keep.example.org."), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "other.example.org."), Decision.Blocked)
	// ... and a regex block.
	testing.expect_value(t, engine_match(e, "blocked.but-allowed.test."), Decision.Allowed)
	testing.expect_value(t, engine_match(e, "blocked.test."), Decision.Blocked)
	// With nothing blocking the name it is still Allowed, not None: an allow
	// rule on the question is what exempts an answer from the CNAME walk.
	testing.expect_value(t, engine_match(e, "free.test."), Decision.Allowed)
}

@(test)
test_regex_rules_are_counted :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	added := parse_list(block, allow, "||a.example^\n/^b/\n/^b/\n@@/^c/\n", .Adblock)
	// A repeated pattern reports as added, as a repeated name does, and is
	// held once.
	testing.expect_value(t, added, 4)
	testing.expect_value(t, block.count, 2)
	testing.expect_value(t, allow.count, 1)

	e := engine_make()
	defer free(e)
	engine_swap(e, block, allow)
	s := engine_stats(e)
	testing.expect_value(t, s.block_rules, 2)
	testing.expect_value(t, s.allow_rules, 1)
}

// A list written as bare domains may still carry a regex line; a `/` can never
// be part of a domain, so the line can only have meant one thing.
@(test)
test_regex_rule_in_a_domains_list :: proc(t: ^testing.T) {
	e := engine_of("plain.example\n/^ads[0-9]\\./\n-/^ads1\\./\n", .Domains)
	defer engine_destroy(e)
	testing.expect_value(t, engine_match(e, "plain.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ads7.example."), Decision.Blocked)
	// `-` makes it an allow rule, as it does a domain.
	testing.expect_value(t, engine_match(e, "ads1.example."), Decision.Allowed)

	// A `!` or `#` opens a comment in such a list; one inside the slashes
	// would leave a shorter pattern that matches far more.
	f := engine_of("/q/!x/\n/^kept\\./ # a comment\nwide.example\n@@/w/!x/\n@@/i/#x/\n", .Domains)
	defer engine_destroy(f)
	testing.expect_value(t, engine_match(f, "q.example."), Decision.None)
	testing.expect_value(t, engine_match(f, "kept.example."), Decision.Blocked)
	// `@@` takes its own road to the adblock parser, and is held to the same.
	testing.expect_value(t, engine_match(f, "wide.example."), Decision.Blocked)
	testing.expect_value(t, len(f.allow.regexes), 0)
}

/*
urlfilter tries a rule only on a name whose `http://` URL holds the pattern's
longest literal run, so these are what AdGuard Home blocks, checked against its
`DNSEngine`: an alternation matches only through its longest branch, an escape
glues its letter to the literal after it, and a `?` turns the test off.
*/
@(test)
test_regex_rule_needs_its_shortcut :: proc(t: ^testing.T) {
	e := engine_of("/ads|tracker/\n/\\bpixel\\b/\n/^beacon\\d?\\./\n")
	defer engine_destroy(e)
	testing.expect_value(t, engine_match(e, "ads.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "tracker.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "pixel.example."), Decision.None)
	testing.expect_value(t, engine_match(e, "beacon.example."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "beacon7.example."), Decision.Blocked)

	testing.expect_value(t, regex_shortcut(`^(a|c)\.[0-9a-f]{56}\.com$`, context.temp_allocator), "com")
	testing.expect_value(t, regex_shortcut(`^ADS\d+`, context.temp_allocator), "ads")
	testing.expect_value(t, regex_shortcut(`a{2}b\{c}d`, context.temp_allocator), "")
	testing.expect_value(t, regex_shortcut(`x\(ab)`, context.temp_allocator), "ab")
}

// urlfilter reads a `$$` or `$@$` at the first `$` as an HTML filtering rule,
// which DNS never applies, a regex rule's included.
@(test)
test_regex_html_rule_marker :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	testing.expect_value(t, parse_rule(block, allow, "/ads$$/"), 0)
	testing.expect_value(t, parse_rule(block, allow, "/ads$@$x/"), 0)
	testing.expect_value(t, parse_rule(block, allow, "/ads$/"), 1)
}

@(test)
test_regex_rules_that_are_refused :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	refused := []string {
		// Empty, or matching the empty string: urlfilter would match every
		// name with it.
		"//",
		"/ads|/",
		"/x*/",
		"/(|a)/",
		"/^/",
		// Not RE2: an unclosed group or class, a stray `)`, a range running
		// backwards, a repeat of a repeat or of nothing, a class range to a
		// class escape, `\b` in a class, a count past 1000 or below its start,
		// a trailing `\`.
		"/(ads/",
		"/[ab/",
		`/a)/`,
		`/[a-Z]/`,
		`/[^a-Z]/`,
		`/[b-\.]/`,
		`/a{2}{3}/`,
		`/a**/`,
		`/a+?+/`,
		`/a*??/`,
		`/*a/`,
		`/a|+b/`,
		`/{2}a/`,
		`/[a-\d]/`,
		`/[\b]ads/`,
		`/[\B]ads/`,
		`/[a-\b]/`,
		`/a{1001}/`,
		`/a{3,2}/`,
		`/a\/`,
		// RE2, outside the subset `re2_parse` reads: lookahead, flags, named
		// groups, a backreference, `\x`, `\A`, `\z`, `\Q`, `\p`, `\n`, octal, a
		// POSIX class.
		"/(?=ads)/",
		"/(?i)ads/",
		"/(?P<n>ads)/",
		`/(a)\1/`,
		`/\x61/`,
		`/\Aa/`,
		`/a\z/`,
		`/\Qa/`,
		`/\pLa/`,
		`/a\n/`,
		`/a\0/`,
		`/[[:alpha:]]/`,
		// A raw byte outside printable ASCII: no query name holds one.
		"/š/",
		"/\x01/",
		// A cosmetic rule to urlfilter, not a network rule: a marker at the
		// first `#` or `$`.
		`/ads#?#x/`,
		`/ads##x/`,
		`/ads#%#x/`,
		`/ads|a$$/`,
	}
	for rule in refused {
		testing.expectf(t, parse_rule(block, allow, rule) == 0, "%q was added", rule)
	}
	testing.expect_value(t, block.count, 0)

	e := engine_make()
	defer free(e)
	engine_swap(e, block, allow)
	testing.expect_value(t, engine_match(e, "a.example."), Decision.None)
	engine_swap(e, nil, nil)

	// What RE2 reads the same way is still kept.
	for rule in ([]string{`/[a-z0-9-]/`, `/[-a]/`, `/[\w-]/`, `/[\--z]/`, `/[a-c-e]/`, `/[a-z0-9-_]/`, `/[\da-z]/`, `/[A-Z]/`, `/[!-~]/`, `/(a)(b)/`, `/\)/`, `/[)]/`}) {
		testing.expectf(t, parse_rule(block, allow, rule) == 1, "%q was refused", rule)
	}
}

/*
Patterns RE2 reads one way and Odin's own parser another, and names spelled one
way by miekg/dns and another by `dns`: each blocks here exactly what it blocks
in AdGuard Home. Every `want` is urlfilter's answer, from its `DNSEngine` over
the name as miekg/dns presents it; `scripts/re2diff` asks it the same of random
patterns.
*/
@(test)
test_regex_reads_as_re2 :: proc(t: ^testing.T) {
	Case :: struct {
		rule: string,
		name: string,
		want: bool,
	}
	cases := []Case {
		// Odin takes `#` outside a group as the start of a comment.
		{`/ads#x/`, "ads#x", true},
		{`/ads#x/`, "ads", false},
		// A space before it keeps `#?#` and `$$` from being markers.
		{`/a #?#|ads/`, "ads", true},
		{`/ads|a $$/`, "ads", true},
		// A `{` that is no count is itself; Odin's strconv read these as counts,
		// and `{,3}` as "up to three".
		{`/^a{02}$/`, "a{02}", true},
		{`/^a{02}$/`, "aa", false},
		{`/^a{2,03}$/`, "a{2,03}", true},
		{`/^a{1_0}$/`, "a{1_0}", true},
		{`/^a{1_0}$/`, "aaaaaaaaaa", false},
		{`/^a{,3}$/`, "a{,3}", true},
		{`/^a{,3}$/`, "aa", false},
		{`/^ab{$/`, "ab{", true},
		// `+` repeats the `{` before it.
		{`/^a{+2}$/`, "a{+2}", false},
		{`/^a{+2}$/`, "a{{2}", true},
		// `(?i)` folds every letter in a range, whatever its ends; Odin folded
		// only a range from a letter to a letter, and then only its ends.
		{`/^[\.-a]$/`, "b", true},
		{`/^[\.-a]$/`, "_", true},
		{`/^[\.-a]$/`, "-", false},
		{`/^[0-Z]$/`, "b", true},
		{`/^[0-Z]$/`, "_", false},
		{`/^[A-z]$/`, "_", true},
		{`/^[A-z]$/`, "-", false},
		{`/^[Z-a]$/`, "_", true},
		{`/^[Z-a]$/`, "b", false},
		// It folds before `^` negates.
		{`/^[^A]$/`, "a", false},
		{`/^[^A]$/`, "b", true},
		// A range starts only from the element just before its `-`; Odin
		// started one from whatever single rune it held.
		{`/^[a\d-z]$/`, "-", true},
		{`/^[a\d-z]$/`, "5", true},
		{`/^[a\d-z]$/`, "b", false},
		{`/^[ab-c-e]$/`, "-", true},
		{`/^[ab-c-e]$/`, "d", false},
		{`/^[\w-_]$/`, "-", true},
		{`/^[--/]$/`, "/", true},
		{`/^[--/]$/`, "_", false},
		// A range may end in an escape; Odin read what it escaped on its own,
		// and `[[-\\]` tripped an assertion in its parser.
		{`/^[+-\.]$/`, ",", true},
		{`/^[+-\.]$/`, "5", false},
		{`/^[[-\\]$/`, "[", true},
		{`/^[[-\\]$/`, "a", false},
		// `]` first is itself; Odin read `[]` as an empty class.
		{`/^[]a]$/`, "]", true},
		{`/^[]a]$/`, "b", false},
		{`/^[^]a]$/`, "]", false},
		{`/^[^]a]$/`, "b", true},
		// A repeat of an anchor or a boundary, as RE2 takes it.
		{`/^*ads$/`, "xads", true},
		{`/ads\b+/`, "ads", true},
		{`/ads\b+/`, "adsx", false},
		{`/x(?:$){2}/`, "ax", true},
		{`/x(?:$){2}/`, "xa", false},
		// A group captures nothing, so Odin's limit of nine does not apply.
		{`/^(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)$/`, "abcdefghij", true},
		// The name is matched as miekg/dns spells it: `(` and `;` behind a
		// `\`, and a label's `.`, `\` and space as `\.`, `\\` and `\ `.
		{`/^a\(b$/`, "a(b", false},
		{`/^a\\\(b$/`, "a(b", true},
		{`/^a\\;b$/`, "a;b", true},
		{`/^a\\\.b$/`, "a\\046b", true},
		{`/^a\\\\b$/`, "a\\092b", true},
		{`/^a\\ b$/`, "a\\032b", true},
		{`/^a\\032b$/`, "a\\032b", false},
		{`/^a\\001b$/`, "a\\001b", true},
	}
	for c in cases {
		block, allow := set_make(), set_make()
		defer set_destroy(block)
		defer set_destroy(allow)
		if !testing.expectf(t, parse_rule(block, allow, c.rule) == 1, "%s was refused", c.rule) {
			continue
		}
		e := engine_make()
		engine_swap(e, block, allow)
		got := engine_match(e, c.name) == .Blocked
		testing.expectf(t, got == c.want, "%s on %q: blocked %v, want %v", c.rule, c.name, got, c.want)
		engine_swap(e, nil, nil)
		free(e)
	}
}

// A name spelled as miekg/dns spells it can be longer than as `dns` spells
// it, and the spelled-out form is what `MAX_REGEX_NAME` holds to a hostname's
// length.
@(test)
test_regex_subject_fits_a_hostname :: proc(t: ^testing.T) {
	e := engine_of("/\\\\\\(/\n")
	defer engine_destroy(e)
	parens :: proc(n: int) -> string {
		return strings.repeat("(", n, context.temp_allocator)
	}
	// 125 of them, each spelled `\(`, and a dot: 251 characters.
	testing.expect_value(t, engine_match(e, fmt.tprintf("%s.%s", parens(62), parens(63))), Decision.Blocked)
	// 126 and two dots: 254.
	testing.expect_value(t, engine_match(e, fmt.tprintf("%s.%s.(", parens(62), parens(63))), Decision.None)
	testing.expect_value(t, engine_match(e, fmt.tprintf("%s.%s.%s.%s", parens(62), parens(62), parens(62), parens(62))), Decision.None)
}

// Go's `repeatIsValid`: counts nested in one another multiply to 1000 at most.
// The program bound refuses these too, by a few bytes, so the rule is asked of
// the parser alone.
@(test)
test_regex_nested_counts_multiply :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	Case :: struct {
		pattern: string,
		ok:      bool,
	}
	for c in ([]Case {
			{"(?:a{2}){500}", true},
			{"(?:a{2}){501}", false},
			{"(?:(?:a{0}){1000}){1000}", false},
			{"(?:(?:a{0}){1000}){1}", true},
			{"(?:(?:a{2,}){10}){51}", false},
			{"(?:(?:a*){1000}b){1000}", false},
			{"(?:a*){1000}", true},
			{"(?:a{2}|b{3}){334}", false},
			{"(?:a{2}|b{3}){333}", true},
		}) {
		_, ok := re2_parse(c.pattern)
		testing.expectf(t, ok == c.ok, "%s: parsed %v, want %v", c.pattern, ok, c.ok)
	}
}

// Odin's optimizer folds `z|\W` into one class and loses the negation; with it
// on, this blocked `a`.
@(test)
test_regex_negated_class_in_an_alternation :: proc(t: ^testing.T) {
	e := engine_of("/^(z|\\W)$/\n/^(\\S|0)$/\n")
	defer engine_destroy(e)
	testing.expect_value(t, engine_match(e, "a"), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "z"), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "-"), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "ab"), Decision.None)
	e2 := engine_of("/^(z|\\W)$/\n")
	defer engine_destroy(e2)
	testing.expect_value(t, engine_match(e2, "a"), Decision.None)
	testing.expect_value(t, engine_match(e2, "-"), Decision.Blocked)
}

// The AdGuard DNS filter's one allow regex needs a `#` in the name, which none
// holds; read as Odin's tokenizer reads it, it allowed every name with `.png`.
@(test)
test_regex_hash_is_no_comment :: proc(t: ^testing.T) {
	e := engine_of("||gdfp.gifshow.com^\n@@/\\.(gif|jpe?g|png|webp)#(\\/?.+)?(\\/(ad)s?\\/|\\/ad-)/\n")
	defer engine_destroy(e)
	testing.expect_value(t, engine_match(e, "gdfp.gifshow.com."), Decision.Blocked)
	testing.expect_value(t, engine_match(e, "img.png.example."), Decision.None)
}

// What RE2 and Odin read the same way is kept, and means what RE2 means. The
// `\B` is written beside a group, not a letter, so its shortcut stays empty.
@(test)
test_regex_syntax_both_engines_share :: proc(t: ^testing.T) {
	src := `/^\w+\.\d{2}\b/
/^(x*)*y\.test$/
/^(?:ab+)+\.test$/
/^[\w-]+\.dash\.test$/
/^\S+\.\D\.test$/
/.\B(mid)\B./
`
	e := engine_of(src)
	defer engine_destroy(e)
	Want :: struct {
		name: string,
		want: Decision,
	}
	for w in ([]Want {
			{"ab.12.test", .Blocked},
			{"ab.123", .None},
			{"xxy.test", .Blocked},
			{"abbab.test", .Blocked},
			{"a-b_c.dash.test", .Blocked},
			{"a.b.test", .Blocked},
			{"a.1.test", .None},
			{"amidst.test", .Blocked},
			{"mid.test", .None},
		}) {
		testing.expectf(t, engine_match(e, w.name) == w.want, "%s: got %v, want %v", w.name, engine_match(e, w.name), w.want)
	}
}

/*
Repetition is where a pattern's size stops being its length: Odin's compiler
writes `e{N}` out N times, and checks the program's size only once it has
written all of it. So the bound has to be known before compiling, and these must
come back refused, quickly, and without the memory the expansion would take.
Each takes microseconds; a second is room for a loaded runner, and what the
guard's absence costs is minutes.
*/
@(test)
test_regex_repetition_is_bounded_before_compiling :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	bombs := []string {
		"/a{99999999999}/",
		"/a{1,9223372036854775807}/",
		"/((a{1000}){1000}){1000}/",
		"/(((((a{9}){9}){9}){9}){9}){9}/",
		"/(a|b|c|d|e|f|g|h){100000}/",
		// Counts past `max(i64)` arrive negative; this pair reaches the
		// compiler's "invalid repetition group" panic.
		"/a{9223372036854775808,9223372036854775809}/",
		"/a{18446744073709551615}/",
		"/a{0,18446744073709551615}/",
		// Past RE2's 1000, which urlfilter would not compile either.
		"/a{1001}/",
	}
	for rule in bombs {
		start := time.tick_now()
		n := parse_rule(block, allow, rule)
		took := time.tick_since(start)
		testing.expectf(t, n == 0, "%q was added", rule)
		testing.expectf(t, took < time.Second, "%q took %v to refuse", rule, took)
	}
	testing.expect_value(t, block.regex_bytes, 0)

	// The deepest a pattern inside `MAX_REGEX_PATTERN` can nest, which is how
	// deep the parser, the optimizer and `node_bound` recurse. Refused on size
	// or accepted, what matters is that it comes back.
	half := MAX_REGEX_PATTERN / 2 - 1
	deep := []string {
		fmt.tprintf("/%sa%s/", strings.repeat("(", half, context.temp_allocator), strings.repeat(")", half, context.temp_allocator)),
		fmt.tprintf("/%sa%s/", strings.repeat("(?:", half / 2, context.temp_allocator), strings.repeat(")", half / 2, context.temp_allocator)),
		fmt.tprintf("/%sa/", strings.repeat("a|", half, context.temp_allocator)),
		fmt.tprintf("/%sa/", strings.repeat("b|a", MAX_REGEX_PATTERN / 3 - 1, context.temp_allocator)),
		// Unbalanced, as deep as the length allows: refused, after `re2_parse`
		// has recursed once per `(`.
		fmt.tprintf("/%s/", strings.repeat("(", MAX_REGEX_PATTERN, context.temp_allocator)),
		fmt.tprintf("/%s/", strings.repeat("(?:", MAX_REGEX_PATTERN / 3, context.temp_allocator)),
		fmt.tprintf("/%s/", strings.repeat("[", MAX_REGEX_PATTERN, context.temp_allocator)),
	}
	for rule in deep {
		start := time.tick_now()
		parse_rule(block, allow, rule)
		took := time.tick_since(start)
		testing.expectf(t, took < time.Second, "%d-byte pattern took %v", len(rule), took)
	}
}

@(test)
test_regex_pattern_and_program_limits :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	long := strings.repeat("a", MAX_REGEX_PATTERN + 1)
	defer delete(long)
	testing.expect_value(t, parse_rule(block, allow, fmt.tprintf("/%s/", long)), 0)
	testing.expect_value(t, parse_rule(block, allow, fmt.tprintf("/%s/", long[1:])), 0)

	// Just inside the program limit, and matched against the longest name
	// there is: the scratch a match runs in is sized from that limit. Each
	// `[a-z]?` is a split and a class, seven bytes.
	big := fmt.tprintf("/[a-z]{{0,%d}}z/", (MAX_REGEX_PROGRAM - 18) / 7)
	testing.expectf(t, parse_rule(block, allow, big) == 1, "%s was refused", big)
	size := len(block.regexes[0].re.program)
	testing.expectf(t, size > MAX_REGEX_PROGRAM - 32 && size <= MAX_REGEX_PROGRAM, "%s compiled to %d bytes", big, size)
	over := fmt.tprintf("/[a-z]{{0,%d}}y/", (MAX_REGEX_PROGRAM - 18) / 7 + 3)
	testing.expectf(t, parse_rule(block, allow, over) == 0, "%s was added", over)

	e := engine_make()
	defer free(e)
	engine_swap(e, block, nil)
	labels := make([dynamic]string, context.temp_allocator)
	for _ in 0 ..< 4 {
		append(&labels, strings.repeat("a", 62, context.temp_allocator))
	}
	name := strings.join(labels[:], ".", context.temp_allocator)
	testing.expect_value(t, engine_match(e, name), Decision.None)
	a := strings.repeat("a", MAX_REGEX_NAME - 1, context.temp_allocator)
	testing.expect_value(t, engine_match(e, fmt.tprintf("%sz", a)), Decision.Blocked)
	// Past a hostname's length the name spells bytes as `\DDD`, which only
	// makes a scan longer: no regex is asked about it.
	testing.expect_value(t, engine_match(e, fmt.tprintf("%saz", a)), Decision.None)
	testing.expect_value(t, engine_match(e, fmt.tprintf("%s\\001z", a)), Decision.None)
	engine_swap(e, nil, nil)
}

// What a set may hold is charged in program bytes, the thing a match's cost
// grows with, and a list that runs past it keeps what came first.
@(test)
test_regex_budget_per_set :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	i := 0
	for block.regex_refused == 0 {
		parse_rule(block, allow, fmt.tprintf("/^r%d[0-9a-f]{{60}}$/", i))
		i += 1
		if !testing.expect(t, i < 100_000) {
			return
		}
	}
	testing.expect(t, block.regex_bytes <= MAX_REGEX_TOTAL)
	testing.expect_value(t, block.count, len(block.regexes))
	testing.expect_value(t, block.count, i - 1)

	e := engine_make()
	defer free(e)
	engine_swap(e, block, nil)
	hex := strings.repeat("0", 60, context.temp_allocator)
	testing.expect_value(t, engine_match(e, fmt.tprintf("r0%s", hex)), Decision.Blocked)
	testing.expect_value(t, engine_match(e, fmt.tprintf("r%d%s", i - 1, hex)), Decision.None)
	engine_swap(e, nil, nil)
}

// A class is two bytes of program however many entries it lists, and a match
// tests them one by one, so each is charged too. Every other printable byte
// is the most runs a class can have once `re2_parse` has merged neighbours;
// those patterns would otherwise fit the budget by the hundred and cost a
// query fifty times as much.
@(test)
test_regex_budget_charges_class_entries :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	class: strings.Builder
	strings.builder_init(&class, context.temp_allocator)
	strings.write_byte(&class, '[')
	entries := 0
	for c := u8('!'); c <= '~'; c += 2 {
		if c == ']' || c == '-' {
			strings.write_byte(&class, '\\')
		}
		strings.write_byte(&class, c)
		entries += 1
	}
	strings.write_byte(&class, ']')
	classes := strings.repeat(strings.to_string(class), (MAX_REGEX_PATTERN - 8) / len(strings.to_string(class)), context.temp_allocator)
	entries *= len(classes) / len(strings.to_string(class))
	for i := 0; block.regex_refused == 0; i += 1 {
		parse_rule(block, allow, fmt.tprintf("/%s%d/", classes, i))
	}
	testing.expectf(t, len(block.regexes) > 0 && len(block.regexes) <= MAX_REGEX_TOTAL / entries, "%d class-heavy patterns kept", len(block.regexes))
	testing.expect(t, block.regex_bytes <= MAX_REGEX_TOTAL)
	// What a `$badfilter` gives back is what was charged.
	charged := block.regex_bytes
	parse_rule(block, allow, fmt.tprintf("/%s0/$badfilter", classes))
	testing.expect(t, block.regex_bytes < charged - entries)
}

// `program_bound` is what keeps a pattern from being compiled at all, so it
// must never come in under what the compiler writes.
@(test)
test_program_bound_covers_the_compiler :: proc(t: ^testing.T) {
	shapes := []string {
		// The AdGuard DNS filter's own.
		`^142\.91\.159\.(1[5-9]\d|2[0-4]\d|250):(80|443)$`,
		`^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$`,
		`^https:\/\/(a|c)\.[0-9a-f]{56}\.com$`,
		`(https?:\/\/)213\.32\.115\..{100,}`,
		`\.(gif|jpe?g|png|webp)#(\/?.+)?(\/(ad)s?\/|\/ad-)`,
		// Every node and repeat shape.
		`a`, `.`, `^$`, `\bx\B`, `[^a-z]`, `(?:ab)`, `a|b|c`, `abi|abe`,
		`a*`, `a*?`, `a+`, `a+?`, `a?`, `a??`, `.*$`, `.+$`,
		`(ab){7}`, `(ab){7,}`, `(ab){3,7}`, `(ab){0,}`, `(a{2,3}|b{4}){2,5}`,
		`((a|b)*c+){3}d?`, `x{1000}`, `[a-z]{496}z`,
	}
	for shape in shapes {
		context.allocator = context.temp_allocator
		tree, parsed := re2_parse(shape)
		if !testing.expectf(t, parsed, "%q did not parse", shape) {
			continue
		}
		re, compiled := regex_compile(tree, context.temp_allocator)
		testing.expectf(t, compiled, "%q did not compile", shape)
		// Past the limit the bound saturates, which refuses the pattern.
		bound := program_bound(tree)
		testing.expectf(
			t,
			bound > MAX_REGEX_PROGRAM || bound >= len(re.program),
			"%q: bound %d, compiled %d",
			shape,
			bound,
			len(re.program),
		)
	}
}

// Past the first pattern that does not fit, none is compiled, a small one
// included: a long hostile list costs a comparison a line, not a compile.
@(test)
test_regex_budget_stops_at_the_first_refusal :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	for i := 0; block.regex_refused == 0; i += 1 {
		parse_rule(block, allow, fmt.tprintf("/^r%d[0-9a-f]{{300}}$/", i))
	}
	kept := len(block.regexes)
	testing.expect(t, block.regex_bytes + 64 <= MAX_REGEX_TOTAL, "no room left for the small pattern")
	testing.expect_value(t, parse_rule(block, allow, "/^small$/"), 0)
	testing.expect_value(t, len(block.regexes), kept)
	testing.expect_value(t, block.regex_refused, 2)
	// One already held still reports as held.
	testing.expect_value(t, parse_rule(block, allow, "/^r0[0-9a-f]{300}$/"), 1)
}

// A `$badfilter` is keyed like the rule it cancels, into a buffer sized for the
// longest pattern a rule may have; a longer one cancels nothing.
@(test)
test_regex_badfilter_past_the_pattern_limit :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)

	long := strings.repeat("a", 4 * MAX_REGEX_PATTERN, context.temp_allocator)
	testing.expect_value(t, parse_rule(block, allow, fmt.tprintf("/%s/$badfilter", long)), 0)
	testing.expect_value(t, len(block.cancelled), 0)
}

// Odin's compiler holds a program to 254 different classes, which is short of
// what RE2 takes, so a pattern with more is refused rather than compiled.
@(test)
test_regex_class_count_limit :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	alphabet := "0123456789abcdefghijklmnopqrstuvwxyz"
	pattern :: proc(alphabet: string, n: int) -> string {
		b := strings.builder_make(context.temp_allocator)
		made := 0
		for i in 0 ..< len(alphabet) {
			for j in i + 1 ..< len(alphabet) {
				if made == n {
					return strings.to_string(b)
				}
				fmt.sbprintf(&b, "[%c%c]", alphabet[i], alphabet[j])
				made += 1
			}
		}
		return strings.to_string(b)
	}
	testing.expect_value(t, parse_rule(block, allow, fmt.tprintf("/%s/", pattern(alphabet, 254))), 1)
	testing.expect_value(t, parse_rule(block, allow, fmt.tprintf("/%s/", pattern(alphabet, 255))), 0)
}

// A `$badfilter` of a pattern that could never be added cancels nothing, and
// is not counted as a cancel, which is how an operator's is warned of.
@(test)
test_regex_badfilter_of_a_refused_pattern :: proc(t: ^testing.T) {
	block, allow := set_make(), set_make()
	defer set_destroy(block)
	defer set_destroy(allow)
	for rule in ([]string{`/\x41/$badfilter`, `/(?=a)/$badfilter`, `/a)/$badfilter`}) {
		parse_rule(block, allow, rule)
	}
	testing.expect_value(t, block.cancels, 0)
	testing.expect_value(t, len(block.cancelled), 0)
	parse_rule(block, allow, `/^a{02}$/$badfilter`)
	testing.expect_value(t, block.cancels, 1)
}
