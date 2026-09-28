package filter

import "core:mem"
import "core:mem/virtual"
import "core:strconv"
import "core:strings"
import "core:text/regex"
import "core:text/regex/common"
import "core:text/regex/parser"
import "core:text/regex/tokenizer"
import "core:text/regex/virtual_machine"

/*
Adblock regex rules: `/ads[0-9]+\.example\./`.

AdGuard Home matches one against the query name - urlfilter's `matchPattern`
runs it over the hostname, lowercased and without its trailing dot, and compiles
it case-insensitively unless the rule says `$match-case` - so lists written for
it (the AdGuard DNS filter) carry them.

List text is untrusted, and a pattern is matched on every query the allow set
does not settle, so what one may cost is decided here and not by its author:

  - The engine is `core:text/regex`, a Pike VM: every thread steps in lock step
    over the name and threads on the same instruction merge, so a match costs at
    most the name's length times the program's size, however the pattern nests.
    There is no backtracking to blow up.
  - Every `{N}` is held to RE2's 1000, read from the text (`tokens_ok`).
  - Its compiler writes `e{N}` out N times and only checks the program's size
    once it is done, so `((a{1000}){1000}){1000}` would take gigabytes before it
    was refused. `program_bound` works out an upper bound on the size from the
    parsed tree first, and a pattern over `MAX_REGEX_PROGRAM` is never compiled.
  - A set holds `MAX_REGEX_TOTAL` between all its patterns, charged in program
    bytes and class entries (`regex_cost`): the bound on what one query can be
    made to spend here, charged on the thing the cost grows with rather than on
    a count of rules.
  - A match runs in a buffer on the caller's stack, sized from
    `MAX_REGEX_PROGRAM`, so it allocates nothing and is the same whichever
    thread model the query arrived on.
*/

// Pattern bytes between the slashes. Parsing recurses about once per byte, so
// this is also the stack the parse may take.
MAX_REGEX_PATTERN :: 1024
// The largest `{N}`, as RE2 has it.
MAX_REGEX_REPEAT :: 1000
// Compiled bytes of one pattern.
MAX_REGEX_PROGRAM :: 1024
/*
What all the patterns in one set may cost, in `regex_cost`'s units. The AdGuard
DNS filter's 22 block patterns come to 2.1 KiB and add a few microseconds to a
query; a list built to be slow can make a query spend about a millisecond here
at the budget, on a 253-character name.
*/
MAX_REGEX_TOTAL :: 8 * 1024
/*
The longest name a regex is matched against: a hostname's 253 characters.
Only a name spelling bytes as `\DDD` runs past it, to about 1000, and that
quadruples the scan and costs a slow list ten milliseconds a match, a name the
client chooses. A name that long is no hostname, so no rule meant it.
*/
MAX_REGEX_NAME :: 253

/*
Without the optimizer: its alternation-to-class rewrite merges a negated class
as a plain one, so `z|\W` matched `a`. A differential run against Go's regexp
over 120,000 random patterns found that and nothing else once it was off, and
the AdGuard DNS filter's patterns come to 32 bytes more without it. It also
makes the tree `program_bound` measures the one that is compiled.
*/
@(private)
REGEX_FLAGS :: regex.Flags{.No_Capture, .Case_Insensitive, .No_Optimization}

/*
What `regex.match` asks of its temporary allocator: the VM's two thread arrays
of at most one thread per opcode, its busy bitmap, and the one capture array the
starting thread is given. With `.No_Capture` nothing else is allocated. The
slack covers the arena's alignment.
*/
@(private)
MATCH_SCRATCH :: 2 * MAX_REGEX_PROGRAM * size_of(virtual_machine.Thread) + (MAX_REGEX_PROGRAM / 64 + 1) * size_of(u64) + 2 * size_of([2 * common.MAX_CAPTURE_GROUPS]int) + 256

Regex_Rule :: struct {
	// As written between the slashes, for `$badfilter` and duplicates.
	pattern:  string,
	re:       regex.Regular_Expression,
	// `regex_cost(re)`, what it holds of the set's budget.
	cost:     int,
	// `regex_shortcut(pattern)`: a name not holding it is not matched.
	shortcut: string,
}

/*
Add `/pattern/`, reporting whether the set now holds it.

A pattern this engine cannot run as AdGuard would, or that would cost more than
the limits above allow, is refused; one that no longer fits in the set's budget,
and every one after it, is counted in `regex_refused` so the loader can say so.
*/
regex_add :: proc(s: ^Set, pattern: string) -> (stored: bool) {
	key_buf: [MAX_REGEX_PATTERN + 2]u8
	if !regex_pattern_ok(pattern) || !tokens_ok(pattern) || regex_key(pattern, key_buf[:]) in s.cancelled {
		return false
	}
	if pattern in s.regex_held {
		return true
	}
	/*
	Once one pattern has not fitted, none after it is compiled: a list of a
	million patterns past the budget would otherwise hold the loader for as long
	as compiling each one to throw it away takes, about fifteen seconds for a
	40 MB list. It also makes which ones apply simple to say: the first ones
	loaded, up to the first that did not fit.
	*/
	if s.regex_refused > 0 {
		s.regex_refused += 1
		return false
	}

	if s.regex_scratch.curr_block == nil && virtual.arena_init_growing(&s.regex_scratch) != nil {
		return false
	}
	defer virtual.arena_free_all(&s.regex_scratch)
	temp := virtual.arena_allocator(&s.regex_scratch)

	{
		context.allocator = temp
		tree, err := parser.parse(pattern, REGEX_FLAGS)
		if err != nil || program_bound(tree) > MAX_REGEX_PROGRAM {
			return false
		}
	}
	// Compiled into the scratch arena first, so a refused program leaves
	// nothing behind in the set, then again into the set's own arena.
	trial, trial_err := regex.create(pattern, REGEX_FLAGS, temp, temp)
	if trial_err != nil || len(trial.program) > MAX_REGEX_PROGRAM {
		return false
	}
	if _, matches_empty := regex.match_and_allocate_capture(trial, "", temp, temp); matches_empty {
		// `/ads|/`, `/x*/`, `/^/`: matches every name it is tried on.
		return false
	}
	cost := regex_cost(trial)
	if s.regex_bytes + cost > MAX_REGEX_TOTAL {
		s.regex_refused += 1
		return false
	}
	re, err := regex.create(pattern, REGEX_FLAGS, s.allocator, temp)
	if err != nil {
		return false
	}
	shortcut := strings.clone(regex_shortcut(pattern, temp), s.allocator)
	kept := Regex_Rule{strings.clone(pattern, s.allocator), re, cost, shortcut}
	append(&s.regexes, kept)
	s.regex_held[kept.pattern] = {}
	s.regex_bytes += kept.cost
	s.count += 1
	return true
}

// Take back `/pattern/`, whether it is already in the set or arrives after this.
regex_cancel :: proc(s: ^Set, pattern: string) {
	// Nothing that fails this was ever added, and its key would not fit.
	if !regex_pattern_ok(pattern) {
		return
	}
	key_buf: [MAX_REGEX_PATTERN + 2]u8
	key := regex_key(pattern, key_buf[:])
	if key not_in s.cancelled {
		s.cancelled[strings.clone(key, s.allocator)] = {.Apex}
	}
	for r, i in s.regexes {
		if r.pattern == pattern {
			delete_key(&s.regex_held, pattern)
			s.regex_bytes -= r.cost
			s.count -= 1
			ordered_remove(&s.regexes, i)
			return
		}
	}
}

/*
What a pattern costs a match: its program bytes, and one more for every rune and
range a class instruction tests. A class is two bytes of program however many
entries it lists, and the VM tries them one by one on every character, so
charging bytes alone let a set of `[~~~...]` patterns make a query spend fifty
times what the budget allows.
*/
@(private)
regex_cost :: proc(re: regex.Regular_Expression) -> int {
	cost := len(re.program)
	iter := virtual_machine.Opcode_Iterator{re.program, 0}
	for op, pc in virtual_machine.iterate_opcodes(&iter) {
		#partial switch op {
		case .Rune_Class, .Rune_Class_Negated, .Wait_For_Rune_Class, .Wait_For_Rune_Class_Negated:
			data := re.class_data[re.program[pc + 1]]
			cost += len(data.runes) + len(data.ranges)
		}
	}
	return cost
}

// Whether any of the set's patterns matches `normalised`.
regex_lookup :: proc(s: ^Set, normalised: string) -> bool {
	if s == nil || len(s.regexes) == 0 || len(normalised) > MAX_REGEX_NAME {
		return false
	}
	// Left uninitialised: the arena zeroes what it hands out, and zeroing all
	// 33 KiB here would be a memset on every lookup.
	buf: [MATCH_SCRATCH]u8 = ---
	arena: mem.Arena
	mem.arena_init(&arena, buf[:])
	scratch := mem.arena_allocator(&arena)
	// The URL urlfilter builds for a name, which a rule's shortcut is looked for in.
	url_buf: [len(URL_PREFIX) + MAX_REGEX_NAME]u8
	copy(url_buf[:], URL_PREFIX)
	copy(url_buf[len(URL_PREFIX):], normalised)
	url := string(url_buf[:len(URL_PREFIX) + len(normalised)])
	for r in s.regexes {
		if !strings.contains(url, r.shortcut) {
			continue
		}
		mem.arena_free_all(&arena)
		_, matched := regex.match_and_allocate_capture(r.re, normalised, scratch, scratch)
		if matched {
			return true
		}
	}
	return false
}

@(private)
URL_PREFIX :: "http://"

/*
urlfilter's `findRegexpShortcut`: the longest run of the pattern holding no
regex metacharacter, once everything from the first `{`, `(` or `[` to the last
of its kind is dropped. `NetworkRule.Match` tries a rule only on a request whose
URL, `http://` and the name, holds that run (`matchShortcut`), so AdGuard Home
never matches `/ads|tracker/` against `ads.example` - the run is `tracker` - nor
`/\bads/` against anything, since `\b` leaves a `b` glued to `ads`. Without the
same test elodin would block names no AdGuard Home install ever has. None, as
there, for a pattern holding a `?` or a run of one character.
*/
@(private)
regex_shortcut :: proc(pattern: string, allocator: mem.Allocator) -> string {
	if strings.contains(pattern, "?") {
		return ""
	}
	p := strings.concatenate({"...", pattern}, allocator)
	p = strip_brackets(p, '{', '}', allocator)
	p = strip_brackets(p, '(', ')', allocator)
	p = strip_brackets(p, '[', ']', allocator)
	longest := ""
	start := 0
	for i := 0; i <= len(p); i += 1 {
		if i == len(p) || strings.index_byte(`\^$*+?.()|[]{}`, p[i]) >= 0 {
			if i - start > len(longest) {
				longest = p[start:i]
			}
			start = i + 1
		}
	}
	if len(longest) <= 1 {
		return ""
	}
	return strings.to_lower(longest, allocator)
}

/*
Go's `([^\\])\{.*[^\\]\}` replaced by `$1...`, as `findRegexpShortcut` does it:
from the first `{` after a byte other than `\` to the last `}` after one, at
least a byte apart. Being greedy, that match is the only one.
*/
@(private)
strip_brackets :: proc(p: string, open, close: u8, allocator: mem.Allocator) -> string {
	for s := 0; s + 1 < len(p); s += 1 {
		if p[s] == '\\' || p[s + 1] != open {
			continue
		}
		for j := len(p) - 1; j >= s + 3; j -= 1 {
			if p[j] == close && p[j - 1] != '\\' {
				return strings.concatenate({p[:s + 1], "...", p[j + 1:]}, allocator)
			}
		}
	}
	return p
}

/*
A pattern whose meaning here is what it means to AdGuard Home.

urlfilter compiles with Go's RE2 syntax, and `core:text/regex` accepts some of
it with another meaning. Where the two disagree the pattern is refused, never
run as Odin reads it, so a list cannot block a name AdGuard Home would not:

  - An escaped letter or digit other than `\d \D \w \W \s \S \b \B`, which mean
    the same in both. Odin reads the rest as the letter itself: `\1` is a `1`
    (RE2 refuses backreferences), `\x41` is `x41`, `\A` and `\z` are not
    anchors. An escaped punctuation mark is that mark in both.
  - `[:`, which opens a POSIX class like `[[:alpha:]]` in RE2 and is only
    characters to Odin.
  - `#`, which Odin's tokenizer takes as the start of a comment outside a
    group, dropping the rest of the pattern: the AdGuard DNS filter's
    `@@/\.(gif|jpe?g|png|webp)#.../` would allow every name holding `.png`.
    A name never holds a `#`, so RE2 can never match one either.
  - A byte outside printable ASCII: a query name spells one as `\DDD`, so the
    pattern could never match it there, and the ASCII engine stores a pattern
    rune as its low byte, which would make `š` (U+0161) match an `a`.

Empty is refused too, because urlfilter would match every name with it, which no
list author means by `//`; `regex_add` refuses any other pattern that matches
the empty string, such as `ads|` or `x*`, for the same reason: it matches
every name its shortcut lets it be tried on, and every name when it has none.
AdGuard Home keeps them; a typo is the likelier author.
*/
@(private)
regex_pattern_ok :: proc(pattern: string) -> bool {
	if len(pattern) == 0 || len(pattern) > MAX_REGEX_PATTERN || strings.contains(pattern, "[:") || strings.contains(pattern, "#") {
		return false
	}
	escaped := false
	for c in transmute([]u8)pattern {
		if c < 0x20 || c >= 0x7f {
			return false
		}
		if escaped {
			escaped = false
			alnum := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if alnum && strings.index_byte("dDwWsSbB", c) < 0 {
				return false
			}
		} else if c == '\\' {
			escaped = true
		}
	}
	// A trailing `\` escapes nothing.
	return !escaped
}

/*
What has to be read from the pattern's own tokens, because the parsed tree
no longer shows it.

  - Every `{N,M}` count bare digits with no leading zero, as RE2 reads one, and
    at most `MAX_REGEX_REPEAT`. The parser reads a count as
    a u64 and stores it as an int, so `{0,18446744073709551615}` arrives as
    `{0,}` and cannot be told from it, and a pair past `max(i64)` arrives as a
    shape the compiler has no case for and panics on. Past 1000 RE2 - and so
    urlfilter - refuses the pattern too, so AdGuard Home would never match the
    rule either.
  - No `)` without its `(`: Odin's parser takes `ads)` as `ads`, RE2 refuses it.
  - No class range running backwards, `[a-Z]`: RE2 refuses it, and Odin's case
    folding turns it into `[a-z]`.
*/
@(private)
tokens_ok :: proc(pattern: string) -> bool {
	t: tokenizer.Tokenizer
	tokenizer.init(&t, pattern, REGEX_FLAGS)
	depth := 0
	for {
		tok := tokenizer.scan(&t)
		#partial switch tok.kind {
		case .EOF, .Invalid:
			// Whatever is left is the parser's to refuse.
			return true
		case .Open_Paren, .Open_Paren_Non_Capture:
			depth += 1
		case .Close_Paren:
			depth -= 1
			if depth < 0 {
				return false
			}
		case .Rune_Class:
			if !class_ranges_ok(tok.text) {
				return false
			}
		case .Repeat_N:
			// RE2 reads `{,M}` as the characters; Odin as "up to M".
			if strings.has_prefix(tok.text, ",") {
				return false
			}
			counts := tok.text
			for count in strings.split_iterator(&counts, ",") {
				if count == "" {
					continue
				}
				// RE2 takes a count only as bare digits without a leading
				// zero, and `{02}`, `{+2}` or `{1_0}` as characters; Odin's
				// strconv reads all three as numbers.
				if strings.trim_left(count, "0123456789") != "" || (len(count) > 1 && count[0] == '0') {
					return false
				}
				n, ok := strconv.parse_u64_of_base(count, 10)
				if !ok || n > MAX_REGEX_REPEAT {
					return false
				}
			}
		}
	}
}

/*
The ranges in a class's text, read as Go's `parseClass` reads them: `lo-hi`
with `hi` not below `lo`. `regex_pattern_ok` has already held an escaped letter
to `\d \D \w \W \s \S` and `\b \B`, which RE2 refuses inside a class and Odin
reads as the letter.

Odin's parser makes a range of any `-` not at the end while it holds a single
rune, popping the last one it pushed, where RE2 starts a range only from the
element just before. The two agree when that element is a literal, which is the
last rune pushed, and when Odin holds nothing, where both read the `-` as
itself (`[a-c-e]`). After a range or a class escape with a literal still held
(`[ab-c-e]`, `[a\d-z]`) they do not, and how many runes a class escape leaves
held is Odin's business, so after one a `-` that is not a range's is refused
(`[\d-z]`). Odin also ends a range at a `\` and reads what it escapes on its
own, so a range may not end in an escape: `[+-\.]` would hold the digits, and
`[[-\\]` trips an assertion in its parser.

An empty class is refused: Odin reads `[]a]` and `[^]a]` as the empty class then
`a]`, where RE2 reads a class holding `]` and `a`.
*/
@(private)
class_ranges_ok :: proc(class: string) -> bool {
	text := strings.trim_prefix(class, "^")
	if text == "" {
		return false
	}
	// The literal last read, -1 after a class escape, -2 at the start, -3
	// after a range, -4 after a literal `-`.
	prev := -2
	// Literals Odin's parser holds for a `-` to pop, and whether a class
	// escape has left it holding some number of its own.
	held := 0
	after_escape := false
	for i := 0; i < len(text); i += 1 {
		c := int(text[i])
		if c == '-' && i + 1 < len(text) && prev != -2 {
			if prev < 0 {
				if held > 0 || after_escape {
					return false
				}
				// Both read it as itself.
				held, prev = 1, -4
				continue
			}
			i += 1
			if text[i] == '\\' {
				return false
			}
			hi := int(text[i])
			if hi < prev || !range_folds_alike(prev, hi) {
				return false
			}
			held -= 1
			prev = -3
			continue
		}
		if c == '\\' && i + 1 < len(text) {
			i += 1
			switch text[i] {
			case 'b', 'B':
				return false
			case 'd', 'D', 'w', 'W', 's', 'S':
				after_escape = true
				prev = -1
				continue
			}
			c = int(text[i])
		} else if c == '-' {
			// A literal `-` Odin never starts a range from, where RE2 does:
			// `[--/]` is `-` to `/` in RE2 and `-`, `-`, `/` in Odin.
			held += 1
			prev = -4
			continue
		}
		held += 1
		prev = c
	}
	return true
}

/*
Whether Odin's case folding of the range `lo-hi` matches the same lowercased
names as RE2's `(?i)`, which folds every letter inside it. Odin folds a range
only when both ends are letters, and then folds the ends alone: `[A-z]` becomes
`[a-zA-Z]`, losing `_`, and `[.-a]` or `[0-Z]` are not folded at all, so a name's
`b` misses a range that holds `B`.
*/
@(private)
range_folds_alike :: proc(lo, hi: int) -> bool {
	if hi < 'A' || lo > 'Z' {
		// No capital in it, and the name holds none.
		return true
	}
	lo_letter := (lo >= 'A' && lo <= 'Z') || (lo >= 'a' && lo <= 'z')
	hi_letter := (hi >= 'A' && hi <= 'Z') || (hi >= 'a' && hi <= 'z')
	if lo_letter && hi_letter {
		// Folded end by end, which is right only when both ends are capitals.
		return hi <= 'Z'
	}
	// Not folded: every capital's lower case has to be in the range too.
	return min(hi, 'Z') + ('a' - 'A') <= hi
}

// Keyed with its slashes in `cancelled`, beside names that can hold no slash.
// `pattern` has passed `regex_pattern_ok`, so it fits.
@(private)
regex_key :: proc(pattern: string, buf: []u8) -> string {
	buf[0] = '/'
	copy(buf[1:], pattern)
	buf[len(pattern) + 1] = '/'
	return string(buf[:len(pattern) + 2])
}

/*
An upper bound on the bytes `compiler.generate_code` writes for `node`, from the
sizes it emits: a byte or a class is two, a split five, a jump three, a repeat
its inner code once per count. Saturates past the limit, so a count near the
top of `u64` cannot overflow it. `compile` adds a `.*?` prefix, a wait and the
final match on top, which the constant covers.
*/
@(private)
program_bound :: proc(node: parser.Node) -> int {
	return min(node_bound(node) + 16, MAX_REGEX_PROGRAM + 1)
}

@(private)
node_bound :: proc(node: parser.Node) -> int {
	CAP :: MAX_REGEX_PROGRAM + 1
	sat :: proc(n: int) -> int {return min(n, CAP)}
	switch n in node {
	case nil:
		return 0
	case ^parser.Node_Rune:
		return 5
	case ^parser.Node_Rune_Class, ^parser.Node_Anchor:
		return 2
	case ^parser.Node_Wildcard, ^parser.Node_Word_Boundary, ^parser.Node_Match_All_And_Escape:
		return 1
	case ^parser.Node_Group:
		return sat(node_bound(n.inner) + 4)
	case ^parser.Node_Concatenation:
		total := 0
		for sub in n.nodes {
			total = sat(total + node_bound(sub))
		}
		return total
	case ^parser.Node_Alternation:
		return sat(node_bound(n.left) + node_bound(n.right) + 8)
	case ^parser.Node_Repeat_Zero:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 8)
	case ^parser.Node_Repeat_Zero_Non_Greedy:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 8)
	case ^parser.Node_Repeat_One:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 5)
	case ^parser.Node_Repeat_One_Non_Greedy:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 5)
	case ^parser.Node_Optional:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 5)
	case ^parser.Node_Optional_Non_Greedy:
		return CAP if is_repeat(n.inner) else sat(node_bound(n.inner) + 5)
	case ^parser.Node_Repeat_N:
		if is_repeat(n.inner) {
			return CAP
		}
		// `tokens_ok` has held every count to 0..=1000, so the -1s here
		// are the parser's "no bound", and each shape is one the compiler has.
		lo, hi := n.lower, n.upper
		// e{N} is e N times; e{,M} is `e?` M times; e{N,} is e N times and
		// then `e*`; e{N,M} is e N times and then `e?` M-N times.
		inner := node_bound(n.inner)
		switch {
		case lo == hi:
			return sat(inner * lo)
		case lo == -1:
			return sat((inner + 5) * hi)
		case hi == -1:
			return sat(inner * (lo + 1) + 8)
		}
		return sat(inner * lo + (inner + 5) * (hi - lo))
	}
	return CAP
}

/*
A repeat applied straight to a repeat, `a**` or `a{2}{3}`: RE2 refuses it as an
invalid nested repetition, where Odin multiplies the two. Through a group,
`(a*)*`, both accept it.
*/
@(private)
is_repeat :: proc(node: parser.Node) -> bool {
	#partial switch _ in node {
	case ^parser.Node_Repeat_Zero, ^parser.Node_Repeat_Zero_Non_Greedy, ^parser.Node_Repeat_One, ^parser.Node_Repeat_One_Non_Greedy, ^parser.Node_Repeat_N, ^parser.Node_Optional, ^parser.Node_Optional_Non_Greedy:
		return true
	}
	return false
}
