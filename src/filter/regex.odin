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
it (the AdGuard DNS filter, HaGeZi, OISD's adblock variant) carry them.

List text is untrusted, and a pattern is matched on every query the hash sets do
not settle, so what one may cost is decided here and not by its author:

  - The engine is `core:text/regex`, a Pike VM: every thread steps in lock step
    over the name and threads on the same instruction merge, so a match costs at
    most the name's length times the program's size, however the pattern nests.
    There is no backtracking to blow up.
  - Every `{N}` is held to RE2's 1000, read from the text (`tokens_ok`).
  - Its compiler writes `e{N}` out N times and only checks the program's size
    once it is done, so `((a{1000}){1000}){1000}` would take gigabytes before it
    was refused. `program_bound` works out an upper bound on the size from the
    parsed tree first, and a pattern over `MAX_REGEX_PROGRAM` is never compiled.
  - A set holds `MAX_REGEX_TOTAL` bytes of program between all its patterns:
    the bound on what one query can be made to spend here, charged on the thing
    the cost grows with rather than on a count of rules.
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
Compiled bytes of all the patterns in one set. The AdGuard DNS filter's 22
block patterns come to 1.5 KiB and add a few microseconds to a query; a list
built to be slow can make a query spend about a millisecond here at the budget,
on a 253-character name.
*/
MAX_REGEX_TOTAL :: 8 * 1024
/*
The longest name a regex is matched against: a hostname's 253 characters.
Only a name spelling bytes as `\DDD` runs past it, to about 1000, and that
quadruples the scan and costs a slow list ten milliseconds a match, a name the
client chooses. A name that long is no hostname, so no rule meant it.
*/
MAX_REGEX_NAME :: 253

@(private)
REGEX_FLAGS :: regex.Flags{.No_Capture, .Case_Insensitive}

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
	pattern: string,
	re:      regex.Regular_Expression,
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
	for r in s.regexes {
		if r.pattern == pattern {
			return true
		}
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

	scratch: virtual.Arena
	if virtual.arena_init_growing(&scratch) != nil {
		return false
	}
	defer virtual.arena_destroy(&scratch)
	temp := virtual.arena_allocator(&scratch)

	{
		context.allocator = temp
		tree, err := parser.parse(pattern, REGEX_FLAGS)
		if err != nil || program_bound(tree) > MAX_REGEX_PROGRAM {
			return false
		}
	}
	// Compiled into the scratch arena first, so a refused program leaves
	// nothing behind in the set, then again into the set's own arena.
	if trial, err := regex.create(pattern, REGEX_FLAGS, temp, temp); err != nil || len(trial.program) > MAX_REGEX_PROGRAM {
		return false
	} else if s.regex_bytes + len(trial.program) > MAX_REGEX_TOTAL {
		s.regex_refused += 1
		return false
	}
	re, err := regex.create(pattern, REGEX_FLAGS, s.allocator, temp)
	if err != nil {
		return false
	}
	kept := Regex_Rule{strings.clone(pattern, s.allocator), re}
	append(&s.regexes, kept)
	s.regex_bytes += len(re.program)
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
			s.regex_bytes -= len(r.re.program)
			s.count -= 1
			ordered_remove(&s.regexes, i)
			return
		}
	}
}

// Whether any of the set's patterns matches `normalised`.
regex_lookup :: proc(s: ^Set, normalised: string) -> bool {
	if s == nil || len(s.regexes) == 0 || len(normalised) > MAX_REGEX_NAME {
		return false
	}
	buf: [MATCH_SCRATCH]u8
	arena: mem.Arena
	mem.arena_init(&arena, buf[:])
	scratch := mem.arena_allocator(&arena)
	for r in s.regexes {
		mem.arena_free_all(&arena)
		_, matched := regex.match_and_allocate_capture(r.re, normalised, scratch, scratch)
		if matched {
			return true
		}
	}
	return false
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
list author means by `//`.
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

  - Every `{N,M}` count at most `MAX_REGEX_REPEAT`. The parser reads a count as
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
with `hi` not below `lo`. A `-` next to `\d`, `\w` or `\s` and not at the end is
refused too: Odin takes the rune before the escape as a range's start there,
where RE2 reads the `-` as itself or refuses the pattern. `regex_pattern_ok`
has already held an escaped letter to those classes and `\b \B`.
*/
@(private)
class_ranges_ok :: proc(class: string) -> bool {
	text := strings.trim_prefix(class, "^")
	// The literal last read, -1 after a class escape, -2 at the start or
	// after a range.
	prev := -2
	for i := 0; i < len(text); i += 1 {
		c := int(text[i])
		if c == '-' && prev != -2 && i + 1 < len(text) {
			if prev == -1 {
				return false
			}
			i += 1
			hi := int(text[i])
			if hi == '\\' && i + 1 < len(text) {
				i += 1
				if strings.index_byte("dDwWsS", text[i]) >= 0 {
					return false
				}
				hi = int(text[i])
			}
			if hi < prev {
				return false
			}
			prev = -2
			continue
		}
		if c == '\\' && i + 1 < len(text) {
			i += 1
			c = -1 if strings.index_byte("dDwWsS", text[i]) >= 0 else int(text[i])
		}
		prev = c
	}
	return true
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
