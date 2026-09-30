package filter

import "core:mem"
import "core:mem/virtual"
import "core:slice"
import "core:strings"
import "core:text/regex"
import "core:text/regex/common"
import "core:text/regex/compiler"
import "core:text/regex/parser"
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
  - Every `{N}` is held to RE2's 1000, and counts nested in one another to
    1000 between them (`re2_repeat`).
  - Its compiler writes `e{N}` out N times and only checks the program's size
    once it is done, so a long `(...){1000}` would take a megabyte before it
    was refused. `program_bound` works out an upper bound on the size from the
    tree first, and a pattern over `MAX_REGEX_PROGRAM` is never compiled.
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
Only a name spelling bytes out - as `\DDD`, or `\(` and the like in the form
`regex_subject` spells - runs past it, to about 1000, and that
quadruples the scan and costs a slow list ten milliseconds a match, a name the
client chooses. A name that long is no hostname, so no rule meant it.
*/
MAX_REGEX_NAME :: 253

/*
The tree `re2_parse` builds goes to the compiler as it is: Odin's optimizer,
which `regex.create` would run, merged a negated class as a plain one in its
alternation-to-class rewrite, so `z|\W` matched `a`. It also makes the tree
`program_bound` measures the one that is compiled. Case is folded by
`re2_parse`, not by a flag, and `.No_Optimization` keeps `compiler.compile`
from threading jumps too, so the program is the tree as it was built.
*/
@(private)
REGEX_FLAGS :: regex.Flags{.No_Capture, .No_Optimization}

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

A pattern outside the RE2 subset `re2_parse` reads, or that would cost more than
the limits above allow, is refused; one that no longer fits in the set's budget,
and every one after it, is counted in `regex_refused` so the loader can say so.
*/
regex_add :: proc(s: ^Set, pattern: string) -> (stored: bool) {
	key_buf: [MAX_REGEX_PATTERN + 2]u8
	// Empty is refused too: urlfilter would match every name with it, which
	// no list author means by `//`.
	if len(pattern) == 0 || len(pattern) > MAX_REGEX_PATTERN || regex_key(pattern, key_buf[:]) in s.cancelled {
		return false
	}
	if pattern in s.regex_held {
		return true
	}
	if s.regex_scratch.curr_block == nil && virtual.arena_init_growing(&s.regex_scratch) != nil {
		return false
	}
	defer virtual.arena_free_all(&s.regex_scratch)
	temp := virtual.arena_allocator(&s.regex_scratch)

	tree: parser.Node
	{
		context.allocator = temp
		parsed: bool
		tree, parsed = re2_parse(pattern)
		if !parsed {
			return false
		}
	}
	/*
	Once one pattern has not fitted, none after it is compiled: a list of a
	million patterns past the budget would otherwise hold the loader for as long
	as compiling each one to throw it away takes, about fifteen seconds for a
	40 MB list. It also makes which ones apply simple to say: the first ones
	loaded, up to the first that did not fit. Parsing is one pass over the
	pattern, and keeps what is not RE2 out of the count.
	*/
	if s.regex_refused > 0 {
		s.regex_refused += 1
		return false
	}
	if program_bound(tree) > MAX_REGEX_PROGRAM {
		return false
	}
	// Compiled into the scratch arena, so a refused program leaves nothing
	// behind in the set, and copied into the set's own arena once it is kept.
	trial, compiled := regex_compile(tree, temp)
	if !compiled || len(trial.program) > MAX_REGEX_PROGRAM {
		return false
	}
	if _, matches_empty := regex.match_and_allocate_capture(trial, "", temp, temp); matches_empty {
		// `/ads|/`, `/x*/`, `/^/`: matches every name its shortcut lets it be
		// tried on, and every name when it has none. AdGuard Home keeps them;
		// a typo is the likelier author.
		return false
	}
	cost := regex_cost(trial)
	if s.regex_bytes + cost > MAX_REGEX_TOTAL {
		s.regex_refused += 1
		return false
	}
	re := regex_copy(trial, s.allocator)
	shortcut := strings.clone(regex_shortcut(pattern, temp), s.allocator)
	kept := Regex_Rule{strings.clone(pattern, s.allocator), re, cost, shortcut}
	append(&s.regexes, kept)
	s.regex_held[kept.pattern] = {}
	s.regex_bytes += kept.cost
	s.count += 1
	return true
}

/*
What `regex.create` does after parsing, for the tree `re2_parse` builds:
compiled with the scratch allocator, which also holds what is returned.
*/
@(private)
regex_compile :: proc(tree: parser.Node, temp: mem.Allocator) -> (re: regex.Regular_Expression, ok: bool) {
	context.allocator = temp
	program, classes, err := compiler.compile(tree, REGEX_FLAGS)
	if err != nil {
		return
	}
	re.flags = REGEX_FLAGS
	re.program = program[:]
	re.class_data = make([]virtual_machine.Rune_Class_Data, len(classes))
	for c, i in classes {
		re.class_data[i] = {c.runes[:], c.ranges[:]}
	}
	return re, true
}

// `re`, copied into `allocator`, packed as `regex.create` packs it.
@(private)
regex_copy :: proc(re: regex.Regular_Expression, allocator: mem.Allocator) -> (out: regex.Regular_Expression) {
	context.allocator = allocator
	out.flags = re.flags
	out.program = slice.clone(re.program)
	if len(re.class_data) > 0 {
		out.class_data = make([]virtual_machine.Rune_Class_Data, len(re.class_data))
	}
	for c, i in re.class_data {
		if len(c.runes) > 0 {
			out.class_data[i].runes = slice.clone(c.runes)
		}
		if len(c.ranges) > 0 {
			out.class_data[i].ranges = slice.clone(c.ranges)
		}
	}
	return
}

// Take back `/pattern/`, whether it is already in the set or arrives after this.
regex_cancel :: proc(s: ^Set, pattern: string) {
	// Nothing that fails these was ever added, and a longer key would not
	// fit. A cancel that can match nothing is not counted as one, so the
	// operator's own is warned of as adding nothing.
	if len(pattern) == 0 || len(pattern) > MAX_REGEX_PATTERN || !regex_parses(s, pattern) {
		return
	}
	s.cancels += 1
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

// Whether `re2_parse` reads `pattern`, parsed in the set's scratch arena.
@(private)
regex_parses :: proc(s: ^Set, pattern: string) -> bool {
	if s.regex_scratch.curr_block == nil && virtual.arena_init_growing(&s.regex_scratch) != nil {
		return false
	}
	defer virtual.arena_free_all(&s.regex_scratch)
	context.allocator = virtual.arena_allocator(&s.regex_scratch)
	_, parsed := re2_parse(pattern)
	return parsed
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
	if s == nil || len(s.regexes) == 0 {
		return false
	}
	subject_buf: [MAX_REGEX_NAME]u8
	subject, fits := regex_subject(normalised, subject_buf[:])
	if !fits {
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
	copy(url_buf[len(URL_PREFIX):], subject)
	url := string(url_buf[:len(URL_PREFIX) + len(subject)])
	for r in s.regexes {
		if !strings.contains(url, r.shortcut) {
			continue
		}
		mem.arena_free_all(&arena)
		_, matched := regex.match_and_allocate_capture(r.re, subject, scratch, scratch)
		if matched {
			return true
		}
	}
	return false
}

/*
The name as AdGuard Home hands it to urlfilter, in miekg/dns's presentation:
that puts a `\` before `. \ space ' @ ; ( ) "` in a label, where `dns` writes
the first three as `\DDD` and the rest bare. Every other byte is written alike
by both. Without this `/a\(b/` would miss the name `a(b` that it blocks there,
and `/\\/` block every name with a byte spelled `\DDD`. False when it does not
fit in `buf`.
*/
@(private)
regex_subject :: proc(name: string, buf: []u8) -> (subject: string, fits: bool) {
	n := 0
	put :: proc(buf: []u8, n: ^int, bytes: ..u8) -> bool {
		if n^ + len(bytes) > len(buf) {
			return false
		}
		copy(buf[n^:], bytes)
		n^ += len(bytes)
		return true
	}
	for i := 0; i < len(name); i += 1 {
		c := name[i]
		switch c {
		case '\\':
			if i + 3 < len(name) && is_digit(name[i + 1]) && is_digit(name[i + 2]) && is_digit(name[i + 3]) {
				b := int(name[i + 1] - '0') * 100 + int(name[i + 2] - '0') * 10 + int(name[i + 3] - '0')
				if b == '.' || b == '\\' || b == ' ' {
					put(buf, &n, '\\', u8(b)) or_return
				} else {
					put(buf, &n, ..transmute([]u8)name[i:i + 4]) or_return
				}
				i += 3
				continue
			}
		case '\'', '@', ';', '(', ')', '"':
			put(buf, &n, '\\') or_return
		}
		put(buf, &n, c) or_return
	}
	return string(buf[:n]), true
}

@(private)
is_digit :: proc(c: u8) -> bool {
	return c >= '0' && c <= '9'
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

// Keyed with its slashes in `cancelled`, beside names that can hold no slash.
// `pattern` is at most `MAX_REGEX_PATTERN` long, so it fits.
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
its inner code once per count. Saturates past the limit. `compile` adds a `.*?` prefix, a wait and the
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
	// The shapes `re2_parse` makes; it makes no other.
	#partial switch n in node {
	case nil:
		return 0
	case ^parser.Node_Rune:
		return 5
	case ^parser.Node_Rune_Class, ^parser.Node_Anchor:
		return 2
	case ^parser.Node_Wildcard, ^parser.Node_Word_Boundary:
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
		return sat(node_bound(n.inner) + 8)
	case ^parser.Node_Repeat_One:
		return sat(node_bound(n.inner) + 5)
	case ^parser.Node_Optional:
		return sat(node_bound(n.inner) + 5)
	case ^parser.Node_Repeat_N:
		// `re2_repeat` has held every count to 0..=1000 and `lo` to `hi`, -1 for
		// none, so each shape is one the compiler has.
		lo, hi := n.lower, n.upper
		// e{N} is e N times; e{N,} is e N times and then `e*`; e{N,M} is e N
		// times and then `e?` M-N times.
		inner := node_bound(n.inner)
		switch {
		case lo == hi:
			return sat(inner * lo)
		case hi == -1:
			return sat(inner * (lo + 1) + 8)
		}
		return sat(inner * lo + (inner + 5) * (hi - lo))
	}
	return CAP
}
