package filter

import "core:text/regex/parser"

/*
The RE2 syntax a `/re/` rule may use, read here into the tree Odin's compiler
takes. `core:text/regex`'s own tokenizer and parser never see list text: each
disagreement with RE2 found in them - `#` opening a comment, `ads)` read as
`ads`, `[]a]` as an empty class, `{02}` as a count, ranges folded or popped
otherwise - was a pattern that meant one thing to AdGuard Home and another here,
and a denylist of the known ones leaves every unknown one loaded.

What is read follows Go's `regexp/syntax` (`parse.go`) as urlfilter compiles a
rule, `(?i)` and the pattern with the Perl flags. Anything else is refused:

  - literals, and `\` before punctuation for the mark itself;
  - `.`, `^`, `$`, and `\b \B` outside a class;
  - `\d \D \w \W \s \S`, which RE2 holds to ASCII;
  - classes of literals, ranges and those six, `]` first as itself, `[:` refused;
  - groups, `(?:...)`, and `|`;
  - `* + ?` and `{n}`, `{n,}`, `{n,m}`, lazy or not: a match is a yes or a no,
    so which way a repeat leans does not change it. A count is bare digits with
    no leading zero, at most 1000, and nested counts multiply to 1000 at most
    (`repeatIsValid`); a `{` that is no count is itself, as in RE2.

A repeat of a repeat (`a**`, `a{2}{3}`) and a repeat with nothing before it are
refused, as RE2 refuses them. Flags, named groups, `\x`, `\p`, `\A`, `\z`,
backreferences and octal are outside the subset.

A name reaching a regex is lowercased by `normalise` and holds only printable
ASCII, `dns` spelling every other byte `\DDD`. So `(?i)` is a letter read as its
lower case and a class folded to hold both, and a class is only its ASCII
members: `.` needs no `\n` kept out, and `[^a]` no runes past `~` put in.
*/

@(private)
Re2_Parser :: struct {
	s: string,
	i: int,
}

// The ASCII bytes a class holds.
@(private)
Ascii_Set :: bit_set[0 ..< 128]

// Allocates the tree in `context.allocator`.
@(private)
re2_parse :: proc(pattern: string) -> (tree: parser.Node, ok: bool) {
	for c in transmute([]u8)pattern {
		if c < 0x20 || c >= 0x7f {
			return nil, false
		}
	}
	p := Re2_Parser{pattern, 0}
	tree = re2_alternation(&p) or_return
	// Short of the end only at a `)` with no `(`, which RE2 refuses.
	return tree, p.i == len(p.s)
}

@(private)
re2_alternation :: proc(p: ^Re2_Parser) -> (node: parser.Node, ok: bool) {
	node = re2_concatenation(p) or_return
	for p.i < len(p.s) && p.s[p.i] == '|' {
		p.i += 1
		right := re2_concatenation(p) or_return
		node = new_clone(parser.Node_Alternation{node, right})
	}
	return node, true
}

@(private)
re2_concatenation :: proc(p: ^Re2_Parser) -> (node: parser.Node, ok: bool) {
	nodes: [dynamic]parser.Node
	for p.i < len(p.s) && p.s[p.i] != '|' && p.s[p.i] != ')' {
		atom := re2_atom(p) or_return
		append(&nodes, re2_repeat(p, atom) or_return)
	}
	switch len(nodes) {
	case 0:
		return nil, true
	case 1:
		return nodes[0], true
	}
	return new_clone(parser.Node_Concatenation{nodes}), true
}

@(private)
re2_atom :: proc(p: ^Re2_Parser) -> (node: parser.Node, ok: bool) {
	c := p.s[p.i]
	p.i += 1
	switch c {
	case '(':
		if p.i < len(p.s) && p.s[p.i] == '?' {
			if p.i + 1 == len(p.s) || p.s[p.i + 1] != ':' {
				return nil, false
			}
			p.i += 2
		}
		inner := re2_alternation(p) or_return
		if p.i == len(p.s) {
			return nil, false
		}
		p.i += 1
		return new_clone(parser.Node_Group{inner = inner}), true
	case '[':
		return re2_class(p)
	case '.':
		return new(parser.Node_Wildcard), true
	case '^', '$':
		return new_clone(parser.Node_Anchor{start = c == '^'}), true
	case '*', '+', '?':
		// Nothing to repeat.
		return nil, false
	case '{':
		if _, _, _, is_count := re2_count(p.s[p.i - 1:]); is_count {
			return nil, false
		}
	case '\\':
		if p.i == len(p.s) {
			return nil, false
		}
		e := p.s[p.i]
		p.i += 1
		if e == 'b' || e == 'B' {
			return new_clone(parser.Node_Word_Boundary{non_word = e == 'B'}), true
		}
		if set, is_perl := re2_perl_class(e); is_perl {
			return re2_class_node(set), true
		}
		if is_alnum(e) {
			return nil, false
		}
		c = e
	}
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	return new_clone(parser.Node_Rune{rune(c)}), true
}

// The repeat, if any, that follows `atom`.
@(private)
re2_repeat :: proc(p: ^Re2_Parser, atom: parser.Node) -> (node: parser.Node, ok: bool) {
	if p.i == len(p.s) {
		return atom, true
	}
	switch p.s[p.i] {
	case '*':
		node = new_clone(parser.Node_Repeat_Zero{atom})
		p.i += 1
	case '+':
		node = new_clone(parser.Node_Repeat_One{atom})
		p.i += 1
	case '?':
		node = new_clone(parser.Node_Optional{atom})
		p.i += 1
	case '{':
		lo, hi, n, is_count := re2_count(p.s[p.i:])
		if !is_count {
			return atom, true
		}
		if lo > MAX_REGEX_REPEAT || hi > MAX_REGEX_REPEAT || (hi >= 0 && lo > hi) {
			return nil, false
		}
		node = new_clone(parser.Node_Repeat_N{inner = atom, lower = lo, upper = hi})
		p.i += n
		if (lo >= 2 || hi >= 2) && !re2_repeat_valid(node, MAX_REGEX_REPEAT) {
			return nil, false
		}
	case:
		return atom, true
	}
	if p.i < len(p.s) && p.s[p.i] == '?' {
		p.i += 1
	}
	if p.i < len(p.s) {
		switch p.s[p.i] {
		case '*', '+', '?':
			return nil, false
		case '{':
			if _, _, _, is_count := re2_count(p.s[p.i:]); is_count {
				return nil, false
			}
		}
	}
	return node, true
}

/*
Go's `parseRepeat` on `s`, which starts at a `{`: whether it is a count, and
its bounds, `hi` -1 for none. `parseInt` takes bare digits with no leading zero;
a count past 1000 is only checked for being past it.
*/
@(private)
re2_count :: proc(s: string) -> (lo, hi, n: int, ok: bool) {
	i := 1
	number :: proc(s: string, i: ^int) -> (v: int, ok: bool) {
		start := i^
		for i^ < len(s) && s[i^] >= '0' && s[i^] <= '9' {
			v = min(v * 10 + int(s[i^] - '0'), MAX_REGEX_REPEAT + 1)
			i^ += 1
		}
		return v, i^ > start && (i^ - start == 1 || s[start] != '0')
	}
	lo = number(s, &i) or_return
	hi = lo
	if i < len(s) && s[i] == ',' {
		i += 1
		hi = -1
		if i < len(s) && s[i] != '}' {
			hi = number(s, &i) or_return
		}
	}
	if i == len(s) || s[i] != '}' {
		return
	}
	return lo, hi, i + 1, true
}

// Go's `repeatIsValid`: `{}` counts nested inside one another come to `n` at most.
@(private)
re2_repeat_valid :: proc(node: parser.Node, n: int) -> bool {
	n := n
	// The shapes `re2_parse` makes; a leaf holds no count.
	#partial switch v in node {
	case ^parser.Node_Repeat_N:
		m := v.upper if v.upper >= 0 else v.lower
		if v.upper == 0 {
			return true
		}
		if m > n {
			return false
		}
		if m > 0 {
			n /= m
		}
		return re2_repeat_valid(v.inner, n)
	case ^parser.Node_Repeat_Zero:
		return re2_repeat_valid(v.inner, n)
	case ^parser.Node_Repeat_One:
		return re2_repeat_valid(v.inner, n)
	case ^parser.Node_Optional:
		return re2_repeat_valid(v.inner, n)
	case ^parser.Node_Group:
		return re2_repeat_valid(v.inner, n)
	case ^parser.Node_Alternation:
		return re2_repeat_valid(v.left, n) && re2_repeat_valid(v.right, n)
	case ^parser.Node_Concatenation:
		for sub in v.nodes {
			if !re2_repeat_valid(sub, n) {
				return false
			}
		}
	}
	return true
}

// Go's `parseClass`, after the `[`.
@(private)
re2_class :: proc(p: ^Re2_Parser) -> (node: parser.Node, ok: bool) {
	negated := p.i < len(p.s) && p.s[p.i] == '^'
	if negated {
		p.i += 1
	}
	set: Ascii_Set
	for first := true; p.i == len(p.s) || p.s[p.i] != ']' || first; first = false {
		if p.i == len(p.s) || (p.s[p.i] == '[' && p.i + 1 < len(p.s) && p.s[p.i + 1] == ':') {
			return nil, false
		}
		if p.s[p.i] == '\\' && p.i + 1 < len(p.s) {
			if perl, is_perl := re2_perl_class(p.s[p.i + 1]); is_perl {
				set += perl
				p.i += 2
				continue
			}
		}
		lo := re2_class_char(p) or_return
		hi := lo
		// `[a-]` is `a` and `-`.
		if p.i + 1 < len(p.s) && p.s[p.i] == '-' && p.s[p.i + 1] != ']' {
			p.i += 1
			hi = re2_class_char(p) or_return
			if hi < lo {
				return nil, false
			}
		}
		for c in lo ..= hi {
			set += {int(c)}
		}
	}
	p.i += 1
	// `(?i)` folds before `^` negates, so `[^A]` holds no `a`.
	for c in int('a') ..= int('z') {
		if c in set || c - 32 in set {
			set += {c, c - 32}
		}
	}
	return re2_class_node(~set if negated else set), true
}

// A class's literal: a byte, or `\` and a punctuation mark.
@(private)
re2_class_char :: proc(p: ^Re2_Parser) -> (c: u8, ok: bool) {
	c = p.s[p.i]
	p.i += 1
	if c != '\\' {
		return c, true
	}
	if p.i == len(p.s) || is_alnum(p.s[p.i]) {
		return 0, false
	}
	p.i += 1
	return p.s[p.i - 1], true
}

// RE2's Perl classes, which it holds to ASCII.
@(private)
re2_perl_class :: proc(c: u8) -> (set: Ascii_Set, ok: bool) {
	switch c {
	case 'd', 'D':
		set = ascii_range('0', '9')
	case 'w', 'W':
		set = ascii_range('0', '9') + ascii_range('A', 'Z') + ascii_range('a', 'z') + {'_'}
	case 's', 'S':
		set = {'\t', '\n', '\f', '\r', ' '}
	case:
		return {}, false
	}
	return ~set if c < 'a' else set, true
}

@(private)
ascii_range :: proc(lo, hi: int) -> (set: Ascii_Set) {
	for c in lo ..= hi {
		set += {c}
	}
	return
}

// The class as runs: a run of one a rune, a longer one a range.
@(private)
re2_class_node :: proc(set: Ascii_Set) -> parser.Node {
	class := new(parser.Node_Rune_Class)
	for lo := 0; lo < 128; lo += 1 {
		if lo not_in set {
			continue
		}
		hi := lo
		for hi < 127 && ((hi + 1) in set) {
			hi += 1
		}
		if lo == hi {
			append(&class.runes, rune(lo))
		} else {
			append(&class.ranges, parser.Rune_Class_Range{rune(lo), rune(hi)})
		}
		lo = hi
	}
	return class
}

@(private)
is_alnum :: proc(c: u8) -> bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
