package filter

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:text/regex"
import "core:text/regex/parser"
import "elodin:dns"
import "elodin:testkit"

/*
A rule set whose allocator runs dry turns away what it cannot hold, says so
(`set_whole`), and never traps or reports a name stored that it cannot find
(#765).

Each sweep refuses one allocation - the first, then the second, and so on - until
a run refuses none, so every allocation a load makes is refused once.
*/

// The query types a `$dnstype` rule below names some of.
@(private = "file")
OOM_TYPES :: [8]dns.Type{.A, .AAAA, .MX, .TXT, .NS, .SOA, .PTR, .SRV}

@(private = "file")
OOM_TYPED :: 40

@(test)
test_table_insert_without_memory_leaves_the_table_as_it_was :: proc(t: ^testing.T) {
	N :: 200
	refused_slots, refused_blob, refused_retype := false, false, false
	for fail_at := 1; ; fail_at += 1 {
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		tb: Table
		if !table_init(&tb, testkit.fail_nth(&f)) {
			// The first blob is the first allocation.
			testing.expect_value(t, fail_at, 1)
			continue
		}
		defer table_destroy(&tb)
		lost, unretyped := -1, -1
		for i in 0 ..< N {
			key := fmt.tprintf("name-%d.padding-to-grow-the-blob.example", i)
			slots := len(tb.slots)
			if !table_insert(&tb, key, {.Apex}) {
				lost = i
				refused_slots ||= len(tb.slots) == slots && (tb.used + 1) * 5 > slots * TABLE_LOAD_FIFTHS
				refused_blob ||= len(tb.slots) != slots || (tb.used + 1) * 5 <= slots * TABLE_LOAD_FIFTHS
				continue
			}
			if i % 3 == 0 && table_retype(&tb, key) == nil {
				unretyped = i
				refused_retype = true
			}
		}
		if f.seen < fail_at {
			// Nothing was refused: every allocation has been.
			testing.expect(t, !tb.out_of_memory, "a run with every allocation granted is marked out of memory")
			break
		}
		testing.expectf(t, (lost >= 0) != (unretyped >= 0), "run %d: refused an insert at %d and a retype at %d, where one allocation was refused", fail_at, lost, unretyped)
		testing.expectf(t, tb.out_of_memory, "run %d: a refusal is not marked", fail_at)
		testing.expect_value(t, tb.used, N if lost < 0 else N - 1)
		for i in 0 ..< N {
			key := fmt.tprintf("name-%d.padding-to-grow-the-blob.example", i)
			slot := table_find(&tb, key)
			if i == lost {
				testing.expectf(t, slot < 0, "run %d: %s was refused and is found", fail_at, key)
				continue
			}
			if !testing.expectf(t, slot >= 0, "run %d: %s was stored and is not found", fail_at, key) {
				return
			}
			want := Rule_Flags{.Apex, .Typed} if i % 3 == 0 && i != unretyped else Rule_Flags{.Apex}
			testing.expect_value(t, transmute(Rule_Flags)tb.blob[tb.slots[slot].off], want)
		}
	}
	// The sweep reached each growth an insert asks for.
	testing.expect(t, refused_slots, "no slots growth was refused")
	testing.expect(t, refused_blob, "no blob growth was refused on an insert")
	testing.expect(t, refused_retype, "no blob growth was refused on a retype")
}

/*
Names, `$dnstype` rules each with a set of types of its own, regexes, and
`$badfilter` rules for names and regexes: every allocation a list makes a set do.
*/
@(private = "file")
oom_list :: proc() -> string {
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< 150 {
		fmt.sbprintf(&b, "||name-%d.oom.example^\n", i)
	}
	types := OOM_TYPES
	for i in 1 ..= OOM_TYPED {
		// The apex alone first, so the typed rule moves its entry.
		fmt.sbprintf(&b, "|typed-%d.oom.example^\n||typed-%d.oom.example^$dnstype=", i, i)
		sep := ""
		for type, bit in types {
			if i & (1 << uint(bit)) != 0 {
				fmt.sbprintf(&b, "%s%v", sep, type)
				sep = "|"
			}
		}
		strings.write_byte(&b, '\n')
	}
	for i in 0 ..< 6 {
		fmt.sbprintf(&b, "/re%d[a-z]+\\.oom/\n", i)
	}
	for i in 0 ..< 30 {
		fmt.sbprintf(&b, "||gone-%d.oom.example^$badfilter\n", i)
	}
	strings.write_string(&b, "/re0[a-z]+\\.oom/$badfilter\n")
	return strings.to_string(b)
}

/*
Route every allocation `s` makes through `f`, backed by the set's own arena:
`set_make` again, with an allocator that can be made to refuse. False where the
table or the containers could not be made, as `set_make` would have been.
*/
@(private = "file")
set_through :: proc(s: ^Set, f: ^testkit.Fail_Nth) -> bool {
	f.backing = s.allocator
	s.allocator = testkit.fail_nth(f)
	table_destroy(&s.names)
	return table_init(&s.names, s.allocator) && set_init(s)
}

@(test)
test_a_set_without_memory_is_not_whole_and_never_traps :: proc(t: ^testing.T) {
	text := oom_list()
	want := set_make()
	defer set_destroy(want)
	parse_list(want, want, text, .Adblock)
	if !testing.expect(t, set_whole(want), "the reference set is not whole") {
		return
	}
	// The premise: each kind of rule took.
	testing.expect(t, len(want.filters) > OOM_TYPED / 2, "the typed rules interned too few filters")
	testing.expect_value(t, len(want.regexes), 5)
	testing.expect(t, len(want.cancelled) > 30, "the badfilters were not kept")

	refused_init := 0
	for fail_at := 1; ; fail_at += 1 {
		f := testkit.Fail_Nth{fail_at = fail_at, fail_for = 1}
		s := set_make()
		if !testing.expect(t, s != nil, "no set to start from") {
			return
		}
		e := engine_make()
		defer engine_destroy(e)
		if !set_through(s, &f) {
			refused_init += 1
			set_destroy(s)
			continue
		}
		parse_list(s, s, text, .Adblock)
		whole := f.seen < fail_at
		testing.expectf(t, set_whole(s) == whole, "run %d: whole %v, with %d of %d allocations made", fail_at, set_whole(s), f.seen, fail_at)
		// Every rule's name and every type a rule names is asked about: a
		// filter id with no filter, or an entry cut short, traps here.
		engine_swap(e, s, set_make())
		types := OOM_TYPES
		for i in 1 ..= OOM_TYPED {
			for qtype in types {
				engine_match(e, fmt.tprintf("x.typed-%d.oom.example", i), qtype)
				engine_match(e, fmt.tprintf("typed-%d.oom.example", i), qtype)
			}
		}
		for i in 0 ..< 150 {
			engine_match(e, fmt.tprintf("name-%d.oom.example", i), .A)
		}
		engine_match(e, "re1abc.oom", .A)
		if whole {
			testing.expect_value(t, s.count, want.count)
			testing.expect_value(t, len(s.filters), len(want.filters))
			testing.expect(t, engine_match(e, "re1abc.oom", .A) == .Blocked, "a whole set lost its regex")
			break
		}
	}
	// `set_init`'s zero filter and its id, and the first blob.
	testing.expect_value(t, refused_init, 3)
}

/*
No pattern a list may hold takes more of the regex scratch than a quarter of
REGEX_SCRATCH to parse, compile and try against the empty name, so none finds it
full: the parser and the compiler take a refused allocation for a node or an
instruction left out (#765). The pieces are the costliest per byte found - a
class of several runs every two bytes, alternation, and nesting - each repeated
to a few lengths, the shorter of which compile.
*/
@(test)
test_every_pattern_fits_the_regex_scratch :: proc(t: ^testing.T) {
	PIECES :: [?]string{"\\w", "\\W", "\\S", "[!#%')+-/13579;=?]", "[^!#%')+-/13579;=?]", "a|", "(a)", "(\\w\\W\\d\\D\\s\\S){9}"}
	s := set_make()
	defer set_destroy(s)
	temp, ok := regex_scratch_allocator(s)
	if !testing.expect(t, ok, "no scratch arena") {
		return
	}
	compiled, empty, peak := 0, 0, 0
	for piece in PIECES {
		for reps in ([]int{4, 16, 64, MAX_REGEX_PATTERN / len(piece)}) {
			defer free_all(temp)
			// Ends on a whole `a` where a piece leaves an operator open.
			pattern := strings.concatenate({strings.repeat(piece, reps, context.temp_allocator), "a"}, context.temp_allocator)
			if len(pattern) > MAX_REGEX_PATTERN {
				pattern = pattern[len(piece):]
			}
			tree: parser.Node
			parsed: bool
			{
				context.allocator = temp
				tree, parsed = re2_parse(pattern)
			}
			if !testing.expectf(t, parsed, "%s x %d does not parse", piece, reps) {
				continue
			}
			if program_bound(tree) <= MAX_REGEX_PROGRAM {
				if trial, built := regex_compile(tree, temp); built {
					_, matches_empty := regex.match_and_allocate_capture(trial, "", temp, temp)
					compiled += 1
					empty += int(matches_empty)
				}
			}
			peak = max(peak, int(s.regex_scratch.total_used))
			testing.expectf(t, s.regex_scratch.total_used <= REGEX_SCRATCH / 4, "%s x %d took %d bytes of the scratch", piece, reps, s.regex_scratch.total_used)
		}
	}
	// The premise: compiling and matching were measured, not only parsing, and
	// the costliest took a share worth bounding.
	testing.expectf(t, compiled >= len(PIECES), "%d of the patterns compiled", compiled)
	// `(a)` and `a|` repeated never match the empty name; `a|...|a` does not either.
	testing.expect_value(t, empty, 0)
	testing.expectf(t, peak >= REGEX_SCRATCH / 16, "the costliest took only %d bytes", peak)
}
