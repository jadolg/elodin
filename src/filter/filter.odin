package filter

import "core:mem"
import "core:mem/virtual"
import "core:strings"
import "core:sync"
import "elodin:brlock"
import "core:unicode"
import "elodin:dns"

/*
Domain matching for sink lists.

Every rule is stored once, keyed by the domain it names (see table.odin), with
flags saying what the rule covers:

  - Apex        the domain itself           (hosts entries, "example.com")
  - Subdomains  everything below it         ("*.example.com")

An adblock rule such as `||example.com^` sets both. A lookup therefore costs one
table probe for the apex plus one probe per parent label, which is bounded by the
domain's depth rather than by the size of the list.
*/

Rule_Flag :: enum u8 {
	Apex,
	Subdomains,
	// The entry is followed by `$dnstype` filter ids (table.odin), and `Apex`
	// and `Subdomains` say what it covers for every type.
	Typed,
}

// What covers a name: nothing, only a `$dnstype` rule, or a rule for every type.
Coverage :: enum u8 {
	None,
	Typed,
	Any,
}

Rule_Flags :: bit_set[Rule_Flag;u8]

Decision :: enum u8 {
	None,
	Blocked,
	Allowed,
}

// Longest domain we will normalise on the stack: 255 wire bytes can expand to
// four presentation characters each.
@(private)
MAX_NORMALISED :: 1024

Set :: struct {
	names:     Table,
	// What `$badfilter` rules have taken back, kept so a rule arriving later -
	// further down the list, or from the next one - is cancelled too.
	cancelled: map[string]Rule_Flags,
	// How many `$badfilter` rules were taken, so one that adds nothing can be
	// told from one that was skipped.
	cancels:   int,
	// Every distinct `$dnstype` filter a rule here has, by the id a `.Typed`
	// table entry holds, and the ids by content; see `type_intern`.
	filters:    [dynamic]Type_Filter,
	filter_ids: map[string]u32,
	// `/re/` rules, matched after the name tables; `engine_match` says when, and
	// regex.odin what bounds them.
	regexes:       [dynamic]Regex_Rule,
	// The patterns `regexes` holds, so a line is checked against them in one
	// probe rather than a scan: past the budget every line still asks.
	regex_held:    map[string]^Type_Filter,
	// What they cost, in `regex_cost`'s units: program bytes and class entries.
	regex_bytes:   int,
	// Patterns turned away because `regex_bytes` was already at its budget.
	regex_refused: int,
	// Names refused only for an international name's characters past ASCII,
	// written in UTF-8 rather than punycode (#400), so the loader can say so; see
	// `rule_key` for which characters those are.
	not_ascii:     int,
	// What `regex_add` parses and trial-compiles into, emptied after each call:
	// a fresh arena a pattern cost a map and unmap, 4 µs a line.
	regex_scratch: virtual.Arena,
	arena:     virtual.Arena,
	allocator: mem.Allocator,
	// Names any rule covers, for any type, plus the regex patterns held.
	count:     int,
}

Engine :: struct {
	// Taken by every match, so a striped lock rather than an `RW_Mutex`: see
	// `brlock` for what one word all the readers write costs.
	lock:       brlock.Lock,
	block:      ^Set,
	allow:      ^Set,
	/*
	Which rule sets these are, counted up on every swap.

	A number rather than a timestamp: what a caller needs of it is only whether
	it is the same one it saw last, and two swaps inside one clock tick are a
	thing a reload loop can do. Zero is "no list has ever been loaded", which is
	what a caller that has never asked can stamp its own work with and be sure of
	being told to ask again.

	It exists for answers held somewhere else. A decision this engine makes about
	a name is made afresh every time it is asked, so nothing here needs it; a
	decision *cached* elsewhere - the resolver keeps whole answers, matched
	against the lists when they were stored - has no other way to notice that the
	lists it was matched against are gone.
	*/
	generation: u64,
	// Rule counts. What was asked and what was blocked is the server's to
	// count, once per query, and a shared counter here would be written by every
	// thread on every match.
	stats:      Stats,
}

Stats :: struct {
	block_rules: int,
	allow_rules: int,
}

set_make :: proc() -> ^Set {
	s := new(Set)
	if err := virtual.arena_init_growing(&s.arena); err != nil {
		panic("filter: cannot create arena")
	}
	s.allocator = virtual.arena_allocator(&s.arena)
	table_init(&s.names, context.allocator)
	s.cancelled = make(map[string]Rule_Flags, s.allocator)
	s.filters = make([dynamic]Type_Filter, 1, s.allocator)
	s.filter_ids = make(map[string]u32, s.allocator)
	s.filter_ids["\x00"] = 0
	s.regexes = make([dynamic]Regex_Rule, s.allocator)
	s.regex_held = make(map[string]^Type_Filter, s.allocator)
	return s
}

set_destroy :: proc(s: ^Set) {
	if s == nil {
		return
	}
	table_destroy(&s.names)
	virtual.arena_destroy(&s.regex_scratch)
	virtual.arena_destroy(&s.arena)
	free(s)
}

/*
Add a rule for `domain`, reporting whether the set now covers it.

`domain` is taken as written by the list author; it is lowercased and stripped
of any trailing dot before being stored. A name no query can spell is refused,
and so is a rule a `$badfilter` has wholly cancelled, and a name past the 4 GiB
of names a set holds (`table_insert`). A rule for only some query types
(`types`, from `$dnstype`) is refused when the name's rules would then list more
than MAX_RULE_TYPES of them.
*/
set_add :: proc(s: ^Set, domain: string, flags: Rule_Flags, types := ANY_TYPE) -> (stored: bool) {
	buf: [MAX_NORMALISED]u8
	key, ok, not_ascii := rule_key(domain, buf[:])
	if !ok {
		s.not_ascii += int(not_ascii)
		return false
	}
	add := flags - s.cancelled[key]
	if add == {} {
		return false
	}
	existing := table_entry(&s.names, key)
	held := entry_held(existing, len(key))
	switch {
	case type_is_any(types) && existing != nil:
		existing^ += add
		stored = true
	case type_is_any(types):
		stored = table_insert(&s.names, key, add)
	case:
		stored = typed_add(s, key, existing, add, types)
	}
	if stored && !held {
		s.count += 1
	}
	return
}

/*
Take back what a rule for `domain` with `flags` would add, whether that rule is
already in the set or arrives after this.

ponytail: rules are stored merged per name, so this cancels the coverage rather
than one rule's text - `||x^$badfilter` also lifts a hosts entry for `x`, and
`||x^$important,badfilter` lifts a plain `||x^`, and `*.x$badfilter` (or
`||*.x^$badfilter`) narrows a `||x^` to its apex, where AdGuard would lift only the
rule written the same way. Keep rule texts per name if that ever matters.
*/
set_cancel :: proc(s: ^Set, domain: string, flags: Rule_Flags) {
	buf: [MAX_NORMALISED]u8
	key, ok, not_ascii := rule_key(domain, buf[:])
	if !ok {
		s.not_ascii += int(not_ascii)
		return
	}
	s.cancels += 1
	if existing, found := s.cancelled[key]; found {
		s.cancelled[key] = existing + flags
	} else {
		s.cancelled[strings.clone(key, s.allocator)] = flags
	}
	if existing := table_entry(&s.names, key); existing != nil {
		held := entry_held(existing, len(key))
		existing^ -= flags
		if .Typed in existing^ {
			ids := typed_ids(existing, len(key))
			for flag in flags {
				ids[int(flag)] = 0
			}
			typed_ids_store(existing, len(key), ids)
		}
		if held && !entry_held(existing, len(key)) {
			s.count -= 1
		}
	}
}

/*
`set_add` for a rule covering only some types: merged into what the name's other
such rules cover, one filter for its apex and one for below it. An anchor the
table covers for every type already takes nothing more, and one whose rules add
up to every type (`~A` and `~AAAA`) is covered for every type, as a plain rule
covers it. `entry` is `key`'s, or nil.
*/
@(private)
typed_add :: proc(s: ^Set, key: string, entry: ^Rule_Flags, flags: Rule_Flags, types: Type_Filter) -> bool {
	entry := entry
	add := flags - (entry^ if entry != nil else {})
	if add == {} {
		return true
	}
	ids: [2]u32
	if entry != nil && .Typed in entry^ {
		ids = typed_ids(entry, len(key))
	}
	buf: [2 * MAX_RULE_TYPES]u16
	every: Rule_Flags
	for flag in add {
		merged := type_union(s.filters[ids[int(flag)]], types, buf[:]) or_return
		if type_is_any(merged) {
			every += {flag}
			ids[int(flag)] = 0
		} else {
			ids[int(flag)] = type_intern(s, merged) or_return
		}
	}
	switch {
	case entry == nil:
		table_insert(&s.names, key, {.Typed}) or_return
		entry = table_entry(&s.names, key)
	case .Typed not_in entry^:
		entry = table_retype(&s.names, key)
		if entry == nil {
			return false
		}
	}
	entry^ += every
	typed_ids_store(entry, len(key), ids)
	return true
}

// Whether any rule covers the name of `entry` (nil for none), for any type:
// what `count` counts.
@(private)
entry_held :: proc(entry: ^Rule_Flags, key_len: int) -> bool {
	if entry == nil {
		return false
	}
	return entry^ & {.Apex, .Subdomains} != {} || (.Typed in entry^ && typed_ids(entry, key_len) != {})
}

// What covers `name` for `qtype` as `flag` says: the table, for every type, or
// a `$dnstype` filter its entry holds.
@(private)
covers :: proc(s: ^Set, name: string, flag: Rule_Flag, qtype: dns.Type) -> Coverage {
	entry := table_entry(&s.names, name)
	switch {
	case entry == nil:
		return .None
	case flag in entry^:
		return .Any
	case .Typed in entry^ && type_matches(s.filters[typed_ids(entry, len(name))[int(flag)]], qtype):
		return .Typed
	}
	return .None
}

// Whether a rule covers `normalised` for `qtype`.
set_lookup :: proc(s: ^Set, normalised: string, qtype: dns.Type) -> bool {
	return set_cover(s, normalised, qtype) != .None
}

/*
Whether a `$dnstype` rule covers `normalised` for some type, whichever it is: its
own entry's apex, or a parent's subdomains.
*/
@(private)
set_covers_some_type :: proc(s: ^Set, normalised: string) -> bool {
	if s == nil || s.names.used == 0 {
		return false
	}
	flag, rest := Rule_Flag.Apex, normalised
	for rest != "" {
		if entry := table_entry(&s.names, rest); entry != nil && .Typed in entry^ && typed_ids(entry, len(rest))[int(flag)] != 0 {
			return true
		}
		idx := strings.index_byte(rest, '.')
		if idx < 0 {
			break
		}
		flag, rest = .Subdomains, rest[idx + 1:]
	}
	return false
}

/*
What covers `normalised` for `qtype`: its own entry's apex, or a parent's
subdomains. A rule for every type is looked for past one for some, so a block
can say which it was.
*/
set_cover :: proc(s: ^Set, normalised: string, qtype: dns.Type) -> (best: Coverage) {
	if s == nil || s.names.used == 0 {
		return .None
	}
	best = covers(s, normalised, .Apex, qtype)
	rest := normalised
	for best != .Any {
		idx := strings.index_byte(rest, '.')
		if idx < 0 {
			break
		}
		rest = rest[idx + 1:]
		if rest == "" {
			break
		}
		best = max(best, covers(s, rest, .Subdomains, qtype))
	}
	return
}

// Starts empty; rule sets arrive via `engine_swap` once a load completes, so a
// server can come up and answer before its lists have finished downloading.
engine_make :: proc() -> ^Engine {
	return new(Engine)
}

engine_destroy :: proc(e: ^Engine) {
	if e == nil {
		return
	}
	set_destroy(e.block)
	set_destroy(e.allow)
	free(e)
}

// Swap in freshly built rule sets, returning the old ones for the caller to
// destroy once no in-flight query can still be reading them. Neither may be a
// set already swapped in: each is trimmed before the lock, which would move
// slots under a query reading them.
engine_swap :: proc(e: ^Engine, block, allow: ^Set) -> (old_block, old_allow: ^Set) {
	// Before the lock: a set is done growing once it is swapped in, and this
	// copies its slots, which no query should wait on.
	if block != nil {
		table_trim(&block.names)
	}
	if allow != nil {
		table_trim(&allow.names)
	}
	brlock.write_lock(&e.lock)
	defer brlock.write_unlock(&e.lock)
	old_block, old_allow = e.block, e.allow
	e.block, e.allow = block, allow
	// An atomic read-modify-write, not a plain read and an atomic store: the
	// write lock keeps other *writers* out and says nothing about the
	// lock-free readers in `engine_generation`, so a plain load here would be
	// one half of a race with them.
	sync.atomic_add(&e.generation, 1)
	e.stats.block_rules = block.count if block != nil else 0
	e.stats.allow_rules = allow.count if allow != nil else 0
	return
}

/*
Which rule sets `engine_match` is answering from at the moment.

A caller that takes this number before matching, and stamps it onto what it
stores, cannot credit its result to a set that arrived after the match began: it
stamps the older number and is told to match again, which is the harmless
direction. `engine_swap` publishes the sets before it moves the number, both
under the write lock, so a reader that has seen the new number is matching
against the new sets.

Read without taking the lock; see below for why the write side makes that safe.
*/
engine_generation :: proc(e: ^Engine) -> u64 {
	if e == nil {
		return 0
	}
	/*
	Read without the lock, which the write side makes safe: `generation` is only
	ever moved inside `engine_swap`, under the write lock, by one store. So
	an atomic load sees either the number before that store or the number after
	it, which is exactly what the read lock guarantees and is all a caller
	needs - the stamp it then writes is compared for equality, never ordered
	against another reader's.

	Worth the paragraph because this is on the hot path: it runs once per query
	on top of the read lock `engine_match` takes for the question and one more
	per name in the chain, and it was a second lock round trip for a number that
	changes when a list is reloaded and at no other time.
	*/
	return sync.atomic_load(&e.generation)
}

/*
Decide what to do with a query name.

`name` may be in either wire-presentation form ("ads.example.com.") or plain
form; both normalise to the same key. Allow rules take precedence, matching how
Pi-hole and AdGuard treat their allowlists.

The regex rules come after the name tables, which settle most names in a few
probes. An allow regex still has to be asked about a name the block table lists,
and about one nothing blocks, since `Allowed` exempts an answer from the CNAME
walk; a block regex only about a name no table has blocked for every type.

`qtype` is the type the client asked for, which a `$dnstype` rule is matched
against. `typed_only`, when given, is set on a block to whether the name keeps
other types: only such rules made it, or a `$dnstype` allow rule exempts some of
its types. Then the answer must not say it has none (RFC 8020 section 2), and
the caller answers NODATA for NXDOMAIN.
*/
engine_match :: proc(e: ^Engine, name: string, qtype: dns.Type, typed_only: ^bool = nil) -> Decision {
	buf: [MAX_NORMALISED]u8
	key, ok := normalise(name, buf[:])
	if !ok {
		return .None
	}

	stripe := brlock.read_lock(&e.lock)
	defer brlock.read_unlock(&e.lock, stripe)

	if set_cover(e.allow, key, qtype) != .None {
		return .Allowed
	}
	listed := set_cover(e.block, key, qtype)
	if regex_lookup(e.allow, key, qtype, first = true) != .None {
		return .Allowed
	}
	// Past a block for some types, the regexes are asked only for whether it
	// was one for every type, which only `typed_only` wants to know.
	if listed == .None || (listed == .Typed && typed_only != nil) {
		listed = max(listed, regex_lookup(e.block, key, qtype, first = typed_only == nil))
	}
	if listed == .None {
		return .None
	}
	if typed_only != nil {
		// The zero filter alone in `filters`: the allow set holds no `$dnstype`
		// rule (`type_keep`), and most never do.
		typed_only^ =
			listed == .Typed ||
			(e.allow != nil &&
					len(e.allow.filters) > 1 &&
					(set_covers_some_type(e.allow, key) || regex_lookup(e.allow, key, qtype, some_type = true) != .None))
	}
	return .Blocked
}

engine_stats :: proc(e: ^Engine) -> Stats {
	stripe := brlock.read_lock(&e.lock)
	defer brlock.read_unlock(&e.lock, stripe)
	return e.stats
}

// A query spells a control or non-ASCII byte as \DDD, so a rule holding one raw
// can never match; and a slash marks a line the parser mis-split. `not_ascii`
// says a byte past ASCII is all that refused it, so its punycode form would match:
// every such character is a letter, number or mark, which a label can hold, or a
// joiner or punctuation mark RFC 5892 appendix A admits in context. A no-break or
// zero-width space, a BOM, a symbol, a byte that is not UTF-8 (decoded as
// U+FFFD), or ASCII no label holds (`*`, `:`) has no punycode form a stub sends.
@(private)
rule_key :: proc(domain: string, buf: []u8) -> (key: string, ok: bool, not_ascii: bool) {
	key, ok = normalise(domain, buf)
	for c in transmute([]u8)key {
		if c == '/' || c <= 0x20 || c == 0x7f {
			return "", false, false
		}
		not_ascii ||= c >= 0x80
	}
	if !not_ascii {
		return
	}
	for r in key {
		switch r {
		case 'a' ..= 'z', '0' ..= '9', '-', '_', '.', 0x200c, 0x200d, 0x00b7, 0x0375, 0x05f3, 0x05f4, 0x30fb, 0x3002, 0xff0e, 0xff61:
		// The ASCII a label holds; RFC 5892 appendix A's CONTEXTJ and CONTEXTO
		// code points: the joiners and the middle dot, keraia, geresh, gershayim
		// and katakana middle dot; and the ideographic, fullwidth and halfwidth
		// full stops, which a lookup reads as a dot (RFC 3490 section 3.1). Any
		// other ASCII is a symbol, refused below.
		case:
			if !unicode.is_letter(r) && !unicode.is_number(r) && !unicode.is_nonspacing_mark(r) && !unicode.is_spacing_mark(r) {
				return "", false, false
			}
		}
	}
	return "", false, true
}

@(private)
normalise :: proc(name: string, buf: []u8) -> (out: string, ok: bool) {
	s := name
	if len(s) > 0 && s[len(s) - 1] == '.' {
		s = s[:len(s) - 1]
	}
	if len(s) == 0 || len(s) > len(buf) {
		return "", false
	}
	for i in 0 ..< len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		buf[i] = c
	}
	return string(buf[:len(s)]), true
}
