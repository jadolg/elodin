package filter

import "core:mem"
import "core:mem/virtual"
import "core:strings"
import "core:sync"

/*
Domain matching for sink lists.

Every rule is stored once, keyed by the domain it names, with flags saying what
the rule covers:

  - Apex        the domain itself           (hosts entries, "example.com")
  - Subdomains  everything below it         ("*.example.com")

An adblock rule such as `||example.com^` sets both. A lookup therefore costs one
map probe for the apex plus one probe per parent label, which is bounded by the
domain's depth rather than by the size of the list.
*/

Rule_Flag :: enum u8 {
	Apex,
	Subdomains,
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
	rules:     map[string]Rule_Flags,
	arena:     virtual.Arena,
	allocator: mem.Allocator,
	count:     int,
}

Engine :: struct {
	mu:         sync.RW_Mutex,
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
	// Names the engine answers for directly regardless of lists.
	stats:      Stats,
}

Stats :: struct {
	block_rules: int,
	allow_rules: int,
	queries:     u64,
	blocked:     u64,
}

set_make :: proc() -> ^Set {
	s := new(Set)
	if err := virtual.arena_init_growing(&s.arena); err != nil {
		panic("filter: cannot create arena")
	}
	s.allocator = virtual.arena_allocator(&s.arena)
	s.rules = make(map[string]Rule_Flags, 1024, s.allocator)
	return s
}

set_destroy :: proc(s: ^Set) {
	if s == nil {
		return
	}
	virtual.arena_destroy(&s.arena)
	free(s)
}

/*
Add a rule for `domain`.

`domain` is taken as written by the list author; it is lowercased and stripped
of any trailing dot before being stored.
*/
set_add :: proc(s: ^Set, domain: string, flags: Rule_Flags) {
	buf: [MAX_NORMALISED]u8
	key, ok := normalise(domain, buf[:])
	if !ok || key == "" {
		return
	}
	if existing, found := s.rules[key]; found {
		s.rules[key] = existing + flags
		return
	}
	s.rules[strings.clone(key, s.allocator)] = flags
	s.count += 1
}

set_lookup :: proc(s: ^Set, normalised: string) -> bool {
	if s == nil || len(s.rules) == 0 {
		return false
	}
	if flags, found := s.rules[normalised]; found && .Apex in flags {
		return true
	}
	// Walk up the parents; only Subdomains rules apply to them.
	rest := normalised
	for {
		idx := strings.index_byte(rest, '.')
		if idx < 0 {
			return false
		}
		rest = rest[idx + 1:]
		if rest == "" {
			return false
		}
		if flags, found := s.rules[rest]; found && .Subdomains in flags {
			return true
		}
	}
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
// destroy once no in-flight query can still be reading them.
engine_swap :: proc(e: ^Engine, block, allow: ^Set) -> (old_block, old_allow: ^Set) {
	sync.rw_mutex_lock(&e.mu)
	defer sync.rw_mutex_unlock(&e.mu)
	old_block, old_allow = e.block, e.allow
	e.block, e.allow = block, allow
	sync.atomic_store(&e.generation, e.generation + 1)
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
under the exclusive lock, so a reader that has seen the new number is matching
against the new sets.

Read without taking the lock; see below for why the write side makes that safe.
*/
engine_generation :: proc(e: ^Engine) -> u64 {
	if e == nil {
		return 0
	}
	/*
	Read without the lock, which the write side makes safe: `generation` is only
	ever moved inside `engine_swap`, under the exclusive lock, by one store. So
	an atomic load sees either the number before that store or the number after
	it, which is exactly what the shared lock guaranteed and is all a caller
	needs - the stamp it then writes is compared for equality, never ordered
	against another reader's.

	Worth the paragraph because this is on the hot path: it runs once per query
	on top of the shared lock `engine_match` takes for the question and one more
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
*/
engine_match :: proc(e: ^Engine, name: string) -> Decision {
	buf: [MAX_NORMALISED]u8
	key, ok := normalise(name, buf[:])
	if !ok {
		return .None
	}

	sync.rw_mutex_shared_lock(&e.mu)
	defer sync.rw_mutex_shared_unlock(&e.mu)

	sync.atomic_add(&e.stats.queries, 1)
	if set_lookup(e.allow, key) {
		return .Allowed
	}
	if set_lookup(e.block, key) {
		sync.atomic_add(&e.stats.blocked, 1)
		return .Blocked
	}
	return .None
}

engine_stats :: proc(e: ^Engine) -> Stats {
	sync.rw_mutex_shared_lock(&e.mu)
	defer sync.rw_mutex_shared_unlock(&e.mu)
	return Stats {
		block_rules = e.stats.block_rules,
		allow_rules = e.stats.allow_rules,
		queries = sync.atomic_load(&e.stats.queries),
		blocked = sync.atomic_load(&e.stats.blocked),
	}
}

// Lowercase, drop a trailing dot, and reject anything that cannot be a domain.
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
		if c == ' ' || c == '\t' || c == '/' {
			return "", false
		}
		buf[i] = c
	}
	return string(buf[:len(s)]), true
}
