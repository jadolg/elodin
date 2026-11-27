package dnssec

import "core:hash"
import "core:mem"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:loop"

// ---------------------------------------------------------------------------
// The zone cache
// ---------------------------------------------------------------------------

@(private)
cache_get :: proc(
	v: ^Validator,
	zone: string,
	now: loop.Moment,
	allocator: mem.Allocator,
) -> (
	entry: Zone_Entry,
	found: bool,
	/*
	What the non-cut memo says about the same name, answered here rather than
	through a call of its own so that one step of the walk takes the
	validator's lock once.

	Read only when the name is absent from the zones, which is narrower than
	"when `found` is false": an entry that has expired but not yet been swept
	shadows the memo too. That costs a lookup the memo would have saved and
	nothing else, and it is not the invariant it looks like - the guard in
	`non_cut_remember` declines only a *live* zone entry, so a name can sit in
	both maps with the zone's copy expired.
	*/
	non_cut: bool,
) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := dns.fold_into(zone, fold_buf[:])
	if !key_ok {
		return {}, false, false
	}

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	cached, in_map := v.zones[key]
	if !in_map {
		slot := v.non_cuts[non_cut_slot(v, key)]
		return {}, false, slot.name == key && now <= slot.expires
	}
	if now > cached.expires {
		return {}, false, false
	}
	// A hit is what keeps an entry alive when the cache overflows. The root, or
	// the closest anchor, is read here at the start of every chain, which is
	// what puts it out of reach of a flood of names nobody asks for twice.
	zone_touch(v, cached)
	/*
	The RDATA is copied, not referenced. A `Dnskey` is a handful of slices into
	memory this cache owns, and another thread may evict the entry the moment
	the lock is released; handing out the struct alone would leave the caller
	reading a freed key for the rest of its query. The caller works in a
	per-request arena, so the copy costs a couple of kilobytes and is dropped
	with everything else.
	*/
	out := Zone_Entry {
		status  = cached.status,
		expires = cached.expires,
	}
	if len(cached.keys) > 0 {
		copies := make([dynamic]Dnskey, 0, len(cached.keys), allocator)
		for key in cached.keys {
			rdata := make([]u8, len(key.rdata), allocator)
			copy(rdata, key.rdata)
			parsed, perr := parse_dnskey(rdata)
			if perr != .None {
				continue
			}
			append(&copies, parsed)
		}
		out.keys = copies[:]
	}
	return out, true, false
}

/*
A step that came back broken may be one the walk should never have reached.

The memo says a name exists and is no cut. Existence is the half that can lapse,
and a cut appearing is the half that can change: either way the walk skips the
name on the memo's word and asks about one a label further down, where the
answer settles nothing. An NSEC3 name error proves the closest encloser and the
next closer, so the step below the next closer is neither matched nor covered; a
delegation that has since appeared answers from inside the child zone, whose
records are not the parent's and are dropped; and where the first name below the
new cut is itself signed, the DS that arrives is signed by a zone the walk never
established. All three read as broken.

So a broken step gives the name above it back to the lookup. One name per step,
which for a run of them is one question each before the walk gets past it - the
memo sheds the run from the bottom up - and the ceiling on how long that can go
on is `MAX_NON_CUT_TTL` rather than this. Forgetting a name the memo had right
costs the one DS lookup it was saving.
*/
@(private)
forget_skipped_non_cut :: proc(v: ^Validator, parent, child: string) {
	// Nothing was skipped when the child sits directly under the zone the walk
	// established, so there is no name between them to be wrong about.
	if label_count(child) <= label_count(parent) + 1 {
		return
	}
	non_cut_forget(v, name_drop_labels(child, 1))
}

/*
Give back a name the walk was asked about and did not reach.

The three forgets in `zone_step` all sit after its DS query, and a table hit
returns before it - so when the name the memo holds is itself the one that
became a zone, no lookup is made and nothing notices. Every verdict that rests
on reaching that name then comes out broken, and asking again changes nothing,
because the walk skips the name again without asking.

So the verdicts that rest on it say so. `established` being a proper ancestor of
the name is the whole of the test: the walk held up and still stopped short, and
the memo is the only thing that makes it stop short. Being wrong costs the one
DS lookup the entry was saving.
*/
@(private)
forget_unreached_non_cut :: proc(v: ^Validator, name, established: string) {
	if !dns.name_below(name, established) {
		return
	}
	non_cut_forget(v, name)
}

// The slot a name owns. FNV-1a over the folded name, from this process's own
// offset basis - see `Validator.non_cut_seed` for why the basis is not the
// published one.
@(private)
non_cut_slot :: proc(v: ^Validator, key: string) -> int {
	return int(hash.fnv32a(transmute([]u8)key, v.non_cut_seed) % u32(len(v.non_cuts)))
}

// Forget one name, for a caller that does not hold the lock.
@(private)
non_cut_forget :: proc(v: ^Validator, name: string) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := dns.fold_into(name, fold_buf[:])
	if !key_ok {
		return
	}
	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)
	non_cut_drop(v, key)
}

// Release the slot `key` would occupy, if it is the name sitting there. The
// caller holds the lock.
@(private)
non_cut_drop :: proc(v: ^Validator, key: string) {
	slot := &v.non_cuts[non_cut_slot(v, key)]
	if slot.name != key {
		return
	}
	delete(slot.name, v.allocator)
	slot^ = {}
}

// Remember one, clamped so a denial naming no TTL still expires and one naming
// a year is not believed for one. The name in the slot gives way, which is the
// whole of the replacement policy; see `Validator.non_cuts`. Nothing, for a
// question that has run dry (`ran_dry`).
@(private)
non_cut_remember :: proc(v: ^Validator, budget: ^Budget, name: string, ttl: u32, now: loop.Moment, lapses := max(u32)) {
	if ran_dry(budget) {
		return
	}
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := dns.fold_into(name, fold_buf[:])
	if !key_ok {
		return
	}
	lifetime := min(clamp(ttl, MIN_ZONE_TTL, MAX_NON_CUT_TTL), lapses)
	expires := loop.moment_add(now, time.Duration(lifetime) * time.Second)

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	/*
	Not if the name is a zone. `cache_put` drops any memo entry as it settles
	one, which covers a name remembered and then settled; this is the same race
	arriving in the other order, and it is just as reachable - two walks both
	missing the caches for one child, one upstream in the pool answering with
	the DS and another with a stale denial of it.

	Left unguarded the two hold the same name with their own lifetimes, and a
	clamped negative TTL outlasting the DS TTL means that once the zone entry
	expires the walk reads a live signed cut as no cut. Every signature that
	zone makes is then refused, and no lookup can put it right because the memo
	answers before the question is asked.
	*/
	if zone, settled := v.zones[key]; settled && now <= zone.expires {
		return
	}

	slot := &v.non_cuts[non_cut_slot(v, key)]
	if slot.name == key {
		// Already ours; only the expiry moves.
		slot.expires = expires
		return
	}
	if slot.name != "" {
		delete(slot.name, v.allocator)
	}
	slot.name = strings.clone(key, v.allocator)
	slot.expires = expires
}

// Drop every name the table owns. Only `destroy_validator` wants this, and
// nothing else can still be looking by then.
@(private)
clear_non_cuts :: proc(v: ^Validator) {
	for &slot in v.non_cuts {
		if slot.name != "" {
			delete(slot.name, v.allocator)
			slot = {}
		}
	}
}

// `now` is on the moment clock `cache_get` and `sweep` read: the walk's
// `Budget.began`, the instant `lapses` is counted from and the walk reads the
// cache at. It is in the past, so an entry whose lifetime the walk has already
// outrun is stored expired to every later walk and to `sweep`. Nothing is
// stored for a question that has run dry (`ran_dry`), but the name is still
// taken out of the non-cut memo, which needs no memory and costs at most a
// lookup. True when the entry was stored.
@(private)
cache_put :: proc(v: ^Validator, budget: ^Budget, zone: string, status: Status, keys: []Dnskey, ttl: u32, now: loop.Moment, lapses := max(u32)) -> (kept: bool) {
	fold_buf: [dns.MAX_NAME_PRESENTATION]u8
	key, key_ok := dns.fold_into(zone, fold_buf[:])
	if !key_ok {
		return
	}
	/*
	`ttl` already holds the records' TTLs to the Original TTL their signatures
	carry (RFC 4035 section 5.3.3), and the floor applies over both - the way
	Unbound's minimum and Knot Resolver's `ttl_min` do - since a zone's owner
	choosing zero must not turn every question into a walk. `lapses` is when
	the signatures stop verifying, and nothing outlives that.
	*/
	lifetime := min(clamp(ttl, MIN_ZONE_TTL, MAX_ZONE_TTL), lapses)

	/*
	Watched, so a copy the heap refused - a key, the list, the name - stores
	nothing rather than an entry short of a key, which would refuse every
	signature that key makes until the entry expires.
	*/
	held_dry := false
	watch := dns.Dry_Watch{backing = v.allocator, dry = &held_dry}
	stored := dns.dry_watch_allocator(&watch)
	entry: ^Zone_Entry
	if !ran_dry(budget) {
		entry = new(Zone_Entry, stored)
	}
	if entry == nil {
		non_cut_forget(v, key)
		return
	}
	// Before the lock, and before anything is evicted to make room for it.
	entry.zone = strings.clone(key, stored)
	entry.status = status
	entry.expires = loop.moment_add(now, time.Duration(lifetime) * time.Second)
	oversized: bool
	entry.keys, oversized = own_keys(v, keys, stored, &held_dry)

	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	/*
	This name has just been settled as a zone, so anything the memo says about
	it is answering an older question and must go.

	`zone_step` reads the zones first, so a live entry here already wins - but
	the two lifetimes are their own. A delegation appearing between two walks,
	or two upstreams in a pool disagreeing about one, can leave both maps
	holding the same name, and if the memo's clamped negative TTL outlasts the
	zone's the walk goes back to treating a live signed cut as no cut once the
	zone entry expires. That refuses the zone's own signatures, which is
	SERVFAIL for every name in it until the memo ages out.
	*/
	non_cut_drop(v, key)
	if held_dry {
		free_entry(v, entry)
		return
	}

	/*
	Past `MAX_CACHED_ZONE_KEY_BYTES` nothing is stored, and anything already
	stored for the name is left where it is: it is a set this server did
	validate, under its own lifetime, and dropping it would let an oversized
	reply evict a good entry. The memo above still goes, because the name has
	been settled as a zone whatever the cache does with it.
	*/
	if oversized {
		sync.atomic_add(&v.oversized, 1)
		free_entry(v, entry)
		return
	}

	if old, exists := v.zones[key]; exists {
		zone_replace(v, old, entry)
		return true
	}
	// The coldest entries, and only as many as it takes to make room. A
	// wholesale flush would throw out everyone else's root and TLD keys; see
	// `Validator.lru_head`.
	for len(v.zones) >= v.max_cached_zones && v.lru_tail != nil {
		drop_zone(v, v.lru_tail)
	}
	// A map that could not grow takes nothing, and says so only by not holding
	// the key; an entry linked without it would never be found or swept.
	v.zones[entry.zone] = entry
	if entry.zone not_in v.zones {
		free_entry(v, entry)
		return
	}
	zone_push_front(v, entry)
	return true
}

/*
A copy of the `keys` a zone entry keeps, in `stored`: only the usable ones, and
`oversized` when they come to more than `MAX_CACHED_ZONE_KEY_BYTES`. A copy that
ran `stored` dry sets `held_dry` and stops short.
*/
@(private)
own_keys :: proc(v: ^Validator, keys: []Dnskey, stored: mem.Allocator, held_dry: ^bool) -> (owned_keys: []Dnskey, oversized: bool) {
	if len(keys) == 0 {
		return nil, false
	}
	// Appended rather than written by index: skipping a key that will not
	// parse must shorten the set, not leave a zero-valued one sitting in it.
	// A gap carries algorithm 0, which no signature matches, and an RRset
	// with nothing to check it against is reported unsupported - which
	// `validate_rrset` reads as insecure. A cache holding entries that
	// quietly mean "treat this zone as unsigned" fails the wrong way.
	owned := make([dynamic]Dnskey, 0, len(keys), stored)
	held := 0
	for k in keys {
		/*
		Only keys that could sign something. `check_signature` and
		`signature_worth_trying` both skip the rest - a key without the zone
		bit, one revoked under RFC 5011, one whose protocol field is not 3 -
		so copying them holds memory for keys nothing will ever read, and
		lets a zone pad its own entry with records that need not be keys at
		all. Filtered on the caller's copy, which carries the same bytes as
		the copy below and so gives the same answer.
		*/
		if !key_usable(k) {
			continue
		}
		if held + len(k.rdata) > MAX_CACHED_ZONE_KEY_BYTES {
			oversized = true
			break
		}
		rdata := make([]u8, len(k.rdata), stored)
		if held_dry^ {
			delete(rdata, v.allocator)
			break
		}
		copy(rdata, k.rdata)
		parsed, perr := parse_dnskey(rdata)
		if perr != .None {
			delete(rdata, v.allocator)
			continue
		}
		held += len(rdata)
		if _, aerr := append(&owned, parsed); aerr != nil {
			delete(rdata, v.allocator)
			break
		}
	}
	return owned[:], oversized
}

// Put `entry` in the cache in place of `old`, under the same name, with `v.mu`
// held.
@(private)
zone_replace :: proc(v: ^Validator, old, entry: ^Zone_Entry) {
	// Reuse the string the map is already keyed by, and drop this one's: the
	// map's key must not change under it while it holds the entry.
	delete(entry.zone, v.allocator)
	entry.zone = old.zone
	old.zone = ""
	zone_unlink(v, old)
	free_entry(v, old)
	v.zones[entry.zone] = entry
	zone_push_front(v, entry)
}

/*
The eviction order. The caller holds the lock in every case.

`drop_zone` is the only way an entry leaves `zones`: doing it by hand at each
call site is how a list ends up pointing at something that has been freed, and
the next overflow then evicts through a dangling pointer.
*/
@(private)
drop_zone :: proc(v: ^Validator, e: ^Zone_Entry) {
	zone_unlink(v, e)
	// Before `free_entry`, which frees the string the map is keyed on.
	delete_key(&v.zones, e.zone)
	free_entry(v, e)
}

@(private)
zone_push_front :: proc(v: ^Validator, e: ^Zone_Entry) {
	e.prev = nil
	e.next = v.lru_head
	if v.lru_head != nil {
		v.lru_head.prev = e
	}
	v.lru_head = e
	if v.lru_tail == nil {
		v.lru_tail = e
	}
}

@(private)
zone_unlink :: proc(v: ^Validator, e: ^Zone_Entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if v.lru_head == e {
		v.lru_head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if v.lru_tail == e {
		v.lru_tail = e.prev
	}
	e.prev, e.next = nil, nil
}

@(private)
zone_touch :: proc(v: ^Validator, e: ^Zone_Entry) {
	if v.lru_head == e {
		return
	}
	zone_unlink(v, e)
	zone_push_front(v, e)
}

// Drop entries whose lifetime has run out.
sweep :: proc(v: ^Validator) -> (removed: int) {
	return sweep_at(v, loop.moment_now())
}

// `sweep` as of `clock`, which a test moves past an entry's expiry.
@(private)
sweep_at :: proc(v: ^Validator, clock: loop.Moment) -> (removed: int) {
	if v == nil {
		return 0
	}
	sync.mutex_lock(&v.mu)
	defer sync.mutex_unlock(&v.mu)

	// Collected first: deleting from a map while walking it is not something to
	// rely on.
	expired := make([dynamic]^Zone_Entry, 0, 16, context.temp_allocator)
	for _, entry in v.zones {
		if clock > entry.expires {
			append(&expired, entry)
		}
	}
	for entry in expired {
		drop_zone(v, entry)
		removed += 1
	}

	// The non-cuts go the same way but are not counted: `removed` is reported
	// as expired zone keys - `sweep_validator`, and the line it feeds in
	// `main.odin` - and a table slot holds no keys. Folding them in would have
	// that number overstate key-cache churn to whoever is reading it to decide
	// whether the zone cache is thrashing.
	for &slot in v.non_cuts {
		if slot.name != "" && clock > slot.expires {
			delete(slot.name, v.allocator)
			slot = {}
		}
	}
	return
}
