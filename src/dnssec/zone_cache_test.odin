package dnssec

import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #336: the zone-key cache was bounded by entry count alone, kept whatever a
zone published, and emptied itself when it filled.

Three separate ways for one client's names to cost everybody else. The count
bound says nothing about size, so a zone that publishes sixty-four RSA keys
occupies as much room as `MAX_KEYS_PER_ZONE` times the largest key the parser
will read; `cache_put` copied every parsed key whether or not it could sign
anything; and a full cache threw away every zone in it, so a flood of fresh
names took the root and the TLDs with it and left every client re-walking from
the top.
*/

// These tests never reach an upstream: what they exercise is the cache itself,
// reached through `cache_put` and `cache_get` directly.
@(private = "file")
no_upstream :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator) -> (wire: []u8, ok: bool) {
	return nil, false
}

@(private = "file")
cache_now :: proc() -> time.Time {
	return time.unix(FIXTURE_TIME, 0)
}

// A DNSKEY whose RDATA is `size` bytes, usable unless `flags` says otherwise.
// Nothing about it verifies anything; these tests are about what the cache
// keeps, not about what validates.
@(private = "file")
sized_key :: proc(size: int, flags := u16(DNSKEY_FLAG_ZONE), protocol := u8(3)) -> Dnskey {
	rdata := make([]u8, size, context.temp_allocator)
	rdata[0] = u8(flags >> 8)
	rdata[1] = u8(flags)
	rdata[2] = protocol
	rdata[3] = ALG_RSASHA256
	for i in 4 ..< size {
		rdata[i] = u8(i)
	}
	key, err := parse_dnskey(rdata)
	if err != .None {
		panic("the fixture does not parse")
	}
	return key
}

// What the cache is actually holding for one zone, which is the number the
// bound has to be expressed in. A zone that is not cached holds nothing.
@(private = "file")
cached_key_bytes :: proc(v: ^Validator, zone: string) -> int {
	entry, found := v.zones[zone]
	if !found {
		return 0
	}
	total := 0
	for key in entry.keys {
		total += len(key.rdata)
	}
	return total
}

/*
One zone cannot take an unbounded share of the cache.

`fetch_keys` admits `MAX_KEYS_PER_ZONE` records and the RSA parser reads a
modulus of `MAX_MODULUS_BYTES`, so what a single apex could hand the cache was
bounded only by what fits in a DNS message. Multiply that by
`DEFAULT_MAX_CACHED_ZONES` and the cache alone is larger than the machines this
runs on.
*/
@(test)
test_one_zone_cannot_fill_the_cache_by_itself :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	// The worst set the rest of the validator will admit: as many keys as a
	// zone may publish, each as large as the RSA parser will read.
	huge := make([dynamic]Dnskey, 0, MAX_KEYS_PER_ZONE, context.temp_allocator)
	for _ in 0 ..< MAX_KEYS_PER_ZONE {
		append(&huge, sized_key(4 + MAX_MODULUS_BYTES + MAX_EXPONENT_BYTES))
	}
	cache_put(v, "flood.example.", .Secure, huge[:], MAX_ZONE_TTL, cache_now())

	held := cached_key_bytes(v, "flood.example.")
	testing.expectf(
		t,
		held <= MAX_CACHED_ZONE_KEY_BYTES,
		"one zone put %d bytes of keys in the cache; the bound is %d",
		held,
		MAX_CACHED_ZONE_KEY_BYTES,
	)
	free_all(context.temp_allocator)
}

// And the bound is not so tight that an ordinary apex stops being cached. A
// zone mid-rollover publishes a handful of keys; every one of them stays.
@(test)
test_an_ordinary_apex_is_still_cached_whole :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	// Four RSA-2048 keys, which is more than any real zone carries at once.
	ordinary := make([dynamic]Dnskey, 0, 4, context.temp_allocator)
	for _ in 0 ..< 4 {
		append(&ordinary, sized_key(4 + 256 + 3))
	}
	cache_put(v, "example.com.", .Secure, ordinary[:], MAX_ZONE_TTL, cache_now())

	entry, found := v.zones["example.com."]
	testing.expect(t, found, "an ordinary apex should be cached")
	if found {
		testing.expectf(t, len(entry.keys) == 4, "kept %d of 4 ordinary keys", len(entry.keys))
	}
	free_all(context.temp_allocator)
}

/*
A key that cannot sign anything is not worth the room.

`key_usable` is what every verification path already filters on - a key without
the zone bit, one revoked under RFC 5011, or one whose protocol field is not 3
is skipped wherever a signature is checked. Copying them into the cache holds
memory for keys nothing will ever look at, and lets a zone pad its own entry
with records that do not have to be real keys at all.
*/
@(test)
test_the_cache_keeps_only_keys_that_could_sign :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	good := sized_key(4 + 256)
	set := []Dnskey {
		good,
		// No zone bit: RFC 4034 says it signs no zone data.
		sized_key(4 + 256, flags = 0),
		// Revoked (RFC 5011).
		sized_key(4 + 256, flags = DNSKEY_FLAG_ZONE | DNSKEY_FLAG_REVOKE),
		// Protocol is fixed at 3; anything else is not a DNSSEC key.
		sized_key(4 + 256, protocol = 4),
	}
	cache_put(v, "example.com.", .Secure, set, MAX_ZONE_TTL, cache_now())

	entry, found := v.zones["example.com."]
	testing.expect(t, found, "the zone should have been cached")
	if !found {
		return
	}
	testing.expectf(t, len(entry.keys) == 1, "cached %d keys; only one of the four can sign", len(entry.keys))
	for key, i in entry.keys {
		testing.expectf(t, key_usable(key), "cached key %d cannot sign anything", i)
	}
	free_all(context.temp_allocator)
}

/*
The root's keys survive a flood of zones nobody else asked for.

This is the half of the issue that costs every other client rather than the
server: a full cache used to be emptied wholesale, so a client cycling
`max_cached_zones` names of its own threw out the root and every TLD beside it,
and every question in flight went back to walking from the top.

The root is touched here the way a walk touches it - `zone_keys` reads it from
the cache at the start of every chain - so under any eviction that prefers what
is being used, it is the last thing to go rather than collateral.
*/
@(test)
test_a_flood_of_fresh_zones_does_not_evict_the_root :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{max_cached_zones = 16})
	defer destroy_validator(v)

	now := cache_now()
	root_keys := []Dnskey{sized_key(4 + 256)}
	cache_put(v, ".", .Secure, root_keys, MAX_ZONE_TTL, now)

	for i in 0 ..< 64 {
		// What every walk does before it descends, and what makes the root the
		// most recently used entry there is.
		_, found, _ := cache_get(v, ".", now, context.temp_allocator)
		testing.expectf(t, found, "the root left the cache after %d fresh zones", i)
		if !found {
			return
		}
		zone := fmt.tprintf("z%d.example.", i)
		cache_put(v, zone, .Secure, root_keys, MAX_ZONE_TTL, now)
	}

	_, found, _ := cache_get(v, ".", now, context.temp_allocator)
	testing.expect(t, found, "the root should have outlived a flood of single-use zones")
	testing.expectf(t, len(v.zones) <= 16, "the cache holds %d zones against a bound of 16", len(v.zones))
	free_all(context.temp_allocator)
}

/*
A full cache drops one zone, and it drops the one nobody has asked for.

The wholesale flush made the cost of overflowing the cache fall on every zone in
it; what makes room now is the entry at the cold end of the list.
*/
@(test)
test_a_full_cache_evicts_the_least_recently_used_zone :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{max_cached_zones = 3})
	defer destroy_validator(v)

	now := cache_now()
	keys := []Dnskey{sized_key(4 + 256)}
	for zone in ([]string{"a.example.", "b.example.", "c.example."}) {
		cache_put(v, zone, .Secure, keys, MAX_ZONE_TTL, now)
	}

	// `a` is used again, so `b` becomes the coldest entry.
	_, a_found, _ := cache_get(v, "a.example.", now, context.temp_allocator)
	testing.expect(t, a_found, "a.example. should still be cached")

	cache_put(v, "d.example.", .Secure, keys, MAX_ZONE_TTL, now)

	testing.expectf(t, len(v.zones) == 3, "the cache holds %d zones against a bound of 3", len(v.zones))
	_, still_a := v.zones["a.example."]
	_, still_b := v.zones["b.example."]
	_, still_c := v.zones["c.example."]
	_, still_d := v.zones["d.example."]
	testing.expect(t, still_a, "a.example. was used most recently and should have stayed")
	testing.expect(t, !still_b, "b.example. was the coldest entry and should have gone")
	testing.expect(t, still_c, "c.example. should have stayed")
	testing.expect(t, still_d, "d.example. was just inserted and should be there")
	free_all(context.temp_allocator)
}

/*
Replacing a zone's entry does not leave a second one behind.

The replace path hands the map's own key string to the new entry and frees the
old one; with an eviction order to maintain as well, the old entry has to leave
that too or the list ends up pointing at freed memory - and the count the bound
is read from ends up counting entries that are gone.
*/
@(test)
test_refreshing_a_zone_keeps_the_cache_consistent :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{max_cached_zones = 4})
	defer destroy_validator(v)

	now := cache_now()
	keys := []Dnskey{sized_key(4 + 256)}
	for _ in 0 ..< 10 {
		cache_put(v, "example.com.", .Secure, keys, MAX_ZONE_TTL, now)
	}
	testing.expectf(t, len(v.zones) == 1, "ten refreshes of one zone left %d entries", len(v.zones))

	// The list has to still be walkable end to end and hold exactly what the
	// map does, or the next eviction reads something that has been freed.
	cache_put(v, "other.example.", .Secure, keys, MAX_ZONE_TTL, now)
	count := 0
	for e := v.lru_head; e != nil; e = e.next {
		count += 1
		testing.expectf(t, count <= 8, "the eviction list loops or outlives its entries")
		if count > 8 {
			break
		}
	}
	testing.expectf(t, count == len(v.zones), "the eviction list holds %d entries, the map %d", count, len(v.zones))
	free_all(context.temp_allocator)
}

/*
A swept entry leaves the eviction order with it.

`sweep` deletes expired zones straight out of the map. An entry freed there but
left linked is a dangling pointer the next eviction follows.
*/
@(test)
test_sweeping_an_expired_zone_leaves_the_eviction_order_intact :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{max_cached_zones = 4})
	defer destroy_validator(v)

	now := cache_now()
	keys := []Dnskey{sized_key(4 + 256)}
	cache_put(v, "a.example.", .Secure, keys, MIN_ZONE_TTL, now)
	cache_put(v, "b.example.", .Secure, keys, MIN_ZONE_TTL, now)

	later := time.time_add(now, time.Duration(MIN_ZONE_TTL + 1) * time.Second)
	removed := sweep(v, later)
	testing.expectf(t, removed == 2, "swept %d of 2 expired zones", removed)

	count := 0
	for e := v.lru_head; e != nil; e = e.next {
		count += 1
		if count > 8 {
			break
		}
	}
	testing.expectf(t, count == 0, "the eviction list still holds %d swept entries", count)

	// And the cache still works afterwards.
	cache_put(v, "c.example.", .Secure, keys, MAX_ZONE_TTL, later)
	_, found, _ := cache_get(v, "c.example.", later, context.temp_allocator)
	testing.expect(t, found, "the cache should still take entries after a sweep")
	free_all(context.temp_allocator)
}

/*
An oversized reply does not take a good entry with it.

The set already held was validated and has a lifetime of its own. Dropping it to
make way for one the cache then refuses would turn the byte cap into a way of
clearing a zone's keys - reachable only by whoever owns the zone, since a set
reaches `cache_put` as `.Secure` only after the parent's DS and the zone's own
signature have both held, but a cache that loses entries over a reply it did not
store is the wrong shape whoever can reach it.
*/
@(test)
test_an_oversized_key_set_does_not_drop_the_one_already_held :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	now := cache_now()
	good := []Dnskey{sized_key(4 + 256)}
	cache_put(v, "example.com.", .Secure, good, MAX_ZONE_TTL, now)

	huge := make([dynamic]Dnskey, 0, MAX_KEYS_PER_ZONE, context.temp_allocator)
	for _ in 0 ..< MAX_KEYS_PER_ZONE {
		append(&huge, sized_key(4 + MAX_MODULUS_BYTES + MAX_EXPONENT_BYTES))
	}
	cache_put(v, "example.com.", .Secure, huge[:], MAX_ZONE_TTL, now)

	entry, found := v.zones["example.com."]
	testing.expect(t, found, "the validated entry should have survived an oversized reply")
	if found {
		testing.expectf(t, len(entry.keys) == 1, "the entry holds %d keys rather than the one it was given", len(entry.keys))
	}
	held := cached_key_bytes(v, "example.com.")
	testing.expectf(t, held <= MAX_CACHED_ZONE_KEY_BYTES, "the entry grew to %d bytes", held)
	free_all(context.temp_allocator)
}

/*
And a name the cache declines is still settled as a zone.

`cache_put` drops the non-cut memo for the name it is storing, because the memo
says "no delegation here" and a DNSKEY set says there is one. Leaving it behind
on the path that stores nothing would let the walk keep skipping the cut for as
long as `MAX_NON_CUT_TTL` - which refuses every signature the zone makes, and,
where the parent's own denial covers the names inside the child, lets a forged
denial for one of them be proven against the parent's keys.
*/
@(test)
test_an_oversized_key_set_still_settles_the_name :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	now := cache_now()
	non_cut_remember(v, "example.com.", MIN_ZONE_TTL, now)
	_, _, remembered := cache_get(v, "example.com.", now, context.temp_allocator)
	testing.expect(t, remembered, "the memo should hold the name to begin with")

	huge := make([dynamic]Dnskey, 0, MAX_KEYS_PER_ZONE, context.temp_allocator)
	for _ in 0 ..< MAX_KEYS_PER_ZONE {
		append(&huge, sized_key(4 + MAX_MODULUS_BYTES + MAX_EXPONENT_BYTES))
	}
	cache_put(v, "example.com.", .Secure, huge[:], MAX_ZONE_TTL, now)

	_, _, still_remembered := cache_get(v, "example.com.", now, context.temp_allocator)
	testing.expect(t, !still_remembered, "a name settled as a zone is no longer a remembered non-cut")
	free_all(context.temp_allocator)
}

/*
The default is the validator's, so nothing has to keep two numbers in step.

`Options.max_cached_zones` is what the configuration passes, and the
configuration's own default is zero rather than a figure of its own - see
`Dnssec_Config.max_cached_zones`. That only holds if zero here means the
built-in number.
*/
@(test)
test_an_unset_zone_cache_bound_takes_the_default :: proc(t: ^testing.T) {
	unset := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(unset)
	testing.expect_value(t, unset.max_cached_zones, DEFAULT_MAX_CACHED_ZONES)

	// And a figure somebody wrote is the figure they get.
	named := make_validator(no_upstream, nil, Options{max_cached_zones = 64})
	defer destroy_validator(named)
	testing.expect_value(t, named.max_cached_zones, 64)

	// A number that cannot be a bound is not one more way of asking for the
	// default by accident - the loader refuses it - but the validator must not
	// build a cache of zero entries out of one either.
	negative := make_validator(no_upstream, nil, Options{max_cached_zones = -1})
	defer destroy_validator(negative)
	testing.expect_value(t, negative.max_cached_zones, DEFAULT_MAX_CACHED_ZONES)
}

/*
A cache of one still works, and still holds the entry that is being used.

The smallest bound is where an off-by-one in the eviction loop shows: at one,
every insert has to evict before it stores, and a loop that ran one time too few
would grow the cache while a loop that ran one too many would empty it and then
store into nothing.
*/
@(test)
test_a_cache_of_one_zone_holds_exactly_one :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{max_cached_zones = 1})
	defer destroy_validator(v)

	now := cache_now()
	keys := []Dnskey{sized_key(4 + 256)}
	for i in 0 ..< 8 {
		cache_put(v, fmt.tprintf("z%d.example.", i), .Secure, keys, MAX_ZONE_TTL, now)
		testing.expectf(t, len(v.zones) == 1, "after %d inserts the cache holds %d zones, not 1", i + 1, len(v.zones))
	}

	// The last one in is the one held, and it is readable.
	entry, found, _ := cache_get(v, "z7.example.", now, context.temp_allocator)
	testing.expect(t, found, "the most recent zone should be the one still cached")
	if found {
		testing.expectf(t, len(entry.keys) == 1, "the surviving entry holds %d keys", len(entry.keys))
	}
	_, stale, _ := cache_get(v, "z0.example.", now, context.temp_allocator)
	testing.expect(t, !stale, "the first zone should have been evicted long ago")

	// The list has to agree with the map at the extreme too.
	count := 0
	for e := v.lru_head; e != nil; e = e.next {
		count += 1
		if count > 4 {
			break
		}
	}
	testing.expectf(t, count == 1, "the eviction list holds %d entries against a map of 1", count)
	free_all(context.temp_allocator)
}

// And the refusals are counted, because a zone that cannot be cached is walked
// again on every question and nothing else would say so.
@(test)
test_a_refused_key_set_is_counted :: proc(t: ^testing.T) {
	v := make_validator(no_upstream, nil, Options{})
	defer destroy_validator(v)

	testing.expect_value(t, oversized_key_sets(v), 0)

	huge := make([dynamic]Dnskey, 0, MAX_KEYS_PER_ZONE, context.temp_allocator)
	for _ in 0 ..< MAX_KEYS_PER_ZONE {
		append(&huge, sized_key(4 + MAX_MODULUS_BYTES + MAX_EXPONENT_BYTES))
	}
	cache_put(v, "flood.example.", .Secure, huge[:], MAX_ZONE_TTL, cache_now())
	testing.expect_value(t, oversized_key_sets(v), 1)

	// An ordinary set does not touch it.
	cache_put(v, "example.com.", .Secure, []Dnskey{sized_key(4 + 256)}, MAX_ZONE_TTL, cache_now())
	testing.expect_value(t, oversized_key_sets(v), 1)
	free_all(context.temp_allocator)
}
