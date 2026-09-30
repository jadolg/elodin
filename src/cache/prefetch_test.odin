package cache

import "core:testing"
import "core:time"

/*
Put an entry stored with `lifetime` seconds of TTL, `left` of which remain.

Written straight onto the entry, as `sync_expire` does, so the window is reached
without sleeping through the lifetime that leads up to it.
*/
@(private = "file")
age_into :: proc(c: ^Cache, key: string, lifetime: u32, left: time.Duration) -> bool {
	wire, msg := build_answer("prefetch.example.", lifetime, context.temp_allocator)
	if !put(c, key, wire, msg) {
		return false
	}
	e := c.entries[key]
	e.expires = time.time_add(time.now(), left)
	e.inserted = time.time_add(e.expires, -time.Duration(lifetime) * time.Second)
	return true
}

@(private = "file")
prefetch_cache :: proc(min_ttl: u32 = 9) -> ^Cache {
	return make_cache(Options{max_entries = 8, max_ttl = 86400, prefetch = true, prefetch_min_ttl = min_ttl})
}

/*
A hit in the last tenth of an entry's lifetime is handed the refresh, and the
hits before it are not (issue #468).

With a 600-second entry the window is the last sixty seconds, so a name asked
every fifteen seconds is certain to land in it - which is the case the rule was
chosen for. A hit with seventy seconds left is outside it.
*/
@(test)
test_prefetch_is_claimed_inside_the_last_tenth :: proc(t: ^testing.T) {
	c := prefetch_cache()
	defer destroy(c)

	testing.expect(t, age_into(c, "early", 600, 70 * time.Second), "the entry was not stored")
	_, early, got := get(c, "early", context.temp_allocator, prefetch = true)
	testing.expect(t, got, "the entry was not found")
	testing.expect(t, !early.prefetch, "an entry with 70s of 600 left was handed its refresh")

	testing.expect(t, age_into(c, "late", 600, 50 * time.Second), "the entry was not stored")
	_, late, _ := get(c, "late", context.temp_allocator, prefetch = true)
	testing.expect(t, late.prefetch, "an entry with 50s of 600 left was not handed its refresh")
	free_all(context.temp_allocator)
}

/*
The claim is the entry's one chance: the hit that gets it and nothing after.

That is the guard against an upstream that is failing. The refresh it started
left the entry where it was, still inside its window, and without the claim
every hit until expiry would start another - an upstream query per client
query. The answer a refresh does bring back is a new entry, whose own window
has its own claim.
*/
@(test)
test_prefetch_is_claimed_once_per_entry :: proc(t: ^testing.T) {
	c := prefetch_cache()
	defer destroy(c)

	testing.expect(t, age_into(c, "k", 600, 30 * time.Second), "the entry was not stored")
	_, first, _ := get(c, "k", context.temp_allocator, prefetch = true)
	_, second, _ := get(c, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, first.prefetch, "the first hit in the window was not handed the refresh")
	testing.expect(t, !second.prefetch, "a second hit was handed the refresh the first one already had")

	// Replaced, as a refresh that worked replaces it: the claim is the new entry's.
	testing.expect(t, age_into(c, "k", 600, 30 * time.Second), "the entry was not replaced")
	_, renewed_hit, _ := get(c, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, renewed_hit.prefetch, "a replaced entry kept the old one's claim")
	free_all(context.temp_allocator)
}

/*
Nothing is claimed by a lookup that would not act on it, or by one the cache is
not set up to answer that way.

A caller that leaves `prefetch` off - a follower of a query in flight, a probe
for a verdict - would spend the entry's one claim on a refresh nobody starts. An
entry stored with less than `prefetch_min_ttl` is left to expire, and `0` makes
every entry eligible. `prefetch: false` claims nothing at all, and neither does
an expired entry: that is `serve_stale`'s refresh, not this one.
*/
@(test)
test_prefetch_is_claimed_only_where_asked_and_eligible :: proc(t: ^testing.T) {
	c := prefetch_cache(min_ttl = 60)
	defer destroy(c)

	testing.expect(t, age_into(c, "unasked", 600, 1 * time.Second), "the entry was not stored")
	_, unasked, _ := get(c, "unasked", context.temp_allocator)
	testing.expect(t, !unasked.prefetch, "a lookup that did not ask was handed the refresh")
	_, asked, _ := get(c, "unasked", context.temp_allocator, prefetch = true)
	testing.expect(t, asked.prefetch, "the lookup that did not ask spent the entry's claim")

	testing.expect(t, age_into(c, "short", 59, 1 * time.Second), "the entry was not stored")
	_, short, _ := get(c, "short", context.temp_allocator, prefetch = true)
	testing.expect(t, !short.prefetch, "an entry below prefetch_min_ttl was handed the refresh")

	testing.expect(t, age_into(c, "at", 60, 1 * time.Second), "the entry was not stored")
	_, at, _ := get(c, "at", context.temp_allocator, prefetch = true)
	testing.expect(t, at.prefetch, "an entry at prefetch_min_ttl was not handed the refresh")

	every := prefetch_cache(min_ttl = 0)
	defer destroy(every)
	testing.expect(t, age_into(every, "tiny", 1, 50 * time.Millisecond), "the entry was not stored")
	_, tiny, _ := get(every, "tiny", context.temp_allocator, prefetch = true)
	testing.expect(t, tiny.prefetch, "prefetch_min_ttl: 0 left a one-second entry out")

	off := make_cache(Options{max_entries = 8, max_ttl = 86400, prefetch = false})
	defer destroy(off)
	testing.expect(t, age_into(off, "k", 600, 1 * time.Second), "the entry was not stored")
	_, disabled, _ := get(off, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, !disabled.prefetch, "prefetch: false handed out a refresh")

	stale := make_cache(Options{max_entries = 8, max_ttl = 86400, prefetch = true, serve_stale = true})
	defer destroy(stale)
	testing.expect(t, age_into(stale, "k", 600, -1 * time.Second), "the entry was not stored")
	_, expired, found := get(stale, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, found && expired.stale, "the expired entry was not lent")
	testing.expect(t, !expired.prefetch, "an expired entry was handed a prefetch")
	free_all(context.temp_allocator)
}

// `renewed` is what says a prefetch worked: a different entry under the key.
@(test)
test_renewed_reads_the_entry_not_the_answer :: proc(t: ^testing.T) {
	c := prefetch_cache()
	defer destroy(c)

	testing.expect(t, age_into(c, "k", 600, 30 * time.Second), "the entry was not stored")
	_, hit, _ := get(c, "k", context.temp_allocator)
	testing.expect(t, !renewed(c, "k", hit.serial), "the entry that was looked at reads as renewed")
	testing.expect(t, age_into(c, "k", 600, 600 * time.Second), "the entry was not replaced")
	testing.expect(t, renewed(c, "k", hit.serial), "a replaced entry reads as not renewed")
	testing.expect(t, !renewed(c, "gone", hit.serial), "a key with no entry reads as renewed")
	free_all(context.temp_allocator)
}

/*
A renewal that ends when the old entry would have keeps the old entry's spent
claim, and does not read as renewed.

That is what an upstream that is itself a cache hands a prefetch: its copy
counted down with ours, so the answer carries the seconds ours had left. Given a
claim of its own, the new entry would be refreshed again in its last tenth, for
the same instant, and again - upstream queries that buy nothing, counted as
successes. A renewal that does end later is a new entry with its own claim.
*/
@(test)
test_a_renewal_that_ends_no_later_keeps_the_spent_claim :: proc(t: ^testing.T) {
	c := prefetch_cache()
	defer destroy(c)

	testing.expect(t, age_into(c, "k", 600, 30 * time.Second), "the entry was not stored")
	_, claimed, _ := get(c, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, claimed.prefetch, "the entry was not handed its refresh")

	// The upstream's counted-down copy: thirty seconds, the time ours had left.
	wire, msg := build_answer("prefetch.example.", 30, context.temp_allocator)
	testing.expect(t, put(c, "k", wire, msg), "the renewal was not stored")
	testing.expect(t, !renewed(c, "k", claimed.serial), "a renewal ending at the old expiry reads as renewed")
	c.entries["k"].inserted = time.time_add(time.now(), -28 * time.Second)
	c.entries["k"].expires = time.time_add(time.now(), 2 * time.Second)
	_, again, _ := get(c, "k", context.temp_allocator, prefetch = true)
	testing.expect(t, !again.prefetch, "a renewal that did not extend the entry was handed another refresh")

	// A renewal that does end later is a new entry, with its own claim.
	full, full_msg := build_answer("prefetch.example.", 600, context.temp_allocator)
	_, spent, _ := get(c, "k", context.temp_allocator)
	testing.expect(t, put(c, "k", full, full_msg), "the renewal was not stored")
	testing.expect(t, renewed(c, "k", spent.serial), "a renewal that extended the entry reads as not renewed")
	free_all(context.temp_allocator)
}
