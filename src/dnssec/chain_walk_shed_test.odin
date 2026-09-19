package dnssec

import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:dns"

/*
Issue #356: the chain walk blocks the thread that is answering the client, and
nothing bounded how many threads could be doing that at once.

`zone_trust` descends from the apex asking a DS per label, and each step that
misses both caches is an upstream round trip taken in line - up to
`MAX_LOOKUPS_PER_QUERY` of them for one client question. #349's memo takes a
*repeated* run down to one walk per name, but a client that varies a label near
the apex makes every name below it fresh by construction and misses the memo the
whole way down, however often it asks. No cache closes that; the note on
`MAX_CACHED_NON_CUTS` has the argument, and a bound on the run itself was tried
in #349 and reverted because deployed `ip6.arpa.` zones sit deeper than the walk
an attacker needs.

So what is bounded here is not the walk but the number of them in flight. The
first test is the reproduction: without a bound, every thread that asks is a
thread parked on the walk's first round trip at the same moment.

The two after it are the other half of the bargain - that a walk turned away
still reads its caches, and that being turned away is `Indeterminate` and never
a downgrade to `Insecure`, which would make load shedding into a way of
stripping a zone's signatures.
*/

/*
An upstream that never answers, counting how many walks are waiting on it at
once.

Never, until the test says so: that is what makes the count below a fact rather
than a race. A walk that takes a slot is still holding it when the last walker
has been turned away, so exactly `max_chain_walks` of them reach this and every
other one is shed - whatever order the threads happen to start in.
*/
@(private = "file")
Slow_Upstream :: struct {
	mu:       sync.Mutex,
	in_fli:   int,
	peak:     int,
	calls:    int,
	released: bool,
}

@(private = "file")
slow_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	u := cast(^Slow_Upstream)ctx
	sync.mutex_lock(&u.mu)
	u.in_fli += 1
	u.calls += 1
	if u.in_fli > u.peak {
		u.peak = u.in_fli
	}
	sync.mutex_unlock(&u.mu)

	for !sync.atomic_load(&u.released) {
		time.sleep(time.Millisecond)
	}

	sync.mutex_lock(&u.mu)
	u.in_fli -= 1
	sync.mutex_unlock(&u.mu)
	// Nothing came back, which is where a walk that reached the upstream and
	// waited ends up. What this measures is the waiting, not the answer.
	return nil, false
}

@(private = "file")
Walker :: struct {
	v:      ^Validator,
	status: Status,
	reason: string,
	done:   bool,
}

@(private = "file")
walk_once :: proc(w: ^Walker) {
	budget := query_budget(w.v)
	status, _, _ := zone_trust(
		w.v,
		&budget,
		"a.b.c.example.com.",
		time.unix(FIXTURE_TIME, 0),
		context.temp_allocator,
	)
	w.status = status
	w.reason = walk_reason(&budget)
	free_all(context.temp_allocator)
	sync.atomic_store(&w.done, true)
}

/*
Eight clients ask at once, and the server will walk two chains upstream.

Without the bound all eight are blocked on the upstream at the same moment -
which on a real server is eight handler threads, each held for as many round
trips as the question has labels, and the whole of #356. With it, two are, and
the other six are told the chain could not be reached without having held
anything. Unfixed, the six never finish while the upstream is silent, so the wait
below runs out and says so.
*/
@(test)
test_only_so_many_chain_walks_block_at_once :: proc(t: ^testing.T) {
	SLOTS :: 2
	WALKERS :: 8

	up := Slow_Upstream{}
	v := make_validator(slow_query, &up, Options{max_chain_walks = SLOTS})
	defer destroy_validator(v)

	walkers: [WALKERS]Walker
	threads: [WALKERS]^thread.Thread
	for i in 0 ..< WALKERS {
		walkers[i].v = v
		threads[i] = thread.create_and_start_with_poly_data(&walkers[i], walk_once)
	}

	// The walks that found no slot should come back while the upstream is still
	// silent. Waiting for them is the measurement: unfixed, they are queued
	// behind it instead and none of them does.
	finished := 0
	start := time.now()
	for time.since(start) < 10 * time.Second {
		finished = 0
		for i in 0 ..< WALKERS {
			if sync.atomic_load(&walkers[i].done) {
				finished += 1
			}
		}
		if finished >= WALKERS - SLOTS {
			break
		}
		time.sleep(time.Millisecond)
	}

	sync.mutex_lock(&up.mu)
	peak := up.peak
	calls := up.calls
	sync.mutex_unlock(&up.mu)

	// Let the two that took a slot go, so the threads can be joined whatever the
	// result above was.
	sync.atomic_store(&up.released, true)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	testing.expectf(
		t,
		finished == WALKERS - SLOTS,
		"%d of %d walks should have come back while the upstream was silent, %d did: the walk is unbounded and #356 is open",
		WALKERS - SLOTS,
		WALKERS,
		finished,
	)
	testing.expectf(t, peak <= SLOTS, "at most %d walks should have been upstream at once, %d were", SLOTS, peak)
	// And the ones turned away really were turned away, rather than queued
	// behind the flood and let through a moment later.
	testing.expectf(t, calls == SLOTS, "only the walks that took a slot should reach the upstream, %d did", calls)

	shed := 0
	for w in walkers {
		testing.expect_value(t, w.status, Status.Indeterminate)
		if w.reason == WALKS_IN_FLIGHT {
			shed += 1
		}
	}
	testing.expectf(t, shed == WALKERS - SLOTS, "%d walks should say so in their own words, %d did", WALKERS - SLOTS, shed)
	testing.expect_value(t, walks_shed(v), u64(WALKERS - SLOTS))
}

/*
A walk with no slot still answers out of the cache.

This is what keeps the bound from being a second denial of service. The zones a
resolver answers for all day are cached, and a question about one of them needs
no round trip at all - so a flood holding every slot must not stop it being
answered, and must not cost it its AD bit either.
*/
@(test)
test_a_shed_walk_still_answers_from_the_cache :: proc(t: ^testing.T) {
	up := Slow_Upstream{}
	// One slot, and the test holds it for the whole of the walk below.
	v := make_validator(slow_query, &up, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	// A chain already in the cache, put there the way a first question would.
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "com.", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "example.com.", .Secure, keys, MAX_ZONE_TTL, now)

	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	defer drop_walk_slot(v)

	budget := query_budget(v)
	status, _, established := zone_trust(v, &budget, "example.com.", now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, established, "example.com.")

	sync.mutex_lock(&up.mu)
	calls := up.calls
	sync.mutex_unlock(&up.mu)
	testing.expectf(t, calls == 0, "a cached chain should ask nobody, it asked %d times", calls)
	free_all(context.temp_allocator)
}

/*
And a shed walk that cannot be answered from the cache says it could not reach
the chain - it does not say the zone is unsigned.

`Insecure` here would be load shedding stripping a zone's signatures, which is
the attacker's goal rather than the defence's. `Bogus` would be almost as bad in
the other direction: an accusation of forgery this server has no evidence for,
and one that a resolver downstream may cache.
*/
@(test)
test_a_shed_walk_is_never_a_downgrade :: proc(t: ^testing.T) {
	up := Slow_Upstream{}
	v := make_validator(slow_query, &up, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	defer drop_walk_slot(v)

	budget := query_budget(v)
	status, _, _ := zone_trust(v, &budget, "nothing.cached.example.", now, context.temp_allocator)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect_value(t, walk_reason(&budget), WALKS_IN_FLIGHT)

	sync.mutex_lock(&up.mu)
	calls := up.calls
	sync.mutex_unlock(&up.mu)
	testing.expectf(t, calls == 0, "a shed walk should reach no upstream, it reached one %d times", calls)
	free_all(context.temp_allocator)
}
