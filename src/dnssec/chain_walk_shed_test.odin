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

The rest are the other half of the bargain, and the third of them is there
because the second reads better than the truth. A walk turned away still reads
its caches, so a chain both caches answer is unaffected - but a cached apex is
not a cached name, and a hostname below one still costs a DS per label. Both
shapes are pinned, so what a flood costs is written down rather than implied.

Last, that being turned away is `Indeterminate` and never a downgrade to
`Insecure`, which would make load shedding into a way of stripping a zone's
signatures.
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
	calls := 0
	peak := 0
	start := time.now()
	for time.since(start) < 10 * time.Second {
		finished = 0
		for i in 0 ..< WALKERS {
			if sync.atomic_load(&walkers[i].done) {
				finished += 1
			}
		}
		sync.mutex_lock(&up.mu)
		peak = up.peak
		calls = up.calls
		sync.mutex_unlock(&up.mu)
		/*
		Both, not just the first. A walk that takes a slot has raised
		`Validator.walks` before it reaches the upstream - there is a
		`spend_lookup`, an encode and a call in between - so a loop that stopped
		as soon as the losers were counted could read `calls` while a winner was
		still on its way to the mutex, and fail on a loaded box for no reason.
		The upstream is silent until this loop is done, so waiting for both
		cannot deadlock on anything but the bug.
		*/
		if finished >= WALKERS - SLOTS && calls >= SLOTS {
			break
		}
		time.sleep(time.Millisecond)
	}

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
A walk that needs no lookup is not affected by the bound at all.

This is what keeps the bound from being a second denial of service, and it is
why the slot is taken at the first upstream lookup rather than on the way into
the walk: a question a warm cache answers must neither be refused while every
slot is held nor take a slot other walks need - and must not move `walks_shed`,
which an operator reads as the flood's own number.
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
	// The count, not the budget's flag: `zone_trust` clears that on the way out
	// whether or not a slot was taken, so it reads false either way. One is the
	// slot this test is holding itself, and a walk that took a second would
	// have made it two.
	testing.expect_value(t, sync.atomic_load(&v.walks), 1)
	testing.expect_value(t, walks_shed(v), u64(0))
	free_all(context.temp_allocator)
}

/*
And a name *below* a warm apex is not a warm name: while every slot is held, it
stops.

The walk has to rule out a zone cut at every label, so `www.example.com.` costs
a DS lookup even with `example.com.` cached and secure - only the non-cut memo
makes that free, and a name nobody has asked for before is not in it. So a flood
holding every slot does reach past its own names into ordinary traffic, which is
the trade #356 asks for and is worth a test of its own rather than a sentence
somebody has to believe.
*/
@(test)
test_a_shed_walk_below_a_warm_apex_still_stops :: proc(t: ^testing.T) {
	up := Slow_Upstream{}
	v := make_validator(slow_query, &up, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "com.", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "example.com.", .Secure, keys, MAX_ZONE_TTL, now)

	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	defer drop_walk_slot(v)

	budget := query_budget(v)
	status, _, _ := zone_trust(v, &budget, "www.example.com.", now, context.temp_allocator)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect_value(t, walk_reason(&budget), WALKS_IN_FLIGHT)
	// This one is the flood's cost and belongs in the number an operator reads.
	testing.expect_value(t, walks_shed(v), u64(1))

	sync.mutex_lock(&up.mu)
	calls := up.calls
	sync.mutex_unlock(&up.mu)
	testing.expectf(t, calls == 0, "a shed walk should reach no upstream, it reached one %d times", calls)
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

// Answers from the captured set, so the chain below is the real one.
@(private = "file")
captured_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			out, decoded := decode_hex(f.wire, allocator)
			return out, decoded
		}
	}
	return nil, false
}

/*
A signature this server never looked at must not come back as a forgery.

The one shape of this bound that could accuse a zone, and it arrives by the back
door. `validate_rrset` walks to each signature's signer and skips the signature
when the walk does not reach it, then settles what the failure *means* by
walking to the owner - and the signer's chain is a prefix of the owner's, so a
slot freeing in between is all it takes for the second walk to succeed where the
first did not. Nothing verified, the zone is signed, and the answer is `Bogus`:
EDE 6, "DNSSEC Bogus", for a set whose only signature was never tried.

The interval is a race on a running server and is made explicit here - the walk
is shed while the test holds the only slot, and the slot is given back before
the set is judged, which is the same sequence with the timing taken out. The
signature is a fabricated one so that nothing verifies and the tail is reached;
what is on trial is the verdict, not the cryptography.
*/
@(test)
test_a_walk_this_server_shed_is_not_called_a_forgery :: proc(t: ^testing.T) {
	v := make_validator(captured_query, nil, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	unix := u32(FIXTURE_TIME)
	budget := query_budget(v)

	// A flood holds the only slot, and this query's signer walk is turned away.
	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	shed_status, _, _ := zone_trust(v, &budget, "cloudflare.com.", now, context.temp_allocator)
	testing.expect_value(t, shed_status, Status.Indeterminate)
	testing.expect_value(t, walk_reason(&budget), WALKS_IN_FLIGHT)
	testing.expect(t, budget.shed_walk, "the budget should remember that a walk was turned away")

	// The flood ebbs, so the walk to the owner below finds a slot and succeeds.
	drop_walk_slot(v)

	records := []dns.Record {
		{name = "cloudflare.com.", type = .A, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = {0xc0, 0xa8, 0x00, 0x01}}},
	}
	sigs := []Rrsig {
		{
			type_covered = .A,
			algorithm = ALG_ECDSAP256SHA256,
			labels = 2,
			original_ttl = 300,
			inception = unix - 3600,
			expiration = unix + 3600,
			key_tag = 34505,
			signer = "cloudflare.com.",
			signature = make([]u8, 64, context.temp_allocator),
		},
	}

	status, _, reason, _, _ := validate_rrset(
		v,
		&budget,
		"cloudflare.com.",
		.A,
		.IN,
		records,
		sigs,
		unix,
		now,
		context.temp_allocator,
	)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect_value(t, reason, WALKS_IN_FLIGHT)
	free_all(context.temp_allocator)
}

/*
And a shed walk cannot tell an unsigned zone from a signed one, so it refuses
that too.

The half of the blast radius that is easiest to miss. `zone_step` reaches
`.Insecure` only by asking for the DS and reading a proof that there is no
delegation, so a walk with no slot has no way to say "this name is in an
unsigned zone, forward the answer". It says `Indeterminate`, and the client gets
SERVFAIL for a name that has nothing to do with DNSSEC at all.

Which makes the real cost of a full table "every cold name", not "every cold
signed name" - the thing an operator sizing `dnssec.max_chain_walks` has to know,
and the reason the bound reserves workers rather than capping them.
*/
@(test)
test_a_shed_walk_cannot_tell_an_unsigned_zone_from_a_signed_one :: proc(t: ^testing.T) {
	up := Slow_Upstream{}
	v := make_validator(captured_query, nil, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	// The chain above the name is known and signed; what is not known is
	// whether anything is delegated below it, which is the DS lookup.
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "com.", .Secure, keys, MAX_ZONE_TTL, now)

	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	defer drop_walk_slot(v)

	budget := query_budget(v)
	status, _, _ := zone_trust(v, &budget, "unsigned.example.com.", now, context.temp_allocator)
	// Not `.Insecure`, which is the answer that would have been forwarded.
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect_value(t, walk_reason(&budget), WALKS_IN_FLIGHT)

	sync.mutex_lock(&up.mu)
	calls := up.calls
	sync.mutex_unlock(&up.mu)
	testing.expectf(t, calls == 0, "a shed walk should reach no upstream, it reached one %d times", calls)
	free_all(context.temp_allocator)
}

/*
A question answered on its own connection thread is never turned away.

TCP, DoT and HTTP/1.1 answer on the connection's thread rather than on a worker
of the shared pool - `max_connections` is what bounds them - so a walk there
holds nothing anybody else is waiting for, and the bound has no business
refusing it. Without this, a hundred DoT clients asking cold names on a
sixteen-worker box would have had most of them refused with no attacker present
at all.
*/
@(test)
test_a_query_on_its_own_thread_is_never_shed :: proc(t: ^testing.T) {
	up := Slow_Upstream{}
	v := make_validator(slow_query, &up, Options{max_chain_walks = 1})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	// Every slot taken, which is the flood at its worst.
	testing.expect(t, take_walk_slot(v), "the one slot should be free")
	defer drop_walk_slot(v)

	budget := query_budget(v)
	budget.own_thread = true
	// Released before the walk, so this reaches the upstream rather than
	// waiting on it: what is on trial is whether it was allowed to ask at all.
	sync.atomic_store(&up.released, true)
	status, _, _ := zone_trust(v, &budget, "a.b.c.example.com.", now, context.temp_allocator)

	sync.mutex_lock(&up.mu)
	calls := up.calls
	sync.mutex_unlock(&up.mu)
	testing.expectf(t, calls > 0, "the walk should have reached the upstream, it asked %d times", calls)
	// The upstream answered nothing, so the walk ends there - but it ends
	// having asked, and saying so, rather than refused for want of a slot.
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expect(t, walk_reason(&budget) != WALKS_IN_FLIGHT, "a query on its own thread should never be shed")
	testing.expect_value(t, walks_shed(v), u64(0))
	free_all(context.temp_allocator)
}
