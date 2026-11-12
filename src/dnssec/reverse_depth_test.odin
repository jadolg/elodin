package dnssec

import "core:fmt"
import "core:strings"
import "core:testing"
import "elodin:dns"

/*
Issue #352: the chain walk must not refuse a name for having many labels, since
a full IPv6 reverse name has more of them than `MAX_CHAIN_DEPTH` allows cuts.

`MAX_CHAIN_DEPTH` bounds a delegation hierarchy - zone cuts - and `zone_trust`
spends it on cuts, not on `label_count(name)`. A reverse name for an IPv6
address is one nibble per label: thirty-two of them, plus `ip6` and `arpa`, so
thirty-four against a bound of twenty-four. Spent on labels, every such name
would be `Indeterminate` before a single DS was asked for, and `Indeterminate`
is SERVFAIL with EDE 22. The client-facing paths that reach the walk with the
question's own name rather than a signer's are `validate_denial` - every
NXDOMAIN and NODATA, which is most of IPv6 reverse space - and
`validate_rrset`'s fallback owner walk, so with validation on a resolver would
answer essentially no IPv6 reverse lookup. IPv4 reverse names are six labels
and never reach the bound, which is why such a mistake would hide.

What actually bounds the work is elsewhere: `MAX_LOOKUPS_PER_QUERY` for the
round trips, `MAX_NSEC3_ROUNDS_PER_QUERY` for the hashing,
`MAX_VERIFICATIONS_PER_QUERY` for the signature checks, and the wire format
itself for the label count - a name is 255 octets and a label costs two, so
nothing can carry more than 127.
*/

// The upstream is a `Counting_Upstream` with no fixtures: it answers nothing and
// counts what it was asked. A walk that refused the name on its label count
// would ask it nothing, deciding against the name rather than against anything
// the chain said.

// The eleven empty non-terminals between `ip6.arpa.` and `R6_APEX`.
@(private = "file")
ip6_non_cuts :: proc() -> []string {
	names := make([]string, 11, context.temp_allocator)
	for &name, i in names {
		name = name_drop_labels(R6_QNAME, 34 - 2 - (i + 1))
	}
	return names
}

// 127 labels of one character: the longest name the wire format carries.
@(private = "file")
longest_name :: proc() -> string {
	b := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< 127 {
		strings.write_string(&b, "a.")
	}
	return strings.to_string(b)
}

// Every suffix of `longest_name()` below the root, the name itself first: the
// names the longest walk has to rule out.
@(private = "file")
longest_suffixes :: proc() -> []string {
	longest := longest_name()
	names := make([]string, 127, context.temp_allocator)
	for &name, i in names {
		name = name_drop_labels(longest, i)
	}
	return names
}

/*
The tests below seed the non-cut table with seed 0 and remember a run of names
in it, assuming each name keeps its own slot: a collision would evict one
mid-walk and change the verdict (issue #362). This holds them to it, so a seed
or name change that collides fails here rather than flaking there.
*/
@(test)
test_reverse_depth_names_do_not_collide_in_non_cut_table :: proc(t: ^testing.T) {
	v := make_validator(counting_query, nil, Options{})
	defer destroy_validator(v)
	v.non_cut_seed = 0

	expect_distinct_non_cut_slots(t, v, ip6_non_cuts())
	expect_distinct_non_cut_slots(t, v, longest_suffixes())
	free_all(context.temp_allocator)
}

/*
The walk asks about an IPv6 reverse name rather than refusing it for its length.

With the root primed and secure, a walk that gets as far as its first DS lookup
has accepted the name; one that comes back having asked nobody anything has
refused it on the label count alone. The upstream here answers nothing, so the
verdict is `Indeterminate` either way - what separates the two is whether a
question was asked at all.
*/
@(test)
test_an_ipv6_reverse_name_reaches_the_chain :: proc(t: ^testing.T) {
	testing.expect_value(t, label_count(R6_QNAME), 34)
	testing.expect(
		t,
		label_count(R6_QNAME) > MAX_CHAIN_DEPTH,
		"this test is only worth anything while a reverse name has more labels than the bound",
	)

	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	now := fixture_now()
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, fixture_moment(now))

	budget := query_budget(v)
	zone_trust(v, &budget, R6_QNAME, now, context.temp_allocator)
	testing.expectf(
		t,
		up.calls > 0,
		"the walk refused %q without asking anybody about it",
		R6_QNAME,
	)
	testing.expect_value(t, up.first, "arpa.")
	free_all(context.temp_allocator)
}

/*
And the same walk, when the chain below the root is there to be walked: it
establishes the deepest zone rather than falling back to the root.

`arpa.`, `ip6.arpa.` and the /32 the address sits in are secure in the cache,
and the label below that zone's apex is a name the upstream will not answer
about - so the walk has to have descended fourteen labels to be sitting on the
right zone when it stops. A walk bounded on labels would never leave `.`.
*/
@(test)
test_an_ipv6_reverse_walk_settles_on_the_deepest_cached_zone :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	// A fixed seed makes the non-cut table deterministic, and with it the 11
	// names below are held to distinct slots by the test above.
	v.non_cut_seed = 0
	defer destroy_validator(v)

	now := fixture_now()
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))
	cache_put(v, "arpa.", .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))
	cache_put(v, "ip6.arpa.", .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))
	// Every empty non-terminal between `ip6.arpa.` and the apex is a name the
	// walk has to rule out, and a cached non-cut is how it does that for free.
	for name in ip6_non_cuts() {
		non_cut_remember(v, name, MAX_ZONE_TTL, fixture_moment(now))
	}
	apex := name_drop_labels(R6_QNAME, 34 - 14)
	testing.expect_value(t, apex, R6_APEX)
	cache_put(v, apex, .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))

	budget := query_budget(v)
	status, _, established := zone_trust(v, &budget, R6_QNAME, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expectf(
		t,
		established == apex || established == name_drop_labels(R6_QNAME, 34 - 15),
		"the walk stopped at %q rather than below the /32 it had keys for",
		established,
	)
	free_all(context.temp_allocator)
}

/*
`MAX_CHAIN_DEPTH` still bounds what it names: zone cuts.

A chain of secure zones one label apart, every one of them in the cache so that
no lookup allowance runs out first, is the shape the bound is about - and past
it the walk gives up rather than keeps descending. `Indeterminate` and not
`Insecure`: a bound of this server's running out is this server saying it did
not finish, never that the zone below is unsigned.
*/
@(test)
test_a_hierarchy_deeper_than_the_bound_is_still_refused :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	now := fixture_now()
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))

	// One cut per label, `MAX_CHAIN_DEPTH` of them and then one more.
	name := "."
	for i in 0 ..< MAX_CHAIN_DEPTH + 1 {
		name = fmt.tprintf("z%d.%s", i, name if name != "." else "")
		cache_put(v, name, .Secure, keys, MAX_ZONE_TTL, fixture_moment(now))
	}
	testing.expect_value(t, label_count(name), MAX_CHAIN_DEPTH + 1)

	budget := query_budget(v)
	status, _, _ := zone_trust(v, &budget, name, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expectf(t, up.calls == 0, "a cached chain should need no upstream, it asked %d times", up.calls)

	// And one cut short of the bound is walked to the end.
	shorter := name_drop_labels(name, 2)
	testing.expect_value(t, label_count(shorter), MAX_CHAIN_DEPTH - 1)
	budget = query_budget(v)
	ok_status, _, established := zone_trust(v, &budget, shorter, now, context.temp_allocator)
	testing.expect_value(t, ok_status, Status.Secure)
	testing.expect_value(t, established, shorter)
	free_all(context.temp_allocator)
}

/*
And the longest name the wire format can carry is walked rather than refused,
and walked to the end.

A name is 255 octets and a label costs two of them - a length byte and a
character - so 127 labels is the most anything can reach the walk with, whatever
a client asks and whatever an upstream puts in an owner or a signer. That is
what bounds the walk's label loop, and it is worth pinning: a name built to be
long is exactly what an attacker would send at a walk with no label bound of
its own.

Every label is remembered as a non-cut, so the walk costs no lookup and the test
measures the walk rather than an allowance running out in front of it.
*/
@(test)
test_the_longest_name_the_wire_allows_is_walked_to_the_end :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	// A fixed seed makes the non-cut table deterministic, and with it the 127
	// suffixes below are held to distinct slots by the test above.
	v.non_cut_seed = 0
	defer destroy_validator(v)

	now := fixture_now()
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, fixture_moment(now))

	longest := longest_name()
	testing.expect_value(t, label_count(longest), 127)
	// 127 labels of one character, plus the root: the 255 octets a name gets.
	testing.expect_value(t, len(longest) + 1, dns.MAX_NAME_WIRE)

	for name in longest_suffixes() {
		non_cut_remember(v, name, MAX_ZONE_TTL, fixture_moment(now))
	}

	budget := query_budget(v)
	status, _, established := zone_trust(v, &budget, longest, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, established, ".")
	testing.expectf(t, up.calls == 0, "every label was remembered, so nothing should have been asked; %d were", up.calls)
	free_all(context.temp_allocator)
}
