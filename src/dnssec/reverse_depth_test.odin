package dnssec

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #352: the chain walk refused a name for having too many labels, and a
full IPv6 reverse name has more of them than the bound allowed.

`MAX_CHAIN_DEPTH` says in its own comment that it bounds a delegation
hierarchy - zone cuts - and `zone_trust` spent it on `label_count(name)`
instead. A reverse name for an IPv6 address is one nibble per label: thirty-two
of them, plus `ip6` and `arpa`, so thirty-four against a bound of twenty-four.
Every such name was `Indeterminate` before a single DS was asked for, and
`Indeterminate` is SERVFAIL with EDE 22. The client-facing paths that reach the
walk with the question's own name rather than a signer's are `validate_denial` -
every NXDOMAIN and NODATA, which is most of IPv6 reverse space - and
`validate_rrset`'s fallback owner walk, so with validation on a resolver
answered essentially no IPv6 reverse lookup. IPv4 reverse names are six labels
and were never affected, which is why this hid.

What actually bounds the work is elsewhere and was all along:
`MAX_LOOKUPS_PER_QUERY` for the round trips, `MAX_NSEC3_ROUNDS_PER_QUERY` for
the hashing, `MAX_VERIFICATIONS_PER_QUERY` for the signature checks, and the
wire format itself for the label count - a name is 255 octets and a label costs
two, so nothing can carry more than 127. The bound here is back on what it says
it bounds.
*/

// The reverse name of 2001:4860:4860::8888, from the issue: thirty-two nibble
// labels under `ip6.arpa.`
@(private = "file")
IP6_PTR :: "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa."

// An upstream that answers nothing and counts what it was asked. Nothing is
// asked of it before the fix, which is the whole of the bug: the walk decided
// against the name rather than against anything the chain said.
@(private = "file")
Counting_Upstream :: struct {
	calls: int,
	first: string,
}

@(private = "file")
counting_query :: proc(
	ctx: rawptr,
	name: string,
	type: dns.Type,
	allocator: mem.Allocator,
) -> (
	wire: []u8,
	ok: bool,
) {
	u := cast(^Counting_Upstream)ctx
	u.calls += 1
	if u.first == "" {
		u.first = strings.clone(name, context.allocator)
	}
	return nil, false
}

/*
The walk asks about an IPv6 reverse name rather than refusing it for its length.

With the root primed and secure, a walk that gets as far as its first DS lookup
has accepted the name; one that comes back having asked nobody anything has
refused it on the label count alone. The upstream here answers nothing, so the
verdict is `Indeterminate` either way - what separates the bug from the fix is
whether a question was asked at all.
*/
@(test)
test_an_ipv6_reverse_name_reaches_the_chain :: proc(t: ^testing.T) {
	testing.expect_value(t, label_count(IP6_PTR), 34)
	testing.expect(
		t,
		label_count(IP6_PTR) > MAX_CHAIN_DEPTH,
		"this test is only worth anything while a reverse name has more labels than the bound",
	)

	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, now)

	budget := query_budget(v)
	zone_trust(v, &budget, IP6_PTR, now, context.temp_allocator)
	testing.expectf(
		t,
		up.calls > 0,
		"the walk refused %q without asking anybody about it",
		IP6_PTR,
	)
	testing.expect_value(t, up.first, "arpa.")
	delete(up.first)
	free_all(context.temp_allocator)
}

/*
And the same walk, when the chain below the root is there to be walked: it
establishes the deepest zone rather than falling back to the root.

`arpa.`, `ip6.arpa.` and the /32 the address sits in are secure in the cache,
and the label below that zone's apex is a name the upstream will not answer
about - so the walk has to have descended fourteen labels to be sitting on the
right zone when it stops. Before the fix it never left `.`.
*/
@(test)
test_an_ipv6_reverse_walk_settles_on_the_deepest_cached_zone :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "arpa.", .Secure, keys, MAX_ZONE_TTL, now)
	cache_put(v, "ip6.arpa.", .Secure, keys, MAX_ZONE_TTL, now)
	// Every empty non-terminal between `ip6.arpa.` and the apex is a name the
	// walk has to rule out, and a cached non-cut is how it does that for free.
	for i in 1 ..= 11 {
		non_cut_remember(v, name_drop_labels(IP6_PTR, 34 - 2 - i), MAX_ZONE_TTL, now)
	}
	apex := name_drop_labels(IP6_PTR, 34 - 14)
	testing.expect_value(t, apex, "0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa.")
	cache_put(v, apex, .Secure, keys, MAX_ZONE_TTL, now)

	budget := query_budget(v)
	status, _, established := zone_trust(v, &budget, IP6_PTR, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Indeterminate)
	testing.expectf(
		t,
		established == apex || established == name_drop_labels(IP6_PTR, 34 - 15),
		"the walk stopped at %q rather than below the /32 it had keys for",
		established,
	)
	delete(up.first)
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

	now := time.unix(FIXTURE_TIME, 0)
	keys := []Dnskey{}
	cache_put(v, ".", .Secure, keys, MAX_ZONE_TTL, now)

	// One cut per label, `MAX_CHAIN_DEPTH` of them and then one more.
	name := "."
	for i in 0 ..< MAX_CHAIN_DEPTH + 1 {
		name = fmt.tprintf("z%d.%s", i, name if name != "." else "")
		cache_put(v, name, .Secure, keys, MAX_ZONE_TTL, now)
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
	delete(up.first)
	free_all(context.temp_allocator)
}

/*
And the longest name the wire format can carry is walked rather than refused,
and walked to the end.

A name is 255 octets and a label costs two of them - a length byte and a
character - so 127 labels is the most anything can reach the walk with, whatever
a client asks and whatever an upstream puts in an owner or a signer. That is
what stands in for the label bound this walk used to keep, and it is worth
pinning: it is the number the loop below is really bounded by now, and a name
built to be long is exactly what an attacker would send at a walk that lost its
own limit.

Every label is remembered as a non-cut, so the walk costs no lookup and the test
measures the walk rather than an allowance running out in front of it.
*/
@(test)
test_the_longest_name_the_wire_allows_is_walked_to_the_end :: proc(t: ^testing.T) {
	up := Counting_Upstream{}
	v := make_validator(counting_query, &up, Options{})
	defer destroy_validator(v)

	now := time.unix(FIXTURE_TIME, 0)
	cache_put(v, ".", .Secure, []Dnskey{}, MAX_ZONE_TTL, now)

	b := strings.builder_make(context.temp_allocator)
	for _ in 0 ..< 127 {
		strings.write_string(&b, "a.")
	}
	longest := strings.to_string(b)
	testing.expect_value(t, label_count(longest), 127)
	// 127 labels of one character, plus the root: the 255 octets a name gets.
	testing.expect_value(t, len(longest) + 1, dns.MAX_NAME_WIRE)

	for i in 0 ..< 127 {
		non_cut_remember(v, name_drop_labels(longest, i), MAX_ZONE_TTL, now)
	}

	budget := query_budget(v)
	status, _, established := zone_trust(v, &budget, longest, now, context.temp_allocator)
	testing.expect_value(t, status, Status.Secure)
	testing.expect_value(t, established, ".")
	testing.expectf(t, up.calls == 0, "every label was remembered, so nothing should have been asked; %d were", up.calls)
	delete(up.first)
	free_all(context.temp_allocator)
}
