package dnssec

import "core:testing"
import "elodin:dns"

/*
RFC 8145 5.1's own examples: a root anchor of tag 17476 is `_ta-4444`, a tag
of 999 is padded to `03e7`, and three anchors for example.com sort smallest
first into `_ta-0635-7aae-aa1b.example.com.`.
*/
@(test)
test_the_key_tag_query_name_is_rfc_8145s :: proc(t: ^testing.T) {
	Case :: struct {
		zone: string,
		tags: []u16,
		want: string,
	}
	cases := []Case {
		{zone = ".", tags = {17476}, want = "_ta-4444."},
		{zone = ".", tags = {999}, want = "_ta-03e7."},
		{zone = "example.com.", tags = {1589, 31406, 43547}, want = "_ta-0635-7aae-aa1b.example.com."},
	}
	for c in cases {
		got, ok := key_tag_query_name(c.zone, c.tags, context.temp_allocator)
		testing.expectf(t, ok && got == c.want, "%v under %q: %q (ok %v), want %q", c.tags, c.zone, got, ok, c.want)
	}
	free_all(context.temp_allocator)
}

// A name DNS cannot carry, or no tags at all, is no Key Tag query (RFC 8145 1.1).
@(test)
test_a_key_tag_query_name_that_does_not_fit_is_refused :: proc(t: ^testing.T) {
	too_many := make([]u16, MAX_KEY_TAGS + 1, context.temp_allocator)
	for &tag, i in too_many {
		tag = u16(i)
	}
	_, label_fits := key_tag_query_name(".", too_many, context.temp_allocator)
	testing.expect(t, !label_fits, "a `_ta-` label past 63 octets was built")
	_, at_limit := key_tag_query_name(".", too_many[:MAX_KEY_TAGS], context.temp_allocator)
	testing.expect(t, at_limit, "the most tags a label holds were refused")

	// Three labels of 63 octets and one of 55 are 249 octets on the wire, a
	// zone DNS can name; `_ta-0001` puts 9 more in front, 258.
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	long := concat(label, ".", label, ".", label, ".", label[:55], ".")
	wire: [256]u8
	_, zone_err := dns.encode_name(long, wire[:])
	testing.expectf(t, zone_err == .None, "the premise: the zone is a name DNS can carry (%v)", zone_err)
	_, name_fits := key_tag_query_name(long, []u16{1}, context.temp_allocator)
	testing.expect(t, !name_fits, "a Key Tag query name past 255 octets was built")

	_, none := key_tag_query_name(".", nil, context.temp_allocator)
	testing.expect(t, !none, "a Key Tag query name was built with no tags")
	free_all(context.temp_allocator)
}

@(private = "file")
concat :: proc(parts: ..string) -> string {
	n := 0
	for p in parts {
		n += len(p)
	}
	out := make([]u8, n, context.temp_allocator)
	at := 0
	for p in parts {
		at += copy(out[at:], p)
	}
	return string(out)
}

// The tags signalled for a zone are its anchors', sorted, each once; none for
// a zone no anchor is for.
@(test)
test_anchor_key_tags_are_sorted_and_unique :: proc(t: ^testing.T) {
	anchors := []Trust_Anchor {
		{zone = "example.", ds = {key_tag = 43547}},
		{zone = ".", ds = {key_tag = 20326}},
		{zone = "EXAMPLE.", ds = {key_tag = 1589}},
		{zone = "example.", ds = {key_tag = 43547, digest_type = DIGEST_SHA256}},
	}
	v := Validator {
		anchors = anchors,
	}
	got := anchor_key_tags(&v, "example.", context.temp_allocator)
	testing.expectf(t, len(got) == 2 && got[0] == 1589 && got[1] == 43547, "example.'s tags are %v, want [1589, 43547]", got)
	testing.expectf(t, len(anchor_key_tags(&v, "other.", context.temp_allocator)) == 0, "a zone with no anchor has tags")
	free_all(context.temp_allocator)
}
