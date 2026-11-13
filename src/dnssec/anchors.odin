package dnssec

import "core:encoding/hex"
import "core:strings"
import "elodin:dns"
import "elodin:netx"

/*
Trust anchors.

Validation has to start somewhere that was not learned from the DNS. The two
entries below are the root zone key-signing keys IANA publishes at
https://data.iana.org/root-anchors/root-anchors.xml, as DS records: KSK-2017,
in use since February 2017, and KSK-2024, published in July 2024 ahead of the
rollover that replaces its predecessor.

Both are carried because a rollover replaces one with the other without warning
a resolver: whichever key the root is signing with on the day, one of these
matches it. Anyone who would rather pin their own can replace the set from the
configuration file.
*/

@(private)
ROOT_KSK_2017_DIGEST := []u8 {
	0xe0, 0x6d, 0x44, 0xb8, 0x0b, 0x8f, 0x1d, 0x39, 0xa9, 0x5c, 0x0b, 0x0d, 0x7c, 0x65, 0xd0, 0x84,
	0x58, 0xe8, 0x80, 0x40, 0x9b, 0xbc, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xc7, 0xf8, 0xec, 0x8d,
}

@(private)
ROOT_KSK_2024_DIGEST := []u8 {
	0x68, 0x3d, 0x2d, 0x0a, 0xcb, 0x8c, 0x9b, 0x71, 0x2a, 0x19, 0x48, 0xb2, 0x7f, 0x74, 0x12, 0x19,
	0x29, 0x8d, 0x0a, 0x45, 0x0d, 0x61, 0x2c, 0x48, 0x3a, 0xf4, 0x44, 0xa4, 0xc0, 0xfb, 0x2b, 0x16,
}

@(private)
ROOT_ANCHORS := []Trust_Anchor {
	{zone = ".", ds = {key_tag = 20326, algorithm = ALG_RSASHA256, digest_type = DIGEST_SHA256, digest = ROOT_KSK_2017_DIGEST}},
	{zone = ".", ds = {key_tag = 38696, algorithm = ALG_RSASHA256, digest_type = DIGEST_SHA256, digest = ROOT_KSK_2024_DIGEST}},
}

root_anchors :: proc() -> []Trust_Anchor {
	return ROOT_ANCHORS
}

/*
Is there an anchor for `zone` here that this build can follow?

An anchor names an algorithm and a digest, and `fetch_keys` can only follow one
it can check - so a zone whose every anchor names something `probe_algorithms`
dropped has no anchor at all, and is an insecure delegation the moment it is
asked about.

A chain starts at the closest anchor above the name (`closest_anchor`), so
every anchored zone is a starting point and each is asked about: an anchor
below the root that cannot be followed leaves its zone insecure, and one for
the root leaves every name outside the operator's own zones insecure.
*/
usable_anchor :: proc(anchors: []Trust_Anchor, zone: string) -> bool {
	for anchor in anchors {
		if !dns.name_equal_fold(anchor.zone, zone) {
			continue
		}
		if ds_usable(anchor.ds) {
			return true
		}
	}
	return false
}

// The first anchored zone none of whose anchors this build can follow. An
// operator anchors a zone to have it validated, and an anchor `fetch_keys`
// cannot check serves the zone insecure instead.
unfollowable_anchor_zone :: proc(anchors: []Trust_Anchor) -> (zone: string, found: bool) {
	for anchor in anchors {
		if !usable_anchor(anchors, anchor.zone) {
			return anchor.zone, true
		}
	}
	return "", false
}

/*
The anchored zone a chain to `name` starts at: the deepest one at or above it,
RFC 6840 Appendix C.1. The root when nothing closer is anchored, whether or not
the root is - `zone_keys` then finds no anchor, which is `Indeterminate`.
*/
closest_anchor :: proc(anchors: []Trust_Anchor, name: string) -> string {
	closest := "."
	for anchor in anchors {
		if dns.name_at_or_below(name, anchor.zone) && label_count(anchor.zone) > label_count(closest) {
			closest = anchor.zone
		}
	}
	return closest
}

// Is any of this set an anchor for the root at all, followable or not? What
// separates "the crypto policy took the root anchor away" from "nobody
// anchored the root", which are different things to tell an operator.
anchors_the_root :: proc(anchors: []Trust_Anchor) -> bool {
	for anchor in anchors {
		if dns.name_equal_fold(anchor.zone, ".") {
			return true
		}
	}
	return false
}

/*
Read a trust anchor from a line of configuration.

Both the bare fields and a full presentation-form DS record are accepted, so an
anchor can be pasted straight out of `dig`:

	20326 8 2 E06D44B8...
	. IN DS 20326 8 2 E06D44B8...

A digest split across several whitespace-separated groups is joined back up,
which is how the long ones are usually written.
*/
parse_trust_anchor :: proc(text: string, allocator := context.allocator) -> (anchor: Trust_Anchor, ok: bool) {
	fields := strings.fields(text, context.temp_allocator)
	if len(fields) < 4 {
		return {}, false
	}

	zone := "."
	start := 0
	for field, i in fields {
		if dns.name_equal_fold(field, "DS") {
			if i > 0 {
				zone = fields[0]
			}
			start = i + 1
			break
		}
	}
	if len(fields) - start < 4 {
		return {}, false
	}

	key_tag, tag_ok := netx.parse_decimal(fields[start], 0xffff)
	algorithm, alg_ok := netx.parse_decimal(fields[start + 1], 0xff)
	digest_type, dt_ok := netx.parse_decimal(fields[start + 2], 0xff)
	if !tag_ok || !alg_ok || !dt_ok {
		return {}, false
	}

	joined := strings.concatenate(fields[start + 3:], context.temp_allocator)
	digest, digest_ok := decode_hex(joined, allocator)
	// `decode_hex` frees its own failure; every refusal after it frees what it kept.
	defer if !ok {
		delete(digest, allocator)
	}
	if !digest_ok || len(digest) == 0 {
		return {}, false
	}
	/*
	`digest_size` rather than `digest_supported`: this is a length check on a
	digest type we recognise, and `digest_supported` also answers for what the
	local crypto policy will compute. Reading it here would
	make the same anchor line parse or fail depending on when it was parsed -
	`--check` runs before the probe, `start_validator` after it - over a
	question that has nothing to do with the policy.
	*/
	if len(digest) != digest_size(u8(digest_type)) && digest_size(u8(digest_type)) != 0 {
		return {}, false
	}

	canonical := dns.name_canonical(zone, allocator) or_return
	return Trust_Anchor {
			zone = canonical,
			ds = Ds {
				key_tag = u16(key_tag),
				algorithm = u8(algorithm),
				digest_type = u8(digest_type),
				digest = digest,
			},
		},
		true
}

/*
Release what `parse_trust_anchor` allocated: the canonical zone name and the
digest.

For parsed anchors only. `root_anchors` hands back static storage, and a
`Validator` borrows whichever set it was given rather than owning it - see
`destroy_validator`, which deliberately leaves `anchors` alone because it cannot
tell the two apart. So whoever parsed them frees them.
*/
destroy_trust_anchor :: proc(anchor: Trust_Anchor, allocator := context.allocator) {
	delete(anchor.ds.digest, allocator)
	delete(anchor.zone, allocator)
}

// `hex.decode`, which hands back the buffer it allocated on a bad digit as well
// as on success, so the caller would have to know to free a failure.
@(private)
decode_hex :: proc(text: string, allocator := context.allocator) -> (out: []u8, ok: bool) {
	out, ok = hex.decode(transmute([]u8)text, allocator)
	if !ok {
		delete(out, allocator)
		return nil, false
	}
	return
}
