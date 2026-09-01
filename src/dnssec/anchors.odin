package dnssec

import "core:strconv"
import "core:strings"
import "elodin:dns"

/*
Trust anchors.

Validation has to start somewhere that was not learned from the DNS. The two
entries below are the root zone key-signing keys IANA publishes at
https://data.iana.org/root-anchors/root-anchors.xml, as DS records: KSK-2017,
in use since February 2017, and KSK-2024, published in July 2024 against the
rollover to come.

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
		if strings.equal_fold(field, "DS") {
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

	key_tag, tag_ok := strconv.parse_uint(fields[start], 10)
	algorithm, alg_ok := strconv.parse_uint(fields[start + 1], 10)
	digest_type, dt_ok := strconv.parse_uint(fields[start + 2], 10)
	if !tag_ok || !alg_ok || !dt_ok || key_tag > 0xffff || algorithm > 0xff || digest_type > 0xff {
		return {}, false
	}

	joined := strings.concatenate(fields[start + 3:], context.temp_allocator)
	digest, digest_ok := decode_hex(joined, allocator)
	if !digest_ok || len(digest) == 0 {
		return {}, false
	}
	if len(digest) != digest_size(u8(digest_type)) && digest_supported(u8(digest_type)) {
		return {}, false
	}

	return Trust_Anchor {
			zone = dns.name_canonical(zone, allocator),
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

@(private)
decode_hex :: proc(text: string, allocator := context.allocator) -> (out: []u8, ok: bool) {
	if len(text) % 2 != 0 {
		return nil, false
	}
	buf := make([]u8, len(text) / 2, allocator)
	for i := 0; i < len(text); i += 2 {
		hi, hi_ok := hex_value(text[i])
		lo, lo_ok := hex_value(text[i + 1])
		if !hi_ok || !lo_ok {
			delete(buf, allocator)
			return nil, false
		}
		buf[i / 2] = hi << 4 | lo
	}
	return buf, true
}

@(private)
hex_value :: proc(c: u8) -> (v: u8, ok: bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
