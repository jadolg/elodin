package dnssec

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"
import "elodin:loop"

// Issue #337: a signature's validity allows for a signer whose clock runs ahead
// of ours, and an RRset it verified is never served or kept longer than it says.

@(private = "file")
st_fixture :: proc(key: string) -> []u8 {
	for f in FIXTURES {
		if f.key == key {
			return unhex(f.wire)
		}
	}
	return nil
}

@(private = "file")
st_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, _: ^time.Tick) -> (wire: []u8, ok: bool) {
	for f in FIXTURES {
		if f.type == type && dns.name_equal_fold(f.name, name) {
			return unhex(f.wire, allocator), true
		}
	}
	return nil, false
}

// The first RRSIG in a captured reply.
@(private = "file")
first_sig :: proc(key: string) -> Rrsig {
	msg, _ := dns.decode_message(st_fixture(key), context.temp_allocator)
	for section in ([][]dns.Record{msg.answer, msg.authority}) {
		for rec in section {
			if rec.type != .RRSIG {
				continue
			}
			rdata, _ := raw_rdata(rec)
			sig, err := parse_rrsig(rdata, context.temp_allocator)
			if err == .None {
				return sig
			}
		}
	}
	return {}
}

@(test)
test_signature_inception_skew :: proc(t: ^testing.T) {
	now := u32(1_785_664_800)
	sig := Rrsig {
		inception  = now + 30,
		expiration = now + 30 * 86400,
	}
	testing.expect(t, signature_current(sig, now), "a signature minted 30 s in our future is rejected")
	sig.inception = now + SIG_INCEPTION_SKEW
	testing.expect(t, signature_current(sig, now), "an inception at the edge of the skew is rejected")
	sig.inception = now + SIG_INCEPTION_SKEW + 1
	testing.expect(t, !signature_current(sig, now), "an inception past the skew is accepted")

	// No skew on the far end: that would be a replay window for a signature
	// its zone has stopped publishing.
	lapsed := Rrsig {
		inception  = now - 86400,
		expiration = now - 1,
	}
	testing.expect(t, !signature_current(lapsed, now), "a lapsed signature is accepted")

	// Nor may the skew admit a window that ends before it begins.
	backwards := Rrsig {
		inception  = now + 60,
		expiration = now + 30,
	}
	testing.expect(t, !signature_current(backwards, now), "an expiration before the inception is accepted")
}

@(test)
test_signed_ttl_ceiling :: proc(t: ^testing.T) {
	now := u32(1_785_664_800)
	sig := Rrsig {
		original_ttl = 300,
		inception    = now - 86400,
		expiration   = now + 86400,
	}
	testing.expect_value(t, signed_ttl_ceiling(sig, now), u32(300))
	sig.expiration = now + 100
	testing.expect_value(t, signed_ttl_ceiling(sig, now), u32(100))
	sig.expiration = now
	testing.expect_value(t, signed_ttl_ceiling(sig, now), u32(0))
	// Across the 2106 wrap the difference is still the serial one.
	sig.expiration = 50
	testing.expect_value(t, signed_ttl_ceiling(sig, max(u32) - 49), u32(100))
}

/*
RFC 4035 section 5.3.3: an authenticated RRset, and its RRSIG, go out with a TTL
no greater than the RRSIG's Original TTL or the time left before it expires. The
TTL fields themselves are unsigned, so an on-path attacker raising them still
validates - the clamp is what keeps a signed answer from outliving its word.
*/
@(test)
test_served_ttl_is_clamped_to_the_signature :: proc(t: ^testing.T) {
	v := make_validator(st_query, nil, Options{})
	defer destroy_validator(v)

	msg, derr := dns.decode_message(st_fixture("example_a"), context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	original := max(u32)
	for &rec in msg.answer {
		if rec.type == .RRSIG {
			rdata, _ := raw_rdata(rec)
			sig, _ := parse_rrsig(rdata, context.temp_allocator)
			original = min(original, sig.original_ttl)
		}
		rec.ttl = 604800
	}
	raised, _, _ := dns.encode_message(msg, context.temp_allocator)

	// Once with a signature that has hours left, where the Original TTL binds,
	// and once a hundred seconds before it lapses, where the expiration does.
	// Nothing else in the chain lapses before this one.
	last := first_sig("example_a").expiration
	cases := []struct {
		at:      u32,
		ceiling: u32,
	}{{FIXTURE_TIME, original}, {last - 100, min(original, 100)}}
	for c in cases {
		result := validate(v, "www.example.com.", .A, raised, time.unix(i64(c.at), 0))
		testing.expectf(t, result.status == .Secure, "at %d the raised answer is %v (%s)", c.at, result.status, result.reason)
		out, ok := strip_unauthenticated(raised, result)
		testing.expect(t, ok, "the prune failed")
		served, _ := dns.decode_message(out, context.temp_allocator)
		testing.expect(t, len(served.answer) >= 2, "the answer lost its records")
		for rec in served.answer {
			testing.expectf(t, rec.ttl <= c.ceiling, "at %d %v went out with TTL %d over a ceiling of %d", c.at, rec.type, rec.ttl, c.ceiling)
		}
	}
	free_all(context.temp_allocator)
}

// A TTL already under the ceiling is the one the records carry, untouched.
@(test)
test_served_ttl_under_the_ceiling_is_kept :: proc(t: ^testing.T) {
	v := make_validator(st_query, nil, Options{})
	defer destroy_validator(v)
	msg, _ := dns.decode_message(st_fixture("example_a"), context.temp_allocator)
	for &rec in msg.answer {
		rec.ttl = 7
	}
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	result := validate(v, "www.example.com.", .A, wire, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)
	out, _ := strip_unauthenticated(wire, result)
	served, _ := dns.decode_message(out, context.temp_allocator)
	for rec in served.answer {
		testing.expect_value(t, rec.ttl, u32(7))
	}
	free_all(context.temp_allocator)
}

/*
A question asked a fraction of a second past a whole one: every signature's lapse
is counted in whole seconds from the one `now` falls in, so the zone cache is
timed from that second as well, and no key outlives its signature by the
fraction. The same walk at the whole second is the yardstick: the one 0.9 s past
it must hold `example.com.`'s keys 0.9 s less.
*/
@(test)
test_zone_keys_are_timed_from_the_whole_second :: proc(t: ^testing.T) {
	// How long the entry is held, bounded both ways by the moments either
	// side of the walk.
	held :: proc(t: ^testing.T, now: time.Time) -> (least, most: time.Duration, ok: bool) {
		v := make_validator(st_query, nil, Options{})
		defer destroy_validator(v)
		before := loop.moment_now()
		result := validate(v, "www.example.com.", .A, st_fixture("example_a"), now)
		after := loop.moment_now()
		testing.expect_value(t, result.status, Status.Secure)
		entry, found := v.zones["example.com."]
		if !testing.expect(t, found, "example.com. was not cached") {
			return
		}
		return time.Duration(entry.expires - after), time.Duration(entry.expires - before), true
	}
	_, whole, whole_ok := held(t, time.unix(FIXTURE_TIME, 0))
	part, _, part_ok := held(t, time.unix(FIXTURE_TIME, i64(900 * time.Millisecond)))
	if whole_ok && part_ok {
		testing.expectf(t, part <= whole - 900 * time.Millisecond, "held %v from 0.9 s past the second, %v from the second itself", part, whole)
	}
	free_all(context.temp_allocator)
}

/*
The same section, for the records the chain walk keeps: a zone's keys are held
no longer than the DS and DNSKEY signatures that vouched for them. Each zone is
walked to a hundred seconds before the first of those lapses - the root's own
DNSKEY signature, `com.`'s DNSKEY one, `example.com.`'s DS - and must not be
kept past it, which the hour `MAX_ZONE_TTL` would otherwise allow.
*/
@(test)
test_zone_keys_do_not_outlive_their_signatures :: proc(t: ^testing.T) {
	cases := []struct {
		zone:  string,
		bound: string,
	}{{".", "root_dnskey"}, {"com.", "com_dnskey"}, {"example.com.", "example_ds"}}
	for c in cases {
		v := make_validator(st_query, nil, Options{})
		defer destroy_validator(v)
		last := first_sig(c.bound).expiration
		budget := query_budget(v)
		// The walk's `now` read fifty seconds before its steps store anything,
		// as a walk held up on its upstreams has: the entry is timed from that
		// instant, not from when the step that stored it finished.
		budget.began = loop.moment_add(budget.began, -50 * time.Second)
		status, _, _ := zone_trust(v, &budget, c.zone, time.unix(i64(last) - 100, 0), context.temp_allocator)
		end_walk(v, &budget)
		testing.expectf(t, status == .Secure, "%s walked to %v", c.zone, status)
		entry, found := v.zones[c.zone]
		testing.expectf(t, found, "%s was not cached", c.zone)
		if found {
			// The walk ran 100 s before the signature lapses.
			over := time.Duration(entry.expires - loop.moment_add(budget.began, 100 * time.Second))
			testing.expectf(t, over <= 0, "%s is kept %v past its signature", c.zone, over)
		}
	}
	free_all(context.temp_allocator)
}

/*
RFC 4035 section 5.3.3 takes the least of four, two of them received: an RRSIG
sent with a lower TTL than its set brings the set down to it, and a set whose
records disagree goes out as one TTL, the lowest.
*/
@(test)
test_served_ttl_takes_the_least_received :: proc(t: ^testing.T) {
	v := make_validator(st_query, nil, Options{})
	defer destroy_validator(v)
	msg, _ := dns.decode_message(st_fixture("example_a"), context.temp_allocator)
	for &rec in msg.answer {
		rec.ttl = 100 if rec.type == .RRSIG else 250
	}
	wire, _, _ := dns.encode_message(msg, context.temp_allocator)
	result := validate(v, "www.example.com.", .A, wire, time.unix(FIXTURE_TIME, 0))
	testing.expect_value(t, result.status, Status.Secure)
	out, _ := strip_unauthenticated(wire, result)
	served, _ := dns.decode_message(out, context.temp_allocator)
	testing.expect(t, len(served.answer) >= 2, "the answer lost its records")
	for rec in served.answer {
		testing.expectf(t, rec.ttl == 100, "%v went out with TTL %d, the RRSIG arrived with 100", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}

// The root's and `com.`'s DNSKEY sets, sent with a TTL of two minutes.
@(private = "file")
st_short_dnskey_query :: proc(ctx: rawptr, name: string, type: dns.Type, allocator: mem.Allocator, deadline: ^time.Tick) -> (wire: []u8, ok: bool) {
	wire, ok = st_query(ctx, name, type, allocator, deadline)
	if !ok || type != .DNSKEY || !(name == "." || dns.name_equal_fold(name, "com.")) {
		return
	}
	msg, err := dns.decode_message(wire, allocator)
	if err != .None {
		return nil, false
	}
	for &rec in msg.answer {
		if rec.type == .DNSKEY {
			rec.ttl = 120
		}
	}
	out, _, eerr := dns.encode_message(msg, allocator)
	return out, eerr == .None
}

// The DNSKEY set's own TTL is one of the four RFC 4035 section 5.3.3 takes the
// least of, so a zone's keys are not kept past it on the strength of the DS's.
@(test)
test_zone_keys_do_not_outlive_their_dnskey_ttl :: proc(t: ^testing.T) {
	v := make_validator(st_short_dnskey_query, nil, Options{})
	defer destroy_validator(v)
	now := time.unix(FIXTURE_TIME, 0)
	budget := query_budget(v)
	before := loop.moment_now()
	status, _, _ := zone_trust(v, &budget, "com.", now, context.temp_allocator)
	end_walk(v, &budget)
	testing.expectf(t, status == .Secure, "com. walked to %v", status)
	// The root's keys come from the trust anchor rather than a DS, so they
	// take a road of their own into the cache.
	for zone in ([]string{".", "com."}) {
		entry, found := v.zones[zone]
		testing.expectf(t, found, "%s was not cached", zone)
		if found {
			// A second of slack for the moment the entry was stored after `before`.
			held := time.Duration(entry.expires - before)
			testing.expectf(t, held <= 121 * time.Second, "%s's keys are kept %v over a DNSKEY TTL of 120 s", zone, held)
		}
	}
	free_all(context.temp_allocator)
}
