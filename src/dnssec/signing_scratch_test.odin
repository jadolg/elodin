package dnssec

import "base:runtime"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
A signature over an RRset is checked against the set's canonical form, and every
signature a response carries over one set is checked against the same one. Issue
#527: a render per attempt costs about one and a half times the set per
signature, so one 60 KB set and the `MAX_VERIFICATIONS_PER_QUERY` forgeries a
zone may publish over it under a real key tag would take 5.8 MB of arena per
query.
*/

@(private = "file")
SS_DNSKEY_RDATA :: "0101030fe6087a0da6db23c6753cb6ee6edc1cc7683652baa4d3edf04c5c62bd8cbfc884"
@(private = "file")
SS_KEY_TAG :: 14506
@(private = "file")
SS_NOW :: 1785664800
@(private = "file")
SS_OWNER :: "big.example.com."

@(private = "file")
ss_key :: proc() -> []Dnskey {
	rdata, _ := decode_hex(SS_DNSKEY_RDATA, context.temp_allocator)
	key, _ := parse_dnskey(rdata)
	keys := make([]Dnskey, 1, context.temp_allocator)
	keys[0] = key
	return keys
}

// 230 distinct 250-byte TXT records: 61,870 bytes on the wire.
@(private = "file")
ss_big_txt :: proc() -> []dns.Record {
	records := make([]dns.Record, 230, context.temp_allocator)
	for &rec, i in records {
		chunk := make([]u8, 250, context.temp_allocator)
		for j in 0 ..< len(chunk) {
			chunk[j] = u8('a' + (i + j) % 26)
		}
		chunk[0] = u8(i)
		strs := make([]string, 1, context.temp_allocator)
		strs[0] = string(chunk)
		rec = dns.Record {
			name = SS_OWNER,
			type = .TXT,
			class = .IN,
			ttl = 300,
			data = dns.Rdata_TXT{strings = strs},
		}
	}
	return records
}

// A signature naming the key's tag and algorithm, current, and garbage: it
// passes every free check and costs a verification.
@(private = "file")
ss_forged_rrsig :: proc() -> dns.Record {
	rdata := make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&rdata, u8(u16(dns.Type.TXT) >> 8), u8(u16(dns.Type.TXT)))
	append(&rdata, ALG_ED25519, 3)
	append(&rdata, 0, 0, 1, 44) // original TTL
	for v in ([2]u32{SS_NOW + 86400, SS_NOW - 86400}) { 	// expiration, inception
		append(&rdata, u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v))
	}
	append(&rdata, u8(SS_KEY_TAG >> 8), u8(SS_KEY_TAG & 0xff))
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, _ := dns.encode_name("example.com.", name_buf[:])
	append(&rdata, ..name_buf[:n])
	for _ in 0 ..< 64 {
		append(&rdata, 0x41)
	}
	return dns.Record{name = SS_OWNER, type = .RRSIG, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = rdata[:]}}
}

@(private = "file")
ss_section :: proc(signatures: int) -> []dns.Record {
	section := make([dynamic]dns.Record, 0, 230 + signatures, context.temp_allocator)
	append(&section, ..ss_big_txt())
	for _ in 0 ..< signatures {
		append(&section, ss_forged_rrsig())
	}
	return section[:]
}

@(private = "file")
arena_used :: proc() -> int {
	return int((cast(^runtime.Arena)context.temp_allocator.data).total_used)
}

@(test)
test_signature_attempts_render_the_rrset_once :: proc(t: ^testing.T) {
	// What one attempt costs and what all of them do, each from an empty arena;
	// the difference is what the attempts after the first add.
	used: [2]int
	for signatures, i in ([2]int{1, MAX_VERIFICATIONS_PER_QUERY}) {
		free_all(context.temp_allocator)
		keys := ss_key()
		section := ss_section(signatures)
		budget: Budget
		before := arena_used()
		_, _, _, ok, exhausted := verified_rrset(&budget, section, SS_OWNER, .TXT, .IN, "example.com.", keys, SS_NOW, context.temp_allocator)
		used[i] = arena_used() - before
		// The premise: every forgery reached a verification.
		testing.expect(t, !ok && !exhausted)
		testing.expect_value(t, budget.verifications, signatures)
	}
	// The set once and the buffer once, about 64 KB each, whatever the number
	// of signatures. A render per attempt would be about 91 KB more apiece.
	testing.expect(t, used[0] < 3 * 64 * 1024)
	testing.expectf(
		t,
		used[1] - used[0] < (MAX_VERIFICATIONS_PER_QUERY - 1) * 512,
		"%d more attempts over a 60 KB RRset cost %d more bytes of arena",
		MAX_VERIFICATIONS_PER_QUERY - 1,
		used[1] - used[0],
	)
	free_all(context.temp_allocator)
}

@(test)
test_signing_input_is_charged_to_the_request :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	section := ss_section(MAX_VERIFICATIONS_PER_QUERY)
	keys := ss_key()

	// Room for the readings and not for the render: refused as our own
	// allowance, not as a forgery, and before the verifications run out.
	spent := dns.REQUEST_DECODE_BUDGET - 1024
	budget := Budget {
		spent = &spent,
	}
	_, _, _, ok, exhausted := verified_rrset(&budget, section, SS_OWNER, .TXT, .IN, "example.com.", keys, SS_NOW, context.temp_allocator)
	testing.expect(t, !ok)
	testing.expect(t, exhausted, "a render past the request's budget was paid for")
	testing.expect_value(t, budget.verifications, 1)
	testing.expect(t, spent > dns.REQUEST_DECODE_BUDGET)
	testing.expect_value(t, exhausted_reason(&budget), READING_OVER_BUDGET)

	// With room it is charged, and once: one signature over the set and
	// sixty-four cost the same.
	charged: [2]int
	for signatures, i in ([2]int{1, MAX_VERIFICATIONS_PER_QUERY}) {
		spent = 0
		budget = Budget {
			spent = &spent,
		}
		_, _, _, ok, exhausted = verified_rrset(&budget, section[:230 + signatures], SS_OWNER, .TXT, .IN, "example.com.", keys, SS_NOW, context.temp_allocator)
		testing.expect(t, !ok && !exhausted)
		testing.expect_value(t, budget.verifications, signatures)
		testing.expect_value(t, exhausted_reason(&budget), "verification budget spent")
		charged[i] = spent
	}
	testing.expectf(t, charged[0] > 2 * 60_000, "the render charged %d bytes", charged[0])
	testing.expect_value(t, charged[1], charged[0])
	free_all(context.temp_allocator)
}

@(test)
test_a_reused_scratch_builds_what_a_fresh_render_builds :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	records := ss_big_txt()
	scratch: Signing_Scratch

	// Every field that differs between signatures over one set, varied: the
	// header, the signer's length, the Original TTL, and the owner a wildcard
	// signature is made under.
	before := 0
	for i in 0 ..< MAX_VERIFICATIONS_PER_QUERY {
		sig := Rrsig {
			type_covered = .TXT,
			algorithm    = ALG_ED25519,
			labels       = u8(2 + i % 2),
			original_ttl = u32(300 + i),
			expiration   = 0xffffffff,
			inception    = u32(i),
			key_tag      = u16(i),
			signer       = strings.concatenate({strings.repeat("s", min(i + 1, 63), context.temp_allocator), ".example.com."}, context.temp_allocator),
		}
		owner := SS_OWNER if i % 2 == 1 else "*.example.com."
		fresh, ok1 := signing_input(sig, owner, .IN, records, context.temp_allocator)
		mark := arena_used()
		reused, ok2 := signing_input(sig, owner, .IN, records, context.temp_allocator, &scratch)
		testing.expect(t, ok1 && ok2)
		testing.expectf(t, string(fresh) == string(reused), "attempt %d built different bytes from a reused scratch", i)
		// After the first, a longer signer or owner costs nothing new.
		if i > 0 {
			before += arena_used() - mark
		}
	}
	testing.expectf(t, before == 0, "attempts after the first took %d bytes of arena", before)

	// A scratch handed another set renders that one.
	other := ss_big_txt()[:3]
	sig := Rrsig {
		type_covered = .TXT,
		algorithm    = ALG_ED25519,
		labels       = 3,
		original_ttl = 300,
		signer       = "example.com.",
	}
	fresh, _ := signing_input(sig, SS_OWNER, .IN, other, context.temp_allocator)
	reused, _ := signing_input(sig, SS_OWNER, .IN, other, context.temp_allocator, &scratch)
	testing.expect(t, string(fresh) == string(reused))
	free_all(context.temp_allocator)
}

@(test)
test_a_set_that_will_not_render_is_tried_once :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	// OPT has no canonical form; see `write_canonical_rdata`.
	records := make([]dns.Record, 2, context.temp_allocator)
	records[0] = ss_big_txt()[0]
	records[1] = dns.Record {
		name = SS_OWNER,
		type = .OPT,
		data = dns.Rdata_OPT{},
	}
	sig := Rrsig {
		type_covered = .TXT,
		labels       = 3,
		signer       = "example.com.",
	}
	scratch: Signing_Scratch
	_, ok := signing_input(sig, SS_OWNER, .IN, records, context.temp_allocator, &scratch)
	testing.expect(t, !ok)
	mark := arena_used()
	_, ok = signing_input(sig, SS_OWNER, .IN, records, context.temp_allocator, &scratch)
	testing.expect(t, !ok)
	testing.expect_value(t, arena_used() - mark, 0)
	free_all(context.temp_allocator)
}

// A request already past its budget renders nothing, as it reads nothing.
@(test)
test_a_spent_request_renders_nothing :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	records := ss_big_txt()
	sig := Rrsig {
		type_covered = .TXT,
		labels       = 3,
		signer       = "example.com.",
	}
	spent := dns.REQUEST_DECODE_BUDGET + 1
	budget := Budget {
		spent = &spent,
	}
	scratch := Signing_Scratch {
		budget = &budget,
	}
	mark := arena_used()
	_, ok := signing_input(sig, SS_OWNER, .IN, records, context.temp_allocator, &scratch)
	testing.expect(t, !ok)
	testing.expect(t, scratch.over_budget)
	testing.expect_value(t, arena_used() - mark, 0)
	free_all(context.temp_allocator)
}

@(private = "file")
ss_no_query :: proc(_: rawptr, _: string, _: dns.Type, _: mem.Allocator, _: ^time.Tick) -> ([]u8, bool) {
	return nil, false
}

// `validate_rrset` over the big set and `signatures` forgeries under a key the
// validator already holds for the zone: the arena it took, its verdict, and the
// verifications it spent.
@(private = "file")
ss_answer :: proc(signatures: int, spent: ^int) -> (used: int, status: Status, reason: string, verifications: int) {
	free_all(context.temp_allocator)
	now := time.unix(SS_NOW, 0)
	v := make_validator(ss_no_query, nil, Options{})
	defer destroy_validator(v)
	cache_put(v, ".", .Secure, nil, MAX_ZONE_TTL, fixture_moment(now))
	cache_put(v, "com.", .Secure, nil, MAX_ZONE_TTL, fixture_moment(now))
	cache_put(v, "example.com.", .Secure, ss_key(), MAX_ZONE_TTL, fixture_moment(now))

	records := ss_big_txt()
	sigs := make([]Rrsig, signatures, context.temp_allocator)
	for &sig in sigs {
		sig = Rrsig {
			type_covered = .TXT,
			algorithm    = ALG_ED25519,
			labels       = 3,
			original_ttl = 300,
			expiration   = SS_NOW + 86400,
			inception    = SS_NOW - 86400,
			key_tag      = SS_KEY_TAG,
			signer       = "example.com.",
			signature    = make([]u8, 64, context.temp_allocator),
		}
	}
	budget := query_budget(v)
	budget.spent = spent
	before := arena_used()
	status, _, reason, _, _ = validate_rrset(v, &budget, SS_OWNER, .TXT, .IN, records, sigs, SS_NOW, now, context.temp_allocator)
	return arena_used() - before, status, reason, budget.verifications
}

// The answer path, the one every client question takes.
@(test)
test_answer_signatures_do_not_rerender_the_set :: proc(t: ^testing.T) {
	// The premise: every forgery reached a verification.
	few, _, _, tried := ss_answer(1, nil)
	testing.expect_value(t, tried, 1)
	many, _, _, all := ss_answer(MAX_VERIFICATIONS_PER_QUERY, nil)
	testing.expect_value(t, all, MAX_VERIFICATIONS_PER_QUERY)
	testing.expectf(
		t,
		many - few < (MAX_VERIFICATIONS_PER_QUERY - 1) * 512,
		"%d more attempts over a 60 KB answer cost %d more bytes of arena",
		MAX_VERIFICATIONS_PER_QUERY - 1,
		many - few,
	)

	// And charged: a request without room for the render is told so, as our
	// own allowance and not as a forgery.
	spent := dns.REQUEST_DECODE_BUDGET - 1024
	_, refused, reason, _ := ss_answer(MAX_VERIFICATIONS_PER_QUERY, &spent)
	testing.expect_value(t, refused, Status.Indeterminate)
	testing.expect_value(t, reason, READING_OVER_BUDGET)
	free_all(context.temp_allocator)
}

/*
The charge is at least what the arena gave up, even when the RDATA buffer
outgrows the arena block it started in and is copied rather than grown in
place: the copies it leaves behind are the request's too.
*/
@(test)
test_the_render_charge_covers_what_the_arena_took :: proc(t: ^testing.T) {
	sig := Rrsig {
		type_covered = .TXT,
		labels       = 3,
		signer       = "example.com.",
	}
	// Starting at each offset across the last 256 KiB of the block `free_all`
	// keeps, whatever its size, so that some of them put the buffer's growth
	// across the block's end.
	least, most := max(int), 0
	for k in 0 ..< 16 {
		free_all(context.temp_allocator)
		records := ss_big_txt()
		block := (cast(^runtime.Arena)context.temp_allocator.data).curr_block
		offset := max(0, int(block.capacity - block.used) - 256 * 1024) + k * 16 * 1024
		if offset > 0 {
			_ = make([]u8, offset, context.temp_allocator)
		}
		spent := 0
		budget := Budget {
			spent = &spent,
		}
		scratch := Signing_Scratch {
			budget = &budget,
		}
		mark := arena_used()
		_, ok := signing_input(sig, SS_OWNER, .IN, records, context.temp_allocator, &scratch)
		taken := arena_used() - mark
		testing.expect(t, ok)
		testing.expectf(t, spent >= taken, "at offset %d the render took %d bytes of arena and charged %d", offset, taken, spent)
		least, most = min(least, taken), max(most, taken)
	}
	// The premise: some offset left a copy behind rather than growing in place.
	testing.expectf(t, most > least, "no offset grew the buffer across a block's end (took %d bytes at each)", most)
	free_all(context.temp_allocator)
}

/*
The reason names the allowance that stopped the loop, not whichever happens to
be gone afterwards: a loop that runs out of verifications before it renders
anything says so, on a request some reading has already taken past its budget.
*/
@(test)
test_the_reason_is_what_stopped_the_loop :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	section := ss_section(MAX_VERIFICATIONS_PER_QUERY)
	spent := dns.REQUEST_DECODE_BUDGET + 1
	budget := Budget {
		spent         = &spent,
		verifications = MAX_VERIFICATIONS_PER_QUERY,
	}
	_, _, _, ok, exhausted := verified_rrset(&budget, section, SS_OWNER, .TXT, .IN, "example.com.", ss_key(), SS_NOW, context.temp_allocator)
	testing.expect(t, !ok && exhausted)
	testing.expect_value(t, exhausted_reason(&budget), VERIFICATIONS_SPENT)

	// And the last loop to stop is the one reported: a render refused, then a
	// later loop out of verifications.
	spent = dns.REQUEST_DECODE_BUDGET - 1024
	budget = Budget {
		spent = &spent,
	}
	_, _, _, ok, exhausted = verified_rrset(&budget, section, SS_OWNER, .TXT, .IN, "example.com.", ss_key(), SS_NOW, context.temp_allocator)
	testing.expect(t, !ok && exhausted)
	testing.expect_value(t, exhausted_reason(&budget), READING_OVER_BUDGET)
	budget.verifications = MAX_VERIFICATIONS_PER_QUERY
	_, _, _, ok, exhausted = verified_rrset(&budget, section, SS_OWNER, .TXT, .IN, "example.com.", ss_key(), SS_NOW, context.temp_allocator)
	testing.expect(t, !ok && exhausted)
	testing.expect_value(t, exhausted_reason(&budget), VERIFICATIONS_SPENT)
	free_all(context.temp_allocator)
}

/*
The render stops when the request runs out, rather than rendering the whole set
and finding out after. A set's canonical form can be many times its wire size -
names in RDATA arrive compressed and are rendered in full - so what a refused
render takes is one step of the buffer's growth, not the set.
*/
@(test)
test_a_render_stops_when_the_request_runs_out :: proc(t: ^testing.T) {
	free_all(context.temp_allocator)
	records := ss_big_txt()
	sig := Rrsig {
		type_covered = .TXT,
		labels       = 3,
		signer       = "example.com.",
	}
	// Room to start - the index arrays and the first steps of the buffer - and
	// not for the set, whose RDATA alone is 58 KB.
	ROOM :: 32 * 1024
	spent := dns.REQUEST_DECODE_BUDGET - ROOM
	budget := Budget {
		spent = &spent,
	}
	scratch := Signing_Scratch {
		budget = &budget,
	}
	mark := arena_used()
	_, ok := signing_input(sig, SS_OWNER, .IN, records, context.temp_allocator, &scratch)
	taken := arena_used() - mark
	testing.expect(t, !ok)
	testing.expect_value(t, budget.ran_out, READING_OVER_BUDGET)
	// The room plus at most the step of growth that crossed it.
	testing.expectf(t, taken < ROOM * 3 / 2, "a render refused %d bytes short of the budget took %d bytes of arena", ROOM, taken)
	free_all(context.temp_allocator)
}
