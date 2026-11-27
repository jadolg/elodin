package cache

import "core:slice"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:dns"

/*
Issue #419: `put`'s `supersedes` forgets the expired copy when what it refuses is
an answer, and only then.

A TTL of 0, a denial without a SOA and an entry too large to keep are the
upstream's word that the old copy no longer holds. A failure rcode, a truncated
reply, an NXDOMAIN contradicting its own answer section and a lapsed signature
are not answers, and the copy is what RFC 8767 keeps for them.
*/
@(private = "file")
Supersede_Case :: struct {
	name:      string,
	msg:       dns.Message,
	// Shrink the budget below the candidate, so it is refused for size.
	tiny:      bool,
	// Shrink only the shard's share, as a reload between the two checks does.
	share:     bool,
	// Added to the held entry's serial, to name an entry that is not there.
	off:       u64,
	forgotten: bool,
}

@(private = "file")
supersede_msg :: proc(rcode: dns.Rcode, answer: ..dns.Record) -> dns.Message {
	m := dns.Message {
		id       = 0x4190,
		question = slice.clone([]dns.Question{{name = "example.com.", type = .A, class = .IN}}, context.temp_allocator),
		answer   = slice.clone(answer, context.temp_allocator),
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.rcode = u8(rcode)
	return m
}

@(private = "file")
supersede_a :: proc(ttl: u32) -> dns.Record {
	return {name = "example.com.", type = .A, class = .IN, ttl = ttl, data = dns.Rdata_A{addr = {5, 6, 7, 8}}}
}

// An RRSIG over the A record that lapsed an hour ago.
@(private = "file")
lapsed_rrsig :: proc() -> dns.Record {
	expiration := u32(time.time_to_unix(time.now())) - 3600 // lint:allow wall-clock: an RRSIG's expiration is an instant on it
	return rrsig_record("example.com.", .A, expiration, 300, original_ttl = 300)
}

@(test)
test_a_refused_answer_forgets_the_entry_it_supersedes :: proc(t: ^testing.T) {
	truncated := supersede_msg(.No_Error, supersede_a(300))
	truncated.flags.tc = true
	cases := []Supersede_Case {
		{name = "a TTL-0 answer", msg = supersede_msg(.No_Error, supersede_a(0)), forgotten = true},
		{name = "a NODATA without a SOA", msg = supersede_msg(.No_Error), forgotten = true},
		{name = "an NXDOMAIN without a SOA", msg = supersede_msg(.NX_Domain), forgotten = true},
		{name = "an answer too large to keep", msg = supersede_msg(.No_Error, supersede_a(300)), tiny = true, forgotten = true},
		{name = "an answer too large for its shard", msg = supersede_msg(.No_Error, supersede_a(300)), share = true, forgotten = true},
		{name = "a TTL-0 answer naming another entry", msg = supersede_msg(.No_Error, supersede_a(0)), off = 1},
		{name = "an NXDOMAIN carrying an address", msg = supersede_msg(.NX_Domain, supersede_a(300))},
		{name = "a NOERROR about another name", msg = supersede_msg(.No_Error, {name = "other.example.", type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {5, 6, 7, 8}}})},
		{name = "a SERVFAIL", msg = supersede_msg(.Serv_Fail)},
		{name = "a truncated answer", msg = truncated},
		{name = "an answer whose signature lapsed", msg = supersede_msg(.No_Error, supersede_a(300), lapsed_rrsig())},
		{name = "a NODATA without a SOA whose signature lapsed", msg = supersede_msg(.No_Error, lapsed_rrsig())},
	}
	for c in cases {
		answers := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
		defer destroy(answers)
		kb: [KEY_MAX]u8
		key := make_key(kb[:], "example.com.", .A, .IN, false)
		held_wire, held := build_answer("example.com.", 300, context.temp_allocator)
		if !testing.expectf(t, put(answers, key, held_wire, held), "%s: the held answer was not stored", c.name) {
			continue
		}
		held_entry := entry_of(answers, key)
		if !testing.expectf(t, held_entry != nil, "%s: the held answer is not under its key", c.name) {
			continue
		}
		serial := held_entry.serial
		if c.tiny {
			sync.atomic_store(&answers.max_bytes, 1)
		}
		if c.share {
			answers.shards[0].max_bytes = 1
		}

		wire, _, err := dns.encode_message(c.msg, context.temp_allocator)
		msg, derr := dns.decode_message(wire, context.temp_allocator)
		if !testing.expectf(t, err == .None && derr == .None, "%s: the candidate would not round-trip", c.name) {
			continue
		}
		testing.expectf(t, !put(answers, key, wire, msg, supersedes = serial + c.off), "%s: the candidate was stored", c.name)
		e := entry_of(answers, key)
		found := e != nil
		if c.forgotten {
			testing.expectf(t, !found, "%s: the entry it supersedes is still there", c.name)
		} else {
			testing.expectf(t, found && e.serial == serial, "%s: the held entry was dropped", c.name)
		}
	}
	free_all(context.temp_allocator)
}
