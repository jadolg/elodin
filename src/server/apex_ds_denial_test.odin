package server

import "core:encoding/base32"
import "core:strings"
import "core:testing"
import "elodin:dns"
import "elodin:dnssec"

@(private = "file")
APEX :: "corp.example.com."

@(private = "file")
BASE32HEX := [32]byte {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
}

/*
An NSEC3 in `example.com.` for the span from `from` to `to`, no salt. `from` nil
is the hash of `APEX` at `iterations`, which makes the record the one matching it.
*/
@(private = "file")
nsec3_at :: proc(from, to: []u8, flags: u8, iterations: u16, types: ..dns.Type) -> dns.Record {
	owner := from
	if owner == nil {
		owner = make([]u8, 20, context.temp_allocator)
		if !dnssec.nsec3_hash(APEX, nil, iterations, owner) {
			panic("the apex does not hash")
		}
	}
	rdata := make([dynamic]u8, context.temp_allocator)
	append(&rdata, 1, flags, u8(iterations >> 8), u8(iterations), 0, 20)
	append(&rdata, ..to)
	append(&rdata, ..type_bitmap(..types))
	label := base32.encode(owner, BASE32HEX, context.temp_allocator)
	return dns.Record {
		name = strings.concatenate({label, ".example.com."}, context.temp_allocator),
		type = .NSEC3,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = rdata[:]},
	}
}

/*
Issue #244: a NODATA for an apex `DS` is the insecure delegation's proof only
where the denial records do not show the parent holding the name itself.

RFC 4035 section 5.2 gives the proof as an NSEC at the name with NS set and DS
clear, RFC 5155 section 8.9 the NSEC3 one, opt-out included, and RFC 6840
section 4.4 rules out the child's own apex record standing for it. A record at
the name with NS clear - an A record for a portal - or records showing the name
as an empty non-terminal are a name the parent holds, and the route answers.
What the records cannot settle - none at all, which is an unsigned parent, a
record past the iteration ceiling, an opt-out span - keeps the NODATA as the
proof: only a positive showing turns it away.
*/
@(test)
test_an_apex_ds_nodata_is_the_proof_unless_the_denial_shows_no_delegation :: proc(t: ^testing.T) {
	zero := make([]u8, 20, context.temp_allocator)
	ones := make([]u8, 20, context.temp_allocator)
	for &b in ones {
		b = 0xff
	}
	Case :: struct {
		what:   string,
		reply:  []u8,
		proved: bool,
	}
	cases := []Case {
		{"no denial records", ds_nodata(APEX), true},
		{"an NSEC with NS", ds_nodata(APEX, nsec_at(APEX, "example.", .NS, .RRSIG, .NSEC)), true},
		{"an NSEC without NS", ds_nodata(APEX, nsec_at(APEX, "example.", .A, .RRSIG, .NSEC)), false},
		{"the child's apex NSEC", ds_nodata(APEX, nsec_at(APEX, "example.", .NS, .SOA, .RRSIG, .NSEC, .DNSKEY)), false},
		{"an empty non-terminal", ds_nodata(APEX, nsec_at("example.com.", "vpn.corp.example.com.", .NS, .SOA, .RRSIG, .NSEC)), false},
		{"an NSEC3 with NS", ds_nodata(APEX, nsec3_at(nil, zero, 0, 0, .NS)), true},
		{"an NSEC3 without NS", ds_nodata(APEX, nsec3_at(nil, zero, 0, 0, .A, .RRSIG)), false},
		{"an NSEC3 past the ceiling", ds_nodata(APEX, nsec3_at(nil, zero, 0, 150, .A, .RRSIG)), true},
		{"an opt-out span", ds_nodata(APEX, nsec3_at(zero, ones, 1, 0, .NS, .SOA)), true},
		{"a span that is not opt-out", ds_nodata(APEX, nsec3_at(zero, ones, 0, 0, .NS, .SOA)), false},
		// Issue #353: a reply `resolve_query` refuses is no proof to serve.
		{"an OPT record in authority", ds_nodata(APEX, nsec_at(APEX, "example.", .NS, .RRSIG, .NSEC), dns.make_opt(4096, false)), false},
	}

	// The premise: each reply is a NODATA whose authority the decoder hands over.
	for c in cases {
		m, err := dns.decode_message(c.reply, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: %v", c.what, err) {
			return
		}
		testing.expectf(t, len(m.answer) == 0 && dns.Rcode(m.flags.rcode) == .No_Error, "%s is not a NODATA", c.what)
	}
	m, derr := dns.decode_message(cases[2].reply, context.temp_allocator)
	if !testing.expectf(t, derr == .None && len(m.authority) == 1, "%s: %v", cases[2].what, derr) {
		return
	}
	// The bitmap follows the next name, `example.`, written out in full.
	next: [dns.MAX_NAME_WIRE]u8
	next_len, _ := dns.encode_name("example.", next[:])
	types := m.authority[0].data.(dns.Rdata_Raw).data[next_len:]
	testing.expect(t, !dnssec.bitmap_has(types, .NS) && dnssec.bitmap_has(types, .A), "the held name's NSEC has the NS bit")

	for c in cases {
		spent := 0
		proved, settled := parent_answers_apex_ds(c.reply, APEX, true, &spent, dnssec.DEFAULT_MAX_NSEC3_ITERATIONS, context.temp_allocator)
		testing.expectf(t, proved == c.proved, "%s: proved %v, want %v", c.what, proved, c.proved)
		// The proof is settled; what is not the proof is no fact to store against.
		testing.expectf(t, settled == c.proved, "%s: settled %v", c.what, settled)
	}

	/*
	RFC 9824's compact denial: an NSEC at the name with only RRSIG, NSEC and
	NXNAME, which a parent sends for a name it does not have. Not the proof, and
	settled as the NXDOMAIN it stands for, so the route's answer is kept.
	*/
	{
		spent := 0
		proved, settled := parent_answers_apex_ds(
			ds_nodata(APEX, nsec_at(APEX, "example.", .RRSIG, .NSEC, .NXNAME)),
			APEX,
			true,
			&spent,
			dnssec.DEFAULT_MAX_NSEC3_ITERATIONS,
			context.temp_allocator,
		)
		testing.expect(t, !proved, "a compact denial was read as an insecure delegation")
		testing.expect(t, settled, "a compact denial did not settle as the NXDOMAIN it stands for")
	}

	// A configured ceiling of zero is the validator's default, not zero: a
	// record at ten iterations is read.
	spent := 0
	proved, _ := parent_answers_apex_ds(ds_nodata(APEX, nsec3_at(nil, zero, 0, 10, .A, .RRSIG)), APEX, true, &spent, 0, context.temp_allocator)
	testing.expect(t, !proved, "a ceiling of zero refused a ten-iteration NSEC3 the validator would read")
	free_all(context.temp_allocator)
}
