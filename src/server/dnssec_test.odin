package server

import "core:net"
import "core:testing"
import "core:thread"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:upstream"

/*
The parts of the DNSSEC path that shape what the client sees.

The validator's own verdicts are checked in `src/dnssec` against captured
chains, and the running server's behaviour in the integration suite. What is
left is the presentation: which records survive, what the AD bit says, and what
goes out on the wire to ask the upstream in the first place.
*/

// A slice literal lives only as long as the scope that wrote it, so anything a
// helper hands back has to be allocated rather than composed in place.
@(private = "file")
question :: proc() -> []dns.Question {
	out := make([]dns.Question, 1, context.temp_allocator)
	out[0] = dns.Question {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
	}
	return out
}

/*
An RRSIG's RDATA, far enough along to be read as one.

Only the covered type is ever looked at here - `dnssec.strip_unauthenticated`
keeps a signature for the RRset it covers, so a record whose first two bytes say
nothing is a signature over nothing and is dropped. The rest is filler: no
signature is verified anywhere in this file, which is `src/dnssec`'s work
against captured chains.
*/
/*
The signer these synthetic signatures name.

Written out rather than left as the root, because the prune keeps a signature
only when its signer is the one the verdict was reached against - so the name in
here and the `signer` on the `Authenticated_Set` below have to be the same name,
and a test whose fixture quietly disagreed with its verdict would drop the
signature and look like a prune bug.
*/
@(private = "file")
TEST_SIGNER :: "example.com."

@(private = "file")
rrsig_over :: proc(covered: dns.Type) -> dns.Rdata_Raw {
	// 18 bytes of fixed fields, the signer name, then a signature.
	name_buf: [dns.MAX_NAME_WIRE]u8
	n, err := dns.encode_name(TEST_SIGNER, name_buf[:])
	if err != .None {
		panic("cannot encode the test signer")
	}
	rdata := make([]u8, 18 + n + 8, context.temp_allocator)
	rdata[0] = u8(u16(covered) >> 8)
	rdata[1] = u8(u16(covered))
	rdata[2] = 13 // ECDSA P-256, so the algorithm at least names something real
	rdata[3] = 3 // labels
	copy(rdata[18:], name_buf[:n])
	return dns.Rdata_Raw{data = rdata}
}

@(private = "file")
signed_response :: proc() -> dns.Message {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name = "www.example.com.",
		type = .A,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_A{addr = {93, 184, 216, 34}},
	}
	answer[1] = dns.Record {
		name = "www.example.com.",
		type = .RRSIG,
		class = .IN,
		ttl = 300,
		data = rrsig_over(.A),
	}
	authority := make([]dns.Record, 1, context.temp_allocator)
	authority[0] = dns.Record {
		name = "example.com.",
		type = .NSEC,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = make([]u8, 12, context.temp_allocator)},
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(4096, true)

	msg := dns.Message {
		id         = 0x2b2b,
		question   = question(),
		answer     = answer,
		authority  = authority,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.ra = true
	return msg
}

/*
The verdict a validator would have reached over `signed_response`.

Spelled out rather than reduced to "secure", because that is what a verdict is
now: `present_response` cuts a secure answer down to the RRsets the validator
names, so a `Result` that names nothing strips the message to its OPT record.
*/
@(private = "file")
secure_verdict :: proc() -> dnssec.Result {
	answer := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	answer[0] = dnssec.Authenticated_Set {
		name   = "www.example.com.",
		type   = .A,
		class  = .IN,
		signer = TEST_SIGNER,
	}
	authority := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	authority[0] = dnssec.Authenticated_Set {
		name   = "example.com.",
		type   = .NSEC,
		class  = .IN,
		signer = TEST_SIGNER,
	}
	return dnssec.Result{status = .Secure, answer = answer, authority = authority}
}

@(private = "file")
client_query :: proc(dnssec_ok: bool, with_edns := true) -> dns.Message {
	msg := dns.Message {
		id       = 0x2b2b,
		question = question(),
	}
	msg.flags.rd = true
	if with_edns {
		additional := make([]dns.Record, 1, context.temp_allocator)
		additional[0] = dns.make_opt(1232, dnssec_ok)
		msg.additional = additional
	}
	return msg
}

@(test)
test_strip_removes_dnssec_records :: proc(t: ^testing.T) {
	wire, _, err := dns.encode_message(signed_response(), context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	stripped := strip_dnssec_records(wire, client_query(false), .A, context.temp_allocator, dns.MAX_MESSAGE)
	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	testing.expect_value(t, len(msg.answer), 1)
	testing.expect_value(t, msg.answer[0].type, dns.Type.A)
	testing.expect_value(t, len(msg.authority), 0)

	// The client's own EDNS parameters come back, with DO clear because it
	// never asked for the records that bit requests.
	testing.expect(t, dns.edns_present(msg), "the OPT record should survive")
	testing.expect(t, !dns.edns_do(msg), "DO should be clear for a client that did not set it")
	testing.expect_value(t, dns.edns_udp_size(msg), u16(1232))
	free_all(context.temp_allocator)
}

@(test)
test_strip_keeps_records_that_were_asked_for :: proc(t: ^testing.T) {
	// A client asking for RRSIG records wants RRSIG records.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped := strip_dnssec_records(wire, client_query(false), .RRSIG, context.temp_allocator, dns.MAX_MESSAGE)

	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(msg.answer), 2)
	free_all(context.temp_allocator)
}

@(test)
test_strip_omits_opt_for_a_client_without_edns :: proc(t: ^testing.T) {
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped := strip_dnssec_records(
		wire,
		client_query(false, with_edns = false),
		.A,
		context.temp_allocator,
		dns.MAX_MESSAGE,
	)

	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(msg), "a client that sent no OPT should get none back")
	free_all(context.temp_allocator)
}

@(test)
test_ad_bit_records_the_verdict :: proc(t: ^testing.T) {
	// What goes into the cache says what was established, whoever asked.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	secure := present_response(wire, client_query(false), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, secure[3] & 0x20 != 0, "AD should record a secure verdict")

	// Not secure: the bit must come off even though the upstream may have set it.
	insecure_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	insecure_wire[3] |= 0x20
	insecure := present_response(
		insecure_wire,
		client_query(true),
		.A,
		dnssec.Result{status = .Insecure},
		context.temp_allocator,
	)
	testing.expect(t, insecure[3] & 0x20 == 0, "AD must not survive an unauthenticated answer")
	free_all(context.temp_allocator)
}

@(test)
test_ad_bit_only_reaches_clients_that_asked :: proc(t: ^testing.T) {
	// RFC 6840 section 5.8. The same stored bytes, three clients.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	wire[3] |= 0x20

	with_do := make([]u8, len(wire), context.temp_allocator)
	copy(with_do, wire)
	apply_ad_policy(with_do, client_query(true))
	testing.expect(t, with_do[3] & 0x20 != 0, "a DO client asked and should be told")

	asked_ad := make([]u8, len(wire), context.temp_allocator)
	copy(asked_ad, wire)
	query_with_ad := client_query(false)
	query_with_ad.flags.ad = true
	apply_ad_policy(asked_ad, query_with_ad)
	testing.expect(t, asked_ad[3] & 0x20 != 0, "a client setting AD asked and should be told")

	silent := make([]u8, len(wire), context.temp_allocator)
	copy(silent, wire)
	apply_ad_policy(silent, client_query(false))
	testing.expect(t, silent[3] & 0x20 == 0, "a client that asked nothing should be told nothing")
	free_all(context.temp_allocator)
}

@(test)
test_cd_bit_is_not_echoed_back :: proc(t: ^testing.T) {
	// Our own upstream query sets CD, and the upstream echoes it. Passing that
	// on would tell a client that its answer went unchecked.
	wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	wire[3] |= 0x10

	out := present_response(wire, client_query(true), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, out[3] & 0x10 == 0, "CD should be clear for a client that did not set it")

	stripped_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped_wire[3] |= 0x10
	stripped := present_response(stripped_wire, client_query(false), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, stripped[3] & 0x10 == 0, "CD should be clear on a stripped answer too")
	free_all(context.temp_allocator)
}

@(test)
test_ad_never_goes_out_over_records_the_verdict_missed :: proc(t: ^testing.T) {
	/*
	RFC 4035 section 3.2.3. The verdict names the RRsets that were checked, and
	this is the last place the rest can be taken out - after it, the AD bit goes
	on and the message goes into the cache for every later client to be given.

	The DO client is the one to check, because it is the one whose message is
	otherwise passed through byte for byte. Nothing else on this path would take
	the forgery below out: `strip_dnssec_records` drops RRSIG, NSEC, NSEC3 and
	NSEC3PARAM and hands on every other type it finds, so a forged NS and the
	address to go with it walk straight through it.
	*/
	msg := signed_response()
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	append(&authority, ..msg.authority)
	append(
		&authority,
		dns.Record {
			name = "example.com.",
			type = .NS,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_Name{name = "ns.attacker.example."},
		},
	)
	/*
	And the same question asked sideways: an address for the name that *was*
	authenticated, in the section that was not. The verdict names an RRset in a
	section, so this one has no credentials of its own to be waved through on -
	the signature that held up was checked over the answer section's records and
	says nothing about these.
	*/
	append(
		&authority,
		dns.Record {
			name = "www.example.com.",
			type = .A,
			class = .IN,
			ttl = 300,
			data = dns.Rdata_A{addr = {203, 0, 113, 67}},
		},
	)
	msg.authority = authority[:]

	additional := make([dynamic]dns.Record, 0, len(msg.additional) + 1, context.temp_allocator)
	append(&additional, ..msg.additional)
	append(
		&additional,
		dns.Record {
			name = "ns.attacker.example.",
			type = .A,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_A{addr = {203, 0, 113, 66}},
		},
	)
	msg.additional = additional[:]

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	out := present_response(wire, client_query(true), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, out[3] & 0x20 != 0, "AD should record the secure verdict")

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	for rec in decoded.authority {
		testing.expectf(t, rec.type != .NS, "an unsigned NS RRset went out under AD as %v", rec.name)
	}
	testing.expect_value(t, len(decoded.authority), 1)
	testing.expect_value(t, decoded.authority[0].type, dns.Type.NSEC)

	// The glue goes with it, and the OPT record - which is not data anybody
	// signs - stays.
	testing.expect_value(t, len(decoded.additional), 1)
	testing.expect(t, dns.edns_present(decoded), "the OPT record should survive")

	// The answer and the signature over it both stay: an RRSIG rides on the
	// RRset it covers, and this one covers an RRset that held up.
	testing.expect_value(t, len(decoded.answer), 2)
	testing.expect_value(t, decoded.answer[0].type, dns.Type.A)
	testing.expect_value(t, decoded.answer[1].type, dns.Type.RRSIG)
	free_all(context.temp_allocator)
}

/*
What the prune leaves behind still has to survive the two paths after it.

`strip_dnssec_records` runs next for a client that never set DO, and this is the
order they run in: the prune first, at full size, and the client's own trimming
after. It is the prune that takes the forgery out in both cases -
`strip_dnssec_records` is interested in RRSIG, NSEC, NSEC3 and NSEC3PARAM and
would pass a forged NS on untouched - so what this pins is that the second pass
does not undo the first: it re-encodes the message from scratch, and a prune
whose result it were handed the unpruned bytes for would put every dropped
record back.
*/
@(test)
test_a_pruned_answer_survives_the_strip_for_a_client_without_do :: proc(t: ^testing.T) {
	msg := signed_response()
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1, context.temp_allocator)
	append(&authority, ..msg.authority)
	append(
		&authority,
		dns.Record {
			name = "example.com.",
			type = .NS,
			class = .IN,
			ttl = 86400,
			data = dns.Rdata_Name{name = "ns.attacker.example."},
		},
	)
	msg.authority = authority[:]

	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	out := present_response(wire, client_query(false), .A, secure_verdict(), context.temp_allocator)
	testing.expect(t, out[3] & 0x20 != 0, "AD should record the secure verdict")

	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	// The answer the client asked for, with the DNSSEC records it did not ask
	// for taken back out - and the forged NS gone, which only the prune does.
	testing.expect_value(t, len(decoded.answer), 1)
	testing.expect_value(t, decoded.answer[0].type, dns.Type.A)
	testing.expect_value(t, len(decoded.authority), 0)

	// The OPT is the client's again, rebuilt by the strip: its buffer size, and
	// DO clear because it never asked.
	testing.expect(t, dns.edns_present(decoded), "the OPT record should survive")
	testing.expect(t, !dns.edns_do(decoded), "DO should be clear for a client that did not set it")
	testing.expect_value(t, dns.edns_udp_size(decoded), u16(1232))
	free_all(context.temp_allocator)
}

@(private = "file")
aaaa_question :: proc() -> []dns.Question {
	out := make([]dns.Question, 1, context.temp_allocator)
	out[0] = dns.Question {
		name  = "www.example.com.",
		type  = .AAAA,
		class = .IN,
	}
	return out
}

@(private = "file")
aaaa_query :: proc() -> dns.Message {
	msg := dns.Message {
		id       = 0x2b2b,
		question = aaaa_question(),
	}
	msg.flags.rd = true
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, true)
	msg.additional = additional
	return msg
}

/*
The everyday shape this prune costs something: AAAA for a name that is CNAME'd
to an IPv4-only host. The CNAME is signed and checks out; the NODATA at the end
of it is proven in the target's zone, which the validator never establishes - so
that proof and the SOA beside it go out with the rest of what nobody checked.
*/
@(private = "file")
cname_nodata_response :: proc() -> dns.Message {
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = dns.Record {
		name = "www.example.com.",
		type = .CNAME,
		class = .IN,
		ttl = 600,
		data = dns.Rdata_Name{name = "cdn.example.net."},
	}
	answer[1] = dns.Record {
		name = "www.example.com.",
		type = .RRSIG,
		class = .IN,
		ttl = 600,
		data = rrsig_over(.CNAME),
	}
	authority := make([]dns.Record, 3, context.temp_allocator)
	authority[0] = dns.Record {
		name = "example.net.",
		type = .SOA,
		class = .IN,
		ttl = 900,
		data = dns.Rdata_SOA {
			ns = "ns.example.net.",
			mbox = "hostmaster.example.net.",
			serial = 1,
			refresh = 7200,
			retry = 3600,
			expire = 1209600,
			minimum = 900,
		},
	}
	authority[1] = dns.Record {
		name = "cdn.example.net.",
		type = .NSEC,
		class = .IN,
		ttl = 900,
		data = dns.Rdata_Raw{data = make([]u8, 12, context.temp_allocator)},
	}
	authority[2] = dns.Record {
		name = "example.net.",
		type = .RRSIG,
		class = .IN,
		ttl = 900,
		data = rrsig_over(.SOA),
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(4096, true)

	msg := dns.Message {
		id         = 0x2b2b,
		question   = aaaa_question(),
		answer     = answer,
		authority  = authority,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.ra = true
	return msg
}

/*
A pruned answer must still be an answer the cache will keep.

`cache.put` reads a lifetime out of one of two branches, and which one it lands
in is decided by `rcode == .NX_Domain || len(msg.answer) == 0`. NODATA after a
CNAME keeps the CNAME in its answer section, so it takes the ordinary branch and
is held for the shortest TTL among the records that are left. The other branch
reads the SOA, which is exactly what the prune took away.

Worth pinning because it comes out right by which branch the message falls into
rather than by anything the prune does on purpose. The cache here is built with
`negative_ttl` 0 to make that visible: had this entry taken the negative branch
there would be no SOA left to read and no fallback to stand in for it, and
`cache.put` would have refused it. An answer shape that quietly stopped being
cacheable would send every AAAA lookup for a CNAME'd name upstream, every time,
with nothing to connect it to this change.

The stored bytes are then served back through `handle_query`, because the copy
in the cache is the pruned one and `serve_from_cache` is what hands it to every
later client.
*/
@(test)
test_a_pruned_answer_is_still_cached_and_served :: proc(t: ^testing.T) {
	wire, _, err := dns.encode_message(cname_nodata_response(), context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	// The verdict `validate_answer` reaches on this shape: the CNAME held up,
	// and nothing in the authority section was ever looked at.
	covered := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	covered[0] = dnssec.Authenticated_Set {
		name   = "www.example.com.",
		type   = .CNAME,
		class  = .IN,
		signer = TEST_SIGNER,
	}
	verdict := dnssec.Result {
		status = .Secure,
		answer = covered,
	}

	out := present_response(wire, aaaa_query(), .AAAA, verdict, context.temp_allocator)
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)

	if !testing.expect_value(t, len(decoded.answer), 2) {
		return
	}
	testing.expect_value(t, decoded.answer[0].type, dns.Type.CNAME)
	testing.expect_value(t, len(decoded.authority), 0)
	// The condition `cache.put` reads, stated where a change to it would show.
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.No_Error)
	testing.expect(t, len(decoded.answer) > 0, "an empty answer section would take the negative branch")

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 0})
	defer cache.destroy(answers)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "www.example.com.", .AAAA, .IN, true, false)
	if !testing.expect(t, cache.put(answers, key, out, decoded), "a pruned answer was not cacheable") {
		return
	}

	/*
	The other side of that, so the reason it worked is on the record rather than
	inferred. Take the CNAME out as well and the same message falls into the
	negative branch, where there is now no SOA to read a lifetime from and no
	`negative_ttl` behind it - and the cache turns the entry away.
	*/
	{
		answerless := decoded
		answerless.answer = nil
		empty, _, eerr := dns.encode_message(answerless, context.temp_allocator)
		testing.expect_value(t, eerr, dns.Encode_Error.None)
		other := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 0})
		defer cache.destroy(other)
		testing.expect(
			t,
			!cache.put(other, key, empty, answerless),
			"an answer section pruned to nothing was cached anyway, so this test proves less than it claims",
		)
	}

	cfg := config.default_config()
	cfg.log.queries = false
	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	// Present so the request counts as one this server would validate, which is
	// what lets the stored AD bit reach a client that asked for it.
	s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	query_wire, _, qenc := dns.encode_message(aaaa_query(), context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	served, outcome, ok := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	testing.expect(t, ok, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Cached)
	if !ok {
		return
	}
	testing.expect(t, served[3] & 0x20 != 0, "the stored verdict should reach a client that set DO")

	hit, hderr := dns.decode_message(served, context.temp_allocator)
	testing.expect_value(t, hderr, dns.Decode_Error.None)
	if !testing.expect_value(t, len(hit.answer), 2) {
		return
	}
	testing.expect_value(t, hit.answer[0].type, dns.Type.CNAME)
	testing.expect_value(t, len(hit.authority), 0)
	free_all(context.temp_allocator)
}

/*
The other half of that shape, where the answer section stops deciding.

A CNAME pointing at a name that does not exist comes back NXDOMAIN with the
CNAME still in the answer section, and `cache.put` reads the rcode first: the
negative branch is taken whatever the answer holds. The prune has just removed
the SOA that branch reads - it belongs to the target's zone, which the validator
never established - so the lifetime falls back to `cache.negative_ttl`, and to
nothing at all where an operator has set that to zero.

Pinned as the cost it is, not as a property worth having. It is what this prune
leaves behind until the denial at a CNAME target is validated properly.

The verdict here is built by hand, and since `denial_after_chain` was added it
is one the validator will not reach on its own: a chain ending without the type
asked for now comes back `Insecure`, so nothing is pruned and the proof reaches
the client. What this still pins is the prune's own behaviour when it *is*
handed such a verdict - worth keeping, because the shape becomes reachable again
the moment #186 lands and the denial at the target's zone is genuinely checked.
*/
@(test)
test_a_pruned_nxdomain_after_a_cname_falls_back_to_the_configured_negative_ttl :: proc(t: ^testing.T) {
	msg := cname_nodata_response()
	msg.flags.rcode = u8(dns.Rcode.NX_Domain)
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, err, dns.Encode_Error.None)

	covered := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	covered[0] = dnssec.Authenticated_Set {
		name   = "www.example.com.",
		type   = .CNAME,
		class  = .IN,
		signer = TEST_SIGNER,
	}
	verdict := dnssec.Result {
		status = .Secure,
		answer = covered,
	}

	out := present_response(wire, aaaa_query(), .AAAA, verdict, context.temp_allocator)
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, dns.rcode_of(decoded), dns.Rcode.NX_Domain)
	testing.expect_value(t, len(decoded.authority), 0)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "www.example.com.", .AAAA, .IN, true, false)

	// With a fallback configured the entry is kept - for that number, not for
	// the one the zone's SOA asked for.
	configured := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 300})
	defer cache.destroy(configured)
	testing.expect(t, cache.put(configured, key, out, decoded), "a pruned NXDOMAIN should still be cacheable")

	// With none, there is nothing left to read a lifetime from and the entry is
	// turned away. Every repeat of this question then goes upstream.
	none := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 0})
	defer cache.destroy(none)
	testing.expect(
		t,
		!cache.put(none, key, out, decoded),
		"cache.put found a lifetime for a pruned NXDOMAIN, so the comment above is out of date",
	)
	free_all(context.temp_allocator)
}

@(test)
test_upstream_query_asks_for_signatures :: proc(t: ^testing.T) {
	query := client_query(false)
	wire, ok := dnssec_upstream_query(query, context.temp_allocator)
	testing.expect(t, ok, "the upstream query should build")

	msg, err := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	testing.expect(t, msg.flags.cd, "CD should be set so the upstream's verdict is not inherited")
	testing.expect(t, dns.edns_do(msg), "DO should be set so signatures come back")
	testing.expect_value(t, dns.edns_udp_size(msg), u16(UPSTREAM_UDP_SIZE))

	testing.expect_value(t, len(msg.question), 1)
	testing.expect_value(t, msg.question[0].name, "www.example.com.")
	testing.expect_value(t, msg.question[0].type, dns.Type.A)

	/*
	Nothing is asserted about the transaction ID here on purpose. This procedure
	leaves it as the client wrote it, and `resolve_query` replaces it with a
	fresh one once this path and the plain forwarding path have converged - so
	the ID a client chose surviving this far is expected, and the ID reaching an
	upstream is what has to be checked. `query_id_test.odin` checks it, through
	the whole server.
	*/
	free_all(context.temp_allocator)
}

/*
An answer we did not check ourselves must not claim to have been checked.

The AD bit says "this resolver authenticated this data". When validation is off,
or the client asked us to leave it alone with CD, we authenticated nothing — so
whatever the upstream put in that bit is its claim, not ours, and passing it on
lends it our name. RFC 6840 section 5.8 and RFC 4035 section 3.2.2.

Driven through `handle_query` on the cache path rather than against
`apply_ad_policy` directly, because the defect was not in that procedure: it
was in only calling it when we had validated.
*/

@(private = "file")
Ad_Case :: struct {
	name:      string,
	validator: bool,
	cd:        bool,
}

@(private = "file")
serve_cached_with_ad :: proc(t: ^testing.T, c: Ad_Case) -> (response: []u8, ok: bool) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	stored := signed_response()
	stored.flags.ad = true
	wire, _, enc := dns.encode_message(stored, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	cfg := config.default_config()
	cfg.log.queries = false
	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	if c.validator {
		// A validator that is never asked anything: with CD set, nothing
		// reaches it.
		s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	}
	defer if s.validator != nil {
		dnssec.destroy_validator(s.validator)
	}

	query := client_query(false, with_edns = false)
	query.flags.cd = c.cd
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(
		key_buf[:],
		query.question[0].name,
		query.question[0].type,
		query.question[0].class,
		dns.edns_do(query),
		query.flags.cd,
	)
	decoded, derr := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	if !cache.put(answers, key, wire, decoded) {
		testing.expectf(t, false, "%s: the answer was not cached, so the served path was never taken", c.name)
		return nil, false
	}

	out, outcome, served := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	testing.expectf(t, served, "%s: no response was produced", c.name)
	testing.expectf(t, outcome == .Cached, "%s: expected the cached path, got %v", c.name, outcome)
	return out, served && outcome == .Cached
}

@(test)
test_ad_bit_is_not_forwarded_when_we_did_not_validate :: proc(t: ^testing.T) {
	cases := []Ad_Case {
		// DNSSEC off entirely: there is no verdict to report.
		{name = "no validator", validator = false, cd = false},
		// DNSSEC on, but the client set CD, which is a request to leave the
		// checking alone. We do, so we have nothing to attest either.
		{name = "checking disabled by the client", validator = true, cd = true},
	}
	for c in cases {
		out, ok := serve_cached_with_ad(t, c)
		if !ok {
			continue
		}
		testing.expectf(
			t,
			len(out) >= dns.HEADER_SIZE && out[3] & 0x20 == 0,
			"%s: the upstream's AD bit reached the client as ours",
			c.name,
		)
		free_all(context.temp_allocator)
	}
}

/*
A reply to a query we could not parse still has to be recognisable as a reply.

`make_response` builds from the decoded message, and a query that did not decode
leaves that empty — id zero, no question. Encoding an empty message succeeds, so
`error_response` returned those twelve bytes and never reached the fallback that
was written to patch the request's own header. The client is waiting on its own
transaction ID, so what came back was dropped as unsolicited and the query
waited out its full timeout instead.
*/
@(test)
test_formerr_for_an_unparseable_query_carries_its_id :: proc(t: ^testing.T) {
	// A header claiming a question that is not there: enough to fail the decode
	// while still being a header we can answer from.
	query := make([]u8, dns.HEADER_SIZE, context.temp_allocator)
	query[0], query[1] = 0xab, 0xcd
	query[2] = 0x01 // RD
	query[5] = 1 // qdcount, with no question following it

	_, derr := dns.decode_message(query, context.temp_allocator)
	testing.expect(t, derr != .None, "the fixture parsed, so it is not testing the unparseable path")

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	s := Server {
		cfg = &cfg,
	}

	out, outcome, ok := handle_query(&s, query, .UDP, "test", context.temp_allocator)
	testing.expect(t, ok, "no response was produced for a malformed query")
	testing.expect_value(t, outcome, Outcome.Failed)
	if !ok || len(out) < dns.HEADER_SIZE {
		return
	}

	id, id_ok := dns.peek_id(out)
	testing.expect(t, id_ok, "the response is too short to carry an id")
	testing.expectf(t, id == 0xabcd, "the reply carries id %04x, not the query's abcd", id)
	testing.expect(t, out[2] & 0x80 != 0, "the reply is not marked as a response")
	testing.expect_value(t, out[3] & 0xf, u8(dns.Rcode.Form_Err))

	free_all(context.temp_allocator)
}

/*
An answer we did not check must not be stored carrying a claim that we did.

`validating` is recomputed for every request, so nothing ties the AD bit an
entry carries to whether that entry was ever validated. The two agree today only
because the cache key carries CD and the class, which keeps the entries a
non-validating request writes away from the requests that would trust them -
an accident of the key rather than a property of the cache, and one that stops
holding the moment `validating` is turned off after the key is built, as it is
when the upstream query cannot be rebuilt.

So the bit is settled before the entry goes in, and this drives the real store
path to check it: a miss, forwarded to an upstream that sets AD, with CD on the
client's query so no verdict of ours is ever reached.
*/

@(private = "file")
Udp_Mock :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
}

@(private = "file")
udp_mock_once :: proc(m: ^Udp_Mock) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(m.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(m.reply) > len(buf) {
		return
	}
	out: [4096]u8
	copy(out[:], m.reply)
	// Echo the query's transaction id, so the reply is matched to it.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(m.socket, out[:len(m.reply)], remote)
}

@(test)
test_unvalidated_answer_is_not_cached_with_ad :: proc(t: ^testing.T) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	from_upstream := signed_response()
	from_upstream.flags.ad = true
	reply, _, enc := dns.encode_message(from_upstream, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)

	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if serr != nil {
		testing.expectf(t, false, "cannot bind the mock upstream: %v", serr)
		return
	}
	defer net.close(socket)
	// The mock has no timeout of its own and the join below waits for it, so
	// without this a query that never arrives hangs the run instead of failing
	// it. See the note on `MOCK_RECV_TIMEOUT`.
	_ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	bound, berr := net.bound_endpoint(socket)
	if berr != nil {
		testing.expectf(t, false, "cannot read the mock's port: %v", berr)
		return
	}

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = true
	cfg.dnssec.enabled = true
	cfg.upstream.strategy = .Failover
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	g, gerr := upstream.make_group(cfg.upstream, nil)
	if gerr != .None {
		testing.expectf(t, false, "cannot build the upstream group: %v", gerr)
		return
	}
	defer upstream.destroy_group(g)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600})
	defer cache.destroy(answers)

	s := Server {
		cfg     = &cfg,
		group   = g,
		answers = answers,
	}
	// A validator that is never asked anything: CD below keeps it out of the way.
	s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	// CD set, so `validating` is false and we reach no verdict of our own.
	query := client_query(false, with_edns = false)
	query.flags.cd = true
	query_wire, _, qenc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, qenc, dns.Encode_Error.None)

	m := Udp_Mock {
		socket = socket,
		reply  = reply,
	}
	server := thread.create_and_start_with_poly_data(&m, udp_mock_once)
	out, outcome, served := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	// Joined here rather than deferred: the mock reads `reply` out of the scratch
	// arena this test resets on its way out.
	thread.join(server)
	thread.destroy(server)

	testing.expect(t, served, "no response was produced")
	testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
	// Already right, and the reason this went unnoticed: the client is told nothing.
	testing.expect(
		t,
		len(out) >= dns.HEADER_SIZE && out[3] & 0x20 == 0,
		"the upstream's AD bit reached the client as ours",
	)

	// What the entry carries is the point.
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(
		key_buf[:],
		query.question[0].name,
		query.question[0].type,
		query.question[0].class,
		dns.edns_do(query),
		query.flags.cd,
	)
	stored, _, found := cache.get(answers, key, context.temp_allocator)
	testing.expect(t, found, "the answer was not cached, so nothing was stored to check")
	if found {
		testing.expect(
			t,
			len(stored) >= dns.HEADER_SIZE && stored[3] & 0x20 == 0,
			"an answer we never validated was cached carrying AD",
		)
	}
	free_all(context.temp_allocator)
}
