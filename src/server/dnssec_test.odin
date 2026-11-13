package server

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:dns"
import "elodin:dnssec"

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
question :: proc(type := dns.Type.A) -> []dns.Question {
	out := make([]dns.Question, 1, context.temp_allocator)
	out[0] = dns.Question {
		name  = "www.example.com.",
		type  = type,
		class = .IN,
	}
	return out
}

// `msg` on the wire, or `ok` false with the failure reported.
@(private = "file")
encode :: proc(t: ^testing.T, msg: dns.Message, loc := #caller_location) -> (wire: []u8, ok: bool) {
	out, _, err := dns.encode_message(msg, context.temp_allocator)
	return out, testing.expect_value(t, err, dns.Encode_Error.None, loc = loc)
}

// The cache key a client's query `q` is looked up under.
@(private = "file")
key_of :: proc(buf: []u8, q: dns.Message) -> string {
	return cache.make_key(buf, q.question[0].name, q.question[0].type, q.question[0].class, dns.edns_do(q), q.flags.cd)
}

// An RRset the validator vouched for, signed by `TEST_SIGNER`.
@(private = "file")
auth_set :: proc(name: string, type: dns.Type) -> dnssec.Authenticated_Set {
	return dnssec.Authenticated_Set{name = name, type = type, class = .IN, signer = TEST_SIGNER, ttl = 86400}
}

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

/*
An RRSIG's RDATA, far enough along to be read as one.

What is read of it is the covered type, the signer and the validity window -
`dnssec.strip_unauthenticated` keeps a signature for the RRset it covers, so a
record whose first two bytes say nothing is a signature over nothing and is
dropped. The rest is filler: no signature is verified anywhere in this file,
which is `src/dnssec`'s work against captured chains.
*/
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
	// A window around now, so a cache that will not keep an answer past its
	// signatures (#165) keeps this one: expiration a day ahead, inception a day
	// behind.
	now := u32(time.time_to_unix(time.now()))
	dns.write_ttl_at(rdata, 8, now + 86400)
	dns.write_ttl_at(rdata, 12, now - 86400)
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

Spelled out rather than reduced to "secure", because that is what a verdict is:
`present_response` cuts a secure answer down to the RRsets the validator names,
so a `Result` that names nothing strips the message to its OPT record.
*/
@(private = "file")
secure_verdict :: proc() -> dnssec.Result {
	answer := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	answer[0] = auth_set("www.example.com.", .A)
	authority := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
	authority[0] = auth_set("example.com.", .NSEC)
	return dnssec.Result{status = .Secure, answer = answer, authority = authority}
}

@(private = "file")
client_query :: proc(dnssec_ok: bool, with_edns := true, type := dns.Type.A) -> dns.Message {
	msg := dns.Message {
		id       = 0x2b2b,
		question = question(type),
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
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}

	stripped := strip_dnssec_records(wire, client_query(false), .A, nil, context.temp_allocator, dns.MAX_MESSAGE)
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
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	stripped := strip_dnssec_records(wire, client_query(false), .RRSIG, nil, context.temp_allocator, dns.MAX_MESSAGE)

	msg, derr := dns.decode_message(stripped, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(msg.answer), 2)
	free_all(context.temp_allocator)
}

@(test)
test_strip_omits_opt_for_a_client_without_edns :: proc(t: ^testing.T) {
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	stripped := strip_dnssec_records(
		wire,
		client_query(false, with_edns = false),
		.A,
		nil,
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
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	secure := present_response(wire, client_query(false), .A, secure_verdict(), nil, context.temp_allocator)
	testing.expect(t, secure[3] & 0x20 != 0, "AD should record a secure verdict")

	// Not secure: the bit must come off even though the upstream may have set it.
	insecure_wire, insecure_encoded := encode(t, signed_response())
	if !insecure_encoded {
		return
	}
	insecure_wire[3] |= 0x20
	insecure := present_response(
		insecure_wire,
		client_query(true),
		.A,
		dnssec.Result{status = .Insecure},
		nil,
		context.temp_allocator,
	)
	testing.expect(t, insecure[3] & 0x20 == 0, "AD must not survive an unauthenticated answer")
	free_all(context.temp_allocator)
}

@(test)
test_ad_bit_only_reaches_clients_that_asked :: proc(t: ^testing.T) {
	// RFC 6840 section 5.8. The same stored bytes, three clients.
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
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
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	wire[3] |= 0x10

	out := present_response(wire, client_query(true), .A, secure_verdict(), nil, context.temp_allocator)
	testing.expect(t, out[3] & 0x10 == 0, "CD should be clear for a client that did not set it")

	stripped_wire, stripped_encoded := encode(t, signed_response())
	if !stripped_encoded {
		return
	}
	stripped_wire[3] |= 0x10
	stripped := present_response(stripped_wire, client_query(false), .A, secure_verdict(), nil, context.temp_allocator)
	testing.expect(t, stripped[3] & 0x10 == 0, "CD should be clear on a stripped answer too")
	free_all(context.temp_allocator)
}

// `msg` with an unsigned NS for `example.com.` naming `ns.attacker.example.`
// added to its authority section, and `also` after it.
@(private = "file")
with_forged_ns :: proc(msg: dns.Message, also: ..dns.Record) -> dns.Message {
	out := msg
	authority := make([dynamic]dns.Record, 0, len(msg.authority) + 1 + len(also), context.temp_allocator)
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
	append(&authority, ..also)
	out.authority = authority[:]
	return out
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
	/*
	And the same question asked sideways: an address for the name that *was*
	authenticated, in the section that was not. The verdict names an RRset in a
	section, so this one has no credentials of its own to be waved through on -
	the signature that held up was checked over the answer section's records and
	says nothing about these.
	*/
	msg := with_forged_ns(signed_response(), a_record("www.example.com.", {203, 0, 113, 67}, 300))

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

	wire, encoded := encode(t, msg)
	if !encoded {
		return
	}

	out := present_response(wire, client_query(true), .A, secure_verdict(), nil, context.temp_allocator)
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
	msg := with_forged_ns(signed_response())

	wire, encoded := encode(t, msg)
	if !encoded {
		return
	}

	out := present_response(wire, client_query(false), .A, secure_verdict(), nil, context.temp_allocator)
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
		question   = question(.AAAA),
		answer     = answer,
		authority  = authority,
		additional = additional,
	}
	msg.flags.qr = true
	msg.flags.ra = true
	return msg
}

/*
A denial after a CNAME, pruned, is not cached.

The prune takes the SOA out with the rest of the authority section when the
verdict does not name it, and what is left
is a CNAME that never reaches the type asked for, under NOERROR or NXDOMAIN.
Either way that is a denial (RFC 2308 section 2.2), and a denial without a SOA
is not kept at all (RFC 2308 section 5), whatever `cache.negative_ttl` says.

The verdict here is built by hand. The validator reaches this shape when the
denial at the chain's end is proven and the SOA beside it is not - an SOA whose
signature fails, or one the verification budget ran out before - since
`proved_denial` names the proof and leaves the SOA out. What this pins is the
prune's behaviour over that verdict.
*/
@(test)
test_a_pruned_denial_after_a_cname_is_not_cached :: proc(t: ^testing.T) {
	for rcode in ([]dns.Rcode{.No_Error, .NX_Domain}) {
		msg := cname_nodata_response()
		msg.flags.rcode = u8(rcode)
		wire, encoded := encode(t, msg)
		if !encoded {
			return
		}

		covered := make([]dnssec.Authenticated_Set, 1, context.temp_allocator)
		covered[0] = auth_set("www.example.com.", .CNAME)
		verdict := dnssec.Result {
			status = .Secure,
			answer = covered,
		}

		out := present_response(wire, client_query(true, type = .AAAA), .AAAA, verdict, nil, context.temp_allocator)
		decoded, derr := dns.decode_message(out, context.temp_allocator)
		testing.expect_value(t, derr, dns.Decode_Error.None)
		testing.expect_value(t, dns.rcode_of(decoded), rcode)
		testing.expect_value(t, len(decoded.answer), 2)
		testing.expect_value(t, len(decoded.authority), 0)

		key_buf: [cache.KEY_MAX]u8
		key := cache.make_key(key_buf[:], "www.example.com.", .AAAA, .IN, true, false)

		// Not even with a `min_ttl` floor to lift it: there is nothing left in
		// it to read a lifetime from.
		answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, min_ttl = 60, negative_ttl = 300})
		defer cache.destroy(answers)
		testing.expectf(t, !cache.put(answers, key, out, decoded), "cache.put kept a pruned %v after a CNAME", rcode)

		// The same message unpruned, SOA and all, is kept: the refusal is the
		// missing SOA and not the shape.
		full, ferr := dns.decode_message(wire, context.temp_allocator)
		testing.expect_value(t, ferr, dns.Decode_Error.None)
		testing.expectf(t, cache.put(answers, key, wire, full), "cache.put refused an unpruned %v after a CNAME", rcode)
	}
	free_all(context.temp_allocator)
}

/*
A pruned answer that reaches the type asked for is cached and served.

The stored bytes are the pruned copy, and `serve_from_cache` is what hands them
to every later client - with the stored AD bit, for one that set DO.
*/
@(test)
test_a_pruned_answer_is_still_cached_and_served :: proc(t: ^testing.T) {
	msg := cname_nodata_response()
	answer := make([]dns.Record, len(msg.answer) + 1, context.temp_allocator)
	copy(answer, msg.answer)
	answer[len(msg.answer)] = dns.Record {
		name = "cdn.example.net.",
		type = .AAAA,
		class = .IN,
		ttl = 600,
		data = dns.Rdata_AAAA{addr = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	msg.answer = answer
	wire, encoded := encode(t, msg)
	if !encoded {
		return
	}

	covered := make([]dnssec.Authenticated_Set, 2, context.temp_allocator)
	covered[0] = auth_set("www.example.com.", .CNAME)
	covered[1] = auth_set("cdn.example.net.", .AAAA)
	verdict := dnssec.Result {
		status = .Secure,
		answer = covered,
	}

	out := present_response(wire, client_query(true, type = .AAAA), .AAAA, verdict, nil, context.temp_allocator)
	decoded, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect_value(t, len(decoded.answer), 3)
	testing.expect_value(t, len(decoded.authority), 0)

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = 3600, negative_ttl = 0})
	defer cache.destroy(answers)
	key_buf: [cache.KEY_MAX]u8
	key := cache.make_key(key_buf[:], "www.example.com.", .AAAA, .IN, true, false)
	if !testing.expect(t, cache.put(answers, key, out, decoded), "a pruned answer was not cacheable") {
		return
	}

	cfg := test_config()
	cfg.cache.enabled = true
	s := Server {
		cfg     = &cfg,
		answers = answers,
	}
	// Present so the request counts as one this server would validate, which is
	// what lets the stored AD bit reach a client that asked for it.
	s.validator = dnssec.make_validator(nil, nil, dnssec.Options{})
	defer dnssec.destroy_validator(s.validator)

	query_wire, query_encoded := encode(t, client_query(true, type = .AAAA))
	if !query_encoded {
		return
	}

	served, outcome, ok := handle_query(&s, query_wire, .UDP, "test", context.temp_allocator)
	testing.expect(t, ok, "no response was produced")
	testing.expect_value(t, outcome, Outcome.Cached)
	if !ok {
		return
	}
	testing.expect(t, served[3] & 0x20 != 0, "the stored verdict should reach a client that set DO")
	hit, hderr := dns.decode_message(served, context.temp_allocator)
	testing.expect_value(t, hderr, dns.Decode_Error.None)
	testing.expect_value(t, len(hit.answer), 3)
	testing.expect_value(t, len(hit.authority), 0)
	free_all(context.temp_allocator)
}

/*
An answer we did not check ourselves must not claim to have been checked.

The AD bit says "this resolver authenticated this data". When validation is off,
or the client asked us to leave it alone with CD, we authenticated nothing — so
whatever the upstream put in that bit is its claim, not ours, and passing it on
lends it our name. RFC 6840 section 5.8 and RFC 4035 section 3.2.2.

Driven through `handle_query` on the cache path rather than against
`apply_ad_policy` directly, because the policy has to apply on every served
path, not only after validation.
*/

@(private = "file")
Ad_Case :: struct {
	name:      string,
	validator: bool,
	cd:        bool,
	// The CD bit on the answer as the upstream sent it.
	stored_cd: bool,
}

@(private = "file")
serve_cached_with_ad :: proc(t: ^testing.T, c: Ad_Case) -> (response: []u8, ok: bool) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	stored := signed_response()
	stored.flags.ad = true
	stored.flags.cd = c.stored_cd
	wire, encoded := encode(t, stored)
	if !encoded {
		return nil, false
	}

	cfg := test_config()
	cfg.cache.enabled = true
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
	query_wire, qencoded := encode(t, query)
	if !qencoded {
		return nil, false
	}

	key_buf: [cache.KEY_MAX]u8
	key := key_of(key_buf[:], query)
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
`error_response` decides on whether there is anything to build from, and with
nothing patches the request's own header instead: the client is waiting on its
own transaction ID, and a reply without it would be dropped as unsolicited and
the query would wait out its full timeout.
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

	cfg := test_config()
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
entry carries to whether that entry was ever validated. The two agree only
because the cache key carries CD and the class, which keeps the entries a
non-validating request writes away from the requests that would trust them - an
accident of the key rather than a property of the cache.

So the bit is settled before the entry goes in, and this drives the real store
path to check it: a miss, forwarded to an upstream that sets AD, with CD on the
client's query so no verdict of ours is ever reached.
*/

@(test)
test_unvalidated_answer_is_not_cached_with_ad :: proc(t: ^testing.T) {
	// The answer as an upstream sent it, AD set. Nothing here established that.
	from_upstream := signed_response()
	from_upstream.flags.ad = true
	reply, reply_encoded := encode(t, from_upstream)
	if !reply_encoded {
		return
	}

	h: Harness
	// A validator that is never asked anything: CD below keeps it out of the way.
	if !harness_start(t, &h, caching = true, validating = true) {
		return
	}
	defer harness_stop(&h)

	// CD set, so `validating` is false and we reach no verdict of our own.
	query := client_query(false, with_edns = false)
	query.flags.cd = true
	query_wire, query_encoded := encode(t, query)
	if !query_encoded {
		return
	}

	out, outcome, served, asked := harness_ask(&h, query_wire, reply, client = "test")
	testing.expect(t, asked, "the upstream was never asked")
	testing.expect(t, served, "no response was produced")
	testing.expectf(t, outcome == .Forwarded, "expected the forwarded path, got %v", outcome)
	// The client's copy carries no AD either.
	testing.expect(
		t,
		len(out) >= dns.HEADER_SIZE && out[3] & 0x20 == 0,
		"the upstream's AD bit reached the client as ours",
	)

	// What the entry carries is the point.
	key_buf: [cache.KEY_MAX]u8
	stored, _, found := cache.get(h.answers, key_of(key_buf[:], query), context.temp_allocator)
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

/*
CD comes back the way the client wrote it, whatever the upstream's copy says.

RFC 4035 section 3.2.2 has a responder copy CD from the query, and the answer an
upstream hands over is its echo of the question this server put - or not an echo
at all: OpenDNS clears CD on every answer, so a client that set it behind that
upstream (208.67.222.222) would be told checking had been left on. So the
client's bit is put back on every path: the validated one, and an answer served
without validating, which is every answer to a CD query.
*/
@(test)
test_cd_bit_echoes_the_client_not_the_upstream :: proc(t: ^testing.T) {
	cases := []Ad_Case {
		{name = "client set cd, upstream dropped it, no validator", validator = false, cd = true},
		{name = "client set cd, upstream dropped it, validator on", validator = true, cd = true},
		{name = "client left cd clear, upstream set it", validator = false, cd = false, stored_cd = true},
	}
	for c in cases {
		out, ok := serve_cached_with_ad(t, c)
		if !ok || len(out) < dns.HEADER_SIZE {
			continue
		}
		testing.expectf(t, (out[3] & 0x10 != 0) == c.cd, "%s: cd is %v, the client asked with %v", c.name, out[3] & 0x10 != 0, c.cd)
	}
}

@(test)
test_settle_header_states_this_servers_rd_ra_aa_z :: proc(t: ^testing.T) {
	// RFC 1035 section 4.1.1. An authoritative-only upstream's answer - AA set,
	// RA clear, and Z set by a careless one - stored for a client that set RD,
	// then served to one that did not.
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	wire[2] |= 0x04 | 0x01
	wire[3] = (wire[3] &~ 0x80) | 0x40

	no_rd := client_query(false)
	no_rd.flags.rd = false
	settle_header(wire, no_rd, false)
	testing.expect(t, wire[2] & 0x04 == 0, "AA is an authority's to set, not a forwarder's")
	testing.expect(t, wire[3] & 0x80 != 0, "RA says this server recurses, whatever the upstream said")
	testing.expect(t, wire[2] & 0x01 == 0, "RD is copied from this client's query, which left it clear")
	testing.expect(t, wire[3] & 0x40 == 0, "Z must be zero in every response")

	settle_header(wire, client_query(false), true)
	testing.expect(t, wire[2] & 0x01 != 0, "RD is copied from this client's query, which set it")
	testing.expect(t, wire[2] & 0x04 == 0 && wire[3] & 0x80 != 0, "the validated path settles AA and RA too")

	// Shorter than a header: nothing to settle, and nothing to write past.
	short := []u8{0, 0, 0x04}
	settle_header(short, client_query(false), false)
	testing.expect(t, short[2] == 0x04, "a buffer shorter than a header is left alone")
	free_all(context.temp_allocator)
}

// `signed_response` with the A record's and its signature's TTLs raised to a week.
@(private = "file")
raised_ttl_response :: proc() -> dns.Message {
	msg := signed_response()
	msg.answer[0].ttl = 604800
	msg.answer[1].ttl = 604800
	return msg
}

/*
RFC 4035 section 5.3.3, at the point the answer leaves for the client and the
cache: an A record whose unsigned TTL was raised on the path goes out under AD
with no more than the verified signature's ceiling (#337).
*/
@(test)
test_a_served_ttl_is_held_to_the_signature :: proc(t: ^testing.T) {
	wire, encoded := encode(t, raised_ttl_response())
	if !encoded {
		return
	}
	verdict := secure_verdict()
	verdict.answer[0].ttl = 300
	out := present_response(wire, client_query(true), .A, verdict, nil, context.temp_allocator)
	served, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, served.flags.ad, "a secure verdict lost its AD bit")
	testing.expect_value(t, len(served.answer), 2)
	for rec in served.answer {
		testing.expectf(t, rec.ttl == 300, "%v went out with TTL %d, ceiling 300", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}

/*
And where the prune cannot rebuild the answer: it goes out as it arrived and
without AD, but no longer than the signatures behind it allow - the copy kept
in the cache is the one every later client gets, so a raised TTL kept there is
the same problem by another road.
*/
@(test)
test_an_unrebuildable_answer_still_has_its_ttl_held :: proc(t: ^testing.T) {
	msg := raised_ttl_response()
	wire, encoded := encode(t, msg)
	if !encoded {
		return
	}
	/*
	An authenticated MX whose exchange is a compression pointer the decoder
	could not follow (it points past the message), so it stays raw RDATA and
	`encode_message` refuses to write it: the prune's rebuild fails. Appended by
	hand, after the answer, since no encoder will write it.
	*/
	mx := []u8 {
		0xc0, 0x0c, // www.example.com., the question's name
		0x00, 0x0f, 0x00, 0x01, // MX IN
		0x00, 0x09, 0x3a, 0x80, // 604800
		0x00, 0x04, 0x00, 0x0a, 0xff, 0xff, // preference 10, pointer to 0x3fff
	}
	ancount := int(wire[7]) + 1
	answer_end := 0
	{
		// The answer section ends where the authority begins; re-encoding with
		// only the question and answer gives that offset.
		head := msg
		head.authority = nil
		head.additional = nil
		head_wire, head_encoded := encode(t, head)
		if !head_encoded {
			return
		}
		answer_end = len(head_wire)
	}
	broken := make([dynamic]u8, 0, len(wire) + len(mx), context.temp_allocator)
	append(&broken, ..wire[:answer_end])
	append(&broken, ..mx)
	append(&broken, ..wire[answer_end:])
	broken[7] = u8(ancount)
	verdict := secure_verdict()
	verdict.answer[0].ttl = 300
	sets := make([]dnssec.Authenticated_Set, 2, context.temp_allocator)
	sets[0] = verdict.answer[0]
	sets[1] = verdict.answer[0]
	sets[1].type = .MX
	verdict.answer = sets
	out := present_response(broken[:], client_query(true), .A, verdict, nil, context.temp_allocator)
	served, derr := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, dns.Decode_Error.None)
	testing.expect(t, !served.flags.ad, "the fallback should not claim AD")
	for rec in served.answer {
		testing.expectf(t, rec.ttl <= 300, "%v went out with TTL %d over a ceiling of 300", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}

/*
A Secure answer whose prune runs out of memory is not presented at all (#636):
the fallback for a prune that fails on the message - the answer without AD - is
what the cache would keep for the life of the entry, and the refusal was this
server's, for a moment. Every allocation of the prune refused in turn.
*/
@(test)
test_a_prune_that_runs_dry_presents_nothing :: proc(t: ^testing.T) {
	wire, encoded := encode(t, signed_response())
	if !encoded {
		return
	}
	defer free_all(context.temp_allocator)
	whole, whole_ok := present_response(wire, client_query(true), .A, secure_verdict(), nil, context.temp_allocator)
	if !testing.expect(t, whole_ok, "the answer was not presented with nothing refused") {
		return
	}
	testing.expect(t, whole[3] & 0x20 != 0, "AD did not record a secure verdict with nothing refused")
	query, verdict := client_query(true), secure_verdict()
	refused := 0
	for n := 1; ; n += 1 {
		// The request's arena; `Fail_Nth` hands what it passes on to the temp
		// allocator, so that one is left alone.
		f := Fail_Nth{fail_at = n, fail_for = 1}
		out, ok := present_response(wire, query, .A, verdict, nil, mem.Allocator{procedure = fail_nth_proc, data = &f})
		if f.seen < n {
			break
		}
		refused += 1
		// A refusal past the prune - the AD-less copy's own rebuild - is not
		// this test's; the prune's are the ones that leave AD off.
		testing.expectf(t, !ok || out[3] & 0x20 != 0, "allocation %d refused: presented without AD", n)
	}
	testing.expect(t, refused > 0, "the prune allocated nothing to refuse")
}
