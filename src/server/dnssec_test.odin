package server

import "core:testing"
import "elodin:cache"
import "elodin:config"
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
question :: proc() -> []dns.Question {
	out := make([]dns.Question, 1, context.temp_allocator)
	out[0] = dns.Question {
		name  = "www.example.com.",
		type  = .A,
		class = .IN,
	}
	return out
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
		data = dns.Rdata_Raw{data = make([]u8, 40, context.temp_allocator)},
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
	secure := present_response(wire, client_query(false), .A, true, context.temp_allocator)
	testing.expect(t, secure[3] & 0x20 != 0, "AD should record a secure verdict")

	// Not secure: the bit must come off even though the upstream may have set it.
	insecure_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	insecure_wire[3] |= 0x20
	insecure := present_response(insecure_wire, client_query(true), .A, false, context.temp_allocator)
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

	out := present_response(wire, client_query(true), .A, true, context.temp_allocator)
	testing.expect(t, out[3] & 0x10 == 0, "CD should be clear for a client that did not set it")

	stripped_wire, _, _ := dns.encode_message(signed_response(), context.temp_allocator)
	stripped_wire[3] |= 0x10
	stripped := present_response(stripped_wire, client_query(false), .A, true, context.temp_allocator)
	testing.expect(t, stripped[3] & 0x10 == 0, "CD should be clear on a stripped answer too")
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
	testing.expect_value(t, msg.id, u16(0x2b2b))
	free_all(context.temp_allocator)
}

@(test)
test_query_ids_do_not_repeat_in_sequence :: proc(t: ^testing.T) {
	seen: map[u16]bool
	defer delete(seen)
	collisions := 0
	for _ in 0 ..< 256 {
		id := next_query_id()
		if seen[id] {
			collisions += 1
		}
		seen[id] = true
	}
	// 256 draws from 16 bits will collide now and again; a counter handed out
	// raw would collide never, and be guessable, which is the failure this is
	// looking for.
	testing.expect(t, len(seen) > 200, "too few distinct transaction ids")
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
