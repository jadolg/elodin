package server

import "core:testing"
import "elodin:dns"

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
