package server

import "core:testing"
import "elodin:dns"

/*
An OPT record minted onto an answer that fits, where the eleven appended bytes
do not and the same answer compressed has room for them (issue #598).

`dns.ensure_opt` appends the record to the bytes as they arrived, so an upstream
that writes its names in full hands over an answer the encoder would make
shorter. Abandoning the mint there leaves an EDNS client without an OPT record
for want of bytes the answer did not need; `match_client_opt` rebuilds it
compressed instead, and abandons the mint only when that does not fit either.
*/

@(private = "file")
QNAME :: "a-fairly-long-owner-name.example.com."

@(private = "file")
loose_answer :: proc() -> []u8 {
	answer := make([]dns.Record, 20, context.temp_allocator)
	for &rec, i in answer {
		rec = dns.Record{name = QNAME, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, u8(i)}}}
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = QNAME, type = .A, class = .IN}
	m := dns.Message{id = 7, question = question, answer = answer}
	m.flags.qr = true
	wire, _, _ := dns.encode_message(m, context.temp_allocator, compress = false)
	return wire
}

@(private = "file")
edns_query :: proc() -> dns.Message {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = QNAME, type = .A, class = .IN}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)
	return dns.Message{id = 7, question = question, additional = additional}
}

@(test)
test_a_mint_that_only_fits_compressed_is_rebuilt :: proc(t: ^testing.T) {
	wire := loose_answer()
	// The answer fits; the answer plus an appended record does not.
	limit := len(wire) + 5
	spent := 0
	out := match_client_opt(wire, edns_query(), 1232, limit, .Cached, &spent, context.temp_allocator)

	testing.expect(t, len(out) <= limit, "the answer went out over the limit")
	m, err := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	testing.expect(t, dns.edns_present(m), "an EDNS client got no OPT record for an answer that fits compressed")
	testing.expect_value(t, len(m.answer), 20)
	testing.expect(t, !m.flags.tc, "TC was set on an answer that fits")
	free_all(context.temp_allocator)
}

// Where not even the compressed answer has room, the mint is abandoned and the
// answer goes whole, without one.
@(test)
test_a_mint_that_fits_no_way_is_abandoned :: proc(t: ^testing.T) {
	wire := loose_answer()
	compact, _, _ := dns.encode_message(dns.decode_message(wire, context.temp_allocator) or_else {}, context.temp_allocator)
	// The answer fits; even compressed, the answer plus a record does not.
	limit := len(compact) + 5
	spent := 0
	out := match_client_opt(compact, edns_query(), 1232, limit, .Cached, &spent, context.temp_allocator)

	m, err := dns.decode_message(out, context.temp_allocator)
	testing.expect_value(t, err, dns.Decode_Error.None)
	testing.expect(t, !dns.edns_present(m), "a record that does not fit was minted")
	testing.expect_value(t, len(m.answer), 20)
	testing.expect(t, !m.flags.tc, "TC was set on an answer that fits")
	free_all(context.temp_allocator)
}
