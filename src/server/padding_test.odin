package server

import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
EDNS(0) padding on the way back to a client (RFC 7830, RFC 8467 section 4.2).

A DoT or DoH client that pads its queries is telling this server that it cares
about the one thing the encryption does not hide, and the server's half of that
bargain is to answer in a whole number of 468-octet blocks so its own replies
stop naming themselves by length. What the cases below pin is the shape of that
bargain rather than the arithmetic, which `src/dns/padding_test.odin` covers:
padded on the two encrypted transports, absent on the two clear ones, and absent
for a client that did not ask.

Answered from a rewrite rule, so no upstream is involved and the length under
test is one this server chose on its own.
*/

@(private = "file")
PADDED :: "padded.example."

@(private = "file")
padding_server :: proc(cfg: ^config.Config) -> Server {
	cfg^ = config.default_config()
	cfg.log.queries = false
	cfg.cache.enabled = false
	cfg.blocking.enabled = false
	cfg.dnssec.enabled = false

	answers := make([]config.Rewrite_Answer, 1, context.temp_allocator)
	answers[0] = config.Rewrite_Answer {
		kind = .A,
		v4   = {192, 0, 2, 1},
	}
	rewrites := make([]config.Rewrite, 1, context.temp_allocator)
	rewrites[0] = config.Rewrite {
		domain  = PADDED,
		answers = answers,
		ttl     = 300,
	}
	cfg.rewrites = rewrites
	return Server{cfg = cfg}
}

/*
A query the way a padding client sends one: an OPT record, and the message
rounded up to a multiple of 128 octets (RFC 8467 section 4.1).

`pad` false leaves the OPT record with no options in it, which is every other
EDNS client.
*/
@(private = "file")
padding_query :: proc(pad: bool) -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = PADDED,
		type  = .A,
		class = .IN,
	}
	additional := make([]dns.Record, 1, context.temp_allocator)
	additional[0] = dns.make_opt(1232, false)

	msg := dns.Message {
		id         = 0x7f7f,
		question   = questions,
		additional = additional,
	}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	if !pad {
		return wire
	}
	out, ok := dns.pad_query(wire, dns.PAD_QUERY_BLOCK, dns.MAX_MESSAGE, context.temp_allocator)
	if !ok {
		return nil
	}
	return out
}

@(private = "file")
answer_padding :: proc(wire: []u8) -> (data: []u8, found: bool) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(m, .Padding)
}

@(private = "file")
answers_the_rewrite :: proc(t: ^testing.T, wire: []u8) {
	m, err := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the padded answer does not decode: %v", err) {
		return
	}
	if !testing.expect_value(t, len(m.answer), 1) {
		return
	}
	a, is_a := m.answer[0].data.(dns.Rdata_A)
	testing.expect(t, is_a, "the padded answer lost its A record")
	testing.expect_value(t, a.addr, [4]u8{192, 0, 2, 1})
}

@(test)
test_a_padded_query_is_answered_in_whole_blocks_on_the_encrypted_transports :: proc(t: ^testing.T) {
	for proto in ([]Protocol{.DoT, .DoH}) {
		cfg: config.Config
		s := padding_server(&cfg)

		query := padding_query(true)
		if !testing.expect(t, query != nil, "could not build the padded query") {
			return
		}

		out, outcome, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the padded query went unanswered", proto) {
			return
		}
		testing.expect_value(t, outcome, Outcome.Rewritten)

		testing.expectf(
			t,
			len(out) % dns.PAD_RESPONSE_BLOCK == 0,
			"%v: a %d-byte answer went out %d past a 468-octet block",
			proto,
			len(out),
			len(out) % dns.PAD_RESPONSE_BLOCK,
		)

		data, found := answer_padding(out)
		testing.expectf(t, found, "%v: the answer carries no padding option", proto)
		for b, i in data {
			if !testing.expectf(t, b == 0, "%v: padding byte %d is %02x, not zero", proto, i, b) {
				break
			}
		}

		// The padding is bytes on the end, not bytes instead of the answer.
		answers_the_rewrite(t, out)

		free_all(context.temp_allocator)
	}
}

@(test)
test_the_clear_transports_are_not_padded :: proc(t: ^testing.T) {
	/*
	RFC 8467 section 5: padding a message an observer can already read hides
	nothing from it. On UDP it is worse than nothing - the bytes come out of
	`server.max_udp_response`, which is this server's amplification factor, so a
	padded 468-octet answer to a 40-octet question is a reflector improved for
	no gain in confidentiality.
	*/
	for proto in ([]Protocol{.UDP, .TCP}) {
		cfg: config.Config
		s := padding_server(&cfg)

		query := padding_query(true)
		if !testing.expect(t, query != nil, "could not build the padded query") {
			return
		}

		out, _, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", proto) {
			return
		}

		_, found := answer_padding(out)
		testing.expectf(t, !found, "%v: the answer came back padded", proto)
		testing.expectf(
			t,
			len(out) < dns.PAD_RESPONSE_BLOCK,
			"%v: a rewrite answer grew to %d bytes",
			proto,
			len(out),
		)

		free_all(context.temp_allocator)
	}
}

@(test)
test_a_client_that_did_not_ask_for_padding_is_not_padded :: proc(t: ^testing.T) {
	// RFC 7830 section 4: the option goes back to a requestor that sent one,
	// and to no one else. A client that budgeted for a 60-byte answer does not
	// get 468 bytes because its transport happened to be encrypted.
	for proto in ([]Protocol{.DoT, .DoH}) {
		cfg: config.Config
		s := padding_server(&cfg)

		query := padding_query(false)
		if !testing.expect(t, query != nil, "could not build the query") {
			return
		}

		out, _, ok := handle_query(&s, query, proto, "127.0.0.1:5555", context.temp_allocator)
		if !testing.expectf(t, ok, "%v: the query went unanswered", proto) {
			return
		}

		_, found := answer_padding(out)
		testing.expectf(t, !found, "%v: an unpadded client was handed padding", proto)

		free_all(context.temp_allocator)
	}
}
