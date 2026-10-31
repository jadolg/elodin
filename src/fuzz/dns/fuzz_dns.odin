package fuzz_dns

import "elodin:dns"
import "elodin:fuzz/harness"

// Every query and every upstream answer arrives through this one entry point,
// so it is the single most exposed parser in the binary.
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	_, _ = dns.decode_message(data[:size])
	// Reached from the UDP read loop for a rate-limited query, on the bytes as
	// they arrived and without decoding them first, so it is its own parser of
	// hostile input and gets its own turn here.
	_, _ = dns.truncated_response(data[:size])
	/*
	The padding writer walks the OPT record of a message this server did not
	write - an upstream's reply on its way out to a DoT or DoH client - and
	splices bytes into it, so the walk and the splice both read hostile input.
	The response block, because that is the direction whose input is hostile:
	the query it pads on the way upstream is one of ours.
	*/
	_, _ = dns.pad_response(data[:size], dns.PAD_RESPONSE_BLOCK, dns.MAX_MESSAGE, 1232)
	// Every upstream reply is judged by this on the raw bytes, and its alias
	// branch walks and decodes them on its own (issues #410, #451).
	_ = dns.peek_referral(data[:size])
	// And by this, which walks every record and an OPT record's options (#353).
	_ = dns.peek_opt_unreadable(data[:size])
	// Every forwarded and cached answer is read for its RRSIGs' expirations on
	// the raw bytes, before anything decodes them (issue #165).
	_, _ = dns.signatures_lapse(data[:size], 0)
	reencode(data[:size])
	edit_in_place(data[:size])
	return 0
}

/*
The road `fit_response` takes with an upstream's answer that is over a client's
limit: decode it, then encode it again with the truncation walk. The limit is the
input's own ID, wrapped into 512 - the size RFC 1035 section 4.2.1 promises
every UDP client - up to libFuzzer's default 4096-byte input cap, so every ID
puts the cut somewhere an input can reach.

What comes back is checked for the two things the server sends on: it is within
the limit, and it is a message - one the decoder reads, whose TC bit says what
the encoder reported, and which, without TC, has every answer and authority
record it started with.

A name the decoder wrote and the encoder will not read back is a disagreement
between the two, and `fit_response` turns it into an empty TC answer. The other
encode errors are refusals the encoder makes on purpose (raw RDATA holding a
pointer, a question over the limit) and are not checked.
*/
reencode :: proc(raw: []u8) {
	m, err := dns.decode_message(raw)
	if err != .None {
		return
	}
	limit := 512 + int(m.id) % (4096 - 512 + 1)
	out, truncated, enc_err := dns.encode_message(m, max_size = limit)
	#partial switch enc_err {
	case .None:
	case .Bad_Escape, .Bad_Name, .Label_Too_Long, .Name_Too_Long:
		panic("a decoded name does not encode")
	case:
		return
	}
	if len(out) > limit {
		panic("a re-encoded message outgrew its limit")
	}
	again, dec_err := dns.decode_message(out)
	if dec_err != .None {
		panic("a re-encoded message does not decode")
	}
	if truncated != again.flags.tc && !m.flags.tc {
		panic("the TC bit disagrees with the cut")
	}
	if !truncated && (len(again.answer) != len(m.answer) || len(again.authority) != len(m.authority)) {
		panic("records were cut without TC")
	}
}

/*
The walkers the server runs on an upstream's answer as raw bytes, without
decoding it first. The ones that write in place get a copy, since libFuzzer's
input is read-only.
*/
edit_in_place :: proc(raw: []u8) {
	_ = dns.peek_rcode(raw)
	_ = dns.peek_udp_size(raw)
	_, _ = dns.peek_question(raw)
	_, _ = dns.peek_alias_target(raw)
	_, _ = dns.peek_edns_option(raw, .Cookie)
	_, _ = dns.strip_edns_options(raw)
	_, _ = dns.remove_opt(raw)
	// The per-client options the server takes out of a forwarded answer and
	// puts into one on its way back (cookie, extended error, keepalive).
	_, _ = dns.remove_edns_option(raw, .Cookie)
	_, _ = dns.ensure_edns_option(raw, .Ext_Error, {0, 0}, 1232)

	// The cache's walk: where the TTLs are, what they say, and the rewrite of
	// each one as the entry ages.
	if offsets, ok := dns.scan_ttl_offsets(raw); ok {
		ttls := dns.read_ttls(raw, offsets)
		dns.patch_ttls(dns.clone_message_bytes(raw), offsets, ttls, 60, 5)
	}
	dns.cap_ttls(dns.clone_message_bytes(raw), 300)
	// Against the input itself, so the question names match and the copy runs,
	// and against its second half, a different query as the cache meets one.
	dns.copy_question_case(dns.clone_message_bytes(raw), raw)
	dns.copy_question_case(dns.clone_message_bytes(raw), raw[len(raw) / 2:])
	_ = dns.set_edns_udp_size(dns.clone_message_bytes(raw), 1232)
	_ = dns.clear_edns_extended_rcode(dns.clone_message_bytes(raw))
	_ = dns.set_edns_version_and_flags(dns.clone_message_bytes(raw), 0, true)
}
