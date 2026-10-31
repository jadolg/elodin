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

	// `decode_message`, and the re-encode `fit_response` runs on what it read.
	reencode(data[:size])
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
	edit_in_place(data[:size])
	return 0
}

/*
The road `fit_response` takes with an upstream's answer that is over a client's
limit: decode it, then encode it again with the truncation walk. The limit is the
input's own ID, wrapped into the range from 512 - the size RFC 1035 section
4.2.1 promises every UDP client - to one byte short of the message's own encoded
length, so every ID of a message over 512 bytes puts the cut somewhere inside it.
The encoded length rather than the input's: the decoder ignores bytes past the
last record, and the encoder may compress harder than the input did or leave a
second OPT record out, so the input's length can be well past anything a limit
below it would cut.

A name the decoder wrote and the encoder will not read back is a disagreement
between the two, and `fit_response` turns it into an empty TC answer; so is a
character-string over 255 bytes, which a one-byte length cannot have read. The
other encode errors are refusals the encoder makes on purpose (raw RDATA holding
a pointer, a question over the limit) and are not checked.
*/
reencode :: proc(raw: []u8) {
	m, err := dns.decode_message(raw)
	if err != .None {
		return
	}
	// Where the whole message will not encode, the limited encode below meets the
	// same error and judges it.
	size := len(raw)
	if whole, _, whole_err := dns.encode_message(m); whole_err == .None {
		size = len(whole)
	}
	limit := 512 + int(m.id) % max(1, size - 512)
	out, truncated, enc_err := dns.encode_message(m, max_size = limit)
	#partial switch enc_err {
	case .None:
	case .Bad_Escape, .Bad_Name, .Label_Too_Long, .Name_Too_Long, .Too_Large:
		panic("a decoded message does not encode")
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
	check_cut(m, again, truncated, limit)
}

/*
What the encoder promises about a cut, checked from the two messages rather than
from what it reported. Without TC the answer and authority sections come back
whole and the rcode the same, upper bits and all (RFC 6891 section 6.1.3). With
TC something was left out, and the OPT record is still there wherever the
question and the record fit on their own, since it carries the payload size,
cookie and extended error the client asks again with.
*/
check_cut :: proc(m, again: dns.Message, truncated: bool, limit: int) {
	if !truncated {
		if len(again.answer) != len(m.answer) || len(again.authority) != len(m.authority) {
			panic("records were cut without TC")
		}
		if dns.rcode_of(again) != dns.rcode_of(m) {
			panic("the rcode changed without TC")
		}
		return
	}
	// `truncated` is the encoder's own report and the counts are the messages',
	// so an input that already carried TC is judged like any other.
	if records_kept(again) >= records_kept(m) {
		panic("TC on an answer nothing was cut from")
	}
	opt, found := dns.find_opt(m)
	if !found || opt.name != "." {
		return
	}
	if _, raw_rdata := opt.data.(dns.Rdata_Raw); raw_rdata {
		return
	}
	alone := dns.Message{id = m.id, flags = m.flags, question = m.question, additional = {opt}}
	if fits, _, e := dns.encode_message(alone); e == .None && len(fits) <= limit && !dns.edns_present(again) {
		panic("a cut lost the OPT record it had room for")
	}
}

// Records a message carries once encoded: every one, but a second OPT record,
// which RFC 6891 section 6.1.1 forbids and the encoder leaves out.
records_kept :: proc(m: dns.Message) -> int {
	n := len(m.answer) + len(m.authority)
	opt_seen := false
	for rec in m.additional {
		if rec.type == .OPT {
			if opt_seen {
				continue
			}
			opt_seen = true
		}
		n += 1
	}
	return n
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
	// The two normalisations a client's answer goes through, checked for having
	// left no option behind and no OPT record at all.
	if out, ok := dns.strip_edns_options(raw); ok {
		if m, err := dns.decode_message(out); err == .None {
			for rec in m.additional {
				if opt, is_opt := rec.data.(dns.Rdata_OPT); is_opt && rec.type == .OPT && len(opt.options) > 0 {
					panic("a stripped OPT record still carries an option")
				}
			}
		}
	}
	if out, ok := dns.remove_opt(raw); ok {
		if m, err := dns.decode_message(out); err == .None && dns.edns_present(m) {
			panic("a removed OPT record is still there")
		}
	}
	// The per-client options the server takes out of a forwarded answer and
	// puts into one on its way back (cookie, extended error, keepalive), each
	// checked for having done it.
	if out, ok := dns.remove_edns_option(raw, .Cookie); ok {
		if _, found := dns.peek_edns_option(out, .Cookie); found {
			panic("a removed option is still there")
		}
	}
	if out, ok := dns.ensure_edns_option(raw, .Ext_Error, {0, 0}, 1232); ok {
		if _, found := dns.peek_edns_option(out, .Ext_Error); !found {
			panic("an ensured option is not there")
		}
	}

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
