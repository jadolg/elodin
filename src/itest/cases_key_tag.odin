package itest

import "core:fmt"
import "core:slice"
import "elodin:dns"

/*
RFC 8145 section 4.2.2: a client's own `edns-key-tag` option on its DNSKEY
question reaches the upstream, beside this server's anchors' tags in an option
of its own when it validates (4.2.2.1) and as it came when it does not
(4.2.2.2), and never comes back in the answer (4.2.2.1, 4.3).
*/
run_client_key_tag_cases :: proc(r: ^Runner) {
	run_client_key_tag_validating_case(r)
	run_client_key_tag_forwarding_case(r)
}

// The data of every edns-key-tag option in `wire`'s OPT record, in order; nil
// and a failed check when it does not decode.
@(private = "file")
key_tag_lists :: proc(r: ^Runner, wire: []u8, what: string) -> (lists: [dynamic][]u8, ok: bool) {
	if !check(r, wire != nil, "%s: nothing to read", what) {
		return nil, false
	}
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if !check(r, derr == .None, "%s does not decode: %v", what, derr) {
		return nil, false
	}
	opt, has_opt := dns.find_opt(m)
	if !check(r, has_opt, "%s carries no OPT record", what) {
		return nil, false
	}
	lists = make([dynamic][]u8, context.temp_allocator)
	for o in opt.data.(dns.Rdata_OPT).options {
		if o.code == u16(dns.EDNS_Option_Code.Key_Tag) {
			append(&lists, o.data)
		}
	}
	return lists, true
}

// A NODATA answer to `name`'s DNSKEY whose OPT record carries an edns-key-tag
// option, which RFC 8145 section 4.3 forbids a responder to send.
@(private = "file")
reply_with_key_tag :: proc(name: string) -> (wire: []u8, ok: bool) {
	question := []dns.Question{{name = name, type = .DNSKEY, class = .IN}}
	options := []dns.EDNS_Option{{code = u16(dns.EDNS_Option_Code.Key_Tag), data = []u8{0x99, 0x99}}}
	opt := dns.make_opt(1232, false)
	opt.data = dns.Rdata_OPT{options = options}
	additional := []dns.Record{opt}
	m := dns.Message {
		question   = question,
		additional = additional,
	}
	m.flags.qr, m.flags.rd, m.flags.ra = true, true, true
	out, _, err := dns.encode_message(m, context.allocator)
	return out, err == .None
}

// That `wire`'s edns-key-tag options are `want`, in order.
@(private = "file")
check_key_tag_lists :: proc(r: ^Runner, wire: []u8, what: string, want: [][]u8) {
	got, ok := key_tag_lists(r, wire, what)
	if !ok || !check(r, len(got) == len(want), "%s carries %d edns-key-tag options (%x), want %d (%x)", what, len(got), got[:], len(want), want) {
		return
	}
	for w, i in want {
		check(r, slice.equal(got[i], w), "%s: edns-key-tag option %d holds %x, want %x", what, i, got[i], w)
	}
}

/*
A validating server forwards a client's DNSKEY question for an anchored zone
with two options: the anchor's tag, 18109 (46bd), and the client's own list.
CD keeps the answer from being validated, so the client's is the only DNSKEY
query the upstream sees.
*/
@(private = "file")
run_client_key_tag_validating_case :: proc(r: ^Runner) {
	start_case(r, "dnssec: a client's edns-key-tag goes upstream beside the anchors' and not back (RFC 8145 section 4.2.2.1, #753)")
	defer end_case(r)
	upstream_port := next_port(r)
	mock := mock_make("key-tag-validating", upstream_port)
	for f in ANCHORED_REVERSE_FIXTURES {
		mock_reply(mock, f.qname, f.qtype, from_hex(f.response, context.allocator))
	}
	if !mock_start_or_skip(r, mock, "key-tag-validating") {
		return
	}
	defer mock_stop(mock)
	udp_port := next_port(r)
	config := dnssec_config(udp_port, upstream_port, []string{ROOT_DS, ANCHORED_REVERSE_ANCHOR}, extra = "special_use: {private_reverse: false}\n")
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	client := [][]u8{{0x12, 0x34, 0x46, 0xbd}}
	query := build_query("168.192.in-addr.arpa.", u16(dns.Type.DNSKEY), edns_size = 1232, dnssec_ok = true, checking_disabled = true, key_tags = client)
	res := query_udp(udp_port, query, context.temp_allocator)
	if !check(r, res.ok, "no answer to the DNSKEY question") {
		return
	}
	h := parse_header(r, res.wire)
	check(r, h.rcode == int(dns.Rcode.No_Error) && h.ancount > 0, "the premise: the DNSKEY question was answered (rcode %d, %d answers)", h.rcode, h.ancount)
	check_key_tag_lists(r, mock_last_query_of(mock, u16(dns.Type.DNSKEY)), "the forwarded DNSKEY query", {{0x46, 0xbd}, client[0]})
	check_key_tag_lists(r, res.wire, "the answer", nil)
}

/*
A non-validating server copies a client's edns-key-tag options onto its
DNSKEY question as they came, and onto no other: not onto an A question that
carried one, which RFC 8145 section 4.2 forbids, and not onto the DNSKEY
question a rewrite's CNAME chases to, whose zone the client's tags are not
about. No answer carries one back.
*/
@(private = "file")
run_client_key_tag_forwarding_case :: proc(r: ^Runner) {
	start_case(r, "upstream: a non-validating server copies a client's edns-key-tag onto its DNSKEY question only (RFC 8145 section 4.2.2.2, #753)")
	defer end_case(r)
	upstream_port := next_port(r)
	mock := mock_make("key-tag-forwarding", upstream_port)
	// An upstream that breaks RFC 8145 section 4.3 and answers with the option.
	if reply, built := reply_with_key_tag("plain.key-tag.test."); check(r, built, "the mock's reply does not encode") {
		mock_reply(mock, "plain.key-tag.test.", u16(dns.Type.DNSKEY), reply)
	}
	mock_synth_all(mock, {203, 0, 113, 59})
	if !mock_start_or_skip(r, mock, "key-tag-forwarding") {
		return
	}
	defer mock_stop(mock)
	udp_port := next_port(r)
	config := base_config(
		udp_port,
		fmt.tprintf("[udp://127.0.0.1:%d]", upstream_port),
		extra = "dnssec: { enabled: false }\nrewrites:\n  - { domain: alias.key-tag.test, answer: target.key-tag.test }\n",
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)
	client := [][]u8{{0x12, 0x34}, {0xab, 0xcd, 0x46, 0xbd}}

	ask_with_tags :: proc(r: ^Runner, udp_port: int, name: string, type: dns.Type, client: [][]u8) -> []u8 {
		res := query_udp(udp_port, build_query(name, u16(type), edns_size = 1232, key_tags = client), context.temp_allocator)
		if !check(r, res.ok, "no answer to %s %v", name, type) {
			return nil
		}
		check_key_tag_lists(r, res.wire, fmt.tprintf("the answer to %s %v", name, type), nil)
		return res.wire
	}

	ask_with_tags(r, udp_port, "plain.key-tag.test.", .DNSKEY, client)
	check_key_tag_lists(r, mock_last_query_of(mock, u16(dns.Type.DNSKEY)), "the forwarded DNSKEY query", client)
	upstream_reply, _ := mock_last_reply(mock) // lint:allow a count, not an error: `key_tag_lists` fails a nil reply
	check_key_tag_lists(r, upstream_reply, "the premise: the upstream's reply", {{0x99, 0x99}})

	ask_with_tags(r, udp_port, "plain.key-tag.test.", .A, client)
	check_key_tag_lists(r, mock_last_query_of(mock, u16(dns.Type.A)), "the forwarded A query", nil)

	ask_with_tags(r, udp_port, "alias.key-tag.test.", .DNSKEY, client)
	chased := mock_last_query_of(mock, u16(dns.Type.DNSKEY))
	if m, derr := dns.decode_message(chased, context.temp_allocator); check(r, derr == .None && len(m.question) == 1, "the chased DNSKEY query does not decode: %v", derr) {
		check(r, dns.name_equal_fold(m.question[0].name, "target.key-tag.test."), "the premise: the rewrite's target was asked, not %q", m.question[0].name)
	}
	check_key_tag_lists(r, chased, "the chased DNSKEY query", nil)
}
