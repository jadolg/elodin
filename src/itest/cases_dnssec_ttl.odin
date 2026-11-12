package itest

import "core:strings"
import "elodin:dns"

/*
Issue #337: a validated answer goes out with no more TTL than its signature
allows (RFC 4035 section 5.3.3).

The TTL field is the one part of a record no RRSIG covers, so an answer whose
TTLs were raised on the path still validates. The mock serves a whole signed
chain - scenario `deep_run_of_empty_non_terminals` of
`testdata/gen/sign_fixtures.py`, copied by key, the same bytes
`src/dnssec/minted_denial_test.odin` reads - with every TTL in the answer raised
to a week, and the client must see AD and no TTL over the RRSIG's Original TTL:
from the fresh answer, from the cache, and with the signatures stripped for a
client that did not ask for them.
*/

@(private = "file")
TTL_ANCHOR :: ". IN DS 53447 15 2 466D69A4558C0297C2B2CAE4867A8156C47696CA6C7990070C0988D0B2BA2090"

@(private = "file")
TTL_QNAME :: "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest."

@(private = "file")
TTL_RAISED :: 604800

@(private = "file")
TTL_FIXTURES := []Fixture{
	{
		key      = "dr_root_dnskey",
		qname    = ".",
		qtype    = 48,
		response = "1234858000010002000000000000300001000030000100000e1000240101030fde306b46123761bf4844692b2f015019" +
			"0c044d26c77dc73bfcc1cd0a8d439fcb00002e000100000e10005300300f0000000e107d3b18206a478820d0c70080f4" +
			"037d933b1e30dc90a08a968a6cab939724334ae2eeed5a6c8bb5910087fb5dd070f35ccf2a9fbfc8192d30d614550dd4" +
			"d5181eeb430840b565e77b4a7008",
	},
	{
		key      = "dr_ds",
		qname    = "drtest.",
		qtype    = 43,
		response = "1234858000010002000000000664727465737400002b00010664727465737400002b000100000e100024979c0f02589e" +
			"a37ced5411574b33601e7ab21825d1c07a68b75cd87a0917130af327373b0664727465737400002e000100000e100053" +
			"002b0f0100000e107d3b18206a478820d0c700b32cb085caed54ff8ab502986e8f44fc7b064f1e163d9bfd0d2cb89012" +
			"38710197cb5f0abb0ffad36be81faf43207475294ba0cd1f22782ad70a2284c829c109",
	},
	{
		key      = "dr_dnskey",
		qname    = "drtest.",
		qtype    = 48,
		response = "12348580000100020000000006647274657374000030000106647274657374000030000100000e1000240101030f2ab6" +
			"0ae3e0f5bce02cbe2b056532161861914462c55b5c638bccf126a93eff290664727465737400002e000100000e10005a" +
			"00300f0100000e107d3b18206a478820979c0664727465737400d4865c6e2ffde4cb7138dfc1a15096070f00d6094de7" +
			"b0d0ae334716c5a0d38cee26ecf79c8542e4c3aaa1c7b3abfeeca99161652c2471c618e4ae26aee8540d",
	},
	{
		key      = "dr_ds_l1",
		qname    = "l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002b0001" +
			"026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002f000100000e10002a0100026c3102" +
			"6c32026c33026c34026c35026c36026c37026c3806647274657374000006000000000003026c31026c32026c33026c34" +
			"026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f0900000e107d3b18206a478820979c" +
			"0664727465737400fe1b4e2ffad6c4dfd57f81290b5400a04f70cb180ead6acc9adcdf7b35e83f5567d93bfaa8d99e2e" +
			"76224359b4cae5f944d56231ec98a482633ba3e84a802709",
	},
	{
		key      = "dr_ds_l2",
		qname    = "l2.l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c32026c33026c34026c35026c36026c37026c380664727465737400002b0001026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002f000100000e1000270100026c32026c33026c3402" +
			"6c35026c36026c37026c3806647274657374000006000000000003026c32026c33026c34026c35026c36026c37026c38" +
			"0664727465737400002e000100000e10005a002f0f0800000e107d3b18206a478820979c0664727465737400b2048454" +
			"0be55ea56899074b80c81cd4219c29ddfa4d428c4cb36a3dbbb61b3e83261b87b584395155821f1bd4eb37dc3b3c5796" +
			"58504ab9d4535c4c6603c30e",
	},
	{
		key      = "dr_ds_l3",
		qname    = "l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c33026c34026c35026c36026c37026c380664727465737400002b0001026c33026c34" +
			"026c35026c36026c37026c380664727465737400002f000100000e1000240100026c33026c34026c35026c36026c3702" +
			"6c3806647274657374000006000000000003026c33026c34026c35026c36026c37026c380664727465737400002e0001" +
			"00000e10005a002f0f0700000e107d3b18206a478820979c0664727465737400f3ed962537e1ecdf8fa0c5c11c44a6ae" +
			"d6fffd095d4c667dfe7c5e87e72d977a5886c17774393aec4592bdbe1aa937984c3a52aa63521dce00b596133cc95f04",
	},
	{
		key      = "dr_ds_l4",
		qname    = "l4.l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c34026c35026c36026c37026c380664727465737400002b0001026c34026c35026c36" +
			"026c37026c380664727465737400002f000100000e1000210100026c34026c35026c36026c37026c3806647274657374" +
			"000006000000000003026c34026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f060000" +
			"0e107d3b18206a478820979c0664727465737400cf077c3e866848058e2ca3e5ccec717489af65ae8d39fca376316d19" +
			"4263d413e3302e8872a0f145c26c310aa98d059a5519a8e18ac5de37f25607cfda880b0e",
	},
	{
		key      = "dr_ds_l5",
		qname    = "l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c35026c36026c37026c380664727465737400002b0001026c35026c36026c37026c38" +
			"0664727465737400002f000100000e10001e0100026c35026c36026c37026c3806647274657374000006000000000003" +
			"026c35026c36026c37026c380664727465737400002e000100000e10005a002f0f0500000e107d3b18206a478820979c" +
			"0664727465737400b54d4cf2d179877ff0dd83502c0de9835e596d820431ce01004a6a4ecc06164eb134335271497eef" +
			"e34b80472981d0996cabf2dcbaa97f539cd139f218c39a04",
	},
	{
		key      = "dr_ds_l6",
		qname    = "l6.l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c36026c37026c380664727465737400002b0001026c36026c37026c38066472746573" +
			"7400002f000100000e10001b0100026c36026c37026c3806647274657374000006000000000003026c36026c37026c38" +
			"0664727465737400002e000100000e10005a002f0f0400000e107d3b18206a478820979c0664727465737400edca654c" +
			"e10b1babbca6ae6dc04b1a523e5e8950cb26d92f3c0bae89923b9ced3fdaeddbca5b2da24dbe72f75b172515fc6712e2" +
			"658239e95609eb33d813f70b",
	},
	{
		key      = "dr_ds_l7",
		qname    = "l7.l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c37026c380664727465737400002b0001026c37026c380664727465737400002f0001" +
			"00000e1000180100026c37026c3806647274657374000006000000000003026c37026c380664727465737400002e0001" +
			"00000e10005a002f0f0300000e107d3b18206a478820979c066472746573740013546dc26538b7917db4b0c9629f0f88" +
			"5e8542dd06ffd742539f263ddc7cd0ba8d2d570369bdd060c431f8b59ad6663f5ca0fec9e2878273224f2d7cfa102603",
	},
	{
		key      = "dr_ds_l8",
		qname    = "l8.drtest.",
		qtype    = 43,
		response = "123485800001000000020000026c380664727465737400002b0001026c380664727465737400002f000100000e100015" +
			"0100026c3806647274657374000006000000000003026c380664727465737400002e000100000e10005a002f0f020000" +
			"0e107d3b18206a478820979c0664727465737400af23c6a9189517aa4665b409370bf6db4df0a54f62470a5045672df9" +
			"27140ae2500afa054fdd54d9c382b22c8470d72fc34275fbc78347d44618491964a41403",
	},
	{
		key      = "dr_sub_ds",
		qname    = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 43,
		response = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"002b000103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002b000100000e10" +
			"0024cea60f022d6d2aa542713cfa3d696a27d868ad3878e3589dfdd1fb30657706e619cb581203737562026c31026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002e000100000e10005a002b0f0a00000e107d3b1820" +
			"6a478820979c0664727465737400b347ae39750320ea5c8acd9ed30f22c68e8f9fb7f79b3d7868f4e66b994c0bf34766" +
			"6e895464b975f44ffd56232eeb675a007daa6e00de5092c64407fd132203",
	},
	{
		key      = "dr_sub_dnskey",
		qname    = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 48,
		response = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"0030000103737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000030000100000e10" +
			"00240101030f3e08aabfb6984cc366becf0853851f546f541a01e6269e743e5ea48bd12673d003737562026c31026c32" +
			"026c33026c34026c35026c36026c37026c380664727465737400002e000100000e10007600300f0a00000e107d3b1820" +
			"6a478820cea603737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000c2373b08768" +
			"aa442c6ee25aeb21b11a5fa1eec30424d442d8414f79e15d6bbf2fa5338d1b056e81cc9b3c7d2f5e334dc34e471220f0" +
			"a899dbb31250bdfd2b07",
	},
	{
		key      = "dr_sub_answer",
		qname    = "sub.l1.l2.l3.l4.l5.l6.l7.l8.drtest.",
		qtype    = 1,
		response = "12348580000100020000000003737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400" +
			"0001000103737562026c31026c32026c33026c34026c35026c36026c37026c3806647274657374000001000100000e10" +
			"0004c000020103737562026c31026c32026c33026c34026c35026c36026c37026c380664727465737400002e00010000" +
			"0e10007600010f0a00000e107d3b18206a478820cea603737562026c31026c32026c33026c34026c35026c36026c3702" +
			"6c3806647274657374005f28964758c450d9879d586223df7d0581a1d8821cdc729f0b6bd5b55619ae972ead77c40b47" +
			"be621d8d4c1da973979e491ad683db70912be181d4451d433507",
	},
}

// The answer with every TTL raised, and the Original TTL its RRSIG carries.
@(private = "file")
raised_answer :: proc(wire: []u8) -> (out: []u8, original: u32, ok: bool) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, 0, false
	}
	original = max(u32)
	for &rec in msg.answer {
		rec.ttl = TTL_RAISED
		if raw, is_raw := rec.data.(dns.Rdata_Raw); is_raw && rec.type == .RRSIG && len(raw.data) >= 8 {
			original = min(original, pw_u32(raw.data, 4))
		}
	}
	encoded, _, eerr := dns.encode_message(msg, context.allocator)
	return encoded, original, eerr == .None && original < TTL_RAISED
}

// The mock serving the chain, with the answer's ttls raised; not started.
@(private = "file")
ttl_mock :: proc(r: ^Runner) -> (mock: ^Mock, reference: []u8, original: u32, ok: bool) {
	mock = mock_make("dnssec-ttl", next_port(r))
	for f in TTL_FIXTURES {
		wire := from_hex(f.response, context.allocator)
		if f.key == "dr_sub_answer" {
			wire, original = raised_answer(wire) or_return
			reference = wire
		}
		mock_reply(mock, f.qname, f.qtype, wire)
	}
	return mock, reference, original, true
}

run_dnssec_ttl_cases :: proc(r: ^Runner) {
	mock, reference, original, built := ttl_mock(r)
	if !built {
		skip_case(r, "dnssec: served ttl", "cannot raise the answer's ttls")
		mock_stop(mock)
		return
	}
	if !mock_start_or_skip(r, mock, "dnssec: served ttl") {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := dnssec_config(udp_port, mock.port, []string{TTL_ANCHOR}, log = "{ level: info }", cache = "{ enabled: true }")
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	cases := []struct {
		name:      string,
		dnssec_ok: bool,
		records:   int,
	} {
		{"dnssec: a raised ttl is served no higher than the signature's original ttl", true, 2},
		{"dnssec: the cached copy of that answer keeps the ceiling", true, 2},
		{"dnssec: and so does the copy stripped for a client without DO", false, 1},
	}
	for c, i in cases {
		start_case(r, c.name)
		asked := mock_total(mock)
		res := query_udp(udp_port, build_query(TTL_QNAME, u16(dns.Type.A), edns_size = 1232, dnssec_ok = c.dnssec_ok))
		// The second case is the same question again, so it has to be the cache's copy.
		if i == 1 {
			check(r, mock_total(mock) == asked, "the repeated question went upstream rather than to the cache")
		}
		if check(r, res.ok, "no response") {
			if msg, decoded := decode_reply(r, res.wire); decoded {
				check_eq_int(r, int(dns.rcode_of(msg)), int(dns.Rcode.No_Error), "rcode")
				// A client that set neither DO nor AD is not told (RFC 6840 section 5.8).
				check(r, msg.flags.ad == c.dnssec_ok, "AD is %v for a client with DO %v", msg.flags.ad, c.dnssec_ok)
				check_eq_int(r, len(msg.answer), c.records, "answer records")
				for rec in msg.answer {
					check(r, rec.ttl <= original, "%v went out with ttl %d over an original ttl of %d", rec.type, rec.ttl, original)
				}
			}
		}
		end_case(r)
	}

	start_case(r, "parity: a ttl lowered to the signature's ceiling is the validator's job, not a divergence")
	parity_signed_ttl_case(r, udp_port, reference, original)
	end_case(r)
}

/*
The comparison has to know the clamp above is required (RFC 4035 section
5.3.3), and has to know it by that name: every ttl it finds lowered is put down
to the signature, and nothing is left unexplained.
*/
@(private = "file")
parity_signed_ttl_case :: proc(r: ^Runner, udp_port: int, reference: []u8, original: u32) {
	q := Parity_Query {
		id        = 0x3370,
		qtype     = u16(dns.Type.A),
		qclass    = 1,
		rd        = true,
		edns      = true,
		udp_size  = 1232,
		do_bit    = true,
		transport = .UDP,
		desc      = TTL_QNAME,
	}
	q.wire = build_query(TTL_QNAME, q.qtype, q.id, q.qclass, q.udp_size, dnssec_ok = true)
	if m := pw_parse(q.wire, context.temp_allocator); m.ok && len(m.question) == 1 {
		q.name = m.question[0].name
	}
	res := query_udp(udp_port, q.wire, context.temp_allocator)
	if !check(r, res.ok, "no response") {
		return
	}
	/*
	The reference as the mock sent it, under this query's id and with AD set.
	The mock mode reads any AD of elodin's as invented, since its zone has no
	chain; this one has, so the bit is taken as agreed and the comparison is
	left to the ttls.
	*/
	up := make([]u8, len(reference), context.temp_allocator)
	copy(up, reference)
	up[0], up[1] = u8(q.id >> 8), u8(q.id)
	up[3] |= 0x20
	policy := Parity_Policy {
		mode              = .Mock,
		dnssec_validation = true,
		ttl_exact         = true,
		transport         = .UDP,
		client_udp_limit  = 1232,
		cache             = true,
		cache_age         = 5,
	}
	signed := signed_diffs(r, parity_compare(q, up, res.wire, policy))
	check(r, signed == 2, "%d of the answer's two lowered ttls were put down to the signature", signed)

	/*
	And the set's own received TTLs, the other half of the same minimum: an
	upstream that sent the RRSIG at 200 gets its A back at 200 too. Built from
	the answer above rather than asked for, since the mock serves one copy.
	*/
	low_up, lowered := lowered_rrsig(up, 200)
	if !check(r, lowered, "the reference could not be rewritten with a lower rrsig ttl") {
		return
	}
	low_el := make([]u8, len(res.wire), context.temp_allocator)
	copy(low_el, res.wire)
	dns.cap_ttls(low_el, 200)
	signed = signed_diffs(r, parity_compare(q, low_up, low_el, policy))
	check(r, signed == 1, "%d of the set's ttls were put down to the rrsig's received one", signed)
}

// How many of a comparison's differences are put down to RFC 4035 section 5.3.3,
// failing the case on any difference left unexplained.
@(private = "file")
signed_diffs :: proc(r: ^Runner, c: Parity_Compare) -> int {
	signed := 0
	for d in c.diffs {
		if d.reason == "" {
			fail(r, "%s: upstream %s, elodin %s", d.what, d.upstream, d.elodin)
		} else if strings.contains(d.reason, "RFC 4035 section 5.3.3") {
			signed += 1
		}
	}
	return signed
}

// The reply with its RRSIGs' TTLs set to `ttl` and nothing else changed; not ok
// when it cannot be decoded or encoded again.
@(private = "file")
lowered_rrsig :: proc(wire: []u8, ttl: u32) -> (out: []u8, ok: bool) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	for &rec in msg.answer {
		if rec.type == .RRSIG {
			rec.ttl = ttl
		}
	}
	encoded, _, eerr := dns.encode_message(msg, context.temp_allocator)
	return encoded, eerr == .None
}
