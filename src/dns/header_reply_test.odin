package dns

import "core:testing"

/*
The two replies built from a query's own header - the slipped TC answer and the
FORMERR fallback of `error_response` - state this server's flags, not the
client's: AA is clear because a forwarder is no authority (RFC 1035 section
4.1.1), and Z is clear because it "Must be zero in all queries and responses".
*/
@(test)
test_header_built_replies_clear_aa_and_z :: proc(t: ^testing.T) {
	query := Message {
		id       = 0xbeef,
		question = []Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	query.flags.aa = true
	query.flags.z = true
	wire, _, err := encode_message(query, context.temp_allocator)
	if !testing.expect_value(t, err, Encode_Error.None) {
		return
	}
	// The premise: the bits are on the wire as the client sent them.
	if !testing.expect(t, wire[2] & 0x04 != 0 && wire[3] & 0x40 != 0, "the fixture does not carry AA and Z") {
		return
	}

	tc, tc_ok := truncated_response(wire, 1232, context.temp_allocator)
	if testing.expect(t, tc_ok, "truncated_response built nothing") {
		testing.expectf(t, tc[2] & 0x04 == 0, "AA echoed on the slipped reply: flags %02x%02x", tc[2], tc[3])
		testing.expectf(t, tc[3] & 0x40 == 0, "Z echoed on the slipped reply: flags %02x%02x", tc[2], tc[3])
		testing.expect(t, tc[2] & 0x02 != 0, "TC not set on the slipped reply")
	}

	// An empty Message forces the fallback that patches the query's header.
	fe, fe_ok := error_response(wire, Message{}, .Form_Err, context.temp_allocator)
	if testing.expect(t, fe_ok, "error_response built nothing") {
		testing.expectf(t, fe[2] & 0x04 == 0, "AA echoed on the FORMERR fallback: flags %02x%02x", fe[2], fe[3])
		testing.expectf(t, fe[3] & 0x40 == 0, "Z echoed on the FORMERR fallback: flags %02x%02x", fe[2], fe[3])
		testing.expect_value(t, fe[3] & 0x0f, u8(Rcode.Form_Err))
	}
	free_all(context.temp_allocator)
}

/*
RFC 6891 section 6.1.1: "If an OPT record is present in a received request,
compliant responders MUST include an OPT record in their respective responses."
The slipped TC reply carries one when the query did - version 0, this server's
payload size, the query's DO bit (RFC 3225 section 3) - and none otherwise. A
query whose OPT record cannot be read, or that asks in a version above 0, keeps
the header-only reply: the full path answers those FORMERR or BADVERS.
*/
@(test)
test_slipped_reply_carries_opt_when_the_query_did :: proc(t: ^testing.T) {
	ADVERTISE :: u16(1400)

	Case :: struct {
		what:     string,
		opts:     []Record,
		want_opt: bool,
		want_do:  bool,
	}
	v1 := make_opt(1232, false)
	v1.ttl |= 1 << 16
	not_root := make_opt(1232, false)
	not_root.name = "example."
	CASES := []Case {
		{what = "no OPT", opts = nil},
		{what = "OPT, DO clear", opts = {make_opt(1232, false)}, want_opt = true},
		{what = "OPT, DO set", opts = {make_opt(4096, true)}, want_opt = true, want_do = true},
		{what = "OPT in version 1", opts = {v1}},
		{what = "OPT owned by a name other than the root", opts = {not_root}},
	}

	for c in CASES {
		query := Message {
			id         = 0x1234,
			question   = []Question{{name = "example.com.", type = .A, class = .IN}},
			additional = c.opts,
		}
		query.flags.rd = true
		wire, _, err := encode_message(query, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: the fixture did not encode: %v", c.what, err) {
			continue
		}
		_, has_opt := find_opt_span(wire)
		if !testing.expectf(t, has_opt == (c.opts != nil), "%s: the fixture's OPT is not where the case says", c.what) {
			continue
		}

		out, ok := truncated_response(wire, ADVERTISE, context.temp_allocator)
		if !testing.expectf(t, ok, "%s: no reply built", c.what) {
			continue
		}
		decoded, derr := decode_message(out, context.temp_allocator)
		if !testing.expectf(t, derr == .None, "%s: the reply does not decode: %v", c.what, derr) {
			continue
		}
		testing.expectf(t, decoded.flags.tc, "%s: TC not set", c.what)
		testing.expectf(t, len(decoded.question) == 1, "%s: %d questions echoed", c.what, len(decoded.question))
		opt, found := find_opt(decoded)
		testing.expectf(t, found == c.want_opt, "%s: OPT in the reply = %v", c.what, found)
		testing.expectf(t, len(decoded.additional) == (1 if c.want_opt else 0), "%s: ARCOUNT %d", c.what, len(decoded.additional))
		if found {
			testing.expectf(t, u16(opt.class) == ADVERTISE, "%s: payload size %d", c.what, u16(opt.class))
			testing.expectf(t, edns_version(decoded) == 0, "%s: version %d", c.what, edns_version(decoded))
			testing.expectf(t, edns_do(decoded) == c.want_do, "%s: DO = %v", c.what, edns_do(decoded))
			od, is_opt := opt.data.(Rdata_OPT)
			testing.expectf(t, is_opt && len(od.options) == 0, "%s: options %v", c.what, opt.data)
		}
	}
	free_all(context.temp_allocator)
}
