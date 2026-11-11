package dns

import "core:testing"

/*
Every rebuild in edns.odin refuses a re-encode that had to truncate.

A rebuild can grow the message it was handed: the encoder writes an SRV target
in full, so a target the sender compressed comes back longer. A stream answer
near `MAX_MESSAGE` then re-encodes past it, and a rebuild that kept the
encoder's cut would hand back a message with records dropped and TC set - a
stream client told to ask again over the TCP it is already on.
*/

// SRV records whose owner and target both point at the question name, so each
// is 20 bytes on the wire and 29 once the encoder writes the target in full.
@(private = "file")
GROWING_SRVS :: 3200

/*
A response near 64 KiB of compressed SRV answers, with the OPT record (when
asked for) followed by an A record, so every writer has to take the rebuild
path rather than cut bytes off the end.
*/
@(private = "file")
growing_answer :: proc(with_opt: bool, option := false, srvs := GROWING_SRVS) -> []u8 {
	buf := make([dynamic]u8, 0, 65535, context.temp_allocator)
	arcount := 1 + (1 if with_opt else 0)
	append(&buf, 0x42, 0x42, 0x81, 0x80, 0, 1, u8(srvs >> 8), u8(srvs & 0xff), 0, 0, 0, u8(arcount))
	append(&buf, 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 33, 0, 1)
	for _ in 0 ..< srvs {
		// owner, SRV IN, TTL 300, RDLENGTH 8, priority 1 weight 1 port 53, target
		append(&buf, 0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 1, 0x2c, 0, 8, 0, 1, 0, 1, 0, 53, 0xc0, 0x0c)
	}
	if with_opt {
		if option {
			// NSID "x"
			append(&buf, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 1, 'x')
		} else {
			append(&buf, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
		}
	}
	append(&buf, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1)
	return buf[:]
}

/*
`ok` is allowed only on a message that came back whole: TC clear and every
answer still there. A refusal is what the callers already handle - each has a
fallback for it.
*/
@(private = "file")
expect_whole_or_refused :: proc(t: ^testing.T, out: []u8, ok: bool, label: string) {
	if !ok {
		return
	}
	m, derr := decode_message(out, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "%s: the rebuild does not decode: %v", label, derr) {
		return
	}
	testing.expectf(t, !m.flags.tc, "%s: the rebuild came back cut, with TC set, and ok", label)
	testing.expectf(t, len(m.answer) == GROWING_SRVS, "%s: %d of %d answers survived", label, len(m.answer), GROWING_SRVS)
}

@(test)
test_every_rebuild_refuses_a_reencode_that_outgrew_the_message :: proc(t: ^testing.T) {
	plain := growing_answer(true)
	with_nsid := growing_answer(true, option = true)
	bare := growing_answer(false)

	// The premise: the input fits, and its re-encode does not.
	testing.expectf(t, len(plain) <= MAX_MESSAGE, "the input is %d bytes, over the limit", len(plain))
	m, derr := decode_message(plain, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	_, truncated, eerr := encode_message(m, context.temp_allocator, MAX_MESSAGE)
	testing.expect_value(t, eerr, Encode_Error.None)
	testing.expect(t, truncated, "the re-encode fits, so this test proves nothing")

	out, ok := remove_opt(plain, context.temp_allocator)
	expect_whole_or_refused(t, out, ok, "remove_opt")

	out, ok = set_edns_option(plain, .NSID, transmute([]u8)string("y"), context.temp_allocator)
	expect_whole_or_refused(t, out, ok, "set_edns_option")

	out, ok = remove_edns_option(with_nsid, .NSID, context.temp_allocator)
	expect_whole_or_refused(t, out, ok, "remove_edns_option")

	out, ok = strip_edns_options(with_nsid, context.temp_allocator)
	expect_whole_or_refused(t, out, ok, "strip_edns_options")

	out, ok = ensure_opt_compressed(bare, 1232, context.temp_allocator)
	expect_whole_or_refused(t, out, ok, "ensure_opt_compressed")
}

/*
A re-encode whose answers still fit but whose OPT record no longer does. The
encoder leaves the record out of a complete answer without setting TC, so an
option writer that took that as `ok` would hand back a message with no OPT
record at all - the option it was asked to write, and every other, gone.

2258 SRVs re-encode to 65509 bytes: room for the bare record, not for one
carrying a 20-byte option.
*/
@(test)
test_a_rebuild_that_drops_its_opt_record_is_refused :: proc(t: ^testing.T) {
	SRVS :: 2258
	plain := growing_answer(true, srvs = SRVS)
	data := make([]u8, 20, context.temp_allocator)

	out, ok := set_edns_option(plain, .NSID, data, context.temp_allocator)
	if !ok {
		free_all(context.temp_allocator)
		return
	}
	m, derr := decode_message(out, context.temp_allocator)
	testing.expect_value(t, derr, Decode_Error.None)
	testing.expectf(t, len(m.answer) == SRVS, "%d of %d answers survived", len(m.answer), SRVS)
	opt, has_opt := find_opt(m)
	testing.expect(t, has_opt, "set_edns_option came back ok with no OPT record")
	if has_opt {
		rdata, _ := opt.data.(Rdata_OPT)
		testing.expectf(t, len(rdata.options) == 1, "set_edns_option came back ok with options %v", rdata.options)
	}
	free_all(context.temp_allocator)
}
