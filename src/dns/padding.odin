package dns

import "core:mem"

/*
EDNS(0) padding (RFC 7830), sized by the policy in RFC 8467.

Encryption hides what a message says, not how long it is, and DNS messages are
distinctive enough by length that an observer holding a list of candidate names
can often tell which one was asked. Padding is the defined answer: an option
carrying nothing but zeroes, sized so the whole message lands on a block
boundary. Every question whose natural length falls in the same block then
leaves the same footprint on the wire.

Worth doing on an encrypted transport and nowhere else. RFC 8467 section 5 says
as much - padding a message anyone can read hides nothing from anyone - and on
UDP the bytes would come out of the response budget that bounds this server's
amplification factor, which is a real cost paid for no confidentiality at all.
So the two callers are the DoT and DoH paths in either direction, and this file
has no opinion about the rest.

Both procedures work on wire bytes rather than on a `Message`, for the reason
the rest of `edns.odin` does: the messages that need padding are an upstream's
reply, a cache entry or a query being relayed, and decoding one only to encode
it again would throw away the name compression it arrived with.

The size is measured twice on purpose. Adding the option can cost more than the
four bytes of its header - a message whose OPT record is not the last thing in
it has to be rebuilt through the encoder, which is free to compress names
differently than whoever wrote the bytes did - so the length after the option
goes in is a fact to be read rather than one to be predicted. The first write is
the measurement, the second is the padding, and the result is checked against
the block before it is handed back.
*/

// RFC 8467 section 4.1: a client pads its queries to a multiple of 128 octets.
PAD_QUERY_BLOCK :: 128
// RFC 8467 section 4.2: a responder pads its responses to a multiple of 468.
PAD_RESPONSE_BLOCK :: 468

/*
The largest block either procedure will pad to.

The zeroes come from the stack, so the block has a ceiling; 512 is the smallest
round number above RFC 8467's larger recommendation, and a caller asking for
more than that is asking for a policy this file does not implement.
*/
@(private)
PAD_BLOCK_MAX :: 512

/*
Pad an encoded query out to a multiple of `block` octets.

`limit` bounds the padded message, and a query that cannot reach the next
boundary within it is left alone rather than padded partway: a message rounded
to something other than a block boundary states its own size just as precisely
as an unpadded one, and the caller still has a query it can send.

Fails when the query carries no OPT record, and that is deliberate rather than a
gap. An option has nowhere to live without one, and minting one would start an
EDNS negotiation on behalf of a client that did not ask for it - the same
reasoning that keeps `upstream.attach_cookie` from adding a record to carry a
cookie. What comes back from the upstream would change shape, and the client
that never sent an OPT record must not be handed one back (RFC 6891 section
6.2.2). A query that already has the record - which is nearly all of them, and
every query this server generates for itself - is padded; the rest go as they
are.

`ok` is false for every one of those, and it means "this is not padded", never
"this cannot be sent". Callers send `msg` unchanged.
*/
pad_query :: proc(
	msg: []u8,
	block: int,
	limit: int,
	allocator := context.allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	return pad_message(msg, block, limit, 0, false, allocator)
}

/*
Pad an encoded response out to a multiple of `block` octets.

As `pad_query`, except that a response with no OPT record gets one, advertising
`udp_size`. The client asked with EDNS - it sent a padding option, which is what
makes this response one to pad - and an answer that lost the record on the way
through an upstream that does not do EDNS is not a reason to hand that client an
unpadded reply. `attach_cookie` mints one in the same circumstances for the same
reason.

Any padding already on the message is replaced rather than added to, which is
what makes this safe to run over an upstream's own padded reply: the length that
matters is the one leaving here, on this transport, and the upstream's block
size was a statement about a different hop.
*/
pad_response :: proc(
	msg: []u8,
	block: int,
	limit: int,
	udp_size: u16,
	allocator := context.allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	return pad_message(msg, block, limit, udp_size, true, allocator)
}

@(private)
pad_message :: proc(
	msg: []u8,
	block: int,
	limit: int,
	udp_size: u16,
	mint_opt: bool,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	if block <= 1 || block > PAD_BLOCK_MAX || len(msg) < HEADER_SIZE {
		return nil, false
	}

	// An empty option, to learn what carrying one costs this message.
	probe, probed := pad_write(msg, nil, udp_size, mint_opt, allocator)
	if !probed {
		return nil, false
	}

	short := len(probe) % block
	if short == 0 {
		// The probe is the answer: the option's own header landed the message on
		// a boundary with nothing left to add.
		if len(probe) > limit {
			pad_release(probe, msg, allocator)
			return nil, false
		}
		return probe, true
	}

	need := block - short
	if len(probe) + need > limit {
		pad_release(probe, msg, allocator)
		return nil, false
	}

	// Zeroes, as RFC 7830 section 3 asks for. Odin zeroes an array by default,
	// and `need` is below `PAD_BLOCK_MAX` because `short` is above zero.
	zeroes: [PAD_BLOCK_MAX]u8
	written: bool
	out, written = pad_write(msg, zeroes[:need], udp_size, mint_opt, allocator)
	// Superseded either way, and it came out of `allocator`.
	pad_release(probe, msg, allocator)
	if !written {
		return nil, false
	}

	/*
	The measurement held, or the message does not go out padded.

	Both writes put the same option into the same message by the same route, so
	the second lands exactly `need` bytes past the first and both of these are
	always true. They are checked because the alternative to checking is
	trusting it: a message padded to something that is not a block boundary is
	one whose length still names it, and it would leave here looking like the
	mitigation had been applied - while one past `limit` is a message the
	transport was promised it would not be handed.
	*/
	if len(out) % block != 0 || len(out) > limit {
		pad_release(out, msg, allocator)
		return nil, false
	}
	return out, true
}

// Put `data` into the message's padding option, minting an OPT record for it
// only when the caller says one may be minted.
@(private)
pad_write :: proc(
	msg: []u8,
	data: []u8,
	udp_size: u16,
	mint_opt: bool,
	allocator: mem.Allocator,
) -> (
	out: []u8,
	ok: bool,
) {
	if mint_opt {
		return ensure_edns_option(msg, .Padding, data, udp_size, allocator)
	}
	return set_edns_option(msg, .Padding, data, allocator)
}

/*
Free a buffer this file made and is not returning.

On the arena paths this is a no-op, and on the race path `allocator` is the
process heap, where nothing else would ever reclaim it - see the leak
`rebuild_edns_option` used to hand that caller. Guarded against freeing the
input: every writer above allocates, but a free of the caller's own query would
be far worse than a buffer left behind, and the guard costs a comparison.
*/
@(private)
pad_release :: proc(buf: []u8, msg: []u8, allocator: mem.Allocator) {
	if buf == nil || raw_data(buf) == raw_data(msg) {
		return
	}
	delete(buf, allocator)
}
