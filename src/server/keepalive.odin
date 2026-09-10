package server

import "core:mem"
import "core:time"
import "elodin:dns"

/*
edns-tcp-keepalive, RFC 7828: telling a client on a connection how long this
server will hold it idle.

The number is `server.client_timeout` and nothing else. It is the receive
timeout `stream_job` puts on every TCP, DoT and DoH socket, so it is literally
"the TIMEOUT value that is currently associated with the TCP session" that
section 3.3.2 requires a server to specify - read from the same field at the
moment the answer is built rather than copied into a constant beside it, so an
operator who changes the setting changes what clients are told.

Without it the timeout is a thing a client can only learn by losing a
connection: it either re-handshakes on a cadence it guessed, or holds one it
believes is alive and finds out on its next query. Both are the handshake cost
`max_connections_per_prefix` and the connection rate limit are sized around,
paid again for want of two bytes in a record this server is minting anyway.

A MAY rather than a SHOULD - section 3.3.2 - and RFC 7858 section 3.4 declines
to require it of DoT at all, so nothing here is a conformance fix. The half that
is one is in `resolve_query`, where the client's own option is taken back out of
the query before it is forwarded.
*/

/*
`server.client_timeout` in the units RFC 7828 section 3.1 gives the TIMEOUT
field: 100 milliseconds, unsigned, network byte order.

Truncated rather than rounded, because the two directions of the error are not
worth the same. A client told less than the real timeout asks again early and
keeps its connection; one told more holds a connection this server has already
reclaimed and spends a round trip discovering it. So the figure sent is never
longer than the connection actually lives.

`ok` is false where there is no timeout to state. A non-positive
`client_timeout` is no receive timeout on the socket at all - `net.set_option`
reads it as "wait indefinitely" - and the only value this could send for that is
0, which section 3.4 defines as "close as soon as possible": the exact opposite
of what such a connection does. There is no encoding for "no idle timeout", so
the option is left off and the client is told nothing rather than told a lie.

The ceiling is the field's own. 65535 hundredths is a little under two hours,
and a `client_timeout` past that is clamped down to it for the same reason the
truncation goes that way.
*/
@(private)
keepalive_units :: proc(d: time.Duration) -> (units: u16, ok: bool) {
	if d <= 0 {
		return 0, false
	}
	hundredths := i64(d / (100 * time.Millisecond))
	if hundredths > i64(max(u16)) {
		return max(u16), true
	}
	// A timeout under 100ms floors to zero, which is the one value this may not
	// send by accident: it would tell the client to close at once. Such a
	// connection is closed at once in practice, but saying so is a decision and
	// not a rounding artefact, so it is left to the honest answer of saying
	// nothing.
	if hundredths == 0 {
		return 0, false
	}
	return u16(hundredths), true
}

/*
Put this server's idle timeout into an answer already encoded, for the clients
and the transports it means anything to.

Three conditions, and each is a rule rather than a policy.

The transport: TCP and DoT, which are the TCP sessions RFC 7828 is about. Not
UDP, where section 3.3.1 says a server "MUST ignore the option" - the gate here
is where that ignoring happens, and `keepalive_test.odin` pins it so that it
stays a decision rather than a side effect of some other check. Not DoH either,
where RFC 8484 section 10 rules the whole extension out: "Extensions that are
specific to the choice of transport, such as [RFC7828], are not applicable to
DoH." A DoH connection's lifetime is HTTP's business and is described by HTTP's
own headers, and `client_timeout` there is one bound among several that h2
imposes rather than the idle timeout of a DNS session.

The client having asked: section 3.3.2 permits answering any query that carried
an OPT record, with or without the option in it, and this server takes the
narrower reading for the reason `pad_answer` takes it about padding. An option a
client did not ask for is bytes it did not budget for, and a stub that does not
implement RFC 7828 has nothing to do with two it must then skip past. Section
3.2.1 has a client signal its interest by sending the option; a client that
signalled nothing is told nothing.

The answer having room: an option that will not fit is dropped and the answer
goes as it stands, which is what `pad_answer` does and for the same reason. The
limit on these transports is the 65535 of the DNS framing, so this is a message
already within six bytes of the largest one there is - and a client that reads
no keepalive option simply keeps its own idea of when to close, which is where
it was before this ran.

Ordered after `attach_cookie` and before `pad_answer`: it writes into the OPT
record the way the cookie does, so it must run after `match_client_opt` has
settled whose record that is, and before the padding, which is a statement about
a length nothing may change behind it.
*/
@(private)
attach_keepalive :: proc(
	s: ^Server,
	wire: []u8,
	query: dns.Message,
	proto: Protocol,
	limit: int,
	advertise: u16,
	allocator: mem.Allocator,
) -> []u8 {
	if proto != .TCP && proto != .DoT {
		return wire
	}
	if len(wire) < dns.HEADER_SIZE {
		return wire
	}
	if _, asked := dns.find_edns_option(query, .TCP_Keepalive); !asked {
		return wire
	}
	units, statable := keepalive_units(s.cfg.server.client_timeout)
	if !statable {
		return wire
	}
	value := [2]u8{u8(units >> 8), u8(units)}
	/*
	`ensure_edns_option` rather than `set_edns_option`, for the case
	`attach_cookie` reaches it for: an answer from an upstream that dropped EDNS
	has no OPT record to write into, and a client that asked with one expects one
	back. `advertise` is what that minted record reports, worked out once by the
	caller - on these transports it is the client's own figure, which is the only
	number available where this server has no datagram ceiling to state.
	*/
	out, ok := dns.ensure_edns_option(wire, .TCP_Keepalive, value[:], advertise, allocator)
	if !ok || len(out) > limit {
		return wire
	}
	return out
}
