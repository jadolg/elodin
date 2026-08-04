package dns

import "core:crypto"

/*
A transaction ID for a query this process is about to send.

RFC 5452 section 9.2 asks for an ID that nothing outside this process and the
server being asked can predict, and on UDP that is not a formality: the ID and
the ephemeral source port are the whole of what an off-path attacker has to
guess to have a forged datagram accepted as the answer. Everything else it needs
is either known (the upstream's address and port) or its own doing (the
question). Sixteen bits of the roughly thirty-one available live here.

It comes from the system entropy source rather than from a counter, a hash of
one, or the clock. A forwarder is asked by clients that choose the ID on the way
in, so an ID derived from anything a client can see, time or influence is one an
attacker can arrange to know - and a counter, however well mixed, tells whoever
has seen one ID what the next few will be. The clock is no better: `time.now()`
has whatever resolution the platform gives it, and low bits that only ever move
in thousands are low bits that are not there.

The getrandom() syscall behind this costs about 200 ns, against a query that is
about to spend milliseconds waiting for an upstream to answer, so nothing here
is worth buffering or stretching with a userspace generator.
*/
random_id :: proc() -> u16 {
	b: [2]u8
	crypto.rand_bytes(b[:])
	return u16(b[0]) << 8 | u16(b[1])
}
