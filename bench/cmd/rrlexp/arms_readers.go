package main

/*
The arms about `listeners.udp.readers`: what a bystander loses to a flood the
server cannot drain, and what a second, third and fourth reader buy back.

Every other arm here asks what the rate limiter does. This pair asks about the
ceiling above it. Everything a datagram costs before the limiter can see it -
the `recvfrom`, the allow-list compare, the siphash of the source prefix -
happens on the thread that read it, so with one reader the server hears at one
core's rate; past that the kernel's receive queue overflows and datagrams are
dropped by the socket. A datagram dropped there was never charged to anybody's
budget and never counted by anything in the server: the client whose query is
lost is whichever one the queue was full for, which is where the limiter's
fairness stops applying.

The arms below are `other-prefix/flat-out` with the reader count pinned at one,
two and four, so that the `read` and `queue drops` columns of the server table
can be compared across them: `read` is what the readers took off the sockets and
`queue drops` is what the kernel threw away because none of them got there first.

Pinned rather than derived, because the derived figure is this machine's CPU
count and a row that depends on it cannot be compared with a row taken anywhere
else. Run them with `-server-cpus`, or the arms differ by how much machine the
generator had as well as by the reader count - and even then, a generator on the
same box cannot settle this: see
`bench/results/2026-09-03-udp-readers.md`, which records what these arms did and
did not establish.

Note what they are no longer measuring. The victim's 36% loss that issue #233
was filed on was mostly the slip's doing - the truncated answers were charged to
no budget then, so the read loop was performing half a million sends a second of
its own - and issue #232 fixed that. What is left here is the drain rate itself.
*/
func readerArms() []arm {
	// The same flood and the same victim as `other-prefix/flat-out`: flat out,
	// from four sockets, at a prefix the victim is not in. Written out here
	// rather than shared, so that changing that arm cannot silently change what
	// this pair is comparing.
	flood := func() *clientSpec {
		return &clientSpec{src: "127.0.0.1", transport: "udp", rate: 0, sockets: 4}
	}
	victim := clientSpec{src: "127.1.0.1", transport: "udp", rate: *victimRate, sockets: 1}

	return []arm{
		{
			name:     "readers/one",
			question: "what a bystander loses when one thread has to read every datagram",
			limiter:  true, rps: *rps, slip: *slip, readers: 1,
			attacker: flood(),
			victim:   victim,
		},
		{
			name:     "readers/two",
			question: "the same flood with a second reader, on a server pinned to two CPUs",
			limiter:  true, rps: *rps, slip: *slip, readers: 2,
			attacker: flood(),
			victim:   victim,
		},
		{
			name:     "readers/four",
			question: "and with more readers than the server has CPUs, which is where they contend",
			limiter:  true, rps: *rps, slip: *slip, readers: 4,
			attacker: flood(),
			victim:   victim,
		},
	}
}
