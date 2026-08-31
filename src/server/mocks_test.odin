package server

import "core:net"
import "core:time"

/*
How long a mock upstream waits for the query it was started to answer.

Every mock upstream in this package has the same shape: the test binds a socket,
points the resolver's only upstream at it, starts the mock on a thread and then
calls `handle_query` on the test thread. The mock's wait therefore begins when
its thread is scheduled and covers everything that happens before the test
thread reaches the send - and nothing bounds that gap. The resolver's own
`upstream.timeout` does not: it only starts running once the query is on the
wire.

So this is a bound on a hang and nothing else, the same job `Send_Timeout`
does for the sender in `test_a_refusal_outlives_a_body_that_is_still_arriving`.
A value tight enough to double as a deadline on the exchange asserts a property
of the machine instead of one of the resolver: two seconds was enough to fail
`Tests (arm64)` at random, on a loaded shared runner where the whole package
took 5.1s against ~3.3s locally, with `the upstream was never asked` - a
statement about the scheduler dressed up as one about forwarding (#191).

Well past every `upstream.timeout` the harnesses here configure, so the resolver
is what gives up first: a query that genuinely never comes fails the exchange on
the test thread, and the mock is only what stops the join behind it from waiting
forever.

A mock that is there to report that *nothing* arrived wants the opposite of this
and does not use it: `mock_untouched` below reads the socket after the call has
returned rather than racing it, which is both exact and quick.
*/
MOCK_RECV_TIMEOUT :: 10 * time.Second

/*
Whether the upstream was left alone, read once `handle_query` has returned.

For the cases that expect nothing to be forwarded at all. No mock thread, and so
nothing to race: a query this server forwards is written to the socket before the
call can return, so anything that leaked is already sitting in the receive buffer
by the time this looks. A mock started beforehand can only be worse at the same
job - it stops waiting on a timer, and a leak that arrives after it gave up is a
leak the test reports as absence.

Not zero milliseconds: `SO_RCVTIMEO` reads zero as "no timeout", which on a socket
nothing is going to send to is the one value that hangs. `nothing_reached` in
special_use_test.odin is this same reading, kept there because it also wants the
question the leaked query asked.
*/
mock_untouched :: proc(socket: net.UDP_Socket) -> bool {
	_ = net.set_option(socket, .Receive_Timeout, 20 * time.Millisecond)
	// Left as the harnesses set it, so a fixture socket can be read this way in
	// the middle of a test that goes on to expect an exchange.
	defer _ = net.set_option(socket, .Receive_Timeout, MOCK_RECV_TIMEOUT)
	buf: [4096]u8
	n, _, err := net.recv_udp(socket, buf[:])
	return err != nil || n == 0
}
