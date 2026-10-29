package upstream

import "core:net"
import "core:sys/linux"
import "core:testing"
import "core:time"

/*
A dialled connection stays non-blocking (#547).

Everything that reads or writes it - a pipelined TCP upstream, a UDP upstream's
retry over TCP, the DoH clients - does so on a fiber, through `loop`'s socket
calls, which wait for readiness on the loop instead of in the kernel. A socket
handed back in blocking mode makes each of those reads sleep in the kernel for
up to the upstream's timeout, and every other fiber on the loop with it; nothing
fails, the loop just answers one query at a time.
*/
@(test)
test_a_dialled_connection_stays_non_blocking :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)

	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial: %v", derr) {
		return
	}
	defer net.close(socket)
	flags, ferr := linux.fcntl(linux.Fd(socket), linux.F_GETFL)
	testing.expect_value(t, ferr, linux.Errno.NONE)
	testing.expect(t, .NONBLOCK in flags, "the dialled socket is blocking")
}
