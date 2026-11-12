package upstream

import "core:net"
import "core:sync"
import "core:sys/linux"
import "core:testing"
import "core:time"
import "elodin:config"

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
	fd_flags, fderr := linux.fcntl(linux.Fd(socket), linux.F_GETFD)
	testing.expect_value(t, fderr, linux.Errno.NONE)
	// F_GETFD answers the descriptor flags as a number, FD_CLOEXEC being 1.
	testing.expect(t, int(fd_flags) & 1 != 0, "the dialled socket survives an exec")
}

// Dials `reset_once_dial` has made; this file's test is its only user.
@(private = "file")
reset_once_dials: int

// The peer resetting the first dial before it connected, and the rest landing.
@(private = "file")
reset_once_dial :: proc(endpoint: net.Endpoint, timeout: time.Duration) -> (net.TCP_Socket, Error) {
	if sync.atomic_add(&reset_once_dials, 1) == 0 {
		return 0, .Dial_Reset
	}
	return dial_tcp_timeout(endpoint, timeout)
}

/*
A `tcp` upstream's connection is dialled through `open_stream`, so a dial the
peer reset before it connected is retried once, as a `tls` one's is. Which of a
reset dial and a reset handshake the same peer produces is the scheduler's luck,
and `Dial_Reset` exists so either is retried (#638).
*/
@(test)
test_a_tcp_dial_reset_before_it_connected_is_retried :: proc(t: ^testing.T) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, _ := net.bound_endpoint(listener)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "reset", kind = .TCP, address = "127.0.0.1", port = bound.port},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		return
	}
	defer destroy(u)
	u.dial = reset_once_dial

	c, err := dial_pipe(u, time.Second, time.Second)
	testing.expectf(t, err == .None, "a reset dial was not retried: %v", err)
	testing.expect_value(t, sync.atomic_load(&reset_once_dials), 2)
	pipe_unref(c)
}
