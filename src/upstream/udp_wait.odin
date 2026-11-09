package upstream

import "core:net"
import "core:time"
import "elodin:loop"

/*
`loop.recv_udp_until` and `loop.send_udp_until`, for every UDP wait in this
package, so a test can read the deadline each was handed.

That a stage shares its exchange's deadline - a cookie retry, a bootstrap query,
a read after a stray - is then a comparison of deadlines, where judging how long
the exchange took against a margin is one a scheduler stall can cross (issue
#556). Kept per thread: the package's tests run in parallel, and each runs its
exchanges on its own thread, off the loop. Waits from fibers sharing a loop
thread land in one record, so a test that reads it runs one exchange at a time
on its thread. Written only in tests; declared in every build, as
`odin check` compiles the test files without `ODIN_TEST`. `mise run check`
keeps every other file in the package off the `loop` UDP calls, so a new wait
cannot go round the record.
*/
@(private)
Udp_Wait :: struct {
	// When the wait began, and the deadline it was handed.
	at, deadline: time.Tick,
}

@(private, thread_local)
udp_waits: [16]Udp_Wait

// How many waits there were since the test reset it, past the 16 kept too.
@(private, thread_local)
udp_wait_count: int

@(private)
note_udp_wait :: #force_inline proc(deadline: time.Tick) {
	when ODIN_TEST {
		if udp_wait_count < len(udp_waits) {
			udp_waits[udp_wait_count] = {loop.tick_now(), deadline}
		}
		udp_wait_count += 1
	}
}

@(private)
udp_recv_until :: proc(socket: net.UDP_Socket, buf: []u8, deadline: time.Tick) -> (int, net.Endpoint, net.UDP_Recv_Error) {
	note_udp_wait(deadline)
	return loop.recv_udp_until(socket, buf, deadline)
}

@(private)
udp_send_until :: proc(socket: net.UDP_Socket, buf: []u8, deadline: time.Tick) -> (int, net.UDP_Send_Error) {
	note_udp_wait(deadline)
	return loop.send_udp_until(socket, buf, deadline)
}
