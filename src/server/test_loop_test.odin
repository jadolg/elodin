package server

import "core:thread"
import "elodin:loop"

/*
One event loop on a thread of its own, for a test that drives the server from
the test's thread and needs somewhere for detached work to run - a refresh, a
query a reader admitted, an HTTP/2 request.

`stop_test_loop` returns once every fiber on the loop has finished, which is the
join a test needs before it tears down what those fibers were using.
*/
Test_Loop :: struct {
	loops:  [1]^loop.Loop,
	thread: ^thread.Thread,
}

start_test_loop :: proc(tl: ^Test_Loop) -> bool {
	l, ok := loop.make_loop()
	if !ok {
		return false
	}
	tl.loops[0] = l
	tl.thread = loop.spawn_thread(l, loop.run, context)
	if tl.thread == nil {
		loop.destroy(l)
		tl.loops[0] = nil
		return false
	}
	return true
}

stop_test_loop :: proc(tl: ^Test_Loop) {
	if tl.loops[0] == nil {
		return
	}
	loop.stop(tl.loops[0])
	thread.join(tl.thread)
	thread.destroy(tl.thread)
	loop.destroy(tl.loops[0])
	tl^ = {}
}
