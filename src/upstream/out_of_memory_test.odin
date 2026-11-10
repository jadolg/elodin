package upstream

import "core:mem"
import "core:testing"
import "core:time"

/*
Issue #620: a query this server cannot allocate the buffers for is not sent, and
says so as `Out_Of_Memory` rather than trapping on an empty slice. Neither the
copy `pipe_query` takes nor the frame `pipe_write` builds touches the connection
first, so the connection is left as it was.
*/
@(test)
test_a_pipelined_query_that_cannot_be_copied_or_framed_is_not_sent :: proc(t: ^testing.T) {
	query := make([]u8, 32)
	defer delete(query)
	deadline := time.tick_add(time.tick_now(), time.Second)

	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	_, copy_err := pipe_query(nil, nil, query, deadline, temp)
	write_err := pipe_write(nil, query, deadline)
	context.temp_allocator = temp

	testing.expect_value(t, copy_err, Error.Out_Of_Memory)
	testing.expect_value(t, write_err, Error.Out_Of_Memory)
}

// Charged as `Backlogged` is: not at all, since it says nothing about the upstream.
@(test)
test_a_failure_of_this_server_s_own_is_not_charged_to_the_upstream :: proc(t: ^testing.T) {
	testing.expect(t, !charges_member(.Out_Of_Memory, false), "this server's memory was charged to the upstream")
	testing.expect(t, !charges_member(.Backlogged, false))
	testing.expect(t, !charges_member(.Timeout, true))
	testing.expect(t, charges_member(.Timeout, false))
	testing.expect(t, charges_member(.IO_Error, false))
}
