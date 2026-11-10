package upstream

import "core:mem"
import "core:testing"
import "core:time"
import "elodin:dns"

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

/*
A reply's question is checked against the query's even where the temp allocator
has run dry: a failed read of the query's question is not a query without one,
or any reply carrying the right ID would be taken for the answer.
*/
@(test)
test_a_reply_read_without_memory_is_not_matched :: proc(t: ^testing.T) {
	asked := [1]dns.Question{{name = "example.com.", type = .A, class = .IN}}
	other := [1]dns.Question{{name = "attacker.test.", type = .A, class = .IN}}
	query, _, qerr := dns.encode_message(dns.Message{id = 0x1234, question = asked[:]})
	defer delete(query)
	reply, _, rerr := dns.encode_message(dns.Message{id = 0x1234, flags = {qr = true}, question = other[:]})
	defer delete(reply)
	testing.expect_value(t, qerr, dns.Encode_Error.None)
	testing.expect_value(t, rerr, dns.Encode_Error.None)
	testing.expect(t, !response_matches(query, reply), "the fixture's question mismatch went unseen")

	temp := context.temp_allocator
	context.temp_allocator = mem.nil_allocator()
	matched := response_matches(query, reply)
	context.temp_allocator = temp

	testing.expect(t, !matched, "a reply for another name was matched once the question could not be read")

	// Nor is a genuine one refused for it, which would charge the upstream as a
	// `Bad_Response` for this server's memory.
	ours, _, oerr := dns.encode_message(dns.Message{id = 0x1234, flags = {qr = true}, question = asked[:]})
	defer delete(ours)
	testing.expect_value(t, oerr, dns.Encode_Error.None)
	context.temp_allocator = mem.nil_allocator()
	genuine := response_matches(query, ours)
	context.temp_allocator = temp
	testing.expect(t, genuine, "the upstream's own reply was refused for want of memory")
}

// Nor is a reply this server has no memory to copy taken for an empty answer.
@(test)
test_a_reply_that_cannot_be_copied_is_not_an_empty_answer :: proc(t: ^testing.T) {
	query := []u8{0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reply := []u8{0xab, 0xcd, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	out, err := pipe_reply_copy(reply, query, mem.nil_allocator())
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect_value(t, len(out), 0)

	copied, copy_err := pipe_reply_copy(reply, query, context.temp_allocator)
	defer free_all(context.temp_allocator)
	testing.expect_value(t, copy_err, Error.None)
	if testing.expect_value(t, len(copied), len(reply)) {
		testing.expect_value(t, copied[0], 0x12)
		testing.expect_value(t, copied[2], 0x80)
	}
}
