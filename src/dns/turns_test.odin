package dns

import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:loop"

/*
A request decoding an answer built to expand gives its loop turns as it goes,
and one decoding an ordinary answer never does.

Each check spawns a fiber from the query's own fiber, so it sits on the ready
list behind it and runs only when the query gives the loop up: whether it has
run after a charge or a decode is whether that charge or decode took a turn.
*/
@(test)
test_decoding_gives_the_loop_turns :: proc(t: ^testing.T) {
	l, made := loop.make_loop()
	if !testing.expect(t, made, "no loop") {
		return
	}
	th := loop.spawn_thread(l, loop.run, context)
	if !testing.expect(t, th != nil, "no loop thread") {
		loop.destroy(l)
		return
	}
	defer {
		loop.stop(l)
		thread.join(th)
		thread.destroy(th)
		loop.destroy(l)
	}

	Shared :: struct {
		done:            sync.Sema,
		other_ran:       bool,
		short_of_a_turn: bool,
		at_a_turn:       bool,
		uncounted:       bool,
		ordinary:        bool,
		expanding:       bool,
		expanding_err:   Decode_Error,
	}
	s: Shared
	_, _ = loop.spawn(l, proc(data: rawptr) {
		s := (^Shared)(data)
		beside :: proc(data: rawptr) {
			(^Shared)(data).other_ran = true
		}
		h := Heavy_Slots{}

		// One byte short of the step, then the byte that crosses it.
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		spent := 0
		charge_against(&h, &spent, DECODE_BYTES_PER_TURN - 1)
		s.short_of_a_turn = s.other_ran
		charge_against(&h, &spent, 1)
		s.at_a_turn = s.other_ran
		release_against(&h, &spent)

		// A reading nobody counts is not a request, and takes no turns.
		s.other_ran = false
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		charge_against(&h, nil, 4 * DECODE_BYTES_PER_TURN)
		s.uncounted = s.other_ran

		// An ordinary answer decodes without a turn.
		s.other_ran = false
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		plain := 0
		_, _ = decode_message(expanding_answer(3), context.temp_allocator, &plain)
		s.ordinary = s.other_ran

		// One built to expand gives the loop up while it is read.
		s.other_ran = false
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		heavy_read := 0
		_, s.expanding_err = decode_message(expanding_answer(3900), context.temp_allocator, &heavy_read)
		s.expanding = s.other_ran
		release_against(&h, &heavy_read)
		sync.sema_post(&s.done)
	}, &s)

	if !testing.expect(t, sync.sema_wait_with_timeout(&s.done, 10 * time.Second), "the query fiber never finished") {
		return
	}
	testing.expect(t, !s.short_of_a_turn, "a charge short of DECODE_BYTES_PER_TURN gave the loop up")
	testing.expect(t, s.at_a_turn, "the charge crossing DECODE_BYTES_PER_TURN did not give the loop a turn")
	testing.expect(t, !s.uncounted, "a reading with no request behind it gave the loop up")
	testing.expect(t, !s.ordinary, "an ordinary answer gave the loop up")
	testing.expect(t, s.expanding, "an answer built to expand was read without a turn")
}

/*
A response to a 250-byte question whose `records` A records are owned by
two-byte pointers to it: 16 bytes of wire each, 250 bytes each once decoded.
*/
@(private = "file")
expanding_answer :: proc(records: int) -> []u8 {
	b := make([dynamic]u8, context.temp_allocator)
	append(&b, 0, 1, 0x81, 0x80, 0, 1, u8(records >> 8), u8(records), 0, 0, 0, 0)
	for _ in 0 ..< 4 {
		append(&b, 60)
		for _ in 0 ..< 60 {
			append(&b, 'a')
		}
	}
	append(&b, 0, 0, 1, 0, 1)
	for i in 0 ..< records {
		append(&b, 0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 10, 77, u8(i >> 8), u8(i))
	}
	return b[:]
}
