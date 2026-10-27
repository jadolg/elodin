package dnssec

import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:loop"

/*
A signature check and an NSEC3 hash are CPU and never wait, so a walk spending
its budget without a lookup in between would hold its loop throughout. The
budget's charges are where the loop gets its turns: a fiber started beside the
query runs at the `VERIFICATIONS_PER_TURN`th check and not before, and at the
charge that crosses `NSEC3_ROUNDS_PER_TURN` and not at one that does not.
*/
@(test)
test_spending_the_budget_gives_the_loop_turns :: proc(t: ^testing.T) {
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
		before_check:    bool,
		at_check:        bool,
		short_of_rounds: bool,
		crossing_rounds: bool,
	}
	s: Shared
	_, _ = loop.spawn(l, proc(data: rawptr) {
		s := (^Shared)(data)
		beside :: proc(data: rawptr) {
			(^Shared)(data).other_ran = true
		}
		// Started from here, so it is on the ready list behind this fiber and
		// runs only once this one gives the loop up.
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		budget: Budget
		for _ in 0 ..< VERIFICATIONS_PER_TURN - 1 {
			spend_verification(&budget)
		}
		s.before_check = s.other_ran
		spend_verification(&budget)
		s.at_check = s.other_ran

		s.other_ran = false
		_, _ = loop.spawn(loop.current_loop(), beside, s)
		rr := Nsec3 {
			hash_algorithm = NSEC3_HASH_SHA1,
		}
		nsec3 := Nsec3_Budget {
			max_iterations = 0,
		}
		spend_nsec3_rounds(&nsec3, rr, "a.")
		s.short_of_rounds = s.other_ran
		nsec3.rounds = NSEC3_ROUNDS_PER_TURN - 1
		spend_nsec3_rounds(&nsec3, rr, "a.")
		s.crossing_rounds = s.other_ran
		sync.sema_post(&s.done)
	}, &s)

	if !testing.expect(t, sync.sema_wait_with_timeout(&s.done, 10 * time.Second), "the query fiber never finished") {
		return
	}
	testing.expect(t, !s.before_check, "the loop was given up before a turn's worth of signature checks")
	testing.expect(t, s.at_check, "a turn's worth of signature checks held the loop")
	testing.expect(t, !s.short_of_rounds, "the loop was given up by a hash that crossed no turn")
	testing.expect(t, s.crossing_rounds, "hashing past a turn's worth of rounds held the loop")
}
