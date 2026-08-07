package server

import "core:sync"
import "core:testing"
import "core:time"

/*
The connection limit is `len(threads) - permanent`, so `permanent` has to keep
meaning what it says for as long as the manager runs.
*/

@(private = "file")
returns_immediately :: proc(data: rawptr) {}

@(private = "file")
Held :: struct {
	go: bool,
}

@(private = "file")
holds_until_released :: proc(data: rawptr) {
	h := cast(^Held)data
	for !sync.atomic_load(&h.go) {
		time.sleep(time.Millisecond)
	}
}

@(private = "file")
wait_for_reap :: proc(cm: ^Conn_Manager, want: int) -> int {
	deadline := time.time_add(time.now(), 2 * time.Second)
	got := active_connections(cm)
	for got != want && time.diff(time.now(), deadline) > 0 {
		time.sleep(time.Millisecond)
		got = active_connections(cm)
	}
	return got
}

/*
Reaping a listener loop must take it off the permanent tally too.

The loops are excluded from the connection limit by being counted separately
and subtracted. `reap_locked` removed a finished thread from the list without
touching that count, so once a loop had been reaped the subtraction was against
a number that no longer described anything: the total goes negative, and the
limit stops holding for as many connections as there were loops.
*/
@(test)
test_reaping_a_permanent_thread_keeps_the_count_honest :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 1)
	defer conn_manager_shutdown(&cm)

	// A listener loop, as `start_udp` and `start_stream_listener` register one,
	// that then finishes - which is what shutdown does to all of them.
	testing.expect_value(t, conn_spawn(&cm, nil, returns_immediately, counted = false), Spawn_Result.Started)
	testing.expect_value(t, wait_for_reap(&cm, 0), 0)

	// With the tally corrected, the one slot the limit allows is still one slot.
	held := Held{}
	defer sync.atomic_store(&held.go, true)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released), Spawn_Result.Started)
	testing.expect_value(t, active_connections(&cm), 1)
	/*
	And the refusal says which of the two it was.

	`Limit_Reached` and `Thread_Failed` ask an operator for opposite things -
	raise the limit, or find out what stopped the OS giving this process a
	thread - so the accept loop counts and reports them apart. A boolean could
	not tell them apart, and named `max_connections` for both.
	*/
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released), Spawn_Result.Limit_Reached)
}
