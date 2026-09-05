package server

import "core:net"
import "core:strings"
import "core:testing"
import "core:time"

/*
Every `net.Accept_Error`, against a table written out by hand.

Written as an enumerated array rather than as a switch mirroring the
implementation, which is what this test used to be and which could not fail: a
`#partial switch` copied from `accept_failed` agrees with it by construction,
including where both are wrong.

The array is the guard the mirror only claimed to be. Odin refuses an incomplete
enumerated array literal - "Unhandled enumerated array case" - so a member added
to `net.Accept_Error` upstream is a compile error here until somebody decides
which side of the line it falls on, which is exactly the decision that must not
be made by a default.
*/
@(test)
test_only_the_idle_and_transient_accept_errors_are_not_failures :: proc(t: ^testing.T) {
	failure := [net.Accept_Error]bool {
		// The idle path: the poll tick the loops are built on.
		.None                   = false,
		.Would_Block            = false,
		.Timeout                = false,
		// A connection that went away; the queue has moved on.
		.Aborted                = false,
		.Interrupted            = false,
		// Failures. `Unknown` carries both a pending network error and, were the
		// mapping ever to change, a descriptor shortage - which is why what to
		// do about a failure is decided by whether it clears and not here.
		.Network_Unreachable    = true,
		.Insufficient_Resources = true,
		.Invalid_Argument       = true,
		.Unsupported_Socket     = true,
		.Not_Listening          = true,
		.Unknown                = true,
	}
	for err in net.Accept_Error {
		testing.expectf(
			t,
			accept_failed(err) == failure[err],
			"%v: accept_failed should be %v, got %v",
			err,
			failure[err],
			accept_failed(err),
		)
	}
}

/*
The two errors the fix turns on, named on their own.

A descriptor shortage has to be waited out or the loop spins; a pending network
error - `EPROTO`, `EHOSTUNREACH` and the rest of the set `accept(2)` says to
treat like `EAGAIN` - reaches `core:net` as `Unknown`, and must not cost a
listener a second of deafness on its own. Both are failures, and it is
`ACCEPT_FAST_RETRIES` that separates them.
*/
@(test)
test_a_shortage_and_a_pending_network_error_are_both_failures :: proc(t: ^testing.T) {
	testing.expect(t, accept_failed(.Insufficient_Resources), "EMFILE/ENFILE must not be retried forever at once")
	testing.expect(t, accept_failed(.Unknown), "a pending network error is a failure, and clears by itself")
	testing.expect(
		t,
		ACCEPT_FAST_RETRIES > 1,
		"one immediate retry is not enough for a network event that queues more than one",
	)
}

/*
The two shapes, held side by side.

`spawn_failure_words`' test reasoning: the printing cannot be wrong in a way that
matters and the choosing can, so what is asserted is that a descriptor shortage
sends an operator to the descriptor limit and that the other shape does not - a
line telling somebody to raise `RLIMIT_NOFILE` at a socket that has gone invalid
is the mistake this arrangement exists to prevent.
*/
@(test)
test_the_accept_failure_words_send_a_shortage_to_the_descriptor_limit :: proc(t: ^testing.T) {
	mine, theirs: bool

	short := accept_failure_words(.Insufficient_Resources, &mine)
	testing.expect(
		t,
		strings.contains(short.hint, "RLIMIT_NOFILE") && strings.contains(short.hint, "LimitNOFILE"),
		"a descriptor shortage has to name the limit to raise, in both the forms an operator meets it",
	)
	testing.expect(
		t,
		short.reported != &mine,
		"a shortage is the process's, so it is reported once for the process and not once per listener",
	)

	other := accept_failure_words(.Not_Listening, &mine)
	testing.expect(
		t,
		!strings.contains(other.hint, "RLIMIT_NOFILE"),
		"an error that is not a shortage must not send an operator to the descriptor limit",
	)
	testing.expect(
		t,
		other.reported == &mine && accept_failure_words(.Not_Listening, &theirs).reported == &theirs,
		"a socket that has gone bad is one socket, so each listener keeps its own flag",
	)
	testing.expect(
		t,
		strings.contains(short.hint, "accept_backoff=") && strings.contains(other.hint, "accept_backoff="),
		"both name the counter that goes on after the one warn has scrolled away",
	)
}

@(test)
test_descriptors_wanted_counts_everything_that_holds_one :: proc(t: ^testing.T) {
	d := Descriptor_Demand {
		max_connections  = 512,
		pooled_upstream  = 16,
		workers          = 128,
		upstream_workers = 64,
		udp_readers      = 4,
	}
	testing.expect_value(t, descriptors_wanted(d), 512 + 16 + 128 + 64 + 4 + DESCRIPTOR_RESERVE)

	// The readers are a term of their own because an operator may set 64 of
	// them, which would otherwise eat a reserve sized for eight.
	many := d
	many.udp_readers = 64
	testing.expect_value(t, descriptors_wanted(many) - descriptors_wanted(d), 60)
}

@(test)
test_the_descriptor_line_is_silent_unless_the_limit_is_short :: proc(t: ^testing.T) {
	d := Descriptor_Demand {
		max_connections = 512,
		pooled_upstream = 16,
		workers         = 128,
	}
	wanted := descriptors_wanted(d)

	_, exact := descriptor_limit_line(wanted, d)
	testing.expect(t, !exact, "a limit that exactly covers the demand is not short")

	_, plenty := descriptor_limit_line(wanted * 4, d)
	testing.expect(t, !plenty, "a limit well over it is not short")

	// Unreadable, which is not the same as small: nothing is claimed about a
	// limit that could not be read.
	_, unknown := descriptor_limit_line(0, d)
	testing.expect(t, !unknown, "a limit that could not be read says nothing")

	line, short := descriptor_limit_line(1024, Descriptor_Demand{max_connections = 4096})
	testing.expect(t, short, "a limit below the table has to be said")
	testing.expect(
		t,
		strings.contains(line, "1024") && strings.contains(line, "4096"),
		"the line has to carry both figures, or it cannot be acted on",
	)
	testing.expect(
		t,
		strings.contains(line, "accept_backoff="),
		"the counter has to be named, since the warn is said once and the counter goes on",
	)
}

/*
The premise the line rests on, read from the platform rather than assumed.

`descriptor_limit` is the only reason any of the above is ever printed, and a
`sysconf` that reported something other than the live soft limit would leave it
silent on exactly the machine that needs it. Asserted loosely here - the figure
is the machine's - because the tight check cannot be made without lowering a
process-wide limit under a test runner that runs its tests in parallel. That one
was made out of band, in the pull request: a process whose `RLIMIT_NOFILE` was
lowered under it saw the lowered figure here, and its next `accept` returned
`Insufficient_Resources`.
*/
@(test)
test_the_descriptor_limit_is_readable :: proc(t: ^testing.T) {
	testing.expect(
		t,
		descriptor_limit() > 0,
		"RLIMIT_NOFILE has to be readable, or the shortage warning can never be printed",
	)
}

/*
The loop's own behaviour, as a sequence, without a socket.

The classifier tests above say which errors are failures; none of them says what
the loop does with a *run* of them, which is the whole of this change and the
part where "the fourth in a row" and "the first after a success" are easy to get
wrong. `accept_action` is the whole decision, so driving it with a sequence is
driving the loop.
*/
@(test)
test_a_burst_that_clears_costs_almost_nothing :: proc(t: ^testing.T) {
	/*
	The shape the review caught: four connections behind an nftables reject, or a
	flapping route, arriving together. `accept(2)` says to retry these at once,
	and a flat back-off charged the whole listener a second of deafness for each
	one - worse than the spin this change removes, since the spin at least kept
	accepting.
	*/
	failures := 0
	total: time.Duration
	reports := 0
	for _ in 0 ..< 4 {
		act := accept_action(.Unknown, failures)
		failures = act.failures
		total += act.wait
		reports += 1 if act.report else 0
	}
	testing.expect(
		t,
		total < 10 * time.Millisecond,
		"a burst of pending network errors must not cost the listener a perceptible wait",
	)
	testing.expect_value(t, reports, 0)

	// And the queue moves on: one accepted connection puts it back to nothing.
	after := accept_action(.None, failures)
	testing.expect_value(t, after.failures, 0)
	testing.expect_value(t, after.wait, 0)
}

@(test)
test_the_first_failures_are_retried_at_once :: proc(t: ^testing.T) {
	failures := 0
	for i in 1 ..= ACCEPT_FAST_RETRIES {
		act := accept_action(.Insufficient_Resources, failures)
		failures = act.failures
		testing.expectf(t, act.wait == 0, "failure %d should be retried at once", i)
		testing.expect_value(t, act.failures, i)
	}
	// The next one waits, because it has not cleared.
	act := accept_action(.Insufficient_Resources, failures)
	testing.expect(t, act.wait > 0, "a failure that survives the free retries has to be waited out")
}

@(test)
test_a_shortage_reaches_one_attempt_a_second_and_stays :: proc(t: ^testing.T) {
	failures := 0
	total: time.Duration
	first_report := -1
	// Long enough to be well past the escalation, short enough to be a test.
	for i in 0 ..< 40 {
		act := accept_action(.Insufficient_Resources, failures)
		failures = act.failures
		total += act.wait
		if act.report && first_report < 0 {
			first_report = i
		}
	}
	testing.expect(
		t,
		accept_action(.Insufficient_Resources, failures).wait == ACCEPT_BACKOFF,
		"a shortage that does not clear settles at the ceiling",
	)
	testing.expect(
		t,
		first_report >= 0 && total <= 40 * ACCEPT_BACKOFF,
		"the escalation has to reach the ceiling, and cannot exceed it",
	)
	/*
	The spin the issue is about, bounded. Three free retries and the escalation
	come to about a second between them, and every attempt after that waits the
	ceiling - so forty attempts at a condition that never clears is some
	twenty-eight seconds of waiting rather than forty iterations at whatever
	speed the CPU manages.
	*/
	testing.expect(
		t,
		total > 25 * time.Second,
		"a shortage that does not clear has to cost about a second per attempt, not nothing",
	)
	/*
	And the escalation is quick: the report is what an operator sees, and it
	should not be minutes away.
	*/
	testing.expect(
		t,
		first_report < 15,
		"the ceiling, and so the warning, has to be reached in the first seconds",
	)
}

/*
Waiting is not reporting.

The one `warn` a listener gets has to be spent on a condition that lasted. A
burst that clears inside the escalation is not one, and the flag it would have
burned belongs to the socket that genuinely goes bad later.
*/
@(test)
test_a_short_wait_does_not_spend_the_one_warning :: proc(t: ^testing.T) {
	act := accept_action(.Unknown, ACCEPT_FAST_RETRIES)
	testing.expect(t, act.wait > 0 && act.wait < ACCEPT_BACKOFF, "the first wait is a short one")
	testing.expect(t, !act.report, "a wait that may yet clear must not spend the warning")
}

/*
Every wait, for far longer than a shortage would ever be left running.

The bound this asserts is not an edge case: the first version of `accept_action`
overflowed `i64` at the 48th consecutive failure - some thirty-five seconds into
a descriptor shortage - and produced waits of zero and below. `act.wait > 0` is
what the loops test, so those iterations neither slept nor counted: the spin
came back, briefly, in the middle of the fix for it, and the counter said
nothing.

Two hundred iterations rather than the forty the first test of this ran, because
forty stopped eight short of the first wrapped value. A test that stops before
the arithmetic goes wrong is the shape of test this whole review has been about.
*/
@(test)
test_no_wait_is_ever_zero_or_negative :: proc(t: ^testing.T) {
	failures := 0
	for i in 0 ..< 200 {
		act := accept_action(.Insufficient_Resources, failures)
		failures = act.failures
		if act.failures <= ACCEPT_FAST_RETRIES {
			// The free retries, which are a wait of nothing on purpose.
			testing.expect_value(t, act.wait, 0)
			continue
		}
		testing.expectf(
			t,
			act.wait > 0,
			"iteration %d (failure %d): wait is %v, so the loop would neither sleep nor count",
			i,
			act.failures,
			act.wait,
		)
		testing.expectf(
			t,
			act.wait <= ACCEPT_BACKOFF,
			"iteration %d: wait is %v, past the ceiling of %v",
			i,
			act.wait,
			ACCEPT_BACKOFF,
		)
	}
	// And it is the ceiling by then, not something merely positive.
	testing.expect_value(t, accept_action(.Insufficient_Resources, failures).wait, ACCEPT_BACKOFF)
}
