package server

import "core:net"
import "core:strings"
import "core:testing"

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
