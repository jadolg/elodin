package server

import "core:strings"
import "core:testing"

/*
What a refusal costs this server to say.

Both refusals in the listeners are reached by a peer that chose to be refused:
`server.allow_from` turns away a datagram or a connection from a source that is
not on the list, and `server.max_connections` turns away a connection once the
limit is reached. A line per attempt at `warn` hands whoever is sending them a
way to write to this server's disk for as long as they keep sending - so the
first one names the setting and every one after it is `debug`, where an operator
who has gone looking will find it.

The gate is the whole of that behaviour, so it is what is pinned here rather than
the lines themselves: a reporter that stops calling it, or one added without it,
is a reporter that logs a flood.
*/

/*
Both the flag and the level are the case's own: the flag rather than either of
the package's globals, so a reporter that has already fired elsewhere in the
suite cannot decide the answer, and the level as a parameter rather than
`logx.set_level`, which is process-wide and would race the fifteen other threads
this suite runs on.
*/
@(test)
test_report_once_says_it_once :: proc(t: ^testing.T) {
	reported: bool

	say, first := report_once(&reported, false)
	testing.expect(t, say, "the first refusal said nothing")
	testing.expect(t, first, "the first refusal was not reported as the first")

	// Every one after it is suppressed entirely while debug is off: the caller is
	// an attacker's send loop, and formatting an address for each packet is work
	// to be done only on purpose.
	for i in 0 ..< 3 {
		again, again_first := report_once(&reported, false)
		testing.expectf(t, !again, "refusal %d was logged at warn as well", i + 2)
		testing.expect(t, !again_first, "a later refusal claimed to be the first")
	}

	// With debug on every refusal is reported - and none of them is the first, so
	// none of them is a `warn`.
	for i in 0 ..< 3 {
		again, again_first := report_once(&reported, true)
		testing.expectf(t, again, "refusal %d was dropped at debug level", i + 5)
		testing.expect(t, !again_first, "a later refusal claimed to be the first")
	}
}

/*
A connection turned away on accept was never a query.

The check runs before a byte is read, so "refused a query from" describes
something that did not happen - and the same counter is a sum of two units,
datagrams on UDP and connections on the stream transports. The wording is what
tells an operator which of the two a line is about.
*/
@(test)
test_a_refusal_is_named_for_what_was_refused :: proc(t: ^testing.T) {
	testing.expect_value(t, refused_unit(.UDP), "query")
	for proto in ([]Protocol{.TCP, .DoT, .DoH}) {
		testing.expectf(
			t,
			refused_unit(proto) == "connection",
			"%v refuses connections but its refusal is called a %s",
			proto,
			refused_unit(proto),
		)
	}
}

/*
A connection refused for want of a slot and one refused for want of a thread are
told which is which.

The whole reason the two are kept apart is that they send an operator in opposite
directions: raise `server.max_connections`, or go and find what stopped the OS
giving this process a thread - and a host under `RLIMIT_NPROC` refuses well below
the limit, where raising it makes things worse. So the words are chosen from the
cause, and the two sets have to be the right way round. Swapped, nothing else in
the suite would notice: both lines still appear, and both still count something.

Pinned on the distinguishing phrases rather than on whole sentences, so the
wording stays free to change.
*/
@(test)
test_a_spawn_failure_names_its_own_cause :: proc(t: ^testing.T) {
	limit := spawn_failure_words(.Limit_Reached)
	share := spawn_failure_words(.Prefix_Limit_Reached)
	failed := spawn_failure_words(.Thread_Failed)

	testing.expect(
		t,
		strings.contains(limit.line, "server.max_connections") && strings.contains(limit.hint, "raise"),
		"a full connection limit does not tell the operator to raise it",
	)
	/*
	And a client that has filled its own share is not told the table is full.

	The two are one connection apart and a `warn` apart, and the wrong one of
	them is worse than saying nothing: an operator whose table is half empty,
	told to raise `max_connections`, raises it and hands the client that filled
	its share a larger share of a larger table. So the line names the setting
	that actually refused the connection.
	*/
	testing.expect(
		t,
		strings.contains(share.line, "server.max_connections_per_prefix"),
		"a connection refused over one client's share does not name the setting that refused it",
	)
	testing.expect(
		t,
		strings.contains(share.hint, "raise server.max_connections_per_prefix"),
		"a filled share does not tell the operator which figure to raise",
	)
	testing.expect(
		t,
		strings.contains(share.hint, "conn_refused="),
		"a filled share does not say where it is counted",
	)
	testing.expect(
		t,
		strings.contains(failed.line, "will not help"),
		"a refused thread was blamed on the connection limit",
	)
	testing.expect(
		t,
		strings.contains(failed.hint, "RLIMIT_NPROC"),
		"a refused thread does not say where the actual limit is",
	)
	// Each counts into the field it names, and the stats line spells them this way.
	testing.expect(t, strings.contains(limit.hint, "conn_refused="), "the limit's line names the wrong counter")
	testing.expect(t, strings.contains(failed.hint, "conn_failed="), "the thread failure's line names the wrong counter")

	/*
	And a separate flag each.

	Shared, whichever cause happened first would suppress the other for the
	lifetime of the process - so a server that filled its connection limit in the
	first minute would never say a word about the pids ceiling it hit an hour
	later, or about the client that spent the afternoon holding its whole share.
	*/
	testing.expect(t, limit.reported != failed.reported, "the two connection limits share one once-only flag")
	testing.expect(t, share.reported != limit.reported, "a filled share is silenced by a full table")
	testing.expect(t, share.reported != failed.reported, "a filled share is silenced by a refused thread")
}

/*
Each cause names the limit that refused the connection, not simply a limit.

The lines take a number, and there are two it could be. A share refused against
`max_connections` reads as a table that is full at a moment when it is mostly
empty - which is the same wrong turn the wording is careful to avoid, arrived at
through the argument instead of the format string. Nothing else in the suite
would notice: both lines still print a plausible figure.
*/
@(test)
test_a_spawn_failure_names_the_limit_that_refused_it :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 512, 256)
	defer conn_manager_shutdown(&cm)

	testing.expect_value(t, spawn_failure_limit(.Limit_Reached, &cm), 512)
	testing.expect_value(t, spawn_failure_limit(.Prefix_Limit_Reached, &cm), 256)
	// A thread the OS would not start happened below the table, so the table is
	// the figure that says "below": see the line it prints.
	testing.expect_value(t, spawn_failure_limit(.Thread_Failed, &cm), 512)
}

/*
What the connection table allows, said once at startup.

The default share is derived from `max_connections` at load, so neither figure
need appear in anybody's configuration file - and an operator whose client
cannot connect has no other place to read them. The no-cap form is the one worth
pinning: it has to say that one client may hold the table, because that is the
surprising half of that configuration.
*/
@(test)
test_the_connection_limits_line_says_what_one_client_may_hold :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)

	capped := connection_limits_line(512, 256)
	testing.expect(t, strings.contains(capped, "512"), "the line does not say how many connections there are")
	testing.expect(t, strings.contains(capped, "256"), "the line does not say what one client may hold")

	// A share as large as the table is no cap, and reads as one rather than as a
	// limit that happens never to be reached.
	uncapped := connection_limits_line(512, 512)
	testing.expect(
		t,
		strings.contains(uncapped, "all of them"),
		"a share as large as the table is not reported as no cap at all",
	)
}
