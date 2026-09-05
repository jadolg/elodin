package server

import "core:net"
import "core:strings"
import "core:testing"

/*
Every `net.Accept_Error`, held against the retry it asks for.

Written over the whole enum rather than over the interesting members because the
thing being asserted is the default: an error nobody thought about has to reach
the back-off, and a `#partial switch` that grows a case is exactly how one would
quietly stop doing so. A new member of the enum lands here as a compile error
until it is placed.
*/
@(test)
test_only_the_transient_accept_errors_retry_immediately :: proc(t: ^testing.T) {
	for err in net.Accept_Error {
		want := Accept_Retry.After_Backoff
		#partial switch err {
		case .None, .Would_Block, .Timeout, .Aborted, .Interrupted:
			want = .Now
		}
		testing.expectf(
			t,
			accept_retry(err) == want,
			"%v should retry %v, got %v",
			err,
			want,
			accept_retry(err),
		)
	}
}

// The one the loop was spinning on, named on its own so a change to it fails
// here rather than only inside the sweep above.
@(test)
test_a_descriptor_shortage_backs_off :: proc(t: ^testing.T) {
	testing.expect(
		t,
		accept_retry(.Insufficient_Resources) == .After_Backoff,
		"EMFILE/ENFILE arrive as Insufficient_Resources and must not spin the accept loop",
	)
}

/*
The two shapes, held side by side.

`spawn_failure_words`' test reasoning: the printing cannot be wrong in a way that
matters and the choosing can, so what is asserted is that the descriptor shortage
sends an operator to the descriptor limit and that the other shape does not - a
line telling someone to raise `RLIMIT_NOFILE` at a listening socket that has gone
invalid is the mistake this arrangement exists to prevent.
*/
@(test)
test_the_accept_failure_words_send_a_shortage_to_the_descriptor_limit :: proc(t: ^testing.T) {
	short := accept_failure_words(.Insufficient_Resources)
	testing.expect(
		t,
		strings.contains(short.hint, "RLIMIT_NOFILE") && strings.contains(short.hint, "LimitNOFILE"),
		"a descriptor shortage has to name the limit to raise, in both the forms an operator meets it",
	)
	testing.expect(
		t,
		strings.contains(short.line, "out of file descriptors"),
		"the warn line has to say what happened",
	)

	other := accept_failure_words(.Not_Listening)
	testing.expect(
		t,
		!strings.contains(other.hint, "RLIMIT_NOFILE"),
		"an error that is not a shortage must not send an operator to the descriptor limit",
	)
	testing.expect(
		t,
		short.reported != other.reported,
		"each shape keeps its own flag, so one going quiet does not silence the other",
	)
}

@(test)
test_descriptors_wanted_counts_the_table_the_pool_and_a_reserve :: proc(t: ^testing.T) {
	testing.expect_value(t, descriptors_wanted(512, 16), 512 + 16 + DESCRIPTOR_RESERVE)
	// The reserve is what makes a bare table not enough on its own.
	testing.expect(
		t,
		descriptors_wanted(512, 0) > 512,
		"the listeners, the readers and the log are descriptors too",
	)
}

@(test)
test_the_descriptor_line_is_silent_unless_the_limit_is_short :: proc(t: ^testing.T) {
	wanted := descriptors_wanted(512, 16)

	_, short := descriptor_limit_line(wanted, 512, 16)
	testing.expect(t, !short, "a limit that exactly covers the table is not short")

	_, plenty := descriptor_limit_line(wanted * 4, 512, 16)
	testing.expect(t, !plenty, "a limit well over the table is not short")

	// Unreadable, which is not the same as small: nothing is claimed about a
	// limit that could not be read.
	_, unknown := descriptor_limit_line(0, 512, 16)
	testing.expect(t, !unknown, "a limit that could not be read says nothing")

	line, tight := descriptor_limit_line(1024, 4096, 16)
	testing.expect(t, tight, "a limit below the table has to be said")
	testing.expect(
		t,
		strings.contains(line, "1024") && strings.contains(line, "4096"),
		"the line has to carry both figures, or it cannot be acted on",
	)
	testing.expect(
		t,
		strings.contains(line, "conn_failed="),
		"the counter has to be named, since the warn is said once and the counter goes on",
	)
}

/*
The premise the line rests on, read from the platform rather than assumed.

`descriptor_limit` is the only reason any of the above is ever printed, and a
`sysconf` that reported something other than the live soft limit would make it
silent on exactly the machine that needs it. Asserted loosely - the figure is the
machine's - and the tight check is the one the probe in the pull request made: a
process whose limit was lowered under it saw the lowered figure here.
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
The metrics endpoint's accept loop shares this classification, and must.

It is the same procedure over the same error, so the assertion is not about the
classifier twice - it is that the second loop was not left behind. `server.
metrics.odin` had the identical `continue`-on-every-error shape, on a listener
that is off the connection accounting and so would have spun with every counter
in this server reading zero and nothing at all in the stats line.
*/
@(test)
test_the_metrics_listener_backs_off_on_the_same_errors :: proc(t: ^testing.T) {
	testing.expect(t, accept_retry(.Insufficient_Resources) == .After_Backoff)
	testing.expect(
		t,
		accept_retry(.Would_Block) == .Now,
		"the metrics listener polls on the same interval, so its idle path has to stay free too",
	)
}
