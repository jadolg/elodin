package server

import "core:testing"
import "elodin:logx"

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
The level is process-wide and this needs both answers out of `logx.enabled`, so
the two halves are one case rather than two that could run at the same time.

The flag is owned by the case rather than being either of the package's globals,
so a reporter that has already fired elsewhere in the suite cannot decide the
answer.
*/
@(test)
test_report_once_says_it_once :: proc(t: ^testing.T) {
	restore := logx_level_for_test(.Info)
	defer logx.set_level(restore)

	reported: bool

	say, first := report_once(&reported)
	testing.expect(t, say, "the first refusal said nothing")
	testing.expect(t, first, "the first refusal was not reported as the first")

	// Every one after it is suppressed entirely while debug is off: the caller is
	// an attacker's send loop, and formatting an address for each packet is work
	// to be done only on purpose.
	for i in 0 ..< 3 {
		again, again_first := report_once(&reported)
		testing.expectf(t, !again, "refusal %d was logged at warn as well", i + 2)
		testing.expect(t, !again_first, "a later refusal claimed to be the first")
	}

	// With debug on every refusal is reported - and none of them is the first, so
	// none of them is a `warn`.
	logx.set_level(.Debug)
	for i in 0 ..< 3 {
		again, again_first := report_once(&reported)
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

// The lowest level `logx.enabled` still says yes to is the level it is set to.
@(private = "file")
logx_level_for_test :: proc(want: logx.Level) -> (previous: logx.Level) {
	previous = .Error
	for level in ([]logx.Level{.Debug, .Info, .Warn, .Error}) {
		if logx.enabled(level) {
			previous = level
			break
		}
	}
	logx.set_level(want)
	return previous
}
