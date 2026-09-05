package server

import "core:fmt"
import "core:net"
import "core:sys/posix"
import "elodin:logx"

/*
What an accept loop does with an error, which is not the same for all of them.

`net.accept_tcp` fails for three unrelated reasons and the loop used to answer
all of them with `continue`. That is right for two of them and wrong for the
third:

  - **The poll tick.** The listening sockets carry a `Receive_Timeout` of
    `LISTENER_POLL` so the loop wakes to see `stop` (`start_stream`), and every
    tick of it returns `Would_Block` - `Timeout` on a platform that reports it
    that way. It is the ordinary idle path, once a second per listener, and it
    has to stay free: no line, no counter, and no sleep on top of the second the
    kernel already waited.
  - **A connection that went away.** `Aborted` is a peer that closed between the
    SYN and the accept, `Interrupted` a signal. The queue has moved on, the next
    accept is a fresh one, and retrying at once is the whole handling.
  - **The process is out of descriptors.** `EMFILE`, `ENFILE`, `ENOBUFS` and
    `ENOMEM` all arrive as `Insufficient_Resources`, and the connection stays
    queued. So the next accept fails on the same shortage immediately, and a loop
    that answers with `continue` is a busy wait - a core per listener, serving
    nothing, for as long as the shortage lasts.

`Now` for the first two, `After_Backoff` for everything else. **The default is
the back-off, deliberately.** An error this does not know about is one whose
persistence it also does not know, and the safe reading of "unknown, repeated at
full speed" is the failure above. It also means the mapping this file believes -
that a descriptor shortage arrives as `Insufficient_Resources` - is not what the
fix rests on: were it wrong, the shortage would fall to the default and still be
backed off, and what would be lost is the specific hint in the log rather than
the loop.
*/
Accept_Retry :: enum {
	Now,
	After_Backoff,
}

accept_retry :: proc(err: net.Accept_Error) -> Accept_Retry {
	#partial switch err {
	case .None, .Would_Block, .Timeout, .Aborted, .Interrupted:
		return .Now
	}
	return .After_Backoff
}

/*
How long a loop waits before trying an accept that failed again.

`LISTENER_POLL` rather than a figure of its own, because the loop already has
exactly this constant and exactly this meaning: it is the longest an accept loop
ever goes without looking at `stop`. A shorter back-off would buy nothing - the
condition it waits out is a descriptor shortage, not a busy moment - and a longer
one would be a second meaning for "how long shutdown can take", which is the
thing the poll interval already is.

So a spinning loop becomes one attempt per second per listener, and shutdown is
no slower than it was: a loop asleep here is a loop that was going to be blocked
in `accept` for the same second anyway.
*/
ACCEPT_BACKOFF :: LISTENER_POLL

/*
Say why an accept loop is backing off, once, and then quietly.

`report_spawn_failure`'s reasoning, met one step earlier: this is the same loop,
and what decides the line rate here is a shortage that lasts rather than a peer
that repeats, so a line per attempt would be a line per back-off for as long as
the condition holds. The counter is what makes the demotion safe - `conn_failed=`
goes on climbing after the one `warn` has scrolled away.

Two shapes, because the two ask for different things. A descriptor shortage is an
environment that has to be raised, and the setting to raise is not in elodin's
configuration at all - which is the whole reason it needs saying, since every
other refusal in this file names a key an operator can find in their own file.
Anything else reaching here is a listening socket that has stopped working, where
there is nothing to raise and the useful thing is the error itself.

Each keeps its own flag so one going quiet does not silence the other, and the
words are returned as data for the reason `spawn_failure_words` returns them: the
choosing is the part that can be wrong and a test can hold the two side by side.
*/
@(private)
accept_resources_reported: bool

@(private)
accept_unexpected_reported: bool

@(private)
Accept_Failure_Words :: struct {
	reported: ^bool,
	// The `debug` line, for every occurrence after the first.
	brief:    string,
	// The `warn`, said once, and the line under it saying what to do.
	line:     string,
	hint:     string,
}

@(private)
accept_failure_words :: proc(err: net.Accept_Error) -> Accept_Failure_Words {
	if err == .Insufficient_Resources {
		return Accept_Failure_Words {
			reported = &accept_resources_reported,
			brief = "%s: still out of descriptors, not accepting for %v (%v)",
			line = "%s: cannot accept, the process is out of file descriptors - waiting %v before trying again (%v)",
			hint = "raise the descriptor limit (RLIMIT_NOFILE, LimitNOFILE= in the systemd unit) so it covers server.max_connections with room over; until it does, connections are refused rather than served, and are counted as conn_failed= in the stats line",
		}
	}
	return Accept_Failure_Words {
		reported = &accept_unexpected_reported,
		brief = "%s: accept failed again, not accepting for %v (%v)",
		line = "%s: accept failed and the listening socket may no longer be usable - waiting %v before trying again (%v)",
		hint = "nothing in the configuration bounds this one; the error beside it is what the kernel said, and these are counted as conn_failed= in the stats line",
	}
}

/*
Named by the listener rather than by a `Protocol`, because the metrics endpoint
has an accept loop too and is not one. It shares the flags with the DNS
listeners deliberately: what is being rate-limited is the operator's attention,
and one line about a descriptor shortage is the whole message however many loops
met it.
*/
@(private)
report_accept_failure :: proc(listener: string, err: net.Accept_Error) {
	words := accept_failure_words(err)
	say, first := report_once(words.reported, logx.enabled(.Debug))
	if !say {
		return
	}
	// As in `report_spawn_failure`: the accept loop is the one place that never
	// resets its own temp arena, and the line was formatted out of it.
	defer free_all(context.temp_allocator)

	if !first {
		logx.debugf(words.brief, listener, ACCEPT_BACKOFF, err)
		return
	}
	logx.warnf(words.line, listener, ACCEPT_BACKOFF, err)
	logx.warnf(words.hint)
}

/*
Descriptors this configuration wants at most, against the one limit that is not
in it.

Two terms are counted because two are worth counting and both are exact. The
connection table is the one that moves: `max_connections` is a promise to hold
that many sockets at once, and a limit below it is a promise the process cannot
keep. The idle upstream pool is the next largest and is as easy to know -
`upstream.max_idle` per configured server.

Everything else is a handful and is covered by a reserve rather than enumerated:
up to four listening sockets, the metrics listener, up to eight UDP readers, the
log, and the list files while they load. `DESCRIPTOR_RESERVE` is deliberately
larger than that adds up to, because the failure this bounds is a listener that
stops accepting and the cost of the slack is nothing.

A count, not a measurement: it says what the configuration could want, not what
the process holds. `process_open_fds` is the other question and the metrics
endpoint already answers it.
*/
DESCRIPTOR_RESERVE :: 64

descriptors_wanted :: proc(max_connections, upstream_idle: int) -> int {
	return max_connections + upstream_idle + DESCRIPTOR_RESERVE
}

/*
Said only when the limit cannot cover the table, at startup and by `--check`
alike.

Quiet otherwise, which is the departure from `connection_limits_line` beside it
and is the point: that line reports a figure an operator cannot read anywhere
else, and this one reports an environment they can - `ulimit -n` - and that is
almost always fine. A line every start saying so would be noise in the steady
state, and the steady state is where this server's log has to stay readable.

The same words in both places for the reason that one gives: an operator reads
`--check` before restarting, and two wordings of one fact drift apart.

A warning rather than a refusal to start. The configuration is not wrong - the
machine is short - and a server that will serve `soft - reserve` clients instead
of `max_connections` is worth more to the operator than one that will not start
at all. What it must not do is meet the shortage silently, which is what it did.
*/
descriptor_limit_line :: proc(soft_limit, max_connections, upstream_idle: int) -> (line: string, short: bool) {
	wanted := descriptors_wanted(max_connections, upstream_idle)
	if soft_limit <= 0 || soft_limit >= wanted {
		return "", false
	}
	return fmt.tprintf(
		"descriptors: the limit is %d, short of the %d this configuration can want (server.max_connections %d, %d pooled upstream connections, and %d for the listeners, the readers and the log). Past it, connections are refused rather than served and are counted as conn_failed=; raise RLIMIT_NOFILE (LimitNOFILE= in the systemd unit)",
		soft_limit,
		wanted,
		max_connections,
		upstream_idle,
		DESCRIPTOR_RESERVE,
	), true
}

/*
The soft `RLIMIT_NOFILE`, or 0 where it cannot be read.

`sysconf(_SC_OPEN_MAX)` rather than a `getrlimit` binding of our own: it reports
the live soft limit - verified against a process whose limit was lowered under it
- and `metrics/process.odin` already reads the same figure for
`process_max_fds`, so there is one answer to this question in the tree rather
than two.
*/
descriptor_limit :: proc() -> int {
	if limit := posix.sysconf(._OPEN_MAX); limit > 0 {
		return int(limit)
	}
	return 0
}
