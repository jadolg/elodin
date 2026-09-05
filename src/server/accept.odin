package server

import "core:fmt"
import "core:net"
import "core:time"
import "elodin:logx"
import "elodin:metrics"

/*
Whether an accept error is a failure at all.

`net.accept_tcp` returns for three unrelated reasons and only one of them is
trouble:

  - **The poll tick.** The listening sockets carry a `Receive_Timeout` of
    `LISTENER_POLL` so the loop wakes to see `stop` (`start_stream`), and every
    tick of it returns `Would_Block` - `Timeout` on a platform that reports it
    that way. It is the ordinary idle path, once a second per listener.
  - **A connection that went away.** `Aborted` is a peer that closed between the
    SYN and the accept, `Interrupted` a signal. The queue has moved on and the
    next accept is a fresh one.
  - **Everything else**, which is a failure and which the loop counts.

Deliberately not the whole decision. What to *do* about a failure cannot be read
off this enum, because Linux hands two very different things through it. From
`accept(2)`:

> Linux accept() passes already-pending network errors on the new socket as an
> error code from accept(). [...] These errors should be treated like EAGAIN by
> retrying.

That set - `EPROTO`, `ENETDOWN`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`,
`EHOSTUNREACH`, `ENETUNREACH`, and `EPERM` from a firewall reject - is per
connection and clears as soon as the queue moves past it. `core:net` maps all of
them to `Unknown` (`EOPNOTSUPP` to `Unsupported_Socket`), which is where a
descriptor shortage would also land if the mapping this file believes were ever
wrong. One asks to be retried at once; the other asks to be waited out, and they
arrive as the same value.

So the loop does not decide on the value. It counts *consecutive* failures and
retries the first `ACCEPT_FAST_RETRIES` immediately, which is what `accept(2)`
asks for and costs a pending network error nothing at all - no wait, no line, no
counter. A failure that survives that many attempts in a row is one that is not
clearing, and only then is it waited out. That is the reading that does not
depend on telling the two apart, which is the reading available.
*/
accept_failed :: proc(err: net.Accept_Error) -> bool {
	#partial switch err {
	case .None, .Would_Block, .Timeout, .Aborted, .Interrupted:
		return false
	}
	return true
}

/*
How many times a failing accept is retried at once before the loop waits at all.

Small, because what it buys is that a per-connection error clears without a wait,
and the queue moves past one of those in one attempt. Not one, so that a handful
arriving together - a network event does not produce exactly one - still costs
nothing.
*/
ACCEPT_FAST_RETRIES :: 3

/*
The first wait, and the longest one.

Waits escalate rather than starting at the ceiling, which is the difference
between waiting out the two conditions that arrive as the same error. A run of
pending network errors - four queued connections behind an nftables `reject`, a
flapping route - is over in a millisecond or two of waiting and then the queue
moves; a descriptor shortage is not over at all. Starting at the ceiling made the
first of those cost a listener a full second of deafness per failure for as long
as bad entries kept arriving, which is a worse failure than the spin this change
set out to remove: the spin at least kept accepting.

Doubling from a millisecond reaches the ceiling in about a second of total
waiting, so a shortage is at one attempt per second almost immediately, while a
burst that clears costs single-digit milliseconds.

`LISTENER_POLL` is the ceiling because the loop already has that constant with
that meaning: the longest it ever goes without looking at `stop`.

It does cost shutdown something, which is worth stating rather than waving at:
under a descriptor shortage `accept` returns at once, so before this change a
loop saw `stop` within microseconds of it being set, and now it may be most of a
second into a wait. `conn_manager_shutdown` joins without a deadline, so an
elodin stopped while out of descriptors takes up to a second longer per listener
to go. Against a shutdown that already waits on client connections for up to
`server.client_timeout`, that is not the slow part.
*/
ACCEPT_FIRST_WAIT :: time.Millisecond
ACCEPT_BACKOFF :: LISTENER_POLL

/*
How many times the wait may double before it is the ceiling anyway.

Ten, because a millisecond doubled ten times is 1.024 seconds and the ceiling is
one - so there is no eleventh useful step, and every failure past it wants the
ceiling by definition rather than by arithmetic.

Bounding it is not tidiness. `ACCEPT_FIRST_WAIT << steps` is an `i64` of
nanoseconds, and a base of a million overflows one at 44 steps: the first version
of this guarded at 62 on the reasoning that `1 << 62` nanoseconds is centuries,
which is true of a base of *one* and not of this one. Past 44 the shift wrapped,
several values came out zero or negative, `act.wait > 0` was false for them, and
the loop spent those iterations neither waiting nor counting - a burst of exactly
the busy-accept this file exists to remove, about thirty-five seconds into a
descriptor shortage and invisible in the counter.

The assertion below is what keeps that from coming back the next time somebody
raises one of the two constants: it fails to compile rather than overflowing at
runtime.
*/
ACCEPT_ESCALATION_STEPS :: 10
#assert(ACCEPT_FIRST_WAIT << uint(ACCEPT_ESCALATION_STEPS) >= ACCEPT_BACKOFF)

/*
The ceiling for a failure that is not a shortage, which is a different question.

What a wait costs depends on what the failed accept did to the queue, and the two
conditions that reach here differ in exactly that:

  - A descriptor shortage consumes nothing. The peer stays queued, no accept can
    succeed until the shortage clears, and a second between attempts costs the
    queue nothing at all - it is not moving either way.
  - A per-connection error - `EPROTO`, `EHOSTUNREACH`, `EPERM` from a firewall
    reject - is *delivered by* the accept that fails, so the entry is gone and
    the queue has moved. Waiting a second there does cost: it holds the next
    connection behind an error that has already been dealt with.

A burst of those clears inside the escalation and never reaches a ceiling. A
sustained stream of them does, and against a full second it would leave a
listener taking one connection a second with good ones queued behind the bad -
which is the starvation this file already argues against, arrived at from the
other side. Fifty milliseconds still ends any spin, at twenty attempts a second,
and each of those attempts takes an entry off the queue.

The classification only picks the ceiling here. It does not decide whether to
wait, so a shortage that arrived as something other than `Insufficient_Resources`
would still be waited out - at twenty attempts a second rather than one, which is
a pace rather than a spin.
*/
ACCEPT_QUEUE_CEILING :: 50 * time.Millisecond

@(private)
accept_ceiling :: proc(err: net.Accept_Error) -> time.Duration {
	return ACCEPT_BACKOFF if err == .Insufficient_Resources else ACCEPT_QUEUE_CEILING
}

/*
What the loop does about one accept error, as data.

The whole of the loop's decision, so that it can be tested as a sequence rather
than as a shape: nothing else in `accept_loop` and `metrics_accept_loop` decides
anything, and `is this the fourth failure in a row or the first after a
success` is exactly the sort of thing that is wrong in a way no unit test of a
classifier would show.

`report` is deliberately not "we waited". A wait short enough to be part of the
escalation is a condition that may yet clear, and the one `warn` this design
allots per listener must not be spent on one that does: it is said when the wait
has reached the ceiling, which is the point at which the condition has outlived
every reading of it but the persistent one.
*/
Accept_Action :: struct {
	// The consecutive-failure count carried into the next iteration.
	failures: int,
	// Zero where the loop should retry at once.
	wait:     time.Duration,
	report:   bool,
}

accept_action :: proc(err: net.Accept_Error, failures: int) -> Accept_Action {
	if !accept_failed(err) {
		return Accept_Action{failures = 0}
	}
	n := failures + 1
	if n <= ACCEPT_FAST_RETRIES {
		return Accept_Action{failures = n}
	}
	// The ceiling for anything past the useful doublings, so the shift can never
	// be one that overflows - see `ACCEPT_ESCALATION_STEPS`.
	ceiling := accept_ceiling(err)
	wait := ceiling
	if steps := n - ACCEPT_FAST_RETRIES - 1; steps < ACCEPT_ESCALATION_STEPS {
		wait = min(ceiling, ACCEPT_FIRST_WAIT << uint(steps))
	}
	// Said once the wait has stopped escalating, which is where the condition has
	// outlived every reading of it but the persistent one - whichever ceiling
	// this failure is held to.
	return Accept_Action{failures = n, wait = wait, report = wait >= ceiling}
}

/*
Say why an accept loop is waiting, once, and then quietly.

`report_spawn_failure`'s reasoning, met one step earlier: this is the same loop,
and what decides the line rate here is a condition that lasts rather than a peer
that repeats, so a line per attempt would be a line per second for as long as it
holds. `accept_backoff=` in the stats line is what makes the demotion safe.

Reached only once the wait has escalated to `ACCEPT_BACKOFF` - see
`accept_action` - so the flag below is not spent on a burst that clears.

Two shapes, because the two ask for different things. A descriptor shortage is an
environment that has to be raised, and the limit to raise is not in elodin's
configuration at all - which is the whole reason it needs saying, since every
other refusal in this file names a key an operator can find in their own file.
Anything else reaching here is a listening socket that has stopped working, where
there is nothing to raise and the useful thing is the error itself.

The shortage keeps one flag for the process and the other shape keeps one per
listener, which is what each of them is: descriptors are exhausted for the
process, so the second listener to notice is repeating the first, while a socket
that has gone bad is one socket and says nothing about its neighbour. Sharing
that second flag would let whichever listener failed first silence the one an
operator actually needed to hear about.
*/
@(private)
accept_shortage_reported: bool

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
accept_failure_words :: proc(err: net.Accept_Error, listener_flag: ^bool) -> Accept_Failure_Words {
	if err == .Insufficient_Resources {
		return Accept_Failure_Words {
			reported = &accept_shortage_reported,
			brief = "%s: still out of descriptors, waiting %v before accepting again (%v)",
			line = "%s: cannot accept, the process is out of file descriptors - waiting %v between attempts until that clears (%v)",
			hint = "raise the descriptor limit (RLIMIT_NOFILE, LimitNOFILE= in the systemd unit) so it covers server.max_connections with room over; until it does, no connection can be accepted on any listener, and each wait is counted as accept_backoff= in the stats line",
		}
	}
	return Accept_Failure_Words {
		reported = listener_flag,
		brief = "%s: accept is still failing, waiting %v before trying again (%v)",
		line = "%s: accept keeps failing and this listening socket may no longer be usable - waiting %v between attempts (%v)",
		hint = "nothing in the configuration bounds this one; the error beside it is what the kernel said, and each wait is counted as accept_backoff= in the stats line",
	}
}

@(private)
report_accept_failure :: proc(listener: string, err: net.Accept_Error, listener_flag: ^bool) {
	words := accept_failure_words(err, listener_flag)
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
Descriptors this configuration can hold open at once, against the one limit that
is not in it.

Every term is a set of descriptors that can be held *at the same time*, and the
sets are disjoint, so the total is their sum:

  - the connection table, which is a promise to hold that many client sockets;
  - the idle upstream pools, `upstream.max_idle` per configured server, routes
    included;
  - the worker pools, since a worker doing an upstream exchange holds a socket
    for the round trip and a socket checked out of a pool is not in it - so
    `workers` and `upstream_workers` are in-flight upstream sockets that the
    pools do not account for;
  - the UDP readers, one socket each, which is up to `MAX_UDP_READERS` (64) when
    an operator sets the figure rather than the eight a derivation will pick.

`DESCRIPTOR_RESERVE` covers what is left - four listening sockets, the metrics
socket, the log, and the list files while they load - and is a cushion rather
than a count, which is why it is larger than that adds up to.

A ceiling on what the configuration permits, not a reading of what is held.
`process_open_fds` is the other question and the metrics endpoint answers it.
*/
DESCRIPTOR_RESERVE :: 32

Descriptor_Demand :: struct {
	max_connections:  int,
	pooled_upstream:  int,
	workers:          int,
	upstream_workers: int,
	udp_readers:      int,
}

descriptors_wanted :: proc(d: Descriptor_Demand) -> int {
	return(
		d.max_connections +
		d.pooled_upstream +
		d.workers +
		d.upstream_workers +
		d.udp_readers +
		DESCRIPTOR_RESERVE \
	)
}

/*
Said at startup only, and only when the limit cannot cover the table.

Quiet otherwise, which is the departure from `connection_limits_line` beside it:
that line reports a figure an operator cannot read anywhere else, and this one
reports an environment they can - `ulimit -n` - and which is almost always fine.
A line every start saying so would be noise in the steady state, and the steady
state is where this server's log has to stay readable.

Startup only, and *not* `--check`, which is the other departure and the sharper
one. Every other figure `--check` prints is read from the file it was handed, and
this one would be read from whichever process happens to be running the check - a
shell with the distribution's 1024 rather than the service with the unit's
`LimitNOFILE`. That check would warn about a service that is fine and stay silent
about one that is not, which is worse than not being printed: the operator would
be reading it as a statement about the server. At startup the process is the
server, so the figure is the right one.

A warning rather than a refusal to start. The configuration is not wrong - the
machine is short - and a server that will hold fewer clients than asked is worth
more to the operator than one that will not start at all. What it must not do is
meet the shortage silently, which is what it did.
*/
descriptor_limit_line :: proc(soft_limit: int, d: Descriptor_Demand) -> (line: string, short: bool) {
	wanted := descriptors_wanted(d)
	if soft_limit <= 0 || soft_limit >= wanted {
		return "", false
	}
	return fmt.tprintf(
		"descriptors: the limit is %d, short of the %d this configuration can want (server.max_connections %d, %d pooled upstream connections, %d worker threads that hold one for a round trip, %d UDP readers, and %d over). Past it, accepts fail and the listeners wait between attempts, counted as accept_backoff=; raise RLIMIT_NOFILE (LimitNOFILE= in the systemd unit)",
		soft_limit,
		wanted,
		d.max_connections,
		d.pooled_upstream,
		d.workers + d.upstream_workers,
		d.udp_readers,
		DESCRIPTOR_RESERVE,
	), true
}

/*
The soft `RLIMIT_NOFILE`, or 0 where it cannot be read.

`metrics.descriptor_limit` rather than a copy of it here: `process_max_fds`
publishes the same figure from the same `sysconf(_SC_OPEN_MAX)`, and two readings
of one limit are two things to keep in step. It reports the live soft limit,
verified against a process whose limit was lowered under it.
*/
descriptor_limit :: proc() -> int {
	return metrics.descriptor_limit()
}
