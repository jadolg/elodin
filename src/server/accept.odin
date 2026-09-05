package server

import "core:fmt"
import "core:net"
import "core:sys/posix"
import "elodin:logx"

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
How many times a failing accept is retried at once before the loop waits.

Small, because the thing it buys is that a per-connection error clears without a
wait, and the queue moves past one of those in one attempt. Not one, so that a
handful arriving together - a network event does not produce exactly one - still
costs nothing.

The cost of it being too large is a spin of that many iterations, which is
nothing; the cost of it being too small is a listener that goes deaf for a second
over an error that would have cleared. So it errs upward.
*/
ACCEPT_FAST_RETRIES :: 3

/*
How long a loop waits once a failure has not cleared.

`LISTENER_POLL` rather than a figure of its own, because the loop already has
exactly this constant and exactly this meaning: it is the longest an accept loop
ever goes without looking at `stop`. A shorter wait would buy nothing - what it
waits out is a descriptor shortage, not a busy moment - and a longer one would be
a second meaning for "how long shutdown can take", which the poll interval
already is.

So a spinning loop becomes one attempt per second per listener, and shutdown is
no slower than it was: a loop asleep here would have been blocked in `accept` for
the same second anyway.
*/
ACCEPT_BACKOFF :: LISTENER_POLL

/*
Say why an accept loop is waiting, once, and then quietly.

`report_spawn_failure`'s reasoning, met one step earlier: this is the same loop,
and what decides the line rate here is a condition that lasts rather than a peer
that repeats, so a line per attempt would be a line per second for as long as it
holds. `accept_backoff=` in the stats line is what makes the demotion safe.

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
