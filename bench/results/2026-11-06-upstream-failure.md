# Upstream failure: what clients see while one goes away

Measured 2026-11-06 with `go run ./cmd/rrlexp -only upstream-fail` against an
`o:speed` build of `main` at 82a8687, on a 4-core aarch64 Linux VM with 7 GB of
RAM, which derives `server.max_pending` 3164. The rate limiter is off, the mock
upstreams answer in 20 ms with 70 A records, and everything else is the shipped
default: `upstream.timeout` 5 s, `attempts` 2, `serve_stale` off unless the arm
says otherwise. Another session's `cmd/bench` run shared the machine, which
these arms' low rates make little of, but it is where a lone slow p99 comes from.

Each arm is 30 s with the server read every second. The first upstream fails at
+3 s and comes back at +18 s. Two clients run throughout:

- the **victim** asks one name at 50 q/s, so after its first query it's a cache
  hit. Anything it loses is a dead upstream reaching a query that never needed
  one.
- the **misses** ask a new name every time at 200 q/s. That's the traffic that
  needs an upstream.

`blackhole` reads every query and answers none. `refused` closes the port, so
the kernel answers with ICMP port unreachable and a TCP reset.

## Summary

"During" is +3 s to +18 s. A window's answered share counts replies that
arrived in it, so misses held 5 s and answered later bring the outage window's
total back to 100% under the two-upstream strategies. The series below show
the stall.

| arm | victim answered during | victim answers' p50 / p99 during | misses answered during | peak in flight / max_pending | shed during | stale served during | `upstream_up` 0 → 1 | misses back |
|---|---:|---:|---:|---:|---:|---:|---|---|
| upstream-fail/blackhole/failover | 100% | 62µs / 493µs | 100% | 1004 / 3164 | 0 | 0 | +8s → +23s | before it returned (+9s) |
| upstream-fail/blackhole/round-robin | 100% | 39µs / 852µs | 100% | 504 / 3164 | 0 | 0 | +9s → +24s | before it returned (+9s) |
| upstream-fail/blackhole/race | 100% | 44µs / 1.1ms | 100% | 4 / 3164 | 0 | 0 | +8s → +23s | never lost |
| upstream-fail/refused/failover | 100% | 56µs / 476µs | 100% | 1004 / 3164 | 0 | 0 | +8s → +23s | before it returned (+9s) |
| upstream-fail/refused/round-robin | 100% | 68µs / 390µs | 100% | 504 / 3164 | 0 | 0 | +9s → +24s | before it returned (+9s) |
| upstream-fail/refused/race | 100% | 66µs / 1.1ms | 100% | 4 / 3164 | 0 | 0 | +8s → +23s | never lost |
| upstream-fail/blackhole/only-upstream/stale-off | 7% | 80µs / 869µs | 0% | 2444 / 3164 | 0 | 0 | +8s → +19s | within 1s |
| upstream-fail/blackhole/only-upstream/stale-on | 100% | 72µs / 1.1ms | 0% | 2000 / 3164 | 0 | 697 | +8s → +19s | within 1s |
| upstream-fail/refused/only-upstream/stale-off | 7% | 50µs / 331µs | 0% | 2443 / 3164 | 0 | 0 | +8s → +19s | within 1s |
| upstream-fail/refused/only-upstream/stale-on | 100% | 74µs / 34.7ms | 0% | 1999 / 3164 | 0 | 697 | +8s → +19s | within 1s |
| upstream-fail/blackhole/only-upstream/pending-full | 17% | 65µs / 1ms | 0% | 256 / 256 | 3114 | 0 | +8s → +19s | within 1s |

## What it says

**With two upstreams, cache hits are untouched.** The victim gets 100% in every
strategy arm, and its p99 stays within 1.1 ms. #255 predicted a stall from a shared
worker pool, but the event loop (#547) doesn't hold a thread for an upstream round trip,
so a held miss no longer delays a hit.

**`race` costs nothing, `failover` holds every miss 5 s, `round-robin` half
of them.** Until the failing member is parked (+8 s: three consecutive
failures, each a 5 s timeout), `failover` sends every miss to it first. In
flight climbs 200 a second to 1004, and nothing is answered for 5 s. Under
`round-robin` half the misses land on it (peak 504). Under `race` the healthy
member answers first and in flight never passes 5. When it's back at +18 s,
the member stays parked until its 10 s cooldown ends at +23 s, which costs
nothing because the healthy member is there.

**`refused` is no cheaper than `blackhole`.** The rows match to the second.
Elodin sends on an unconnected UDP socket, so Linux never delivers the port
unreachable, and a closed port waits out the timeout. Filed as #622.

**With the only upstream gone, `serve_stale` is the whole difference for a
cached name.** The victim's answers expire every 2 s in these arms. With serve-
stale off it got 7% during the outage, then SERVFAIL after the full budget.
With it on it got 100%, answered stale at the 1.8 s `stale_timeout`, and p99
stayed under a millisecond in every second of both arms. The refused arm's
34.7 ms over the whole outage is a few slow replies among about 750, too few to
reach any one second's p99. Misses get nothing either way, and parking the only
member frees nothing: it's still asked, so each miss holds a slot for
`timeout × attempts` = 10 s and in flight peaks at 2444.

**Once held misses fill `max_pending`, cache hits are shed with them.** The
`pending-full` arm pins `max_pending` to 256 with fresh victim answers. From +5 s,
250 datagrams a second are shed and the victim gets 17% for the outage, 0% in
most seconds. The UDP reader sheds before it looks at the cache. This is the
total stall #255 described, with `max_pending` in place of the worker pool. On a
1 GiB machine the bound derives to about 409, which about 41 miss q/s against a
blackholed only upstream fills. Filed as #623.

**Recovery is immediate.** With the only upstream gone, misses are answered
again in the first second after it returns. With a second member they're back
at +9 s, before it returns: the failing one is parked at +8 s and the healthy
one answers everything from then on. A stale-off victim is fully back within 3 s, the time its
coalesced query takes to give up.

## The series

Seconds from the start of the window, trimmed to the transitions. The full run
prints every second.

### upstream-fail/blackhole/failover — down at +3s, back at +18s

| at | failing up | steady up | in flight | shed/s | stale/s | victim answered | victim p50 | victim p99 | misses answered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1 | 1 | 4 | 0 | 0 | 100% | 73µs | 118µs | 100% |
| 4s | 1 | 1 | 204 | 0 | 0 | 100% | 78µs | 144µs | 0% |
| 5s | 1 | 1 | 404 | 0 | 0 | 100% | 80µs | 163µs | 0% |
| 6s | 1 | 1 | 604 | 0 | 0 | 100% | 83µs | 134µs | 0% |
| 9s | 0 | 1 | 806 | 0 | 0 | 100% | 90µs | 1.1ms | 200% |
| 11s | 0 | 1 | 406 | 0 | 0 | 100% | 87µs | 137µs | 200% |
| 12s | 0 | 1 | 206 | 0 | 0 | 100% | 75µs | 137µs | 200% |
| 13s | 0 | 1 | 6 | 0 | 0 | 100% | 63µs | 144µs | 200% |
| 17s | 0 | 1 | 4 | 0 | 0 | 100% | 28µs | 53µs | 100% |
| 18s | 0 | 1 | 4 | 0 | 0 | 100% | 31µs | 56µs | 100% |
| 19s | 0 | 1 | 4 | 0 | 0 | 100% | 32µs | 2.6ms | 100% |
| 20s | 0 | 1 | 4 | 0 | 0 | 100% | 41µs | 256µs | 100% |
| 21s | 0 | 1 | 4 | 0 | 0 | 100% | 31µs | 61µs | 100% |

### upstream-fail/blackhole/round-robin — down at +3s, back at +18s

| at | failing up | steady up | in flight | shed/s | stale/s | victim answered | victim p50 | victim p99 | misses answered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1 | 1 | 4 | 0 | 0 | 100% | 60µs | 113µs | 100% |
| 4s | 1 | 1 | 104 | 0 | 0 | 100% | 59µs | 167µs | 50% |
| 5s | 1 | 1 | 204 | 0 | 0 | 100% | 62µs | 116µs | 50% |
| 6s | 1 | 1 | 304 | 0 | 0 | 100% | 64µs | 121µs | 50% |
| 9s | 0 | 1 | 407 | 0 | 0 | 100% | 26µs | 111µs | 148% |
| 11s | 0 | 1 | 207 | 0 | 0 | 100% | 28µs | 55µs | 150% |
| 12s | 0 | 1 | 107 | 0 | 0 | 100% | 32µs | 468µs | 150% |
| 13s | 0 | 1 | 7 | 0 | 0 | 100% | 29µs | 133µs | 150% |
| 17s | 0 | 1 | 4 | 0 | 0 | 100% | 48µs | 5.1ms | 100% |
| 18s | 0 | 1 | 4 | 0 | 0 | 100% | 31µs | 106µs | 100% |
| 19s | 0 | 1 | 4 | 0 | 0 | 100% | 29µs | 83µs | 100% |
| 20s | 0 | 1 | 4 | 0 | 0 | 100% | 33µs | 480µs | 100% |
| 21s | 0 | 1 | 4 | 0 | 0 | 100% | 68µs | 123µs | 100% |

### upstream-fail/blackhole/only-upstream/stale-off — down at +3s, back at +18s

| at | failing up | steady up | in flight | shed/s | stale/s | victim answered | victim p50 | victim p99 | misses answered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1 | — | 5 | 0 | 0 | 100% | 83µs | 1.4ms | 100% |
| 4s | 1 | — | 205 | 0 | 0 | 100% | 81µs | 869µs | 0% |
| 5s | 1 | — | 451 | 0 | 0 | 8% | 50µs | 68µs | 0% |
| 6s | 1 | — | 701 | 0 | 0 | 0% | — | — | 0% |
| 9s | 0 | — | 1451 | 0 | 0 | 0% | — | — | 0% |
| 11s | 0 | — | 1951 | 0 | 0 | 0% | — | — | 0% |
| 12s | 0 | — | 2201 | 0 | 0 | 0% | — | — | 0% |
| 13s | 0 | — | 2444 | 0 | 0 | 0% | — | — | 0% |
| 17s | 0 | — | 1343 | 0 | 0 | 0% | — | — | 0% |
| 18s | 0 | — | 1195 | 0 | 0 | 0% | — | — | 0% |
| 19s | 1 | — | 1048 | 0 | 0 | 0% | — | — | 98% |
| 20s | 1 | — | 603 | 0 | 0 | 90% | 66µs | 1.1ms | 101% |
| 21s | 1 | — | 403 | 0 | 0 | 100% | 64µs | 410µs | 100% |

### upstream-fail/blackhole/only-upstream/pending-full — down at +3s, back at +18s

| at | failing up | steady up | in flight | shed/s | stale/s | victim answered | victim p50 | victim p99 | misses answered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1 | — | 4 | 0 | 0 | 100% | 82µs | 384µs | 100% |
| 4s | 1 | — | 204 | 0 | 0 | 100% | 72µs | 1ms | 0% |
| 5s | 1 | — | 256 | 186 | 0 | 24% | 68µs | 104µs | 0% |
| 6s | 1 | — | 256 | 250 | 0 | 0% | — | — | 0% |
| 9s | 0 | — | 256 | 250 | 0 | 0% | — | — | 0% |
| 11s | 0 | — | 256 | 250 | 0 | 0% | — | — | 0% |
| 12s | 0 | — | 256 | 250 | 0 | 0% | — | — | 0% |
| 13s | 0 | — | 256 | 246 | 0 | 2% | 1ms | 1ms | 0% |
| 17s | 0 | — | 256 | 250 | 0 | 0% | — | — | 0% |
| 18s | 0 | — | 256 | 248 | 0 | 0% | — | — | 0% |
| 19s | 1 | — | 60 | 1 | 0 | 100% | 45µs | 465µs | 98% |
| 20s | 1 | — | 6 | 0 | 0 | 100% | 51µs | 346µs | 100% |
| 21s | 1 | — | 6 | 0 | 0 | 100% | 57µs | 622µs | 100% |

## What it settles in #255

- **#164**, closed, is the recovery half: stale answers no longer wait out the
  upstream budget. With `serve_stale` on, a cached name is answered at
  `stale_timeout` for the whole outage.
- **`serve_stale` default.** With a second upstream it does nothing. With the
  only upstream gone it's the difference between 7% and 100% for cached names.
  Changing the default is a separate decision, and RFC 8767 leaves it to the
  operator. The numbers are here for it.
- **The 5 s `upstream.timeout`.** It's what each miss is held for while the
  failing member is first in line and unparked. It no longer costs other clients
  anything until held misses reach `max_pending` (#623).
- **Asynchronous upstream I/O** is what #547 delivered. These arms are the
  measurement it lacked.
