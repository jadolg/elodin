# An hour of flooding, read while it ran

Measured 2026-09-03 on the machine the reports beside it were taken on — a
4-core aarch64 Linux VM with 7 GB of RAM — from an `o:speed` build of the branch
that adds the mode:

```
mise run release
cd bench && go run ./cmd/rrlexp -soak 1h -soak-sample 5m
```

The fourth gap issue #235 lists. Every other arm of this harness is eight or ten
seconds long and reports what the server had done by the end of them, which is
the whole of what there is to say about a ten-second flood. It says nothing about
what accumulates: whether the resident memory settles or climbs, whether a cache
under eviction stays the size it was told to be, whether the connection table
gives back what it lends, and whether the answers the limiter allows are still
arriving at the end. Each of those is a shape rather than a final number.

One arm, one hour, the server's own `/metrics` read every five minutes:

- a 20,000 q/s flood from `127.0.0.2`, asking a name of its own every time, so
  every query it gets past the limiter is a cache miss and an upstream round trip;
- a victim on `127.1.0.1` — another /24 — asking 50 q/s over TCP on **a
  connection per query**, so the connection table is churning for the whole hour
  rather than holding one connection opened at the start;
- `cache.max_entries` at the shipped 10,000 rather than the 400,000 the short
  arms use. Over ten seconds the large figure keeps the generator's own unique
  names from evicting anything; over an hour eviction is not an artefact to be
  avoided but the thing being watched;
- `max_connections` 512 and `max_connections_per_prefix` 256 written out rather
  than left implicit, so the sampled `connections_active` has figures beside it;
- the shipped limiter defaults: 500 responses/s per /24, `slip: 2`.

## The series

| at | RSS | threads | fds | cache entries | cache bytes | conns active | `conn_refused` | answers/s | limited/s | victim answered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5m | 74 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 514 | 19,600 | **100%** (14522/14523) |
| 10m | 75 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14519/14519) |
| 15m | 75 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14522/14522) |
| 20m | 74 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14523/14523) |
| 25m | 75 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14521/14521) |
| 30m | 74 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14508/14508) |
| 35m | 74 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 510 | 19,539 | **100%** (14508/14508) |
| 40m | 74 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14507/14507) |
| 45m | 74 MB | 103 | 22 | 10,000 | 20 MB | 1 | 0 | 510 | 19,538 | **100%** (14493/14493) |
| 50m | 74 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 533 | 19,515 | **100%** (14521/14521) |
| 55m | 75 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 548 | 19,500 | **100%** (14517/14517) |
| 60m | 75 MB | 103 | 23 | 10,000 | 20 MB | 1 | 0 | 548 | 19,500 | **100%** (14514/14514) |

The gauges are as of the sample; the rates are over the five minutes before it.

**Nothing drifts.** Resident memory is 74 MB at five minutes and 75 MB at sixty,
and the one megabyte between them is the cache reaching the size it was
configured for. Threads are 103 throughout — the pinned 64 workers, 32 upstream
workers, the listeners and the maintenance loop — and the descriptor count moves
between 22 and 23, which is the victim's current connection being open or not.

**The cache holds at its limit and keeps working.** Ten thousand entries from the
first sample to the last, 20 MB of them, against a flood asking 20,000 distinct
names a second: 1.87 million queries reached the resolver over the hour, so the
table turned over about 187 times without growing by a byte or costing the victim
an answer.

**The connection table lends and reclaims.** `connections_active` is 1 at every
sample and `conn_refused` is 0 at every sample, while the victim opened and closed
**174,176 connections** over the hour. A slot handed back 174,000 times is the
thing this arm was built to watch, and the table neither leaked one nor refused
one.

**The limiter holds for an hour, not for ten seconds.** 510 answers a second
through the middle of the run against 19,538 datagrams a second refused; the
budget is 500 and the slip adds its own 62-a-second pool on top, which is what
the extra ten are. The last three windows sit at 548 answers and 19,500 refusals
— the flood's own offered rate wobbling by a fraction of a percent on a machine
it shares with the server, not the bucket giving way.

## The victim, and the flood, over the whole hour

| | offered | answered | p50 | p99 |
|---|---:|---:|---:|---:|
| victim, TCP, another /24 | 174,176 | **174,176 (100%)** | 20.4 ms | 21.7 ms |

| | offered/s | answered/s | truncated/s | at the named address | CPU/s | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| flood, UDP, `127.0.0.2` | 20,000 | 470 | 58 | 0.55 MB | 0.06 | 78 MB |

Not one of the victim's 174,176 queries went unanswered, and every one of them
came back at a single upstream round trip. Server totals for the hour:
1,866,931 queries resolved, 70,326,858 datagrams rate-limited, 209,946 answered
truncated by the slip, and 0.06 of a core.

The 388 queries `elodin_queries_dropped_total` reports were shed in the first
moments of the arm, before the limiter's bucket had been drawn down — the same
figure the ten-second arms show, and none were shed in the hour that followed.

## What this does not say

**One flood, one shape.** This is the arm that already had a known-good
ten-second result (`other-prefix/limiter-on` in
`2026-09-03-rate-limit-bystander.md`), run long, so that the hour is read
against a row rather than against nothing. An hour of *handshakes*
(`2026-09-03-handshake-floods.md`) or an hour of held connections
(`2026-09-03-connection-table-share.md`) is a different question, and `-soak`
runs whichever arm the code names rather than a chosen one.

**The limiter's own table is not sampled, because there is nothing to sample.**
`RRL_BUCKETS` is a fixed 16,384 buckets allocated at startup and never grown, so
what an hour of flooding can do to it is in the resident memory beside it and
nowhere else. That a bucket is handed from one prefix to another only once it has
refilled is asserted directly in `src/server/ratelimit_test.odin`.

**An hour is not a week.** What this rules out is drift at the rate an hour can
show: a megabyte an hour would have been visible here, and a megabyte a day would
not. The arm takes a `-soak` of any length, and the longer runs are the ones
nobody has taken yet.
