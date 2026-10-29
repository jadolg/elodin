# The event loop against the thread model and Unbound

Measured on a 4-core arm64 VM (7.7 GiB, Linux 7.0.0-38-generic), the server
under test and the generator sharing it. Three servers, the same harness
configuration for each:

- **before**: elodin dev-8e947cd, the thread model (`origin/main` when #547 was cut);
- **after**: elodin dev-035eedb, the event loop as the review rounds left it;
- **Unbound 1.24.2**, forwarding to the same mock (`unboundConfig` in
  `cmd/bench/server.go` maps each setting).

Mock upstream at 20 ms unless a row says otherwise. DNSSEC off. Each run 10 s
measured after 2 s of warmup, median of 3. Taken a section at a time with
`go run ./cmd/bench -only <section>`, the before rows with `-binary` and
`-held 5000`.

The after and Unbound rows of a table come from one run, taken on 2026-10-27.
The before rows are from the day before, except the cache-hit rows, which were
taken again beside the others: the machine ran about a fifth slower on the
second day, Unbound included. Past capacity and the idle table are from
dev-846ee95, the event loop before review; nothing measured since moves them.

The mock's own answer time wanders between 20 and 45 ms on this machine (timed
with `dig` against it alone), so miss rows taken at a different minute differ by
more than the servers do. Five runs of the misses section on the final head gave
68,695-78,260 qps at 20 ms and 72,659-77,806 at 5 ms; the table has the first.
Run alternately with dev-846ee95, the 20 ms rows were level and the 5 ms rows
48,000 against 73,000.

## Cache misses against the upstream delay

2,000 clients over UDP, every name unique, `max_pending` 4096.

| server | upstream delay | cache misses | p50 | p99 | timed out |
|---|---|---|---|---|---|
| before | 20 ms | 3,536 qps | 569.9 ms | 733.1 ms | 0 |
| after | 20 ms | 72,672 qps | 25.5 ms | 57.5 ms | 0 |
| Unbound | 20 ms | 39,693 qps | 22.6 ms | 44.7 ms | 1,640 |
| before | 5 ms | 21,830 qps | 89.5 ms | 134.6 ms | 0 |
| after | 5 ms | 77,806 qps | 24.9 ms | 43.6 ms | 0 |
| Unbound | 5 ms | 58,875 qps | 10.2 ms | 22.2 ms | 3,222 |

At 20 ms the thread model is its 128 workers over the delay; the event loop is
twenty times that and nearly twice Unbound. At 5 ms the event loop is out of CPU
first: it answers more than Unbound, but its p50 is queueing in the loops, where
Unbound answers in two round trips. Unbound's timeouts are the queries it drops
past `num-queries-per-thread`; elodin's past `max_pending` would show as the
same, and none reach it here.

## Event loops on two cores

Server pinned to CPUs 0-1, generator to 2-3, 1,000 clients over UDP,
`max_pending` 4096. Loops are `listeners.udp.readers` (Unbound: `num-threads`);
for the thread model the figure is only its UDP reader count.

| server | loops | cache misses | miss p99 | cache hits | hit p99 |
|---|---|---|---|---|---|
| before | 1 | 3,078 qps | 399.2 ms | 490,748 qps | 4.9 ms |
| before | 2 | 3,140 qps | 443.8 ms | 494,322 qps | 5.2 ms |
| before | 4 | 3,086 qps | 426.5 ms | 478,804 qps | 5.4 ms |
| after | 1 | 40,372 qps | 44.2 ms | 266,535 qps | 4.9 ms |
| after | 2 | 44,265 qps | 36.5 ms | 476,378 qps | 5.6 ms |
| after | 4 | 44,956 qps | 35.0 ms | 476,992 qps | 6.8 ms |
| Unbound | 1 | 3,170 qps | 98.2 ms | 312,578 qps | 3.4 ms |
| Unbound | 2 | 9,960 qps | 90.5 ms | 307,937 qps | 2.9 ms |
| Unbound | 4 | 27,255 qps | 42.0 ms | 315,985 qps | 5.2 ms |

Loops past the cores add nothing, which is why the derived count is the cores.
One loop answers fewer hits than the thread model's pool did on two cores; two
answer about as many (the before rows are the first day's, on the faster
machine).

## Memory per query in flight

Upstream answering after 3 s, every name unique, cache off, `max_pending`
N + 256. (peak RSS − idle RSS) ÷ N.

| server | in flight | answered | idle RSS | peak RSS | per query |
|---|---|---|---|---|---|
| before | 1,000 | 128 of 1,000 | 13 MB | 15 MB | — |
| after | 1,000 | all | 10 MB | 27 MB | 17 KB |
| after | 3,000 | all | 10 MB | 59 MB | 17 KB |
| Unbound | 1,000 | all | 172 MB | 185 MB | 13 KB |
| Unbound | 3,000 | all | 173 MB | 219 MB | 16 KB |

The thread model holds as many as it has workers and queues the rest past the
generator's five-second wait. Unbound's idle figure is its preallocated buffers
and caches at this configuration.

## Memory per idle connection

Each client asks one cached name and holds its connection idle.
(RSS held − RSS before) ÷ N. Unbound's rows stop at 5,000: it allocates a
64 KiB buffer per configured TCP handler at start, which is its "RSS before"
here, and 20,000 is several GiB before a client connects.

| server | transport | 1,000 | 5,000 | 20,000 |
|---|---|---|---|---|
| before | TCP | 25 KB | 25 KB | — |
| after | TCP | 21 KB | 21 KB | 21 KB |
| Unbound | TCP | 0.2 KB (276 MB before) | 0.1 KB (1,038 MB before) | — |
| before | DoT | 95 KB | 93 KB | — |
| after | DoT | 74 KB | 72 KB | 72 KB |
| Unbound | DoT | 55 KB | 53 KB | — |
| before | DoH/2 | 94 KB | 91 KB | — |
| after | DoH/2 | 72 KB | 71 KB | 70 KB |
| Unbound | DoH/2 | 69 KB | 68 KB | — |

20,000 held DoT connections on the event loop are 1.4 GB, OpenSSL's session
being most of it, on five threads.

## Cache hits

100 clients each holding its connection, every answer from the cache, every core.

| server | transport | throughput | p50 | p99 | CPU per query |
|---|---|---|---|---|---|
| before | UDP | 322,735 qps | 0.18 ms | 2.2 ms | 7 µs |
| after | UDP | 446,569 qps | 0.12 ms | 1.7 ms | 5 µs |
| Unbound | UDP | 549,112 qps | 0.07 ms | 2.5 ms | 2 µs |
| before | TCP | 175,918 qps | 0.13 ms | 5.0 ms | 12 µs |
| after | TCP | 297,431 qps | 0.21 ms | 2.3 ms | 8 µs |
| Unbound | TCP | 393,763 qps | 0.13 ms | 1.6 ms | 5 µs |

CPU per query on the other transports (`-only cpu`):

| server | DoT | DoH/1.1 | DoH/2 |
|---|---|---|---|
| before | 14 µs | 15 µs | 30 µs |
| after | 9 µs | 13 µs | 17 µs |
| Unbound | 7 µs | — (HTTP/2 only) | 14 µs |

This is the gap left: a cache hit costs about 1.2–2.5× Unbound's CPU, the most on UDP. It is the
work done per query, not waiting, so it is not what the event loop changed.

## Past capacity

Cache misses from 6,000 clients at once, 20 ms upstream.

| server | max_pending | served | p50 | p99 | dropped |
|---|---|---|---|---|---|
| before | 1,024 | 3,242 qps | 270.7 ms | 398.8 ms | 24,903 |
| before | 8,192 | 3,218 qps | 1,791.5 ms | 1,950.5 ms | 0 |
| after | 1,024 | 39,943 qps | 21.4 ms | 35.7 ms | 24,880 |
| after | 8,192 | 45,111 qps | 120.4 ms | 231.3 ms | 0 |

For the thread model `max_pending` is the queue behind the workers; on the
event loop it is the queries in flight, so the bound is the throughput.

## Idle and steady state

| | before | after |
|---|---|---|
| idle, no lists | 13 MB | 10 MB |
| under load with 250,000 rules and the cache full | 119 MB | 104 MB |
| threads, idle | ~200 | 5 |
