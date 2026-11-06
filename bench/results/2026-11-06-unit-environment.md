# The bench under the shipped unit's environment

Issue #521: `mise run bench` started elodin with the harness's own environment,
so every figure described glibc's default mmap threshold rather than the
`MALLOC_MMAP_THRESHOLD_=131072` that `packaging/elodin.service` sets. The harness
now starts elodin with the unit's `Environment=` lines. This run re-takes the
matrix that way, with the previous harness (no unit environment) run against the
same binary as a control, section by section, the two arms back to back.

4-core arm64 VM (7.7 GiB, Linux 7.0.0-38-generic), glibc's malloc. elodin release
build of `82a8687`. Each run 10 s measured after 2 s of warmup, median of 3, 15 s
idle between runs. `-servers elodin`; the Unbound and competition rows are not
re-taken here.

## What changed: nothing past the noise

| figure (docs/sizing.md) | unit environment | control |
|---|---|---|
| per idle TCP connection, 1,000 / 20,000 held | 4.6 / 4.6 KB | 4.7 / 4.6 KB |
| per idle DoT connection, 1,000 / 20,000 held | 39 / 33 KB | 38 / 33 KB |
| per idle DoH/2 connection, 1,000 / 20,000 held | 42 / 35 KB | 41 / 36 KB |
| per query in flight, 1,000 / 3,000 | 17 / 17 KB | 17 / 17 KB |
| CPU per handshake, ECDSA / RSA | 195 / 558 µs | 197 / 548 µs |
| idle, no lists | 10 MB | 10 MB |

Saturating throughput moved both ways by up to 16% between the arms (UDP at 100
clients 557k against 662k, rewritten answers 698k against 644k). Two checks say
that is this box's noise rather than the threshold:

- **No allocator syscalls on the answer path.** With bpftrace on the server
  under 100-client UDP and TCP cache-hit load, 4 s each arm, twice:
  `mmap`, `munmap`, `brk` and `madvise` were called zero times in either arm,
  against 1.8–2.6 million syscalls a second in all. A fiber's stack and scratch
  are elodin's own mappings, and nothing a cache hit mallocs reaches 128 KiB, so
  the threshold has nothing on that path to act on.
- **UDP alternated in both orders.** Eight 8 s runs of the same binary,
  plain/unit/plain/unit/plain/unit/unit/plain: 650,677 / 630,860 / 640,545 /
  688,387 / 662,328 / 676,728 / 648,469 / 649,537 qps; the unit arm averages
  661k, the control 651k.

The threshold's effect is where #513 put it: a blocklist rebuild's tables, which
the itest `lists: a rebuild under the shipped unit's environment gives the old
sets' memory back` covers.

## Not re-taken: query logging

The logging section writes ~220 bytes a query, over 3 GB per logged run at full
rate, and filled this VM's disk on the first attempts: the server kept
answering, the lines were lost, and the section reported 24 bytes a query. It
now refuses to start with less than 5 GiB free in `-workdir`, and deletes each
log once read. No document quotes its figures.

## The unit-environment run

### Workloads

| workload | throughput | p50 | p99 | peak RSS |
|---|---|---|---|---|
| cache hits | 602,499 qps | 0.12 ms | 3.4 ms | 23 MB |
| blocked | 635,714 qps | 0.13 ms | 3.3 ms | 23 MB |
| rewritten | 697,616 qps | 0.10 ms | 3.3 ms | 23 MB |
| light mixed load (20 in flight) | 428,552 qps | 0.02 ms | 0.33 ms | 21 MB |
| sustained cache misses | 3,395 qps | 31.8 ms | 78.9 ms | 25 MB |

### Transports, one connection per client

| transport | clients | throughput | p50 | p99 | answered per client (min–max) | errors |
|---|---|---|---|---|---|---|
| UDP | 100 | 556,550 qps | 0.06 ms | 2.4 ms | 53402 – 60742 | 0 |
| TCP | 100 | 479,678 qps | 0.07 ms | 2.8 ms | 46777 – 50745 | 0 |
| DoT | 100 | 376,968 qps | 0.13 ms | 1.8 ms | 36691 – 39366 | 0 |
| DoH over HTTP/1.1 | 100 | 151,257 qps | 0.33 ms | 4.4 ms | 14710 – 15611 | 0 |
| DoH over HTTP/2 | 100 | 124,192 qps | 0.48 ms | 4.0 ms | 11977 – 12902 | 0 |
| TCP | 500 | 508,477 qps | 0.55 ms | 5.4 ms | 9532 – 11390 | 0 |

### HTTP/1.1 against HTTP/2 under concurrency

10 clients, 8 concurrent requests each, every one a cache miss.

| | throughput | p50 | p99 |
|---|---|---|---|
| DoH over HTTP/1.1 | 238 qps | 322.3 ms | 439.6 ms |
| DoH over HTTP/2 | 2,049 qps | 34.4 ms | 81.2 ms |

### CPU per query

| server | transport | CPU per query | at 5,000 qps |
|---|---|---|---|
| elodin dev-82a8687 | TCP | 4 µs | 0.02 core |
| elodin dev-82a8687 | UDP | 3 µs | 0.02 core |
| elodin dev-82a8687 | DoT | 6 µs | 0.03 core |
| elodin dev-82a8687 | DoH over HTTP/1.1 | 11 µs | 0.06 core |
| elodin dev-82a8687 | DoH over HTTP/2 | 13 µs | 0.07 core |

### Fresh TLS handshakes

| key | handshakes/s | CPU per handshake | p50 |
|---|---|---|---|
| ECDSA | 6,378 /s | 195 µs | 2.1 ms |
| RSA | 3,801 /s | 558 µs | 3.8 ms |

### Memory

| | |
|---|---|
| idle, no lists | 10 MB |
| blocklists | ~44 B per rule (11 MB for 250,000 rules) |
| answer cache | ~595 B per entry (6 MB at the default 10,000) |
| realistic total under load | 83 MB with 250,000 rules and 105,702 cached answers |

### Past capacity

Cache misses from 6,000 clients at once, against an upstream answering after 20ms. With N queries in flight at that delay, nothing can be served faster than N ÷ delay.

| max_pending | served | p50 | p99 | dropped |
|---|---|---|---|---|
| 1,024 (at most 51,200 qps) | 38,952 qps | 21.4 ms | 57.0 ms | 24,880 |
| 8,192 (at most 409,600 qps) | 116,315 qps | 49.6 ms | 107.0 ms | 0 |

A dropped query gets no answer at all, so it shows up as a client timeout rather than an error code. A thread-model release queues what its workers cannot carry, so for one of those the second row is the unbounded queue.

### Event loops on two cores

Server pinned to CPUs 0-1, generator to 2-3, 1,000 clients over UDP, `max_pending` 4096. elodin's loops are `listeners.udp.readers`; Unbound's are `num-threads`. A thread-model release takes `readers` as its UDP reader count only.

| server | loops | cache misses | miss p99 | cache hits | hit p99 |
|---|---|---|---|---|---|
| elodin dev-82a8687 | 1 | 44,441 qps | 45.5 ms | 491,717 qps | 5.1 ms |
| elodin dev-82a8687 | 2 | 34,002 qps | 73.8 ms | 472,008 qps | 6.4 ms |
| elodin dev-82a8687 | 4 | 40,943 qps | 56.5 ms | 501,616 qps | 5.5 ms |

### Cache misses against the upstream delay

2,000 clients over UDP, every name unique, `max_pending` 4096.

| server | upstream delay | cache misses | p50 | p99 | timed out | generator ceiling |
|---|---|---|---|---|---|---|
| elodin dev-82a8687 | 20ms | 84,816 qps | 22.5 ms | 45.5 ms | 0 | 100,000 qps |
| elodin dev-82a8687 | 5ms | 117,867 qps | 16.4 ms | 30.6 ms | 0 | 400,000 qps |

### Memory per idle connection

Each client asks one cached name and then holds its connection idle. The figure is (RSS with every connection held − RSS before the first) ÷ N. `max_connections` and its per-prefix share are N + 64 (Unbound: `incoming-num-tcp`), and the idle timeout 120 s.

| server | transport | connections | answered | RSS before | RSS held | per idle connection |
|---|---|---|---|---|---|---|
| elodin dev-82a8687 | TCP | 1,000 | all | 10 MB | 15 MB | 4.6 KB |
| elodin dev-82a8687 | TCP | 5,000 | all | 10 MB | 33 MB | 4.6 KB |
| elodin dev-82a8687 | TCP | 20,000 | all | 10 MB | 101 MB | 4.6 KB |
| elodin dev-82a8687 | DoT | 1,000 | all | 10 MB | 49 MB | 39 KB |
| elodin dev-82a8687 | DoT | 5,000 | all | 10 MB | 175 MB | 34 KB |
| elodin dev-82a8687 | DoT | 20,000 | all | 10 MB | 647 MB | 33 KB |
| elodin dev-82a8687 | DoH over HTTP/2 | 1,000 | all | 10 MB | 51 MB | 42 KB |
| elodin dev-82a8687 | DoH over HTTP/2 | 5,000 | all | 10 MB | 185 MB | 36 KB |
| elodin dev-82a8687 | DoH over HTTP/2 | 20,000 | all | 10 MB | 702 MB | 35 KB |

### Memory per query in flight

Upstream answering after 3s, every name unique, cache off, `max_pending` N + 256 (Unbound: `num-queries-per-thread` 4096). The figure is (peak RSS − idle RSS) ÷ N.

| server | in flight | answered | idle RSS | peak RSS | per query in flight |
|---|---|---|---|---|---|
| elodin dev-82a8687 | 1,000 | all | 10 MB | 27 MB | 17 KB |
| elodin dev-82a8687 | 3,000 | all | 10 MB | 59 MB | 17 KB |

A thread-model release carries only as many as it has workers at once and queues the rest, so behind a three-second upstream most of its queries outlive the generator's five-second wait.

### Cache-hit latency

100 clients, each holding its connection, every answer from the cache.

| server | transport | throughput | p50 | p99 |
|---|---|---|---|---|
| elodin dev-82a8687 | UDP | 602,286 qps | 0.06 ms | 2.3 ms |
| elodin dev-82a8687 | TCP | 543,757 qps | 0.07 ms | 2.9 ms |

