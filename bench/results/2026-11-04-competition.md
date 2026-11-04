# elodin against ten other resolvers and forwarders

Measured on a 4-core arm64 VM (8 GB, Linux 7.0.0-38-generic), with the server
under test and the generator on the same machine. Taken with

```sh
go run ./cmd/bench -only compare -servers all -competitors ~/competitors -cooldown 5s
```

on 2026-11-04, elodin at dev-3ba1ae8. Unbound's rows were taken an hour later
from an unconfined copy of the binary (`-servers unbound -unbound /home/ubuntu/unbound-bench`;
the first run hit the AppArmor profile in the README). Mock upstream at 20 ms,
DNSSEC off, each run 10 s after 2 s of warmup, median of 3.

The servers, each given elodin's listeners, certificate, upstream, cache size,
thread count, in-flight bound and idle timeout wherever it has a setting for
them, with rate limiting, query logging and statistics off
(`cmd/bench/competitors.go` says how each maps):

| server | version | transports here | list format |
|---|---|---|---|
| elodin | dev-3ba1ae8 | UDP, TCP, DoT, DoH/1.1, DoH/2 | domains |
| Unbound | 1.24.2 (Ubuntu) | UDP, TCP, DoT, DoH/2 | `local-zone: always_nxdomain` |
| AdGuard Home | 0.107.80 (release) | UDP, TCP, DoT, DoH/1.1, DoH/2 | `\|\|name^` |
| Blocky | 0.35.0 (release) | UDP, TCP, DoT, DoH/1.1 (it does not serve HTTP/2) | domains |
| Pi-hole FTL | 6.8 (release) | UDP, TCP | gravity.db |
| CoreDNS | 1.15.0 (release) | UDP, TCP, DoT, DoH/1.1, DoH/2 | — (no list plugin) |
| dnsmasq | 2.92 (Ubuntu) | UDP (TCP forks a child per connection) | `address=/name/` |
| PowerDNS Recursor | 5.3.5 (Ubuntu) | UDP, TCP | RPZ |
| dnsdist | 2.0.2 (Ubuntu) | UDP, TCP, DoT, DoH/2 | `QNameSetRule` |
| BIND | 9.20.24 (Ubuntu) | UDP, TCP, DoT, DoH/2 | RPZ |
| Knot Resolver | 6.2.0 (Ubuntu) | UDP, TCP, DoT, DoH/2 | RPZ |

Knot is one process, so one thread; it scales by running a process per core,
which a harness sampling one pid does not do. Its rows are one process on two
cores.

## Memory

Idle is the server started with its cache on and nothing asked. Lists is 250,000 names, each in the server's own list format, read once `blocked.bench.test` answers NXDOMAIN. Per cache entry is two servers whose caches hold 1,000 and 200,000 answers, each given 40 s of unique names at 128 clients: the difference in RSS over the difference in entries held, so a cache allocated up front counts.

| server | idle RSS | with the list | per rule | per cache entry |
|---|---|---|---|---|
| elodin dev-3ba1ae8 | 10 MB | 19 MB | 38 B | 484 B (filled 133,361) |
| Unbound 1.24.2 | 173 MB | 254 MB | 343 B | 707 B (filled 148,758) |
| AdGuard Home 0.107.80 | 31 MB | 65 MB | 142 B | 563 B (filled 137,236) |
| Blocky 0.35.0 | 28 MB | 37 MB | 38 B | 715 B (filled 144,890) |
| Pi-hole FTL 6.8 | 10 MB | 10 MB | 0 B | 299 B (filled 155,165) |
| CoreDNS 1.15.0 | 50 MB | — | — | 880 B (filled 121,347) |
| dnsmasq 2.92 | 5 MB | 27 MB | 92 B | 202 B (filled 121,527) |
| PowerDNS Recursor 5.3.5 | 43 MB | 82 MB | 167 B | 868 B (filled 133,531) |
| dnsdist 2.0.2 | 92 MB | 154 MB | 260 B | 292 B (filled 136,816) |
| BIND 9.20.24 | 22 MB | 183 MB | 675 B | 364 B (filled 144,824) |
| Knot Resolver 6.2.0 | 17 MB | 54 MB | 157 B | 743 B (filled 118,888) |

## Cache hits on two cores

Server on CPUs 0-1 with two threads, generator on 2-3, 100 clients each holding its connection, every answer from the cache. Each cell is throughput / p99 / CPU per query. A blocked answer is the UDP row's name on the list.

| server | UDP | TCP | DoT | DoH/1.1 | DoH/2 | blocked (UDP) |
|---|---|---|---|---|---|---|
| elodin dev-3ba1ae8 | 474,004 / 1.4 ms / 4 µs | 320,075 / 1.3 ms / 7 µs | 273,407 / 0.59 ms / 8 µs | 141,587 / 3.2 ms / 13 µs | 135,636 / 2.5 ms / 15 µs | 464,493 / 2.3 ms / 4 µs |
| Unbound 1.24.2 | 592,689 / 0.61 ms / 3 µs | 310,577 / 2.5 ms / 6 µs | 308,440 / 2.5 ms / 7 µs | — | 121,673 / 2.8 ms / 14 µs | 564,449 / 0.64 ms / 2 µs |
| AdGuard Home 0.107.80 | 107,230 / 3.2 ms / 21 µs | 105,071 / 4.1 ms / 21 µs | 99,936 / 4.2 ms / 23 µs | 76,770 / 5.7 ms / 28 µs | 55,336 / 6.5 ms / 40 µs | 117,465 / 3.0 ms / 19 µs |
| Blocky 0.35.0 | 141,044 / 2.9 ms / 15 µs | 22 / 928.1 ms / 1324 µs (**16,582,936 timed out**) | 34 / 1173.4 ms / 794 µs (**76,676,729 timed out**) | 77,063 / 5.5 ms / 27 µs | — | 148,516 / 2.3 ms / 15 µs |
| Pi-hole FTL 6.8 | 147,255 / 2.8 ms / 15 µs | 493 / 333.7 ms / 1245 µs (**16,459,332 timed out**) | — | — | — | 160,342 / 2.3 ms / 14 µs |
| CoreDNS 1.15.0 | 258,872 / 1.6 ms / 8 µs | 260,953 / 3.3 ms / 6 µs | 252,710 / 3.1 ms / 6 µs | 118,209 / 4.6 ms / 14 µs | 64,255 / 5.8 ms / 29 µs | — |
| dnsmasq 2.92 | 263,360 / 0.57 ms / 4 µs | — | — | — | — | 253,221 / 0.57 ms / 4 µs |
| PowerDNS Recursor 5.3.5 | 535,693 / 0.72 ms / 3 µs | 356,982 / 1.4 ms / 3 µs | — | — | — | 543,022 / 0.71 ms / 3 µs |
| dnsdist 2.0.2 | 647,421 / 0.65 ms / 3 µs | 332,651 / 2.5 ms / 5 µs | 310,059 / 2.8 ms / 6 µs | — | 118,594 / 2.8 ms / 12 µs | 442,072 / 1.5 ms / 3 µs |
| BIND 9.20.24 | 433,172 / 1.1 ms / 4 µs | 328,885 / 3.1 ms / 6 µs | 290,343 / 1.3 ms / 8 µs | — | 119,348 / 3.3 ms / 16 µs | 162,707 / 1.4 ms / 11 µs |
| Knot Resolver 6.2.0 | 278,431 / 0.88 ms / 4 µs | 168,850 / 1.3 ms / 7 µs | 130,738 / 1.5 ms / 9 µs | — | 1,474 / 123.9 ms / 85 µs | 260,921 / 0.68 ms / 4 µs |

## Cache misses on two cores

As above, 1,000 clients over UDP, every name unique, upstream at 20ms, the in-flight bound raised to 4,096 wherever the server has one. The generator cannot ask faster than 50,000 qps.

| server | cache misses | p50 | p99 | timed out | CPU per miss |
|---|---|---|---|---|---|
| elodin dev-3ba1ae8 | 43,443 qps | 21.9 ms | 40.5 ms | 0 | 26 µs |
| Unbound 1.24.2 | 8,190 qps | 31.9 ms | 77.1 ms | 1,673 | 27 µs |
| AdGuard Home 0.107.80 | 6,236 qps | 25.9 ms | 82.4 ms | 2,159 | 73 µs |
| Blocky 0.35.0 | 7,018 qps | 24.5 ms | 77.7 ms | 2,285 | 61 µs |
| Pi-hole FTL 6.8 | 2,296 qps | 63.3 ms | 122.7 ms | 2,387 | 230 µs |
| CoreDNS 1.15.0 | 4,383 qps | 33.1 ms | 92.4 ms | 2,320 | 65 µs |
| dnsmasq 2.92 | 2,174 qps | 65.4 ms | 120.1 ms | 2,388 | 227 µs |
| PowerDNS Recursor 5.3.5 | 38,803 qps | 24.2 ms | 67.8 ms | 0 | 47 µs |
| dnsdist 2.0.2 | 4,273 qps | 34.3 ms | 91.2 ms | 2,287 | 27 µs |
| BIND 9.20.24 | 8,895 qps | 30.0 ms | 79.8 ms | 1,630 | 34 µs |
| Knot Resolver 6.2.0 | 3,950 qps | 34.3 ms | 93.4 ms | 2,338 | 43 µs |

## What a held connection and a waiting query cost

1,000 clients each ask one cached name and hold the connection idle; (RSS held − RSS before) ÷ N. In flight is 1,000 unique names behind a 3 s upstream, cache off; (peak − idle) ÷ N, with how many were answered.

| server | per idle TCP | per idle DoT | per idle DoH/2 | per query in flight |
|---|---|---|---|---|
| elodin dev-3ba1ae8 | 17 KB | 73 KB | 73 KB | 17 KB (all answered) |
| Unbound 1.24.2 | 0.4 KB | 55 KB | 70 KB | 15 KB (all answered) |
| AdGuard Home 0.107.80 | 20 KB | 45 KB | 70 KB | 20 KB (**810 of 1,000** answered) |
| Blocky 0.35.0 | 12 KB | 36 KB | — | failed |
| Pi-hole FTL 6.8 | 0.0 KB (**60 of 1,000**) | — | — | 0.5 KB (**573 of 1,000** answered) |
| CoreDNS 1.15.0 | 7.0 KB | 37 KB | 17 KB (**200 of 1,000**) | 7.8 KB (**622 of 1,000** answered) |
| dnsmasq 2.92 | — | — | — | 0.2 KB (**528 of 1,000** answered) |
| PowerDNS Recursor 5.3.5 | 2.7 KB | — | — | 16 KB (all answered) |
| dnsdist 2.0.2 | 0.1 KB | 25 KB | 42 KB | 0.0 KB (all answered) |
| BIND 9.20.24 | 19 KB | 64 KB | 69 KB (**986 of 1,000**) | 34 KB (**0 of 1,000** answered) |
| Knot Resolver 6.2.0 | 13 KB | 41 KB | 60 KB | 17 KB (all answered) |

Cells that failed:

- Blocky 0.35.0, in flight: cmp-inflight (blocky) did not come up: read udp 127.0.0.1:45062->127.0.0.1:40009: i/o timeout

## Reading the tables

- **Throughput is two cores, CPU is efficiency.** A server that spends a third
  core cannot pass for a faster one here, and CPU per query is the figure to
  compare across them.
- **Timed-out counts beyond what could have been asked** (Blocky's TCP and DoT,
  Pi-hole's TCP) are the generator counting each failed attempt on a held
  connection those servers stopped answering on. Read them as "stopped
  answering", not as a number. Pi-hole's TCP is dnsmasq's: a forked child per
  connection, which also explains its 60 of 1,000 held.
- **Per cache entry** is the difference between a 1,000-answer and a
  200,000-answer cache over the entries each reached, so a cache allocated up
  front (dnsmasq, dnsdist) is charged for. Pi-hole's list costs no RSS
  because FTL reads it from SQLite, so it lives in the page cache.
- **Unbound's idle 173 MB** is the TCP handler buffers it allocates at start for
  the configured connection table (`incoming-num-tcp`), as in
  2026-10-26-event-loop.md.
- **In flight behind a 3 s upstream**: Blocky never answered one, BIND none
  within the generator's five seconds, and dnsmasq and Pi-hole about half. Their
  per-query figures describe what they held, not what they answered.

## Where elodin is ahead

- **Cache misses.** 43,443 qps with nothing dropped. PowerDNS is the only other
  server within reach (38,803). Every other server answered under 9,000 and
  dropped between 1,600 and 2,400 of the generator's 1,000-client load.
- **Lists.** 38 B per rule, level with Blocky and a quarter of AdGuard Home's 142 B.
  It is under the RPZ resolvers' 157–675 B and well under dnsdist's 260 B.
- **Idle and total weight.** 10 MB idle and 19 MB with the list. Only dnsmasq is
  lighter idle (5 MB), and Pi-hole matches it while keeping its list on disk.
- **DoH/1.1 and DoH/2.** The highest throughput of every server that serves
  them.

## Where elodin falls behind, and what is filed

- **Cache-hit CPU: 4 µs over UDP and 7 µs over TCP.** Unbound, PowerDNS and
  dnsdist answer for 3 µs over UDP and 3–6 µs over TCP. Reproduced in
  #594: Odin's `core:time` reads the clock with a raw syscall (6 per UDP query,
  9 per TCP); a TCP query takes 3 reads and 2 `epoll_ctl`; and every hit
  decodes and re-encodes the cached answer.
- **73 KB per idle DoT connection**, the most of every server measured (dnsdist:
  25 KB). #595: `SSL_MODE_RELEASE_BUFFERS` measured at ~20 KB saved for no
  visible CPU.
- **17 KB per idle TCP connection** (dnsdist 0.1 KB, Unbound 0.4 KB, PowerDNS
  2.7 KB). #596: 13 KB of it is the parked fiber's stack.
