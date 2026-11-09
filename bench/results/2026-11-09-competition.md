# elodin against ten other resolvers and forwarders, third round

Measured on the same 4-core arm64 VM as 2026-11-05-competition.md (8 GB,
Linux 7.0.0-42-generic), server and generator on the same machine, on
2026-11-09 with elodin at dev-e02e553: every issue the second round filed
(#610 to #614) merged. Taken with

```sh
sudo sysctl net.core.rmem_default=1048576
go run ./cmd/bench -only compare -servers all -competitors ~/competitors \
  -unbound /home/ubuntu/unbound-bench -mock-cpus 2-3 -cooldown 5s
# Pi-hole's rows, after its TCP limit was set
go run ./cmd/bench -only compare -servers pihole -competitors ~/competitors \
  -mock-cpus 2-3 -cooldown 5s
```

Pi-hole's rows are from that second run, the others from the first. Its UDP
row read 181k in the first and 164k in the second, about the run-to-run
spread.

Mock upstream at 20 ms, DNSSEC off, each run 10 s after 2 s of warmup, median
of 3. elodin runs its shipped defaults (`server.pin_loops` off) under the
shipped unit's environment. Versions are as in the first two rounds.

## What changed in the harness since the second round

- **UDP, TCP and DoT hits run under dnsperf** (#633) for every server, with
  `-e`. The Go loadgen put about 3 ms of its own scheduling into the DoT p99
  (#610), so this round's hit cells do not compare with the second round's.
- **Server CPU counts from the end of the warmup.** The second round's CPU
  per query counted the warmup's CPU over the measured queries only, about
  1.2x high.
- **BIND loads its list with `log no`.** It logged every rewrite, and `-g`
  sends that to stderr whatever the logging statement says: 950 MB during the
  second round's blocked row, which read 159k qps against 414k for a hit. It
  now reads 342k.
- **Pi-hole serves the shared TCP connection limit** (`max-tcp-connections`),
  as the others serve their counterpart of `max_connections`. At dnsmasq's
  default of 20 the other 80 connections waited in the listen backlog,
  accepted by the kernel and never served or closed, so dnsperf had nothing
  to redial: 30 qps with every client timed out. With the limit set it holds
  997 of 1,000 idle connections, 60 before.
- **Pi-hole's TCP CPU and per idle TCP connection read unmeasured.** It serves
  each TCP connection from a forked child, and the harness samples one pid.

## elodin since the second round

Only rows whose method did not change; the second round's CPU divided by 1.2.

| row | dev-5c06dae | dev-e02e553 |
|---|---|---|
| misses sustained | 75,000 qps | 100,000 qps, the ladder's top step |
| CPU per miss there | 27 µs (≈22) | 14 µs |
| at 2,000 qps: p99 / CPU | 22.3 ms / 52 µs (≈43) | 21.5 ms / 40 µs |
| per idle TCP / DoT / DoH/2 | 8.7 / 43 / 46 KB | 4.7 / 39 / 41 KB |
| per query in flight | 17 KB | 16 KB |

100,000 qps is about what the mock carries on two cores, so elodin's miss
ceiling is unmeasured. Blocked answers are left out: within one run they cost
93% of a hit against 76% in the second round, but both cells changed
generator, so how much of that is #611 the two rounds cannot say.

## Memory

Idle is the server started with its cache on and nothing asked. Lists is 250,000 names, each in the server's own list format, read once `blocked.bench.test` answers NXDOMAIN. Per cache entry is two servers whose caches hold 1,000 and 200,000 answers, each given 40 s of unique names at 128 clients: the difference in RSS over the difference in entries held, so a cache allocated up front counts.

| server | idle RSS | with the list | per rule | per cache entry |
|---|---|---|---|---|
| elodin dev-e02e553 | 10 MB | 21 MB | 43 B | 311 B (filled 117,344) |
| Unbound 1.24.2 | 171 MB | 255 MB | 354 B | 724 B (filled 126,549) |
| AdGuard Home 0.107.80 | 31 MB | 64 MB | 139 B | 565 B (filled 120,069) |
| Blocky 0.35.0 | 28 MB | 36 MB | 34 B | 725 B (filled 125,759) |
| Pi-hole FTL 6.8 | 10 MB | 10 MB | 0 B | 234 B (filled 108,143) |
| CoreDNS 1.15.0 | 49 MB | — | — | 939 B (filled 112,569) |
| dnsmasq 2.92 | 5 MB | 26 MB | 89 B | 223 B (filled 102,106) |
| PowerDNS Recursor 5.3.5 | 42 MB | 83 MB | 171 B | 946 B (filled 115,989) |
| dnsdist 2.0.2 | 99 MB | 161 MB | 260 B | 283 B (filled 112,149) |
| BIND 9.20.24 | 22 MB | 183 MB | 674 B | 362 B (filled 117,059) |
| Knot Resolver 6.2.0 | 17 MB | 54 MB | 156 B | 771 B (filled 108,823) |

## Cache hits on two cores

Server on CPUs 0-1 with two threads, generator on 2-3, 100 clients each holding its connection, every answer from the cache. Each cell is throughput / p99 / CPU per query. A blocked answer is the UDP row's name on the list.

| server | UDP | TCP | DoT | DoH/1.1 | DoH/2 | blocked (UDP) |
|---|---|---|---|---|---|---|
| elodin dev-e02e553 | 776,871 / 0.43 ms / 2 µs | 573,482 / 0.29 ms / 3 µs | 434,835 / 0.34 ms / 4 µs | 140,559 / 2.8 ms / 9 µs | 132,570 / 2.7 ms / 11 µs | 719,401 / 0.26 ms / 2 µs |
| Unbound 1.24.2 | 717,338 / 0.12 ms / 2 µs | 436,802 / 0.48 ms / 4 µs | 349,829 / 0.48 ms / 5 µs | — | 137,312 / 2.4 ms / 11 µs | 701,416 / 0.34 ms / 1 µs |
| AdGuard Home 0.107.80 | 114,949 / 3.0 ms / 16 µs | 120,344 / 4.0 ms / 15 µs | 116,778 / 3.9 ms / 16 µs | 83,749 / 5.2 ms / 22 µs | 56,046 / 6.5 ms / 33 µs | 126,453 / 2.7 ms / 15 µs |
| Blocky 0.35.0 | 162,465 / 2.4 ms / 11 µs | 128,743 / 1.7 ms / 12 µs (**81 failed, 10,000 reconnects**) | 47,226 / 3.9 ms / 15 µs (**70 failed, 3,747 reconnects**) | 85,081 / 4.8 ms / 20 µs | — | 168,238 / 1.9 ms / 11 µs |
| Pi-hole FTL 6.8 | 164,114 / 1.9 ms / 12 µs | 9,887 / 122.9 ms / — (a process per connection) (**59 failed, 947 reconnects**) | — | — | — | 180,605 / 1.7 ms / 10 µs |
| CoreDNS 1.15.0 | 298,030 / 1.3 ms / 6 µs | 343,391 / 1.8 ms / 4 µs | 283,369 / 1.9 ms / 5 µs | 125,998 / 4.4 ms / 11 µs | 66,456 / 5.6 ms / 23 µs | — |
| dnsmasq 2.92 | 319,818 / 0.37 ms / 3 µs | — | — | — | — | 307,723 / 0.39 ms / 3 µs |
| PowerDNS Recursor 5.3.5 | 720,304 / 0.14 ms / 2 µs | 340,244 / 0.53 ms / 2 µs | — | — | — | 697,348 / 0.17 ms / 2 µs |
| dnsdist 2.0.2 | 794,461 / 0.27 ms / 2 µs | 556,330 / 0.34 ms / 3 µs | 429,393 / 0.41 ms / 4 µs | — | 128,732 / 2.5 ms / 9 µs | 743,237 / 0.24 ms / 2 µs |
| BIND 9.20.24 | 580,912 / 0.37 ms / 3 µs | 375,123 / 0.70 ms / 5 µs | 295,640 / 0.80 ms / 6 µs | — | 139,116 / 2.6 ms / 11 µs | 342,069 / 0.64 ms / 5 µs |
| Knot Resolver 6.2.0 | 279,675 / 0.46 ms / 3 µs | 186,102 / 1.0 ms / 5 µs | 151,024 / 1.2 ms / 6 µs | — | 1,247 / 123.0 ms / 88 µs | 256,979 / 0.56 ms / 3 µs |

## Cache misses on two cores

As above, every name unique, upstream at 20ms, the in-flight bound raised to 4,096 wherever the server has one. The load is offered at a fixed rate and climbs 2,000, 5,000, 10,000, 25,000, 50,000, 75,000, 100,000 qps until a step loses more than 0.1% of its queries or answers under 97% of the rate; sustained is the last step carried, with its latency and CPU. At 2,000 qps is every server at the same load, median of 3.

| server | sustained | p50 / p99 there | CPU per miss there | at 2,000 qps: p50 / p99 / CPU | lost at the next step |
|---|---|---|---|---|---|
| elodin dev-e02e553 | 100,000 qps | 21.4 ms / 62.9 ms | 14 µs | 20.4 ms / 21.5 ms / 40 µs | — (carried every step) |
| Unbound 1.24.2 | 25,000 qps | 20.6 ms / 50.8 ms | 22 µs | 20.5 ms / 24.1 ms / 52 µs | 0.4% at 50,000 (answered 36,629 qps) |
| AdGuard Home 0.107.80 | 10,000 qps | 20.6 ms / 34.6 ms | 58 µs | 20.4 ms / 22.6 ms / 105 µs | 0.7% at 25,000 (answered 17,732 qps) |
| Blocky 0.35.0 | 10,000 qps | 20.5 ms / 54.5 ms | 54 µs | 20.4 ms / 21.9 ms / 105 µs | 1.1% at 25,000 (answered 17,248 qps) |
| Pi-hole FTL 6.8 | 2,000 qps | 20.9 ms / 53.1 ms | 222 µs | 20.9 ms / 53.1 ms / 222 µs | 6.3% at 5,000 (answered 3,116 qps) |
| CoreDNS 1.15.0 | 25,000 qps | 20.6 ms / 50.2 ms | 26 µs | 20.5 ms / 21.9 ms / 77 µs | 0.5% at 50,000 (answered 49,659 qps) |
| dnsmasq 2.92 | 2,000 qps | 21.0 ms / 58.3 ms | 192 µs | 21.0 ms / 58.3 ms / 192 µs | 2.1% at 5,000 (answered 3,351 qps) |
| PowerDNS Recursor 5.3.5 | 25,000 qps | 20.8 ms / 215.8 ms | 44 µs | 20.5 ms / 22.5 ms / 64 µs | 0.1% at 50,000 (answered 28,955 qps) |
| dnsdist 2.0.2 | 75,000 qps | 20.8 ms / 54.6 ms | 6 µs | 20.3 ms / 21.4 ms / 27 µs | 0.3% at 100,000 (answered 53,751 qps) |
| BIND 9.20.24 | 25,000 qps | 20.8 ms / 75.5 ms | 29 µs | 20.5 ms / 23.9 ms / 66 µs | 0.7% at 50,000 (answered 36,419 qps) |
| Knot Resolver 6.2.0 | 10,000 qps | 20.5 ms / 32.6 ms | 23 µs | 20.4 ms / 22.5 ms / 42 µs | 0.6% at 25,000 (answered 17,863 qps) |

## What a held connection and a waiting query cost

1,000 clients each ask one cached name and hold the connection idle; (RSS held − RSS before) ÷ N. In flight is 1,000 unique names behind a 1 s upstream, cache off; (peak − idle) ÷ N, with how many were answered.

| server | per idle TCP | per idle DoT | per idle DoH/2 | per query in flight |
|---|---|---|---|---|
| elodin dev-e02e553 | 4.7 KB | 39 KB | 41 KB | 16 KB (all answered) |
| Unbound 1.24.2 | 0.2 KB | 55 KB | 69 KB | 13 KB (all answered) |
| AdGuard Home 0.107.80 | 21 KB | 46 KB | 72 KB | 25 KB (all answered) |
| Blocky 0.35.0 | 20 KB | 34 KB | — | 32 KB (all answered) |
| Pi-hole FTL 6.8 | — (a process per connection) | — | — | 0.8 KB (all answered) |
| CoreDNS 1.15.0 | 7.2 KB | 37 KB | 57 KB | 14 KB (all answered) |
| dnsmasq 2.92 | — | — | — | 0.3 KB (all answered) |
| PowerDNS Recursor 5.3.5 | 1.4 KB | — | — | 16 KB (all answered) |
| dnsdist 2.0.2 | 0.1 KB | 26 KB | 42 KB | 0.0 KB (all answered) |
| BIND 9.20.24 | 9.8 KB | 65 KB | 73 KB | 33 KB (all answered) |
| Knot Resolver 6.2.0 | 7.0 KB | 41 KB | 60 KB | 22 KB (all answered) |

## Reading the tables

- **Knot Resolver is one process, one thread**; the others have two.
- **Knot's DoH/2** answers each request about 48 ms late at any client count,
  the shape of Nagle meeting a delayed ACK.
- **Blocky's TCP and DoT** include reconnects: it closes a connection after
  a number of queries.
- **Pi-hole's TCP** is a forked dnsmasq child per connection, which closes too.
- **dnsdist and dnsmasq are forwarders**: no recursion state, hence their
  CPU per miss and cost per query in flight.
- **Saturated p99s are each at the server's own maximum rate.** Compare tails
  at an equal `-rate` before believing a gap.

## Where elodin is ahead

- Cache misses: the only server to carry every step, 100,000 qps; dnsdist
  75,000, the recursors 25,000 or fewer.
- DoH/1.1 hits, 141k against CoreDNS's 126k.
- TCP p99, 0.29 ms, the lowest, at the highest TCP rate.

## Level

- UDP (777k against dnsdist's 794k), TCP (573k against 556k), DoT (435k
  against 429k), DoH/2 (133k against BIND's 139k), blocked (719k against
  743k): inside the spread.
- Weight: 10 MB idle, as Pi-hole, behind dnsmasq's 5 MB. 21 MB with
  250,000 names, behind Pi-hole's 10 MB (its list is in SQLite on disk) and
  ahead of dnsmasq's 26 MB.

## Where elodin falls behind

- CPU per miss: 14 µs against dnsdist's 6 µs.
- UDP p99 at saturation: 0.43 ms, against Unbound 0.12, PowerDNS 0.14,
  dnsdist 0.27, BIND and dnsmasq 0.37 ms, each at its own rate.
- Per idle TCP connection: 4.7 KB against 0.1-1.4 KB for dnsdist, Unbound and
  PowerDNS. Per idle DoT: 39 KB against dnsdist's 26 KB.
- Per query in flight: 16 KB against Unbound's 13 KB and CoreDNS's 14 KB
  (the forwarders hold under 1 KB).
- Per cache entry: 311 B, fourth behind dnsmasq, Pi-hole and dnsdist.
