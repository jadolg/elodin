# elodin against ten other resolvers and forwarders, second round

Measured on the same 4-core arm64 VM as 2026-11-04-competition.md (8 GB,
Linux 7.0.0-38-generic), server and generator on the same machine, on
2026-11-05 with elodin at dev-5c06dae: every issue the first round filed
(#594, #595, #596, #598, #599) merged. Taken with

```sh
sudo sysctl net.core.rmem_default=1048576
go run ./cmd/bench -only compare -servers all -competitors ~/competitors \
  -unbound /home/ubuntu/unbound-bench -mock-cpus 2-3 -cooldown 5s
```

Mock upstream at 20 ms, DNSSEC off, each run 10 s after 2 s of warmup, median
of 3. Versions and transports are as in the first round.

## What changed in the harness, and why the first round's misses do not compare

The first round's failures were mostly the harness's:

- **Receive buffers were not equal.** elodin asks for a 1 MiB UDP receive
  buffer; most of the others have no setting and took the kernel default,
  208 KiB. A thousand clients starting at once overflowed it, every query
  the kernel dropped (`RcvbufErrors` matched the timed-out count exactly) cost
  its client the generator's 5 s timeout, and the row measured the timeout.
  Unbound's 8,190 misses a second with 1,673 dropped became 42,784 with none
  once the default was raised. The section now refuses to run below 1 MiB.
- **The generator's `-rate` delivered a fraction of the rate asked**
  (2,225 qps for 8,000): a `time.Ticker` drops the ticks nobody waits on. It
  is one shared schedule now and holds the rate.
- **Cache misses are an offered-load ladder,** not 1,000 clients in a closed
  loop: the highest rate a server carries losing at most 0.1%, and every
  server at one equal load, 2,000 qps, which the slowest carry.
- **A TCP or DoT client whose connection breaks dials again** instead of
  counting a failure per spin on a dead socket (the first round's 16 million
  "timed out" for Blocky and Pi-hole).
- **Per-server limits brought to elodin's:** CoreDNS serves at most 200 DoH
  connections unless `https { max_connections }` says otherwise; BIND's
  listen backlog is 10 (`tcp-listen-queue`).
- **The in-flight row waits on a 1 s upstream, not 3 s.** BIND retransmits
  after 800 ms and drops the late replies, so behind 1.5 s it answers after
  five; Blocky gives up on an attempt after about three. Both now answer all
  1,000.
- **The cached name is asked once before the hit rows,** as a running cache
  would have it. BIND drops the copies of one question past
  `clients-per-query` (10) while the first is upstream, which cost it 90
  five-second timeouts on its UDP row.
- **The mock upstream runs on the generator's cores** (`-mock-cpus 2-3`); the
  two together carry 100,000 misses a second there with nothing dropped.

The first round's miss table, and its claim that elodin answered five times
the misses of everything but PowerDNS, should be read as the harness's
numbers, not the servers'.

## elodin before and after the first round's fixes

dev-3ba1ae8 (the first round's build) and dev-5c06dae, run back to back
through `-only compare -servers elodin` with this harness:

| row | dev-3ba1ae8 | dev-5c06dae | change |
|---|---|---|---|
| UDP hits | 461,882 / 1.4 ms / 4 µs | 728,891 / 0.52 ms / 2 µs | +58% |
| TCP hits | 333,036 / 0.94 ms / 7 µs | 451,937 / 1.3 ms / 4 µs | +36% |
| DoT hits | 269,624 / 0.60 ms / 8 µs | 310,048 / 2.7 ms / 6 µs | +15%, **p99 4.5×** |
| DoH/1.1 hits | 138,440 / 2.8 ms / 13 µs | 132,311 / 3.1 ms / 11 µs | −4% (noise), CPU −15% |
| DoH/2 hits | 130,337 / 2.7 ms / 16 µs | 126,274 / 2.7 ms / 13 µs | −3% (noise), CPU −19% |
| blocked (UDP) | 473,623 / 1.4 ms / 4 µs | 512,231 / 1.3 ms / 3 µs | +8% |
| misses sustained / CPU | 50,000 / 29 µs | 50,000 / 25 µs | CPU −14% |
| per cache entry | 492 B | 302 B | −39% (#599) |
| per idle TCP | 17 KB | 8.7 KB | −49% (#596) |
| per idle DoT | 74 KB | 43 KB | −42% (#595) |
| per idle DoH/2 | 72 KB | 43 KB | −40% |
| per query in flight | 17 KB | 17 KB | — |

**The DoT p99 regression is #604.** Each merge since dev-3ba1ae8, DoT at 100
clients on two cores, two runs each:

| merge | DoT p99 |
|---|---|
| 3ba1ae8 (first round) | 1.30, 0.67 ms |
| 15ab3b5 #602 | 0.63, 0.54 ms |
| 4080df4 #603 (#595) | 0.55, 0.69 ms |
| 3417de8 #606 | 0.83, 1.01 ms |
| 979abb2 #604 (#594) | 3.17, 3.06 ms |
| 3a524ff #609 | 2.92, 2.57 ms |
| 5c06dae #608 | 3.08, 3.04 ms |

Across #604 DoT's p50 fell (0.33 → 0.25 ms) and its p99 rose (0.71 → 3.05
ms), with the spread of queries per client widening (16,706–17,154 →
16,872–18,012); TCP improved on all three (p99 2.39 → 1.44 ms).

No DoT connection waits in elodin (#610). Counted under this load, no read
left decrypted bytes in OpenSSL, and 205 of 2.38 million parks found bytes
already queued, each an arrival racing the park that level-triggered epoll
fires on at once. What #604 changed is that a cache hit got cheap enough for
each loop to go idle: at saturation a loop thread ran at 87% and slept in
`epoll_wait` about 5,500 times a second, where before it ran at 100% and
never slept. On this VM a halted vCPU takes the host about 3 ms to wake, and
every build and transport has that 3 ms mode. #604 moved it from DoT's p99.9
to its p99:

- Reverting #604's read path, its epoll change or its vDSO clock alone leaves
  the p99 at 3 ms. Reverting the epoll change and the clock together restores
  the per-query system calls, keeps the loops at 100%, and brings the p99 back
  to 0.66 ms.
- Keeping CPUs 0-1 from halting with `SCHED_IDLE` spinners, which a woken
  thread preempts, moves the mode back to p99.9: dev-979abb2 at saturation
  goes from 3.2 to 1.03 ms.
- The guest scheduler delayed 18 of 22,524 loop wake-ups by more than 0.1 ms,
  so the wait is in the host, not in Linux.
- At the same DoT throughput, Unbound (300,491 / 2.5 ms) and dnsdist
  (305,056 / 3.1 ms) show the same tail. BIND (8 µs per query) and Knot
  (131,079 a second) spend more per query, so they idle less.

A loop that spun before sleeping would hide the wake-up here, at the cost of
CPU on every idle device. Unbound, BIND, Knot Resolver, PowerDNS Recursor and
dnsmasq block in their pollers too.

## Memory

Idle is the server started with its cache on and nothing asked. Lists is 250,000 names, each in the server's own list format, read once `blocked.bench.test` answers NXDOMAIN. Per cache entry is two servers whose caches hold 1,000 and 200,000 answers, each given 40 s of unique names at 128 clients: the difference in RSS over the difference in entries held, so a cache allocated up front counts.

| server | idle RSS | with the list | per rule | per cache entry |
|---|---|---|---|---|
| elodin dev-5c06dae | 10 MB | 19 MB | 38 B | 301 B (filled 132,699) |
| Unbound 1.24.2 | 172 MB | 255 MB | 350 B | 733 B (filled 125,199) |
| AdGuard Home 0.107.80 | 31 MB | 65 MB | 143 B | 555 B (filled 126,507) |
| Blocky 0.35.0 | 28 MB | 35 MB | 29 B | 652 B (filled 133,953) |
| Pi-hole FTL 6.8 | 10 MB | 10 MB | 0 B | 247 B (filled 132,433) |
| CoreDNS 1.15.0 | 49 MB | — | — | 849 B (filled 135,823) |
| dnsmasq 2.92 | 7 MB | 26 MB | 80 B | 194 B (filled 116,995) |
| PowerDNS Recursor 5.3.5 | 41 MB | 84 MB | 180 B | 893 B (filled 125,698) |
| dnsdist 2.0.2 | 99 MB | 161 MB | 261 B | 271 B (filled 119,380) |
| BIND 9.20.24 | 22 MB | 179 MB | 658 B | 357 B (filled 133,085) |
| Knot Resolver 6.2.0 | 17 MB | 54 MB | 156 B | 705 B (filled 123,443) |

## Cache hits on two cores

Server on CPUs 0-1 with two threads, generator on 2-3, 100 clients each holding its connection, every answer from the cache. Each cell is throughput / p99 / CPU per query. A blocked answer is the UDP row's name on the list.

| server | UDP | TCP | DoT | DoH/1.1 | DoH/2 | blocked (UDP) |
|---|---|---|---|---|---|---|
| elodin dev-5c06dae | 640,906 / 0.68 ms / 3 µs | 437,557 / 1.2 ms / 4 µs | 299,340 / 3.1 ms / 6 µs | 123,750 / 3.4 ms / 11 µs | 119,597 / 2.8 ms / 14 µs | 488,474 / 1.4 ms / 3 µs |
| Unbound 1.24.2 | 569,632 / 0.61 ms / 3 µs | 311,175 / 2.5 ms / 6 µs | 300,491 / 2.5 ms / 7 µs | — | 114,695 / 2.9 ms / 15 µs | 593,258 / 0.56 ms / 2 µs |
| AdGuard Home 0.107.80 | 101,234 / 3.6 ms / 22 µs | 108,850 / 3.9 ms / 21 µs | 97,053 / 4.4 ms / 23 µs | 75,694 / 5.8 ms / 29 µs | 49,970 / 7.2 ms / 45 µs | 113,363 / 3.1 ms / 20 µs |
| Blocky 0.35.0 | 140,551 / 3.4 ms / 15 µs | 121,212 / 5.4 ms / 16 µs (**11,366 failed, 11,366 reconnects**) | 111,693 / 5.6 ms / 17 µs (**10,411 failed, 10,411 reconnects**) | 79,636 / 5.3 ms / 26 µs | — | 136,352 / 3.1 ms / 16 µs |
| Pi-hole FTL 6.8 | 134,742 / 3.4 ms / 17 µs | 10,627 / 28.3 ms / 93 µs (**1,517 failed, 1,517 reconnects**) | — | — | — | 145,135 / 4.5 ms / 16 µs |
| CoreDNS 1.15.0 | 218,929 / 2.3 ms / 9 µs | 238,054 / 3.5 ms / 7 µs | 236,663 / 3.4 ms / 7 µs | 107,949 / 4.9 ms / 15 µs | 57,474 / 6.6 ms / 32 µs | — |
| dnsmasq 2.92 | 264,933 / 0.53 ms / 4 µs | — | — | — | — | 255,976 / 0.55 ms / 4 µs |
| PowerDNS Recursor 5.3.5 | 579,567 / 0.61 ms / 3 µs | 350,452 / 1.4 ms / 3 µs | — | — | — | 515,741 / 0.78 ms / 3 µs |
| dnsdist 2.0.2 | 490,577 / 1.3 ms / 3 µs | 320,706 / 2.6 ms / 6 µs | 305,056 / 3.1 ms / 6 µs | — | 106,126 / 3.7 ms / 14 µs | 473,252 / 1.3 ms / 3 µs |
| BIND 9.20.24 | 414,427 / 1.2 ms / 4 µs | 304,450 / 3.0 ms / 7 µs | 282,845 / 1.1 ms / 8 µs | — | 116,155 / 3.5 ms / 16 µs | 159,466 / 1.4 ms / 11 µs |
| Knot Resolver 6.2.0 | 276,020 / 0.78 ms / 4 µs | 161,664 / 1.5 ms / 7 µs | 131,079 / 1.5 ms / 9 µs | — | 1,562 / 123.6 ms / 79 µs | 258,655 / 0.62 ms / 4 µs |

## Cache misses on two cores

As above, every name unique, upstream at 20ms, the in-flight bound raised to 4,096 wherever the server has one. The load is offered at a fixed rate and climbs 2,000, 5,000, 10,000, 25,000, 50,000, 75,000, 100,000 qps until a step loses more than 0.1% of its queries or answers under 97% of the rate; sustained is the last step carried, with its latency and CPU. At 2,000 qps is every server at the same load, median of 3.

| server | sustained | p50 / p99 there | CPU per miss there | at 2,000 qps: p50 / p99 / CPU | lost at the next step |
|---|---|---|---|---|---|
| elodin dev-5c06dae | 75,000 qps | 32.8 ms / 106.8 ms | 27 µs | 20.4 ms / 22.3 ms / 52 µs | 0.0% at 100,000 (answered 79,115 qps) |
| Unbound 1.24.2 | 25,000 qps | 20.6 ms / 59.1 ms | 28 µs | 20.4 ms / 24.9 ms / 56 µs | 0.6% at 50,000 (answered 34,798 qps) |
| AdGuard Home 0.107.80 | 10,000 qps | 20.6 ms / 67.6 ms | 72 µs | 20.5 ms / 25.1 ms / 129 µs | 0.9% at 25,000 (answered 17,357 qps) |
| Blocky 0.35.0 | 5,000 qps | 20.5 ms / 38.4 ms | 86 µs | 20.5 ms / 26.0 ms / 127 µs | 0.2% at 10,000 (answered 9,979 qps) |
| Pi-hole FTL 6.8 | 2,000 qps | 20.9 ms / 72.1 ms | 253 µs | 20.9 ms / 72.1 ms / 253 µs | 4.6% at 5,000 (answered 3,239 qps) |
| CoreDNS 1.15.0 | 25,000 qps | 20.6 ms / 67.5 ms | 32 µs | 20.5 ms / 23.0 ms / 90 µs | 0.8% at 50,000 (answered 37,715 qps) |
| dnsmasq 2.92 | 2,000 qps | 21.0 ms / 58.6 ms | 219 µs | 21.0 ms / 58.6 ms / 219 µs | 1.5% at 5,000 (answered 4,821 qps) |
| PowerDNS Recursor 5.3.5 | 10,000 qps | 20.5 ms / 38.5 ms | 54 µs | 20.5 ms / 22.3 ms / 76 µs | 0.3% at 25,000 (answered 17,259 qps) |
| dnsdist 2.0.2 | 75,000 qps | 21.0 ms / 61.8 ms | 8 µs | 20.3 ms / 21.7 ms / 33 µs | 0.1% at 100,000 (answered 84,324 qps) |
| BIND 9.20.24 | 25,000 qps | 20.9 ms / 67.7 ms | 37 µs | 20.5 ms / 26.1 ms / 75 µs | 0.4% at 50,000 (answered 49,699 qps) |
| Knot Resolver 6.2.0 | 10,000 qps | 20.6 ms / 37.1 ms | 28 µs | 20.4 ms / 22.8 ms / 52 µs | 0.7% at 25,000 (answered 22,541 qps) |

## What a held connection and a waiting query cost

1,000 clients each ask one cached name and hold the connection idle; (RSS held − RSS before) ÷ N. In flight is 1,000 unique names behind a 1 s upstream, cache off; (peak − idle) ÷ N, with how many were answered.

| server | per idle TCP | per idle DoT | per idle DoH/2 | per query in flight |
|---|---|---|---|---|
| elodin dev-5c06dae | 8.7 KB | 43 KB | 46 KB | 17 KB (all answered) |
| Unbound 1.24.2 | 0.2 KB | 53 KB | 64 KB | 12 KB (all answered) |
| AdGuard Home 0.107.80 | 20 KB | 44 KB | 66 KB | 21 KB (all answered) |
| Blocky 0.35.0 | 14 KB | 34 KB | — | 32 KB (all answered) |
| Pi-hole FTL 6.8 | 0.0 KB (**60 of 1,000**) | — | — | 0.8 KB (all answered) |
| CoreDNS 1.15.0 | 18 KB | 35 KB | 62 KB | 14 KB (all answered) |
| dnsmasq 2.92 | — | — | — | 0.3 KB (all answered) |
| PowerDNS Recursor 5.3.5 | 0.1 KB | — | — | 16 KB (all answered) |
| dnsdist 2.0.2 | 0.1 KB | 25 KB | 42 KB | 0.0 KB (all answered) |
| BIND 9.20.24 | 21 KB | 65 KB | 74 KB | 33 KB (all answered) |
| Knot Resolver 6.2.0 | 17 KB | 42 KB | 60 KB | 22 KB (all answered) |

## Reading the tables

- **Sustained misses are a lower bound, and the next step an upper one.**
  The ladder is coarse: PowerDNS carried 25,000 alone with nothing lost (p99
  191 ms) and lost 0.3% at 25,000 in the run. The drops at a failing step
  were checked for Unbound with `/proc/net/udp`: all of them on its own
  listening socket, none at the mock or the generator.
- **CPU per miss at 2,000 qps** carries each server's fixed cost of being
  awake (timers, idle threads), spread over few queries; at the sustained
  rate it is the cost of a miss.
- **Blocky's TCP and DoT reconnects** are Blocky closing a connection after a
  number of queries (miekg/dns's per-connection cap); the generator dials
  again and the row includes those handshakes.
- **Pi-hole's TCP** is dnsmasq's: a forked child per connection, which also
  explains its 60 of 1,000 held.
- **Knot's DoH/2** answers each request about 48 ms after it is asked at 1,
  10 or 100 clients alike, so its throughput is clients ÷ 48 ms: the shape of
  Nagle's algorithm meeting a delayed ACK. kresd has no setting for it.
- **dnsdist and dnsmasq's 0.0–0.3 KB per query in flight** is a forwarder
  keeping a slot per query and nothing else; dnsdist sends its misses through
  a packet cache with no recursion state.

## Where elodin is ahead

- **Cache hits over UDP, TCP and both DoH**: first on each, at 3 µs per
  UDP hit and 4 µs per TCP hit, level with PowerDNS and Unbound now (#594).
  DoH/2 is first by 3% over BIND, inside the run-to-run spread.
- **Cache misses**: one of two servers to carry 75,000 a second on two cores
  (dnsdist the other); the recursors carry 10,000–25,000.
- **Idle and total weight**: 10 MB idle, 19 MB with 250,000 names.

## Where elodin falls behind

- **DoT p99 at 3 ms**, against BIND's 1.1 ms and Knot's 1.5 ms. This is the VM's
  vCPU wake-up, not a wait in elodin (#610, above); Unbound and dnsdist show
  the same tail at the same throughput.
- **CPU per cache miss** (#612): 27 µs at saturation against dnsdist's 8 µs, and a
  p99 of 107 ms at 75,000 against dnsdist's 62 ms. Unbound and Knot are
  level with elodin at 28 µs.
- **Blocked answers cost more than cached ones** (#611): 488,474 a second against
  640,906 for a hit. Unbound (593,258) and PowerDNS (515,741) answer a
  listed name as fast as a cached one.
- **Per idle TCP connection** (#613): 8.7 KB, halved, against 0.1–0.2 KB for
  PowerDNS, dnsdist and Unbound.
- **Per idle DoT connection** (#614): 43 KB against dnsdist's 25 KB, Blocky's 34 KB
  and CoreDNS's 35 KB.
- **Per query in flight** (#614): 17 KB against Unbound's 12 KB and CoreDNS's 14 KB.
- **Per cache entry**: 301 B, fourth behind dnsmasq (194 B), Pi-hole (247 B)
  and dnsdist (271 B).
